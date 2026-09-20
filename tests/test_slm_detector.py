import unittest

from mail_guard.ai.slm_detector import SLMDetector
from mail_guard.email_headers import EmailHeaders
from mail_guard.models import EmailAuthentication, EmailCategory, NormalizedEmail


def email() -> NormalizedEmail:
    return NormalizedEmail(
        message_id="test-1",
        sender="security@example.com",
        reply_to="verify@other.example",
        subject="帳戶驗證",
        body_text="請立即登入並驗證密碼。",
        links=["https://other.example/login"],
        authentication=EmailAuthentication(dmarc="fail"),
    )


def classifier_with_probability(phishing_probability: float):
    def classifier(*args, **kwargs):
        return [[
            {"label": "LABEL_0", "score": 1 - phishing_probability},
            {"label": "LABEL_1", "score": phishing_probability},
        ]]

    return classifier


class FakeTokenizer:
    model_max_length = 12

    def __init__(self) -> None:
        self.tokens: dict[str, int] = {}
        self.reverse: dict[int, str] = {}

    def num_special_tokens_to_add(self, pair=False):
        return 2

    def __call__(self, text, **kwargs):
        ids = []
        for token in text.split():
            if token not in self.tokens:
                token_id = len(self.tokens) + 1
                self.tokens[token] = token_id
                self.reverse[token_id] = token
            ids.append(self.tokens[token])
        return {"input_ids": ids}

    def decode(self, ids, skip_special_tokens=True):
        return " ".join(self.reverse[token_id] for token_id in ids)


class ChunkingClassifier:
    def __init__(self) -> None:
        self.tokenizer = FakeTokenizer()
        self.segments: list[str] = []

    def __call__(self, segments, **kwargs):
        self.segments = segments
        outputs = []
        for segment in segments:
            phishing = 0.9 if "danger" in segment else 0.1
            outputs.append([
                {"label": "LABEL_0", "score": 1 - phishing},
                {"label": "LABEL_1", "score": phishing},
            ])
        return outputs


class SLMDetectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_maps_high_phishing_probability_to_risk_score(self) -> None:
        result = await SLMDetector(
            classifier=classifier_with_probability(0.8), min_confidence=0.75
        ).analyze(email())

        self.assertEqual(result.category, EmailCategory.PHISHING)
        self.assertEqual(result.risk_score, 80)
        self.assertEqual(result.confidence, 0.8)

    async def test_low_confidence_has_uncertain_category(self) -> None:
        result = await SLMDetector(
            classifier=classifier_with_probability(0.6), min_confidence=0.75
        ).analyze(email())

        self.assertEqual(result.category, EmailCategory.UNCERTAIN)
        self.assertEqual(result.risk_score, 60)
        self.assertEqual(result.confidence, 0.6)
        self.assertIn("不確定門檻", result.signals[-1])

    async def test_confident_safe_result_uses_inverse_probability(self) -> None:
        result = await SLMDetector(
            classifier=classifier_with_probability(0.1), min_confidence=0.75
        ).analyze(email())

        self.assertEqual(result.category, EmailCategory.SAFE)
        self.assertEqual(result.risk_score, 10)
        self.assertEqual(result.confidence, 0.9)

    async def test_long_email_keeps_final_segment(self) -> None:
        classifier = ChunkingClassifier()
        message = NormalizedEmail(
            message_id="long",
            body_text=" ".join([*["normal"] * 100, "danger"]),
        )
        result = await SLMDetector(
            classifier=classifier,
            max_segments=2,
            min_confidence=0.75,
        ).analyze(message)

        self.assertEqual(len(classifier.segments), 2)
        self.assertIn("danger", classifier.segments[-1])
        self.assertEqual(result.category, EmailCategory.PHISHING)
        self.assertIn("第 2 段風險最高", result.signals[-1])

    async def test_rejects_output_without_configured_phishing_label(self) -> None:
        def classifier(*args, **kwargs):
            return [[{"label": "UNKNOWN", "score": 1.0}]]

        with self.assertRaisesRegex(RuntimeError, "缺少 phishing label"):
            await SLMDetector(classifier=classifier).analyze(email())

    def test_slm_input_keeps_body_first_and_excludes_technical_headers(self) -> None:
        message = email().model_copy(
            update={"headers": EmailHeaders(received=["from hidden.example"])}
        )
        formatted = SLMDetector._format_email(message)
        self.assertTrue(formatted.startswith(message.body_text))
        self.assertIn("other.example/login", formatted)
        self.assertNotIn("DMARC=fail", formatted)
        self.assertNotIn("hidden.example", formatted)

    def test_rejects_invalid_confidence_threshold(self) -> None:
        with self.assertRaisesRegex(ValueError, "0.5"):
            SLMDetector(min_confidence=0.4)


if __name__ == "__main__":
    unittest.main()
