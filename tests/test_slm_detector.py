import unittest

from mail_guard.ai.slm_detector import LABEL_TO_CATEGORY, SLMDetector
from mail_guard.email_headers import EmailHeaders
from mail_guard.models import EmailCategory, NormalizedEmail


def email() -> NormalizedEmail:
    return NormalizedEmail(
        message_id="test-1",
        sender="security@example.com",
        subject="帳戶驗證",
        body_text="請立即登入並驗證密碼。",
    )


class SLMDetectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_maps_phishing_result_to_high_risk(self) -> None:
        phishing_label = next(
            label
            for label, category in LABEL_TO_CATEGORY.items()
            if category is EmailCategory.PHISHING
        )

        def classifier(*args, **kwargs):
            return {"labels": [phishing_label], "scores": [0.8]}

        result = await SLMDetector(classifier=classifier).analyze(email())

        self.assertEqual(result.category, EmailCategory.PHISHING)
        self.assertEqual(result.risk_score, 92)
        self.assertEqual(result.confidence, 0.8)

    async def test_low_confidence_is_uncertain(self) -> None:
        safe_label = next(
            label
            for label, category in LABEL_TO_CATEGORY.items()
            if category is EmailCategory.SAFE
        )

        def classifier(*args, **kwargs):
            return {"labels": [safe_label], "scores": [0.2]}

        result = await SLMDetector(classifier=classifier).analyze(email())

        self.assertEqual(result.category, EmailCategory.UNCERTAIN)
        self.assertEqual(result.risk_score, 50)

    async def test_rejects_invalid_model_output(self) -> None:
        def classifier(*args, **kwargs):
            return {"labels": [], "scores": []}

        with self.assertRaisesRegex(RuntimeError, "有效的分類結果"):
            await SLMDetector(classifier=classifier).analyze(email())

    def test_slm_input_does_not_include_technical_headers(self) -> None:
        message = email().model_copy(
            update={"headers": EmailHeaders(received=["from hidden.example"])}
        )
        formatted = SLMDetector._format_email(message)
        self.assertNotIn("hidden.example", formatted)


if __name__ == "__main__":
    unittest.main()
