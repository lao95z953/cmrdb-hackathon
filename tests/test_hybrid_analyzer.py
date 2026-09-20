import unittest

from mail_guard.ai.hybrid_analyzer import HybridEmailAnalyzer
from mail_guard.models import AnalysisResult, EmailCategory, NormalizedEmail


class FakeAnalyzer:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    async def analyze(self, email):
        if self.error:
            raise self.error
        return self.result


def result(category: EmailCategory, score: int) -> AnalysisResult:
    return AnalysisResult(
        category=category,
        risk_score=score,
        confidence=0.9,
        signals=[category.value],
        explanation_zh="測試",
    )


EMAIL = NormalizedEmail(message_id="test")


class HybridAnalyzerTests(unittest.IsolatedAsyncioTestCase):
    async def test_score_weights_slm_20_percent_and_gemini_80_percent(self):
        analyzer = HybridEmailAnalyzer(
            FakeAnalyzer(result(EmailCategory.PHISHING, 80)),
            FakeAnalyzer(result(EmailCategory.PHISHING, 100)),
        )
        merged = await analyzer.analyze(EMAIL)
        self.assertEqual(merged.risk_score, 96)

    async def test_both_explicit_malicious_can_reach_cleanup_threshold(self):
        analyzer = HybridEmailAnalyzer(
            FakeAnalyzer(result(EmailCategory.PHISHING, 90)),
            FakeAnalyzer(result(EmailCategory.SCAM, 88)),
        )
        merged = await analyzer.analyze(EMAIL)
        self.assertGreaterEqual(merged.risk_score, 85)

    async def test_score_uses_weighting_without_a_minimum_floor(self):
        analyzer = HybridEmailAnalyzer(
            FakeAnalyzer(result(EmailCategory.MALWARE, 80)),
            FakeAnalyzer(result(EmailCategory.SAFE, 0)),
        )
        merged = await analyzer.analyze(EMAIL)
        self.assertEqual(merged.risk_score, 16)

    async def test_failure_falls_back_without_cleanup(self):
        analyzer = HybridEmailAnalyzer(
            FakeAnalyzer(result(EmailCategory.PHISHING, 95)),
            FakeAnalyzer(error=RuntimeError("offline")),
        )
        merged = await analyzer.analyze(EMAIL)
        self.assertEqual(merged.risk_score, 84)
        self.assertIn("停用自動清理", merged.signals[-1])


if __name__ == "__main__":
    unittest.main()
