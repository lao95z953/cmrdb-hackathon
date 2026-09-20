import unittest

from mail_guard.models import AnalysisResult, EmailCategory, NormalizedEmail
from mail_guard.service import MailProtectionService


class FakeAnalyzer:
    def __init__(self, score: int) -> None:
        self.score = score

    async def analyze(self, email: NormalizedEmail) -> AnalysisResult:
        return AnalysisResult(
            category=EmailCategory.PHISHING,
            risk_score=self.score,
            confidence=0.9,
            signals=["寄件者與 Reply-To 網域不一致", "要求立即輸入密碼"],
            explanation_zh="具有帳號竊取特徵。",
        )


class ServiceExplanationTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_risk_level_has_a_chinese_reason(self) -> None:
        cases = [
            (20, "低風險", "低於 30"),
            (40, "中度風險", "30 至 59"),
            (70, "高風險", "60 至 84"),
            (90, "明確垃圾或惡意郵件", "85 以上"),
        ]

        for score, level_name, threshold_reason in cases:
            with self.subTest(score=score):
                result = await MailProtectionService(FakeAnalyzer(score)).protect(
                    NormalizedEmail(message_id=f"message-{score}")
                )
                explanation = result.analysis.explanation_zh
                self.assertIn(level_name, explanation)
                self.assertIn(threshold_reason, explanation)
                self.assertIn("寄件者與 Reply-To 網域不一致", explanation)
                self.assertIn("要求立即輸入密碼", explanation)


if __name__ == "__main__":
    unittest.main()
