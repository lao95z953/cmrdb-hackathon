import unittest

from mail_guard.models import AnalysisResult, EmailCategory, NormalizedEmail
from mail_guard.service import MailProtectionService


class FakeAnalyzer:
    def __init__(
        self,
        score: int,
        category: EmailCategory = EmailCategory.PHISHING,
        confidence: float = 0.9,
    ) -> None:
        self.score = score
        self.category = category
        self.confidence = confidence

    async def analyze(self, email: NormalizedEmail) -> AnalysisResult:
        return AnalysisResult(
            category=self.category,
            risk_score=self.score,
            confidence=self.confidence,
            signals=["寄件者與 Reply-To 網域不一致", "要求立即輸入密碼"],
            explanation_zh="具有帳號竊取特徵。",
        )


class ServiceExplanationTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_risk_level_has_a_chinese_reason(self) -> None:
        cases = [
            (20, EmailCategory.SAFE, 0.9, "低風險", "低於 30"),
            (50, EmailCategory.UNCERTAIN, 0.6, "不確定", "信任度不足"),
            (40, EmailCategory.PHISHING, 0.9, "中度風險", "30 至 59"),
            (90, EmailCategory.PHISHING, 0.9, "高風險", "60 以上"),
        ]

        for score, category, confidence, level_name, reason in cases:
            with self.subTest(score=score, category=category):
                result = await MailProtectionService(
                    FakeAnalyzer(score, category, confidence)
                ).protect(NormalizedEmail(message_id=f"message-{score}"))
                explanation = result.analysis.explanation_zh
                self.assertIn(level_name, explanation)
                self.assertIn(reason, explanation)
                self.assertIn(f"信任度 {confidence:.1%}", explanation)
                self.assertIn("寄件者與 Reply-To 網域不一致", explanation)


if __name__ == "__main__":
    unittest.main()
