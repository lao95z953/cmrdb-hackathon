import unittest

from mail_guard.models import AnalysisResult, EmailCategory, RiskLevel
from mail_guard.policy import decide_protection


def result(
    score: int,
    *,
    category: EmailCategory = EmailCategory.PHISHING,
    confidence: float = 0.9,
) -> AnalysisResult:
    return AnalysisResult(
        category=category,
        risk_score=score,
        confidence=confidence,
        signals=[],
        explanation_zh="test",
    )


class PolicyTests(unittest.TestCase):
    def test_low_has_no_color(self) -> None:
        decision = decide_protection(result(29, category=EmailCategory.SAFE))
        self.assertEqual(decision.level, RiskLevel.LOW)
        self.assertIsNone(decision.color)

    def test_uncertain_has_its_own_yellow_decision(self) -> None:
        decision = decide_protection(
            result(60, category=EmailCategory.UNCERTAIN, confidence=0.6)
        )
        self.assertEqual(decision.level, RiskLevel.UNCERTAIN)
        self.assertEqual(decision.color, "yellow")
        self.assertTrue(decision.links_enabled)

    def test_medium_is_yellow(self) -> None:
        self.assertEqual(decide_protection(result(30)).level, RiskLevel.MEDIUM)

    def test_high_is_red_and_restricted(self) -> None:
        decision = decide_protection(result(60))
        self.assertEqual(decision.level, RiskLevel.HIGH)
        self.assertFalse(decision.links_enabled)

    def test_score_over_85_remains_high_without_quarantine(self) -> None:
        decision = decide_protection(result(95))
        self.assertEqual(decision.level, RiskLevel.HIGH)
        self.assertEqual(decision.action.value, "restrict")


if __name__ == "__main__":
    unittest.main()
