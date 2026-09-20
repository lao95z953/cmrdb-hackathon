import unittest

from mail_guard.models import AnalysisResult, EmailCategory, RiskLevel
from mail_guard.policy import decide_protection


def result(score: int) -> AnalysisResult:
    return AnalysisResult(
        category=EmailCategory.UNCERTAIN,
        risk_score=score,
        confidence=0.8,
        signals=[],
        explanation_zh="test",
    )


class PolicyTests(unittest.TestCase):
    def test_low_has_no_color(self) -> None:
        decision = decide_protection(result(29))
        self.assertEqual(decision.level, RiskLevel.LOW)
        self.assertIsNone(decision.color)

    def test_medium_is_yellow(self) -> None:
        self.assertEqual(decide_protection(result(30)).color, "yellow")

    def test_high_is_red_and_restricted(self) -> None:
        decision = decide_protection(result(60))
        self.assertEqual(decision.level, RiskLevel.HIGH)
        self.assertFalse(decision.links_enabled)

    def test_blocked_is_quarantined(self) -> None:
        decision = decide_protection(result(85))
        self.assertEqual(decision.level, RiskLevel.BLOCKED)
        self.assertEqual(decision.action.value, "quarantine")


if __name__ == "__main__":
    unittest.main()

