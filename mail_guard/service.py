from .ai.base import EmailAnalyzer
from .email.base import EmailConnector
from .models import AnalysisResult, NormalizedEmail, ProtectedEmail, ProtectionDecision, RiskLevel
from .policy import decide_protection


LEVEL_NAMES = {
    RiskLevel.LOW: "低風險",
    RiskLevel.UNCERTAIN: "不確定",
    RiskLevel.MEDIUM: "中度風險",
    RiskLevel.HIGH: "高風險",
}

LEVEL_REASONS = {
    RiskLevel.LOW: "風險分數低於 30，因此正常顯示郵件。",
    RiskLevel.UNCERTAIN: "模型信任度不足，因此加上不確定標籤並交由使用者判斷。",
    RiskLevel.MEDIUM: "風險分數介於 30 至 59，因此顯示黃色提醒。",
    RiskLevel.HIGH: "風險分數達到 60 以上，因此顯示紅色警告並停用連結與附件。",
}


def explain_decision(
    analysis: AnalysisResult, decision: ProtectionDecision
) -> AnalysisResult:
    """把模型訊號、信任度與固定風險政策整理成使用者看得懂的原因。"""
    signals = list(dict.fromkeys(signal.strip() for signal in analysis.signals if signal.strip()))
    evidence = "、".join(signals) if signals else "模型未提供額外的風險訊號"
    explanation = (
        f"判定為{LEVEL_NAMES[decision.level]}（{analysis.risk_score} 分，"
        f"信任度 {analysis.confidence:.1%}）。"
        f"判斷原因：{evidence}。"
        f"{LEVEL_REASONS[decision.level]}"
        f"模型說明：{analysis.explanation_zh}"
    )
    return analysis.model_copy(update={"explanation_zh": explanation})


class MailProtectionService:
    """唯一負責串接郵件模組與 SLM 的應用層。"""

    def __init__(self, analyzer: EmailAnalyzer) -> None:
        self.analyzer = analyzer

    async def protect(self, email: NormalizedEmail) -> ProtectedEmail:
        analysis = await self.analyzer.analyze(email)
        decision = decide_protection(analysis)
        analysis = explain_decision(analysis, decision)
        return ProtectedEmail(email=email, analysis=analysis, decision=decision)

    async def scan_connector(
        self, connector: EmailConnector, limit: int = 10
    ) -> list[ProtectedEmail]:
        protected: list[ProtectedEmail] = []
        for email in await connector.list_inbox(limit):
            result = await self.protect(email)
            await connector.apply_decision(email, result.decision)
            protected.append(result)
        return protected
