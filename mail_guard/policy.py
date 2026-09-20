from .models import AnalysisResult, ProtectionDecision, RecommendedAction, RiskLevel


def decide_protection(result: AnalysisResult) -> ProtectionDecision:
    """把 AI 分數轉成確定、可稽核的產品行為。"""

    score = result.risk_score
    if score < 30:
        return ProtectionDecision(
            level=RiskLevel.LOW,
            action=RecommendedAction.ALLOW,
            color=None,
            warning=None,
            links_enabled=True,
            attachments_enabled=True,
        )
    if score < 60:
        return ProtectionDecision(
            level=RiskLevel.MEDIUM,
            action=RecommendedAction.WARN,
            color="yellow",
            warning="AI 判斷這封郵件可能含有垃圾、詐騙或其他可疑資訊，請提高警覺。",
            links_enabled=True,
            attachments_enabled=True,
        )
    if score < 85:
        return ProtectionDecision(
            level=RiskLevel.HIGH,
            action=RecommendedAction.RESTRICT,
            color="red",
            warning="這封郵件具有高度風險，請勿隨意點擊連結、下載附件或提供個人資料。",
            links_enabled=False,
            attachments_enabled=False,
        )
    return ProtectionDecision(
        level=RiskLevel.BLOCKED,
        action=RecommendedAction.QUARANTINE,
        color="red",
        warning="SLM 與雲端 AI 均判斷為明確垃圾或惡意郵件，已移至 Gmail 垃圾桶（可復原）。",
        links_enabled=False,
        attachments_enabled=False,
    )
