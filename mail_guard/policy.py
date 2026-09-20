from .models import (
    AnalysisResult,
    EmailCategory,
    ProtectionDecision,
    RecommendedAction,
    RiskLevel,
)


def decide_protection(result: AnalysisResult) -> ProtectionDecision:
    """將 SLM 的類別、信任度與風險分數轉成可稽核的產品行為。"""

    if result.category is EmailCategory.UNCERTAIN:
        return ProtectionDecision(
            level=RiskLevel.UNCERTAIN,
            action=RecommendedAction.WARN,
            color="yellow",
            warning=(
                "模型信任度不足，無法可靠判斷這封郵件。"
                "請檢查寄件者、連結及附件後再操作。"
            ),
            links_enabled=True,
            attachments_enabled=True,
        )

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
            warning="SLM 發現可疑訊號，請先確認寄件者與連結再操作。",
            links_enabled=True,
            attachments_enabled=True,
        )
    return ProtectionDecision(
        level=RiskLevel.HIGH,
        action=RecommendedAction.RESTRICT,
        color="red",
        warning=(
            "SLM 判斷這封郵件具有高度風險，請勿點擊連結、下載附件或提供個人資料。"
        ),
        links_enabled=False,
        attachments_enabled=False,
    )
