from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .email_headers import EmailHeaders


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class EmailCategory(str, Enum):
    SAFE = "safe"
    SPAM = "spam"
    PHISHING = "phishing"
    SCAM = "scam"
    MALWARE = "malware"
    UNCERTAIN = "uncertain"


class RecommendedAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    RESTRICT = "restrict"
    QUARANTINE = "quarantine"


class EmailAuthentication(BaseModel):
    model_config = ConfigDict(title="郵件身分驗證")

    spf: str | None = Field(default=None, title="SPF 驗證結果")
    dkim: str | None = Field(default=None, title="DKIM 驗證結果")
    dmarc: str | None = Field(default=None, title="DMARC 驗證結果")


class NormalizedEmail(BaseModel):
    """所有郵件供應商都必須轉成這個格式，AI 不接觸 Gmail API。"""

    model_config = ConfigDict(title="標準化郵件")

    provider: str = Field(default="unknown", title="郵件服務來源")
    message_id: str = Field(title="郵件識別碼")
    thread_id: str | None = Field(default=None, title="郵件討論串識別碼")
    sender: str = Field(default="", title="寄件者")
    reply_to: str | None = Field(default=None, title="回覆地址")
    recipients: list[str] = Field(default_factory=list, title="收件者")
    subject: str = Field(default="", title="郵件主旨")
    body_text: str = Field(default="", title="郵件純文字內容")
    links: list[str] = Field(default_factory=list, title="郵件內的連結")
    attachment_names: list[str] = Field(default_factory=list, title="附件名稱")
    authentication: EmailAuthentication = Field(
        default_factory=EmailAuthentication,
        title="郵件身分驗證結果",
    )
    headers: EmailHeaders = Field(
        default_factory=EmailHeaders,
        title="郵件標頭資訊",
    )


class AnalysisResult(BaseModel):
    model_config = ConfigDict(title="AI 分析結果")

    category: EmailCategory = Field(title="郵件分類")
    risk_score: int = Field(ge=0, le=100, title="風險分數")
    confidence: float = Field(ge=0, le=1, title="模型信心值")
    signals: list[str] = Field(title="風險判斷依據")
    explanation_zh: str = Field(title="中文分析說明")


class ProtectionDecision(BaseModel):
    model_config = ConfigDict(title="防護決策")

    level: RiskLevel = Field(title="風險等級")
    action: RecommendedAction = Field(title="建議動作")
    color: str | None = Field(title="警示顏色")
    warning: str | None = Field(title="警示訊息")
    links_enabled: bool = Field(title="是否允許開啟連結")
    attachments_enabled: bool = Field(title="是否允許開啟附件")


class ProtectedEmail(BaseModel):
    model_config = ConfigDict(title="郵件防護結果")

    email: NormalizedEmail = Field(title="郵件內容")
    analysis: AnalysisResult = Field(title="AI 分析")
    decision: ProtectionDecision = Field(title="防護決策")
