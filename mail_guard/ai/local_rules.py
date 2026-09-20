from urllib.parse import urlparse

from ..models import AnalysisResult, EmailCategory, NormalizedEmail


class LocalRuleAnalyzer:
    """無 API Key 時可使用的展示模式，不應當成正式安全產品。"""

    async def analyze(self, email: NormalizedEmail) -> AnalysisResult:
        text = f"{email.subject}\n{email.body_text}".lower()
        signals: list[str] = []
        score = 5

        suspicious_terms = {
            "立即登入": 22,
            "驗證帳戶": 20,
            "帳戶停用": 20,
            "密碼": 12,
            "驗證碼": 18,
            "緊急匯款": 35,
            "gift card": 30,
            "點擊連結": 12,
            "恭喜中獎": 35,
        }
        for term, points in suspicious_terms.items():
            if term in text:
                score += points
                signals.append(f"包含可疑用語：{term}")

        sender_domain = _domain_from_address(email.sender)
        reply_domain = _domain_from_address(email.reply_to or "")
        if sender_domain and reply_domain and sender_domain != reply_domain:
            score += 20
            signals.append("寄件者與 Reply-To 網域不一致")

        for link in email.links:
            host = (urlparse(link).hostname or "").lower()
            if host and sender_domain and not host.endswith(sender_domain):
                score += 8
                signals.append("郵件連結與寄件者網域不同")
                break

        if (email.authentication.dmarc or "").lower() == "fail":
            score += 25
            signals.append("DMARC 驗證失敗")

        score = min(score, 100)
        if score >= 85:
            category = EmailCategory.PHISHING
        elif score >= 60:
            category = EmailCategory.SCAM
        elif score >= 30:
            category = EmailCategory.SPAM
        else:
            category = EmailCategory.SAFE

        return AnalysisResult(
            category=category,
            risk_score=score,
            confidence=0.55,
            signals=signals or ["本機規則未發現明顯危險特徵"],
            explanation_zh="目前使用本機規則展示模式；設定 OPENAI_API_KEY 後會改用 AI 分析。",
        )


def _domain_from_address(value: str) -> str:
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].strip(" >").lower()

