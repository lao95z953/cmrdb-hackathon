from __future__ import annotations

import asyncio

from .base import EmailAnalyzer
from ..models import AnalysisResult, EmailCategory, NormalizedEmail


MALICIOUS_CATEGORIES = {
    EmailCategory.SPAM,
    EmailCategory.PHISHING,
    EmailCategory.SCAM,
    EmailCategory.MALWARE,
}
CATEGORY_PRIORITY = {
    EmailCategory.SAFE: 0,
    EmailCategory.UNCERTAIN: 1,
    EmailCategory.SPAM: 2,
    EmailCategory.SCAM: 3,
    EmailCategory.PHISHING: 4,
    EmailCategory.MALWARE: 5,
}


class HybridEmailAnalyzer:
    """結合 SLM 與 Gemini；只有雙方一致明確惡意才允許進入清理門檻。"""

    def __init__(self, slm: EmailAnalyzer, gemini: EmailAnalyzer) -> None:
        self.slm = slm
        self.gemini = gemini

    async def analyze(self, email: NormalizedEmail) -> AnalysisResult:
        results = await asyncio.gather(
            self.slm.analyze(email),
            self.gemini.analyze(email),
            return_exceptions=True,
        )
        valid = [result for result in results if isinstance(result, AnalysisResult)]
        if not valid:
            messages = [type(result).__name__ for result in results]
            raise RuntimeError(f"SLM 與 Gemini 均分析失敗：{', '.join(messages)}")
        if len(valid) == 1:
            return _safe_fallback(valid[0])
        return _merge(valid[0], valid[1])


def _safe_fallback(result: AnalysisResult) -> AnalysisResult:
    # 缺少第二模型共識時最多標為高度風險，不自動移至垃圾桶。
    return result.model_copy(
        update={
            "risk_score": min(result.risk_score, 84),
            "signals": [*result.signals, "另一個模型無法使用，已停用自動清理"],
            "explanation_zh": f"{result.explanation_zh} 目前僅有單一模型結果，不會自動清理。",
        }
    )


def _merge(slm: AnalysisResult, gemini: AnalysisResult) -> AnalysisResult:
    both_explicit = all(
        result.category in MALICIOUS_CATEGORIES and result.risk_score >= 85
        for result in (slm, gemini)
    )
    average_score = round(slm.risk_score * 0.2 + gemini.risk_score * 0.8)

    risk_score = average_score

    category = max(
        (slm.category, gemini.category),
        key=lambda item: CATEGORY_PRIORITY[item],
    )
    return AnalysisResult(
        category=category,
        risk_score=risk_score,
        confidence=(slm.confidence + gemini.confidence) / 2,
        signals=[
            *[f"SLM：{signal}" for signal in slm.signals],
            *[f"Gemini：{signal}" for signal in gemini.signals],
            "雙模型明確惡意共識" if both_explicit else "未達雙模型自動清理共識",
        ],
        explanation_zh=(
            f"SLM 判定 {slm.category.value}（{slm.risk_score} 分）；"
            f"Gemini 判定 {gemini.category.value}（{gemini.risk_score} 分）。"
            f"合併後為 {risk_score} 分。"
        ),
    )
