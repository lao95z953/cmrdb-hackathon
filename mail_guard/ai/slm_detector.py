from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Any

from ..models import AnalysisResult, EmailCategory, NormalizedEmail


DEFAULT_MODEL = "MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli"

# 使用自然語言標籤，讓 NLI 類型的小模型不需另外微調也能分類。
LABEL_TO_CATEGORY = {
    "正常且安全的電子郵件": EmailCategory.SAFE,
    "垃圾廣告或大量行銷郵件": EmailCategory.SPAM,
    "企圖竊取帳號密碼的釣魚郵件": EmailCategory.PHISHING,
    "企圖騙取金錢或個人資料的詐騙郵件": EmailCategory.SCAM,
    "包含惡意程式或危險附件的郵件": EmailCategory.MALWARE,
}

Classifier = Callable[..., dict[str, Any]]


class SLMDetector:
    """以本機小型語言模型進行零樣本郵件風險分類。"""

    def __init__(
        self,
        model: str | None = None,
        *,
        classifier: Classifier | None = None,
        max_chars: int | None = None,
    ) -> None:
        self.model = model or os.getenv("SLM_MODEL", DEFAULT_MODEL)
        self.max_chars = max_chars or int(os.getenv("SLM_MAX_CHARS", "6000"))
        self._classifier = classifier

    def _get_classifier(self) -> Classifier:
        if self._classifier is None:
            try:
                from transformers import pipeline
            except ImportError as exc:
                raise RuntimeError(
                    "SLM 模式需要額外套件，請執行 "
                    "pip install -r requirements-slm.txt"
                ) from exc

            # 首次使用時才載入模型；模型可填 Hugging Face ID 或本機路徑。
            self._classifier = pipeline(
                task="zero-shot-classification",
                model=self.model,
                device=-1,
            )
        return self._classifier

    async def analyze(self, email: NormalizedEmail) -> AnalysisResult:
        text = self._format_email(email)[: self.max_chars]
        output = await asyncio.to_thread(
            self._get_classifier(),
            text,
            candidate_labels=list(LABEL_TO_CATEGORY),
            hypothesis_template="這封郵件是{}。",
            multi_label=False,
        )
        return self._to_result(output)

    @staticmethod
    def _format_email(email: NormalizedEmail) -> str:
        return (
            f"主旨：{email.subject}\n"
            f"寄件者：{email.sender}\n"
            f"內文：{email.body_text}"
        )

    @staticmethod
    def _to_result(output: dict[str, Any]) -> AnalysisResult:
        labels = output.get("labels") or []
        scores = output.get("scores") or []
        if not labels or not scores or labels[0] not in LABEL_TO_CATEGORY:
            raise RuntimeError("SLM 未回傳有效的分類結果")

        label = str(labels[0])
        confidence = max(0.0, min(float(scores[0]), 1.0))
        category = LABEL_TO_CATEGORY[label]

        # 信心過低時保留 uncertain，避免模型被迫猜測後直接隔離郵件。
        if confidence < 0.35:
            category = EmailCategory.UNCERTAIN

        risk_score = _risk_score(category, confidence)
        return AnalysisResult(
            category=category,
            risk_score=risk_score,
            confidence=confidence,
            signals=[f"SLM 分類：{label}", f"模型信心：{confidence:.1%}"],
            explanation_zh=(
                f"本機小型語言模型將郵件判定為「{category.value}」，"
                f"風險分數為 {risk_score}。此結果應搭配寄件者驗證與人工判斷。"
            ),
        )


def _risk_score(category: EmailCategory, confidence: float) -> int:
    if category is EmailCategory.SAFE:
        return round((1 - confidence) * 29)
    if category is EmailCategory.SPAM:
        return round(30 + confidence * 29)
    if category is EmailCategory.UNCERTAIN:
        return 50
    # phishing、scam、malware 都是高風險；只有極高信心才進入自動隔離區間。
    return round(60 + confidence * 40)
