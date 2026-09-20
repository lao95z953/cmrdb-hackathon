from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Any

from ..models import AnalysisResult, EmailCategory, NormalizedEmail


DEFAULT_MODEL = "songhieng/chn-roberta-phishing-content-detector-1.0"
DEFAULT_PHISHING_LABEL = "LABEL_1"

Classifier = Callable[..., Any]


class SLMDetector:
    """使用本機二元文字分類模型判斷郵件是否為 phishing。"""

    def __init__(
        self,
        model: str | None = None,
        *,
        classifier: Classifier | None = None,
        max_chars: int | None = None,
        min_confidence: float | None = None,
        max_segments: int | None = None,
        phishing_label: str | None = None,
    ) -> None:
        self.model = model or os.getenv("SLM_MODEL", DEFAULT_MODEL)
        self.max_chars = max_chars or int(os.getenv("SLM_MAX_CHARS", "6000"))
        self.min_confidence = (
            min_confidence
            if min_confidence is not None
            else float(os.getenv("SLM_MIN_CONFIDENCE", "0.75"))
        )
        self.max_segments = max_segments or int(os.getenv("SLM_MAX_SEGMENTS", "8"))
        self.phishing_label = phishing_label or os.getenv(
            "SLM_PHISHING_LABEL", DEFAULT_PHISHING_LABEL
        )
        if not 0.5 <= self.min_confidence <= 1:
            raise ValueError("SLM_MIN_CONFIDENCE 必須介於 0.5 與 1.0")
        if self.max_segments < 1:
            raise ValueError("SLM_MAX_SEGMENTS 必須至少為 1")
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

            self._classifier = pipeline(
                task="text-classification",
                model=self.model,
                tokenizer=self.model,
                device=-1,
            )
        return self._classifier

    async def analyze(self, email: NormalizedEmail) -> AnalysisResult:
        classifier = self._get_classifier()
        segments = self._build_segments(email, classifier)
        outputs = await asyncio.to_thread(
            classifier,
            segments,
            truncation=True,
            max_length=512,
            top_k=None,
        )
        phishing_probability, segment_number = self._phishing_probability(outputs)
        return self._to_result(
            phishing_probability,
            segment_number=segment_number,
            segment_count=len(segments),
        )

    @staticmethod
    def _format_context(email: NormalizedEmail) -> str:
        """附加模型可直接辨識的文字，不加入未見於訓練資料的欄位名稱。"""
        values = [email.subject, *email.links[:10], *email.attachment_names[:10]]
        return "\n".join(value for value in values if value)

    @classmethod
    def _format_email(cls, email: NormalizedEmail) -> str:
        """無 tokenizer 的測試替身使用單段輸入；本文放在主旨之前。"""
        return "\n".join(
            value for value in (email.body_text, cls._format_context(email)) if value
        )

    def _build_segments(
        self, email: NormalizedEmail, classifier: Classifier
    ) -> list[str]:
        tokenizer = getattr(classifier, "tokenizer", None)
        if tokenizer is None:
            return [self._format_email(email)[: self.max_chars]]

        context = self._format_context(email)
        body = email.body_text[: self.max_chars]
        max_length = min(int(getattr(tokenizer, "model_max_length", 512)), 512)
        special_tokens = int(tokenizer.num_special_tokens_to_add(pair=False))
        context_ids = tokenizer(
            context, add_special_tokens=False, truncation=False, verbose=False
        )["input_ids"]
        body_ids = tokenizer(
            body, add_special_tokens=False, truncation=False, verbose=False
        )["input_ids"]

        available = max_length - special_tokens - len(context_ids) - 4
        if available < 32:
            context_ids = context_ids[: max_length // 3]
            context = tokenizer.decode(context_ids, skip_special_tokens=True)
            available = max_length - special_tokens - len(context_ids) - 4
        available = max(32, available)

        if not body_ids:
            return [context]

        overlap = min(64, available // 4)
        step = max(1, available - overlap)
        starts = list(range(0, len(body_ids), step))
        if len(starts) > self.max_segments:
            starts = [*starts[: self.max_segments - 1], starts[-1]]

        segments = []
        for start in starts:
            chunk = tokenizer.decode(
                body_ids[start : start + available], skip_special_tokens=True
            )
            segments.append("\n".join(value for value in (chunk, context) if value))
        return segments

    def _phishing_probability(self, outputs: Any) -> tuple[float, int]:
        if isinstance(outputs, dict):
            per_segment = [[outputs]]
        elif outputs and isinstance(outputs[0], dict):
            per_segment = [outputs]
        else:
            per_segment = outputs

        if not per_segment:
            raise RuntimeError("SLM 未回傳有效的分類結果")

        probabilities: list[float] = []
        for segment in per_segment:
            match = next(
                (
                    item
                    for item in segment
                    if str(item.get("label", "")).casefold()
                    == self.phishing_label.casefold()
                ),
                None,
            )
            if match is None:
                raise RuntimeError(
                    f"SLM 輸出缺少 phishing label：{self.phishing_label}"
                )
            probabilities.append(max(0.0, min(float(match["score"]), 1.0)))

        highest = max(range(len(probabilities)), key=probabilities.__getitem__)
        return probabilities[highest], highest + 1

    def _to_result(
        self,
        phishing_probability: float,
        *,
        segment_number: int = 1,
        segment_count: int = 1,
    ) -> AnalysisResult:
        risk_score = round(phishing_probability * 100)
        predicted_phishing = phishing_probability >= 0.5
        confidence = (
            phishing_probability if predicted_phishing else 1 - phishing_probability
        )

        if confidence < self.min_confidence:
            category = EmailCategory.UNCERTAIN
        elif predicted_phishing:
            category = EmailCategory.PHISHING
        else:
            category = EmailCategory.SAFE

        signals = [
            f"SLM phishing 機率：{phishing_probability:.1%}",
            f"分類信任度：{confidence:.1%}",
        ]
        if segment_count > 1:
            signals.append(
                f"共分析 {segment_count} 段，第 {segment_number} 段風險最高"
            )
        if category is EmailCategory.UNCERTAIN:
            signals.append(
                f"信任度低於不確定門檻 {self.min_confidence:.0%}"
            )

        return AnalysisResult(
            category=category,
            risk_score=risk_score,
            confidence=confidence,
            signals=signals,
            explanation_zh=(
                f"本機 SLM 將郵件判定為「{category.value}」，"
                f"phishing 風險分數為 {risk_score}，分類信任度為 {confidence:.1%}。"
            ),
        )
