import os

from .base import EmailAnalyzer
from .local_rules import LocalRuleAnalyzer


def create_analyzer() -> EmailAnalyzer:
    """建立單一分析器；預設只使用本機 SLM，不做模型合併。"""
    backend = os.getenv("ANALYZER_BACKEND", "slm").strip().lower()

    if backend == "slm":
        from .slm_detector import SLMDetector

        return SLMDetector()
    if backend == "local":
        return LocalRuleAnalyzer()
    if backend == "gemini":
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if not gemini_api_key:
            raise ValueError("ANALYZER_BACKEND=gemini 時必須設定 GEMINI_API_KEY")
        from .gemini_analyzer import GeminiEmailAnalyzer

        return GeminiEmailAnalyzer(api_key=gemini_api_key)
    if backend == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("ANALYZER_BACKEND=openai 時必須設定 OPENAI_API_KEY")
        try:
            from .openai_analyzer import OpenAIEmailAnalyzer
        except ImportError as exc:
            raise RuntimeError(
                "OpenAI 模式需要額外套件，請執行 "
                "pip install -r requirements-openai.txt"
            ) from exc

        return OpenAIEmailAnalyzer(api_key=api_key)

    raise ValueError("ANALYZER_BACKEND 必須是 slm、local、openai 或 gemini")
