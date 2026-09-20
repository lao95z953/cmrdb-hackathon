import os

from .base import EmailAnalyzer
from .local_rules import LocalRuleAnalyzer


def create_analyzer() -> EmailAnalyzer:
    backend = os.getenv("ANALYZER_BACKEND", "auto").strip().lower()
    if backend == "hybrid":
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if not gemini_api_key:
            raise ValueError("ANALYZER_BACKEND=hybrid 時必須設定 GEMINI_API_KEY")

        from .gemini_analyzer import GeminiEmailAnalyzer
        from .hybrid_analyzer import HybridEmailAnalyzer
        from .slm_detector import SLMDetector

        return HybridEmailAnalyzer(
            slm=SLMDetector(),
            gemini=GeminiEmailAnalyzer(api_key=gemini_api_key),
        )
    if backend == "gemini":
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if not gemini_api_key:
            raise ValueError("ANALYZER_BACKEND=gemini 時必須設定 GEMINI_API_KEY")
        from .gemini_analyzer import GeminiEmailAnalyzer

        return GeminiEmailAnalyzer(api_key=gemini_api_key)
    if backend == "slm":
        from .slm_detector import SLMDetector

        return SLMDetector()
    if backend == "local":
        return LocalRuleAnalyzer()
    if backend not in {"auto", "openai"}:
        raise ValueError(
            "ANALYZER_BACKEND 必須是 auto、openai、gemini、slm、hybrid 或 local"
        )

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        if backend == "openai":
            raise ValueError("ANALYZER_BACKEND=openai 時必須設定 OPENAI_API_KEY")
        return LocalRuleAnalyzer()

    # 延後載入 SDK，讓無金鑰展示模式也能清楚運作。
    from .openai_analyzer import OpenAIEmailAnalyzer

    return OpenAIEmailAnalyzer(api_key=api_key)
