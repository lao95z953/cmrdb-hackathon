from typing import Protocol

from ..models import AnalysisResult, NormalizedEmail


class EmailAnalyzer(Protocol):
    async def analyze(self, email: NormalizedEmail) -> AnalysisResult: ...

