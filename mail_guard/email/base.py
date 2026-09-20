from typing import Protocol

from ..models import NormalizedEmail, ProtectionDecision


class EmailConnector(Protocol):
    async def list_inbox(self, limit: int = 10) -> list[NormalizedEmail]: ...

    async def apply_decision(self, email: NormalizedEmail, decision: ProtectionDecision) -> None: ...

