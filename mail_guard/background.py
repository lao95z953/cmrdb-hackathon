from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from datetime import datetime, timezone

from .email.gmail import GmailConnector
from .google_oauth import GoogleOAuth
from .service import MailProtectionService


class BackgroundProtection:
    """定期分析尚未處理的收件匣郵件，不影響手動掃描流程。"""

    def __init__(self, oauth: GoogleOAuth, service: MailProtectionService) -> None:
        self.oauth = oauth
        self.service = service
        self.interval_seconds = max(30, int(os.getenv("BACKGROUND_SCAN_SECONDS", "300")))
        self.scan_limit = min(50, max(1, int(os.getenv("BACKGROUND_SCAN_LIMIT", "20"))))
        self.last_run: str | None = None
        self.last_error: str | None = None
        self.last_processed = 0
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="mailguard-background")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    def wake(self) -> None:
        self._wake.set()

    def status(self) -> dict[str, object]:
        return {
            "enabled": self.oauth.background_enabled,
            "interval_seconds": self.interval_seconds,
            "last_run": self.last_run,
            "last_error": self.last_error,
            "last_processed": self.last_processed,
        }

    async def run_once(self) -> int:
        session_id = self.oauth.background_session_id
        if not self.oauth.background_enabled or not session_id:
            return 0
        access_token = await self.oauth.access_token_for(session_id)
        if not access_token:
            raise RuntimeError("Gmail 登入已失效，請重新登入")

        connector = GmailConnector(access_token)
        emails = await connector.list_inbox(self.scan_limit)
        seen = set(self.oauth.background_seen_ids)
        new_emails = [email for email in emails if email.message_id not in seen]
        processed_ids: list[str] = []
        for email in reversed(new_emails):
            result = await self.service.protect(email)
            await connector.apply_decision(email, result.decision)
            processed_ids.append(email.message_id)
        self.oauth.remember_seen([email.message_id for email in emails])
        return len(processed_ids)

    async def _run(self) -> None:
        while True:
            if self.oauth.background_enabled:
                try:
                    self.last_processed = await self.run_once()
                    self.last_error = None
                    self.last_run = datetime.now(timezone.utc).isoformat()
                except Exception as exc:
                    self.last_error = f"{type(exc).__name__}: {exc}"
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                pass
