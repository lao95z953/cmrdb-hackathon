import unittest
from unittest.mock import patch

from mail_guard.background import BackgroundProtection
from mail_guard.models import NormalizedEmail


class FakeOAuth:
    def __init__(self) -> None:
        self.background_enabled = True
        self.background_session_id = "session"
        self.background_seen_ids = ["old"]

    async def access_token_for(self, session_id: str) -> str:
        return "token"

    def remember_seen(self, message_ids: list[str]) -> None:
        self.background_seen_ids = list(
            dict.fromkeys([*message_ids, *self.background_seen_ids])
        )


class FakeConnector:
    applied: list[str] = []

    def __init__(self, access_token: str) -> None:
        self.access_token = access_token

    async def list_inbox(self, limit: int):
        return [
            NormalizedEmail(message_id="new"),
            NormalizedEmail(message_id="old"),
        ]

    async def apply_decision(self, email, decision) -> None:
        self.applied.append(email.message_id)


class FakeService:
    def __init__(self) -> None:
        self.processed: list[str] = []

    async def protect(self, email):
        self.processed.append(email.message_id)
        return type("Result", (), {"decision": object()})()


class BackgroundProtectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_processes_new_messages_once(self) -> None:
        oauth = FakeOAuth()
        service = FakeService()
        worker = BackgroundProtection(oauth, service)
        FakeConnector.applied = []

        with patch("mail_guard.background.GmailConnector", FakeConnector):
            first_count = await worker.run_once()
            second_count = await worker.run_once()

        self.assertEqual(first_count, 1)
        self.assertEqual(second_count, 0)
        self.assertEqual(service.processed, ["new"])
        self.assertEqual(FakeConnector.applied, ["new"])


if __name__ == "__main__":
    unittest.main()
