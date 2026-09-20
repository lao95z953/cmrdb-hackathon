import unittest
from unittest.mock import patch

from mail_guard.email.gmail import GmailConnector
from mail_guard.models import (
    NormalizedEmail,
    ProtectionDecision,
    RecommendedAction,
    RiskLevel,
)


class FakeResponse:
    def __init__(self, data=None):
        self.data = data or {}

    def json(self):
        return self.data

    def raise_for_status(self):
        return None


class FakeClient:
    def __init__(self):
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, **kwargs):
        return FakeResponse({"labels": [{"id": "label-1", "name": "AI-明確垃圾"}]})

    async def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return FakeResponse()


class GmailCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_blocked_mail_is_labeled_then_moved_to_trash(self):
        client = FakeClient()
        decision = ProtectionDecision(
            level=RiskLevel.BLOCKED,
            action=RecommendedAction.QUARANTINE,
            color="red",
            warning="test",
            links_enabled=False,
            attachments_enabled=False,
        )
        with patch("mail_guard.email.gmail.httpx.AsyncClient", return_value=client):
            await GmailConnector("token").apply_decision(
                NormalizedEmail(message_id="message-1"), decision
            )

        self.assertTrue(client.posts[0][0].endswith("/message-1/modify"))
        self.assertEqual(client.posts[0][1]["json"], {"addLabelIds": ["label-1"]})
        self.assertTrue(client.posts[1][0].endswith("/message-1/trash"))


if __name__ == "__main__":
    unittest.main()
