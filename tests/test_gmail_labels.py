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
        return FakeResponse({"labels": [{"id": "label-1", "name": "AI-不確定"}]})

    async def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return FakeResponse()


class GmailLabelTests(unittest.IsolatedAsyncioTestCase):
    async def test_uncertain_mail_is_labeled_without_moving_to_trash(self):
        client = FakeClient()
        decision = ProtectionDecision(
            level=RiskLevel.UNCERTAIN,
            action=RecommendedAction.WARN,
            color="yellow",
            warning="test",
            links_enabled=True,
            attachments_enabled=True,
        )
        with patch("mail_guard.email.gmail.httpx.AsyncClient", return_value=client):
            await GmailConnector("token").apply_decision(
                NormalizedEmail(message_id="message-1"), decision
            )

        self.assertEqual(len(client.posts), 1)
        self.assertTrue(client.posts[0][0].endswith("/message-1/modify"))
        self.assertEqual(client.posts[0][1]["json"], {"addLabelIds": ["label-1"]})


if __name__ == "__main__":
    unittest.main()
