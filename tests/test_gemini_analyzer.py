import unittest

from mail_guard.ai.gemini_analyzer import GeminiEmailAnalyzer
from mail_guard.email_headers import EmailHeaders
from mail_guard.models import EmailCategory, NormalizedEmail


class FakeResponse:
    text = """{
        "category": "phishing",
        "risk_score": 91,
        "confidence": 0.92,
        "signals": ["要求輸入密碼"],
        "explanation_zh": "具有帳號竊取特徵。"
    }"""


class FakeModels:
    def __init__(self):
        self.request = None

    def generate_content(self, **kwargs):
        self.request = kwargs
        return FakeResponse()


class FakeClient:
    def __init__(self):
        self.models = FakeModels()


class GeminiAnalyzerTests(unittest.IsolatedAsyncioTestCase):
    async def test_structured_result_is_validated(self):
        client = FakeClient()
        analyzer = GeminiEmailAnalyzer(api_key="test", client=client)

        result = await analyzer.analyze(
            NormalizedEmail(
                message_id="test",
                subject="立即驗證帳號",
                body_text="請輸入密碼。",
                headers=EmailHeaders(received=["from suspicious.example"]),
            )
        )

        self.assertEqual(result.category, EmailCategory.PHISHING)
        self.assertEqual(result.risk_score, 91)
        config = client.models.request["config"]
        self.assertEqual(config["response_mime_type"], "application/json")
        self.assertIn("response_json_schema", config)
        self.assertIn("from suspicious.example", client.models.request["contents"])
        self.assertIn("Received 傳遞路徑", client.models.request["contents"])


if __name__ == "__main__":
    unittest.main()
