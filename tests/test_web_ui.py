import unittest

from fastapi.testclient import TestClient

from mail_guard.api import app


class WebUITests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_home_is_simple_chinese_interface(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("智慧郵件防護", response.text)
        self.assertIn("驗證 Gmail", response.text)
        self.assertIn("開始掃描", response.text)
        self.assertIn("模型不確定", response.text)
        self.assertIn("本機 SLM 郵件風險偵測", response.text)
        self.assertIn("信任 ${(item.analysis.confidence*100).toFixed(0)}%", response.text)
        self.assertIn("智慧郵件背景防護", response.text)
        self.assertIn('id="backgroundToggle"', response.text)

    def test_session_is_disconnected_without_cookie(self):
        response = self.client.get("/api/session/status")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["connected"])
        self.assertEqual(response.json()["analyzer"], "SLMDetector")


if __name__ == "__main__":
    unittest.main()
