import unittest

from mail_guard.api import app


class ChineseOpenAPITests(unittest.TestCase):
    def test_all_operations_have_chinese_summaries(self) -> None:
        schema = app.openapi()
        expected = {
            ("/health", "get"): "檢查系統狀態",
            ("/auth/google/start", "get"): "登入 Google 帳戶",
            ("/auth/google/callback", "get"): "接收 Google 授權結果",
            ("/auth/google/logout", "post"): "登出 Google 帳戶",
            ("/api/analyze", "post"): "分析單封郵件",
            ("/api/gmail/scan", "post"): "使用存取權杖掃描 Gmail",
            ("/api/gmail/scan-connected", "post"): "掃描已登入的 Gmail",
        }

        for (path, method), summary in expected.items():
            self.assertEqual(schema["paths"][path][method]["summary"], summary)

    def test_request_schema_uses_chinese_field_titles(self) -> None:
        schema = app.openapi()
        email_schema = schema["components"]["schemas"]["NormalizedEmail"]
        self.assertEqual(email_schema["title"], "標準化郵件")
        self.assertEqual(email_schema["properties"]["subject"]["title"], "郵件主旨")


if __name__ == "__main__":
    unittest.main()
