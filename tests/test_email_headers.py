import unittest

from mail_guard.email.gmail import _normalize_message
from mail_guard.email_headers import extract_email_headers, normalize_headers


RAW_HEADERS = [
    {"name": "Date", "value": "Sat, 20 Sep 2026 12:00:00 +0800"},
    {"name": "Message-ID", "value": "<message@example.com>"},
    {"name": "MIME-Version", "value": "1.0"},
    {"name": "Received", "value": "from first.example"},
    {"name": "received", "value": "from second.example"},
]


class EmailHeaderTests(unittest.TestCase):
    def test_normalization_keeps_repeated_headers(self) -> None:
        headers = normalize_headers(RAW_HEADERS)
        self.assertEqual(
            headers["received"],
            ["from first.example", "from second.example"],
        )

    def test_extracts_only_supported_technical_headers(self) -> None:
        headers = extract_email_headers([*RAW_HEADERS, {"name": "X-Secret", "value": "hidden"}])
        self.assertEqual(headers.rfc_message_id, "<message@example.com>")
        self.assertEqual(headers.mime_version, "1.0")
        self.assertEqual(len(headers.received), 2)
        self.assertNotIn("X-Secret", headers.model_dump_json())

    def test_gmail_normalization_attaches_headers(self) -> None:
        email = _normalize_message(
            {
                "id": "gmail-1",
                "payload": {"headers": RAW_HEADERS},
                "snippet": "test",
            }
        )
        self.assertEqual(email.headers.date, "Sat, 20 Sep 2026 12:00:00 +0800")
        self.assertEqual(email.headers.received[-1], "from second.example")


if __name__ == "__main__":
    unittest.main()
