from __future__ import annotations

import base64
import re
from email.header import decode_header, make_header
from typing import Any

import httpx

from ..email_headers import extract_email_headers, first_header, normalize_headers
from ..models import EmailAuthentication, NormalizedEmail, ProtectionDecision, RiskLevel


GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class GmailConnector:
    """只處理 Gmail I/O，不包含任何 AI 判斷。"""

    def __init__(self, access_token: str) -> None:
        self.headers = {"Authorization": f"Bearer {access_token}"}

    async def list_inbox(self, limit: int = 10) -> list[NormalizedEmail]:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(
                f"{GMAIL_API}/messages",
                headers=self.headers,
                params={"q": "in:inbox", "maxResults": min(limit, 50)},
            )
            response.raise_for_status()
            refs = response.json().get("messages", [])

            emails: list[NormalizedEmail] = []
            for ref in refs:
                item = await client.get(
                    f"{GMAIL_API}/messages/{ref['id']}",
                    headers=self.headers,
                    params={"format": "full"},
                )
                item.raise_for_status()
                emails.append(_normalize_message(item.json()))
            return emails

    async def apply_decision(
        self, email: NormalizedEmail, decision: ProtectionDecision
    ) -> None:
        if decision.level is RiskLevel.LOW:
            return

        label_name = {
            RiskLevel.UNCERTAIN: "AI-不確定",
            RiskLevel.MEDIUM: "AI-中度風險",
            RiskLevel.HIGH: "AI-高度風險",
        }[decision.level]

        async with httpx.AsyncClient(timeout=30) as client:
            label_id = await self._get_or_create_label(client, label_name)
            body: dict[str, list[str]] = {"addLabelIds": [label_id]}
            response = await client.post(
                f"{GMAIL_API}/messages/{email.message_id}/modify",
                headers=self.headers,
                json=body,
            )
            response.raise_for_status()

    async def _get_or_create_label(self, client: httpx.AsyncClient, name: str) -> str:
        response = await client.get(f"{GMAIL_API}/labels", headers=self.headers)
        response.raise_for_status()
        for label in response.json().get("labels", []):
            if label.get("name") == name:
                return label["id"]

        response = await client.post(
            f"{GMAIL_API}/labels",
            headers=self.headers,
            json={
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        )
        response.raise_for_status()
        return response.json()["id"]


def _normalize_message(message: dict[str, Any]) -> NormalizedEmail:
    payload = message.get("payload", {})
    raw_headers = [
        {"name": header.get("name", ""), "value": _decode_header(header.get("value", ""))}
        for header in payload.get("headers", [])
    ]
    headers = normalize_headers(raw_headers)
    body, attachments = _walk_parts(payload)

    return NormalizedEmail(
        provider="gmail",
        message_id=message["id"],
        thread_id=message.get("threadId"),
        sender=first_header(headers, "from") or "",
        reply_to=first_header(headers, "reply-to"),
        recipients=[first_header(headers, "to")] if first_header(headers, "to") else [],
        subject=first_header(headers, "subject") or "",
        body_text=body or message.get("snippet", ""),
        links=list(dict.fromkeys(URL_PATTERN.findall(body))),
        attachment_names=attachments,
        authentication=_parse_authentication(
            first_header(headers, "authentication-results") or ""
        ),
        headers=extract_email_headers(raw_headers),
    )


def _walk_parts(part: dict[str, Any]) -> tuple[str, list[str]]:
    texts: list[str] = []
    attachments: list[str] = []

    def walk(node: dict[str, Any]) -> None:
        filename = node.get("filename")
        if filename:
            attachments.append(filename)
        if node.get("mimeType") == "text/plain":
            data = node.get("body", {}).get("data")
            if data:
                texts.append(_decode_base64url(data))
        for child in node.get("parts", []):
            walk(child)

    walk(part)
    return "\n".join(texts), attachments


def _decode_base64url(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _decode_header(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeDecodeError):
        return value


def _parse_authentication(value: str) -> EmailAuthentication:
    lowered = value.lower()

    def status(name: str) -> str | None:
        match = re.search(rf"\b{name}\s*=\s*(pass|fail|neutral|none|softfail)", lowered)
        return match.group(1) if match else None

    return EmailAuthentication(spf=status("spf"), dkim=status("dkim"), dmarc=status("dmarc"))
