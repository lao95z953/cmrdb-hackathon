from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EmailHeaders(BaseModel):
    """供分析器使用的標準化技術標頭。"""

    model_config = ConfigDict(title="郵件標頭資訊")

    date: str | None = Field(default=None, title="寄送日期")
    rfc_message_id: str | None = Field(default=None, title="RFC Message-ID")
    mime_version: str | None = Field(default=None, title="MIME-Version")
    received: list[str] = Field(default_factory=list, title="郵件傳遞路徑")


def normalize_headers(
    raw_headers: Iterable[Mapping[str, Any]],
) -> dict[str, list[str]]:
    """將 Gmail Header 清單轉為不分大小寫且保留重複值的對照表。"""
    headers: defaultdict[str, list[str]] = defaultdict(list)
    for header in raw_headers:
        name = str(header.get("name") or "").strip().lower()
        value = str(header.get("value") or "").strip()
        if name and value:
            headers[name].append(value)
    return dict(headers)


def first_header(headers: Mapping[str, list[str]], name: str) -> str | None:
    values = headers.get(name.lower(), [])
    return values[0] if values else None


def all_headers(headers: Mapping[str, list[str]], name: str) -> list[str]:
    return list(headers.get(name.lower(), []))


def extract_email_headers(
    raw_headers: Iterable[Mapping[str, Any]],
) -> EmailHeaders:
    """擷取安全分析需要的標頭，不保留無關或可能含敏感資訊的欄位。"""
    headers = normalize_headers(raw_headers)
    return EmailHeaders(
        date=first_header(headers, "date"),
        rfc_message_id=first_header(headers, "message-id"),
        mime_version=first_header(headers, "mime-version"),
        received=all_headers(headers, "received"),
    )
