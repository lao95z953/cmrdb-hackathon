from __future__ import annotations

import os
import json
import secrets
import time
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx


AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
STATE_PATH = Path(__file__).resolve().parent.parent / ".mailguard_state.bin"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[_DataBlob, object]:
    buffer = ctypes.create_string_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("持久化背景防護目前僅支援 Windows")
    source, source_buffer = _blob(data)
    result = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "MailGuard", None, None, None, 0, ctypes.byref(result)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(result.pbData)


def _unprotect(data: bytes) -> bytes:
    source, source_buffer = _blob(data)
    result = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(result)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(result.pbData)


@dataclass
class GoogleTokens:
    access_token: str
    refresh_token: str | None
    expires_at: float


class GoogleOAuth:
    """Google OAuth flow with Windows-user-encrypted local persistence."""

    def __init__(self, state_path: Path = STATE_PATH) -> None:
        self.client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        self.client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
        self.redirect_uri = os.getenv(
            "GOOGLE_REDIRECT_URI",
            "http://127.0.0.1:8000/auth/google/callback",
        )
        self.state_path = state_path
        self._tokens: dict[str, GoogleTokens] = {}
        self.background_session_id: str | None = None
        self.background_enabled = False
        self.background_seen_ids: list[str] = []
        self._load_state()

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri)

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": GMAIL_SCOPE,
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "consent",
            "state": state,
        }
        return f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> GoogleTokens:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                TOKEN_ENDPOINT,
                data={
                    "code": code,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            response.raise_for_status()
            data = response.json()
        return GoogleTokens(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=time.time() + int(data.get("expires_in", 3600)) - 60,
        )

    def create_session(self, tokens: GoogleTokens) -> str:
        session_id = secrets.token_urlsafe(32)
        self._tokens[session_id] = tokens
        self._save_state()
        return session_id

    async def access_token_for(self, session_id: str) -> str | None:
        tokens = self._tokens.get(session_id)
        if not tokens:
            return None
        if time.time() < tokens.expires_at:
            return tokens.access_token
        if not tokens.refresh_token:
            self._tokens.pop(session_id, None)
            return None

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                TOKEN_ENDPOINT,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": tokens.refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            response.raise_for_status()
            data = response.json()
        tokens.access_token = data["access_token"]
        tokens.expires_at = time.time() + int(data.get("expires_in", 3600)) - 60
        self._save_state()
        return tokens.access_token

    def delete_session(self, session_id: str) -> None:
        self._tokens.pop(session_id, None)
        if self.background_session_id == session_id:
            self.background_session_id = None
            self.background_enabled = False
            self.background_seen_ids = []
        self._save_state()

    def set_background(self, session_id: str, enabled: bool) -> None:
        if enabled and session_id not in self._tokens:
            raise ValueError("Gmail 登入工作階段不存在")
        self.background_enabled = enabled
        self.background_session_id = session_id if enabled else None
        if not enabled:
            self.background_seen_ids = []
        self._save_state()

    def remember_seen(self, message_ids: list[str]) -> None:
        combined = list(dict.fromkeys([*message_ids, *self.background_seen_ids]))
        self.background_seen_ids = combined[:500]
        self._save_state()

    def _save_state(self) -> None:
        data = {
            "tokens": {
                session_id: {
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "expires_at": tokens.expires_at,
                }
                for session_id, tokens in self._tokens.items()
            },
            "background_session_id": self.background_session_id,
            "background_enabled": self.background_enabled,
            "background_seen_ids": self.background_seen_ids,
        }
        encrypted = _protect(json.dumps(data).encode("utf-8"))
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_bytes(encrypted)
        temporary.replace(self.state_path)

    def _load_state(self) -> None:
        if not self.state_path.exists():
            return
        try:
            data = json.loads(_unprotect(self.state_path.read_bytes()).decode("utf-8"))
            self._tokens = {
                session_id: GoogleTokens(**values)
                for session_id, values in data.get("tokens", {}).items()
            }
            self.background_session_id = data.get("background_session_id")
            self.background_enabled = bool(data.get("background_enabled"))
            self.background_seen_ids = list(data.get("background_seen_ids", []))[:500]
            if self.background_session_id not in self._tokens:
                self.background_enabled = False
                self.background_session_id = None
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self._tokens = {}
            self.background_session_id = None
            self.background_enabled = False
            self.background_seen_ids = []
