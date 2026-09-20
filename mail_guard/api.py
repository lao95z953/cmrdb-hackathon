import secrets
from pathlib import Path

import httpx
from fastapi import Cookie, FastAPI, Header, HTTPException, Query
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from .ai import create_analyzer
from .background import BackgroundProtection
from .email import GmailConnector
from .google_oauth import GoogleOAuth
from .models import NormalizedEmail, ProtectedEmail
from .service import MailProtectionService


load_dotenv()


app = FastAPI(
    title="智慧郵件防護 API",
    summary="使用 AI 與規則引擎偵測郵件風險",
    description=(
        "分析郵件內容、掃描 Gmail 收件匣，並依風險分數提供警告、限制或隔離建議。"
        "所有隔離操作皆可復原，不會永久刪除郵件。"
    ),
    version="0.1.0",
    openapi_tags=[
        {"name": "系統狀態", "description": "確認服務及分析器是否可用。"},
        {"name": "Google 帳戶", "description": "Gmail OAuth 登入、回呼與登出。"},
        {"name": "郵件分析", "description": "分析單封郵件或批次掃描 Gmail。"},
    ],
)
service = MailProtectionService(create_analyzer())
google_oauth = GoogleOAuth()
background_protection = BackgroundProtection(google_oauth, service)
UI_PATH = Path(__file__).parent / "index.html"


class GmailScanRequest(BaseModel):
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        title="掃描封數",
        description="本次最多掃描的收件匣郵件數量（1 至 50 封）。",
    )


class BackgroundSetting(BaseModel):
    enabled: bool = Field(title="是否啟用智慧郵件背景防護")


@app.on_event("startup")
async def start_background_protection() -> None:
    background_protection.start()


@app.on_event("shutdown")
async def stop_background_protection() -> None:
    await background_protection.stop()


@app.get("/", include_in_schema=False, response_class=FileResponse)
async def home() -> FileResponse:
    return FileResponse(UI_PATH)


@app.get("/api/session/status", include_in_schema=False)
async def session_status(
    mailguard_session: str | None = Cookie(default=None),
) -> dict[str, object]:
    connected = False
    if mailguard_session:
        try:
            connected = bool(await google_oauth.access_token_for(mailguard_session))
        except httpx.HTTPError:
            connected = False
    return {
        "configured": google_oauth.configured,
        "connected": connected,
        "analyzer": type(service.analyzer).__name__,
        "background": background_protection.status(),
    }


@app.put("/api/background", include_in_schema=False)
async def update_background_setting(
    setting: BackgroundSetting,
    mailguard_session: str | None = Cookie(default=None),
) -> dict[str, object]:
    if setting.enabled:
        if not mailguard_session or not await google_oauth.access_token_for(mailguard_session):
            raise HTTPException(status_code=401, detail="請先登入 Gmail 再啟用背景防護")
        google_oauth.set_background(mailguard_session, True)
        background_protection.wake()
    else:
        if google_oauth.background_session_id:
            google_oauth.set_background(google_oauth.background_session_id, False)
        background_protection.wake()
    return background_protection.status()


@app.get(
    "/health",
    tags=["系統狀態"],
    summary="檢查系統狀態",
    description="顯示目前使用的分析器，以及 Google OAuth 是否完成設定。",
)
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "analyzer": type(service.analyzer).__name__,
        "google_oauth": "configured" if google_oauth.configured else "not_configured",
    }


@app.get(
    "/auth/google/start",
    tags=["Google 帳戶"],
    summary="登入 Google 帳戶",
    description="前往 Google 授權頁面，允許系統讀取及標記 Gmail 郵件。",
)
async def google_login() -> RedirectResponse:
    if not google_oauth.configured:
        raise HTTPException(
            status_code=503,
            detail="請先在 .env 設定 GOOGLE_CLIENT_ID 與 GOOGLE_CLIENT_SECRET",
        )
    state = secrets.token_urlsafe(32)
    response = RedirectResponse(google_oauth.authorization_url(state))
    response.set_cookie(
        "mailguard_oauth_state",
        state,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=600,
    )
    return response


@app.get(
    "/auth/google/callback",
    response_class=HTMLResponse,
    tags=["Google 帳戶"],
    summary="接收 Google 授權結果",
    description="由 Google 授權頁面自動呼叫，一般使用者不需要手動執行。",
)
async def google_callback(
    code: str | None = Query(default=None, description="Google 授權碼。"),
    state: str | None = Query(default=None, description="防止跨站請求偽造的隨機狀態值。"),
    error: str | None = Query(default=None, description="Google 回傳的授權錯誤。"),
    mailguard_oauth_state: str | None = Cookie(
        default=None,
        description="登入開始時建立的 OAuth 狀態 Cookie。",
    ),
) -> HTMLResponse:
    if error:
        raise HTTPException(status_code=400, detail=f"Google 授權失敗：{error}")
    if not code or not state or not mailguard_oauth_state:
        raise HTTPException(status_code=400, detail="Google OAuth 回呼缺少必要參數")
    if not secrets.compare_digest(state, mailguard_oauth_state):
        raise HTTPException(status_code=400, detail="Google OAuth state 驗證失敗")

    try:
        tokens = await google_oauth.exchange_code(code)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="無法向 Google 交換 Token") from exc

    session_id = google_oauth.create_session(tokens)
    response = HTMLResponse(
        """
        <!doctype html><html lang="zh-Hant"><meta charset="utf-8">
        <title>MailGuard 登入成功</title>
        <body style="font-family:sans-serif;max-width:680px;margin:60px auto">
        <h1>Gmail 連接成功</h1>
        <p>授權已完成，現在可以回到防護中心掃描郵件。</p>
        <p><a href="/">開啟智慧郵件防護</a></p>
        </body></html>
        """
    )
    response.delete_cookie("mailguard_oauth_state")
    response.set_cookie(
        "mailguard_session",
        session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=86_400,
    )
    return response


@app.post(
    "/auth/google/logout",
    tags=["Google 帳戶"],
    summary="登出 Google 帳戶",
    description="清除伺服器記憶體中的 Gmail 登入工作階段。",
)
async def google_logout(
    mailguard_session: str | None = Cookie(
        default=None,
        description="Gmail 登入工作階段 Cookie。",
    ),
) -> dict[str, str]:
    if mailguard_session:
        google_oauth.delete_session(mailguard_session)
    return {"status": "logged_out"}


@app.post(
    "/api/analyze",
    response_model=ProtectedEmail,
    tags=["郵件分析"],
    summary="分析單封郵件",
    description="接收標準化郵件內容，回傳 AI 分析、風險分數與建議防護動作。",
)
async def analyze_email(email: NormalizedEmail) -> ProtectedEmail:
    """Android 或其他郵件連接器都可以直接呼叫的 AI 分析端點。"""
    return await service.protect(email)


@app.post(
    "/api/gmail/scan",
    response_model=list[ProtectedEmail],
    tags=["郵件分析"],
    summary="使用存取權杖掃描 Gmail",
    description="使用請求標頭中的 Gmail 存取權杖，掃描並標記收件匣郵件。",
)
async def scan_gmail(
    request: GmailScanRequest,
    x_gmail_access_token: str | None = Header(
        default=None,
        description="Google OAuth 提供的 Gmail 存取權杖。",
    ),
) -> list[ProtectedEmail]:
    """黑客松原型：正式環境應改用後端加密 token vault。"""
    if not x_gmail_access_token:
        raise HTTPException(status_code=401, detail="缺少 X-Gmail-Access-Token")
    connector = GmailConnector(x_gmail_access_token)
    try:
        return await service.scan_connector(connector, request.max_results)
    except Exception as exc:
        # 不把 Gmail access token 或完整遠端回應傳回用戶端。
        raise HTTPException(status_code=502, detail=f"Gmail 掃描失敗：{type(exc).__name__}") from exc


@app.post(
    "/api/gmail/scan-connected",
    response_model=list[ProtectedEmail],
    tags=["郵件分析"],
    summary="掃描已登入的 Gmail",
    description="使用目前瀏覽器的登入工作階段，掃描並標記 Gmail 收件匣。",
)
async def scan_connected_gmail(
    request: GmailScanRequest,
    mailguard_session: str | None = Cookie(
        default=None,
        description="完成 Google 登入後建立的工作階段 Cookie，通常由瀏覽器自動帶入。",
    ),
) -> list[ProtectedEmail]:
    if not mailguard_session:
        raise HTTPException(status_code=401, detail="尚未登入 Gmail")
    try:
        access_token = await google_oauth.access_token_for(mailguard_session)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Google Token 更新失敗") from exc
    if not access_token:
        raise HTTPException(status_code=401, detail="Gmail 登入已過期，請重新登入")

    connector = GmailConnector(access_token)
    try:
        return await service.scan_connector(connector, request.max_results)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gmail 掃描失敗：{type(exc).__name__}") from exc
