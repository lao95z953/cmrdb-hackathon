# 智慧郵件防護系統

這是一個將「郵件連接」與「AI 判斷」分開的黑客松原型。

## 模組分工

```text
Android / Gmail
      ↓
mail_guard/email/       只負責取得、正規化、標記郵件
      ↓ NormalizedEmail
mail_guard/ai/          只負責判斷內容風險
      ↓ AnalysisResult
mail_guard/policy.py    將分數轉成黃／紅色與隔離政策
      ↓
Android UI 或 Gmail 標籤
```

- `mail_guard/email/gmail.py`：Gmail API 連接器。
- `mail_guard/ai/openai_analyzer.py`：OpenAI Responses API 分析器。
- `mail_guard/ai/local_rules.py`：沒有 API Key 時的展示模式。
- `mail_guard/ai/slm_detector.py`：在本機執行小型多語言模型的文字風險偵測器。
- `mail_guard/policy.py`：固定且可測試的風險門檻。
- `mail_guard/service.py`：在應用層串接兩邊。
- `mail_guard/api.py`：提供 Android 可呼叫的 HTTP API。

## 風險政策

| 分數 | 層級 | 處理 |
|---:|---|---|
| 0–29 | 低度 | 正常顯示，不標顏色 |
| 30–59 | 中度 | 黃色提醒 |
| 60–84 | 高度 | 紅色提醒，停用連結與附件 |
| 85–100 | 明確惡意 | 從 Gmail 收件匣移出並加上 `AI-隔離` 標籤 |

系統不會永久刪除郵件，避免誤判後無法復原。

## 啟動

需要 Python 3.11 以上：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python 智慧郵件防護系統.py
```

若要使用 AI，在 `.env` 或系統環境變數設定 `OPENAI_API_KEY`。請勿將金鑰寫進 Android App。

### 使用本機 SLM Detector

SLM 模式不會把郵件內容傳送給 OpenAI。先安裝額外相依套件：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-slm.txt
```

接著在 `.env` 設定：

```env
ANALYZER_BACKEND=slm
SLM_MODEL=MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli
SLM_MAX_CHARS=6000
```

第一次分析時會從 Hugging Face 下載模型並快取；之後可離線執行。`SLM_MODEL`
也可以改成本機模型資料夾。若要切回原本行為，將 `ANALYZER_BACKEND` 設為
`auto`；其他可用值為 `openai` 與 `local`。

### 使用 Gemini＋SLM 雙模型判斷

雙模型模式會同時執行本機 SLM 與 Gemini，只有兩者都判定為明確惡意且分數
達 85，才會把 Gmail 郵件移至垃圾桶；其中一個模型失效或兩者意見不一致時，
最多標記為紅色高度風險，不會自動清理。垃圾桶郵件仍可由使用者復原。

安裝相依套件：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-hybrid.txt
```

在 `.env` 設定：

```env
ANALYZER_BACKEND=hybrid
GEMINI_API_KEY=你的_Gemini_API_Key
GEMINI_MODEL=gemini-3.5-flash-lite
SLM_MODEL=MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli
```

此模式會將郵件主旨、寄件者、本文及安全中繼資料傳送至 Gemini API，請先確認
使用者同意與資料處理規範。API Key 只能放在 `.env`，不得放入 Android App、Git
或聊天訊息。

啟動後開啟：

- API 文件：`http://127.0.0.1:8000/docs`
- 健康檢查：`http://127.0.0.1:8000/health`

## 測試單封郵件

即使沒有 OpenAI 金鑰，也可以使用本機展示模式：

```powershell
$body = @{
  provider = "demo"
  message_id = "demo-1"
  sender = "security@example.net"
  reply_to = "steal@example.org"
  subject = "帳戶即將停用"
  body_text = "請立即登入並點擊連結驗證帳戶"
  links = @("https://suspicious.example.org/login")
  attachment_names = @()
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/analyze `
  -ContentType "application/json" `
  -Body $body
```

## Android 串接方式

Android 將郵件轉成 `NormalizedEmail` JSON 後呼叫：

```http
POST /api/analyze
Content-Type: application/json
```

回傳的 `decision.color` 會是 `null`、`yellow` 或 `red`；Android UI 只負責依結果顯示，不需要包含 AI 程式或 OpenAI 金鑰。

黑客松版本也提供 Gmail 整批掃描：

```http
POST /api/gmail/scan
X-Gmail-Access-Token: <Google OAuth access token>
Content-Type: application/json

{"max_results": 10}
```

Google OAuth 至少需要能讀取及修改郵件／標籤的 Gmail 權限。正式產品不可長期由 Android 傳遞 access token，應改成後端 OAuth callback、加密 token vault，以及你自己的使用者驗證。

## 測試

```powershell
python -m unittest discover -s tests -v
```

OpenAI 實作使用 Responses API、`store=False` 與 JSON Schema Structured Outputs。官方文件：<https://developers.openai.com/api/reference/cli/resources/responses/methods/create>

## Google OAuth 登入

在 `.env` 設定 Google Cloud 網頁應用程式用戶端：

```env
GOOGLE_CLIENT_ID=你的Web用戶端ID
GOOGLE_CLIENT_SECRET=你的Web用戶端密碼
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/auth/google/callback
```

重新啟動後開啟：

```text
http://127.0.0.1:8000/auth/google/start
```

授權完成後，到 `/docs` 呼叫 `POST /api/gmail/scan-connected`。Google Token 會使用
Windows 使用者層級加密後保存在本機；正式產品仍應改用專用的加密資料庫或秘密管理服務。

## 智慧郵件背景防護

登入 Gmail 後，可在首頁開啟「智慧郵件背景防護」。啟用後系統預設每 5 分鐘
檢查一次最新郵件，只分析尚未處理的郵件；手動掃描功能仍可照常使用。

開關、已處理郵件識別碼及 OAuth Token 會儲存在專案根目錄的
`.mailguard_state.bin`。該檔案使用 Windows DPAPI 綁定目前的 Windows 使用者進行
加密，已列入 `.gitignore`，不得傳送給其他人。程式重新啟動後會恢復原本的開關
狀態並繼續執行；若登出 Gmail，背景防護會一併停用。

可在 `.env` 調整執行頻率與每次查看的郵件數量：

```env
BACKGROUND_SCAN_SECONDS=300
BACKGROUND_SCAN_LIMIT=20
```

背景掃描最短間隔為 30 秒，每次最多查看 50 封郵件。
