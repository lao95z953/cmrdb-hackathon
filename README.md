# 智慧郵件防護系統

這是黑客松階段的 Gmail 風險分析原型。預設在本機執行單一 SLM，依 phishing 機率與分類信任度套用 Gmail 標籤。系統不再合併多個模型，也不會自動把郵件移至垃圾桶。

目前有 Python 後端和 Web UI，沒有 Android App。分類器尚未經過正式資料集驗證，請使用測試信箱。

## 判斷流程

```text
Gmail
  ↓
郵件正規化、URL 與驗證資訊擷取
  ↓
本機 SLM 二元分類
  ├─ phishing probability → risk score
  └─ winner probability   → confidence
  ↓
confidence gate
  ├─ 低於門檻 → uncertain
  └─ 高於門檻 → 依 risk score 分級
  ↓
Gmail 標籤與 Web UI
```

主要模組：

- `mail_guard/email/gmail.py`：Gmail API 連接器及郵件正規化。
- `mail_guard/email_headers.py`：擷取安全分析需要的郵件標頭。
- `mail_guard/ai/slm_detector.py`：本機 SLM、分段分析及信任度判斷。
- `mail_guard/policy.py`：把模型結果轉成產品動作。
- `mail_guard/service.py`：串接分析器、政策與郵件連接器。
- `mail_guard/api.py`：FastAPI、Google OAuth、Web UI 與 HTTP API。

## SLM 輸出如何轉成決策

二元模型輸出 phishing probability `p`：

```text
risk_score = round(p × 100)
confidence = max(p, 1 - p)
```

如果 `confidence` 低於 `SLM_MIN_CONFIDENCE`，郵件會直接進入 `uncertain`，不再用風險分數強迫分類。預設門檻是 0.75。

| 條件 | 層級 | Gmail／UI 動作 |
|---|---|---|
| confidence < 0.75 | 不確定 | 黃色提醒，加上 `AI-不確定` |
| score 0–29 | 低度 | 正常顯示，不加標籤 |
| score 30–59 | 中度 | 黃色提醒，加上 `AI-中度風險` |
| score 60–100 | 高度 | 紅色提醒，加上 `AI-高度風險` |

高風險只會加標籤。黑客松版本不會永久刪除、移出收件匣或移至垃圾桶。

模型輸出的 softmax 不是經過本專案校準的惡意機率。`99%` 只代表模型輸出，不代表實際有 99% 機率是 phishing。

## 預設模型

```text
songhieng/chn-roberta-phishing-content-detector-1.0
```

模型沒有提供 label mapping，本專案依本機控制案例明確設定：

```env
SLM_PHISHING_LABEL=LABEL_1
```

這是 Demo 設定，不是作者提供的正式定義。模型的測試紀錄與限制位於：

```text
docs/model-smoke-test-chn-roberta.md
```

模型只能處理 512 tokens。`SLMDetector` 會將長郵件切成多段並保留最後一段，避免只分析郵件開頭。每一段依序放入本文、主旨、URL 與附件名稱；整封郵件取 phishing probability 最高的一段。寄件者、Reply-To 及 SPF／DKIM／DMARC 保留在標準化資料中，不混入這個未知訓練格式的文字分類器。

## 安裝與快速啟動

專案目前以 Windows 本機展示為主要環境（Python 3.10+）。

### 方式一：一鍵快速啟動（推薦）

專案內建自動化腳本，會自動處理虛擬環境、安裝 CPU 版 PyTorch、產生 `.env` 並啟動伺服器：

- **Windows 批次檔**：直接雙擊 `run.bat`（或在終端機輸入 `.\run.bat`）
- **PowerShell**：執行 `.\run.ps1`

### 方式二：使用 uv 一鍵執行

若有安裝 `uv`，`pyproject.toml` 已設定好 PyTorch CPU 來源，可直接執行：

```powershell
uv run uvicorn mail_guard.api:app --host 127.0.0.1 --port 8000 --reload
```

### 方式三：標準手動安裝

`requirements-slm.txt` 已內建 PyTorch CPU 索引網址，直接安裝即可（不需要手動輸入額外參數）：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-slm.txt
Copy-Item .env.example .env
python -m uvicorn mail_guard.api:app --host 127.0.0.1 --port 8000 --reload
```

網址：

- 防護介面：`http://127.0.0.1:8000/`
- API 文件：`http://127.0.0.1:8000/docs`
- 健康檢查：`http://127.0.0.1:8000/health`

## 設定

`.env` 的 SLM 設定：

```env
ANALYZER_BACKEND=slm
SLM_MODEL=songhieng/chn-roberta-phishing-content-detector-1.0
SLM_PHISHING_LABEL=LABEL_1
SLM_MIN_CONFIDENCE=0.75
SLM_MAX_CHARS=6000
SLM_MAX_SEGMENTS=8
```

- `SLM_MIN_CONFIDENCE`：低於此值時標成不確定，範圍為 0.5–1.0。
- `SLM_MAX_CHARS`：單封郵件最多分析的本文字元數。
- `SLM_MAX_SEGMENTS`：最多送進模型的分段數；超過時保留前段及最後一段。

`ANALYZER_BACKEND` 也保留 `local`、`openai`、`gemini` 作獨立分析器，但不會彼此合併。OpenAI 與 Gemini 分別需要安裝 `requirements-openai.txt`、`requirements-gemini.txt`；預設 SLM 環境不會安裝這兩個雲端 SDK。

## Google OAuth 與 Gmail

在 `.env` 設定 Google Cloud 網頁應用程式 OAuth 用戶端：

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/auth/google/callback
```

需要的 Gmail scope：

```text
https://www.googleapis.com/auth/gmail.modify
```

登入入口：

```text
http://127.0.0.1:8000/auth/google/start
```

Google Token、背景防護開關及已處理郵件 ID 會寫入 `.mailguard_state.bin`，並由 Windows DPAPI 加密。這套持久化方式目前只支援 Windows。

## API

分析單封標準化郵件：

```http
POST /api/analyze
Content-Type: application/json
```

掃描已登入的 Gmail：

```http
POST /api/gmail/scan-connected
Content-Type: application/json

{"max_results": 10}
```

`POST /api/gmail/scan` 接受 `X-Gmail-Access-Token`，只供原型測試。正式產品應由後端管理 Token，並加入使用者驗證與權限隔離。

## 背景防護

登入 Gmail 後可在首頁開啟背景 polling。預設每 5 分鐘查看最新 20 封收件匣郵件，只處理尚未記錄的 message ID。

```env
BACKGROUND_SCAN_SECONDS=300
BACKGROUND_SCAN_LIMIT=20
```

## 測試

```powershell
python -m unittest discover -s tests -v
```

測試使用 fake classifier，不需要下載模型。實機模型測試的環境、案例與結果另記錄於 `docs/model-smoke-test-chn-roberta.md`。

## 已知限制

- 預設模型沒有公開訓練資料、label mapping 或 license。
- 本機 smoke test 曾出現高信心誤判，尤其是中英混合郵件。
- 分段可減少截斷，但多段取最高值可能增加 false positive。
- Gmail parser 主要擷取 `text/plain`；HTML-only 郵件可能漏掉內容。
- Web UI 顯示停用連結與附件的建議，但 Gmail 本身不會禁止使用者操作。
- 沒有 Android App、正式帳號系統、HTTPS 部署與多使用者隔離。
