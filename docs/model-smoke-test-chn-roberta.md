# chn-roberta phishing 模型 Smoke Test

測試日期：2026-09-20

測試模型：`songhieng/chn-roberta-phishing-content-detector-1.0`  
模型 revision：`df57606364a356dafc6905906961bda5b0626f6c`

## 測試目的

確認模型能否在目前 Workstation 執行，以及它對中文、英文與中英混合郵件的基本判斷是否足以接入 MailGuard。

這次沒有連接 Gmail，也沒有移動或修改郵件。測試資料是人工撰寫的 smoke-test cases，不是正式 benchmark，因此下列數字不能當成模型的真實準確率。

## 執行環境

- CPU：AMD Ryzen 7 PRO 5850U，8 cores／16 threads
- RAM：14 GiB
- GPU：無 NVIDIA GPU
- Python：3.12 isolated venv
- PyTorch：CPU build

模型可以正常載入。權重約 499 MB，模型共有 124,647,170 個參數。程序最大 resident memory 約 711 MiB；模型已快取時，啟動並完成一次推論約 5.3 秒。模型常駐後，單封短郵件的 CPU 推論時間約 50–112 ms，平均約 93 ms。

## 模型中繼資料問題

模型輸出只有：

```text
LABEL_0
LABEL_1
```

Model card 與 `config.json` 都沒有定義哪個 label 代表 phishing。以下測試依英文控制案例推定 `LABEL_1` 為 phishing，但這不是作者提供的正式 mapping。

模型使用標準 RoBERTa tokenizer：

```text
RobertaTokenizer
vocab_size = 50265
max_length = 512
```

## 第一輪觀察

模型能辨識部分典型案例，例如要求登入假網站並輸入密碼的中文與英文郵件。但它也以很高信心將下列正常中文內容判為 `LABEL_1`：

- 電子發票通知
- 週年慶行銷通知
- 提醒使用者不要提供密碼的資安宣導

另一個短中文測試「請立即輸入帳號密碼與驗證碼」則被判為 `LABEL_0`，機率約 98.9%。結果對措辭很敏感。

## 中英文成對 Smoke Test

測試集包含 32 封人工案例：14 封中文、14 封英文，以及 4 封中英混合郵件。安全與 phishing 案例包含會議、發票、OTP、行銷、資安宣導、帳戶驗證、網銀、禮物卡、配送費與惡意附件等情境。

假設 `LABEL_1 = phishing`，結果如下：

| 語言 | 案例數 | Smoke-test accuracy | Phishing precision | Phishing recall | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| 中文 | 14 | 71.4% | 66.7% | 85.7% | 3 | 1 |
| 英文 | 14 | 71.4% | 63.6% | 100% | 4 | 0 |
| 中英混合 | 4 | 50.0% | N/A | 0% | 0 | 2 |

中英混合的兩封 phishing 都被判成安全：

- `帳戶偵測到 abnormal activity，請 immediately login ... 輸入 password 及 OTP`
- `我是 CEO，請現在 purchase gift cards，然後 reply 卡號與 PIN`

兩筆錯誤的勝出類別信心仍很高。整組 mixed cases 的平均勝出信心約 97.5%，表示目前不能把模型輸出的 softmax 當成已校準可信度。

## 中文 Tokenization 與截斷

同一 tokenizer 對中文的 token 使用量明顯較高：

| 測試文字 | 字元數 | Tokens | 每 token 字元數 |
|---|---:|---:|---:|
| 中文 | 112 | 218 | 0.51 |
| 英文 | 312 | 59 | 5.29 |
| 中英混合 | 344 | 147 | 2.34 |

模型上限為 512 tokens。長中文郵件可能只讀到前兩三百個中文字。

截斷測試將 phishing 指令放在長篇正常內容後方。中文輸入共有 1,804 tokens，實際只保留前 512 tokens，惡意 URL 與要求輸入密碼的段落完全被截掉，最終被判為安全。英文長郵件也有相同問題，但中文更快耗盡 token budget。

## 結論

模型在這台 Workstation 的速度與記憶體使用可以接受，可作為 Hackathon Demo 的內容分類訊號，但不能控制自動移至垃圾桶，也不應視為正式環境的唯一安全判斷。原因是：

- Label mapping 沒有文件。
- 訓練資料、中文涵蓋及 license 不明。
- 正常通知有多筆高信心誤判。
- 中英混合 phishing 在 smoke test 中全部漏判。
- 中文 tokenization 效率差，長郵件容易漏掉後段攻擊內容。
- Softmax 信心與測試正確性不一致。

Demo 版可將結果轉成低度、不確定、中度與高度標籤，並停用自動清理。程式還需要郵件分段與 URL／Header 技術特徵，降低長郵件截斷及中英混合漏判的影響。正式選型仍應改測有明確 multilingual 訓練與中文評估的模型。
