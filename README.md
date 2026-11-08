<p align="center"><img src="docs/icon.png" width="96" alt=""></p>

# Argus · AI 技能安全掃描

在安裝 Claude 等 AI 工具的「技能」（Skill）之前，請好幾個開源安全掃描工具一起檢查，再把結果整理成一份白話中文報告。全部在自己的電腦上執行，不上傳技能內容，也不需要 AI 金鑰。

名字來自希臘神話裡的百眼巨人 Argus Panoptes：身上的眼睛輪流守望，從不全部閉上。

- 使用者請看：[docs/使用說明.md](docs/使用說明.md)
- 想加入新的掃描工具：[docs/新增掃描工具.md](docs/新增掃描工具.md)

## 目前整合的工具

| 工具 | 作者 | 授權 | 用途 |
|---|---|---|---|
| [SkillSpector](https://github.com/NVIDIA/SkillSpector) | NVIDIA | Apache-2.0 | 專門檢查 AI 技能 |
| [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | Cisco AI Defense | Apache-2.0 | 專門檢查 AI 技能（第二意見） |
| [Bandit](https://github.com/PyCQA/bandit) | PyCQA | Apache-2.0 | Python 程式的危險寫法 |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Yelp | Apache-2.0 | 寫死的密碼與金鑰 |

## 架構

```
core/argus/            核心，只用 Python 標準函式庫；Mac 和之後的 Windows 共用
  server.py            只在本機（127.0.0.1）運作的網頁伺服器，需要每次啟動產生的通行碼
  jobs.py              在背景執行掃描和安裝，提供進度
  targets.py           把「Claude 技能／資料夾／zip／GitHub」變成要掃的技能資料夾（含安全解壓縮）
  report.py            產生獨立的 HTML 報告（不靠 Argus 也能打開、分享）
  model.py             所有工具共用的結果格式（Finding / Outcome / SkillResult）
  native.py            系統的選資料夾、選檔案、在 Finder 打開（唯一跟平台有關的地方）
  scanners/            每個掃描工具一個檔案；加檔案就是加工具
  ui/                  網頁介面（HTML / CSS / JS，沒有外部相依）
mac/                   Mac 啟動器、Info.plist、圖示、打包腳本
tests/                 單元測試、各工具輸出的範例、預覽用伺服器
docs/                  使用說明、開發說明
```

**執行流程**：點兩下 App → `mac/run` 確認有 uv → 用 uv 準備的 Python 3.12 在背景啟動 `python -m argus` → 打開瀏覽器。掃描工具各自用 `uv tool install` 裝成獨立環境，彼此的套件版本不會打架。頁面關掉幾分鐘後，伺服器自動結束。

## 開發

```bash
# 單元測試
python3 -m unittest discover tests

# 用假的掃描工具預覽介面（不用安裝真的工具）
python3 tests/preview_server.py        # 打開它印出的網址

# 直接啟動（會用到電腦上已經裝好的真工具）
PYTHONPATH=core python3 -m argus --open

# 打包 Mac App → dist/Argus-mac-<版本>.zip
bash mac/build.sh
```

需要 Python 3.12 以上。

## 接下來可以做的

- **Windows 版**：核心已經是跨平台的，`native.py` 也寫好了 Windows 的選檔案方式；還差一個 Windows 啟動器（取代 `mac/run`）和打包腳本。
- **更多工具**：例如 [OSV-Scanner](https://github.com/google/osv-scanner)（套件漏洞）、[Semgrep CE](https://github.com/semgrep/semgrep)（更多語言的程式檢查）。
- **選配的 AI 判斷**：Cisco Skill Scanner 和 SkillSpector 都支援用 AI 再確認一次，可以做成「有金鑰才開、預設關閉」的進階選項。

## 授權

© 2026 Square Su，以 [MIT](LICENSE) 授權開源。整合的掃描工具各自適用自己的授權，見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
