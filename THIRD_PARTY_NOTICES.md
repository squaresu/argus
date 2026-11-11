# 第三方軟體授權聲明

Argus 本身以 MIT 授權開源（見 [LICENSE](LICENSE)）。

Argus **不夾帶**下列工具的程式碼。使用者按「安裝」時，Argus 會透過 [uv](https://github.com/astral-sh/uv)（Astral，MIT／Apache-2.0）從各工具的官方來源下載、安裝到使用者自己的電腦上；OSV-Scanner 是單一程式，直接從 Google 在 GitHub 的官方發佈頁下載，並比對官方公布的 SHA-256 檢查碼。這些工具各自適用它們自己的授權條款：

| 工具 | 作者 | 授權 | 來源 |
|---|---|---|---|
| SkillSpector | NVIDIA | Apache-2.0 | https://github.com/NVIDIA/SkillSpector |
| Cisco Skill Scanner | Cisco AI Defense | Apache-2.0 | https://github.com/cisco-ai-defense/skill-scanner |
| Bandit | PyCQA | Apache-2.0 | https://github.com/PyCQA/bandit |
| Semgrep（Community Edition） | Semgrep, Inc. | LGPL-2.1 | https://github.com/semgrep/semgrep |
| detect-secrets | Yelp | Apache-2.0 | https://github.com/Yelp/detect-secrets |
| OSV-Scanner | Google | Apache-2.0 | https://github.com/google/osv-scanner |

Semgrep 使用的檢查規則（`core/argus/scanners/semgrep_rules.yml`）是 Argus 自己寫的，跟 Argus 一樣以 MIT 授權；沒有使用 Semgrep 官方規則庫的規則。

報告裡各類發現的中文說明，是 Argus 根據各工具公開的規則類別撰寫的，不代表原作者的立場。
