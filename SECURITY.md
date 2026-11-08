# 安全問題回報

Argus 是一個安全工具，如果你發現 Argus **本身**的安全問題，例如：

- 報告或介面可能被技能裡的內容利用（例如插入網頁程式碼）
- 本機頁面可以被其他網站或其他電腦操作
- 解壓縮或下載技能時，可能把檔案寫到不該寫的地方

請**不要**開公開的 Issue，改用 GitHub 的私下回報：到本 repo 的 **Security → Report a vulnerability**。

請附上：使用的 Argus 版本、macOS 版本、重現步驟，以及可能的影響。收到後會盡快回覆。

## 不屬於 Argus 的問題

- **某個技能被誤判或漏判**：這是各掃描工具（SkillSpector、Cisco Skill Scanner、Bandit、detect-secrets）的規則問題，請回報給該工具的專案。如果是 Argus 的中文說明或「多半不用擔心」分組不恰當，可以開一般的 Issue。
- **各掃描工具本身的漏洞**：請直接回報給該工具的專案。
