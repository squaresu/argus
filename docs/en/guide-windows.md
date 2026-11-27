# Argus (Windows): User guide

**Argus** is a small Windows tool. Before you install a "skill" for Claude or another AI tool, it asks several open-source security scanners to check it, then turns what they find into one plain-language report.

The name comes from Argus Panoptes, the hundred-eyed giant of Greek myth: his eyes took turns keeping watch, and never all closed at once.

---

## What you need

- Windows 10 or Windows 11 (regular Intel/AMD PCs or ARM PCs)
- An internet connection the first time (to install what Argus needs and the scanners)
- No need to install Python or Git yourself

---

## Getting started

1. **Unzip**: Right-click the `Argus-win-version.zip` you downloaded → "**Extract All**". You'll get an "Argus" folder.
   (Be sure to extract it first. Double-clicking inside the zip won't work.)
2. **Move it**: Put the whole Argus folder somewhere you can find it and won't move it later, such as "Documents".
3. **Open it the first time**: Double-click **Argus.cmd** in the folder. Argus doesn't come from the Microsoft Store, so Windows may block it at first. That's normal:
   - If you see a blue "**Windows protected your PC**" screen: click "**More info**" → "**Run anyway**".
   - If you see "**Open File - Security Warning**": click "**Run**".
4. **Install uv**: The first time, Argus asks whether to install uv (a free, open-source helper it uses to install the scanners). Click "**Yes**".
5. **Wait for it to open**: The first start downloads a few things and takes about a minute. A small window shows the progress, then your browser opens the Argus page by itself.
6. **Install the scanners**: Under "Which scanners?", click "**Install all**" at the top right. Argus installs each scanner in turn (about 1–3 minutes each). You can also click "Install" next to a scanner to install them one at a time. Once they're all installed, this section shrinks to a single line. Click "Adjust" to change it.

After the first time, shortcuts with the Argus icon appear in the **Start menu** and on your **desktop**. Open Argus from there from now on. No need to look for Argus.cmd again.

---

## How to use it

> Argus starts in dark mode. To switch to light mode, click the moon button at the top right. Click it again (the sun) to go back to dark.
> Argus follows your computer's language. To change it, use the language menu next to the theme switch at the top right.

### 1. What to check?

| Option | What it does |
|---|---|
| My Claude skills | Finds the Claude skills and plugins on this computer (in `C:\Users\your-name\.claude`) and checks them all at once |
| A folder | Pick a skill folder you've downloaded but haven't installed yet |
| A zip file | Pick a skill's zip file |
| GitHub link | Paste a link to a public repo, or to a folder inside one |
| My MCP servers | Checks the MCP servers set up in Claude Code, Claude Desktop, plugins and Cursor. It only reads the settings files. It never starts a server, and doesn't need any scanners installed |

When a folder, zip or repo holds several skills, each one is checked separately and gets its own card in the report.

### 2. Which scanners?

| Scanner | Good at |
|---|---|
| **SkillSpector** (NVIDIA) | Made for AI skills: 70+ patterns, including prompt injection, data leaks, dangerous commands and vulnerable packages |
| **Cisco Skill Scanner** (Cisco) | Another rule set made for AI skills, as a second opinion |
| **Bandit** (PyCQA) | Looks for risky code in a skill's Python files. Skills without Python show "Not applicable" |
| **Semgrep** (Semgrep) | Uses Argus's own rules to check a skill's JavaScript/TypeScript code: running commands, running text as code, reading key files, changing startup settings, and sending data somewhere suspicious. Skills without this kind of code show "Not applicable" |
| **detect-secrets** (Yelp) | Looks for passwords and API keys written into a skill |
| **OSV-Scanner** (Google) | Checks whether the packages a skill uses have known vulnerabilities or have been reported as malicious. It only reads package lists that name exact versions (for example package-lock.json, or a requirements.txt with ==). Without one, it shows "Not applicable". **It sends package names and versions to OSV.dev to look them up**, never the skill itself |

**Argus also checks a few things itself:**
- **Files**: whether a skill includes files the scanners can't read (compiled programs, archives), and package lists that don't pin the version.
- **Plugin hooks and commands** (when checking "My Claude skills"): a plugin can set up hooks, commands that run automatically every time you send a message or Claude uses a tool. Argus lists every command that runs automatically in each plugin, flags any that go online on their own, download and run programs, touch keys or change startup settings, and checks the code they use. In the report they appear as "plugin name (plugin hooks, commands and code)".

**When a scanner has a new version:** When you open Argus, any scanner with a new version shows "New version x.y" and an "Update" button. Click it to switch to the new version (about 1–3 minutes). Argus only asks PyPI and GitHub for version numbers and never sends anything else. Scanners don't update themselves, so it's a good idea to update when you see "New version", especially SkillSpector and Cisco: new kinds of attack are only caught by newer rules.

### 3. Start the check

Click "Start check" and the page shows the progress. When it's done, the report appears right on the page, and a copy is saved in the "Documents → Argus Reports" folder. You can find earlier reports under "Recent reports" on the home page.

Next to "Start check", Argus tells you how many skills there are and **about how long it will take**. (For GitHub links and zip files, it only knows how many skills there are after downloading and unpacking, so it first shows the time per skill.) While checking, the progress screen shows the time so far and about how much is left. The estimates get better over time: Argus remembers how long each scanner actually takes on your computer.

### Reminders to check again

When you open Argus, a reminder appears at the top of the home page if any of these is true for your Claude skills:

- a skill's files have changed since the last check;
- you've installed a skill that hasn't been checked yet;
- it's been more than 30 days since the last check.

Click "**Check now**" and Argus selects "My Claude skills" for you. Click "Later" and it won't remind you again for 7 days (unless something else changes). Argus only compares files. It never starts a scan by itself.

If there are a lot of skills and it's taking a long time, click "**Stop**" below the progress screen. Whatever has been checked so far still goes into a report.

When you're done with the report, just close the browser tab. Argus quits by itself a few minutes later.

### Use with Claude

The "**Use with Claude**" section near the bottom of the home page has two switches:

**Ask Argus to check, right from Claude**
When this is on, Argus adds a skill called "argus" to Claude. Then, in **Claude Code** (in a terminal, or the Code tab in Claude Desktop), you can say things like:

- "Check this skill before installing it: https://github.com/…"
- "Are the skills I've installed safe?"
- "Check my MCP servers"

Claude runs Argus on its own and tells you the result in plain words. No need to open Argus or copy and paste anything. When you ask Claude to install a skill, it checks it first and tells you what it found before installing.

> Regular Claude chats (on the web or the mobile app) can't run programs on your computer, so only Claude Code can use this skill.
> Behind the scenes it uses the `argus` command that Argus creates (at `%USERPROFILE%\\.local\\bin\\argus.cmd`). Argus updates it every time it opens, so after you move or update Argus, just open it once.

**Automatic check for new skills**: only on Mac for now. It's coming to Windows later. Meanwhile, the "Reminders to check again" you see when opening Argus still tell you which skills have changed.

### Updating Argus

When there's a new version, a "**New version available**" notice appears at the top of the home page. (Argus checks every time it opens. You can also click "**Check for updates**" in "About".)

- Click "**Update now**": Argus downloads the new version, makes sure it's the official release, replaces the old one and reopens by itself. Your scanners and earlier reports are kept, and the shortcuts don't need to be recreated.
- Click "**Update manually**": follow the steps in the window to download and replace it yourself.
- Click "**Later**": you won't be reminded about this version again.

If the automatic update fails (for example, because a window showing the Argus folder is open and its files are in use), Argus stays on the current version. Close that window and try again, or use "Update manually" instead.

---

## Reading the report

At the very top of the report is a **one-line conclusion**, so you know what to do without reading the whole thing:

- 🟢 **OK to install** (for skills and MCP servers you already have, it says "OK to keep using"): nothing to worry about, or everything flagged is "Probably fine".
- 🟡 **Ask first**: a few things are worth a look. If you're not sure, click "Copy for Claude to judge", or ask someone who knows.
- 🔴 **Not recommended**: there's high-risk code. Unless you're sure it's a normal feature, hold off for now.

When you check many skills at once, the conclusion says how many are "Not recommended" and how many are "Ask first", and lists their names. Click a name to jump to that skill. Skills that are "OK to keep using" are folded into one line of names at the end; click to see the details. Reports with many skills have a filter bar at the top, so you can show just one kind of result or search for a skill by name. Each card's "Details" shows what each scanner found and what the skill can do. To save the report or share it, use your browser's "Print → Save as PDF".

The same kind of warning from the same scanner is grouped into one card, for example "14 places", instead of being listed 14 times.

Argus reaches the conclusion with fixed rules: it starts from each scanner's result (taking the most serious one), then sets aside anything "Probably fine" and anything you've already reviewed. Each card lists every scanner's own result, for example "SkillSpector Not recommended · Cisco Caution · Bandit Safe".

Under each skill, the findings are split into two groups: "**Worth a look**" and "**Probably fine**". The second group holds obvious false alarms picked out by fixed rules, and each one says "why it's probably fine".

If you're not sure, click "**Copy for Claude to judge**", paste it into a Claude chat and send. Claude goes through each item and tells you which ones are real concerns.

> **"Not recommended" doesn't mean malicious.** Scanners look at how code is written, not what it's for, so they often flag normal features too.

### What it can do

Under each skill's name, a row of icons shows **what it does**:

| Icon | Meaning |
|---|---|
| 🌐 Goes online | Connects to online services or downloads things |
| ⚙️ Runs programs | Runs programs or commands on your computer |
| 📁 Writes or deletes files | Creates, changes or deletes files |
| 🔑 Touches secrets or Claude settings | Reads keys, .env files or Claude's settings folder |
| ⚡ Runs automatically | Runs on its own at certain moments, without you asking |
| 📦 Installs packages | Installs other programs or packages |
| 📄 Text instructions only | None of the above: just written instructions for the AI |

Click an icon to see which line of which file Argus based it on. It's a handy way to spot things that don't add up, like "why does a scriptwriting skill need to go online?" This is Argus's best guess from the files, not a guarantee.

### Mark as reviewed

When you've looked over a skill and it seems fine, click "**Mark as reviewed**" at the bottom of its card. The next time you scan:

- **Nothing changed**: it shows "✓ Reviewed", and findings you've already seen are folded into "Seen before", so you don't have to go through them again.
- **The author updated the skill**: it shows "⚠ This skill has changed since you reviewed it", and lists which files were added, changed or deleted. New findings get a red "New" tag.

This guards against a common trick: a skill starts out clean, and once lots of people have installed it, something sneaky is slipped in with an update. Even for skills you haven't marked as reviewed, Argus compares with the last scan and lets you know if anything changed. Click the button again to undo.

This button only appears when you open the report inside Argus. It isn't there when you open a saved report file directly.

### MCP server reports

When you choose "My MCP servers", each server gets its own card showing where it's set up, how it runs (or which address it connects to), and any of these warnings:

- **Version not pinned**: it downloads the latest version every time it starts, so whenever the author, or someone who has taken over their account, publishes a new version, your computer runs it right away. Packages from large companies or the official MCP project are put under "Probably fine".
- **Pulls the latest code from GitHub every time it starts**: it skips the package registry and doesn't name a version, so any change the author pushes runs right away.
- **Passes messages from other people to Claude**: plugins for Discord, Telegram, iMessage and the like. Text someone sends you could be taken by Claude as instructions. Turn it off if you're not using it.
- **Connection isn't encrypted**: it uses http:// to connect to an outside service.
- **Key written directly in the settings file**: a reminder about how keys are stored. Keys are always hidden in the report.
- **Docker has too much access, including your whole home folder**: it gets more access than it usually needs.

These are mostly about setup habits and don't mean the server is malicious. If you're not sure, you can click "Copy for Claude to judge" here too.

---

## Privacy and security

- Your "reviewed" records and the data used to compare scans stay on your computer. Nothing is uploaded.
- When checking MCP servers, Argus only reads the settings files and never starts a server. Keys in the settings are always hidden in the report.
- All scanning happens on your computer. **Skill contents are never uploaded**, and never sent to an AI service.
- Argus only goes online to: install what Argus needs and the scanners; check whether the scanners have new versions (version numbers only); download a GitHub skill you've asked it to check; look up whether packages have known vulnerabilities (only package names and versions are sent to [OSV.dev](https://osv.dev), when OSV-Scanner is used); and check GitHub for a new version of Argus, downloading it when you click "Update now".
- The Argus page only runs on your computer (its address is 127.0.0.1). Other computers can't connect to it.

---

## Common questions

**I double-clicked it and got "Windows protected your PC"**
Follow the "Open it the first time" steps above: click "More info" → "Run anyway". After that, open Argus from the shortcut in the Start menu or on your desktop, and you won't see it again.

**I double-clicked it a while ago, and the browser still hasn't opened**
The first start downloads Python, which can take 2–3 minutes on a slow connection. If it hasn't opened after 3 minutes, an error message appears. The log is in `%APPDATA%\Argus\logs` (paste that into the address bar of File Explorer to open it).

**The window for choosing a folder doesn't appear**
Sometimes it opens behind the browser. Check the taskbar.

**The page is stuck and nothing responds**
Click "About" at the top right → "**Quit Argus**", then open Argus again.

**A scanner failed to install, or shows "Didn't finish"**
Make sure you're online and try again. In the report, the reason is shown in brackets after "Didn't finish". If a scanner is broken, the home page shows "Reinstall".

**It won't open or install on my work computer**
Work computers may block PowerShell scripts or installing software. Please check with your IT team first.

**I want to remove it**
Delete the Argus folder and the Argus shortcuts in the Start menu and on your desktop. Your reports are in "Documents → Argus Reports". Keep them or delete them, as you like.

---

## Disclaimer

Scan results are for reference only. They don't mean a skill is definitely safe or definitely harmful. Each scanner can only find patterns it already knows, may raise false alarms, and may miss new or deliberately hidden tricks. "Probably fine" is a grouping made by fixed rules and doesn't guarantee there's no problem. Whether to install or use a skill, and how, is your own decision and at your own risk. Argus is provided "as is" under the MIT License, without warranty of any kind, and the author is not liable for any loss from using it or from decisions based on its results. Argus is an independent open-source project. It isn't affiliated with or endorsed by NVIDIA, Cisco, PyCQA, Yelp, Anthropic or any other company or organization.

---

## License

- Argus © 2026 Square Su, open source under the MIT License. You're free to use, change and share it.
- The scanners it uses are all open-source software: SkillSpector, Cisco Skill Scanner, Bandit, detect-secrets and OSV-Scanner are licensed under Apache-2.0, and Semgrep under LGPL-2.1. Argus doesn't bundle their code; it installs each one's official release on your computer. See THIRD_PARTY_NOTICES.md for details.
