"""The parts of a Claude Code plugin that aren't skills: hooks, commands, agents, and the scripts they run.

Hooks matter most: a plugin can have Claude Code run a command by itself on events such as every message you
send or every tool Claude uses, with nobody asking. This reads the plugin's hook settings (from hooks/hooks.json
or plugin.json), flags commands that do risky things, and lists every hook under 能做的事. The plugin's other
files, minus its skill folders (those are scanned as skills), are copied aside so the code scanners can read
the scripts the hooks and commands run.
"""

import re
import shutil
from pathlib import Path

from . import capabilities, filecheck, targets
from .model import Finding, Outcome, SkillResult

SCANNER = 'argus-plugin'
SCANNER_NAME = 'Argus 外掛檢查'
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
MAX_COPY = 50 * 1024 * 1024
EVENTS = {'SessionStart': '每次打開 Claude 時', 'SessionEnd': '結束對話時', 'UserPromptSubmit': '你每次送出訊息時',
          'PreToolUse': 'Claude 每次使用工具之前', 'PostToolUse': 'Claude 每次使用工具之後', 'Stop': 'Claude 每次回答完時',
          'SubagentStop': '子代理完成時', 'Notification': '跳出通知時', 'PreCompact': '整理對話之前'}
# (rule, severity, title, what) for a hook's command
RULES = [
    ('HOOK-PIPE-SHELL', 'CRITICAL', '自動下載並執行程式',
     re.compile(r'(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node)\b|\$\((curl|wget)\b'),
     '這個 hook 會自己從網路下載程式並直接執行，下載的內容隨時可能被換掉。'),
    ('HOOK-DECODE', 'CRITICAL', '自動解開隱藏的指令並執行',
     re.compile(r'base64\s+(-d|--decode|-D)\b|\beval\s'), '這個 hook 會先解開或組出一段指令再執行，看不出實際做了什麼。'),
    ('HOOK-WIPE', 'CRITICAL', '自動刪除整個家目錄或硬碟',
     re.compile(r'\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+["\']?(~|\$HOME|/)["\']?/?(\s|$)'), '這個 hook 會刪除整個家目錄或從根目錄開始刪除。'),
    ('HOOK-NETWORK', 'HIGH', '自動連網',
     re.compile(r'\b(curl|wget|nc|ncat|scp|rsync|ftp)\b|https?://'),
     '這個 hook 會自己連到網路。它在你每次對話時都可能執行，看得到的內容（例如你送出的訊息）可能被送出去。'),
    ('HOOK-SENSITIVE', 'HIGH', '自動讀取存放機密的檔案',
     re.compile(r'\.ssh/|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|Keychains|find-generic-password|\.claude\.json'),
     '這個 hook 會碰到 SSH 金鑰、雲端帳號憑證、鑰匙圈或 Claude 設定。'),
    ('HOOK-STARTUP', 'HIGH', '自動改動開機或 Claude 設定',
     re.compile(r'\.zshrc|\.bashrc|\.bash_profile|\.zprofile|LaunchAgents|crontab|launchctl|\.claude/settings'),
     '這個 hook 會改動開機時執行的設定或 Claude 的設定，可能讓程式一直留在電腦上。'),
    ('HOOK-SUDO', 'MEDIUM', '自動要求管理員權限', re.compile(r'(^|[;&|]\s*)sudo\s'),
     '這個 hook 會用管理員權限執行指令。'),
]
TIP = '看這個指令要做的事，跟外掛的用途對不對得上；拿不準就按「複製給 Claude 判斷」。'


def _manifest(folder: Path):
    return targets._load_json(folder / '.claude-plugin' / 'plugin.json') or targets._load_json(folder / 'plugin.json') or {}


def _paths(folder: Path, value, default):
    """A plugin.json entry naming a file or folder (or several), inside the plugin only; else the default."""
    named = [value] if isinstance(value, str) else [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
    base = folder.resolve()
    out = [p for p in ((folder / v).resolve() for v in named) if p.is_relative_to(base)]
    return out or [folder / default]


def hooks_of(folder: Path):
    """→ [(event, matcher, command)] from hooks/hooks.json, or plugin.json's "hooks" (a path or the settings)."""
    m = _manifest(folder)
    sources = []
    if isinstance(m.get('hooks'), dict):
        sources.append(m['hooks'])
    for p in _paths(folder, m.get('hooks') if not isinstance(m.get('hooks'), dict) else None, 'hooks/hooks.json'):
        data = targets._load_json(p)
        if isinstance(data, dict):
            sources.append(data)
    found = []
    for data in sources:
        events = data.get('hooks') if isinstance(data.get('hooks'), dict) else data
        for event, groups in (events or {}).items():
            for g in groups if isinstance(groups, list) else []:
                if not isinstance(g, dict):
                    continue
                for h in g.get('hooks') or []:
                    if isinstance(h, dict) and h.get('command'):
                        found.append((event, str(g.get('matcher') or ''), str(h['command'])))
    return found


def markdown_names(folder: Path, value, default):
    names = []
    for root in _paths(folder, value, default):
        if root.is_file() and root.suffix == '.md':
            names.append(root.stem)
        elif root.is_dir():
            names += sorted(p.stem for p in root.rglob('*.md'))[:50]
    return names


def _copy_without_skills(folder: Path, dest: Path):
    """The plugin minus its skill folders (scanned as skills already), so the code scanners see the rest."""
    skill_roots = {r.resolve() for r in targets.plugin_skill_roots(folder)}
    total = 0

    def ignore(d, names):
        nonlocal total
        skip = []
        for n in names:
            p = Path(d) / n
            if n in SKIP_DIRS or p.resolve() in skill_roots or p.is_symlink():
                skip.append(n)
            elif p.is_file():
                total += p.stat().st_size
                if total > MAX_COPY:
                    skip.append(n)
        return skip
    shutil.copytree(folder, dest, ignore=ignore)
    return dest


def inspect(name, folder: Path, label, work: Path):
    """One installed plugin → (SkillResult, folder for the scanners), or None when it has nothing but skills."""
    m = _manifest(folder)
    hooks = hooks_of(folder)
    commands = markdown_names(folder, m.get('commands'), 'commands')
    agents = markdown_names(folder, m.get('agents'), 'agents')
    skill_roots = [r.resolve() for r in targets.plugin_skill_roots(folder)]
    code = [p for p in folder.rglob('*') if p.is_file() and p.suffix.lower() in capabilities_code()
            and not any(part in SKIP_DIRS for part in p.parts)
            and not any(p.resolve().is_relative_to(r) for r in skill_roots)][:1]
    if not (hooks or commands or agents or code):
        return None
    copy = _copy_without_skills(folder, work / f'plugin-{re.sub(r"[^A-Za-z0-9_.-]", "_", label)}')
    findings, evidence = [], []
    for event, matcher, command in hooks:
        when = EVENTS.get(event, event) + (f'（{matcher}）' if matcher and matcher != '*' else '')
        evidence.append(f'{when}：{command[:160]}')
        for rule, severity, title, pattern, what in RULES:
            if pattern.search(command):
                findings.append(Finding(scanner=SCANNER, title=title, what=what, tip=TIP, severity=severity,
                                        file='hooks（自動執行的指令）', rule=rule, category='hook',
                                        snippet=f'{when}\n{command[:600]}', detail=f'{rule}: {event} hook'))
    caps = [c for c in capabilities.analyze(copy) if c['id'] not in ('text', 'autorun' if hooks else '')]
    if hooks:
        caps.insert(0, {'id': 'autorun', 'icon': '⚡', 'label': f'自動執行 {len(hooks)} 個指令',
                        'what': 'Claude Code 會在這些時候自己執行這些指令，不用你叫它。', 'evidence':
                        [{'file': '', 'line': None, 'text': t} for t in evidence[:12]]})
    if commands or agents:
        parts = [f'指令 {len(commands)} 個' if commands else '', f'代理 {len(agents)} 個' if agents else '']
        caps.append({'id': 'prompts', 'icon': '💬', 'label': '、'.join(x for x in parts if x),
                     'what': '外掛附帶的斜線指令和代理，Claude 會照著裡面的文字做事。',
                     'evidence': [{'file': '', 'line': None, 'text': '、'.join((['/' + c for c in commands] + agents)[:20])}]})
    severities = {f.severity for f in findings}
    verdict = 'DO_NOT_INSTALL' if 'CRITICAL' in severities else 'CAUTION' if 'HIGH' in severities else 'SAFE'
    note = ('這是外掛裡技能以外的部分：自動執行的 hooks、斜線指令、代理和它們用到的程式。'
            + ('指令和代理的文字內容只列出名字，還沒有用 SkillSpector／Cisco 檢查。' if commands or agents else ''))
    result = SkillResult(f'{name}（外掛的 hooks、指令和程式）', str(folder), kind='plugin', key=f'plugin:{label.split(" ")[0]}',
                         capabilities=caps, outcomes=[Outcome(SCANNER, verdict, findings, note=note), filecheck.check(copy)])
    return result, copy


def capabilities_code():
    return {'.py', '.js', '.mjs', '.cjs', '.ts', '.sh', '.bash', '.zsh', '.rb', '.go', '.php', '.ps1', '.command'}


def collect(work: Path, home=None):
    """Every installed plugin that has more than skills → [(SkillResult, folder for the scanners)]."""
    out = []
    for name, folder, label in targets.plugins_with_labels(home):
        try:
            found = inspect(name, folder, label, work)
        except OSError:
            continue
        if found:
            out.append(found)
    return out
