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

from . import capabilities, filecheck, i18n, targets
from .i18n import N_, _
from .model import Finding, Outcome, SkillResult

SCANNER = 'argus-plugin'
SCANNER_NAME = N_('Argus 外掛檢查')      # translated where it's shown
# where a hook finding is: stored in the source language, since file= is part of the finding's fingerprint;
# shown with file_label()
HOOKS_FILE = N_('hooks（自動執行的指令）')
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
MAX_COPY = 50 * 1024 * 1024
EVENTS = {'SessionStart': N_('每次打開 Claude 時'), 'SessionEnd': N_('結束對話時'), 'UserPromptSubmit': N_('你每次送出訊息時'),
          'PreToolUse': N_('Claude 每次使用工具之前'), 'PostToolUse': N_('Claude 每次使用工具之後'), 'Stop': N_('Claude 每次回答完時'),
          'SubagentStop': N_('子代理完成時'), 'Notification': N_('跳出通知時'), 'PreCompact': N_('整理對話之前')}
# (rule, severity, title, what) for a hook's command
RULES = [
    ('HOOK-PIPE-SHELL', 'CRITICAL', N_('自動下載並執行程式'),
     re.compile(r'(curl|wget)\b[^|;]*\|\s*(sudo\s+(-\S+\s+)*)?(sh|bash|zsh|python3?|node|perl|ruby)\b(?!\s+-m\s+json\.tool)'
                r'|[$<]\(\s*(curl|wget)\b'),
     N_('這個 hook 會自己從網路下載程式並直接執行，下載的內容隨時可能被換掉。')),
    ('HOOK-DECODE', 'CRITICAL', N_('自動解開隱藏的指令並執行'),
     re.compile(r'base64\s+(-d|--decode|-D)\b|\beval\s'), N_('這個 hook 會先解開或組出一段指令再執行，看不出實際做了什麼。')),
    ('HOOK-WIPE', 'CRITICAL', N_('自動刪除整個家目錄或硬碟'),
     re.compile(r'\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+)+(--no-preserve-root\s+)?["\']?(~|\$HOME|\$\{HOME\}|/)["\']?/?\*?["\']?(\s|;|&|$)'), N_('這個 hook 會刪除整個家目錄或從根目錄開始刪除。')),
    ('HOOK-NETWORK', 'HIGH', N_('自動連網'),
     re.compile(r'\b(curl|wget|nc|ncat|scp|rsync|ftp)\b|https?://'),
     N_('這個 hook 會自己連到網路。它在你每次對話時都可能執行，看得到的內容（例如你送出的訊息）可能被送出去。')),
    ('HOOK-SENSITIVE', 'HIGH', N_('自動讀取存放機密的檔案'),
     re.compile(r'\.ssh/|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|Keychains|find-generic-password|\.claude\.json'),
     N_('這個 hook 會碰到 SSH 金鑰、雲端帳號憑證、鑰匙圈或 Claude 設定。')),
    ('HOOK-STARTUP', 'HIGH', N_('自動改動開機或 Claude 設定'),
     re.compile(r'\.zshrc|\.bashrc|\.bash_profile|\.zprofile|LaunchAgents|crontab|launchctl|\.claude/settings'),
     N_('這個 hook 會改動開機時執行的設定或 Claude 的設定，可能讓程式一直留在電腦上。')),
    ('HOOK-SUDO', 'MEDIUM', N_('自動要求管理員權限'), re.compile(r'(^|[;&|]\s*)sudo\s'),
     N_('這個 hook 會用管理員權限執行指令。')),
]
TIP = N_('看這個指令要做的事，跟外掛的用途對不對得上；拿不準就按「複製給 Claude 判斷」。')


def file_label(file):
    """A finding's file= as shown: HOOKS_FILE in the language in use, anything else (a real path) as it is."""
    return _(text=file) if file == HOOKS_FILE else file


def _manifest(folder: Path):
    for p in (folder / '.claude-plugin' / 'plugin.json', folder / 'plugin.json'):
        data = targets._load_json(p)
        if isinstance(data, dict):
            return data
    return {}


def _paths(folder: Path, value, default):
    """The default place plus any file or folder plugin.json names (inside the plugin only): in Claude Code,
    named paths add to the default, they don't replace it."""
    named = [value] if isinstance(value, str) else [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
    base = folder.resolve()
    out = [(folder / default).resolve()]
    for p in ((folder / v).resolve() for v in named):
        if p.is_relative_to(base) and p not in out:
            out.append(p)
    return out


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
    as_list = lambda x: x if isinstance(x, list) else [x] if isinstance(x, dict) else []
    for data in sources:
        events = data.get('hooks') if isinstance(data.get('hooks'), dict) else data
        for event, groups in events.items():
            for g in as_list(groups):
                if not isinstance(g, dict):
                    continue
                for h in as_list(g.get('hooks')) + ([g] if 'command' in g else []):
                    if isinstance(h, dict) and h.get('command'):
                        found.append((str(event), str(g.get('matcher') or ''), str(h['command'])))
    return list(dict.fromkeys(found))


def markdown_names(folder: Path, value, default):
    names = []
    for root in _paths(folder, value, default):
        if root.is_file() and root.suffix == '.md':
            names.append(root.stem)
        elif root.is_dir():
            names += sorted(p.stem for p in root.rglob('*.md'))[:50]
    return names


def _copy_without_skills(folder: Path, dest: Path):
    """The plugin minus its skill folders (scanned as skills already), so the code scanners see the rest.
    → how many files were left out because the copy got too big. Files that can't be copied are skipped."""
    skill_roots = {r.resolve() for r in targets.plugin_skill_roots(folder)}
    total, left_out = 0, 0

    def ignore(d, names):
        nonlocal total, left_out
        skip = []
        for n in names:
            p = Path(d) / n
            try:
                if n in SKIP_DIRS or p.is_symlink() or p.resolve() in skill_roots or not (p.is_dir() or p.is_file()):
                    skip.append(n)          # sockets, pipes and links aren't copied
                elif p.is_file():
                    total += p.stat().st_size
                    if total > MAX_COPY:
                        skip.append(n)
                        left_out += 1
            except OSError:
                skip.append(n)
        return skip
    try:
        shutil.copytree(folder, dest, ignore=ignore, dirs_exist_ok=True)
    except shutil.Error:
        pass                                # some files couldn't be read: scan the rest
    return left_out


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
    copy = work / f'plugin-{re.sub(r"[^A-Za-z0-9_.-]", "_", label)}'
    n = 2
    while copy.exists():                    # two plugins whose labels clean up the same way
        copy, n = copy.with_name(f'{copy.name.rsplit("~", 1)[0]}~{n}'), n + 1
    left_out = _copy_without_skills(folder, copy)
    findings, evidence = [], []
    for event, matcher, command in hooks:
        matched = matcher and matcher != '*'
        # the snippet is part of the finding's fingerprint, so it stays in the source language
        stable_when = EVENTS.get(event, event) + (f'（{matcher}）' if matched else '')  # i18n: keep
        when = (_(text=EVENTS[event]) if event in EVENTS else event) + (_('（{matcher}）', matcher=matcher) if matched else '')
        evidence.append(_('{when}：{command}', when=when, command=command[:160]))
        for rule, severity, title, pattern, what in RULES:
            if pattern.search(command):
                findings.append(Finding(scanner=SCANNER, title=_(text=title), what=_(text=what), tip=_(text=TIP),
                                        severity=severity, file=HOOKS_FILE, rule=rule, category='hook',
                                        snippet=f'{stable_when}\n{command[:600]}', detail=f'{rule}: {event} hook'))
    caps = [c for c in capabilities.analyze(copy) if c['id'] not in ('text', 'autorun' if hooks else '')]
    if hooks:
        caps.insert(0, {'id': 'autorun', 'icon': '⚡', 'label': _('自動執行 {n} 個指令', n=len(hooks)),
                        'what': _('Claude Code 會在這些時候自己執行這些指令，不用你叫它。'), 'evidence':
                        [{'file': '', 'line': None, 'text': t} for t in evidence[:12]]})
    if commands or agents:
        parts = [_('指令 {n} 個', n=len(commands)) if commands else '', _('代理 {n} 個', n=len(agents)) if agents else '']
        caps.append({'id': 'prompts', 'icon': '💬', 'label': i18n.join(x for x in parts if x),
                     'what': _('外掛附帶的斜線指令和代理，Claude 會照著裡面的文字做事。'),
                     'evidence': [{'file': '', 'line': None, 'text': i18n.join((['/' + c for c in commands] + agents)[:20])}]})
    severities = {f.severity for f in findings}
    verdict = 'DO_NOT_INSTALL' if 'CRITICAL' in severities else 'CAUTION' if 'HIGH' in severities else 'SAFE'
    note = (_('這是外掛裡技能以外的部分：自動執行的 hooks、斜線指令、代理和它們用到的程式。')
            + (_('指令和代理的文字內容只列出名字，還沒有用 SkillSpector／Cisco 檢查。') if commands or agents else '')
            + (_('外掛太大，有 {n} 個檔案沒有被程式掃描工具檢查到。', n=left_out) if left_out else ''))
    result = SkillResult(_('{name}（外掛的 hooks、指令和程式）', name=name), str(folder), kind='plugin', key=f'plugin:{label.split(" ")[0]}',
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
        except Exception as err:            # say so rather than leave the plugin out without a word
            found = (SkillResult(_('{name}（外掛的 hooks、指令和程式）', name=name), str(folder), kind='plugin',
                                 key=f'plugin:{label.split(" ")[0]}',
                                 outcomes=[Outcome(SCANNER, 'ERROR', error=_('讀不了這個外掛：{err}', err=f'{type(err).__name__}: {err}'))]),
                     None)
        if found:
            out.append(found)
    return out
