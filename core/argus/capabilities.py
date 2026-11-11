"""What a skill can do, read straight from its files: network, running programs, writing files, secrets, ...

Argus works this out itself instead of from the scanners' findings, so it reads the same however many scanners
ran. Only what can take effect counts: the skill's own programs, SKILL.md (the AI follows it), and hook or
settings files. READMEs and the references/examples documents are left out, since they describe or illustrate.
"""

import re
from pathlib import Path

from .model import CODE_EXT, is_documentation, is_type_definitions

MAX_BYTES = 1_000_000
MAX_FILES = 3000
MAX_EVIDENCE = 3
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
SCRIPT_EXT = CODE_EXT | {'.ps1', '.bat', '.cmd', '.bash', '.zsh'}

# (id, icon, label, what it means)
KINDS = [
    ('network', '🌐', '連網', '會連到網路上的服務或下載東西。'),
    ('exec', '⚙️', '執行程式', '會在你的電腦上執行程式或指令。'),
    ('write', '📁', '寫入或刪除檔案', '會建立、修改或刪除你電腦上的檔案。'),
    ('secrets', '🔑', '碰觸機密或 Claude 設定', '會讀取環境變數、金鑰、.env 檔或 Claude 的設定資料夾。'),
    ('autorun', '⚡', '自動執行', '附帶 hooks 或設定，會在特定時機自動執行，不用你叫它。'),
    ('install', '📦', '安裝套件', '會安裝其他程式或套件。'),
]
TEXT_ONLY = {'id': 'text', 'icon': '📄', 'label': '只有文字說明', 'what': '沒有附帶程式，也沒有要求 AI 連網、執行指令或改檔案。',
             'evidence': []}

CODE_PATTERNS = {
    'network': re.compile(r'urllib\.request|urlopen\(|\brequests\.(get|post|put|patch|delete|request|Session)\b|\bhttpx\.|'
                          r'http\.client|aiohttp|\bfetch\(|\baxios\b|XMLHttpRequest|new WebSocket|socket\.socket|'
                          r'\bcurl\s+-|\bcurl\s+https?:|\bwget\s|Invoke-WebRequest|Invoke-RestMethod|smtplib'),
    'exec': re.compile(r'\bsubprocess\.|os\.system\(|os\.popen\(|\bexecSync\(|\bexecFileSync\(|\bspawn\(|'
                       r'child_process|(?<![.\w])exec\(|Start-Process'),
    'write': re.compile(r'''open\([^)\n]*['"](w|a|x|wb|ab|w\+|a\+)['"]|\.write_text\(|\.write_bytes\(|writeFile|'''
                        r'''fs\.(write|unlink|rm|mkdir|rename)|shutil\.(rmtree|move|copy)|os\.(remove|unlink|rename|makedirs)|'''
                        r'''\.unlink\(|\brm\s+-[rf]|\bmkdir\s|Remove-Item|Set-Content|Out-File'''),
    # reading secrets, not merely naming something TOKEN
    'secrets': re.compile(r'\.claude/|\.claude\\|~/\.ssh|\.aws/credentials|(^|[/\s\'"])\.env\b|os\.environ|process\.env|'
                          r'getenv\(|\$env:|keychain|find-generic-password'),
    'install': re.compile(r'\bpip3?\s+install\b|\buv\s+(pip|tool|add)\b|\bnpm\s+(i|install)\b|\bnpx\s|\byarn\s+add\b|'
                          r'\bpnpm\s+(add|install)\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bgo\s+install\b|'
                          r'\bcargo\s+install\b|\bwinget\s+install\b'),
}
# in SKILL.md, only instructions count (code blocks and tool permissions), not ordinary prose about a topic
SKILL_PATTERNS = {
    'network': re.compile(r'\b(WebFetch|WebSearch)\b|\bcurl\s|\bwget\s|Invoke-WebRequest'),
    'exec': re.compile(r'```(bash|sh|shell|zsh|console|powershell|ps1)\b|\bBash\(|allowed-tools:.*\bBash\b'),
    'write': re.compile(r'allowed-tools:.*\b(Write|Edit|MultiEdit)\b|\brm\s+-[rf]|\bmkdir\s'),
    # in instructions, telling the AI to use a key by name also counts
    'secrets': re.compile(CODE_PATTERNS['secrets'].pattern + r'|\b[A-Z0-9]+_(API_KEY|SECRET|TOKEN|PASSWORD)\b'),
    'install': CODE_PATTERNS['install'],
}
COMMENT = re.compile(r'^\s*(#|//|\*|/\*|<!--|rem\s|::)', re.I)
DEPENDENCY_FILES = {'requirements.txt', 'package.json', 'pyproject.toml', 'pipfile', 'go.mod', 'cargo.toml', 'gemfile'}


def _files(folder: Path):
    count = 0
    stack = [folder]
    while stack and count < MAX_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir() and not e.is_symlink():
                if e.name not in SKIP_DIRS:
                    stack.append(e)
            elif e.is_file():
                count += 1
                yield e


def _read(path: Path):
    try:
        if path.stat().st_size > MAX_BYTES:
            return ''
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def analyze(folder: Path):
    """→ list of {id, icon, label, what, evidence: [{file, line, text}]}, in KINDS order; TEXT_ONLY when nothing."""
    found = {k[0]: [] for k in KINDS}

    def note(kind, rel, line_no, text):
        if len(found[kind]) < MAX_EVIDENCE:
            found[kind].append({'file': rel, 'line': line_no, 'text': text.strip()[:160]})

    scripts = 0
    for f in _files(folder):
        rel = f.relative_to(folder).as_posix()
        name, ext = f.name.lower(), f.suffix.lower()
        if is_type_definitions(rel) or is_documentation(rel):
            continue
        if name in DEPENDENCY_FILES:
            note('install', rel, None, f'附帶 {f.name}，執行前通常要先安裝裡面列的套件')
        if name in ('hooks.json', 'settings.json', 'settings.local.json') or rel.startswith('hooks/'):
            text = _read(f)
            if '"hooks"' in text or rel.startswith('hooks/') or '"command"' in text:
                note('autorun', rel, None, '附帶 hooks 設定，會在 Claude 的特定時機自動執行指令')
        if ext in SCRIPT_EXT:
            scripts += 1
            patterns = CODE_PATTERNS
        elif name == 'skill.md':
            patterns = SKILL_PATTERNS
        else:
            continue
        for n, line in enumerate(_read(f).splitlines(), 1):
            if patterns is CODE_PATTERNS and COMMENT.match(line):
                continue
            for kind, pattern in patterns.items():
                if pattern.search(line):
                    note(kind, rel, n, line)
    if scripts:
        found['exec'].insert(0, {'file': '', 'line': None, 'text': f'附帶 {scripts} 個程式檔'})
        del found['exec'][MAX_EVIDENCE:]
    caps = [{'id': k, 'icon': icon, 'label': label, 'what': what, 'evidence': found[k]}
            for k, icon, label, what in KINDS if found[k]]
    return caps or [dict(TEXT_ONLY)]
