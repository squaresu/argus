"""Argus's own look at a skill's files, alongside the scanners: what none of them can read, and packages that
aren't pinned to a version.

- Compiled programs and libraries (.so, .dylib, .dll, .exe, Mach-O / ELF files) and archives can't be read by
  any of the scanners, so whatever is in them goes unchecked. A skill rarely needs them; they're flagged.
- A package list without exact versions (package.json without a lock file, requirements.txt without ==) means
  whatever is newest gets installed; OSV-Scanner can't check what it can't pin down. That's a reminder.
"""

import json
import os
import re
from pathlib import Path

from .model import Finding, Outcome

SCANNER = 'argus-files'
SCANNER_NAME = 'Argus 檔案檢查'
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
MAX_FILES = 5000
BINARY_EXT = {'.so', '.dylib', '.dll', '.exe', '.bin', '.node', '.wasm', '.app', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.jar',
              '.class', '.o', '.a', '.lib'}
ARCHIVE_EXT = {'.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.whl', '.egg'}
MAGIC = {b'\x7fELF': 'Linux 程式', b'MZ': 'Windows 程式', b'\xcf\xfa\xed\xfe': 'Mac 程式', b'\xce\xfa\xed\xfe': 'Mac 程式',
         b'\xca\xfe\xba\xbe': 'Mac 程式', b'\xfe\xed\xfa\xcf': 'Mac 程式'}
LOCKS = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'}
PINNED_REQ = re.compile(r'^\s*[A-Za-z0-9._\[\],-]+\s*===?\s*[\w.*+!-]+')


def _files(folder: Path):
    count = 0
    for d, dirs, files in os.walk(folder):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for name in files:
            count += 1
            if count > MAX_FILES:
                return
            yield Path(d) / name


def _magic(path: Path):
    try:
        with path.open('rb') as fh:
            head = fh.read(4)
    except OSError:
        return ''
    return next((kind for sig, kind in MAGIC.items() if head.startswith(sig)), '')


def check(folder: Path) -> Outcome:
    folder = Path(folder)
    unreadable, archives, findings = [], [], []
    package_json, has_lock = [], set()
    for path in _files(folder):
        rel = path.relative_to(folder).as_posix()
        name, ext = path.name.lower(), path.suffix.lower()
        if name in LOCKS:
            has_lock.add(path.parent)
        if name == 'package.json':
            package_json.append(path)
        if name.startswith('requirements') and ext == '.txt':
            loose = _loose_requirements(path)
            if loose:
                findings.append(Finding(
                    scanner=SCANNER, title='套件沒有鎖定版本', severity='LOW', file=rel, rule='UNPINNED-PYTHON',
                    what=f'{"、".join(loose[:5])}{" 等" if len(loose) > 5 else ""}沒有寫明版本，安裝時會抓最新版。',
                    tip='套件作者發佈的新版有問題時，這個技能也會跟著受影響；OSV-Scanner 也沒辦法檢查沒寫版本的套件。',
                    calm='只是提醒，不是找到問題。'))
        kind = 'compiled' if ext in BINARY_EXT else 'archive' if ext in ARCHIVE_EXT else ''
        if not kind and ext not in {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.ttf', '.otf', '.woff', '.woff2'}:
            kind = 'compiled' if _magic(path) else ''
        if kind == 'compiled':
            unreadable.append(rel)
        elif kind == 'archive':
            archives.append(rel)
    for path in package_json:
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        deps = {**(data.get('dependencies') or {}), **(data.get('optionalDependencies') or {})} if isinstance(data, dict) else {}
        if deps and path.parent not in has_lock:
            findings.append(Finding(
                scanner=SCANNER, title='套件沒有鎖定版本', severity='LOW', file=path.relative_to(folder).as_posix(),
                rule='UNPINNED-NODE', what=f'用到 {len(deps)} 個套件，但沒有附上鎖定版本的清單（package-lock.json 之類），安裝時會抓最新版。',
                tip='套件作者發佈的新版有問題時，這個技能也會跟著受影響；OSV-Scanner 也沒辦法檢查沒寫版本的套件。',
                calm='只是提醒，不是找到問題。'))
    if unreadable:
        findings.insert(0, Finding(
            scanner=SCANNER, title='附帶看不到內容的程式', severity='MEDIUM', file='；'.join(unreadable[:8]) + (' 等' if len(unreadable) > 8 else ''),
            rule='UNREADABLE-BINARY',
            what=f'技能裡有 {len(unreadable)} 個編譯過的程式或程式庫。掃描工具都讀不了這種檔案，裡面做了什麼沒有被檢查到。',
            tip='一般技能用不到這種檔案。確定是知名工具附帶的（例如官方的轉檔程式）再用；來路不明的，先不要裝。'))
    if archives:
        findings.append(Finding(
            scanner=SCANNER, title='附帶壓縮檔', severity='LOW', file='；'.join(archives[:8]) + (' 等' if len(archives) > 8 else ''),
            rule='ARCHIVE', what=f'技能裡有 {len(archives)} 個壓縮檔，裡面的內容沒有被檢查到。',
            tip='看技能說明有沒有交代這些壓縮檔是做什麼的；技能如果會自己解開並執行裡面的東西，要特別小心。'))
    real = [f for f in findings if not f.calm]
    return Outcome(SCANNER, 'CAUTION' if any(f.severity == 'MEDIUM' for f in real) else 'SAFE', findings)


def _loose_requirements(path: Path):
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []
    loose = []
    for line in lines:
        line = line.split('#', 1)[0].strip()
        if not line or line.startswith(('-', 'git+', 'http')):
            continue
        if not PINNED_REQ.match(line):
            loose.append(re.split(r'[<>=!~;\s\[]', line, 1)[0])
    return loose
