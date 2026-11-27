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

from . import i18n
from .i18n import N_, _
from .model import Finding, Outcome

SCANNER = 'argus-files'
SCANNER_NAME = N_('Argus 檔案檢查')      # translated where it's shown
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
MAX_FILES = 5000
BINARY_EXT = {'.so', '.dylib', '.dll', '.exe', '.bin', '.node', '.wasm', '.app', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.jar',
              '.class', '.o', '.a', '.lib'}
ARCHIVE_EXT = {'.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.whl', '.egg'}
# the kinds are only tested for being there, never shown
MAGIC = {b'\x7fELF': 'Linux 程式', b'MZ': 'Windows 程式', b'\xcf\xfa\xed\xfe': 'Mac 程式', b'\xce\xfa\xed\xfe': 'Mac 程式',  # i18n: keep
         b'\xca\xfe\xba\xbe': 'Mac 程式', b'\xfe\xed\xfa\xcf': 'Mac 程式'}  # i18n: keep
LOCKS = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'}
PINNED_REQ = re.compile(r'^\s*[A-Za-z0-9._\[\],-]+\s*===?\s*[\w.*+!-]+')


def _files(folder: Path, cut):
    count = 0
    for d, dirs, files in os.walk(folder):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for name in files:
            count += 1
            if count > MAX_FILES:
                cut.append(True)
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
    """Never raises: an odd file shouldn't stop the whole scan."""
    try:
        return _check(Path(folder))
    except Exception as err:
        return Outcome(SCANNER, 'ERROR', error=f'{type(err).__name__}: {err}')


def _check(folder: Path) -> Outcome:
    unreadable, archives, findings = [], [], []
    package_json, has_lock, cut = [], set(), []
    for path in _files(folder, cut):
        rel = path.relative_to(folder).as_posix()
        name, ext = path.name.lower(), path.suffix.lower()
        if name in LOCKS:
            has_lock.add(path.parent)
        if name == 'package.json':
            package_json.append(path)
        if name.startswith('requirements') and ext == '.txt':
            loose = _loose_requirements(path)
            if loose:
                names = i18n.join(loose[:5])
                findings.append(Finding(
                    scanner=SCANNER, title=_('套件沒有鎖定版本'), severity='LOW', file=rel, rule='UNPINNED-PYTHON',
                    what=_('{names} 等沒有寫明版本，安裝時會抓最新版。', names=names) if len(loose) > 5
                    else _('{names}沒有寫明版本，安裝時會抓最新版。', names=names),
                    tip=_('套件作者發佈的新版有問題時，這個技能也會跟著受影響；OSV-Scanner 也沒辦法檢查沒寫版本的套件。'),
                    calm=_('只是提醒，不是找到問題。')))
        kind = 'compiled' if ext in BINARY_EXT else 'archive' if ext in ARCHIVE_EXT else ''
        if not kind and ext not in {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.ttf', '.otf', '.woff', '.woff2'}:
            kind = 'compiled' if _magic(path) else ''
        if kind == 'compiled':
            unreadable.append(rel)
        elif kind == 'archive':
            archives.append(rel)
    for path in package_json:
        try:
            data = json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError):
            continue
        deps = {}
        for key in ('dependencies', 'optionalDependencies'):
            value = data.get(key) if isinstance(data, dict) else None
            if isinstance(value, dict):
                deps.update(value)
        if deps and path.parent not in has_lock:
            findings.append(Finding(
                scanner=SCANNER, title=_('套件沒有鎖定版本'), severity='LOW', file=path.relative_to(folder).as_posix(),
                rule='UNPINNED-NODE',
                what=_('用到 {n} 個套件，但沒有附上鎖定版本的清單（package-lock.json 之類），安裝時會抓最新版。', n=len(deps)),
                tip=_('套件作者發佈的新版有問題時，這個技能也會跟著受影響；OSV-Scanner 也沒辦法檢查沒寫版本的套件。'),
                calm=_('只是提醒，不是找到問題。')))
    # file= is part of the finding's fingerprint, so the list is joined the same way in every language
    if unreadable:
        files = '；'.join(unreadable[:8]) + (' 等' if len(unreadable) > 8 else '')  # i18n: keep
        findings.insert(0, Finding(
            scanner=SCANNER, title=_('附帶看不到內容的程式'), severity='MEDIUM', file=files, rule='UNREADABLE-BINARY',
            what=_('技能裡有 {n} 個編譯過的程式或程式庫。掃描工具都讀不了這種檔案，裡面做了什麼沒有被檢查到。', n=len(unreadable)),
            tip=_('一般技能用不到這種檔案。確定是知名工具附帶的（例如官方的轉檔程式）再用；來路不明的，先不要裝。')))
    if archives:
        files = '；'.join(archives[:8]) + (' 等' if len(archives) > 8 else '')  # i18n: keep
        findings.append(Finding(
            scanner=SCANNER, title=_('附帶壓縮檔'), severity='LOW', file=files,
            rule='ARCHIVE', what=_('技能裡有 {n} 個壓縮檔，裡面的內容沒有被檢查到。', n=len(archives)),
            tip=_('看技能說明有沒有交代這些壓縮檔是做什麼的；技能如果會自己解開並執行裡面的東西，要特別小心。')))
    real = [f for f in findings if not f.calm]
    note = _('檔案超過 {n} 個，只看了前 {n} 個。', n=MAX_FILES) if cut else ''
    return Outcome(SCANNER, 'CAUTION' if any(f.severity == 'MEDIUM' for f in real) else 'SAFE', findings, note=note)


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
            loose.append(re.split(r'[<>=!~;\s\[]', line, maxsplit=1)[0])
    return loose
