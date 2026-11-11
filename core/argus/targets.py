"""Turn what the person picked (their Claude skills, a folder, a zip, a GitHub link) into skill folders to scan."""

import json
import re
import shutil
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from . import VERSION, tools

MAX_DOWNLOAD = 200 * 1024 * 1024
MAX_UNZIPPED = 500 * 1024 * 1024
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
GITHUB = re.compile(r'^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)(?:/(tree|blob)/([^/#?]+)(?:/([^#?]*))?)?')


class TargetError(Exception):
    """A problem the person can fix; the message is shown to them as is."""


def claude_roots():
    """Where this computer's Claude skills live: ~/.claude/skills and each installed, switched-on plugin.
    (~/.claude/plugins also holds every marketplace's whole catalog; those plugins are only on offer.)"""
    return [tools.HOME / '.claude' / 'skills'] + [folder for _, folder in installed_plugins()]


def claude_skills():
    return sorted({s for r in claude_roots() if r.exists() for s in find_skills(r)})


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def installed_plugins(home: Path | None = None):
    """→ [(plugin name, its folder)] for the Claude Code plugins that are installed and not turned off.

    ~/.claude/plugins also holds each marketplace's whole catalog; those plugins are only on offer, so they're skipped.
    """
    home = home or tools.HOME
    root = home / '.claude' / 'plugins'
    record = _load_json(root / 'installed_plugins.json') or {}
    enabled = (_load_json(home / '.claude' / 'settings.json') or {}).get('enabledPlugins') or {}
    found = []
    for ident, entries in (record.get('plugins') or {}).items():
        if enabled.get(ident) is False:                    # installed but turned off: Claude Code doesn't start it
            continue
        for entry in entries if isinstance(entries, list) else [entries]:
            folder = (entry or {}).get('installPath') if isinstance(entry, dict) else None
            if folder and Path(folder).is_dir():
                found.append((ident.split('@')[0], Path(folder)))
    known = any(isinstance(e, dict) and e.get('installPath') for v in (record.get('plugins') or {}).values()
                for e in (v if isinstance(v, list) else [v]))
    if not known and (root / 'cache').is_dir():           # no usable record: what's been downloaded to run
        for f in sorted((root / 'cache').rglob('plugin.json'))[:200]:
            folder = f.parent.parent if f.parent.name == '.claude-plugin' else f.parent
            found.append(((_load_json(f) or {}).get('name') or folder.name, folder))
    seen, unique = set(), []
    for name, folder in found:
        if folder not in seen:
            seen.add(folder)
            unique.append((name, folder))
    return unique


def find_skills(root: Path, max_depth=6):
    """Folders under root that hold a SKILL.md, without descending into .git, node_modules and the like."""
    found = []

    def walk(d: Path, depth):
        try:
            entries = list(d.iterdir())
        except OSError:
            return
        if any(e.name.lower() == 'skill.md' and e.is_file() for e in entries):
            found.append(d)
        if depth < max_depth:
            for e in sorted(entries):
                if e.is_dir() and e.name not in SKIP_DIRS:
                    walk(e, depth + 1)

    walk(root, 0)
    return found


def expand(folder: Path):
    """A folder holding several skills is scanned one skill at a time."""
    if (folder / 'SKILL.md').is_file() or (folder / 'skill.md').is_file():
        return [folder]
    return find_skills(folder) or [folder]


def safe_extract(zip_path: Path, dest: Path):
    """Unzip, refusing entries that would land outside dest and archives that unpack to something huge."""
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise TargetError('這個檔案不是有效的 zip 檔。')
    with zf:
        if sum(i.file_size for i in zf.infolist()) > MAX_UNZIPPED:
            raise TargetError('這個 zip 解開後超過 500 MB，不像是一般的技能，所以沒有解開。')
        root = dest.resolve()
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(root):
                raise TargetError('這個 zip 裡有指向資料夾外面的路徑，可能是惡意檔案，所以沒有解開。')
            if info.filename.startswith('__MACOSX/'):
                continue
            zf.extract(info, dest)
    return dest


def single_folder(d: Path):
    """A zip that holds one top-level folder is really that folder."""
    entries = [e for e in d.iterdir() if e.name not in ('__MACOSX', '.DS_Store')]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else d


def download(url, dest: Path):
    req = urllib.request.Request(url, headers={'User-Agent': f'Argus/{VERSION}'})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, dest.open('wb') as out:
            size = 0
            while chunk := resp.read(1 << 20):
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise TargetError('下載的檔案超過 200 MB，不像是一般的技能，已經停止。')
                out.write(chunk)
    except TargetError:
        raise
    except Exception as err:
        raise TargetError(f'下載失敗，請確認網址正確、而且是公開的 repo。（{err}）')


def github(url, work: Path):
    """Fetch a GitHub link as a zip (so Git isn't needed) and return the folder it points at."""
    m = GITHUB.match(url.strip())
    if not m:
        raise TargetError('目前只支援 GitHub 網址，例如 https://github.com/擁有者/repo。')
    owner, repo, kind, ref, sub = m.groups()
    repo = repo.removesuffix('.git')
    zip_path = work / 'github.zip'
    download(f'https://github.com/{owner}/{repo}/archive/{ref or "HEAD"}.zip', zip_path)
    root = single_folder(safe_extract(zip_path, work / 'github'))
    target = root / urllib.parse.unquote(sub.strip('/')) if sub else root
    if kind == 'blob':          # a link to a file inside the skill: scan its folder
        target = target.parent
    if not target.resolve().is_relative_to(root.resolve()) or not target.exists():
        raise TargetError(f'在下載的內容裡找不到這個路徑：{sub}')
    return target


def resolve(kind, value, work: Path):
    """→ (title for the report, list of skill folders)."""
    if kind == 'claude':
        skills = claude_skills()
        if not skills:
            raise TargetError(f'在 {tools.HOME / ".claude"} 裡找不到任何技能（SKILL.md）。')
        return '我所有的 Claude 技能', skills
    if kind == 'folder':
        p = Path(value or '')
        if not p.is_dir():
            raise TargetError('找不到這個資料夾。')
        return p.name, expand(p)
    if kind == 'zip':
        p = Path(value or '')
        if not p.is_file():
            raise TargetError('找不到這個 zip 檔。')
        return p.name, expand(single_folder(safe_extract(p, work / 'zip')))
    if kind == 'github':
        return value.strip(), expand(github(value, work))
    raise TargetError('不認得的掃描對象。')


def skill_name(folder: Path):
    """The name in SKILL.md's front matter, or the folder name."""
    for name in ('SKILL.md', 'skill.md'):
        try:
            head = (folder / name).read_text(encoding='utf-8', errors='replace')[:4000]
        except OSError:
            continue
        m = re.search(r'^---\s*\n(.*?)\n---', head, re.S)
        if m:
            n = re.search(r'^name:\s*["\']?(.+?)["\']?\s*$', m.group(1), re.M)
            if n:
                return n.group(1).strip()
    return folder.name


def cleanup(work: Path):
    shutil.rmtree(work, ignore_errors=True)
