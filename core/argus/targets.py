"""Turn what the person picked (their Claude skills, a folder, a zip, a GitHub link) into skill folders to scan."""

import json
import re
import shutil
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from . import VERSION, tools
from .i18n import _

MAX_DOWNLOAD = 200 * 1024 * 1024
MAX_UNZIPPED = 500 * 1024 * 1024
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
GITHUB = re.compile(r'^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)(?:/(tree|blob)/([^/#?]+)(?:/([^#?]*))?)?')


class TargetError(Exception):
    """A problem the person can fix; the message is shown to them as is."""


def claude_roots():
    """Where this computer's Claude skills live: ~/.claude/skills, and the skill folders of each installed,
    switched-on plugin. (~/.claude/plugins also holds every marketplace's whole catalog; those plugins are only
    on offer.)"""
    return [tools.HOME / '.claude' / 'skills'] + [r for _name, folder in installed_plugins() for r in plugin_skill_roots(folder)]


def plugin_skill_roots(folder: Path):
    """The folders Claude Code loads a plugin's skills from: skills/, plus any its plugin.json names under
    "skills" (named paths add to the default, they don't replace it). Other folders in a plugin (an alternative
    skill set, examples, tests) are never loaded, so they aren't scanned either."""
    manifest = _load_json(folder / '.claude-plugin' / 'plugin.json') or _load_json(folder / 'plugin.json') or {}
    named = manifest.get('skills') if isinstance(manifest, dict) else None
    paths = [named] if isinstance(named, str) else [p for p in named if isinstance(p, str)] if isinstance(named, list) else []
    roots = [folder / 'skills']
    base = folder.resolve()
    for p in paths:
        root = (folder / p).resolve()
        if root.is_relative_to(base) and root not in {r.resolve() for r in roots}:   # only inside the plugin
            roots.append(root)
    return roots


def claude_skills():
    return sorted({s for r in claude_roots() if r.exists() for s in find_skills(r)})


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return None


def installed_plugins(home: Path | None = None):
    """→ [(plugin name, its folder)] for the Claude Code plugins that are installed and not turned off."""
    return [(name, folder) for name, folder, _label in plugins_with_labels(home)]


def plugins_with_labels(home: Path | None = None):
    """→ [(plugin name, its folder, label)]; the label says which plugin and version, e.g. figma@claude-plugins-official
    1.4.0, so two copies of the same skill can be told apart.

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
        entries = [e for e in (entries if isinstance(entries, list) else [entries])
                   if isinstance(e, dict) and e.get('installPath') and Path(e['installPath']).is_dir()]
        if entries:   # one copy per plugin: the most recently installed or updated
            newest = max(entries, key=lambda e: str(e.get('lastUpdated') or e.get('installedAt') or ''))
            label = ident + (f" {newest['version']}" if newest.get('version') else '')
            found.append((ident.split('@')[0], Path(newest['installPath']), label))
    known = any(isinstance(e, dict) and e.get('installPath') for v in (record.get('plugins') or {}).values()
                for e in (v if isinstance(v, list) else [v]))
    if not known and (root / 'cache').is_dir():           # no usable record: what's been downloaded to run
        latest = {}   # cache/<marketplace>/<plugin>/<version>: older versions stay behind, keep the newest
        for f in sorted((root / 'cache').rglob('plugin.json'))[:200]:
            folder = f.parent.parent if f.parent.name == '.claude-plugin' else f.parent
            if (folder / '.orphaned_at').exists():   # an old version an update replaced; Claude Code no longer loads it
                continue
            try:
                age = folder.stat().st_mtime
            except OSError:
                continue
            key = folder.parent
            if key not in latest or age > latest[key][2]:
                latest[key] = ((_load_json(f) or {}).get('name') or folder.name, folder, age)
        # cache/<marketplace>/<plugin>/<version>
        found += [(name, folder, f'{name}@{folder.parent.parent.name} {folder.name}') for name, folder, _age in latest.values()]
    seen, unique = set(), []
    for name, folder, label in found:
        if folder not in seen:
            seen.add(folder)
            unique.append((name, folder, label))
    return unique


def skill_source(folder: Path, home: Path | None = None):
    """Where an installed skill comes from: its plugin (and version), or the person's own skills folder."""
    home = home or tools.HOME
    real = folder.resolve()
    for _name, root, label in plugins_with_labels(home):
        try:
            if real.is_relative_to(root.resolve()):
                return label
        except OSError:
            continue
    return _('自己的技能（~/.claude/skills）')


def label_duplicates(results, folders, home: Path | None = None):
    """Two installed skills with the same name (e.g. the same plugin from two marketplaces): add where each one
    comes from to its name in the report, so it's clear which to keep."""
    names = [r.name for r in results]
    for r, folder in zip(results, folders):
        if names.count(r.name) > 1:
            r.duplicate = True
            r.base_name = r.name
            r.name = _('{name}（{source}）', name=r.name, source=skill_source(folder, home))


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
        raise TargetError(_('這個檔案不是有效的 zip 檔。'))
    with zf:
        if sum(i.file_size for i in zf.infolist()) > MAX_UNZIPPED:
            raise TargetError(_('這個 zip 解開後超過 500 MB，不像是一般的技能，所以沒有解開。'))
        root = dest.resolve()
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(root):
                raise TargetError(_('這個 zip 裡有指向資料夾外面的路徑，可能是惡意檔案，所以沒有解開。'))
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
                    raise TargetError(_('下載的檔案超過 200 MB，不像是一般的技能，已經停止。'))
                out.write(chunk)
    except TargetError:
        raise
    except Exception as err:
        failed = TargetError(_('下載失敗，請確認網址正確、而且是公開的 repo。（{err}）', err=err))
        failed.not_found = getattr(err, 'code', None) == 404
        raise failed


def github_title(url):
    """A GitHub link as owner/repo, plus the folder inside it: the report's title, without ?fbclid=… and the like."""
    m = GITHUB.match(url.strip())
    if not m:
        return url.strip()
    owner, repo, _kind, _ref, sub = m.groups()
    return '/'.join(x for x in (owner, repo.removesuffix('.git'), (sub or '').strip('/')) if x)


def github(url, work: Path):
    """Fetch a GitHub link as a zip (so Git isn't needed) and return the folder it points at."""
    m = GITHUB.match(url.strip())
    if not m:
        raise TargetError(_('目前只支援 GitHub 網址，例如 https://github.com/擁有者/repo。'))
    owner, repo, kind, ref, sub = m.groups()
    repo = repo.removesuffix('.git')
    zip_path = work / 'github.zip'
    # a branch name can hold slashes (feature/x): try longer and longer names until GitHub knows one
    parts = [ref] + [p for p in (sub or '').split('/') if p] if ref else ['HEAD']
    for k in range(1, min(len(parts), 6) + 1):
        try:
            download(f'https://github.com/{owner}/{repo}/archive/{"/".join(parts[:k])}.zip', zip_path)
            sub = '/'.join(parts[k:]) if ref else sub
            break
        except TargetError as err:
            if not getattr(err, 'not_found', False) or k == min(len(parts), 6):
                raise
    root = single_folder(safe_extract(zip_path, work / 'github'))
    target = root / urllib.parse.unquote(sub.strip('/')) if sub else root
    if kind == 'blob' and target != root:   # a link to a file inside the skill: scan its folder
        target = target.parent
    if not target.resolve().is_relative_to(root.resolve()) or not target.exists():
        raise TargetError(_('在下載的內容裡找不到這個路徑：{path}', path=sub))
    return target


def resolve(kind, value, work: Path):
    """→ (title for the report, list of skill folders)."""
    if kind == 'claude':
        skills = claude_skills()
        if not skills:
            raise TargetError(_('在 {folder} 裡找不到任何技能（SKILL.md）。', folder=tools.HOME / '.claude'))
        return _('我所有的 Claude 技能'), skills
    if kind == 'folder':
        p = Path(value or '')
        if not p.is_dir():
            raise TargetError(_('找不到這個資料夾。'))
        return p.name, expand(p)
    if kind == 'zip':
        p = Path(value or '')
        if not p.is_file():
            raise TargetError(_('找不到這個 zip 檔。'))
        return p.name, expand(single_folder(safe_extract(p, work / 'zip')))
    if kind == 'github':
        return github_title(value), expand(github(value, work))
    if kind == 'paths':   # given skill folders, already on this computer (the automatic check of new skills)
        if not isinstance(value, list):
            raise TargetError(_('不認得的掃描對象。'))
        folders = [Path(v) for v in value if isinstance(v, str) and v and Path(v).is_dir()]
        if not folders:
            raise TargetError(_('要檢查的技能資料夾都不見了。'))
        return _('新裝或更新的 Claude 技能'), folders
    raise TargetError(_('不認得的掃描對象。'))


def skill_name(folder: Path):
    """The name in SKILL.md's front matter, or the folder name."""
    for name in ('SKILL.md', 'skill.md'):
        try:
            head = (folder / name).read_text(encoding='utf-8-sig', errors='replace')[:4000]
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
