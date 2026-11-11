"""OSV-Scanner (Google): checks the packages a skill depends on against OSV.dev's database of known problems.

It reads lists that name exact versions (package-lock.json, requirements.txt with ==, uv.lock, …) and asks
OSV.dev about those package names and versions. Only names and versions are sent, never the skill's files.
OSV.dev also lists packages reported as malicious (ids starting MAL-), which is the case that matters most.

OSV-Scanner is a single program rather than a Python package, so it is downloaded from Google's GitHub
releases into the same folder uv uses, after checking it against the release's published SHA-256 sums.
"""

import hashlib
import json
import os
import platform
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .. import VERSION, tools
from ..model import Finding, Outcome
from .base import Scanner, failed

RELEASES = 'https://github.com/google/osv-scanner/releases'
FALLBACK_VERSION = '2.7.1'   # used when GitHub doesn't say which release is the latest
MAX_BINARY = 200 * 1024 * 1024
# files that name exact package versions; a package.json or a requirements.txt without == pins nothing
LOCKFILES = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'poetry.lock',
             'pipfile.lock', 'uv.lock', 'pdm.lock', 'pylock.toml', 'cargo.lock', 'go.mod', 'gemfile.lock',
             'composer.lock', 'pubspec.lock', 'mix.lock', 'packages.lock.json', 'gradle.lockfile', 'pom.xml'}
REQUIREMENTS = re.compile(r'^requirements[\w.-]*\.txt$', re.I)
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
TIP = ('套件有漏洞不代表技能有惡意，只表示它用的某個套件版本比較舊。影響大小要看技能有沒有用到出問題的那部分；'
       '技能作者升級到修好的版本就能解決。')


def exe_name():
    return 'osv-scanner.exe' if tools.IS_WIN else 'osv-scanner'


def asset_name():
    system = 'windows' if tools.IS_WIN else 'darwin' if tools.IS_MAC else 'linux'
    arch = 'arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'amd64'
    return f'osv-scanner_{system}_{arch}' + ('.exe' if tools.IS_WIN else '')


def _get(url, limit):
    """Download url (following GitHub's redirects to its file storage), with the system curl as a fallback on a
    company network whose security gateway Python's certificates don't cover."""
    from .. import updates
    req = urllib.request.Request(url, headers={'User-Agent': f'Argus/{VERSION}'})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read(limit + 1)
    except urllib.error.URLError as err:
        if not updates.is_certificate_error(err):
            raise
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'download'
            p = updates._curl(['-fL', '-o', str(out), url], 300)
            if p.returncode != 0:
                raise
            data = out.read_bytes()
    if len(data) > limit:
        raise OSError('下載的檔案大小不對')
    return data


def latest_version():
    from .. import updates
    try:
        m = re.search(r'/releases/tag/v?(2\.[\d.]+)$', updates.location(f'{RELEASES}/latest'))
    except Exception:
        m = None
    return m.group(1) if m else FALLBACK_VERSION


def install_binary():
    """Download OSV-Scanner, check its SHA-256 against the release's list, put it next to the uv tools."""
    version = latest_version()
    name = asset_name()
    base = f'{RELEASES}/download/v{version}/'
    sums = _get(base + 'osv-scanner_SHA256SUMS', 1 << 20).decode('utf-8', 'replace')
    expected = next((line.split()[0] for line in sums.splitlines() if line.strip().endswith(' ' + name)), '')
    if not expected:
        raise OSError(f'OSV-Scanner {version} 沒有這台電腦能用的版本（{name}）。')
    data = _get(base + name, MAX_BINARY)
    if hashlib.sha256(data).hexdigest() != expected.lower():
        raise OSError('下載的 OSV-Scanner 跟官方公布的檢查碼不符，已經停止安裝。')
    tools.TOOL_BIN.mkdir(parents=True, exist_ok=True)
    dest = tools.TOOL_BIN / exe_name()
    tmp = dest.with_name(dest.name + '.part')
    tmp.write_bytes(data)
    os.chmod(tmp, 0o755)
    os.replace(tmp, dest)
    return version


def severity_of(score):
    """OSV-Scanner's max_severity is a CVSS score as text, or '' when the advisory gives none."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return 'MEDIUM'
    return 'CRITICAL' if s >= 9 else 'HIGH' if s >= 7 else 'MEDIUM' if s >= 4 else 'LOW'


def fixed_version(vulns, ids, package):
    for v in vulns:
        if v.get('id') not in ids:
            continue
        for a in v.get('affected') or []:
            if (a.get('package') or {}).get('name') != package:
                continue
            for r in a.get('ranges') or []:
                for ev in r.get('events') or []:
                    if ev.get('fixed'):
                        return ev['fixed']
    return ''


def parse(data, root='') -> Outcome:
    findings = []
    root = str(root).rstrip('/\\')
    for res in data.get('results') or []:
        path = ((res.get('source') or {}).get('path') or '')
        if root and path.startswith(root):
            path = path[len(root):].lstrip('/\\')
        for p in res.get('packages') or []:
            pkg = p.get('package') or {}
            name, version, eco = pkg.get('name', ''), pkg.get('version', ''), pkg.get('ecosystem', '')
            vulns = p.get('vulnerabilities') or []
            for g in p.get('groups') or []:
                ids = g.get('ids') or []
                names = [i for i in (g.get('aliases') or ids) if i.startswith('CVE-')] or ids
                summary = next((v.get('summary') or v.get('details', '') for v in vulns if v.get('id') in ids), '')
                fixed = fixed_version(vulns, ids, name)
                if any(i.startswith('MAL-') for i in ids):
                    f = Finding(scanner='osv', title='用到被通報為惡意的套件', severity='CRITICAL', file=path,
                                what=f'{name} {version}（{eco}）被列在 OSV.dev 的惡意套件清單裡，裝了它就可能執行有害的程式。',
                                tip='不要安裝這個技能，除非作者已經換掉這個套件。', rule=ids[0], category='malicious-package',
                                snippet=f'{name} {version}', detail=f'osv: {summary[:300]}')
                else:
                    f = Finding(scanner='osv', title='套件有已知漏洞', severity=severity_of(g.get('max_severity')),
                                file=path, what=f'{name} {version}（{eco}）有已知漏洞：{"、".join(names[:3])}。'
                                + (f'修好的版本是 {fixed}。' if fixed else '目前還沒有修好的版本。'),
                                tip=TIP, rule=ids[0] if ids else '', category='known-vulnerability',
                                snippet=f'{name} {version}', detail=f'osv: {summary[:300]}')
                findings.append(f)
    if any(f.category == 'malicious-package' for f in findings):
        verdict = 'DO_NOT_INSTALL'
    elif any(f.severity in ('CRITICAL', 'HIGH') for f in findings):
        verdict = 'CAUTION'
    else:
        verdict = 'SAFE'
    return Outcome('osv', verdict, findings)


def has_lockfile(skill_dir: Path, limit=5000):
    for i, (d, dirs, files) in enumerate(os.walk(skill_dir)):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        if i > limit:
            break
        if any(f.lower() in LOCKFILES or REQUIREMENTS.match(f) for f in files):
            return True
    return False


class OsvScanner(Scanner):
    id = 'osv'
    name = 'OSV-Scanner'
    vendor = 'Google'
    license = 'Apache-2.0'
    homepage = 'https://github.com/google/osv-scanner'
    summary = '檢查技能用到的套件有沒有已知漏洞或被通報為惡意。會把套件名稱和版本送到 OSV.dev 查詢（不會送出技能內容）。'
    order = 50
    exe = 'osv-scanner'
    needs_uv = False

    def version(self):
        return super().version().removeprefix('osv-scanner version:').strip()

    def install(self, uv):
        try:
            version = install_binary()
        except Exception as err:
            from .. import updates
            reason = updates.why_failed(err) if isinstance(err, urllib.error.URLError) else str(err)
            return 1, '', reason
        return 0, f'OSV-Scanner {version}', ''

    def applies_to(self, skill_dir):
        return has_lockfile(skill_dir)

    def scan(self, skill_dir, work):
        code, out, err = tools.run([tools.find_exe(self.exe), 'scan', 'source', '-r', '--no-resolve', '--format', 'json',
                                    '--experimental-exclude', 'node_modules', '.'], cwd=skill_dir, timeout=600)
        if code == 128:
            return Outcome(self.id, 'SKIPPED', note='OSV-Scanner：沒有找到寫明版本的套件清單。')
        try:
            data = json.loads(out)
        except ValueError:
            if 'osv.dev' in err or 'request failed' in err:
                return failed(self.id, '連不上 OSV.dev（查漏洞的資料庫），請確認網路後再試。')
            return failed(self.id, tools.last_lines(err))
        return parse(data, skill_dir)


SCANNER = OsvScanner()
