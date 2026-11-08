"""New versions of Argus: notice them, and update in place with one click.

The check asks GitHub for the latest published release each time Argus starts, and again when the person presses
檢查更新. Only a plain request for the release information is sent, nothing about the person's skills or reports.
When GitHub can't be reached, the last answer is used, or no notice is shown.

Updating downloads that release's zip for this system (Argus-mac-… or Argus-win-…) from this project's own GitHub
releases, checks it really is a newer Argus, swaps it in for the running copy (keeping the old one to roll back
to), and reopens. On a Mac the copy is Argus.app; on Windows it's the Argus folder holding Argus.cmd and app\.
"""

import json
import os
import re
import shutil
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

from . import VERSION, tools

REPO = 'squaresu/argus'
API = f'https://api.github.com/repos/{REPO}/releases/latest'
RELEASES = f'https://github.com/{REPO}/releases/latest'
DOWNLOADS = f'https://github.com/{REPO}/releases/download/'
MAX_ZIP = 50 * 1024 * 1024

APP_ID = 'local.argus.skill-scanner'   # in the Mac Info.plist and the Windows app\argus-app.id


def asset_pattern():
    return re.compile(r'^Argus-%s-[\d.]+\.zip$' % ('win' if tools.IS_WIN else 'mac'))


_result = {'checked': False, 'failed': False, 'latest': '', 'url': RELEASES, 'asset': '', 'newer': False, 'auto': False, 'why_manual': ''}


class UpdateError(Exception):
    """Shown to the person as is."""


def version_tuple(text):
    """'v2.0.10' → (2, 0, 10); anything unparsable → ()."""
    m = re.search(r'(\d+(?:\.\d+)*)', text or '')
    return tuple(int(x) for x in m.group(1).split('.')) if m else ()


def is_newer(latest, current=VERSION):
    a, b = version_tuple(latest), version_tuple(current)
    return bool(a and b and a > b)


def fetch():
    req = urllib.request.Request(API, headers={'Accept': 'application/vnd.github+json', 'User-Agent': f'Argus/{VERSION}'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    pattern = asset_pattern()
    asset = next((a.get('browser_download_url') for a in data.get('assets') or [] if pattern.match(a.get('name') or '')), '')
    return (data.get('tag_name') or '').lstrip('vV'), data.get('html_url') or RELEASES, asset or ''


def is_argus_copy(path: Path):
    """An installed Argus: Argus.app on a Mac, or the Windows folder with Argus.cmd and app\."""
    return path.suffix == '.app' or ((path / 'Argus.cmd').is_file() and (path / 'app').is_dir())


def app_bundle():
    """The installed copy of Argus this code is running from, or None (e.g. run from source)."""
    for parent in Path(__file__).resolve().parents:
        if is_argus_copy(parent):
            return parent
    return None


def why_manual(app=None):
    """Why a one-click update can't work here, or ''."""
    app = app or app_bundle()
    if not (tools.IS_MAC or tools.IS_WIN) or app is None:
        return '這個版本的 Argus 不能自動更新，請手動下載新版。'
    if tools.IS_MAC and ('AppTranslocation' in str(app) or not os.access(app.parent, os.W_OK)):
        return 'Argus 不在「應用程式」資料夾裡（或沒有權限修改），沒辦法自動更新。請先把 Argus 拖到「應用程式」資料夾，或手動下載新版。'
    if tools.IS_WIN and not os.access(app.parent, os.W_OK):
        return 'Argus 放在沒有權限修改的資料夾裡，沒辦法自動更新。請把 Argus 資料夾搬到「文件」之類的地方，或手動下載新版。'
    return ''


def check(fetcher=None):
    """Ask GitHub now. (Reusing an hours-old answer once hid a release published in between, so the saved answer
    is only a fallback for when GitHub can't be reached.)"""
    fetcher = fetcher or fetch
    cache = tools.state_dir() / 'update.json'
    try:
        latest, url, asset = fetcher()
        try:
            cache.write_text(json.dumps({'at': time.time(), 'latest': latest, 'url': url, 'asset': asset}),
                             encoding='utf-8')
        except OSError:
            pass
    except Exception:
        try:
            saved = json.loads(cache.read_text(encoding='utf-8'))
            latest, url, asset = saved['latest'], saved.get('url') or RELEASES, saved.get('asset') or ''
        except (OSError, ValueError, KeyError):
            _result.update(checked=True, failed=True)   # offline and nothing saved: no notice
            return _result
    reason = why_manual() if asset else '這次的發佈沒有附上這個系統用的 zip，請手動下載。'
    _result.update(checked=True, failed=False, latest=latest, url=url, asset=asset, newer=is_newer(latest),
                   auto=not reason, why_manual=reason)
    return _result


def status():
    return dict(_result)


# --- updating in place ---

def download(url, dest: Path):
    if not url.startswith(DOWNLOADS):
        raise UpdateError('更新檔不是來自 Argus 官方的 GitHub 發佈頁，已經停止。')
    req = urllib.request.Request(url, headers={'User-Agent': f'Argus/{VERSION}'})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, dest.open('wb') as out:
            size = 0
            while chunk := resp.read(1 << 20):
                size += len(chunk)
                if size > MAX_ZIP:
                    raise UpdateError('更新檔大得不合理，已經停止。')
                out.write(chunk)
    except UpdateError:
        raise
    except Exception as err:
        raise UpdateError(f'下載新版失敗，請檢查網路後再試。（{err}）')


def unpack(zip_path: Path, dest: Path):
    """Unzip safely, keeping the files' permissions (the launcher must stay executable)."""
    root = dest.resolve()
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                target = (dest / info.filename).resolve()
                if not target.is_relative_to(root):
                    raise UpdateError('更新檔裡有不正常的路徑，已經停止。')
                if info.filename.startswith('__MACOSX/'):
                    continue
                zf.extract(info, dest)
                mode = (info.external_attr >> 16) & 0o777
                if mode and not info.is_dir():
                    os.chmod(target, mode)
    except zipfile.BadZipFile:
        raise UpdateError('下載的更新檔壞掉了，請再試一次。')
    apps = [p for p in dest.iterdir() if p.is_dir() and is_argus_copy(p)]
    if len(apps) != 1:
        raise UpdateError('更新檔裡找不到 Argus，已經停止。')
    return apps[0]


def verify(new_app: Path, version):
    """The download must be an Argus for this system, of exactly the advertised, newer version."""
    if tools.IS_WIN:
        run = new_app / 'app' / 'launch.ps1'
        init = new_app / 'app' / 'core' / 'argus' / '__init__.py'
        ident = new_app / 'app' / 'argus-app.id'
    else:
        run = new_app / 'Contents' / 'MacOS' / 'run'
        init = new_app / 'Contents' / 'Resources' / 'core' / 'argus' / '__init__.py'
        ident = new_app / 'Contents' / 'Info.plist'
    if not (run.is_file() and init.is_file() and ident.is_file()):
        raise UpdateError('更新檔的內容不完整，已經停止。')
    if APP_ID not in ident.read_text(encoding='utf-8', errors='replace'):
        raise UpdateError('更新檔不是 Argus，已經停止。')
    m = re.search(r"^VERSION = '([^']+)'", init.read_text(encoding='utf-8'), re.M)
    found = m.group(1) if m else ''
    if found != version or not is_newer(found):
        raise UpdateError(f'更新檔的版本（{found or "不明"}）跟預期的 {version} 不一樣，已經停止。')
    os.chmod(run, 0o755)


def swap(app: Path, new_app: Path):
    """Put new_app where app is; the old one goes to Argus's folder so it can be put back."""
    staged = app.parent / f'.{app.name}-update'
    backup = tools.state_dir() / 'previous' / app.name
    shutil.rmtree(staged, ignore_errors=True)
    shutil.rmtree(backup.parent, ignore_errors=True)
    backup.parent.mkdir(parents=True)
    try:
        shutil.move(str(new_app), str(staged))      # next to the app, so the final step is a quick rename
        shutil.move(str(app), str(backup))
    except OSError as err:
        shutil.rmtree(staged, ignore_errors=True)
        if backup.exists() and not app.exists():
            shutil.move(str(backup), str(app))
        if tools.IS_MAC:
            raise UpdateError('macOS 不讓 Argus 替換自己。請到「系統設定 → 隱私權與安全性 → App 管理」允許 Argus，'
                              f'或手動下載新版。（{err}）')
        raise UpdateError(f'沒辦法替換 Argus 的檔案（可能有檔案正在使用中）。請關掉 Argus 資料夾的視窗後再試，或手動下載新版。（{err}）')
    try:
        os.rename(staged, app)
    except OSError as err:
        shutil.move(str(backup), str(app))         # put the old one back: Argus keeps working as before
        shutil.rmtree(staged, ignore_errors=True)
        raise UpdateError(f'替換失敗，已經還原成原本的版本。（{err}）')


def apply(job, app=None):
    """The update job: download, check, swap. Argus is reopened afterwards by the page (see /api/relaunch)."""
    info = status()
    app = app or app_bundle()
    reason = why_manual(app)
    if reason:
        raise UpdateError(reason)
    if not (info['newer'] and info['asset']):
        raise UpdateError('目前沒有可以安裝的新版本。')
    job.total = 3
    with tempfile.TemporaryDirectory(prefix='argus-update-') as tmp:
        tmp = Path(tmp)
        job.say(f'正在下載 Argus {info["latest"]}…')
        download(info['asset'], tmp / 'update.zip')
        job.done = 1
        job.say('正在確認下載的檔案…')
        new_app = unpack(tmp / 'update.zip', tmp / 'unpacked')
        verify(new_app, info['latest'])
        job.done = 2
        job.say('正在換成新版…')
        swap(app, new_app)
    job.done = 3
    job.result = str(app)
