"""Running command-line tools, finding them, and where Argus keeps its files."""

import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

HOME = Path.home()
IS_MAC = sys.platform == 'darwin'
IS_WIN = os.name == 'nt'

# uv puts the tools it installs here on every platform
TOOL_BIN = HOME / '.local' / 'bin'

# the reports folder's name in each language; a folder that already exists is kept, whatever the language now
REPORT_FOLDERS = {
    'zh-TW': 'Argus 報告',  # i18n: keep (a folder name that must stay stable)
    'en': 'Argus Reports',
    'ja': 'Argus レポート',  # i18n: keep (a folder name that must stay stable)
    'ko': 'Argus 보고서',  # i18n: keep (a folder name that must stay stable)
}


def documents_dir():
    if IS_WIN:
        try:
            import ctypes.wintypes
            buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
            ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf)  # 5 = My Documents
            if buf.value:
                return Path(buf.value)
        except Exception:
            pass
    return HOME / 'Documents'


def state_dir():
    if IS_MAC:
        d = HOME / 'Library' / 'Application Support' / 'Argus'
    elif IS_WIN:
        d = Path(os.environ.get('APPDATA', HOME)) / 'Argus'
    else:
        d = HOME / '.local' / 'state' / 'argus'
    d.mkdir(parents=True, exist_ok=True)
    return d


def reports_dir():
    """The reports folder in Documents: the one that's already there ('Argus 報告' first), or else a new one named
    in the language in use."""
    docs = documents_dir()
    for name in REPORT_FOLDERS.values():
        if (docs / name).is_dir():
            return docs / name
    from . import i18n          # not at the top: i18n imports this module
    d = docs / REPORT_FOLDERS.get(i18n.lang(), REPORT_FOLDERS['en'])
    d.mkdir(parents=True, exist_ok=True)
    return d


def report_file(name):
    """A report in the reports folder by its file name → its path, or None for anything else (another folder,
    C:\\…, a drive-relative D:x.html, a name that isn't a report)."""
    name = str(name or '')
    if not name.endswith('.html') or any(c in name for c in '/\\:\0') or name.startswith('.'):
        return None
    f = reports_dir() / name
    return f if f.is_file() else None


def find_exe(name):
    found = shutil.which(name, path=os.pathsep.join([str(TOOL_BIN), os.environ.get('PATH', '')]))
    return found


def child_env():
    env = dict(os.environ)
    env['PATH'] = os.pathsep.join([str(TOOL_BIN), env.get('PATH', '')])
    # no colours or progress bars in captured output, and UTF-8 even on a Chinese-locale Windows
    env.update(PYTHONUTF8='1', PYTHONIOENCODING='utf-8', NO_COLOR='1', TERM='dumb')
    # Semgrep would otherwise contact semgrep.dev to check its own version (and hang when it can't reach it)
    env.update(SEMGREP_ENABLE_VERSION_CHECK='0', SEMGREP_SEND_METRICS='off')
    return env


_running = {}            # program → the scan it belongs to (or None), so 停止檢查 can end that scan's programs
_running_lock = threading.Lock()
_local = threading.local()


def for_job(job):
    """Programs run() starts from this thread belong to job (a scan), until for_job(None)."""
    _local.job = job


def run(cmd, timeout=900, cwd=None):
    """Run a command; return (exit code, stdout, stderr). A command that can't start, times out or is stopped
    gives code -1."""
    job = getattr(_local, 'job', None)
    # its own process group, so stopping it also stops the helper programs it starts
    kwargs = {'creationflags': 0x08000000 | 0x00000200} if IS_WIN else {'start_new_session': True}   # NO_WINDOW | NEW_PROCESS_GROUP
    with _running_lock:     # checked together with registering, so 停止檢查 can't slip in between
        if job is not None and getattr(job, 'cancelled', False):
            from .i18n import _          # not at the top: i18n imports this module
            return -1, '', _('已經停止。')
        try:
            p = subprocess.Popen(cmd, cwd=cwd, env=child_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 stdin=subprocess.DEVNULL, **kwargs)
        except OSError as err:
            return -1, '', str(err)
        _running[p] = job
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        p.communicate()
        from .i18n import _
        return -1, '', _('超過 {n} 分鐘沒有完成，已經停止。', n=timeout // 60)
    finally:
        with _running_lock:
            _running.pop(p, None)
    return p.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')


def stop_all(job=None):
    """End the programs run() has going for job (停止檢查), or all of them. Their run() calls return an error.
    Call after setting job.cancelled, so nothing new starts for it."""
    with _running_lock:
        procs = [p for p, owner in _running.items() if job is None or owner is job]
    for p in procs:
        _kill_tree(p)


def _kill_tree(p):
    try:
        if IS_WIN:
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)], capture_output=True, creationflags=0x08000000)
        else:
            os.killpg(p.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            p.kill()
        except OSError:
            pass


def last_lines(text, n=3, limit=400):
    """The end of an error output, which is where the reason usually is."""
    lines = [line.strip() for line in (text or '').splitlines() if line.strip()]
    msg = ' '.join(lines[-n:])
    return msg[-limit:]


def python_spec():
    """The Python every scanner is installed with.

    3.12 because SkillSpector's yara-python has no ready-made build for 3.14; on Apple chips the arm64 build
    is asked for by name, so an Intel (Rosetta) copy of uv can't install parts for the wrong chip.
    """
    if IS_MAC and platform.machine() == 'arm64':
        return 'cpython-3.12-macos-aarch64-none'
    if IS_WIN and platform.machine().upper() == 'ARM64':
        return 'cpython-3.12-windows-x86_64-none'   # no ARM64 wheels for yara-python; x64 runs emulated
    return '3.12'


def mac_version():
    try:
        return int(platform.mac_ver()[0].split('.')[0])
    except (ValueError, IndexError):
        return 0
