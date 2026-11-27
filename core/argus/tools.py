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
    d = documents_dir() / 'Argus 報告'
    d.mkdir(parents=True, exist_ok=True)
    return d


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


_running = set()            # programs started by run(), so 停止檢查 can end them
_running_lock = threading.Lock()


def run(cmd, timeout=900, cwd=None):
    """Run a command; return (exit code, stdout, stderr). A command that can't start, times out or is stopped
    gives code -1."""
    # its own process group, so stopping it also stops the helper programs it starts
    kwargs = {'creationflags': 0x08000000 | 0x00000200} if IS_WIN else {'start_new_session': True}   # NO_WINDOW | NEW_PROCESS_GROUP
    try:
        p = subprocess.Popen(cmd, cwd=cwd, env=child_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, **kwargs)
    except OSError as err:
        return -1, '', str(err)
    with _running_lock:
        _running.add(p)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        p.communicate()
        return -1, '', f'超過 {timeout // 60} 分鐘沒有完成，已經停止。'
    finally:
        with _running_lock:
            _running.discard(p)
    return p.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')


def stop_all():
    """End every program run() has going (停止檢查). Their run() calls return with an error."""
    with _running_lock:
        procs = list(_running)
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
