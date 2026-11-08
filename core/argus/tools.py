"""Running command-line tools, finding them, and where Argus keeps its files."""

import os
import platform
import shutil
import subprocess
import sys
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
    return env


def run(cmd, timeout=900, cwd=None):
    """Run a command; return (exit code, stdout, stderr). A command that can't start or times out gives code -1."""
    kwargs = {'creationflags': 0x08000000} if IS_WIN else {}   # CREATE_NO_WINDOW: no console flashing up
    try:
        p = subprocess.run(cmd, cwd=cwd, env=child_env(), capture_output=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, **kwargs)
    except subprocess.TimeoutExpired:
        return -1, '', f'超過 {timeout // 60} 分鐘沒有完成，已經停止。'
    except OSError as err:
        return -1, '', str(err)
    return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')


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
