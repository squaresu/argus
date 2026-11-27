"""The few things a web page can't do itself: the system's folder/file pickers, and opening things in Finder."""

import subprocess

from . import tools
from .i18n import _


def _applescript_text(text):
    """text inside an AppleScript "…" string."""
    return text.replace('\\', '\\\\').replace('"', '\\"')


def _powershell_text(text):
    """text inside a PowerShell "…" string."""
    return text.replace('`', '``').replace('"', '`"').replace('$', '`$')


class Unsupported(Exception):
    pass


def _osascript(script):
    p = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ''   # non-zero: the person pressed Cancel


# an invisible topmost owner window, so the dialog opens in front of the browser instead of behind it;
# UTF-8 output, so Chinese folder names come back intact
_PS_PRELUDE = ('[Console]::OutputEncoding = [Text.Encoding]::UTF8; Add-Type -AssemblyName System.Windows.Forms; '
               '$o = New-Object Windows.Forms.Form -Property @{TopMost=$true; ShowInTaskbar=$false; Opacity=0; '
               'StartPosition="CenterScreen"}; $o.Show(); $o.Activate(); ')


def _powershell(script):
    cmd = ['powershell', '-NoProfile', '-STA', '-Command', _PS_PRELUDE + script]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', creationflags=0x08000000)
    return p.stdout.strip()


def pick_folder():
    """A folder path, or '' if the person cancelled."""
    if tools.IS_MAC:
        prompt = _applescript_text(_('選擇技能資料夾'))
        return _osascript(f'POSIX path of (choose folder with prompt "{prompt}")').rstrip('/')
    if tools.IS_WIN:
        prompt = _powershell_text(_('選擇技能資料夾'))
        return _powershell(f'$d = New-Object Windows.Forms.FolderBrowserDialog; $d.Description = "{prompt}"; '
                           'if ($d.ShowDialog($o) -eq "OK") { $d.SelectedPath }')
    raise Unsupported(_('這台電腦不支援選擇資料夾，請直接輸入路徑。'))


def pick_zip():
    if tools.IS_MAC:
        prompt = _applescript_text(_('選擇技能的 zip 檔'))
        return _osascript(f'POSIX path of (choose file with prompt "{prompt}" of type {{"zip", "public.zip-archive"}})')
    if tools.IS_WIN:
        title = _powershell_text(_('選擇技能的 zip 檔'))
        return _powershell(f'$d = New-Object Windows.Forms.OpenFileDialog; $d.Title = "{title}"; '
                           '$d.Filter = "zip (*.zip)|*.zip"; if ($d.ShowDialog($o) -eq "OK") { $d.FileName }')
    raise Unsupported(_('這台電腦不支援選擇檔案，請直接輸入路徑。'))


def relaunch(app):
    """Start the Argus at `app` (the .app on a Mac, the Argus folder on Windows) as if double-clicked."""
    if tools.IS_WIN:
        launcher = str(app / 'app' / 'launch.ps1')
        subprocess.Popen(['powershell', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
                          '-File', launcher], creationflags=0x00000008 | 0x00000200, close_fds=True)   # detached
    else:
        subprocess.Popen(['open', '-n', str(app)])


def open_path(path):
    """Open a file or folder the way double-clicking it would."""
    if tools.IS_MAC:
        subprocess.Popen(['open', str(path)])
    elif tools.IS_WIN:
        import os
        os.startfile(str(path))
    else:
        subprocess.Popen(['xdg-open', str(path)])
