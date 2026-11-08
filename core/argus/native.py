"""The few things a web page can't do itself: the system's folder/file pickers, and opening things in Finder."""

import subprocess

from . import tools


class Unsupported(Exception):
    pass


def _osascript(script):
    p = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ''   # non-zero: the person pressed Cancel


def _powershell(script):
    cmd = ['powershell', '-NoProfile', '-STA', '-Command', script]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', creationflags=0x08000000)
    return p.stdout.strip()


def pick_folder():
    """A folder path, or '' if the person cancelled."""
    if tools.IS_MAC:
        return _osascript('POSIX path of (choose folder with prompt "選擇技能資料夾")').rstrip('/')
    if tools.IS_WIN:
        return _powershell('Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; '
                           '$d.Description = "選擇技能資料夾"; if ($d.ShowDialog() -eq "OK") { $d.SelectedPath }')
    raise Unsupported('這台電腦不支援選擇資料夾，請直接輸入路徑。')


def pick_zip():
    if tools.IS_MAC:
        return _osascript('POSIX path of (choose file with prompt "選擇技能的 zip 檔" of type {"zip", "public.zip-archive"})')
    if tools.IS_WIN:
        return _powershell('Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; '
                           '$d.Filter = "zip (*.zip)|*.zip"; if ($d.ShowDialog() -eq "OK") { $d.FileName }')
    raise Unsupported('這台電腦不支援選擇檔案，請直接輸入路徑。')


def open_path(path):
    """Open a file or folder the way double-clicking it would."""
    if tools.IS_MAC:
        subprocess.Popen(['open', str(path)])
    elif tools.IS_WIN:
        import os
        os.startfile(str(path))
    else:
        subprocess.Popen(['xdg-open', str(path)])
