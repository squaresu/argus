# Argus: the Windows launcher. Starts Argus's local page (or brings it back) in the browser.
# Windows PowerShell 5.1 needs this file saved as UTF-8 *with BOM*, or the Chinese text breaks; build.sh does that.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$APP = 'Argus'
$HERE = $PSScriptRoot                                   # ...\Argus\app
$STATE = Join-Path $env:APPDATA 'Argus'
$LOGS = Join-Path $STATE 'logs'
New-Item -ItemType Directory -Force -Path $STATE, $LOGS | Out-Null
# a launcher started from Explorer can carry a stale PATH; uv puts what it installs in ~\.local\bin
$env:PATH = @([Environment]::GetEnvironmentVariable('Path', 'User'), [Environment]::GetEnvironmentVariable('Path', 'Machine'),
              (Join-Path $HOME '.local\bin'), $env:PATH) -join ';'
$FONT = New-Object Drawing.Font('Microsoft JhengHei UI', 10)

# an invisible topmost window, so dialogs open in front instead of behind the browser
$owner = New-Object Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false; Opacity = 0; StartPosition = 'CenterScreen' }
$owner.Show(); $owner.Hide()
function Ask($msg) { [Windows.Forms.MessageBox]::Show($owner, $msg, $APP, 'YesNo', 'Question') -eq 'Yes' }
function Fail($msg) { $wait.Hide(); [void][Windows.Forms.MessageBox]::Show($owner, $msg, $APP, 'OK', 'Error'); exit 1 }

# a small "please wait" window, since everything else runs without a console
$wait = New-Object Windows.Forms.Form -Property @{
  Text = $APP; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false; TopMost = $true; StartPosition = 'CenterScreen'
  AutoSize = $true; AutoSizeMode = 'GrowAndShrink'; Font = $FONT; Padding = '18,16,18,16'; ControlBox = $false
}
if (Test-Path (Join-Path $HERE 'argus.ico')) { $wait.Icon = New-Object Drawing.Icon (Join-Path $HERE 'argus.ico') }
$waitText = New-Object Windows.Forms.Label -Property @{ AutoSize = $true; MinimumSize = '340,0'; MaximumSize = '460,0' }
$wait.Controls.Add($waitText)
function Status($msg) {
  $waitText.Text = $msg
  if (-not $wait.Visible) { $wait.Show() }
  [Windows.Forms.Application]::DoEvents()
}
function Pump($seconds) {   # wait while keeping the window responsive
  $until = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $until) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 100 }
}

# Start Menu and desktop shortcuts with the Argus icon, pointing at wherever this copy of Argus lives
function Make-Shortcuts {
  $shell = New-Object -ComObject WScript.Shell
  $args_ = "-NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$HERE\launch.ps1`""
  $places = @([Environment]::GetFolderPath('Programs'))
  $desktopDone = Join-Path $STATE 'desktop-shortcut-made'
  if (-not (Test-Path $desktopDone)) { $places += [Environment]::GetFolderPath('Desktop') }   # once: if it's deleted, it stays deleted
  foreach ($dir in $places) {
    $lnk = $shell.CreateShortcut((Join-Path $dir 'Argus.lnk'))
    $lnk.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lnk.Arguments = $args_
    $lnk.WorkingDirectory = $STATE
    $lnk.IconLocation = "$HERE\argus.ico,0"
    $lnk.Description = 'Argus · AI 技能安全掃描'
    $lnk.Save()
  }
  New-Item -ItemType File -Force -Path $desktopDone | Out-Null
}
try { Make-Shortcuts } catch {}
# files unzipped from a download carry Windows's "came from the internet" mark, which makes it warn on every start;
# Argus's own files only (the folder this launcher sits in)
try { Get-ChildItem -Path (Split-Path $HERE) -Recurse -File | Unblock-File } catch {}

# 1. already running? bring its page back, unless it's an older Argus still running from before an update
$VERSION = ((Select-String -Path (Join-Path $HERE 'core\argus\__init__.py') -Pattern "^VERSION = '(.+)'").Matches[0].Groups[1].Value)
$urlFile = Join-Path $STATE 'url'
if (Test-Path $urlFile) {
  $url = (Get-Content $urlFile -Raw -Encoding UTF8).Trim()
  $base = $url -replace '/\?.*$', ''
  try {
    $ping = Invoke-RestMethod -Uri "$base/api/ping" -TimeoutSec 2
    if ($ping.version -eq $VERSION) { Start-Process $url; exit 0 }
    Invoke-RestMethod -Method Post -Uri "$base/api/quit" -Headers @{ 'X-Argus-Token' = ($url -replace '^.*t=', '') } -TimeoutSec 2 | Out-Null
    Start-Sleep -Seconds 1
  } catch {}
}

# 2. uv runs Argus and installs the scanners
function Find-Uv {
  $c = Get-Command uv -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) { return $c.Source }
  $p = Join-Path $HOME '.local\bin\uv.exe'
  if (Test-Path $p) { return $p }
  $null
}
$uv = Find-Uv
if (-not $uv) {
  if (-not (Ask "第一次使用 Argus，要先安裝 uv（用來安裝掃描工具的免費開源小程式）。要現在安裝嗎？（需要網路，大約 1 分鐘）")) { exit 0 }
  Status '正在安裝 uv…'
  $cmd = '[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://astral.sh/uv/install.ps1 | iex'
  $p = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "`"$cmd`"") -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $LOGS 'uv-install.log') -RedirectStandardError (Join-Path $LOGS 'uv-install-err.log')
  while (-not $p.HasExited) { Pump 0.3 }
  $uv = Find-Uv
  if (-not $uv) { Fail "安裝 uv 失敗，請檢查網路後再試。`n（紀錄在 $LOGS）" }
}

# the same Python the scanners are installed with (see core\argus\tools.py: python_spec)
$pyspec = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'cpython-3.12-windows-x86_64-none' } else { '3.12' }

# 3. start the local page in the background, then open it
Remove-Item $urlFile -ErrorAction SilentlyContinue
Status 'Argus 正在啟動，第一次大約需要 1 分鐘…'
$env:PYTHONPATH = Join-Path $HERE 'core'
$env:PYTHONUTF8 = '1'
Start-Process -FilePath $uv -ArgumentList @('run', '--no-project', '--python', $pyspec, 'python', '-m', 'argus') `
  -WorkingDirectory $STATE -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $LOGS 'argus.log') -RedirectStandardError (Join-Path $LOGS 'argus-err.log') | Out-Null
for ($i = 0; $i -lt 360; $i++) {
  if ((Test-Path $urlFile) -and (Get-Item $urlFile).Length -gt 0) { break }
  Pump 0.5
}
if (-not ((Test-Path $urlFile) -and (Get-Item $urlFile).Length -gt 0)) { Fail "Argus 沒有順利啟動。`n（紀錄在 $LOGS\argus-err.log）" }
$wait.Hide()
Start-Process ((Get-Content $urlFile -Raw -Encoding UTF8).Trim())
