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

# the language of these messages: the one picked in Argus (its settings.json), else Windows's display language,
# else English; the same order as core\argus\i18n.py
$L = $env:ARGUS_LANG
if (-not $L) { try { $L = (Get-Content (Join-Path $STATE 'settings.json') -Raw -Encoding UTF8 | ConvertFrom-Json).lang } catch {} }
if (-not $L) { try { $L = (Get-UICulture).Name } catch {} }
$L = switch -Regex ("$L") { '^zh' { 'zh-TW' } '^ja' { 'ja' } '^ko' { 'ko' } default { 'en' } }
function T($zh, $en, $ja, $ko) { switch ($L) { 'en' { $en } 'ja' { $ja } 'ko' { $ko } default { $zh } } }   # the one in the language in use
$FONT = New-Object Drawing.Font((T 'Microsoft JhengHei UI' 'Segoe UI' 'Yu Gothic UI' 'Malgun Gothic'), 10)

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
    $lnk.Description = T 'Argus · AI 技能安全掃描' 'Argus · AI skill security scan' 'Argus · AI スキルのセキュリティスキャン' 'Argus · AI 스킬 보안 검사'
    $lnk.Save()
  }
  New-Item -ItemType File -Force -Path $desktopDone | Out-Null
}
try { Make-Shortcuts } catch {}
# files unzipped from a download carry Windows's "came from the internet" mark, which makes it warn on every start;
# Argus's own files only (the folder this launcher sits in)
try { Get-ChildItem -Path (Split-Path $HERE) -Recurse -File | Unblock-File } catch {}

# 1. already running? bring its page back, unless it's another copy or version of Argus, or its files have gone
$VERSION = ((Select-String -Path (Join-Path $HERE 'core\argus\__init__.py') -Pattern "^VERSION = '(.+)'").Matches[0].Groups[1].Value)
$urlFile = Join-Path $STATE 'url'
if (Test-Path $urlFile) {
  $url = (Get-Content $urlFile -Raw -Encoding UTF8).Trim()
  $base = $url -replace '/\?.*$', ''
  try {
    $ping = Invoke-RestMethod -Uri "$base/api/ping" -TimeoutSec 2
    # reuse it only if it's this copy and version of Argus and its files are still there
    $where = (Resolve-Path (Join-Path $HERE 'core\argus')).Path
    if ($ping.version -eq $VERSION -and $ping.where -eq $where -and $ping.ok) { Start-Process $url; exit 0 }
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
  if (-not (Ask (T "第一次使用 Argus，要先安裝 uv（用來安裝掃描工具的免費開源小程式）。要現在安裝嗎？（需要網路，大約 1 分鐘）" `
      "The first time you use Argus, it needs to install uv (a small free, open-source program that installs the scanning tools). Install it now? (Needs the internet, about 1 minute)" `
      "Argus を初めて使うときは、先に uv（スキャンツールのインストールに使う、無料のオープンソースの小さなプログラム）をインストールします。今すぐインストールしますか？（インターネット接続が必要、約 1 分）" `
      "Argus를 처음 사용할 때는 먼저 uv(검사 도구를 설치하는 무료 오픈 소스 소형 프로그램)를 설치해야 합니다. 지금 설치할까요? (인터넷 연결 필요, 약 1분)"))) { exit 0 }
  Status (T '正在安裝 uv…' 'Installing uv…' 'uv をインストールしています…' 'uv 설치 중…')
  $cmd = '[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://astral.sh/uv/install.ps1 | iex'
  $p = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "`"$cmd`"") -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $LOGS 'uv-install.log') -RedirectStandardError (Join-Path $LOGS 'uv-install-err.log')
  while (-not $p.HasExited) { Pump 0.3 }
  $uv = Find-Uv
  if (-not $uv) {
    Fail (T "安裝 uv 失敗，請檢查網路後再試。`n（紀錄在 $LOGS）" "Couldn't install uv. Check the internet connection and try again.`n(Log: $LOGS)" `
      "uv をインストールできませんでした。ネットワークを確認して、もう一度お試しください。`n（ログ：$LOGS）" "uv를 설치하지 못했습니다. 인터넷 연결을 확인한 후 다시 시도하세요.`n(기록: $LOGS)")
  }
}

# the same Python the scanners are installed with (see core\argus\tools.py: python_spec)
$pyspec = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'cpython-3.12-windows-x86_64-none' } else { '3.12' }

# 3. start the local page in the background, then open it
Remove-Item $urlFile -ErrorAction SilentlyContinue
Status (T 'Argus 正在啟動，第一次大約需要 1 分鐘…' 'Argus is starting. The first time takes about 1 minute…' `
  'Argus を起動しています。初回は 1 分ほどかかります…' 'Argus를 시작하는 중입니다. 처음에는 1분 정도 걸립니다…')
$env:PYTHONPATH = Join-Path $HERE 'core'
$env:PYTHONUTF8 = '1'
Start-Process -FilePath $uv -ArgumentList @('run', '--no-project', '--python', $pyspec, 'python', '-m', 'argus') `
  -WorkingDirectory $STATE -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $LOGS 'argus.log') -RedirectStandardError (Join-Path $LOGS 'argus-err.log') | Out-Null
for ($i = 0; $i -lt 360; $i++) {
  if ((Test-Path $urlFile) -and (Get-Item $urlFile).Length -gt 0) { break }
  Pump 0.5
}
if (-not ((Test-Path $urlFile) -and (Get-Item $urlFile).Length -gt 0)) {
  Fail (T "Argus 沒有順利啟動。`n（紀錄在 $LOGS\argus-err.log）" "Argus didn't start.`n(Log: $LOGS\argus-err.log)" `
    "Argus を起動できませんでした。`n（ログ：$LOGS\argus-err.log）" "Argus가 제대로 시작되지 않았습니다.`n(기록: $LOGS\argus-err.log)")
}
$wait.Hide()
Start-Process ((Get-Content $urlFile -Raw -Encoding UTF8).Trim())
