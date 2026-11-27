"""Argus's own check of the MCP servers set up on this computer. It reads settings files only, never starts a server.

Scanners that list an MCP server's tools have to run the server first, which defeats checking before trusting
it. This looks at how each server is set up instead: what runs, where it connects, which keys sit in plain text,
whether it updates itself to whatever was published last, and how much of the computer it can reach.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from . import targets, tools
from .i18n import N_, _
from .i18n import _ as tr          # tr(value): text kept in a table or built from N_(…), translated where it's shown
from .model import Finding, Outcome, SkillResult

SCANNER = 'argus-mcp'
SCANNER_NAME = N_('Argus MCP 檢查')
TOOL = SimpleNamespace(id=SCANNER, name=SCANNER_NAME, vendor='Argus', license='MIT')
# commands that download what they run each time they start, and package managers whose x / dlx / exec does the same;
# `bun run start` or `node server.js` runs code already on the computer
DOWNLOADERS = {'npx', 'bunx', 'pnpx', 'uvx', 'pipx'}
PACKAGE_MANAGERS = {'bun', 'pnpm', 'yarn', 'npm'}
# big companies' and the MCP project's own packages: following their latest release is a small risk
WELL_KNOWN = re.compile(
    r'^(@(modelcontextprotocol|playwright|anthropic-ai|microsoft|azure|google-cloud|googleworkspace|aws|awslabs|'
    r'cloudflare|vercel|supabase|stripe|notionhq|sentry|upstash|figma|github|atlassian|linear|shopify|mongodb-js|'
    r'netlify|neondatabase|heroku|twilio|redis)/|firebase-tools(@|$)|awslabs\.|mcp-server-(fetch|git|time|sqlite)([=@]|$))',
    re.I)
# chat apps whose plugins pass messages other people send straight to Claude
MESSAGING = {'discord': 'Discord', 'telegram': 'Telegram', 'imessage': 'iMessage', 'whatsapp': 'WhatsApp',
             'signal': 'Signal', 'fakechat': N_('測試用聊天室')}
CODE_FILE = re.compile(r'\.(m?[jt]sx?|cjs|py|rb|sh|go|jar|exe|php)$', re.I)
SHELLS = {'sh', 'bash', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh'}
LOCAL_HOSTS = re.compile(r'^https?://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?(/|$)', re.I)
SECRET_NAME = re.compile(r'KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH|CREDENTIAL|COOKIE|SESSION', re.I)
SECRET_VALUE = re.compile(r'^(sk-|sk_live_|sk_test_|rk_live_|ghp_|gho_|ghs_|github_pat_|xox[abpr]-|AKIA|AIza|glpat-|'
                          r'ey[A-Za-z0-9_-]{10,}\.)')
SECRET_FLAG = re.compile(r'^--?([\w-]*(key|token|secret|password|passwd|auth|credential|cookie)[\w-]*)(=(.*))?$', re.I)
LONG_TOKEN = re.compile(r'^[A-Za-z0-9_\-]{24,}$')
REFERENCE = re.compile(r'^\$\{?[A-Za-z_]\w*\}?$|^\{\{.*\}\}$|^\$\{\w+:-?.*\}$')


def mask(value):
    value = str(value)
    return value if len(value) <= 8 else value[:4] + '••••••' + value[-2:]


def _secret_looking(value):
    return bool(SECRET_VALUE.match(value)) or (bool(LONG_TOKEN.match(value)) and bool(re.search(r'\d', value))
                                                and bool(re.search(r'[A-Za-z]', value)))


def redact_url(url):
    """A URL to show: the password, secret-looking query values and long tokens in the path hidden."""
    url = re.sub(r'^(\w+://)([^/@:\s]*):([^/@\s]+)@', lambda m: f'{m.group(1)}{m.group(2)}:••••••@', url)

    def query(m):
        k, v = m.group(1), m.group(2)
        return f'{k}={mask(v)}' if v and (SECRET_NAME.search(k) or _secret_looking(v)) else m.group(0)
    head, sep, rest = url.partition('?')
    head = '/'.join(mask(part) if _secret_looking(part) else part for part in head.split('/'))
    return head + sep + re.sub(r'([^&=#]+)=([^&#]*)', query, rest)


def redact_args(args):
    """Command-line arguments to show: values after --token and the like, KEY=value secrets and keys hidden."""
    out, hide_next = [], False
    for a in args:
        if hide_next:
            out.append(mask(a))
            hide_next = False
            continue
        flag = SECRET_FLAG.match(a)
        if flag and flag.group(3):
            out.append(f'--{flag.group(1)}={mask(flag.group(4))}' if flag.group(4) else a)
        elif flag:
            out.append(a)
            hide_next = True
        elif re.match(r'^[A-Za-z_][\w.-]*=', a) and SECRET_NAME.search(a.split('=', 1)[0]):
            k, v = a.split('=', 1)
            out.append(f'{k}={mask(v)}' if v and not REFERENCE.match(v) else a)
        elif re.match(r'^\w+://', a):
            out.append(redact_url(a))
        else:
            out.append(mask(a) if _secret_looking(a) else a)
    return out


class Place(str):
    """Where a server is set up, as shown (in the language in use). .key is the same in the source language: it goes
    into the result's key and the findings' fingerprints, which must not change when the language does."""

    def __new__(cls, text, **kw):
        self = super().__new__(cls, tr(text, **kw))
        self.key = text.format(**kw)
        self.args = kw
        return self


@dataclass
class McpFinding(Finding):
    """A finding whose shown file and snippet are in the language in use; its fingerprint uses the source-language
    ones (key_file, key_snippet), so a finding marked 已看過 stays known after the language changes."""
    key_file: str = ''
    key_snippet: str = ''

    @property
    def fingerprint(self):
        snippet = self.key_snippet or self.snippet
        text = '|'.join((self.scanner, self.rule, self.category, self.key_file or self.file, ' '.join(snippet.split())))
        return hashlib.sha1(text.encode('utf-8')).hexdigest()[:16]


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def _servers(block):
    """A config's {name: server} block, whether nested under "mcpServers" or not."""
    if not isinstance(block, dict):
        return {}
    inner = block.get('mcpServers')
    if isinstance(inner, dict):
        return {k: v for k, v in inner.items() if isinstance(v, dict)}
    return {k: v for k, v in block.items() if isinstance(v, dict) and ('command' in v or 'url' in v)}


def claude_desktop_dir():
    if tools.IS_MAC:
        return tools.HOME / 'Library' / 'Application Support' / 'Claude'
    if tools.IS_WIN:
        import os
        return Path(os.environ.get('APPDATA', tools.HOME)) / 'Claude'
    return tools.HOME / '.config' / 'Claude'


def discover(home: Path | None = None, desktop: Path | None = None):
    """→ list of (server name, where it's set up, config dict). Reads files only."""
    home = home or tools.HOME
    desktop = desktop or claude_desktop_dir()
    found = []

    def add(block, where):
        for name, cfg in _servers(block).items():
            found.append((name, where, cfg))

    user = _load(home / '.claude.json') or {}
    add(user, Place(N_('Claude Code（所有專案）')))
    for project, settings in (user.get('projects') or {}).items():
        # a server set up both for you alone and in the project's .mcp.json: Claude Code uses yours, so only that one is shown
        mine = _servers(settings)
        shared = _servers(_load(Path(project) / '.mcp.json'))
        for name, cfg in mine.items():
            where = N_('Claude Code 專案：{project}（專案的 .mcp.json 也有同名設定，Claude Code 會用這一份）') if name in shared \
                else N_('Claude Code 專案：{project}')
            found.append((name, Place(where, project=Path(project).name), cfg))
        for name, cfg in shared.items():
            if name not in mine:
                found.append((name, Place(N_('專案的 .mcp.json：{project}'), project=Path(project).name), cfg))
    add(_load(desktop / 'claude_desktop_config.json'), Place(N_('Claude 桌面版')))
    ext_root = desktop / 'Claude Extensions'
    if ext_root.is_dir():
        for manifest in sorted(ext_root.glob('*/manifest.json')):
            m = _load(manifest) or {}
            cfg = ((m.get('server') or {}).get('mcp_config')) or {}
            if cfg:
                found.append((m.get('display_name') or m.get('name') or manifest.parent.name,
                              Place(N_('Claude 桌面版擴充功能')), cfg))
    for name, folder in targets.installed_plugins(home):
        place = Place(N_('Claude Code 外掛：{plugin}'), plugin=name)
        add(_load(folder / '.mcp.json'), place)
        m = _load(folder / '.claude-plugin' / 'plugin.json') or _load(folder / 'plugin.json') or {}
        servers = m.get('mcpServers')
        if isinstance(servers, str):                       # "mcpServers": "./servers.json"
            servers = _load(folder / servers)
        if isinstance(servers, dict):
            add(servers, place)
    add(_load(home / '.cursor' / 'mcp.json'), Place('Cursor'))
    # the same server set up in two places is shown once
    seen, unique = set(), []
    for name, where, cfg in found:
        ident = (name, json.dumps({k: cfg.get(k) for k in ('command', 'args', 'url')}, sort_keys=True))
        if ident not in seen:
            seen.add(ident)
            unique.append((name, where, cfg))
    return unique


def _download(exe, args):
    """→ the package or source this command downloads every time it starts, or '' when it runs code already here."""
    if exe in PACKAGE_MANAGERS:
        sub = next((a for a in args if not a.startswith('-')), '')
        if sub not in ('x', 'dlx', 'exec') or (exe in ('pnpm', 'yarn') and sub == 'exec'):
            return ''                                    # bun run start, pnpm exec tsc ...: the plugin's own code
        args = args[args.index(sub) + 1:]
    elif exe == 'deno':
        target = next((a for a in args[1:] if not a.startswith('-')), '') if args[:1] == ['run'] else ''
        return target if re.match(r'(https?:|npm:|jsr:)', target) else ''
    elif exe not in DOWNLOADERS:
        return ''
    if exe == 'pipx' and args[:1] == ['run']:
        args = args[1:]
    for flag in ('--from', '-p', '--package'):        # uvx --from git+https://... cmd, npx -p pkg cmd
        if flag in args[:-1]:
            return args[args.index(flag) + 1]
    return _package_arg(args)


def _git_source(pkg):
    return bool(re.match(r'(git\+|github:|gitlab:|https?://(github|gitlab)\.com/)', pkg))


def _git_pinned(pkg):
    """git+https://github.com/o/r@v1.2 (Python) or github:o/r#v1.2 (npm) name a release or commit."""
    tail = re.sub(r'^git\+ssh://git@', '', pkg)
    return '#' in tail or re.search(r'@[^/@]+$', tail) is not None


def _pkg_pinned(runner, pkg):
    if runner in ('uvx', 'pipx'):
        return bool(re.search(r'(==|@)\d', pkg))
    m = re.match(r'^(@[^/]+/)?[^@]+@(.+)$', pkg)       # npm style: name@version or @scope/name@version
    return bool(m and m.group(2) not in ('latest', 'next', '*'))


def _package_arg(args):
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ('-p', '--package', '--from', '--with'):
            skip_next = True
            continue
        if a in ('dlx', 'run', 'x', 'exec'):
            continue
        if not a.startswith('-'):
            return a
    return ''


def _broad_path(arg):
    a = arg.rstrip('/\\')
    home = str(tools.HOME).rstrip('/\\')
    return a in ('', '~', '$HOME', '${HOME}', '%USERPROFILE%', home, '/Users', '/home', 'C:', 'C:\\Users') or \
        re.fullmatch(r'/(Users|home)/[^/]+', a) is not None or re.fullmatch(r'[A-Za-z]:\\Users\\[^\\]+', a) is not None


def inspect(name, where, cfg):
    """One MCP server → SkillResult(kind='mcp')."""
    command = str(cfg.get('command') or '')
    args = [str(a) for a in cfg.get('args') or []]
    url = str(cfg.get('url') or '')
    env = cfg.get('env') if isinstance(cfg.get('env'), dict) else {}
    headers = cfg.get('headers') if isinstance(cfg.get('headers'), dict) else {}
    exe = Path(command.replace('\\', '/')).name.lower()
    findings, caps = [], []
    where_key = getattr(where, 'key', where)

    def finding(title, what, tip, severity, rule, snippet='', calm='', key_snippet=''):
        findings.append(McpFinding(scanner=SCANNER, title=title, what=what, tip=tip, severity=severity, rule=rule,
                                   category='mcp', file=where, snippet=snippet, detail=f'{rule}: {title}', calm=calm,
                                   key_file=where_key, key_snippet=key_snippet))

    def cap(cid, icon, label, what, evidence):
        caps.append({'id': cid, 'icon': icon, 'label': label, 'what': what,
                     'evidence': [{'file': where, 'line': None, 'text': e} for e in evidence][:3]})

    raw_args, args = args, redact_args(args)     # what's shown never carries a key; checks read the raw values
    raw_url, url = url, redact_url(url)
    shown = ' '.join([command] + args)[:300]
    if url:
        local = bool(LOCAL_HOSTS.match(raw_url))
        host = re.sub(r'^\w+://(?:[^/@]*@)?([^/?#]+).*$', r'\1', raw_url)
        if not local:
            cap('network', '🌐', _('連網'), _('你和 Claude 的對話內容中，跟這個工具有關的部分會送到這個服務。'),
                [_('連到 {host}', host=host)])
        if raw_url.lower().startswith('http://') and not local:
            finding(_('連線沒有加密'), _('用 http:// 連到外部服務，傳輸內容（包括金鑰）可能被同一個網路上的人看到。'),
                    _('改成 https:// 的網址；沒有 https 的服務就不建議使用。'), 'HIGH', 'MCP-HTTP', url)
    else:
        cap('exec', '⚙️', _('執行程式'), _('這個 MCP 伺服器是在你的電腦上執行的程式，有你的帳號能做的所有權限。'), [shown])
        cap('autorun', '⚡', _('自動執行'), _('Claude 一打開就會自動啟動它，不用你叫它。'), [_('跟著 Claude 一起啟動')])
    # what runs
    raw_pkg = _download(exe, raw_args)
    pkg = redact_url(raw_pkg) if raw_pkg else raw_pkg
    if pkg and _git_source(raw_pkg):
        cap('install', '📦', _('安裝套件'), _('每次啟動時會從 GitHub 下載程式碼來執行。'), [pkg])
        cap('network', '🌐', _('連網'), _('啟動時會從網路下載程式。'), [_('從 {source} 下載', source=pkg)])
        if not _git_pinned(raw_pkg):
            finding(_('每次啟動都抓 GitHub 上最新的程式碼'),
                    _('它直接從 {source} 下載程式，沒有經過套件庫，也沒有指定版本。作者推上去的任何改動（或帳號被盜後別人推的改動），'
                      '你下次啟動時就會執行，中間沒有人檢查。', source=pkg),
                    _('沒在用就關掉；要用的話，請懂的人把它固定在某個版本（網址後面加 @版本號）。'), 'MEDIUM', 'MCP-GIT-SOURCE', shown)
    elif pkg:
        cap('install', '📦', _('安裝套件'), _('每次啟動時會從網路下載套件來執行。'), [f'{exe} {pkg}'])
        cap('network', '🌐', _('連網'), _('啟動時會從網路下載程式。'), [_('從套件庫下載 {package}', package=pkg)])
        if not _pkg_pinned(exe, raw_pkg):
            finding(_('版本沒鎖定，會自動換成最新版'),
                    _('每次啟動都會下載 {package} 的最新版。作者（或盜用作者帳號的人）發佈新版時，'
                      '你的電腦會直接執行新版，中間沒有人檢查。', package=pkg),
                    _('把版本寫死，例如 {package}@1.2.3（Python 套件寫成 {package}==1.2.3），想更新時再手動改。', package=pkg),
                    'MEDIUM', 'MCP-UNPINNED', shown,
                    calm=_('這是大公司或 MCP 官方發佈的套件，被動手腳的機會很低；想更保險再鎖定版本。') if WELL_KNOWN.match(raw_pkg) else '')
    # chat apps: other people's messages reach Claude
    plugin = str(getattr(where, 'args', {}).get('plugin', '')).lower()
    chat = next((k for k in (name.lower(), plugin) if k in MESSAGING), '')
    if chat:
        app = tr(MESSAGING[chat])
        cap('inbound', '📨', _('接收外部訊息'), _('會把 {app} 收到的訊息交給 Claude。', app=app), [_('{app} 的訊息', app=app)])
        if chat == 'imessage':
            what = _('這個外掛會把 {app} 收到的訊息轉給 Claude。別人傳來的文字，可能被 Claude 當成指令照做，'
                     '例如讀你的檔案或把東西傳出去。它也讀得到你的簡訊紀錄。', app=app)
        elif chat == 'fakechat':
            what = _('這個外掛會把 {app} 收到的訊息轉給 Claude。別人傳來的文字，可能被 Claude 當成指令照做，'
                     '例如讀你的檔案或把東西傳出去。這是官方拿來測試的假聊天室，一般人用不到。', app=app)
        else:
            what = _('這個外掛會把 {app} 收到的訊息轉給 Claude。別人傳來的文字，可能被 Claude 當成指令照做，'
                     '例如讀你的檔案或把東西傳出去。', app=app)
        finding(_('會把別人傳來的訊息交給 Claude'), what,
                _('沒在用就關掉；要用的話，只讓你信任的人傳訊息給它，並留意 Claude 接下來要做的事。'), 'MEDIUM', 'MCP-INBOUND-MESSAGES',
                shown or url)
    if exe == 'docker':
        joined = ' '.join(args)
        image = next((a for a in reversed(args) if not a.startswith('-') and ('/' in a or ':' in a)), '')
        cap('install', '📦', _('安裝套件'), _('會用 Docker 下載並執行容器映像檔。'), [image or joined[:120]])
        if '--privileged' in args:
            finding(_('Docker 用最高權限執行'), _('--privileged 讓容器幾乎可以控制你的整台電腦，等於沒有隔離。'),
                    _('一般的 MCP 伺服器不需要這個權限，除非你很確定，否則不要用。'), 'HIGH', 'MCP-DOCKER-PRIVILEGED', joined[:200])
        if 'docker.sock' in joined:
            finding(_('容器可以控制 Docker'), _('把 docker.sock 交給容器，它就能開新的容器、存取你電腦上的檔案。'),
                    _('除非這個工具的用途就是管理 Docker，否則不該這樣設定。'), 'HIGH', 'MCP-DOCKER-SOCK', joined[:200])
        if re.search(r'--net(work)?[= ]host', joined):
            finding(_('容器直接使用你電腦的網路'), _('--network host 讓容器可以連到你電腦上只對本機開放的服務。'),
                    _('大多數 MCP 伺服器不需要這樣設定。'), 'MEDIUM', 'MCP-DOCKER-HOSTNET', joined[:200])
        for i, a in enumerate(args):
            if a in ('-v', '--volume', '--mount') and i + 1 < len(args):
                source = re.split(r'[:,]', args[i + 1].replace('source=', '').replace('src=', ''))[0]
                if _broad_path(source) or source == '/':
                    finding(_('容器可以存取整個家目錄或整顆硬碟'),
                            _('把 {folder} 掛進容器，裡面的程式就能讀寫這些檔案。', folder=source or '/'),
                            _('只掛它真的需要的資料夾。'), 'MEDIUM', 'MCP-DOCKER-MOUNT', a + ' ' + args[i + 1])
        unpinned_image = image and (image.endswith(':latest') or not re.search(r':[^/]+$|@sha256:', image))
        if unpinned_image:
            finding(_('容器版本沒鎖定，會自動換成最新版'), _('{image} 沒有指定版本，每次都可能拿到不同的映像檔。', image=image),
                    _('指定版本號或 @sha256 摘要。'), 'MEDIUM', 'MCP-DOCKER-UNPINNED', image)
    if exe in SHELLS:
        script = ' '.join(args)
        if re.search(r'(curl|wget|iwr|Invoke-WebRequest)[^|]*\|\s*(sh|bash|zsh|iex|python)', script, re.I):
            finding(_('下載後直接執行'), _('指令會從網路下載程式並立刻執行，沒有任何檢查。'), _('不建議使用這種設定。'), 'HIGH',
                    'MCP-PIPE-SHELL', script[:200])
        else:
            finding(_('透過 shell 執行指令'), _('實際執行什麼，要看後面那串指令；這種寫法比較難一眼看出它在做什麼。'),
                    _('看一下指令內容，或請 Claude 解釋。'), 'LOW', 'MCP-SHELL', script[:200])
    if exe == 'sudo' or 'sudo' in args[:1]:
        finding(_('用管理員權限執行'), _('sudo 讓這個伺服器用最高權限執行，可以修改整台電腦。'), _('一般 MCP 伺服器不需要管理員權限。'),
                'HIGH', 'MCP-SUDO', shown)
    # which folders it is handed
    paths = [a for a in args if (a.startswith(('/', '~', '$HOME', '${HOME}')) or re.match(r'^[A-Za-z]:\\', a))
             and not CODE_FILE.search(a)]          # the program it runs is not a folder it is handed
    if paths:
        cap('write', '📁', _('可以存取的資料夾'), _('這些資料夾交給了這個伺服器，它通常可以讀取、也可能可以修改裡面的檔案。'), paths)
        for p in paths:
            if _broad_path(p) or p.rstrip('/\\') in ('', '/'):
                finding(_('可以存取整個家目錄或整顆硬碟'), _('交給它的資料夾是 {folder}，範圍包含你所有的文件、照片和設定檔。', folder=p),
                        _('只給它真正要用的資料夾，例如某個專案資料夾。'), 'MEDIUM', 'MCP-BROAD-PATH', p)
    # keys written into the settings file: each line shown in the language in use, and kept in the source language
    # for the finding's fingerprint
    leaked, leaked_key = [], []

    def leak(text, **kw):
        leaked.append(tr(text, **kw))
        leaked_key.append(text.format(**kw))
    for label, mapping in ((N_('環境變數 {name} = {value}'), env), (N_('連線標頭 {name} = {value}'), headers)):
        for k, v in mapping.items():
            v = str(v)
            value = v.split(' ', 1)[-1] if v.lower().startswith(('bearer ', 'token ')) else v
            if value and not REFERENCE.match(value) and (SECRET_NAME.search(k) or SECRET_VALUE.match(value)):
                leak(label, name=k, value=mask(value))
    for raw, a in zip(raw_args, args):
        if a != raw:
            leak(N_('啟動參數 {arg}'), arg=a)
    if url != raw_url:
        leak(N_('連線網址 {url}'), url=url)
    if leaked:
        cap('secrets', '🔑', _('碰觸機密或 Claude 設定'), _('設定檔裡交給了它金鑰或密碼。'), leaked)
        finding(_('金鑰直接寫在設定檔裡'), _('金鑰以明文存在設定檔裡，設定檔被備份、分享或被其他程式讀到時，金鑰就跟著外流。'),
                _('這不代表這個伺服器有問題，是保管方式的提醒。可以的話改用環境變數或系統鑰匙圈。'), 'MEDIUM', 'MCP-PLAINTEXT-SECRET',
                '\n'.join(leaked), key_snippet='\n'.join(leaked_key))
    severities = {f.severity for f in findings if not f.calm}
    verdict = 'DO_NOT_INSTALL' if 'HIGH' in severities else 'CAUTION' if 'MEDIUM' in severities else 'SAFE'
    note = _('連線網址：{url}。', url=url) if url else _('執行指令：{command}。', command=shown)
    result = SkillResult(name=name, path=where, kind='mcp',
                         outcomes=[Outcome(SCANNER, verdict, findings, note=note)],
                         capabilities=caps)
    digest = hashlib.sha256(json.dumps(cfg, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()
    result.key = f'mcp:{where_key}:{name}'
    result.tracked = {'設定': digest}  # i18n: keep (a stored key, compared between scans)
    return result


def inspect_all(**kw):
    return [inspect(name, where, cfg) for name, where, cfg in discover(**kw)]
