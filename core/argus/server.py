"""A small web server on this computer only (127.0.0.1) that serves Argus's page and runs its jobs.

Every request must carry the session token (in the page's URL or an X-Argus-Token header) and a localhost
Host header, so other web pages and other computers can't drive it. It stops by itself a couple of minutes
after the page is closed.
"""

import json
import mimetypes
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import (COPYRIGHT, DISCLAIMER, DISCLAIMER_SHORT, LICENSE, NAME, TAGLINE, VERSION, jobs, native, scanners,
               targets, tools, updates)

UI = Path(__file__).parent / 'ui'
TOKEN = secrets.token_urlsafe(24)
IDLE_SECONDS = 150
_last_seen = time.time()
# scanner id → (status, version). status: missing | checking | ok | broken (installed but won't start).
# Starting a tool to ask its version can take a while (the first start after installing especially),
# so it runs in the background and the page never waits for it.
_status = {}


def check_tools(only=None):
    todo = [s for s in scanners.all_scanners() if only is None or s.id == only]
    for s in todo:
        _status[s.id] = ('checking', '') if s.installed() else ('missing', '')

    def one(s):
        if _status[s.id][0] == 'checking':
            v = s.version()
            _status[s.id] = ('ok', v) if v else ('broken', '')
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(one, todo))


def tool_info(s):
    status, version = _status.get(s.id, ('checking', ''))
    if status == 'checking' and not s.installed():
        status = 'missing'
    # a tool that's present but still being checked can already be ticked and used
    return s.info() | {'status': status, 'version': version, 'installed': status in ('ok', 'checking')}


def state():
    running = [j for j in jobs._jobs.values() if j.status == 'running']
    return {
        'app': {'name': NAME, 'tagline': TAGLINE, 'version': VERSION, 'copyright': COPYRIGHT, 'license': LICENSE,
                'disclaimer': DISCLAIMER, 'disclaimer_short': DISCLAIMER_SHORT, 'reports': str(tools.reports_dir()),
                'platform': 'mac' if tools.IS_MAC else 'win' if tools.IS_WIN else 'other'},
        'scanners': [tool_info(s) for s in scanners.all_scanners()],
        'history': jobs.history(),
        'running': next((j.id for j in running if j.kind == 'scan'), None),
        'updating': next((j.id for j in running if j.kind == 'update'), None),
        'installing': next(({'id': j.target, 'job': j.id} for j in running if j.kind == 'install'), None),
        'claude_found': any(r.exists() for r in targets.claude_roots()),
        'update': updates.status(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f'{NAME}/{VERSION}'

    def log_message(self, *args):   # keep the terminal quiet
        pass

    # --- plumbing ---
    def send(self, code, body, ctype='application/json; charset=utf-8'):
        data = body if isinstance(body, bytes) else (
            json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def allowed(self):
        host = (self.headers.get('Host') or '').rsplit(':', 1)[0]
        if host not in ('127.0.0.1', 'localhost'):
            return False
        q = parse_qs(urlparse(self.path).query)
        return secrets.compare_digest(self.headers.get('X-Argus-Token') or (q.get('t') or [''])[0], TOKEN)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        try:
            return json.loads(self.rfile.read(n) or b'{}') if n else {}
        except ValueError:
            return {}

    # --- routes ---
    def do_GET(self):
        global _last_seen
        path = urlparse(self.path).path
        if path == '/api/ping':   # lets the launcher know Argus is already running
            return self.send(200, {'app': NAME, 'version': VERSION})
        if not self.allowed():
            return self.send(403, {'error': '請從 Argus App 打開這個頁面。'})
        _last_seen = time.time()
        if path == '/':
            page = (UI / 'index.html').read_text(encoding='utf-8').replace('__TOKEN__', TOKEN)
            return self.send(200, page, 'text/html; charset=utf-8')
        if path.startswith('/ui/'):
            f = (UI / path[4:]).resolve()
            if f.is_file() and f.is_relative_to(UI.resolve()):
                ctype = mimetypes.guess_type(f.name)[0] or 'application/octet-stream'
                return self.send(200, f.read_bytes(), ctype + ('; charset=utf-8' if ctype.startswith('text') or 'javascript' in ctype else ''))
            return self.send(404, {'error': 'not found'})
        if path.startswith('/reports/'):
            name = unquote(path[len('/reports/'):])
            f = tools.reports_dir() / name
            if '/' not in name and '\\' not in name and name.endswith('.html') and f.is_file():
                return self.send(200, f.read_bytes(), 'text/html; charset=utf-8')
            return self.send(404, {'error': '找不到這份報告。'})
        if path == '/api/state':
            return self.send(200, state())
        if path.startswith('/api/job/'):
            job = jobs.get(path.rsplit('/', 1)[1])
            return self.send(200, job.to_dict()) if job else self.send(404, {'error': '找不到這個工作。'})
        if path == '/api/alive':
            return self.send(200, {'ok': True})
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        global _last_seen
        if not self.allowed():
            return self.send(403, {'error': '請從 Argus App 打開這個頁面。'})
        _last_seen = time.time()
        path, data = urlparse(self.path).path, self.body()
        try:
            if path == '/api/pick':
                picked = native.pick_zip() if data.get('kind') == 'zip' else native.pick_folder()
                return self.send(200, {'path': picked})
            if path == '/api/scan':
                if jobs.busy():
                    return self.send(409, {'error': '已經有工作在進行，請等它完成。'})
                job = jobs.scan(data.get('kind'), data.get('value'), data.get('scanners') or [])
                return self.send(200, job.to_dict())
            if path == '/api/install':
                if jobs.busy():
                    return self.send(409, {'error': '已經有工作在進行，請等它完成。'})
                sid = data.get('id')
                # the install job checks the tool starts; record that before the job reports done
                job = jobs.install(sid, on_checked=lambda v: _status.__setitem__(sid, ('ok', v) if v else ('broken', '')))
                return self.send(200, job.to_dict())
            if path == '/api/check-update':   # 「檢查更新」 in About
                return self.send(200, updates.check())
            if path == '/api/update':
                if jobs.busy():
                    return self.send(409, {'error': '已經有工作在進行，請等它完成再更新。'})
                return self.send(200, jobs.update().to_dict())
            if path == '/api/relaunch':   # after an update: open the new Argus, then this one stops
                app = updates.app_bundle()
                if app is None:
                    return self.send(400, {'error': '找不到 Argus 的位置，請自己重新打開 Argus。'})
                native.relaunch(app)
                threading.Timer(1.5, self.server.shutdown).start()
                return self.send(200, {'ok': True})
            if path == '/api/quit':   # "結束 Argus": stop now, e.g. when something is stuck
                threading.Timer(0.5, self.server.shutdown).start()
                return self.send(200, {'ok': True})
            if path == '/api/open':
                target = tools.reports_dir()
                if data.get('file'):
                    f = target / data['file']
                    if '/' in data['file'] or not f.is_file():
                        return self.send(404, {'error': '找不到這份報告。'})
                    target = f
                native.open_path(target)
                return self.send(200, {'ok': True})
        except (targets.TargetError, native.Unsupported) as err:
            return self.send(400, {'error': str(err)})
        self.send(404, {'error': 'not found'})


def watchdog(server):
    while True:
        time.sleep(15)
        if time.time() - _last_seen > IDLE_SECONDS and not jobs.busy():
            server.shutdown()
            return


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    port = int(argv[argv.index('--port') + 1]) if '--port' in argv else 0
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    url = f'http://127.0.0.1:{server.server_address[1]}/?t={TOKEN}'
    threading.Thread(target=check_tools, daemon=True).start()
    threading.Thread(target=updates.check, daemon=True).start()
    if '--no-idle-exit' not in argv:
        threading.Thread(target=watchdog, args=(server,), daemon=True).start()
    url_file = tools.state_dir() / 'url'
    url_file.write_text(url, encoding='utf-8')   # the launcher reads this to open the page
    print(url, flush=True)
    if '--open' in argv:
        native.open_path(url)
    try:
        server.serve_forever()
    finally:
        if url_file.exists() and url_file.read_text(encoding='utf-8') == url:
            url_file.unlink()
