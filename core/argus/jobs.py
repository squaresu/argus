"""Scans and installs run in the background as jobs; the page polls them for progress."""

import json
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from . import report, scanners, targets, tools
from .model import Outcome, SkillResult

PARALLEL = 3   # scanner runs at a time; each is its own process

_jobs = {}
_lock = threading.Lock()


class Job:
    def __init__(self, kind, label):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.label = label
        self.status = 'running'      # running → done | error
        self.done = 0
        self.total = 0
        self.current = '準備中…'
        self.log = []
        self.error = ''
        self.result = None           # a scan: the report's file name
        self.target = ''             # an install: the scanner id
        self.started = time.time()

    def say(self, text):
        self.current = text
        self.log.append(f'{datetime.now():%H:%M:%S}  {text}')
        del self.log[:-200]

    def to_dict(self):
        return {k: getattr(self, k) for k in ('id', 'kind', 'label', 'status', 'done', 'total', 'current',
                                              'log', 'error', 'result', 'target')}


def start(job, work):
    with _lock:
        _jobs[job.id] = job

    def runner():
        try:
            work(job)
            job.status = 'done'
        except targets.TargetError as err:
            job.status, job.error = 'error', str(err)
        except Exception as err:   # anything unexpected still ends the job with a message
            job.status, job.error = 'error', f'發生未預期的錯誤：{err}'
        job.say('完成' if job.status == 'done' else job.error)

    threading.Thread(target=runner, daemon=True).start()
    return job


def get(job_id):
    return _jobs.get(job_id)


def busy():
    return any(j.status == 'running' for j in _jobs.values())


# --- scanning ---

def scan(kind, value, scanner_ids):
    chosen = [s for s in scanners.all_scanners() if s.id in scanner_ids and s.installed()]
    if not chosen:
        raise targets.TargetError('請至少勾選一個已安裝的掃描工具。')

    def work(job):
        tmp = Path(tempfile.mkdtemp(prefix='argus-'))
        try:
            job.say('正在準備要掃描的內容…')
            title, folders = targets.resolve(kind, value, tmp)
            results = [SkillResult(targets.skill_name(f), str(f)) for f in folders]
            pairs = [(r, f, s) for r, f in zip(results, folders) for s in chosen]
            job.total = len(pairs)
            job.say(f'找到 {len(folders)} 個技能，用 {len(chosen)} 個工具檢查…')
            versions = {s.id: s.version() or '?' for s in chosen}

            def one(pair):
                result, folder, scanner = pair
                if not scanner.applies_to(folder):
                    outcome = Outcome(scanner.id, 'SKIPPED', note=f'{scanner.name}：沒有它要檢查的檔案。')
                else:
                    with tempfile.TemporaryDirectory(prefix='argus-') as w:
                        try:
                            outcome = scanner.scan(folder, Path(w))
                        except Exception as err:   # a plug-in bug shouldn't sink the whole scan
                            outcome = Outcome(scanner.id, 'ERROR', error=f'{type(err).__name__}: {err}')
                for f in outcome.findings:   # show paths relative to the skill, as the person sees it
                    if f.file.startswith(str(folder)):
                        f.file = f.file[len(str(folder)):].lstrip('/\\')
                with _lock:
                    result.outcomes.append(outcome)
                    job.done += 1
                    job.say(f'{scanner.name} 檢查完「{result.name}」（{job.done} / {job.total}）')

            with ThreadPoolExecutor(PARALLEL) as pool:
                list(pool.map(one, pairs))
            order = [s.id for s in chosen]
            for r in results:
                r.outcomes.sort(key=lambda o: order.index(o.scanner))
            job.say('正在產生報告…')
            job.result = report.save(title, results, chosen, versions)
        finally:
            targets.cleanup(tmp)

    return start(Job('scan', '掃描'), work)


# --- installing a scanner ---

def install(scanner_id, on_checked=None):
    scanner = scanners.get(scanner_id)
    if scanner is None:
        raise targets.TargetError('不認得的掃描工具。')
    reason = scanner.preflight()
    if reason:
        raise targets.TargetError(reason)

    def work(job):
        uv = tools.find_exe('uv')
        if not uv:
            raise targets.TargetError('找不到 uv（安裝工具用的程式）。請關掉 Argus 再重新打開，它會自動安裝 uv。')
        job.total = 2
        job.say(f'正在安裝 {scanner.name}，大約 1–3 分鐘…')
        log = tools.state_dir() / 'install.log'
        code, out, err = tools.run(scanner.install_command(uv), timeout=1200)
        with log.open('a', encoding='utf-8') as fh:
            fh.write(f'\n=== {datetime.now():%Y-%m-%d %H:%M} {scanner.name} (exit {code})\n{out}\n{err}\n')
        job.done = 1
        if code != 0:
            raise targets.TargetError(f'安裝 {scanner.name} 失敗：{tools.last_lines(err)}（完整紀錄在 {log}）')
        job.say('安裝好了，正在確認能不能正常啟動（第一次可能要一分鐘）…')
        version = scanner.version()
        if on_checked:
            on_checked(version)
        if not version:
            raise targets.TargetError(f'{scanner.name} 裝好了，但打不開。（紀錄在 {log}）')
        job.done = 2

    job = Job('install', scanner.name)
    job.target = scanner_id
    return start(job, work)


# --- past reports ---

def history(limit=30):
    items = []
    for meta in sorted(tools.reports_dir().glob('*.json'), reverse=True)[:limit]:
        try:
            d = json.loads(meta.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if (tools.reports_dir() / d.get('file', '')).is_file():
            items.append(d)
    return items
