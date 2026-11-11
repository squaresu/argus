"""Scans and installs run in the background as jobs; the page polls them for progress."""

import json
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from . import capabilities, mcp, reminder, report, reviews, scanners, targets, timing, tools, updates
from .model import Outcome, SkillResult

PARALLEL = timing.PARALLEL   # scanner runs at a time; each is its own process

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
        self.estimate = 0            # a scan: seconds the whole thing should take, once its size is known

    def say(self, text):
        self.current = text
        self.log.append(f'{datetime.now():%H:%M:%S}  {text}')
        del self.log[:-200]

    def remaining(self):
        """Rough seconds left: from the up-front estimate until a few runs are done, then from the pace so far."""
        elapsed = time.time() - self.started
        if self.status != 'running' or not self.total:
            return None
        if self.done >= max(3, self.total // 5):
            return round(elapsed / self.done * (self.total - self.done)) + timing.OVERHEAD
        return max(round(self.estimate - elapsed), 10) if self.estimate else None

    def to_dict(self):
        return {k: getattr(self, k) for k in ('id', 'kind', 'label', 'status', 'done', 'total', 'current',
                                              'log', 'error', 'result', 'target')} | {
            'elapsed': round(time.time() - self.started), 'remaining': self.remaining()}


def start(job, work):
    with _lock:
        _jobs[job.id] = job

    def runner():
        try:
            work(job)
            job.status = 'done'
        except (targets.TargetError, updates.UpdateError) as err:
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

def skill_key(kind, value, folder: Path, tmp: Path):
    """Identifies a skill across scans: its real folder when it's on this computer; for a download, where it came
    from and where it sits inside (leaving out the archive's own top folder, whose name changes with the version)."""
    if kind in ('claude', 'folder'):
        return 'path:' + str(folder.resolve())
    try:
        parts = folder.relative_to(tmp).parts
    except ValueError:
        parts = (folder.name,)
    inside = '/'.join(parts[2:] if kind == 'github' else parts[1:]) or '.'
    return f'{kind}:{value.strip()}::{inside}'


def track(results, folders):
    """Compare each result with the reviewed copy (or the last scan), mark findings already seen, remember this
    scan. → {key: {'name', 'snapshot'}} for the report, so 標記為已看過 records exactly what the report showed."""
    store = reviews.Store()
    snapshots = {}
    for r, folder in zip(results, folders):
        snap = reviews.snapshot(folder, r.findings, files=r.tracked or None)
        r.change = store.compare(r.key, snap)
        known = set(r.change.get('known', []))
        for f in r.findings:
            f.known = f.fingerprint in known
        store.remember_scan(r.key, r.name, snap)
        snapshots[r.key] = {'name': r.name, 'snapshot': snap}
    store.save()
    return snapshots


def scan(kind, value, scanner_ids):
    if kind == 'mcp':
        return scan_mcp()
    chosen = [s for s in scanners.all_scanners() if s.id in scanner_ids and s.installed()]
    if not chosen:
        raise targets.TargetError('請至少勾選一個已安裝的掃描工具。')

    def work(job):
        tmp = Path(tempfile.mkdtemp(prefix='argus-'))
        try:
            job.say('正在準備要掃描的內容…')
            title, folders = targets.resolve(kind, value, tmp)
            results = [SkillResult(targets.skill_name(f), str(f), key=skill_key(kind, value, f, tmp),
                                   capabilities=capabilities.analyze(f)) for f in folders]
            pairs = [(r, f, s) for r, f in zip(results, folders) for s in chosen]
            job.total = len(pairs)
            job.estimate = time.time() - job.started + timing.estimate(
                [s.id for _, f, s in pairs if s.applies_to(f)])
            job.say(f'找到 {len(folders)} 個技能，用 {len(chosen)} 個工具檢查，預估{timing.words(job.estimate)}…')
            versions = {s.id: s.version() or '?' for s in chosen}

            def one(pair):
                result, folder, scanner = pair
                if not scanner.applies_to(folder):
                    outcome = Outcome(scanner.id, 'SKIPPED', note=f'{scanner.name}：沒有它要檢查的檔案。')
                else:
                    with tempfile.TemporaryDirectory(prefix='argus-') as w:
                        began = time.time()
                        try:
                            outcome = scanner.scan(folder, Path(w))
                        except Exception as err:   # a plug-in bug shouldn't sink the whole scan
                            outcome = Outcome(scanner.id, 'ERROR', error=f'{type(err).__name__}: {err}')
                        if outcome.verdict != 'ERROR':
                            timing.record(scanner.id, time.time() - began)
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
            job.say('正在跟上次的結果比對…')
            snapshots = track(results, folders)
            job.say('正在產生報告…')
            job.result = report.save(title, results, chosen, versions, snapshots, installed=kind == 'claude')
            if kind in ('claude', 'folder'):   # what was just scanned no longer needs a reminder
                reminder.recheck()
        finally:
            targets.cleanup(tmp)

    return start(Job('scan', '掃描'), work)


def estimate(kind, value, scanner_ids):
    """Before a scan: how many skills and roughly how long. Downloads aren't counted until they're fetched."""
    chosen = [s for s in scanners.all_scanners() if s.id in scanner_ids and s.installed()]
    if kind == 'claude':
        folders = targets.claude_skills()
    elif kind == 'folder' and value and Path(value).is_dir():
        folders = targets.expand(Path(value))
    else:
        return {'skills': None, 'per_skill': timing.estimate([s.id for s in chosen]) if chosen else 0}
    folders = folders[:500]
    runs = [s.id for f in folders for s in chosen if s.applies_to(f)]
    return {'skills': len(folders), 'seconds': timing.estimate(runs)}


def scan_mcp():
    """Argus's own check of the MCP servers set up on this computer: reads settings, starts nothing."""
    def work(job):
        job.say('正在讀取 MCP 伺服器的設定…')
        results = mcp.inspect_all()
        if not results:
            raise targets.TargetError('在這台電腦上找不到任何 MCP 伺服器的設定（Claude Code、Claude 桌面版、外掛、Cursor）。')
        job.total = job.done = len(results)
        job.say(f'找到 {len(results)} 個 MCP 伺服器，正在比對…')
        snapshots = track(results, [None] * len(results))
        job.result = report.save('我的 MCP 伺服器', results, [mcp.TOOL], {mcp.SCANNER: '內建'}, snapshots, installed=True)

    return start(Job('scan', '掃描 MCP 伺服器'), work)


def mark_reviewed(report_file, key, reviewed=True):
    """標記為已看過 (or undo it) for one skill, using the snapshot saved with that report."""
    meta = tools.reports_dir() / (Path(report_file).stem + '.json')
    try:
        entry = json.loads(meta.read_text(encoding='utf-8'))['snapshots'][key]
    except (OSError, ValueError, KeyError):
        raise targets.TargetError('這份報告比較舊，沒有記錄可以比對的資料。請重新掃描一次再標記。')
    store = reviews.Store()
    store.mark(key, entry['name'], entry['snapshot'], reviewed)
    store.save()
    return store.reviewed_count()


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
        if not uv and scanner.needs_uv:
            raise targets.TargetError('找不到 uv（安裝工具用的程式）。請關掉 Argus 再重新打開，它會自動安裝 uv。')
        job.total = 2
        job.say(f'正在安裝 {scanner.name}，大約 1–3 分鐘…')
        log = tools.state_dir() / 'install.log'
        code, out, err = scanner.install(uv)
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


# --- updating Argus itself ---

def update():
    return start(Job('update', '更新 Argus'), updates.apply)


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
