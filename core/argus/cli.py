"""The Argus command line, for Claude and for the automatic check. The page is the usual way in; this is
the same scan without it.

    argus scan <target> [--tools id,id]   target: a folder, a zip, a GitHub link, `claude` or `mcp`
    argus watch [--now]                   scan Claude skills installed or changed since they were last checked

`scan` prints the conclusion, what needs a look, and where the full report is (the same text as the report's
複製整份報告給 Claude 判斷). Progress goes to stderr, so the result on stdout stays clean.
"""

import sys
import time
from pathlib import Path

from . import NAME, VERSION, integrations, jobs, reminder, report, scanners, tools

USAGE = __doc__.split('\n\n')[1]
SETTLE = 45   # seconds to wait after a change before checking, so an install in progress can finish


def target_of(value):
    """What the person typed → (kind, value) for jobs.scan."""
    v = value.strip()
    if v.lower() in ('claude', 'mcp'):
        return v.lower(), ''
    if v.startswith(('http://', 'https://')):
        return 'github', v
    p = Path(v).expanduser()
    if p.is_file() and p.suffix.lower() == '.zip':
        return 'zip', str(p)
    return 'folder', str(p)


def run(kind, value, scanner_ids, say=lambda text: None):
    """Start a scan and wait for it. → the finished job (status 'done' or 'error')."""
    job = jobs.scan(kind, value, scanner_ids)
    last = ''
    while job.status == 'running':
        if job.current != last:
            last = job.current
            say(last)
        time.sleep(0.5)
    return job


def installed_scanner_ids(wanted=None):
    ids = [s.id for s in scanners.all_scanners() if s.installed()]
    return [i for i in ids if i in wanted] if wanted else ids


def scan_command(args):
    if not args:
        print(USAGE, file=sys.stderr)
        return 2
    wanted = None
    if '--tools' in args:
        i = args.index('--tools')
        wanted = [t.strip() for t in (args[i + 1] if i + 1 < len(args) else '').split(',') if t.strip()]
        args = args[:i] + args[i + 2:]
    kind, value = target_of(' '.join(args))
    ids = installed_scanner_ids(wanted)
    if kind != 'mcp' and not ids:
        print('還沒有安裝任何掃描工具。請打開 Argus App，在「用哪些工具？」按「安裝」。', file=sys.stderr)
        return 1
    job = run(kind, value, ids, say=lambda text: print(f'… {text}', file=sys.stderr, flush=True))
    if job.status != 'done':
        print(f'沒有完成：{job.error}', file=sys.stderr)
        return 1
    results = job.results
    is_mcp = kind == 'mcp'
    unit = '個 MCP 伺服器' if is_mcp else '個技能'
    _, line = report.summary_line(results, job.installed, unit)
    out = [f'{NAME} {VERSION} 檢查完成：共 {len(results)} {unit}',
           f'Argus 依規則的初步結論：{line}', '',
           report.claude_all(results, job.installed, unit),
           f'完整報告：{tools.reports_dir() / job.result}']
    print('\n'.join(out))
    return 0


def watch_command(args):
    """One pass of the automatic check (launchd starts it when the skills change)."""
    lock = tools.state_dir() / 'autocheck.lock'
    if lock.exists() and time.time() - lock.stat().st_mtime < 3 * 3600:
        print('another check is still running', flush=True)
        return 0
    lock.write_text(str(time.time()))
    try:
        if '--now' not in args:
            time.sleep(SETTLE)
        todo = reminder.pending()
        print(f'{time.strftime("%Y-%m-%d %H:%M")} {len(todo)} skill(s) to check', flush=True)
        if not todo:
            return 0
        ids = installed_scanner_ids()
        if not ids:
            return 0
        job = run('paths', [str(f) for f in todo], ids)
        if job.status != 'done':
            integrations.notify('Argus', f'自動檢查新技能時出了問題：{job.error}')
            return 1
        worst, line = report.summary_line(job.results, True, '個技能')
        names = '、'.join(r.name for r in job.results[:4]) + (' 等' if len(job.results) > 4 else '')
        message = f'檢查了新裝或更新的技能（{names}）。\n結論：{line}'
        integrations.notify('Argus 自動檢查', message, report=tools.reports_dir() / job.result, urgent=worst != 'ok')
        return 0
    finally:
        lock.unlink(missing_ok=True)


def main(argv):
    command, args = (argv[0], argv[1:]) if argv else ('', [])
    if command == 'scan':
        return scan_command(args)
    if command == 'watch':
        return watch_command(args)
    print(USAGE, file=sys.stderr)
    return 2
