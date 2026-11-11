"""How long each scanner takes per skill on this computer, so a scan can say up front roughly how long it'll be.

Starts from rough guesses and learns from every scan (kept in Argus's own folder, on this computer only).
"""

import json
import threading

from . import tools

# seconds per skill, before this computer has measured anything (SkillSpector and Cisco start a large program)
GUESS = {'skillspector': 45, 'cisco': 30, 'bandit': 5, 'semgrep': 20, 'secrets': 5, 'osv': 8}
OTHER = 15
PARALLEL = 3      # scanner runs at a time (see jobs.PARALLEL)
OVERHEAD = 5      # preparing, comparing and writing the report
_lock = threading.Lock()


def _path():
    return tools.state_dir() / 'timings.json'


def load():
    try:
        data = json.loads(_path().read_text(encoding='utf-8'))
        return {k: float(v) for k, v in data.items() if isinstance(v, (int, float))}
    except (OSError, ValueError, AttributeError):
        return {}


def record(scanner_id, seconds):
    """Fold one measured run into the running average (recent runs count more)."""
    with _lock:
        data = load()
        old = data.get(scanner_id)
        data[scanner_id] = round(seconds if old is None else old * 0.7 + seconds * 0.3, 1)
        try:
            _path().write_text(json.dumps(data), encoding='utf-8')
        except OSError:
            pass


def per_run(scanner_id, learned=None):
    learned = load() if learned is None else learned
    return learned.get(scanner_id, GUESS.get(scanner_id, OTHER))


def estimate(runs):
    """runs: the scanner id of every (skill, scanner) pair to be run → seconds for the whole scan."""
    learned = load()
    total = sum(per_run(sid, learned) for sid in runs)
    return round(total / min(PARALLEL, max(len(runs), 1)) + OVERHEAD) if runs else 0


def words(seconds):
    """Seconds as a rough, friendly length of time."""
    if seconds < 60:
        return '不到 1 分鐘'
    minutes = round(seconds / 60)
    return f'大約 {minutes} 分鐘' if minutes < 60 else f'大約 {minutes / 60:.1f} 小時'
