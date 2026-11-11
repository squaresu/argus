"""Reminds the person to check their Claude skills again: when a skill changed or arrived since it was last
scanned, or hasn't been scanned for a month. Compares files with what the last scan saw; reads only.
"""

import threading
import time
from datetime import datetime

from . import reviews, targets

STALE_DAYS = 30
LIST_LIMIT = 6
_result = {'checked': False}
_lock = threading.Lock()


def check():
    """Compare every installed Claude skill with its last scan. Runs in the background; see status()."""
    global _result
    if not _lock.acquire(blocking=False):   # already checking
        return
    try:
        _result = {'checked': False}
        _result = compute()
    except Exception as err:   # a reminder must never get in the way
        _result = {'checked': True, 'show': False, 'error': str(err)}
    finally:
        _lock.release()


def compute(now=None, store=None, skills=None):
    now = now or time.time()
    store = store or reviews.Store()
    skills = targets.claude_skills() if skills is None else skills
    new, changed, stale, ages = [], [], [], []
    for folder in skills:
        name = targets.skill_name(folder)
        last = (store.data.get('path:' + str(folder.resolve())) or {}).get('last')
        if not last:
            new.append(name)
            continue
        try:
            age = (now - datetime.strptime(last.get('at', ''), '%Y/%m/%d %H:%M').timestamp()) / 86400
        except ValueError:
            age = STALE_DAYS
        ages.append(age)
        if reviews.diff_files(last.get('files') or {}, reviews.file_hashes(folder))['count']:
            changed.append(name)
        elif age >= STALE_DAYS:
            stale.append(name)
    never = bool(skills) and not ages
    return {'checked': True, 'show': bool(new or changed or stale), 'total': len(skills), 'never': never,
            'new': sorted(new)[:LIST_LIMIT], 'new_count': len(new),
            'changed': sorted(changed)[:LIST_LIMIT], 'changed_count': len(changed),
            'stale_count': len(stale), 'days': int(max(ages)) if ages else None,
            # changes when the situation does, so 稍後再說 can come back when there's something new
            'signature': f'{len(skills)}:{",".join(sorted(new + changed))}'}


def status():
    return dict(_result)


def recheck():
    threading.Thread(target=check, daemon=True).start()
