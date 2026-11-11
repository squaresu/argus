"""已看過 and update tracking: remember a skill's files and findings, and say what changed since.

Two records per skill, both kept on this computer only (in Argus's own folder):
- reviewed: what the skill looked like when the person pressed 標記為已看過 in a report;
- last: what it looked like at the most recent scan, so a change is noticed even for skills never reviewed.
Each holds a hash of every file (to list added, changed and removed files) and the fingerprints of the findings
(to tell findings already seen from new ones).
"""

import hashlib
import json
import time
from pathlib import Path

from . import tools

MAX_FILES = 3000
MAX_BYTES = 20 * 1024 * 1024
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
LIST_LIMIT = 12


def file_hashes(folder: Path):
    """{relative path: sha256} for the skill's files (bounded, so a huge folder can't stall a scan)."""
    hashes = {}
    stack = [folder]
    while stack and len(hashes) < MAX_FILES:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir() and not e.is_symlink():
                if e.name not in SKIP_DIRS:
                    stack.append(e)
            elif e.is_file():
                try:
                    if e.stat().st_size > MAX_BYTES:
                        digest = f'large:{e.stat().st_size}'
                    else:
                        digest = hashlib.sha256(e.read_bytes()).hexdigest()
                except OSError:
                    continue
                hashes[e.relative_to(folder).as_posix()] = digest
    return hashes


def snapshot(folder: Path | None, findings, files=None):
    return {'at': time.strftime('%Y/%m/%d %H:%M'), 'files': files if files is not None else file_hashes(folder),
            'findings': sorted({f.fingerprint for f in findings})}


def diff_files(old, new):
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    return {'added': added[:LIST_LIMIT], 'removed': removed[:LIST_LIMIT], 'changed': changed[:LIST_LIMIT],
            'count': len(added) + len(removed) + len(changed)}


class Store:
    """reviews.json: {skill key: {'name', 'reviewed': snapshot or None, 'last': snapshot}}."""

    def __init__(self, path: Path | None = None):
        self.path = path or tools.state_dir() / 'reviews.json'
        try:
            self.data = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            self.data = {}

    def save(self):
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.data, ensure_ascii=False), encoding='utf-8')
        tmp.replace(self.path)

    def compare(self, key, snap):
        """How this scan compares with the reviewed copy (or, failing that, the last scan). Marks nothing."""
        entry = self.data.get(key) or {}
        reviewed, last = entry.get('reviewed'), entry.get('last')
        base = reviewed or last
        if not base:
            return {'status': 'new'}
        files = diff_files(base.get('files', {}), snap['files'])
        known = set(base.get('findings', []))
        new_findings = [fp for fp in snap['findings'] if fp not in known]
        if reviewed:
            status = 'reviewed' if not files['count'] else 'changed_since_review'
            return {'status': status, 'since': reviewed.get('at', ''), 'files': files, 'known': sorted(known),
                    'new_findings': len(new_findings)}
        status = 'changed_since_scan' if files['count'] else 'same_as_last_scan'
        return {'status': status, 'since': last.get('at', ''), 'files': files, 'known': [],
                'new_findings': len(new_findings)}

    def remember_scan(self, key, name, snap):
        self.data.setdefault(key, {'reviewed': None})
        self.data[key].update(name=name, last=snap)

    def mark(self, key, name, snap, reviewed=True):
        self.data.setdefault(key, {'last': snap})
        self.data[key]['name'] = name
        self.data[key]['reviewed'] = snap if reviewed else None

    def reviewed_count(self):
        return sum(1 for v in self.data.values() if v.get('reviewed'))

    def clear_reviews(self):
        for v in self.data.values():
            v['reviewed'] = None
