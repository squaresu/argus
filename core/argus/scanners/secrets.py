"""detect-secrets (Yelp): finds passwords, API keys and tokens written into files."""

import json
import re

from .. import tools
from ..model import Finding, Outcome
from .base import Scanner, failed

WHAT = '檔案裡好像直接寫了密碼、API 金鑰或權杖。技能被分享出去，這些機密也會跟著外流。'
TIP = '看那一行是真的金鑰，還是範例用的假值（例如 sk-xxxx、your-api-key）；真的金鑰不該出現在技能裡。'
NOISY_TYPES = {'Hex High Entropy String', 'Base64 High Entropy String'}
EXAMPLE_PATH = re.compile(r'(^|/)(tests?|examples?|samples?|fixtures?|docs?)(/|$)|example|sample|mock|fake|dummy', re.I)


def masked_line(path, line_no):
    """The flagged line with long secret-looking runs mostly hidden, so the report doesn't spread the secret."""
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for n, line in enumerate(fh, 1):
                if n == line_no:
                    line = line.strip()[:300]
                    return re.sub(r'[A-Za-z0-9_\-+/=]{12,}', lambda m: m.group()[:4] + '••••••' + m.group()[-2:], line)
    except OSError:
        pass
    return ''


def parse(data, root=None) -> Outcome:
    findings = []
    for filename, hits in (data.get('results') or {}).items():
        for h in hits:
            kind = h.get('type') or 'Secret'
            f = Finding(scanner='secrets', title=f'可能寫死的機密（{kind}）', what=WHAT, tip=TIP, severity='MEDIUM',
                        file=filename, line=h.get('line_number'), rule=kind, category=kind,
                        detail=f'detect-secrets: {kind}')
            if root is not None and f.line:
                f.snippet = masked_line(root / filename, f.line)
            if kind in NOISY_TYPES:
                f.calm = '只是一串看起來很亂的字，常是檔案雜湊、ID 或編碼過的圖片，不一定是密碼。'
            elif EXAMPLE_PATH.search(filename):
                f.calm = '出現在範例、測試或說明檔裡，常是示範用的假值。'
            findings.append(f)
    real = [f for f in findings if not f.calm]
    return Outcome('secrets', 'CAUTION' if real else 'SAFE', findings,
                   note='找到疑似寫死的機密：技能本身不一定有惡意，但不該把真的金鑰放進技能。' if real else '')


class DetectSecrets(Scanner):
    id = 'secrets'
    name = 'detect-secrets'
    vendor = 'Yelp'
    license = 'Apache-2.0'
    homepage = 'https://github.com/Yelp/detect-secrets'
    summary = '找技能裡有沒有寫死的密碼、API 金鑰或權杖。'
    order = 40
    exe = 'detect-secrets'
    package = 'detect-secrets'

    def scan(self, skill_dir, work):
        code, out, err = tools.run([tools.find_exe(self.exe), 'scan', '--all-files', '--exclude-files',
                                    r'(^|/)(\.git|node_modules)/', '.'], cwd=skill_dir)
        try:
            data = json.loads(out)
        except ValueError:
            return failed(self.id, tools.last_lines(err))
        return parse(data, skill_dir)


SCANNER = DetectSecrets()
