"""The shapes every scanner's results are turned into, so the report can treat all scanners alike."""

import os
from dataclasses import asdict, dataclass, field

# verdicts, worst first; SKIPPED (nothing for this scanner to check) and ERROR don't decide a skill's verdict
VERDICTS = ['DO_NOT_INSTALL', 'CAUTION', 'SAFE']
VERDICT_ZH = {
    'DO_NOT_INSTALL': ('不建議安裝', 'danger'),
    'CAUTION': ('注意', 'caution'),
    'SAFE': ('安全', 'safe'),
    'ERROR': ('沒掃完', 'error'),
    'SKIPPED': ('不適用', 'muted'),
}
SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
SEVERITY_ZH = {'CRITICAL': ('嚴重', 'danger'), 'HIGH': ('高', 'danger'), 'MEDIUM': ('中', 'caution'),
               'LOW': ('低', 'safe'), 'INFO': ('資訊', 'safe')}

STYLE_EXT = {'.css', '.scss', '.sass', '.less'}
CODE_EXT = {'.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.sh', '.rb', '.go', '.rs', '.java', '.swift', '.php'}


@dataclass
class Finding:
    scanner: str          # scanner id
    title: str            # short Chinese name of the kind of problem
    what: str = ''        # what it means, in plain Chinese
    tip: str = ''         # how to tell a real problem from a false alarm
    severity: str = 'MEDIUM'
    file: str = ''
    line: int | None = None
    snippet: str = ''
    rule: str = ''        # the scanner's own rule id
    category: str = ''    # the scanner's own category name, kept for the question to Claude
    detail: str = ''      # the scanner's own explanation (usually English)
    calm: str = ''        # why this is probably nothing to worry about; '' means it needs a look

    @property
    def ext(self):
        return os.path.splitext(self.file)[1].lower()


@dataclass
class Outcome:
    """One scanner's result for one skill."""
    scanner: str
    verdict: str                      # one of VERDICTS, or ERROR / SKIPPED
    findings: list[Finding] = field(default_factory=list)
    score: int | None = None          # 0-100 when the scanner gives one
    note: str = ''                    # a sentence about this result, shown under the skill
    error: str = ''


@dataclass
class SkillResult:
    name: str
    path: str
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def verdict(self):
        decided = [o.verdict for o in self.outcomes if o.verdict in VERDICTS]
        if decided:
            return min(decided, key=VERDICTS.index)
        return 'ERROR' if any(o.verdict == 'ERROR' for o in self.outcomes) else 'SAFE'

    @property
    def findings(self):
        return [f for o in self.outcomes for f in o.findings]

    def to_dict(self):
        return asdict(self) | {'verdict': self.verdict}


def worst_severity(findings):
    sev = [f.severity for f in findings if f.severity in SEVERITIES]
    return min(sev, key=SEVERITIES.index) if sev else None


def clip(text, n):
    text = (text or '').strip()
    return text if len(text) <= n else text[:n] + '…'
