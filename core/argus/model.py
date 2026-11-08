"""The shapes every scanner's results are turned into, so the report can treat all scanners alike."""

import os
import re
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


DOC_EXT = {'.md', '.markdown', '.txt', '.rst'}
DOC_DIRS = {'references', 'reference', 'examples', 'example', 'docs', 'doc'}
# example hosts used in documentation, never real destinations
PLACEHOLDER_HOST = re.compile(r'https?://(?:[\w-]+\.)*(?:example\.(?:com|org|net)|localhost|127\.0\.0\.1)\b', re.I)


def is_type_definitions(path):
    """A TypeScript .d.ts file only describes an interface; nothing in it runs."""
    return path.lower().endswith('.d.ts')


def is_documentation(path):
    """README, or a text/Markdown file (or example config) under references/, examples/ or docs/.

    SKILL.md itself is not counted: it is what the AI follows as instructions.
    """
    parts = path.replace('\\', '/').split('/')
    name, ext = parts[-1].lower(), os.path.splitext(parts[-1])[1].lower()
    if name in ('readme.md', 'readme.txt', 'readme'):
        return True
    in_docs = len(parts) > 1 and parts[0].lower() in DOC_DIRS
    return in_docs and (ext in DOC_EXT or (parts[0].lower() in ('examples', 'example') and ext in ('.json', '.yaml', '.yml')))


def is_table_padding(snippet):
    """Most lines are Markdown table rows: the long runs of spaces are just column alignment."""
    lines = [line.strip().lstrip('*').strip() for line in snippet.splitlines() if line.strip()]
    return bool(lines) and sum(line.startswith('|') for line in lines) >= max(2, len(lines) * 0.6)


def worst_severity(findings):
    sev = [f.severity for f in findings if f.severity in SEVERITIES]
    return min(sev, key=SEVERITIES.index) if sev else None


def clip(text, n):
    text = (text or '').strip()
    return text if len(text) <= n else text[:n] + '…'
