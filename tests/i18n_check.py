"""Checks Argus's translations.

    python3 tests/i18n_check.py            # report: text not marked for translation, missing / stale / broken entries
    python3 tests/i18n_check.py --sync     # also add missing sentences to each catalog as "" and drop stale ones

What counts as a sentence to translate:
- Python: the text in _('…') and N_('…') (only plain text in them: no f-strings, no joining)
- ui/app.js and the report's script: the text in t('…')
- ui/index.html: each text between tags, title / aria-label / placeholder / alt, and the inside of data-i18n elements

Text in Chinese anywhere else in the code (not in a comment or docstring) is listed as not marked, unless its
line ends with the comment  i18n: keep  (Python: # i18n: keep, JavaScript: // i18n: keep).
"""

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / 'core' / 'argus'
sys.path.insert(0, str(ROOT / 'core'))
from argus import i18n  # noqa: E402

CJK = re.compile(r'[぀-ヿ㐀-鿿가-힯！-～　-〿]')
PLACEHOLDER = re.compile(r'\{(\w*)\}')
TAG = re.compile(r'</?\w+')
JS_CALL = re.compile(r'''\bt\(\s*(['"`])((?:\\.|(?!\1).)*?)\1''', re.S)
KEEP = 'i18n: keep'


def _js_unescape(s):
    return re.sub(r'\\(.)', lambda m: {'n': '\n', 't': '\t'}.get(m.group(1), m.group(1)), s)


def python_sources():
    found, unmarked, shadow = {}, [], []
    for path in sorted(CORE.rglob('*.py')):
        if '__pycache__' in path.parts:
            continue
        text = path.read_text(encoding='utf-8')
        lines = text.splitlines()
        tree = ast.parse(text)
        marked, docstrings = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                    docstrings.add(id(body[0].value))
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ''
                if name in ('_', 'N_') and node.args:
                    a = node.args[0]
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        found.setdefault(a.value, f'{path.relative_to(ROOT)}:{a.lineno}')
                        marked.add(id(a))
                    elif isinstance(a, (ast.JoinedStr, ast.BinOp)):   # f-strings and joins can't be looked up
                        unmarked.append(f'{path.relative_to(ROOT)}:{node.lineno}  _() needs plain text, not {type(a).__name__}')
            if isinstance(node, ast.Name) and node.id == '_' and isinstance(node.ctx, ast.Store) and path.name != 'i18n.py':
                shadow.append(f'{path.relative_to(ROOT)}:{node.lineno}')
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and CJK.search(node.value) \
                    and id(node) not in marked and id(node) not in docstrings:
                line = lines[node.lineno - 1]
                if KEEP not in line and not _in_js_template(path, node, lines):
                    unmarked.append(f'{path.relative_to(ROOT)}:{node.lineno}  {node.value[:60]!r}')
    return found, unmarked, shadow


def _in_js_template(path, node, lines):
    """report.py holds the report's script as one long string: its sentences are checked as JavaScript."""
    return path.name == 'report.py' and len(node.value) > 2000 and 'addEventListener' in node.value


def js_sources():
    found, unmarked = {}, []
    scripts = [(CORE / 'ui' / 'app.js', (CORE / 'ui' / 'app.js').read_text(encoding='utf-8'))]
    report = (CORE / 'report.py').read_text(encoding='utf-8')
    for node in ast.walk(ast.parse(report)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 2000 \
                and 'addEventListener' in node.value:
            scripts.append((CORE / 'report.py', node.value))
    for path, text in scripts:
        spans = []
        for m in JS_CALL.finditer(text):
            s = _js_unescape(m.group(2))
            if m.group(1) == '`' and '${' in s:
                unmarked.append(f'{path.relative_to(ROOT)}  t(`…${{}}…`) needs plain text: {s[:50]!r}')
                continue
            found.setdefault(s, str(path.relative_to(ROOT)))
            spans.append(m.span())
        code = _strip_js_comments(text)
        for n, line in enumerate(code.splitlines(), 1):
            if CJK.search(line) and KEEP not in line:
                rest = JS_CALL.sub('', line)
                if CJK.search(rest):
                    unmarked.append(f'{path.relative_to(ROOT)}:{n}  {line.strip()[:70]}')
    return found, unmarked


def _strip_js_comments(text):
    out = []
    for line in text.splitlines():
        stripped = re.sub(r'(^|\s)//(?!.*i18n: keep).*$', '', line) if '//' in line and not re.search(r'https?://', line) else line
        out.append(stripped)
    return re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), '\n'.join(out), flags=re.S)


def html_sources():
    page = (CORE / 'ui' / 'index.html').read_text(encoding='utf-8')
    page = re.sub(r'<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->', '', page, flags=re.S)
    return {s: 'core/argus/ui/index.html' for s in i18n.html_texts(page) if CJK.search(s)}


def all_sources():
    py, unmarked, shadow = python_sources()
    js, js_unmarked = js_sources()
    sources = {**html_sources(), **js, **py}
    return sources, unmarked + js_unmarked, shadow


def check_entry(src, value):
    """→ what's wrong with one translation ('' when fine)."""
    values = list(value.values()) if isinstance(value, dict) else [value]
    if isinstance(value, dict) and 'other' not in value:
        return 'a number-dependent entry needs "other"'
    want = set(PLACEHOLDER.findall(src))
    for v in values:
        if not isinstance(v, str) or not v.strip():
            return 'empty'
        if set(PLACEHOLDER.findall(v)) - want or (want - set(PLACEHOLDER.findall(v)) - {'n'} if isinstance(value, dict) else want - set(PLACEHOLDER.findall(v))):
            return f'placeholders differ: {sorted(want)} vs {sorted(set(PLACEHOLDER.findall(v)))}'
        if sorted(TAG.findall(src)) != sorted(TAG.findall(v)):
            return 'HTML tags differ'
    return ''


def main(sync=False):
    sources, unmarked, shadow = all_sources()
    problems = 0
    if shadow:
        problems += len(shadow)
        print(f'_ used as a variable where _() translates ({len(shadow)}):', *shadow, sep='\n  ')
    if unmarked:
        problems += len(unmarked)
        print(f'\nChinese text not marked for translation ({len(unmarked)}):', *unmarked[:400], sep='\n  ')
    for code in i18n.LANGS:
        if code == i18n.SOURCE:
            continue
        path = i18n.FOLDER / f'{code}.json'
        cat = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
        missing = [s for s in sources if not cat.get(s)]
        stale = [s for s in cat if s not in sources]
        broken = [(s, why) for s, v in cat.items() if s in sources and v and (why := check_entry(s, v))]
        print(f'\n{code}: {len(sources) - len(missing)} / {len(sources)} translated, {len(missing)} missing, '
              f'{len(stale)} stale, {len(broken)} broken')
        for s, why in broken[:50]:
            print(f'  broken ({why}): {s[:70]!r}')
        problems += len(missing) + len(broken)
        if sync:
            new = {s: cat.get(s, '') for s in sources}
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps(new, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(f'\n{len(sources)} sentences; {problems} problems')
    return problems


if __name__ == '__main__':
    sys.exit(1 if main(sync='--sync' in sys.argv) else 0)
