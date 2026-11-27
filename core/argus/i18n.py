"""Argus in several languages.

The Traditional Chinese text in the code is the source: _('掃描沒有完成。') looks the sentence up in the
catalog of the language in use (i18n/en.json, ja.json, ko.json: {source: translation}) and falls back to the
source when a sentence isn't translated yet. Placeholders are named: _('有 {n} 項需要看一下。', n=3).

- A translation can depend on a number: {"one": "1 skill", "other": "{n} skills"}, picked by the n= argument.
- N_('…') marks text that is translated later, where it's used (rule titles kept in a table, for instance).
- The language: the one chosen in Argus (remembered in Argus's settings), or else the computer's.

tests/i18n_check.py lists every marked sentence and checks each catalog has all of them, placeholders intact.
"""

import html
import json
import locale
import os
import re
import subprocess
import threading
from pathlib import Path

from . import tools

SOURCE = 'zh-TW'
LANGS = {'zh-TW': '繁體中文', 'en': 'English', 'ja': '日本語', 'ko': '한국어'}   # i18n: keep (each language in its own script)
HTML_LANG = {'zh-TW': 'zh-Hant', 'en': 'en', 'ja': 'ja', 'ko': 'ko'}
FOLDER = Path(__file__).resolve().parent / 'i18n'

_lang = None
_catalogs = {}
_lock = threading.Lock()


def N_(text):
    """Marks text to translate where it's shown; returns it unchanged."""
    return text


def match(code):
    """A language code from the system or a browser (zh-Hant-TW, zh_TW, en-US, ja, ko-KR…) → one Argus has."""
    c = (code or '').replace('_', '-').lower()
    if c.startswith('zh'):
        return 'zh-TW'          # Simplified Chinese readers can read Traditional; closer than English
    for lang in ('ja', 'ko', 'en'):
        if c.startswith(lang):
            return lang
    return None


def system_lang():
    """The computer's language, as one Argus has (English when it has none of them)."""
    found = []
    if tools.IS_MAC:
        try:
            out = subprocess.run(['defaults', 'read', '-g', 'AppleLanguages'], capture_output=True, text=True, timeout=5).stdout
            found += [x.strip(' \n\t",()') for x in out.split(',')]
        except (OSError, subprocess.SubprocessError):
            pass
    if tools.IS_WIN:
        try:
            import ctypes
            found.append(locale.windows_locale.get(ctypes.windll.kernel32.GetUserDefaultUILanguage(), ''))
        except Exception:
            pass
    found += [os.environ.get(k, '') for k in ('LC_ALL', 'LC_MESSAGES', 'LANG')]
    try:
        found.append(locale.getlocale()[0] or '')
    except ValueError:
        pass
    return next((m for m in map(match, found) if m), 'en')


def _settings_path():
    return tools.state_dir() / 'settings.json'


def _settings():
    try:
        data = json.loads(_settings_path().read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def chosen():
    """The language picked in Argus, or None to follow the computer."""
    lang = _settings().get('lang')
    return lang if lang in LANGS else None


def lang():
    global _lang
    if _lang is None:
        forced = os.environ.get('ARGUS_LANG')          # tests, or someone who wants another language just once
        _lang = forced if forced in LANGS else chosen() or system_lang()
    return _lang


def set_lang(code):
    """Pick a language (None: follow the computer again). → the language now in use."""
    global _lang
    if code is not None and code not in LANGS:
        raise ValueError(code)
    data = _settings()
    if code is None:
        data.pop('lang', None)
    else:
        data['lang'] = code
    _settings_path().write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding='utf-8')
    _lang = None
    return lang()


def catalog(code=None):
    code = code or lang()
    if code == SOURCE:
        return {}
    with _lock:
        if code not in _catalogs:
            try:
                _catalogs[code] = json.loads((FOLDER / f'{code}.json').read_text(encoding='utf-8'))
            except (OSError, ValueError):
                _catalogs[code] = {}
        return _catalogs[code]


def _(text, **kw):
    """text in the language in use, with {name} placeholders filled from kw."""
    found = catalog().get(text, text) if text else text
    if isinstance(found, dict):         # a translation that depends on a number
        found = found.get('one') if kw.get('n') == 1 and 'one' in found else found.get('other', text)
    if not kw:
        return found
    try:
        return found.format(**kw)
    except (KeyError, IndexError, ValueError):
        return text.format(**kw)        # a broken translation shouldn't break the page


def join(items):
    """A list in words: 甲、乙、丙 / a, b, c."""
    return _('、').join(items)


# <p data-i18n>一句 <b>有標記</b> 的話</p>: the whole inside is one sentence, tags and all (no nesting of the same tag)
_WHOLE = re.compile(r'(<(\w+)\b[^>]*\sdata-i18n\b[^>]*>)(.*?)(</\2>)', re.S)
_TEXT = re.compile(r'>([^<>]*[^\x00-\x7f][^<>]*)<')
_ATTR = re.compile(r'\b(title|aria-label|placeholder|alt|content|data-label)="([^"]*[^\x00-\x7f][^"]*)"')


def translate_html(page, code=None):
    """A page written in the source language (index.html) → in the language in use: each text between tags,
    and title / aria-label / placeholder / alt, looked up whole (surrounding spaces kept)."""
    cat = catalog(code)
    code = code or lang()
    page = page.replace('<html lang="zh-Hant"', f'<html lang="{HTML_LANG[code]}"', 1)
    if not cat:
        return page

    def text(m):
        raw = m.group(1)
        core = raw.strip()
        found = cat.get(html.unescape(core))
        if not isinstance(found, str):
            return m.group(0)
        return '>' + raw[:len(raw) - len(raw.lstrip())] + html.escape(found, quote=False) + raw[len(raw.rstrip()):] + '<'

    def attr(m):
        found = cat.get(html.unescape(m.group(2)))
        return f'{m.group(1)}="{html.escape(found)}"' if isinstance(found, str) else m.group(0)

    def whole(m):
        found = cat.get(' '.join(m.group(3).split()))
        return m.group(1) + found + m.group(4) if isinstance(found, str) else m.group(0)
    page = _WHOLE.sub(whole, page)
    return _ATTR.sub(attr, _TEXT.sub(text, page))


def html_texts(page):
    """The texts translate_html looks up in a page: for tests/i18n_check.py."""
    wholes = [' '.join(m.group(3).split()) for m in _WHOLE.finditer(page)]
    rest = _WHOLE.sub(lambda m: m.group(1) + m.group(4), page)
    return wholes + [html.unescape(m.group(1).strip()) for m in _TEXT.finditer(rest) if m.group(1).strip()] + \
           [html.unescape(m.group(2)) for m in _ATTR.finditer(rest)]
