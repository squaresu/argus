"""NVIDIA SkillSpector: a security scanner made for AI agent skills (static analysis only, no AI key)."""

import json
import os
import re

from .. import tools
from ..i18n import N_, _
from ..model import (CODE_EXT, PLACEHOLDER_HOST, STYLE_EXT, Finding, Outcome, clip, is_documentation,
                     is_table_padding, is_type_definitions)
from .base import Scanner, failed, fetch_text

# what each kind of finding means, and how to tell a real problem from the scanner being cautious
CATEGORY = {
    'Prompt Injection': (N_('提示詞注入'), N_('技能裡有試圖改寫 AI 原本規則的文字。'), N_('如果那段文字是在「保護」AI（例如提醒它把資料當資料、不要照做），通常是誤判。')),
    'Data Exfiltration': (N_('資料外流'), N_('程式可能讀取或送出你的資料、密碼或環境變數。'), N_('看程式有沒有把資料送到外部網址。只在電腦內部傳給另一個程式通常沒問題。')),
    'Privilege Escalation': (N_('提升權限'), N_('試圖取得管理員權限或修改系統設定。'), N_('一般設計、文件類技能不需要這種權限，出現就要小心。')),
    'Supply Chain': (N_('套件來源'), N_('會下載或安裝其他套件，套件本身可能有已知漏洞。'), N_('看安裝的是不是知名、官方的套件。')),
    'Excessive Agency': (N_('過度自主'), N_('讓 AI 在沒有確認的情況下自行做決定或動作。'), N_('如果是讀取、整理資料通常沒關係；如果會自動刪除、付款或寄信，要確認。')),
    'Output Handling': (N_('輸出處理'), N_('把內容直接輸出到網頁或指令裡，可能被利用。'), N_('多半是範例程式，確認不會執行陌生內容即可。')),
    'System Prompt Leakage': (N_('洩漏系統指令'), N_('可能讓 AI 把內部指令給別人看。'), N_('常把「只輸出最後結果」這類格式規定誤判成這一項。')),
    'Memory Poisoning': (N_('記憶污染'), N_('試圖在 AI 的長期記憶裡寫入東西。'), N_('確認寫入的是你要的內容。')),
    'Tool Misuse': (N_('工具濫用'), N_('用指令做刪除、搬移等動作，或把多個指令串在一起。'), N_('如果是說明文件裡的範例指令，而且只處理技能自己的暫存檔，通常是誤判。')),
    'Rogue Agent': (N_('失控的代理'), N_('讓 AI 自己啟動其他 AI、長時間自動執行，或修改自己的程式。'), N_('開發用的技能常有這種功能，一般使用者用不到就別裝。')),
    'Anti-Refusal': (N_('要 AI 不准拒絕'), N_('試圖讓 AI 不拒絕、不道歉、不解釋。'), N_('「不要道歉、不要解釋」若只是輸出格式要求，通常是誤判。')),
    'Trigger Abuse': (N_('觸發條件濫用'), N_('技能會在不相關的時候被叫出來。'), N_('看描述是否過度寬鬆。')),
    'Dangerous Code Execution': (N_('執行程式'), N_('程式會執行其他程式或指令。'), N_('轉檔、產生圖片的技能需要這個，看它執行的是不是固定的工具。')),
    'Data Flow': (N_('資料流向'), N_('程式會把密碼、金鑰、環境變數或檔案內容送到網路上。'), N_('如果是用你自己設定的 API 金鑰去呼叫對應的服務（例如 OpenAI），這是正常用法；送到不明的網址才要小心。')),
    'YARA Match': (N_('符合惡意樣式'), N_('內容符合已知的可疑樣式。'), N_('樣式比對容易誤判，看實際內容最準。')),
    'MCP Least Privilege': (N_('沒聲明權限'), N_('技能沒寫清楚需要哪些權限，但程式會讀檔、連網或執行指令。'), N_('屬於提醒，不代表有問題。')),
    'MCP Tool Poisoning': (N_('工具描述被動手腳'), N_('工具的說明文字裡藏了指令。'), N_('出現就要小心。')),
    'MCP Rug Pull': (N_('版本沒鎖定'), N_('技能用到的版本或設定沒有固定下來，日後內容可能被換掉。'), N_('屬於提醒，不代表現在有問題。')),
    'Agent Snooping': (N_('窺探 AI 設定'), N_('程式會讀取 Claude 的設定資料夾。'), N_('開發工具需要找專案位置時會這樣做，一般技能不需要。')),
    'Harmful Content': (N_('有害內容'), N_('含有可能有害的內容。'), N_('看實際內容判斷。')),
    'Server-Side Request Forgery': (N_('連到內部網址'), N_('程式可能被利用去連內部網路。'), N_('需要看程式細節。')),
    'Insecure Deserialization': (N_('不安全的資料讀取'), N_('用不安全的方式讀取外部檔案。'), N_('需要看程式細節。')),
    'Bundled Execution Surface': (N_('會自動執行的設定'), N_('技能附帶的 hooks 或設定，會在特定時機自動執行指令。'), N_('看它執行的是什麼指令；會自動執行又看不懂的，先不要裝。')),
    'analysis-evasion': (N_('沒能完整檢查'), N_('檔案太大或太複雜，掃描器沒看完。'), N_('不代表有問題，只是這部分沒被檢查到。')),
}

# Rules for findings that are usually nothing to worry about. They only move a finding into a separate group
# with the reason; nothing is hidden, and SkillSpector's score and verdict stay as they are.
REMINDER_CATS = {'MCP Least Privilege', 'MCP Rug Pull', 'analysis-evasion'}
# kinds of finding that look for instructions written to the AI (Rogue Agent also covers code behaviour,
# so it's only waved through in style sheets)
AI_TEXT_CATS = {'Prompt Injection', 'System Prompt Leakage', 'Anti-Refusal', 'Rogue Agent', 'Memory Poisoning',
                'Excessive Agency', 'Trigger Abuse', 'Harmful Content'}
# rules that match plain wording ("show your instructions", "never refuse"), not program behaviour
WORDING_RULES = {'P6', 'P7', 'AR1', 'AR2', 'AR3'}
# kinds of finding about what a program does; in a README or a references/examples document they are
# describing or illustrating something, not doing it. Instruction-style findings (prompt injection and
# the like) are not in this list: the AI does read references as instructions.
BEHAVIOUR_CATS = {'Privilege Escalation', 'Tool Misuse', 'Agent Snooping', 'Excessive Agency', 'Rogue Agent',
                  'Dangerous Code Execution'}


def calm_reason(category, rule, path, snippet=''):
    ext = os.path.splitext(path)[1].lower()
    if category in REMINDER_CATS:
        return _('只是提醒，不是找到問題。')
    if is_type_definitions(path):
        return _('出現在 TypeScript 型別定義檔（.d.ts）裡。這種檔案只描述程式介面、給編輯器看，不會被執行，多半是誤判。')
    if ext in STYLE_EXT and category in AI_TEXT_CATS:
        return _('出現在網頁的樣式檔裡。樣式檔只管顏色和排版，AI 不會讀、也不會執行，多半是誤判。')
    if ext in CODE_EXT and rule in WORDING_RULES:
        return _('這條規則找的是「寫給 AI 看的話」，但它出現在程式碼裡，通常只是程式剛好用到 prompt、instructions 之類的字，多半是誤判。')
    if rule == 'P9' and is_table_padding(snippet):
        return _('這些空白是 Markdown 表格為了對齊欄位留的，不是用來藏東西。')
    if rule == 'E1' and PLACEHOLDER_HOST.search(snippet) and not PLACEHOLDER_HOST.sub('', snippet).count('://'):
        return _('網址是 example.com、localhost 這類說明文件專用的示範網址，不是真的會連去的地方。')
    if rule == 'P4':
        return _('只是「一律優先用某種做法」這類寫作建議，不是在暗中操控 AI。')
    if category in BEHAVIOUR_CATS and is_documentation(path):
        return _('出現在說明文件（README、references、examples）裡，是在說明或舉例，不是技能實際會執行的程式。')
    return ''


def parse(data) -> Outcome:
    """SkillSpector's JSON report → Outcome."""
    ra = data.get('risk_assessment') or {}
    findings = []
    for i in data.get('issues') or []:
        cat = i.get('category') or ''
        loc = i.get('location') or {}
        title, what, tip = CATEGORY.get(cat, (cat or i.get('id') or _('其他'), '', ''))
        f = Finding(
            scanner='skillspector', title=_(text=title), what=_(text=what) or clip(i.get('explanation'), 300), tip=_(text=tip),
            severity=(i.get('severity') or 'MEDIUM').upper(), file=loc.get('file') or '', line=loc.get('start_line'),
            snippet='' if cat == 'analysis-evasion' else clip(i.get('code_snippet'), 600),
            rule=i.get('id') or '', category=cat, detail=clip(i.get('explanation'), 400),
        )
        f.calm = calm_reason(cat, f.rule, f.file, i.get('code_snippet') or '')
        findings.append(f)
    verdict = ra.get('recommendation') or 'CAUTION'
    note = ''
    if verdict == 'CAUTION' and not findings and (data.get('analysis_completeness') or {}).get('status') == 'partial':
        note = _('沒有發現問題；只是技能裡提到的某些檔案找不到，所以 SkillSpector 保守地標成「注意」。')
    return Outcome('skillspector', verdict, findings, score=ra.get('score'), note=note)


class SkillSpector(Scanner):
    id = 'skillspector'
    name = 'SkillSpector'
    vendor = 'NVIDIA'
    license = 'Apache-2.0'
    homepage = 'https://github.com/NVIDIA/SkillSpector'
    summary = N_('專門檢查 AI 技能：提示詞注入、資料外流、危險指令、套件漏洞等 70 多種寫法。')
    order = 10
    exe = 'skillspector'
    # a zip of the source instead of git+https, so Git doesn't have to be installed
    package = 'skillspector @ https://github.com/NVIDIA/skillspector/archive/refs/heads/main.zip'

    def newest(self):
        # installed from the main branch on GitHub, so the version there is what a reinstall would bring
        text = fetch_text('https://raw.githubusercontent.com/NVIDIA/skillspector/main/pyproject.toml')
        m = re.search(r'^version\s*=\s*["\']([^"\']+)', text, re.M)
        return m.group(1) if m else ''

    def preflight(self):
        # its yara-python has ready-made Mac builds only for macOS 14+; older Macs compile it, which needs
        # Apple's Command Line Tools
        if tools.IS_MAC and 0 < tools.mac_version() < 14:
            code, _out, _err = tools.run(['xcode-select', '-p'], timeout=20)
            if code != 0:
                return _('這台 Mac 是 macOS 13 以前的版本，要先安裝 Apple 的「命令列開發者工具」：'
                         '打開「終端機」輸入 xcode-select --install，裝完再按一次安裝。')
        return ''

    def scan(self, skill_dir, work):
        out = work / 'skillspector.json'
        # the real folder: SkillSpector refuses a shortcut (symlink), and ~/.claude/skills often holds those
        code, _out, err = tools.run([tools.find_exe(self.exe), 'scan', str(skill_dir.resolve()), '--no-llm',
                                  '--format', 'json', '--output', str(out)])
        try:
            data = json.loads(out.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError):
            return failed(self.id, tools.last_lines(err))
        return parse(data)


SCANNER = SkillSpector()
