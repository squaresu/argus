"""Cisco Skill Scanner: a second skill-focused scanner, run with its rules only (its AI judge needs a key)."""

import json

from .. import tools
from ..model import STYLE_EXT, Finding, Outcome, clip
from .base import Scanner, failed

CATEGORY = {
    'prompt_injection': ('提示詞注入', '技能裡有試圖改寫 AI 原本規則的文字。', '如果那段文字是在「保護」AI（例如提醒它把資料當資料、不要照做），通常是誤判。'),
    'command_injection': ('指令注入', '程式組指令時夾帶了外部輸入，可能被拿來執行任意指令。', '看被執行的是不是固定的工具、外部內容有沒有被直接塞進指令。'),
    'data_exfiltration': ('資料外流', '程式可能讀取或送出你的資料、密碼或環境變數。', '看資料送到哪裡；送到技能本來就要用的官方服務通常沒問題。'),
    'unauthorized_tool_use': ('越權使用工具', '技能使用了說明裡沒提到的工具或權限。', '看技能的用途需不需要這些工具。'),
    'obfuscation': ('混淆過的內容', '有編碼、壓縮或刻意難讀的內容，可能在藏東西。', '正常技能很少需要混淆；圖片、字型等二進位檔偶爾會被誤判。'),
    'hardcoded_secrets': ('寫死的密碼或金鑰', '程式裡直接寫了密碼、API 金鑰之類的機密。', '如果是範例用的假值通常沒關係；真的金鑰不該出現在技能裡。'),
    'social_engineering': ('誘導性說法', '用話術誘導 AI 或使用者做不該做的事。', '看那段話的目的；單純的說明文字常被誤判。'),
    'resource_abuse': ('資源濫用', '可能大量消耗電腦資源、網路或 API 額度。', '看是不是技能正常工作需要的量。'),
    'policy_violation': ('違反規範', '寫法違反技能規格或安全規範。', '多半是格式問題，看說明決定。'),
    'malware': ('惡意程式樣式', '內容符合已知惡意程式的樣式。', '出現就要小心，建議先不要裝。'),
    'harmful_content': ('有害內容', '含有可能有害的內容。', '看實際內容判斷。'),
    'skill_discovery_abuse': ('窺探其他技能', '會去讀取或列出你裝的其他技能。', '一般技能不需要知道你裝了什麼。'),
    'transitive_trust_abuse': ('借用信任', '透過信任的來源間接載入不受信任的內容。', '看它載入的是什麼。'),
    'autonomy_abuse': ('過度自主', '讓 AI 在沒有確認的情況下自行做決定或動作。', '如果會自動刪除、付款或寄信，要確認。'),
    'tool_chaining_abuse': ('串接工具繞過限制', '把多個工具串起來，可能繞過單一工具的限制。', '看串起來的目的是不是技能的正常流程。'),
    'unicode_steganography': ('隱藏字元', '用看不見的特殊字元藏了內容。', '出現就要小心，正常技能不需要隱藏字元。'),
    'supply_chain_attack': ('套件來源', '會下載或安裝其他套件，來源可能有風險。', '看安裝的是不是知名、官方的套件。'),
}
AI_TEXT_CATS = {'prompt_injection', 'social_engineering', 'autonomy_abuse', 'harmful_content'}


def calm_reason(category, severity, ext):
    if severity in ('INFO', 'SAFE'):
        return '只是資訊，不是找到問題。'
    if ext in STYLE_EXT and category in AI_TEXT_CATS:
        return '出現在網頁的樣式檔裡。樣式檔只管顏色和排版，AI 不會讀、也不會執行，多半是誤判。'
    return ''


def parse(data) -> Outcome:
    """Cisco Skill Scanner's JSON report for one skill → Outcome."""
    if 'results' in data:   # a multi-skill report; Argus scans one skill at a time
        data = (data.get('results') or [{}])[0]
    findings = []
    for i in data.get('findings') or []:
        cat = i.get('category') or ''
        sev = (i.get('severity') or 'MEDIUM').upper()
        title, what, tip = CATEGORY.get(cat, (i.get('title') or cat or '其他', '', ''))
        f = Finding(
            scanner='cisco', title=title, what=what or clip(i.get('description'), 300), tip=tip,
            severity='INFO' if sev == 'SAFE' else sev, file=i.get('file_path') or '', line=i.get('line_number'),
            snippet=clip(i.get('snippet'), 600), rule=i.get('rule_id') or '', category=cat,
            detail=clip(' — '.join(x for x in (i.get('title'), i.get('description')) if x), 400),
        )
        f.calm = calm_reason(cat, sev, f.ext)
        findings.append(f)
    worst = (data.get('max_severity') or 'SAFE').upper()
    verdict = {'CRITICAL': 'DO_NOT_INSTALL', 'HIGH': 'DO_NOT_INSTALL', 'MEDIUM': 'CAUTION'}.get(worst, 'SAFE')
    note = ''
    if data.get('analyzers_failed'):
        note = 'Cisco Skill Scanner 有部分檢查沒有完成，結果可能不完整。'
    return Outcome('cisco', verdict, findings, note=note)


class CiscoSkillScanner(Scanner):
    id = 'cisco'
    name = 'Cisco Skill Scanner'
    vendor = 'Cisco AI Defense'
    license = 'Apache-2.0'
    homepage = 'https://github.com/cisco-ai-defense/skill-scanner'
    summary = '另一套專門檢查 AI 技能的規則，當作第二意見：注入、外流、混淆、隱藏字元等。'
    order = 20
    exe = 'skill-scanner'
    package = 'cisco-ai-skill-scanner'

    def preflight(self):
        if tools.IS_MAC and 0 < tools.mac_version() < 13:
            return 'Cisco Skill Scanner 需要 macOS 13 以上。'
        return ''

    def scan(self, skill_dir, work):
        out = work / 'cisco.json'
        # rules only: --use-llm would need an AI key and send the skill to a model provider
        code, _, err = tools.run([tools.find_exe(self.exe), 'scan', str(skill_dir), '--lenient',
                                  '--format', 'json', '--output', str(out)])
        try:
            data = json.loads(out.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError):
            return failed(self.id, tools.last_lines(err))
        return parse(data)


SCANNER = CiscoSkillScanner()
