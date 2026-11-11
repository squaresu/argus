"""Semgrep (Community Edition): looks through a skill's JavaScript and TypeScript with Argus's own rules.

Bandit only reads Python; many skills ship Node scripts instead. The rules live next to this file
(semgrep_rules.yml) and aim at what matters in a skill rather than general code quality. Semgrep runs with
those local rules only, metrics off, so nothing about the skill leaves the computer.
"""

import json
import re
from pathlib import Path

from .. import tools
from ..model import Finding, Outcome, clip, is_documentation, is_type_definitions
from .base import Scanner, failed, has_files

RULES = Path(__file__).with_name('semgrep_rules.yml')
JS_EXT = {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx'}

# rule → (title, what it means, severity)
RULE_ZH = {
    'decode-and-run': ('解開隱藏的文字後當程式執行', '先把一段編碼過的文字解開，再直接當成程式執行。這是藏惡意程式最常見的手法，正常的技能幾乎不會這樣寫。', 'CRITICAL'),
    'run-text-as-code': ('把文字當程式執行', '用 eval、new Function 或 vm 執行一段文字。文字內容如果來自網路或使用者，等於可以執行任何程式。', 'HIGH'),
    'exec-command': ('執行組出來的指令', '用 exec 透過 shell 執行指令，而且指令是用變數拼出來的。內容如果夾帶外部輸入，可能被改成執行別的指令。', 'HIGH'),
    'spawn-shell': ('透過 shell 執行程式', '啟動其他程式時開了 shell: true，參數會被 shell 解讀，比較容易被夾帶指令。', 'MEDIUM'),
    'dump-env': ('一次讀出所有環境變數', '把所有環境變數整包讀出來。環境變數裡常有 API 金鑰和權杖，如果接著送到網路上就是外流。', 'HIGH'),
    'sensitive-path': ('提到存放機密的檔案', '程式裡出現 SSH 金鑰、雲端帳號憑證、瀏覽器 Cookie 或密碼這類檔案的位置。一般技能用不到這些檔案。', 'HIGH'),
    'startup-file': ('提到開機或 Claude 設定檔', '程式裡出現 .zshrc、LaunchAgents、crontab 或 Claude 設定檔的位置。改動這些檔案，可以讓程式在每次開機或打開 Claude 時自動執行。', 'HIGH'),
    'throwaway-endpoint': ('連到常被用來收集資料的服務', '程式會連到 Discord／Telegram 機器人、webhook.site、ngrok 這類服務。正常技能偶爾會用，但這也是偷資料時最常用的收件地址。', 'HIGH'),
    'raw-ip': ('直接連到 IP 位址', '程式直接連到一串數字的 IP 位址，而不是一般網站的名字，比較難看出它連去哪裡。', 'MEDIUM'),
    'tls-off': ('關掉 HTTPS 安全檢查', '連線時關掉了憑證檢查，傳輸的內容可能被同一個網路上的人看到或竄改。', 'MEDIUM'),
}
TIP = '看程式要做的事需不需要這樣寫；拿不準就按「複製給 Claude 判斷」。'
EXAMPLE_PATH = re.compile(r'(^|/)(examples?|samples?|demos?)/', re.I)
TEST_PATH = re.compile(r'(^|/)(tests?|__tests__|spec|__mocks__|fixtures?)(/|$)|\.(test|spec)\.[cm]?[jt]sx?$', re.I)


def calm_reason(rule, path):
    if is_type_definitions(path):
        return 'TypeScript 型別定義檔（.d.ts）只描述介面，裡面的東西不會執行。'
    if is_documentation(path):
        return '出現在說明文件或範例裡，不是技能實際執行的程式。'
    if rule not in ('decode-and-run', 'throwaway-endpoint', 'sensitive-path', 'startup-file'):
        if TEST_PATH.search(path):
            return '出現在測試程式裡，一般使用技能時不會執行。'
        if EXAMPLE_PATH.search(path):
            return '出現在範例程式裡，一般使用技能時不會執行。'
    return ''


def parse(data) -> Outcome:
    findings, seen = [], set()
    hits = sorted(data.get('results') or [], key=lambda r: r.get('check_id', '') != 'argus.decode-and-run')
    decoded = set()
    for r in hits:
        rule = (r.get('check_id') or '').rsplit('.', 1)[-1]
        path = (r.get('path') or '').removeprefix('./')
        line = (r.get('start') or {}).get('line')
        # one finding per rule per line; decode-and-run already says what run-text-as-code would
        if (rule, path, line) in seen or (rule == 'run-text-as-code' and (path, line) in decoded):
            continue
        seen.add((rule, path, line))
        if rule == 'decode-and-run':
            decoded.add((path, line))
        title, what, severity = RULE_ZH.get(rule, (rule, '', 'MEDIUM'))
        extra = r.get('extra') or {}
        f = Finding(scanner='semgrep', title=title, what=what, tip=TIP, severity=severity, file=path, line=line,
                    snippet=clip(extra.get('lines'), 600), rule=rule, category=rule,
                    detail=f"semgrep: {clip(extra.get('message'), 300)}")
        f.calm = calm_reason(rule, path)
        findings.append(f)
    real = [f for f in findings if not f.calm]
    if any(f.severity == 'CRITICAL' for f in real):
        verdict = 'DO_NOT_INSTALL'
    elif any(f.severity == 'HIGH' for f in real):
        verdict = 'CAUTION'
    else:
        verdict = 'SAFE'
    return Outcome('semgrep', verdict, findings)


class Semgrep(Scanner):
    id = 'semgrep'
    name = 'Semgrep'
    vendor = 'Semgrep'
    license = 'LGPL-2.1'
    homepage = 'https://github.com/semgrep/semgrep'
    summary = '用 Argus 的規則檢查技能裡的 JavaScript／TypeScript 程式，例如執行指令、讀取金鑰檔、把資料送到可疑的地方。'
    order = 35
    exe = 'semgrep'
    package = 'semgrep'

    def applies_to(self, skill_dir):
        return has_files(skill_dir, JS_EXT)

    def scan(self, skill_dir, work):
        out = work / 'semgrep.json'
        code, _, err = tools.run([tools.find_exe(self.exe), 'scan', '--config', str(RULES), '--json', '--output', str(out),
                                  '--metrics', 'off', '--disable-version-check', '--quiet', '--timeout', '20',
                                  '--max-target-bytes', '2000000', '--exclude', 'node_modules', '--exclude', '.git',
                                  '.'], cwd=skill_dir)
        try:
            data = json.loads(out.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return failed(self.id, tools.last_lines(err))
        return parse(data)


SCANNER = Semgrep()
