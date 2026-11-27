"""Bandit: the long-standing checker for risky patterns in Python code (PyCQA)."""

import json

from .. import tools
from ..i18n import N_, _
from ..model import Finding, Outcome, clip
from .base import Scanner, failed, has_files

# the checks that come up most in skills, in plain Chinese; the rest fall back to Bandit's own text
TESTS = {
    'B102': (N_('執行任意程式碼'), N_('用 exec() 執行一段文字當程式。')),
    'B103': (N_('檔案權限太寬'), N_('把檔案設成任何人都能改。')),
    'B104': (N_('對外開放連線'), N_('伺服器綁在所有網路介面上，同網路的人可能連得到。')),
    'B105': (N_('寫死的密碼'), N_('程式裡直接寫了密碼。')),
    'B106': (N_('寫死的密碼'), N_('呼叫函式時直接帶了密碼。')),
    'B107': (N_('寫死的密碼'), N_('函式的預設值是密碼。')),
    'B108': (N_('暫存檔位置不安全'), N_('把檔案放在固定的 /tmp 路徑，可能被其他程式動手腳。')),
    'B110': (N_('吞掉錯誤'), N_('發生錯誤時直接略過，問題可能被藏起來。')),
    'B113': (N_('網路請求沒設時限'), N_('連線卡住時會一直等。')),
    'B301': (N_('不安全的資料讀取（pickle）'), N_('讀取 pickle 檔可能直接執行裡面的程式。')),
    'B307': (N_('執行任意程式碼'), N_('用 eval() 執行一段文字當程式。')),
    'B310': (N_('開啟任意網址'), N_('用 urlopen 開網址，網址若可被外部控制，可能連到不該連的地方。')),
    'B314': (N_('不安全的 XML 讀取'), N_('讀取 XML 的方式可能被惡意檔案利用。')),
    'B324': (N_('弱雜湊演算法'), N_('用了 MD5、SHA1 這類過時的演算法。')),
    'B501': (N_('沒驗證憑證'), N_('連線時關掉了 HTTPS 憑證檢查，可能被竊聽。')),
    'B506': (N_('不安全的 YAML 讀取'), N_('用 yaml.load 讀取，可能執行檔案裡的程式。')),
    'B602': (N_('透過 shell 執行指令'), N_('用 shell 執行指令，內容若夾帶外部輸入可能被利用。')),
    'B605': (N_('透過 shell 執行指令'), N_('用 os.system 之類的方式執行指令。')),
    'B608': (N_('SQL 注入'), N_('用字串拼出資料庫查詢。')),
}
# reminders rather than problems
CALM_TESTS = {
    'B101': N_('用 assert 做檢查只是程式寫法的提醒，對使用者沒有影響。'),
    'B404': N_('只是載入了 subprocess 模組，本身不代表會執行危險指令。'),
    'B603': N_('執行指令時沒有經過 shell，是比較安全的寫法；看它執行的是不是固定的工具即可。'),
    'B607': N_('只是提醒執行指令時沒寫完整路徑。'),
    'B311': N_('用一般亂數產生器，只有在做密碼、金鑰時才有問題。'),
}
TIP = N_('這是 Python 一般寫法的檢查，不是專門針對 AI 技能；看程式用途判斷，拿不準就交給 Claude。')


def parse(data) -> Outcome:
    findings = []
    for i in data.get('results') or []:
        tid = i.get('test_id') or ''
        sev = (i.get('issue_severity') or 'MEDIUM').upper()
        conf = (i.get('issue_confidence') or '').upper()
        title, what = TESTS.get(tid, (i.get('test_name') or tid, ''))
        f = Finding(
            scanner='bandit', title=_(text=title), what=_(text=what) or clip(i.get('issue_text'), 300), tip=_(text=TIP), severity=sev,
            file=i.get('filename') or '', line=i.get('line_number'), snippet=clip(i.get('code'), 600),
            rule=tid, category=i.get('test_name') or '', detail=clip(i.get('issue_text'), 400),
        )
        f.calm = _(text=CALM_TESTS.get(tid, '')) or (_('低風險、低把握的寫法提醒。') if sev == 'LOW' and conf != 'HIGH' else '')
        findings.append(f)
    # Bandit doesn't know about AI skills, so on its own it never says "don't install"
    serious = [f for f in findings if f.severity == 'HIGH' and not f.calm]
    return Outcome('bandit', 'CAUTION' if serious else 'SAFE', findings)


class Bandit(Scanner):
    id = 'bandit'
    name = 'Bandit'
    vendor = 'PyCQA'
    license = 'Apache-2.0'
    homepage = 'https://github.com/PyCQA/bandit'
    summary = N_('檢查技能裡的 Python 程式有沒有危險寫法，例如執行任意指令、不安全的檔案讀取。')
    order = 30
    exe = 'bandit'
    package = 'bandit'

    def applies_to(self, skill_dir):
        return has_files(skill_dir, {'.py'})

    def scan(self, skill_dir, work):
        out = work / 'bandit.json'
        code, _out, err = tools.run([tools.find_exe(self.exe), '-r', '.', '-f', 'json', '-o', str(out), '-q',
                                  '--exit-zero', '-x', './.git,./node_modules'], cwd=skill_dir)
        try:
            data = json.loads(out.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError):
            return failed(self.id, tools.last_lines(err))
        outcome = parse(data)
        for f in outcome.findings:   # Bandit reports paths as ./x.py
            f.file = f.file.removeprefix('./')
        return outcome


SCANNER = Bandit()
