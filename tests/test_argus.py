"""Run with:  python3 -m unittest discover tests   (from the project folder)"""

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'core'))

from argus import report, scanners, targets  # noqa: E402
from argus.model import Outcome, SkillResult  # noqa: E402
from argus.scanners import bandit, cisco, secrets, skillspector  # noqa: E402

FIX = Path(__file__).parent / 'fixtures'


def fixture(name):
    return json.loads((FIX / name).read_text(encoding='utf-8'))


class Registry(unittest.TestCase):
    def test_all_scanners_found_in_order(self):
        self.assertEqual([s.id for s in scanners.all_scanners()], ['skillspector', 'cisco', 'bandit', 'secrets'])

    def test_every_scanner_describes_itself(self):
        for s in scanners.all_scanners():
            for field in ('name', 'vendor', 'license', 'homepage', 'summary', 'exe', 'package'):
                self.assertTrue(getattr(s, field), f'{s.id}.{field}')


class SkillSpectorParse(unittest.TestCase):
    def setUp(self):
        self.o = skillspector.parse(fixture('skillspector.json'))
        self.by_file = {f.file: f for f in self.o.findings}

    def test_verdict_and_score_kept(self):
        self.assertEqual((self.o.verdict, self.o.score), ('DO_NOT_INSTALL', 100))

    def test_chinese_titles(self):
        self.assertEqual(self.by_file['scripts/provider_adapters.py'].title, '資料流向')

    def test_calm_rules(self):
        self.assertTrue(self.by_file['assets/dashboard/app.js'].calm)          # wording rule in code
        self.assertTrue(self.by_file['assets/dashboard/styles.css'].calm)      # anything AI-text in a style sheet
        self.assertTrue(self.by_file['SKILL.md'].calm)                         # a reminder
        self.assertFalse(self.by_file['scripts/check.py'].calm)                # rogue agent in code needs a look
        self.assertFalse(self.by_file['scripts/provider_adapters.py'].calm)


class CiscoParse(unittest.TestCase):
    def test_parse(self):
        o = cisco.parse(fixture('cisco.json'))
        self.assertEqual(o.verdict, 'DO_NOT_INSTALL')
        calm = {f.rule: bool(f.calm) for f in o.findings}
        self.assertEqual(calm, {'PROMPT_INJECTION_IGNORE': False, 'X': True, 'INFO1': True})
        self.assertEqual(o.findings[0].title, '提示詞注入')

    def test_multi_skill_report_shape(self):
        o = cisco.parse({'results': [fixture('cisco.json')]})
        self.assertEqual(len(o.findings), 3)

    def test_clean(self):
        self.assertEqual(cisco.parse({'max_severity': 'SAFE', 'findings': []}).verdict, 'SAFE')


class BanditParse(unittest.TestCase):
    def test_parse(self):
        o = bandit.parse(fixture('bandit.json'))
        self.assertEqual(o.verdict, 'CAUTION')    # never DO_NOT_INSTALL on its own
        calm = {f.rule: bool(f.calm) for f in o.findings}
        self.assertEqual(calm, {'B602': False, 'B404': True, 'B101': True})

    def test_python_only(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(bandit.SCANNER.applies_to(Path(d)))
            (Path(d) / 'a.py').write_text('x = 1')
            self.assertTrue(bandit.SCANNER.applies_to(Path(d)))


class SecretsParse(unittest.TestCase):
    def test_parse_and_mask(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'config.py').write_text('# settings\nAPI_KEY = "sk-live-0123456789abcdefghij"\n')
            o = secrets.parse(fixture('secrets.json'), Path(d))
        by = {f.file: f for f in o.findings}
        self.assertEqual(o.verdict, 'CAUTION')
        self.assertFalse(by['config.py'].calm)
        self.assertTrue(by['examples/demo.py'].calm)
        self.assertTrue(by['assets/logo.svg'].calm)
        self.assertNotIn('0123456789abcdefghij', by['config.py'].snippet)
        self.assertIn('••••', by['config.py'].snippet)


class Targets(unittest.TestCase):
    def test_expand_finds_each_skill(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ('skills/a', 'skills/b', 'node_modules/c'):
                (root / name).mkdir(parents=True)
                (root / name / 'SKILL.md').write_text('---\nname: x\n---')
            self.assertEqual(sorted(p.name for p in targets.expand(root)), ['a', 'b'])
            self.assertEqual(targets.expand(root / 'skills' / 'a'), [root / 'skills' / 'a'])

    def test_zip_slip_refused(self):
        with tempfile.TemporaryDirectory() as d:
            z = Path(d) / 'evil.zip'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('../outside.txt', 'x')
            with self.assertRaises(targets.TargetError):
                targets.safe_extract(z, Path(d) / 'out')
            self.assertFalse((Path(d) / 'outside.txt').exists())

    def test_zip_with_one_folder(self):
        with tempfile.TemporaryDirectory() as d:
            z = Path(d) / 'skill.zip'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('my-skill/SKILL.md', '---\nname: "My Skill"\n---\n')
            title, folders = targets.resolve('zip', str(z), Path(d) / 'work')
            self.assertEqual((title, [f.name for f in folders]), ('skill.zip', ['my-skill']))
            self.assertEqual(targets.skill_name(folders[0]), 'My Skill')

    def test_github_link_parsing(self):
        m = targets.GITHUB.match('https://github.com/o/r/tree/main/skills/pdf')
        self.assertEqual(m.groups(), ('o', 'r', 'tree', 'main', 'skills/pdf'))
        self.assertIsNone(targets.GITHUB.match('https://gitlab.com/o/r'))


class Report(unittest.TestCase):
    def test_render(self):
        r = SkillResult('short-drama', '/x', [
            skillspector.parse(fixture('skillspector.json')),
            cisco.parse(fixture('cisco.json')),
            Outcome('bandit', 'ERROR', error='</script><b>boom</b>'),
            Outcome('secrets', 'SKIPPED'),
        ])
        page = report.render('https://github.com/o/r', [r], scanners.all_scanners(), {'skillspector': '2.12'})
        self.assertIn('不建議安裝', page)
        self.assertIn('Square Su', page)
        self.assertNotIn('<b>boom</b>', page)              # scanner text is escaped
        self.assertEqual(page.count('</script>'), 2)        # nothing in the data closes the script early
        self.assertEqual(r.verdict, 'DO_NOT_INSTALL')

    def test_verdict_ignores_errors_and_skips(self):
        r = SkillResult('x', '/x', [Outcome('a', 'SAFE'), Outcome('b', 'ERROR'), Outcome('c', 'SKIPPED')])
        self.assertEqual(r.verdict, 'SAFE')
        self.assertEqual(SkillResult('y', '/y', [Outcome('a', 'ERROR')]).verdict, 'ERROR')


if __name__ == '__main__':
    unittest.main()
