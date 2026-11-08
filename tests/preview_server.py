"""Run the Argus page with stand-in scanners, to work on the interface without installing the real tools.

    python3 tests/preview_server.py [port]

The stand-ins return the sample results in tests/fixtures; "選擇…" picks tests/fixtures as the folder.
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'core'))

from argus import native, scanners, server  # noqa: E402
from argus.scanners import bandit, cisco, secrets, skillspector  # noqa: E402

FIX = Path(__file__).parent / 'fixtures'
PARSERS = {'skillspector': skillspector.parse, 'cisco': cisco.parse, 'bandit': bandit.parse, 'secrets': secrets.parse}
INSTALLED = {'skillspector', 'cisco', 'bandit'}   # leave one "not installed" to show the install button


def stand_in(real):
    class StandIn(type(real)):
        def version(self):
            return '1.0 (preview)' if self.id in INSTALLED else ''

        def installed(self):
            return self.id in INSTALLED

        def applies_to(self, skill_dir):
            return True

        def install_command(self, uv):
            INSTALLED.add(self.id)
            return [sys.executable, '-c', 'import time; time.sleep(2)']

        def scan(self, skill_dir, work):
            time.sleep(0.6)
            return PARSERS[self.id](json.loads((FIX / f'{self.id}.json').read_text(encoding='utf-8')))

    s = StandIn()
    return s


scanners._cache = [stand_in(s) for s in scanners.all_scanners()]
native.pick_folder = lambda: str(FIX)
native.pick_zip = lambda: ''
native.open_path = lambda p: print('open', p)
server.jobs.tools.find_exe = lambda name: sys.executable   # "uv" for the stand-in install

if __name__ == '__main__':
    port = sys.argv[1] if len(sys.argv) > 1 else '8765'
    server.main(['--port', port, '--no-idle-exit'])
