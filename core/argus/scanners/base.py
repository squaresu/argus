"""What a scanner plug-in looks like. See docs/新增掃描工具.md for a walkthrough."""

from pathlib import Path

from .. import tools
from ..model import Outcome


class Scanner:
    # --- describe the tool (shown in the app's tool list and the About page) ---
    id = ''              # short, stable id used in settings and reports
    name = ''            # the tool's own name
    vendor = ''          # who makes it
    license = ''         # its open-source licence
    homepage = ''
    summary = ''         # one Chinese sentence: what it checks
    order = 100          # position in the list
    default_on = True    # ticked when the app opens

    # --- how to get it ---
    exe = ''             # the command uv installs into ~/.local/bin
    package = ''         # what `uv tool install` installs (a PyPI name, or "name @ url")
    version_args = ('--version',)

    def installed(self):
        return tools.find_exe(self.exe) is not None

    def version(self):
        """The installed version, or '' when the tool doesn't start (a broken install counts as not installed)."""
        exe = tools.find_exe(self.exe)
        if not exe:
            return ''
        code, out, err = tools.run([exe, *self.version_args], timeout=180)
        if code != 0:
            return ''
        text = (out or err).strip().splitlines()
        return text[0][:60] if text else '?'

    def preflight(self):
        """A reason this tool can't be installed on this computer, or ''."""
        return ''

    def install_command(self, uv):
        return [uv, 'tool', 'install', '--force', '--reinstall', '--compile-bytecode', '--python', tools.python_spec(),
                self.package]

    needs_uv = True      # False for a tool that installs itself some other way (override install)

    def install(self, uv):
        """Install (or reinstall) the tool. → (exit code, output, error output), like tools.run."""
        return tools.run(self.install_command(uv), timeout=1200)

    # --- the actual work ---
    def applies_to(self, skill_dir: Path):
        """False when there's nothing for this tool to look at (e.g. no Python files for a Python checker)."""
        return True

    def scan(self, skill_dir: Path, work: Path) -> Outcome:
        """Scan one skill folder. `work` is a private scratch folder. Must not raise; errors go in Outcome.error."""
        raise NotImplementedError

    def info(self):
        return {k: getattr(self, k) for k in ('id', 'name', 'vendor', 'license', 'homepage', 'summary', 'default_on')}


def failed(scanner_id, reason):
    return Outcome(scanner_id, 'ERROR', error=reason or '沒有產生結果')


def has_files(skill_dir: Path, suffixes, limit=5000):
    for i, p in enumerate(skill_dir.rglob('*')):
        if i > limit:
            break
        if p.suffix.lower() in suffixes and '.git' not in p.parts and 'node_modules' not in p.parts:
            return True
    return False
