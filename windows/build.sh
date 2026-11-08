#!/bin/bash
# Build dist/Argus-win-<version>.zip:  bash windows/build.sh
# Layout inside the zip:  Argus/Argus.cmd, Argus/app/{launch.ps1, argus.ico, argus-app.id, core/argus/…}, plus the docs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(sed -n "s/^VERSION = '\(.*\)'/\1/p" "$ROOT/core/argus/__init__.py")
DIST="$ROOT/dist"
mkdir -p "$DIST"
rm -f "$DIST/Argus-win-$VERSION.zip"
python3 - "$ROOT" "$DIST/Argus-win-$VERSION.zip" <<'EOF'
import sys, zipfile
from pathlib import Path
root, out = Path(sys.argv[1]), sys.argv[2]

def crlf(text):
    return text.replace('\r\n', '\n').replace('\n', '\r\n')

with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:   # zipfile marks the Chinese names as UTF-8
    z.writestr('Argus/Argus.cmd', crlf((root / 'windows/Argus.cmd').read_text(encoding='utf-8')))
    # Windows PowerShell 5.1 reads scripts without a BOM as ANSI, which garbles the Chinese text
    z.writestr('Argus/app/launch.ps1', b'\xef\xbb\xbf' + crlf((root / 'windows/launch.ps1').read_text(encoding='utf-8')).encode('utf-8'))
    z.write(root / 'windows/argus.ico', 'Argus/app/argus.ico')
    z.writestr('Argus/app/argus-app.id', 'local.argus.skill-scanner\n')   # lets an update confirm it's really Argus
    for f in sorted((root / 'core/argus').rglob('*')):
        if f.is_file() and '__pycache__' not in f.parts and f.suffix != '.pyc':
            z.write(f, 'Argus/app/core/' + f.relative_to(root / 'core').as_posix())
    z.write(root / 'docs/使用說明-Windows.md', 'Argus/使用說明.md')
    z.write(root / 'LICENSE', 'Argus/LICENSE')
    z.write(root / 'THIRD_PARTY_NOTICES.md', 'Argus/THIRD_PARTY_NOTICES.md')
EOF
echo "built $DIST/Argus-win-$VERSION.zip"
