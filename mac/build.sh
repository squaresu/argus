#!/bin/bash
# Build dist/Argus.app and the zip people download:  bash mac/build.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(sed -n "s/^VERSION = '\(.*\)'/\1/p" "$ROOT/core/argus/__init__.py")
DIST="$ROOT/dist"
APP="$DIST/Argus.app/Contents"

rm -rf "$DIST/Argus.app" "$DIST/Argus-mac-$VERSION.zip"
mkdir -p "$APP/MacOS" "$APP/Resources/core"
sed "s/__VERSION__/$VERSION/g" "$ROOT/mac/Info.plist" >"$APP/Info.plist"
cp "$ROOT/mac/run" "$APP/MacOS/run" && chmod 755 "$APP/MacOS/run"
cp "$ROOT/mac/AppIcon.icns" "$APP/Resources/"
# the core, without caches
(cd "$ROOT/core" && find argus -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 |
  xargs -0 -I{} sh -c 'mkdir -p "$1/$(dirname "{}")" && cp "{}" "$1/{}"' _ "$APP/Resources/core")
cp "$ROOT/docs/使用說明.md" "$DIST/Argus-使用說明.md"
cp "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_NOTICES.md" "$DIST/"
(cd "$DIST" && zip -qry "Argus-mac-$VERSION.zip" Argus.app Argus-使用說明.md LICENSE THIRD_PARTY_NOTICES.md)
echo "built $DIST/Argus-mac-$VERSION.zip"
