#!/usr/bin/env bash
#
# Build the Praxis Lite standalone bundle for the current OS (macOS/Linux).
#
#   ./packaging/build.sh
#
# Produces, under dist/artifacts/:
#   Praxis-Lite-macos-<arch>.zip     (macOS)
#   Praxis-Lite-linux-<arch>.tar.gz  (Linux)
#
# Requires a Python 3.11+ venv with the package installed (pip install -e .).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
ARCH="$(uname -m)"
OS="$(uname -s)"

case "$OS" in
  Darwin) OSNAME="macos" ;;
  Linux)  OSNAME="linux" ;;
  *)      OSNAME="$OS" ;;
esac

$PY -m pip install --quiet --upgrade pyinstaller

echo "==> Building Praxis Lite for $OSNAME/$ARCH"
rm -rf build/pyinstaller dist/praxis
$PY -m PyInstaller packaging/praxis.spec --noconfirm \
    --distpath dist --workpath build/pyinstaller

# macOS: ad-hoc code-sign the nested libraries + launcher. This is a
# prerequisite for (optional) Developer-ID notarization and keeps the
# signature consistent; on its own it does NOT bypass Gatekeeper for a
# *downloaded* app — the installer clears quarantine, or ship a notarized
# .dmg (see packaging/README.md).
if [ "$OS" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
  echo "==> Ad-hoc code-signing the macOS bundle"
  find dist/praxis \( -name "*.so" -o -name "*.dylib" \) -type f \
    -exec codesign --force --timestamp=none -s - {} + 2>/dev/null || true
  codesign --force --timestamp=none -s - dist/praxis/praxis 2>/dev/null || true
fi

mkdir -p dist/artifacts
case "$OS" in
  Darwin)
    out="dist/artifacts/Praxis-Lite-macos-${ARCH}.zip"
    ( cd dist && rm -f "artifacts/Praxis-Lite-macos-${ARCH}.zip" \
      && zip -qr "artifacts/Praxis-Lite-macos-${ARCH}.zip" praxis )
    echo "==> Wrote $out ($(du -sh dist/praxis | cut -f1))"
    ;;
  Linux)
    out="dist/artifacts/Praxis-Lite-linux-${ARCH}.tar.gz"
    tar -czf "$out" -C dist praxis
    echo "==> Wrote $out ($(du -sh dist/praxis | cut -f1))"
    ;;
esac

echo "==> Done. Artifacts in dist/artifacts/:"
ls -lh dist/artifacts/
