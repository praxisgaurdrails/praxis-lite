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
