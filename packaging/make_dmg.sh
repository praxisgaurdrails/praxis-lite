#!/usr/bin/env bash
# Build a macOS .dmg containing Praxis.app (drag-to-Applications) plus a
# one-click "Install Praxis" helper that puts `praxis` on PATH and connects
# it to your AI tools.
#
#   bash packaging/make_dmg.sh            # after packaging/build.sh
#
# Produces dist/artifacts/Praxis-Lite-macos-<arch>.dmg
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ARCH="$(uname -m)"

[ -d dist/Praxis.app ] || { echo "Run packaging/build.sh first (no dist/Praxis.app)"; exit 1; }

STAGE="build/dmg"
APP="$STAGE/Praxis.app"
rm -rf "$STAGE"; mkdir -p "$STAGE"

# PyInstaller (BUNDLE) already produced a correctly-laid-out Praxis.app.
[ -d dist/Praxis.app ] || { echo "No dist/Praxis.app — build.sh must run the spec with BUNDLE"; exit 1; }
cp -R dist/Praxis.app "$APP"

# Ad-hoc sign the whole .app (consistent signature across all libs).
if command -v codesign >/dev/null 2>&1; then
  find "$APP" \( -name "*.so" -o -name "*.dylib" \) -type f \
    -exec codesign --force --timestamp=none -s - {} + 2>/dev/null || true
  codesign --force --timestamp=none -s - "$APP/Contents/MacOS/praxis" 2>/dev/null || true
  codesign --force --timestamp=none -s - "$APP" 2>/dev/null || true
fi

# One-click installer inside the DMG: sets up PATH + connects AI tools and,
# crucially, clears quarantine on the copied app so it runs.
cat > "$STAGE/Install Praxis.command" <<'EOF'
#!/bin/sh
set -e
echo "Installing Praxis…"
SRC="$(cd "$(dirname "$0")" && pwd)/Praxis.app"
DEST="$HOME/.praxis/app"
rm -rf "$DEST"; mkdir -p "$DEST"
cp -R "$SRC" "$DEST/Praxis.app"
# Clear quarantine so macOS lets the libraries load.
xattr -cr "$DEST/Praxis.app" 2>/dev/null || true
if command -v codesign >/dev/null 2>&1; then
  find "$DEST/Praxis.app" \( -name "*.so" -o -name "*.dylib" \) -type f -exec codesign --force -s - {} + 2>/dev/null || true
  codesign --force -s - "$DEST/Praxis.app/Contents/MacOS/praxis" 2>/dev/null || true
fi
LAUNCH="$DEST/Praxis.app/Contents/MacOS/praxis"
mkdir -p "$HOME/.local/bin"
ln -sf "$LAUNCH" "$HOME/.local/bin/praxis"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *)
  for RC in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    [ -f "$RC" ] && grep -q '.local/bin' "$RC" 2>/dev/null || \
    { [ -f "$RC" ] && printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC"; }
  done ;;
esac
"$LAUNCH" --version || true
[ -f "$HOME/.praxis/config.toml" ] || "$LAUNCH" init --strictness balanced --yes >/dev/null 2>&1 || true
"$LAUNCH" install || true
"$LAUNCH" autostart enable >/dev/null 2>&1 || true
echo ""
echo "✅ Praxis installed and running in your menubar (shield icon)."
echo "Restart your AI tool (Codex, Claude, Cursor…). Manage Praxis from the menubar."
echo "Open a NEW terminal so the 'praxis' command works."
EOF
chmod +x "$STAGE/Install Praxis.command"

ln -s /Applications "$STAGE/Applications"

mkdir -p dist/artifacts
DMG="dist/artifacts/Praxis-Lite-macos-${ARCH}.dmg"
rm -f "$DMG"
hdiutil create -volname "Praxis" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
echo "==> Wrote $DMG ($(du -sh "$DMG" | cut -f1))"
