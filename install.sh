#!/bin/sh
# Praxis one-line installer for macOS & Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/praxisgaurdrails/praxis-lite/main/install.sh | sh
#
# Downloads the standalone Praxis Lite app (no Python or pip required),
# installs it to ~/.praxis, puts `praxis` on your PATH, picks a safe
# default policy, and connects it to any AI tools you already have.
set -eu

REPO="praxisgaurdrails/praxis-lite"
APP_DIR="$HOME/.praxis/app"
BIN_DIR="$HOME/.local/bin"

say()  { printf "\033[36m%s\033[0m\n" "$*"; }
ok()   { printf "\033[32m%s\033[0m\n" "$*"; }
warn() { printf "\033[33m%s\033[0m\n" "$*"; }
die()  { printf "\033[31m%s\033[0m\n" "$*" >&2; exit 1; }

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    if [ "$ARCH" != "arm64" ]; then
      warn "Note: the prebuilt Mac app is Apple Silicon (arm64). On an Intel"
      warn "Mac, install with pip instead:  pip3 install praxis-guardrail"
    fi
    ASSET="Praxis-Lite-macos-arm64.zip"
    EXT="zip"
    ;;
  Linux)
    ASSET="Praxis-Lite-linux-x86_64.tar.gz"
    EXT="tar.gz"
    ;;
  *)
    die "Unsupported OS: $OS. On Windows, run the PowerShell installer (see the README)."
    ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required but not found."

say "Downloading Praxis for $OS ($ARCH)…"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP/praxis.$EXT" || die "Download failed: $URL"

say "Installing to $APP_DIR …"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
case "$EXT" in
  zip)    unzip -q "$TMP/praxis.$EXT" -d "$APP_DIR" ;;
  tar.gz) tar -xzf "$TMP/praxis.$EXT" -C "$APP_DIR" ;;
esac

LAUNCHER="$APP_DIR/praxis/praxis"
[ -f "$LAUNCHER" ] || die "Install looks incomplete (no launcher at $LAUNCHER)."
chmod +x "$LAUNCHER"

# macOS: clear the quarantine flag so it runs without a Gatekeeper prompt.
if [ "$OS" = "Darwin" ]; then
  xattr -dr com.apple.quarantine "$APP_DIR/praxis" >/dev/null 2>&1 || true
fi

# Put `praxis` on PATH.
mkdir -p "$BIN_DIR"
ln -sf "$LAUNCHER" "$BIN_DIR/praxis"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    for RC in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
      [ -f "$RC" ] || continue
      grep -q '.local/bin' "$RC" 2>/dev/null && continue
      printf '\n# Added by Praxis installer\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC"
    done
    PATH="$BIN_DIR:$PATH"
    ADDED_PATH=1
    ;;
esac

ok ""
ok "✅ Praxis installed."
"$LAUNCHER" --version || true

# Pick a safe default policy (balanced) if the user has none yet.
if [ ! -f "$HOME/.praxis/config.toml" ]; then
  say ""
  say "Setting a safe default policy (balanced)…"
  "$LAUNCHER" init --strictness balanced --yes >/dev/null 2>&1 || true
fi

# Connect Praxis to any detected AI tools (Codex, Claude, Cursor, Windsurf…).
say ""
say "Connecting Praxis to your AI tools…"
"$LAUNCHER" install || true

ok ""
ok "🛡️  All set. Restart your AI tool (ChatGPT/Codex, Claude, Cursor…) so it"
ok "    picks up Praxis. Then just use your AI normally — Praxis is watching."
ok ""
ok "    Change how strict it is:   praxis init"
ok "    See connected tools:       praxis clients"
if [ "${ADDED_PATH:-0}" = "1" ]; then
  warn ""
  warn "Open a NEW terminal (or run 'source ~/.zshrc') so the 'praxis' command works."
fi
