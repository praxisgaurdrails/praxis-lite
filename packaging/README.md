# Packaging — Praxis Lite standalone bundles

These files build the **download-and-run** version of Praxis Lite (a
self-contained bundle that needs no Python on the target machine). Most
users should just `pip install praxis-guardrail`; the bundles exist for
people who don't have Python.

## What gets built

| Platform | Artifact |
| --- | --- |
| macOS | `Praxis-Lite-macos-<arch>.zip` |
| Linux | `Praxis-Lite-linux-<arch>.tar.gz` |
| Windows | `Praxis-Lite-windows.zip` |

Each bundle contains a `praxis` launcher that is the CLI, the daemon, and
the MCP server all in one (selected by subcommand).

## Build locally

```bash
# macOS / Linux (from a venv with the package installed)
pip install -e . pyinstaller
./packaging/build.sh

# Windows
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

Output lands in `dist/artifacts/`.

## Build in CI

`.github/workflows/build-bundles.yml` builds all three platforms on
native GitHub runners and attaches them to the GitHub Release whenever a
`vX.Y.Z` tag is pushed. (You can't cross-compile PyInstaller, so each OS
must build on its own runner.)
