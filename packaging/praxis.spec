# PyInstaller spec for the Praxis Lite standalone bundle.
#
# Praxis Lite is the free, MIT-licensed on-device MCP filesystem
# guardrail. This spec builds a single self-contained folder bundle that
# needs no Python install on the target machine.
#
# Build:  pyinstaller packaging/praxis.spec --noconfirm
# Output: dist/praxis  (launcher is dist/praxis/praxis)
#
# The same binary serves three roles via subcommands:
#   praxis install / enable / disable / clients   -> the CLI
#   praxis daemon start ...                        -> the background daemon
#   praxis mcp --as-principal agent:x ...          -> the MCP server AI tools spawn

import sys
from pathlib import Path

block_cipher = None

# Repo root (spec lives in packaging/).
ROOT = Path(SPECPATH).parent

hiddenimports = [
    "praxis.mcp.praxis_server",
    "praxis.daemon",
    "praxis.orchestrator",
    "praxis.connectivity",
    "praxis.integrations.clients",
    "praxis.llm.ollama",
    "praxis.llm.registry",
    "praxis.runbook.cache",
    "praxis.runbook.capture",
    "praxis.runbook.replay",
    "praxis.filesystem.executor",
    "praxis.filesystem.search",
    "praxis.filesystem.search_backends",
    "praxis.transports.local_socket",
    "mcp",
    "mcp.server",
    "mcp.server.fastmcp",
    "mcp.server.stdio",
    "starlette",
    "starlette.applications",
    "starlette.routing",
    "starlette.responses",
    "starlette.requests",
    "uvicorn",
    "sse_starlette",
    "rapidfuzz",
    "httpx",
    "pydantic",
    "click",
    "rich",
    "aiofiles",
    "yaml",
    # Menubar app (optional at runtime, bundled so the app ships with it).
    "praxis.menubar",
    "praxis.autostart",
    "pystray",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
]

# Menubar tray backend is OS-specific.
if sys.platform == "darwin":
    hiddenimports += [
        "pystray._darwin",
        "objc",
        "AppKit",
        "Foundation",
        "Quartz",
    ]
elif sys.platform.startswith("win"):
    hiddenimports += ["pystray._win32"]
else:
    hiddenimports += ["pystray._xorg", "pystray._gtk", "pystray._appindicator"]

# Lite excludes the heavy premium (Full-only) dependencies entirely.
# NOTE: starlette + uvicorn are NOT excluded — mcp's FastMCP imports
# starlette at module load even for the stdio transport, so excluding it
# breaks `praxis mcp` in the frozen bundle.
excludes = [
    "numpy.f2py",
    "tkinter",
    "matplotlib",
    "IPython",
    "pytest",
    "playwright",
    "fastembed",
    "onnxruntime",
    "fastapi",
    "jinja2",
]

# Bundle the policy presets.
datas = []
policies = ROOT / "policies"
if policies.exists():
    for f in policies.glob("*.yaml"):
        datas.append((str(f), "policies"))
skills = ROOT / "skills" / "praxis" / "policies"
if skills.exists():
    for f in skills.glob("*.yaml"):
        datas.append((str(f), "skills/praxis/policies"))

a = Analysis(
    [str(ROOT / "packaging" / "praxis_entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="praxis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="praxis",
)

# On macOS also emit a proper Praxis.app (correct Contents/MacOS +
# Contents/Frameworks layout) for the .dmg.  This lives alongside the
# onedir `dist/praxis` folder used by the .zip/.tar bundles.
if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Praxis.app",
        icon=None,
        bundle_identifier="app.praxis.guardrail",
        info_plist={
            "CFBundleName": "Praxis",
            "CFBundleDisplayName": "Praxis",
            "CFBundleExecutable": "praxis",
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
        },
    )
