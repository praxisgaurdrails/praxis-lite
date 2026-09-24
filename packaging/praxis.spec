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
    "rapidfuzz",
    "httpx",
    "pydantic",
    "click",
    "rich",
    "aiofiles",
    "yaml",
]

# Lite excludes the heavy premium (Full-only) dependencies entirely.
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
    "uvicorn",
    "jinja2",
    "starlette",
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
