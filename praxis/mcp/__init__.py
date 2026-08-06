"""
Praxis MCP — the on-device filesystem guardrail exposed over the Model
Context Protocol.

Any MCP client (Claude Desktop, Codex/ChatGPT, Cursor, Windsurf, ...) can
connect to the Praxis MCP server and get guarded ``fs.search`` /
``fs.read`` / ``fs.delete`` tools. Every call is checked against the
caller's principal and risk tier before it runs.

    from praxis.mcp import main
    raise SystemExit(main())            # `praxis-mcp` entry point

    from praxis.mcp import build_server, register_fs_tools
"""

from praxis.mcp.praxis_server import build_server, main
from praxis.mcp.fs_tools import register_fs_tools

__all__ = ["build_server", "main", "register_fs_tools"]
