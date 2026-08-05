"""
Praxis filesystem tools exposed as MCP tools.

Any MCP-compatible client (Claude Desktop, Cursor, ChatGPT Desktop when
they add MCP, generic MCP tool callers) can register the Praxis MCP
server and then call ``fs_search``, ``fs_read``, ``fs_delete`` and the
rest of the FS surface.  The tools are ordinary FastMCP tool functions
under the hood — they resolve the caller's principal, hand the request
to :class:`~praxis.filesystem.executor.FSExecutor`, and return the
:class:`~praxis.filesystem.types.FSResult` as a plain dict.

Principal resolution for MCP:

* When the Praxis daemon *launches* the MCP server (stdio transport),
  the daemon knows which client asked for it (from Claude Desktop's
  config, Cursor's config, etc.) and passes ``as_principal`` at
  construction time.  Everything on that server is treated as that
  agent.
* When the MCP server is HTTP-fronted, callers present a capability
  token via a header the transport passes into ``token_resolver`` on
  each call.  That path is Phase 3.1 — for now the HTTP mode inherits
  the ``as_principal`` fallback.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from praxis.filesystem.executor import FSExecutor
from praxis.filesystem.types import FSAction, FSActionEvent
from praxis.principal import Principal
from praxis.transports.local_socket import _build_event_from_args, _fs_result_to_dict

logger = logging.getLogger("praxis.mcp.fs_tools")


PrincipalGetter = Callable[[], Principal]
"""Zero-arg function that returns the principal to use for the current
call.  Injected by the caller so different transports can plug in
different resolution strategies."""

SessionProvider = Callable[[Principal], Any]
"""Optional per-call evidence-session factory."""


def register_fs_tools(
    mcp,
    executor: FSExecutor,
    principal_getter: PrincipalGetter,
    session_provider: SessionProvider | None = None,
) -> None:
    """Register the eleven ``fs_*`` tools on a FastMCP instance.

    ``mcp`` is a ``mcp.server.fastmcp.FastMCP`` — we take it as an
    ``Any`` to avoid a hard import of the ``mcp`` package at module
    load time (some environments only install ``mcp`` for the MCP
    extra).

    Each tool is intentionally documented via its docstring so
    Claude / Cursor render usable help text in the MCP client UI.
    """

    async def _run(action: FSAction, args: dict[str, Any]) -> dict[str, Any]:
        principal = principal_getter()
        event = _build_event_from_args(
            action=action,
            args=args,
            principal=principal,
        )
        session = None
        if session_provider is not None:
            provided = session_provider(principal)
            if hasattr(provided, "__await__"):
                session = await provided
            else:
                session = provided
        result = await executor.execute(event, session=session)
        return _fs_result_to_dict(result)

    # ------------------------------------------------------------------
    # T0 — Read
    # ------------------------------------------------------------------

    @mcp.tool()
    async def fs_search(
        query: str,
        paths: list[str] | None = None,
        ext: str = "",
        limit: int = 10,
    ) -> dict[str, Any]:
        """Search the user's disk by filename (v1 filename fuzzy).

        Returns a ranked list of file paths whose name matches the query.
        Ranking blends fuzzy match, recency, and a directory prior — so
        files in ``~/Documents`` outrank equivalents in
        ``~/Library/Caches``.

        Args:
            query: The text the user is looking for.  Case-insensitive.
                Synonyms are auto-expanded (``resume`` also matches ``cv``,
                ``passport`` matches ``id``, etc.).
            paths: Optional list of directories to search under.  Empty
                = search the user's home directory.
            ext: Optional extension filter, e.g. ``"pdf"``.
            limit: Max hits to return (default 10).

        Returns:
            ``result.hits`` is a list of ``{path, score, matched_query}``
            dicts sorted best-first.
        """
        return await _run(
            FSAction.SEARCH,
            {"query": query, "paths": paths or [], "ext": ext, "limit": limit},
        )

    @mcp.tool()
    async def fs_read(path: str, max_bytes: int = 0) -> dict[str, Any]:
        """Read a file's bytes as a UTF-8 string.

        Refuses to touch credential stores (``~/.ssh``, ``~/.aws``,
        keychains, ``.env``) regardless of principal.  Files larger than
        ``max_bytes`` (or the executor's default cap) are truncated with
        ``result.truncated == true``.
        """
        return await _run(FSAction.READ, {"paths": [path], "max_bytes": max_bytes})

    @mcp.tool()
    async def fs_stat(path: str) -> dict[str, Any]:
        """Return metadata for a path — size, mtime, mode, is_dir, is_file."""
        return await _run(FSAction.STAT, {"paths": [path]})

    @mcp.tool()
    async def fs_list_dir(path: str, glob: str = "") -> dict[str, Any]:
        """List entries directly under a directory.

        Args:
            path: The directory to list.
            glob: Optional shell-style pattern, e.g. ``"*.pdf"``.
                Empty = list everything.
        """
        return await _run(FSAction.LIST_DIR, {"paths": [path], "glob": glob})

    # ------------------------------------------------------------------
    # T1 — Benign write (approval-required for external agents)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def fs_create_dir(path: str) -> dict[str, Any]:
        """Create a directory (parents included).  Idempotent.

        For external agents this triggers a user-approval prompt.
        """
        return await _run(FSAction.CREATE_DIR, {"paths": [path]})

    @mcp.tool()
    async def fs_create_file(path: str, content: str = "") -> dict[str, Any]:
        """Create a new file with the given UTF-8 content.

        Refuses if the path already exists — use ``fs_overwrite`` (T2)
        to replace an existing file.

        For external agents this triggers a user-approval prompt.
        """
        return await _run(
            FSAction.CREATE_FILE, {"paths": [path], "content": content}
        )

    @mcp.tool()
    async def fs_write(
        path: str,
        content: str,
        if_exists: str = "error",
    ) -> dict[str, Any]:
        """Write UTF-8 bytes to a file.

        Args:
            path: Destination file.
            content: The text to write.
            if_exists: One of ``"error"`` (default — refuse), ``"append"``
                (add to end).  Overwriting an existing file is a T2 op
                — use ``fs_overwrite``.
        """
        return await _run(
            FSAction.WRITE,
            {"paths": [path], "content": content, "if_exists": if_exists},
        )

    # ------------------------------------------------------------------
    # T2 — Destructive (blocked for external agents by default)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def fs_delete(paths: list[str]) -> dict[str, Any]:
        """Delete file(s) — staged to Praxis's trash for 24h.

        Files are moved to ``~/.praxis/trash/`` first, not hard-deleted.
        The user can restore any staged entry within the retention
        window.

        **For external agents this is blocked by default.**  A trusted-
        agent policy may enable it with per-op approval.  For the local
        user (``praxis:local``) this triggers OS-native 2FA + a 10s
        cool-off before the trash move happens.
        """
        return await _run(FSAction.DELETE, {"paths": paths})

    @mcp.tool()
    async def fs_move(paths: list[str], target_dir: str) -> dict[str, Any]:
        """Move file(s) into a target directory.  Destructive → T2."""
        return await _run(
            FSAction.MOVE, {"paths": paths, "target_dir": target_dir}
        )

    @mcp.tool()
    async def fs_rename(path: str, new_name: str) -> dict[str, Any]:
        """Rename a file in place.  ``new_name`` must be a basename."""
        return await _run(
            FSAction.RENAME, {"paths": [path], "new_name": new_name}
        )

    @mcp.tool()
    async def fs_overwrite(path: str, content: str) -> dict[str, Any]:
        """Overwrite an existing file — backs the original up to trash first.

        Unlike ``fs_write`` this replaces existing content but always
        keeps a recoverable copy in ``~/.praxis/trash/``.
        """
        return await _run(
            FSAction.OVERWRITE, {"paths": [path], "content": content}
        )


__all__ = [
    "register_fs_tools",
    "PrincipalGetter",
    "SessionProvider",
]
