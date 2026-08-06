"""
Praxis MCP standalone server — the entry point Codex / Claude Desktop /
Cursor / any MCP client spawns as a stdio (or streamable-http) subprocess.

Usage from the shell (typically invoked by an MCP client's config, not
by hand)::

    python -m praxis.mcp.praxis_server \\
        --as-principal agent:codex \\
        --search-roots ~/Documents ~/Downloads \\
        --auto-approve

Or in ``~/.codex/config.toml``::

    [mcp_servers.praxis]
    command = "python"
    args = [
        "-m", "praxis.mcp.praxis_server",
        "--as-principal", "agent:codex",
        "--search-roots", "~/Documents", "~/Downloads", "~/Desktop"
    ]

The server exposes the eleven ``fs_*`` tools from
:mod:`praxis.mcp.fs_tools` behind the full principal + tier +
approval + evidence + kill-switch pipeline.  Every action Codex takes
is governed by exactly the same policy engine the CLI / popover use.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from praxis.approval import (
    ApprovalCoordinator,
    AutoApproveNotifier,
    NullAuthenticator,
    default_notifier,
)
from praxis.evidence.vault import EvidenceSession, EvidenceVault
from praxis.filesystem import (
    FSExecutor,
    FSPolicyEngine,
    StagedTrash,
    pick_default_backend,
)
from praxis.kill_switch import get_kill_switch
from praxis.mcp.fs_tools import register_fs_tools
from praxis.principal import Principal, PrincipalKind
from praxis.tiers import RiskTier

logger = logging.getLogger("praxis.mcp.praxis_server")


DEFAULT_STATE_DIR = Path.home() / ".praxis"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="praxis-mcp",
        description=(
            "Praxis MCP server — exposes filesystem tools to any MCP client "
            "(Codex, Claude Desktop, Cursor) with principal-aware policy "
            "gating and a hash-chained evidence log."
        ),
    )
    p.add_argument(
        "--as-principal",
        default="agent:mcp-caller",
        help=(
            "Principal to attribute all calls on this stdio to.  Format: "
            "'agent:<name>' or 'praxis:local'.  Default: agent:mcp-caller."
        ),
    )
    p.add_argument(
        "--search-roots",
        default="",
        help=(
            "Comma-separated root directories fs_search should scan, e.g. "
            "'~/Documents,~/Downloads'.  Default: $HOME."
        ),
    )
    p.add_argument(
        "--search-root",
        action="append",
        default=[],
        dest="search_root_list",
        help="A single search root (repeatable). Alternative to --search-roots.",
    )
    p.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=(
            "Where Praxis keeps its trash + evidence + local key.  "
            "Default: ~/.praxis"
        ),
    )
    p.add_argument(
        "--auto-approve",
        action="store_true",
        help=(
            "Auto-approve every T1/T2 request instead of prompting the "
            "user.  UNSAFE — for local testing only.  Default: deny."
        ),
    )
    p.add_argument(
        "--no-evidence",
        action="store_true",
        help=(
            "Do not record any actions to the evidence vault.  For "
            "tests / ephemeral use."
        ),
    )
    p.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default="stdio",
        help="MCP transport.  stdio is what MCP clients spawn.",
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="For streamable-http / sse transports.",
    )
    p.add_argument(
        "--port",
        type=int,
        default=18792,
        help="For streamable-http / sse transports.",
    )
    p.add_argument(
        "--log-level",
        default="WARNING",
        help="Python logging level.  WARNING is quiet for stdio use.",
    )
    return p.parse_args(argv)


def _parse_principal(s: str) -> Principal:
    """Parse ``praxis:local`` or ``agent:<name>`` from the CLI arg."""
    if s == "praxis:local":
        return Principal.local(proven_via="mcp_server:startup_arg")
    if s == "unknown":
        return Principal.unknown(proven_via="mcp_server:explicit_unknown")
    if s.startswith("agent:"):
        name = s[len("agent:"):].strip()
        if not name:
            raise SystemExit(f"invalid principal: {s!r} (empty agent name)")
        return Principal.agent(
            name=name, proven_via="mcp_server:startup_arg"
        )
    raise SystemExit(
        f"invalid --as-principal {s!r}. Use 'praxis:local' or 'agent:<name>'."
    )


# ---------------------------------------------------------------------------
# Server builder
# ---------------------------------------------------------------------------


def build_server(
    principal: Principal,
    search_roots: list[str],
    state_dir: Path,
    auto_approve: bool,
    no_evidence: bool,
) -> tuple[FastMCP, "_ServerState"]:
    """Wire up the FastMCP instance + all the plumbing.

    Returned :class:`_ServerState` holds references the daemon needs to
    keep alive (evidence session, executor, coordinator, etc.).  We
    return them explicitly to keep them from being GC'd while the
    stdio loop runs.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        state_dir.chmod(0o700)
    except OSError:
        pass

    # Approvals: safe default = deny; user opts in to auto-approve.
    if auto_approve:
        notifier = AutoApproveNotifier()
    else:
        notifier = default_notifier()  # the null/deny notifier
    coordinator = ApprovalCoordinator(
        notifier=notifier,
        authenticator=NullAuthenticator(),
    )

    trash = StagedTrash(trash_dir=state_dir / "trash")
    kill_switch = get_kill_switch()
    kill_switch.bind_approval_coordinator(coordinator.cancel_all)

    executor = FSExecutor(
        policy=FSPolicyEngine(),
        approvals=coordinator,
        trash=trash,
        kill_switch=kill_switch,
        search_backend=pick_default_backend(),
    )

    # Evidence — one session per subprocess launch.
    evidence: EvidenceVault | None = None
    session: EvidenceSession | None = None
    if not no_evidence:
        # Praxis treats the tamper-proof audit trail as a core (free)
        # feature — bypass the legacy Praxis license gate.
        evidence = EvidenceVault(state_dir / "evidence", enforce_license=False)

    async def _session_provider(_p: Principal) -> EvidenceSession | None:
        """One session per server lifetime, lazily created.

        Evidence is best-effort: if the vault can't start for any
        reason, we return None and the tool still runs.  The guardrail
        must never fail closed just because auditing is unavailable.
        """
        nonlocal session, evidence
        if evidence is None:
            return None
        if session is None:
            agent_id = principal.name if principal.is_agent else "local"
            try:
                session = await evidence.start_session(agent_id=agent_id)
            except Exception as e:
                logger.warning("evidence unavailable (%s); running without audit", e)
                evidence = None
                return None
        return session

    # Expand each search root now so the backend doesn't have to.
    expanded_roots = [str(Path(r).expanduser()) for r in search_roots]
    # Wrap the executor's search backend with a "default roots when none provided" behavior.
    # We do this by overriding fs_search's default paths in the tool wrapper.
    # Simpler: just record the roots so we can pass them explicitly if callers omit paths.
    _default_roots = expanded_roots

    # ---- Build the MCP instance ----
    instructions = (
        "Praxis governs every filesystem operation you propose. "
        "You are seen as principal: " + str(principal) + ". "
        "Reads (fs_search, fs_read, fs_stat, fs_list_dir) are permitted. "
        "Writes (fs_create_dir, fs_create_file, fs_write) require user "
        "approval when you request them. "
        "Destructive operations (fs_delete, fs_move, fs_rename, "
        "fs_overwrite) are BLOCKED for external agents by default; ask "
        "the user to run them directly. "
        "Reading credential stores (~/.ssh, ~/.aws, keychains, .env) is "
        "refused regardless. "
        "Every action is hash-chained into an audit log."
    )
    mcp = FastMCP("praxis", instructions=instructions)

    # Static principal for this stdio subprocess.
    def _get_principal() -> Principal:
        return principal

    register_fs_tools(
        mcp=mcp,
        executor=executor,
        principal_getter=_get_principal,
        session_provider=_session_provider,
    )

    # Extra convenience tool: return the daemon's current state so
    # clients can render it in a status view.
    @mcp.tool()
    async def praxis_status() -> dict[str, Any]:
        """Report the daemon's current principal, trash size, and health."""
        return {
            "principal": str(principal),
            "kill_switch_fired": kill_switch.is_fired,
            "trash_entries": len(trash.list_entries()),
            "trash_size_bytes": trash.total_size_bytes(),
            "default_search_roots": _default_roots,
            "evidence_enabled": evidence is not None,
        }

    state = _ServerState(
        executor=executor,
        coordinator=coordinator,
        trash=trash,
        evidence=evidence,
        session_ref=lambda: session,
        principal=principal,
    )
    return mcp, state


class _ServerState:
    """Handles the daemon keeps alive during the run."""

    def __init__(
        self,
        executor: FSExecutor,
        coordinator: ApprovalCoordinator,
        trash: StagedTrash,
        evidence: EvidenceVault | None,
        session_ref,
        principal: Principal,
    ) -> None:
        self.executor = executor
        self.coordinator = coordinator
        self.trash = trash
        self.evidence = evidence
        self.session_ref = session_ref
        self.principal = principal

    async def close(self) -> None:
        """End the evidence session cleanly at shutdown."""
        session = self.session_ref()
        if session is not None:
            try:
                await session.end()
            except Exception:
                logger.exception("evidence session end failed")


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    principal = _parse_principal(args.as_principal)
    # Safety guard: refuse to run as ``praxis:local`` over an MCP
    # subprocess — that principal is reserved for the Unix-socket path.
    if principal.kind == PrincipalKind.LOCAL:
        print(
            "ERROR: --as-principal praxis:local is not permitted for MCP "
            "subprocesses.  praxis:local is reserved for the Unix-socket "
            "entry point that verifies possession of the local key.  Use "
            "--as-principal agent:<your-client-name> instead.",
            file=sys.stderr,
        )
        return 2

    # Resolve search roots from --search-roots (comma-separated) and/or
    # --search-root (repeatable).  Falls back to $HOME.
    roots: list[str] = []
    if args.search_roots:
        roots.extend(r.strip() for r in args.search_roots.split(",") if r.strip())
    if args.search_root_list:
        roots.extend(args.search_root_list)
    if not roots:
        roots = [str(Path.home())]

    mcp, state = build_server(
        principal=principal,
        search_roots=roots,
        state_dir=args.state_dir,
        auto_approve=args.auto_approve,
        no_evidence=args.no_evidence,
    )

    # Print startup banner to stderr so MCP clients see it in their logs
    # without polluting stdout (which is the MCP wire protocol).
    print(
        f"[praxis] MCP server ready — principal={principal} "
        f"transport={args.transport} state_dir={args.state_dir}",
        file=sys.stderr,
    )

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        elif args.transport == "streamable-http":
            mcp.run(transport="streamable-http", host=args.host, port=args.port)
        elif args.transport == "sse":
            mcp.run(transport="sse", host=args.host, port=args.port)
    finally:
        try:
            asyncio.run(state.close())
        except Exception:
            pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
