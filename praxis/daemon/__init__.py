"""
Praxis Daemon — one long-running process that owns everything.

Wires together:

* :class:`~praxis.principal.PrincipalResolver` (local key at
  ``~/.praxis/local_key``, HMAC-signed capability tokens).
* :class:`~praxis.filesystem.FSPolicyEngine` + tier gate.
* :class:`~praxis.approval.ApprovalCoordinator` (OS notifier +
  authenticator injected at wire-up).
* :class:`~praxis.filesystem.StagedTrash` at ``~/.praxis/trash``.
* :class:`~praxis.evidence.vault.EvidenceVault` at
  ``~/.praxis/evidence`` — one session per daemon lifetime.
* :class:`~praxis.filesystem.FSExecutor` — the one place FS ops run.
* :class:`~praxis.transports.LocalSocketServer` — Unix socket entry
  point at ``~/.praxis/socket`` for CLI + popover.
* Optional MCP stdio launcher (spawned per-agent in a separate
  ``PraxisServerLauncher`` — this daemon itself does not host MCP;
  each MCP client spawns its own subprocess).
* Optional FastAPI REST sidecar mounted on 127.0.0.1:18790.
* :class:`~praxis.connectivity.ConnectivityMonitor` (see
  :mod:`praxis.connectivity`).

Started via ``python -m praxis.daemon`` or
``praxis daemon start`` from the CLI.  Runs until Ctrl-C or a kill-
switch fire.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import signal
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from praxis.approval import (
    ApprovalCoordinator,
    Authenticator,
    Notifier,
    NullAuthenticator,
    default_authenticator,
    default_notifier,
)
from praxis.evidence.vault import EvidenceSession, EvidenceVault
from praxis.filesystem.executor import FSExecutor
from praxis.filesystem.policy import FSPolicyEngine
from praxis.filesystem.search_backends import pick_default_backend
from praxis.filesystem.trash import StagedTrash
from praxis.kill_switch import get_kill_switch
from praxis.principal import Principal, PrincipalResolver, ensure_local_key
from praxis.tokens.capability import TokenStore
from praxis.transports.local_socket import LocalSocketServer

logger = logging.getLogger("praxis.daemon")


DEFAULT_STATE_DIR = Path.home() / ".praxis"
DEFAULT_SOCKET_PATH = DEFAULT_STATE_DIR / "socket"
DEFAULT_PID_FILE = DEFAULT_STATE_DIR / "daemon.pid"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class DaemonConfig:
    """Startup config for the Praxis daemon."""

    state_dir: Path = field(default_factory=lambda: DEFAULT_STATE_DIR)
    socket_path: Path | None = None
    """Unix socket path.  Defaults to ``state_dir / 'socket'``."""

    enable_rest: bool = False
    """Mount the REST sidecar on ``rest_host:rest_port``.  Off by default
    — REST is for advanced integration, most users use the socket + MCP."""

    rest_host: str = "127.0.0.1"
    rest_port: int = 18790

    enable_connectivity: bool = True
    """Run the online/offline state monitor in the background."""

    auto_approve: bool = False
    """Testing / demo mode — auto-approve every T1/T2.  UNSAFE in production."""

    log_level: str = "INFO"

    search_backend: Any = None
    """Optional override for the fs.search backend.  Defaults to
    ``pick_default_backend()`` — Spotlight on macOS, plocate on Linux,
    walker fallback.  Tests inject WalkerBackend for determinism."""

    def resolved_socket_path(self) -> Path:
        return self.socket_path or (self.state_dir / "socket")

    def resolved_trash_dir(self) -> Path:
        return self.state_dir / "trash"

    def resolved_evidence_dir(self) -> Path:
        return self.state_dir / "evidence"

    def resolved_local_key_path(self) -> Path:
        return self.state_dir / "local_key"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k, v in list(d.items()):
            if isinstance(v, Path):
                d[k] = str(v)
        return d


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


class PraxisDaemon:
    """The long-running background process.

    Instantiate with a :class:`DaemonConfig`, call :meth:`start`, then
    :meth:`serve_forever` (or use :meth:`run` which does both then blocks).
    """

    def __init__(self, config: DaemonConfig | None = None) -> None:
        self.config = config or DaemonConfig()
        self._started = False
        self._shutdown_event: asyncio.Event | None = None

        # Components (populated in start()).
        self.resolver: PrincipalResolver | None = None
        self.token_store: TokenStore | None = None
        self.approvals: ApprovalCoordinator | None = None
        self.trash: StagedTrash | None = None
        self.evidence: EvidenceVault | None = None
        self._session: EvidenceSession | None = None
        self.executor: FSExecutor | None = None
        self.socket_server: LocalSocketServer | None = None
        self.rest_app: Any = None
        self._rest_task: asyncio.Task | None = None
        self.connectivity: Any = None  # ConnectivityMonitor (avoid import cycle)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._started

    async def status(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of the daemon's state."""
        kill = get_kill_switch()
        return {
            "running": self._started,
            "state_dir": str(self.config.state_dir),
            "socket_path": str(self.config.resolved_socket_path()),
            "socket_running": bool(
                self.socket_server and self.socket_server.is_running
            ),
            "rest_running": bool(self.rest_app and self._rest_task),
            "connectivity": (
                self.connectivity.snapshot() if self.connectivity else None
            ),
            "kill_switch_fired": kill.is_fired,
            "trash_entries": len(self.trash.list_entries()) if self.trash else 0,
            "trash_size_bytes": self.trash.total_size_bytes() if self.trash else 0,
            "active_tokens": (
                self.token_store.active_count if self.token_store else 0
            ),
            "evidence_session": (
                self._session.session_id if self._session else None
            ),
            "started_at": self._started_at if hasattr(self, "_started_at") else None,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(
        self,
        notifier: Notifier | None = None,
        authenticator: Authenticator | None = None,
    ) -> None:
        """Wire up every component and bind the transports."""
        if self._started:
            return

        logging.basicConfig(
            level=self.config.log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        self._started_at = time.time()

        state = self.config.state_dir
        state.mkdir(parents=True, exist_ok=True)
        try:
            state.chmod(0o700)
        except OSError:
            pass

        # --- User config (strictness matrix + roots) ---
        from praxis.config import PraxisConfig, set_config

        self.praxis_config = PraxisConfig.load(state / "config.toml")
        set_config(self.praxis_config)
        logger.info("Praxis strictness = %s", self.praxis_config.strictness)

        # --- Principal resolver + local key ---
        key_path = self.config.resolved_local_key_path()
        key = ensure_local_key(key_path)
        self.resolver = PrincipalResolver(
            local_key=key,
            local_key_path=key_path,
        )
        self.token_store = TokenStore()

        # --- Approval coordinator ---
        if self.config.auto_approve:
            from praxis.approval import AutoApproveNotifier

            notifier = notifier or AutoApproveNotifier()
        self.approvals = ApprovalCoordinator(
            notifier=notifier or default_notifier(),
            authenticator=authenticator or default_authenticator(),
        )

        # --- Trash, evidence, executor ---
        self.trash = StagedTrash(trash_dir=self.config.resolved_trash_dir())
        self.evidence = EvidenceVault(
            storage_dir=self.config.resolved_evidence_dir(),
            enforce_license=False,
        )
        # Evidence recording is best-effort: the guardrail must keep
        # working even if the vault can't start (license gate, disk
        # full, etc.).  A guardrail that fails closed on evidence would
        # be worse than one that keeps blocking bad actions without a
        # full audit trail.
        try:
            self._session = await self.evidence.start_session(agent_id="daemon")
        except Exception as e:
            logger.warning(
                "evidence vault unavailable (%s); running without an "
                "audit trail. The guardrail is still fully active.",
                e,
            )
            self._session = None
        self.executor = FSExecutor(
            policy=FSPolicyEngine(),
            approvals=self.approvals,
            trash=self.trash,
            kill_switch=get_kill_switch(),
            search_backend=self.config.search_backend or pick_default_backend(),
        )

        # --- Kill switch wiring ---
        kill = get_kill_switch()
        kill.bind_token_store(
            lambda: self.token_store.revoke_all_for_agent("*", by="kill_switch")
        )
        kill.bind_approval_coordinator(self.approvals.cancel_all)
        kill.register(lambda: logger.warning("kill switch fired"))

        # --- Local socket (praxis:local entry point) ---
        session_ref = self._session

        def _session_provider(_p: Principal) -> EvidenceSession | None:
            return session_ref

        self.socket_server = LocalSocketServer(
            executor=self.executor,
            resolver=self.resolver,
            socket_path=self.config.resolved_socket_path(),
            session_provider=_session_provider,
        )
        await self.socket_server.start()

        # --- Connectivity monitor (background task) ---
        if self.config.enable_connectivity:
            from praxis.connectivity import ConnectivityMonitor

            self.connectivity = ConnectivityMonitor()
            await self.connectivity.start()

        # --- Optional REST sidecar ---
        if self.config.enable_rest:
            await self._start_rest()

        # --- PID file ---
        pid_file = state / "daemon.pid"
        try:
            pid_file.write_text(f"{__import__('os').getpid()}\n")
        except OSError:
            pass

        self._started = True
        self._shutdown_event = asyncio.Event()
        logger.info(
            "praxis daemon started (socket=%s, rest=%s, connectivity=%s)",
            self.config.resolved_socket_path(),
            self.config.enable_rest,
            self.config.enable_connectivity,
        )

    async def stop(self) -> None:
        """Shut down every component cleanly."""
        if not self._started:
            return

        # Reverse of start order.
        if self.connectivity:
            with contextlib.suppress(Exception):
                await self.connectivity.stop()

        if self._rest_task:
            self._rest_task.cancel()
            with contextlib.suppress(BaseException):
                await self._rest_task

        if self.socket_server:
            with contextlib.suppress(Exception):
                await self.socket_server.stop()

        if self._session and self.evidence:
            with contextlib.suppress(Exception):
                await self._session.end()

        # Remove PID file.
        pid_file = self.config.state_dir / "daemon.pid"
        with contextlib.suppress(OSError):
            pid_file.unlink()

        if self._shutdown_event:
            self._shutdown_event.set()
        self._started = False
        logger.info("praxis daemon stopped")

    async def serve_forever(self) -> None:
        """Block until :meth:`stop` is called or a signal fires."""
        assert self._started, "call start() first"
        assert self._shutdown_event is not None

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self._handle_signal(s)),
                )
            except NotImplementedError:  # pragma: no cover (Windows)
                pass

        await self._shutdown_event.wait()

    async def _handle_signal(self, sig: int) -> None:
        logger.info("caught signal %d, shutting down", sig)
        await self.stop()

    async def run(
        self,
        notifier: Notifier | None = None,
        authenticator: Authenticator | None = None,
    ) -> None:
        """Start + serve_forever + stop.  For non-programmatic use."""
        await self.start(notifier=notifier, authenticator=authenticator)
        try:
            await self.serve_forever()
        finally:
            await self.stop()

    # ------------------------------------------------------------------
    # REST sidecar (optional)
    # ------------------------------------------------------------------

    async def _start_rest(self) -> None:
        """Bring up the FastAPI /api/v1/fs/* router in a background task.

        The REST sidecar (OpenClaw / framework integration) is a Praxis
        Full feature; in Lite the dependencies are absent, so this is a
        no-op that logs and returns.
        """
        try:
            from fastapi import FastAPI
            import uvicorn

            from praxis.sidecar.fs_routes import create_fs_router
        except ImportError:
            logger.warning(
                "REST sidecar is a Praxis Full feature (deps unavailable); skipping"
            )
            return

        session_ref = self._session

        def _session_provider(_p: Principal) -> EvidenceSession | None:
            return session_ref

        app = FastAPI(title="Praxis Sidecar", version="0.1.0")
        app.include_router(
            create_fs_router(
                executor=self.executor,
                resolver=self.resolver,
                token_store=self.token_store,
                session_provider=_session_provider,
            )
        )
        self.rest_app = app

        cfg = uvicorn.Config(
            app,
            host=self.config.rest_host,
            port=self.config.rest_port,
            log_level=self.config.log_level.lower(),
            access_log=False,
        )
        server = uvicorn.Server(cfg)
        self._rest_task = asyncio.create_task(server.serve())


# ---------------------------------------------------------------------------
# Module-level entrypoint (`python -m praxis.daemon`)
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="praxis-daemon",
        description="Praxis background daemon.",
    )
    p.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    p.add_argument("--socket", type=Path, default=None)
    p.add_argument("--rest", action="store_true", help="Enable REST sidecar")
    p.add_argument("--rest-host", default="127.0.0.1")
    p.add_argument("--rest-port", type=int, default=18790)
    p.add_argument(
        "--no-connectivity",
        action="store_true",
        help="Disable the online/offline monitor",
    )
    p.add_argument("--auto-approve", action="store_true")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)

    config = DaemonConfig(
        state_dir=args.state_dir,
        socket_path=args.socket,
        enable_rest=args.rest,
        rest_host=args.rest_host,
        rest_port=args.rest_port,
        enable_connectivity=not args.no_connectivity,
        auto_approve=args.auto_approve,
        log_level=args.log_level,
    )
    daemon = PraxisDaemon(config)
    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "DEFAULT_PID_FILE",
    "DEFAULT_SOCKET_PATH",
    "DEFAULT_STATE_DIR",
    "DaemonConfig",
    "PraxisDaemon",
    "main",
]
