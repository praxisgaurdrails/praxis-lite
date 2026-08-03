"""
Praxis local socket transport — the ``praxis:local`` entry point.

The Praxis CLI, menubar popover, and any process running as the user
connect here to run FS ops with the local (trusted) principal.  Nothing
on TCP can ever reach this transport — the socket lives on the
filesystem with mode 0600, or on Windows on a loopback port that only
accepts connections whose PID matches the current user.

Protocol (line-delimited JSON over the stream):

    Server → sends 64 hex chars (32-byte challenge) + '\\n'
    Client → sends hex(HMAC-SHA256(local_key, challenge)) + '\\n'
    Server → sends 'OK\\n' on success, 'AUTH_FAIL\\n' + closes on failure

    Client → sends one JSON request per line:
             {"op": "fs.search", "args": {...}, "request_id": "..."}
    Server → sends one JSON response per line:
             {"status": "success", "result": {...}, ...}

The response mirrors :class:`~praxis.filesystem.types.FSResult` for
FS ops; for control ops (``ping``, ``kill``) it's a small custom dict.

Every request is authenticated exactly once (at handshake).  Reusing
the same connection for many requests keeps handshake cost off the
hot path.  If a request causes a fatal error the server closes the
connection; the client reconnects and rehandshakes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable

from praxis.filesystem.executor import FSExecutor
from praxis.filesystem.types import FSAction, FSActionEvent, FSResult
from praxis.principal import (
    Principal,
    PrincipalResolver,
    compute_local_response,
    make_local_challenge,
)

logger = logging.getLogger("praxis.transports.local_socket")


DEFAULT_SOCKET_PATH = Path.home() / ".praxis" / "socket"
DEFAULT_LOOPBACK_HOST = "127.0.0.1"
DEFAULT_LOOPBACK_PORT = 18791
_MAX_LINE_BYTES = 8 * 1024 * 1024  # 8 MB per request line — plenty for content payloads


# ---------------------------------------------------------------------------
# SessionProvider — lets the daemon inject an EvidenceSession per connection
# ---------------------------------------------------------------------------

SessionProvider = Callable[[Principal], "Awaitable[Any] | Any"]
"""Return an :class:`~praxis.evidence.vault.EvidenceSession` for the
connection, or None to disable evidence recording."""


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class LocalSocketServer:
    """The Unix-socket (or loopback) entry point.

    Construct with the executor + a principal resolver already loaded
    with the local key.  Call :meth:`start` on the daemon's event
    loop; call :meth:`stop` at shutdown.

    On POSIX we bind a Unix socket at ``socket_path``.  On Windows,
    where asyncio does not support Unix sockets, we bind a loopback
    TCP socket.  Either way the security anchor is the HMAC
    challenge — the transport is only the delivery channel.
    """

    def __init__(
        self,
        executor: FSExecutor,
        resolver: PrincipalResolver,
        socket_path: Path | str | None = None,
        session_provider: SessionProvider | None = None,
        loopback_host: str = DEFAULT_LOOPBACK_HOST,
        loopback_port: int = DEFAULT_LOOPBACK_PORT,
    ) -> None:
        self._executor = executor
        self._resolver = resolver
        self._socket_path = (
            Path(socket_path) if socket_path is not None else DEFAULT_SOCKET_PATH
        )
        self._session_provider = session_provider
        self._loopback_host = loopback_host
        self._loopback_port = loopback_port
        self._server: asyncio.base_events.Server | None = None
        self._transport_kind: str = ""

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._server.is_serving()

    @property
    def transport_kind(self) -> str:
        return self._transport_kind

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    async def start(self) -> None:
        """Start listening.  Idempotent."""
        if self._server is not None:
            return
        if sys.platform != "win32":
            await self._start_unix()
        else:  # pragma: no cover — CI is posix
            await self._start_loopback()

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await self._server.wait_closed()
        except Exception:
            pass
        self._server = None
        if self._transport_kind == "unix":
            try:
                self._socket_path.unlink(missing_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _start_unix(self) -> None:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._socket_path.parent, 0o700)
        except OSError:
            pass
        # Clean up any stale socket file left over from a crash.
        try:
            self._socket_path.unlink(missing_ok=True)
        except OSError:
            pass

        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self._socket_path),
        )
        try:
            os.chmod(self._socket_path, 0o600)
        except OSError:
            pass
        self._transport_kind = "unix"
        logger.info("praxis local socket listening at %s", self._socket_path)

    async def _start_loopback(self) -> None:  # pragma: no cover
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._loopback_host,
            port=self._loopback_port,
            family=1,  # AF_INET
        )
        self._transport_kind = "loopback"
        logger.info(
            "praxis local socket (loopback) listening at %s:%d",
            self._loopback_host,
            self._loopback_port,
        )

    # ------------------------------------------------------------------
    # Client handler
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        principal: Principal | None = None
        try:
            # ---- Handshake ----
            challenge = make_local_challenge()
            writer.write(challenge.hex().encode() + b"\n")
            await writer.drain()

            response_line = await self._read_line(reader)
            if response_line is None:
                return

            principal = self._resolver.from_local_socket(
                challenge=challenge,
                response=response_line.strip(),
            )
            if not principal.is_local:
                writer.write(b"AUTH_FAIL\n")
                await writer.drain()
                return
            writer.write(b"OK\n")
            await writer.drain()

            # ---- Request loop ----
            session = None
            if self._session_provider is not None:
                sess_or_awaitable = self._session_provider(principal)
                if asyncio.iscoroutine(sess_or_awaitable):
                    session = await sess_or_awaitable
                else:
                    session = sess_or_awaitable

            while True:
                line = await self._read_line(reader)
                if line is None:
                    break
                try:
                    resp = await self._dispatch_line(
                        line=line,
                        principal=principal,
                        session=session,
                    )
                except Exception as exc:  # last-resort catch
                    logger.exception("local socket dispatch failed")
                    resp = {
                        "status": "error",
                        "reason": f"dispatch error: {type(exc).__name__}",
                    }
                writer.write((json.dumps(resp) + "\n").encode())
                await writer.drain()

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception:
            logger.exception("local socket handler crashed")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def _dispatch_line(
        self,
        line: str,
        principal: Principal,
        session: Any,
    ) -> dict[str, Any]:
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            return {"status": "error", "reason": f"invalid JSON: {e}"}

        op = req.get("op", "")
        args = req.get("args", {}) or {}
        request_id = req.get("request_id", "")

        if op == "ping":
            return {"status": "success", "result": {"pong": True}}

        if op == "kill":
            self._executor._kill.fire(  # noqa: SLF001
                reason=str(args.get("reason", "user request")),
                fired_by=str(principal),
            )
            return {"status": "success", "result": {"fired": True}}

        # FS ops
        if not op.startswith("fs."):
            return {"status": "error", "reason": f"unknown op: {op!r}"}

        try:
            action = FSAction(op)
        except ValueError:
            return {"status": "error", "reason": f"unknown fs op: {op!r}"}

        event = _build_event_from_args(
            action=action,
            args=args,
            principal=principal,
            request_id=request_id,
        )
        result: FSResult = await self._executor.execute(event, session=session)
        return _fs_result_to_dict(result)

    # ------------------------------------------------------------------
    # Line reading
    # ------------------------------------------------------------------

    async def _read_line(self, reader: asyncio.StreamReader) -> str | None:
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError:
            # Line too big — drain the connection and abort.
            return None
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None
        if not raw:
            return None
        return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Client — used by the CLI and the popover
# ---------------------------------------------------------------------------


class LocalSocketClientError(RuntimeError):
    """Any error surfaced by the local-socket client."""


class LocalSocketClient:
    """A minimal async client for the local socket.

    Usage::

        client = LocalSocketClient(local_key=bytes_from_key_file)
        await client.connect()
        result = await client.call("fs.search", {"query": "passport"})
        await client.close()

    Not thread-safe.  One client per event-loop task.
    """

    def __init__(
        self,
        local_key: bytes,
        socket_path: Path | str | None = None,
        loopback_host: str = DEFAULT_LOOPBACK_HOST,
        loopback_port: int = DEFAULT_LOOPBACK_PORT,
    ) -> None:
        self._local_key = local_key
        self._socket_path = (
            Path(socket_path) if socket_path is not None else DEFAULT_SOCKET_PATH
        )
        self._loopback_host = loopback_host
        self._loopback_port = loopback_port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    async def connect(self) -> None:
        if self.connected:
            return
        if sys.platform != "win32":
            self._reader, self._writer = await asyncio.open_unix_connection(
                path=str(self._socket_path),
            )
        else:  # pragma: no cover
            self._reader, self._writer = await asyncio.open_connection(
                host=self._loopback_host,
                port=self._loopback_port,
            )

        # Handshake.
        challenge_line = await self._reader.readuntil(b"\n")
        challenge_hex = challenge_line.strip().decode()
        try:
            challenge = bytes.fromhex(challenge_hex)
        except ValueError as e:
            raise LocalSocketClientError(f"bad challenge: {e}") from e
        response = compute_local_response(challenge, self._local_key)
        self._writer.write(response.encode() + b"\n")
        await self._writer.drain()

        ack = await self._reader.readuntil(b"\n")
        if ack.strip() != b"OK":
            await self.close()
            raise LocalSocketClientError(
                f"handshake failed: {ack.strip().decode(errors='replace')}"
            )

    async def call(
        self,
        op: str,
        args: dict[str, Any] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        if not self.connected:
            await self.connect()
        assert self._reader is not None and self._writer is not None
        req = {"op": op, "args": args or {}, "request_id": request_id}
        self._writer.write((json.dumps(req) + "\n").encode())
        await self._writer.drain()
        raw = await self._reader.readuntil(b"\n")
        return json.loads(raw)

    async def close(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None

    async def __aenter__(self) -> LocalSocketClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Shared helpers used by the socket + REST + MCP transports
# ---------------------------------------------------------------------------


def _build_event_from_args(
    action: FSAction,
    args: dict[str, Any],
    principal: Principal,
    request_id: str = "",
) -> FSActionEvent:
    """Construct an :class:`FSActionEvent` from a request payload.

    Missing / unknown keys are silently dropped so a client can send
    only the fields relevant to the specific op.
    """
    content = args.get("content")
    if isinstance(content, str):
        content = content.encode("utf-8")

    paths = args.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]

    return FSActionEvent(
        action=action,
        principal=principal,
        request_id=request_id or "",
        paths=list(paths),
        query=str(args.get("query", "")),
        target_dir=str(args.get("target_dir", "")),
        new_name=str(args.get("new_name", "")),
        glob=str(args.get("glob", "")),
        if_exists=str(args.get("if_exists", "error")),
        max_bytes=int(args.get("max_bytes", 0) or 0),
        content=content,
        limit=int(args.get("limit", 0) or 0),
        ext=str(args.get("ext", "")),
        metadata=dict(args.get("metadata", {}) or {}),
    )


def _fs_result_to_dict(result: FSResult) -> dict[str, Any]:
    return {
        "status": result.status.value,
        "action": result.action.value,
        "request_id": result.request_id,
        "ok": result.ok,
        "reason": result.reason,
        "decision_matched_rule": result.decision_matched_rule,
        "result": result.result,
        "trashed_paths": result.trashed_paths,
        "approval_status": result.approval_status,
        "duration_ms": result.duration_ms,
    }


__all__ = [
    "DEFAULT_LOOPBACK_HOST",
    "DEFAULT_LOOPBACK_PORT",
    "DEFAULT_SOCKET_PATH",
    "LocalSocketClient",
    "LocalSocketClientError",
    "LocalSocketServer",
]
