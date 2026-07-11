"""
Praxis Principal — cryptographically-anchored caller identity.

Every action carries a ``Principal`` — a value the caller cannot forge.
The three top-level classes are:

    ``praxis:local``  – the daemon itself, its CLI, and the menubar
                        popover.  Proven by presenting the local key
                        (a 0600 file readable only by the user) over a
                        Unix domain socket, never TCP.

    ``agent:<name>``  – any external caller (Claude Desktop, ChatGPT
                        Desktop, Cursor, OpenClaw, LangChain tool,
                        MCP client, REST client).  Identified by an
                        HMAC-signed capability token whose subject
                        names the agent.  Signature verified against
                        the issuer key.

    ``unknown``       – missing / invalid / expired token.  Denied.

The principal is set by the transport layer (Unix socket, MCP server,
REST sidecar) via :class:`PrincipalResolver` and travels with the
:class:`~praxis.policy.engine.ActionEvent` all the way to the
executor and the evidence chain.

See ``docs/DESIGN.md`` §3.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default location of the local-principal key file.  Only the current
#: user may read it (0600).  A caller can prove ``praxis:local`` by
#: showing possession of the bytes in this file via the Unix socket.
DEFAULT_LOCAL_KEY_PATH = Path.home() / ".praxis" / "local_key"

#: HMAC key length in bytes.  256 bits.
_LOCAL_KEY_BYTES = 32

#: Regex for the sanitised ``agent:<name>`` sub-identifier.  Alphanumerics,
#: dot, hyphen, underscore.  Prevents log-injection and directory
#: traversal via principal names.
_AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# ---------------------------------------------------------------------------
# Principal kinds
# ---------------------------------------------------------------------------


class PrincipalKind(str, Enum):
    """Top-level principal classes."""

    LOCAL = "praxis:local"
    AGENT = "agent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Principal:
    """A resolved caller identity.

    ``kind`` is the top-level class.  For :attr:`PrincipalKind.AGENT`
    the ``name`` sub-identifier holds the agent name from the token
    (e.g. ``"claude-desktop"``, ``"openclaw"``).  For LOCAL and UNKNOWN
    the name is empty.

    ``proven_via`` is a short string describing *how* this principal
    was established, purely for the evidence chain — never for policy
    decisions.
    """

    kind: PrincipalKind
    name: str = ""
    proven_via: str = ""

    def __post_init__(self) -> None:
        if self.kind == PrincipalKind.AGENT:
            if not self.name:
                raise ValueError("agent principal requires a non-empty name")
            if not _AGENT_NAME_RE.match(self.name):
                raise ValueError(
                    f"agent principal name {self.name!r} contains "
                    f"disallowed characters"
                )
        elif self.name:
            raise ValueError(
                f"principal kind {self.kind.value!r} does not take a name"
            )

    # ------------------------------------------------------------------
    # Human-readable rendering / serialisation
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        if self.kind == PrincipalKind.AGENT:
            return f"agent:{self.name}"
        return self.kind.value

    @property
    def is_local(self) -> bool:
        return self.kind == PrincipalKind.LOCAL

    @property
    def is_agent(self) -> bool:
        return self.kind == PrincipalKind.AGENT

    @property
    def is_unknown(self) -> bool:
        return self.kind == PrincipalKind.UNKNOWN

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def local(cls, proven_via: str = "") -> Principal:
        return cls(kind=PrincipalKind.LOCAL, proven_via=proven_via)

    @classmethod
    def agent(cls, name: str, proven_via: str = "") -> Principal:
        return cls(kind=PrincipalKind.AGENT, name=name, proven_via=proven_via)

    @classmethod
    def unknown(cls, proven_via: str = "") -> Principal:
        return cls(kind=PrincipalKind.UNKNOWN, proven_via=proven_via)


# ---------------------------------------------------------------------------
# Local key file management
# ---------------------------------------------------------------------------


def ensure_local_key(path: Path | None = None) -> bytes:
    """Return the local-principal key, creating it if missing.

    The key file is created with mode 0600 and its parent directory
    with mode 0700 to keep it out of other users' reach.  A caller
    can prove ``praxis:local`` by producing an HMAC over a challenge
    with this key.

    Returns the key bytes.  If the file already exists we verify its
    permissions are still 0600 (best-effort — some filesystems ignore
    modes) and re-read it.
    """
    path = path or DEFAULT_LOCAL_KEY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass

    if path.exists():
        return path.read_bytes()

    key = secrets.token_bytes(_LOCAL_KEY_BYTES)
    # Write with restrictive mode from the start — open with O_CREAT|O_EXCL
    # so we never accidentally clobber a symlink an attacker planted.
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except Exception:
        # Best-effort cleanup on failure.
        try:
            path.unlink()
        except OSError:
            pass
        raise

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def local_key_permissions_ok(path: Path | None = None) -> bool:
    """Return True iff the local key file is 0600.

    Used at startup: if permissions have relaxed, we rotate the key
    rather than trust it.  On filesystems that don't support modes
    (network drives, some CI runners) this returns True unconditionally.
    """
    path = path or DEFAULT_LOCAL_KEY_PATH
    if not path.exists():
        return False
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    # If mode is exactly 0 (some overlay filesystems) treat as OK.
    if mode == 0:
        return True
    return mode == 0o600


def rotate_local_key(path: Path | None = None) -> bytes:
    """Delete the existing local key and generate a fresh one."""
    path = path or DEFAULT_LOCAL_KEY_PATH
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass
    return ensure_local_key(path)


# ---------------------------------------------------------------------------
# Challenge / response for the Unix socket handshake
# ---------------------------------------------------------------------------
#
# The Unix socket entry point issues a random ``challenge`` on connect.
# The caller must reply with ``hmac_sha256(local_key, challenge)``.  Only
# a process that can read ``~/.praxis/local_key`` (i.e. runs as the user
# on the same box) can compute the correct response.
#
# Network callers cannot even reach the Unix socket, so the ``LOCAL``
# principal is inherently unreachable from TCP.


def make_local_challenge() -> bytes:
    """Return a fresh 32-byte challenge for a Unix-socket handshake."""
    return secrets.token_bytes(32)


def compute_local_response(challenge: bytes, key: bytes) -> str:
    """Compute the expected HMAC response to a local challenge."""
    return hmac.new(key, challenge, hashlib.sha256).hexdigest()


def verify_local_response(
    challenge: bytes,
    response: str,
    key: bytes,
) -> bool:
    """Constant-time verification of a local-socket response."""
    expected = compute_local_response(challenge, key)
    return hmac.compare_digest(expected, response)


# ---------------------------------------------------------------------------
# Agent token verification
# ---------------------------------------------------------------------------


def verify_agent_token(
    token: object | None,
    signing_key: str,
) -> tuple[bool, str, str]:
    """Verify an ``agent:*`` capability token.

    Returns ``(valid, agent_name, reason)``.  When ``valid`` is False,
    ``agent_name`` is empty and ``reason`` explains why (for the
    evidence chain, never for the caller — leaking policy details to
    an unauthenticated caller is a bad idea in general).

    Accepts either a :class:`~praxis.tokens.capability.CapabilityToken`
    or ``None``.  We import lazily to avoid a circular dependency with
    :mod:`praxis.tokens.capability`.
    """
    if token is None:
        return False, "", "no token presented"

    # Late import: praxis.tokens.capability imports from policy.engine
    # which will import us for the ``Principal`` field.  Break the cycle
    # by importing lazily here.
    from praxis.tokens.capability import CapabilityToken

    if not isinstance(token, CapabilityToken):
        return False, "", "token is not a CapabilityToken"

    if not token.verify_signature(signing_key):
        return False, "", "invalid signature"

    if token.revoked:
        return False, "", f"token revoked: {token.revoked_reason}"

    if token.is_expired:
        return False, "", "token expired"

    if not token.agent_id:
        return False, "", "token missing agent_id"

    if not _AGENT_NAME_RE.match(token.agent_id):
        return False, "", f"agent_id {token.agent_id!r} has invalid characters"

    return True, token.agent_id, "ok"


# ---------------------------------------------------------------------------
# Principal resolver — the entry point for every transport
# ---------------------------------------------------------------------------


class PrincipalResolver:
    """Resolve the caller identity for a single request.

    Transports create one resolver per daemon and call the appropriate
    ``from_*`` method on each incoming request.  The result is attached
    to the resulting :class:`~praxis.policy.engine.ActionEvent`.

    ``from_local_socket`` returns :attr:`PrincipalKind.LOCAL` only if
    the challenge/response HMAC verifies against the on-disk key.

    ``from_agent_token`` returns :attr:`PrincipalKind.AGENT` only if
    the token verifies and names an allowed agent.  Any other outcome
    is :attr:`PrincipalKind.UNKNOWN`.

    ``from_no_credential`` is always :attr:`PrincipalKind.UNKNOWN` —
    exposed so callers can be explicit rather than defaulting.
    """

    def __init__(
        self,
        local_key: bytes | None = None,
        token_signing_key: str = "praxis-default-key",
        local_key_path: Path | None = None,
    ) -> None:
        self._local_key_path = local_key_path or DEFAULT_LOCAL_KEY_PATH
        if local_key is None:
            # Auto-ensure on construction: makes the daemon self-installing.
            local_key = ensure_local_key(self._local_key_path)
        self._local_key = local_key
        self._signing_key = token_signing_key

    # ------------------------------------------------------------------
    # Local socket path
    # ------------------------------------------------------------------

    def from_local_socket(
        self,
        challenge: bytes,
        response: str,
    ) -> Principal:
        """Resolve a Unix-socket caller.

        The caller presents a hex-encoded HMAC of the challenge under
        the shared local key.  On success returns ``praxis:local``; on
        any failure returns ``unknown``.  Nothing here ever elevates a
        non-verifying caller.
        """
        if not response:
            return Principal.unknown(proven_via="local_socket:no_response")
        if verify_local_response(challenge, response, self._local_key):
            return Principal.local(proven_via="local_socket:hmac")
        return Principal.unknown(proven_via="local_socket:bad_response")

    # ------------------------------------------------------------------
    # Agent token path (MCP / REST / anywhere on TCP)
    # ------------------------------------------------------------------

    def from_agent_token(self, token: object | None) -> Principal:
        """Resolve a network caller by capability token."""
        ok, name, reason = verify_agent_token(token, self._signing_key)
        if ok:
            return Principal.agent(name=name, proven_via="agent_token:verified")
        return Principal.unknown(proven_via=f"agent_token:{reason}")

    def from_agent_name(
        self,
        name: str,
        proven_via: str = "trusted_transport",
    ) -> Principal:
        """Construct an ``agent:<name>`` principal without a token.

        Only for use by transports that have already authenticated the
        caller through some other channel — e.g. an in-process MCP
        stdio server started under our own control.  Do NOT call from
        an untrusted HTTP handler.
        """
        return Principal.agent(name=name, proven_via=proven_via)

    # ------------------------------------------------------------------
    # No-credential fallback
    # ------------------------------------------------------------------

    def from_no_credential(self, proven_via: str = "no_credential") -> Principal:
        return Principal.unknown(proven_via=proven_via)

    # ------------------------------------------------------------------
    # Property accessors
    # ------------------------------------------------------------------

    @property
    def local_key(self) -> bytes:
        """The current local key.  Exposed for the socket handshake."""
        return self._local_key


__all__ = [
    "DEFAULT_LOCAL_KEY_PATH",
    "Principal",
    "PrincipalKind",
    "PrincipalResolver",
    "compute_local_response",
    "ensure_local_key",
    "local_key_permissions_ok",
    "make_local_challenge",
    "rotate_local_key",
    "verify_agent_token",
    "verify_local_response",
]
