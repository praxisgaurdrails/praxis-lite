"""
Path safety for the Praxis filesystem tools.

Every path an executor is about to touch runs through
:func:`classify_path` first.  The classifier decides whether the path
is safe (T0-T2 permitted) or falls into the T3 permanently-refused
denylist (things like ``~/Library/Keychains``, ``/System``, ``/etc``,
``rm -rf ~`` territory).

The denylist is intentionally conservative — false positives are
harmless (the user is told to edit the config file), false negatives
could brick a machine.

See ``docs/DESIGN.md`` §6 ("T3 — Refused").
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from praxis.filesystem.types import normalise_path


class PathClass(str, Enum):
    """Classification of a filesystem path."""

    SAFE = "safe"
    """Normal user path — subject to policy engine + tier gate."""

    SYSTEM = "system"
    """OS-owned directory — T3-refused for writes; reads are allowed."""

    SECRETS = "secrets"
    """Credentials store (keychain, ssh keys, aws creds).  T3-refused
    for reads AND writes."""

    HOME_ROOT = "home_root"
    """The user's home directory itself — refuses recursive delete."""

    PSEUDO = "pseudo"
    """/proc, /sys, /dev — T3-refused for writes."""


@dataclass(frozen=True)
class PathVerdict:
    """Result of :func:`classify_path`."""

    path_class: PathClass
    reason: str
    """Human-readable justification for the classification."""

    @property
    def is_safe(self) -> bool:
        return self.path_class == PathClass.SAFE


# ---------------------------------------------------------------------------
# Denylists
# ---------------------------------------------------------------------------

# System directories — read allowed, write refused.  Kept short and
# generic so we don't accidentally block legitimate tool installs.
_SYSTEM_PREFIXES: tuple[str, ...] = (
    "/System",
    "/Library/Extensions",
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/etc",
    "/boot",
    "/private/etc",
    "/private/var/db",
    # Windows equivalents (case-insensitive matched below)
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData\\Microsoft",
)

# Secret stores — read AND write refused.  These are the ones a
# compromised model would target first.
_SECRETS_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)/Library/Keychains(/|$)"),
    re.compile(r"(?i)/\.ssh(/|$)"),
    re.compile(r"(?i)/\.aws(/|$)"),
    re.compile(r"(?i)/\.gnupg(/|$)"),
    re.compile(r"(?i)/\.password-store(/|$)"),
    re.compile(r"(?i)\\AppData\\Local\\Microsoft\\Vault(/|\\|$)"),
    re.compile(r"(?i)\\AppData\\Roaming\\Microsoft\\Credentials(/|\\|$)"),
    re.compile(r"(?i)/\.docker/config\.json$"),
    re.compile(r"(?i)/\.netrc$"),
    re.compile(r"(?i)/\.pypirc$"),
    re.compile(r"(?i)/\.env(\..*)?$"),
)

# Pseudo-filesystems — write refused always.
_PSEUDO_PREFIXES: tuple[str, ...] = (
    "/proc",
    "/sys",
    "/dev",
)


def _is_home_root(p: Path) -> bool:
    """Return True iff ``p`` is literally the user's home dir."""
    try:
        return p == Path.home().resolve()
    except OSError:
        return False


def _matches_prefix(p_str: str, prefixes: tuple[str, ...]) -> bool:
    """Case-insensitive prefix match against a tuple of forbidden roots."""
    lower = p_str.lower()
    for prefix in prefixes:
        px = prefix.lower()
        if lower == px or lower.startswith(px + os.sep) or lower.startswith(px + "/") or lower.startswith(px + "\\"):
            return True
    return False


def classify_path(path: str | Path) -> PathVerdict:
    """Return the safety classification for a path.

    ``path`` may or may not exist.  We normalise it to an absolute path
    first — this defeats ``..`` traversals ("~/Documents/../../etc/passwd"
    resolves to ``/etc/passwd`` and is caught by the system prefix
    check).
    """
    p = normalise_path(path)
    p_str = str(p)

    if _is_home_root(p):
        return PathVerdict(
            path_class=PathClass.HOME_ROOT,
            reason="path is the user's home directory itself",
        )

    for pat in _SECRETS_MARKERS:
        if pat.search(p_str):
            return PathVerdict(
                path_class=PathClass.SECRETS,
                reason=f"path is in a credential store ({pat.pattern})",
            )

    if _matches_prefix(p_str, _SYSTEM_PREFIXES):
        return PathVerdict(
            path_class=PathClass.SYSTEM,
            reason="path is under an OS-owned system directory",
        )

    if _matches_prefix(p_str, _PSEUDO_PREFIXES):
        return PathVerdict(
            path_class=PathClass.PSEUDO,
            reason="path is under a pseudo-filesystem",
        )

    return PathVerdict(
        path_class=PathClass.SAFE,
        reason="normal user path",
    )


# ---------------------------------------------------------------------------
# Op-specific safety
# ---------------------------------------------------------------------------


def refuses_write(verdict: PathVerdict) -> bool:
    """True iff writing to this path must be refused outright (T3)."""
    return verdict.path_class in (
        PathClass.SYSTEM,
        PathClass.SECRETS,
        PathClass.PSEUDO,
    )


def refuses_read(verdict: PathVerdict) -> bool:
    """True iff reading this path must be refused outright (T3).

    Only the SECRETS class refuses reads — you can legitimately read
    ``/etc/hosts`` or ``/System`` files.  Credentials are the only
    thing we won't hand back to any principal ever.
    """
    return verdict.path_class == PathClass.SECRETS


def refuses_delete(verdict: PathVerdict) -> bool:
    """True iff deleting/moving this path must be refused (T3).

    Adds ``HOME_ROOT`` on top of :func:`refuses_write` — you can
    delete individual files inside ``~`` but never ``~`` itself.
    """
    return refuses_write(verdict) or verdict.path_class == PathClass.HOME_ROOT


__all__ = [
    "PathClass",
    "PathVerdict",
    "classify_path",
    "refuses_delete",
    "refuses_read",
    "refuses_write",
]
