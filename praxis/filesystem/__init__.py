"""Praxis filesystem tools — v1 surface."""

from praxis.filesystem.executor import DEFAULT_READ_CAP_BYTES, FSExecutor
from praxis.filesystem.paths import (
    PathClass,
    PathVerdict,
    classify_path,
    refuses_delete,
    refuses_read,
    refuses_write,
)
from praxis.filesystem.policy import FSPolicyEngine
from praxis.filesystem.search import SearchHit, search_filenames
from praxis.filesystem.search_backends import (
    PlocateBackend,
    SearchBackend,
    SearchCandidate,
    SpotlightBackend,
    WalkerBackend,
    WindowsSearchBackend,
    pick_default_backend,
)
from praxis.filesystem.trash import (
    DEFAULT_TRASH_DIR,
    DEFAULT_TTL_SECONDS,
    StagedTrash,
    TrashEntry,
)
from praxis.filesystem.types import (
    FS_TIER,
    FSAction,
    FSActionEvent,
    FSResult,
    FSResultStatus,
    normalise_path,
    tier_for,
)

__all__ = [
    "DEFAULT_READ_CAP_BYTES",
    "DEFAULT_TRASH_DIR",
    "DEFAULT_TTL_SECONDS",
    "FS_TIER",
    "FSAction",
    "FSActionEvent",
    "FSExecutor",
    "FSPolicyEngine",
    "FSResult",
    "FSResultStatus",
    "PathClass",
    "PathVerdict",
    "PlocateBackend",
    "SearchBackend",
    "SearchCandidate",
    "SearchHit",
    "SpotlightBackend",
    "StagedTrash",
    "TrashEntry",
    "WalkerBackend",
    "WindowsSearchBackend",
    "classify_path",
    "normalise_path",
    "pick_default_backend",
    "refuses_delete",
    "refuses_read",
    "refuses_write",
    "search_filenames",
    "tier_for",
]
