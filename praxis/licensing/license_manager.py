"""
Praxis License Manager — Hardened, tamper-proof trial and license system.

Anti-tamper protections:
    1. CLOCK MANIPULATION  → Monotonic elapsed-time tracking + NTP verification
    2. FILE DELETION       → Redundant breadcrumb in secondary OS-specific location
    3. FILE EDITING        → HMAC integrity seal on every field in license.json
    4. MACHINE TRANSFER    → Hardware fingerprint binding (hostname+CPU+OS+user+disk)
    5. REINSTALL RESET     → Persistent breadcrumb outside install directory
    6. KEY EXTRACTION      → Signing key is derived via PBKDF2, not stored as plaintext

Tiers:
    COMMUNITY   — Free forever, basic features (Lite edition)
    TRIAL       — Full features for 5 days (auto-activated on first use)
    PRO         — Paid, all features, single-org
    ENTERPRISE  — Paid, all features + SLA, SSO, dedicated support
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# License Tiers
# ---------------------------------------------------------------------------

class LicenseTier(str, Enum):
    """Available license tiers."""
    COMMUNITY = "community"
    TRIAL = "trial"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# ---------------------------------------------------------------------------
# Feature Flags per Tier
# ---------------------------------------------------------------------------

TIER_FEATURES: dict[LicenseTier, dict[str, Any]] = {
    LicenseTier.COMMUNITY: {
        "max_policies": 2,
        "max_rules_per_policy": 10,
        "custom_yaml_policies": True,
        "evidence_vault": False,
        "capability_tokens": False,
        "sidecar_api": True,
        "multi_agent": False,
        "dashboard": False,
        "export_evidence": False,
        "webhook_alerts": False,
        "priority_support": False,
        "sso": False,
        "max_evaluations_per_hour": 1000,
        "max_sessions": 10,
        "api_rate_limit_per_min": 60,
        "commercial_use": False,
        "custom_branding": False,
        "audit_log_retention_days": 1,
    },
    LicenseTier.TRIAL: {
        "max_policies": 999,
        "max_rules_per_policy": 999,
        "custom_yaml_policies": True,
        "evidence_vault": True,
        "capability_tokens": True,
        "sidecar_api": True,
        "multi_agent": True,
        "dashboard": True,
        "export_evidence": True,
        "webhook_alerts": True,
        "priority_support": False,
        "sso": False,
        "max_evaluations_per_hour": 10000,
        "max_sessions": 999,
        "api_rate_limit_per_min": 600,
        "commercial_use": False,
        "custom_branding": False,
        "audit_log_retention_days": 1,
    },
    LicenseTier.PRO: {
        "max_policies": 999,
        "max_rules_per_policy": 999,
        "custom_yaml_policies": True,
        "evidence_vault": True,
        "capability_tokens": True,
        "sidecar_api": True,
        "multi_agent": True,
        "dashboard": True,
        "export_evidence": True,
        "webhook_alerts": True,
        "priority_support": True,
        "sso": False,
        "max_evaluations_per_hour": 100000,
        "max_sessions": 999,
        "api_rate_limit_per_min": 6000,
        "commercial_use": True,
        "custom_branding": True,
        "audit_log_retention_days": 30,
    },
    LicenseTier.ENTERPRISE: {
        "max_policies": 999,
        "max_rules_per_policy": 999,
        "custom_yaml_policies": True,
        "evidence_vault": True,
        "capability_tokens": True,
        "sidecar_api": True,
        "multi_agent": True,
        "dashboard": True,
        "export_evidence": True,
        "webhook_alerts": True,
        "priority_support": True,
        "sso": True,
        "max_evaluations_per_hour": 999999,
        "max_sessions": 999,
        "api_rate_limit_per_min": 60000,
        "commercial_use": True,
        "custom_branding": True,
        "audit_log_retention_days": 365,
    },
}


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

PRICING = {
    LicenseTier.COMMUNITY: {"monthly": 0, "annual": 0, "currency": "USD"},
    LicenseTier.TRIAL: {"monthly": 0, "annual": 0, "currency": "USD", "duration_days": 5},
    LicenseTier.PRO: {"monthly": 49, "annual": 468, "currency": "USD"},
    LicenseTier.ENTERPRISE: {"monthly": 199, "annual": 1908, "currency": "USD"},
}


# ═══════════════════════════════════════════════════════════════════════════
# RSA Public Key — used to VERIFY license keys (private key held by admin)
# The private key is NOT shipped in this package. Only the admin keygen tool
# (admin/keygen.py) has access to the private key for signing.
# ═══════════════════════════════════════════════════════════════════════════

from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

_RSA_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtPCjj5r58h5Zw5n1kHQ3
zX2n0bUkxVQKIyMz9Xa1ranOZAiyRmkcqPssIwyyq5Zwv6bRbOj6YZvimIWUswYp
RVIsRFNwCot2WKUbiaofdEQ/nNqd7AR7Ja0cGl+kkPtFkBRDOTyDs4qkJY1/U9X1
47xEE76zp/QnTVQ+W0U0H4qL6ADIjfIQRajkVAkChX3wBAgIL4DMZXrTrWNDK2R4
t+BbwF8UWuOsTyjvJf0v//Pi/Sc+IINFYfA7mvXSttqMstbA/uriG1aIDRiISyYZ
w2j3PUjXabNA13nJ7AbZ89/aAGhEcBNLoVjvejMHf0+t3nrYOyHi7Sca6A3aoxiD
gwIDAQAB
-----END PUBLIC KEY-----"""

_RSA_PUBLIC_KEY = load_pem_public_key(_RSA_PUBLIC_KEY_PEM)


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-TAMPER: Derived key for local file integrity seals only
# (This protects license.json from manual edits — NOT used for license keys)
# ═══════════════════════════════════════════════════════════════════════════

def _derive_seal_key(purpose: str) -> bytes:
    """Derive a signing key for local file integrity seals via PBKDF2."""
    _p1 = b"praxis"
    _p2 = b"\x2d\x73\x69\x67\x6e"        # -sign
    _p3 = b"\x2d\x76\x31\x2d"            # -v1-
    _p4 = hashlib.sha256(b"praxis-security").digest()[:8]
    base = _p1 + _p2 + _p3 + _p4
    return hashlib.pbkdf2_hmac("sha256", base, purpose.encode(), 100_000)


_SEAL_KEY_MATERIAL = _derive_seal_key("file-integrity-seal")


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-TAMPER: Hardware fingerprint (machine-bound)
# ═══════════════════════════════════════════════════════════════════════════

def _get_machine_fingerprint() -> str:
    """
    Generate a stable hardware fingerprint for this machine.
    Binds the license / trial to THIS device.
    """
    parts = [
        platform.node(),
        platform.machine(),
        platform.system(),
        platform.processor()[:32] if platform.processor() else "",
        os.getenv("USERNAME", os.getenv("USER", "unknown")),
    ]
    # Extra binding on Windows
    if platform.system() == "Windows":
        try:
            import subprocess
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "serialnumber"],
                capture_output=True, text=True, timeout=3,
            )
            serial = result.stdout.strip().split("\n")[-1].strip()
            if serial and serial != "SerialNumber":
                parts.append(serial)
        except Exception:
            pass

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-TAMPER: NTP time verification (defeats clock rollback)
# ═══════════════════════════════════════════════════════════════════════════

def _get_network_time() -> float | None:
    """
    Get current time from an external HTTP server to detect clock tampering.
    Returns Unix timestamp or None if network is unavailable.
    """
    import urllib.request
    from email.utils import parsedate_to_datetime

    endpoints = [
        "https://worldtimeapi.org/api/timezone/Etc/UTC",
        "https://www.google.com",
        "https://www.cloudflare.com",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=3) as resp:
                date_header = resp.headers.get("Date", "")
                if date_header:
                    dt = parsedate_to_datetime(date_header)
                    return dt.timestamp()
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Online License Validation (Cloudflare Worker)
# ═══════════════════════════════════════════════════════════════════════════

_LICENSE_SERVER_URL = "https://praxis-license-server.praxis-api.workers.dev"

# Interval between online re-validation checks (seconds)
_ONLINE_REVALIDATE_INTERVAL = 6 * 3600  # Every 6 hours


def _online_validate(
    license_id: str,
    machine_fingerprint: str,
    activate: bool = False,
) -> dict | None:
    """
    Validate or activate a license against the online server.

    Returns the server response dict, or None if the server is unreachable
    (fail-open for offline use — the local RSA check is still required).
    """
    import urllib.request

    endpoint = "/activate" if activate else "/validate"
    url = _LICENSE_SERVER_URL + endpoint
    payload = json.dumps({
        "license_id": license_id,
        "machine_fingerprint": machine_fingerprint,
        "hostname": platform.node(),
    }).encode()

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        # Server unreachable — fail-open (local RSA validation still protects)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-TAMPER: File integrity seal (detects manual edits)
# ═══════════════════════════════════════════════════════════════════════════

def _compute_seal(data: dict) -> str:
    """Compute HMAC seal over all license fields except the seal itself."""
    canonical = json.dumps(
        {k: v for k, v in sorted(data.items()) if k != "_seal"},
        sort_keys=True, separators=(",", ":"),
    )
    return hmac.new(
        _SEAL_KEY_MATERIAL, canonical.encode(), hashlib.sha256
    ).hexdigest()


def _verify_seal(data: dict) -> bool:
    """Verify that the license file has not been manually edited."""
    stored_seal = data.get("_seal", "")
    if not stored_seal:
        return False
    expected = _compute_seal(data)
    return hmac.compare_digest(expected, stored_seal)


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-TAMPER: Redundant breadcrumb (survives file deletion)
# ═══════════════════════════════════════════════════════════════════════════

def _get_backup_path() -> Path:
    """Secondary storage location — different from ~/.praxis/."""
    system = platform.system()
    if system == "Windows":
        base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / ".praxis_license_seal"
    elif system == "Darwin":
        return Path.home() / "Library" / "Application Support" / ".praxis_seal"
    else:
        base = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        return base / ".praxis_seal"


def _write_breadcrumb(fingerprint: str, trial_started_at: float) -> None:
    """Write a tamper-proof breadcrumb to the backup location."""
    data = {"fp": fingerprint, "ts": trial_started_at}
    raw = json.dumps(data, sort_keys=True)
    seal = hmac.new(_SEAL_KEY_MATERIAL, raw.encode(), hashlib.sha256).hexdigest()
    payload = {"data": data, "seal": seal}
    try:
        path = _get_backup_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))
    except Exception:
        pass


def _read_breadcrumb() -> float | None:
    """
    Read the trial start time from the backup breadcrumb.
    Returns original trial_started_at, or None if not found / invalid.
    """
    try:
        path = _get_backup_path()
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        data = payload["data"]
        seal = payload["seal"]
        raw = json.dumps(data, sort_keys=True)
        expected = hmac.new(_SEAL_KEY_MATERIAL, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, seal):
            return None
        if data["fp"] != _get_machine_fingerprint():
            return None
        return data["ts"]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class LicenseInfo(BaseModel):
    """Represents a validated license."""
    license_id: str = ""
    tier: LicenseTier = LicenseTier.COMMUNITY
    owner_email: str = ""
    organization: str = ""
    machine_fingerprint: str = ""
    activated_at: float = 0.0
    expires_at: float = 0.0
    trial_started_at: float = 0.0
    license_key: str = ""
    features: dict[str, Any] = Field(default_factory=dict)
    is_valid: bool = True
    validation_message: str = ""
    # Anti-tamper fields
    elapsed_used: float = 0.0        # Total seconds the trial has been running
    last_check_wall: float = 0.0     # Last wall-clock seen (detect rollback)
    eval_counter: int = 0            # Total evaluations ever (monotonic)

    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at

    @property
    def remaining_seconds(self) -> float:
        if self.expires_at == 0:
            return float("inf")
        return max(0, self.expires_at - time.time())

    @property
    def remaining_human(self) -> str:
        secs = self.remaining_seconds
        if secs == float("inf"):
            return "unlimited"
        if secs <= 0:
            return "expired"
        hours = int(secs // 3600)
        mins = int((secs % 3600) // 60)
        if hours > 24:
            days = hours // 24
            return f"{days}d {hours % 24}h"
        return f"{hours}h {mins}m"

    def has_feature(self, feature: str) -> bool:
        return self.features.get(feature, False)

    def get_limit(self, feature: str) -> int | float:
        return self.features.get(feature, 0)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TrialExpiredError(Exception):
    """Raised when the 5-day trial has expired."""
    def __init__(self):
        super().__init__(
            "Your 5-day Praxis trial has expired. "
            "Upgrade to Pro ($49/mo) — contact hello@praxis.app "
            "or continue with the free Community tier."
        )


class LicenseRequiredError(Exception):
    """Raised when a paid feature is used without a valid license."""
    def __init__(self, feature: str, required_tier: str = "Pro"):
        super().__init__(
            f"Feature '{feature}' requires Praxis {required_tier}. "
            f"Contact hello@praxis.app to upgrade"
        )


class LicenseLimitError(Exception):
    """Raised when a usage limit is exceeded."""
    def __init__(self, limit_name: str, current: int, maximum: int):
        super().__init__(
            f"Limit exceeded: {limit_name} ({current}/{maximum}). "
            f"Contact hello@praxis.app to upgrade"
        )


class LicenseTamperError(Exception):
    """Raised when license tampering is detected."""
    def __init__(self, reason: str):
        super().__init__(
            f"License tamper detected: {reason}. "
            f"Trial revoked. Contact hello@praxis.app for a license key"
        )


# ---------------------------------------------------------------------------
# License Key Verification (RSA-SHA256 — asymmetric)
#
# License keys are signed with a PRIVATE key held by admin (admin/keygen.py).
# This package only has the PUBLIC key for verification — nobody can forge keys
# by reading the source code.
# ---------------------------------------------------------------------------

def _verify_license_signature(data: dict, signature_b64: str) -> bool:
    """Verify an RSA-SHA256 signature on license data using the embedded public key."""
    try:
        payload = json.dumps(data, sort_keys=True).encode()
        sig_bytes = base64.urlsafe_b64decode(signature_b64.encode())
        _RSA_PUBLIC_KEY.verify(
            sig_bytes,
            payload,
            rsa_padding.PKCS1v15(),
            crypto_hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def generate_license_key(
    tier: LicenseTier,
    owner_email: str,
    organization: str = "",
    duration_days: int = 365,
    _private_key=None,
) -> str:
    """
    Generate an RSA-signed license key.

    IMPORTANT: This requires the private key. In production, use admin/keygen.py
    which loads the private key from a secure location. This function is here
    for the admin tool to call — it cannot work without a private key.

    For testing, pass _private_key explicitly.
    """
    if _private_key is None:
        raise RuntimeError(
            "Cannot generate license keys without the private key. "
            "Use admin/keygen.py to generate keys."
        )

    license_id = f"lic_{uuid.uuid4().hex[:16]}"
    now = time.time()
    data = {
        "license_id": license_id,
        "tier": tier.value,
        "owner_email": owner_email,
        "organization": organization,
        "issued_at": now,
        "expires_at": now + (duration_days * 86400),
        "version": "1",
    }
    # Sign with RSA private key
    payload = json.dumps(data, sort_keys=True).encode()
    sig_bytes = _private_key.sign(
        payload,
        rsa_padding.PKCS1v15(),
        crypto_hashes.SHA256(),
    )
    data["signature"] = base64.urlsafe_b64encode(sig_bytes).decode()
    raw = json.dumps(data, sort_keys=True)
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_license_key(key: str) -> dict | None:
    """Decode and verify an RSA-signed license key. Returns None if invalid."""
    try:
        raw = base64.urlsafe_b64decode(key.encode()).decode()
        data = json.loads(raw)
        sig_b64 = data.pop("signature", "")
        if not sig_b64:
            return None
        if _verify_license_signature(data, sig_b64):
            return data
        return None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# License Manager (Singleton) — Hardened
# ═══════════════════════════════════════════════════════════════════════════

class LicenseManager:
    """
    Central license manager with hardened anti-tamper protection.

    Protections:
        - Clock rollback detection (monotonic time + last_check_wall + NTP)
        - File integrity seal (HMAC on all license.json fields)
        - Redundant breadcrumb (survives ~/.praxis/ deletion)
        - Machine fingerprint binding (can't copy license between PCs)
        - Elapsed-time tracking (defeats clock-freeze attacks)

    Usage:
        lm = LicenseManager()
        lm.check_feature("evidence_vault")       # Raises if not allowed
        lm.get_limit("max_policies")              # Returns the limit
        lm.activate_license("your-license-key")   # Unlock PRO/ENTERPRISE
    """

    _instance: LicenseManager | None = None
    _CONFIG_DIR = Path.home() / ".praxis"
    _LICENSE_FILE = _CONFIG_DIR / "license.json"

    def __new__(cls) -> LicenseManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._license: LicenseInfo | None = None
        self._eval_count: int = 0
        self._eval_window_start: float = time.time()
        self._session_count: int = 0
        self._mono_start: float = time.monotonic()
        self._tamper_detected: bool = False
        self._last_online_check: float = 0.0  # Last time we validated online
        self._load_or_activate()

    # ── Loading & Activation (with anti-tamper) ─────────────────────────

    def _load_or_activate(self) -> None:
        """Load existing license or auto-activate trial, with full tamper checks."""

        if self._LICENSE_FILE.exists():
            try:
                data = json.loads(self._LICENSE_FILE.read_text(encoding="utf-8"))

                # ── TAMPER CHECK 1: Integrity seal ──
                if not _verify_seal(data):
                    self._handle_tamper("License file integrity check failed")
                    return

                self._license = LicenseInfo(**{
                    k: v for k, v in data.items() if k != "_seal"
                })

                # ── TAMPER CHECK 2: Machine fingerprint ──
                if (self._license.machine_fingerprint
                        and self._license.machine_fingerprint != _get_machine_fingerprint()):
                    self._handle_tamper("Machine fingerprint mismatch")
                    return

                # ── TAMPER CHECK 3: Clock rollback ──
                if self._license.last_check_wall > 0:
                    now = time.time()
                    if now < self._license.last_check_wall - 120:
                        # Clock went backwards by >2 min — verify with NTP
                        net_time = _get_network_time()
                        if net_time is None or net_time >= self._license.last_check_wall - 120:
                            # Either no network (assume tamper) or NTP confirms current time is fine
                            # If NTP also shows past → might be legit NTP correction
                            if net_time is None:
                                self._handle_tamper("System clock rolled back (offline)")
                                return
                            if net_time < self._license.last_check_wall - 120:
                                pass  # Legit NTP correction, allow
                            # else NTP says current — clock was rolled back
                            else:
                                self._handle_tamper("System clock rolled back")
                                return

                # Update last-seen wall time
                self._license.last_check_wall = time.time()
                self._save_license()

                # Normal expiry check
                if self._license.tier == LicenseTier.TRIAL:
                    if self._is_trial_expired():
                        self._expire_trial()
                elif self._license.tier in (LicenseTier.PRO, LicenseTier.ENTERPRISE):
                    if self._license.is_expired:
                        self._license.tier = LicenseTier.COMMUNITY
                        self._license.features = TIER_FEATURES[LicenseTier.COMMUNITY]
                        self._license.validation_message = "License expired — using Community tier"
                        self._save_license()
                return

            except (json.JSONDecodeError, Exception):
                pass  # Corrupt file — check breadcrumb

        # ── No license file — check for breadcrumb (anti-deletion) ──
        breadcrumb_ts = _read_breadcrumb()
        if breadcrumb_ts is not None:
            elapsed_since_trial = time.time() - breadcrumb_ts
            if elapsed_since_trial > self._TRIAL_DURATION_SECONDS:
                # Trial already expired — community only, no new trial
                self._set_community("Previous trial expired — using Community tier")
                return
            elif elapsed_since_trial >= 0:
                # Trial still active — restore it
                self._license = LicenseInfo(
                    license_id=f"trial_{uuid.uuid4().hex[:16]}",
                    tier=LicenseTier.TRIAL,
                    machine_fingerprint=_get_machine_fingerprint(),
                    activated_at=breadcrumb_ts,
                    trial_started_at=breadcrumb_ts,
                    expires_at=breadcrumb_ts + self._TRIAL_DURATION_SECONDS,
                    features=TIER_FEATURES[LicenseTier.TRIAL],
                    is_valid=True,
                    last_check_wall=time.time(),
                    elapsed_used=elapsed_since_trial,
                    validation_message="Trial restored (license file was deleted)",
                )
                self._save_license()
                return
            else:
                # Negative elapsed = clock was set to before breadcrumb time
                self._set_community("Clock anomaly detected — trial revoked")
                _write_breadcrumb(_get_machine_fingerprint(), time.time() - (self._TRIAL_DURATION_SECONDS + 1))
                return

        # Truly first time — activate trial
        self._activate_trial()

    _TRIAL_DURATION_SECONDS = 5 * 24 * 3600  # 5 days

    def _is_trial_expired(self) -> bool:
        """
        Multi-layered trial expiry check:
        1. Wall clock past expires_at?
        2. NTP time past expires_at? (best-effort)
        3. Monotonic elapsed-time counter exceeded 5 days?
        """
        if not self._license or self._license.tier != LicenseTier.TRIAL:
            return False

        # Check 1: Wall clock
        if time.time() > self._license.expires_at:
            return True

        # Check 2: NTP (best-effort, non-blocking)
        try:
            net_time = _get_network_time()
            if net_time is not None and net_time > self._license.expires_at:
                return True
        except Exception:
            pass

        # Check 3: Cumulative elapsed time
        mono_elapsed = time.monotonic() - self._mono_start
        total_elapsed = self._license.elapsed_used + mono_elapsed
        if total_elapsed > self._TRIAL_DURATION_SECONDS:
            return True

        return False

    def _activate_trial(self) -> None:
        """Activate a 5-day free trial with anti-tamper protections."""
        now = time.time()
        fingerprint = _get_machine_fingerprint()
        self._license = LicenseInfo(
            license_id=f"trial_{uuid.uuid4().hex[:16]}",
            tier=LicenseTier.TRIAL,
            machine_fingerprint=fingerprint,
            activated_at=now,
            trial_started_at=now,
            expires_at=now + self._TRIAL_DURATION_SECONDS,
            features=TIER_FEATURES[LicenseTier.TRIAL],
            is_valid=True,
            last_check_wall=now,
            elapsed_used=0.0,
            eval_counter=0,
            validation_message="5-day trial activated — all features unlocked!",
        )
        self._save_license()
        # Write breadcrumb to secondary location
        _write_breadcrumb(fingerprint, now)
        self._mono_start = time.monotonic()

    def _expire_trial(self) -> None:
        """Expire the trial → fall back to community."""
        self._license.tier = LicenseTier.COMMUNITY
        self._license.features = TIER_FEATURES[LicenseTier.COMMUNITY]
        self._license.is_valid = True
        self._license.validation_message = "Trial expired — using Community tier"
        self._save_license()

    def _set_community(self, message: str) -> None:
        """Set license to community tier."""
        self._license = LicenseInfo(
            tier=LicenseTier.COMMUNITY,
            machine_fingerprint=_get_machine_fingerprint(),
            activated_at=time.time(),
            features=TIER_FEATURES[LicenseTier.COMMUNITY],
            is_valid=True,
            last_check_wall=time.time(),
            validation_message=message,
        )
        self._save_license()

    def _handle_tamper(self, reason: str) -> None:
        """Handle detected tampering — revoke to community, burn breadcrumb."""
        self._tamper_detected = True
        self._set_community(f"Tamper detected: {reason}")
        # Write an already-expired breadcrumb so trial can never be re-activated
        _write_breadcrumb(_get_machine_fingerprint(), time.time() - (self._TRIAL_DURATION_SECONDS + 1))

    # ── Persistence with integrity seal ─────────────────────────────────

    def _save_license(self) -> None:
        """Persist license to disk with HMAC integrity seal."""
        try:
            self._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            # Update elapsed tracking for trials
            if self._license and self._license.tier == LicenseTier.TRIAL:
                mono_now = time.monotonic()
                self._license.elapsed_used += mono_now - self._mono_start
                self._mono_start = mono_now
                self._license.last_check_wall = time.time()

            data = json.loads(self._license.model_dump_json())
            data["_seal"] = _compute_seal(data)
            self._LICENSE_FILE.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    # ── Public API ──────────────────────────────────────────────────────

    @property
    def license(self) -> LicenseInfo:
        return self._license

    @property
    def tier(self) -> LicenseTier:
        return self._license.tier

    @property
    def is_trial(self) -> bool:
        return self._license.tier == LicenseTier.TRIAL

    @property
    def is_trial_expired(self) -> bool:
        return self._license.tier == LicenseTier.TRIAL and self._is_trial_expired()

    @property
    def is_paid(self) -> bool:
        return self._license.tier in (LicenseTier.PRO, LicenseTier.ENTERPRISE)

    @property
    def is_community(self) -> bool:
        return self._license.tier == LicenseTier.COMMUNITY

    def remaining_trial_time(self) -> str:
        return self._license.remaining_human

    def check_feature(self, feature: str) -> bool:
        """Check if a feature is available. Raises LicenseRequiredError if not."""
        # Refresh expiry
        if self._license.tier == LicenseTier.TRIAL and self._is_trial_expired():
            self._expire_trial()

        # Periodic online revalidation for paid tiers
        if self._license.tier in (LicenseTier.PRO, LicenseTier.ENTERPRISE):
            self._periodic_online_check()

        features = TIER_FEATURES.get(self._license.tier, TIER_FEATURES[LicenseTier.COMMUNITY])
        allowed = features.get(feature, False)
        if not allowed:
            min_tier = "Pro"
            for t in [LicenseTier.PRO, LicenseTier.ENTERPRISE]:
                if TIER_FEATURES[t].get(feature, False):
                    min_tier = t.value.title()
                    break
            raise LicenseRequiredError(feature, min_tier)
        return True

    def get_limit(self, limit_name: str) -> int | float:
        features = TIER_FEATURES.get(self._license.tier, TIER_FEATURES[LicenseTier.COMMUNITY])
        return features.get(limit_name, 0)

    def check_eval_rate(self) -> bool:
        now = time.time()
        if now - self._eval_window_start > 3600:
            self._eval_count = 0
            self._eval_window_start = now
        self._eval_count += 1
        limit = int(self.get_limit("max_evaluations_per_hour"))
        if self._eval_count > limit:
            raise LicenseLimitError("evaluations_per_hour", self._eval_count, limit)
        return True

    def check_policy_count(self, count: int) -> bool:
        limit = int(self.get_limit("max_policies"))
        if count >= limit:
            raise LicenseLimitError("max_policies", count, limit)
        return True

    def check_session_count(self) -> bool:
        limit = int(self.get_limit("max_sessions"))
        self._session_count += 1
        if self._session_count > limit:
            raise LicenseLimitError("max_sessions", self._session_count, limit)
        return True

    def activate_license(self, key: str) -> LicenseInfo:
        """Activate a PRO or ENTERPRISE license key (with online validation)."""
        data = decode_license_key(key)
        if data is None:
            raise ValueError(
                "Invalid license key. Please check your key and try again. "
                "Contact hello@praxis.app for a valid key"
            )

        license_id = data["license_id"]
        tier = LicenseTier(data["tier"])
        fingerprint = _get_machine_fingerprint()

        # ── Online activation check ──
        server_result = _online_validate(license_id, fingerprint, activate=True)
        if server_result is not None:
            if not server_result.get("valid", False) and not server_result.get("activated", False):
                reason = server_result.get("reason", "validation_failed")
                raise ValueError(
                    f"License activation failed: {reason}. "
                    f"Contact support at hello@praxis.app"
                )

        self._license = LicenseInfo(
            license_id=license_id,
            tier=tier,
            owner_email=data.get("owner_email", ""),
            organization=data.get("organization", ""),
            machine_fingerprint=fingerprint,
            activated_at=time.time(),
            expires_at=data.get("expires_at", 0),
            license_key=key,
            features=TIER_FEATURES[tier],
            is_valid=True,
            last_check_wall=time.time(),
            validation_message=f"{tier.value.title()} license activated!",
        )
        self._save_license()
        return self._license

    def deactivate(self) -> None:
        """Deactivate the current license (revert to community)."""
        self._set_community("License deactivated — using Community tier")

    def _periodic_online_check(self) -> None:
        """
        Re-validate paid license against the online server every 6 hours.
        If the server says revoked/expired → downgrade to community.
        If the server is unreachable → allow (fail-open, local RSA still valid).
        """
        now = time.time()
        if now - self._last_online_check < _ONLINE_REVALIDATE_INTERVAL:
            return  # Not time yet

        self._last_online_check = now

        if not self._license or not self._license.license_id:
            return

        result = _online_validate(
            self._license.license_id,
            self._license.machine_fingerprint or _get_machine_fingerprint(),
        )

        if result is None:
            # Server unreachable — fail-open
            return

        if not result.get("valid", False):
            reason = result.get("reason", "validation_failed")
            self._set_community(f"License revoked by server: {reason}")

    def reset_for_testing(self) -> None:
        """Reset the singleton (for tests only)."""
        LicenseManager._instance = None
        self._initialized = False
        if self._LICENSE_FILE.exists():
            self._LICENSE_FILE.unlink()

    def status_dict(self) -> dict:
        return {
            "tier": self._license.tier.value,
            "is_valid": self._license.is_valid,
            "is_expired": self._license.is_expired,
            "remaining": self._license.remaining_human,
            "owner": self._license.owner_email or "(not set)",
            "organization": self._license.organization or "(not set)",
            "license_id": self._license.license_id,
            "message": self._license.validation_message,
            "features": TIER_FEATURES.get(self._license.tier, {}),
        }

    def banner(self) -> str:
        t = self._license.tier.value.upper()
        remaining = self._license.remaining_human
        if self._license.tier == LicenseTier.TRIAL:
            return (
                f"🛡️  Praxis [TRIAL] — {remaining} remaining (5-day trial) | "
                f"Upgrade: hello@praxis.app"
            )
        elif self._license.tier == LicenseTier.COMMUNITY:
            return (
                f"🛡️  Praxis [FREE] — Community tier | "
                f"Upgrade for full features: hello@praxis.app"
            )
        elif self._license.tier == LicenseTier.PRO:
            return f"🛡️  Praxis [PRO] — Licensed to {self._license.owner_email or self._license.organization}"
        else:
            return f"🛡️  Praxis [ENTERPRISE] — {self._license.organization}"
