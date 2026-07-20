"""
Praxis Feature Gate — Decorators and middleware for enforcing license tiers.

Usage in code:
    from praxis.licensing.feature_gate import require_feature, require_tier

    @require_feature("evidence_vault")
    async def start_session(...):
        ...

    @require_tier(LicenseTier.PRO)
    def export_report(...):
        ...

Usage in sidecar:
    The LicenseMiddleware auto-injects into FastAPI and checks rate limits,
    feature access, and trial expiry on every request.
"""

from __future__ import annotations

import functools
import time
from typing import Any, Callable

from praxis.licensing.license_manager import (
    LicenseManager,
    LicenseTier,
    LicenseRequiredError,
    LicenseLimitError,
    TIER_FEATURES,
)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_feature(feature: str):
    """Decorator: raises LicenseRequiredError if feature is not available."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            lm = LicenseManager()
            lm.check_feature(feature)
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            lm = LicenseManager()
            lm.check_feature(feature)
            return await func(*args, **kwargs)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper
    return decorator


def require_tier(min_tier: LicenseTier):
    """Decorator: ensures the current tier is at least min_tier."""
    tier_order = [LicenseTier.COMMUNITY, LicenseTier.TRIAL, LicenseTier.PRO, LicenseTier.ENTERPRISE]

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            lm = LicenseManager()
            current_idx = tier_order.index(lm.tier)
            required_idx = tier_order.index(min_tier)
            if current_idx < required_idx:
                raise LicenseRequiredError(func.__name__, min_tier.value.title())
            return func(*args, **kwargs)
        return wrapper
    return decorator


def check_rate_limit():
    """Call this before every evaluation to enforce rate limits."""
    lm = LicenseManager()
    lm.check_eval_rate()


# ---------------------------------------------------------------------------
# FastAPI Middleware for Sidecar
# ---------------------------------------------------------------------------

def create_license_middleware():
    """
    Creates FastAPI middleware that:
    1. Checks trial expiry
    2. Enforces per-evaluation rate limits (/api/v1/evaluate)
    3. Enforces per-minute API rate limits (all endpoints)
    4. Adds license info to response headers
    5. Blocks gated endpoints for COMMUNITY tier
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    # Endpoints that require specific features — matched by prefix
    GATED_ENDPOINTS: list[tuple[str, str, str]] = [
        # (path_prefix, http_method_or_any, required_feature)
        ("/api/v1/tokens", "ANY", "capability_tokens"),
        ("/api/v1/sessions", "POST", "evidence_vault"),      # Creating sessions
        ("/api/v1/sessions/", "ANY", "evidence_vault"),       # Session detail/records/verify/end
    ]

    # Endpoints exempt from ALL checks (rate limits, feature gates)
    EXEMPT_ENDPOINTS = {
        "/api/v1/health",
        "/api/v1/license/status",
        "/api/v1/license/activate",
    }

    class LicenseMiddleware(BaseHTTPMiddleware):
        def __init__(self, app):
            super().__init__(app)
            self._api_call_timestamps: list[float] = []

        async def dispatch(self, request: Request, call_next):
            lm = LicenseManager()
            path = request.url.path
            method = request.method.upper()

            # Always allow health and license endpoints
            if path in EXEMPT_ENDPOINTS:
                response = await call_next(request)
                response.headers["X-Praxis-Tier"] = lm.tier.value
                return response

            # ── CHECK 1: Trial expiry → downgrade to Community ──
            if lm.is_trial and lm.is_trial_expired:
                lm._expire_trial()

            # ── CHECK 2: Feature gating for specific endpoints ──
            for endpoint_prefix, gate_method, feature in GATED_ENDPOINTS:
                if path.startswith(endpoint_prefix):
                    if gate_method == "ANY" or method == gate_method:
                        features = TIER_FEATURES.get(lm.tier, TIER_FEATURES[LicenseTier.COMMUNITY])
                        if not features.get(feature, False):
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": "feature_not_available",
                                    "message": (
                                        f"Feature '{feature}' is not available on the "
                                        f"{lm.tier.value.title()} tier. "
                                        f"Upgrade to Pro for full access."
                                    ),
                                    "current_tier": lm.tier.value,
                                    "required_tier": "pro",
                                    "upgrade_url": "mailto:hello@praxis.app",
                                },
                            )

            # ── CHECK 3: Per-evaluation rate limit (/api/v1/evaluate) ──
            if path in ("/api/v1/evaluate", "/api/v1/evaluate/batch") and method == "POST":
                try:
                    lm.check_eval_rate()
                except LicenseLimitError as e:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "rate_limit_exceeded",
                            "message": str(e),
                            "current_tier": lm.tier.value,
                            "upgrade_url": "mailto:hello@praxis.app",
                        },
                    )

            # ── CHECK 4: Per-minute API rate limit (all endpoints) ──
            now = time.time()
            cutoff = now - 60
            self._api_call_timestamps = [
                t for t in self._api_call_timestamps if t > cutoff
            ]
            api_rate_limit = int(TIER_FEATURES.get(
                lm.tier, TIER_FEATURES[LicenseTier.COMMUNITY]
            ).get("api_rate_limit_per_min", 60))

            if len(self._api_call_timestamps) >= api_rate_limit:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "api_rate_limit_exceeded",
                        "message": (
                            f"API rate limit exceeded: {api_rate_limit} requests/minute "
                            f"on {lm.tier.value.title()} tier."
                        ),
                        "current_tier": lm.tier.value,
                        "limit": api_rate_limit,
                        "upgrade_url": "mailto:hello@praxis.app",
                    },
                )
            self._api_call_timestamps.append(now)

            # ── Process the request ──
            response = await call_next(request)

            # ── Add license info headers ──
            response.headers["X-Praxis-Tier"] = lm.tier.value
            if lm.is_trial:
                response.headers["X-Praxis-Trial-Remaining"] = lm.remaining_trial_time()

            return response

    return LicenseMiddleware
