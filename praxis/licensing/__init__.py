"""
Praxis Licensing — Commercial license management, trial enforcement, and feature gating.
"""

from praxis.licensing.license_manager import (
    LicenseManager,
    LicenseTier,
    LicenseInfo,
    TrialExpiredError,
    LicenseRequiredError,
    LicenseTamperError,
)

__all__ = [
    "LicenseManager",
    "LicenseTier",
    "LicenseInfo",
    "TrialExpiredError",
    "LicenseRequiredError",
    "LicenseTamperError",
]
