"""
Global test fixtures – ensure the LicenseManager singleton never leaks
between test modules.
"""

import pytest
from praxis.licensing.license_manager import LicenseManager, LicenseTier


@pytest.fixture(autouse=True)
def _reset_license_singleton(request, monkeypatch):
    """
    Guarantee every test starts with a clean LicenseManager singleton,
    then force the singleton into TRIAL tier so the paid feature gates
    (evidence_vault, capability_tokens, multi_agent, etc.) don't block
    tests that exercise the daemon end-to-end.

    The licensing tests themselves need the real expiry / online-check
    behaviour, so we skip the monkeypatch for that module.
    """
    is_licensing_test = "test_licensing" in request.node.nodeid

    if not is_licensing_test:
        monkeypatch.setattr(
            LicenseManager, "_is_trial_expired", lambda self: False, raising=False
        )
        monkeypatch.setattr(
            LicenseManager, "_periodic_online_check", lambda self: None, raising=False
        )

    LicenseManager._instance = None

    if not is_licensing_test:
        lm = LicenseManager()
        try:
            lm._license.tier = LicenseTier.TRIAL
        except Exception:
            pass

    yield
    LicenseManager._instance = None


@pytest.fixture(autouse=True)
def _reset_praxis_config():
    """Ensure the process-wide PraxisConfig cache never leaks between
    tests (config tests install paranoid/permissive globally)."""
    from praxis.config import reset_config

    reset_config()
    yield
    reset_config()
