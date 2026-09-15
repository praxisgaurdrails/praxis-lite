"""Tests for the hardened Praxis licensing system.

Covers all anti-tamper protections:
- RSA-signed license key verification
- Clock rollback detection
- File integrity seal (tamper detection)
- Breadcrumb persistence (survives file deletion)
- Machine fingerprint binding
- Elapsed-time tracking
"""

import json
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from praxis.licensing.license_manager import (
    LicenseManager,
    LicenseTier,
    LicenseInfo,
    TrialExpiredError,
    LicenseRequiredError,
    LicenseLimitError,
    LicenseTamperError,
    TIER_FEATURES,
    PRICING,
    generate_license_key,
    decode_license_key,
    _get_machine_fingerprint,
    _compute_seal,
    _verify_seal,
    _write_breadcrumb,
    _read_breadcrumb,
    _get_backup_path,
)

from cryptography.hazmat.primitives.asymmetric import rsa


# ---------------------------------------------------------------------------
# RSA test key (generated fresh for tests, NOT the production key)
# ---------------------------------------------------------------------------

_TEST_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)


def _generate_test_key(tier, email, org="", days=365):
    """Helper: generate a license key using the test private key."""
    return generate_license_key(
        tier=tier,
        owner_email=email,
        organization=org,
        duration_days=days,
        _private_key=_TEST_PRIVATE_KEY,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_license_manager(tmp_path):
    """Reset the singleton and use temp directories for each test."""
    LicenseManager._instance = None

    backup_path = tmp_path / "backup" / ".praxis_seal"

    patcher_dir = patch.object(LicenseManager, '_CONFIG_DIR', tmp_path)
    patcher_file = patch.object(LicenseManager, '_LICENSE_FILE', tmp_path / "license.json")
    patcher_backup = patch(
        'praxis.licensing.license_manager._get_backup_path',
        return_value=backup_path,
    )
    patcher_ntp = patch(
        'praxis.licensing.license_manager._get_network_time',
        return_value=None,
    )
    # Patch the RSA public key so tests verify against the test private key
    patcher_rsa = patch(
        'praxis.licensing.license_manager._RSA_PUBLIC_KEY',
        _TEST_PRIVATE_KEY.public_key(),
    )

    patcher_dir.start()
    patcher_file.start()
    patcher_backup.start()
    patcher_ntp.start()
    patcher_rsa.start()

    yield backup_path  # Yield the backup path so tests can access it

    patcher_rsa.stop()
    patcher_ntp.stop()
    patcher_backup.stop()
    patcher_file.stop()
    patcher_dir.stop()

    # Ensure no stale singleton leaks into other test modules
    LicenseManager._instance = None


# ---------------------------------------------------------------------------
# Trial Activation Tests
# ---------------------------------------------------------------------------

class TestTrialActivation:
    def test_auto_activates_trial_on_first_use(self):
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL
        assert lm.is_trial
        assert not lm.is_paid
        assert not lm.is_community

    def test_trial_has_5_day_expiry(self):
        lm = LicenseManager()
        remaining = lm.license.remaining_seconds
        assert 4.9 * 86400 < remaining <= 5 * 86400

    def test_trial_has_all_features(self):
        lm = LicenseManager()
        features = TIER_FEATURES[LicenseTier.TRIAL]
        assert features["evidence_vault"] is True
        assert features["capability_tokens"] is True
        assert features["custom_yaml_policies"] is True
        assert features["multi_agent"] is True
        assert features["dashboard"] is True

    def test_trial_remaining_human_readable(self):
        lm = LicenseManager()
        remaining = lm.remaining_trial_time()
        assert "h" in remaining

    def test_trial_banner(self):
        lm = LicenseManager()
        banner = lm.banner()
        assert "TRIAL" in banner
        assert "hello@praxis.app" in banner


# ---------------------------------------------------------------------------
# Trial Expiry Tests
# ---------------------------------------------------------------------------

class TestTrialExpiry:
    def test_expired_trial_falls_back_to_community(self, tmp_path):
        # Create an already-expired trial with a valid seal
        expired_data = {
            "license_id": "trial_expired",
            "tier": "trial",
            "owner_email": "",
            "organization": "",
            "machine_fingerprint": _get_machine_fingerprint(),
            "activated_at": time.time() - 86400,
            "trial_started_at": time.time() - 86400,
            "expires_at": time.time() - 3600,
            "license_key": "",
            "features": TIER_FEATURES[LicenseTier.TRIAL],
            "is_valid": True,
            "validation_message": "",
            "elapsed_used": 0.0,
            "last_check_wall": time.time() - 3600,
            "eval_counter": 0,
        }
        expired_data["_seal"] = _compute_seal(expired_data)
        (tmp_path / "license.json").write_text(json.dumps(expired_data, indent=2))

        lm = LicenseManager()
        assert lm.tier == LicenseTier.COMMUNITY
        assert lm.is_community

    def test_community_features_are_limited(self):
        features = TIER_FEATURES[LicenseTier.COMMUNITY]
        assert features["max_policies"] == 2
        assert features["evidence_vault"] is False
        assert features["capability_tokens"] is False
        assert features["multi_agent"] is False
        assert features["max_evaluations_per_hour"] == 1000


# ---------------------------------------------------------------------------
# License Key Tests
# ---------------------------------------------------------------------------

class TestLicenseKeys:
    def test_generate_and_decode_pro_key(self):
        key = _generate_test_key(
            LicenseTier.PRO, "user@example.com", "Acme Inc", 365
        )
        assert isinstance(key, str)
        assert len(key) > 50

        data = decode_license_key(key)
        assert data is not None
        assert data["tier"] == "pro"
        assert data["owner_email"] == "user@example.com"
        assert data["organization"] == "Acme Inc"

    def test_generate_and_decode_enterprise_key(self):
        key = _generate_test_key(
            LicenseTier.ENTERPRISE, "admin@bigcorp.com", "BigCorp", 730
        )
        data = decode_license_key(key)
        assert data is not None
        assert data["tier"] == "enterprise"

    def test_invalid_key_returns_none(self):
        assert decode_license_key("this-is-not-a-valid-key") is None
        assert decode_license_key("") is None

    def test_tampered_key_returns_none(self):
        key = _generate_test_key(LicenseTier.PRO, "user@test.com")
        tampered = key[:-2] + ("A" if key[-2] != "A" else "B") + key[-1]
        assert decode_license_key(tampered) is None

    def test_generate_without_private_key_raises(self):
        """Calling generate_license_key without _private_key must raise."""
        with pytest.raises(RuntimeError, match="private key"):
            generate_license_key(LicenseTier.PRO, "user@test.com")


# ---------------------------------------------------------------------------
# License Activation Tests
# ---------------------------------------------------------------------------

class TestLicenseActivation:
    def test_activate_pro_license(self):
        key = _generate_test_key(LicenseTier.PRO, "buyer@startup.com", "Startup Inc")
        lm = LicenseManager()
        assert lm.is_trial

        info = lm.activate_license(key)
        assert info.tier == LicenseTier.PRO
        assert info.owner_email == "buyer@startup.com"
        assert info.organization == "Startup Inc"
        assert lm.is_paid

    def test_activate_enterprise_license(self):
        key = _generate_test_key(LicenseTier.ENTERPRISE, "it@corp.com", "Corp Ltd")
        lm = LicenseManager()
        info = lm.activate_license(key)
        assert info.tier == LicenseTier.ENTERPRISE
        assert lm.is_paid

    def test_activate_invalid_key_raises(self):
        lm = LicenseManager()
        with pytest.raises(ValueError, match="Invalid license key"):
            lm.activate_license("garbage-key-12345")

    def test_deactivate_reverts_to_community(self):
        key = _generate_test_key(LicenseTier.PRO, "user@test.com")
        lm = LicenseManager()
        lm.activate_license(key)
        assert lm.is_paid

        lm.deactivate()
        assert lm.is_community
        assert not lm.is_paid


# ---------------------------------------------------------------------------
# Feature Gating Tests
# ---------------------------------------------------------------------------

class TestFeatureGating:
    def test_trial_allows_all_features(self):
        lm = LicenseManager()
        assert lm.check_feature("evidence_vault")
        assert lm.check_feature("capability_tokens")
        assert lm.check_feature("custom_yaml_policies")

    def test_community_blocks_paid_features(self, tmp_path):
        comm_data = {
            "license_id": "",
            "tier": "community",
            "owner_email": "",
            "organization": "",
            "machine_fingerprint": _get_machine_fingerprint(),
            "activated_at": time.time(),
            "expires_at": 0.0,
            "trial_started_at": 0.0,
            "license_key": "",
            "features": TIER_FEATURES[LicenseTier.COMMUNITY],
            "is_valid": True,
            "validation_message": "",
            "elapsed_used": 0.0,
            "last_check_wall": time.time(),
            "eval_counter": 0,
        }
        comm_data["_seal"] = _compute_seal(comm_data)
        (tmp_path / "license.json").write_text(json.dumps(comm_data, indent=2))

        lm = LicenseManager()
        with pytest.raises(LicenseRequiredError, match="evidence_vault"):
            lm.check_feature("evidence_vault")
        with pytest.raises(LicenseRequiredError, match="capability_tokens"):
            lm.check_feature("capability_tokens")

    def test_community_allows_basic_sidecar(self, tmp_path):
        comm_data = {
            "license_id": "",
            "tier": "community",
            "owner_email": "",
            "organization": "",
            "machine_fingerprint": _get_machine_fingerprint(),
            "activated_at": time.time(),
            "expires_at": 0.0,
            "trial_started_at": 0.0,
            "license_key": "",
            "features": TIER_FEATURES[LicenseTier.COMMUNITY],
            "is_valid": True,
            "validation_message": "",
            "elapsed_used": 0.0,
            "last_check_wall": time.time(),
            "eval_counter": 0,
        }
        comm_data["_seal"] = _compute_seal(comm_data)
        (tmp_path / "license.json").write_text(json.dumps(comm_data, indent=2))

        lm = LicenseManager()
        assert lm.check_feature("sidecar_api")


# ---------------------------------------------------------------------------
# Rate Limiting Tests
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_eval_rate_limit_within_bounds(self):
        lm = LicenseManager()
        for _ in range(100):
            lm.check_eval_rate()

    def test_policy_count_limit(self, tmp_path):
        comm_data = {
            "license_id": "",
            "tier": "community",
            "owner_email": "",
            "organization": "",
            "machine_fingerprint": _get_machine_fingerprint(),
            "activated_at": time.time(),
            "expires_at": 0.0,
            "trial_started_at": 0.0,
            "license_key": "",
            "features": TIER_FEATURES[LicenseTier.COMMUNITY],
            "is_valid": True,
            "validation_message": "",
            "elapsed_used": 0.0,
            "last_check_wall": time.time(),
            "eval_counter": 0,
        }
        comm_data["_seal"] = _compute_seal(comm_data)
        (tmp_path / "license.json").write_text(json.dumps(comm_data, indent=2))

        lm = LicenseManager()
        lm.check_policy_count(1)
        with pytest.raises(LicenseLimitError, match="max_policies"):
            lm.check_policy_count(2)


# ---------------------------------------------------------------------------
# Pricing Tests
# ---------------------------------------------------------------------------

class TestPricing:
    def test_community_is_free(self):
        assert PRICING[LicenseTier.COMMUNITY]["monthly"] == 0

    def test_pro_pricing(self):
        assert PRICING[LicenseTier.PRO]["monthly"] == 49
        assert PRICING[LicenseTier.PRO]["annual"] == 468

    def test_enterprise_pricing(self):
        assert PRICING[LicenseTier.ENTERPRISE]["monthly"] == 199

    def test_trial_is_free(self):
        assert PRICING[LicenseTier.TRIAL]["monthly"] == 0
        assert PRICING[LicenseTier.TRIAL]["duration_days"] == 5


# ---------------------------------------------------------------------------
# Persistence Tests
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_license_persists_to_disk(self, tmp_path):
        lm = LicenseManager()
        assert (tmp_path / "license.json").exists()

        data = json.loads((tmp_path / "license.json").read_text())
        assert data["tier"] == "trial"
        assert "_seal" in data  # Must have integrity seal

    def test_license_reloads_from_disk(self, tmp_path):
        lm1 = LicenseManager()
        key = _generate_test_key(LicenseTier.PRO, "user@test.com")
        lm1.activate_license(key)

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.PRO
        assert lm2.license.owner_email == "user@test.com"

    def test_sealed_file_has_integrity(self, tmp_path):
        """Verify that saved license file has a valid seal."""
        lm = LicenseManager()
        data = json.loads((tmp_path / "license.json").read_text())
        assert _verify_seal(data)


# ---------------------------------------------------------------------------
# Status & Display Tests
# ---------------------------------------------------------------------------

class TestStatusDisplay:
    def test_status_dict(self):
        lm = LicenseManager()
        status = lm.status_dict()
        assert status["tier"] == "trial"
        assert status["is_valid"] is True
        assert "remaining" in status
        assert "features" in status

    def test_machine_fingerprint_is_stable(self):
        fp1 = _get_machine_fingerprint()
        fp2 = _get_machine_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 32


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_license_info_remaining_unlimited(self):
        info = LicenseInfo(expires_at=0)
        assert info.remaining_human == "unlimited"
        assert not info.is_expired

    def test_license_info_remaining_expired(self):
        info = LicenseInfo(expires_at=time.time() - 100)
        assert info.remaining_human == "expired"
        assert info.is_expired

    def test_tier_features_all_defined(self):
        for tier in LicenseTier:
            assert tier in TIER_FEATURES
            features = TIER_FEATURES[tier]
            assert "max_policies" in features
            assert "evidence_vault" in features
            assert "sidecar_api" in features


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-TAMPER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestIntegritySeal:
    """Test that manually editing license.json is detected."""

    def test_editing_tier_detected(self, tmp_path):
        """Changing tier in the JSON file → tamper detected → community."""
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL

        # Manually edit the tier in the JSON
        data = json.loads((tmp_path / "license.json").read_text())
        data["tier"] = "pro"  # Hack: change trial to pro
        # Do NOT update the seal
        (tmp_path / "license.json").write_text(json.dumps(data, indent=2))

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.COMMUNITY
        assert "Tamper" in lm2.license.validation_message

    def test_editing_expires_at_detected(self, tmp_path):
        """Changing expires_at to extend trial → tamper detected."""
        lm = LicenseManager()

        data = json.loads((tmp_path / "license.json").read_text())
        data["expires_at"] = time.time() + 999999  # Extend far into the future
        (tmp_path / "license.json").write_text(json.dumps(data, indent=2))

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.COMMUNITY
        assert "Tamper" in lm2.license.validation_message

    def test_removing_seal_detected(self, tmp_path):
        """Removing the _seal field → tamper detected."""
        lm = LicenseManager()

        data = json.loads((tmp_path / "license.json").read_text())
        del data["_seal"]
        (tmp_path / "license.json").write_text(json.dumps(data, indent=2))

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.COMMUNITY

    def test_valid_seal_passes(self, tmp_path):
        """Unmodified file with valid seal loads normally."""
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.TRIAL


class TestFileDeletion:
    """Test that deleting license.json doesn't grant a fresh trial."""

    def test_deleting_license_file_restores_from_breadcrumb(self, tmp_path):
        """Delete license.json → trial is restored from breadcrumb, not reset."""
        lm = LicenseManager()
        original_start = lm.license.trial_started_at
        assert lm.tier == LicenseTier.TRIAL

        # Delete the license file
        (tmp_path / "license.json").unlink()

        LicenseManager._instance = None
        lm2 = LicenseManager()
        # Trial should be restored, not a fresh one
        assert lm2.tier == LicenseTier.TRIAL
        # Start time should match original (from breadcrumb)
        assert abs(lm2.license.trial_started_at - original_start) < 2

    def test_deleting_license_after_trial_expired(self, tmp_path):
        """Delete license.json after trial would have expired → community only."""
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL

        # Write a breadcrumb that says trial started 6 days ago
        _write_breadcrumb(_get_machine_fingerprint(), time.time() - 6 * 86400)

        # Delete the license file
        (tmp_path / "license.json").unlink()

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.COMMUNITY
        assert "expired" in lm2.license.validation_message.lower()


class TestClockRollback:
    """Test that setting the clock back is detected."""

    def test_clock_rollback_detected(self, tmp_path):
        """
        Simulate clock rollback: save license with last_check_wall = now,
        then reload with time.time() returning a past value.
        """
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL

        current = time.time()

        # Reload with the clock set far back
        LicenseManager._instance = None
        with patch('praxis.licensing.license_manager.time') as mock_time:
            mock_time.time.return_value = current - 7200  # 2 hours in the past
            mock_time.monotonic.return_value = time.monotonic()
            lm2 = LicenseManager()
            # Should detect clock rollback → community
            assert lm2.tier == LicenseTier.COMMUNITY
            assert "Tamper" in lm2.license.validation_message or "clock" in lm2.license.validation_message.lower()


class TestMachineBinding:
    """Test that copying license.json to another machine is detected."""

    def test_different_machine_fingerprint_rejected(self, tmp_path):
        """License from another machine → tamper detected."""
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL

        # Change the machine fingerprint
        LicenseManager._instance = None
        with patch(
            'praxis.licensing.license_manager._get_machine_fingerprint',
            return_value="deadbeef" * 4,
        ):
            lm2 = LicenseManager()
            assert lm2.tier == LicenseTier.COMMUNITY
            assert "Tamper" in lm2.license.validation_message


class TestBreadcrumb:
    """Test the redundant breadcrumb system."""

    def test_breadcrumb_is_created_on_trial(self, tmp_path, reset_license_manager):
        """Trial activation creates a breadcrumb backup."""
        backup_path = reset_license_manager
        lm = LicenseManager()
        assert lm.tier == LicenseTier.TRIAL
        # Breadcrumb should have been written
        ts = _read_breadcrumb()
        assert ts is not None
        assert abs(ts - lm.license.trial_started_at) < 2

    def test_tampered_breadcrumb_ignored(self, tmp_path, reset_license_manager):
        """If someone edits the breadcrumb file, it's ignored."""
        backup_path = reset_license_manager
        lm = LicenseManager()

        # Tamper with the breadcrumb
        assert backup_path.exists(), f"Breadcrumb should exist at {backup_path}"
        payload = json.loads(backup_path.read_text())
        payload["data"]["ts"] = payload["data"]["ts"] + 99999
        payload["seal"] = "tampered_seal_value"
        backup_path.write_text(json.dumps(payload))

        ts = _read_breadcrumb()
        assert ts is None  # Tampered breadcrumb returns None

    def test_breadcrumb_machine_bound(self, tmp_path, reset_license_manager):
        """Breadcrumb from another machine is rejected."""
        lm = LicenseManager()

        # Read breadcrumb with different fingerprint
        with patch(
            'praxis.licensing.license_manager._get_machine_fingerprint',
            return_value="different_machine_fp_here1234",
        ):
            ts = _read_breadcrumb()
            assert ts is None


class TestElapsedTimeTracking:
    """Test that elapsed time tracking defeats clock-freeze attacks."""

    def test_elapsed_time_is_tracked(self, tmp_path):
        """License file stores elapsed_used field."""
        lm = LicenseManager()
        assert lm.license.elapsed_used >= 0

        data = json.loads((tmp_path / "license.json").read_text())
        assert "elapsed_used" in data

    def test_last_check_wall_updated_on_save(self, tmp_path):
        """last_check_wall is updated every time the license is saved."""
        lm = LicenseManager()
        data = json.loads((tmp_path / "license.json").read_text())
        assert data["last_check_wall"] > 0
        assert abs(data["last_check_wall"] - time.time()) < 5


class TestTamperRevocation:
    """Test that after tamper detection, trial can never be re-activated."""

    def test_tamper_burns_breadcrumb(self, tmp_path):
        """After tamper, breadcrumb is burned (set to expired timestamp)."""
        lm = LicenseManager()

        # Simulate tamper: edit the file
        data = json.loads((tmp_path / "license.json").read_text())
        data["tier"] = "enterprise"
        (tmp_path / "license.json").write_text(json.dumps(data, indent=2))

        LicenseManager._instance = None
        lm2 = LicenseManager()
        assert lm2.tier == LicenseTier.COMMUNITY

        # Now even if they delete the license file, breadcrumb is burned
        (tmp_path / "license.json").unlink()
        LicenseManager._instance = None
        lm3 = LicenseManager()
        assert lm3.tier == LicenseTier.COMMUNITY
        assert "expired" in lm3.license.validation_message.lower()
