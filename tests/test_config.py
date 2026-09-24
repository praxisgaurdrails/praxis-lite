"""Tests for praxis.config — the user-configurable strictness matrix."""

from __future__ import annotations

from pathlib import Path

import pytest

from praxis.config import (
    PRESETS,
    PraxisConfig,
    default_config_path,
    get_config,
    reset_config,
    set_config,
)
from praxis.principal import Principal, PrincipalKind
from praxis.policy.tier_gate import apply_tier_gate
from praxis.tiers import RiskTier


# --------------------------------------------------------------------------
# Presets & outcome resolution
# --------------------------------------------------------------------------

def test_balanced_matches_historical_matrix():
    c = PraxisConfig.from_preset("balanced")
    assert c.outcome("agent", "read") == "allow"
    assert c.outcome("agent", "write") == "ask"
    assert c.outcome("agent", "delete") == "block"
    assert c.outcome("local", "read") == "allow"
    assert c.outcome("local", "write") == "allow"
    assert c.outcome("local", "delete") == "ask"


def test_paranoid_locks_agents_down():
    c = PraxisConfig.from_preset("paranoid")
    assert c.outcome("agent", "write") == "block"
    assert c.outcome("agent", "delete") == "block"
    assert c.outcome("local", "write") == "ask"


def test_permissive_lets_agents_delete_with_approval():
    c = PraxisConfig.from_preset("permissive")
    assert c.outcome("agent", "delete") == "ask"
    assert c.outcome("local", "delete") == "allow"


def test_unknown_inputs_fail_safe_to_block():
    c = PraxisConfig.from_preset("balanced")
    assert c.outcome("nobody", "read") == "block"
    assert c.outcome("agent", "chmod") == "block"


def test_invalid_preset_raises():
    with pytest.raises(ValueError):
        PraxisConfig.from_preset("yolo")


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def test_save_load_roundtrip_preset(tmp_path: Path):
    p = tmp_path / "config.toml"
    PraxisConfig.from_preset("paranoid").save(p)
    loaded = PraxisConfig.load(p)
    assert loaded.strictness == "paranoid"
    assert loaded.outcome("agent", "write") == "block"


def test_save_load_roundtrip_custom(tmp_path: Path):
    p = tmp_path / "config.toml"
    c = PraxisConfig(strictness="custom")
    c.decisions["agent"]["delete"] = "ask"
    c.decisions["local"]["write"] = "ask"
    c.search_roots = ["~/Projects", "~/Notes"]
    c.save(p)

    loaded = PraxisConfig.load(p)
    assert loaded.strictness == "custom"
    assert loaded.outcome("agent", "delete") == "ask"
    assert loaded.outcome("local", "write") == "ask"
    assert loaded.search_roots == ["~/Projects", "~/Notes"]


def test_missing_file_returns_balanced(tmp_path: Path):
    loaded = PraxisConfig.load(tmp_path / "does-not-exist.toml")
    assert loaded.strictness == "balanced"
    assert loaded.outcome("agent", "delete") == "block"


def test_corrupt_file_falls_back_to_balanced(tmp_path: Path):
    p = tmp_path / "config.toml"
    p.write_text("this is not = valid = toml = [[[")
    loaded = PraxisConfig.load(p)
    assert loaded.strictness == "balanced"


def test_state_dir_env_overrides_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PRAXIS_STATE_DIR", str(tmp_path))
    assert default_config_path() == tmp_path / "config.toml"


# --------------------------------------------------------------------------
# Tier gate honours the active config
# --------------------------------------------------------------------------

def _agent() -> Principal:
    return Principal.agent("claude-desktop", proven_via="mcp")


def test_tier_gate_paranoid_blocks_agent_write():
    from praxis.policy.engine import Decision

    set_config(PraxisConfig.from_preset("paranoid"))
    d = apply_tier_gate(_agent(), RiskTier.T1)
    assert d is not None
    assert d.decision == Decision.BLOCK
    assert d.matched_rule == "tier_gate.agent_t1"


def test_tier_gate_permissive_asks_agent_delete():
    from praxis.policy.engine import Decision

    set_config(PraxisConfig.from_preset("permissive"))
    d = apply_tier_gate(_agent(), RiskTier.T2)
    assert d is not None
    assert d.decision == Decision.REQUIRE_APPROVAL
    assert d.matched_rule == "tier_gate.agent_t2"


def test_tier_gate_balanced_default_blocks_agent_delete():
    from praxis.policy.engine import Decision

    reset_config()  # no file -> balanced
    d = apply_tier_gate(_agent(), RiskTier.T2)
    assert d is not None
    assert d.decision == Decision.BLOCK


def test_tier_gate_t3_always_blocked_even_permissive():
    from praxis.policy.engine import Decision

    set_config(PraxisConfig.from_preset("permissive"))
    d = apply_tier_gate(_agent(), RiskTier.T3)
    assert d is not None
    assert d.decision == Decision.BLOCK
    assert "t3_blocked" in d.matched_rule


def test_get_config_caches():
    reset_config()
    a = get_config()
    b = get_config()
    assert a is b
