"""Tests for edition detection (Lite vs Full)."""

from praxis.edition import Edition, detect_edition


class TestEdition:
    def test_detect_returns_edition(self):
        ed = detect_edition()
        assert isinstance(ed, Edition)

    def test_full_requires_browser_and_sidecar(self):
        full = Edition(
            browser_guardrail=True, rest_sidecar=True,
            dashboard=True, semantic_matching=True,
        )
        assert full.is_full
        assert full.name == "Full"
        assert full.missing() == []

    def test_lite_when_missing_premium(self):
        lite = Edition(
            browser_guardrail=False, rest_sidecar=False,
            dashboard=False, semantic_matching=False,
        )
        assert not lite.is_full
        assert lite.name == "Lite"
        missing = lite.missing()
        assert "browser guardrail (SecureBrowser)" in missing
        assert any("REST sidecar" in m for m in missing)

    def test_partial_is_still_lite(self):
        # Has sidecar but not browser → still Lite (both headline features required)
        partial = Edition(
            browser_guardrail=False, rest_sidecar=True,
            dashboard=True, semantic_matching=True,
        )
        assert not partial.is_full
        assert partial.name == "Lite"

    def test_this_dev_env_is_full(self):
        # The dev venv has playwright + fastapi installed → Full.
        ed = detect_edition()
        # Don't hard-assert (CI lite runners won't have them), just check
        # the logic is coherent with what's installed.
        import importlib.util
        has_pw = importlib.util.find_spec("playwright") is not None
        has_api = importlib.util.find_spec("fastapi") is not None
        if has_pw and has_api:
            assert ed.is_full
