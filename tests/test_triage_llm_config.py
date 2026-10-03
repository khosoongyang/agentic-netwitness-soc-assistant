"""tests/test_triage_llm_config.py -- audit T-15 / T-16.

T-15: with no OPENAI_API_KEY the config fell back to the literal "changeme",
sent it to the provider and failed with an opaque "Connection error"; the
README/configuration docs claimed a no-key fallback that does not exist.
Triage must fail fast, with a specific error and no network call.

T-16: _provider_supports_json_mode() returned True for every provider
unless TRIAGE_JSON_MODE=never, despite its name promising detection.
"""
from __future__ import annotations

import pytest

from agents.triage import soc_triage_agent as sta


def test_no_key_triage_fails_fast_with_specific_error(tmp_path, monkeypatch):
    from test_triage_step1_agent_integration import _history_db, _incident
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(sta, "_TICKET_DB", tmp_path / "t.db")
    sta._ticket_db_init()

    def no_network(*a, **k):
        raise AssertionError("no network call may be attempted without a key")

    a = sta.TriageAgent(baseline_db_path=_history_db(tmp_path / "h.db"))
    assert a.cfg.api_key == ""
    monkeypatch.setattr(sta, "_stream_or_invoke", no_network)
    res = a.triage(_incident(), force=True)
    assert res["error"].startswith(sta.LLM_NOT_CONFIGURED)
    assert "OPENAI_API_KEY" in res["error"]


@pytest.mark.parametrize("key", ["", "  ", "changeme", "replace_me", "sk-replace_me"])
def test_placeholder_keys_are_not_configured(key):
    assert sta._llm_key_configured(key) is False


def test_real_looking_key_is_configured():
    assert sta._llm_key_configured("sk-offline-dummy") is True


def test_docs_no_longer_claim_a_no_key_triage_fallback():
    from pathlib import Path
    root = Path(sta.__file__).resolve().parents[2]
    for doc in ("README.md", "docs/configuration.md"):
        text = (root / doc).read_text(encoding="utf-8")
        assert "fall back to their non-LLM/templated paths" not in text
        assert "fall back to non-LLM/templated behavior rather than failing" not in text


@pytest.mark.parametrize("url,expected", [
    ("https://api.openai.com/v1", True),
    ("https://my-resource.openai.azure.com/openai", True),
    ("http://localhost:11434/v1", False),
    ("http://127.0.0.1:8000/v1", False),
    ("https://llm.internal.example/v1", False),
    ("", True),          # unset => the OpenAI default
])
def test_json_mode_detected_by_provider(url, expected, monkeypatch):
    monkeypatch.delenv("TRIAGE_JSON_MODE", raising=False)
    assert sta._provider_supports_json_mode(url) is expected


@pytest.mark.parametrize("forced,expected", [("always", True), ("never", False)])
def test_json_mode_env_override_still_wins(forced, expected, monkeypatch):
    monkeypatch.setenv("TRIAGE_JSON_MODE", forced)
    assert sta._provider_supports_json_mode("http://localhost:11434/v1") is expected
    assert sta._provider_supports_json_mode("https://api.openai.com/v1") is expected
