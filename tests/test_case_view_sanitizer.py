"""tests/test_case_view_sanitizer.py -- regression coverage for a real bug
found while restoring the Triage stage's frontend presentation.

backend/services/case_view_service.py::_sanitize_for_display() is the
generic sanitizer every stage's persisted result passes through before
reaching the frontend (backend/services/case_service.py::_safe_stage_result
-> build_workflow_stages() -> GET /api/cases/<id>/workflow's stages[].result
-- what frontend/js/pages/workspace.js's new renderTriageStage() reads).

Before this fix, three of its heuristics were broad enough to silently
corrupt real Triage output on its way to the frontend, even though
agents/triage/soc_triage_agent.py itself produced the field correctly:

  1. `_SECRET_KEY_RE` searched for "key"/"token"/etc. as a raw substring
     anywhere in a field NAME -- so Triage's `metakeys` /
     `matched_metakeys` / `metakey_values` / `category_metakeys` (all
     contain "key" fused mid-word) were replaced with "\u00abredacted\u00bb"
     wholesale, even though none of them are credentials.
  2. `_HIDDEN_FIELD_RE` searched for "reasoning"/"thinking" as a raw
     substring -- so Triage's per-category IOC `reasoning` (the actual
     finding explanation, e.g. "Unusual HTTP traffic to an internal host on
     port 8888") and every stage's `ai_thinking` (workflow/state_store.py's
     documented cross-stage field, workflow/stage_summaries.py::
     render_triage_thinking_plain()'s deliberately analyst-facing "Thinking
     Process" panel content) were dropped outright.
  3. `_LOCAL_PATH_RE`'s unix-path alternative (`/[\\w./-]{6,}`) had no
     left boundary, so ordinary prose containing a slash with no preceding
     whitespace -- e.g. Triage's own IOC_CONFIDENTIALITY checklist text
     "...originating from/terminating on the device" -- had its "/" silently
     eaten mid-word ("from/terminating" -> "fromterminating").

This module locks in the fix (all three no longer corrupt legitimate
content) while confirming the two real, evidenced redaction/hiding
behaviors this sanitizer must still perform (tests/test_readonly_api.py::
test_case_workflow_uses_persisted_stage_and_lock_state pins the exact
"api_key" -> "\u00abredacted\u00bb" case already; tests/test_investigation_stage.py::
test_sanitize_drops_hidden_reasoning_fields pins "internal_notes") are
untouched by this fix.
"""
from __future__ import annotations

from backend.services.case_view_service import _sanitize_for_display


# =============================================================================
# Fields that must survive unmodified (the bug this module guards against)
# =============================================================================

def test_metakeys_field_names_are_not_redacted_as_secrets():
    payload = {
        "metakeys": ["ip.dst", "port.dst"],
        "matched_metakeys": ["ip.dst"],
        "metakey_values": {"ip.dst": "10.0.0.5"},
        "category_metakeys": ["ip.dst"],
    }
    sanitized = _sanitize_for_display(payload)
    assert sanitized == payload


def test_ioc_category_reasoning_field_is_not_hidden():
    payload = {"per_category": {"confidentiality": {
        "matched_ioc_names": ["Unknown traffic originating from/terminating on the device"],
        "reasoning": "Unusual HTTP traffic to an internal host on port 8888.",
    }}}
    sanitized = _sanitize_for_display(payload)
    assert sanitized["per_category"]["confidentiality"]["reasoning"] == (
        "Unusual HTTP traffic to an internal host on port 8888.")


def test_ai_thinking_field_is_not_hidden():
    payload = {"ai_summary": "Suspicious execution.", "ai_thinking": "The IOC checklist matched 6 indicator(s)..."}
    sanitized = _sanitize_for_display(payload)
    assert sanitized["ai_thinking"] == "The IOC checklist matched 6 indicator(s)..."


def test_prose_containing_a_slash_is_not_corrupted():
    text = "Unknown traffic originating from/terminating on the device"
    sanitized = _sanitize_for_display({"summary": text})
    assert sanitized["summary"] == text


def test_prose_containing_multiple_slash_separated_words_is_not_corrupted():
    text = "Review authentication logs for pass/fail and read/write anomalies"
    sanitized = _sanitize_for_display({"summary": text})
    assert sanitized["summary"] == text


# =============================================================================
# Real redaction/hiding behavior that must still work (regression guard for
# the fix itself -- must not have been fixed by simply disabling redaction)
# =============================================================================

def test_a_field_literally_named_api_key_is_still_redacted():
    sanitized = _sanitize_for_display({"api_key": "must-not-leak", "openai_api_key": "sk-secret"})
    assert sanitized["api_key"] == "\u00abredacted\u00bb"
    assert sanitized["openai_api_key"] == "\u00abredacted\u00bb"


def test_internal_notes_field_is_still_hidden():
    sanitized = _sanitize_for_display({"status": "completed", "internal_notes": "private chain of thought"})
    assert "internal_notes" not in sanitized


def test_chain_of_thought_field_is_still_hidden():
    sanitized = _sanitize_for_display({"chain_of_thought": "raw scratch reasoning"})
    assert "chain_of_thought" not in sanitized


def test_a_genuine_local_absolute_path_is_still_shortened():
    sanitized = _sanitize_for_display({"path": "output written to /home/user/secrets/report.json now"})
    assert "/home/user/secrets/" not in sanitized["path"]
    assert "report.json" in sanitized["path"]


def test_a_genuine_windows_absolute_path_is_still_shortened():
    sanitized = _sanitize_for_display({"path": r"see C:\Users\jdoe\AppData\ticket.json for details"})
    assert r"C:\Users\jdoe\AppData" not in sanitized["path"]
    assert "ticket.json" in sanitized["path"]
