"""tests/test_case_view_triage_alignment.py -- Phase 3 of the canonical
Triage Result contract migration: aligning case-view/chat-context
consumers of the persisted RAW triage_result_json with the actual
canonical shape TriageAgent.triage() produces (TriageAgentSuccessOutput:
metakeys_payload/ticket/trace/used_parsed_context/error[/cached], plus
generate_triage_ai_summary()'s ai_summary/ai_thinking/ai_summary_model/
ai_summary_generated_at) -- as opposed to the SEPARATE Reporting-flattened
triage_doc shape (workflow/engine.py::handoff_to_reporting()'s
incident_id/severity/classification/mitre_tactic/... flat dict), which
this phase does not touch.

Every fixture here uses a REAL canonical raw Triage shape -- no flattened
triage_doc-style fixtures are used to stand in for raw persisted state.

Same isolation conventions as tests/test_investigation_stage.py: an
isolated tmp_path SQLite DB and trusted artifact root, no live subprocess,
no real LLM/OpenAI/network calls.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from workflow import state_store as wss
from workflow import engine as sw
import backend.services.case_view_service as cv


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "test_case_view_triage.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    wss.db_init()
    yield


# =============================================================================
# Fixtures: a REAL canonical raw Triage result (TriageAgentSuccessOutput
# shape) and a raw source incident.
# =============================================================================

def _risk_rating_kwargs() -> dict:
    return dict(
        likelihood_initiation="High",
        likelihood_occurrence="Medium",
        likelihood_adverse_impact="High",
        overall_risk="High",
        rationale="Repeated failed logons followed by a privileged success.",
    )


def _canonical_triage_result(classification="HIGH", incident_id="INC-1",
                             risk_level="high", mitre_tactic="Credential Access",
                             mitre_technique="Brute Force") -> dict:
    """A full, real TriageAgentSuccessOutput-shaped dict -- exactly what
    TriageAgent.triage() persists (before generate_triage_ai_summary()'s
    additive ai_summary/ai_thinking/ai_summary_model/
    ai_summary_generated_at keys are merged in by the workflow)."""
    return {
        "metakeys_payload": {
            "incident_id": incident_id, "incident_title": "Suspicious privileged logon",
            "timestamp": "2026-08-20T10:00:00.000000",
            "matched_metakeys": ["ip.src", "user.name"],
            "metakey_values": {"ip.src": "10.0.0.5", "user.name": "jdoe"},
            "ioc_summary": "[NETWORK] 10.0.0.5 — brute-force pattern",
            "risk_level": risk_level, "classification": risk_level,
            "mitre_tactic": mitre_tactic, "mitre_technique": mitre_technique,
        },
        "ticket": {
            "unc": "#00042A", "incident_id": incident_id, "title": "Suspicious privileged logon",
            "incident_time": "2026-08-20 10:00:00 UTC", "created_at": "2026-08-20T10:00:05.123456",
            "classification": classification,
            "risk_rating": _risk_rating_kwargs(),
            "incident_category": "Internal Hacking (attempted)",
            "mitre_tactic": mitre_tactic, "mitre_technique": mitre_technique,
            "initial_response_time": "<= 30 minutes",
            "summary": "Repeated failed logons from 10.0.0.5 preceded a successful "
                       "privileged logon for user jdoe.",
            "recommended_actions": ["Isolate the affected host",
                                    "Reset the targeted account credentials"],
            "matched_ioc_count": 3, "metakeys": ["ip.src", "user.name"],
        },
        "trace": [], "used_parsed_context": False, "error": None,
    }


def _incident(incident_id: str = "INC-1", **overrides) -> dict:
    inc = {"id": incident_id, "title": "Test incident", "alertMeta": {}}
    inc.update(overrides)
    return inc


def _seed_raw_incident(incident_id: str, run_id: str, incident: dict) -> None:
    path = sw._save_run_artifact(incident_id, run_id, "raw_incident.json", "raw_incident",
                                 {"incident": incident, "data_availability":
                                  sw._data_availability(incident)})
    wss.save_raw_incident_path(incident_id, run_id, str(path))


def _run_with_approved_triage(incident_id: str, triage_result: dict,
                              incident_overrides: dict | None = None) -> str:
    run_id = wss.start_run(incident_id)
    _seed_raw_incident(incident_id, run_id, _incident(incident_id, **(incident_overrides or {})))
    wss.save_triage_result(incident_id, run_id, triage_result)
    wss._guarded_update(incident_id, run_id, {"triage_status": "Approved"})
    return run_id


# =============================================================================
# 1, 2 & 3. classification / summary / recommended_actions surfaced
# correctly from the raw nested canonical shape.
# =============================================================================

def test_persisted_raw_triage_classification_surfaced_correctly():
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result(classification="HIGH"))
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert ctx["confirmed_facts"]["triage"]["classification"] == "HIGH"


def test_ticket_summary_surfaced_correctly():
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result())
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert "Repeated failed logons" in ctx["confirmed_facts"]["triage"]["summary"]


def test_recommended_actions_surfaced_correctly():
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result())
    ctx = cv.build_aegis_context("INC-1", run_id)
    actions = ctx["confirmed_facts"]["triage"]["recommended_actions"]
    assert "Isolate the affected host" in actions
    assert "Reset the targeted account credentials" in actions


# =============================================================================
# 4. risk_level is sourced from metakeys_payload (the real canonical
# location) -- case_view_service.py does not currently read Triage's own
# risk_level anywhere (verified by grep: its only "risk_level"/"risk_rating"
# reads are Threat Intelligence's enrichment_risk_level, a different
# concept), so this proves the canonical raw location itself is intact and
# unambiguous for any future consumer, rather than asserting on a
# non-existent case-view read.
# =============================================================================

def test_risk_level_is_sourced_from_metakeys_payload():
    triage_result = _canonical_triage_result(risk_level="critical")
    run_id = _run_with_approved_triage("INC-1", triage_result)
    state = wss.get_state("INC-1")
    raw = json.loads(state["triage_result_json"])
    assert raw["metakeys_payload"]["risk_level"] == "critical"
    # Not a top-level field, and not conflated with ticket.classification
    # (a differently-cased, differently-owned value on the same ticket).
    assert "risk_level" not in raw
    assert raw["ticket"]["classification"] != raw["metakeys_payload"]["risk_level"]


# =============================================================================
# 5. MITRE tactic/technique are sourced correctly from their real canonical
# locations (both ticket and metakeys_payload carry them, per Phase 1) --
# and build_mitre() (case_view_service.py's actual MITRE tab builder)
# deliberately never reads Triage's ticket.mitre_tactic/mitre_technique at
# all (it sources from NetWitness's own AlertTactics/AlertTechniques, a
# keyword inferrer, or Investigation's narrative table -- a real, existing
# stage-ownership design, not a Phase 3 concern), so this is verified at
# the raw-shape level rather than asserting on a non-existent MITRE read
# inside case_view_service.py.
# =============================================================================

def test_mitre_tactic_and_technique_sourced_correctly_in_raw_shape():
    triage_result = _canonical_triage_result(mitre_tactic="Initial Access",
                                             mitre_technique="Spearphishing Attachment")
    run_id = _run_with_approved_triage("INC-1", triage_result)
    state = wss.get_state("INC-1")
    raw = json.loads(state["triage_result_json"])
    assert raw["ticket"]["mitre_tactic"] == "Initial Access"
    assert raw["ticket"]["mitre_technique"] == "Spearphishing Attachment"
    assert raw["metakeys_payload"]["mitre_tactic"] == "Initial Access"
    assert raw["metakeys_payload"]["mitre_technique"] == "Spearphishing Attachment"


def test_build_mitre_does_not_read_triage_ticket_mitre_fields(monkeypatch):
    # A deliberately wrong ticket.mitre_tactic must NOT leak into the MITRE
    # tab's NetWitness-detection tier -- confirms build_mitre() stays
    # scoped to NetWitness/Investigation sources, unaffected by this phase.
    triage_result = _canonical_triage_result(mitre_tactic="Should Never Appear")
    run_id = _run_with_approved_triage("INC-1", triage_result)
    result = cv.build_case_view("INC-1", run_id)
    mitre_tactics = [m.get("tactic") for m in result.get("mitre") or []]
    assert "Should Never Appear" not in mitre_tactics


# =============================================================================
# 6 & 7. Triage confidence is not fabricated; no nonexistent top-level raw
# "severity" is relied upon.
# =============================================================================

def test_triage_confidence_is_not_fabricated():
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result())
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert "confidence" not in ctx["confirmed_facts"]["triage"]


def test_no_top_level_raw_severity_is_relied_upon():
    triage_result = _canonical_triage_result(classification="HIGH")
    run_id = _run_with_approved_triage("INC-1", triage_result)

    # The producer itself never emits a top-level "severity" key.
    state = wss.get_state("INC-1")
    raw = json.loads(state["triage_result_json"])
    assert "severity" not in raw

    # ...and the consumer must not silently expect one either.
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert "severity" not in ctx["confirmed_facts"]["triage"]
    assert ctx["confirmed_facts"]["triage"]["classification"] == "HIGH"


def test_confirmed_facts_dead_keys_no_longer_present():
    """Regression: severity/confidence/confirmed_facts/evidence_gaps used
    to be read directly off the raw triage_result_json's TOP LEVEL, where
    none of them ever exist -- always silently None/[]. Now removed
    outright rather than kept as permanently-null placeholders."""
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result())
    ctx = cv.build_aegis_context("INC-1", run_id)
    triage_facts = ctx["confirmed_facts"]["triage"]
    for dead_key in ("severity", "confidence", "confirmed_facts", "evidence_gaps"):
        assert dead_key not in triage_facts


# =============================================================================
# 8. Source/NetWitness severity remains separate from Triage classification.
# =============================================================================

def test_source_severity_and_triage_classification_remain_separate_and_can_disagree():
    triage_result = _canonical_triage_result(classification="CRITICAL")
    run_id = _run_with_approved_triage(
        "INC-1", triage_result,
        incident_overrides={"riskScore": "Low"},  # deliberately disagrees with Triage
    )
    wss._guarded_update("INC-1", run_id, {"severity": "Low"})

    result = cv.build_case_view("INC-1", run_id)
    case_context = result["overview"]["case_context"]
    assert case_context["triage_classification"]["value"] == "CRITICAL"
    assert case_context["netwitness_severity"]["value"] != "Critical"
    # Two distinctly-labeled fields, never collapsed into one.
    assert "triage_classification" in case_context
    assert "netwitness_severity" in case_context


# =============================================================================
# 9. Investigation's own final severity remains a separate concept/field
# (investigation_result_json.severity is a REAL, legitimately-owned
# top-level field on that stage's own contract -- unlike Triage's raw
# result, which has no such field at all).
# =============================================================================

def test_investigation_severity_is_a_distinct_field_from_triage_classification():
    triage_result = _canonical_triage_result(classification="MEDIUM")
    run_id = _run_with_approved_triage("INC-1", triage_result)
    wss._guarded_update("INC-1", run_id, {
        "investigation_status": "Approved",
        "investigation_result_json": json.dumps({
            "summary": "Investigation concluded this was a false positive.",
            "severity": "Low", "classification": "false_positive",
            "indicators": [], "missing_evidence": [], "narrative_report": "",
        }),
    })
    ctx = cv.build_aegis_context("INC-1", run_id)
    facts = ctx["confirmed_facts"]
    assert facts["triage"]["classification"] == "MEDIUM"
    assert facts["investigation"]["severity"] == "Low"
    assert facts["triage"]["classification"] != facts["investigation"]["severity"]


# =============================================================================
# 10. Missing/error Triage result degrades safely.
# =============================================================================

def test_missing_triage_result_degrades_safely():
    run_id = wss.start_run("INC-1")
    _seed_raw_incident("INC-1", run_id, _incident("INC-1"))
    # triage_status left "not_started" / triage_result_json left NULL.
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert ctx["confirmed_facts"]["triage"]["label"] != "confirmed"
    assert "classification" not in ctx["confirmed_facts"]["triage"]


def test_error_triage_result_degrades_safely():
    error_result = {"error": "OpenAI request timed out", "metakeys_payload": {},
                    "ticket": {}, "trace": []}
    run_id = wss.start_run("INC-1")
    _seed_raw_incident("INC-1", run_id, _incident("INC-1"))
    wss.save_triage_result("INC-1", run_id, error_result)
    # A real Triage failure never reaches triage_status="Approved" in the
    # live pipeline, but the read-side must not crash even if it somehow
    # did -- ticket.get(...) on {} is always safe.
    wss._guarded_update("INC-1", run_id, {"triage_status": "Approved"})
    ctx = cv.build_aegis_context("INC-1", run_id)
    triage_facts = ctx["confirmed_facts"]["triage"]
    assert triage_facts["label"] == "confirmed"
    # ticket.get(...) on an empty {} ticket safely degrades to None/[]
    # rather than raising -- no dead top-level "severity"/"confidence"
    # fields reappear just because the real fields are also empty.
    assert triage_facts["classification"] is None
    assert triage_facts["summary"] is None
    assert triage_facts["recommended_actions"] == []
    assert "severity" not in triage_facts
    assert "confidence" not in triage_facts


# =============================================================================
# 11. mock/raw canonical shape still works (workflow/engine.py's
# mock_triage_result(), already validated in Phase 1 against
# TriageAgentSuccessOutput).
# =============================================================================

def test_mock_raw_canonical_shape_still_works():
    mock_result = sw.mock_triage_result({"id": "INC-1", "title": "Mock incident"})
    run_id = _run_with_approved_triage("INC-1", mock_result)
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert ctx["confirmed_facts"]["triage"]["classification"] == "HIGH"
    assert "confidence" not in ctx["confirmed_facts"]["triage"]
    result = cv.build_case_view("INC-1", run_id)
    assert result["overview"]["case_context"]["triage_classification"]["value"] == "HIGH"


# =============================================================================
# 12. API/frontend-facing response contracts remain stable: the same keys
# case_view_service.py's callers rely on are still present and unrenamed.
# =============================================================================

def test_confirmed_facts_triage_block_retains_stable_contract_keys():
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result())
    ctx = cv.build_aegis_context("INC-1", run_id)
    triage_facts = ctx["confirmed_facts"]["triage"]
    assert triage_facts["label"] == "confirmed"
    for key in ("classification", "summary", "recommended_actions"):
        assert key in triage_facts


def test_build_case_view_overview_case_context_keys_unchanged():
    run_id = _run_with_approved_triage("INC-1", _canonical_triage_result())
    result = cv.build_case_view("INC-1", run_id)
    case_context = result["overview"]["case_context"]
    for key in ("netwitness_severity", "triage_classification", "unified_verdict",
               "host", "user"):
        assert key in case_context


# =============================================================================
# Explicit regression: a minimal raw dict with ONLY the nested canonical
# shape (no workflow-added extras, no top-level severity/classification)
# must not be REQUIRED to also carry a flattened top-level severity/
# classification pair to surface correctly.
# =============================================================================

def test_minimal_nested_raw_dict_does_not_require_flattened_top_level_fields():
    minimal_raw = {
        "ticket": {"classification": "HIGH", "summary": "", "recommended_actions": []},
        "metakeys_payload": {"risk_level": "high"},
    }
    # Confirms the fixture itself intentionally omits the flattened shape.
    assert "severity" not in minimal_raw
    assert "classification" not in minimal_raw

    run_id = _run_with_approved_triage("INC-1", minimal_raw)
    ctx = cv.build_aegis_context("INC-1", run_id)
    assert ctx["confirmed_facts"]["triage"]["classification"] == "HIGH"
