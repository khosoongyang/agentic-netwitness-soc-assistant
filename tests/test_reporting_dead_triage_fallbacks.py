"""tests/test_reporting_dead_triage_fallbacks.py -- Phase 4 of the canonical
Triage Result contract migration.

Verifies agents/reporting/reporting/context_builder.py::build_context() and
agents/reporting/reporting/export_context_enhancer.py after removing dead
Reporting fallback terms that claimed to read Triage fields no real
producer has ever written (confidence, likely_scenario, affected_assets,
affected_users, iocs, evidence, timeline, missing_evidence/missing_fields,
powershell_analysis/powershell_command_analysis, recommendations,
approval_required, soc_analyst_approval_status, containment_status/
containment_recommended/containment_action/recommended_containment_action,
severity_reason/confidence_reason, report_status, validation_status,
current_stage, case_id, next_action/recommended_next_action).

Every "triage_result" fixture here matches the REAL flattened shape
workflow/engine.py::handoff_to_reporting() actually writes to
triage_result.json (agent/status/incident_id/alert_id/title/severity/
classification/mitre_tactic/mitre_technique/risk_rating/ioc_summary/
matched_metakeys/matched_ioc_count/incident_category/
initial_response_time/summary/recommended_actions/ticket/created_at) --
never a fake flattened shape carrying fields Triage does not produce.
"""
from __future__ import annotations

from agents.reporting.reporting.context_builder import build_context


def _real_triage_doc(**overrides) -> dict:
    """Exactly the shape handoff_to_reporting() writes to
    triage_result.json -- see workflow/engine.py:2395-2417."""
    doc = {
        "agent": "Triage Agent",
        "status": "completed",
        "incident_id": "INC-1",
        "alert_id": "INC-1",
        "title": "Suspicious privileged logon",
        "severity": "HIGH",
        "classification": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "risk_rating": {
            "likelihood_initiation": "High", "likelihood_occurrence": "Medium",
            "likelihood_adverse_impact": "High", "overall_risk": "High",
            "rationale": "Repeated failed logons preceded a privileged success.",
        },
        "ioc_summary": "[NETWORK] 10.0.0.5 — brute-force pattern",
        "matched_metakeys": ["ip.src", "user.name"],
        "matched_ioc_count": 3,
        "incident_category": "Internal Hacking (attempted)",
        "initial_response_time": "<= 30 minutes",
        "summary": "Repeated failed logons from 10.0.0.5 preceded a successful "
                  "privileged logon for user jdoe.",
        "recommended_actions": ["Isolate the affected host",
                                "Reset the targeted account credentials"],
        "ticket": {"incident_id": "INC-1", "unc": "#00042A"},
        "created_at": "2026-08-20T10:00:05.123456",
    }
    doc.update(overrides)
    return doc


def _inputs(**overrides) -> dict:
    inputs = {
        "processed_alert": {},
        "enriched_alert": {},
        "triage_result": _real_triage_doc(),
        "investigation_result": {},
        "threat_intel_result": {},
    }
    inputs.update(overrides)
    return inputs


# =============================================================================
# 1. Classification resolves from the real Triage field.
# =============================================================================

def test_classification_resolves_from_real_triage_field():
    ctx = build_context(_inputs())
    assert ctx["classification"] == "HIGH"


def test_classification_falls_back_to_incident_category_when_classification_absent():
    triage = _real_triage_doc()
    del triage["classification"]
    ctx = build_context(_inputs(triage_result=triage))
    assert ctx["classification"] == "Internal Hacking (attempted)"


# =============================================================================
# 2. Severity degraded fallback still resolves from the real Triage severity
# alias when Investigation supplies none at all.
# =============================================================================

def test_severity_degrades_to_real_triage_severity_alias_when_investigation_absent():
    ctx = build_context(_inputs(investigation_result={}))
    assert ctx["severity"]["value"] == "HIGH"


def test_severity_prefers_investigation_over_triage_when_both_present():
    investigation = {"severity": "Low"}
    ctx = build_context(_inputs(investigation_result=investigation))
    assert ctx["severity"]["value"] == "Low"


# =============================================================================
# 3. incident_category fallback still works (already covered above as part
# of the classification chain -- incident_category is Triage's real field
# name for this, never a separate fabricated key).
# =============================================================================

def test_incident_category_is_a_real_triage_field_used_in_the_classification_chain():
    triage = _real_triage_doc(classification="", incident_category="Phishing")
    ctx = build_context(_inputs(triage_result=triage))
    assert ctx["classification"] == "Phishing"


# =============================================================================
# 4. recommended_actions still work as the degraded containment/
# recommendation fallback when Investigation supplies nothing.
# =============================================================================

def test_recommended_actions_used_as_degraded_containment_fallback():
    ctx = build_context(_inputs(investigation_result={}))
    assert "Isolate the affected host" in ctx["recommended_containment_actions"]
    assert "Reset the targeted account credentials" in ctx["recommended_containment_actions"]


def test_investigation_recommended_containment_preferred_over_triage_recommended_actions():
    investigation = {"recommended_containment": ["Investigation containment action"]}
    ctx = build_context(_inputs(investigation_result=investigation))
    assert ctx["recommended_containment_actions"] == ["Investigation containment action"]


# =============================================================================
# 5. incident_id/alert_id/title identity fallbacks still work.
# =============================================================================

def test_identity_fields_fall_back_to_real_triage_fields():
    ctx = build_context(_inputs(processed_alert={}, enriched_alert={}))
    assert ctx["incident_id"] == "INC-1"
    assert ctx["alert_id"] == "INC-1"
    assert ctx["case_title"] == "Suspicious privileged logon"


# =============================================================================
# 6. Triage confidence is not considered a valid source.
# =============================================================================

def test_triage_confidence_is_never_a_valid_source_even_when_present_on_raw_doc():
    # Even if some other producer accidentally wrote a "confidence" key onto
    # the raw triage doc, it must never be treated as a source -- Triage
    # does not own this concept.
    triage = _real_triage_doc(confidence="Low")
    ctx = build_context(_inputs(triage_result=triage, investigation_result={}))
    assert ctx["confidence"]["value"] == "Not Provided"


# =============================================================================
# 7. Triage likely_scenario is not considered.
# =============================================================================

def test_triage_likely_scenario_is_never_considered():
    triage = _real_triage_doc(likely_scenario="Should never surface")
    ctx = build_context(_inputs(triage_result=triage, investigation_result={}))
    assert ctx["likely_scenario"] == "Not Provided"


# =============================================================================
# 8. Nonexistent Triage IOC field is not considered.
# =============================================================================

def test_triage_iocs_field_is_never_considered():
    triage = _real_triage_doc(iocs=[{"value": "10.0.0.5", "type": "ip"}])
    ctx = build_context(_inputs(triage_result=triage, investigation_result={}))
    assert ctx["iocs"] == []


# =============================================================================
# 9. Nonexistent Triage evidence-gap fields are not considered.
# =============================================================================

def test_triage_missing_evidence_and_missing_fields_are_never_considered():
    triage = _real_triage_doc(
        missing_evidence=["Should never surface"],
        missing_fields=["Should never surface either"],
    )
    ctx = build_context(_inputs(triage_result=triage, investigation_result={}))
    assert ctx["evidence_gaps"] == []


# =============================================================================
# 10. Nonexistent Triage containment fields are not considered.
# =============================================================================

def test_triage_containment_fields_are_never_considered():
    triage = _real_triage_doc(
        containment_status="contained",
        containment_action="Should never surface",
        recommended_containment_action="Should never surface either",
        soc_analyst_approval_status="approved",
        approval_required=True,
    )
    ctx = build_context(_inputs(triage_result=triage, investigation_result={}))
    assert ctx["containment_status"] != "contained"
    assert ctx["approval"]["approval_status"] != "approved"
    assert ctx["approval"]["approval_required"] != True  # noqa: E712


# =============================================================================
# 11. Investigation canonical fields still take precedence (regression
# guard -- Phase 5 behaviour must remain unaffected by Phase 4).
# =============================================================================

def test_investigation_canonical_severity_and_classification_still_take_precedence():
    investigation = {
        "investigation_analysis": {
            "incident_id": "INC-1", "severity": "Critical", "confidence": "High",
            "execution_trace": [], "incident_summary": "x", "actions_taken": [],
            "recommended_containment": ["Canonical action"],
            "business_impact_checklist": {
                "critical_system": "yes", "essential_service": "no",
                "data_sensitivity": "unknown", "operational_impact": "no",
            },
            "severity_justification": "x", "confidence_justification": "x",
            "mitre_mappings": [], "mitre_attack_table": None, "policy_audit_logs": [],
        },
        "classification": "Confirmed Compromise",
    }
    ctx = build_context(_inputs(investigation_result=investigation))
    assert ctx["severity"]["value"] == "Critical"
    assert ctx["confidence"]["value"] == "High"
    assert ctx["classification"] == "Confirmed Compromise"
    assert ctx["recommended_containment_actions"] == ["Canonical action"]


# =============================================================================
# 12. Reporting still handles a missing/empty Triage result safely.
# =============================================================================

def test_missing_triage_result_degrades_safely():
    ctx = build_context(_inputs(triage_result={}))
    assert ctx["classification"] == "Not Provided"
    assert ctx["confidence"]["value"] == "Not Provided"
    assert ctx["incident_id"] == "unknown"
    # No verbatim containment bullet text exists with nothing to supply it
    # (empty, not a crash); the separate generic-fallback recommendations
    # list still populates its three baseline bullets.
    assert ctx["recommended_containment_actions"] == []
    assert len(ctx["recommendations"]) == 3


def test_none_triage_result_degrades_safely():
    ctx = build_context(_inputs(triage_result=None))
    assert isinstance(ctx, dict)
    assert ctx["classification"] == "Not Provided"


# =============================================================================
# Regression: a minimal raw dict with ONLY the nested/real flattened shape
# (no confidence/likely_scenario/iocs/etc.) must not be required to also
# carry those fabricated fields to resolve correctly.
# =============================================================================

def test_minimal_real_triage_doc_does_not_require_fabricated_fields():
    minimal_triage = {"incident_id": "INC-1", "classification": "HIGH", "ticket": {}}
    ctx = build_context(_inputs(triage_result=minimal_triage))
    assert ctx["classification"] == "HIGH"
    assert ctx["confidence"]["value"] == "Not Provided"
