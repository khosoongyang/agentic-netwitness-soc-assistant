"""tests/test_reporting_canonical_investigation_fields.py -- Phase 5 of the
canonical Investigation Result contract migration.

Verifies that agents/reporting/reporting/context_builder.py::build_context()
(and agents/reporting/adapters/run_reporting.py::_limitations()) now prefer
the canonical Phase 1-3 Investigation fields -- the nested
investigation_result["investigation_analysis"] payload and the Phase 3
feedback_loop.gaps evidence-gap detail -- ahead of every existing
compatibility fallback, while every legacy/cross-stage fallback chain
remains intact and functional for pre-migration or Investigation-skipped
inputs. No fallback branch is removed in this phase.
"""
from __future__ import annotations

from agents.reporting.reporting.context_builder import build_context
from agents.reporting.adapters.run_reporting import _limitations, _has_limitations, _resolve_reporting_mode


def _base_inputs(**overrides) -> dict:
    inputs = {
        "processed_alert": {"incident_id": "INC-1", "alert_id": "ALERT-1"},
        "enriched_alert": {},
        "triage_result": {
            "ticket": {"incident_id": "INC-1"},
            "severity": "Medium",
            "confidence": "Low",
            "classification": "Suspicious Activity",
        },
        "investigation_result": {},
        "threat_intel_result": {},
    }
    inputs.update(overrides)
    return inputs


_CANONICAL_AGENT_PAYLOAD = {
    "incident_id": "INC-1",
    "severity": "Critical",
    "confidence": "High",
    "execution_trace": [],
    "incident_summary": "Canonical structured investigation summary.",
    "actions_taken": [],
    "recommended_containment": ["Isolate host X (canonical)"],
    "business_impact_checklist": {
        "critical_system": "yes", "essential_service": "no",
        "data_sensitivity": "unknown", "operational_impact": "no",
    },
    "severity_justification": "x",
    "confidence_justification": "x",
    "mitre_mappings": [{
        "timeline_phase": "Execution (canonical)",
        "observed_evidence": "PowerShell spawned",
        "tactic": "Execution",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "technique_id": "T1059.001",
    }],
    "mitre_attack_table": None,
    "policy_audit_logs": [],
}


# =============================================================================
# 1-4: canonical severity/confidence/containment/mitre preferred, with
# canonical and legacy values deliberately different so it's obvious which
# source won
# =============================================================================

def test_canonical_severity_is_preferred_over_legacy_flat_and_triage():
    investigation = {
        "investigation_analysis": _CANONICAL_AGENT_PAYLOAD,
        "severity": "Low",  # deliberately different legacy flat alias
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))
    assert ctx["severity"]["value"] == "Critical"


def test_canonical_confidence_is_preferred_over_triage_confidence():
    """This is the headline Phase 5 behaviour: Investigation confidence used
    to always fall through to Triage's pre-investigation estimate because it
    was never populated. It must now win once the canonical contract exists,
    with a deliberately different Triage confidence proving the source."""
    investigation = {"investigation_analysis": _CANONICAL_AGENT_PAYLOAD}
    inputs = _base_inputs(investigation_result=investigation)
    assert inputs["triage_result"]["confidence"] == "Low"  # sanity: differs

    ctx = build_context(inputs)

    assert ctx["confidence"]["value"] == "High"


def test_canonical_recommended_containment_is_preferred_over_legacy_flat():
    investigation = {
        "investigation_analysis": _CANONICAL_AGENT_PAYLOAD,
        "recommended_containment": ["Legacy flat containment action"],
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))
    assert ctx["recommended_containment_actions"] == ["Isolate host X (canonical)"]


def test_canonical_mitre_mappings_are_preferred_over_legacy_flat():
    investigation = {
        "investigation_analysis": _CANONICAL_AGENT_PAYLOAD,
        "mitre_mappings": [{"timeline_phase": "Legacy flat", "observed_evidence": "x",
                            "tactic": "x", "technique_name": "x", "technique_id": "T0000"}],
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))
    assert ctx["mitre_mapping"][0]["timeline_phase"] == "Execution (canonical)"
    assert ctx["mitre_attack_mapping"][0]["timeline_phase"] == "Execution (canonical)"


# =============================================================================
# 5: canonical workflow evidence gaps (feedback_loop.gaps) preferred
# =============================================================================

def test_canonical_feedback_loop_gaps_preferred_over_legacy_missing_evidence():
    investigation = {
        "feedback_loop": {"triggered": True, "passes": 1,
                          "gaps": ["step_2: Check lateral movement (canonical)"]},
        "missing_evidence": ["Legacy generic gap message"],
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))
    gap_texts = [g["gap"] for g in ctx["evidence_gaps"]]
    assert gap_texts == ["step_2: Check lateral movement (canonical)"]


def test_run_reporting_limitations_prefers_feedback_loop_gaps():
    inv = {
        "feedback_loop": {"gaps": ["step_3: Check exfiltration (canonical)"]},
        "missing_evidence": ["Legacy generic gap message"],
    }
    assert _limitations(inv) == ["step_3: Check exfiltration (canonical)"]


# =============================================================================
# 6-7: legacy flat Investigation fields and pre-migration payloads still work
# =============================================================================

def test_legacy_flat_investigation_fields_still_work_without_canonical_payload():
    """Pre-migration-shaped investigation_result (no investigation_analysis
    key at all, e.g. from before Phase 2/3, or the Markdown-fallback path)
    must resolve exactly as it did before Phase 5."""
    investigation = {
        "severity": "High",
        "confidence": "Medium",
        "recommended_containment": ["Legacy flat containment action"],
        "mitre_mappings": [{"timeline_phase": "Legacy flat", "observed_evidence": "x",
                            "tactic": "x", "technique_name": "x", "technique_id": "T0000"}],
        "missing_evidence": ["Legacy generic gap message"],
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))

    assert ctx["severity"]["value"] == "High"
    assert ctx["confidence"]["value"] == "Medium"
    assert ctx["recommended_containment_actions"] == ["Legacy flat containment action"]
    assert ctx["mitre_mapping"][0]["timeline_phase"] == "Legacy flat"
    assert [g["gap"] for g in ctx["evidence_gaps"]] == ["Legacy generic gap message"]


def test_pre_migration_investigation_payload_with_no_new_fields_at_all():
    """Simulates an investigation_result.json persisted before this whole
    migration existed -- no investigation_analysis, no feedback_loop, no
    confidence key whatsoever."""
    investigation = {"status": "completed", "severity": "High",
                     "summary": "Old-style investigation summary."}
    ctx = build_context(_base_inputs(investigation_result=investigation))

    assert ctx["severity"]["value"] == "High"
    assert ctx["confidence"]["value"] == "Low"  # falls through to Triage
    assert ctx["investigation_summary"] == "Old-style investigation summary."


# =============================================================================
# 8-9: Triage fallback still works when Investigation confidence is absent;
# investigation-skipped / needs_more_data scenarios still work
# =============================================================================

def test_triage_confidence_fallback_when_investigation_confidence_absent():
    investigation = {"status": "completed", "severity": "High"}  # no confidence at all
    ctx = build_context(_base_inputs(investigation_result=investigation))
    assert ctx["confidence"]["value"] == "Low"  # Triage's confidence


def test_investigation_skipped_needs_more_data_scenario_still_works():
    """Mirrors workflow/engine.py::handoff_to_reporting()'s own
    investigation-skipped placeholder shape exactly."""
    investigation = {
        "agent": "Investigation Agent",
        "status": "needs_more_data",
        "incident_id": "INC-1",
        "summary": "Investigation stage was skipped or produced no output.",
        "missing_evidence": ["Investigation was not run for this incident."],
        "reporting_mode": "with_limitations",
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))

    assert ctx["reporting_mode"] == "with_limitations"
    assert ctx["confidence"]["value"] == "Low"  # falls through to Triage
    assert [g["gap"] for g in ctx["evidence_gaps"]] == [
        "Investigation was not run for this incident."]


# =============================================================================
# 10: completed_limited scenario still works
# =============================================================================

def test_completed_limited_scenario_still_works():
    investigation = {
        "status": "completed_limited",
        "severity": "High",
        "missing_evidence": ["Final analysis report was not generated."],
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))

    assert ctx["reporting_mode"] == "with_limitations"
    assert [g["gap"] for g in ctx["evidence_gaps"]] == [
        "Final analysis report was not generated."]


# =============================================================================
# 11-12: reporting_mode / eligibility behaviour is unchanged by Phase 5
# =============================================================================

def test_reporting_mode_unaffected_by_canonical_payload_presence():
    """A canonical investigation_analysis payload with status "completed"
    must NOT, by itself, flip reporting_mode -- that decision is untouched
    in Phase 5 and depends only on status/missing_evidence/explicit override,
    exactly as before."""
    investigation = {
        "status": "completed",
        "investigation_analysis": _CANONICAL_AGENT_PAYLOAD,
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))
    assert ctx["reporting_mode"] == "standard"


def test_reporting_mode_still_flips_on_legacy_completed_limited_status():
    investigation = {"status": "completed_limited",
                     "investigation_analysis": _CANONICAL_AGENT_PAYLOAD}
    ctx = build_context(_base_inputs(investigation_result=investigation))
    assert ctx["reporting_mode"] == "with_limitations"


def test_has_limitations_and_resolve_reporting_mode_untouched_by_feedback_loop():
    """_has_limitations()/_resolve_reporting_mode() (Reporting eligibility/
    mode decision) must NOT be affected by feedback_loop.gaps -- only
    _limitations()'s displayed content changes in Phase 5."""
    inv_with_only_feedback_loop = {
        "status": "completed",
        "feedback_loop": {"triggered": True, "gaps": ["some gap"]},
    }
    assert _has_limitations(inv_with_only_feedback_loop, {}) is False
    assert _resolve_reporting_mode(inv_with_only_feedback_loop, {}) == "standard"


# =============================================================================
# 13: report generation still succeeds (context builds without raising, has
# the expected top-level shape)
# =============================================================================

def test_report_context_still_builds_successfully_with_full_canonical_payload():
    investigation = {
        "status": "completed",
        "investigation_analysis": _CANONICAL_AGENT_PAYLOAD,
        "feedback_loop": {"triggered": False, "passes": 0, "gaps": []},
    }
    ctx = build_context(_base_inputs(investigation_result=investigation))

    assert isinstance(ctx, dict)
    assert "appendix_summaries" in ctx
    assert ctx["severity"]["value"] == "Critical"
    assert ctx["confidence"]["value"] == "High"
    assert ctx["reporting_mode"] == "standard"
