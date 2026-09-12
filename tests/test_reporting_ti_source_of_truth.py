"""tests/test_reporting_ti_source_of_truth.py -- Threat Intelligence Reporting
Phase 1 (Reporting-consumer correctness fix).

The Threat Intelligence contract audit found that
agents/reporting/reporting/context_builder.py::build_context() confused two
unrelated artifacts:

  * threat_intel_result.json -- the authoritative Threat Intelligence result
    produced by agents/threat_intelligence/threat_intel.py::
    run_threat_intel_for_dashboard() (enrichment_risk_score,
    enrichment_risk_level, enrichment_risk_reasons, threat_intelligence,
    warnings, summary, notes, status).

  * agents/reporting/inputs/enriched_alert.json -- an UNRELATED,
    Triage/incident-derived artifact built by
    workflow/engine.py::handoff_to_reporting() (incident_id, alert_title,
    incident_summary, severity, risk_score, host, source_ip, username,
    iocs, raw_incident). It never carries a "status"/"enrichment_risk_score"/
    "notes" key -- those reads always resolved to None before this fix.

This file verifies context_builder.py now sources every genuinely
Threat-Intelligence-owned field from threat_intel_result, with the unrelated
enriched_alert.risk_score never masquerading as TI's enrichment_risk_score,
and that every other stage's fields (Parsing's raw risk_score, Triage's
risk_rating, Investigation's severity) remain untouched and separately
sourced.
"""
from __future__ import annotations

from agents.reporting.reporting.context_builder import build_context


def _real_enriched_alert(**overrides) -> dict:
    """Exactly the shape workflow/engine.py::handoff_to_reporting() writes to
    enriched_alert.json -- see engine.py:2422-2438. This is Triage/incident
    -derived and carries NO Threat Intelligence fields."""
    doc = {
        "incident_id": "INC-1",
        "alert_title": "Suspicious privileged logon",
        "incident_summary": "SOC alert requires review: Suspicious privileged logon",
        "severity": "High",
        "risk_score": 20,
        "host": "WIN-HOST-01",
        "source_ip": "10.0.0.5",
        "username": "jdoe",
        "iocs": [],
        "raw_incident": {"id": "INC-1"},
    }
    doc.update(overrides)
    return doc


def _real_threat_intel_result(**overrides) -> dict:
    """Exactly the shape agents/threat_intelligence/threat_intel.py::
    run_threat_intel_for_dashboard() returns (and workflow/engine.py::
    handoff_to_reporting() persists verbatim to threat_intel_result.json) --
    see threat_intel.py:1250-1277."""
    doc = {
        "agent": "Threat Intelligence Enrichment",
        "agent_source": "threat_intel.py",
        "status": "completed",
        "current_stage": "threat_intelligence_completed",
        "created_at": "2026-08-20T10:05:00+00:00",
        "summary": "Threat intelligence enrichment completed with High enrichment risk.",
        "enrichment_risk_score": 80,
        "enrichment_risk_level": "High",
        "enrichment_risk_reasons": [
            "VirusTotal reported 3 malicious detection(s) for IP 203.0.113.9.",
        ],
        "threat_intelligence": {
            "iocs": {"ip_indicators": ["203.0.113.9"]},
            "virustotal": {"file_hash": None, "ip_results": [], "domain_results": []},
            "abuseipdb": {"ip_results": []},
            "alienvault_otx": {"otx_results": []},
            "notes": [],
        },
        "notes": [],
        "warnings": [],
        "enriched_alert": {},
        "output_files": {},
        "recommended_next_action": "SOC analyst approval is required before Investigation Agent can run.",
    }
    doc.update(overrides)
    return doc


def _inputs(**overrides) -> dict:
    inputs = {
        "processed_alert": {"risk_score": 10},
        "enriched_alert": _real_enriched_alert(),
        "triage_result": {"incident_id": "INC-1", "risk_rating": {"overall_risk": "High"}},
        "investigation_result": {"severity": "Critical"},
        "threat_intel_result": _real_threat_intel_result(),
    }
    inputs.update(overrides)
    return inputs


# =============================================================================
# 1 & regression. threat_intel_result.enrichment_risk_score wins over the
# unrelated enriched_alert.risk_score -- the exact confirmed bug.
# =============================================================================

def test_enrichment_risk_score_comes_from_threat_intel_result_not_enriched_alert():
    ctx = build_context(_inputs())
    assert ctx["enrichment_risk_score"] == 80
    assert ctx["enrichment_risk_score"] != 20


def test_regression_confirmed_bug_exact_reproduction():
    """The exact regression scenario from the Threat Intelligence audit."""
    threat_intel_result = {"enrichment_risk_score": 80, "enrichment_risk_level": "High"}
    enriched_alert = {"risk_score": 20}
    ctx = build_context({
        "processed_alert": {},
        "enriched_alert": enriched_alert,
        "triage_result": {},
        "investigation_result": {},
        "threat_intel_result": threat_intel_result,
    })
    assert ctx["enrichment_risk_score"] == 80
    assert ctx["enrichment_risk_score"] != 20


# =============================================================================
# 2. Raw/source risk_score is not exposed as enrichment_risk_score.
# =============================================================================

def test_raw_source_risk_score_not_exposed_as_enrichment_risk_score():
    ctx = build_context(_inputs())
    # Parsing/source-owned risk score stays under its own keys.
    assert ctx["original_alert_risk_score"] == 10
    assert ctx["initial_risk_score"] == 10
    # Threat-Intelligence-owned enrichment_risk_score is a different value
    # entirely, never the enriched_alert's raw risk_score (20) either.
    assert ctx["enrichment_risk_score"] == 80


def test_enriched_alert_risk_score_alone_does_not_produce_a_fake_enrichment_score():
    """With no threat_intel_result at all, enriched_alert.risk_score (20)
    must NOT masquerade as the enrichment risk score. threat_intel_result
    .get("enrichment_risk_score") on an empty dict is None (a safe, honest
    "we don't know" -- not a fabricated 20)."""
    ctx = build_context(_inputs(threat_intel_result={}))
    assert ctx["enrichment_risk_score"] is None
    assert ctx["enrichment_risk_score"] != 20


# =============================================================================
# 3 & 4. enrichment_risk_level comes from threat_intel_result, and score/level
# stay sourced from the same TI result (never mixed across stages).
# =============================================================================

def test_enrichment_risk_level_comes_from_threat_intel_result():
    ctx = build_context(_inputs())
    assert ctx["enrichment_risk_level"] == "High"


def test_score_and_level_are_sourced_from_the_same_threat_intel_result():
    ti = _real_threat_intel_result(enrichment_risk_score=45, enrichment_risk_level="Medium")
    ctx = build_context(_inputs(threat_intel_result=ti))
    assert ctx["enrichment_risk_score"] == 45
    assert ctx["enrichment_risk_level"] == "Medium"


# =============================================================================
# 5 & 6. threat_intelligence_result_available reflects threat_intel_result,
# not the unrelated enriched_alert.
# =============================================================================

def test_threat_intelligence_result_available_yes_when_threat_intel_result_present():
    ctx = build_context(_inputs())
    assert ctx["quality_checks"]["threat_intelligence_result_available"] == "Yes"


def test_threat_intelligence_result_available_no_when_threat_intel_result_absent_even_with_enriched_alert():
    ctx = build_context(_inputs(threat_intel_result={}))
    # enriched_alert is still fully populated (Triage/incident data), but
    # that must not make this flag say "Yes".
    assert ctx["raw_inputs"]["enriched_alert"]
    assert ctx["quality_checks"]["threat_intelligence_result_available"] == "No"


# =============================================================================
# 7 & 8. Threat Intelligence appendix section uses the correct source for TI
# fields, and correctly-owned neighbours (Parsing/Investigation) are
# untouched.
# =============================================================================

def test_appendix_enrichment_status_comes_from_threat_intel_result():
    ctx = build_context(_inputs())
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert appendix["Enrichment Status"] == "completed"


def test_appendix_enriched_risk_score_comes_from_threat_intel_result():
    ctx = build_context(_inputs())
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert appendix["Enriched Risk Score"] == "80"


def test_appendix_threat_intel_notes_comes_from_threat_intel_result_summary():
    ctx = build_context(_inputs())
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert "enrichment risk" in appendix["Threat Intel Notes"]


def test_appendix_original_alert_risk_score_still_parsing_owned():
    ctx = build_context(_inputs())
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert appendix["Original Alert Risk Score"] == "10"


def test_appendix_final_risk_rating_still_investigation_owned():
    ctx = build_context(_inputs())
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert appendix["Final Risk Rating"] == ctx["severity"]["label"]


# =============================================================================
# 9. Missing TI result still degrades safely (no crash, "Not Provided"/"No").
# =============================================================================

def test_missing_threat_intel_result_degrades_safely():
    ctx = build_context(_inputs(threat_intel_result={}))
    assert ctx["enrichment_risk_score"] is None
    assert ctx["enrichment_risk_level"] is None
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert appendix["Enrichment Status"] == "Not Provided"
    assert appendix["Enriched Risk Score"] == "Not Provided"
    assert appendix["Threat Intel Notes"] == "Not Provided"
    assert ctx["quality_checks"]["threat_intelligence_result_available"] == "No"


def test_threat_intel_result_missing_entirely_from_inputs_degrades_safely():
    """threat_intel_result absent from the inputs dict altogether (not just
    empty) must behave identically -- build_context() defaults it to {}."""
    inputs = _inputs()
    del inputs["threat_intel_result"]
    ctx = build_context(inputs)
    assert ctx["enrichment_risk_score"] is None
    assert ctx["quality_checks"]["threat_intelligence_result_available"] == "No"


# =============================================================================
# 10. Canonical Investigation/Triage Reporting behaviour is unchanged.
# =============================================================================

def test_investigation_severity_remains_separate_from_ti_risk_level():
    ctx = build_context(_inputs())
    assert ctx["severity"]["label"] == "Critical"
    assert ctx["enrichment_risk_level"] == "High"


def test_triage_risk_rating_remains_separate_and_untouched():
    ctx = build_context(_inputs())
    assert ctx["triage"] == {"incident_id": "INC-1", "risk_rating": {"overall_risk": "High"}}


# =============================================================================
# 11. Existing legacy enriched fallback remains where intentionally
# supported (export_context_enhancer's threat_intel_result -> enriched
# precedence), and enriched.get("enrichment_risk_score") stays as a legacy
# fallback path (not removed) even though no real producer populates it.
# =============================================================================

def test_legacy_enriched_alert_fallback_still_used_when_threat_intel_result_omits_the_key():
    """threat_intel_result present but missing enrichment_risk_score (an
    edge case, not the normal shape) still falls through to the legacy
    enriched.get("enrichment_risk_score") path rather than crashing or
    silently defaulting past a genuinely-set legacy value."""
    ti = {"status": "completed"}
    enriched = _real_enriched_alert(enrichment_risk_score=55)
    ctx = build_context(_inputs(threat_intel_result=ti, enriched_alert=enriched))
    assert ctx["enriched_risk_score"] == 55


def test_export_context_enhancer_precedence_untouched():
    from agents.reporting.reporting.export_context_enhancer import _threat_intel_index
    ti_source = {"threat_intelligence": {"virustotal": {"ip_results": []}}}
    # Precedence itself (threat_intel_result preferred over enriched_alert)
    # lives in export_context_enhancer.rebuild_iocs() and is documented as
    # intentional legacy compatibility -- Phase 1 does not touch it. This
    # smoke-checks the helper it relies on still runs unmodified.
    assert _threat_intel_index(ti_source) == {}


# =============================================================================
# 12. No producer-side TI shape changes occurred.
# =============================================================================

def test_threat_intel_producer_shape_unchanged():
    from agents.threat_intelligence import threat_intel
    result = threat_intel.calculate_enrichment_risk({})
    assert set(result.keys()) == {
        "enrichment_risk_score", "enrichment_risk_level", "enrichment_risk_reasons",
    }
    assert result["enrichment_risk_score"] == 0
    assert result["enrichment_risk_level"] == "Low"
