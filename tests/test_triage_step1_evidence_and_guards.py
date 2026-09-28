"""tests/test_triage_step1_evidence_and_guards.py -- Triage Step 1:
evidence packet (agents/triage/evidence_packet.py), citation verification
and hard guards a-e + deterministic uncertainty (agents/triage/guards.py).

Fully offline: synthetic incidents and baselines, no DB, no LLM.
"""
from __future__ import annotations

import copy

import pytest

from agents.triage.evidence_packet import (
    STRONG_SIGNAL_LABELS,
    build_evidence_packet,
    get_leaf,
    iter_leaves,
    render_packet_for_prompt,
)
from agents.triage.guards import (
    CORE_EVIDENCE,
    MANDATORY_EVIDENCE,
    apply_guards,
    build_assessment,
    compute_uncertainty,
    evidence_completeness,
    missing_mandatory_evidence,
    normalize_assessment,
    verify_citations,
)
from agents.triage.triage_result import EvidencePacket, TriageAssessment
from triage_step1_payloads import (
    SAMPLE_INCIDENT,
    SAMPLE_PARSED_CONTEXT,
    evidence_packet,
    measured_baseline,
    true_positive_model_output,
    unknown_baseline,
)


def _with_context(packet: dict, key: str = "change_context") -> dict:
    """Simulate a future step filling a context.* placeholder."""
    p = copy.deepcopy(packet)
    p["context"][key] = {"value": "CHG-1234 approved maintenance window",
                         "status": "measured", "source": "test:change_calendar"}
    return p


def _malware_incident() -> dict:
    inc = dict(SAMPLE_INCIDENT)
    inc["summary"] = "EDR detected a Cobalt Strike beacon on the host"
    return inc


def _claim(text: str, *cites: str) -> dict:
    return {"claim": text, "cites": list(cites)}


# =============================================================================
# Evidence packet shape and statuses
# =============================================================================

def test_packet_validates_and_has_all_sections():
    p = evidence_packet()
    EvidencePacket.model_validate(p)
    assert set(p) == {"detection", "entity", "data_quality", "baseline", "rule_signals", "context"}
    assert set(p["detection"]) == {"createdBy", "ruleId", "created", "sources", "riskScore",
                                   "priority", "alertCount", "eventCount", "tactics", "techniques"}


def test_every_leaf_has_value_status_source():
    for path, leaf in iter_leaves(evidence_packet()):
        assert set(leaf) == {"value", "status", "source"}, path
        assert leaf["status"] in ("measured", "inferred", "missing"), path
        assert isinstance(leaf["source"], str) and leaf["source"], path


def test_statuses_measured_inferred_missing():
    p = evidence_packet()
    assert get_leaf(p, "detection.riskScore") == {
        "value": 70, "status": "measured", "source": "incident.riskScore"}
    assert get_leaf(p, "detection.tactics")["status"] == "missing"
    assert get_leaf(p, "entity.value")["value"] == "10.0.0.5"
    assert get_leaf(p, "entity.kind")["value"] == "ip_internal"
    assert get_leaf(p, "baseline.same_source_entity_30d") ["value"] == 4
    assert get_leaf(p, "baseline.same_source_entity_30d")["status"] == "measured"
    assert get_leaf(p, "baseline.same_source_entity_annualized")["status"] == "inferred"
    assert get_leaf(p, "data_quality.parser_status")["value"] == "completed"
    assert get_leaf(p, "data_quality.missing_fields") == {
        "value": [], "status": "measured",
        "source": "parsed_context.parser_metadata.missing_fields"}


def test_context_is_always_missing_in_step1():
    p = evidence_packet()
    for key in ("asset_context", "change_context", "confirmed_benign_history"):
        assert get_leaf(p, f"context.{key}")["status"] == "missing"


def test_missing_parsed_context_is_missing_not_assumed():
    p = build_evidence_packet(SAMPLE_INCIDENT, None, measured_baseline())
    for key in ("parser_status", "parser_confidence", "missing_fields", "data_quality"):
        assert get_leaf(p, f"data_quality.{key}")["status"] == "missing"


def test_unknown_baseline_makes_every_count_missing():
    p = evidence_packet(baseline=unknown_baseline())
    assert get_leaf(p, "baseline.status")["status"] == "missing"
    assert get_leaf(p, "baseline.reason")["status"] == "measured"   # the reason is known
    for path, leaf in iter_leaves({"baseline": p["baseline"]}):
        if path not in ("baseline.status", "baseline.reason"):
            assert leaf["status"] == "missing", path


def test_partial_window_counts_are_inferred_lower_bounds():
    b = measured_baseline(window_complete={"7d": True, "30d": False, "90d": False})
    p = evidence_packet(baseline=b)
    assert get_leaf(p, "baseline.same_source_entity_7d")["status"] == "measured"
    assert get_leaf(p, "baseline.same_source_entity_30d")["status"] == "inferred"
    assert "lower bound" in get_leaf(p, "baseline.same_source_entity_30d")["source"]
    assert get_leaf(p, "baseline.same_source_entity_annualized")["status"] == "missing"


def test_unresolved_entity_is_missing():
    p = build_evidence_packet({"id": "X", "title": "Odd thing"}, None, unknown_baseline())
    assert get_leaf(p, "entity.value")["status"] == "missing"


def test_alert_meta_entity_is_inferred():
    inc = {"id": "X", "title": "Lateral Movement via SSH", "alertMeta": {"SourceIp": ["10.0.0.9"]}}
    p = build_evidence_packet(inc, None, unknown_baseline())
    assert get_leaf(p, "entity.value")["status"] == "inferred"


def test_rule_signals_use_existing_scorer():
    p = evidence_packet(incident=_malware_incident())
    malware = get_leaf(p, "rule_signals.malware")
    assert malware["status"] == "measured"
    assert malware["value"]["weight"] == 4
    assert malware["value"]["mitre_technique"] == "T1059"
    assert malware["value"]["mitre_tactic"] == "Execution"
    assert any(m["match"].lower() in ("cobalt strike", "beacon") for m in malware["value"]["matched"])
    assert malware["value"]["matched"][0]["path"] == "incident.summary"
    summary = get_leaf(p, "rule_signals.scan_summary")["value"]
    assert "malware" in summary["strong_labels"]
    assert "suspicious_ip" in summary["labels"]            # from the title IP
    assert "suspicious_ip" not in summary["strong_labels"]  # excluded from the floor


def test_dot_paths_are_addressable_and_rendered():
    p = evidence_packet()
    assert get_leaf(p, "baseline.same_source_entity_30d") is not None
    assert get_leaf(p, "baseline") is None                  # a section, not a leaf
    assert get_leaf(p, "baseline.nope") is None
    assert get_leaf(p, "") is None
    text = render_packet_for_prompt(p)
    assert "baseline.same_source_entity_30d [measured] = 4" in text
    assert "context.asset_context [missing] = —" in text


def test_packet_is_json_safe():
    import json
    json.dumps(evidence_packet(incident=_malware_incident()))


# =============================================================================
# verify_citations (T3)
# =============================================================================

def test_valid_citations_are_kept():
    p = evidence_packet()
    a = verify_citations(normalize_assessment(true_positive_model_output()), p)
    assert a["citation_errors"] == []
    assert a["hypotheses"]["malicious"]["evidence_for"][0]["cites"] == ["detection.riskScore"]


def test_unknown_path_is_removed_and_listed():
    raw = true_positive_model_output()
    raw["hypotheses"]["malicious"]["evidence_for"] = [
        _claim("risk", "detection.riskScore", "detection.made_up")]
    a = verify_citations(normalize_assessment(raw), evidence_packet())
    assert a["hypotheses"]["malicious"]["evidence_for"][0]["cites"] == ["detection.riskScore"]
    assert {"location": "hypotheses.malicious.evidence_for[0]",
            "path": "detection.made_up", "error": "unknown_path"} in a["citation_errors"]


def test_missing_status_cite_is_removed_and_listed():
    raw = true_positive_model_output()
    raw["hypotheses"]["benign"]["evidence_for"] = [
        _claim("asset is a scanner", "context.asset_context", "baseline.is_known_noisy")]
    a = verify_citations(normalize_assessment(raw), evidence_packet())
    assert a["hypotheses"]["benign"]["evidence_for"][0]["cites"] == ["baseline.is_known_noisy"]
    assert any(e["path"] == "context.asset_context" and e["error"] == "missing_status"
               for e in a["citation_errors"])


def test_claim_with_zero_valid_cites_is_dropped():
    raw = true_positive_model_output()
    raw["hypotheses"]["benign"]["evidence_for"] = [
        _claim("it is a known admin tool", "context.asset_context"),
        _claim("no cites at all"),
    ]
    a = verify_citations(normalize_assessment(raw), evidence_packet())
    assert a["hypotheses"]["benign"]["evidence_for"] == []
    dropped = [e for e in a["citation_errors"] if e["error"].startswith("uncited_claim_dropped")]
    assert len(dropped) == 2


def test_lookalike_cannot_be_ruled_out_without_valid_cites():
    raw = true_positive_model_output()
    raw["lookalike_ruled_out"] = {"lookalike": "C2 beacon", "ruled_out": True,
                                  "reason": "because", "cites": ["context.change_context"]}
    a = verify_citations(normalize_assessment(raw), evidence_packet())
    assert a["lookalike_ruled_out"]["ruled_out"] is False
    assert a["lookalike_ruled_out"]["cites"] == []


def test_evidence_checked_keeps_missing_leaves_but_drops_unknown_paths():
    raw = true_positive_model_output()
    raw["evidence_checked"] = ["context.asset_context", "bogus.path", "detection.riskScore"]
    a = verify_citations(normalize_assessment(raw), evidence_packet())
    assert a["evidence_checked"] == ["context.asset_context", "detection.riskScore"]


def test_verify_citations_does_not_mutate_input():
    a = normalize_assessment(true_positive_model_output())
    before = copy.deepcopy(a)
    verify_citations(a, evidence_packet())
    assert a == before


# =============================================================================
# Guards a-e (T4)
# =============================================================================

def _benign_raw(disposition: str, *benign_cites: str) -> dict:
    return {"proposed_disposition": disposition,
            "hypotheses": {"benign": {"evidence_for": [_claim("benign reason", *benign_cites)]}},
            "fn_cost_if_wrong": "x"}


def _run(raw: dict, packet: dict) -> dict:
    return build_assessment(raw, packet)


def _rules(a: dict) -> list[str]:
    return [g["rule"] for g in a["guard_actions"]]


def test_well_cited_true_positive_passes_unchanged():
    a = _run(true_positive_model_output(), evidence_packet())
    assert a["disposition"] == "true_positive"
    assert a["guard_actions"] == []
    TriageAssessment.model_validate(a)


def test_guard_a_missing_mandatory_evidence_blocks_false_positive():
    packet = evidence_packet(baseline=unknown_baseline())
    a = _run(_benign_raw("false_positive", "detection.createdBy"), packet)
    assert a["disposition"] == "needs_info"
    assert _rules(a)[0] == "a_missing_mandatory_evidence"
    assert a["guard_actions"][0] == {
        "rule": "a_missing_mandatory_evidence", "from": "false_positive", "to": "needs_info",
        "reason": a["guard_actions"][0]["reason"]}
    assert "baseline_measured" in a["guard_actions"][0]["reason"]


@pytest.mark.parametrize("name", [n for n, *_ in MANDATORY_EVIDENCE])
def test_guard_a_each_mandatory_item(name):
    inc = dict(SAMPLE_INCIDENT)
    parsed = copy.deepcopy(SAMPLE_PARSED_CONTEXT)
    baseline = measured_baseline()
    if name == "detection_source":
        inc.pop("createdBy")
    elif name == "resolved_entity":
        inc["title"] = "Something happened"
    elif name == "incident_time":
        inc.pop("created")
    elif name == "baseline_measured":
        baseline = unknown_baseline()
    elif name == "parser_completed":
        parsed["parser_status"] = "failed"
    packet = build_evidence_packet(inc, parsed, baseline)
    assert name in missing_mandatory_evidence(packet)
    a = _run(_benign_raw("false_positive", "detection.riskScore"), packet)
    assert a["disposition"] == "needs_info"
    assert "a_missing_mandatory_evidence" in _rules(a)


def test_guard_a_does_not_block_true_positive():
    packet = evidence_packet(baseline=unknown_baseline())
    a = _run(true_positive_model_output(), packet)
    assert a["disposition"] == "true_positive"
    assert "a_missing_mandatory_evidence" not in _rules(a)


def test_guard_b_strong_signal_floor():
    packet = evidence_packet(incident=_malware_incident())
    a = _run(_benign_raw("false_positive", "detection.createdBy", "data_quality.parser_status"),
             packet)
    assert a["disposition"] == "needs_info"
    assert _rules(a) == ["b_strong_signal_floor"]
    assert "malware" in a["guard_actions"][0]["reason"]


def test_guard_b_is_satisfied_by_a_non_missing_context_cite():
    packet = _with_context(evidence_packet(incident=_malware_incident()))
    a = _run(_benign_raw("false_positive", "detection.createdBy", "context.change_context"), packet)
    assert "b_strong_signal_floor" not in _rules(a)
    assert a["disposition"] == "false_positive"


def test_guard_b_ignores_suspicious_ip():
    """SAMPLE_INCIDENT's title contains an IP (suspicious_ip, weight 1) only."""
    packet = evidence_packet()
    assert get_leaf(packet, "rule_signals.suspicious_ip") is not None
    a = _run(_benign_raw("false_positive", "detection.createdBy"), packet)
    assert "b_strong_signal_floor" not in _rules(a)
    assert a["disposition"] == "false_positive"


def test_strong_signal_labels_constant():
    assert STRONG_SIGNAL_LABELS == {"privilege_escalation", "malware", "lateral_movement",
                                    "persistence", "exfiltration"}


def test_guard_c_benign_expected_unreachable_in_step1():
    """context.* is always missing in Step 1, so benign_expected cannot survive."""
    a = _run(_benign_raw("benign_expected", "baseline.is_known_noisy",
                         "baseline.same_source_entity_30d", "context.change_context"),
             evidence_packet())
    assert a["disposition"] == "needs_info"
    assert "c_benign_expected_requires_context" in _rules(a)
    assert any(e["path"] == "context.change_context" for e in a["citation_errors"])


def test_guard_c_benign_expected_allowed_with_real_context():
    packet = _with_context(evidence_packet())
    a = _run(_benign_raw("benign_expected", "context.change_context"), packet)
    assert a["disposition"] == "benign_expected"
    assert a["guard_actions"] == []


def test_guard_d_false_positive_needs_detection_or_data_quality_cite():
    a = _run(_benign_raw("false_positive", "baseline.same_source_entity_30d"), evidence_packet())
    assert a["disposition"] == "needs_info"
    assert _rules(a) == ["d_false_positive_requires_rule_or_data_evidence"]
    ok = _run(_benign_raw("false_positive", "data_quality.parser_confidence"), evidence_packet())
    assert ok["disposition"] == "false_positive"


def test_guard_e_true_positive_without_cited_malicious_hypothesis():
    raw = true_positive_model_output()
    raw["hypotheses"]["malicious"]["evidence_for"] = [_claim("looks bad", "made.up")]
    a = _run(raw, evidence_packet())
    assert a["disposition"] == "needs_info"
    assert _rules(a) == ["e_uncited_supporting_hypothesis"]


def test_guard_e_false_positive_needs_benign_evidence_for():
    raw = {"proposed_disposition": "false_positive",
           "hypotheses": {"malicious": {"evidence_against": [_claim("rule misfire",
                                                                    "detection.ruleId")]}}}
    a = _run(raw, evidence_packet())
    assert a["disposition"] == "needs_info"
    assert _rules(a) == ["e_uncited_supporting_hypothesis"]


def test_guards_apply_in_order_and_stop_at_needs_info():
    packet = evidence_packet(incident=_malware_incident(), baseline=unknown_baseline())
    a = _run(_benign_raw("benign_expected", "baseline.reason"), packet)
    assert _rules(a) == ["a_missing_mandatory_evidence"]   # later rules see needs_info


def test_needs_info_proposal_is_never_overridden():
    a = _run({"proposed_disposition": "needs_info"}, evidence_packet())
    assert a["disposition"] == "needs_info" and a["guard_actions"] == []


@pytest.mark.parametrize("bad", [None, "", "malicious", 42])
def test_invalid_or_absent_proposal_becomes_needs_info(bad):
    raw = {"proposed_disposition": bad} if bad is not None else {}
    a = _run(raw, evidence_packet())
    assert a["disposition"] == "needs_info"
    assert a["proposed_disposition"] == "needs_info"
    assert _rules(a) == ["schema_proposed_disposition"]


def test_guard_never_upgrades_to_a_benign_disposition():
    for proposal in ("true_positive", "needs_info"):
        a = _run({"proposed_disposition": proposal}, evidence_packet())
        assert a["disposition"] in ("true_positive", "needs_info")


def test_apply_guards_does_not_mutate_input():
    a = verify_citations(normalize_assessment(_benign_raw("false_positive", "x.y")), evidence_packet())
    before = copy.deepcopy(a)
    apply_guards(a, evidence_packet())
    assert a == before


# =============================================================================
# Uncertainty (deterministic)
# =============================================================================

def test_completeness_counts_measured_mandatory_and_core():
    total = len(MANDATORY_EVIDENCE) + len(CORE_EVIDENCE)
    # entity.kind is "inferred" for hostnames, measured for IPs; context.* missing (3).
    assert evidence_completeness(evidence_packet()) == pytest.approx((total - 3) / total)


def test_uncertainty_medium_for_complete_step1_packet():
    assert compute_uncertainty(evidence_packet(), []) == "medium"


def test_uncertainty_low_is_reachable_only_with_context():
    p = evidence_packet()
    for key in ("asset_context", "change_context", "confirmed_benign_history"):
        p = _with_context(p, key)
    assert compute_uncertainty(p, []) == "low"


def test_uncertainty_high_when_mandatory_evidence_missing():
    assert compute_uncertainty(evidence_packet(baseline=unknown_baseline()), []) == "high"


def test_each_guard_override_raises_uncertainty():
    p = evidence_packet()
    one = [{"rule": "x", "from": "a", "to": "b", "reason": "r"}]
    assert compute_uncertainty(p, one) == "high"
    full = p
    for key in ("asset_context", "change_context", "confirmed_benign_history"):
        full = _with_context(full, key)
    assert compute_uncertainty(full, one) == "medium"
    assert compute_uncertainty(full, one * 5) == "high"


def test_model_reported_confidence_is_ignored():
    raw = true_positive_model_output()
    raw["confidence"] = 0.99
    raw["uncertainty"] = "low"
    a = _run(raw, evidence_packet())
    assert a["uncertainty"] == "medium"
    assert "confidence" not in a


def test_assessment_serializes_guard_from_key():
    a = _run(_benign_raw("false_positive", "baseline.reason"), evidence_packet())
    assert "from" in a["guard_actions"][0] and "from_" not in a["guard_actions"][0]
