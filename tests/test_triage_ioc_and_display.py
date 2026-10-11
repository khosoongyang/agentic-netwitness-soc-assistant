"""tests/test_triage_ioc_and_display.py -- Triage-stage restoration coverage
for two pieces of agents/triage/soc_triage_agent.py that had zero prior test
coverage (grepped: no existing test file references them):

  1. _resolve_ioc_matches() -- the deterministic index/name resolver that
     turns the IOC-checklist LLM call's `matched_iocs` entries (which may be
     an int, a numeric string, "IOC 3", "#3", a comma-separated list, or a
     bare IOC name) into 0-based positions in the real IOC_AVAILABILITY /
     IOC_CONFIDENTIALITY / IOC_INTEGRITY checklists. This is the exact
     function the IOC Checklist phase (_run_ioc) depends on to avoid
     silently reading "0 IOCs matched" when the model doesn't emit a clean
     integer list -- see its own docstring.

  2. render_triage_trace() / format_ticket_display() -- the markdown
     formatters that produced the historical "SOC Triage Report" / "Triage
     Ticket" output shown in the pre-restoration screenshots. These are
     pure, deterministic functions (no LLM, no DB); this module locks in
     that the exact historical section labels/fields are still produced
     from a synthetic trace/ticket, so a future edit to soc_triage_agent.py
     can't silently regress the section names an analyst (or an exported
     ticket document) depends on.

No LLM/network/DB access anywhere in this module.
"""
from __future__ import annotations

from agents.triage.soc_triage_agent import (
    ALL_IOCS,
    IOC_AVAILABILITY,
    IOC_CONFIDENTIALITY,
    IOC_INTEGRITY,
    SOC_CLASSIFICATION_TABLE,
    TriageAgent,
    _build_ioc_findings,
    _resolve_ioc_matches,
    format_ticket_display,
    render_triage_trace,
)


# =============================================================================
# _resolve_ioc_matches
# =============================================================================

_IOC_LIST = [
    {"ioc": "Unknown traffic originating from/terminating on the device"},  # 0
    {"ioc": "Unexplained changes from privileged accounts"},                # 1
    {"ioc": "Anomalous file transfers"},                                    # 2
]


def test_none_input_returns_empty_list():
    assert _resolve_ioc_matches(None, _IOC_LIST) == []


def test_plain_integers_are_one_indexed_to_zero_based_positions():
    # The checklist is presented to the LLM 1-indexed ("[1] ...", "[2] ...");
    # the model's matched_iocs integers are in that same 1-indexed space.
    assert _resolve_ioc_matches([1, 2], _IOC_LIST) == [0, 1]


def test_numeric_strings_and_bracketed_forms_resolve():
    assert _resolve_ioc_matches(["3"], _IOC_LIST) == [2]
    assert _resolve_ioc_matches(["[2]"], _IOC_LIST) == [1]


def test_ioc_number_and_hash_prefixed_tokens_resolve():
    assert _resolve_ioc_matches(["IOC 2"], _IOC_LIST) == [1]
    assert _resolve_ioc_matches(["#3"], _IOC_LIST) == [2]


def test_comma_and_word_separated_numeric_tokens_resolve():
    assert _resolve_ioc_matches(["1, 3"], _IOC_LIST) == [0, 2]
    assert _resolve_ioc_matches(["2 and 3"], _IOC_LIST) == [1, 2]


def test_bare_ioc_name_resolves_by_exact_and_substring_match():
    assert _resolve_ioc_matches(
        ["Unexplained changes from privileged accounts"], _IOC_LIST) == [1]
    # substring: model paraphrases/truncates the checklist name
    assert _resolve_ioc_matches(["privileged accounts"], _IOC_LIST) == [1]


def test_a_single_scalar_item_is_accepted_not_just_a_list():
    assert _resolve_ioc_matches(2, _IOC_LIST) == [1]
    assert _resolve_ioc_matches("3", _IOC_LIST) == [2]


def test_out_of_range_indices_are_excluded():
    assert _resolve_ioc_matches([0, 99, -5], _IOC_LIST) == []


def test_duplicate_indices_across_forms_are_deduplicated_and_order_preserved():
    assert _resolve_ioc_matches([1, "1", "IOC 1", "#1"], _IOC_LIST) == [0]
    assert _resolve_ioc_matches([2, 1, 3], _IOC_LIST) == [1, 0, 2]


def test_bool_items_are_skipped_not_treated_as_int_one_or_zero():
    # bool is an int subclass in Python -- must not silently resolve to
    # index 0/-1 (True == 1, False == 0).
    assert _resolve_ioc_matches([True, False], _IOC_LIST) == []


def test_blank_and_unmatched_tokens_are_ignored():
    assert _resolve_ioc_matches(["", "   ", "nothing recognisable here"], _IOC_LIST) == []


# =============================================================================
# Structured IOC findings (_build_ioc_findings / _run_ioc)
# =============================================================================

# The Windows Update CTL lookup from the Triage screenshot: high-risk alert,
# external DNS, but a well-known benign destination.
_CTL_INCIDENT = {
    "id": "INC-1",
    "title": "High Risk Alerts: NetWitness Packets",
    "alertMeta": {"SourceIp": ["192.168.10.207"], "DestinationIp": ["4.175.87.197"]},
    "alerts": [{"name": "DNS query to external resolver", "domain": "ctldl.windowsupdate.com",
                "events": [{"destination": {"port": 53}}]}],
}

_CTL_FINDING = {
    "ioc": 1,
    "title": "Potential unauthorised external data communication",
    "evidence": {"ip.src": "192.168.10.207", "ip.dst": "4.175.87.197",
                 "port.dst": "53", "domain": "ctldl.windowsupdate.com",
                 "bytes.out": "9999999"},
    "cia_reasoning": ("The endpoint sent DNS to an unverified external resolver. DNS can carry "
                      "hostnames or encoded data out of the network, which would be an "
                      "unauthorised disclosure."),
    "not_established": "Confirms outbound DNS occurred, not that sensitive data was transmitted.",
    "why_suspicious": "DNS sent directly to an external IP instead of the internal resolver.",
    "benign_explanation": "ctldl.windowsupdate.com is Microsoft's certificate trust list endpoint.",
    "would_confirm": ["bytes.out well above DNS norms", "high-entropy subdomains"],
    "impact": "Potential",
    "confidence": "LOW",
}


def _haystack(incident: dict) -> str:
    from agents.triage.soc_triage_agent import _leaf_strings
    return "\n".join(_leaf_strings(incident)).lower()


def test_finding_objects_resolve_and_normalise_levels():
    [f] = _build_ioc_findings([_CTL_FINDING], IOC_CONFIDENTIALITY, _haystack(_CTL_INCIDENT))
    assert f["ioc"] == "Anomalous outbound or internal network communication"
    assert f["index"] == 1
    assert f["impact"] == "potential"
    assert f["confidence"] == "low"
    assert f["would_confirm"] == ["bytes.out well above DNS norms", "high-entropy subdomains"]


def test_evidence_values_absent_from_the_incident_are_marked_unverified():
    [f] = _build_ioc_findings([_CTL_FINDING], IOC_CONFIDENTIALITY, _haystack(_CTL_INCIDENT))
    assert f["evidence"] == {"ip.src": "192.168.10.207", "ip.dst": "4.175.87.197",
                             "port.dst": "53", "domain": "ctldl.windowsupdate.com"}
    assert f["unverified_evidence"] == {"bytes.out": "9999999"}


def test_evidence_match_is_whole_token_not_substring():
    # "4.175.87.19" is a prefix of the real IP, not the same value.
    [f] = _build_ioc_findings([{"ioc": 1, "evidence": {"ip.dst": "4.175.87.19"}}],
                              IOC_CONFIDENTIALITY, _haystack(_CTL_INCIDENT))
    assert f["evidence"] == {}
    assert f["unverified_evidence"] == {"ip.dst": "4.175.87.19"}


def test_legacy_integer_matches_still_produce_bare_findings():
    findings = _build_ioc_findings([1, 3], IOC_CONFIDENTIALITY, "")
    assert [f["index"] for f in findings] == [1, 3]
    assert all(f["impact"] == "" and f["evidence"] == {} for f in findings)


def test_unknown_levels_are_dropped_and_duplicates_collapsed():
    findings = _build_ioc_findings(
        [{"ioc": 2, "impact": "severe", "confidence": "certain"}, 2, "#2"],
        IOC_CONFIDENTIALITY, "")
    assert len(findings) == 1
    assert findings[0]["impact"] == "" and findings[0]["confidence"] == ""


def _ioc_agent(model_json: dict) -> TriageAgent:
    import json
    agent = TriageAgent.__new__(TriageAgent)
    agent.progress_fn = None
    agent.thinking_container = None
    agent.llm = None
    agent._call = lambda messages, label: json.dumps(model_json)
    return agent


_CTL_MODEL_JSON = {
    "confidentiality": {
        "status": "potential",
        "summary": "Information may leave the trusted environment via an unverified DNS resolver.",
        "matched_iocs": [_CTL_FINDING]},
    "integrity": {
        "status": "no_evidence",
        "summary": "No modification of files, accounts, configuration or DNS settings was observed."},
    "availability": {
        "status": "No Evidence",
        "summary": "No service interruption or resource exhaustion was observed."},
}


def test_run_ioc_exposes_findings_rollup_and_composed_reasoning():
    out = _ioc_agent(_CTL_MODEL_JSON)._run_ioc(_CTL_INCIDENT)
    conf = out["per_category"]["confidentiality"]
    assert conf["matched_ioc_names"] == ["Anomalous outbound or internal network communication"]
    assert conf["matched_indices"] == [1]
    assert conf["status"] == "potential"
    assert conf["confidence"] == "low"
    f = conf["findings"][0]
    assert f["title"] == "Potential unauthorised external data communication"
    assert "unauthorised disclosure" in f["cia_reasoning"]
    assert f["not_established"].startswith("Confirms outbound DNS occurred")
    assert f["evidence"]["domain"] == "ctldl.windowsupdate.com"
    # Composed for the markdown trace / observability / Risk phase.
    assert conf["reasoning"].startswith(
        "Potential unauthorised external data communication (potential, low confidence):")
    assert "Not established:" in conf["reasoning"]
    assert "Benign explanation:" in conf["reasoning"]
    assert "bytes.out=9999999" not in conf["reasoning"]
    assert out["total_ioc_count"] == 1


def test_every_cia_property_gets_an_assessment_and_reaches_the_risk_phase():
    out = _ioc_agent(_CTL_MODEL_JSON)._run_ioc(_CTL_INCIDENT)
    integ = out["per_category"]["integrity"]
    avail = out["per_category"]["availability"]
    assert integ["status"] == "no_evidence" and integ["findings"] == []
    assert avail["status"] == "no_evidence"   # "No Evidence" normalised
    lines = out["ioc_summary"].splitlines()
    assert len(lines) == 3
    assert any(l.startswith("[CONFIDENTIALITY] Potential impact — Information may leave") for l in lines)
    assert any(l.startswith("[INTEGRITY] No evidence — No modification of files") for l in lines)
    assert any(l.startswith("[AVAILABILITY] No evidence — No service interruption") for l in lines)


def test_an_impact_claimed_without_a_checklist_finding_is_downgraded():
    out = _ioc_agent({
        "confidentiality": {"status": "confirmed", "summary": "Alert says exfiltration.",
                            "matched_iocs": []},
        "integrity": {"status": "insufficient evidence", "summary": "Only one packet session."},
        "availability": {"matched_iocs": []},
    })._run_ioc(_CTL_INCIDENT)
    assert out["per_category"]["confidentiality"]["status"] == "insufficient_evidence"
    assert out["per_category"]["integrity"]["status"] == "insufficient_evidence"
    assert out["per_category"]["availability"]["status"] == "no_evidence"


def test_render_triage_trace_shows_unmatched_property_assessments():
    out = _ioc_agent(_CTL_MODEL_JSON)._run_ioc(_CTL_INCIDENT)
    rendered = render_triage_trace([{"step": "IOC Checklist", "status": "ok",
                                     "total_ioc_count": 1, "per_category": out["per_category"]}])
    assert "**Integrity:** No evidence — No modification of files" in rendered
    assert "**Confidentiality:** Anomalous outbound or internal network communication" in rendered


def test_run_ioc_keeps_model_reasoning_for_the_legacy_schema():
    agent = _ioc_agent({
        "availability": {"matched_iocs": [], "reasoning": ""},
        "confidentiality": {"matched_iocs": [1], "reasoning": "Outbound to an external IP."},
        "integrity": {"matched_iocs": []},
    })
    out = agent._run_ioc(_CTL_INCIDENT)
    conf = out["per_category"]["confidentiality"]
    assert conf["reasoning"] == "Outbound to an external IP."
    assert out["ioc_summary"] == ("[CONFIDENTIALITY] Anomalous outbound or internal network "
                                  "communication — Outbound to an external IP.")


# =============================================================================
# render_triage_trace() -- the historical "SOC Triage Report" markdown
# =============================================================================

def _sample_trace() -> list[dict]:
    return [
        {"step": "IOC Checklist", "status": "ok", "total_ioc_count": 2,
         "ioc_summary": "[CONFIDENTIALITY] Unknown traffic — HTTP to internal host",
         "matched_metakeys": ["ip.dst", "port.dst"],
         "per_category": {
             "confidentiality": {
                 "matched_ioc_names": ["Unknown traffic originating from/terminating on the device"],
                 "reasoning": "Unusual HTTP traffic to an internal host on port 8888."},
             "integrity": {
                 "matched_ioc_names": ["Odd device/platform behaviour"],
                 "reasoning": "Unknown binary running from a nonstandard path."},
         }},
        {"step": "Risk Rating", "status": "ok",
         "data": {"likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                  "likelihood_adverse_impact": "High", "overall_risk": "High",
                  "rationale": "Suspicious execution with a privileged user context."}},
        {"step": "SOC Classification", "status": "ok",
         "data": {"classification": "high", "incident_category": "Compromised asset (non-critical)",
                  "response_time": "30 to 60 minutes",
                  "summary": "Suspicious execution of a masqueraded binary.",
                  "recommended_actions": ["Isolate the affected host.",
                                          "Validate the legitimacy of the binary."]}},
    ]


def test_render_triage_trace_reproduces_historical_phase_headings():
    rendered = render_triage_trace(_sample_trace())
    assert "Phase — IOC Checklist" in rendered
    assert "Phase — Risk Rating" in rendered
    assert "Phase — SOC Classification" in rendered


def test_render_triage_trace_ioc_section_shows_count_summary_and_category_findings():
    rendered = render_triage_trace(_sample_trace())
    assert "Total IOCs matched:** 2" in rendered
    assert "Meta-Keys:** `ip.dst`, `port.dst`" in rendered
    assert "Confidentiality:** Unknown traffic originating from/terminating on the device" in rendered
    assert "Integrity:** Odd device/platform behaviour" in rendered


def test_render_triage_trace_risk_rating_table_has_all_four_dimensions():
    rendered = render_triage_trace(_sample_trace())
    assert "Likelihood of Initiation | **High**" in rendered
    assert "Likelihood of Occurrence | **Medium**" in rendered
    assert "Likelihood of Adverse Impact | **High**" in rendered
    assert "**Overall Risk** | **High**" in rendered


def test_render_triage_trace_classification_section_has_all_fields():
    rendered = render_triage_trace(_sample_trace())
    assert "**Classification:** HIGH" in rendered
    assert "**Category:** Compromised asset (non-critical)" in rendered
    assert "**Response Time:** 30 to 60 minutes" in rendered
    assert "Isolate the affected host." in rendered


# =============================================================================
# format_ticket_display() -- the historical "Triage Ticket" markdown table
# =============================================================================

def _sample_ticket() -> dict:
    return {
        "unc": "#00059A", "incident_id": "INC-52993",
        "title": "High Risk Alerts: NetWitness Endpoint",
        "incident_time": "2025-07-21 06:20:39 UTC", "created_at": "2026-07-26T16:56:30.739456",
        "classification": "HIGH", "incident_category": "Compromised asset (non-critical)",
        "mitre_tactic": "Execution", "mitre_technique": "T1059 Command and Scripting Interpreter",
        "initial_response_time": "30 to 60 minutes", "matched_ioc_count": 6,
        "risk_rating": {"likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                        "likelihood_adverse_impact": "High", "overall_risk": "High",
                        "rationale": ""},
        "summary": "Suspicious execution of a masqueraded binary.",
        "recommended_actions": ["Isolate the affected host.",
                                "Validate the legitimacy of the binary."],
        "metakeys": ["ip.dst", "port.dst", "process.name"],
    }


def test_format_ticket_display_header_row_has_all_historical_fields():
    rendered = format_ticket_display(_sample_ticket())
    for label in ("Incident ID", "Title", "Incident Time", "Ticket Created",
                  "Classification", "Category", "MITRE Tactic", "MITRE Technique",
                  "Initial Response Time", "IOCs Matched"):
        assert f"**{label}**" in rendered
    assert "INC-52993" in rendered
    assert "**HIGH**" in rendered
    assert "T1059 Command and Scripting Interpreter" in rendered
    assert "| 6 |" in rendered


def test_format_ticket_display_has_risk_rating_summary_actions_and_metakeys_sections():
    rendered = format_ticket_display(_sample_ticket())
    assert "### Risk Rating" in rendered
    assert "### Triage Summary" in rendered
    assert "Suspicious execution of a masqueraded binary." in rendered
    assert "### Recommended Actions" in rendered
    assert "- Isolate the affected host." in rendered
    assert "### Matched Meta-Keys" in rendered
    assert "`ip.dst`, `port.dst`, `process.name`" in rendered


def test_format_ticket_display_include_header_false_drops_only_the_unc_header():
    with_header = format_ticket_display(_sample_ticket(), include_header=True)
    without_header = format_ticket_display(_sample_ticket(), include_header=False)
    assert "## \U0001f7e0 Ticket `#00059A`" in with_header
    assert "Ticket `#00059A`" not in without_header
    assert not without_header.startswith("---")
    # Everything after the header line is byte-identical.
    assert with_header.endswith(without_header)


# =============================================================================
# CIA Triad IOC Checklists & Classification Table Verification
# =============================================================================

def test_cia_triad_checklists_structure():
    assert len(IOC_CONFIDENTIALITY) == 8
    assert len(IOC_INTEGRITY) == 11
    assert len(IOC_AVAILABILITY) == 6
    assert ALL_IOCS["confidentiality"] == IOC_CONFIDENTIALITY
    assert ALL_IOCS["integrity"] == IOC_INTEGRITY
    assert ALL_IOCS["availability"] == IOC_AVAILABILITY

    for cat_name, ioc_list in ALL_IOCS.items():
        for item in ioc_list:
            assert "ioc" in item and isinstance(item["ioc"], str) and item["ioc"]
            assert "desc" in item and isinstance(item["desc"], str) and item["desc"]
            assert "metakeys" in item and isinstance(item["metakeys"], list) and len(item["metakeys"]) > 0


def test_cia_confidentiality_does_not_assume_known_bad_ip():
    # Verify no rubric entry assumes "known bad IPs" without threat intel
    for item in IOC_CONFIDENTIALITY:
        assert "known bad IPs" not in item["ioc"]
    # Check that unverified outbound communication exists
    ioc_names = [item["ioc"] for item in IOC_CONFIDENTIALITY]
    assert "Anomalous outbound or internal network communication" in ioc_names


def test_soc_classification_table_includes_unverified_categories():
    assert "Suspicious Outbound Network Activity (Unverified)" in SOC_CLASSIFICATION_TABLE["high"]["categories"]
    assert "Suspicious Outbound Network Activity (Unverified)" in SOC_CLASSIFICATION_TABLE["medium"]["categories"]
    assert "Anomalous External Traffic / Unconfirmed C2" in SOC_CLASSIFICATION_TABLE["medium"]["categories"]
    assert "Uncorrelated Host Alert" in SOC_CLASSIFICATION_TABLE["medium"]["categories"]


