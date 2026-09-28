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
