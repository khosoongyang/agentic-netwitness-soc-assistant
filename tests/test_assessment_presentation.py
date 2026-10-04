"""Headline-assessment presentation across the Aegis workflow stages.

Backend: case_context.unified_verdict.signals (case_view_service.py::
_unified_verdict_signals) must republish EVERY signal aggregate_verdict()
evaluated — including LOW/level-0 and absent/unavailable ones — with an
analyst-facing display name that names base severity after its real source
(Triage Classification / NetWitness Severity), without changing the verdict.

Frontend: the real renderers in frontend/js/assessment.js and
frontend/js/pages/workspace.js are imported under Node (no DOM needed) and
checked for the headline/details split, scoped labels, and the Case context
"Investigation Severity" rename. Fixtures mirror INC-53027 (NetWitness HIGH,
Triage MEDIUM, Threat Intelligence Low/25, Investigation High -> Unified
Verdict HIGH).
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from agents.investigation.tools.triage_verdict import aggregate_verdict
from backend.services import case_view_service as cv


ROOT = Path(__file__).resolve().parent.parent
ASSESSMENT_JS = ROOT / "frontend" / "js" / "assessment.js"
WORKSPACE_JS = ROOT / "frontend" / "js" / "pages" / "workspace.js"

NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

SIGNAL_KEYS = [
    "base_severity", "asset_criticality", "internal_ioc_correlation",
    "external_threat_intel", "investigation_severity",
]


# ══════════════════════════════════════════════════════════════════════════
# Fixtures (shaped like INC-53027's persisted results)
# ══════════════════════════════════════════════════════════════════════════

INCIDENT = {"id": "INC-T1", "title": "Outbound to flagged IP", "severity": "High",
            "alertMeta": {"SourceIp": ["192.168.10.210"], "DestinationIp": ["188.40.170.197"]}}

TRIAGE = {"ticket": {
    "incident_id": "INC-T1", "classification": "MEDIUM", "incident_category": "Unknown Source IP",
    "risk_rating": {"likelihood_initiation": "Medium", "likelihood_occurrence": "Medium",
                    "likelihood_adverse_impact": "Medium", "overall_risk": "Medium",
                    "rationale": "Single network observation with no endpoint evidence."},
}}

TI = {"enrichment_risk_level": "Low", "enrichment_risk_score": 25,
      "enrichment_risk_reasons": ["VirusTotal reported 9 malicious detection(s) for IP 188.40.170.197."],
      "recommended_next_action": "No elevated enrichment risk was identified.",
      "threat_intelligence": {
          "iocs": {"file_hash": None, "ip_indicators": ["188.40.170.197"], "domain_indicators": [],
                   "powershell_analysis": {"decode_status": "not_present",
                                           "decoded_command_summary": "No PowerShell activity."}},
          "virustotal": {
              "file_hash": {"status": "skipped", "indicator": None, "reason": "No file hash was available."},
              "ip_results": [{"indicator": "188.40.170.197", "status": "completed",
                              "malicious": 9, "suspicious": 0, "reputation": -3}],
              "domain_results": [],
          },
          "abuseipdb": {"ip_results": [{"indicator": "188.40.170.197", "status": "completed",
                                        "abuse_confidence_score": 0, "total_reports": 0,
                                        "country_code": "DE", "isp": "Hetzner"}]},
          "alienvault_otx": {"otx_results": [{"indicator": "188.40.170.197", "indicator_type": "IPv4",
                                              "status": "completed", "pulse_count": 0}]},
      }}

TI_NO_INDICATORS = {**TI, "enrichment_risk_score": 0, "enrichment_risk_reasons": [],
                    "threat_intelligence": {
                        "iocs": {"file_hash": None, "ip_indicators": [], "domain_indicators": []},
                        "virustotal": {"file_hash": {"status": "skipped", "reason": "No file hash was available."},
                                       "ip_results": [], "domain_results": []},
                        "abuseipdb": {"ip_results": []}, "alienvault_otx": {"otx_results": []},
                    }}

INVESTIGATION = {
    "status": "completed", "summary": "Suspicious outbound connection.", "severity": "High",
    "severity_divergence": {"triage": "Medium", "investigation": "High", "direction": "upgraded"},
    "investigation_analysis": {
        "severity": "High", "confidence": "Medium",
        "severity_justification": "High because of a threat-enriched outbound connection.",
        "confidence_justification": "Medium because endpoint telemetry is missing.",
        "business_impact_checklist": {"critical_system": "unknown", "essential_service": "unknown",
                                      "data_sensitivity": "unknown", "operational_impact": "unknown"},
    },
}

IOC_CORR = {"available": True, "results": [{"confidence": "medium", "open_cases": []},
                                            {"confidence": "low", "open_cases": []}]}


def _state(*, triage=TRIAGE, ti=TI, investigation=INVESTIGATION, ioc=IOC_CORR,
           ti_status="Complete", inv_status="Awaiting Approval") -> dict:
    return {
        "severity": "HIGH", "status": "New", "workflow_status": "Awaiting Approval",
        "triage_result_json": json.dumps(triage) if triage else None,
        "threat_intel_status": ti_status if ti else "Pending",
        "threat_intel_result_json": json.dumps(ti) if ti else None,
        "investigation_status": inv_status if investigation else "Pending",
        "investigation_result_json": json.dumps(investigation) if investigation else None,
        "ioc_correlation_status": "Complete" if ioc is not None else None,
        "ioc_correlation_result_json": json.dumps(ioc) if ioc is not None else None,
    }


def _unified(state: dict, incident: dict = INCIDENT) -> dict:
    return cv.build_overview(state, incident, "INC-T1", "run-1")["case_context"]["unified_verdict"]


def _by_key(signals: list[dict]) -> dict:
    return {s["key"]: s for s in signals}


# ══════════════════════════════════════════════════════════════════════════
# Backend: unified_verdict.signals
# ══════════════════════════════════════════════════════════════════════════

def test_all_five_signals_exposed_in_evaluation_order():
    uv = _unified(_state())
    assert [s["key"] for s in uv["signals"]] == SIGNAL_KEYS
    assert uv["value"] == "HIGH"
    for s in uv["signals"]:
        assert set(s) == {"key", "display_name", "value", "level", "status", "counted",
                          "source", "source_stage", "detail", "reason"}


def test_low_signals_are_not_omitted():
    uv = _unified(_state())
    signals = _by_key(uv["signals"])
    ti = signals["external_threat_intel"]
    assert ti["display_name"] == "Threat Intelligence Risk"
    assert ti["value"] == "LOW" and ti["status"] == "scored" and ti["counted"] is True
    assert ti["level"] == 0
    # Level-0 signals are still absent from the legacy `reasons` list — which
    # is exactly why `signals` exists.
    assert not any(r.startswith("external threat intel") for r in uv["reasons"])
    assert signals["asset_criticality"]["status"] == "scored"
    assert signals["asset_criticality"]["value"]


def test_base_severity_named_after_triage_source():
    base = _by_key(_unified(_state())["signals"])["base_severity"]
    assert base["display_name"] == "Triage Classification"
    assert base["value"] == "MEDIUM"
    assert base["source_stage"] == "triage"


def test_base_severity_named_after_netwitness_source_without_triage():
    base = _by_key(_unified(_state(triage=None))["signals"])["base_severity"]
    assert base["display_name"] == "NetWitness Severity"
    assert base["value"] == "HIGH"
    assert base["source_stage"] == "raw_incident"


def test_unrated_base_severity_is_represented_accurately():
    incident = {k: v for k, v in INCIDENT.items() if k != "severity"}
    base = _by_key(_unified(_state(triage=None), incident)["signals"])["base_severity"]
    assert base["display_name"] == "NetWitness Severity"
    assert base["value"] == "UNRATED"
    assert base["status"] == "scored"


def test_base_severity_never_exposed_as_a_label():
    for state in (_state(), _state(triage=None)):
        uv = _unified(state)
        assert all(s["display_name"] != "Base Severity" for s in uv["signals"])
        assert all("base severity" not in s["display_name"].lower() for s in uv["signals"])


def test_absent_threat_intel_and_not_evaluated_investigation():
    uv = _unified(_state(ti=None, investigation=None))
    signals = _by_key(uv["signals"])
    assert [s["key"] for s in uv["signals"]] == SIGNAL_KEYS
    ti = signals["external_threat_intel"]
    assert ti["status"] == "absent" and ti["value"] is None and ti["counted"] is False
    assert "not yet available" in ti["reason"]
    inv = signals["investigation_severity"]
    assert inv["status"] == "not_evaluated" and inv["value"] is None and inv["counted"] is False
    assert inv["reason"]


def test_unavailable_ioc_correlation_is_represented_accurately():
    ioc = _by_key(_unified(_state(ioc={"available": False, "reason": "corpus offline"}))["signals"])[
        "internal_ioc_correlation"]
    assert ioc["status"] == "unavailable"
    assert ioc["value"] is None and ioc["counted"] is False
    assert ioc["detail"] == "corpus offline"


def test_aggregate_verdict_output_is_unchanged():
    """aggregate_verdict() is pinned for the INC-53027-shaped fixture, and the
    signal exposure neither mutates it nor disagrees with it."""
    verdict = aggregate_verdict(INCIDENT, triage_result=TRIAGE, ti_result=TI,
                                investigation_result=INVESTIGATION, ioc_correlation_result=IOC_CORR)
    snapshot = copy.deepcopy(verdict)
    assert verdict["level"] == "HIGH"
    assert [(s["name"], s["level"], s["label"]) for s in verdict["signals"]] == [
        ("base severity", 1, "MEDIUM"),
        ("asset criticality", verdict["signals"][1]["level"], verdict["signals"][1]["label"]),
        ("internal IOC correlation", 2, "medium internal confidence"),
        ("external threat intel", 0, "low"),
        ("investigation severity", 2, "HIGH"),
    ]

    signals = cv._unified_verdict_signals(verdict)
    assert verdict == snapshot
    assert [s["level"] for s in signals] == [s["level"] for s in verdict["signals"]]

    uv = _unified(_state())
    assert uv["value"] == verdict["level"]
    assert uv["reasons"] == [f"{s['name']}: {s['label']}" for s in verdict["rationale"] if s["level"] > 0]
    assert uv["source_stages"] == [s["name"].replace(" ", "_") for s in verdict["signals"]]


def test_signals_reach_the_browser_through_the_case_detail_api(tmp_path, monkeypatch):
    """Regression for "The verdict signal breakdown is not available": the
    field must survive build_case_view() -> get_case_detail() -> JSON
    serialisation, i.e. exactly what GET /api/cases/<id> sends the page."""
    from backend.app import create_app
    from workflow import state_store as wss

    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    wss.db_init()
    state = _state()
    with wss.db_connect() as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, status, raw_json) VALUES (?, ?, ?, ?, ?)",
            ("INC-T1", INCIDENT["title"], "HIGH", "New", json.dumps(INCIDENT)))
        columns = {k: v for k, v in state.items() if k not in ("severity", "status")}
        columns["run_id"] = "run-1"
        connection.execute(
            f"UPDATE incidents SET {', '.join(f'{k} = ?' for k in columns)} WHERE id = ?",
            (*columns.values(), "INC-T1"))
        connection.commit()

    app = create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": wss.DB_FILE})
    response = app.test_client().get("/api/cases/INC-T1")
    assert response.status_code == 200
    uv = response.get_json()["workspace"]["overview"]["case_context"]["unified_verdict"]
    assert uv["value"] == "HIGH"
    assert [s["key"] for s in uv["signals"]] == SIGNAL_KEYS
    assert [s["display_name"] for s in uv["signals"]] == [
        "Triage Classification", "Asset Criticality", "Internal IOC Correlation",
        "Threat Intelligence Risk", "Investigation Severity"]
    assert _by_key(uv["signals"])["external_threat_intel"]["value"] == "LOW"


def test_key_findings_use_scoped_signal_names():
    overview = cv.build_overview(_state(), INCIDENT, "INC-T1", "run-1")
    titles = [f["title"] for f in overview["key_findings"] if f.get("origin") == "deterministic_signal"]
    assert any(t.startswith("Triage Classification — ") for t in titles)
    assert not any("Base Severity" in t for t in titles)


# ══════════════════════════════════════════════════════════════════════════
# Frontend renderers (Node)
# ══════════════════════════════════════════════════════════════════════════

_JS_RENDER = """
const ws = await import(__WORKSPACE__);
const as = await import(__ASSESSMENT__);
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const d = JSON.parse(input);
const out = {};
if (d.parsing) out.parsing = ws.parsingAssessment(d.parsing);
if (d.ticket) out.triage = ws.triageAssessment(d.ticket);
if (d.ti) {
  out.ti = ws.tiAssessment(d.ti);
  out.tiResults = ws.tiProviderResults(d.ti.threat_intelligence || {});
}
if (d.workspace) out.invOverview = ws.investigationOverviewTab(d.workspace);
if (d.inv) out.inv = ws.investigationAssessment(d.inv);
if (d.verdict) out.verdict = as.unifiedVerdictCard(d.verdict);
if (d.detail) out.caseContext = ws.caseContext(d.detail);
process.stdout.write(JSON.stringify(out));
"""


def _render(payload: dict) -> dict:
    script = (_JS_RENDER.replace("__WORKSPACE__", json.dumps(WORKSPACE_JS.as_uri()))
              .replace("__ASSESSMENT__", json.dumps(ASSESSMENT_JS.as_uri())))
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", script],
        input=json.dumps(payload), capture_output=True, text=True,
        encoding="utf-8", timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _headline(html: str) -> str:
    """The default (collapsed) view: everything before the <details>."""
    return html.split("<details", 1)[0]


PARSING_NA = {
    "alert_summary": {"severity": "High", "risk_score": 70},
    "powershell_analysis": {"risk_assessment": {"risk_level": "Low", "risk_score": 0}},
    "data_quality": {"missing_optional_fields": ["session_id", "record_id"],
                     "not_applicable_fields": ["hostname"], "normalised_event_count": 0,
                     "warnings": ["Missing context-relevant parsing fields: protocol"]},
    "parser_metadata": {"normalisation_status": "success"},
}


@requires_node
def test_parsing_headline_and_details():
    html = _render({"parsing": PARSING_NA})["parsing"]
    head = _headline(html)
    assert "NetWitness Severity" in head
    assert "Parser Confidence" not in head
    assert "PowerShell Risk" not in head
    assert "Parser Severity" not in html and "Parsing Risk" not in html
    assert "View parsing details" in html and "Hide parsing details" in html
    for label in ("NetWitness Risk Score", "PowerShell Risk", "PowerShell Risk Score",
                  "Normalisation Status",
                  "Missing Optional Fields", "Not Applicable Fields", "Normalised Event Count", "Warnings"):
        assert label in html, label
    assert "Parser Confidence" not in html
    assert "Parser Confidence Score" not in html
    assert "Confidence Explanation" not in html


@requires_node
def test_parsing_details_omit_fields_that_do_not_exist():
    html = _render({"parsing": {"alert_summary": {"severity": "High"}}})["parsing"]
    assert "PowerShell Risk" not in html
    assert "Parser Confidence" not in html
    assert "Parser Confidence Score" not in html


@requires_node
def test_triage_headline_and_details():
    html = _render({"ticket": TRIAGE["ticket"]})["triage"]
    head = _headline(html)
    assert "Overall Triage Risk" in head and "severity-medium" in head
    assert "Triage Classification" not in head
    assert "View assessment details" in html and "Hide assessment details" in html
    for label in ("Triage Assessment", "Triage Classification", "Incident Category", "Risk Assessment",
                  "Initiation Risk", "Occurrence Risk", "Adverse Impact", "Assessment Rationale"):
        assert label in html, label
    assert "Unknown Source IP" in html
    assert "Triage Severity" not in html and "Confidence" not in html
    assert "Why " not in html and ">Classification<" not in html


@requires_node
def test_triage_overall_risk_is_headline_only():
    html = _render({"ticket": TRIAGE["ticket"]})["triage"]
    assert html.count("Overall Triage Risk") == 1
    assert "Overall Triage Risk" in _headline(html)


@requires_node
def test_triage_risk_definitions_are_static_notes_not_findings():
    html = _render({"ticket": TRIAGE["ticket"]})["triage"]
    risk = html.split("Risk Assessment", 1)[1].split("Assessment Rationale", 1)[0]
    assert risk.count('class="assessment-row-note"') == 3
    assert "Likelihood that an adversary initiates the threat event." in risk
    # The classification rows carry no definition column.
    triage = html.split("Triage Assessment", 1)[1].split("Risk Assessment", 1)[0]
    assert "assessment-row-note" not in triage


@requires_node
def test_triage_rationale_is_stored_text_verbatim():
    ticket = copy.deepcopy(TRIAGE["ticket"])
    ticket["risk_rating"]["rationale"] = "First paragraph <b>as stored</b>.\n\nSecond paragraph."
    html = _render({"ticket": ticket})["triage"]
    assert "<p>First paragraph &lt;b&gt;as stored&lt;/b&gt;.</p><p>Second paragraph.</p>" in html


@requires_node
def test_triage_omits_absent_risk_dimensions():
    ticket = copy.deepcopy(TRIAGE["ticket"])
    del ticket["risk_rating"]["likelihood_adverse_impact"]
    del ticket["risk_rating"]["rationale"]
    html = _render({"ticket": ticket})["triage"]
    assert "Adverse Impact" not in html and "Assessment Rationale" not in html


@requires_node
def test_threat_intel_headline_and_details():
    html = _render({"ti": TI})["ti"]
    head = _headline(html)
    # Score and level are one compact value: "25 (LOW)".
    assert "Risk Score" in head
    assert '25 <span class="ti-risk-level ti-risk-low">(LOW)</span>' in head
    assert "Risk level" not in html
    # Removed: the separate risk headline row and the Aegis Assessment caption.
    assert "Threat Intelligence Risk" not in html and "assessment-headline" not in html
    assert "Aegis Assessment" not in html
    # Removed from the card: recommended action, workflow line and the
    # scoring-factors disclosure.
    assert "<details" not in html
    for old in ("Why Low?", "Threat Intelligence Recommendation", "Provider Overview", "Risk Level",
                "Provider Summary", "Recommended Next Action", "No elevated enrichment risk was identified.",
                "Workflow:", "Assessment Rationale", "scoring factors", "9 malicious detection"):
        assert old not in html, old


@requires_node
def test_threat_intel_assessment_holds_no_provider_tables_or_fabricated_counts():
    html = _render({"ti": TI})["ti"]
    for column in ("<th>Reputation</th>", "<th>Abuse confidence</th>", "<th>Pulse count</th>", "PowerShell Analysis"):
        assert column not in html, column
    # A result persisted before per-indicator recording has no coverage data:
    # nothing is invented for it.
    assert "Provider Coverage" not in html and "Extracted" not in html


@requires_node
def test_threat_intel_raw_provider_details_are_collapsed_and_complete():
    results = _render({"ti": TI})["tiResults"]
    assert results.startswith('<details class="parsing-field-list ti-raw-details">')
    assert "Raw provider details" in results
    for text in ("<th>Reputation</th>", "<th>Abuse confidence</th>", "<th>Pulse count</th>", "Hetzner"):
        assert text in results, text
    # Purely technical metadata and Parsing's PowerShell analysis are not repeated here.
    assert "Available sections" not in results and "PowerShell Analysis" not in results


@requires_node
def test_threat_intel_without_indicators_is_not_a_clean_result():
    html = _render({"ti": TI_NO_INDICATORS})["ti"]
    assert "safe" not in html.lower().replace("not a determination that the incident is safe", "")
    assert "Completed" not in html


@requires_node
def test_threat_intel_raw_tables_show_error_and_not_found_as_recorded():
    ti = copy.deepcopy(TI)
    ti["threat_intelligence"]["abuseipdb"]["ip_results"][0] = {
        "indicator": "188.40.170.197", "status": "error", "status_code": 429}
    ti["threat_intelligence"]["alienvault_otx"]["otx_results"][0]["status"] = "not_found"
    results = _render({"ti": ti})["tiResults"]
    assert "HTTP 429" in results and "state-failed" in results
    assert ">not_found<" in results


@requires_node
def test_threat_intel_risk_score_is_secondary_and_uncapped():
    html = _render({"ti": {**TI, "enrichment_risk_score": 180, "enrichment_risk_level": "High"}})["ti"]
    assert '<p class="assessment-score">180 <span class="ti-risk-level ti-risk-high">(HIGH)</span></p>' in html
    assert "/ 100" not in html and "/100" not in html


@requires_node
def test_threat_intel_card_omits_rationale_and_recommendation():
    reasons = ["First stored reason.", "Second stored reason."]
    action = "Stored recommendation, unchanged."
    html = _render({"ti": {**TI, "enrichment_risk_reasons": reasons, "recommended_next_action": action}})["ti"]
    assert "First stored reason." not in html and action not in html


@requires_node
def test_unified_verdict_is_a_separate_group_below_investigation():
    workspace = {"overview": {"case_context": {"unified_verdict": _unified(_state()),
                                                "netwitness_severity": {"value": "High"}}},
                 "output": {"investigation_result": INVESTIGATION}}
    html = _render({"workspace": workspace})["invOverview"]
    inv_at = html.index("Investigation Severity")
    verdict_at = html.index('class="verdict-section"')
    assert inv_at < verdict_at
    investigation_card = html[:verdict_at]
    assert "Unified Verdict" not in investigation_card
    assert "View verdict calculation" in html[verdict_at:]
    assert html[verdict_at:].count("Triage Classification") >= 1


@requires_node
def test_investigation_headline_and_details():
    html = _render({"inv": INVESTIGATION})["inv"]
    head = _headline(html)
    assert "Investigation Severity" in head and "severity-high" in head
    assert "Unified Verdict" not in html
    for text in ("Assessment Rationale", "Investigation Confidence", "Assessment Change",
                 "Previous Triage Assessment", "Investigation Assessment", "Upgraded",
                 "Business Impact", "Critical System", "Operational Impact"):
        assert text in html, text
    for old in ("Why High?", "Why Medium?", "Severity Divergence", "Business Impact Checklist"):
        assert old not in html, old
    # Confidence badge sits on the heading row, followed by its justification.
    confidence = html.split("Investigation Confidence", 1)[1]
    assert confidence.index("confidence-medium") < confidence.index("Medium because endpoint telemetry is missing.")


@requires_node
def test_investigation_without_justification_uses_neutral_message():
    html = _render({"inv": {"status": "completed", "severity": "High"}})["inv"]
    assert "Severity justification was not recorded for this Investigation run." in html
    assert "Assessment Rationale" in html
    assert "Why High?" not in html
    assert "Assessment Change" not in html and "Business Impact" not in html


@requires_node
@pytest.mark.parametrize("direction,arrow,label", [
    ("upgraded", "\u2191", "Upgraded"), ("downgraded", "\u2193", "Downgraded"),
    ("unchanged", "\u2192", "Unchanged")])
def test_assessment_change_direction_formatting(direction, arrow, label):
    inv = {**INVESTIGATION, "severity_divergence": {**INVESTIGATION["severity_divergence"], "direction": direction}}
    html = _render({"inv": inv})["inv"]
    change = html.split(">Change<", 1)[1].split("</dd>", 1)[0]
    assert arrow in change and label in change
    assert f"assessment-change-{direction}" in change


@requires_node
def test_assessment_change_unknown_direction_is_shown_as_stored():
    inv = {**INVESTIGATION, "severity_divergence": {"triage": "Medium", "investigation": "High", "direction": "re_rated"}}
    change = _render({"inv": inv})["inv"].split(">Change<", 1)[1].split("</dd>", 1)[0]
    assert "re rated" in change
    assert not any(arrow in change for arrow in "\u2191\u2193\u2192")


@requires_node
def test_business_impact_distinguishes_no_from_unknown():
    inv = copy.deepcopy(INVESTIGATION)
    inv["investigation_analysis"]["business_impact_checklist"] = {
        "critical_system": "no", "essential_service": "unknown", "data_sensitivity": "yes",
        "operational_impact": "partial outage"}
    html = _render({"inv": inv})["inv"]
    impact = html.split("Business Impact", 1)[1]
    labels = ["Critical System", "Data Sensitivity", "Essential Service", "Operational Impact"]
    positions = [impact.index(label) for label in labels]
    assert positions == sorted(positions)

    def row(label):
        return impact.split(label, 1)[1].split("</dd>", 1)[0]

    assert "impact-no" in row("Critical System") and ">No<" in row("Critical System")
    assert "impact-unknown" in row("Essential Service") and ">Unknown<" in row("Essential Service")
    assert "impact-yes" in row("Data Sensitivity")
    assert "partial outage" in row("Operational Impact") and "badge" not in row("Operational Impact")


@requires_node
def test_confidence_without_justification_still_shows_badge():
    inv = copy.deepcopy(INVESTIGATION)
    del inv["investigation_analysis"]["confidence_justification"]
    html = _render({"inv": inv})["inv"]
    assert "Investigation Confidence" in html and "confidence-medium" in html


@requires_node
def test_unified_verdict_card_shows_every_signal_with_source_names():
    uv = _unified(_state(ti=None))
    html = _render({"verdict": uv})["verdict"]
    head = _headline(html)
    assert "Unified Verdict" in head
    assert "View verdict calculation" in html and "Hide verdict calculation" in html
    for name in ("Triage Classification", "Asset Criticality", "Internal IOC Correlation",
                 "Threat Intelligence Risk", "Investigation Severity"):
        assert name in html, name
    assert "Base Severity" not in html and "base severity" not in html.lower()
    assert "Not yet available" in html


@requires_node
def test_unified_verdict_card_shows_low_threat_intel():
    html = _render({"verdict": _unified(_state())})["verdict"]
    row = html.split("Threat Intelligence Risk", 1)[1].split('class="assessment-row"', 1)[0]
    assert "severity-low" in row and ">LOW<" in row


@requires_node
def test_case_context_renames_aegis_severity():
    detail = {
        "case": {"id": "INC-T1", "status": "New", "current_stage": "Investigation",
                 "severity": "HIGH", "context": {}, "alert_count": 1},
        "workspace": {"overview": {"case_context": {}},
                      "output": {"status": "Awaiting Approval",
                                 "investigation_result": {"severity": "High", "confidence": "Medium"}}},
    }
    html = _render({"detail": detail})["caseContext"]
    assert "Investigation Severity" in html
    assert "Aegis Severity" not in html
    assert "Investigation Confidence" in html
    assert "Aegis Severity" not in WORKSPACE_JS.read_text(encoding="utf-8")
