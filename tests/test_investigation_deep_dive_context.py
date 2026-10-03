"""tests/test_investigation_deep_dive_context.py -- canonical audit Phase 2C.

Deep-dive (deep_triage_supplement) input completeness: the evidence gaps plus
the SAME Investigation Context Brief Investigation received (one shared
builder) plus a deterministic, bounded raw NetWitness alert digest --
replacing json.dumps(raw_incident, indent=2)[:12000]. Omissions and
evidence-availability states are explicit; the deep-dive output stays
supplemental; C1 case identity is enforced. The deep-dive model is a fake
that records the prompt it receives -- no real LLM, no subprocess, no network.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

import agents.triage as triage_pkg
from agents.triage import soc_triage_agent
from workflow import engine as wf

INV_DIR = Path(__file__).resolve().parent.parent / "agents" / "investigation"
if str(INV_DIR) not in sys.path:
    sys.path.insert(0, str(INV_DIR))
import ingest_pipeline as ip  # noqa: E402

CASE = "INC-2001"
RAW_PROVIDER_MARKER = "RAW-PROVIDER-FREE-TEXT-SHOULD-NOT-REACH-MODEL"
GAPS = ["step_2: Determine whether PowerShell spawned a child process on the host",
        "step_3: Check whether other hosts contacted the destination (lateral movement)"]
DEEP_DIVE_REPLY = {
    "gap_findings": {GAPS[0]: "powershell -enc launched by explorer.exe (alert A1)",
                     GAPS[1]: "not present in incident data"},
    "confidence_per_gap": {GAPS[0]: "high", GAPS[1]: "none"},
    "actionable_queries": {GAPS[1]: "Query firewall logs for 203.0.113.9 from other hosts"},
    "extracted_values": {"process.cmdline": "powershell -enc AAA"},
    "mitre_tactic": "Execution", "incident_category": "Malware",
    "classification": "CRITICAL",
    "deep_dive_summary": "PowerShell execution confirmed; lateral movement evidence absent.",
}


# ── fixtures ────────────────────────────────────────────────────────────────

class RecordingModel(BaseChatModel):
    """Fake deep-dive model: records every prompt, returns DEEP_DIVE_REPLY."""
    calls: list = []

    @property
    def _llm_type(self) -> str:
        return "recording-deep-dive"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.calls.append([(type(m).__name__, str(m.content)) for m in messages])
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=json.dumps(DEEP_DIVE_REPLY)))])


@pytest.fixture()
def model(monkeypatch):
    fake = RecordingModel(calls=[])
    monkeypatch.setattr(soc_triage_agent, "build_llm", lambda cfg, json_mode=False: fake)
    return fake


def _triage(case=CASE, **ticket_overrides):
    ticket = {"incident_id": case, "title": "Suspicious PowerShell and outbound traffic",
              "classification": "HIGH", "incident_category": "Malware",
              "mitre_tactic": "Command and Control", "mitre_technique": "T1071",
              "summary": "TRIAGE-INTERPRETATION-TOKEN: host likely beacons.",
              "risk_rating": {"likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                              "likelihood_adverse_impact": "High", "overall_risk": "High",
                              "rationale": "Repeated beaconing."},
              "incident_time": "2026-01-01T00:00:00Z"}
    ticket.update(ticket_overrides)
    return {"ticket": ticket, "ai_summary": "TRIAGE-AI-SUMMARY-TOKEN",
            "metakeys_payload": {"incident_id": case, "incident_title": ticket["title"],
                                 "metakey_values": {"ip.src": "10.0.0.5", "ip.dst": "203.0.113.9",
                                                    "user.name": "jdoe", "host.name": "WS-01"},
                                 "mitre_tactic": "Command and Control"}}


def _indicator(value, status="enriched", *, typ="ip", roles=("destination",), malicious=0,
               category=None, origins=("Parsed network indicators", "Alert field")):
    ind = {"value": value, "type": typ, "roles": list(roles), "origins": list(origins),
           "status": status, "status_category": category, "providers": {}}
    if status == "enriched":
        ind["providers"] = {
            "virustotal": {"status": "completed", "malicious": malicious, "suspicious": 0,
                           "analysed_vendors": 91, "meaningful_name": RAW_PROVIDER_MARKER},
            "abuseipdb": {"status": "completed", "abuse_confidence_score": malicious * 10,
                          "total_reports": 4, "isp": RAW_PROVIDER_MARKER},
            "otx": {"status": "completed", "pulse_count": malicious, "related_pulses": [RAW_PROVIDER_MARKER]},
        }
    return ind


def _new_ti(n_enriched=3, n_skipped=5, *, warnings=None, provider_state="available"):
    indicators = [_indicator("203.0.113.9", malicious=9)]
    indicators += [_indicator(f"198.51.100.{i}", malicious=i % 3) for i in range(n_enriched - 1)]
    indicators += [_indicator("10.0.0.5", "excluded", roles=("source",), category="private")]
    indicators += [_indicator(f"192.0.2.{i}", "skipped", category="limit") for i in range(n_skipped)]
    return {"status": "completed_with_warnings" if warnings else "completed",
            "enrichment_risk_level": "High", "enrichment_risk_score": 120,
            "enrichment_risk_reasons": ["VirusTotal reported 9 malicious detection(s) for IP 203.0.113.9."],
            "warnings": warnings or [], "ai_summary": "TI-AI-SUMMARY-TOKEN",
            "threat_intelligence": {
                "indicators": indicators,
                "virustotal": {"ip_results": [{"indicator": "x", "note": RAW_PROVIDER_MARKER * 20}]},
                "coverage": {"extracted": len(indicators), "eligible": n_enriched + n_skipped,
                             "enriched": n_enriched, "excluded": 1, "skipped": n_skipped,
                             "skipped_by_limit": n_skipped, "limit_per_type": 10},
                "provider_coverage": {
                    "virustotal": {"label": "VirusTotal", "state": "available", "applicable": n_enriched,
                                   "queried": n_enriched, "failed": 0, "not_configured": 0},
                    "otx": {"label": "AlienVault OTX", "state": provider_state, "applicable": n_enriched,
                            "queried": n_enriched, "failed": 0 if provider_state == "available" else n_enriched,
                            "not_configured": 0}},
                "intelligence_gaps": ["INTEL-GAP-TOKEN: 5 eligible indicator(s) skipped -- limit reached."]}}


def _legacy_ti():
    return {"status": "completed", "enrichment_risk_level": "Low", "enrichment_risk_score": 25,
            "enrichment_risk_reasons": ["VirusTotal reported 9 malicious detection(s) for IP 203.0.113.9."],
            "warnings": [], "threat_intelligence": {
                "iocs": {"ip_indicators": ["203.0.113.9"], "domain_indicators": [], "file_hash": None},
                "virustotal": {"ip_results": [{"status": "completed", "indicator": "203.0.113.9",
                                               "malicious": 9, "suspicious": 0}]},
                "abuseipdb": {"ip_results": [{"status": "completed", "indicator": "203.0.113.9",
                                              "abuse_confidence_score": 0, "total_reports": 0,
                                              "isp": RAW_PROVIDER_MARKER}]},
                "alienvault_otx": {"otx_results": []}}}


def _parsing():
    return {"status": "completed", "parser_confidence": "Medium", "ai_summary": "PARSING-AI-SUMMARY-TOKEN",
            "warnings": ["PARSING-WARNING-TOKEN: destination_port missing"],
            "missing_important_fields": ["destination_port", "protocol"],
            "processed_alert": {"incident_id": CASE, "command_line": "powershell -enc AAA",
                                "network_indicators": {"source_ips": ["10.0.0.5"],
                                                       "destination_ips": ["203.0.113.9"]},
                                "file_indicators": {"file_hashes": ["a" * 64]},
                                "powershell_analysis": {"decode_status": "decoded",
                                                        "decoded_command_summary": "Downloads a payload.",
                                                        "extracted_iocs": {"urls": ["http://evil.example/p"]}}}}


def _event(*, src="10.0.0.5", dst="203.0.113.9", launch=None, filename=None, sha=None,
           user=None, hostname=None, domain_dst=None, padding=None):
    """Real NetWitness Respond event shape (fields as fetched for INC-52970 / INC-53021)."""
    ev = {"source": {"device": {"ip_address": src, "port": 53539},
                     "user": {"username": user or ""}},
          "destination": {"device": {"ip_address": dst, "port": 443,
                                     "geolocation": {"country": "Netherlands", "organization": "ExampleNet"}}},
          "from": f"{src}:53539", "to": f"{dst}:443", "type": "Network",
          "analysis_service": "watchlist port", "analysis_session": "not top 20 dst",
          "hostname": hostname or "", "domain_dst": domain_dst or "",
          "related_links": [{"type": "investigate_original_event", "url": padding or "/x"}]}
    if launch:
        ev["source"]["launch_argument"] = launch
        ev["source"]["filename"] = "powershell.exe"
        ev["source"]["path"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
        ev["type"] = "Process Event"
    if filename:
        ev["data"] = [{"filename": filename, "hash": sha or "", "size": 1024}]
    if sha:
        ev["source"]["file_SHA256"] = sha
    return ev


def _nw_alert(i, *, name="Outbound beacon", severity=50, received=None, **event_kw):
    ev = _event(**event_kw)
    return {"_id": f"alert-{i:03d}", "receivedTime": received or f"2026-01-01T00:{i % 60:02d}:00Z",
            "originalHeaders": {"name": name, "severity": severity, "timestamp": 1752569351244,
                                "deviceProduct": "Event Stream Analysis"},
            "originalAlert": {"severity": severity, "moduleName": name, "events": [ev]},
            "alert": {"name": name, "type": ["Network"], "source": "Event Stream Analysis",
                      "host_summary": f"{ev['from']} to {ev['to']}", "events": [ev]},
            "incidentId": CASE}


def _incident(alerts=None, **overrides):
    inc = {"id": CASE, "title": "Suspicious PowerShell and outbound traffic", "riskScore": 80,
           "priority": "HIGH", "alertCount": len(alerts or []), "alerts": alerts if alerts is not None else [],
           "categories": [{"parent": "Malware", "name": "Command and Control"}],
           "alertMeta": {"SourceIp": ["10.0.0.5"], "DestinationIp": ["203.0.113.9"],
                         "AlertTitles": ["Outbound beacon"]}}
    inc.update(overrides)
    return inc


def _context(incident=None, gaps=GAPS, *, ti="new", parsing=True, triage=None, case_id=CASE):
    ti_result = {"new": _new_ti, "legacy": _legacy_ti}.get(ti, lambda: ti)() if isinstance(ti, str) else ti
    return wf.build_deep_dive_context(
        triage or _triage(), incident if incident is not None else _incident([_nw_alert(1)]), gaps,
        case_id=case_id, threat_intel_result=ti_result, parsing_result=_parsing() if parsing else None)


def _prompt(model) -> tuple[str, str]:
    """(system, human) text of the single deep-dive model call."""
    assert len(model.calls) == 1
    roles = dict(model.calls[0])
    return roles["SystemMessage"], roles["HumanMessage"]


def _run_feedback(monkeypatch, *, triage=None, incident=None, ti="new", inc_id=CASE):
    """investigate_with_feedback with a gap-producing pass 1; returns
    (result, handoff kwargs list, run_investigation kwargs list)."""
    handoffs, runs = [], []
    monkeypatch.setattr(wf, "handoff_to_investigation",
                        lambda tri, inc, **kw: handoffs.append({"triage": tri, "incident": inc, **kw}))
    results = iter([
        {"status": "completed", "narrative_report": "", "execution_trace": [
            {"step_id": "step_2", "instruction": GAPS[0].split(": ", 1)[1], "status": "NOT_MET"},
            {"step_id": "step_3", "instruction": GAPS[1].split(": ", 1)[1], "status": "NOT_MET"}]},
        {"status": "completed", "narrative_report": "", "execution_trace": []},
    ])

    def fake_run(*a, **k):
        runs.append(k)
        return next(results)
    monkeypatch.setattr(wf, "run_investigation", fake_run)
    ti_result = {"new": _new_ti(), "legacy": _legacy_ti()}.get(ti, ti) if isinstance(ti, str) else ti
    result = wf.investigate_with_feedback(
        triage or _triage(), incident if incident is not None else _incident([_nw_alert(1, launch="powershell -enc AAA")]),
        inc_id, threat_intel_result=ti_result, parsing_result=_parsing(), max_passes=1)
    return result, handoffs, runs


# ── 1-2: gaps and case identity reach the deep-dive ─────────────────────────

def test_01_evidence_gaps_always_reach_the_deep_dive(model, monkeypatch):
    _run_feedback(monkeypatch)
    _system, human = _prompt(model)
    assert human.startswith("EVIDENCE GAPS REPORTED BY INVESTIGATION:")
    for gap in GAPS:
        assert gap in human
    # gaps come first -- before any canonical or raw context
    assert human.index(GAPS[1]) < human.index(wf.INVESTIGATION_BRIEF_HEADER) < human.index(wf.DEEP_DIVE_HEADER)


def test_02_canonical_case_id_reaches_the_deep_dive(model, monkeypatch):
    _run_feedback(monkeypatch)
    _system, human = _prompt(model)
    assert f"Case ID (Investigation subject): {CASE}" in human
    assert "Suspicious PowerShell and outbound traffic" in human


# ── 3-4: Parsing and Triage, with provenance ────────────────────────────────

def test_03_parsing_context_reaches_the_deep_dive(model, monkeypatch):
    _run_feedback(monkeypatch)
    _system, human = _prompt(model)
    assert "Decoded PowerShell [Parsing]: status decoded; Downloads a payload." in human
    assert "http://evil.example/p" in human
    assert "Command line: powershell -enc AAA" in human
    assert "Parser confidence: Medium" in human
    assert "PARSING-WARNING-TOKEN" in human
    assert "Parsing missing fields (not present in telemetry): destination_port, protocol" in human
    assert "PARSING-AI-SUMMARY-TOKEN" not in human            # canonical result, not the AI summary


def test_04_triage_context_reaches_the_deep_dive_with_provenance(model, monkeypatch):
    _run_feedback(monkeypatch)
    _system, human = _prompt(model)
    assert "Triage level: HIGH (Triage classification -- not the NetWitness severity)" in human
    assert "Risk dimensions: initiation High" in human
    assert ("Triage interpretation (Triage agent's assessment, not a factual incident description): "
            "TRIAGE-INTERPRETATION-TOKEN") in human
    assert "TRIAGE-AI-SUMMARY-TOKEN" not in human


# ── 5-10, 15-18: Threat Intelligence ────────────────────────────────────────

def test_05_ti_context_reaches_the_deep_dive(model, monkeypatch):
    _run_feedback(monkeypatch)
    _system, human = _prompt(model)
    assert "TI contract: multi-indicator" in human
    assert "Risk Level: High" in human
    assert "- 203.0.113.9 | ip | role: destination" in human
    assert "VT: 9 malicious, 0 suspicious of 91" in human


def test_06_ti_warnings_survive():
    text, _ = _context(ti=_new_ti(warnings=["TI-WARNING-TOKEN: OTX lookup for 203.0.113.9 failed."]))
    assert "TI warnings: TI-WARNING-TOKEN: OTX lookup for 203.0.113.9 failed." in text
    assert "TI reported 1 warning(s)" in text


def test_07_ti_intelligence_gaps_survive():
    text, _ = _context()
    assert "Intelligence gaps: INTEL-GAP-TOKEN" in text


def test_08_ioc_roles_survive():
    text, _ = _context()
    assert "203.0.113.9 | ip | role: destination" in text


def test_09_ioc_origins_survive():
    text, _ = _context()
    assert "origin: Parsed network indicators, Alert field" in text


def test_10_multiple_iocs_are_compacted_deterministically():
    ti = _new_ti(n_enriched=30, n_skipped=60)
    first, _ = _context(ti=ti)
    second, _ = _context(ti=copy.deepcopy(ti))
    assert first == second
    lines = [line for line in first.splitlines() if line.startswith("- ") and "| ip |" in line]
    assert lines[0].startswith("- 203.0.113.9 ")                   # highest provider evidence first
    assert len(lines) <= wf.BRIEF_LIST_LIMITS["indicators"]
    assert "more enriched indicators)" in first
    assert "60 skipped/limit" in first


def test_15_no_raw_ti_provider_dump():
    text, _ = _context()
    assert RAW_PROVIDER_MARKER not in text
    assert '"virustotal"' not in text and "ip_results" not in text and "TI-AI-SUMMARY-TOKEN" not in text


def test_16_legacy_ti_works():
    text, _ = _context(ti="legacy")
    assert "TI contract: legacy" in text
    assert "- 203.0.113.9 | ip | role: not recorded (legacy TI)" in text
    assert "1 in legacy TI result" in text
    assert "NOT CHECKED by TI (no TI record -- NOT evidence of benign): 10.0.0.5 (source IP)" in text


def test_17_new_ti_distinguishes_enriched_excluded_skipped_and_not_checked():
    ti = _new_ti()
    ti["threat_intelligence"]["indicators"] = [i for i in ti["threat_intelligence"]["indicators"]
                                               if i["value"] != "192.0.2.0"]
    inc = _incident([_nw_alert(1)], alertMeta={"SourceIp": ["10.0.0.5"],
                                               "DestinationIp": ["203.0.113.9", "192.0.2.1", "203.0.113.77"]})
    text, _ = _context(inc, ti=ti)
    cov = next(line for line in text.splitlines() if line.startswith("Case IP/domain/hash indicators vs TI"))
    assert "1 enriched" in cov and "1 excluded" in cov and "1 skipped" in cov and "NOT CHECKED" in cov
    assert "203.0.113.77 (destination IP)" in text
    assert "Coverage: extracted" in text


@pytest.mark.parametrize("case", ["provider_failed", "no_result"])
def test_18_partial_ti_works(case):
    if case == "provider_failed":
        text, _ = _context(ti=_new_ti(provider_state="failed", warnings=["OTX failed"]))
        assert "TI provider AlienVault OTX: failed" in text
        assert "TI stage status: completed_with_warnings" in text
    else:
        text, _ = _context(ti=None)
        assert "No Threat Intelligence result is available for this case." in text
        assert "No TI result: all" in text and "NOT CHECKED" in text


# ── 11-14: raw alert digest ─────────────────────────────────────────────────

def test_11_raw_alert_digest_uses_actual_netwitness_fields():
    sha = "b" * 64
    inc = _incident([_nw_alert(1, launch="powershell.exe -enc SQBFAFgA", filename="drop.ps1", sha=sha,
                               domain_dst="evil.example.com"),
                     {"_id": "bare-1", "alert": {"events": [{"type": "Log"}]}}])
    text, meta = _context(inc)
    digest = text[text.index(wf.DEEP_DIVE_HEADER):]
    assert "source.launch_argument: powershell.exe -enc SQBFAFgA" in digest
    assert "source.filename: powershell.exe" in digest
    assert "data.filename: drop.ps1" in digest
    assert f"source.file_SHA256: {sha}" in digest
    assert "from: 10.0.0.5:53539" in digest and "to: 203.0.113.9:443" in digest
    assert "analysis_service: watchlist port" in digest
    assert "destination geo country: Netherlands" in digest
    assert "domains: evil.example.com" in digest
    assert '"Outbound beacon" | NetWitness severity 50' in digest
    # an alert that carries no name/severity/time is not given fabricated ones
    assert '"title not provided" | NetWitness severity not provided | time not provided' in digest
    assert "Medium" not in digest.split("[NETWITNESS ALERTS]")[1]
    assert meta["alerts_total"] == 2 and meta["raw_state"] == "fetched"


def test_12_large_raw_incident_is_compacted_not_prefix_truncated():
    alerts = [_nw_alert(i, dst=f"198.51.100.{i}", padding="/investigate/" + "x" * 3000) for i in range(39)]
    # the only gap-relevant (process) alert is the LAST one in the raw list
    alerts.append(_nw_alert(39, name="PowerShell launched", severity=10, launch="powershell -enc LASTALERT"))
    inc = _incident(alerts)
    raw_prefix = json.dumps(inc, indent=2)[:12000]
    assert "LASTALERT" not in raw_prefix                       # what the old input would have missed
    text, meta = _context(inc)
    assert len(text) <= wf.DEEP_DIVE_CONTEXT_BUDGET and not meta["budget_exceeded"]
    assert "LASTALERT" in text
    alerts_section = text.split("[NETWITNESS ALERTS]")[1]
    assert alerts_section.index("[A1]") < alerts_section.index("LASTALERT") < alerts_section.index("[A2]")
    assert "related_links" not in text and "xxxxxxxxxx" not in text


def test_13_omissions_are_explicit_and_add_up():
    alerts = [_nw_alert(i, name=f"Distinct alert {i}", dst=f"198.51.100.{i}",
                        launch=f"cmd.exe /c step{i} " + "A" * 150) for i in range(40)]
    text, meta = _context(_incident(alerts))
    assert meta["alerts_omitted"] > 0
    assert meta["alerts_shown"] + meta["alerts_omitted"] == 40
    assert (f"Showing {meta['alerts_shown']} of 40 alerts as {meta['alert_groups_shown']} of 40 "
            "distinct alert groups") in text
    assert f"(+{meta['alerts_omitted']} more alerts in {40 - meta['alert_groups_shown']} groups OMITTED" in text
    assert "not shown, NOT absent" in text
    assert text.rstrip().endswith(wf.DEEP_DIVE_FOOTER)
    assert len(text) <= wf.DEEP_DIVE_CONTEXT_BUDGET


def test_identical_alerts_are_collapsed_with_counts():
    alerts = [_nw_alert(i, received=f"2026-01-01T00:0{i}:00Z") for i in range(5)]
    text, meta = _context(_incident(alerts))
    assert "[A1] ×5 identical alerts" in text
    assert "2026-01-01T00:00:00Z .. 2026-01-01T00:04:00Z" in text
    assert "(+4 more ids)" in text
    assert meta["alert_groups_total"] == 1 and meta["alerts_shown"] == 5


def test_gap_categories_prioritise_relevant_alerts_deterministically():
    alerts = [_nw_alert(1, name="High-severity network", severity=90),
              _nw_alert(2, name="Low-severity process", severity=5, launch="powershell -enc AAA")]
    process_first, meta = _context(_incident(alerts), gaps=["step_1: Was PowerShell executed?"])
    assert meta["gap_categories"] == {"process": ["step_1"]}
    assert process_first.index("Low-severity process") < process_first.index("High-severity network")
    no_gap_focus, _ = _context(_incident(alerts), gaps=["step_9: Summarise the business impact"])
    assert "No gap matched a field category" in no_gap_focus
    assert no_gap_focus.index("High-severity network") < no_gap_focus.index("Low-severity process")


@pytest.mark.parametrize("incident, state, phrase", [
    ({}, "raw_incident_unavailable", f"RAW INCIDENT UNAVAILABLE: the raw NetWitness incident record for {CASE}"),
    ({"id": CASE, "title": "t"}, "not_fetched", "NOT FETCHED: no NetWitness alert fetch was recorded"),
    ({"id": CASE, "alerts": [], "alerts_fetch_error": "HTTP 503"}, "provider_failed",
     "PROVIDER FAILED: the NetWitness alert fetch failed (HTTP 503)"),
    ({"id": CASE, "_alerts_stripped": 4}, "unavailable", "EVIDENCE UNAVAILABLE: only the stored slim incident copy"),
    ({"id": CASE, "_alerts_stripped": 1, "alerts": [_nw_alert(1)]}, "unverified", "completeness is NOT verified"),
    ({"id": CASE, "alerts": []}, "no_alerts_observed", "NO EVIDENCE OBSERVED at alert level"),
])
def test_14_data_quality_states_are_explicit(incident, state, phrase):
    text, meta = _context(incident)
    assert meta["raw_state"] == state
    assert phrase in text


def test_14b_missing_raw_incident_reaches_the_prompt_explicitly(model, monkeypatch):
    _run_feedback(monkeypatch, incident={})
    _system, human = _prompt(model)
    assert "RAW INCIDENT UNAVAILABLE" in human
    assert "Raw incident record UNAVAILABLE for this run" in human      # brief's DQ line too
    assert "RAW INCIDENT DATA (FULL CONTEXT)" not in human and "{}" not in human


def test_category_absent_from_all_fetched_alerts_is_no_evidence_observed():
    text, _ = _context(_incident([_nw_alert(1)]), gaps=["step_1: Was PowerShell executed?"])
    assert "NO EVIDENCE OBSERVED for process fields in any of the 1 alert(s) (fields absent from the " \
           "fetched telemetry, not omitted)." in text


def test_context_is_bounded_for_worst_case_inputs():
    triage = _triage(summary="S" * 5000)
    triage["metakeys_payload"]["metakey_values"] = {
        "ip.dst": [f"203.0.113.{i}" for i in range(200)], "domain": [f"d{i}.example.com" for i in range(200)]}
    alerts = [_nw_alert(i, name=f"A{i}", dst=f"198.51.100.{i % 250}", launch="x" * 2000,
                        filename="f" * 500, sha="c" * 64) for i in range(300)]
    inc = _incident(alerts, summary="Z" * 5000, alertMeta={"AlertTitles": [f"T{i}" * 50 for i in range(500)]})
    text, meta = _context(inc, ti=_new_ti(n_enriched=200, n_skipped=500), triage=triage)
    assert len(text) <= wf.DEEP_DIVE_CONTEXT_BUDGET
    assert meta["context_chars"] == len(text) and not meta["budget_exceeded"]
    assert meta["alerts_shown"] >= 1 and meta["alerts_omitted"] > 0


def test_build_is_pure_and_deterministic():
    inc = _incident([_nw_alert(i, launch="powershell -enc AAA" if i % 2 else None) for i in range(12)])
    triage, ti, parsing = _triage(), _new_ti(), _parsing()
    snapshot = copy.deepcopy((inc, triage, ti, parsing))
    a = wf.build_deep_dive_context(triage, inc, GAPS, case_id=CASE, threat_intel_result=ti, parsing_result=parsing)
    b = wf.build_deep_dive_context(triage, inc, GAPS, case_id=CASE, threat_intel_result=ti, parsing_result=parsing)
    assert a == b
    assert (inc, triage, ti, parsing) == snapshot


# ── 19-21: feedback flow, supplemental output, C1 ───────────────────────────

def test_19_deep_dive_answers_survive_the_feedback_handoff(model, monkeypatch):
    result, handoffs, _runs = _run_feedback(monkeypatch)
    assert len(handoffs) == 2
    supplement = handoffs[1]["supplement"]
    assert supplement["requested_gaps"] == GAPS and supplement["feedback_pass"] == 1
    assert supplement["gap_findings"][GAPS[0]].startswith("powershell -enc launched")
    alert = wf.build_investigation_alert(handoffs[1]["triage"], handoffs[1]["incident"], supplement=supplement,
                                         threat_intel_result=handoffs[1]["threat_intel_result"],
                                         parsing_result=handoffs[1]["parsing_result"])
    narrative = ip.serialize_json_to_narrative(alert)[:12000]   # the Investigation document cap
    assert "[DEEP-DIVE ANSWERS (feedback pass)]" in narrative
    assert "powershell -enc launched by explorer.exe" in narrative
    assert "collect via: Query firewall logs for 203.0.113.9" in narrative
    assert result["feedback_loop"]["gaps_answered"] == 1


def test_20_classification_suggestion_remains_non_applied(model, monkeypatch):
    triage = _triage()
    before = copy.deepcopy(triage)
    result, handoffs, runs = _run_feedback(monkeypatch, triage=triage)
    assert triage == before                                     # shared Triage result never mutated
    assert result["feedback_loop"]["suggested_classification"] == "CRITICAL"
    rerun_triage = handoffs[1]["triage"]
    assert rerun_triage["ticket"]["classification"] == "HIGH"   # not applied to the re-run either
    assert [r["triage_classification"] for r in runs] == ["HIGH", "HIGH"]
    alert = wf.build_investigation_alert(rerun_triage, handoffs[1]["incident"],
                                         supplement=handoffs[1]["supplement"])
    assert alert["classification"]["severity"] == "HIGH"
    assert "Deep-dive suggestions (NOT applied; analyst to review): classification CRITICAL" in \
        alert["investigation_context_brief"]
    assert "analyst to review" in result["summary"]


def test_21_c1_identity_is_enforced_for_the_deep_dive(model, monkeypatch):
    with pytest.raises(ValueError, match="identity mismatch: Triage result is for INC-2001"):
        _context(case_id="INC-9999", incident={})
    with pytest.raises(ValueError, match="identity mismatch: raw incident is for INC-7777"):
        _context(_incident([_nw_alert(1)], id="INC-7777"))
    # in the loop: no model call on foreign context; pass-1 findings kept
    result, handoffs, runs = _run_feedback(monkeypatch, inc_id="INC-9999")
    assert model.calls == []
    assert "identity mismatch" in result["feedback_loop"]["supplement_error"]
    assert len(handoffs) == 1 and len(runs) == 1


def test_21b_subject_id_is_the_case_id_in_the_context():
    text, _ = _context()
    assert text.count("Case ID (Investigation subject): ") == 1
    assert f"Case ID (Investigation subject): {CASE}" in text


# ── 22-25: regressions ──────────────────────────────────────────────────────

def test_22_2a_semantics_hold_in_the_digest():
    alerts = [_nw_alert(1, hostname="host-a.corp.example.com", user="alice"),
              _nw_alert(2, name="Other alert", hostname="WS-02")]
    text, _ = _context(_incident(alerts))
    blocks = {b.split("\n", 1)[0]: b for b in text.split("[NETWITNESS ALERTS]")[1].split("\n[A")}
    dns_block = next(b for h, b in blocks.items() if "Outbound beacon" in h)
    ws_block = next(b for h, b in blocks.items() if "Other alert" in h)
    assert "domains: host-a.corp.example.com" in dns_block and "hostnames: host-a" not in dns_block
    assert "users: alice" in dns_block
    assert "alice" not in ws_block and "jdoe" not in ws_block    # no case-level inheritance
    assert "hostnames: WS-02" in ws_block


def test_23_2b_brief_is_reused_verbatim():
    inc, triage, ti, parsing = _incident([_nw_alert(1)]), _triage(), _new_ti(), _parsing()
    alert = wf.build_investigation_alert(triage, inc, threat_intel_result=ti, parsing_result=parsing)
    text, meta = wf.build_deep_dive_context(triage, inc, GAPS, case_id=CASE,
                                            threat_intel_result=ti, parsing_result=parsing)
    assert text.startswith(alert["investigation_context_brief"] + "\n" + wf.DEEP_DIVE_HEADER)
    assert meta["brief_chars"] == len(alert["investigation_context_brief"])
    assert alert == wf._assemble_investigation_alert(triage, inc, threat_intel_result=ti,
                                                     parsing_result=parsing)[0]
    assert "[DEEP-DIVE ANSWERS (feedback pass)]" not in text


def test_24_agent_activity_wrap_point_matches_the_new_signature():
    from observability.adapters import investigation_adapter
    from observability.instrument import Patcher, actual_params

    recorded = []
    patcher = Patcher()
    patcher.wrap = lambda target, hooks: recorded.append((target, hooks)) or True  # type: ignore[assignment]
    investigation_adapter.install(patcher)
    target, hooks = next((t, h) for t, h in recorded if t.attr == "deep_triage_supplement")
    assert target.params == ("incident", "gaps", "cfg", "thinking_container", "investigation_context")
    assert actual_params(target) == target.params
    build = next(t for t, _h in recorded if t.attr == "build_investigation_alert")
    assert actual_params(build) == build.params                 # public handoff signature unchanged


def test_25_reporting_contract_is_unchanged(model, monkeypatch):
    result, _handoffs, _runs = _run_feedback(monkeypatch)
    assert set(result["feedback_loop"]) == {"triggered", "passes", "gaps", "gaps_answered",
                                            "playbook_redirect", "suggested_classification"}
    assert result["feedback_loop"]["gaps"] == GAPS


def test_deep_dive_response_schema_and_system_prompt_are_unchanged(model):
    legacy = soc_triage_agent.deep_triage_supplement({"id": CASE, "alerts": []}, GAPS)
    legacy_system, legacy_human = _prompt(model)
    model.calls.clear()
    text, _ = _context()
    new = soc_triage_agent.deep_triage_supplement({"id": CASE}, GAPS, investigation_context=text)
    new_system, new_human = _prompt(model)
    assert new_system == legacy_system
    assert set(new) == set(legacy) == {"gap_findings", "confidence_per_gap", "actionable_queries",
                                       "extracted_values", "mitre_tactic", "incident_category",
                                       "classification", "deep_dive_summary"}
    assert "RAW INCIDENT DATA (FULL CONTEXT):" in legacy_human          # standalone callers unchanged
    assert "RAW INCIDENT DATA (FULL CONTEXT):" not in new_human
    assert new_human.endswith("Answer every gap with forensic reasoning and provide query "
                              "recommendations. End your response with the JSON object.")


def test_deep_dive_is_called_through_the_package_attribute(model, monkeypatch):
    seen = {}
    monkeypatch.setattr(triage_pkg, "deep_triage_supplement",
                        lambda inc, gaps, **kw: seen.update(kw) or dict(DEEP_DIVE_REPLY))
    _run_feedback(monkeypatch)
    assert seen["investigation_context"].startswith(wf.INVESTIGATION_BRIEF_HEADER)
    assert len(seen["investigation_context"]) <= wf.DEEP_DIVE_CONTEXT_BUDGET
