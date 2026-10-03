"""tests/test_investigation_context_brief.py -- canonical audit Phase 2B.

The deterministic, bounded Investigation Context Brief: built from canonical
structured stage results only, rendered FIRST in the Investigation document,
fixed per-section budgets, explicit truncation, deterministic "(+N more)",
TI coverage / gaps / warnings / per-IOC role+origin+verdicts preserved,
data-quality limitations explicit, deep-dive answers protected, raw TI
provider bundle kept out of the model narrative but still persisted.
No LLM, no subprocess, no network.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from workflow import engine as wf

INV_DIR = Path(__file__).resolve().parent.parent / "agents" / "investigation"
if str(INV_DIR) not in sys.path:
    sys.path.insert(0, str(INV_DIR))
import ingest_pipeline as ip  # noqa: E402

CASE = "INC-2001"
RAW_PROVIDER_MARKER = "RAW-PROVIDER-FREE-TEXT-SHOULD-NOT-REACH-MODEL"


def _triage(**ticket_overrides):
    ticket = {"incident_id": CASE, "title": "Suspicious outbound traffic", "classification": "HIGH",
              "incident_category": "Malware", "mitre_tactic": "Command and Control",
              "mitre_technique": "T1071 Application Layer Protocol",
              "summary": "Host beacons to an external IP.",
              "risk_rating": {"likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                              "likelihood_adverse_impact": "High", "overall_risk": "High",
                              "rationale": "Repeated beaconing."},
              "recommended_actions": ["RECOMMENDED-ACTION-TOKEN"], "incident_time": "2026-01-01T00:00:00Z"}
    ticket.update(ticket_overrides)
    return {"ticket": ticket, "ai_summary": "TRIAGE-AI-SUMMARY-TOKEN",
            "metakeys_payload": {"incident_id": CASE, "incident_title": ticket["title"],
                                 "metakey_values": {"ip.src": "10.0.0.5", "ip.dst": "203.0.113.9",
                                                    "user.name": "jdoe", "host.name": "WS-01"},
                                 "ioc_summary": "[NETWORK] beaconing", "mitre_tactic": "Command and Control"}}


def _indicator(value, status="enriched", *, malicious=0, abuse=0, pulses=0, category=None):
    ind = {"value": value, "type": "ip", "roles": ["destination"],
           "origins": ["Parsed network indicators", "Alert field"], "eligible": status != "excluded",
           "status": status, "status_category": category, "status_reason": None,
           "providers_queried": 3 if status == "enriched" else 0,
           "providers_answered": 3 if status == "enriched" else 0, "providers": {},
           "context": [], "freshness": []}
    if status == "enriched":
        ind["providers"] = {
            "virustotal": {"status": "completed", "malicious": malicious, "suspicious": 0,
                           "analysed_vendors": 91, "meaningful_name": RAW_PROVIDER_MARKER},
            "abuseipdb": {"status": "completed", "abuse_confidence_score": abuse, "total_reports": 4,
                          "isp": RAW_PROVIDER_MARKER},
            "otx": {"status": "completed", "pulse_count": pulses, "related_pulses": [RAW_PROVIDER_MARKER]},
        }
    return ind


def _new_ti(n_enriched=12, n_skipped=80, *, warnings=None, with_coverage=True):
    indicators = [_indicator(f"198.51.100.{i}", malicious=i % 4, abuse=i, pulses=i * 2)
                  for i in range(n_enriched)]
    indicators += [_indicator(f"192.0.2.{i}", "skipped", category="limit") for i in range(n_skipped)]
    bundle = {"iocs": {"ip_indicators": [i["value"] for i in indicators]},
              "virustotal": {"ip_results": [{"indicator": "x", "note": RAW_PROVIDER_MARKER * 50}]},
              "abuseipdb": {"ip_results": []}, "alienvault_otx": {"otx_results": []},
              "notes": [], "indicators": indicators,
              "intelligence_gaps": [f"{n_skipped} eligible indicator(s) skipped -- enrichment limit reached."]}
    if with_coverage:
        bundle["coverage"] = {"extracted": n_enriched + n_skipped, "eligible": n_enriched + n_skipped,
                              "enriched": n_enriched, "excluded": 0, "skipped": n_skipped,
                              "skipped_by_limit": n_skipped, "provider_requests": 3 * n_enriched,
                              "limit_per_type": 10, "by_type": {}}
        bundle["provider_coverage"] = {
            "virustotal": {"label": "VirusTotal", "configured": True, "state": "available", "applicable": 10,
                           "queried": 10, "returned_data": 10, "not_found": 0, "failed": 0, "not_configured": 0},
            "abuseipdb": {"label": "AbuseIPDB", "configured": True, "state": "partial", "applicable": 10,
                          "queried": 10, "returned_data": 8, "not_found": 0, "failed": 2, "not_configured": 0},
        }
    return {"status": "completed_with_warnings" if warnings else "completed",
            "enrichment_risk_level": "High", "enrichment_risk_score": 120,
            "enrichment_risk_reasons": ["VirusTotal reported 3 malicious detection(s) for IP 198.51.100.3."],
            "warnings": warnings or [], "recommended_next_action": "Review the risk reasons.",
            "ai_summary": "TI-AI-SUMMARY-TOKEN", "threat_intelligence": bundle}


def _legacy_ti():
    return {"status": "completed", "enrichment_risk_level": "Low", "enrichment_risk_score": 25,
            "enrichment_risk_reasons": ["VirusTotal reported 9 malicious detection(s) for IP 188.40.170.197."],
            "warnings": [], "threat_intelligence": {
                "iocs": {"ip_indicators": ["188.40.170.197"], "domain_indicators": [], "file_hash": None},
                "virustotal": {"ip_results": [{"status": "completed", "indicator": "188.40.170.197",
                                               "malicious": 9, "suspicious": 0}],
                               "domain_results": [], "file_hash": {"status": "skipped"}},
                "abuseipdb": {"ip_results": [{"status": "completed", "indicator": "188.40.170.197",
                                              "abuse_confidence_score": 0, "total_reports": 0,
                                              "isp": RAW_PROVIDER_MARKER}]},
                "alienvault_otx": {"otx_results": []}, "notes": []}}


def _parsing(**overrides):
    result = {"status": "completed", "parser_confidence": "Medium", "ai_summary": "PARSING-AI-SUMMARY-TOKEN",
              "warnings": ["Missing context-relevant parsing fields: destination_port"],
              "missing_important_fields": ["destination_port", "protocol"],
              "processed_alert": {"incident_id": CASE, "command_line": "powershell -enc AAA",
                                  "network_indicators": {"source_ips": ["10.0.0.5"],
                                                         "destination_ips": ["203.0.113.9", "198.51.100.3"]},
                                  "powershell_analysis": {"decode_status": "decoded",
                                                          "decoded_command_summary": "Downloads a payload.",
                                                          "extracted_iocs": {"urls": ["http://evil.example/p"]}}}}
    result.update(overrides)
    return result


def _incident(**overrides):
    inc = {"id": CASE, "title": "Suspicious outbound traffic", "riskScore": 80, "alerts": []}
    inc.update(overrides)
    return inc


def _build(**kw):
    kw.setdefault("threat_intel_result", _new_ti())
    kw.setdefault("parsing_result", _parsing())
    incident = kw.pop("incident", _incident())
    return wf.build_investigation_alert(kw.pop("triage", _triage()), incident, **kw)


def _section(brief: str, title: str) -> str:
    start = brief.index(f"[{title}]")
    nxt = [brief.find(f"\n[{t}]", start + 1) for t in wf.BRIEF_SECTION_BUDGETS]
    nxt = [n for n in nxt if n > start] + [brief.index(wf.INVESTIGATION_BRIEF_FOOTER)]
    return brief[start:min(nxt)].rstrip("\n")


# ── placement, determinism, bounds ───────────────────────────────────────────

def test_brief_is_rendered_first_in_the_investigation_document():
    doc = ip.serialize_json_to_narrative(_build())
    assert doc.startswith(f"Incident {CASE} details are as follows: {wf.INVESTIGATION_BRIEF_HEADER}")
    assert doc.index(wf.INVESTIGATION_BRIEF_FOOTER) < doc.find("NetWitness sub-alert record(s)") or \
        "NetWitness sub-alert record(s)" not in doc


def test_brief_is_deterministic():
    assert _build()["investigation_context_brief"] == _build()["investigation_context_brief"]
    assert ip.serialize_json_to_narrative(_build()) == ip.serialize_json_to_narrative(_build())


def test_every_section_respects_its_budget_even_with_huge_inputs():
    huge_parsing = _parsing(processed_alert={"network_indicators": {
        "source_ips": [f"10.1.{i // 250}.{i % 250}" for i in range(1000)],
        "destination_ips": [f"203.0.{i // 250}.{i % 250}" for i in range(1000)]},
        "user_and_host_indicators": {"all_usernames": [f"user{i}" for i in range(300)]}})
    triage = _triage(summary="S" * 5000, risk_rating={"likelihood_initiation": "High", "likelihood_occurrence": "High",
                                                      "likelihood_adverse_impact": "High", "overall_risk": "High",
                                                      "rationale": "R" * 5000})
    supp = {"feedback_pass": 1, "requested_gaps": [f"gap {i} " + "G" * 300 for i in range(20)],
            "gap_findings": {f"gap {i} " + "G" * 300: "F" * 2000 for i in range(20)}}
    brief = _build(triage=triage, parsing_result=huge_parsing,
                   threat_intel_result=_new_ti(400, 2000, warnings=[f"w{i}" * 50 for i in range(30)]),
                   supplement=supp)["investigation_context_brief"]
    for title, budget in wf.BRIEF_SECTION_BUDGETS.items():
        assert len(_section(brief, title)) <= budget, title
    assert len(brief) <= sum(wf.BRIEF_SECTION_BUDGETS.values()) + 200
    assert "section truncated at" in brief          # truncation is explicit


# ── large TI / raw provider data cannot crowd out canonical evidence ────────

def test_high_priority_sections_survive_a_huge_multi_ioc_ti_result():
    alert = _build(threat_intel_result=_new_ti(400, 3000, warnings=["AbuseIPDB lookup for 1.2.3.4 failed."]))
    sent = ip.serialize_json_to_narrative(alert)[:12000]
    for needle in ("[CASE]", "[TRIAGE]", "[ENTITIES & TELEMETRY]", "[THREAT INTELLIGENCE]",
                   "Coverage: extracted 3400", "Intelligence gaps:", "TI warnings: AbuseIPDB lookup for 1.2.3.4 failed.",
                   "[DATA QUALITY / LIMITATIONS]", wf.INVESTIGATION_BRIEF_FOOTER):
        assert needle in sent, needle


def test_raw_provider_bundle_is_not_dumped_into_the_model_narrative_but_stays_persisted():
    alert = _build()
    doc = ip.serialize_json_to_narrative(alert)
    assert RAW_PROVIDER_MARKER not in doc
    assert "threat intelligence enrichment" not in doc.lower()
    # still in the queued JSON (sidecar / persisted results untouched)
    assert alert["threat_intelligence_enrichment"]["indicators"][0]["value"] == "198.51.100.0"
    assert RAW_PROVIDER_MARKER in json.dumps(alert["threat_intelligence_enrichment"])


def test_raw_bundle_also_kept_out_of_narratives_built_without_a_brief():
    legacy_alert = {"incident_id": CASE, "threat_intelligence_enrichment": {"x": RAW_PROVIDER_MARKER},
                    "classification": {"severity": "HIGH"}}
    doc = ip.serialize_json_to_narrative(legacy_alert)
    assert RAW_PROVIDER_MARKER not in doc and "classification severity is HIGH" in doc


# ── TI content ───────────────────────────────────────────────────────────────

def test_ti_coverage_gaps_warnings_and_provider_coverage_survive():
    brief = _build(threat_intel_result=_new_ti(warnings=["AbuseIPDB lookup for 198.51.100.3 failed."])
                   )["investigation_context_brief"]
    ti = _section(brief, "THREAT INTELLIGENCE")
    assert "Coverage: extracted 92, eligible 92, enriched 12" in ti
    assert "Provider coverage: AbuseIPDB partial" in ti
    assert "Intelligence gaps: 80 eligible indicator(s) skipped" in ti
    assert "TI warnings: AbuseIPDB lookup for 198.51.100.3 failed." in ti
    assert "NOT enriched: 80 skipped/limit" in ti
    dq = _section(brief, "DATA QUALITY / LIMITATIONS")
    assert "80 eligible indicator(s) were NOT looked up" in dq
    assert "TI provider AbuseIPDB: partial (2 failed" in dq


def test_ioc_role_origin_and_provider_verdicts_survive_for_multiple_iocs():
    ti = _section(_build()["investigation_context_brief"], "THREAT INTELLIGENCE")
    lines = [l for l in ti.splitlines() if l.startswith("- 198.51.100.")]
    assert len(lines) >= 3
    top = lines[0]
    assert top.startswith("- 198.51.100.11 | ip | role: destination | origin: Parsed network indicators, Alert field")
    assert "VT: 3 malicious, 0 suspicious of 91" in top and "AbuseIPDB: confidence 11" in top and "OTX: 22 pulses" in top
    assert RAW_PROVIDER_MARKER not in ti


def test_plus_n_more_is_deterministic_and_correct():
    a = _section(_build()["investigation_context_brief"], "THREAT INTELLIGENCE")
    b = _section(_build()["investigation_context_brief"], "THREAT INTELLIGENCE")
    assert a == b
    shown = len([l for l in a.splitlines() if l.startswith("- 198.51.100.")])
    more = [l for l in a.splitlines() if l.startswith("(+") and "enriched indicators" in l]
    assert more and more[0] == f"(+{12 - shown} more enriched indicators)"


def test_legacy_ti_contract_falls_back_to_legacy_fields():
    ti = _section(_build(threat_intel_result=_legacy_ti())["investigation_context_brief"], "THREAT INTELLIGENCE")
    assert "TI contract: legacy" in ti
    assert "- 188.40.170.197 | ip | role: not recorded (legacy TI)" in ti
    assert "VT: 9 malicious, 0 suspicious" in ti
    assert RAW_PROVIDER_MARKER not in ti
    assert "Coverage:" not in ti                    # legacy and new are never merged


def test_partial_ti_contract_states_what_is_missing():
    ti = _section(_build(threat_intel_result=_new_ti(with_coverage=False))["investigation_context_brief"],
                  "THREAT INTELLIGENCE")
    assert "TI contract: multi-indicator" in ti
    assert "Coverage: not recorded in this TI result" in ti
    assert "Provider coverage: not recorded in this TI result" in ti
    assert "- 198.51.100.11 | ip | role: destination" in ti


def test_no_ti_result_is_explicit_not_silent():
    alert = wf.build_investigation_alert(_triage(), _incident(), parsing_result=_parsing())
    brief = alert["investigation_context_brief"]
    assert "No Threat Intelligence result is available" in brief
    assert "external reputation evidence was NOT obtained" in _section(brief, "DATA QUALITY / LIMITATIONS")


# ── triage / entities / parsing / data quality ──────────────────────────────

def test_triage_summary_is_labelled_as_interpretation_and_levels_are_distinct():
    tri = _section(_build()["investigation_context_brief"], "TRIAGE")
    assert "Triage interpretation (Triage agent's assessment, not a factual incident description): Host beacons" in tri
    assert "Triage level: HIGH (Triage classification -- not the NetWitness severity)" in tri
    assert "Risk rationale: Repeated beaconing." in tri


def test_entities_carry_roles_and_origins():
    ent = _section(_build()["investigation_context_brief"], "ENTITIES & TELEMETRY")
    assert "Source IPs (1): 10.0.0.5 [T,P]" in ent
    assert "Destination IPs (2): 203.0.113.9 [T,P]; 198.51.100.3 [P]" in ent
    assert "Users (1): jdoe [T]" in ent and "Endpoint hosts (1): WS-01 [T]" in ent
    assert "Command line: powershell -enc AAA" in ent
    assert "Decoded PowerShell [Parsing]: status decoded" in ent and "http://evil.example/p" in ent
    assert wf.BRIEF_ORIGIN_LEGEND in ent


def test_parsing_warnings_and_missing_fields_survive():
    dq = _section(_build()["investigation_context_brief"], "DATA QUALITY / LIMITATIONS")
    assert "Parsing warnings: Missing context-relevant parsing fields: destination_port" in dq
    assert "Parsing missing fields (not present in telemetry): destination_port, protocol" in dq
    assert "Parser confidence: Medium" in dq


def test_missing_raw_incident_is_visible():
    dq = _section(_build(incident={})["investigation_context_brief"], "DATA QUALITY / LIMITATIONS")
    assert "Raw incident record UNAVAILABLE" in dq


def test_missing_parsing_result_is_visible():
    dq = _section(_build(parsing_result=None)["investigation_context_brief"], "DATA QUALITY / LIMITATIONS")
    assert "Parsing result UNAVAILABLE" in dq


def test_failed_alert_fetch_is_visible():
    dq = _section(_build(incident=_incident(alerts_fetch_error="HTTP 403"))["investigation_context_brief"],
                  "DATA QUALITY / LIMITATIONS")
    assert "NetWitness alert fetch failed: HTTP 403" in dq


def test_post_stage_ai_summaries_are_not_used():
    doc = ip.serialize_json_to_narrative(_build())
    for token in ("TRIAGE-AI-SUMMARY-TOKEN", "TI-AI-SUMMARY-TOKEN", "PARSING-AI-SUMMARY-TOKEN"):
        assert token not in doc


def test_triage_recommended_actions_still_excluded():
    assert "RECOMMENDED-ACTION-TOKEN" not in json.dumps(_build())


# ── deep-dive answers get reserved space ────────────────────────────────────

def test_deep_dive_answers_survive_even_with_a_large_alert_list():
    alerts = [{"_id": f"id{i}", "alert": {"name": f"Rule {i}", "host_summary": "a:1 to b:2" * 20}}
              for i in range(200)]
    supp = {"feedback_pass": 1, "requested_gaps": ["step_2: lateral movement"],
            "gap_findings": {"step_2: lateral movement": "DEEP-DIVE-ANSWER-TOKEN"},
            "confidence_per_gap": {"step_2: lateral movement": "medium"},
            "actionable_queries": {"step_2: lateral movement": "Query 4624 events"},
            "classification": "CRITICAL"}
    alert = _build(incident=_incident(alerts=alerts), supplement=supp,
                   threat_intel_result=_new_ti(300, 1000))
    sent = ip.serialize_json_to_narrative(alert)[:12000]
    assert "[DEEP-DIVE ANSWERS (feedback pass)]" in sent
    assert "DEEP-DIVE-ANSWER-TOKEN" in sent and "collect via: Query 4624 events" in sent
    assert "Deep-dive suggestions (NOT applied; analyst to review): classification CRITICAL" in sent
    assert "The triage deep dive" not in sent       # no duplicate generic rendering


# ── Pass 1 and Pass 2 get the same canonical foundation ─────────────────────

def _install_stub(monkeypatch, name, **attrs):
    stub = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(stub, k, v)
    monkeypatch.setitem(sys.modules, name, stub)


@pytest.fixture
def orch(monkeypatch, tmp_path):
    _install_stub(monkeypatch, "vector_engine")
    _install_stub(monkeypatch, "chroma_compat", open_persistent_collection=lambda *a, **k: (None, False))
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location("_orch_brief", INV_DIR / "orchestrator.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def test_pass1_and_pass2_receive_the_same_brief_bearing_timeline(orch, monkeypatch):
    calls = {}

    class _Chain:
        def __init__(self, name, respond):
            self.name, self.respond = name, respond

        async def ainvoke(self, payload):
            calls[self.name] = dict(payload)
            return self.respond(payload)

    monkeypatch.setattr(orch, "get_chain_p1", lambda: _Chain("p1", lambda p: types.SimpleNamespace(
        execution_trace=[], suggested_pivots=[])))
    monkeypatch.setattr(orch, "get_chain_p2", lambda: _Chain("p2", lambda p: orch.FinalIncidentAnalysis(
        incident_id=p["incident_id"], severity="High", confidence="Medium", execution_trace=[],
        incident_summary="s", actions_taken=[], recommended_containment=[],
        business_impact_checklist=orch.BusinessImpactChecklist(critical_system="no", essential_service="no",
                                                                data_sensitivity="no", operational_impact="no"),
        severity_justification="j", confidence_justification="j", policy_audit_logs=[])))
    monkeypatch.setattr(orch, "get_policy_manager", lambda: (types.SimpleNamespace(get_section=lambda k: None),
                                                             types.SimpleNamespace(retrieve=lambda t, limit=2: [])))
    monkeypatch.setattr(orch, "run_policy_compliance_rules", lambda **kw: {
        "escalation_required": False, "modified_containment": [], "audit_records": []})

    doc = ip.serialize_json_to_narrative(_build())[:12000]
    alerts = [{"id": CASE, "document": doc, "metadata": {"timestamp_epoch": 1, "timestamp_str": "t"}}]
    playbook = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")

    async def go():
        p1 = await orch.analyze_alert_group_p1(alerts, playbook, subject_id=CASE)
        await orch.compile_final_report(alerts, playbook, p1["execution_trace"], subject_id=CASE)
    asyncio.run(go())

    assert calls["p1"]["timeline"] == calls["p2"]["timeline"]
    assert wf.INVESTIGATION_BRIEF_HEADER in calls["p1"]["timeline"]
    assert "Coverage: extracted" in calls["p2"]["timeline"]


# ── contracts unchanged ──────────────────────────────────────────────────────

def test_existing_queued_alert_keys_are_unchanged_and_brief_is_additive():
    alert = _build()
    for key in ("incident_id", "classification", "incident_details", "network_indicators",
                "endpoint_indicators", "threat_intelligence_summary", "threat_intelligence_enrichment",
                "enrichment_risk_score", "enrichment_risk_level", "enrichment_risk_reasons"):
        assert key in alert, key
    assert alert["incident_id"] == CASE
    assert ip.process_log_file  # ingest entry point unchanged


def test_ingest_metadata_still_derives_from_structured_fields(tmp_path):
    alert = _build()
    path = tmp_path / f"{CASE}_alert.json"
    path.write_text(json.dumps(alert), encoding="utf-8")
    log = ip.process_log_file(str(path))
    assert log["id"] == CASE
    assert log["metadata"]["username"] == "jdoe" and log["metadata"]["hostname"] == "WS-01"
    assert log["metadata"]["tactic"] == "Command and Control"
    assert log["document"].startswith(f"Incident {CASE} details are as follows: {wf.INVESTIGATION_BRIEF_HEADER}")
