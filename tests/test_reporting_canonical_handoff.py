"""tests/test_reporting_canonical_handoff.py -- canonical audit Phase 3.

Investigation -> Reporting canonical handoff: every field Reporting receives
keeps its real owner (Parsing / Triage / Threat Intelligence / Investigation),
nothing is relabelled or fabricated, the correlation cluster's indicators are
kept apart from the current case's IOCs, TI's canonical enriched alert and
multi-IOC contract are used, Investigation evidence gaps are not reported as
missing report fields, and the Investigation result source is visible.
No LLM, no subprocess, no network; handoff files go to a temporary REP_DIR.
"""
from __future__ import annotations

import copy
import json
import threading

import pytest

import canonical_seed as seed
from workflow import engine as wf
from workflow import state_store as wss
import agents.investigation.skills_sidecar as skills_sidecar
from agents.reporting.reporting.context_builder import build_context
from agents.reporting.reporting.export_context_enhancer import (
    _apply_field_provenance, build_appendix_summaries, rebuild_iocs, repair_mitre_mapping)

CASE = "INC-53011"
INV_MITRE = [{"timeline_phase": "C2 beaconing", "observed_evidence": "HTTPS to 203.0.113.9",
              "tactic": "Command and Control", "technique_name": "Web Protocols",
              "technique_id": "T1071.001"}]


def _triage(case=CASE, **ticket):
    t = {"incident_id": case, "unc": "#00042A", "classification": "HIGH", "title": "Beaconing host",
         "incident_category": "Malware", "mitre_tactic": "Execution", "mitre_technique": "T1059.001",
         "summary": "Triage summary.", "risk_rating": {"overall_risk": "High"}}
    t.update(ticket)
    return {"ticket": t, "metakeys_payload": {"incident_id": case, "incident_title": "Beaconing host",
                                              "mitre_tactic": "Execution"}}


def _investigation(case=CASE, *, structured=True, mitre=True, **extra):
    analysis = {"incident_id": case, "severity": "Critical", "confidence": "Medium",
                "execution_trace": [], "incident_summary": "Investigation summary.",
                "actions_taken": [], "recommended_containment": ["Isolate WS-01"],
                "business_impact_checklist": {"critical_system": "no", "essential_service": "no",
                                              "data_sensitivity": "no", "operational_impact": "no"},
                "severity_justification": "SEV-JUSTIFICATION-TOKEN",
                "confidence_justification": "CONF-JUSTIFICATION-TOKEN",
                "mitre_mappings": INV_MITRE if mitre else []}
    inv = {"agent": "Investigation Agent", "incident_id": case, "investigated_for": case,
           "status": "completed", "severity": "Critical", "summary": "Investigation summary.",
           "indicators": ["10.9.9.9", "198.18.0.77", "192.168.10."],          # cluster-wide set
           "cluster_alert_ids": [case, "INC-52825"], "mitre_mappings": INV_MITRE if mitre else [],
           "recommended_containment": ["Isolate WS-01"], "narrative_report": "# Report",
           "workflow": {"investigation_source": "structured_json" if structured else "markdown_fallback"},
           "feedback_loop": {"triggered": True, "passes": 1,
                             "gaps": ["step_2: Determine whether PowerShell spawned a child process"]}}
    if structured:
        inv["investigation_analysis"] = analysis
        inv["confidence"] = "Medium"
        inv["severity_justification"] = "SEV-JUSTIFICATION-TOKEN"
        inv["confidence_justification"] = "CONF-JUSTIFICATION-TOKEN"
    inv.update(extra)
    return inv


def _indicator(value, status, *, typ="ip", malicious=0, category=None, roles=("destination",)):
    ind = {"value": value, "type": typ, "roles": list(roles), "origins": ["Parsed network indicators"],
           "status": status, "status_category": category, "providers": {}}
    if status == "enriched":
        ind["providers"] = {"virustotal": {"status": "completed", "malicious": malicious, "suspicious": 0},
                            "abuseipdb": {"status": "completed", "abuse_confidence_score": 60 if malicious else 0},
                            "otx": {"status": "completed", "pulse_count": 2 if malicious else 0}}
    return ind


def _new_ti(case=CASE, *, warnings=("OTX lookup for 203.0.113.9 failed.",)):
    return {"incident_id": case, "status": "completed_with_warnings", "enrichment_risk_level": "Medium",
            "enrichment_risk_score": 55, "enrichment_risk_reasons": ["VT flagged 203.0.113.9"],
            "warnings": list(warnings),
            "enriched_alert": {"incident_id": case, "alert_id": case, "severity": "Low",
                               "source_ip": "10.0.0.5", "iocs": ["203.0.113.9"]},
            "threat_intelligence": {
                "indicators": [_indicator("203.0.113.9", "enriched", malicious=4),
                               _indicator("192.0.2.50", "skipped", category="limit"),
                               _indicator("10.0.0.5", "excluded", category="private", roles=("source",))],
                "coverage": {"extracted": 3, "eligible": 2, "enriched": 1, "excluded": 1, "skipped": 1},
                "provider_coverage": {"virustotal": {"label": "VirusTotal", "state": "available"}},
                "intelligence_gaps": ["1 eligible indicator(s) skipped -- enrichment limit reached."]}}


def _legacy_ti(case=CASE):
    return {"incident_id": case, "status": "completed", "enrichment_risk_level": "Low", "enrichment_risk_score": 10,
            "warnings": [], "threat_intelligence": {
                "iocs": {"ip_indicators": ["203.0.113.9"], "domain_indicators": [], "file_hashes": []},
                "virustotal": {"ip_results": [{"indicator": "203.0.113.9", "status": "completed",
                                               "malicious": 3, "suspicious": 0}]}}}


def _handoff(tmp_path, monkeypatch, *, triage=None, inv="default", ti="new", incident=None):
    monkeypatch.setattr(wf, "REP_DIR", tmp_path)
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: {"available": False})
    ti_result = {"new": _new_ti(), "legacy": _legacy_ti()}.get(ti, ti) if isinstance(ti, str) else ti
    wf.handoff_to_reporting(triage or _triage(), incident or {"id": CASE, "title": "Beaconing host"},
                            _investigation() if inv == "default" else inv, threat_intel_result=ti_result)
    read = lambda rel: json.loads((tmp_path / rel).read_text(encoding="utf-8"))
    return {"triage": read("outputs/triage_result.json"), "enriched": read("inputs/enriched_alert.json"),
            "investigation": read("outputs/investigation_result.json"),
            "ti": read("inputs/threat_intel_result.json") if (tmp_path / "inputs/threat_intel_result.json").exists() else {}}


def _inputs(files, processed=None):
    return {"processed_alert": processed or {"alert_id": CASE, "severity": "Low", "risk_score": 70},
            "enriched_alert": files["enriched"], "triage_result": files["triage"],
            "investigation_result": files["investigation"], "threat_intel_result": files["ti"],
            "workflow_metadata": {"incident_id": CASE, "run_id": "run-1"}}


def _context(tmp_path, monkeypatch, **kw):
    files = _handoff(tmp_path, monkeypatch, **kw)
    return build_context(_inputs(files)), files


# ── 1-2, 22, 25-26: structured vs fallback, source, latest, identity ────────

def test_01_structured_investigation_result(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch)
    assert ctx["investigation_result_source"] == "structured_json"
    assert ctx["severity"]["label"] == "Critical" and ctx["severity"]["source"] == "Investigation"
    assert ctx["investigation_summary"] == "Investigation summary."
    assert files["investigation"]["investigation_analysis"]["severity"] == "Critical"


def test_02_22_markdown_fallback_is_visible(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch, inv=_investigation(structured=False))
    assert ctx["investigation_result_source"] == "markdown_fallback"
    appendix = build_appendix_summaries(ctx)
    assert appendix["investigation"]["Result Source"] == "markdown_fallback"
    assert ctx["confidence"]["source"] == "not available"               # no structured confidence
    missing, _ = _context(tmp_path, monkeypatch, inv=None)
    assert missing["investigation_result_source"] == "missing"


def test_25_latest_investigation_result_is_handed_off(tmp_path, monkeypatch):
    latest = _investigation(severity="High", summary="LATEST-RESULT-TOKEN")
    captured = {}

    class _Renewer:
        def __init__(self, *a, **k):
            self.lease_lost, self.global_lock_lost = threading.Event(), threading.Event()
        start = stop = also_renew_global_lock = lambda self, *a, **k: None

    def _capture(triage, incident, investigation_result, **kw):
        captured["investigation_result"] = investigation_result
        raise RuntimeError("stop after handoff")

    # Phase 6: Reporting reads its inputs from the canonical persisted state
    # (readiness-checked), so the latest result is persisted in a real
    # canonical run rather than served from a mocked get_state().
    run_id = wss.start_run(CASE)
    seed.seed_parsing_and_raw_incident(CASE, run_id)
    seed.approve_triage(CASE, run_id, _triage())
    wss._guarded_update(CASE, run_id, {"threat_intel_status": "Complete",
                                       "threat_intel_result_json": json.dumps(
                                           seed.threat_intel_result(CASE, run_id, _new_ti()))})
    latest = seed.approve_investigation(CASE, run_id, latest)
    monkeypatch.setattr(wf, "claim_stage", lambda *a, **k: ("worker", 1))
    monkeypatch.setattr(wf, "LeaseRenewer", _Renewer)
    for name in ("acquire_global_lock", "release_global_lock", "release_stage_lease",
                 "set_worker_progress_note", "_save_run_artifact", "complete_stage"):
        monkeypatch.setattr(wf, name, lambda *a, **k: True)
    monkeypatch.setattr(wf.wss, "set_last_error", lambda *a, **k: None)
    monkeypatch.setattr(wf, "load_raw_incident_for_run", lambda *a, **k: {})
    monkeypatch.setattr(wf, "handoff_to_reporting", _capture)
    assert wf.run_reporting_stage(CASE, run_id) == {"status": "failed"}
    assert captured["investigation_result"] == latest                     # state.investigation_result_json


def test_26_case_identity_is_preserved(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch)
    assert ctx["incident_id"] == CASE
    assert files["investigation"]["incident_id"] == CASE and files["triage"]["incident_id"] == CASE
    foreign_ti = _new_ti()
    foreign_ti["enriched_alert"]["incident_id"] = foreign_ti["enriched_alert"]["alert_id"] = "INC-99999"
    files = _handoff(tmp_path, monkeypatch, ti=foreign_ti)
    assert files["enriched"]["canonical"] is False                        # foreign enriched alert refused
    assert files["enriched"]["incident_id"] == CASE


# ── 3-4, 27: MITRE ownership ────────────────────────────────────────────────

def test_03_investigation_and_triage_mitre_stay_distinct(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch)
    assert "mitre_mapping" not in files["investigation"]                  # no injected Triage MITRE
    assert ctx["investigation_mitre"] == INV_MITRE and ctx["mitre_mapping"] == INV_MITRE
    assert ctx["triage_mitre"] == {"tactic": "Execution", "technique": "T1059.001", "source": "Triage"}
    assert files["triage"]["mitre_tactic"] == "Execution"
    assert ctx["mitre_mapping_source"] == "Investigation"
    assert repair_mitre_mapping(ctx, {}) == INV_MITRE


def test_04_no_investigation_mitre_is_not_fabricated_from_triage(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch, inv=_investigation(mitre=False))
    assert "mitre_mapping" not in files["investigation"]
    assert ctx["mitre_mapping"] == [] and ctx["investigation_mitre"] == []
    assert ctx["mitre_mapping_source"].startswith("none")
    assert ctx["triage_mitre"]["tactic"] == "Execution"                   # still shown, as Triage's
    recovered = repair_mitre_mapping(ctx, {})
    assert recovered and all("not an Investigation mapping" in row["mapping_source"] for row in recovered)
    assert ctx["mitre_mapping_source"] == "Reporting recovery (no Investigation MITRE mapping)"


def test_27_no_triage_field_is_presented_as_investigation_owned(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch, inv=_investigation(structured=False, severity=""))
    assert "severity" not in files["triage"] and files["triage"]["triage_level"] == "HIGH"
    assert ctx["severity"]["source"] == "Triage level (Investigation severity unavailable)"
    assert "Investigation severity unavailable" in ctx["severity"]["reason"]
    assert ctx["severity_sources"]["investigation_severity"]["value"] is None
    assert ctx["classification_source"] == "Triage"
    kf = next(f for f in ctx["key_findings"] if f["finding_id"] == "KF-001")
    assert "Triage-owned" in kf["interpretation"] and kf["evidence_refs"] == ["triage_result.json"]
    appendix = build_appendix_summaries(ctx)
    assert "Severity" not in appendix["triage"] and "Confidence" not in appendix["triage"]
    assert appendix["triage"]["Triage Level"] == "HIGH" and appendix["triage"]["Category"] == "Malware"


# ── 5-7: severity sources and justifications ───────────────────────────────

def test_05_differing_severities_keep_their_owners(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch)
    sources = ctx["severity_sources"]
    assert sources["netwitness_severity"] == {"value": "Low", "source": "NetWitness alert (as normalised by Parsing)"}
    assert sources["triage_level"] == {"value": "HIGH", "source": "Triage"}
    assert sources["ti_enrichment_level"]["value"] == "Medium" and sources["ti_enrichment_score"]["value"] == 55
    assert sources["investigation_severity"] == {"value": "Critical", "source": "Investigation"}
    assert sources["investigation_confidence"]["value"] == "Medium"
    assert ctx["severity"]["label"] == "Critical"                         # final = Investigation's


def test_05b_field_provenance_never_credits_the_enriched_alert_with_severity(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch, inv=_investigation(structured=False, severity=""))
    _apply_field_provenance(ctx, {})
    assert ctx["field_provenance"]["severity"]["source"] == "triage_result"
    assert "Investigation severity unavailable" in ctx["field_provenance"]["severity"]["source_path"]


def test_06_07_canonical_justifications_are_used(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch)
    assert ctx["severity"]["reason"] == "SEV-JUSTIFICATION-TOKEN"
    assert ctx["confidence"]["reason"] == "CONF-JUSTIFICATION-TOKEN"
    assert ctx["confidence"]["source"] == "Investigation"


# ── 8-9, 12-17: IOCs and Threat Intelligence ───────────────────────────────

def test_08_09_cluster_indicators_kept_out_of_current_case_iocs(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch)
    assert "indicators" not in files["investigation"] and "iocs" not in files["investigation"]
    assert files["investigation"]["correlation_cluster_indicators"] == ["10.9.9.9", "198.18.0.77", "192.168.10."]
    assert ctx["correlation_cluster_indicators"] == ["10.9.9.9", "198.18.0.77", "192.168.10."]
    values = {i["value"] for i in rebuild_iocs(ctx, {})}
    assert "203.0.113.9" in values
    assert not values & {"10.9.9.9", "198.18.0.77", "192.168.10."}
    # an Investigation result that still carries the cluster set as "indicators" is not a candidate either
    ctx["raw_inputs"]["investigation_result"]["indicators"] = ["10.9.9.9"]
    assert "10.9.9.9" not in {i["value"] for i in rebuild_iocs(ctx, {})}
    assert build_appendix_summaries(ctx)["investigation"]["Correlation Cluster Indicators"] == 3


def test_10_new_ti_provider_verdicts_reach_ioc_rows(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch)
    row = next(i for i in rebuild_iocs(ctx, {}) if i["value"] == "203.0.113.9")
    assert row["reputation"] == "VirusTotal 4 malicious, 0 suspicious; AbuseIPDB confidence 60; OTX 2 pulse(s)"
    assert row["confidence"] == "High" and row["ti_status"] == "enriched"
    assert row["roles"] == ["destination"] and row["origins"] == ["Parsed network indicators"]


def test_11_12_13_ti_coverage_warnings_and_gaps(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch)
    assert ctx["ti_contract"] == "multi_indicator"
    assert ctx["ti_coverage"]["skipped"] == 1 and ctx["ti_provider_coverage"]["virustotal"]["state"] == "available"
    assert ctx["ti_warnings"] == ["OTX lookup for 203.0.113.9 failed."]
    assert ctx["ti_intelligence_gaps"] == ["1 eligible indicator(s) skipped -- enrichment limit reached."]
    appendix = ctx["appendix_summaries"]["enriched_alert"]
    assert "OTX lookup" in appendix["TI Warnings"] and "skipped" in appendix["Intelligence Gaps"]
    assert "enriched: 1" in appendix["TI Coverage"]


def test_14_15_16_skipped_excluded_and_not_checked_are_never_benign(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch)
    ctx["iocs"] = [{"value": "198.51.100.200", "type": "ip"}]               # in no TI record
    rows = {i["value"]: i for i in rebuild_iocs(ctx, {})}
    assert rows["192.0.2.50"]["ti_status"] == "skipped"
    assert rows["192.0.2.50"]["reputation"].startswith("Not checked by Threat Intelligence (skipped: limit)")
    assert rows["10.0.0.5"]["ti_status"] == "excluded"
    assert "Excluded from Threat Intelligence lookup (private)" in rows["10.0.0.5"]["reputation"]
    assert rows["198.51.100.200"]["ti_status"] == "not_checked"
    for value in ("192.0.2.50", "10.0.0.5", "198.51.100.200"):
        assert "not evidence of benign" in rows[value]["reputation"]
        assert rows[value]["confidence"] != "High"


def test_17_old_ti_contract(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch, ti="legacy")
    assert ctx["ti_contract"] == "legacy"
    assert files["enriched"]["canonical"] is False                        # legacy TI has no enriched_alert
    row = next(i for i in rebuild_iocs(ctx, {}) if i["value"] == "203.0.113.9")
    assert row["source"] == "VirusTotal" and "3 malicious" in row["reputation"]


def test_18_new_ti_contract(tmp_path, monkeypatch):
    ctx, files = _context(tmp_path, monkeypatch, ti="new")
    assert ctx["ti_contract"] == "multi_indicator" and files["enriched"]["canonical"] is True


def test_19_partial_ti_contract(tmp_path, monkeypatch):
    partial = {"incident_id": CASE, "status": "completed_with_warnings", "warnings": ["AbuseIPDB unavailable"],
               "threat_intelligence": {"indicators": [_indicator("203.0.113.9", "enriched", malicious=1)]}}
    ctx, _ = _context(tmp_path, monkeypatch, ti=partial)
    assert ctx["ti_coverage"] == {} and ctx["ti_intelligence_gaps"] == []
    assert ctx["ti_warnings"] == ["AbuseIPDB unavailable"]
    assert ctx["appendix_summaries"]["enriched_alert"]["TI Coverage"] == "Not recorded in this TI result"
    row = next(i for i in rebuild_iocs(ctx, {}) if i["value"] == "203.0.113.9")
    assert "1 malicious" in row["reputation"]


# ── 20-21: evidence gaps vs Reporting's missing fields ─────────────────────

def test_20_evidence_gaps_do_not_populate_missing_required_fields(tmp_path, monkeypatch):
    ctx, _ = _context(tmp_path, monkeypatch)
    gap = "step_2: Determine whether PowerShell spawned a child process"
    assert [g["gap"] for g in ctx["evidence_gaps"]] == [gap]
    assert ctx["missing_required_fields"] == [] and ctx["missing_fields"] == []
    assert ctx["report_completeness_score"] == 65                          # score formula unchanged


def test_21_reporting_field_gaps_still_populate_missing_required_fields(tmp_path, monkeypatch):
    investigation = _investigation(structured=False, severity="")
    investigation.pop("incident_id")
    ctx = build_context({"processed_alert": {"severity": "Low"}, "enriched_alert": {}, "triage_result": {},
                         "investigation_result": investigation, "threat_intel_result": {}})
    assert [g["gap"] for g in ctx["evidence_gaps"]]                       # gaps exist, but are not fields
    assert "alert_id" in ctx["missing_required_fields"]
    assert "severity" in ctx["missing_required_fields"] and "confidence" in ctx["missing_required_fields"]
    assert not any(str(f).startswith("step_") for f in ctx["missing_required_fields"])


# ── 23-24: TI canonical enriched alert ─────────────────────────────────────

def test_23_canonical_ti_enriched_alert_is_used(tmp_path, monkeypatch):
    files = _handoff(tmp_path, monkeypatch)
    enriched = files["enriched"]
    assert enriched["enriched_alert_source"] == "threat_intelligence" and enriched["canonical"] is True
    assert enriched["source_ip"] == "10.0.0.5" and "raw_incident" not in enriched
    assert enriched["severity"] == "Low"                                  # NetWitness/Parsing value, not Triage's


def test_24_legacy_reconstruction_is_labelled_non_canonical(tmp_path, monkeypatch):
    files = _handoff(tmp_path, monkeypatch, ti={"incident_id": CASE, "status": "completed"})
    enriched = files["enriched"]
    assert enriched["enriched_alert_source"] == "reconstructed_triage_raw" and enriched["canonical"] is False
    assert "severity" not in enriched                                     # no Triage-derived severity


# ── 28 + Triage document + empty Investigation ─────────────────────────────

def test_28_skills_sidecar_never_overwrites_investigation_fields():
    inv = _investigation()
    inv["iocs"] = ["203.0.113.9"]
    before = copy.deepcopy(inv)
    bundle = {"available": True, "mitre_mapping": ["T1110 Brute Force"], "iocs": [{"value": "1.2.3.4"}],
              "affected_assets": [], "affected_users": [], "recommended_actions": [],
              "skills_intelligence": {"diamond_model": {}}}
    out = skills_sidecar.enrich_investigation_result(inv, bundle)
    for key in ("mitre_mappings", "iocs", "severity", "recommended_containment", "investigation_analysis"):
        assert out[key] == before[key]
    assert "mitre_mapping" not in out
    assert out["skills_intelligence"]["skills_mitre_mapping"] == ["T1110 Brute Force"]
    assert out["skills_intelligence"]["skills_iocs"] == [{"value": "1.2.3.4"}]


@pytest.mark.parametrize("triage, status", [
    (_triage(), "completed"),
    ({"ticket": {"incident_id": CASE}, "error": "LLM timeout", "metakeys_payload": {}}, "failed"),
    ({"metakeys_payload": {"incident_id": CASE}}, "not_recorded"),
])
def test_triage_document_status_is_derived_not_fabricated(tmp_path, monkeypatch, triage, status):
    assert _handoff(tmp_path, monkeypatch, triage=triage)["triage"]["status"] == status


def test_empty_investigation_result_is_not_dressed_up(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(wf, "REP_DIR", tmp_path)
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: calls.append(1) or {"available": True})
    wf.handoff_to_reporting(_triage(), {"id": CASE}, {}, threat_intel_result=_new_ti())
    assert json.loads((tmp_path / "outputs/investigation_result.json").read_text(encoding="utf-8")) == {}
    assert calls == []                                                     # sidecar not run on nothing
    from agents.reporting.reporting.input_loader import ReportingInputError, load_reporting_inputs
    (tmp_path / "inputs/investigation_result.json").write_text("{}", encoding="utf-8")
    (tmp_path / "inputs/triage_result.json").write_text(json.dumps({"incident_id": CASE}), encoding="utf-8")
    (tmp_path / "inputs/processed_alert.json").write_text(json.dumps({"alert_id": CASE}), encoding="utf-8")
    with pytest.raises(ReportingInputError, match="investigation_result"):
        load_reporting_inputs(tmp_path / "inputs")
