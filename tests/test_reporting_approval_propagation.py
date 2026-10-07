"""tests/test_reporting_approval_propagation.py -- canonical audit Phase 4.

Human approval decisions reach Reporting from the canonical workflow_approvals
audit table (run-scoped approval_history.json), one attributed record per gate:
Triage Approval / Investigation Approval / Report Generation Approval. Run and
attempt binding, rejection handling, verbatim analyst/comment values, no
fabricated approver or comment, the candidate report's Reporting gate stays
Pending, and the rendered report and reporting_result.json agree.
Real state_store transitions on a temporary DB; no LLM, no subprocess.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from workflow import engine as wf
from workflow import state_store as wss
import agents.investigation.skills_sidecar as skills_sidecar
from agents.reporting.reporting import export_context_enhancer as ece
from agents.reporting.reporting.context_builder import build_context
from agents.reporting.reporting.output_writer import build_reporting_result

CASE = "INC-53011"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    wss.db_init()
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", tmp_path / "trusted")
    monkeypatch.setattr(wf, "REP_DIR", tmp_path / "rep")
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: {"available": False})
    monkeypatch.setattr(ece, "enhance_narrative", lambda context: {})        # no LLM path


def _triage(case=CASE):
    return {"ticket": {"incident_id": case, "unc": "#00042A", "classification": "HIGH", "title": "Case",
                       "incident_category": "Malware", "mitre_tactic": "Execution", "mitre_technique": "T1059.001"},
            "metakeys_payload": {"incident_id": case, "incident_title": "Case"}}


def _investigation(case=CASE):
    return {"agent": "Investigation Agent", "incident_id": case, "investigated_for": case, "status": "completed",
            "severity": "High", "confidence": "Medium", "indicators": ["10.9.9.9"],
            "mitre_mappings": [{"timeline_phase": "C2", "observed_evidence": "HTTPS", "tactic": "Command and Control",
                                "technique_name": "Web Protocols", "technique_id": "T1071.001"}],
            "workflow": {"investigation_source": "structured_json"},
            "investigation_analysis": {"incident_id": case, "severity": "High", "confidence": "Medium",
                                       "severity_justification": "SEV-J", "confidence_justification": "CONF-J",
                                       "mitre_mappings": [{"timeline_phase": "C2", "observed_evidence": "HTTPS",
                                                           "tactic": "Command and Control",
                                                           "technique_name": "Web Protocols",
                                                           "technique_id": "T1071.001"}]}}


def _ti(case=CASE):
    return {"incident_id": case, "status": "completed", "enrichment_risk_level": "Low", "enrichment_risk_score": 5,
            "warnings": [], "enriched_alert": {"incident_id": case, "alert_id": case, "severity": "Low"},
            "threat_intelligence": {"indicators": []}}


def _await(case, run, stage):
    wss._guarded_update(case, run, {f"{stage}_status": "Awaiting Approval",
                                    "workflow_status": "Awaiting Approval", "approval_stage": stage})


def _decide(case, run, stage, decision, analyst, comments=""):
    _await(case, run, stage)
    if decision == "approved":
        getattr(wss, f"approve_{stage}")(case, run, approved_by=analyst, comments=comments)
    else:
        getattr(wss, f"reject_{stage}")(case, run, rejected_by=analyst, reason=comments)


def _new_run(case=CASE, retry=False):
    run = wss.start_run(case, allow_retry=retry)
    wss._guarded_update(case, run, {"parsing_status": "Complete", "threat_intel_status": "Complete"})
    return run


def _report(case, run, *, attempt=1, render_dir=None):
    """Run-scoped handoff -> build_context -> enhance_export_context (as the
    Reporting agent does); returns (context, inputs dir)."""
    wf.handoff_to_reporting(_triage(case), {"id": case}, _investigation(case), threat_intel_result=_ti(case),
                            incident_id=case, run_id=run, reporting_stage_attempt=attempt)
    attempt_dir = wf.reporting_attempt_dir(case, run, attempt)
    read = lambda rel: json.loads((attempt_dir / rel).read_text(encoding="utf-8"))
    inputs = {"processed_alert": {"alert_id": case, "severity": "Medium"},
              "enriched_alert": read("inputs/enriched_alert.json"), "triage_result": read("outputs/triage_result.json"),
              "investigation_result": read("outputs/investigation_result.json"),
              "threat_intel_result": read("inputs/threat_intel_result.json"),
              "approval_history": read("inputs/approval_history.json"),
              "workflow_metadata": read("inputs/workflow_metadata.json")}
    ctx = ece.enhance_export_context(build_context(inputs))
    return ctx, attempt_dir


def _approved_pipeline(triage_by="alice", inv_by="bob", triage_comment="", inv_comment=""):
    run = _new_run()
    _decide(CASE, run, "triage", "approved", triage_by, triage_comment)
    _decide(CASE, run, "investigation", "approved", inv_by, inv_comment)
    return run


# ── 1-7: per-gate status and attribution ───────────────────────────────────

def test_triage_and_investigation_approved_by_different_analysts():
    run = _approved_pipeline(triage_by="alice", inv_by="bob")
    ctx, _ = _report(CASE, run)
    ac = ctx["approval_context"]
    assert ac["source"] == "workflow_approvals (run-scoped approval_history.json)"
    assert ac["triage"]["status"] == "Approved" and ac["triage"]["actor"] == "alice"
    assert ac["investigation"]["status"] == "Approved" and ac["investigation"]["actor"] == "bob"
    assert ac["investigation"]["stage_attempt"] == 1 and ac["investigation"]["run_id"] == run
    assert ac["triage"]["timestamp"] and ac["investigation"]["timestamp"]


@pytest.mark.parametrize("stage", ["triage", "investigation"])
def test_rejected_stage_is_never_shown_as_approved(stage):
    run = _new_run()
    if stage == "investigation":
        _decide(CASE, run, "triage", "approved", "alice")
    _decide(CASE, run, stage, "rejected", "carol", "Insufficient evidence for host WS-01")
    ctx, _ = _report(CASE, run)
    record = ctx["approval_context"][stage]
    assert record["status"] == "Rejected" and record["actor"] == "carol"
    assert record["comment"] == "Insufficient evidence for host WS-01"


@pytest.mark.parametrize("stage", ["triage", "investigation"])
def test_undecided_stage_is_pending_not_approved(stage):
    run = _new_run()
    if stage == "investigation":
        _decide(CASE, run, "triage", "approved", "alice")
    ctx, _ = _report(CASE, run)
    record = ctx["approval_context"][stage]
    assert record["status"] == "Pending"
    assert record["actor"] == "Not recorded" and record["comment"] == "None recorded"
    assert record["timestamp"] is None


# ── 8-10, 17-19: values verbatim, nothing fabricated ───────────────────────

def test_comments_and_analyst_pass_through_verbatim_and_absences_are_explicit():
    comment = "Approved — verified with endpoint owner;  see ticket #4471 (no reimage)"
    run = _approved_pipeline(triage_by="Soong Yang", inv_by="sy", triage_comment=comment, inv_comment="")
    ctx, _ = _report(CASE, run)
    ac = ctx["approval_context"]
    assert ac["triage"]["comment"] == comment                              # byte-for-byte
    assert ac["triage"]["actor"] == "Soong Yang"
    assert ac["investigation"]["comment"] == "None recorded"               # not invented
    assert ac["reporting"]["actor"] == "Not recorded"                      # not "SOC Analyst"
    flat = json.dumps(ctx, default=str)
    assert "SOC Analyst" not in json.dumps(ctx["approval_context"]) and "No approval comments supplied" not in flat
    assert ctx["approval"]["approved_by"] == "Not recorded"
    assert ctx["approval"]["analyst_comments"] == "None recorded"


def test_absent_analyst_is_not_fabricated():
    run = _new_run()
    _decide(CASE, run, "triage", "approved", "")
    ctx, _ = _report(CASE, run)
    assert ctx["approval_context"]["triage"]["actor"] == "Not recorded"
    assert "SOC Analyst" not in "\n".join(ctx["approval_summary"].values())


# ── 11-13: run, attempt and history binding ────────────────────────────────

def test_stale_run_and_foreign_case_are_ignored():
    old_run = _approved_pipeline(triage_by="old-alice", inv_by="old-bob")
    new_run = _new_run(retry=True)
    assert new_run != old_run
    _decide(CASE, new_run, "triage", "approved", "new-alice")
    ctx, attempt_dir = _report(CASE, new_run)
    ac = ctx["approval_context"]
    assert ac["triage"]["actor"] == "new-alice" and ac["triage"]["run_id"] == new_run
    assert ac["investigation"]["status"] == "Pending"                      # old run's approval NOT inherited
    history = json.loads((attempt_dir / "inputs/approval_history.json").read_text(encoding="utf-8"))
    assert {r["run_id"] for r in history} == {new_run}
    # rows smuggled into the history from another run / case are still ignored
    from agents.reporting.reporting.context_builder import _build_approval_context
    foreign = [{"incident_id": CASE, "run_id": old_run, "approval_stage": "investigation", "decision": "approved",
                "analyst": "x", "stage_attempt": 1, "approval_attempt": 1, "decided_at": "2026-01-01"},
               {"incident_id": "INC-OTHER", "run_id": new_run, "approval_stage": "investigation",
                "decision": "approved", "analyst": "y", "stage_attempt": 1, "approval_attempt": 1, "decided_at": "2026-01-02"}]
    ctx2 = _build_approval_context(history + foreign, {}, {"run_id": new_run, "investigation_attempt": 1}, CASE)
    assert ctx2["investigation"]["status"] == "Pending"


def test_new_investigation_attempt_without_decision_is_pending():
    run = _approved_pipeline(inv_by="bob")
    wss._guarded_update(CASE, run, {"investigation_attempt": 2})          # what rerun_stage() advances
    ctx, _ = _report(CASE, run)
    inv = ctx["approval_context"]["investigation"]
    assert inv["status"] == "Pending" and inv["stage_attempt"] == 2
    assert [p["decision"] for p in inv["previous_decisions"]] == ["Approved"]
    assert inv["previous_decisions"][0]["actor"] == "bob" and inv["previous_decisions"][0]["stage_attempt"] == 1


def test_rejection_followed_by_approval_on_a_later_attempt():
    run = _new_run()
    _decide(CASE, run, "triage", "approved", "alice")
    _decide(CASE, run, "investigation", "rejected", "carol", "Missing process tree")
    wss._guarded_update(CASE, run, {"investigation_attempt": 2})
    _decide(CASE, run, "investigation", "approved", "dave", "Process tree now present")
    ctx, _ = _report(CASE, run)
    inv = ctx["approval_context"]["investigation"]
    assert inv["status"] == "Approved" and inv["actor"] == "dave" and inv["stage_attempt"] == 2
    assert inv["previous_decisions"] == [{**inv["previous_decisions"][0], "decision": "Rejected", "actor": "carol",
                                          "comment": "Missing process tree", "stage_attempt": 1}]
    appendix = ctx["appendix_summaries"]["approval"]
    assert "Rejected by carol" in appendix["Investigation Approval Earlier Decisions"]
    assert appendix["Investigation Approval Status"] == "Approved"


def test_triage_current_decision_is_bound_to_the_current_attempt():
    # Canonical audit R5: Triage decisions are stamped with the real
    # triage_attempt (previously always 1), so the approval of attempt 2 is
    # its own first decision (approval_attempt=1) and attempt 1's rejection
    # is history only.
    run = _new_run()
    _decide(CASE, run, "triage", "rejected", "carol", "re-run triage")
    wss._guarded_update(CASE, run, {"triage_attempt": 2})
    _decide(CASE, run, "triage", "approved", "alice")
    ctx, _ = _report(CASE, run)
    tri = ctx["approval_context"]["triage"]
    assert tri["status"] == "Approved" and tri["actor"] == "alice"
    assert (tri["stage_attempt"], tri["approval_attempt"]) == (2, 1)
    assert [(p["decision"], p["stage_attempt"]) for p in tri["previous_decisions"]] == [("Rejected", 1)]


# ── 16, 23-24: Reporting gate, labels, JSON == rendered report ─────────────

def test_reporting_gate_is_pending_in_the_candidate_report_even_with_earlier_reporting_decisions():
    run = _approved_pipeline()
    _decide(CASE, run, "reporting", "rejected", "erin", "Wrong host in summary")
    wss._guarded_update(CASE, run, {"reporting_attempt": 2})
    ctx, _ = _report(CASE, run, attempt=2)
    rep = ctx["approval_context"]["reporting"]
    assert rep["status"] == "Pending" and rep["actor"] == "Not recorded"
    assert [p["decision"] for p in rep["previous_decisions"]] == ["Rejected"]
    assert ctx["report_generation_approval"]["status"] == "Pending"
    assert ctx["approval"]["approval_status"] == "pending"
    assert ctx["approval_summary"]["report"].startswith("Report generation approval status: Pending -- awaiting final")


def test_rendered_report_and_reporting_result_json_agree(tmp_path):
    from agents.reporting.reporting.report_renderer import render_reports
    run = _approved_pipeline(triage_by="alice", inv_by="bob", inv_comment="Scope confirmed")
    ctx, _ = _report(CASE, run)
    out = tmp_path / "render"
    generated = render_reports(ctx, output_dir=out)
    text = Path(generated["final_incident_report"]).read_text(encoding="utf-8")
    appendix_d = text.split("Appendix D: Approval Summary")[1].split("Appendix E")[0]
    assert "Triage Approval Status: Approved" in appendix_d and "Triage Approval By: alice" in appendix_d
    assert "Investigation Approval By: bob" in appendix_d and "Investigation Approval Comment: Scope confirmed" in appendix_d
    assert "Report Generation Approval Status: Pending" in appendix_d
    assert "Report Generation Approval By: Not recorded" in appendix_d
    assert "SOC Analyst" not in appendix_d and "No approval comments supplied" not in text
    section_10_2 = text.split("10.2 Containment and Approval Status")[1].split("10.3")[0]
    assert "Triage approval: Approved by alice at " in section_10_2
    assert "Investigation approval: Approved by bob at " in section_10_2 and "comment: Scope confirmed" in section_10_2
    assert "Report generation approval status: Pending -- awaiting final Reporting approval" in section_10_2
    result = build_reporting_result(ctx, generated)
    assert result["approval_context"] == ctx["approval_context"]
    for stage, label in (("triage", "Triage"), ("investigation", "Investigation"), ("reporting", "Report Generation")):
        record = result["approval_context"][stage]
        assert f"{label} Approval Status: {record['status']}" in appendix_d
        assert f"{label} Approval By: {record['actor']}" in appendix_d
        assert f"{label} Approval Comment: {record['comment']}" in appendix_d


def test_appendix_and_summary_use_explicit_stage_labels():
    run = _approved_pipeline(triage_by="alice", inv_by="bob")
    ctx, _ = _report(CASE, run)
    appendix = ctx["appendix_summaries"]["approval"]
    assert appendix["Triage Approval Status"] == "Approved" and appendix["Investigation Approval By"] == "bob"
    assert appendix["Report Generation Approval Status"] == "Pending"
    assert "Comments" not in appendix
    summary = ctx["approval_summary"]
    assert summary["triage"].startswith("Triage approval: Approved by alice at ")
    assert summary["investigation"].startswith("Investigation approval: Approved by bob at ")
    rows = dict(ctx["approval_summary_table"])
    assert rows["Triage approval"].startswith("Approved by alice") and "Investigation approval" in rows


# ── 14-15, 22: legacy mode and run-scoped history ──────────────────────────

def test_legacy_investigation_approval_is_not_report_generation_approval():
    legacy = {"decision": "approved", "analyst": "legacy-analyst", "comments": "LGTM", "approval_gate": "investigation"}
    ctx = ece.enhance_export_context(build_context({
        "processed_alert": {"alert_id": CASE}, "triage_result": _triage(), "investigation_result": _investigation(),
        "threat_intel_result": _ti(), "approval_result": legacy, "approval_history": {}}))
    ac = ctx["approval_context"]
    assert ac["source"] == "legacy approval_result.json"
    assert ac["investigation"]["status"] == "Approved" and ac["investigation"]["actor"] == "legacy-analyst"
    assert ac["investigation"]["comment"] == "LGTM"
    assert ac["triage"]["status"] == "Not recorded"
    assert ac["reporting"]["status"] == "Pending"
    assert ctx["report_generation_approval"]["status"] == "Pending"
    assert ctx["report_generation_approval"]["approved_by"] == "Not recorded"     # not "legacy-analyst"
    assert ctx["appendix_summaries"]["approval"]["Investigation Approval By"] == "legacy-analyst"


def test_run_scoped_approval_history_survives_the_handoff():
    run = _approved_pipeline(triage_by="alice", inv_by="bob")
    _, attempt_dir = _report(CASE, run)
    history = json.loads((attempt_dir / "inputs/approval_history.json").read_text(encoding="utf-8"))
    assert [(r["approval_stage"], r["analyst"]) for r in history] == [("triage", "alice"), ("investigation", "bob")]
    manifest = json.loads((attempt_dir / "inputs/handoff_manifest.json").read_text(encoding="utf-8"))
    assert "inputs/approval_history.json" in {k.replace("\\", "/") for k in manifest["files"]}
    meta = json.loads((attempt_dir / "inputs/workflow_metadata.json").read_text(encoding="utf-8"))
    assert meta["investigation_attempt"] == 1 and meta["reporting_attempt"] == 1 and meta["run_id"] == run
    assert not (attempt_dir / "inputs/approval_result.json").exists()     # no shared-folder dependency


# ── 20-21, 25: Phase 3 mappings, identity, Agent Activity ──────────────────

def test_phase3_mappings_and_case_identity_are_unchanged():
    run = _approved_pipeline()
    ctx, _ = _report(CASE, run)
    assert ctx["incident_id"] == CASE and ctx["approval_context"]["case_id"] == CASE
    assert ctx["severity"]["source"] == "Investigation" and ctx["severity"]["reason"] == "SEV-J"
    assert ctx["triage_mitre"]["source"] == "Triage" and ctx["mitre_mapping_source"] == "Investigation"
    assert ctx["correlation_cluster_indicators"] == ["10.9.9.9"]
    assert "10.9.9.9" not in {i["value"] for i in ctx["iocs"]}
    assert ctx["investigation_result_source"] == "structured_json"


def test_field_provenance_credits_the_reporting_gate():
    run = _approved_pipeline()
    ctx, _ = _report(CASE, run)
    # A Pending gate is undecided: no provenance is claimed for it, and in
    # particular never the legacy approval_result.json.
    provenance = ctx["field_provenance"]
    for field in ("approval_status", "analyst_decision", "approved_by"):
        assert provenance.get(field, {}).get("source") in (None, "approval_context")
    assert "approved_by" not in provenance                                 # nothing recorded -> nothing claimed
    assert not any(item.get("recovered_from") == "approval_result" for item in ctx["recovered_fields"])


def test_agent_activity_handoff_counts_the_canonical_history(tmp_path):
    from observability import context, emitter
    from observability.adapters import reporting_adapter
    from observability.store import ActivityStore, query_events

    run = _approved_pipeline()
    wf.handoff_to_reporting(_triage(), {"id": CASE}, _investigation(), threat_intel_result=_ti(),
                            incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    store = ActivityStore(tmp_path / "a.db")
    emitter.attach_store(store)
    token = context.set_scope(context.RunScope(case_id=CASE, run_id=run, stage="reporting", data={}))
    try:
        reporting_adapter._handoff_after({"incident_id": CASE, "run_id": run, "reporting_stage_attempt": 1,
                                          "investigation_result": _investigation(), "threat_intel_result": _ti()},
                                         None, "TKT-1")
    finally:
        context.reset_scope(token)
    assert store.flush()
    event = next(e for e in query_events(case_id=CASE, path=store.path) if e["title"] == "Reporting hand-off written")
    assert "2" in json.dumps(event["metadata"]["details"])                 # two approval decisions handed over
    emitter.detach_store()
    store.close()
