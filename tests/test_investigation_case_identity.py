"""tests/test_investigation_case_identity.py -- canonical Investigation case
identity (canonical downstream audit finding C1).

The invariant under test, for a workflow case C:

    workflow case id
      == investigation_result.incident_id
      == investigation_result.investigation_analysis.incident_id
      == Markdown "# INVESTIGATION SUMMARY: <id> (...)" header id
      == the case an Investigation approval may be recorded for
      == the Investigation identity handed to Reporting

Correlation is deliberately NOT part of identity: the Investigation agent may
merge C into an existing correlation cluster (incident_folder, e.g.
"Incident-001") whose other members (cluster_alert_ids) contribute evidence,
but none of those may ever become C's canonical Investigation identity.

No real `python main.py` subprocess, LLM, or ChromaDB is used. Engine-side
tests monkeypatch workflow.engine._run_subprocess with a fake that writes the
same artefacts the real agent writes; agent-side tests load
agents/investigation/main.py with its heavy RAG modules stubbed (same pattern
as tests/test_investigation_analysis_json.py).
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import time
import types
from pathlib import Path

import pytest

from workflow import commands
from workflow import engine as sw
from workflow import state_store as wss


CASE = "INC-53011"
HIST = "INC-52825"
HIST_2 = "INC-52901"
OTHER_CASE = "INC-53024"

INV_AGENT_DIR = Path(__file__).resolve().parent.parent / "agents" / "investigation"
PLAYBOOK = INV_AGENT_DIR / "playbooks" / "privilegeEscalation.yaml"


# ═════════════════════════════════════════════════════════════════════════════
# Fixtures / builders
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def inv_dir(tmp_path, monkeypatch):
    d = tmp_path / "investigation"
    (d / "incident_reports").mkdir(parents=True)
    (d / "triaged_alerts").mkdir()
    monkeypatch.setattr(sw, "INV_DIR", d)
    return d


def _analysis(incident_id, *, severity="High", summary="Investigation summary."):
    return {
        "incident_id": incident_id,
        "severity": severity,
        "confidence": "Medium",
        "execution_trace": [
            {"step_id": "step_1", "instruction": "Identify the user and host",
             "status": "MET", "findings": "Host identified."},
            {"step_id": "step_2", "instruction": "Check lateral movement",
             "status": "MET", "findings": "None observed."},
        ],
        "incident_summary": summary,
        "actions_taken": ["Reviewed timeline"],
        "recommended_containment": ["Isolate the affected host"],
        "business_impact_checklist": {"critical_system": "no", "essential_service": "no",
                                      "data_sensitivity": "unknown", "operational_impact": "no"},
        "severity_justification": "Single host.",
        "confidence_justification": "Consistent telemetry.",
        "mitre_mappings": [],
        "mitre_attack_table": None,
        "policy_audit_logs": [],
    }


def _markdown(header_id, folder):
    """Real main.py::write_markdown_report() header format."""
    head = (f"# INVESTIGATION SUMMARY: {header_id} ({folder})\n\n"
            if header_id is not None else "# Final analysis\n\n")
    return (head
            + "**Final Severity:** High\n\n**Confidence Level:** Medium\n\n"
            + "## Playbook Execution Trace\n| Step ID | Instruction | Status | Findings |\n"
            + "| --- | --- | --- | --- |\n"
            + "| `step_1` | Identify the user and host | **MET** | ok |\n\n"
            + "## Recommended Containment Actions\n- Isolate the affected host (markdown)\n")


def _folder(name, raw_ids, *, analysis_id="__subject__", md_id="__subject__",
            write_markdown=True, stale=(), manifest=None, severity="High"):
    """One Incident-* folder the fake agent writes. analysis_id/md_id of
    "__subject__" mean "whatever INVESTIGATION_SUBJECT_ID the engine sent";
    None means "do not write that artefact" (md_id=None with
    write_markdown=True writes a header-less report)."""
    return dict(name=name, raw_ids=list(raw_ids), analysis_id=analysis_id, md_id=md_id,
                write_markdown=write_markdown, stale=set(stale), manifest=manifest,
                severity=severity)


def _fake_agent(*folders, calls=None, success=True):
    def _fake(cmd, cwd, timeout, extra_env=None):
        env = dict(extra_env or {})
        if calls is not None:
            calls.append(env)
        subject = env.get("INVESTIGATION_SUBJECT_ID")
        old = time.time() - 3600
        for spec in folders:
            folder = Path(cwd) / "incident_reports" / spec["name"]
            folder.mkdir(parents=True, exist_ok=True)
            written = {}
            data_file = folder / "incident_data.json"
            data_file.write_text(json.dumps({
                "id": spec["name"],
                "metadata": {"severity": spec["severity"]},
                "raw_alerts": [{"id": rid, "metadata": {}} for rid in spec["raw_ids"]],
                "summary_text": "Cluster summary.",
                "indicators": ["203.0.113.45"],
            }), encoding="utf-8")
            written["incident_data.json"] = data_file
            aid = subject if spec["analysis_id"] == "__subject__" else spec["analysis_id"]
            if aid is not None:
                p = folder / "investigation_analysis.json"
                p.write_text(json.dumps(_analysis(aid)), encoding="utf-8")
                written["investigation_analysis.json"] = p
            if spec["write_markdown"]:
                mid = subject if spec["md_id"] == "__subject__" else spec["md_id"]
                p = folder / "final_analysis_report.md"
                p.write_text(_markdown(mid, spec["name"]), encoding="utf-8")
                written["final_analysis_report.md"] = p
            for fname in spec["stale"]:
                if fname in written:
                    os.utime(written[fname], (old, old))
            if spec["manifest"] is not None:
                files = {n: hashlib.sha256(p.read_bytes()).hexdigest()
                         for n, p in written.items()
                         if n in ("investigation_analysis.json", "final_analysis_report.md")}
                manifest = {"run_nonce": env.get("INVESTIGATION_RUN_NONCE"),
                            "subject_id": subject, "files": files}
                manifest.update(spec["manifest"])
                (folder / "investigation_run_manifest.json").write_text(
                    json.dumps(manifest), encoding="utf-8")
        return {"started_at": "now", "returncode": 0 if success else 1,
                "success": success, "stdout": "", "stderr": ""}
    return _fake


def _md_header(narrative):
    return wss.investigation_report_subject(narrative)


def _triage(case_id=CASE):
    return {"ticket": {"incident_id": case_id, "unc": "#00042A", "classification": "HIGH",
                       "title": "Case", "incident_category": "Malware", "mitre_tactic": "Execution",
                       "mitre_technique": "T1204 User Execution", "summary": "s"},
            "metakeys_payload": {"incident_id": case_id, "incident_title": "Case",
                                 "mitre_tactic": "Execution"}}


def _contaminated_result(case_id=CASE, foreign=HIST):
    """Shape of a persisted pre-fix result (e.g. INC-53011 carrying INC-52825)."""
    return {"agent": "Investigation Agent", "status": "completed", "incident_id": case_id,
            "investigated_for": case_id, "incident_folder": "Incident-001",
            "cluster_alert_ids": sorted({case_id, foreign}),
            "summary": "x", "severity": "High",
            "narrative_report": _markdown(foreign, "Incident-001"),
            "investigation_analysis": _analysis(foreign)}


def _valid_result(case_id=CASE):
    return {"agent": "Investigation Agent", "status": "completed", "incident_id": case_id,
            "investigated_for": case_id, "incident_folder": "Incident-001",
            "cluster_alert_ids": sorted({case_id, HIST}),
            "summary": "x", "severity": "High",
            "narrative_report": _markdown(case_id, "Incident-001"),
            "investigation_analysis": _analysis(case_id)}


def _state_awaiting(gate, inv_result, case_id=CASE):
    run_id = wss.start_run(case_id)
    sets = {"parsing_status": "Complete", "triage_status": "Approved",
            "threat_intel_status": "Complete",
            "investigation_result_json": json.dumps(inv_result)}
    if gate == "investigation":
        sets.update({"investigation_status": "Awaiting Approval",
                     "workflow_status": "Awaiting Approval", "approval_stage": "investigation"})
    elif gate == "reporting":
        sets.update({"investigation_status": "Approved", "reporting_status": "Awaiting Approval",
                     "reporting_result_json": json.dumps({"status": "completed"}),
                     "workflow_status": "Awaiting Approval", "approval_stage": "reporting"})
    elif gate == "reporting_processing":
        sets.update({"investigation_status": "Approved", "reporting_status": "Processing",
                     "workflow_status": "Processing"})
    wss._guarded_update(case_id, run_id, sets)
    return run_id


# ═════════════════════════════════════════════════════════════════════════════
# 1-6, 16. Accepted results: canonical identity == case; correlation kept
# ═════════════════════════════════════════════════════════════════════════════

def test_single_case_investigation_identity(inv_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(sw, "_run_subprocess",
                        _fake_agent(_folder("Incident-001", [CASE]), calls=calls))
    result = sw.run_investigation(CASE)

    assert result["status"] == "completed"
    assert result["incident_id"] == CASE
    assert result["investigation_analysis"]["incident_id"] == CASE
    assert _md_header(result["narrative_report"]) == CASE
    assert result["workflow"]["investigation_source"] == "structured_json"
    assert calls[0]["INVESTIGATION_SUBJECT_ID"] == CASE


def test_case_with_no_correlations_has_only_itself_as_evidence(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(_folder("Incident-001", [CASE])))
    result = sw.run_investigation(CASE)
    assert result["cluster_alert_ids"] == [CASE]
    assert not result["summary"].startswith("[Correlated cluster")


def test_case_correlating_with_one_historical_incident(inv_dir, monkeypatch):
    # Historical case is the cluster seed (first raw alert) -- exactly the
    # production shape that used to make the seed the analysis identity.
    monkeypatch.setattr(sw, "_run_subprocess",
                        _fake_agent(_folder("Incident-001", [HIST, CASE])))
    result = sw.run_investigation(CASE)

    assert result["status"] == "completed"
    assert result["investigation_analysis"]["incident_id"] == CASE
    assert result["incident_id"] == CASE
    # Correlated evidence still present and visible.
    assert result["cluster_alert_ids"] == sorted([HIST, CASE])
    assert HIST in result["summary"] and "Correlated cluster Incident-001" in result["summary"]
    assert result["indicators"] == ["203.0.113.45"]


def test_case_correlating_with_multiple_historical_incidents(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess",
                        _fake_agent(_folder("Incident-001", [HIST, HIST_2, CASE])))
    result = sw.run_investigation(CASE)
    assert result["investigation_analysis"]["incident_id"] == CASE
    assert set(result["cluster_alert_ids"]) == {HIST, HIST_2, CASE}


def test_case_merging_into_existing_correlation_cluster(inv_dir, monkeypatch):
    """Pre-existing, stale cluster folder from earlier runs; this run MERGEs
    the case into it (rewrites it). Identity is the case, the folder name is
    only the correlation workspace."""
    folder = inv_dir / "incident_reports" / "Incident-001"
    folder.mkdir()
    (folder / "incident_data.json").write_text(json.dumps(
        {"raw_alerts": [{"id": HIST}], "metadata": {"severity": "Low"}}), encoding="utf-8")
    (folder / "investigation_analysis.json").write_text(json.dumps(_analysis(HIST)), encoding="utf-8")
    old = time.time() - 3600
    for p in folder.iterdir():
        os.utime(p, (old, old))

    monkeypatch.setattr(sw, "_run_subprocess",
                        _fake_agent(_folder("Incident-001", [HIST, CASE])))
    result = sw.run_investigation(CASE)

    assert result["status"] == "completed"
    assert result["incident_folder"] == "Incident-001"
    assert result["investigation_analysis"]["incident_id"] == CASE
    assert result["incident_id"] != result["incident_folder"]


def test_incident_folder_is_never_treated_as_identity(inv_dir, monkeypatch):
    """An analysis whose incident_id is the folder/cluster label is not the case."""
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], analysis_id="Incident-001", md_id="Incident-001")))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"
    assert "investigation_analysis" not in result


def test_cluster_alert_ids_may_contain_other_cases_without_changing_identity():
    assert wss.investigation_identity_problem(CASE, _valid_result(CASE)) is None
    assert set(_valid_result(CASE)["cluster_alert_ids"]) == {CASE, HIST}


# ═════════════════════════════════════════════════════════════════════════════
# 7-8. Mismatches are data-integrity failures (no Markdown fallback)
# ═════════════════════════════════════════════════════════════════════════════

def test_result_belonging_to_another_case_is_rejected(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], analysis_id=OTHER_CASE, md_id=OTHER_CASE)))
    result = sw.run_investigation(CASE)

    assert result["status"] == "failed"
    assert "identity" in result["error"].lower()
    assert OTHER_CASE in result["error"]
    for key in ("investigation_analysis", "narrative_report_used", "recommended_containment"):
        assert key not in result
    assert result["narrative_report"] == ""


def test_current_case_merely_inside_another_cluster_is_not_accepted(inv_dir, monkeypatch):
    """The production bug: INC-53011 in a cluster seeded by INC-52825, the
    agent labelled the analysis INC-52825 -- previously accepted because
    INC-53011 was 'a member of the cluster'."""
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE], analysis_id=HIST, md_id=HIST)))
    result = sw.run_investigation(CASE)

    assert result["status"] == "failed"
    assert "investigation_analysis" not in result
    assert result.get("workflow", {}).get("investigation_source") != "markdown_fallback"


def test_structured_mismatch_never_falls_back_to_markdown_even_if_markdown_matches(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE], analysis_id=HIST, md_id=CASE)))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"
    assert "investigation_analysis" not in result


def test_markdown_fallback_with_foreign_header_is_rejected(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE], analysis_id=None, md_id=HIST)))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"


def test_markdown_fallback_allowed_when_structured_unavailable_and_header_matches(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE], analysis_id=None)))
    result = sw.run_investigation(CASE)
    assert result["status"] == "completed"
    assert result["workflow"]["investigation_source"] == "markdown_fallback"
    assert _md_header(result["narrative_report"]) == CASE


def test_markdown_without_canonical_header_is_not_verifiable(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], analysis_id=None, md_id=None)))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"


# ═════════════════════════════════════════════════════════════════════════════
# 9. Multiple candidate folders
# ═════════════════════════════════════════════════════════════════════════════

def test_two_valid_candidate_folders_fail_as_ambiguous(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE]), _folder("Incident-002", [CASE])))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"
    assert "ambiguous" in result["error"].lower()


def test_one_valid_and_one_foreign_candidate_selects_the_valid_one(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE], analysis_id=HIST, md_id=HIST),
        _folder("Incident-002", [CASE])))
    result = sw.run_investigation(CASE)
    assert result["status"] == "completed"
    assert result["incident_folder"] == "Incident-002"
    assert result["investigation_analysis"]["incident_id"] == CASE


def test_selection_does_not_depend_on_folder_sort_order(inv_dir, monkeypatch):
    """Old semantics picked the FIRST sorted matching folder (Incident-001);
    the valid one here sorts last."""
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], analysis_id=OTHER_CASE, md_id=OTHER_CASE),
        _folder("Incident-009", [CASE])))
    result = sw.run_investigation(CASE)
    assert result["incident_folder"] == "Incident-009"


# ═════════════════════════════════════════════════════════════════════════════
# 10. Freshness
# ═════════════════════════════════════════════════════════════════════════════

def test_stale_folder_from_previous_run_is_not_accepted(inv_dir, monkeypatch):
    folder = inv_dir / "incident_reports" / "Incident-001"
    folder.mkdir()
    (folder / "incident_data.json").write_text(json.dumps({"raw_alerts": [{"id": CASE}]}),
                                               encoding="utf-8")
    (folder / "investigation_analysis.json").write_text(json.dumps(_analysis(CASE)), encoding="utf-8")
    (folder / "final_analysis_report.md").write_text(_markdown(CASE, "Incident-001"), encoding="utf-8")
    old = time.time() - 3600
    for p in folder.iterdir():
        os.utime(p, (old, old))
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent())  # agent wrote nothing
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"
    assert result["incident_folder"] is None


def test_stale_structured_analysis_is_ignored_and_fresh_markdown_used(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], stale={"investigation_analysis.json"})))
    result = sw.run_investigation(CASE)
    assert result["status"] == "completed"
    assert result["workflow"]["investigation_source"] == "markdown_fallback"


def test_stale_structured_and_stale_markdown_fail(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(_folder(
        "Incident-001", [CASE], stale={"investigation_analysis.json", "final_analysis_report.md"})))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"


def test_run_manifest_from_this_run_is_verified(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [HIST, CASE], manifest={})))
    result = sw.run_investigation(CASE)
    assert result["status"] == "completed"
    assert result["investigation_analysis"]["incident_id"] == CASE


def test_run_manifest_from_another_run_rejects_the_output(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], manifest={"run_nonce": "some-previous-run"})))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"


def test_run_manifest_with_foreign_subject_rejects_the_output(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(
        _folder("Incident-001", [CASE], manifest={"subject_id": HIST})))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"


def test_run_manifest_hash_mismatch_rejects_the_output(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(_folder(
        "Incident-001", [CASE],
        manifest={"files": {"investigation_analysis.json": "0" * 64}})))
    result = sw.run_investigation(CASE)
    assert result["status"] == "failed"


def test_each_run_sends_a_distinct_nonce_and_no_single_incident_flag(inv_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(sw, "_run_subprocess",
                        _fake_agent(_folder("Incident-001", [CASE]), calls=calls))
    sw.run_investigation(CASE)
    sw.run_investigation(CASE)
    assert calls[0]["INVESTIGATION_RUN_NONCE"] != calls[1]["INVESTIGATION_RUN_NONCE"]
    for env in calls:
        assert "INVESTIGATION_SINGLE_INCIDENT" not in env
        assert env["INVESTIGATION_FORCE_LLM"] == "1"
        assert env["INVESTIGATION_SUBJECT_ID"] == CASE


# ═════════════════════════════════════════════════════════════════════════════
# 11-13. Reruns / sequential cases / overlapping correlated evidence
# ═════════════════════════════════════════════════════════════════════════════

def test_rerun_of_the_same_case_keeps_identity(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(_folder("Incident-001", [HIST, CASE])))
    first = sw.run_investigation(CASE)
    second = sw.run_investigation(CASE)
    for r in (first, second):
        assert r["status"] == "completed"
        assert r["investigation_analysis"]["incident_id"] == CASE


def test_two_cases_sequentially_with_overlapping_correlated_evidence(inv_dir, monkeypatch):
    """Case A then case B both correlate with HIST and land in the SAME
    cluster folder; each gets its own canonical result and A's earlier
    result object is unaffected by B's run rewriting the folder."""
    monkeypatch.setattr(sw, "_run_subprocess", _fake_agent(_folder("Incident-001", [HIST, CASE])))
    result_a = sw.run_investigation(CASE)
    snapshot_a = json.dumps(result_a, sort_keys=True, default=str)

    monkeypatch.setattr(sw, "_run_subprocess",
                        _fake_agent(_folder("Incident-001", [HIST, CASE, OTHER_CASE])))
    result_b = sw.run_investigation(OTHER_CASE)

    assert result_a["investigation_analysis"]["incident_id"] == CASE
    assert result_b["investigation_analysis"]["incident_id"] == OTHER_CASE
    assert json.dumps(result_a, sort_keys=True, default=str) == snapshot_a
    assert HIST in result_a["cluster_alert_ids"] and HIST in result_b["cluster_alert_ids"]


# ═════════════════════════════════════════════════════════════════════════════
# Identity predicate (shared by stage / approval / Reporting guards)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("mutate, expect_problem", [
    (lambda r: r, False),
    (lambda r: r.update(investigation_analysis=_analysis(HIST)), True),
    (lambda r: r.update(narrative_report=_markdown(HIST, "Incident-001")), True),
    (lambda r: r.update(incident_id=HIST), True),
    (lambda r: r.update(investigated_for=HIST), True),
    (lambda r: r.update(incident_folder="Incident-777"), False),
    (lambda r: r.update(cluster_alert_ids=[HIST, HIST_2, CASE]), False),
])
def test_identity_predicate(mutate, expect_problem):
    result = _valid_result(CASE)
    mutate(result)
    problem = wss.investigation_identity_problem(CASE, result)
    assert (problem is not None) is expect_problem


def test_identity_predicate_flags_every_known_contaminated_shape():
    assert wss.investigation_identity_problem(CASE, _contaminated_result()) is not None
    legacy_markdown_only = _contaminated_result()
    del legacy_markdown_only["investigation_analysis"]
    assert wss.investigation_identity_problem(CASE, legacy_markdown_only) is not None


# ═════════════════════════════════════════════════════════════════════════════
# Stage-level persisted-result boundary + full invariant chain
# ═════════════════════════════════════════════════════════════════════════════

def _stage_env(monkeypatch, case_id=CASE):
    monkeypatch.setattr(sw, "generate_stage_ai_summary", lambda *a, **k: {})
    monkeypatch.setenv("NW_DISABLE_SKILLS_SIDECAR", "1")
    run_id = wss.start_run(case_id)
    wss.save_triage_result(case_id, run_id, _triage(case_id))
    wss._guarded_update(case_id, run_id, {
        "parsing_status": "Complete", "triage_status": "Approved",
        "threat_intel_status": "Complete",
        "threat_intel_result_json": json.dumps({"status": "completed",
                                                "enrichment_risk_level": "Low"}),
        "investigation_status": "Processing", "workflow_status": "Processing"})
    return run_id


def test_stage_refuses_to_persist_a_conflicting_identity(inv_dir, monkeypatch):
    run_id = _stage_env(monkeypatch)
    monkeypatch.setattr(sw, "investigate_with_feedback",
                        lambda *a, **k: _contaminated_result(CASE))
    out = sw.run_investigation_stage(CASE, run_id)
    state = wss.get_state(CASE)

    assert out["status"] == "failed"
    assert state["investigation_status"] == "Failed"
    assert state["reporting_status"] == "Blocked"
    assert "identity" in (state["last_error"] or "").lower()
    persisted = json.loads(state["investigation_result_json"])
    assert "investigation_analysis" not in persisted


def test_end_to_end_identity_invariant(inv_dir, monkeypatch):
    """workflow case == result.incident_id == analysis.incident_id ==
    Markdown header == approvable case == identity handed to Reporting."""
    run_id = _stage_env(monkeypatch)
    fake = _fake_agent(_folder("Incident-001", [HIST, HIST_2, CASE]))
    # The durable stage passes a lock watchdog, so the streaming runner is used.
    monkeypatch.setattr(sw, "_run_subprocess_streaming",
                        lambda cmd, cwd, timeout, extra_env=None, **kw: fake(cmd, cwd, timeout, extra_env))

    sw.run_investigation_stage(CASE, run_id)
    state = wss.get_state(CASE)
    assert state["investigation_status"] == "Awaiting Approval"
    persisted = json.loads(state["investigation_result_json"])

    ids = {CASE, persisted["incident_id"], persisted["investigation_analysis"]["incident_id"],
           _md_header(persisted["narrative_report"])}
    assert ids == {CASE}
    assert set(persisted["cluster_alert_ids"]) == {HIST, HIST_2, CASE}   # evidence kept

    actions = commands.available_actions(wss.get_state(CASE))["stages"]["investigation"]
    assert next(a for a in actions if a["type"] == "approve")["enabled"] is True
    commands.approve_stage(CASE, "investigation", analyst="analyst-1")
    assert wss.get_state(CASE)["investigation_status"] == "Approved"

    sw.handoff_to_reporting(_triage(CASE), {"id": CASE}, persisted,
                            threat_intel_result={"status": "completed"},
                            incident_id=CASE, run_id=run_id, reporting_stage_attempt=1)
    handed = json.loads((sw.reporting_attempt_dir(CASE, run_id, 1) / "outputs"
                         / "investigation_result.json").read_text(encoding="utf-8"))
    assert handed["investigation_analysis"]["incident_id"] == CASE
    assert handed["incident_id"] == CASE
    assert wss.investigation_identity_problem(CASE, handed) is None


# ═════════════════════════════════════════════════════════════════════════════
# 14. Approval safety
# ═════════════════════════════════════════════════════════════════════════════

def test_approve_investigation_refuses_mismatched_case():
    run_id = _state_awaiting("investigation", _contaminated_result())
    with pytest.raises(wss.InvestigationIdentityError):
        wss.approve_investigation(CASE, run_id, approved_by="analyst")
    state = wss.get_state(CASE)
    assert state["investigation_status"] == "Awaiting Approval"
    assert state["reporting_status"] == "Pending"
    assert wss.get_approval_history(CASE, run_id) == []


def test_approve_investigation_accepts_matching_case():
    run_id = _state_awaiting("investigation", _valid_result())
    wss.approve_investigation(CASE, run_id, approved_by="analyst")
    assert wss.get_state(CASE)["investigation_status"] == "Approved"


def test_command_layer_reports_identity_mismatch_code():
    _state_awaiting("investigation", _contaminated_result())
    with pytest.raises(commands.WorkflowCommandError) as err:
        commands.approve_stage(CASE, "investigation", analyst="analyst")
    assert err.value.code == "INVESTIGATION_IDENTITY_MISMATCH"


def test_available_actions_disable_approve_but_keep_reject_and_rerun():
    _state_awaiting("investigation", _contaminated_result())
    actions = {a["type"]: a for a in
               commands.available_actions(wss.get_state(CASE))["stages"]["investigation"]}
    assert actions["approve"]["enabled"] is False
    assert "identity" in actions["approve"]["reason"].lower()
    assert actions["reject"]["enabled"] is True
    assert actions["rerun"]["enabled"] is True


def test_reject_still_works_for_mismatched_case():
    run_id = _state_awaiting("investigation", _contaminated_result())
    wss.reject_investigation(CASE, run_id, rejected_by="analyst", reason="wrong case")
    assert wss.get_state(CASE)["investigation_status"] == "Rejected"


# ═════════════════════════════════════════════════════════════════════════════
# 15. Reporting guards (defence in depth)
# ═════════════════════════════════════════════════════════════════════════════

def test_reporting_stage_refuses_mismatched_investigation(monkeypatch):
    run_id = _state_awaiting("reporting_processing", _contaminated_result())

    def _must_not_run(*a, **k):
        raise AssertionError("Reporting must not consume a mismatched Investigation")

    monkeypatch.setattr(sw, "handoff_to_reporting", _must_not_run)
    monkeypatch.setattr(sw, "run_reporting", _must_not_run)
    out = sw.run_reporting_stage(CASE, run_id)
    state = wss.get_state(CASE)
    assert out["status"] == "failed"
    assert state["reporting_status"] == "Failed"
    assert "identity" in (state["last_error"] or "").lower()


def test_reporting_approval_refuses_mismatched_investigation():
    from agents.reporting.reporting_approval import approve_reporting_candidate

    run_id = _state_awaiting("reporting", _contaminated_result())
    with pytest.raises(wss.InvestigationIdentityError):
        approve_reporting_candidate(CASE, run_id, analyst="analyst")
    assert wss.get_state(CASE)["reporting_status"] == "Awaiting Approval"


def test_reporting_approve_action_disabled_for_mismatched_investigation():
    _state_awaiting("reporting", _contaminated_result())
    actions = {a["type"]: a for a in
               commands.available_actions(wss.get_state(CASE))["stages"]["reporting"]}
    assert actions["approve"]["enabled"] is False
    assert "identity" in actions["approve"]["reason"].lower()


def test_reporting_approval_command_returns_identity_code():
    _state_awaiting("reporting", _contaminated_result())
    with pytest.raises(commands.WorkflowCommandError) as err:
        commands.approve_stage(CASE, "reporting", analyst="analyst")
    assert err.value.code == "INVESTIGATION_IDENTITY_MISMATCH"


# ═════════════════════════════════════════════════════════════════════════════
# Agent side: subject pinning, de-duplication, exact queue matching, manifest
# ═════════════════════════════════════════════════════════════════════════════

def _install_stub(monkeypatch, name, **attrs):
    stub = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(stub, key, value)
    monkeypatch.setitem(sys.modules, name, stub)


@pytest.fixture
def agent(monkeypatch, tmp_path):
    _install_stub(monkeypatch, "ingest_pipeline")
    _install_stub(monkeypatch, "vector_engine")
    _install_stub(monkeypatch, "chroma_compat",
                  open_persistent_collection=lambda *a, **k: (None, False))
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(INV_AGENT_DIR))
    spec = importlib.util.spec_from_file_location("_inv_main_identity", INV_AGENT_DIR / "main.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def _alert(alert_id, epoch, doc="doc"):
    return {"id": alert_id, "document": doc,
            "metadata": {"timestamp_epoch": epoch, "timestamp_str": f"t{epoch}"}}


def test_newest_current_case_copy_wins_during_feedback_dedup(agent):
    hist = _alert(HIST, 100, "historical evidence")
    hist_2 = _alert(HIST_2, 150, "second historical evidence")
    pass1 = _alert(CASE, 200, "pass-1 evidence")
    cluster = [hist, pass1, hist_2]

    pass2 = _alert(CASE, 200, "pass-2 evidence. triage deep dive gap findings: lateral movement answered")
    merged = agent.merge_alert_into_cluster(cluster, pass2)

    assert [a["id"] for a in merged] == [HIST, CASE, HIST_2]        # order preserved
    assert sum(1 for a in merged if a["id"] == CASE) == 1           # exactly one
    current = next(a for a in merged if a["id"] == CASE)
    assert current is pass2                                         # newest wins
    assert "gap findings" in current["document"]                    # gap answers kept
    assert merged[0] is hist and merged[2] is hist_2                # history intact
    assert cluster == [hist, pass1, hist_2]                         # input not mutated


def test_dedup_collapses_existing_duplicates_of_the_current_case_only(agent):
    cluster = [_alert(HIST, 1), _alert(CASE, 2, "old-1"), _alert(HIST, 3), _alert(CASE, 4, "old-2")]
    merged = agent.merge_alert_into_cluster(cluster, _alert(CASE, 5, "new"))
    assert [a["id"] for a in merged] == [HIST, CASE, HIST]          # historical duplicates untouched
    assert merged[1]["document"] == "new"


def test_new_alert_is_appended_when_not_already_in_cluster(agent):
    merged = agent.merge_alert_into_cluster([_alert(HIST, 1)], _alert(CASE, 2))
    assert [a["id"] for a in merged] == [HIST, CASE]


def test_subject_resolution(agent):
    alerts = [_alert(HIST, 1), _alert(CASE, 2)]
    assert agent.resolve_investigation_subject(alerts, CASE) == CASE
    assert agent.resolve_investigation_subject(alerts, None) is None
    assert agent.resolve_investigation_subject(alerts, "INC-NOT-HERE") is None


def test_queue_file_lookup_is_exact_not_substring(agent):
    os.makedirs(agent.UNREAD_ALERTS_FOLDER, exist_ok=True)
    for name in ("INC-53027_alert.json", "INC-5302_alert.json"):
        Path(agent.UNREAD_ALERTS_FOLDER, name).write_text("{}", encoding="utf-8")
    assert Path(agent.find_file_by_incident_id("INC-5302")).name == "INC-5302_alert.json"
    assert Path(agent.find_file_by_incident_id("INC-53027")).name == "INC-53027_alert.json"
    assert agent.find_file_by_incident_id("INC-530") is None


def test_run_manifest_written_only_in_workflow_mode(agent, tmp_path, monkeypatch):
    dest = tmp_path / "Incident-001"
    dest.mkdir()
    (dest / "investigation_analysis.json").write_text("{}", encoding="utf-8")
    report = types.SimpleNamespace(incident_id=CASE)

    monkeypatch.delenv("INVESTIGATION_RUN_NONCE", raising=False)
    agent.write_investigation_run_manifest(str(dest), report)
    assert not (dest / "investigation_run_manifest.json").exists()

    monkeypatch.setenv("INVESTIGATION_RUN_NONCE", "nonce-1")
    agent.write_investigation_run_manifest(str(dest), report)
    manifest = json.loads((dest / "investigation_run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["run_nonce"] == "nonce-1"
    assert manifest["subject_id"] == CASE
    assert manifest["files"]["investigation_analysis.json"] == hashlib.sha256(b"{}").hexdigest()


# ── 17. Prompts / model requests ────────────────────────────────────────────

class _FakeChain:
    def __init__(self, respond):
        self.calls = []
        self._respond = respond

    async def ainvoke(self, payload):
        self.calls.append(dict(payload))
        return self._respond(payload)


def _patch_chains(agent, monkeypatch, *, p2_incident_id=None):
    orch = agent.orchestrator
    p1 = _FakeChain(lambda payload: types.SimpleNamespace(execution_trace=[], suggested_pivots=[]))

    def _p2(payload):
        return orch.FinalIncidentAnalysis(
            incident_id=p2_incident_id or payload["incident_id"], severity="High",
            confidence="Medium", execution_trace=[], incident_summary="summary",
            actions_taken=["a"], recommended_containment=["Isolate host"],
            business_impact_checklist=orch.BusinessImpactChecklist(
                critical_system="no", essential_service="no",
                data_sensitivity="no", operational_impact="no"),
            severity_justification="j", confidence_justification="j", policy_audit_logs=[])

    p2 = _FakeChain(_p2)
    monkeypatch.setattr(orch, "get_chain_p1", lambda: p1)
    monkeypatch.setattr(orch, "get_chain_p2", lambda: p2)
    monkeypatch.setattr(orch, "get_policy_manager", lambda: (
        types.SimpleNamespace(get_section=lambda key: None),
        types.SimpleNamespace(retrieve=lambda text, limit=2: [])))
    monkeypatch.setattr(orch, "run_policy_compliance_rules", lambda **kw: {
        "escalation_required": False, "modified_containment": kw["recommended_containment"],
        "audit_records": []})
    return orch, p1, p2


def _run_both_passes(orch, alerts, subject_id):
    async def go():
        kwargs = {} if subject_id is None else {"subject_id": subject_id}
        p1 = await orch.analyze_alert_group_p1(alerts, str(PLAYBOOK), **kwargs)
        return await orch.compile_final_report(alerts, str(PLAYBOOK), p1["execution_trace"], **kwargs)
    return asyncio.run(go())


def test_isolated_case_model_requests_are_unchanged(agent, monkeypatch):
    """subject == the only/first alert -> byte-identical payloads to the
    legacy (no subject) call."""
    alerts = [_alert(CASE, 100, "only evidence")]
    orch, p1, p2 = _patch_chains(agent, monkeypatch)
    legacy = _run_both_passes(orch, alerts, None)
    pinned = _run_both_passes(orch, alerts, CASE)

    assert p1.calls[0] == p1.calls[1]
    assert p2.calls[0] == p2.calls[1]
    assert legacy.incident_id == pinned.incident_id == CASE


def test_merged_case_prompt_uses_current_subject_and_nothing_else_changes(agent, monkeypatch):
    alerts = [_alert(HIST, 100, "historical"), _alert(CASE, 200, "current")]
    orch, p1, p2 = _patch_chains(agent, monkeypatch)
    legacy = _run_both_passes(orch, alerts, None)
    pinned = _run_both_passes(orch, alerts, CASE)

    assert p1.calls[0]["incident_id"] == HIST and p1.calls[1]["incident_id"] == CASE
    assert p2.calls[0]["incident_id"] == HIST and p2.calls[1]["incident_id"] == CASE
    for calls in (p1.calls, p2.calls):
        a, b = dict(calls[0]), dict(calls[1])
        a.pop("incident_id"); b.pop("incident_id")
        assert a == b                       # timeline, playbook, trace, policies identical
    assert "historical" in p2.calls[1]["timeline"]       # correlated evidence still sent
    assert legacy.incident_id == HIST and pinned.incident_id == CASE


def test_subject_pinning_overrides_a_model_echoing_a_different_id(agent, monkeypatch):
    alerts = [_alert(HIST, 100), _alert(CASE, 200)]
    orch, _p1, _p2 = _patch_chains(agent, monkeypatch, p2_incident_id=HIST)
    report = _run_both_passes(orch, alerts, CASE)
    assert report.incident_id == CASE


# ── 18. Agent Activity wording ──────────────────────────────────────────────

def test_agent_activity_merge_event_does_not_claim_the_case_changed():
    from observability.adapters import investigation_adapter as ia

    line = f"Confirmed Match. Merging alert {CASE} into Incident Incident-001"
    emitted = []
    recorder = types.SimpleNamespace(_emit=lambda **kw: emitted.append(kw))
    for pattern, fn in ia._TEMPLATES:
        m = pattern.search(line)
        if m:
            fn(recorder, m)
            break
    assert emitted, "merge line must still be recognised"
    text = (emitted[0].get("title", "") + " " + str(emitted[0].get("detail", ""))).lower()
    assert "correlation cluster" in text
    assert CASE.lower() in text


@pytest.mark.parametrize("result, expected_status, expected_title", [
    ({"valid": True, "source": "structured_json"}, "completed", "Structured Investigation result validated"),
    ({"valid": True, "source": "markdown_fallback"}, "warning", "reconstructed from the Markdown report"),
    ({"valid": False, "kind": "mismatch", "detail": "investigation_analysis.incident_id is 'INC-52825'"},
     "failed", "identifies a different case"),
    ({"valid": False, "kind": "stale", "detail": "manifest from another run"},
     "failed", "could not be verified for this case"),
])
def test_agent_activity_result_source_events(monkeypatch, tmp_path, result, expected_status, expected_title):
    from observability.adapters import investigation_adapter as ia

    emitted = []
    monkeypatch.setattr(ia, "_scope", lambda: {"stage": "investigation"})
    monkeypatch.setattr(ia, "_group", lambda scope: {})
    monkeypatch.setattr(ia, "emit", lambda **kw: emitted.append(kw))
    ia._candidate_after({"target": str(tmp_path / "Incident-001")}, None, result)

    assert len(emitted) == 1
    assert emitted[0]["status"] == expected_status
    assert expected_title in emitted[0]["title"]
    assert "case changed" not in emitted[0]["title"].lower()
