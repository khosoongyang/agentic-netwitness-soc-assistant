"""tests/test_investigation_case_view_integration.py -- integration coverage
for the Investigation-stage case-detail wiring added alongside the frontend
Investigation tabs (Overview/Output/Timeline/MITRE ATT&CK/Entity Graph/
Evidence/Activity) in frontend/js/pages/workspace.js.

None of this touches agents/investigation/ -- every fixture here builds
inputs the way workflow/engine.py and backend/services/*.py already consume
them, and every assertion is against the adapters this repo owns
(workflow/engine.py, backend/services/case_service.py,
backend/services/case_view_service.py), never against agents/investigation/
internals directly.

Covers:
  1. The real mechanism that prevents Investigation's severity/confidence
     from silently reflecting STALE, previously-persisted
     agents/investigation/incident_reports/ state instead of the current
     run's actual output (workflow/engine.py::run_investigation()'s
     folder freshness guard).
  2. sanitize_investigation_result_for_display() exposing the Phase 3
     canonical contract fields (confidence, execution_trace,
     recommended_containment, mitre_mappings, investigation_analysis) as
     first-class allowlisted fields instead of burying them in
     'additional_output'.
  3. build_mitre() preferring the Investigation Agent's own structured
     mitre_mappings over regex-parsing narrative_report Markdown when the
     structured field is present, with markdown parsing remaining the
     honest fallback when it is absent.
  4. GET /api/cases/<id> (case_service.get_case_detail()) sanitizing
     workspace.output.investigation_result the same way
     GET /api/cases/<id>/workflow already does, so the two endpoints never
     disagree about whether secrets/oversized fields reach the browser.
  5. run_investigation_stage()'s post_investigation pipeline-table write no
     longer silently fails with a NameError on undefined `title`/`run_stamp`
     locals.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from workflow import engine as sw
from workflow import state_store as wss
import backend.services.case_view_service as cv
import backend.services.case_service as case_service


ALERT_ID = "ALERT-1"


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    wss.db_init()
    yield


@pytest.fixture
def inv_dir(tmp_path, monkeypatch):
    d = tmp_path / "investigation"
    (d / "incident_reports").mkdir(parents=True)
    monkeypatch.setattr(sw, "INV_DIR", d)
    return d


# ══════════════════════════════════════════════════════════════════════════
# 1. No stale-context regression: severity/confidence must never silently
#    resolve from an old, untouched Incident-* folder just because it
#    happens to already exist on the shared investigation workspace.
# ══════════════════════════════════════════════════════════════════════════

def test_stale_incident_folder_is_never_mistaken_for_the_current_run(inv_dir, monkeypatch):
    """agents/investigation/incident_reports/ is shared, global state across
    every investigation run (see run_investigation_stage()'s own
    [FYP-STAGE-LOCK] docstring). If a PREVIOUS, unrelated run already left a
    folder on disk whose incident_data.json happens to list this SAME alert
    id -- but that folder predates this run and was never touched by it --
    run_investigation() must NEVER resolve this run's severity/confidence
    from that stale folder. This is the concrete mechanism that stops the
    'severity/confidence went null because stale context was consumed' bug
    class described for this task: a stale folder with unpopulated
    severity/confidence must produce an explicit failure, never a silent
    blank-but-successful result."""
    reports_dir = inv_dir / "incident_reports"
    stale_folder = reports_dir / "Incident-Stale-000"
    stale_folder.mkdir(parents=True)
    stale_data_file = stale_folder / "incident_data.json"
    stale_data_file.write_text(json.dumps({
        "metadata": {},  # no severity ever persisted -- the "went null" shape
        "raw_alerts": [{"id": ALERT_ID}],
        "summary_text": "",
        "indicators": [],
    }), encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale_data_file, (old, old))

    # The current run's subprocess does not touch the stale folder at all
    # (e.g. it crashed, or genuinely produced nothing for this alert).
    monkeypatch.setattr(sw, "_run_subprocess", lambda cmd, cwd, timeout, extra_env=None: {
        "started_at": "now", "returncode": 1, "success": False,
        "stdout": "", "stderr": "no alerts found",
    })

    result = sw.run_investigation(ALERT_ID)

    assert result["incident_folder"] is None
    assert result["status"] == "failed"
    # The stale folder's blank severity/confidence must never leak through.
    assert result["severity"] == ""
    assert result.get("confidence") in (None, "")
    assert "error" in result and result["error"]


def test_refreshed_existing_folder_reports_the_current_runs_severity(inv_dir, monkeypatch):
    """Companion positive case: when this run legitimately MERGEs the alert
    into an existing incident folder and rewrites incident_data.json with a
    new severity, run_investigation() must report THAT fresh value -- the
    freshness guard must not also block legitimate re-use of an
    already-existing, but just-updated, folder."""
    reports_dir = inv_dir / "incident_reports"
    folder_name = "Incident-Existing-001"
    folder = reports_dir / folder_name
    folder.mkdir(parents=True)
    stale_data_file = folder / "incident_data.json"
    stale_data_file.write_text(json.dumps({
        "metadata": {"severity": "LOW"},
        "raw_alerts": [{"id": "OTHER-ALERT"}],
        "summary_text": "old",
        "indicators": [],
    }), encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale_data_file, (old, old))

    def _fake(cmd, cwd, timeout, extra_env=None):
        folder_path = Path(cwd) / "incident_reports" / folder_name
        folder_path.mkdir(parents=True, exist_ok=True)
        (folder_path / "incident_data.json").write_text(json.dumps({
            "metadata": {"severity": "Critical"},
            "raw_alerts": [{"id": ALERT_ID}],
            "summary_text": "Fresh merged summary.",
            "indicators": [],
        }), encoding="utf-8")
        (folder_path / "final_analysis_report.md").write_text(
            "# INVESTIGATION SUMMARY\n**Final Severity:** Critical\n", encoding="utf-8")
        return {"started_at": "now", "returncode": 0, "success": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(sw, "_run_subprocess", _fake)

    result = sw.run_investigation(ALERT_ID)

    assert result["incident_folder"] == folder_name
    assert result["severity"] == "Critical"
    assert result["status"] in ("completed", "completed_limited")


# ══════════════════════════════════════════════════════════════════════════
# 2. Sanitizer allowlist exposes the Phase 3 canonical contract fields
# ══════════════════════════════════════════════════════════════════════════

def test_sanitize_exposes_phase3_canonical_fields_as_first_class():
    result = {
        "status": "completed", "severity": "High", "confidence": "Medium",
        "severity_justification": "because of X", "confidence_justification": "because of Y",
        "execution_trace": [{"step_id": "step_1", "instruction": "i",
                             "status": "MET", "findings": "f"}],
        "recommended_containment": ["Isolate host"],
        "mitre_mappings": [{"timeline_phase": "p", "observed_evidence": "e",
                            "tactic": "Execution", "technique_name": "PowerShell",
                            "technique_id": "T1059.001"}],
        "investigation_analysis": {"policy_audit_logs": [
            {"audit_id": "AUD-1", "decision_point": "DP-07"}]},
        "workflow": {"investigation_source": "structured_json"},
    }
    sanitized = cv.sanitize_investigation_result_for_display(result)

    assert "additional_output" not in sanitized
    assert sanitized["confidence"] == "Medium"
    assert sanitized["execution_trace"][0]["step_id"] == "step_1"
    assert sanitized["recommended_containment"] == ["Isolate host"]
    assert sanitized["mitre_mappings"][0]["technique_id"] == "T1059.001"
    assert sanitized["investigation_analysis"]["policy_audit_logs"][0]["audit_id"] == "AUD-1"
    assert sanitized["workflow"]["investigation_source"] == "structured_json"


def test_sanitize_still_redacts_secrets_nested_under_investigation_analysis():
    """The allowlist widening must not weaken secret redaction -- a secret
    key nested under the now-allowlisted investigation_analysis must still
    be redacted, same as it would be under additional_output."""
    result = {"status": "completed",
             "investigation_analysis": {"api_key": "sk-super-secret",
                                        "policy_audit_logs": []}}
    sanitized = cv.sanitize_investigation_result_for_display(result)
    blob = json.dumps(sanitized)
    assert "sk-super-secret" not in blob
    assert sanitized["investigation_analysis"]["api_key"] == "«redacted»"
    assert sanitized["investigation_analysis"]["policy_audit_logs"] == []


# ══════════════════════════════════════════════════════════════════════════
# 3. build_mitre() prefers structured mitre_mappings over Markdown
# ══════════════════════════════════════════════════════════════════════════

_MARKDOWN_MITRE_TABLE = (
    "| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | "
    "MITRE Technique Name | MITRE ID |\n"
    "| --- | --- | --- | --- | --- |\n"
    "| Wrong phase | wrong evidence | Wrong Tactic | Wrong Technique | T0000 |\n"
)


def test_build_mitre_prefers_structured_mappings_when_present():
    state = {
        "investigation_status": "Awaiting Approval",
        "investigation_result_json": json.dumps({
            "status": "completed",
            "mitre_mappings": [{
                "timeline_phase": "Phase A", "observed_evidence": "evidence A",
                "tactic": "Execution", "technique_name": "PowerShell",
                "technique_id": "T1059.001",
            }],
            "narrative_report": _MARKDOWN_MITRE_TABLE,
        }),
    }
    result = cv.build_mitre(state, {}, "INC-1", "run-1")

    assert len(result["mappings"]) == 1
    mapping = result["mappings"][0]
    assert mapping["technique_id"] == "T1059.001"
    assert mapping["tactic"] == "Execution"
    assert mapping["timeline_phase"] == "Phase A"
    assert mapping["origin"] == "investigation_agent_suggestion"
    # The markdown table's (deliberately different, wrong) values must never
    # leak through once the structured field is available.
    assert "T0000" not in json.dumps(result["mappings"])


def test_build_mitre_falls_back_to_markdown_when_no_structured_mappings():
    """Non-regression: runs persisted before the Phase 3 migration (or any
    markdown_fallback run) have no top-level mitre_mappings key at all --
    build_mitre() must still recover the table from narrative_report."""
    state = {
        "investigation_status": "Approved",
        "investigation_result_json": json.dumps({
            "status": "completed",
            "narrative_report": _MARKDOWN_MITRE_TABLE,
        }),
    }
    result = cv.build_mitre(state, {}, "INC-1", "run-1")

    assert len(result["mappings"]) == 1
    assert result["mappings"][0]["technique_id"] == "T0000"
    assert result["mappings"][0]["origin"] == "investigation_agent_suggestion"


# ══════════════════════════════════════════════════════════════════════════
# 4. GET /api/cases/<id> sanitizes investigation_result the same way
#    GET /api/cases/<id>/workflow does.
# ══════════════════════════════════════════════════════════════════════════

def test_get_case_detail_sanitizes_investigation_result(tmp_path):
    import sqlite3
    db_path = tmp_path / "cases.db"
    wss.DB_FILE = db_path
    wss.db_init()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, status, assignee, "
            "alert_count, created, updated, first_seen, last_seen, raw_json, run_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CASE-X", "Test", "HIGH", "New", "analyst@example.com", 1,
             "2026-01-01", "2026-01-01", "2026-01-01", "2026-01-01",
             json.dumps({}), "CASE-X@run-1"),
        )
        connection.commit()

    def fake_builder(incident_id, run_id):
        return {
            "incident_id": incident_id, "run_id": run_id,
            "output": {"status": "Awaiting Approval", "investigation_result": {
                "status": "completed", "api_key": "must-not-leak", "severity": "High",
            }},
        }

    detail = case_service.get_case_detail(
        "CASE-X", database_path=db_path, case_view_builder=fake_builder)

    inv = detail["workspace"]["output"]["investigation_result"]
    blob = json.dumps(inv)
    assert "must-not-leak" not in blob
    assert inv["severity"] == "High"


def test_get_case_detail_handles_missing_investigation_result_gracefully(tmp_path):
    """No investigation output yet -- must not raise just because
    output.investigation_result is absent or not yet a dict."""
    import sqlite3
    db_path = tmp_path / "cases.db"
    wss.DB_FILE = db_path
    wss.db_init()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, status, assignee, "
            "alert_count, created, updated, first_seen, last_seen, raw_json, run_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CASE-Y", "Test", "HIGH", "New", "analyst@example.com", 1,
             "2026-01-01", "2026-01-01", "2026-01-01", "2026-01-01",
             json.dumps({}), "CASE-Y@run-1"),
        )
        connection.commit()

    def fake_builder(incident_id, run_id):
        return {"incident_id": incident_id, "run_id": run_id,
               "output": {"status": "Pending", "investigation_result": {}}}

    detail = case_service.get_case_detail(
        "CASE-Y", database_path=db_path, case_view_builder=fake_builder)
    assert detail["workspace"]["output"]["investigation_result"] == {}


# ══════════════════════════════════════════════════════════════════════════
# 5. post_investigation pipeline record no longer silently fails with a
#    NameError on undefined `title`/`run_stamp` locals.
# ══════════════════════════════════════════════════════════════════════════

def _run_to_investigation_processing(incident_id: str = "INC-1") -> str:
    run_id = wss.start_run(incident_id)
    wss.save_triage_result(incident_id, run_id, {
        "ticket": {"incident_id": incident_id, "unc": "#001", "classification": "MEDIUM",
                  "title": "Suspicious activity"},
        "metakeys_payload": {"incident_id": incident_id, "metakey_values": {}},
    })
    wss._guarded_update(incident_id, run_id, {
        "triage_status": "Approved", "threat_intel_status": "Complete",
        "investigation_status": "Processing",
    })
    return run_id


def test_post_investigation_pipeline_record_is_written_without_nameerror(monkeypatch):
    """Regression test for a confirmed bug: run_investigation_stage() called
    build_post_investigation_record(inv_result, ticket, title, run_stamp=
    run_stamp) with `title`/`run_stamp` names that were never defined
    anywhere in that function's scope, so every successful investigation run
    raised a NameError there -- silently swallowed by the surrounding
    `except Exception`, meaning the legacy post_investigation pipeline table
    was NEVER populated by the durable stage runner. This proves the fixed
    call actually inserts a row."""
    run_id = _run_to_investigation_processing("INC-1")
    monkeypatch.setattr(sw, "investigate_with_feedback", lambda *a, **k: {
        "status": "completed", "incident_id": "INC-1", "severity": "High",
        "summary": "Investigation completed.",
    })
    sw.pipeline_db_init()

    sw.run_investigation_stage("INC-1", run_id)

    with sw._pl_con() as con:
        rows = con.execute(
            "SELECT incident_id, severity FROM post_investigation"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["incident_id"] == "INC-1"
    assert rows[0]["severity"] == "High"
