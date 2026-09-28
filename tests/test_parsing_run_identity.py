"""Regression tests for the "workflow did not publish a run identity" bug.

Root cause: workflow/engine.py::run_until_triage_approval() used to mint the
run identity (wss.start_run()) *after* enriching the incident via a live
NetWitness API call (enrich_incident_with_apiretrieval_fetch(), which can
block for many seconds per HTTP request). workflow/commands.py::_launch_fresh
starts that function on a background thread and polls the incidents table
for a freshly-published run_id, on a short deadline, so it can hand the
run_id back to the HTTP caller (POST /api/cases/<id>/stages/parsing/runs).
Whenever enrichment took longer than that deadline, no run_id had been
published yet and the request layer raised SERVICE_FAILURE ("The workflow
did not publish a run identity."), even though Parsing had not actually
failed -- it just hadn't been given the chance to start.

The fix reorders run_until_triage_approval() to mint the run identity first
(a fast, local DB write) before the slow enrichment call, and additionally:
  - only marks Parsing "Complete" once its result has actually been
    persisted (save_parsing_result), so a persist failure can't leave the
    stage looking done with no data behind it;
  - records a real wss.set_last_error() message on every Parsing failure
    path, so a genuine failure is distinguishable from "never started";
  - persists the parser's actual structured output (normalised_alert /
    processed_alert), not just a thin status summary, since that is what
    the case page's Normalised Alert panel and Download JSON renders.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from workflow import commands
from workflow import engine as sw
from workflow import state_store as wss


@pytest.fixture(autouse=True)
def isolated_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    with wss.db_connect() as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, raw_json) VALUES (?, ?, ?)",
            ("CASE-PARSE-ID", "Run-identity regression case",
             json.dumps({"id": "CASE-PARSE-ID", "title": "Run-identity regression case"})),
        )
        connection.commit()
    yield
    with commands._TASKS_LOCK:
        commands._TASKS.clear()


def _fake_parsing_result(**overrides) -> dict:
    result = {
        "status": "completed",
        "parser_confidence": "High",
        "recommended_next_action": "Run Triage Agent using the normalised alert context.",
        "summary": "NetWitness alert parsed and normalised for downstream SOC agents.",
        "important_extracted_fields": {"alert_name": "Suspicious PowerShell"},
        "missing_important_fields": [],
        "warnings": [],
        "parser_summary_card": {"parser_confidence": "High"},
        "normalised_alert": {"alert_summary": {"raw_event_count": 4}, "host": "WIN-TEST-01"},
        "processed_alert": {"flat": True, "host": "WIN-TEST-01"},
        "output_files": {"parsed_incident_file": "parsed_incident.json"},
        "ai_summary": None,
        "ai_thinking": None,
        "ai_summary_model": None,
        "ai_summary_generated_at": None,
    }
    result.update(overrides)
    return result


def test_run_until_triage_approval_mints_run_id_before_enrichment(monkeypatch):
    """The run identity must be published before any slow, network-bound
    enrichment work -- callers observing the DB for a fresh run_id (see
    workflow/commands.py::_launch_fresh) must not have to race live
    NetWitness API latency to see it."""
    call_order: list[str] = []
    original_start_run = wss.start_run

    def recording_enrich(incident, host=None, token=None):
        call_order.append("enrich")
        return incident

    def recording_start_run(*args, **kwargs):
        call_order.append("start_run")
        return original_start_run(*args, **kwargs)

    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch", recording_enrich)
    monkeypatch.setattr(sw, "run_parsing", lambda incident, run_id: _fake_parsing_result())
    monkeypatch.setattr(wss, "start_run", recording_start_run)

    ctx = sw.run_until_triage_approval(
        {"id": "CASE-PARSE-ID", "title": "Run-identity regression case"},
        allow_retry=False, parsing_only=True,
    )

    assert call_order[0] == "start_run", (
        "wss.start_run() must run before enrich_incident_with_apiretrieval_fetch()"
    )
    assert ctx.get("run_id")


def test_start_stage_publishes_run_id_despite_slow_enrichment(monkeypatch):
    """End-to-end regression for the reported bug: start_stage("parsing")
    must still return a run_id promptly (and NOT raise SERVICE_FAILURE)
    even when the real Parsing entry point's enrichment step is much
    slower than the observe-loop's old 2-second deadline."""
    slow_seconds = 3.0

    def slow_enrich(incident, host=None, token=None):
        time.sleep(slow_seconds)
        return incident

    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch", slow_enrich)
    monkeypatch.setattr(sw, "run_parsing", lambda incident, run_id: _fake_parsing_result())

    started = time.monotonic()
    result = commands.start_stage("CASE-PARSE-ID", "parsing")
    elapsed = time.monotonic() - started

    assert result.get("run_id"), "start_stage must return a run_id, not raise SERVICE_FAILURE"
    assert result["status"] == "running"
    assert elapsed < slow_seconds, (
        f"start_stage blocked for {elapsed:.2f}s on enrichment latency instead of "
        "returning as soon as the run identity was published"
    )

    deadline = time.monotonic() + 10
    state = wss.get_state("CASE-PARSE-ID")
    while state["workflow_status"] == "Processing" and time.monotonic() < deadline:
        time.sleep(0.05)
        state = wss.get_state("CASE-PARSE-ID")

    assert state["parsing_status"] == "Complete"
    assert state["workflow_status"] == "Awaiting Action"
    assert state["run_id"] == result["run_id"]


def test_parsing_persist_failure_marks_stage_failed_not_complete(monkeypatch):
    """A failure while persisting the parsing result must surface as a real
    Parsing failure (status Failed + last_error set), never as a silent
    "Complete" with no persisted output -- otherwise Continue to Triage
    could become available with nothing behind it."""
    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch", lambda incident, host=None, token=None: incident)
    monkeypatch.setattr(sw, "run_parsing", lambda incident, run_id: _fake_parsing_result())

    def failing_save(*args, **kwargs):
        raise RuntimeError("disk full (simulated)")

    monkeypatch.setattr(wss, "save_parsing_result", failing_save)

    ctx = sw.run_until_triage_approval(
        {"id": "CASE-PARSE-ID", "title": "Run-identity regression case"},
        allow_retry=False, parsing_only=True,
    )

    assert ctx["stages"]["parsing"] == "failed"
    state = wss.get_state("CASE-PARSE-ID")
    assert state["parsing_status"] == "Failed"
    assert state["workflow_status"] == "Failed"
    assert state["last_error"] and "parsing failed" in state["last_error"]
    assert state["parsing_result_json"] is None


def test_parsing_failure_paths_record_last_error(monkeypatch):
    """Every Parsing failure branch must call wss.set_last_error() so the
    case page can show the real backend failure reason instead of nothing
    (previously only threat_intel/investigation/reporting did this)."""
    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch", lambda incident, host=None, token=None: incident)

    def broken_run_parsing(incident, run_id):
        raise RuntimeError("parser exploded (simulated)")

    monkeypatch.setattr(sw, "run_parsing", broken_run_parsing)

    sw.run_until_triage_approval(
        {"id": "CASE-PARSE-ID", "title": "Run-identity regression case"},
        allow_retry=False, parsing_only=True,
    )

    state = wss.get_state("CASE-PARSE-ID")
    assert state["parsing_status"] == "Failed"
    assert state["last_error"] and "parser exploded" in state["last_error"]


def test_parsing_result_persists_real_normalised_alert(monkeypatch):
    """The persisted parsing_result_json must contain the parser's actual
    structured output, not just a thin status summary -- this is what the
    case page's Normalised Alert panel and Download JSON button render."""
    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch", lambda incident, host=None, token=None: incident)
    monkeypatch.setattr(sw, "run_parsing", lambda incident, run_id: _fake_parsing_result())

    sw.run_until_triage_approval(
        {"id": "CASE-PARSE-ID", "title": "Run-identity regression case"},
        allow_retry=False, parsing_only=True,
    )

    state = wss.get_state("CASE-PARSE-ID")
    result = json.loads(state["parsing_result_json"])
    assert result["normalised_alert"] == {"alert_summary": {"raw_event_count": 4}, "host": "WIN-TEST-01"}
    assert result["processed_alert"] == {"flat": True, "host": "WIN-TEST-01"}
    assert result["summary"]
