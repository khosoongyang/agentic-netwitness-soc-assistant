"""Flask contracts for Phase 4 workflow mutations."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from workflow import state_store as wss
from workflow import commands


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_aegis_phase4_backend"


def _load_backend():
    package_dir = PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        PACKAGE_NAME,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load canonical backend")
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE_NAME] = module
    spec.loader.exec_module(module)
    return module


canonical_backend = _load_backend()


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    database = tmp_path / "workflow-api.db"
    monkeypatch.setattr(wss, "DB_FILE", database)
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    with wss.db_connect() as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, status, raw_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("CASE-API", "API case", "HIGH", "New", json.dumps({"id": "CASE-API"})),
        )
        connection.commit()
    monkeypatch.setattr(commands, "_spawn_background", lambda *_args, **_kwargs: None)
    app = canonical_backend.create_app({
        "TESTING": True,
        "AEGIS_CASE_DB_PATH": database,
        "AEGIS_CASE_VIEW_BUILDER": lambda *_: {},
    })
    return app.test_client()


def _awaiting_triage() -> str:
    run_id = wss.start_run("CASE-API")
    wss._guarded_update("CASE-API", run_id, {
        "parsing_status": "Complete",
        "triage_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "triage",
    })
    return run_id


def _approved_triage() -> str:
    run_id = _awaiting_triage()
    wss.approve_triage("CASE-API", run_id, approved_by="Fixture")
    return run_id


def test_post_stage_run_and_duplicate_start_contract(client: FlaskClient) -> None:
    run_id = _approved_triage()
    response = client.post("/api/cases/CASE-API/stages/threat_intel/runs")
    assert response.status_code == 202
    assert response.get_json() == {
        "attempt": 1, "case_id": "CASE-API", "incident_id": "CASE-API",
        "run_id": run_id, "stage": "threat_intel", "status": "running",
    }

    duplicate = client.post("/api/cases/CASE-API/stages/threat_intel/runs")
    assert duplicate.status_code == 409
    assert duplicate.get_json()["error"]["code"] == "WORKFLOW_BUSY"


def test_invalid_and_locked_stage_errors(client: FlaskClient) -> None:
    _awaiting_triage()
    invalid = client.post("/api/cases/CASE-API/stages/not-a-stage/runs")
    locked = client.post("/api/cases/CASE-API/stages/investigation/runs")

    assert invalid.status_code == 400
    assert invalid.get_json()["error"]["code"] == "INVALID_STAGE"
    assert locked.status_code == 409
    assert locked.get_json()["error"]["code"] == "STAGE_LOCKED"


def test_post_rerun_preserves_attempt_and_invalidation(client: FlaskClient) -> None:
    run_id = _approved_triage()
    wss._guarded_update("CASE-API", run_id, {
        "threat_intel_status": "Complete",
        "investigation_status": "Approved",
        "investigation_result_json": "{}",
        "reporting_status": "Approved",
        "reporting_result_json": "{}",
        "workflow_status": "Complete",
    })

    response = client.post("/api/cases/CASE-API/stages/threat_intel/reruns")
    assert response.status_code == 202
    assert response.get_json()["attempt"] == 2
    state = wss.get_state("CASE-API")
    assert state["investigation_status"] == "Pending"
    assert state["reporting_result_json"] is None


def test_run_status_contract(client: FlaskClient) -> None:
    run_id = _awaiting_triage()
    response = client.get(f"/api/runs/{run_id}")
    missing = client.get("/api/runs/missing")

    assert response.status_code == 200
    assert response.get_json()["status"] == "Awaiting Approval"
    assert response.get_json()["poll"] is False
    assert missing.status_code == 404
    assert missing.get_json()["error"]["code"] == "RUN_NOT_FOUND"


def test_approve_and_duplicate_approval_contracts(client: FlaskClient) -> None:
    _awaiting_triage()
    approved = client.post("/api/cases/CASE-API/approvals/triage", json={
        "decision": "approve", "analyst": "API Analyst", "comments": "Reviewed",
    })
    duplicate = client.post("/api/cases/CASE-API/approvals/triage", json={
        "decision": "approve", "analyst": "API Analyst", "comments": "Again",
    })

    assert approved.status_code == 200
    assert approved.get_json()["decision"] == "approve"
    assert duplicate.status_code == 409
    assert duplicate.get_json()["error"]["code"] == "DUPLICATE_APPROVAL"


def test_reject_requires_reason_and_uses_canonical_lock(client: FlaskClient) -> None:
    _awaiting_triage()
    missing = client.post("/api/cases/CASE-API/approvals/triage", json={
        "decision": "reject", "analyst": "API Analyst", "comments": "",
    })
    rejected = client.post("/api/cases/CASE-API/approvals/triage", json={
        "decision": "reject", "analyst": "API Analyst", "comments": "False positive",
    })

    assert missing.status_code == 400
    assert missing.get_json()["error"]["code"] == "REJECTION_REASON_REQUIRED"
    assert rejected.status_code == 200
    assert wss.get_state("CASE-API")["threat_intel_status"] == "Blocked"


def test_case_not_found_and_invalid_evidence_gap_decision(client: FlaskClient) -> None:
    missing = client.post("/api/cases/missing/stages/triage/runs")
    evidence = client.post(
        "/api/cases/CASE-API/evidence-gap-decisions", json={"decision": "invented"}
    )

    assert missing.status_code == 404
    assert missing.get_json()["error"]["code"] == "CASE_NOT_FOUND"
    assert evidence.status_code == 400
    assert evidence.get_json()["error"]["code"] == "INVALID_EVIDENCE_GAP_DECISION"


def test_approval_conflict_and_invalid_decision_contract(client: FlaskClient) -> None:
    _approved_triage()
    conflict = client.post("/api/cases/CASE-API/approvals/investigation", json={
        "decision": "approve", "analyst": "API Analyst",
    })
    invalid = client.post("/api/cases/CASE-API/approvals/triage", json={
        "decision": "maybe", "analyst": "API Analyst",
    })

    assert conflict.status_code == 409
    assert conflict.get_json()["error"]["code"] == "APPROVAL_CONFLICT"
    assert invalid.status_code == 400
    assert invalid.get_json()["error"]["code"] == "INVALID_APPROVAL_DECISION"


def test_resume_interrupted_workflow_contract(client: FlaskClient) -> None:
    run_id = _approved_triage()
    old = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    wss._guarded_update("CASE-API", run_id, {
        "threat_intel_status": "Processing",
        "workflow_status": "Processing",
        "worker_id": None,
        "worker_lease_expires_at": None,
    })
    with wss.db_connect() as connection:
        connection.execute(
            "UPDATE incidents SET workflow_updated_at=? WHERE id=? AND run_id=?",
            (old, "CASE-API", run_id),
        )
        connection.commit()

    response = client.post("/api/cases/CASE-API/workflow/resume")

    assert response.status_code == 202
    assert response.get_json()["run_id"] == run_id
    assert response.get_json()["stage"] == "threat_intel"


def test_api_preserves_canonical_approval_and_stage_handoffs(client: FlaskClient) -> None:
    run_id = _awaiting_triage()
    triage_approval = client.post("/api/cases/CASE-API/approvals/triage", json={
        "decision": "approve", "analyst": "API Analyst", "comments": "Proceed",
    })
    threat_intel_start = client.post(
        "/api/cases/CASE-API/stages/threat_intel/runs"
    )
    assert triage_approval.status_code == 200
    assert threat_intel_start.status_code == 202

    wss._guarded_update("CASE-API", run_id, {
        "threat_intel_status": "Complete",
        "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "investigation",
    })
    investigation_approval = client.post(
        "/api/cases/CASE-API/approvals/investigation",
        json={"decision": "approve", "analyst": "API Analyst", "comments": "Proceed"},
    )
    reporting_start = client.post("/api/cases/CASE-API/stages/reporting/runs")

    assert investigation_approval.status_code == 200
    assert reporting_start.status_code == 202
    state = wss.get_state("CASE-API")
    assert state["reporting_status"] == "Processing"
    assert state["workflow_status"] == "Processing"
