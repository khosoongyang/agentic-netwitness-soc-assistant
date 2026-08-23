"""API tests for the Phase 3 read-only Aegis migration."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

import workflow_state_store as wss


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_aegis_phase3_backend"


def _load_canonical_backend():
    package_dir = PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        PACKAGE_NAME,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the canonical Aegis backend")
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE_NAME] = module
    spec.loader.exec_module(module)
    return module


canonical_backend = _load_canonical_backend()


def _create_pipeline_database(path: Path) -> None:
    tables = (
        "alerts_to_triage", "post_triage_investigate", "post_triage_no_investigate",
        "post_investigation", "initial_ticket", "pending_ticket_report",
        "finalized_report", "workflow_runs",
    )
    with sqlite3.connect(path) as connection:
        for table in tables:
            connection.execute(f"CREATE TABLE {table} (id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO alerts_to_triage (id) VALUES ('CASE-001')")
        connection.commit()


@pytest.fixture
def case_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cases.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO incidents (
                id, title, severity, status, assignee, alert_count,
                created, updated, first_seen, last_seen, raw_json,
                run_id, workflow_status, approval_stage,
                parsing_status, parsing_result_json,
                triage_status, triage_result_json,
                threat_intel_status, investigation_status, reporting_status,
                workflow_updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "CASE-001", "Suspicious PowerShell activity", "HIGH", "New",
                "analyst@example.com", 3, "2026-08-20T10:00:00+00:00",
                "2026-08-20T11:00:00+00:00", "2026-08-20T10:00:00+00:00",
                "2026-08-20T11:00:00+00:00",
                json.dumps({
                    "summary": "PowerShell execution observed.",
                    "riskScore": 82,
                    "alertMeta": {
                        "AlertTitles": ["Suspicious PowerShell"],
                        "Hostname": ["WKSTN-01"],
                        "SourceIp": ["10.0.0.5"],
                    },
                }),
                "CASE-001@run-1", "Awaiting Approval", "triage",
                "Complete", json.dumps({"status": "completed", "summary": "Parsed"}),
                "Awaiting Approval", json.dumps({
                    "status": "completed", "api_key": "must-not-leak",
                    "ticket": {"classification": "High", "summary": "Review required"},
                }),
                "Pending", "Pending", "Pending", "2026-08-20T11:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO incidents (
                id, title, severity, status, assignee, alert_count,
                created, updated, first_seen, last_seen, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "CASE-002", "Closed low-priority case", "LOW", "CLOSED", "",
                1, "2026-08-19T10:00:00+00:00", "2026-08-19T11:00:00+00:00",
                "2026-08-19T10:00:00+00:00", "2026-08-19T11:00:00+00:00", "{}",
            ),
        )
        connection.execute(
            "INSERT INTO fetch_log (fetched_at, count) VALUES (?, ?)",
            ("2026-08-20T11:00:00+00:00", 2),
        )
        connection.commit()
    return path


@pytest.fixture
def empty_case_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "empty-cases.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    return path


@pytest.fixture
def pipeline_database(tmp_path: Path) -> Path:
    path = tmp_path / "pipeline.db"
    _create_pipeline_database(path)
    return path


def _workspace(case_id: str, run_id: str | None) -> dict:
    return {
        "incident_id": case_id,
        "run_id": run_id,
        "overview": {
            "case_context": {
                "netwitness_severity": {"value": "HIGH"},
                "triage_classification": {"value": "High"},
            },
            "key_findings": [{"title": "Suspicious PowerShell", "desc": "Observed"}],
        },
    }


@pytest.fixture
def app(case_database: Path, pipeline_database: Path) -> Flask:
    return canonical_backend.create_app({
        "TESTING": True,
        "AEGIS_CASE_DB_PATH": case_database,
        "AEGIS_PIPELINE_DB_PATH": pipeline_database,
        "AEGIS_CASE_VIEW_BUILDER": _workspace,
    })


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def test_dashboard_returns_legacy_equivalent_aggregates(client: FlaskClient) -> None:
    response = client.get("/api/dashboard")
    body = response.get_json()

    assert response.status_code == 200
    assert body["summary"] == {
        "total_cases": 2,
        "active_cases": 1,
        "critical_active": 0,
        "unassigned_active": 0,
        "awaiting_approval": 1,
        "fetch_count": 1,
        "last_fetch": "2026-08-20T11:00:00+00:00",
    }
    assert body["severity_counts"] == {"HIGH": 1, "LOW": 1}
    assert body["pipeline_counts"]["alerts_to_triage"] == 1
    assert body["recent_cases"][0]["id"] == "CASE-001"


def test_cases_support_search_filter_sort_and_pagination(client: FlaskClient) -> None:
    response = client.get(
        "/api/cases?search=PowerShell&severity=HIGH&status=New&page=1&limit=1&sort=severity"
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["pagination"] == {"page": 1, "limit": 1, "total": 1, "pages": 1}
    assert body["items"][0]["id"] == "CASE-001"
    assert body["items"][0]["current_stage"] == "Triage"


def test_case_detail_reuses_read_only_case_view(client: FlaskClient) -> None:
    response = client.get("/api/cases/CASE-001")
    body = response.get_json()

    assert response.status_code == 200
    assert body["case"]["id"] == "CASE-001"
    assert body["case"]["context"]["hosts"] == ["WKSTN-01"]
    assert body["workspace"]["incident_id"] == "CASE-001"
    assert body["workflow_available"] is True


def test_case_workflow_uses_persisted_stage_and_lock_state(client: FlaskClient) -> None:
    response = client.get("/api/cases/CASE-001/workflow")
    body = response.get_json()

    assert response.status_code == 200
    assert body["current_stage"] == "Triage"
    assert [(stage["key"], stage["state"]) for stage in body["stages"]] == [
        ("parsing", "completed"),
        ("triage", "awaiting_approval"),
        ("threat_intel", "locked"),
        ("investigation", "locked"),
        ("reporting", "locked"),
    ]
    assert body["stages"][1]["requires_approval"] is True
    assert body["stages"][1]["result"]["api_key"] == "«redacted»"
    assert [action["type"] for action in body["stages"][1]["actions"]] == [
        "rerun", "approve", "reject",
    ]
    assert body["stages"][1]["actions"][1]["enabled"] is True
    assert body["evidence_gap"]["mode"] == "automatic"
    assert body["evidence_gap"]["decisions"] == []


def test_unknown_case_uses_json_error_contract(client: FlaskClient) -> None:
    response = client.get("/api/cases/DOES-NOT-EXIST")

    assert response.status_code == 404
    assert response.get_json() == {
        "error": {"code": "CASE_NOT_FOUND", "message": "Case was not found."}
    }


def test_empty_case_list_is_successful(
    empty_case_database: Path, pipeline_database: Path
) -> None:
    app = canonical_backend.create_app({
        "TESTING": True,
        "AEGIS_CASE_DB_PATH": empty_case_database,
        "AEGIS_PIPELINE_DB_PATH": pipeline_database,
    })
    response = app.test_client().get("/api/cases")

    assert response.status_code == 200
    assert response.get_json()["items"] == []
    assert response.get_json()["pagination"]["total"] == 0


def test_service_error_does_not_expose_traceback(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    dashboard_routes = sys.modules[f"{PACKAGE_NAME}.routes.dashboard"]

    def fail_dashboard(**kwargs):
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(dashboard_routes.dashboard_service, "get_dashboard", fail_dashboard)
    response = client.get("/api/dashboard")
    body = response.get_json()

    assert response.status_code == 500
    assert body == {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "The request could not be completed.",
        }
    }
    assert b"sensitive internal detail" not in response.data


def test_read_only_get_requests_do_not_modify_database(
    client: FlaskClient, case_database: Path
) -> None:
    before = case_database.read_bytes()

    for path in (
        "/api/dashboard",
        "/api/cases",
        "/api/cases/CASE-001",
        "/api/cases/CASE-001/workflow",
    ):
        assert client.get(path).status_code == 200

    assert case_database.read_bytes() == before
