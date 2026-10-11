"""Operations Overview analytics: GET /api/dashboard/analytics.

Every chart figure must come from the case database, and every drill-down
the frontend offers (components/overviewAnalytics.js) must reproduce the
clicked count exactly through the existing GET /api/cases filters."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from flask import Flask
from flask.testing import FlaskClient

from workflow import state_store as wss


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_aegis_dashboard_analytics_backend"


def _load_backend():
    package_dir = PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        PACKAGE_NAME, package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE_NAME] = module
    spec.loader.exec_module(module)
    return module


backend = _load_backend()
from _aegis_dashboard_analytics_backend.services import dashboard_service  # noqa: E402


NOW = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)


def _ago(**delta: float) -> str:
    return (NOW - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%S")


def _raw(source_ips=None, sources=("Event Stream Analysis",)) -> str:
    meta = {} if source_ips is None else {"SourceIp": list(source_ips)}
    return json.dumps({"sources": list(sources), "alertMeta": meta})


def _triage(tactic: str | None) -> str:
    return json.dumps({"ticket": {"mitre_tactic": tactic}} if tactic is not None else {"ticket": {}})


# id, title, severity, created, raw_json, workflow_status,
# (parsing, triage, threat_intel, investigation, reporting), triage_result_json
CASES = [
    # Recent (inside 7d), in the workflow, awaiting triage approval.
    ("INC-1", "High Risk Alerts: ESA for 10.0.0.5", "HIGH", _ago(days=2),
     _raw(["10.0.0.5"]), "Awaiting Approval",
     ("Complete", "Awaiting Approval", None, None, None), _triage("Command and Control")),
    # Recent, in the workflow, investigation failed.
    ("INC-2", "High Risk Alerts: ESA for 10.0.0.5", "CRITICAL", _ago(days=1, hours=3),
     _raw(["10.0.0.5", "10.0.0.6"]), "Failed",
     ("Complete", "Approved", "Complete", "Failed", None), _triage("Unknown")),
    # Inside 30d but not 7d; never entered the workflow; blank + duplicate IPs.
    ("INC-3", "High Risk Alerts: NetWitness Endpoint for HOST-1", "MEDIUM", _ago(days=12),
     _raw(["", "10.0.0.6", "10.0.0.6"], ("ECAT",)), None,
     (None, None, None, None, None), None),
    # Old (Wednesday 2024-07-24 09:15 UTC); no source IP; reporting complete.
    ("INC-4", "Threshold Breached", "LOW", "2024-07-24T09:15:00",
     _raw(), "Complete",
     ("Complete", "Approved", "Complete", "Approved", "Approved"), _triage("Discovery")),
    # Old, missing severity, malformed raw JSON.
    ("INC-5", "Lateral Movement via SSH", None, "2024-09-03T23:59:59",
     "not json", None, (None, None, None, None, None), None),
    # Missing created time and title.
    ("INC-6", None, "HIGH", None,
     _raw(["192.168.1.1"]), None, (None, None, None, None, None), None),
]


@pytest.fixture
def case_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cases.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    with sqlite3.connect(path) as connection:
        for case_id, title, severity, created, raw, workflow, stages, triage in CASES:
            connection.execute(
                """INSERT INTO incidents (
                    id, title, severity, status, created, updated, raw_json,
                    run_id, workflow_status, parsing_status, triage_status,
                    threat_intel_status, investigation_status, reporting_status,
                    triage_result_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (case_id, title, severity, "New", created, created, raw,
                 f"{case_id}@run-1" if workflow else None, workflow, *stages, triage),
            )
        connection.commit()
    dashboard_service._analytics_cache.clear()
    return path


@pytest.fixture
def app(case_database: Path) -> Flask:
    return backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": case_database})


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def _analytics(client: FlaskClient, range_key: str = "all") -> dict:
    response = client.get(f"/api/dashboard/analytics?range={range_key}")
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _case_total(client: FlaskClient, **params: str) -> int:
    response = client.get(f"/api/cases?{urlencode({'limit': 1, **params})}")
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()["pagination"]["total"]


def _query_stamp(stamp: str) -> str:
    """Mirror of overviewAnalytics.js queryStamp()."""
    return stamp[:10] if stamp.endswith("T00:00:00") else stamp[:16]


def _created_between(start: str, end: str) -> str:
    return f"created:>={_query_stamp(start)} AND created:<{_query_stamp(end)}"


def test_all_time_aggregates_come_from_the_database(client: FlaskClient) -> None:
    body = _analytics(client)

    assert body["range"] == "all" and body["timezone"] == "UTC"
    assert body["window"]["start"] is None
    assert body["total"] == 6
    assert body["missing_created"] == 1
    assert body["data_bounds"]["earliest_created"] == "2024-07-24T09:15:00"

    severity = {item["key"]: (item["count"], item["filterable"]) for item in body["severity"]["items"]}
    assert severity == {
        "critical": (1, True), "high": (2, True), "medium": (1, True),
        "low": (1, True), "unknown": (1, False),
    }

    rules = {item["label"]: item["count"] for item in body["detection_rules"]["items"]}
    assert rules == {
        "High Risk Alerts: ESA": 2, "High Risk Alerts: NetWitness Endpoint": 1,
        "Threshold Breached": 1, "Lateral Movement via SSH": 1, "Untitled": 1,
    }
    assert body["detection_rules"]["total"] == 6

    # MITRE: triaged incidents only; "Unknown" is reported as not determined.
    tactics = body["mitre_tactics"]
    assert tactics["triaged"] == 3
    assert {item["label"]: item["count"] for item in tactics["items"]} == {
        "Command and Control": 1, "Discovery": 1, "Not determined": 1,
    }

    # Source IPs: distinct incidents per IP; blanks, malformed JSON and
    # missing alertMeta never count.
    ips = body["source_ips"]
    assert {item["label"]: item["count"] for item in ips["items"]} == {
        "10.0.0.5": 2, "10.0.0.6": 2, "192.168.1.1": 1,
    }
    assert (ips["with_ip"], ips["without_ip"]) == (4, 2)


def test_stage_chart_counts_only_incidents_in_the_workflow(client: FlaskClient) -> None:
    stages = _analytics(client)["stages"]

    assert (stages["entered"], stages["unprocessed"]) == (3, 3)
    by_key = {item["key"]: item for item in stages["items"]}
    assert by_key["triage"]["count"] == 1
    assert by_key["triage"]["states"]["awaiting_approval"] == 1
    assert by_key["investigation"]["states"]["failed"] == 1
    # Every stage approved: the case rests on Reporting, completed.
    assert by_key["reporting"]["states"]["completed"] == 1
    assert by_key["parsing"]["count"] == 0
    assert sum(item["count"] for item in stages["items"]) == stages["entered"]


def test_trend_and_heatmap_use_utc_created_time(client: FlaskClient) -> None:
    body = _analytics(client)
    trend = body["trend"]

    assert trend["granularity"] == "month"
    keys = [bucket["key"] for bucket in trend["buckets"]]
    assert keys[0] == "2024-07" and keys[-1] == NOW.strftime("%Y-%m")
    assert len(keys) == len(set(keys))
    counts = {bucket["key"]: bucket["count"] for bucket in trend["buckets"]}
    assert counts["2024-07"] == 1 and counts["2024-08"] == 0 and counts["2024-09"] == 1
    assert (trend["total"], trend["excluded"]) == (5, 1)

    heat = body["heatmap"]
    assert heat["days"][2] == "Wed"
    assert heat["cells"][2][9] == 1          # 2024-07-24 is a Wednesday, 09:xx UTC
    assert heat["cells"][1][23] == 1         # 2024-09-03 is a Tuesday, 23:59 UTC
    assert (heat["total"], heat["excluded"]) == (5, 1)


def test_time_ranges_count_back_from_now(client: FlaskClient) -> None:
    week = _analytics(client, "7d")
    month = _analytics(client, "30d")

    assert week["total"] == 2 and month["total"] == 3
    assert week["missing_created"] == 0
    assert week["stages"]["entered"] == 2 and week["stages"]["unprocessed"] == 0
    assert week["trend"]["granularity"] == "day"
    assert sum(bucket["count"] for bucket in week["trend"]["buckets"]) == 2
    # Daily buckets are contiguous, cover the window and are clipped to it.
    buckets = week["trend"]["buckets"]
    assert buckets[0]["start"] == week["window"]["start"]
    assert buckets[-1]["end"] == week["window"]["end"]
    assert all(a["end"] == b["start"] for a, b in zip(buckets, buckets[1:]))


def test_drilldowns_reproduce_the_chart_counts(client: FlaskClient) -> None:
    for range_key in ("all", "30d", "7d"):
        body = _analytics(client, range_key)
        window = body["window"]
        scope = [] if window["start"] is None else [_created_between(window["start"], window["end"])]
        joined = lambda terms: " AND ".join(terms)

        for item in body["severity"]["items"]:
            if item["filterable"] and item["count"]:
                query = {"query": joined(scope)} if scope else {}
                assert _case_total(client, severity=item["key"].upper(), **query) == item["count"]

        for item in body["stages"]["items"]:
            if item["count"]:
                query = joined([*scope, "NOT workflow_status:not_started"])
                assert _case_total(client, stage=item["key"], query=query) == item["count"], item

        for bucket in body["trend"]["buckets"]:
            if bucket["count"]:
                query = _created_between(bucket["start"], bucket["end"])
                assert _case_total(client, query=query) == bucket["count"], bucket


def test_empty_database_returns_zeros_not_fabricated_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "empty.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    dashboard_service._analytics_cache.clear()
    client = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": path}).test_client()

    body = _analytics(client)
    assert body["total"] == 0
    assert body["data_bounds"] == {"earliest_created": None, "latest_created": None}
    assert body["trend"]["buckets"] == []
    assert all(item["count"] == 0 for item in body["severity"]["items"])
    assert body["detection_rules"]["items"] == [] and body["source_ips"]["items"] == []
    assert body["heatmap"]["max"] == 0


def test_invalid_range_is_rejected(client: FlaskClient) -> None:
    response = client.get("/api/dashboard/analytics?range=90d")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_QUERY"


def test_analytics_is_read_only_and_leaves_dashboard_api_unchanged(
    client: FlaskClient, case_database: Path
) -> None:
    before = case_database.read_bytes()
    dashboard_keys = set(client.get("/api/dashboard").get_json())
    for range_key in ("all", "30d", "7d"):
        _analytics(client, range_key)

    assert case_database.read_bytes() == before
    assert dashboard_keys == {
        "summary", "severity_counts", "active_severity_counts", "status_counts",
        "workflow_counts", "stage_status_counts", "pipeline_counts", "recent_cases",
    }


def test_cache_is_invalidated_by_database_writes(client: FlaskClient, case_database: Path) -> None:
    assert _analytics(client)["total"] == 6
    with sqlite3.connect(case_database) as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, created) VALUES (?,?,?,?)",
            ("INC-7", "New incident", "HIGH", _ago(minutes=5)),
        )
        connection.commit()
    assert _analytics(client)["total"] == 7
