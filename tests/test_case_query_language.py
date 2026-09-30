"""Aegis case query language (Operations Overview search box): the parser in
backend/services/case_query.py, its SQL compilation in case_service.py,
GET /api/cases?query=..., and the frontend helpers in
frontend/js/components/queryAssist.js."""

from __future__ import annotations

import importlib.util
import json
import random
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from workflow import state_store as wss


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT_ROOT / "frontend"
PACKAGE_NAME = "_aegis_case_query_backend"


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
from _aegis_case_query_backend.services import case_query as cq  # noqa: E402
from _aegis_case_query_backend.services import case_service  # noqa: E402


# id, title, severity, status, created, updated, run_id, workflow_status,
# approval_stage, (parsing, triage, threat_intel, investigation, reporting),
# NetWitness source (raw_json.sources[0]; "!malformed" = unparseable raw_json)
CASES = [
    ("INC-9999", "Lateral Movement via SSH", "HIGH", "New", "2026-09-05T08:00:00",
     "2026-09-20T10:00:00", "INC-9999@run-1", "Awaiting Approval", "investigation",
     ("Complete", "Approved", "Complete", "Awaiting Approval", "Pending"), "Event Stream Analysis"),
    ("INC-53027", "High Risk Alerts: ESA for 192.168.10.210", "CRITICAL", "New", "2026-09-30T23:30:00",
     "2026-10-01T00:30:00", None, None, None, (None,) * 5, "Event Stream Analysis"),
    ("INC-100", "Command and Control beacon", "MEDIUM", "New", "2026-08-15T12:00:00",
     "2026-09-01T00:00:00", "INC-100@run-1", "Processing", None,
     ("Processing", None, None, None, None), "ECAT"),
    ("INC-2", "Suspicious PowerShell", "LOW", "New", "2024-07-22T08:31:23",
     "2026-09-30T23:59:59", "INC-2@run-1", "Failed", None,
     ("Complete", "Failed", None, None, None), "ECAT"),
    ("INC-53026", "PowerShell encoded command", "HIGH", "New", "2026-04-26T07:22:45",
     "2026-08-31T23:59:59", None, None, None, (None,) * 5, "Risk Scoring"),
    ("INC-7", "Pass the Hash via Mimikatz", "CRITICAL", "CLOSED", "2025-01-01T00:00:00",
     None, "INC-7@run-1", "Awaiting Approval", "triage",
     ("Complete", "Awaiting Approval", None, None, None), "Event Stream Analysis"),
    ("INC-8", "Living off the land binaries", "MEDIUM", "New", "2026-09-10T00:00:00",
     "2026-09-15T09:30:00", None, None, None, (None,) * 5, "!malformed"),
    ("INC-9", "Command beacon and control channel", "HIGH", "New", "2026-09-09T00:00:00",
     "2026-09-10T00:00:00", None, None, None, (None,) * 5, "Event Stream Analysis"),
    ("INC-10", "Disk 100% full", "LOW", "New", "2026-09-11T00:00:00",
     "2026-09-11T00:00:00", None, None, None, (None,) * 5, "Event Stream Analysis"),
    ("INC-11", "Alert 1000 events", "LOW", "New", "2026-09-12T00:00:00",
     "2026-09-12T00:00:00", None, None, None, (None,) * 5, "Event Stream Analysis"),
    ("INC-12", None, None, None, None, None, None, None, None, (None,) * 5, None),
    ("INC-13", "Ransomware staging", "HIGH", "New", "2026-09-02T00:00:00",
     "2026-09-25T12:00:00", "INC-13@run-1", "Complete", None,
     ("Complete", "Approved", "Complete", "Approved", "Approved"), "Event Stream Analysis"),
]
ALL = {case[0] for case in CASES}
FAKE_VERDICTS = {"INC-9999": "HIGH", "INC-100": "UNRATED", "INC-2": "LOW", "INC-7": "CRITICAL", "INC-13": "MEDIUM"}
ESA = {"INC-9999", "INC-53027", "INC-7", "INC-9", "INC-10", "INC-11", "INC-13"}


def _raw_json(case_id: str, title: str | None, source: str | None) -> str:
    if source == "!malformed":
        return "{not json"
    raw: dict = {"id": case_id, "title": title}
    if source:
        raw["sources"] = [source]
    return json.dumps(raw)


def _insert(connection: sqlite3.Connection, case: tuple) -> None:
    (case_id, title, severity, status, created, updated, run_id, workflow_status,
     approval_stage, stages, source) = case
    connection.execute(
        """INSERT INTO incidents (
            id, title, severity, status, assignee, alert_count, created, updated,
            first_seen, last_seen, raw_json, run_id, workflow_status, approval_stage,
            parsing_status, triage_status, threat_intel_status,
            investigation_status, reporting_status
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (case_id, title, severity, status, "", 1, created, updated, created, created,
         _raw_json(case_id, title, source), run_id, workflow_status, approval_stage, *stages),
    )


@pytest.fixture
def case_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cases.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    with sqlite3.connect(path) as connection:
        for case in CASES:
            _insert(connection, case)
        connection.commit()
    return path


@pytest.fixture
def resolver_calls() -> list[str]:
    return []


@pytest.fixture
def app(case_database: Path, resolver_calls: list[str]) -> Flask:
    def resolver(row: dict) -> str:
        resolver_calls.append(row["id"])
        return FAKE_VERDICTS[row["id"]]

    return backend.create_app({
        "TESTING": True,
        "AEGIS_CASE_DB_PATH": case_database,
        "AEGIS_VERDICT_RESOLVER": resolver,
    })


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def _get(client: FlaskClient, query: str, extra: dict | None = None):
    return client.get("/api/cases", query_string={"limit": 200, "query": query, **(extra or {})})


def _ids(client: FlaskClient, query: str, extra: dict | None = None) -> set[str]:
    response = _get(client, query, extra)
    assert response.status_code == 200, response.get_json()
    return {item["id"] for item in response.get_json()["items"]}


def _error(client: FlaskClient, query: str) -> dict:
    response = _get(client, query)
    assert response.status_code == 400, response.get_json()
    error = response.get_json()["error"]
    assert error["code"] == "INVALID_QUERY"
    assert error["details"]["param"] == "query"
    return error


# ── Mode detection: legacy free text vs structured ───────────────────────


@pytest.mark.parametrize("text", [
    "command and control", "living off the land", "pass the hash", "command OR control",
    "Command AND Control", "not a query", "(PowerShell)", "High Risk Alerts: ESA",
    'he said "hello', "C:\\Windows\\System32", "http://evil.example/x", "fe80::1",
    '"severity:HIGH"', "INC-53027", "KELLYWANG", "10:30",
])
def test_plain_text_is_one_legacy_phrase(text: str) -> None:
    parsed = cq.parse_query(text)
    assert parsed.mode == "text"
    assert parsed.root == cq.Text(text, (0, len(text)))


@pytest.mark.parametrize("text", [
    "title:command AND severity:HIGH", "severity:HIGH and stage:investigation",
    "severity:HIGH or severity:CRITICAL", "NOT severity:LOW", "PowerShell severity:HIGH",
    "Severity:HIGH", "random_field:test", "status:", "severity:",
])
def test_any_field_expression_makes_the_search_structured(text: str) -> None:
    assert cq.is_structured(text)


def test_free_text_phrases_match_as_phrases_not_boolean(client: FlaskClient) -> None:
    assert _ids(client, "command and control") == {"INC-100"}  # not INC-9 ("Command beacon and control")
    assert _ids(client, "living off the land") == {"INC-8"}
    assert _ids(client, "pass the hash") == {"INC-7"}
    assert _ids(client, "command OR control") == set()  # a literal phrase, not command OR control
    assert _ids(client, "PowerShell") == {"INC-2", "INC-53026"}
    assert _ids(client, "INC-53027") == {"INC-53027"}
    assert _ids(client, "KELLYWANG") == set()
    assert _ids(client, "High Risk Alerts: ESA") == {"INC-53027"}
    body = _get(client, "command and control").get_json()
    assert body["query"] == {"text": "command and control", "mode": "text",
                             "normalised": "command and control", "fields": []}


def test_free_text_matches_percent_and_underscore_literally(client: FlaskClient) -> None:
    assert _ids(client, "100%") == {"INC-10"}
    assert _ids(client, 'title:"100%"') == {"INC-10"}
    assert _ids(client, "100") == {"INC-10", "INC-11", "INC-100"}  # id matches too


def test_structured_keywords_are_case_insensitive(client: FlaskClient) -> None:
    for query in ("severity:HIGH AND stage:investigation", "severity:HIGH and stage:investigation",
                  "severity:HIGH And stage:investigation", "severity:HIGH stage:investigation"):
        assert _ids(client, query) == {"INC-9999"}, query
    assert _ids(client, "severity:HIGH or severity:CRITICAL") == \
        {"INC-9999", "INC-53026", "INC-9", "INC-13", "INC-53027", "INC-7"}
    assert _ids(client, "title:command AND severity:HIGH") == {"INC-53026", "INC-9"}


# ── Parser: AST shape, precedence, normalisation ─────────────────────────


def _tree(text: str) -> cq.Node:
    parsed = cq.parse_query(text)
    assert parsed.mode == "structured"
    return parsed.root


def _strip(node: cq.Node):
    """AST without source spans, for shape comparisons."""
    if isinstance(node, cq.Term):
        value = node.value.text if isinstance(node.value, cq.DateValue) else node.value
        return ("TERM", node.field, node.op, value)
    if isinstance(node, cq.Text):
        return ("TEXT", node.text)
    if isinstance(node, cq.Not):
        return ("NOT", _strip(node.item))
    return ("AND" if isinstance(node, cq.And) else "OR", *(_strip(item) for item in node.items))


def test_ast_shapes_and_precedence() -> None:
    assert _strip(_tree("severity:HIGH AND stage:investigation")) == \
        ("AND", ("TERM", "severity", "eq", "HIGH"), ("TERM", "stage", "eq", "investigation"))
    assert _strip(_tree("severity:HIGH OR severity:CRITICAL")) == \
        ("OR", ("TERM", "severity", "eq", "HIGH"), ("TERM", "severity", "eq", "CRITICAL"))
    # NOT binds tighter than AND, AND tighter than OR.
    assert _strip(_tree("NOT severity:LOW AND stage:triage OR verdict:HIGH")) == \
        ("OR", ("AND", ("NOT", ("TERM", "severity", "eq", "LOW")), ("TERM", "stage", "eq", "triage")),
         ("TERM", "verdict", "eq", "high"))
    assert _strip(_tree("(severity:HIGH OR severity:CRITICAL) AND stage:investigation")) == \
        ("AND", ("OR", ("TERM", "severity", "eq", "HIGH"), ("TERM", "severity", "eq", "CRITICAL")),
         ("TERM", "stage", "eq", "investigation"))
    assert _strip(_tree("severity:(HIGH OR CRITICAL)")) == _strip(_tree("severity:HIGH OR severity:CRITICAL"))
    assert _strip(_tree("PowerShell severity:HIGH")) == \
        ("AND", ("TEXT", "PowerShell"), ("TERM", "severity", "eq", "HIGH"))
    assert _strip(_tree("lateral movement severity:HIGH")) == \
        ("AND", ("TEXT", "lateral movement"), ("TERM", "severity", "eq", "HIGH"))
    assert _strip(_tree('"command and control" severity:MEDIUM')) == \
        ("AND", ("TEXT", "command and control"), ("TERM", "severity", "eq", "MEDIUM"))


def test_field_names_aliases_and_values_are_normalised() -> None:
    for text in ("severity:HIGH", "Severity:HIGH", "SEVERITY:high", "severity:=High"):
        assert _strip(_tree(text)) == ("TERM", "severity", "eq", "HIGH"), text
    assert _strip(_tree("id:inc-53027")) == ("TERM", "case", "eq", "INC-53027")
    assert _strip(_tree('stage:"Threat Intelligence"')) == ("TERM", "stage", "eq", "threat_intel")
    assert _strip(_tree('stage:"Parsing & Normalisation"')) == ("TERM", "stage", "eq", "parsing")
    assert _strip(_tree('workflow_status:"In Progress"')) == ("TERM", "workflow_status", "eq", "in_progress")
    assert _strip(_tree("workflow_status:Processing")) == ("TERM", "workflow_status", "eq", "in_progress")
    assert _strip(_tree("workflow_status:awaiting_approval")) == ("TERM", "workflow_status", "eq", "awaiting_approval")
    assert _strip(_tree('workflow_status:"Not Started"')) == ("TERM", "workflow_status", "eq", "not_started")
    assert _strip(_tree("source:esa")) == ("TERM", "source", "eq", "esa")
    assert _strip(_tree('source:"Event Stream Analysis"')) == ("TERM", "source", "eq", "esa")
    assert _strip(_tree("verdict:Unrated")) == ("TERM", "verdict", "eq", "unrated")
    assert _strip(_tree("approval_stage:Investigation")) == ("TERM", "approval_stage", "eq", "investigation")


def test_canonical_rendering_explains_the_query() -> None:
    cases = {
        "severity:high and stage:\"Threat Intelligence\"": "severity:HIGH AND stage:threat_intel",
        "severity:(high or critical) not workflow_status:processing":
            '(severity:HIGH OR severity:CRITICAL) AND NOT workflow_status:"In Progress"',
        "id:inc-1 OR source:esa": "case:INC-1 OR source:ESA",
        "powershell updated:>=2026-09-01": '"powershell" AND updated:>=2026-09-01',
        "NOT (severity:LOW OR severity:MEDIUM)": "NOT (severity:LOW OR severity:MEDIUM)",
    }
    for text, expected in cases.items():
        assert cq.to_query(_tree(text)) == expected, text
        assert cq.to_query(_tree(expected)) == expected  # idempotent


def test_dates_default_to_utc_and_span_their_precision() -> None:
    day = cq.parse_date("2026-09-01")
    assert (day.start, day.end) == ("2026-09-01T00:00:00", "2026-09-02T00:00:00")
    minute = cq.parse_date("2026-09-01T10:00")
    assert (minute.start, minute.end) == ("2026-09-01T10:00:00", "2026-09-01T10:01:00")
    second = cq.parse_date("2026-09-01T10:00:05Z")
    assert (second.start, second.end) == ("2026-09-01T10:00:05", "2026-09-01T10:00:06")
    offset = cq.parse_date("2026-09-01T08:00+08:00")
    assert offset.start == "2026-09-01T00:00:00"
    assert cq.parse_date("2026-09-01T00:30-02:30").start == "2026-09-01T03:00:00"
    for bad in ("not-a-date", "2026-02-30", "2026-09-01T25:00", "2026-09-01+08:00", "2026/09/01",
                "2026-9-1", "2026-09-01T10", "2026-09-01 10:00", "2026-09-01T10:00+24:00", "9999-12-31"):
        value = cq.parse_date(bad)
        assert value is None or bad == "9999-12-31", bad


# ── Query examples against the API ───────────────────────────────────────


def test_required_query_examples(client: FlaskClient) -> None:
    assert _ids(client, "severity:HIGH") == {"INC-9999", "INC-53026", "INC-9", "INC-13"}
    assert _ids(client, "severity:HIGH AND stage:investigation") == {"INC-9999"}
    assert _ids(client, "severity:HIGH OR severity:CRITICAL") == \
        {"INC-9999", "INC-53026", "INC-9", "INC-13", "INC-53027", "INC-7"}
    # NOT is an exact complement: INC-12 (no severity at all) is "not LOW".
    assert _ids(client, "NOT severity:LOW") == ALL - {"INC-2", "INC-10", "INC-11"}
    assert _ids(client, "(severity:HIGH OR severity:CRITICAL) AND stage:investigation") == {"INC-9999"}
    assert _ids(client, "severity:(HIGH OR CRITICAL) AND stage:triage") == {"INC-7"}
    assert _ids(client, 'workflow_status:"Awaiting Approval"') == {"INC-9999", "INC-7"}
    assert _ids(client, "severity:HIGH AND NOT workflow_status:Complete") == {"INC-9999", "INC-53026", "INC-9"}
    assert _ids(client, "verdict:HIGH") == {"INC-9999"}
    assert _ids(client, "source:ESA") == ESA
    assert _ids(client, "created:>=2026-09-01") == \
        {"INC-9999", "INC-53027", "INC-8", "INC-9", "INC-10", "INC-11", "INC-13"}
    assert _ids(client, "updated:>=2026-09-01 AND updated:<2026-10-01") == \
        {"INC-9999", "INC-100", "INC-2", "INC-8", "INC-9", "INC-10", "INC-11", "INC-13"}
    assert _ids(client, "PowerShell severity:HIGH") == {"INC-53026"}


def test_workflow_status_values_map_to_stored_workflow_states(client: FlaskClient) -> None:
    assert _ids(client, 'workflow_status:"In Progress"') == {"INC-100"}
    assert _ids(client, "workflow_status:Processing") == {"INC-100"}
    assert _ids(client, 'workflow_status:"Not Started"') == \
        {"INC-53027", "INC-53026", "INC-8", "INC-9", "INC-10", "INC-11", "INC-12"}
    assert _ids(client, "workflow_status:Complete") == {"INC-13"}
    assert _ids(client, "workflow_status:Failed") == {"INC-2"}
    assert _ids(client, 'workflow_status:"Awaiting Action"') == set()
    assert _ids(client, "workflow_status:Rejected") == set()


def test_stage_case_title_and_approval_stage(client: FlaskClient) -> None:
    assert _ids(client, "stage:triage") == {"INC-2", "INC-7"}
    assert _ids(client, "stage:reporting") == {"INC-13"}
    assert _ids(client, 'stage:"Threat Intelligence"') == set()
    assert _ids(client, "case:INC-53027") == {"INC-53027"}
    assert _ids(client, "id:inc-53027") == {"INC-53027"}
    assert _ids(client, "case:INC-5302") == set()  # exact, unlike free text
    assert _ids(client, 'title:"PowerShell"') == {"INC-2", "INC-53026"}
    assert _ids(client, "approval_stage:investigation") == {"INC-9999"}
    assert _ids(client, "approval_stage:triage") == {"INC-7"}
    assert _ids(client, "approval_stage:reporting") == set()


def test_severity_comparisons_follow_the_defined_order(client: FlaskClient) -> None:
    high_or_critical = {"INC-9999", "INC-53026", "INC-9", "INC-13", "INC-53027", "INC-7"}
    medium_or_low = {"INC-100", "INC-8", "INC-2", "INC-10", "INC-11"}
    assert _ids(client, "severity:>=HIGH") == high_or_critical
    assert _ids(client, "severity:>MEDIUM") == high_or_critical
    assert _ids(client, "severity:<HIGH") == medium_or_low  # INC-12 (no severity) never compares
    assert _ids(client, "severity:<=LOW") == {"INC-2", "INC-10", "INC-11"}
    assert _ids(client, "severity:>CRITICAL") == set()
    assert _ids(client, "severity:=HIGH") == _ids(client, "severity:HIGH")


def test_date_comparisons(client: FlaskClient) -> None:
    assert _ids(client, "updated:2026-09-30") == {"INC-2"}
    assert _ids(client, "updated:<=2026-08-31") == {"INC-53026"}
    assert _ids(client, "updated:>2026-09-30") == {"INC-53027"}
    assert _ids(client, "updated:>=2026-10-01T00:30Z") == {"INC-53027"}
    assert _ids(client, "updated:>2026-10-01T00:30") == set()  # after that whole minute
    # 08:00 at +08:00 is 00:00 UTC; 01:00 at +08:00 is 17:00 UTC the day before.
    assert _ids(client, "updated:>=2026-10-01T08:00+08:00") == {"INC-53027"}
    assert _ids(client, "updated:>=2026-10-01T01:00+08:00") == {"INC-53027", "INC-2"}
    # Missing timestamps never match a comparison, but NOT includes them.
    assert _ids(client, "NOT updated:>=2026-09-01") == {"INC-53026", "INC-7", "INC-12"}


def test_unified_verdict_terms_work_inside_or_and_not(client: FlaskClient) -> None:
    assert _ids(client, "verdict:HIGH OR severity:LOW") == {"INC-9999", "INC-2", "INC-10", "INC-11"}
    assert _ids(client, "NOT verdict:HIGH") == ALL - {"INC-9999"}
    unrated = {"INC-53027", "INC-53026", "INC-8", "INC-9", "INC-10", "INC-11", "INC-12", "INC-100"}
    assert _ids(client, "verdict:UNRATED") == unrated
    assert _ids(client, "verdict:(CRITICAL OR MEDIUM)") == {"INC-7", "INC-13"}


def test_source_uses_normalised_netwitness_values(client: FlaskClient) -> None:
    assert _ids(client, "source:ESA") == ESA
    assert _ids(client, 'source:"event stream analysis"') == ESA
    assert _ids(client, "source:ECAT") == {"INC-100", "INC-2"}
    assert _ids(client, 'source:"Risk Scoring"') == {"INC-53026"}
    # The malformed raw_json row indexed as NULL: never a source match.
    assert _ids(client, "NOT source:ESA") == ALL - ESA
    assert "INC-8" in _ids(client, "NOT source:ESA")


def test_response_echoes_the_interpreted_query(client: FlaskClient) -> None:
    body = _get(client, "severity:high and stage:\"Threat Intelligence\" powershell").get_json()
    assert body["query"] == {
        "text": 'severity:high and stage:"Threat Intelligence" powershell',
        "mode": "structured",
        "normalised": 'severity:HIGH AND stage:threat_intel AND "powershell"',
        "fields": ["severity", "stage"],
    }


# ── Query + GUI filters + sort + pagination ──────────────────────────────


def test_gui_filters_are_anded_with_the_query(client: FlaskClient) -> None:
    assert _ids(client, "title:PowerShell", {"severity": "HIGH", "stage": "parsing"}) == {"INC-53026"}
    # Same field in both: ANDed honestly, never overridden.
    response = _get(client, "severity:HIGH", {"severity": "MEDIUM"}).get_json()
    assert response["items"] == []
    assert response["query"]["fields"] == ["severity"]
    assert _ids(client, "severity:HIGH", {"severity": "HIGH,MEDIUM"}) == {"INC-9999", "INC-53026", "INC-9", "INC-13"}
    assert _ids(client, "stage:investigation", {"workflow_status": "awaiting_approval"}) == {"INC-9999"}
    assert _ids(client, "severity:>=HIGH", {"verdict": "critical"}) == {"INC-7"}
    # The legacy `search` parameter (Cases page) still works, and ANDs too.
    assert _ids(client, "severity:HIGH", {"search": "ssh"}) == {"INC-9999"}
    assert _ids(client, "", {"search": "PowerShell"}) == {"INC-2", "INC-53026"}


def test_gui_custom_range_and_query_dates_mean_the_same_instant(client: FlaskClient) -> None:
    query = _ids(client, "updated:>=2026-09-30T23:00 AND updated:<=2026-10-01T00:30")
    gui = _ids(client, "", {"time_range": "custom", "updated_from": "2026-09-30T23:00:00Z",
                            "updated_to": "2026-10-01T00:30:00Z"})
    assert query == gui == {"INC-2", "INC-53027"}


def test_verdict_is_resolved_only_for_cases_passing_the_other_conditions(
    client: FlaskClient, resolver_calls: list[str]
) -> None:
    assert _ids(client, "verdict:HIGH OR severity:LOW", {"stage": "triage"}) == {"INC-2"}
    assert set(resolver_calls) == {"INC-2", "INC-7"}
    resolver_calls.clear()
    assert _ids(client, "severity:HIGH") and resolver_calls == []


def test_query_filters_before_sort_and_pagination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "many.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    with sqlite3.connect(path) as connection:
        for number in range(1, 301):
            severity = "HIGH" if number % 2 else "LOW"
            _insert(connection, (f"INC-{number}", f"Case {number}", severity, "New",
                                 f"2026-01-01T00:{number // 60:02d}:{number % 60:02d}", None,
                                 None, None, None, (None,) * 5, "ECAT"))
        connection.commit()
    client = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": path}).test_client()
    body = client.get("/api/cases", query_string={
        "query": "severity:LOW source:ECAT", "limit": 200, "sort": "id", "direction": "desc"}).get_json()
    assert body["pagination"]["total"] == 150
    assert len(body["items"]) == 150
    assert body["items"][0]["id"] == "INC-300"
    page = client.get("/api/cases", query_string={
        "query": "severity:HIGH", "limit": 50, "page": 2, "sort": "id", "direction": "asc"}).get_json()
    assert page["pagination"] == {"page": 2, "limit": 50, "total": 150, "pages": 3}
    assert [item["id"] for item in page["items"]][:2] == ["INC-101", "INC-103"]
    assert {item["severity"] for item in page["items"]} == {"HIGH"}


# ── Invalid queries ──────────────────────────────────────────────────────


@pytest.mark.parametrize("query, message, hint, span", [
    ("severity:", 'Expected a value after "severity:".', "Expected: CRITICAL, HIGH, MEDIUM, LOW.", (0, 9)),
    ("severity:VERYHIGH", 'Unknown severity "VERYHIGH".', "Expected: CRITICAL, HIGH, MEDIUM, LOW.", (9, 17)),
    ("stage:banana", 'Unknown stage "banana".',
     "Expected: parsing, triage, threat_intel, investigation, reporting.", (6, 12)),
    ("random_field:test", 'Unknown field "random_field".', None, (0, 12)),
    ("(severity:HIGH", 'Missing closing parenthesis for "(".', None, (0, 1)),
    ("severity:HIGH AND", 'Expected a search term after "AND".', None, (14, 17)),
    ("created:>=not-a-date", 'Invalid date "not-a-date" for created.', None, (10, 20)),
    ("status:New", 'Unknown field "status".', "Did you mean workflow_status:?", (0, 6)),
    ("status:", 'Unknown field "status".', "Did you mean workflow_status:?", (0, 6)),
    ("stage:>investigation", 'Operator ">" is not supported for stage.', "Use stage:value.", (0, 7)),
    ("verdict:>=HIGH", 'Operator ">=" is not supported for verdict.', "Use verdict:value.", (0, 10)),
    ("workflow_status:Awaiting Approval", 'Unknown workflow status "Awaiting".',
     'Quote values that contain spaces: workflow_status:"Awaiting Approval".', (16, 24)),
    ('title:"abc', "Missing closing quote.", None, (6, 10)),
    ("severity:HIGH)", 'Unexpected ")" without a matching "(".', None, (13, 14)),
    ("() severity:HIGH", "Empty parentheses.", None, (0, 2)),
    ("severity:HIGH NOT", 'Expected a search term after "NOT".', None, (14, 17)),
    ("AND severity:HIGH", 'Expected a search term before "AND".', None, (0, 3)),
    ("severity:HIGH OR OR severity:LOW", 'Expected a search term after "OR".', None, (14, 16)),
    ("severity:(HIGH AND LOW)", "Only OR can join values inside severity:( ... ).", None, (15, 18)),
    ("severity:(HIGH OR", 'Missing closing parenthesis for "severity:(".', None, (0, 10)),
    ("created:>=2026-02-30", 'Invalid date "2026-02-30" for created.', None, (10, 20)),
    ('title:""', 'Expected a value after "title:".', None, (0, 8)),
    ("user:admin", 'Unknown field "user".', None, (0, 4)),
    ("src_ip:10.0.0.1 severity:HIGH", 'Unknown field "src_ip".', None, (0, 6)),
])
def test_invalid_queries_return_positioned_errors(
    client: FlaskClient, query: str, message: str, hint: str | None, span: tuple[int, int]
) -> None:
    error = _error(client, query)
    assert error["message"] == message
    if hint is not None:
        assert error["details"]["hint"] == hint
    assert (error["details"]["start"], error["details"]["end"]) == span


def test_unknown_field_hint_lists_fields_and_suggests_quotes(client: FlaskClient) -> None:
    hint = _error(client, "random_field:test")["details"]["hint"]
    assert hint.startswith("Fields: case, title, severity, workflow_status, stage, verdict, approval_stage, source, created, updated.")
    assert "wrap it in quotes" in hint


def test_query_limits(client: FlaskClient) -> None:
    assert _error(client, "severity:HIGH " + "x" * 1000)["message"].startswith("Searches are limited to 1000")
    assert "search terms" in _error(client, " ".join(["severity:HIGH"] * 65))["message"]
    assert "nesting" in _error(client, "(" * 17 + "severity:HIGH" + ")" * 17)["message"]
    assert "nesting" in _error(client, "NOT " * 17 + "severity:HIGH")["message"]
    assert _ids(client, "(" * 16 + "severity:HIGH" + ")" * 16) == {"INC-9999", "INC-53026", "INC-9", "INC-13"}


def test_invalid_queries_never_reach_the_database(
    case_database: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args, **_kwargs):
        raise AssertionError("the database must not be opened for an invalid query")

    monkeypatch.setattr(case_service, "open_readonly_connection", unavailable)
    for query in ("severity:VERYHIGH", "(severity:HIGH", "random_field:x", "created:>=nope"):
        with pytest.raises(backend.errors.InvalidQueryError):
            case_service.list_cases(query=query, database_path=case_database)


def test_gui_parameter_errors_keep_their_existing_contract(client: FlaskClient) -> None:
    body = client.get("/api/cases?workflow_status=closed").get_json()
    assert body["error"] == {"code": "INVALID_QUERY", "message": "Unsupported workflow_status value: closed."}


# ── Security ─────────────────────────────────────────────────────────────


HOSTILE = [
    "' OR 1=1 --", "'; DROP TABLE incidents; --", "\" OR \"\"=\"", "%' OR '%'='",
    "1); DELETE FROM incidents; --", "x' UNION SELECT raw_json FROM incidents --",
    "\\'; ATTACH DATABASE 'x' AS y; --", "*/ OR /*", "?", "??", "') OR ('1'='1",
]


def _sql(query: str) -> tuple[str, list]:
    return case_service._compile(cq.parse_query(query).root, levels={})


def test_hostile_enum_values_are_rejected_by_validation(client: FlaskClient) -> None:
    error = _error(client, "severity:\"HIGH' OR 1=1 --\"")
    assert error["message"] == 'Unknown severity "HIGH\' OR 1=1 --".'
    assert _error(client, "stage:\"triage'; DROP TABLE incidents; --\"")["message"].startswith("Unknown stage")
    assert _error(client, "source:\"ESA' OR '1'='1\"")["message"].startswith("Unknown source")
    assert _error(client, "created:\"2026-09-01' OR 1=1 --\"")["message"].startswith("Invalid date")


def test_hostile_text_values_are_only_ever_parameters(client: FlaskClient, case_database: Path) -> None:
    benign_title, benign_params = _sql('title:"benign"')
    benign_case, _ = _sql('case:"benign"')
    benign_text, _ = _sql('"benign" severity:HIGH')
    for value in HOSTILE:
        quoted = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        title_sql, title_params = _sql(f"title:{quoted}")
        assert title_sql == benign_title, value  # SQL structure identical
        assert value.replace("%", "\\%").replace("_", "\\_") in title_params[0].replace("\\\\", "\\")
        assert _sql(f"case:{quoted}")[0] == benign_case
        assert _sql(f"{quoted} severity:HIGH")[0] == benign_text
        if len(value) > 2:  # "?" alone is every placeholder; structure equality covers it
            assert value not in title_sql
        assert _ids(client, f"title:{quoted}") == set()
        assert _ids(client, value) == set()  # free-text mode
    assert _ids(client, 'title:"\'; DROP TABLE incidents; --"') == set()
    with sqlite3.connect(case_database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == len(CASES)


def test_fuzzed_input_never_alters_sql_structure() -> None:
    rng = random.Random(20261001)
    pieces = ["severity:", "HIGH", "title:", "ZQXMARK", '"', "(", ")", "AND", "or", "NOT", ":", ">=", "<",
              "'", ";", "--", "DROP TABLE incidents", "1=1", "\\", "%", "_", " ", "  ", "created:", "2026-09-01",
              "stage:", "investigation", "case:", "source:", "ESA", "random:", "status:", "=", "*"]
    for _ in range(3000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        try:
            parsed = cq.parse_query(text)
        except cq.QueryError as exc:
            assert 0 <= exc.start <= exc.end <= max(len(text), exc.end)
            continue
        if parsed.root is None:
            continue
        sql, params = case_service._compile(parsed.root, levels={})
        for marker in ("ZQXMARK", "DROP", "1=1", ";", "--", "random"):
            assert marker not in sql, (text, sql)
        assert sql.count("?") == len(params), text


def test_compiler_allowlists_fields_and_operators() -> None:
    errors = backend.errors
    for term in (cq.Term("title; DROP TABLE incidents", "eq", "x"), cq.Term("raw_json", "eq", "x"),
                 cq.Term("stage", "gt", "triage"), cq.Term("title", "ge", "x"),
                 cq.Term("verdict", "lt", "high")):
        with pytest.raises(errors.InvalidQueryError):
            case_service._compile(term, levels={})
    assert set(case_service._TERM_COMPILERS) == set(cq.FIELDS) | {"nw_status"}


def test_no_dynamic_code_execution_in_the_query_layer() -> None:
    for path in (PROJECT_ROOT / "backend" / "services" / "case_query.py",
                 PROJECT_ROOT / "backend" / "services" / "case_service.py"):
        source = path.read_text(encoding="utf-8")
        for forbidden in ("eval(", "exec(", "compile(", "__import__", "executescript"):
            assert forbidden not in source.replace("_compile(", "").replace("re.compile(", ""), (path, forbidden)


# ── source: expression index ─────────────────────────────────────────────


def _plan(path: Path, query: str) -> list[str]:
    sql, params = _sql(query)
    with sqlite3.connect(path) as connection:
        return [row[-1] for row in connection.execute(
            f"EXPLAIN QUERY PLAN SELECT COUNT(*) FROM incidents WHERE {sql}", params)]


def test_source_index_is_created_by_db_init(case_database: Path) -> None:
    with sqlite3.connect(case_database) as connection:
        (sql,) = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (wss.PRIMARY_SOURCE_INDEX,)
        ).fetchone()
    assert wss.PRIMARY_SOURCE_SQL in sql
    assert wss.PRIMARY_SOURCE_SQL in case_service._SOURCE_SQL


@pytest.mark.parametrize("query", ["source:ESA", "source:ECAT OR severity:CRITICAL", "NOT source:ESA",
                                   "(source:ECAT AND NOT severity:LOW) OR title:x"])
def test_source_queries_always_use_the_expression_index(case_database: Path, query: str) -> None:
    plan = " | ".join(_plan(case_database, query))
    assert f"USING INDEX {wss.PRIMARY_SOURCE_INDEX}" in plan, plan


def test_missing_source_index_is_reported_not_scanned(client: FlaskClient, case_database: Path) -> None:
    with sqlite3.connect(case_database) as connection:
        connection.execute(f"DROP INDEX {wss.PRIMARY_SOURCE_INDEX}")
    response = _get(client, "source:ESA")
    assert response.status_code == 503
    assert response.get_json()["error"]["code"] == "QUERY_INDEX_UNAVAILABLE"
    assert _get(client, "severity:HIGH").status_code == 200  # other fields unaffected
    wss.db_init()  # additive migration rebuilds it
    assert _ids(client, "source:ESA") == ESA


# ── Registry consistency + schema endpoint ───────────────────────────────


def test_stage_vocabulary_matches_the_workflow_definitions() -> None:
    definitions = {str(d["key"]): d["name"] for d in case_service._STAGE_DEFINITIONS}
    assert {value.key: value.label for value in cq.FIELDS["stage"].values} == definitions
    assert case_service._WORKFLOW_STATUS_FILTERS["in_progress"] == "Processing"
    assert case_service._WORKFLOW_STATUS_FILTERS["not_started"] is None


def test_query_schema_endpoint(client: FlaskClient) -> None:
    schema = client.get("/api/cases/query-schema").get_json()
    names = [field["name"] for field in schema["fields"]]
    assert names == ["case", "title", "severity", "workflow_status", "stage", "verdict",
                     "approval_stage", "source", "created", "updated"]
    deferred = {"user", "host", "src_ip", "dst_ip", "hash", "domain", "ioc", "mitre",
                "risk_score", "triage_risk", "threat_risk", "investigation_severity", "status"}
    assert not deferred & set(names)
    fields = {field["name"]: field for field in schema["fields"]}
    assert fields["case"]["aliases"] == ["id"]
    assert [value["value"] for value in fields["severity"]["values"]] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert fields["severity"]["operators"] == [":", ":>", ":>=", ":<", ":<="]
    assert fields["stage"]["operators"] == [":"]
    assert [value["value"] for value in fields["approval_stage"]["values"]] == ["triage", "investigation", "reporting"]
    assert {value["insert"] for value in fields["workflow_status"]["values"]} >= {'"Awaiting Approval"', "Failed"}
    assert schema["hints"] == {"status": "workflow_status"}
    assert "Dates without a timezone are interpreted as UTC." in schema["notes"]
    assert "Severity order: CRITICAL > HIGH > MEDIUM > LOW." in schema["notes"]
    assert [example["query"] for example in schema["examples"]] == [
        "severity:HIGH AND stage:investigation", 'workflow_status:"Awaiting Approval"',
        "severity:HIGH OR severity:CRITICAL", "updated:>=2026-09-01", "verdict:HIGH"]
    for example in schema["examples"]:
        assert cq.parse_query(example["query"]).mode == "structured"


# ── Frontend (Node) ──────────────────────────────────────────────────────


_NODE_SCRIPT = r"""
import assert from "node:assert/strict";
const qa = await import(process.argv[1]);
const cf = await import(process.argv[2]);
const schema = JSON.parse(process.argv[3]);

// Mode detection mirrors the backend: only field expressions are structured.
for (const text of ["command and control", "living off the land", "pass the hash", "command OR control",
    "High Risk Alerts: ESA", "C:\\Windows", "http://x.example", '"severity:HIGH"', "PowerShell", ""]) {
  assert.equal(qa.isStructuredQuery(text, schema), false, text);
}
for (const text of ["severity:HIGH and stage:investigation", "PowerShell severity:HIGH", "NOT severity:LOW",
    "severity:", "status:", "random_field:x", "Severity:HIGH", "id:INC-1"]) {
  assert.equal(qa.isStructuredQuery(text, schema), true, text);
}

const at = (text, cursor = text.length) => qa.suggestionsAt(text, cursor, schema);
const labels = (text, cursor) => at(text, cursor).items.map((item) => item.label);

// Field names from a partial word; values after field:; keywords after a term.
assert.deepEqual(labels("sev"), ["severity:"]);
assert.deepEqual(labels("st"), ["stage:"]);
assert.ok(labels("i").length === 0, "single letters in free text stay quiet");
assert.deepEqual(labels("severity:"), ["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
assert.deepEqual(labels("severity:h"), ["HIGH"]);
assert.deepEqual(labels("severity:HIGH"), []);
assert.deepEqual(labels("stage:"), ["parsing", "triage", "threat_intel", "investigation", "reporting"]);
assert.deepEqual(labels("stage:thr"), ["threat_intel"]);
assert.deepEqual(labels("verdict:"), ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNRATED"]);
assert.deepEqual(labels("approval_stage:"), ["triage", "investigation", "reporting"]);
assert.deepEqual(labels("severity:HIGH "), ["AND", "OR", "NOT"]);
assert.deepEqual(labels("severity:HIGH a"), ["AND", "approval_stage:"]);
assert.ok(labels("severity:HIGH AND ").includes("stage:"));
assert.ok(labels("severity:HIGH AND ").includes("NOT"));
assert.deepEqual(labels("command a"), [], "no Boolean suggestions in free text");
assert.deepEqual(labels("created:"), [">=", "<", ">", "<="]);
assert.deepEqual(labels("created:>="), []);
assert.deepEqual(labels("severity:(HIGH OR "), ["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
assert.deepEqual(labels("severity:(HIGH) AND ("), labels("severity:HIGH AND ("));
assert.deepEqual(labels('workflow_status:"Awaiting'), ["Awaiting Action", "Awaiting Approval"]);
assert.deepEqual(labels("workflow_status:in"), ["In Progress"]);
assert.deepEqual(labels("id"), []);
assert.deepEqual(labels("ca"), ["case:"]);

// Choosing a suggestion replaces the partial token (values with spaces are quoted).
let s = at("sev");
assert.deepEqual(qa.applySuggestion("sev", s, s.items[0]), { text: "severity:", cursor: 9 });
s = at('severity:HIGH workflow_status:"Awaiting Ap');
const approval = s.items.find((item) => item.label === "Awaiting Approval");
assert.equal(qa.applySuggestion('severity:HIGH workflow_status:"Awaiting Ap', s, approval).text,
  'severity:HIGH workflow_status:"Awaiting Approval" ');
s = at("severity:HIGH ");
assert.equal(qa.applySuggestion("severity:HIGH ", s, s.items[0]).text, "severity:HIGH AND ");
// Mid-text cursor: only the token before the cursor is replaced.
s = at("sev AND stage:triage", 3);
assert.equal(qa.applySuggestion("sev AND stage:triage", s, s.items[0]).text, "severity: AND stage:triage");
// Severity / verdict values carry the badge tone.
assert.equal(at("severity:").items[0].tone, "tone-critical");
assert.equal(at("stage:").items[0].tone, "");

// Inline error markup: escaped, with the offending span marked.
const html = qa.errorHTML({ message: 'Unknown severity "<b>".', details: { start: 9, end: 12, hint: "Expected: HIGH." } }, "severity:<b>");
assert.match(html, /Unknown severity &quot;&lt;b&gt;&quot;\./);
assert.match(html, /severity:<mark>&lt;b&gt;<\/mark>/);
assert.match(html, /Expected: HIGH\./);

// Help: fields, UTC note, severity order and the SOC examples.
const help = qa.helpHTML(schema);
assert.match(help, /Dates without a timezone are interpreted as UTC\./);
assert.match(help, /CRITICAL &gt; HIGH &gt; MEDIUM &gt; LOW/);
assert.match(help, /High-severity investigations/);
assert.match(help, /data-query="workflow_status:&quot;Awaiting Approval&quot;"/);
assert.match(help, /approval_stage:/);
assert.match(qa.helpHTML(null), /Plain text search still works/);

// The search box sends `query`; GUI filter values are keys the backend accepts.
const api = cf.apiParams({ q: "severity:HIGH", filters: cf.emptyFilters(), sort: "newest" });
assert.equal(api.get("query"), "severity:HIGH");
const keys = Object.fromEntries(schema.fields.map((field) => [field.name, field.values.map((value) => value.key)]));
assert.deepEqual(cf.WORKFLOW_STATUS_OPTIONS.map((option) => option.value), keys.workflow_status);
assert.deepEqual(cf.STAGE_OPTIONS.map((option) => option.value), keys.stage);
assert.deepEqual(cf.VERDICT_OPTIONS.map((option) => option.value), keys.verdict);
assert.deepEqual(cf.SEVERITY_OPTIONS.map((option) => option.value.toUpperCase()), keys.severity);

// Custom range: UTC in, UTC out, UTC on the chip.
const custom = { ...cf.emptyFilters(), time: "custom", from: "2026-09-01T10:00", to: "2026-09-02T18:30:15" };
const customParams = cf.apiParams({ q: "", filters: custom, sort: "newest" });
assert.equal(customParams.get("updated_from"), "2026-09-01T10:00:00Z");
assert.equal(customParams.get("updated_to"), "2026-09-02T18:30:15Z");
assert.equal(cf.activeChips(custom)[0].label, "Updated 2026-09-01 10:00 UTC – 2026-09-02 18:30:15 UTC");

// Fields the Filters panel constrains (for the "constrained by both" hint).
assert.deepEqual(cf.filterQueryFields({ ...cf.emptyFilters(), severity: ["high"], time: "24h" }), ["severity", "updated"]);
assert.deepEqual(cf.filterQueryFields(cf.emptyFilters()), []);
console.log("ok");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_frontend_query_assist_helpers() -> None:
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _NODE_SCRIPT,
         (FRONTEND / "js" / "components" / "queryAssist.js").as_uri(),
         (FRONTEND / "js" / "components" / "caseFilters.js").as_uri(),
         json.dumps(cq.schema())],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")


def test_frontend_wiring() -> None:
    filters = (FRONTEND / "js" / "components" / "caseFilters.js").read_text(encoding="utf-8")
    overview = (FRONTEND / "js" / "pages" / "overview.js").read_text(encoding="utf-8")
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert "createQueryAssist" in filters
    assert "isStructured(" in filters and "setTimeout(applySearch, 300)" in filters
    assert 'error.code === "INVALID_QUERY"' in overview and "showQueryError" in overview
    assert "Ask Aegis" not in html.split('id="topbar-search-input"')[1].split(">")[0]
    css = (FRONTEND / "css" / "case-filters.css").read_text(encoding="utf-8")
    for selector in (".query-assist", ".query-suggestion.is-active", ".query-assist-error", ".query-help"):
        assert selector in css
