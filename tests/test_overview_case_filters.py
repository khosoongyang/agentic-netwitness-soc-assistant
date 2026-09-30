"""Operations Overview search / filter / sort: GET /api/cases extensions and
the frontend state helpers in frontend/js/components/caseFilters.js."""

from __future__ import annotations

import importlib.util
import itertools
import json
import random
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from workflow import state_store as wss


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT_ROOT / "frontend"
PACKAGE_NAME = "_aegis_overview_filters_backend"


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
from _aegis_overview_filters_backend.services import case_service  # noqa: E402


NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _utc(delta: timedelta) -> str:
    """Stored the way sync_service stores NetWitness times: UTC, no "Z"."""
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%S")


# id, title, severity, status, created, updated, last_seen, run_id,
# workflow_status, (parsing, triage, threat_intel, investigation, reporting)
CASES = [
    ("INC-9999", "Lateral Movement via SSH", "HIGH", "New",
     "2026-01-01T00:00:00", _utc(timedelta(hours=2)), "2026-07-29T17:24:49",
     "INC-9999@run-1", "Awaiting Approval",
     ("Complete", "Approved", "Complete", "Awaiting Approval", "Pending")),
    ("INC-53027", "High Risk Alerts: ESA for 192.168.10.210", "CRITICAL", "New",
     "2026-04-28T11:08:52", _utc(timedelta(days=3)), _utc(timedelta(minutes=1)),
     None, None, (None, None, None, None, None)),
    ("INC-100", "SSH brute force", "MEDIUM", "New",
     "2025-06-01T08:00:00", _utc(timedelta(days=40)), "2026-07-29T15:23:45",
     "INC-100@run-1", "Processing",
     ("Processing", None, None, None, None)),
    ("INC-2", "Suspicious PowerShell", "LOW", "New",
     "2024-07-22T08:31:23", _utc(timedelta(minutes=10)), "2026-07-15T16:28:42",
     "INC-2@run-1", "Failed",
     ("Complete", "Failed", None, None, None)),
    ("INC-53026", "SSH tunnel detected", "HIGH", "New",
     "2026-04-26T07:22:45", _utc(timedelta(days=5)), "2026-07-29T15:23:45",
     None, None, (None, None, None, None, None)),
    ("INC-7", "Closed low-priority case", "LOW", "CLOSED",
     "2025-01-01T00:00:00", None, "2026-07-29T15:23:45",
     None, None, (None, None, None, None, None)),
]
ALL_IDS = {case[0] for case in CASES}
RUN_IDS = {case[0] for case in CASES if case[7]}


def _insert(connection: sqlite3.Connection, case: tuple) -> None:
    (case_id, title, severity, status, created, updated, last_seen, run_id,
     workflow_status, stages) = case
    connection.execute(
        """INSERT INTO incidents (
            id, title, severity, status, assignee, alert_count, created, updated,
            first_seen, last_seen, raw_json, run_id, workflow_status,
            parsing_status, triage_status, threat_intel_status,
            investigation_status, reporting_status
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (case_id, title, severity, status, "", 1, created, updated, created,
         last_seen, json.dumps({"id": case_id, "title": title, "priority": severity.title()}),
         run_id, workflow_status, *stages),
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


FAKE_VERDICTS = {"INC-9999": "HIGH", "INC-100": "UNRATED", "INC-2": "LOW"}


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


def _ids(client: FlaskClient, query: str = "") -> list[str]:
    response = client.get(f"/api/cases?limit=200&{query}")
    assert response.status_code == 200, response.get_json()
    return [item["id"] for item in response.get_json()["items"]]


# ── Filters ──────────────────────────────────────────────────────────────


def test_multi_severity_filter_is_an_in_list(client: FlaskClient) -> None:
    assert set(_ids(client, "severity=HIGH,CRITICAL")) == {"INC-9999", "INC-53027", "INC-53026"}
    assert set(_ids(client, "severity=low,medium")) == {"INC-2", "INC-7", "INC-100"}


def test_workflow_status_filter_maps_analyst_keys_to_stored_values(client: FlaskClient) -> None:
    assert set(_ids(client, "workflow_status=not_started")) == {"INC-53027", "INC-53026", "INC-7"}
    assert _ids(client, "workflow_status=in_progress") == ["INC-100"]
    assert set(_ids(client, "workflow_status=awaiting_approval,failed")) == {"INC-9999", "INC-2"}
    assert _ids(client, "workflow_status=complete") == []
    assert client.get("/api/cases?workflow_status=closed").status_code == 400


def test_workflow_stage_filter_uses_the_derived_current_stage(client: FlaskClient) -> None:
    assert _ids(client, "stage=investigation") == ["INC-9999"]
    assert _ids(client, "stage=triage") == ["INC-2"]
    assert set(_ids(client, "stage=parsing")) == {"INC-53027", "INC-100", "INC-53026", "INC-7"}
    assert set(_ids(client, "stage=triage,investigation")) == {"INC-9999", "INC-2"}
    assert client.get("/api/cases?stage=approval").status_code == 400


def test_time_range_filters_on_netwitness_updated_not_last_seen(client: FlaskClient) -> None:
    # INC-53027 was synced (last_seen) a minute ago but last updated 3 days ago.
    assert _ids(client, "time_range=1h") == ["INC-2"]
    assert set(_ids(client, "time_range=24h")) == {"INC-9999", "INC-2"}
    assert set(_ids(client, "time_range=7d")) == {"INC-9999", "INC-2", "INC-53027", "INC-53026"}
    assert set(_ids(client, "time_range=30d")) == {"INC-9999", "INC-2", "INC-53027", "INC-53026"}


def test_custom_time_range_bounds_and_validation(client: FlaskClient) -> None:
    since = (NOW - timedelta(days=4)).isoformat().replace("+00:00", "Z")
    until = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    query = f"time_range=custom&updated_from={since}&updated_to={until}"
    assert set(_ids(client, query)) == {"INC-9999", "INC-53027"}
    # A missing `updated` never matches a bounded range.
    assert "INC-7" not in _ids(client, "updated_to=2100-01-01T00:00:00Z")
    assert client.get("/api/cases?time_range=90d").status_code == 400
    assert client.get("/api/cases?updated_from=yesterday").status_code == 400
    assert client.get(f"/api/cases?updated_from={until}&updated_to={since}").status_code == 400


def test_unified_verdict_filter_resolves_only_run_cases(
    client: FlaskClient, resolver_calls: list[str]
) -> None:
    assert _ids(client, "verdict=high") == ["INC-9999"]
    assert set(resolver_calls) == RUN_IDS
    assert set(_ids(client, "verdict=low,high")) == {"INC-9999", "INC-2"}
    assert _ids(client, "verdict=critical") == []
    assert client.get("/api/cases?verdict=severe").status_code == 400


def test_unrated_verdict_covers_cases_without_a_verdict(client: FlaskClient) -> None:
    unrated = set(_ids(client, "verdict=unrated"))
    assert unrated == {"INC-53027", "INC-53026", "INC-7", "INC-100"}
    assert set(_ids(client, "verdict=unrated,high")) == unrated | {"INC-9999"}


def test_verdict_resolver_is_the_workspace_aggregate_verdict(case_database: Path) -> None:
    from _aegis_overview_filters_backend.services import case_view_service as cv

    with sqlite3.connect(case_database) as connection:
        connection.row_factory = sqlite3.Row
        rows = {row["id"]: dict(row) for row in connection.execute("SELECT * FROM incidents")}

    for case_id, row in rows.items():
        level = cv.unified_verdict_level(row)
        if not row["run_id"]:
            assert level == "UNRATED"
            continue
        incident, _, _ = cv.load_incident_for_case_view(case_id, row["run_id"])
        shown = cv.build_overview(row, incident, case_id, row["run_id"])["case_context"]["unified_verdict"]["value"]
        assert level == (shown if shown in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNRATED")

    # Without an injected resolver, list_cases uses that same function.
    for case_id in RUN_IDS:
        level = cv.unified_verdict_level(rows[case_id]).lower()
        result = case_service.list_cases(verdict=level, database_path=case_database)
        assert case_id in {item["id"] for item in result["items"]}


# ── Sorting ──────────────────────────────────────────────────────────────


def test_incident_id_sort_is_numeric(client: FlaskClient) -> None:
    ascending = ["INC-2", "INC-7", "INC-100", "INC-9999", "INC-53026", "INC-53027"]
    assert _ids(client, "sort=id&direction=asc") == ascending
    assert _ids(client, "sort=id&direction=desc") == ascending[::-1]


def test_newest_and_oldest_sort_on_netwitness_created(client: FlaskClient) -> None:
    newest = ["INC-53027", "INC-53026", "INC-9999", "INC-100", "INC-7", "INC-2"]
    assert _ids(client, "sort=created&direction=desc") == newest
    assert _ids(client, "sort=created&direction=asc") == newest[::-1]


def test_last_seen_sort_breaks_sync_time_ties_by_incident_number(client: FlaskClient) -> None:
    assert _ids(client, "sort=last_seen&direction=desc") == [
        "INC-53027", "INC-9999", "INC-53026", "INC-100", "INC-7", "INC-2"]
    assert _ids(client, "sort=last_seen&direction=asc") == [
        "INC-2", "INC-7", "INC-100", "INC-53026", "INC-9999", "INC-53027"]


def test_search_filters_and_sort_combine(client: FlaskClient) -> None:
    query = ("search=ssh&severity=HIGH&stage=investigation&time_range=7d"
             "&verdict=high&sort=created&direction=desc")
    assert _ids(client, query) == ["INC-9999"]
    # Filters narrow the search; sort orders what remains (INC-100 is SSH
    # but last updated 40 days ago).
    assert _ids(client, "search=ssh&time_range=7d&sort=created&direction=asc") == ["INC-9999", "INC-53026"]
    assert _ids(client, "search=ssh&time_range=7d&sort=severity&direction=desc") == ["INC-53026", "INC-9999"]
    body = client.get("/api/cases?search=ssh&severity=HIGH&stage=investigation&verdict=high").get_json()
    assert body["filters"]["stage"] == ["investigation"]
    assert body["filters"]["verdict"] == ["high"]
    assert body["pagination"]["total"] == 1


def test_legacy_single_value_parameters_are_unchanged(client: FlaskClient) -> None:
    assert set(_ids(client, "severity=HIGH")) == {"INC-9999", "INC-53026"}
    assert set(_ids(client, "severity=high")) == {"INC-9999", "INC-53026"}
    assert _ids(client, "status=CLOSED") == ["INC-7"]
    assert set(_ids(client, "severity=ALL&status=ALL")) == ALL_IDS
    assert set(_ids(client, "search=inc-99")) == {"INC-9999"}

    body = client.get("/api/cases?severity=HIGH&status=ALL&page=1&limit=1").get_json()
    assert body["filters"]["severity"] == "HIGH"
    assert body["filters"]["status"] == "ALL"
    assert body["filters"]["sort"] == "updated"
    assert body["filters"]["direction"] == "desc"
    assert body["pagination"] == {"page": 1, "limit": 1, "total": 2, "pages": 2}
    assert set(body["facets"]["severities"]) == {"CRITICAL", "HIGH", "LOW", "MEDIUM"}
    assert set(body["facets"]["statuses"]) == {"CLOSED", "New"}
    assert {"id", "title", "severity", "status", "current_stage", "last_seen", "updated"} <= set(body["items"][0])

    assert client.get("/api/cases?sort=bogus").status_code == 400
    assert client.get("/api/cases?direction=up").status_code == 400


def test_result_cap_reports_total_matching_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "many.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    with sqlite3.connect(path) as connection:
        for number in range(1, 251):
            _insert(connection, (f"INC-{number}", f"Case {number}", "HIGH", "New",
                                 f"2026-01-01T00:{number // 60:02d}:{number % 60:02d}", None,
                                 None, None, None, (None,) * 5))
        connection.commit()
    client = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": path}).test_client()

    body = client.get("/api/cases?limit=200&sort=created&direction=desc").get_json()
    assert len(body["items"]) == 200
    assert body["pagination"]["total"] == 250
    assert body["items"][0]["id"] == "INC-250"
    assert client.get("/api/cases?limit=201").status_code == 400


# ── Workflow stage SQL == _current_stage_from_row() ──────────────────────

_STAGE_COLUMNS = [f"{definition['key']}_status" for definition in case_service._STAGE_DEFINITIONS]
_NAME_TO_KEY = {definition["name"]: definition["key"] for definition in case_service._STAGE_DEFINITIONS}
_CORE_STATUSES = [None, "Complete", "Approved", "Awaiting Approval", "Processing", "Failed", "Blocked"]
_EXTRA_STATUSES = [
    "", "Pending", "Completed", "Complete with Warnings", "complete_with_warnings",
    "Pending Approval", "awaiting_approval", "Running", "Rejected", " Approved ",
    "APPROVED", "blocked", "Unknown",
]


def _assert_stage_sql_matches(combinations: list[tuple]) -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(f"CREATE TABLE incidents (id INTEGER, {', '.join(c + ' TEXT' for c in _STAGE_COLUMNS)})")
    connection.executemany(
        f"INSERT INTO incidents VALUES (?, {', '.join('?' for _ in _STAGE_COLUMNS)})",
        [(index, *combo) for index, combo in enumerate(combinations)],
    )
    sql = dict(connection.execute(f"SELECT id, {case_service._CURRENT_STAGE_SQL} FROM incidents"))
    for index, combo in enumerate(combinations):
        expected = _NAME_TO_KEY[case_service._current_stage_from_row(dict(zip(_STAGE_COLUMNS, combo)))]
        assert sql[index] == expected, (combo, sql[index], expected)


def test_stage_sql_matches_python_for_every_core_status_combination() -> None:
    _assert_stage_sql_matches(list(itertools.product(_CORE_STATUSES, repeat=len(_STAGE_COLUMNS))))


def test_stage_sql_matches_python_for_status_spelling_variants() -> None:
    pool = _CORE_STATUSES + _EXTRA_STATUSES
    rng = random.Random(20260930)
    _assert_stage_sql_matches([tuple(rng.choice(pool) for _ in _STAGE_COLUMNS) for _ in range(4000)])


# ── Frontend ─────────────────────────────────────────────────────────────


def test_ctrl_k_is_removed_everywhere() -> None:
    sources = [FRONTEND / "index.html", *FRONTEND.glob("css/*.css"),
               *(path for path in FRONTEND.rglob("*.js") if "vendor" not in path.parts)]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "Ctrl K" not in text, path
        assert "search-shortcut" not in text, path
        assert "ctrlKey" not in text and "metaKey" not in text, path


def test_topbar_search_placeholder_is_accurate() -> None:
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert 'placeholder="Search cases, e.g. severity:HIGH AND stage:investigation"' in html
    assert "ask Aegis" not in html.split('id="topbar-search-input"')[1].split(">")[0]
    assert 'id="topbar-tools"' in html
    assert "/frontend/css/case-filters.css" in html


_NODE_SCRIPT = r"""
import assert from "node:assert/strict";
const f = await import(process.argv[1]);

// Filter count: one per active group; chips: one per value.
const filters = { ...f.emptyFilters(), severity: ["high", "critical"], stage: ["investigation"], time: "24h" };
assert.equal(f.activeFilterCount(filters), 3);
assert.deepEqual(f.activeChips(filters).map((c) => c.label), ["High", "Critical", "Investigation", "Last 24 hours"]);
assert.equal(f.activeFilterCount({ ...f.emptyFilters(), time: "custom" }), 0);
assert.equal(f.activeFilterCount({ ...f.emptyFilters(), time: "custom", from: "2026-07-01T09:00" }), 1);
assert.equal(f.activeChips({ ...f.emptyFilters(), verdict: ["high"] })[0].label, "Verdict: High");

// Removing a chip removes only that value.
const removed = f.removeChip(filters, "severity", "high");
assert.deepEqual(removed.severity, ["critical"]);
assert.deepEqual(removed.stage, ["investigation"]);
assert.equal(removed.time, "24h");
assert.equal(f.removeChip(filters, "time", "24h").time, "");
assert.equal(f.activeFilterCount(f.removeChip(filters, "time", "24h")), 2);

// Clear all resets filters but keeps search and sort.
const state = { q: "ssh", filters, sort: "oldest" };
const cleared = f.clearFilters(state);
assert.equal(f.activeFilterCount(cleared.filters), 0);
assert.equal(cleared.q, "ssh");
assert.equal(cleared.sort, "oldest");
assert.equal(f.chipsRowHTML(cleared.filters), "");
assert.match(f.chipsRowHTML(filters), /aria-label="Remove Severity filter: High"/);

// Sort state -> API parameters; search + filters + sort travel together.
const api = f.apiParams({ q: "ssh", filters: { ...filters, verdict: ["unrated"] }, sort: "severity-desc" });
assert.equal(api.get("query"), "ssh");
assert.equal(api.get("search"), null);
assert.equal(api.get("severity"), "HIGH,CRITICAL");
assert.equal(api.get("stage"), "investigation");
assert.equal(api.get("verdict"), "unrated");
assert.equal(api.get("time_range"), "24h");
assert.equal(api.get("sort"), "severity");
assert.equal(api.get("direction"), "desc");
assert.equal(api.get("limit"), "200");
const byDefault = f.apiParams({ q: "", filters: f.emptyFilters(), sort: f.DEFAULT_SORT });
assert.deepEqual([byDefault.get("sort"), byDefault.get("direction")], ["created", "desc"]);
for (const [value, sort, direction] of [["oldest", "created", "asc"], ["id-asc", "id", "asc"],
    ["id-desc", "id", "desc"], ["last-seen-desc", "last_seen", "desc"], ["last-seen-asc", "last_seen", "asc"],
    ["severity-asc", "severity", "asc"]]) {
  const p = f.apiParams({ q: "", filters: f.emptyFilters(), sort: value });
  assert.deepEqual([p.get("sort"), p.get("direction")], [sort, direction], value);
}
assert.equal(f.sortLabel("newest"), "Newest");
assert.equal(f.sortLabel("severity-desc"), "Severity: High → Low");
const custom = f.apiParams({ q: "", filters: { ...f.emptyFilters(), time: "custom", from: "2026-07-01T09:00" }, sort: "newest" });
assert.equal(custom.get("time_range"), "custom");
// Custom bounds are UTC wall-clock time, like dates in the query language.
assert.equal(custom.get("updated_from"), "2026-07-01T09:00:00Z");
assert.equal(custom.get("updated_to"), null);

// URL state round-trips and stays readable.
const full = { q: "lateral movement", filters: { ...filters, workflow_status: ["in_progress"], verdict: ["high", "unrated"] }, sort: "last-seen-asc" };
const url = f.overviewURL(full);
assert.equal(url, "/?view=overview&q=lateral%20movement&severity=high,critical&workflow_status=in_progress&stage=investigation&verdict=high,unrated&time=24h&sort=last-seen-asc");
const parsed = f.stateFromParams(new URL(url, "http://aegis.local").searchParams);
assert.deepEqual(parsed, { ...full, filters: { ...full.filters, severity: ["critical", "high"], verdict: ["high", "unrated"] } });
assert.equal(f.overviewURL({ q: "", filters: f.emptyFilters(), sort: "newest" }), "/?view=overview");
const customURL = f.overviewURL({ q: "", filters: { ...f.emptyFilters(), time: "custom", from: "2026-07-01T09:00", to: "2026-07-02T18:30" }, sort: "newest" });
assert.equal(customURL, "/?view=overview&time=custom&from=2026-07-01T09:00&to=2026-07-02T18:30");
assert.deepEqual(f.stateFromParams(new URL(customURL, "http://aegis.local").searchParams).filters.to, "2026-07-02T18:30");
const junk = f.stateFromParams(new URLSearchParams("severity=high,bogus&stage=nope&sort=weird&time=forever"));
assert.deepEqual(junk.filters.severity, ["high"]);
assert.deepEqual(junk.filters.stage, []);
assert.equal(junk.filters.time, "");
assert.equal(junk.sort, "newest");

// Column headers and the Sort menu share one sort value.
assert.equal(f.nextHeaderSort("last_seen", "newest"), "last-seen-desc");
assert.equal(f.nextHeaderSort("last_seen", "last-seen-desc"), "last-seen-asc");
assert.equal(f.nextHeaderSort("last_seen", "last-seen-asc"), "last-seen-desc");
assert.equal(f.nextHeaderSort("severity", "id-asc"), "severity-desc");
assert.equal(f.nextHeaderSort("case", "severity-desc"), "id-desc");
assert.equal(f.sortLabel(f.nextHeaderSort("last_seen", "newest")), "Last Seen: Newest");
assert.equal(f.headerSortDirection("last_seen", "last-seen-asc"), "ascending");
assert.equal(f.headerSortDirection("severity", "severity-desc"), "descending");
assert.equal(f.headerSortDirection("case", "last-seen-desc"), "none");
for (const [column, values] of Object.entries(f.HEADER_SORTS)) {
  for (const value of values) assert.ok(f.SORT_OPTIONS.some((o) => o.value === value), column);
}

// Custom range validation.
assert.equal(f.validateCustomRange({ ...f.emptyFilters(), time: "24h" }), "");
assert.notEqual(f.validateCustomRange({ ...f.emptyFilters(), time: "custom" }), "");
assert.notEqual(f.validateCustomRange({ ...f.emptyFilters(), time: "custom", from: "2026-07-02T00:00", to: "2026-07-01T00:00" }), "");
console.log("ok");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_frontend_filter_state_helpers() -> None:
    module_url = (FRONTEND / "js" / "components" / "caseFilters.js").as_uri()
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _NODE_SCRIPT, module_url],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")


def test_overview_uses_server_side_case_query() -> None:
    overview = (FRONTEND / "js" / "pages" / "overview.js").read_text(encoding="utf-8")
    assert "/api/dashboard" in overview
    assert "/api/cases?" in overview
    assert "RECENT_LIMIT = 200" in overview
    assert "replaceState" in overview
    for column in ('"case"', '"severity"', '"last_seen"'):
        assert f"sortableHeader({column}" in overview
    assert "<th>Status</th><th>Stage</th>" in overview
