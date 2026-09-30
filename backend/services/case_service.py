"""Read-only case and workflow queries over Aegis's canonical state."""

from __future__ import annotations

import json
import csv
import io
import math
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from workflow import state_store as wss

from ..errors import (
    CaseNotFoundError,
    DataStoreUnavailableError,
    InvalidQueryError,
    StageResultNotAvailableError,
)


_CASE_COLUMNS = (
    "id", "title", "severity", "status", "assignee", "alert_count",
    "created", "updated", "first_seen", "last_seen", "run_id",
    "workflow_status", "approval_stage", "workflow_updated_at",
    "parsing_status", "parsing_result_json", "triage_status",
    "triage_result_json", "threat_intel_status", "threat_intel_result_json",
    "threat_intel_updated_at", "investigation_status",
    "investigation_result_json", "investigation_updated_at",
    "reporting_status", "reporting_result_json", "reporting_updated_at",
    "approved_by", "approved_at", "approval_comments", "last_error",
    "worker_id", "worker_stage", "worker_started_at", "worker_heartbeat_at",
    "worker_lease_expires_at", "worker_progress_note", "investigation_attempt",
    "threat_intel_attempt", "reporting_attempt", "raw_json",
)
_LIST_COLUMNS = tuple(column for column in _CASE_COLUMNS if not column.endswith("_json"))
# Numeric part of an incident ID ("INC-9999" -> 9999) so INC-9999 sorts
# before INC-53027 instead of after it as plain text would.
_NUMERIC_ID = "CAST(SUBSTR(id, INSTR(id, '-') + 1) AS INTEGER)"
_SORT_COLUMNS = {
    "updated": "COALESCE(updated, last_seen, created, '')",
    "created": "COALESCE(created, first_seen, '')",
    # Aegis sync time, not incident activity: many cases share one value.
    "last_seen": "COALESCE(last_seen, '')",
    "severity": "CASE UPPER(COALESCE(severity, '')) "
                "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",
    "status": "UPPER(COALESCE(status, ''))",
    "title": "LOWER(COALESCE(title, ''))",
    "id": _NUMERIC_ID,
}
_TIME_SORTS = {"updated", "created", "last_seen"}
# Operations Overview "Workflow Status" filter: analyst-facing key ->
# incidents.workflow_status as written by the workflow engine. None means
# the case has never entered the workflow (NULL/empty column).
_WORKFLOW_STATUS_FILTERS = {
    "not_started": None,
    "in_progress": "Processing",
    "awaiting_action": "Awaiting Action",
    "awaiting_approval": "Awaiting Approval",
    "rejected": "Rejected",
    "failed": "Failed",
    "complete": "Complete",
}
_VERDICT_FILTERS = ("critical", "high", "medium", "low", "unrated")
# Time Range filters on the NetWitness `updated` timestamp (the incident's
# own lastUpdated, stored as UTC without the trailing "Z") -- deliberately
# NOT last_seen, which is only when Aegis last synced the case.
_TIME_RANGES = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
# Stage-status spellings _semantic_stage_state() recognises besides each
# stage's own "complete" set; shared with the SQL mirror in _current_stage_sql().
_AWAITING_APPROVAL_STATES = ("awaiting approval", "pending approval")
_IN_PROGRESS_STATES = ("processing", "running")
_OTHER_KNOWN_STATES = (*_AWAITING_APPROVAL_STATES, *_IN_PROGRESS_STATES,
                       "failed", "rejected", "blocked")
_STAGE_DEFINITIONS = (
    {
        "key": "parsing", "name": "Parsing & Normalisation",
        "complete": {"complete", "completed"}, "attempt": None,
        "updated": "workflow_updated_at",
    },
    {
        "key": "triage", "name": "Triage",
        "complete": {"approved"}, "attempt": None,
        "updated": "workflow_updated_at",
    },
    {
        "key": "threat_intel", "name": "Threat Intelligence Enrichment",
        "complete": {"complete", "completed", "complete with warnings", "approved"},
        "attempt": "threat_intel_attempt", "updated": "threat_intel_updated_at",
    },
    {
        "key": "investigation", "name": "Investigation",
        "complete": {"approved"}, "attempt": "investigation_attempt",
        "updated": "investigation_updated_at",
    },
    {
        "key": "reporting", "name": "Reporting",
        "complete": {"approved"}, "attempt": "reporting_attempt",
        "updated": "reporting_updated_at",
    },
)


def open_readonly_connection(database_path: str | Path | None = None) -> sqlite3.Connection:
    """Open the canonical case database without permitting writes."""
    path = Path(database_path or wss.DB_FILE).resolve()
    if not path.is_file():
        raise DataStoreUnavailableError()
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _json_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _split_values(value: Any) -> list[str]:
    """Comma-separated (or list) query value -> distinct non-empty values.
    "ALL" is the legacy single-select "no filter" sentinel and is dropped."""
    raw = value if isinstance(value, (list, tuple)) else str(value or "").split(",")
    values: list[str] = []
    for item in raw:
        item = str(item or "").strip()
        if item and item.upper() != "ALL" and item not in values:
            values.append(item)
    return values


def _allowed_values(value: Any, allowed: Any, name: str) -> list[str]:
    values = [item.lower() for item in _split_values(value)]
    unknown = [item for item in values if item not in allowed]
    if unknown:
        raise InvalidQueryError(f"Unsupported {name} value: {unknown[0]}.")
    return values


def _utc_bound(value: Any, name: str) -> str | None:
    """ISO 8601 bound -> naive UTC "YYYY-MM-DDTHH:MM:SS", matching how the
    NetWitness `updated` timestamp is stored. Naive input is taken as UTC."""
    value = str(value or "").strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidQueryError(f"{name} must be an ISO 8601 date/time.") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S")


def _sql_text_list(values: Any) -> str:
    return ", ".join("'" + str(value).replace("'", "''") + "'" for value in values)


def _current_stage_sql() -> str:
    """SQL mirror of _current_stage_from_row(), yielding the stage *key*.

    Generated from _STAGE_DEFINITIONS and the same state spellings
    _semantic_stage_state() uses, so filtering 50k+ rows by current stage
    stays in SQLite. tests/test_overview_case_filters.py proves it agrees
    with the Python implementation across every status combination."""
    whens: list[str] = []
    prior_complete: list[str] = []
    for definition in _STAGE_DEFINITIONS:
        key = str(definition["key"])
        status = f"LOWER(REPLACE(TRIM(COALESCE({key}_status, '')), '_', ' '))"
        complete = f"{status} IN ({_sql_text_list(sorted(definition['complete']))})"
        known = sorted(set(definition["complete"]) | set(_OTHER_KNOWN_STATES))
        not_started = f"{status} NOT IN ({_sql_text_list(known)})"
        prior = " AND ".join(prior_complete) or "1"
        locked = f"({status} = 'blocked' OR (NOT ({prior}) AND {not_started}))"
        whens.append(f"WHEN NOT ({complete}) AND NOT {locked} THEN '{key}'")
        prior_complete.append(f"({complete})")
    return f"CASE {' '.join(whens)} ELSE '{_STAGE_DEFINITIONS[-1]['key']}' END"


_CURRENT_STAGE_SQL = _current_stage_sql()
_STAGE_KEYS = tuple(str(definition["key"]) for definition in _STAGE_DEFINITIONS)


def _in_clause(expression: str, values: list[str]) -> str:
    return f"{expression} IN ({', '.join('?' for _ in values)})"


def _filter_clauses(
    *,
    search: str,
    severities: list[str],
    statuses: list[str],
    workflow_statuses: list[str] = (),
    stages: list[str] = (),
    updated_from: str | None = None,
    updated_to: str | None = None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if severities:
        clauses.append(_in_clause("UPPER(COALESCE(severity, ''))", severities))
        params.extend(value.upper() for value in severities)
    if statuses:
        clauses.append(_in_clause("UPPER(COALESCE(status, ''))", statuses))
        params.extend(value.upper() for value in statuses)
    if workflow_statuses:
        options: list[str] = []
        stored = [_WORKFLOW_STATUS_FILTERS[key] for key in workflow_statuses]
        if None in stored:
            options.append("TRIM(COALESCE(workflow_status, '')) = ''")
        stored = [value for value in stored if value is not None]
        if stored:
            options.append(_in_clause("workflow_status", stored))
            params.extend(stored)
        clauses.append("(" + " OR ".join(options) + ")")
    if stages:
        clauses.append(_in_clause(f"({_CURRENT_STAGE_SQL})", stages))
        params.extend(stages)
    if updated_from or updated_to:
        clauses.append("COALESCE(updated, '') != ''")
    if updated_from:
        clauses.append("SUBSTR(updated, 1, 19) >= ?")
        params.append(updated_from)
    if updated_to:
        clauses.append("SUBSTR(updated, 1, 19) <= ?")
        params.append(updated_to)
    if search:
        clauses.append(
            "(title LIKE ? COLLATE NOCASE OR assignee LIKE ? COLLATE NOCASE "
            "OR id LIKE ? COLLATE NOCASE)"
        )
        pattern = f"%{search}%"
        params.extend((pattern, pattern, pattern))
    return clauses, params


def _where(clauses: list[str]) -> str:
    return " WHERE " + " AND ".join(clauses) if clauses else ""


def _verdict_clause(
    connection: sqlite3.Connection,
    clauses: list[str],
    params: list[Any],
    verdicts: list[str],
    resolver: Callable[[dict[str, Any]], str],
) -> tuple[str, list[Any]]:
    """Unified Verdict is not a stored column: it is aggregate_verdict()'s
    output, which only exists for cases with a workflow run. Resolve it at
    query time for just the run cases that already pass every other
    filter; every case without a run is Unrated by definition."""
    has_run = "COALESCE(run_id, '') != ''"
    rows = connection.execute(
        f"SELECT * FROM incidents{_where([*clauses, has_run])}", params
    ).fetchall()
    matched = [
        row["id"] for row in rows
        if str(resolver(dict(row)) or "UNRATED").lower() in verdicts
    ]
    clause = "id IN (SELECT value FROM json_each(?))"
    if "unrated" in verdicts:
        clause = f"({clause} OR COALESCE(run_id, '') = '')"
    return clause, [json.dumps(matched)]


def _order_clause(sort: str, direction: str) -> str:
    expression, direction = _SORT_COLUMNS[sort], direction.upper()
    if sort == "id":
        return f"{expression} {direction}, id {direction}"
    if sort in _TIME_SORTS:
        # Missing timestamps last either way; ties (e.g. the thousands of
        # cases sharing one last_seen sync time) fall back to incident number.
        return (f"({expression} = '') ASC, {expression} {direction}, "
                f"{_NUMERIC_ID} {direction}, id ASC")
    return f"{expression} {direction}, COALESCE(created, '') DESC, {_NUMERIC_ID} DESC, id ASC"


def _current_stage_from_row(row: dict[str, Any]) -> str:
    stages = build_workflow_stages(row)
    current = next(
        (stage for stage in stages if not stage["completed"] and not stage["locked"]),
        stages[-1],
    )
    return str(current["name"])


def _case_list_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "title": row.get("title") or "Untitled case",
        "severity": row.get("severity") or "Unknown",
        "status": row.get("status") or "Unknown",
        "assignee": row.get("assignee") or "Unassigned",
        "alert_count": int(row.get("alert_count") or 0),
        "created": row.get("created"),
        "updated": row.get("updated"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "run_id": row.get("run_id"),
        "workflow_status": row.get("workflow_status") or "Not started",
        "approval_stage": row.get("approval_stage"),
        "current_stage": _current_stage_from_row(row),
    }


def list_cases(
    *,
    search: str = "",
    severity: str = "",
    status: str = "",
    page: int = 1,
    limit: int = 50,
    sort: str = "updated",
    direction: str = "desc",
    workflow_status: str = "",
    stage: str = "",
    verdict: str = "",
    time_range: str = "",
    updated_from: str = "",
    updated_to: str = "",
    database_path: str | Path | None = None,
    verdict_resolver: Callable[[dict[str, Any]], str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a filtered, sorted page matching the legacy case archive.

    Every filter is optional and they combine with AND; multi-value filters
    take comma-separated values combined with OR (severity=HIGH,CRITICAL).
    The legacy single-value severity/status/"ALL" parameters are unchanged.
    """
    if page < 1:
        raise InvalidQueryError("page must be at least 1.")
    if limit < 1 or limit > 200:
        raise InvalidQueryError("limit must be between 1 and 200.")
    if sort not in _SORT_COLUMNS:
        raise InvalidQueryError(f"Unsupported sort field: {sort}.")
    direction = direction.lower()
    if direction not in {"asc", "desc"}:
        raise InvalidQueryError("direction must be asc or desc.")

    search = str(search or "").strip()
    severities = _split_values(severity)
    statuses = _split_values(status)
    workflow_statuses = _allowed_values(workflow_status, _WORKFLOW_STATUS_FILTERS, "workflow_status")
    stages = _allowed_values(stage, _STAGE_KEYS, "stage")
    verdicts = _allowed_values(verdict, _VERDICT_FILTERS, "verdict")
    time_range = str(time_range or "").strip().lower()
    if time_range in {"", "all"}:
        time_range = ""
    elif time_range != "custom" and time_range not in _TIME_RANGES:
        raise InvalidQueryError(f"Unsupported time_range value: {time_range}.")
    lower_bound = _utc_bound(updated_from, "updated_from")
    upper_bound = _utc_bound(updated_to, "updated_to")
    if time_range in _TIME_RANGES:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is not None:
            current = current.astimezone(timezone.utc).replace(tzinfo=None)
        relative = (current - _TIME_RANGES[time_range]).strftime("%Y-%m-%dT%H:%M:%S")
        lower_bound = max(lower_bound or relative, relative)
    if lower_bound and upper_bound and lower_bound > upper_bound:
        raise InvalidQueryError("updated_from must not be later than updated_to.")

    clauses, params = _filter_clauses(
        search=search, severities=severities, statuses=statuses,
        workflow_statuses=workflow_statuses, stages=stages,
        updated_from=lower_bound, updated_to=upper_bound,
    )
    offset = (page - 1) * limit

    with closing(open_readonly_connection(database_path)) as connection:
        if verdicts:
            if verdict_resolver is None:
                from .case_view_service import unified_verdict_level
                verdict_resolver = unified_verdict_level
            clause, clause_params = _verdict_clause(
                connection, clauses, params, verdicts, verdict_resolver)
            clauses, params = [*clauses, clause], [*params, *clause_params]
        where = _where(clauses)
        total = int(connection.execute(
            f"SELECT COUNT(*) FROM incidents{where}", params
        ).fetchone()[0])
        rows = connection.execute(
            f"SELECT {', '.join(_LIST_COLUMNS)} FROM incidents{where} "
            f"ORDER BY {_order_clause(sort, direction)} "
            "LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        severity_facets = [row[0] for row in connection.execute(
            "SELECT DISTINCT severity FROM incidents "
            "WHERE severity IS NOT NULL AND severity != '' ORDER BY severity"
        ).fetchall()]
        status_facets = [row[0] for row in connection.execute(
            "SELECT DISTINCT status FROM incidents "
            "WHERE status IS NOT NULL AND status != '' ORDER BY status"
        ).fetchall()]

    return {
        "items": [_case_list_item(dict(row)) for row in rows],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": math.ceil(total / limit) if total else 0,
        },
        "filters": {
            "search": search,
            "severity": ",".join(severities) or "ALL",
            "status": ",".join(statuses) or "ALL",
            "sort": sort,
            "direction": direction,
            "workflow_status": workflow_statuses,
            "stage": stages,
            "verdict": verdicts,
            "time_range": time_range or "all",
            "updated_from": lower_bound,
            "updated_to": upper_bound,
        },
        "facets": {"severities": severity_facets, "statuses": status_facets},
    }


def _get_case_row(case_id: str, database_path: str | Path | None = None) -> dict[str, Any]:
    with closing(open_readonly_connection(database_path)) as connection:
        row = connection.execute(
            f"SELECT {', '.join(_CASE_COLUMNS)} FROM incidents WHERE id=?",
            (str(case_id),),
        ).fetchone()
    if row is None:
        raise CaseNotFoundError()
    return dict(row)


def _case_context(row: dict[str, Any]) -> dict[str, Any]:
    raw = _json_object(row.get("raw_json"))
    alert_meta = raw.get("alertMeta") if isinstance(raw.get("alertMeta"), dict) else {}
    return {
        "summary": raw.get("summary") or raw.get("description"),
        "risk_score": raw.get("riskScore") or raw.get("risk_score"),
        "alert_titles": list(alert_meta.get("AlertTitles") or [])[:20],
        "hosts": list(alert_meta.get("Hostname") or [])[:20],
        "source_ips": list(alert_meta.get("SourceIp") or [])[:20],
        "destination_ips": list(alert_meta.get("DestinationIp") or [])[:20],
        "users": list(alert_meta.get("User") or alert_meta.get("Username") or [])[:20],
    }


def get_case_detail(
    case_id: str,
    *,
    database_path: str | Path | None = None,
    case_view_builder: Callable[[str, str | None], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return basic identity plus the existing read-only case-view model."""
    row = _get_case_row(case_id, database_path)
    workspace: dict[str, Any] | None = None
    if row.get("run_id"):
        if case_view_builder is None:
            from .case_view_service import build_case_view
            case_view_builder = build_case_view
        workspace = case_view_builder(str(case_id), row.get("run_id"))
        # build_output() deliberately returns the RAW, unsanitized
        # investigation_result_json (see its own docstring) and expects the
        # caller to sanitize before display -- GET /api/cases/<id>/workflow
        # already does this for the per-stage view via _safe_stage_result()'s
        # investigation special-case below; this is the same sanitization
        # applied at the full case-detail boundary so the two endpoints never
        # disagree on whether secrets/oversized fields reach the browser.
        output = workspace.get("output") if isinstance(workspace, dict) else None
        if isinstance(output, dict) and isinstance(output.get("investigation_result"), dict):
            from .case_view_service import sanitize_investigation_result_for_display
            output["investigation_result"] = sanitize_investigation_result_for_display(
                output["investigation_result"])
    return {
        "case": {**_case_list_item(row), "context": _case_context(row)},
        "workspace": workspace,
        "workflow_available": bool(row.get("run_id") or row.get("workflow_status")),
    }


def get_case_raw(case_id: str, *, database_path: str | Path | None = None) -> dict[str, Any]:
    row = _get_case_row(case_id, database_path)
    return {"case_id": case_id, "incident": _json_object(row.get("raw_json"))}


def get_parsing_result_download(
    case_id: str, *, database_path: str | Path | None = None
) -> tuple[bytes, str]:
    """Return the persisted Parsing & Normalisation result as a downloadable
    JSON file — the complete normalised_alert exactly as stored in
    parsing_result_json, not a frontend reconstruction.

    The normalised_alert is deliberately NOT passed through
    _safe_stage_result(): that is an on-screen display sanitiser whose
    key-name heuristics misfire on the parser's own schema (e.g.
    parser_metadata.extraction_summary.key_fields_found and
    raw_meta_key_count tokenise to "key" and come back "«redacted»") and
    whose 4,000-char truncation would cut long command lines. Legacy
    records with no normalised_alert still fall back to the sanitised
    wrapper, which carries local output_files paths."""
    row = _get_case_row(case_id, database_path)
    stored = _json_object(row.get("parsing_result_json"))
    normalised_alert = stored.get("normalised_alert")
    if isinstance(normalised_alert, dict) and normalised_alert:
        payload = normalised_alert
    else:
        payload = _safe_stage_result("parsing", row.get("parsing_result_json"))
        if not payload:
            raise StageResultNotAvailableError()
    data = json.dumps(payload, indent=2, default=str).encode("utf-8")
    return data, f"{case_id}_normalised_alert.json"


def export_cases_csv(*, database_path: str | Path | None = None) -> tuple[bytes, str]:
    with closing(open_readonly_connection(database_path)) as connection:
        rows = connection.execute(
            "SELECT id,title,severity,status,assignee,alert_count,created,updated,first_seen,last_seen "
            "FROM incidents ORDER BY COALESCE(last_seen,updated,created,'') DESC"
        ).fetchall()
    stream = io.StringIO()
    columns = ["id", "title", "severity", "status", "assignee", "alert_count", "created", "updated", "first_seen", "last_seen"]
    writer = csv.DictWriter(stream, fieldnames=columns)
    writer.writeheader()
    writer.writerows(dict(row) for row in rows)
    return stream.getvalue().encode("utf-8"), "soc_incidents.csv"


def _semantic_stage_state(stage: dict[str, Any], raw_status: str) -> str:
    normalised = raw_status.strip().lower().replace("_", " ")
    if normalised in stage["complete"]:
        return "completed"
    if normalised in _AWAITING_APPROVAL_STATES:
        return "awaiting_approval"
    if normalised in _IN_PROGRESS_STATES:
        return "in_progress"
    if normalised == "failed":
        return "failed"
    if normalised == "rejected":
        return "rejected"
    if normalised == "blocked":
        return "locked"
    return "not_started"


def _status_text(state: str, raw_status: str) -> str:
    labels = {
        "completed": "Completed",
        "in_progress": "In progress",
        "awaiting_approval": "Awaiting approval",
        "locked": "Locked",
        "failed": "Failed",
        "rejected": "Rejected",
        "not_started": "Not started",
    }
    return raw_status or labels[state]


def _safe_stage_result(stage_key: str, raw: Any) -> dict[str, Any] | None:
    result = _json_object(raw)
    if not result:
        return None
    from .case_view_service import _sanitize_for_display, sanitize_investigation_result_for_display
    if stage_key == "investigation":
        return sanitize_investigation_result_for_display(result)
    sanitized = _sanitize_for_display(result)
    return sanitized if isinstance(sanitized, dict) else None


def build_workflow_stages(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a read-only presentation of the persisted canonical stage state."""
    stages: list[dict[str, Any]] = []
    prior_complete = True
    for definition in _STAGE_DEFINITIONS:
        key = str(definition["key"])
        raw_status = str(state.get(f"{key}_status") or "").strip()
        semantic_state = _semantic_stage_state(definition, raw_status)
        locked = semantic_state == "locked" or (
            not prior_complete and semantic_state == "not_started"
        )
        display_state = "locked" if locked else semantic_state
        attempt_column = definition["attempt"]
        attempt = int(state.get(attempt_column) or 1) if attempt_column else None
        stages.append({
            "key": key,
            "name": definition["name"],
            "status": raw_status or "Pending",
            "state": display_state,
            "status_text": _status_text(display_state, "" if locked else raw_status),
            "locked": locked,
            "unlocked": not locked,
            "completed": semantic_state == "completed",
            "requires_approval": semantic_state == "awaiting_approval",
            "attempt": attempt,
            "updated_at": state.get(definition["updated"]),
            "result": _safe_stage_result(key, state.get(f"{key}_result_json")),
        })
        prior_complete = prior_complete and semantic_state == "completed"
    return stages


def get_case_workflow(
    case_id: str,
    *,
    database_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return the five-stage read-only workflow view for one case."""
    state = _get_case_row(case_id, database_path)
    stages = build_workflow_stages(state)
    from workflow.commands import available_actions

    action_state = available_actions(state)
    for stage in stages:
        stage["actions"] = action_state["stages"].get(stage["key"], [])
    current = next(
        (stage for stage in stages if not stage["completed"] and not stage["locked"]),
        stages[-1],
    )
    return {
        "case_id": str(case_id),
        "run_id": state.get("run_id"),
        "available": bool(state.get("run_id") or state.get("workflow_status")),
        "workflow_status": state.get("workflow_status") or "Not started",
        "approval_stage": state.get("approval_stage"),
        "approved_by": state.get("approved_by"),
        "approved_at": state.get("approved_at"),
        "approval_comments": state.get("approval_comments"),
        "current_stage": current["name"],
        "updated_at": state.get("workflow_updated_at"),
        "last_error": state.get("last_error"),
        "progress_note": state.get("worker_progress_note"),
        "evidence_gap": action_state["evidence_gap"],
        "stages": stages,
    }
