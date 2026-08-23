"""Read-only case and workflow queries over Aegis's canonical state."""

from __future__ import annotations

import json
import csv
import io
import math
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Callable

import workflow_state_store as wss

from ..errors import CaseNotFoundError, DataStoreUnavailableError, InvalidQueryError


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
_SORT_COLUMNS = {
    "updated": "COALESCE(updated, last_seen, created, '')",
    "created": "COALESCE(created, first_seen, '')",
    "severity": "CASE UPPER(COALESCE(severity, '')) "
                "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",
    "status": "UPPER(COALESCE(status, ''))",
    "title": "LOWER(COALESCE(title, ''))",
    "id": "LOWER(id)",
}
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


def _normalise_filter(value: str | None) -> str:
    value = str(value or "").strip()
    return "" if value.upper() == "ALL" else value


def _where_clause(*, search: str, severity: str, status: str) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if severity:
        clauses.append("UPPER(COALESCE(severity, '')) = UPPER(?)")
        params.append(severity)
    if status:
        clauses.append("UPPER(COALESCE(status, '')) = UPPER(?)")
        params.append(status)
    if search:
        clauses.append(
            "(title LIKE ? COLLATE NOCASE OR assignee LIKE ? COLLATE NOCASE "
            "OR id LIKE ? COLLATE NOCASE)"
        )
        pattern = f"%{search}%"
        params.extend((pattern, pattern, pattern))
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


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
    database_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return a filtered, sorted page matching the legacy case archive."""
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
    severity = _normalise_filter(severity)
    status = _normalise_filter(status)
    where, params = _where_clause(search=search, severity=severity, status=status)
    offset = (page - 1) * limit

    with closing(open_readonly_connection(database_path)) as connection:
        total = int(connection.execute(
            f"SELECT COUNT(*) FROM incidents{where}", params
        ).fetchone()[0])
        rows = connection.execute(
            f"SELECT {', '.join(_LIST_COLUMNS)} FROM incidents{where} "
            f"ORDER BY {_SORT_COLUMNS[sort]} {direction.upper()}, id ASC "
            "LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        severities = [row[0] for row in connection.execute(
            "SELECT DISTINCT severity FROM incidents "
            "WHERE severity IS NOT NULL AND severity != '' ORDER BY severity"
        ).fetchall()]
        statuses = [row[0] for row in connection.execute(
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
            "severity": severity or "ALL",
            "status": status or "ALL",
            "sort": sort,
            "direction": direction,
        },
        "facets": {"severities": severities, "statuses": statuses},
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
            from case_view import build_case_view
            case_view_builder = build_case_view
        workspace = case_view_builder(str(case_id), row.get("run_id"))
    return {
        "case": {**_case_list_item(row), "context": _case_context(row)},
        "workspace": workspace,
        "workflow_available": bool(row.get("run_id") or row.get("workflow_status")),
    }


def get_case_raw(case_id: str, *, database_path: str | Path | None = None) -> dict[str, Any]:
    row = _get_case_row(case_id, database_path)
    return {"case_id": case_id, "incident": _json_object(row.get("raw_json"))}


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
    if normalised in {"awaiting approval", "pending approval"}:
        return "awaiting_approval"
    if normalised in {"processing", "running"}:
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
    from case_view import _sanitize_for_display, sanitize_investigation_result_for_display
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
