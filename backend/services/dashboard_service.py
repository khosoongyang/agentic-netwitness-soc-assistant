"""Read-only dashboard aggregates matching the legacy Aegis overview."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .case_service import _case_list_item, open_readonly_connection


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PIPELINE_DB = PROJECT_ROOT / "soc_db" / "soc_pipeline.db"
_CLOSED_STATUSES = ("CLOSED", "RESOLVED", "REMEDIATED")
_PIPELINE_TABLES = (
    "alerts_to_triage", "post_triage_investigate", "post_triage_no_investigate",
    "post_investigation", "initial_ticket", "pending_ticket_report",
    "finalized_report", "workflow_runs",
)
_STAGE_COLUMNS = (
    ("parsing", "parsing_status"),
    ("triage", "triage_status"),
    ("threat_intel", "threat_intel_status"),
    ("investigation", "investigation_status"),
    ("reporting", "reporting_status"),
)


def _counts(connection: sqlite3.Connection, column: str, where: str = "") -> dict[str, int]:
    rows = connection.execute(
        f"SELECT COALESCE({column}, ''), COUNT(*) FROM incidents {where} "
        f"GROUP BY COALESCE({column}, '')"
    ).fetchall()
    return {str(row[0] or "Unknown"): int(row[1]) for row in rows}


def _pipeline_counts(database_path: str | Path | None) -> dict[str, int]:
    path = Path(database_path or DEFAULT_PIPELINE_DB).resolve()
    if not path.is_file():
        return {table: 0 for table in _PIPELINE_TABLES}
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=15)
    try:
        connection.execute("PRAGMA query_only=ON")
        output: dict[str, int] = {}
        for table in _PIPELINE_TABLES:
            try:
                output[table] = int(connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0])
            except sqlite3.DatabaseError:
                output[table] = 0
        return output
    finally:
        connection.close()


def get_dashboard(
    *,
    database_path: str | Path | None = None,
    pipeline_database_path: str | Path | None = None,
    recent_limit: int = 8,
) -> dict[str, Any]:
    """Return high-level metrics and recent cases as structured JSON."""
    placeholders = ",".join("?" for _ in _CLOSED_STATUSES)
    with closing(open_readonly_connection(database_path)) as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
        active = int(connection.execute(
            f"SELECT COUNT(*) FROM incidents WHERE "
            f"UPPER(COALESCE(status, '')) NOT IN ({placeholders})",
            _CLOSED_STATUSES,
        ).fetchone()[0])
        unassigned_active = int(connection.execute(
            f"SELECT COUNT(*) FROM incidents WHERE "
            "(assignee IS NULL OR assignee='' OR assignee='Unassigned') AND "
            f"UPPER(COALESCE(status, '')) NOT IN ({placeholders})",
            _CLOSED_STATUSES,
        ).fetchone()[0])
        awaiting_approval = int(connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE workflow_status='Awaiting Approval'"
        ).fetchone()[0])
        severity_counts = _counts(connection, "severity")
        active_severity_counts = _counts(
            connection,
            "severity",
            f"WHERE UPPER(COALESCE(status, '')) NOT IN ({','.join(repr(s) for s in _CLOSED_STATUSES)})",
        )
        status_counts = _counts(connection, "status")
        workflow_counts = _counts(connection, "workflow_status")
        stage_status_counts = {
            key: _counts(connection, column) for key, column in _STAGE_COLUMNS
        }
        recent_rows = connection.execute(
            "SELECT id, title, severity, status, assignee, alert_count, created, "
            "updated, first_seen, last_seen, run_id, workflow_status, "
            "approval_stage, workflow_updated_at, parsing_status, triage_status, "
            "threat_intel_status, investigation_status, reporting_status "
            "FROM incidents ORDER BY COALESCE(last_seen, updated, created, '') DESC "
            "LIMIT ?",
            (max(1, min(int(recent_limit), 20)),),
        ).fetchall()
        try:
            fetch_count = int(connection.execute("SELECT COUNT(*) FROM fetch_log").fetchone()[0])
            latest_fetch = connection.execute(
                "SELECT fetched_at FROM fetch_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.DatabaseError:
            fetch_count, latest_fetch = 0, None

    return {
        "summary": {
            "total_cases": total,
            "active_cases": active,
            "critical_active": active_severity_counts.get("CRITICAL", 0),
            "unassigned_active": unassigned_active,
            "awaiting_approval": awaiting_approval,
            "fetch_count": fetch_count,
            "last_fetch": latest_fetch[0] if latest_fetch else None,
        },
        "severity_counts": severity_counts,
        "active_severity_counts": active_severity_counts,
        "status_counts": status_counts,
        "workflow_counts": workflow_counts,
        "stage_status_counts": stage_status_counts,
        "pipeline_counts": _pipeline_counts(pipeline_database_path),
        "recent_cases": [_case_list_item(dict(row)) for row in recent_rows],
    }
