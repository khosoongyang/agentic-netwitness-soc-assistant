"""Read-only dashboard aggregates matching the legacy Aegis overview."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from workflow import state_store as wss

from ..errors import InvalidQueryError
from .case_service import (
    _STAGE_DEFINITIONS,
    _TIME_RANGES,
    _case_list_item,
    build_workflow_stages,
    open_readonly_connection,
)


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
    recent_limit: int = 250,
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
        awaiting_analyst = int(connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE workflow_status='Awaiting Action'"
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
            (max(1, min(int(recent_limit), 250)),),
        ).fetchall()
        try:
            fetch_count = int(connection.execute("SELECT COUNT(*) FROM fetch_log").fetchone()[0])
            latest_fetch = connection.execute(
                "SELECT fetched_at FROM fetch_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.DatabaseError:
            fetch_count, latest_fetch = 0, None

    pipeline_counts = _pipeline_counts(pipeline_database_path)

    return {
        "summary": {
            "total_cases": total,
            "active_cases": active,
            "critical_active": active_severity_counts.get("CRITICAL", 0),
            "unassigned_active": unassigned_active,
            "awaiting_approval": awaiting_approval,
            "under_investigation": pipeline_counts.get("post_triage_investigate", 0),
            "awaiting_analyst": awaiting_analyst,
            "fetch_count": fetch_count,
            "last_fetch": latest_fetch[0] if latest_fetch else None,
        },
        "severity_counts": severity_counts,
        "active_severity_counts": active_severity_counts,
        "status_counts": status_counts,
        "workflow_counts": workflow_counts,
        "stage_status_counts": stage_status_counts,
        "pipeline_counts": pipeline_counts,
        "recent_cases": [_case_list_item(dict(row)) for row in recent_rows],
    }


# ── Operations Overview analytics (/api/dashboard/analytics) ─────────────
#
# Every figure is read from the canonical case database at request time.
# Timestamps are the NetWitness `created` time, stored as naive UTC
# "YYYY-MM-DDTHH:MM:SS" (sometimes with a trailing offset), so all window
# bounds, buckets and hour/day cells are UTC. 7d/30d windows end *now*, the
# same convention as the Recent Cases Time Range filter.

ANALYTICS_RANGES = ("7d", "30d", "all")
_CREATED = "SUBSTR(created, 1, 19)"
_HAS_CREATED = "COALESCE(created, '') != ''"
_ENTERED_WORKFLOW = "TRIM(COALESCE(workflow_status, '')) != ''"
_KNOWN_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
# Detection rule = the NetWitness incident rule name, i.e. the title before
# " for <entity>" ("High Risk Alerts: ESA for 10.0.0.5" -> "High Risk Alerts: ESA").
_RULE_SQL = ("CASE WHEN INSTR(COALESCE(title, ''), ' for ') > 0 "
             "THEN SUBSTR(title, 1, INSTR(title, ' for ') - 1) "
             "ELSE TRIM(COALESCE(title, '')) END")
# MITRE tactic as recorded by the Triage agent (ticket first, metakeys fallback).
_TACTIC_SQL = ("TRIM(COALESCE(json_extract(triage_result_json, '$.ticket.mitre_tactic'), "
               "json_extract(triage_result_json, '$.metakeys_payload.mitre_tactic'), ''))")
_HAS_TRIAGE = "(COALESCE(triage_result_json, '') != '' AND json_valid(triage_result_json))"
_SOURCE_IPS_SQL = ("json_each(CASE WHEN json_valid(raw_json) AND "
                   "json_type(raw_json, '$.alertMeta.SourceIp') = 'array' "
                   "THEN json_extract(raw_json, '$.alertMeta.SourceIp') ELSE '[]' END)")
_TOP_LIMIT = 8
_HEATMAP_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
# Display order of a workflow stage's state in the stacked stage chart; keys
# are the display states build_workflow_stages() produces.
_STAGE_STATE_LABELS = {
    "completed": "Completed",
    "in_progress": "Running",
    "awaiting_approval": "Awaiting approval",
    "not_started": "Pending",
    "failed": "Failed",
    "rejected": "Rejected",
    "locked": "Blocked",
}
_ANALYTICS_CACHE_SECONDS = 60
_analytics_cache: dict[tuple, tuple[float, dict[str, Any]]] = {}
_analytics_cache_lock = threading.Lock()


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def _parse_stamp(value: str | None) -> datetime | None:
    try:
        return datetime.strptime(str(value)[:19], "%Y-%m-%dT%H:%M:%S") if value else None
    except ValueError:
        return None


def _db_signature(database_path: str | Path | None) -> tuple:
    """Changes whenever SQLite writes to the database (main file or WAL)."""
    path = Path(database_path or wss.DB_FILE).resolve()
    signature: list[Any] = [str(path)]
    for candidate in (path, path.with_name(path.name + "-wal")):
        try:
            stat = candidate.stat()
            signature.extend((stat.st_mtime_ns, stat.st_size))
        except OSError:
            signature.extend((None, None))
    return tuple(signature)


def _ranked(rows: list[sqlite3.Row], total: int, limit: int = _TOP_LIMIT) -> dict[str, Any]:
    """(label, count) rows sorted by count -> top N plus the remainder of
    the rest ("other")."""
    items = [{"label": str(row[0]), "count": int(row[1])} for row in rows]
    return {
        "items": items[:limit],
        "other": sum(item["count"] for item in items[limit:]),
        "distinct": len(items),
        "total": total,
    }


def _next_month(value: datetime) -> datetime:
    return (value.replace(day=28) + timedelta(days=4)).replace(day=1)


def _trend_buckets(start: datetime, end: datetime, granularity: str) -> list[dict[str, Any]]:
    """Zero-filled calendar buckets covering [start, end). Each bucket's
    start/end are clipped to the window so they can drive an exact
    `created:>=… AND created:<…` drill-down."""
    if granularity == "day":
        cursor = start.replace(hour=0, minute=0, second=0, microsecond=0)
        step, key_format = (lambda value: value + timedelta(days=1)), "%Y-%m-%d"
    else:
        cursor = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        step, key_format = _next_month, "%Y-%m"
    buckets: list[dict[str, Any]] = []
    while cursor < end:
        following = step(cursor)
        buckets.append({
            "key": cursor.strftime(key_format),
            "start": _stamp(max(cursor, start)),
            "end": _stamp(min(following, end)),
            "partial": cursor < start or following > end,
            "count": 0,
        })
        cursor = following
    return buckets


def _compute_analytics(database_path: str | Path | None, range_key: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
    # Minute-aligned so the window maps exactly onto `created:>=YYYY-MM-DDTHH:MM`.
    window_start = now - _TIME_RANGES[range_key] if range_key != "all" else None
    window_end = now + timedelta(minutes=1)  # exclusive; includes the current minute
    if window_start is None:
        where, params = "1", []
    else:
        where = f"({_HAS_CREATED} AND {_CREATED} >= ? AND {_CREATED} < ?)"
        params = [_stamp(window_start), _stamp(window_end)]

    with closing(open_readonly_connection(database_path)) as connection:
        bounds = connection.execute(
            f"SELECT MIN({_CREATED}), MAX({_CREATED}) FROM incidents WHERE {_HAS_CREATED}"
        ).fetchone()
        total, missing_created = (int(value) for value in connection.execute(
            f"SELECT COUNT(*), COALESCE(SUM(NOT ({_HAS_CREATED})), 0) FROM incidents WHERE {where}",
            params,
        ).fetchone())

        # Severity, grouped on exactly the expression the severity filter
        # matches (case_service._severity_sql), so a drill-down count agrees.
        severity_counts = {str(row[0]): int(row[1]) for row in connection.execute(
            f"SELECT UPPER(COALESCE(severity, '')) AS value, COUNT(*) FROM incidents "
            f"WHERE {where} GROUP BY value", params,
        ).fetchall()}
        severity_items = [
            {"key": key.lower(), "label": key.title(), "count": severity_counts.pop(key, 0),
             "filterable": True}
            for key in _KNOWN_SEVERITIES
        ]
        unknown_severity = severity_counts.pop("", 0)
        # Any other stored spelling is shown as-is, never folded into a known level.
        severity_items.extend(
            {"key": key.lower(), "label": key.title(), "count": count, "filterable": False}
            for key, count in sorted(severity_counts.items(), key=lambda item: -item[1])
        )
        if unknown_severity:
            severity_items.append({"key": "unknown", "label": "Unknown",
                                   "count": unknown_severity, "filterable": False})

        # Workflow stages: only incidents that have entered the workflow. The
        # current stage and its state come from build_workflow_stages(), the
        # logic behind the case view and the Stage filter (_CURRENT_STAGE_SQL).
        stage_columns = ", ".join(f"{definition['key']}_status" for definition in _STAGE_DEFINITIONS)
        stage_rows = connection.execute(
            f"SELECT {stage_columns} FROM incidents WHERE {where} AND {_ENTERED_WORKFLOW}", params,
        ).fetchall()
        stage_items = {
            str(definition["key"]): {
                "key": str(definition["key"]), "label": str(definition["name"]), "count": 0,
                "states": {state: 0 for state in _STAGE_STATE_LABELS},
            }
            for definition in _STAGE_DEFINITIONS
        }
        for row in stage_rows:
            stages = build_workflow_stages(dict(row))
            current = next(
                (stage for stage in stages if not stage["completed"] and not stage["locked"]),
                stages[-1],
            )
            stage_items[current["key"]]["count"] += 1
            stage_items[current["key"]]["states"][current["state"]] += 1

        # Newly created incidents over time: months for all time, else days.
        if window_start is None:
            granularity = "month"
            first, last = _parse_stamp(bounds[0]), _parse_stamp(bounds[1])
            month = lambda value: value.replace(day=1, hour=0, minute=0, second=0)
            buckets = (_trend_buckets(month(first), _next_month(month(last)), "month")
                       if first and last else [])
            bucket_sql = f"SUBSTR({_CREATED}, 1, 7)"
        else:
            granularity = "day"
            buckets = _trend_buckets(window_start, window_end, "day")
            bucket_sql = f"SUBSTR({_CREATED}, 1, 10)"
        trend_counts = {str(row[0]): int(row[1]) for row in connection.execute(
            f"SELECT {bucket_sql} AS bucket, COUNT(*) FROM incidents "
            f"WHERE {where} AND {_HAS_CREATED} GROUP BY bucket", params,
        ).fetchall()}
        for bucket in buckets:
            bucket["count"] = trend_counts.get(bucket["key"], 0)

        # Detection rules cover every incident; MITRE tactics only triaged ones.
        rule_rows = connection.execute(
            f"SELECT CASE WHEN ({_RULE_SQL}) = '' THEN 'Untitled' ELSE ({_RULE_SQL}) END AS rule, "
            f"COUNT(*) AS n FROM incidents WHERE {where} GROUP BY rule ORDER BY n DESC, rule",
            params,
        ).fetchall()
        tactic_rows = connection.execute(
            f"SELECT CASE WHEN ({_TACTIC_SQL}) IN ('', 'Unknown') THEN 'Not determined' "
            f"ELSE ({_TACTIC_SQL}) END AS tactic, COUNT(*) AS n FROM incidents "
            f"WHERE {where} AND {_HAS_TRIAGE} GROUP BY tactic ORDER BY n DESC, tactic",
            params,
        ).fetchall()
        triaged = sum(int(row[1]) for row in tactic_rows)

        # Source IPs: distinct incidents per alertMeta.SourceIp value.
        ip_rows = connection.execute(
            f"SELECT TRIM(ip.value) AS address, COUNT(DISTINCT incidents.id) AS n "
            f"FROM incidents, {_SOURCE_IPS_SQL} AS ip "
            f"WHERE {where} AND TRIM(COALESCE(ip.value, '')) != '' "
            f"GROUP BY address ORDER BY n DESC, address",
            params,
        ).fetchall()
        with_ip = int(connection.execute(
            f"SELECT COUNT(*) FROM incidents WHERE {where} AND EXISTS ("
            f"SELECT 1 FROM {_SOURCE_IPS_SQL} AS ip WHERE TRIM(COALESCE(ip.value, '')) != '')",
            params,
        ).fetchone()[0])

        # Day-of-week x hour-of-day, UTC. strftime %w: 0 = Sunday -> row 6.
        cells = [[0] * 24 for _ in _HEATMAP_DAYS]
        for weekday, hour, count in connection.execute(
            f"SELECT CAST(strftime('%w', {_CREATED}) AS INTEGER) AS d, "
            f"CAST(strftime('%H', {_CREATED}) AS INTEGER) AS h, COUNT(*) FROM incidents "
            f"WHERE {where} AND {_HAS_CREATED} AND strftime('%w', {_CREATED}) IS NOT NULL "
            f"GROUP BY d, h", params,
        ).fetchall():
            cells[(int(weekday) + 6) % 7][int(hour)] = int(count)

    entered = len(stage_rows)
    heat_total = sum(map(sum, cells))
    trend_total = sum(bucket["count"] for bucket in buckets)
    return {
        "range": range_key,
        "timezone": "UTC",
        "generated_at": _stamp(now) + "Z",
        "window": {
            "start": _stamp(window_start) if window_start else None,
            "end": _stamp(window_end),
        },
        "data_bounds": {"earliest_created": bounds[0], "latest_created": bounds[1]},
        "total": total,
        "missing_created": missing_created,
        "severity": {"items": severity_items, "total": total},
        "stages": {
            "entered": entered,
            "unprocessed": total - entered,
            "items": list(stage_items.values()),
            "state_labels": _STAGE_STATE_LABELS,
        },
        "trend": {
            "granularity": granularity,
            "buckets": buckets,
            "total": trend_total,
            "excluded": total - trend_total,
        },
        "detection_rules": _ranked(rule_rows, total),
        "mitre_tactics": {**_ranked(tactic_rows, triaged), "triaged": triaged},
        "source_ips": {**_ranked(ip_rows, with_ip), "with_ip": with_ip,
                       "without_ip": total - with_ip},
        "heatmap": {
            "days": list(_HEATMAP_DAYS),
            "cells": cells,
            "max": max(map(max, cells)),
            "total": heat_total,
            "excluded": total - heat_total,
        },
    }


def get_dashboard_analytics(
    *,
    range_key: str = "all",
    database_path: str | Path | None = None,
) -> dict[str, Any]:
    """Chart aggregates for the Operations Overview over one time range.

    Cached briefly per (database state, range): any write to the database
    or its WAL changes the key, so a new incident is never hidden, and the
    TTL bounds how far a cached 7d/30d window can drift from "now"."""
    range_key = str(range_key or "all").strip().lower()
    if range_key not in ANALYTICS_RANGES:
        raise InvalidQueryError("range must be one of: 7d, 30d, all.", {"param": "range"})
    signature = _db_signature(database_path)
    key = (signature, range_key)
    with _analytics_cache_lock:
        cached = _analytics_cache.get(key)
        if cached and time.monotonic() - cached[0] < _ANALYTICS_CACHE_SECONDS:
            return cached[1]
    result = _compute_analytics(database_path, range_key)
    with _analytics_cache_lock:
        # Entries for an older database state can never be hit again.
        for stale in [entry for entry in _analytics_cache if entry[0] != signature]:
            del _analytics_cache[stale]
        _analytics_cache[key] = (time.monotonic(), result)
    return result
