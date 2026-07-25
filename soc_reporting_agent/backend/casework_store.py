from __future__ import annotations

"""Legacy SQLite casework store.

Do not use this module in normal Aegis runtime. PostgreSQL is the operational
SOC database via backend.store_factory/get_casework_store. This module remains
only as a legacy reference for tests and one-time migration from old demo data.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.parser_context_guard import extract_alert_identity


WORKFLOW_STAGES = [
    "parsing_normalisation",
    "triage",
    "incident_grouping_review",
    "threat_intelligence",
    "triage_approval",
    "investigation",
    "investigation_evidence_decision",
    "investigation_approval",
    "reporting",
    "soc_analyst_review",
    "case_closure",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _norm_status(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _first(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


def _severity_from_score(score: Any) -> str:
    try:
        val = float(score)
    except Exception:
        return str(score or "Medium").title()
    if val >= 90:
        return "Critical"
    if val >= 70:
        return "High"
    if val >= 40:
        return "Medium"
    return "Low"


def normalise_alert(raw: dict[str, Any]) -> dict[str, Any]:
    raw = raw or {}
    identity = extract_alert_identity(raw)

    incident = raw.get("incident") if isinstance(raw.get("incident"), dict) else {}
    alerts = raw.get("alerts") if isinstance(raw.get("alerts"), list) else []
    primary = next((a for a in alerts if isinstance(a, dict)), None) or (raw.get("alert") if isinstance(raw.get("alert"), dict) else {}) or raw
    headers = primary.get("originalHeaders") if isinstance(primary.get("originalHeaders"), dict) else {}
    original = primary.get("originalAlert") if isinstance(primary.get("originalAlert"), dict) else {}
    meta = incident.get("alertMeta") if isinstance(incident.get("alertMeta"), dict) else {}

    def pick(*values: Any, default: Any = "") -> Any:
        for value in values:
            if isinstance(value, list):
                for item in value:
                    if item not in (None, "", [], {}):
                        return item
            elif value not in (None, "", [], {}):
                return value
        return default

    risk_score = pick(
        raw.get("risk_score"), raw.get("riskScore"), primary.get("riskScore"),
        incident.get("riskScore"), incident.get("averageAlertRiskScore"), raw.get("score"),
        default=70,
    )
    alert_id = str(pick(identity.get("alert_id"), raw.get("alert_id"), raw.get("id"), primary.get("id"), default="")).strip()
    if not alert_id:
        alert_id = f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    title = pick(
        identity.get("alert_title"), raw.get("alert_name"), raw.get("name"), raw.get("incident_title"), raw.get("title"),
        primary.get("title"), headers.get("name"), original.get("moduleName"), incident.get("title"),
        default="NetWitness Alert",
    )
    severity = str(pick(
        raw.get("severity"), raw.get("priority"), raw.get("classification"), primary.get("severity"), headers.get("severity"),
        incident.get("priority"), default=_severity_from_score(risk_score),
    )).title()
    created = pick(
        raw.get("first_seen"), raw.get("created_at"), raw.get("createdTime"), raw.get("timestamp"), raw.get("time"),
        primary.get("created"), headers.get("timestamp"), original.get("time"), incident.get("firstAlertTime"),
        default=now_iso(),
    )
    updated = pick(raw.get("last_seen"), raw.get("updated_at"), raw.get("lastUpdated"), default=created)
    hostname = pick(
        identity.get("hostname"), raw.get("hostname"), raw.get("host"), raw.get("event_domain"), raw.get("destination_hostname"),
        meta.get("HostName"), default="",
    )
    username = pick(
        identity.get("username"), raw.get("username"), raw.get("user"), raw.get("user_name"), meta.get("UserName"), default="",
    )
    iocs = raw.get("iocs") or raw.get("indicators") or []
    if isinstance(iocs, dict):
        iocs = [iocs]
    if not isinstance(iocs, list):
        iocs = [str(iocs)] if iocs else []
    for key in ("file_hash", "sha256", "md5", "source_ip", "destination_ip", "domain"):
        if raw.get(key):
            iocs.append({"type": key, "value": raw[key]})
    return {
        "alert_id": alert_id,
        "alert_name": title,
        "source": raw.get("source") or headers.get("deviceProduct") or "NetWitness",
        "severity": severity,
        "status": raw.get("status") or "New",
        "first_seen": created,
        "last_seen": updated,
        "hostname": hostname,
        "username": username,
        "iocs": iocs,
        "risk_score": risk_score,
        "netwitness_url": raw.get("netwitness_url") or raw.get("url") or raw.get("link"),
        "raw": raw,
    }


class CaseworkStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path), timeout=30)
        con.row_factory = sqlite3.Row
        return con

    def init_db(self) -> None:
        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS counters (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO counters(name, value) VALUES ('ticket', 124);
                INSERT OR IGNORE INTO counters(name, value) VALUES ('incident', 30);

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    alert_name TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    hostname TEXT,
                    username TEXT,
                    iocs_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    netwitness_url TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tickets (
                    ticket_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    current_stage TEXT NOT NULL,
                    affected_assets_json TEXT NOT NULL,
                    affected_users_json TEXT NOT NULL,
                    iocs_json TEXT NOT NULL,
                    parsing_result_json TEXT NOT NULL DEFAULT '{}',
                    triage_result_json TEXT NOT NULL,
                    threat_intel_result_json TEXT NOT NULL DEFAULT '{}',
                    orchestration_decision_result_json TEXT NOT NULL DEFAULT '{}',
                    correlation_result_json TEXT NOT NULL DEFAULT '{}',
                    investigation_result_json TEXT NOT NULL,
                    approval_result_json TEXT NOT NULL,
                    investigation_approval_result_json TEXT NOT NULL DEFAULT '{}',
                    reporting_result_json TEXT NOT NULL,
                    soc_review_result_json TEXT NOT NULL DEFAULT '{}',
                    archive_status TEXT NOT NULL DEFAULT 'active',
                    merged_into_ticket_id TEXT,
                    archived_by TEXT,
                    archived_at TEXT,
                    archive_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS ticket_alerts (
                    ticket_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    status TEXT NOT NULL,
                    linked_at TEXT NOT NULL,
                    linked_by TEXT NOT NULL DEFAULT 'system',
                    link_source TEXT NOT NULL DEFAULT 'manual',
                    correlation_score INTEGER DEFAULT 0,
                    link_reason TEXT NOT NULL DEFAULT '',
                    confirmed_by TEXT,
                    confirmed_at TEXT,
                    PRIMARY KEY(ticket_id, alert_id)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS correlation_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    recommendation_type TEXT NOT NULL,
                    source_alert_id TEXT,
                    target_alert_id TEXT,
                    source_ticket_id TEXT,
                    target_ticket_id TEXT,
                    target_incident_id TEXT,
                    confidence TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    matched_fields_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    analyst_comments TEXT,
                    source_stage TEXT,
                    requires_archive_approval INTEGER NOT NULL DEFAULT 0,
                    archive_status TEXT NOT NULL DEFAULT 'not_required',
                    archive_action_json TEXT NOT NULL DEFAULT '{}',
                    recommended_by_agent TEXT,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_runs (
                    run_id TEXT PRIMARY KEY,
                    ticket_id TEXT,
                    alert_id TEXT,
                    agent_name TEXT NOT NULL,
                    run_type TEXT NOT NULL DEFAULT 'run',
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration_seconds REAL,
                    triggered_by TEXT NOT NULL DEFAULT 'SOC Analyst',
                    is_rerun INTEGER NOT NULL DEFAULT 0,
                    rerun_of_run_id TEXT,
                    output_path TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    ai_used INTEGER,
                    ai_model TEXT,
                    fallback_used INTEGER,
                    payload_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
            con.commit()
        self.ensure_schema_migrations()
        self.seed_demo_data_if_empty()

    def ensure_schema_migrations(self) -> None:
        """Add workflow columns when an older runtime database already exists."""
        required = {
            "incident_id": "TEXT",
            "parsing_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "threat_intel_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "investigation_approval_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "soc_review_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "orchestration_decision_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "correlation_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "archive_status": "TEXT NOT NULL DEFAULT 'active'",
            "merged_into_ticket_id": "TEXT",
            "archived_by": "TEXT",
            "archived_at": "TEXT",
            "archive_reason": "TEXT",
        }
        with self.connect() as con:
            existing = {row["name"] for row in con.execute("PRAGMA table_info(tickets)").fetchall()}
            for column, ddl in required.items():
                if column not in existing:
                    con.execute(f"ALTER TABLE tickets ADD COLUMN {column} {ddl}")
            alert_link_required = {
                "linked_by": "TEXT NOT NULL DEFAULT 'system'",
                "link_source": "TEXT NOT NULL DEFAULT 'manual'",
                "correlation_score": "INTEGER DEFAULT 0",
                "link_reason": "TEXT NOT NULL DEFAULT ''",
                "confirmed_by": "TEXT",
                "confirmed_at": "TEXT",
            }
            existing_links = {row["name"] for row in con.execute("PRAGMA table_info(ticket_alerts)").fetchall()}
            for column, ddl in alert_link_required.items():
                if column not in existing_links:
                    con.execute(f"ALTER TABLE ticket_alerts ADD COLUMN {column} {ddl}")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS correlation_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    recommendation_type TEXT NOT NULL,
                    source_alert_id TEXT,
                    target_alert_id TEXT,
                    source_ticket_id TEXT,
                    target_ticket_id TEXT,
                    target_incident_id TEXT,
                    confidence TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    matched_fields_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    analyst_comments TEXT,
                    source_stage TEXT,
                    requires_archive_approval INTEGER NOT NULL DEFAULT 0,
                    archive_status TEXT NOT NULL DEFAULT 'not_required',
                    archive_action_json TEXT NOT NULL DEFAULT '{}',
                    recommended_by_agent TEXT,
                    payload_json TEXT NOT NULL
                );
            """)
            con.executescript("""
                CREATE TABLE IF NOT EXISTS agent_runs (
                    run_id TEXT PRIMARY KEY,
                    ticket_id TEXT,
                    alert_id TEXT,
                    agent_name TEXT NOT NULL,
                    run_type TEXT NOT NULL DEFAULT 'run',
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration_seconds REAL,
                    triggered_by TEXT NOT NULL DEFAULT 'SOC Analyst',
                    is_rerun INTEGER NOT NULL DEFAULT 0,
                    rerun_of_run_id TEXT,
                    output_path TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    ai_used INTEGER,
                    ai_model TEXT,
                    fallback_used INTEGER,
                    payload_json TEXT NOT NULL DEFAULT '{}'
                );
            """)
            corr_required = {
                "source_stage": "TEXT",
                "requires_archive_approval": "INTEGER NOT NULL DEFAULT 0",
                "archive_status": "TEXT NOT NULL DEFAULT 'not_required'",
                "archive_action_json": "TEXT NOT NULL DEFAULT '{}'",
                "recommended_by_agent": "TEXT",
            }
            existing_corr = {row["name"] for row in con.execute("PRAGMA table_info(correlation_recommendations)").fetchall()}
            for column, ddl in corr_required.items():
                if column not in existing_corr:
                    con.execute(f"ALTER TABLE correlation_recommendations ADD COLUMN {column} {ddl}")
            rows = con.execute("SELECT ticket_id, title, severity, confidence, created_at, updated_at FROM tickets WHERE incident_id IS NULL OR incident_id='' ").fetchall()
            for row in rows:
                incident_id = self._next_incident_id(con)
                con.execute("UPDATE tickets SET incident_id=? WHERE ticket_id=?", (incident_id, row["ticket_id"]))
                con.execute(
                    "INSERT OR IGNORE INTO incidents(incident_id, title, status, severity, confidence, created_at, updated_at, closed_at) VALUES(?,?,?,?,?,?,?,?)",
                    (incident_id, row["title"], "Open", row["severity"], row["confidence"], row["created_at"], row["updated_at"], None),
                )
            con.commit()

    def _next_ticket_id(self, con: sqlite3.Connection) -> str:
        row = con.execute("SELECT value FROM counters WHERE name='ticket'").fetchone()
        value = int(row["value"] if row else 0) + 1
        con.execute("INSERT OR REPLACE INTO counters(name, value) VALUES('ticket', ?)", (value,))
        return f"TKT-{datetime.now(timezone.utc).year}-{value:05d}"

    def _next_incident_id(self, con: sqlite3.Connection) -> str:
        row = con.execute("SELECT value FROM counters WHERE name='incident'").fetchone()
        value = int(row["value"] if row else 0) + 1
        con.execute("INSERT OR REPLACE INTO counters(name, value) VALUES('incident', ?)", (value,))
        return f"INC-{datetime.now(timezone.utc).year}-{value:05d}"

    def seed_demo_data_if_empty(self) -> None:
        with self.connect() as con:
            count = con.execute("SELECT COUNT(*) AS c FROM tickets").fetchone()["c"]
        if count:
            return
        demo_alerts = [
            {"alert_id": "ALERT-2025-77864", "alert_name": "High Risk Endpoint Alert", "severity": "Critical", "hostname": "wkstn-sg-014", "risk_score": 92, "source": "NetWitness Endpoint", "first_seen": "2025-05-22T09:06:22Z"},
            {"alert_id": "ALERT-2025-77865", "alert_name": "Malicious File Detected", "severity": "Critical", "hostname": "wkstn-sg-014", "file_hash": "8c7f-demo-hash", "risk_score": 95, "source": "NetWitness Endpoint", "first_seen": "2025-05-22T09:08:11Z"},
            {"alert_id": "ALERT-2025-77866", "alert_name": "Suspicious Process Execution", "severity": "High", "hostname": "wkstn-sg-014", "risk_score": 82, "source": "NetWitness Endpoint", "first_seen": "2025-05-22T09:11:08Z"},
            {"alert_id": "ALERT-2025-77867", "alert_name": "PowerShell Encoded Command", "severity": "High", "hostname": "wkstn-sg-022", "risk_score": 78, "source": "NetWitness Endpoint", "first_seen": "2025-05-22T10:28:03Z"},
        ]
        for alert in demo_alerts:
            self.upsert_alert(alert)
        ticket = self.create_ticket_from_alert("ALERT-2025-77864", owner="Soong Yang", status="To Parse")
        self.link_alert(ticket["ticket_id"], "ALERT-2025-77865", relationship="Same endpoint malware chain")
        self.link_alert(ticket["ticket_id"], "ALERT-2025-77866", relationship="Same endpoint malware chain")
        self.append_activity(ticket["ticket_id"], "System", "workflow_ready", "completed", "Ticket is ready for Parsing and Normalisation.", {"next_stage": "parsing_normalisation"})
        self.create_ticket_from_alert("ALERT-2025-77867", owner="Unassigned", status="To Triage")

    def upsert_alert(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        alert = normalise_alert(raw_alert)
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO alerts(alert_id, alert_name, source, severity, status, first_seen, last_seen, hostname, username, iocs_json, raw_json, netwitness_url, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    alert_name=excluded.alert_name,
                    source=excluded.source,
                    severity=excluded.severity,
                    status=excluded.status,
                    first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen,
                    hostname=excluded.hostname,
                    username=excluded.username,
                    iocs_json=excluded.iocs_json,
                    raw_json=excluded.raw_json,
                    netwitness_url=excluded.netwitness_url,
                    updated_at=excluded.updated_at
                """,
                (
                    alert["alert_id"], alert["alert_name"], alert["source"], alert["severity"], alert["status"],
                    alert["first_seen"], alert["last_seen"], alert["hostname"], alert["username"], _json(alert["iocs"]),
                    _json(alert["raw"]), alert.get("netwitness_url"), now_iso(),
                ),
            )
            con.commit()
        return self.get_alert(alert["alert_id"]) or alert

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        return self._row_alert(row) if row else None

    def list_alerts(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        clauses: list[str] = []
        values: list[Any] = []
        for field in ("severity", "status"):
            if filters.get(field):
                clauses.append(f"LOWER({field}) = ?")
                values.append(str(filters[field]).lower())
        if filters.get("q"):
            clauses.append("(LOWER(alert_id) LIKE ? OR LOWER(alert_name) LIKE ? OR LOWER(hostname) LIKE ?)")
            q = f"%{str(filters['q']).lower()}%"
            values.extend([q, q, q])
        if filters.get("hostname"):
            clauses.append("LOWER(hostname) LIKE ?")
            values.append(f"%{str(filters['hostname']).lower()}%")
        sql = "SELECT * FROM alerts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY COALESCE(last_seen, first_seen, updated_at) DESC LIMIT ?"
        values.append(int(filters.get("limit") or 200))
        with self.connect() as con:
            rows = con.execute(sql, values).fetchall()
        return [self._row_alert(row) for row in rows]

    def create_ticket_from_alert(self, alert_id: str, owner: str = "Unassigned", status: str | None = None) -> dict[str, Any]:
        alert = self.get_alert(alert_id)
        if not alert:
            raise KeyError(f"Alert {alert_id} not found")
        existing = self.ticket_for_alert(alert_id)
        if existing:
            return existing
        assets = [alert["hostname"]] if alert.get("hostname") else []
        users = [alert["username"]] if alert.get("username") else []
        ts = now_iso()
        current_stage = "parsing_normalisation"
        status = status or "To Parse"
        with self.connect() as con:
            ticket_id = self._next_ticket_id(con)
            incident_id = self._next_incident_id(con)
            con.execute(
                """
                INSERT INTO tickets(ticket_id, incident_id, title, severity, confidence, status, owner, current_stage, affected_assets_json,
                    affected_users_json, iocs_json, parsing_result_json, triage_result_json, threat_intel_result_json,
                    orchestration_decision_result_json, correlation_result_json, investigation_result_json, approval_result_json, investigation_approval_result_json,
                    reporting_result_json, soc_review_result_json, archive_status, merged_into_ticket_id, archived_by, archived_at, archive_reason, created_at, updated_at, closed_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    ticket_id, incident_id, alert["alert_name"], alert["severity"], "Unknown", status, owner, current_stage,
                    _json(assets), _json(users), _json(alert.get("iocs") or []), _json({}), _json({}), _json({}),
                    _json({}), _json({}), _json({}), _json({}), _json({}), _json({}), _json({}),
                    "active", None, None, None, "", ts, ts, None,
                ),
            )
            con.execute(
                "INSERT OR IGNORE INTO incidents(incident_id, title, status, severity, confidence, created_at, updated_at, closed_at) VALUES(?,?,?,?,?,?,?,?)",
                (incident_id, alert["alert_name"], "Open", alert["severity"], "Unknown", ts, ts, None),
            )
            con.execute(
                """
                INSERT OR REPLACE INTO ticket_alerts(ticket_id, alert_id, relationship, status, linked_at, linked_by, link_source, correlation_score, link_reason, confirmed_by, confirmed_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (ticket_id, alert_id, "Primary alert", "In Ticket", ts, "system", "ticket_creation", 100, "Primary alert that created the ticket.", "System", ts),
            )
            con.commit()
        self.append_activity(ticket_id, "System", "ticket_created", "completed", f"Created ticket from NetWitness alert {alert_id}.", {"alert_id": alert_id})
        return self.get_ticket(ticket_id) or {}

    def ticket_for_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT ticket_id FROM ticket_alerts WHERE alert_id=? ORDER BY linked_at DESC LIMIT 1", (alert_id,)).fetchone()
        return self.get_ticket(row["ticket_id"]) if row else None

    def link_alert(
        self,
        ticket_id: str,
        alert_id: str,
        relationship: str = "Related alert",
        *,
        linked_by: str = "SOC Analyst",
        link_source: str = "manual",
        correlation_score: int = 0,
        link_reason: str = "",
        confirmed_by: str | None = None,
    ) -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        alert = self.get_alert(alert_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        if not alert:
            raise KeyError(f"Alert {alert_id} not found")
        iocs = list(ticket.get("iocs") or [])
        iocs.extend(alert.get("iocs") or [])
        iocs = list(dict.fromkeys([json.dumps(i, sort_keys=True) if isinstance(i, dict) else str(i) for i in iocs]))
        assets = list(dict.fromkeys((ticket.get("affected_assets") or []) + ([alert["hostname"]] if alert.get("hostname") else [])))
        users = list(dict.fromkeys((ticket.get("affected_users") or []) + ([alert["username"]] if alert.get("username") else [])))
        ts = now_iso()
        if confirmed_by is None and link_source in {"incident_grouping", "analyst_override", "manual"}:
            confirmed_by = linked_by
        with self.connect() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO ticket_alerts(ticket_id, alert_id, relationship, status, linked_at, linked_by, link_source, correlation_score, link_reason, confirmed_by, confirmed_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (ticket_id, alert_id, relationship, "In Ticket", ts, linked_by, link_source, int(correlation_score or 0), link_reason or relationship, confirmed_by, ts if confirmed_by else None),
            )
            con.execute(
                "UPDATE tickets SET affected_assets_json=?, affected_users_json=?, iocs_json=?, updated_at=? WHERE ticket_id=?",
                (_json(assets), _json(users), _json(iocs), ts, ticket_id),
            )
            con.commit()
        actor = confirmed_by or linked_by or "SOC Analyst"
        self.append_activity(
            ticket_id,
            actor,
            "alert_linked",
            "completed",
            f"Linked alert {alert_id} to this ticket.",
            {"alert_id": alert_id, "relationship": relationship, "link_source": link_source, "correlation_score": correlation_score, "link_reason": link_reason or relationship},
        )
        self.mark_context_refresh_required(ticket_id, reason=f"Alert {alert_id} was linked to this ticket.", actor=actor)
        return self.get_ticket(ticket_id) or {}

    def unlink_alert(self, ticket_id: str, alert_id: str, analyst: str = "SOC Analyst", reason: str = "Removed from incident ticket") -> dict[str, Any]:
        with self.connect() as con:
            con.execute("DELETE FROM ticket_alerts WHERE ticket_id=? AND alert_id=?", (ticket_id, alert_id))
            con.execute("UPDATE tickets SET updated_at=? WHERE ticket_id=?", (now_iso(), ticket_id))
            con.commit()
        self.append_activity(ticket_id, analyst, "alert_removed", "completed", f"Removed alert {alert_id} from this ticket. {reason}", {"alert_id": alert_id, "reason": reason})
        return self.get_ticket(ticket_id) or {}

    def mark_downstream_refresh_required(self, ticket_id: str, agent_name: str, reason: str, actor: str = "System") -> None:
        """Mark outputs after a re-run as stale without marking the re-run target itself."""
        ticket = self.get_ticket(ticket_id) or {}
        order = ["parsing", "triage", "threat_intel", "investigation", "reporting"]
        affected_map = {
            "parsing": ["triage_result", "threat_intel_result", "investigation_result", "reporting_result"],
            "triage": ["threat_intel_result", "investigation_result", "reporting_result"],
            "threat_intel": ["investigation_result", "reporting_result"],
            "investigation": ["reporting_result"],
            "reporting": [],
        }
        affected = affected_map.get(_norm_status(agent_name), [])
        fields: dict[str, Any] = {}
        for key in affected:
            data = dict(ticket.get(key) or {})
            if data:
                data.update({"needs_refresh": True, "context_refresh_required": True, "context_refresh_reason": reason, "updated_at": now_iso()})
                fields[key.replace("_result", "_result")] = data
        if fields:
            self.update_ticket(ticket_id, fields, actor=actor, action="downstream_refresh_required", message=reason)

    def mark_context_refresh_required(self, ticket_id: str, reason: str, actor: str = "System") -> None:
        """Mark downstream outputs as potentially stale when ticket grouping changes."""
        ticket = self.get_ticket(ticket_id) or {}
        triage = dict(ticket.get("triage_result") or {})
        investigation = dict(ticket.get("investigation_result") or {})
        reporting = dict(ticket.get("reporting_result") or {})
        fields: dict[str, Any] = {}
        if triage:
            triage.update({"context_refresh_required": True, "context_refresh_reason": reason, "updated_at": now_iso()})
            fields["triage_result"] = triage
        if investigation:
            investigation.update({"context_refresh_required": True, "context_refresh_reason": reason, "updated_at": now_iso()})
            fields["investigation_result"] = investigation
        if reporting:
            reporting.update({"context_refresh_required": True, "context_refresh_reason": reason, "updated_at": now_iso()})
            fields["reporting_result"] = reporting
        if fields:
            fields["status"] = "Context Changed"
            self.update_ticket(ticket_id, fields, actor=actor, action="context_refresh_required", message=reason)

    def _row_correlation_recommendation(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = _loads(row["payload_json"], {})
        payload.update({
            "recommendation_id": row["recommendation_id"],
            "recommendation_type": row["recommendation_type"],
            "source_alert_id": row["source_alert_id"],
            "target_alert_id": row["target_alert_id"],
            "source_ticket_id": row["source_ticket_id"],
            "target_ticket_id": row["target_ticket_id"],
            "target_incident_id": row["target_incident_id"],
            "confidence": row["confidence"],
            "score": row["score"],
            "matched_fields": _loads(row["matched_fields_json"], []),
            "reason": row["reason"],
            "status": row["status"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "analyst_comments": row["analyst_comments"],
            "source_stage": row["source_stage"] if "source_stage" in row.keys() else payload.get("source_stage"),
            "requires_archive_approval": bool(row["requires_archive_approval"]) if "requires_archive_approval" in row.keys() else bool(payload.get("requires_archive_approval")),
            "archive_status": row["archive_status"] if "archive_status" in row.keys() else payload.get("archive_status", "not_required"),
            "archive_action": _loads(row["archive_action_json"], {}) if "archive_action_json" in row.keys() else payload.get("archive_action") or {},
            "recommended_by_agent": row["recommended_by_agent"] if "recommended_by_agent" in row.keys() else payload.get("recommended_by_agent") or payload.get("created_by"),
            "archive_after_approval": bool(payload.get("archive_after_approval") or (row["requires_archive_approval"] if "requires_archive_approval" in row.keys() else False)),
        })
        return payload

    def create_correlation_recommendation(self, recommendation: dict[str, Any]) -> dict[str, Any]:
        rec = dict(recommendation or {})
        rec_id = rec.get("recommendation_id") or f"CORR-{uuid.uuid4().hex[:10].upper()}"
        target_ticket_id = rec.get("target_ticket_id")
        source_alert_id = rec.get("source_alert_id")
        ts = rec.get("created_at") or now_iso()
        existing_statuses = {"pending"}
        with self.connect() as con:
            existing = con.execute(
                """
                SELECT * FROM correlation_recommendations
                WHERE source_alert_id=? AND target_ticket_id=? AND recommendation_type=? AND status IN ('pending')
                ORDER BY created_at DESC LIMIT 1
                """,
                (source_alert_id, target_ticket_id, rec.get("recommendation_type") or "add_alert_to_existing_ticket"),
            ).fetchone()
            if existing:
                return self._row_correlation_recommendation(existing)
            con.execute(
                """
                INSERT INTO correlation_recommendations(recommendation_id, recommendation_type, source_alert_id, target_alert_id,
                    source_ticket_id, target_ticket_id, target_incident_id, confidence, score, matched_fields_json, reason, status,
                    created_by, created_at, reviewed_by, reviewed_at, analyst_comments, source_stage, requires_archive_approval,
                    archive_status, archive_action_json, recommended_by_agent, payload_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    rec_id,
                    rec.get("recommendation_type") or "add_alert_to_existing_ticket",
                    source_alert_id,
                    rec.get("target_alert_id"),
                    rec.get("source_ticket_id"),
                    target_ticket_id,
                    rec.get("target_incident_id"),
                    rec.get("confidence") or "Medium",
                    int(rec.get("score") or 0),
                    _json(rec.get("matched_fields") or []),
                    rec.get("reason") or "Potentially related alert.",
                    rec.get("status") or "pending",
                    rec.get("created_by") or "Incident Grouping",
                    ts,
                    rec.get("reviewed_by"),
                    rec.get("reviewed_at"),
                    rec.get("analyst_comments"),
                    rec.get("source_stage") or "correlation",
                    1 if rec.get("requires_archive_approval") or rec.get("archive_after_approval") else 0,
                    rec.get("archive_status") or ("pending_analyst_approval" if rec.get("requires_archive_approval") or rec.get("archive_after_approval") else "not_required"),
                    _json(rec.get("archive_action") or rec.get("archive_action_json") or {}),
                    rec.get("recommended_by_agent") or rec.get("created_by") or "Incident Grouping",
                    _json(rec),
                ),
            )
            con.commit()
        if target_ticket_id:
            try:
                self.append_activity(target_ticket_id, rec.get("created_by") or "Incident Grouping", "correlation_recommended", "pending", f"Recommended linking alert {source_alert_id} to this ticket.", rec)
            except Exception:
                pass
        return self.get_correlation_recommendation(rec_id) or rec

    def get_correlation_recommendation(self, recommendation_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM correlation_recommendations WHERE recommendation_id=?", (recommendation_id,)).fetchone()
        return self._row_correlation_recommendation(row) if row else None

    def list_correlation_recommendations(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        clauses: list[str] = []
        values: list[Any] = []
        if filters.get("ticket_id"):
            clauses.append("(target_ticket_id=? OR source_ticket_id=?)")
            values.extend([filters["ticket_id"], filters["ticket_id"]])
        if filters.get("status"):
            clauses.append("LOWER(status)=?")
            values.append(str(filters["status"]).lower())
        sql = "SELECT * FROM correlation_recommendations"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC LIMIT ?"
        values.append(int(filters.get("limit") or 100))
        with self.connect() as con:
            rows = con.execute(sql, values).fetchall()
        return [self._row_correlation_recommendation(row) for row in rows]

    def confirm_correlation_recommendation(self, recommendation_id: str, analyst: str = "SOC Analyst", comments: str = "") -> dict[str, Any]:
        rec = self.get_correlation_recommendation(recommendation_id)
        if not rec:
            raise KeyError(f"Recommendation {recommendation_id} not found")

        rec_type = _norm_status(rec.get("recommendation_type"))
        target_ticket = rec.get("target_ticket_id")
        source_alert = rec.get("source_alert_id")
        source_ticket = rec.get("source_ticket_id")
        if not target_ticket:
            raise ValueError("Recommendation must include target_ticket_id")

        ticket: dict[str, Any]
        if rec_type in {"merge_and_archive_duplicate_ticket", "archive_duplicate_ticket", "merge_tickets"}:
            if not source_ticket:
                raise ValueError("Merge/archive recommendation must include source_ticket_id")
            ticket = self.merge_tickets(
                source_ticket,
                target_ticket,
                analyst=analyst,
                reason=comments or rec.get("reason") or "Analyst approved investigation-driven merge/archive recommendation.",
                archive_duplicate=True,
            )
        elif source_alert:
            ticket = self.link_alert(
                target_ticket,
                source_alert,
                relationship="Confirmed correlated alert",
                linked_by=analyst,
                link_source="incident_grouping",
                correlation_score=int(rec.get("score") or 0),
                link_reason=rec.get("reason") or "Analyst confirmed incident grouping recommendation.",
                confirmed_by=analyst,
            )
            if rec.get("archive_after_approval") and source_ticket and source_ticket != target_ticket:
                self.archive_duplicate_ticket(
                    source_ticket,
                    target_ticket,
                    analyst=analyst,
                    reason=comments or rec.get("reason") or "Source ticket archived after analyst-approved alert grouping.",
                )
                ticket = self.get_ticket(target_ticket) or ticket
        else:
            raise ValueError("Recommendation must include source_alert_id or source_ticket_id")

        ts = now_iso()
        with self.connect() as con:
            payload = dict(rec)
            payload.update({
                "status": "confirmed",
                "reviewed_by": analyst,
                "reviewed_at": ts,
                "analyst_comments": comments,
                "archive_status": "archived" if rec.get("requires_archive_approval") or rec.get("archive_after_approval") else rec.get("archive_status"),
            })
            assignments = "status='confirmed', reviewed_by=?, reviewed_at=?, analyst_comments=?, payload_json=?"
            values: list[Any] = [analyst, ts, comments, _json(payload)]
            existing_cols = {row["name"] for row in con.execute("PRAGMA table_info(correlation_recommendations)").fetchall()}
            if "archive_status" in existing_cols:
                assignments += ", archive_status=?"
                values.append(payload.get("archive_status") or "confirmed")
            values.append(recommendation_id)
            con.execute(f"UPDATE correlation_recommendations SET {assignments} WHERE recommendation_id=?", values)
            con.commit()
        self.append_activity(target_ticket, analyst, "correlation_confirmed", "completed", f"Confirmed incident grouping recommendation {recommendation_id}; grouping changes were applied after analyst approval.", {"recommendation_id": recommendation_id, "alert_id": source_alert, "source_ticket_id": source_ticket, "comments": comments})
        return {"recommendation": self.get_correlation_recommendation(recommendation_id), "ticket": ticket}

    def reject_correlation_recommendation(self, recommendation_id: str, analyst: str = "SOC Analyst", comments: str = "") -> dict[str, Any]:
        rec = self.get_correlation_recommendation(recommendation_id)
        if not rec:
            raise KeyError(f"Recommendation {recommendation_id} not found")
        ts = now_iso()
        with self.connect() as con:
            payload = dict(rec)
            payload.update({"status": "rejected", "reviewed_by": analyst, "reviewed_at": ts, "analyst_comments": comments})
            con.execute(
                "UPDATE correlation_recommendations SET status='rejected', reviewed_by=?, reviewed_at=?, analyst_comments=?, payload_json=? WHERE recommendation_id=?",
                (analyst, ts, comments, _json(payload), recommendation_id),
            )
            con.commit()
        if rec.get("target_ticket_id"):
            self.append_activity(rec["target_ticket_id"], analyst, "correlation_rejected", "completed", f"Rejected incident grouping recommendation {recommendation_id} for alert {rec.get('source_alert_id')}.", {"recommendation_id": recommendation_id, "comments": comments})
        return self.get_correlation_recommendation(recommendation_id) or {}

    def edit_correlation_recommendation(self, recommendation_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", comments: str = "") -> dict[str, Any]:
        rec = self.get_correlation_recommendation(recommendation_id)
        if not rec:
            raise KeyError(f"Recommendation {recommendation_id} not found")
        target = self.get_ticket(target_ticket_id)
        if not target:
            raise KeyError(f"Ticket {target_ticket_id} not found")
        ts = now_iso()
        with self.connect() as con:
            payload = dict(rec)
            payload.update({"target_ticket_id": target_ticket_id, "target_incident_id": target.get("incident_id"), "status": "edited", "reviewed_by": analyst, "reviewed_at": ts, "analyst_comments": comments})
            con.execute(
                "UPDATE correlation_recommendations SET status='edited', target_ticket_id=?, target_incident_id=?, reviewed_by=?, reviewed_at=?, analyst_comments=?, payload_json=? WHERE recommendation_id=?",
                (target_ticket_id, target.get("incident_id"), analyst, ts, comments, _json(payload), recommendation_id),
            )
            con.commit()
        ticket = self.link_alert(
            target_ticket_id,
            rec.get("source_alert_id"),
            relationship="Analyst-edited correlated alert",
            linked_by=analyst,
            link_source="analyst_override",
            correlation_score=int(rec.get("score") or 0),
            link_reason=comments or rec.get("reason") or "Analyst edited incident grouping target.",
            confirmed_by=analyst,
        )
        return {"recommendation": self.get_correlation_recommendation(recommendation_id), "ticket": ticket}

    def move_alert_to_ticket(self, alert_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Manual alert move") -> dict[str, Any]:
        target = self.get_ticket(target_ticket_id)
        if not target:
            raise KeyError(f"Ticket {target_ticket_id} not found")
        source = self.ticket_for_alert(alert_id)
        if source and source.get("ticket_id") == target_ticket_id:
            raise ValueError(f"Alert {alert_id} is already linked to ticket {target_ticket_id}")
        if source and source.get("ticket_id") != target_ticket_id:
            with self.connect() as con:
                con.execute("DELETE FROM ticket_alerts WHERE ticket_id=? AND alert_id=?", (source["ticket_id"], alert_id))
                con.commit()
            self.append_activity(source["ticket_id"], analyst, "alert_moved_out", "completed", f"Moved alert {alert_id} out of this ticket into {target_ticket_id}.", {"alert_id": alert_id, "target_ticket_id": target_ticket_id, "reason": reason})
        return self.link_alert(target_ticket_id, alert_id, relationship="Moved correlated alert", linked_by=analyst, link_source="analyst_override", link_reason=reason, confirmed_by=analyst)

    def split_alert_to_new_ticket(self, ticket_id: str, alert_id: str, analyst: str = "SOC Analyst", reason: str = "Split alert into a separate incident") -> dict[str, Any]:
        source_ticket = self.get_ticket(ticket_id)
        if not source_ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        with self.connect() as con:
            con.execute("DELETE FROM ticket_alerts WHERE ticket_id=? AND alert_id=?", (ticket_id, alert_id))
            con.commit()
        self.append_activity(ticket_id, analyst, "alert_split_out", "completed", f"Split alert {alert_id} out into a new incident ticket.", {"alert_id": alert_id, "reason": reason})
        new_ticket = self.create_ticket_from_alert(alert_id, owner=source_ticket.get("owner") or "Unassigned", status="To Parse")
        self.append_activity(new_ticket["ticket_id"], analyst, "ticket_created_from_split", "completed", f"Created this ticket by splitting alert {alert_id} from {ticket_id}.", {"source_ticket_id": ticket_id, "alert_id": alert_id, "reason": reason})
        return new_ticket

    def archive_duplicate_ticket(self, source_ticket_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Archived as duplicate after analyst approval") -> dict[str, Any]:
        source = self.get_ticket(source_ticket_id)
        target = self.get_ticket(target_ticket_id)
        if not source:
            raise KeyError(f"Source ticket {source_ticket_id} not found")
        if not target:
            raise KeyError(f"Target ticket {target_ticket_id} not found")
        ts = now_iso()
        archived = self.update_ticket(
            source_ticket_id,
            {
                "status": "Archived Duplicate",
                "current_stage": "case_closure",
                "archive_status": "archived_duplicate",
                "merged_into_ticket_id": target_ticket_id,
                "archived_by": analyst,
                "archived_at": ts,
                "archive_reason": reason,
            },
            actor=analyst,
            action="ticket_archived_duplicate",
            message=f"Archived as duplicate and merged into {target_ticket_id}. {reason}",
        )
        self.append_activity(target_ticket_id, analyst, "duplicate_ticket_archived", "completed", f"Archived duplicate ticket {source_ticket_id}; original record remains auditable.", {"source_ticket_id": source_ticket_id, "reason": reason})
        return archived

    def merge_tickets(self, source_ticket_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Manual ticket merge", archive_duplicate: bool = True) -> dict[str, Any]:
        if source_ticket_id == target_ticket_id:
            raise ValueError("Source and target ticket cannot be the same")
        source = self.get_ticket(source_ticket_id)
        target = self.get_ticket(target_ticket_id)
        if not source:
            raise KeyError(f"Source ticket {source_ticket_id} not found")
        if not target:
            raise KeyError(f"Target ticket {target_ticket_id} not found")
        for alert in source.get("related_alerts") or []:
            if alert.get("alert_id"):
                self.move_alert_to_ticket(alert.get("alert_id"), target_ticket_id, analyst=analyst, reason=reason)
        target = self.get_ticket(target_ticket_id) or target
        merged_assets = list(dict.fromkeys((target.get("affected_assets") or []) + (source.get("affected_assets") or [])))
        merged_users = list(dict.fromkeys((target.get("affected_users") or []) + (source.get("affected_users") or [])))
        merged_iocs = list(dict.fromkeys([str(i) for i in ((target.get("iocs") or []) + (source.get("iocs") or []))]))
        updated = self.update_ticket(target_ticket_id, {"affected_assets": merged_assets, "affected_users": merged_users, "iocs": merged_iocs}, actor=analyst, action="ticket_merged_in", message=f"Merged ticket {source_ticket_id} into this incident ticket.")
        if archive_duplicate:
            self.archive_duplicate_ticket(source_ticket_id, target_ticket_id, analyst=analyst, reason=reason)
        else:
            self.update_ticket(source_ticket_id, {"status": "Closed", "current_stage": "case_closure"}, actor=analyst, action="ticket_merged_out", message=f"Merged into ticket {target_ticket_id}. {reason}")
        self.mark_context_refresh_required(target_ticket_id, reason=f"Ticket {source_ticket_id} was merged into this incident. Re-run Investigation before final Reporting if needed.", actor=analyst)
        return self.get_ticket(target_ticket_id) or updated

    def list_tickets(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        clauses: list[str] = []
        values: list[Any] = []
        if filters.get("status"):
            clauses.append("LOWER(status) = ?")
            values.append(str(filters["status"]).lower().replace("_", " "))
        if filters.get("stage"):
            clauses.append("current_stage = ?")
            values.append(str(filters["stage"]))
        if filters.get("severity"):
            clauses.append("LOWER(severity) = ?")
            values.append(str(filters["severity"]).lower())
        if filters.get("owner") == "me":
            clauses.append("LOWER(owner) = ?")
            values.append("soong yang")
        elif _norm_status(filters.get("owner")) == "unassigned":
            clauses.append("LOWER(COALESCE(owner, '')) IN ('', 'unassigned', 'none')")
        elif filters.get("owner"):
            clauses.append("LOWER(owner) = ?")
            values.append(str(filters["owner"]).lower())
        if filters.get("q"):
            clauses.append("(LOWER(ticket_id) LIKE ? OR LOWER(title) LIKE ?)")
            q = f"%{str(filters['q']).lower()}%"
            values.extend([q, q])
        if filters.get("open_only"):
            clauses.append("LOWER(status) NOT IN ('closed', 'archived duplicate')")
            clauses.append("COALESCE(archive_status, 'active') = 'active'")
        sql = "SELECT * FROM tickets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        values.append(int(filters.get("limit") or 200))
        with self.connect() as con:
            rows = con.execute(sql, values).fetchall()
        return [self._row_ticket(row, include_children=False) for row in rows]

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
        return self._row_ticket(row, include_children=True) if row else None

    def update_ticket(self, ticket_id: str, fields: dict[str, Any], actor: str = "System", action: str = "ticket_updated", message: str | None = None) -> dict[str, Any]:
        allowed = {
            "title": "title",
            "severity": "severity",
            "confidence": "confidence",
            "status": "status",
            "owner": "owner",
            "current_stage": "current_stage",
            "affected_assets": "affected_assets_json",
            "affected_users": "affected_users_json",
            "iocs": "iocs_json",
            "parsing_result": "parsing_result_json",
            "triage_result": "triage_result_json",
            "threat_intel_result": "threat_intel_result_json",
            "orchestration_decision_result": "orchestration_decision_result_json",
            "correlation_result": "correlation_result_json",
            "investigation_result": "investigation_result_json",
            "approval_result": "approval_result_json",
            "investigation_approval_result": "investigation_approval_result_json",
            "reporting_result": "reporting_result_json",
            "soc_review_result": "soc_review_result_json",
            "archive_status": "archive_status",
            "merged_into_ticket_id": "merged_into_ticket_id",
            "archived_by": "archived_by",
            "archived_at": "archived_at",
            "archive_reason": "archive_reason",
        }
        assignments: list[str] = []
        values: list[Any] = []
        for key, column in allowed.items():
            if key not in fields:
                continue
            value = fields[key]
            if column.endswith("_json"):
                value = _json(value)
            assignments.append(f"{column}=?")
            values.append(value)
        if fields.get("status") == "Closed":
            assignments.append("closed_at=?")
            values.append(now_iso())
        assignments.append("updated_at=?")
        values.append(now_iso())
        values.append(ticket_id)
        with self.connect() as con:
            con.execute(f"UPDATE tickets SET {', '.join(assignments)} WHERE ticket_id=?", values)
            con.commit()
        self.append_activity(ticket_id, actor, action, "completed", message or f"{actor} updated ticket.", fields)
        return self.get_ticket(ticket_id) or {}

    def append_activity(self, ticket_id: str, actor: str, action: str, status: str, message: str, payload: Any | None = None) -> dict[str, Any]:
        ts = now_iso()
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO activity(ticket_id, actor, action, status, message, payload_json, created_at) VALUES(?,?,?,?,?,?,?)",
                (ticket_id, actor, action, status, message, _json(payload or {}), ts),
            )
            con.execute("UPDATE tickets SET updated_at=? WHERE ticket_id=?", (ts, ticket_id))
            con.commit()
            activity_id = cur.lastrowid
        return {"id": activity_id, "ticket_id": ticket_id, "actor": actor, "action": action, "status": status, "message": message, "payload": payload or {}, "created_at": ts}

    def activity(self, ticket_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM activity WHERE ticket_id=? ORDER BY id DESC LIMIT ?", (ticket_id, limit)).fetchall()
        return [self._row_activity(row) for row in rows]

    def dashboard_summary(self, owner: str | None = None) -> dict[str, Any]:
        tickets = self.list_tickets({"limit": 500})
        alerts = self.list_alerts({"limit": 500})
        if owner:
            owner_key = _norm_status(owner)
            tickets = [t for t in tickets if _norm_status(t.get("owner")) == owner_key]
        open_tickets = [t for t in tickets if _norm_status(t["status"]) != "closed"]
        pending_correlation = self.list_correlation_recommendations({"status": "pending", "limit": 1000})
        return {
            "pending_correlation": len(pending_correlation),
            "new_alerts": len([a for a in alerts if _norm_status(a.get("status")) in {"new", "open"}]),
            "open_tickets": len(open_tickets),
            "critical_cases": len([t for t in open_tickets if _norm_status(t.get("severity")) == "critical"]),
            "pending_approval": len([t for t in tickets if t.get("current_stage") in {"triage_approval", "investigation_approval", "investigation_evidence_decision", "soc_analyst_review", "analyst_approval"} or _norm_status(t.get("status")) in {"awaiting_approval", "awaiting_soc_review"}]),
            "unassigned_cases": len([t for t in open_tickets if _norm_status(t.get("owner")) in {"", "unassigned", "none"}]),
            "multi_alert_cases": len([t for t in tickets if int(t.get("alert_count") or 0) > 1]),
            "closed_cases": len([t for t in tickets if _norm_status(t.get("status")) == "closed"]),
            "stage_counts": {
                "parsing_normalisation": len([t for t in tickets if t.get("current_stage") == "parsing_normalisation"]),
                "triage": len([t for t in tickets if t.get("current_stage") == "triage"]),
                "incident_grouping_review": len([t for t in tickets if t.get("current_stage") == "incident_grouping_review"]),
                "threat_intelligence": len([t for t in tickets if t.get("current_stage") == "threat_intelligence"]),
                "triage_approval": len([t for t in tickets if t.get("current_stage") in {"triage_approval", "analyst_approval"}]),
                "investigation": len([t for t in tickets if t.get("current_stage") == "investigation"]),
                "investigation_approval": len([t for t in tickets if t.get("current_stage") in {"investigation_approval", "investigation_evidence_decision"}]),
                "reporting": len([t for t in tickets if t.get("current_stage") == "reporting"]),
                "soc_analyst_review": len([t for t in tickets if t.get("current_stage") == "soc_analyst_review"]),
                "case_closure": len([t for t in tickets if t.get("current_stage") == "case_closure" or _norm_status(t.get("status")) == "closed"]),
            },
            "scope": {"owner": owner or None, "ticket_count": len(tickets)},
        }

    def prepare_agent_inputs(self, ticket_id: str, inputs_dir: Path) -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        primary_alert = (ticket.get("related_alerts") or [{}])[0]

        # Keep the selected alert's raw payload intact. Do not overwrite the raw
        # alert_id, incident.id, title, event timestamps, or NetWitness event
        # fields with dashboard ticket metadata. Overwriting those fields caused
        # stale or wrong parser context to be reused across tickets.
        raw_alert = dict(primary_alert.get("raw") or {})
        raw_alert.setdefault("_ticket_context", {
            "ticket_id": ticket["ticket_id"],
            "ticket_title": ticket["title"],
            "ticket_severity": ticket["severity"],
            "ticket_confidence": ticket["confidence"],
            "primary_alert_id": primary_alert.get("alert_id"),
            "primary_alert_name": primary_alert.get("alert_name"),
            "affected_assets": ticket.get("affected_assets") or [],
            "affected_users": ticket.get("affected_users") or [],
        })

        # If the raw source is a very small/simple alert, add only missing
        # compatibility fields. For rich incident-with-alerts exports, the parser
        # reads the nested source-of-truth fields directly.
        raw_alert.setdefault("alert_id", primary_alert.get("alert_id"))
        raw_alert.setdefault("alert_name", primary_alert.get("alert_name"))
        raw_alert.setdefault("severity", ticket["severity"])
        if (ticket.get("affected_assets") or []) and not any(k in raw_alert for k in ("host", "hostname")):
            raw_alert["hostname"] = (ticket.get("affected_assets") or [""])[0]
        if (ticket.get("affected_users") or []) and not any(k in raw_alert for k in ("user", "username")):
            raw_alert["username"] = (ticket.get("affected_users") or [""])[0]
        raw_alert.setdefault("iocs", ticket.get("iocs") or primary_alert.get("iocs") or [])

        inputs_dir.mkdir(parents=True, exist_ok=True)
        grouped_context = {
            "ticket_id": ticket["ticket_id"],
            "incident_id": ticket.get("incident_id"),
            "primary_alert": primary_alert,
            "related_alerts": ticket.get("related_alerts") or [],
            "confirmed_alert_links": ticket.get("related_alerts") or [],
            "pending_correlation_recommendations": [r for r in (ticket.get("correlation_recommendations") or []) if _norm_status(r.get("status")) == "pending"],
            "analyst_grouping_history": ticket.get("correlation_history") or [],
            "affected_assets": ticket.get("affected_assets") or [],
            "affected_users": ticket.get("affected_users") or [],
            "combined_iocs": ticket.get("iocs") or [],
            "alert_count": len(ticket.get("related_alerts") or []),
        }
        raw_alert.setdefault("_grouped_incident_context", grouped_context)
        (inputs_dir / "raw_alert.json").write_text(json.dumps(raw_alert, indent=2, ensure_ascii=False), encoding="utf-8")
        (inputs_dir / "ticket_context.json").write_text(json.dumps(grouped_context, indent=2, ensure_ascii=False), encoding="utf-8")
        (inputs_dir / "grouped_incident_context.json").write_text(json.dumps(grouped_context, indent=2, ensure_ascii=False), encoding="utf-8")

        # Parser context is isolated per ticket so one selected ticket cannot
        # accidentally consume another ticket's stale inputs or outputs.
        project_root = inputs_dir.parent
        parsing_dir = project_root / "outputs" / ticket_id / "parsing"
        parsing_dir.mkdir(parents=True, exist_ok=True)
        (parsing_dir / "raw_input_alert.json").write_text(json.dumps(raw_alert, indent=2, ensure_ascii=False), encoding="utf-8")
        input_identity = extract_alert_identity(raw_alert)
        input_identity.update({"ticket_id": ticket_id, "primary_alert_id": primary_alert.get("alert_id")})
        (parsing_dir / "input_identity.json").write_text(json.dumps(input_identity, indent=2, ensure_ascii=False), encoding="utf-8")

        # Triage reads enriched_alert.json. Before external enrichment runs,
        # use the parser's processed alert as the best available context.
        parsing_result = ticket.get("parsing_result") or {}
        processed_alert = parsing_result.get("processed_alert") if isinstance(parsing_result, dict) else None
        if isinstance(processed_alert, dict) and processed_alert:
            (inputs_dir / "processed_alert.json").write_text(json.dumps(processed_alert, indent=2, ensure_ascii=False), encoding="utf-8")
            (inputs_dir / "enriched_alert.json").write_text(json.dumps(processed_alert, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            (inputs_dir / "enriched_alert.json").write_text(json.dumps(raw_alert, indent=2, ensure_ascii=False), encoding="utf-8")

        threat_intel = ticket.get("threat_intel_result") or {}
        enriched_from_ti = threat_intel.get("enriched_alert") if isinstance(threat_intel, dict) else None
        if isinstance(enriched_from_ti, dict) and enriched_from_ti:
            (inputs_dir / "threat_intel_result.json").write_text(json.dumps(threat_intel, indent=2, ensure_ascii=False), encoding="utf-8")
            (inputs_dir / "enriched_alert.json").write_text(json.dumps(enriched_from_ti, indent=2, ensure_ascii=False), encoding="utf-8")

        for key, filename in [
            ("parsing_result", "parser_result.json"),
            ("triage_result", "triage_result.json"),
            ("threat_intel_result", "threat_intel_result.json"),
            ("orchestration_decision_result", "orchestration_decision.json"),
            ("investigation_result", "investigation_result.json"),
            ("approval_result", "approval_result.json"),
            ("investigation_approval_result", "investigation_approval_result.json"),
            ("reporting_result", "final_report.json"),
            ("soc_review_result", "soc_review_result.json"),
        ]:
            if ticket.get(key):
                (inputs_dir / filename).write_text(json.dumps(ticket[key], indent=2, ensure_ascii=False), encoding="utf-8")
        return raw_alert


    def record_agent_run_start(
        self,
        run_id: str,
        ticket_id: str | None,
        agent_name: str,
        run_type: str = "run",
        triggered_by: str = "SOC Analyst",
        rerun_of_run_id: str | None = None,
        output_path: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        ts = now_iso()
        alert_id = None
        if ticket_id:
            ticket = self.get_ticket(ticket_id) or {}
            related = ticket.get("related_alerts") or []
            if related:
                alert_id = related[0].get("alert_id")
        payload = payload or {}
        with self.connect() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO agent_runs(
                    run_id, ticket_id, alert_id, agent_name, run_type, status, progress,
                    started_at, completed_at, duration_seconds, triggered_by, is_rerun,
                    rerun_of_run_id, output_path, error_code, error_message, ai_used,
                    ai_model, fallback_used, payload_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id, ticket_id, alert_id, agent_name, run_type, "running", 0,
                    ts, None, None, triggered_by, 1 if run_type == "rerun" else 0,
                    rerun_of_run_id, output_path, None, None, None, None, None, _json(payload),
                ),
            )
            con.commit()
        if ticket_id:
            self.append_activity(
                ticket_id,
                triggered_by,
                f"{agent_name}_{run_type}_started",
                "running",
                f"{agent_name.replace('_', ' ').title()} {run_type} started.",
                {"run_id": run_id, "agent": agent_name, "run_type": run_type, "rerun_of_run_id": rerun_of_run_id},
            )

    def record_agent_run_finish(
        self,
        run_id: str,
        status: str,
        progress: int = 100,
        output_path: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        output_summary: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        ts = now_iso()
        output_summary = output_summary or {}
        payload = payload or {}
        with self.connect() as con:
            row = con.execute("SELECT started_at, ticket_id, agent_name FROM agent_runs WHERE run_id=?", (run_id,)).fetchone()
            duration = None
            if row and row["started_at"]:
                try:
                    duration = (datetime.fromisoformat(ts) - datetime.fromisoformat(row["started_at"])).total_seconds()
                except Exception:
                    duration = None
            ai_used = output_summary.get("ai_used")
            fallback_used = output_summary.get("fallback_used")
            con.execute(
                """
                UPDATE agent_runs SET status=?, progress=?, completed_at=?, duration_seconds=?,
                    output_path=COALESCE(?, output_path), error_code=?, error_message=?,
                    ai_used=?, ai_model=?, fallback_used=?, payload_json=?
                WHERE run_id=?
                """,
                (
                    status, int(progress or 0), ts, duration, output_path, error_code, error_message,
                    None if ai_used is None else int(bool(ai_used)),
                    output_summary.get("ai_model") or output_summary.get("model"),
                    None if fallback_used is None else int(bool(fallback_used)),
                    _json({"output_summary": output_summary, **payload}),
                    run_id,
                ),
            )
            con.commit()
        if row and row["ticket_id"]:
            self.append_activity(
                row["ticket_id"],
                "System",
                f"{row['agent_name']}_run_finished",
                status,
                f"{row['agent_name'].replace('_', ' ').title()} run {run_id} finished with status {status}.",
                {"run_id": run_id, "output_path": output_path, "error": error_message},
            )

    def list_agent_runs(self, ticket_id: str, agent_name: str | None = None, limit: int = 25) -> list[dict[str, Any]]:
        clauses = ["ticket_id=?"]
        values: list[Any] = [ticket_id]
        if agent_name:
            clauses.append("agent_name=?")
            values.append(agent_name)
        values.append(int(limit))
        with self.connect() as con:
            rows = con.execute(
                f"SELECT * FROM agent_runs WHERE {' AND '.join(clauses)} ORDER BY started_at DESC LIMIT ?",
                values,
            ).fetchall()
        return [self._row_agent_run(row) for row in rows]

    def latest_agent_run(self, ticket_id: str, agent_name: str) -> dict[str, Any] | None:
        runs = self.list_agent_runs(ticket_id, agent_name, limit=1)
        return runs[0] if runs else None

    def _row_agent_run(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            return {}
        return {
            "run_id": row["run_id"],
            "ticket_id": row["ticket_id"],
            "alert_id": row["alert_id"],
            "agent_name": row["agent_name"],
            "run_type": row["run_type"],
            "status": row["status"],
            "progress": row["progress"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "duration_seconds": row["duration_seconds"],
            "triggered_by": row["triggered_by"],
            "is_rerun": bool(row["is_rerun"]),
            "rerun_of_run_id": row["rerun_of_run_id"],
            "output_path": row["output_path"],
            "error_code": row["error_code"],
            "error_message": row["error_message"],
            "ai_used": None if row["ai_used"] is None else bool(row["ai_used"]),
            "ai_model": row["ai_model"],
            "fallback_used": None if row["fallback_used"] is None else bool(row["fallback_used"]),
            "payload": _loads(row["payload_json"], {}),
        }

    def attach_agent_result(self, ticket_id: str, agent: str, data: dict[str, Any]) -> dict[str, Any]:
        data = data or {}
        fields: dict[str, Any] = {}
        status = _norm_status(data.get("status") or data.get("report_status"))
        agent_norm = _norm_status(agent)

        if agent_norm in {"parsing", "parsing_normalisation"}:
            fields["parsing_result"] = data
            processed = data.get("processed_alert") or {}
            normalised = data.get("normalised_alert") or processed.get("normalised_alert") or {}
            extracted = data.get("important_extracted_fields") or {}
            hosts = extracted.get("hosts") or normalised.get("user_and_host_indicators", {}).get("hostnames") or []
            users = extracted.get("users") or normalised.get("user_and_host_indicators", {}).get("all_usernames") or []
            iocs = processed.get("iocs") or []
            if hosts:
                fields["affected_assets"] = list(dict.fromkeys((self.get_ticket(ticket_id) or {}).get("affected_assets", []) + hosts))
            if users:
                fields["affected_users"] = list(dict.fromkeys((self.get_ticket(ticket_id) or {}).get("affected_users", []) + users))
            if iocs:
                fields["iocs"] = list((self.get_ticket(ticket_id) or {}).get("iocs", []) + iocs)
            fields["current_stage"] = "triage"
            fields["status"] = "Triage Required"
        elif agent_norm == "triage":
            fields["triage_result"] = data
            fields["severity"] = str(_first(data.get("severity"), data.get("classification"), default="Medium")).title()
            fields["confidence"] = str(_first(data.get("confidence"), data.get("confidence_level"), default="Medium")).title()
            fields["correlation_result"] = {}
            pending_after_triage = self.list_correlation_recommendations({"ticket_id": ticket_id, "status": "pending", "limit": 100})
            triage_pending = [r for r in pending_after_triage if _norm_status(r.get("source_stage")) in {"triage", "correlation", ""}]
            if data.get("requires_incident_grouping_review") or triage_pending:
                fields["current_stage"] = "triage_grouping_review"
                fields["status"] = "Incident Grouping Review Required"
            elif data.get("approval_required"):
                fields["current_stage"] = "triage_approval"
                fields["status"] = "Awaiting Approval"
            else:
                fields["current_stage"] = "threat_intelligence"
                fields["status"] = "Threat Intel Required"
        elif agent_norm == "orchestration":
            fields["orchestration_decision_result"] = data
        elif agent_norm == "correlation":
            fields["correlation_result"] = data
            if data.get("recommendation_count"):
                fields["current_stage"] = "incident_grouping_review"
                fields["status"] = "Incident Grouping Review Required"
        elif agent_norm in {"threat_intel", "threat_intelligence"}:
            fields["threat_intel_result"] = data
            enriched = data.get("enriched_alert") or {}
            if enriched.get("enrichment_risk_level"):
                fields["confidence"] = (self.get_ticket(ticket_id) or {}).get("confidence") or "Medium"
            fields["current_stage"] = "investigation"
            fields["status"] = "Investigation Required"
        elif agent_norm == "investigation":
            fields["investigation_result"] = data
            fields["correlation_result"] = {}
            # Investigation may now discover related alerts/tickets and prepare
            # analyst-approved grouping/archive recommendations. Do not move to
            # reporting approval until the analyst reviews those recommendations.
            if data.get("recommendation_count") or data.get("requires_incident_grouping_review") or data.get("requires_archive_approval"):
                fields["current_stage"] = "incident_grouping_review"
                fields["status"] = "Incident Grouping Review Required"
            elif status in {"failed", "execution_error", "timed_out", "error", "invalid_output", "missing_required_context"}:
                fields["current_stage"] = "investigation"
                fields["status"] = "Investigation Failed"
            elif status in {"needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "completed_with_evidence_gaps", "completed_limited"}:
                fields["current_stage"] = "investigation_evidence_decision"
                fields["status"] = "Evidence Gap Decision Required"
            else:
                fields["current_stage"] = "investigation_approval"
                fields["status"] = "Awaiting Approval"
        elif agent_norm == "reporting":
            fields["reporting_result"] = data
            fields["current_stage"] = "soc_analyst_review"
            fields["status"] = "Awaiting SOC Review"
        message = f"{agent.replace('_', ' ').title()} appended output to the ticket."
        return self.update_ticket(ticket_id, fields, actor=f"{agent.replace('_', ' ').title()}", action=f"{agent_norm}_updated", message=message)

    def record_evidence_gap_decision(self, ticket_id: str, decision: str, comments: str = "", analyst: str = "SOC Analyst") -> dict[str, Any]:
        """Record the explicit analyst branch for Investigation evidence gaps.

        The Investigation Agent may produce usable findings while still asking
        for more telemetry. The analyst must choose one of two paths:
        continue to Reporting with limitations, or return to Triage because
        Triage owns NetWitness API re-query/enrichment.
        """
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        inv = ticket.get("investigation_result") or {}
        triage_request = inv.get("triage_requery_request") if isinstance(inv, dict) else None
        if not isinstance(triage_request, dict):
            triage_request = {}
        decision_norm = _norm_status(decision)
        if decision_norm in {"continue", "continue_reporting", "continue_to_reporting", "reporting", "with_limitations"}:
            decision_norm = "continue_to_reporting"
        elif decision_norm in {"triage", "return", "return_to_triage", "more", "request_more_evidence", "more_evidence"}:
            decision_norm = "return_to_triage"
        else:
            raise ValueError("decision must be continue_to_reporting or return_to_triage")

        payload = {
            "decision": "approved" if decision_norm == "continue_to_reporting" else "return_to_triage",
            "status": "completed" if decision_norm == "continue_to_reporting" else "request_more_evidence",
            "evidence_gap_decision": decision_norm,
            "reporting_mode": "with_limitations",
            "comments": comments,
            "analyst": analyst,
            "approval_gate": "investigation_evidence_gap_decision",
            "missing_evidence": inv.get("missing_evidence") or inv.get("missing_fields") or [],
            "triage_requery_request": triage_request,
            "created_at": now_iso(),
        }

        fields: dict[str, Any] = {"investigation_approval_result": payload}
        if decision_norm == "continue_to_reporting":
            fields.update({"current_stage": "reporting", "status": "Ready for Report"})
            message = f"{analyst} chose to continue to Reporting Agent with investigation limitations documented."
            action = "evidence_gap_continue_to_reporting"
        else:
            existing_triage = ticket.get("triage_result") or {}
            if not isinstance(existing_triage, dict):
                existing_triage = {}
            triage_payload = dict(existing_triage)
            triage_payload.update({
                "status": "needs_more_evidence",
                "current_stage": "triage_requery_requested",
                "investigation_throwback": True,
                "triage_requery_request": triage_request,
                "missing_evidence": payload["missing_evidence"],
                "recommended_next_action": "Run Triage Agent again to collect the requested NetWitness evidence.",
                "updated_at": now_iso(),
            })
            fields.update({
                "triage_result": triage_payload,
                "current_stage": "triage",
                "status": "Needs Triage Evidence",
            })
            message = f"{analyst} returned the case to Triage Agent for more NetWitness evidence."
            action = "evidence_gap_return_to_triage"
        return self.update_ticket(ticket_id, fields, actor=analyst, action=action, message=message)

    def record_approval(self, ticket_id: str, decision: str, comments: str = "", analyst: str = "SOC Analyst", gate: str | None = None) -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        decision_norm = _norm_status(decision)
        stage = _norm_status(gate or ticket.get("current_stage"))
        is_investigation_gate = stage in {"investigation_approval", "investigation_review"}
        payload = {
            "decision": decision_norm,
            "status": "completed" if decision_norm in {"approved", "approve"} else decision_norm,
            "comments": comments,
            "analyst": analyst,
            "approval_gate": "investigation_approval" if is_investigation_gate else "triage_approval",
            "created_at": now_iso(),
        }
        fields: dict[str, Any] = {}
        if is_investigation_gate:
            fields["investigation_approval_result"] = payload
            if decision_norm in {"approved", "approve"}:
                fields.update({"current_stage": "reporting", "status": "Ready for Report"})
            elif decision_norm in {"rejected", "reject"}:
                fields.update({"current_stage": "case_closure", "status": "Closed"})
            else:
                fields.update({"current_stage": "investigation", "status": "Needs Investigation"})
        else:
            fields["approval_result"] = payload
            if decision_norm in {"approved", "approve"}:
                fields.update({"current_stage": "threat_intelligence", "status": "Threat Intel Required"})
            elif decision_norm in {"rejected", "reject"}:
                fields.update({"current_stage": "case_closure", "status": "Closed"})
            else:
                fields.update({"current_stage": "triage", "status": "Triage Required"})
        return self.update_ticket(ticket_id, fields, actor=analyst, action=f"approval_{decision_norm}", message=f"{analyst} recorded {payload['approval_gate']} decision: {decision_norm}.")

    def record_soc_review(self, ticket_id: str, decision: str = "confirmed", comments: str = "", analyst: str = "SOC Analyst") -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        decision_norm = _norm_status(decision or "confirmed")
        payload = {
            "decision": decision_norm,
            "status": "completed" if decision_norm in {"confirmed", "approved", "approve"} else decision_norm,
            "comments": comments,
            "analyst": analyst,
            "review_gate": "soc_analyst_review",
            "created_at": now_iso(),
        }
        fields: dict[str, Any] = {"soc_review_result": payload}
        if decision_norm in {"confirmed", "approved", "approve"}:
            fields.update({"current_stage": "case_closure", "status": "Ready for Closure"})
        elif decision_norm in {"rejected", "reject"}:
            fields.update({"current_stage": "reporting", "status": "Ready for Report"})
        else:
            fields.update({"current_stage": "soc_analyst_review", "status": "Awaiting SOC Review"})
        return self.update_ticket(ticket_id, fields, actor=analyst, action=f"soc_review_{decision_norm}", message=f"{analyst} recorded SOC analyst review decision: {decision_norm}.")

    def reports_for_ticket(self, ticket_id: str) -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        return {
            "ticket_id": ticket_id,
            "reporting_result": ticket.get("reporting_result") or {},
            "reports": [
                {"key": "executive_summary", "title": "Executive Summary", "status": "available" if ticket.get("reporting_result") else "not_ready"},
                {"key": "technical_findings", "title": "Technical Findings", "status": "available" if ticket.get("reporting_result") else "not_ready"},
                {"key": "soc_analyst_review", "title": "SOC Analyst Review", "status": "available" if ticket.get("reporting_result") else "not_ready"},
                {"key": "final_incident_report", "title": "Final Incident Report", "status": "available" if ticket.get("reporting_result") else "not_ready"},
            ],
        }

    def _row_alert(self, row: sqlite3.Row) -> dict[str, Any]:
        with self.connect() as con:
            linked = con.execute("SELECT ticket_id FROM ticket_alerts WHERE alert_id=? ORDER BY linked_at DESC LIMIT 1", (row["alert_id"],)).fetchone()
        return {
            "alert_id": row["alert_id"],
            "alert_name": row["alert_name"],
            "source": row["source"],
            "severity": row["severity"],
            "status": row["status"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "hostname": row["hostname"],
            "username": row["username"],
            "iocs": _loads(row["iocs_json"], []),
            "raw": _loads(row["raw_json"], {}),
            "netwitness_url": row["netwitness_url"],
            "linked_ticket": linked["ticket_id"] if linked else None,
            "updated_at": row["updated_at"],
        }

    def _row_activity(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ticket_id": row["ticket_id"],
            "actor": row["actor"],
            "action": row["action"],
            "status": row["status"],
            "message": row["message"],
            "payload": _loads(row["payload_json"], {}),
            "created_at": row["created_at"],
        }

    def _row_ticket(self, row: sqlite3.Row, include_children: bool = False) -> dict[str, Any]:
        ticket = {
            "ticket_id": row["ticket_id"],
            "incident_id": row["incident_id"] if "incident_id" in row.keys() else None,
            "title": row["title"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "status": row["status"],
            "owner": row["owner"],
            "current_stage": row["current_stage"],
            "affected_assets": _loads(row["affected_assets_json"], []),
            "affected_users": _loads(row["affected_users_json"], []),
            "iocs": _loads(row["iocs_json"], []),
            "parsing_result": _loads(row["parsing_result_json"], {}),
            "triage_result": _loads(row["triage_result_json"], {}),
            "threat_intel_result": _loads(row["threat_intel_result_json"], {}),
            "orchestration_decision_result": _loads(row["orchestration_decision_result_json"], {}),
            "correlation_result": _loads(row["correlation_result_json"], {}) if "correlation_result_json" in row.keys() else {},
            "investigation_result": _loads(row["investigation_result_json"], {}),
            "approval_result": _loads(row["approval_result_json"], {}),
            "investigation_approval_result": _loads(row["investigation_approval_result_json"], {}),
            "reporting_result": _loads(row["reporting_result_json"], {}),
            "soc_review_result": _loads(row["soc_review_result_json"], {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "closed_at": row["closed_at"],
            "archive_status": row["archive_status"] if "archive_status" in row.keys() else "active",
            "merged_into_ticket_id": row["merged_into_ticket_id"] if "merged_into_ticket_id" in row.keys() else None,
            "archived_by": row["archived_by"] if "archived_by" in row.keys() else None,
            "archived_at": row["archived_at"] if "archived_at" in row.keys() else None,
            "archive_reason": row["archive_reason"] if "archive_reason" in row.keys() else "",
        }
        with self.connect() as con:
            count = con.execute("SELECT COUNT(*) AS c FROM ticket_alerts WHERE ticket_id=?", (ticket["ticket_id"],)).fetchone()["c"]
        ticket["alert_count"] = count
        if include_children:
            with self.connect() as con:
                rows = con.execute(
                    """
                    SELECT a.*, ta.relationship, ta.status AS link_status, ta.linked_at,
                           ta.linked_by, ta.link_source, ta.correlation_score, ta.link_reason, ta.confirmed_by, ta.confirmed_at
                    FROM ticket_alerts ta JOIN alerts a ON a.alert_id=ta.alert_id
                    WHERE ta.ticket_id=?
                    ORDER BY ta.linked_at
                    """,
                    (ticket["ticket_id"],),
                ).fetchall()
            related = []
            for alert_row in rows:
                alert = self._row_alert(alert_row)
                alert["relationship"] = alert_row["relationship"]
                alert["link_status"] = alert_row["link_status"]
                alert["linked_at"] = alert_row["linked_at"]
                alert["linked_by"] = alert_row["linked_by"] if "linked_by" in alert_row.keys() else None
                alert["link_source"] = alert_row["link_source"] if "link_source" in alert_row.keys() else None
                alert["correlation_score"] = alert_row["correlation_score"] if "correlation_score" in alert_row.keys() else None
                alert["link_reason"] = alert_row["link_reason"] if "link_reason" in alert_row.keys() else None
                alert["confirmed_by"] = alert_row["confirmed_by"] if "confirmed_by" in alert_row.keys() else None
                alert["confirmed_at"] = alert_row["confirmed_at"] if "confirmed_at" in alert_row.keys() else None
                related.append(alert)
            ticket["related_alerts"] = related
            ticket["activity_log"] = self.activity(ticket["ticket_id"])
            ticket["correlation_recommendations"] = self.list_correlation_recommendations({"ticket_id": ticket["ticket_id"], "limit": 50})
            ticket["pending_correlation_count"] = len([r for r in ticket["correlation_recommendations"] if _norm_status(r.get("status")) == "pending"])
            ticket["correlation_history"] = [r for r in ticket["correlation_recommendations"] if _norm_status(r.get("status")) != "pending"]
        return ticket
