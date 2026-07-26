from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from backend import stage_workflow
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


class PostgresUnavailableError(RuntimeError):
    """Raised when PostgreSQL is required but unavailable."""

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": "failed_postgres_unavailable",
            "message": "PostgreSQL is required. SQLite fallback is disabled.",
            "reporting_mode": "blocked",
            "error": str(self),
        }


def postgres_required_payload(message: str | None = None) -> dict[str, Any]:
    return {
        "status": "failed_postgres_unavailable",
        "message": message or "PostgreSQL is required. SQLite fallback is disabled.",
        "reporting_mode": "blocked",
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> Json:
    return Json(value if value is not None else {})


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
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


def _row_keys(row: Any) -> set[str]:
    if not row:
        return set()
    if isinstance(row, dict):
        return set(row.keys())
    try:
        return set(row.keys())
    except Exception:
        return set()


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


class PostgresCaseworkStore:
    def __init__(self, dsn: str | None = None, initialise: bool = True):
        self.dsn = (dsn or os.getenv("POSTGRES_DSN") or os.getenv("REPORTING_POSTGRES_DSN") or self._dsn_from_parts() or "").strip()
        if not self.dsn:
            raise PostgresUnavailableError("POSTGRES_DSN is not configured.")
        if initialise:
            self.init_db()

    @staticmethod
    def _dsn_from_parts() -> str:
        host = os.getenv("POSTGRES_HOST")
        db = os.getenv("POSTGRES_DB")
        user = os.getenv("POSTGRES_USER")
        if not (host and db and user):
            return ""
        port = os.getenv("POSTGRES_PORT", "5432")
        password = os.getenv("POSTGRES_PASSWORD", "")
        auth = f"{user}:{password}" if password else user
        return f"postgresql://{auth}@{host}:{port}/{db}"

    def connect(self):
        try:
            return psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
        except Exception as exc:
            raise PostgresUnavailableError(str(exc)) from exc

    def healthcheck(self) -> bool:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            row = cur.fetchone()
        return bool(row and row.get("ok") == 1)

    def init_db(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "database" / "postgres_schema.sql"
        try:
            with self.connect() as con, con.cursor() as cur:
                cur.execute(schema_path.read_text(encoding="utf-8"))
                con.commit()
        except PostgresUnavailableError:
            raise
        except Exception as exc:
            raise PostgresUnavailableError(f"PostgreSQL schema initialisation failed: {exc}") from exc

    def _next_counter(self, name: str) -> int:
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                """
                INSERT INTO counters(name, value) VALUES (%s, 1)
                ON CONFLICT (name) DO UPDATE SET value = counters.value + 1
                RETURNING value
                """,
                (name,),
            )
            value = int(cur.fetchone()["value"])
            con.commit()
        return value

    def _next_ticket_id(self) -> str:
        return f"TKT-{datetime.now(timezone.utc).year}-{self._next_counter('ticket'):05d}"

    def _next_incident_id(self) -> str:
        return f"INC-{datetime.now(timezone.utc).year}-{self._next_counter('incident'):05d}"

    def next_triage_unc(self) -> str:
        value = self._next_counter("triage_unc_number") - 1
        number = value % 100000
        suffix_index = value // 100000
        letters = ""
        while True:
            letters = chr(ord("A") + (suffix_index % 26)) + letters
            suffix_index = suffix_index // 26 - 1
            if suffix_index < 0:
                break
        return f"#{number:05d}{letters}"

    def upsert_alert(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        alert = normalise_alert(raw_alert)
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts(alert_id, alert_name, source, severity, status, first_seen, last_seen, hostname, username, iocs_json, raw_json, netwitness_url, updated_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (alert_id) DO UPDATE SET
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
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE alert_id=%s", (alert_id,))
            row = cur.fetchone()
        return self._row_alert(row) if row else None

    def list_alerts(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        clauses: list[str] = []
        values: list[Any] = []
        for field in ("severity", "status"):
            if filters.get(field):
                clauses.append(f"LOWER({field}) = %s")
                values.append(str(filters[field]).lower())
        if filters.get("q"):
            clauses.append("(LOWER(alert_id) LIKE %s OR LOWER(alert_name) LIKE %s OR LOWER(hostname) LIKE %s)")
            q = f"%{str(filters['q']).lower()}%"
            values.extend([q, q, q])
        if filters.get("hostname"):
            clauses.append("LOWER(hostname) LIKE %s")
            values.append(f"%{str(filters['hostname']).lower()}%")
        sql = "SELECT * FROM alerts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY COALESCE(last_seen, first_seen, updated_at) DESC LIMIT %s"
        values.append(int(filters.get("limit") or 200))
        with self.connect() as con, con.cursor() as cur:
            cur.execute(sql, values)
            rows = cur.fetchall()
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
        ticket_id = self._next_ticket_id()
        incident_id = self._next_incident_id()
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tickets(ticket_id, incident_id, title, severity, confidence, status, owner, current_stage, affected_assets_json,
                    affected_users_json, iocs_json, parsing_result_json, triage_result_json, threat_intel_result_json,
                    orchestration_decision_result_json, correlation_result_json, investigation_result_json, approval_result_json, investigation_approval_result_json,
                    reporting_result_json, soc_review_result_json, archive_status, merged_into_ticket_id, archived_by, archived_at, archive_reason, created_at, updated_at, closed_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    ticket_id, incident_id, alert["alert_name"], alert["severity"], "Unknown", status or "To Parse", owner, "parsing_normalisation",
                    _json(assets), _json(users), _json(alert.get("iocs") or []), _json({}), _json({}), _json({}),
                    _json({}), _json({}), _json({}), _json({}), _json({}), _json({}), _json({}),
                    "active", None, None, None, "", ts, ts, None,
                ),
            )
            cur.execute(
                "INSERT INTO incidents(incident_id, title, status, severity, confidence, created_at, updated_at, closed_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (incident_id) DO NOTHING",
                (incident_id, alert["alert_name"], "Open", alert["severity"], "Unknown", ts, ts, None),
            )
            cur.execute(
                """
                INSERT INTO ticket_alerts(ticket_id, alert_id, relationship, status, linked_at, linked_by, link_source, correlation_score, link_reason, confirmed_by, confirmed_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (ticket_id, alert_id) DO UPDATE SET relationship=excluded.relationship, status=excluded.status
                """,
                (ticket_id, alert_id, "Primary alert", "In Ticket", ts, "system", "ticket_creation", 100, "Primary alert that created the ticket.", "System", ts),
            )
            con.commit()
        self.append_activity(ticket_id, "System", "ticket_created", "completed", f"Created ticket from NetWitness alert {alert_id}.", {"alert_id": alert_id})
        return self.get_ticket(ticket_id) or {}

    def ticket_for_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT ticket_id FROM ticket_alerts WHERE alert_id=%s ORDER BY linked_at DESC LIMIT 1", (alert_id,))
            row = cur.fetchone()
        return self.get_ticket(row["ticket_id"]) if row else None

    def link_alert(
        self,
        ticket_id: str,
        alert_id: str,
        relationship: str = "Related alert",
        linked_by: str = "SOC Analyst",
        link_source: str = "manual",
        correlation_score: int = 0,
        link_reason: str = "",
        confirmed_by: str | None = None,
    ) -> dict[str, Any]:
        if not self.get_ticket(ticket_id):
            raise KeyError(f"Ticket {ticket_id} not found")
        if not self.get_alert(alert_id):
            raise KeyError(f"Alert {alert_id} not found")
        ts = now_iso()
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ticket_alerts(ticket_id, alert_id, relationship, status, linked_at, linked_by, link_source, correlation_score, link_reason, confirmed_by, confirmed_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (ticket_id, alert_id) DO UPDATE SET
                    relationship=excluded.relationship,
                    status=excluded.status,
                    linked_by=excluded.linked_by,
                    link_source=excluded.link_source,
                    correlation_score=excluded.correlation_score,
                    link_reason=excluded.link_reason,
                    confirmed_by=excluded.confirmed_by,
                    confirmed_at=excluded.confirmed_at
                """,
                (ticket_id, alert_id, relationship, "In Ticket", ts, linked_by, link_source, int(correlation_score or 0), link_reason or relationship, confirmed_by, ts if confirmed_by else None),
            )
            con.commit()
        self.append_activity(ticket_id, linked_by, "alert_linked", "completed", f"Linked alert {alert_id}: {relationship}", {"alert_id": alert_id, "relationship": relationship, "link_source": link_source, "correlation_score": correlation_score, "link_reason": link_reason})
        self.mark_context_refresh_required(ticket_id, reason=f"Alert {alert_id} was linked to this ticket.", actor=linked_by)
        return self.get_ticket(ticket_id) or {}

    def unlink_alert(self, ticket_id: str, alert_id: str, analyst: str = "SOC Analyst", reason: str = "Removed from incident ticket") -> dict[str, Any]:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("DELETE FROM ticket_alerts WHERE ticket_id=%s AND alert_id=%s", (ticket_id, alert_id))
            con.commit()
        self.append_activity(ticket_id, analyst, "alert_unlinked", "completed", f"Unlinked alert {alert_id}.", {"alert_id": alert_id, "reason": reason})
        self.mark_context_refresh_required(ticket_id, reason=f"Alert {alert_id} was removed from this ticket.", actor=analyst)
        return self.get_ticket(ticket_id) or {}

    def mark_downstream_refresh_required(self, ticket_id: str, agent_name: str, reason: str, actor: str = "System") -> None:
        ticket = self.get_ticket(ticket_id) or {}
        order = ["parsing", "triage", "threat_intel", "investigation", "reporting"]
        clear_map = {
            "parsing": ["triage_result", "threat_intel_result", "investigation_result", "reporting_result"],
            "triage": ["investigation_result", "reporting_result"],
            "threat_intel": ["triage_result", "investigation_result", "reporting_result"],
            "investigation": ["reporting_result"],
            "reporting": [],
        }
        agent_norm = _norm_status(agent_name)
        fields: dict[str, Any] = {}
        for key in clear_map.get(agent_norm, []):
            current = ticket.get(key) or {}
            if isinstance(current, dict) and current:
                patched = dict(current)
                patched.update({"context_refresh_required": True, "context_refresh_reason": reason, "updated_at": now_iso()})
                fields[key] = patched
        if fields:
            self.update_ticket(ticket_id, fields, actor=actor, action="downstream_refresh_required", message=reason)

    def mark_context_refresh_required(self, ticket_id: str, reason: str, actor: str = "System") -> None:
        ticket = self.get_ticket(ticket_id) or {}
        fields: dict[str, Any] = {}
        for key in ("investigation_result", "reporting_result"):
            current = ticket.get(key) or {}
            if isinstance(current, dict) and current:
                patched = dict(current)
                patched.update({"context_refresh_required": True, "context_refresh_reason": reason, "updated_at": now_iso()})
                fields[key] = patched
        if fields:
            self.update_ticket(ticket_id, fields, actor=actor, action="context_refresh_required", message=reason)

    def create_correlation_recommendation(self, recommendation: dict[str, Any]) -> dict[str, Any]:
        rec = dict(recommendation or {})
        rec_id = rec.get("recommendation_id") or f"CORR-{uuid.uuid4().hex[:10].upper()}"
        target_ticket_id = rec.get("target_ticket_id")
        source_alert_id = rec.get("source_alert_id")
        rec_type = rec.get("recommendation_type") or "add_alert_to_existing_ticket"
        ts = rec.get("created_at") or now_iso()
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM correlation_recommendations
                WHERE source_alert_id=%s AND target_ticket_id=%s AND recommendation_type=%s AND status='pending'
                ORDER BY created_at DESC LIMIT 1
                """,
                (source_alert_id, target_ticket_id, rec_type),
            )
            existing = cur.fetchone()
            if existing:
                return self._row_correlation_recommendation(existing)
            cur.execute(
                """
                INSERT INTO correlation_recommendations(recommendation_id, recommendation_type, source_alert_id, target_alert_id,
                    source_ticket_id, target_ticket_id, target_incident_id, confidence, score, matched_fields_json, reason, status,
                    created_by, created_at, reviewed_by, reviewed_at, analyst_comments, source_stage, requires_archive_approval,
                    archive_status, archive_action_json, recommended_by_agent, payload_json)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    rec_id, rec_type, source_alert_id, rec.get("target_alert_id"), rec.get("source_ticket_id"), target_ticket_id,
                    rec.get("target_incident_id"), rec.get("confidence") or "Medium", int(rec.get("score") or 0), _json(rec.get("matched_fields") or []),
                    rec.get("reason") or "Potentially related alert.", rec.get("status") or "pending", rec.get("created_by") or "Incident Grouping",
                    ts, rec.get("reviewed_by"), rec.get("reviewed_at"), rec.get("analyst_comments"), rec.get("source_stage") or "correlation",
                    bool(rec.get("requires_archive_approval") or rec.get("archive_after_approval")),
                    rec.get("archive_status") or ("pending_analyst_approval" if rec.get("requires_archive_approval") or rec.get("archive_after_approval") else "not_required"),
                    _json(rec.get("archive_action") or rec.get("archive_action_json") or {}),
                    rec.get("recommended_by_agent") or rec.get("created_by") or "Incident Grouping",
                    _json(rec),
                ),
            )
            con.commit()
        if target_ticket_id:
            self.append_activity(target_ticket_id, rec.get("created_by") or "Incident Grouping", "correlation_recommended", "pending", f"Recommended linking alert {source_alert_id} to this ticket.", rec)
        return self.get_correlation_recommendation(rec_id) or rec

    def get_correlation_recommendation(self, recommendation_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM correlation_recommendations WHERE recommendation_id=%s", (recommendation_id,))
            row = cur.fetchone()
        return self._row_correlation_recommendation(row) if row else None

    def list_correlation_recommendations(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        clauses: list[str] = []
        values: list[Any] = []
        if filters.get("ticket_id"):
            clauses.append("(target_ticket_id=%s OR source_ticket_id=%s)")
            values.extend([filters["ticket_id"], filters["ticket_id"]])
        if filters.get("status"):
            clauses.append("LOWER(status)=%s")
            values.append(str(filters["status"]).lower())
        sql = "SELECT * FROM correlation_recommendations"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC LIMIT %s"
        values.append(int(filters.get("limit") or 100))
        with self.connect() as con, con.cursor() as cur:
            cur.execute(sql, values)
            rows = cur.fetchall()
        return [self._row_correlation_recommendation(row) for row in rows]

    def confirm_correlation_recommendation(self, recommendation_id: str, analyst: str = "SOC Analyst", comments: str = "") -> dict[str, Any]:
        rec = self.get_correlation_recommendation(recommendation_id)
        if not rec:
            raise KeyError(f"Recommendation {recommendation_id} not found")
        target_ticket_id = rec.get("target_ticket_id")
        source_alert_id = rec.get("source_alert_id")
        if source_alert_id and target_ticket_id:
            if not self.get_alert(source_alert_id):
                payload = rec.get("payload") or {}
                if payload.get("candidate_alert"):
                    self.upsert_alert(payload["candidate_alert"])
            self.link_alert(
                target_ticket_id,
                source_alert_id,
                relationship=rec.get("reason") or "Confirmed related alert",
                linked_by=analyst,
                link_source="analyst_confirmed_correlation",
                correlation_score=int(rec.get("score") or 0),
                link_reason=comments or rec.get("reason") or "Analyst confirmed correlation.",
                confirmed_by=analyst,
            )
        if rec.get("archive_after_approval") and rec.get("source_ticket_id") and target_ticket_id:
            self.archive_duplicate_ticket(rec["source_ticket_id"], target_ticket_id, analyst=analyst, reason=comments or rec.get("reason") or "Analyst approved duplicate archive.")
        ts = now_iso()
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                "UPDATE correlation_recommendations SET status='confirmed', reviewed_by=%s, reviewed_at=%s, analyst_comments=%s WHERE recommendation_id=%s",
                (analyst, ts, comments, recommendation_id),
            )
            con.commit()
        if target_ticket_id:
            self.append_activity(target_ticket_id, analyst, "correlation_confirmed", "completed", f"Confirmed correlation recommendation {recommendation_id}.", {"recommendation_id": recommendation_id, "comments": comments})
        return {"recommendation": self.get_correlation_recommendation(recommendation_id), "ticket": self.get_ticket(target_ticket_id) if target_ticket_id else None}

    def reject_correlation_recommendation(self, recommendation_id: str, analyst: str = "SOC Analyst", comments: str = "") -> dict[str, Any]:
        rec = self.get_correlation_recommendation(recommendation_id)
        if not rec:
            raise KeyError(f"Recommendation {recommendation_id} not found")
        ts = now_iso()
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                "UPDATE correlation_recommendations SET status='rejected', reviewed_by=%s, reviewed_at=%s, analyst_comments=%s WHERE recommendation_id=%s",
                (analyst, ts, comments, recommendation_id),
            )
            con.commit()
        if rec.get("target_ticket_id"):
            self.append_activity(rec["target_ticket_id"], analyst, "correlation_rejected", "completed", f"Rejected correlation recommendation {recommendation_id}.", {"recommendation_id": recommendation_id, "comments": comments})
        return self.get_correlation_recommendation(recommendation_id) or rec

    def edit_correlation_recommendation(self, recommendation_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", comments: str = "") -> dict[str, Any]:
        rec = self.get_correlation_recommendation(recommendation_id)
        if not rec:
            raise KeyError(f"Recommendation {recommendation_id} not found")
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                "UPDATE correlation_recommendations SET target_ticket_id=%s, analyst_comments=%s WHERE recommendation_id=%s",
                (target_ticket_id, comments, recommendation_id),
            )
            con.commit()
        self.append_activity(target_ticket_id, analyst, "correlation_edited", "completed", f"Edited recommendation {recommendation_id}.", {"recommendation_id": recommendation_id, "comments": comments})
        return self.get_correlation_recommendation(recommendation_id) or rec

    def move_alert_to_ticket(self, alert_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Manual alert move") -> dict[str, Any]:
        current = self.ticket_for_alert(alert_id)
        if current:
            with self.connect() as con, con.cursor() as cur:
                cur.execute("DELETE FROM ticket_alerts WHERE alert_id=%s", (alert_id,))
                con.commit()
        return self.link_alert(target_ticket_id, alert_id, relationship=reason, linked_by=analyst, link_source="manual_move", link_reason=reason, confirmed_by=analyst)

    def split_alert_to_new_ticket(self, ticket_id: str, alert_id: str, analyst: str = "SOC Analyst", reason: str = "Split alert into a separate incident") -> dict[str, Any]:
        self.unlink_alert(ticket_id, alert_id, analyst=analyst, reason=reason)
        new_ticket = self.create_ticket_from_alert(alert_id, owner=analyst, status="To Parse")
        self.append_activity(new_ticket["ticket_id"], analyst, "alert_split_to_new_ticket", "completed", reason, {"source_ticket_id": ticket_id, "alert_id": alert_id})
        return new_ticket

    def archive_duplicate_ticket(self, source_ticket_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Archived as duplicate after analyst approval") -> dict[str, Any]:
        return self.update_ticket(
            source_ticket_id,
            {
                "archive_status": "archived_duplicate",
                "merged_into_ticket_id": target_ticket_id,
                "archived_by": analyst,
                "archived_at": now_iso(),
                "archive_reason": reason,
                "status": "Archived Duplicate",
                "current_stage": "case_closure",
            },
            actor=analyst,
            action="ticket_archived_duplicate",
            message=f"Archived as duplicate of {target_ticket_id}. {reason}",
        )

    def merge_tickets(self, source_ticket_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Manual ticket merge", archive_duplicate: bool = True) -> dict[str, Any]:
        source = self.get_ticket(source_ticket_id)
        target = self.get_ticket(target_ticket_id)
        if not source or not target:
            raise KeyError("Source or target ticket not found")
        for alert in source.get("related_alerts") or []:
            self.link_alert(target_ticket_id, alert["alert_id"], relationship=reason, linked_by=analyst, link_source="ticket_merge", link_reason=reason, confirmed_by=analyst)
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

    def list_tickets(self, filters: dict[str, Any] | None = None, include_archived: bool | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        if include_archived is not None:
            filters = {**filters, "include_archived": include_archived}
        clauses: list[str] = []
        values: list[Any] = []
        if filters.get("status"):
            clauses.append("LOWER(status) = %s")
            values.append(str(filters["status"]).lower().replace("_", " "))
        if filters.get("stage"):
            clauses.append("current_stage = %s")
            values.append(str(filters["stage"]))
        if filters.get("severity"):
            clauses.append("LOWER(severity) = %s")
            values.append(str(filters["severity"]).lower())
        if filters.get("owner") == "me":
            clauses.append("LOWER(owner) = %s")
            values.append("soong yang")
        elif _norm_status(filters.get("owner")) == "unassigned":
            clauses.append("LOWER(COALESCE(owner, '')) IN ('', 'unassigned', 'none')")
        elif filters.get("owner"):
            clauses.append("LOWER(owner) = %s")
            values.append(str(filters["owner"]).lower())
        if filters.get("q"):
            clauses.append("(LOWER(ticket_id) LIKE %s OR LOWER(title) LIKE %s)")
            q = f"%{str(filters['q']).lower()}%"
            values.extend([q, q])
        if filters.get("open_only"):
            clauses.append("LOWER(status) NOT IN ('closed', 'archived duplicate')")
            clauses.append("COALESCE(archive_status, 'active') = 'active'")
        elif filters.get("include_archived") is False:
            clauses.append("COALESCE(archive_status, 'active') = 'active'")
        sql = "SELECT * FROM tickets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT %s"
        values.append(int(filters.get("limit") or 200))
        with self.connect() as con, con.cursor() as cur:
            cur.execute(sql, values)
            rows = cur.fetchall()
        return [self._row_ticket(row, include_children=False) for row in rows]

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM tickets WHERE ticket_id=%s", (ticket_id,))
            row = cur.fetchone()
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
            assignments.append(f"{column}=%s")
            values.append(value)
        if not assignments:
            return self.get_ticket(ticket_id) or {}
        if fields.get("status") == "Closed":
            assignments.append("closed_at=%s")
            values.append(now_iso())
        assignments.append("updated_at=%s")
        values.append(now_iso())
        values.append(ticket_id)
        with self.connect() as con, con.cursor() as cur:
            cur.execute(f"UPDATE tickets SET {', '.join(assignments)} WHERE ticket_id=%s", values)
            cur.execute(
                """
                INSERT INTO workflow_state(ticket_id, current_stage, status, next_required_approval, payload_json, updated_at)
                VALUES(%s,%s,%s,%s,%s,%s)
                ON CONFLICT (ticket_id) DO UPDATE SET
                    current_stage=excluded.current_stage,
                    status=excluded.status,
                    next_required_approval=excluded.next_required_approval,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    ticket_id,
                    fields.get("current_stage") or (self.get_ticket(ticket_id) or {}).get("current_stage") or "",
                    fields.get("status") or (self.get_ticket(ticket_id) or {}).get("status") or "",
                    fields.get("next_required_approval"),
                    _json(fields),
                    now_iso(),
                ),
            )
            con.commit()
        self.append_activity(ticket_id, actor, action, "completed", message or f"{actor} updated ticket.", fields)
        return self.get_ticket(ticket_id) or {}

    def append_activity(self, ticket_id: str, actor: str, action: str, status: str, message: str, payload: Any | None = None) -> dict[str, Any]:
        ts = now_iso()
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                "INSERT INTO activity(ticket_id, actor, action, status, message, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (ticket_id, actor, action, status, message, _json(payload or {}), ts),
            )
            row = cur.fetchone()
            cur.execute("UPDATE tickets SET updated_at=%s WHERE ticket_id=%s", (ts, ticket_id))
            con.commit()
        return {"id": row["id"] if row else None, "ticket_id": ticket_id, "actor": actor, "action": action, "status": status, "message": message, "payload": payload or {}, "created_at": ts}

    def activity(self, ticket_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM activity WHERE ticket_id=%s ORDER BY id DESC LIMIT %s", (ticket_id, limit))
            rows = cur.fetchall()
        return [self._row_activity(row) for row in rows]

    def dashboard_summary(self, owner: str | None = None) -> dict[str, Any]:
        tickets = self.list_tickets({"limit": 500})
        alerts = self.list_alerts({"limit": 500})
        if owner:
            owner_key = _norm_status(owner)
            tickets = [t for t in tickets if _norm_status(t.get("owner")) == owner_key]
        open_tickets = [t for t in tickets if _norm_status(t["status"]) != "closed"]
        pending_correlation = self.list_correlation_recommendations({"status": "pending", "limit": 1000})
        stage_counts = {
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
        }
        return {
            "pending_correlation": len(pending_correlation),
            "new_alerts": len([a for a in alerts if _norm_status(a.get("status")) in {"new", "open"}]),
            "open_tickets": len(open_tickets),
            "critical_cases": len([t for t in open_tickets if _norm_status(t.get("severity")) == "critical"]),
            "pending_approval": len([t for t in tickets if t.get("current_stage") in {"triage_approval", "investigation_approval", "investigation_evidence_decision", "soc_analyst_review", "analyst_approval"} or _norm_status(t.get("status")) in {"awaiting_approval", "awaiting_soc_review"}]),
            "unassigned_cases": len([t for t in open_tickets if _norm_status(t.get("owner")) in {"", "unassigned", "none"}]),
            "multi_alert_cases": len([t for t in tickets if int(t.get("alert_count") or 0) > 1]),
            "closed_cases": len([t for t in tickets if _norm_status(t.get("status")) == "closed"]),
            "stage_counts": stage_counts,
            "scope": {"owner": owner or None, "ticket_count": len(tickets)},
        }

    def prepare_agent_inputs(self, ticket_id: str, inputs_dir: Path) -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        inputs_dir.mkdir(parents=True, exist_ok=True)
        raw_alert = (ticket.get("related_alerts") or [{}])[0].get("raw") or {}
        valid_parsing = ticket.get("parsing_result") if stage_workflow.output_valid(ticket, "parsing") else {}
        valid_triage = ticket.get("triage_result") if stage_workflow.output_valid(ticket, "triage") else {}
        valid_threat = ticket.get("threat_intel_result") if stage_workflow.output_valid(ticket, "threat_intel") else {}
        valid_investigation = ticket.get("investigation_result") if stage_workflow.output_valid(ticket, "investigation") else {}
        valid_reporting = ticket.get("reporting_result") if stage_workflow.output_valid(ticket, "reporting") else {}
        files = {
            "ticket_context.json": ticket,
            "raw_alert.json": raw_alert,
            "processed_alert.json": valid_parsing or {},
            "parser_result.json": valid_parsing or {},
            "triage_result.json": valid_triage or {},
            "threat_intel_result.json": valid_threat or {},
            "enriched_alert.json": (valid_threat or {}).get("enriched_alert") or {},
            "investigation_result.json": valid_investigation or {},
            "approval_result.json": ticket.get("approval_result") or {},
            "investigation_approval_result.json": ticket.get("investigation_approval_result") or {},
            "reporting_result.json": valid_reporting or {},
        }
        for filename, payload in files.items():
            path = inputs_dir / filename
            if payload:
                path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            elif path.exists() and filename not in {"ticket_context.json", "raw_alert.json"}:
                path.unlink()
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
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                """
                INSERT INTO agent_runs(run_id, ticket_id, alert_id, agent_name, run_type, status, progress,
                    started_at, completed_at, duration_seconds, triggered_by, is_rerun, rerun_of_run_id,
                    output_path, error_code, error_message, ai_used, ai_model, fallback_used, payload_json)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (run_id) DO UPDATE SET status=excluded.status, progress=excluded.progress, payload_json=excluded.payload_json
                """,
                (
                    run_id, ticket_id, alert_id, agent_name, run_type, "running", 0,
                    ts, None, None, triggered_by, run_type == "rerun", rerun_of_run_id,
                    output_path, None, None, None, None, None, _json(payload),
                ),
            )
            con.commit()
        if ticket_id:
            self.append_activity(ticket_id, triggered_by, f"{agent_name}_{run_type}_started", "running", f"{agent_name.replace('_', ' ').title()} {run_type} started.", {"run_id": run_id, "agent": agent_name, "run_type": run_type, "rerun_of_run_id": rerun_of_run_id})

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
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT started_at, ticket_id, agent_name FROM agent_runs WHERE run_id=%s", (run_id,))
            row = cur.fetchone()
            duration = None
            if row and row.get("started_at"):
                try:
                    duration = (datetime.fromisoformat(ts) - datetime.fromisoformat(row["started_at"])).total_seconds()
                except Exception:
                    duration = None
            ai_used = output_summary.get("ai_used")
            fallback_used = output_summary.get("fallback_used")
            cur.execute(
                """
                UPDATE agent_runs SET status=%s, progress=%s, completed_at=%s, duration_seconds=%s, output_path=%s,
                    error_code=%s, error_message=%s, ai_used=%s, ai_model=%s, fallback_used=%s, payload_json=%s
                WHERE run_id=%s
                """,
                (
                    status, progress, ts, duration, output_path, error_code, error_message,
                    ai_used if ai_used is None else bool(ai_used), output_summary.get("ai_model") or output_summary.get("model"),
                    fallback_used if fallback_used is None else bool(fallback_used), _json({**payload, "output_summary": output_summary}), run_id,
                ),
            )
            con.commit()
        if row and row.get("ticket_id"):
            self.append_activity(row["ticket_id"], "System", f"{row.get('agent_name')}_finished", status, f"{str(row.get('agent_name') or 'Agent').replace('_', ' ').title()} finished with status {status}.", {"run_id": run_id, "status": status, "output_summary": output_summary})

    def list_agent_runs(self, ticket_id: str, agent_name: str | None = None, limit: int = 25) -> list[dict[str, Any]]:
        clauses = ["ticket_id=%s"]
        values: list[Any] = [ticket_id]
        if agent_name:
            clauses.append("agent_name=%s")
            values.append(agent_name)
        values.append(limit)
        with self.connect() as con, con.cursor() as cur:
            cur.execute(f"SELECT * FROM agent_runs WHERE {' AND '.join(clauses)} ORDER BY started_at DESC LIMIT %s", values)
            rows = cur.fetchall()
        return [self._row_agent_run(row) for row in rows]

    def latest_agent_run(self, ticket_id: str, agent_name: str) -> dict[str, Any] | None:
        runs = self.list_agent_runs(ticket_id, agent_name, limit=1)
        return runs[0] if runs else None

    def attach_agent_result(self, ticket_id: str, agent: str, data: dict[str, Any]) -> dict[str, Any]:
        data = data or {}
        fields: dict[str, Any] = {}
        status = _norm_status(data.get("status") or data.get("report_status"))
        agent_norm = _norm_status(agent)
        if stage_workflow.stage_definition(agent_norm):
            success = _norm_status(data.get("workflow_status")) != "failed" and status not in stage_workflow.FAILED
            data = stage_workflow.completed_result(agent_norm, data, success=success)
        result_id = data.get("result_id") or f"{agent_norm.upper()}-{uuid.uuid4().hex[:12]}"
        run_id = os.getenv("SOC_RUN_ID")

        if agent_norm in {"parsing", "parsing_normalisation"}:
            fields["parsing_result"] = data
            fields["orchestration_decision_result"] = {}
            processed = data.get("processed_alert") or {}
            normalised = data.get("normalised_alert") or processed.get("normalised_alert") or {}
            extracted = data.get("important_extracted_fields") or {}
            hosts = extracted.get("hosts") or normalised.get("user_and_host_indicators", {}).get("hostnames") or []
            users = extracted.get("users") or normalised.get("user_and_host_indicators", {}).get("all_usernames") or []
            iocs = processed.get("iocs") or []
            current = self.get_ticket(ticket_id) or {}
            if hosts:
                fields["affected_assets"] = list(dict.fromkeys((current.get("affected_assets", []) + hosts)))
            if users:
                fields["affected_users"] = list(dict.fromkeys((current.get("affected_users", []) + users)))
            if iocs:
                fields["iocs"] = list((current.get("iocs", []) + iocs))
            if data.get("workflow_status") == "failed":
                fields["current_stage"] = "parsing_normalisation"
                fields["status"] = "Parsing Failed"
            else:
                fields["current_stage"] = "triage"
                fields["status"] = "Triage Required"
        elif agent_norm == "triage":
            fields["triage_result"] = data
            fields["severity"] = str(_first(data.get("severity"), data.get("classification"), default="Medium")).title()
            fields["confidence"] = str(_first(data.get("confidence"), data.get("confidence_level"), default="Medium")).title()
            fields["correlation_result"] = {}
            self._insert_result("triage_results", result_id, ticket_id, run_id, status or "completed", data, severity=fields["severity"], confidence=fields["confidence"], classification=data.get("classification"))
            if data.get("workflow_status") == "failed":
                fields["current_stage"] = "triage"
                fields["status"] = "Triage Failed"
            else:
                fields["current_stage"] = "triage_approval"
                fields["status"] = "Awaiting Approval"
        elif agent_norm == "orchestration":
            fields["orchestration_decision_result"] = data
        elif agent_norm == "correlation":
            fields["correlation_result"] = data
            self._insert_result("correlation_results", result_id, ticket_id, run_id, status or "completed", data, source_stage=data.get("source_stage") or "correlation")
            if data.get("recommendation_count"):
                fields["current_stage"] = "incident_grouping_review"
                fields["status"] = "Incident Grouping Review Required"
        elif agent_norm in {"threat_intel", "threat_intelligence"}:
            fields["threat_intel_result"] = data
            fields["orchestration_decision_result"] = {}
            self._insert_result("threat_intel_results", result_id, ticket_id, run_id, status or "completed", data)
            enriched = data.get("enriched_alert") or {}
            if enriched.get("enrichment_risk_level"):
                fields["confidence"] = (self.get_ticket(ticket_id) or {}).get("confidence") or "Medium"
            if data.get("workflow_status") == "failed":
                fields["current_stage"] = "threat_intelligence"
                fields["status"] = "Threat Intelligence Enrichment Failed"
            else:
                fields["current_stage"] = "threat_intel_approval"
                fields["status"] = "Awaiting Approval"
        elif agent_norm == "investigation":
            fields["investigation_result"] = data
            fields["correlation_result"] = data.get("correlation_summary_payload") or {}
            self._insert_result(
                "investigation_results",
                result_id,
                ticket_id,
                run_id,
                status or "completed",
                data,
                source_triage_result_id=data.get("source_triage_result_id"),
                chromadb_collection=data.get("chromadb_collection"),
                chromadb_path=data.get("chromadb_path"),
            )
            if data.get("correlated_alerts") is not None:
                self._insert_result("correlation_results", f"CORRRESULT-{uuid.uuid4().hex[:12]}", ticket_id, run_id, "completed", {"correlated_alerts": data.get("correlated_alerts"), "correlation_summary": data.get("correlation_summary")}, source_stage="investigation")
            if data.get("workflow_status") == "failed":
                fields["current_stage"] = "investigation"
                fields["status"] = "Investigation Failed"
            else:
                fields["current_stage"] = "investigation_approval"
                fields["status"] = "Awaiting Approval"
        elif agent_norm == "reporting":
            fields["reporting_result"] = data
            self._insert_result("reporting_results", result_id, ticket_id, run_id, status or "completed", data)
            if data.get("workflow_status") == "failed":
                fields["current_stage"] = "reporting"
                fields["status"] = "Reporting Failed"
            else:
                fields["current_stage"] = "reporting_approval"
                fields["status"] = "Awaiting Approval"
        message = f"{agent.replace('_', ' ').title()} appended output to the ticket."
        return self.update_ticket(ticket_id, fields, actor=f"{agent.replace('_', ' ').title()}", action=f"{agent_norm}_updated", message=message)

    def _insert_result(self, table: str, result_id: str, ticket_id: str, run_id: str | None, status: str, payload: dict[str, Any], **extra: Any) -> None:
        ts = payload.get("created_at") or payload.get("generated_at") or now_iso()
        with self.connect() as con, con.cursor() as cur:
            if table == "triage_results":
                cur.execute(
                    "INSERT INTO triage_results(result_id, ticket_id, run_id, status, severity, confidence, classification, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (result_id) DO NOTHING",
                    (result_id, ticket_id, run_id, status, extra.get("severity"), extra.get("confidence"), extra.get("classification"), _json(payload), ts),
                )
            elif table == "investigation_results":
                cur.execute(
                    "INSERT INTO investigation_results(result_id, ticket_id, run_id, status, source_triage_result_id, chromadb_collection, chromadb_path, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (result_id) DO NOTHING",
                    (result_id, ticket_id, run_id, status, extra.get("source_triage_result_id"), extra.get("chromadb_collection"), extra.get("chromadb_path"), _json(payload), ts),
                )
            elif table == "correlation_results":
                cur.execute(
                    "INSERT INTO correlation_results(result_id, ticket_id, run_id, source_stage, status, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (result_id) DO NOTHING",
                    (result_id, ticket_id, run_id, extra.get("source_stage") or "investigation", status, _json(payload), ts),
                )
            elif table in {"threat_intel_results", "reporting_results"}:
                cur.execute(
                    f"INSERT INTO {table}(result_id, ticket_id, run_id, status, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT (result_id) DO NOTHING",
                    (result_id, ticket_id, run_id, status, _json(payload), ts),
                )
            con.commit()

    def latest_triage_result(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM triage_results WHERE ticket_id=%s ORDER BY created_at DESC LIMIT 1", (ticket_id,))
            row = cur.fetchone()
        if row:
            payload = _loads(row.get("payload_json"), {})
            payload.setdefault("triage_result_id", row.get("result_id"))
            return payload
        ticket = self.get_ticket(ticket_id) or {}
        return ticket.get("triage_result") or None

    def latest_threat_intel_result(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM threat_intel_results WHERE ticket_id=%s ORDER BY created_at DESC LIMIT 1", (ticket_id,))
            row = cur.fetchone()
        if row:
            return _loads(row.get("payload_json"), {})
        ticket = self.get_ticket(ticket_id) or {}
        return ticket.get("threat_intel_result") or None

    def approval_complete(self, ticket_id: str, gate: str = "triage_approval") -> bool:
        ticket = self.get_ticket(ticket_id) or {}
        key = "investigation_approval_result" if gate == "investigation_approval" else "approval_result"
        result = ticket.get(key) or {}
        decision = _norm_status(result.get("decision") or result.get("status"))
        return decision in {"approved", "approve", "completed", "continue_to_reporting"}

    def record_evidence_gap_decision(self, ticket_id: str, decision: str, comments: str = "", analyst: str = "SOC Analyst") -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        inv = ticket.get("investigation_result") or {}
        triage_request = inv.get("triage_requery_request") if isinstance(inv, dict) else {}
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
            "triage_requery_request": triage_request if isinstance(triage_request, dict) else {},
            "created_at": now_iso(),
        }
        self._insert_approval(ticket_id, "investigation_evidence_gap_decision", payload)
        if decision_norm == "continue_to_reporting":
            fields = {"investigation_approval_result": payload, "current_stage": "reporting", "status": "Ready for Report"}
            action = "evidence_gap_continue_to_reporting"
            message = f"{analyst} chose to continue to Reporting Agent with investigation limitations documented."
        else:
            existing_triage = ticket.get("triage_result") or {}
            triage_payload = dict(existing_triage) if isinstance(existing_triage, dict) else {}
            triage_payload.update({"status": "needs_more_evidence", "current_stage": "triage_requery_requested", "investigation_throwback": True, "triage_requery_request": payload["triage_requery_request"], "missing_evidence": payload["missing_evidence"], "recommended_next_action": "Run Triage Agent again to collect the requested NetWitness evidence.", "updated_at": now_iso()})
            fields = {"investigation_approval_result": payload, "triage_result": triage_payload, "current_stage": "triage", "status": "Needs Triage Evidence"}
            action = "evidence_gap_return_to_triage"
            message = f"{analyst} returned the case to Triage Agent for more NetWitness evidence."
        return self.update_ticket(ticket_id, fields, actor=analyst, action=action, message=message)

    def record_approval(self, ticket_id: str, decision: str, comments: str = "", analyst: str = "SOC Analyst", gate: str | None = None) -> dict[str, Any]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket {ticket_id} not found")
        decision_norm = _norm_status(decision)
        stage = stage_workflow.stage_definition(gate or ticket.get("current_stage"))
        if not stage or not stage.get("approval_gate"):
            raise ValueError("This workflow stage does not require approval.")
        allowed, reason, _ = stage_workflow.can_approve(ticket, stage)
        if not allowed:
            raise ValueError(reason)
        if decision_norm not in {"approved", "approve"}:
            raise ValueError("Only approval is supported by this workflow control.")
        gate_name = stage["approval_gate"]
        payload = {
            "decision": decision_norm,
            "status": "completed" if decision_norm in {"approved", "approve"} else decision_norm,
            "comments": comments,
            "analyst": analyst,
            "approval_gate": gate_name,
            "created_at": now_iso(),
        }
        self._insert_approval(ticket_id, gate_name, payload)
        fields = stage_workflow.approval_fields(ticket, stage, payload)
        return self.update_ticket(ticket_id, fields, actor=analyst, action=f"approval_{decision_norm}", message=f"{analyst} recorded {payload['approval_gate']} decision: {decision_norm}.")

    def _insert_approval(self, ticket_id: str, gate: str, payload: dict[str, Any]) -> None:
        approval_id = payload.get("approval_id") or f"APR-{uuid.uuid4().hex[:12].upper()}"
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                "INSERT INTO approvals(approval_id, ticket_id, gate, decision, status, analyst, comments, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (approval_id, ticket_id, gate, payload.get("decision") or "", payload.get("status") or "", payload.get("analyst") or "SOC Analyst", payload.get("comments") or "", _json(payload), payload.get("created_at") or now_iso()),
            )
            con.commit()

    def record_soc_review(self, ticket_id: str, decision: str = "confirmed", comments: str = "", analyst: str = "SOC Analyst") -> dict[str, Any]:
        mapped = "approved" if _norm_status(decision) in {"confirmed", "approved", "approve"} else decision
        return self.record_approval(ticket_id, mapped, comments=comments, analyst=analyst, gate="reporting_approval")

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

    def _row_correlation_recommendation(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = _loads(row.get("payload_json"), {})
        payload.update({
            "recommendation_id": row.get("recommendation_id"),
            "recommendation_type": row.get("recommendation_type"),
            "source_alert_id": row.get("source_alert_id"),
            "target_alert_id": row.get("target_alert_id"),
            "source_ticket_id": row.get("source_ticket_id"),
            "target_ticket_id": row.get("target_ticket_id"),
            "target_incident_id": row.get("target_incident_id"),
            "confidence": row.get("confidence"),
            "score": row.get("score"),
            "matched_fields": _loads(row.get("matched_fields_json"), []),
            "reason": row.get("reason"),
            "status": row.get("status"),
            "created_by": row.get("created_by"),
            "created_at": row.get("created_at"),
            "reviewed_by": row.get("reviewed_by"),
            "reviewed_at": row.get("reviewed_at"),
            "analyst_comments": row.get("analyst_comments"),
            "source_stage": row.get("source_stage") or payload.get("source_stage"),
            "requires_archive_approval": bool(row.get("requires_archive_approval")),
            "archive_status": row.get("archive_status") or payload.get("archive_status", "not_required"),
            "archive_action": _loads(row.get("archive_action_json"), {}),
            "recommended_by_agent": row.get("recommended_by_agent") or payload.get("recommended_by_agent") or payload.get("created_by"),
            "archive_after_approval": bool(payload.get("archive_after_approval") or row.get("requires_archive_approval")),
        })
        return payload

    def _row_agent_run(self, row: dict[str, Any] | None) -> dict[str, Any]:
        if not row:
            return {}
        return {
            "run_id": row.get("run_id"),
            "ticket_id": row.get("ticket_id"),
            "alert_id": row.get("alert_id"),
            "agent_name": row.get("agent_name"),
            "run_type": row.get("run_type"),
            "status": row.get("status"),
            "progress": row.get("progress"),
            "started_at": row.get("started_at"),
            "completed_at": row.get("completed_at"),
            "duration_seconds": row.get("duration_seconds"),
            "triggered_by": row.get("triggered_by"),
            "is_rerun": bool(row.get("is_rerun")),
            "rerun_of_run_id": row.get("rerun_of_run_id"),
            "output_path": row.get("output_path"),
            "error_code": row.get("error_code"),
            "error_message": row.get("error_message"),
            "ai_used": None if row.get("ai_used") is None else bool(row.get("ai_used")),
            "ai_model": row.get("ai_model"),
            "fallback_used": None if row.get("fallback_used") is None else bool(row.get("fallback_used")),
            "payload": _loads(row.get("payload_json"), {}),
        }

    def _row_alert(self, row: dict[str, Any]) -> dict[str, Any]:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT ticket_id FROM ticket_alerts WHERE alert_id=%s ORDER BY linked_at DESC LIMIT 1", (row["alert_id"],))
            linked = cur.fetchone()
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

    def _row_activity(self, row: dict[str, Any]) -> dict[str, Any]:
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

    def _row_ticket(self, row: dict[str, Any], include_children: bool = False) -> dict[str, Any]:
        keys = _row_keys(row)
        ticket = {
            "ticket_id": row["ticket_id"],
            "incident_id": row["incident_id"] if "incident_id" in keys else None,
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
            "correlation_result": _loads(row["correlation_result_json"], {}) if "correlation_result_json" in keys else {},
            "investigation_result": _loads(row["investigation_result_json"], {}),
            "approval_result": _loads(row["approval_result_json"], {}),
            "investigation_approval_result": _loads(row["investigation_approval_result_json"], {}),
            "reporting_result": _loads(row["reporting_result_json"], {}),
            "soc_review_result": _loads(row["soc_review_result_json"], {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "closed_at": row["closed_at"],
            "archive_status": row["archive_status"] if "archive_status" in keys else "active",
            "merged_into_ticket_id": row["merged_into_ticket_id"] if "merged_into_ticket_id" in keys else None,
            "archived_by": row["archived_by"] if "archived_by" in keys else None,
            "archived_at": row["archived_at"] if "archived_at" in keys else None,
            "archive_reason": row["archive_reason"] if "archive_reason" in keys else "",
        }
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM ticket_alerts WHERE ticket_id=%s", (ticket["ticket_id"],))
            ticket["alert_count"] = int(cur.fetchone()["c"])
        if include_children:
            with self.connect() as con, con.cursor() as cur:
                cur.execute(
                    """
                    SELECT a.*, ta.relationship, ta.status AS link_status, ta.linked_at,
                           ta.linked_by, ta.link_source, ta.correlation_score, ta.link_reason, ta.confirmed_by, ta.confirmed_at
                    FROM ticket_alerts ta JOIN alerts a ON a.alert_id=ta.alert_id
                    WHERE ta.ticket_id=%s
                    ORDER BY ta.linked_at
                    """,
                    (ticket["ticket_id"],),
                )
                rows = cur.fetchall()
            related = []
            for alert_row in rows:
                alert = self._row_alert(alert_row)
                alert["relationship"] = alert_row["relationship"]
                alert["link_status"] = alert_row["link_status"]
                alert["linked_at"] = alert_row["linked_at"]
                alert["linked_by"] = alert_row.get("linked_by")
                alert["link_source"] = alert_row.get("link_source")
                alert["correlation_score"] = alert_row.get("correlation_score")
                alert["link_reason"] = alert_row.get("link_reason")
                alert["confirmed_by"] = alert_row.get("confirmed_by")
                alert["confirmed_at"] = alert_row.get("confirmed_at")
                related.append(alert)
            ticket["related_alerts"] = related
            ticket["activity_log"] = self.activity(ticket["ticket_id"])
            ticket["correlation_recommendations"] = self.list_correlation_recommendations({"ticket_id": ticket["ticket_id"], "limit": 50})
            ticket["pending_correlation_count"] = len([r for r in ticket["correlation_recommendations"] if _norm_status(r.get("status")) == "pending"])
            ticket["correlation_history"] = [r for r in ticket["correlation_recommendations"] if _norm_status(r.get("status")) != "pending"]
        return ticket
