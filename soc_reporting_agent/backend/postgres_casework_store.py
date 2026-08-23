# ==============================================================================
# [FYP-FILE] soc_reporting_agent/backend/postgres_casework_store.py
# File: soc_reporting_agent/backend/postgres_casework_store.py
# Important dependencies: __future__, backend, datetime, json, os, pathlib, psycopg2, services.
# ==============================================================================
# Purpose:
#   PostgreSQL-backed implementation of the Aegis "casework store" -- THE
#   operational database layer for SOC alerts, incident tickets, per-stage
#   agent results, analyst approvals, incident-grouping (correlation)
#   recommendations, activity/audit log entries, and agent run telemetry.
#
#   [FYP-EVALUATOR] This is the store actually used at runtime. backend/
#   store_factory.py -> get_casework_store() always returns
#   PostgresCaseworkStore(); the SQLite implementation in casework_store.py
#   is explicitly disabled as a fallback ("PostgreSQL is the only runtime
#   database... so data loss or split-brain workflow state cannot be
#   hidden."). backend/app.py builds the module-level CASEWORK singleton
#   from this class (falling back only to store_factory.
#   UnavailableCaseworkStore, which raises PostgresUnavailableError on every
#   attribute access, if PostgreSQL cannot be reached at import time).
#
# Main functionalities:
#   - normalise_alert(): map a raw NetWitness alert/incident export into
#     the canonical alert dict shape stored in the `alerts` table (logic is
#     identical to casework_store.normalise_alert()).
#   - PostgresCaseworkStore: implements THE SAME public method names and
#     return shapes as backend.casework_store.CaseworkStore (see that
#     file's class docstring for the full list), so callers can treat the
#     two stores as interchangeable -- but this class additionally persists
#     an append-only per-stage result audit trail (triage_results,
#     investigation_results, correlation_results, threat_intel_results,
#     reporting_results tables via _insert_result), an approvals audit
#     trail (_insert_approval), and a denormalised workflow_state snapshot
#     row per ticket (written inside update_ticket) that casework_store.py
#     does not maintain.
#
# Inputs:
#   - dsn: str | None -- PostgreSQL connection string. Resolved from (in
#     order) the `dsn` constructor argument, the POSTGRES_DSN env var, the
#     REPORTING_POSTGRES_DSN env var, or individual POSTGRES_HOST/
#     POSTGRES_DB/POSTGRES_USER/POSTGRES_PORT/POSTGRES_PASSWORD env vars
#     assembled by _dsn_from_parts(). Never hard-coded; only referenced here
#     by environment-variable name, no credentials are embedded in this
#     file.
#   - raw_alert dicts (NetWitness alert/incident JSON) passed to
#     normalise_alert() / upsert_alert().
#   - Per-stage agent result dicts passed to attach_agent_result().
#
# Outputs:
#   - Rows written to a PostgreSQL database (schema DDL is external -- see
#     "Calls" below; it is not embedded in this Python file).
#   - Plain dict/list return values (JSON-serialisable) representing
#     tickets, alerts, activity entries, correlation recommendations, and
#     agent runs -- same shapes as backend.casework_store.CaseworkStore.
#   - JSON files written under an "inputs" directory by
#     prepare_agent_inputs() for the downstream pipeline agents to read.
#
# Workflow position:
#   Storage layer underneath the SOC ticket workflow defined in
#   backend/stage_workflow.py (WORKFLOW_STAGES below mirrors that module's
#   stage ordering). Sits directly below backend/app.py (the Flask API) via
#   the module-level CASEWORK object built through
#   backend.store_factory.get_casework_store().
#
# Called by:
#   - soc_reporting_agent/backend/app.py: builds the CASEWORK singleton via
#     backend.store_factory.get_casework_store() and calls essentially every
#     public method on this class across its API routes (get_ticket,
#     update_ticket, list_tickets, dashboard_summary, upsert_alert,
#     create_ticket_from_alert, link_alert/unlink_alert/move_alert_to_ticket,
#     list_correlation_recommendations, confirm/reject/edit_correlation_
#     recommendation, attach_agent_result, record_agent_run_start/finish,
#     prepare_agent_inputs, append_activity, list_agent_runs,
#     latest_agent_run -- confirmed via repo grep for "CASEWORK.").
#   - soc_reporting_agent/backend/store_factory.py: constructs and returns
#     instances of this class from get_casework_store().
#   - soc_reporting_agent/backend/error_handling.py: imports
#     PostgresUnavailableError to translate store-unavailability into API
#     error responses.
#
# Calls:
#   - psycopg2 / psycopg2.extras (Json, RealDictCursor) for the PostgreSQL
#     driver; every query uses %s placeholders (parameterised, not
#     string-formatted) via this driver.
#   - backend.stage_workflow (stage_definition, output_valid, can_approve,
#     approval_fields, completed_result, FAILED) for workflow-stage rules.
#   - services.parser_context_guard.extract_alert_identity() for alert
#     identity extraction.
#   - init_db() reads and executes
#     soc_reporting_agent/database/postgres_schema.sql (path resolved
#     relative to this file: Path(__file__).resolve().parents[1] /
#     "database" / "postgres_schema.sql"). NOTE: that file was not present
#     in this repository snapshot at the time of this review -- the actual
#     CREATE TABLE / column DDL for tables such as counters, alerts,
#     tickets, ticket_alerts, incidents, correlation_recommendations,
#     activity, agent_runs, workflow_state, triage_results,
#     investigation_results, correlation_results, threat_intel_results,
#     reporting_results and approvals therefore lives outside this Python
#     file and could not be inlined here; table/column names below are
#     inferred from the SQL statements executed against them in this
#     module.
#
# Key evaluator search terms:
#   PostgresCaseworkStore, get_casework_store, POSTGRES_DSN, init_db,
#   attach_agent_result, record_approval, record_evidence_gap_decision,
#   prepare_agent_inputs, workflow_state, correlation_recommendations,
#   _insert_result, _insert_approval, WORKFLOW_STAGES, PostgresUnavailableError,
#   same interface as CaseworkStore (SQLite).
# ==============================================================================
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


# [FYP-SECTION] Workflow stage ordering.
# [FYP-STATE] Mirrors backend.stage_workflow's canonical stage list and the
# identical WORKFLOW_STAGES constant in casework_store.py (SQLite). A
# ticket's `current_stage` column always holds one of these values.
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


# [FYP-SECTION] Availability / error signalling for when PostgreSQL cannot
# be reached or initialised.
# [FYP-ERROR] [FYP-CLASS] PostgresUnavailableError
# Raised by connect()/init_db()/__init__() whenever PostgreSQL is
# unconfigured or unreachable. as_payload() turns the error into a
# JSON-serialisable API response shape
# (status="failed_postgres_unavailable", reporting_mode="blocked") so
# backend/app.py and backend/error_handling.py can surface a clear failure
# to the dashboard instead of a raw stack trace.
# [FYP-USED-BY] store_factory.UnavailableCaseworkStore.__getattr__ raises
# this on every attribute access when the app failed to construct
# PostgresCaseworkStore at startup.
# [FYP-CLASS] `PostgresUnavailableError` — owns PostgresUnavailableError state or behaviour for the reporting backend and API component.
# [FYP-PROCESS] Important methods: as_payload.
# [FYP-USED-BY] Static constructor/type references include soc_reporting_agent/backend/postgres_casework_store.py:__init__, soc_reporting_agent/backend/postgres_casework_store.py:connect, soc_reporting_agent/backend/postgres_casework_store.py:init_db.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class PostgresUnavailableError(RuntimeError):
    """Raised when PostgreSQL is required but unavailable."""

    # [FYP-FUNCTION] Convert Error To API Payload
    # Builds the standard "PostgreSQL unavailable" response dict, embedding
    # str(self) as the `error` detail. No secrets are included (the DSN/
    # credentials are never part of the exception message construction here).
    def as_payload(self) -> dict[str, Any]:
        return {
            "status": "failed_postgres_unavailable",
            "message": "PostgreSQL is required. SQLite fallback is disabled.",
            "reporting_mode": "blocked",
            "error": str(self),
        }


# [FYP-FUNCTION] Build "PostgreSQL Required" Payload
# [FYP-FALLBACK] Module-level helper (usable without an exception instance)
# that produces the same failed_postgres_unavailable/blocked response shape
# as PostgresUnavailableError.as_payload(). Used by
# store_factory.postgres_unavailable_result().
def postgres_required_payload(message: str | None = None) -> dict[str, Any]:
    return {
        "status": "failed_postgres_unavailable",
        "message": message or "PostgreSQL is required. SQLite fallback is disabled.",
        "reporting_mode": "blocked",
    }


# [FYP-SECTION] Small serialisation / normalisation helpers shared by every
# method below. None of these touch the database directly. Logic mirrors
# casework_store.py's module-level helpers, adapted for psycopg2 (Json()
# wrapper instead of json.dumps(), RealDictCursor rows behave like dicts).

# [FYP-FUNCTION] Current UTC Timestamp
# Returns the current time as an ISO-8601 string (UTC). Used for every
# created_at / updated_at / linked_at / started_at value written by this
# module.
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# [FYP-FUNCTION] Wrap Value For JSON/JSONB Column
# Wraps a value in psycopg2.extras.Json so it is adapted to a Postgres
# json/jsonb parameter correctly (as opposed to casework_store.py's SQLite
# version, which manually calls json.dumps() to a TEXT column). None becomes
# Json({}).
def _json(value: Any) -> Json:
    return Json(value if value is not None else {})


# [FYP-FUNCTION] Deserialise JSON Column Value
# Unlike the SQLite version, a Postgres json/jsonb column may already come
# back from psycopg2 as a native dict/list, so this first checks isinstance
# before falling back to json.loads(); returns `default` on empty value or
# parse failure.
def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return default


# [FYP-FUNCTION] Normalise Status/Enum String
# Lower-cases and replaces spaces/hyphens with underscores for consistent
# status/stage comparisons. Identical logic to casework_store.py.
def _norm_status(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


# [FYP-FUNCTION] First Non-Empty Value
# Returns the first argument that is not None/""/[]/{}. Identical logic to
# casework_store.py.
def _first(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


# [FYP-DECISION] [FYP-FUNCTION] Derive Severity Label From Numeric Risk Score
# Maps a NetWitness risk_score (0-100) to Critical/High/Medium/Low via fixed
# thresholds (>=90/70/40). Called by normalise_alert() as the severity
# default. Identical logic to casework_store.py.
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


# [FYP-FUNCTION] Get Row Key Set (Postgres-only helper)
# RealDictCursor rows already behave like dicts, but this helper tolerates
# None or a row-like object without a reliable .keys() by returning an empty
# set instead of raising, used by _row_ticket()'s "does this column exist on
# this row" guards.
def _row_keys(row: Any) -> set[str]:
    if not row:
        return set()
    if isinstance(row, dict):
        return set(row.keys())
    try:
        return set(row.keys())
    except Exception:
        return set()


# [FYP-SECTION] Alert normalisation.
# [FYP-INPUT] Maps a heterogeneous raw NetWitness alert/incident export
# onto the single canonical alert dict shape persisted in the `alerts`
# table. Logic is identical to casework_store.normalise_alert(); kept as a
# separate copy here (not imported) so this module has no import-time
# dependency on the SQLite module. backend/app.py imports THIS copy
# (backend.postgres_casework_store.normalise_alert) directly for alert
# pre-processing outside the store class.

# [FYP-FUNCTION] Normalise Raw NetWitness Alert
# [FYP-INPUT] raw: dict -- arbitrary raw alert/incident JSON as captured
# from NetWitness (defensive against missing/partial fields).
# [FYP-PROCESS] Resolves the primary alert from raw["alerts"]/raw["alert"]/
# raw itself, then uses services.parser_context_guard.extract_alert_identity
# plus fallback key names (pick()) to resolve alert_id, title, severity,
# timestamps, hostname, username and IOCs; generates a fallback
# "ALERT-<timestamp>" id and a risk_score-derived severity when nothing
# explicit is present.
# [FYP-OUTPUT] Canonical alert dict, written to `alerts` by upsert_alert().
# [FYP-CALLS] services.parser_context_guard.extract_alert_identity.
# [FYP-USED-BY] upsert_alert(); backend/app.py (imports this function
# directly).
# [FYP-FUNCTION] `normalise_alert` — transforms normalise alert input into the stable representation required by downstream reporting backend and API processing.
# [FYP-INPUT] Parameters: `raw`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/casework_store.py:upsert_alert, soc_reporting_agent/backend/postgres_casework_store.py:upsert_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_severity_from_score`, `append`, `extract_alert_identity`, `get`, `isinstance`, `next`, `now`, `now_iso`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def normalise_alert(raw: dict[str, Any]) -> dict[str, Any]:
    raw = raw or {}
    identity = extract_alert_identity(raw)

    incident = raw.get("incident") if isinstance(raw.get("incident"), dict) else {}
    alerts = raw.get("alerts") if isinstance(raw.get("alerts"), list) else []
    primary = next((a for a in alerts if isinstance(a, dict)), None) or (raw.get("alert") if isinstance(raw.get("alert"), dict) else {}) or raw
    headers = primary.get("originalHeaders") if isinstance(primary.get("originalHeaders"), dict) else {}
    original = primary.get("originalAlert") if isinstance(primary.get("originalAlert"), dict) else {}
    meta = incident.get("alertMeta") if isinstance(incident.get("alertMeta"), dict) else {}

    # Local closure: first non-empty value/list-item among the candidates, in
    # priority order.
    # [FYP-FUNCTION] `pick` — implements the pick operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `default`, `*values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/casework_store.py:normalise_alert, soc_reporting_agent/backend/postgres_casework_store.py:normalise_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `isinstance`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# [FYP-CLASS] PostgresCaseworkStore
# [FYP-DATABASE] PostgreSQL-backed implementation of the SOC casework
# store -- the class actually instantiated at runtime (see file header).
# Opens a short-lived psycopg2 connection per method call (no long-held
# connection/pool) against self.dsn, and exposes every read/write operation
# the Aegis dashboard/backend needs against alerts, tickets, ticket<->alert
# links, incidents, correlation recommendations, the activity log, agent
# run telemetry, and per-stage result audit tables.
#
# Implements the SAME method names and return shapes as
# backend.casework_store.CaseworkStore (SQLite) -- see that class's
# docstring for the shared list -- so the two are interchangeable from a
# caller's perspective. Extra methods only present here (no SQLite
# equivalent): healthcheck(), next_triage_unc(), _insert_result(),
# _insert_approval(), latest_triage_result(), latest_threat_intel_result(),
# approval_complete(). update_ticket() here also writes a workflow_state
# snapshot row that the SQLite version does not maintain.
# [FYP-CLASS] `PostgresCaseworkStore` — owns PostgresCaseworkStore state or behaviour for the reporting backend and API component.
# [FYP-PROCESS] Important methods: __init__, _dsn_from_parts, connect, healthcheck, init_db, _next_counter, _next_ticket_id, _next_incident_id.
# [FYP-USED-BY] Static constructor/type references include soc_reporting_agent/backend/store_factory.py:get_casework_store.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class PostgresCaseworkStore:
    # [FYP-EVALUATOR] [FYP-FUNCTION] Construct Store / Resolve Connection String
    # [FYP-INPUT] dsn: str | None -- explicit connection string; initialise:
    # bool (default True) -- whether to run init_db() immediately.
    # [FYP-CONFIG] Resolves self.dsn from, in priority order: the `dsn`
    # argument, the POSTGRES_DSN env var, the REPORTING_POSTGRES_DSN env var,
    # or _dsn_from_parts() (built from POSTGRES_HOST/POSTGRES_DB/POSTGRES_USER/
    # POSTGRES_PORT/POSTGRES_PASSWORD env vars). No connection string or
    # credential value is hard-coded in this file; only the env-var names are
    # referenced.
    # [FYP-VALIDATION] [FYP-ERROR] Raises PostgresUnavailableError if no DSN
    # could be resolved from any source.
    # [FYP-DATABASE] When initialise=True (the default), calls init_db() which
    # applies the schema DDL immediately on construction.
    # [FYP-USED-BY] store_factory.get_casework_store().
    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `dsn`, `initialise`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `PostgresUnavailableError`, `_dsn_from_parts`, `getenv`, `init_db`, `strip`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

    def __init__(self, dsn: str | None = None, initialise: bool = True):
        self.dsn = (dsn or os.getenv("POSTGRES_DSN") or os.getenv("REPORTING_POSTGRES_DSN") or self._dsn_from_parts() or "").strip()
        if not self.dsn:
            raise PostgresUnavailableError("POSTGRES_DSN is not configured.")
        if initialise:
            self.init_db()

    # [FYP-FUNCTION] `_dsn_from_parts` — implements the dsn from parts operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/postgres_casework_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `getenv`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    @staticmethod
    # [FYP-FUNCTION] Assemble DSN From Individual Env Vars
    # [FYP-CONFIG] Builds a "postgresql://user:pass@host:port/db" string from
    # POSTGRES_HOST/POSTGRES_DB/POSTGRES_USER (all required) plus optional
    # POSTGRES_PORT (default "5432") and POSTGRES_PASSWORD. Returns "" (falsy)
    # if host/db/user are not all present, so __init__ can fall through to
    # raising PostgresUnavailableError. Referenced here only by env-var name;
    # the actual password value is never logged or embedded in a comment.
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

    # [FYP-FUNCTION] Open PostgreSQL Connection
    # [FYP-ERROR] [FYP-FALLBACK] Wraps psycopg2.connect(self.dsn,
    # cursor_factory=RealDictCursor) and re-raises any failure as
    # PostgresUnavailableError (so callers can rely on a single exception type
    # for "the database is not reachable" across this whole module). Every
    # DB-touching method below opens/closes its own connection via `with
    # self.connect() as con, con.cursor() as cur:`.
    def connect(self):
        try:
            return psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
        except Exception as exc:
            raise PostgresUnavailableError(str(exc)) from exc

    # [FYP-FUNCTION] Database Healthcheck (Postgres-only, no SQLite equivalent)
    # [FYP-DATABASE] Runs `SELECT 1 AS ok` and returns True iff it gets back
    # exactly 1. No confirmed caller found via repo grep at time of review; no
    # direct caller confidently identified beyond ad-hoc diagnostics.
    def healthcheck(self) -> bool:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            row = cur.fetchone()
        return bool(row and row.get("ok") == 1)

    # [FYP-EVALUATOR] [FYP-FUNCTION] Initialise Database Schema
    # [FYP-DATABASE] Reads
    # soc_reporting_agent/database/postgres_schema.sql (path resolved relative
    # to this file) and executes its contents as-is against the database, then
    # commits. Unlike casework_store.py's init_db() (which has the schema
    # inline as executescript() calls plus a separate ensure_schema_migrations()
    # step), all DDL here lives in the external .sql file, so this file has no
    # visibility into whether individual CREATE TABLE statements are
    # idempotent -- that is a property of postgres_schema.sql itself, not
    # enforced by this Python method.
    # [FYP-ERROR] [FYP-FALLBACK] Re-raises PostgresUnavailableError as-is;
    # wraps any other exception (e.g. a malformed schema file, permissions
    # error) into a new PostgresUnavailableError so callers see one consistent
    # failure type.
    # [FYP-USED-BY] __init__() when initialise=True.
    # [FYP-FUNCTION] `init_db` — implements the init db operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/casework_store.py:__init__, soc_reporting_agent/backend/postgres_casework_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `Path`, `PostgresUnavailableError`, `commit`, `connect`, `cursor`, `execute`, `read_text`, `resolve`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

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

    # [FYP-SECTION] Sequential ID / counter generation.
    # [FYP-FUNCTION] Atomically Increment Named Counter
    # [FYP-DATABASE] INSERT ... ON CONFLICT (name) DO UPDATE SET value =
    # counters.value + 1 RETURNING value -- a single atomic upsert-and-return,
    # avoiding the read-then-write race that a separate SELECT+UPDATE could
    # have under concurrent requests. Used for the 'ticket', 'incident' and
    # 'triage_unc_number' counters.
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

    # [FYP-FUNCTION] Allocate Next Ticket ID
    # Formats "TKT-<year>-<00000>" from the 'ticket' counter.
    def _next_ticket_id(self) -> str:
        return f"TKT-{datetime.now(timezone.utc).year}-{self._next_counter('ticket'):05d}"

    # [FYP-FUNCTION] Allocate Next Incident ID
    # Formats "INC-<year>-<00000>" from the 'incident' counter.
    def _next_incident_id(self) -> str:
        return f"INC-{datetime.now(timezone.utc).year}-{self._next_counter('incident'):05d}"

    # [FYP-FUNCTION] Allocate Next Triage Unique Case Number (Postgres-only, no
    # SQLite equivalent)
    # [FYP-PROCESS] Converts the 'triage_unc_number' counter into a
    # "#00000" / "#00000A" / "#00000B" ... style label: the low 5 digits (mod
    # 100000) form the numeric part, and the counter's higher digits are
    # converted to a base-26 letter suffix (A, B, ... Z, then AA-style
    # carrying) once the numeric part has wrapped around. No confirmed caller
    # found via repo grep at time of review.
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

# [FYP-SECTION] Alert storage (CRUD against the `alerts` table).

    # [FYP-FUNCTION] Insert Or Update Alert
    # [FYP-INPUT] raw_alert: dict -- raw NetWitness alert/incident JSON.
    # [FYP-PROCESS] Runs it through normalise_alert(), then INSERT ... ON
    # CONFLICT (alert_id) DO UPDATE so re-ingesting the same alert_id refreshes
    # its fields.
    # [FYP-DATABASE] Writes one row to `alerts`.
    # [FYP-OUTPUT] Returns the stored alert (re-read via get_alert()).
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

    # [FYP-FUNCTION] Load Single Alert By Id
    # [FYP-DATABASE] SELECT * FROM alerts WHERE alert_id=%s. Returns None if not
    # found, else mapped through _row_alert() (includes linked_ticket).
    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE alert_id=%s", (alert_id,))
            row = cur.fetchone()
        return self._row_alert(row) if row else None

    # [FYP-FUNCTION] List/Search Alerts
    # [FYP-INPUT] filters: dict -- severity, status, q (free-text over
    # alert_id/alert_name/hostname), hostname, limit (default 200).
    # [FYP-DATABASE] Dynamic WHERE clause, most-recently-seen first.
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

# [FYP-SECTION] Ticket creation and alert<->ticket linking.

    # [FYP-EVALUATOR] [FYP-FUNCTION] Create Ticket From Alert
    # [FYP-INPUT] alert_id (must already exist via upsert_alert), owner
    # (default "Unassigned"), status (default "To Parse").
    # [FYP-DECISION] Returns the existing ticket instead of creating a
    # duplicate if this alert is already linked to one (ticket_for_alert).
    # [FYP-DATABASE] Allocates ticket_id/incident_id, inserts one row into
    # `tickets` (every *_result_json column starts empty), one row into
    # `incidents` (ON CONFLICT DO NOTHING), one row into `ticket_alerts`
    # marking this alert "Primary alert" (ON CONFLICT DO UPDATE so a retry is
    # safe).
    # [FYP-STATE] New ticket starts at current_stage="parsing_normalisation".
    # [FYP-OUTPUT] The newly created ticket (get_ticket()).
    # [FYP-FUNCTION] `create_ticket_from_alert` — constructs create ticket from alert output for the next reporting backend and API consumer or analyst-facing view.
    # [FYP-INPUT] Parameters: `alert_id`, `owner`, `status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_netwitness_sync, soc_reporting_agent/backend/app.py:api_ticket_from_alert, soc_reporting_agent/backend/casework_store.py:seed_demo_data_if_empty; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `KeyError`, `_json`, `_next_incident_id`, `_next_ticket_id`, `append_activity`, `commit`, `connect`, `cursor`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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

    # [FYP-FUNCTION] Find Ticket Containing Alert
    # [FYP-DATABASE] SELECT ticket_id FROM ticket_alerts WHERE alert_id=%s,
    # most-recently-linked row wins.
    def ticket_for_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT ticket_id FROM ticket_alerts WHERE alert_id=%s ORDER BY linked_at DESC LIMIT 1", (alert_id,))
            row = cur.fetchone()
        return self.get_ticket(row["ticket_id"]) if row else None

    # [FYP-FUNCTION] Link Alert To Ticket
    # [FYP-INPUT] ticket_id, alert_id (both must exist); relationship;
    # linked_by/link_source/correlation_score/link_reason; confirmed_by.
    # [FYP-VALIDATION] Raises KeyError if the ticket or alert does not exist.
    # [FYP-DATABASE] INSERT ... ON CONFLICT (ticket_id, alert_id) DO UPDATE into
    # ticket_alerts.
    # [FYP-FLOW] Logs an "alert_linked" activity entry and calls
    # mark_context_refresh_required() to flag investigation/reporting results as
    # stale.
    # Note: unlike casework_store.CaseworkStore.link_alert(), this method does
    # NOT merge the linked alert's IOCs/hostname/username into the ticket's
    # affected_assets/affected_users/iocs columns -- only the ticket_alerts link
    # row is written here.
    # [FYP-OUTPUT] Updated ticket via get_ticket().
    # [FYP-FUNCTION] `link_alert` — implements the link alert operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `alert_id`, `relationship`, `linked_by`, `link_source`, `correlation_score`, `link_reason`, `confirmed_by`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_ticket_link_alert, soc_reporting_agent/backend/casework_store.py:confirm_correlation_recommendation, soc_reporting_agent/backend/casework_store.py:edit_correlation_recommendation; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `KeyError`, `append_activity`, `commit`, `connect`, `cursor`, `execute`, `get_alert`, `get_ticket`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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

    # [FYP-FUNCTION] Unlink Alert From Ticket
    # [FYP-DATABASE] DELETE FROM ticket_alerts WHERE ticket_id=%s AND
    # alert_id=%s.
    # [FYP-FLOW] Logs "alert_unlinked" and calls mark_context_refresh_required()
    # (the SQLite version's unlink_alert does not call this).
    def unlink_alert(self, ticket_id: str, alert_id: str, analyst: str = "SOC Analyst", reason: str = "Removed from incident ticket") -> dict[str, Any]:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("DELETE FROM ticket_alerts WHERE ticket_id=%s AND alert_id=%s", (ticket_id, alert_id))
            con.commit()
        self.append_activity(ticket_id, analyst, "alert_unlinked", "completed", f"Unlinked alert {alert_id}.", {"alert_id": alert_id, "reason": reason})
        self.mark_context_refresh_required(ticket_id, reason=f"Alert {alert_id} was removed from this ticket.", actor=analyst)
        return self.get_ticket(ticket_id) or {}

    # [FYP-FUNCTION] Flag Downstream Stage Outputs As Stale (targeted rerun)
    # [FYP-INPUT] ticket_id, agent_name (stage that was just re-run), reason.
    # [FYP-PROCESS] Looks up which later result fields become questionable via
    # clear_map, and stamps each non-empty affected result dict with
    # context_refresh_required/context_refresh_reason/updated_at.
    # Note: this clear_map differs slightly from casework_store.py's
    # affected_map -- here "triage" only stales investigation_result/
    # reporting_result (not threat_intel_result), while "threat_intel" stales
    # triage_result in addition to investigation_result/reporting_result; the
    # SQLite version's mapping is the reverse (triage stales threat_intel,
    # threat_intel does not stale triage). This is a genuine behavioural
    # difference between the two store implementations, not just a naming one.
    # [FYP-DATABASE] Delegates the write to update_ticket().
    # [FYP-FUNCTION] `mark_downstream_refresh_required` — implements the mark downstream refresh required operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `agent_name`, `reason`, `actor`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `_norm_status`, `dict`, `get`, `get_ticket`, `isinstance`, `now_iso`, `update`, `update_ticket`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-FUNCTION] Flag Investigation/Reporting As Stale (grouping change)
    # [FYP-INPUT] ticket_id, reason, actor.
    # [FYP-PROCESS] Stamps context_refresh_required/context_refresh_reason/
    # updated_at onto whichever of investigation_result/reporting_result are
    # already populated. Note: unlike casework_store.py's version, this does
    # NOT also flag triage_result or set ticket status to "Context Changed".
    # [FYP-DATABASE] Delegates to update_ticket().
    # [FYP-USED-BY] link_alert(), unlink_alert(), merge_tickets().
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

# [FYP-SECTION] Incident-grouping / correlation recommendations -- the
# analyst review queue of "should alert X be linked to ticket Y?" style
# suggestions.

    # [FYP-FUNCTION] Create Correlation Recommendation
    # [FYP-INPUT] recommendation: dict -- recommendation_type, source_alert_id,
    # target_ticket_id, confidence, score, matched_fields, reason,
    # requires_archive_approval/archive_after_approval, etc.
    # [FYP-VALIDATION] De-dupes against an existing pending recommendation for
    # the same (source_alert_id, target_ticket_id, recommendation_type).
    # [FYP-DATABASE] INSERT INTO correlation_recommendations.
    # [FYP-FLOW] Logs a "correlation_recommended" (pending) activity entry
    # against the target ticket.
    # [FYP-OUTPUT] The stored recommendation.
    # [FYP-FUNCTION] `create_correlation_recommendation` — constructs create correlation recommendation output for the next reporting backend and API consumer or analyst-facing view.
    # [FYP-INPUT] Parameters: `recommendation`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `_json`, `_row_correlation_recommendation`, `append_activity`, `bool`, `commit`, `connect`, `cursor`, `dict`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-FUNCTION] Load Correlation Recommendation By Id
    # [FYP-DATABASE] SELECT * FROM correlation_recommendations WHERE
    # recommendation_id=%s.
    def get_correlation_recommendation(self, recommendation_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM correlation_recommendations WHERE recommendation_id=%s", (recommendation_id,))
            row = cur.fetchone()
        return self._row_correlation_recommendation(row) if row else None

    # [FYP-FUNCTION] List/Filter Correlation Recommendations
    # [FYP-INPUT] filters: dict -- ticket_id (source or target), status, limit
    # (default 100). Pending recommendations sort first.
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

    # [FYP-APPROVAL] [FYP-DECISION] [FYP-FUNCTION] Confirm Correlation
    # Recommendation (analyst approves the suggested grouping)
    # [FYP-INPUT] recommendation_id, analyst, comments.
    # [FYP-VALIDATION] Raises KeyError if the recommendation id is unknown.
    # [FYP-PROCESS] If the recommended source alert is not yet stored, and the
    # recommendation payload carries a "candidate_alert" snapshot, upserts that
    # alert first. Then link_alert()s the source alert onto the target ticket
    # (link_source="analyst_confirmed_correlation"); if
    # archive_after_approval was set, also archive_duplicate_ticket()s the
    # source ticket into the target.
    # Note: unlike casework_store.py's confirm_correlation_recommendation(),
    # this method does not special-case merge/archive-duplicate recommendation
    # types via merge_tickets() -- it always treats the recommendation as an
    # alert-link (only archiving the source ticket as a side effect when
    # archive_after_approval is set).
    # [FYP-DATABASE] UPDATE correlation_recommendations SET status='confirmed',
    # reviewed_by/reviewed_at/analyst_comments.
    # [FYP-OUTPUT] {"recommendation": ..., "ticket": ...}.
    # [FYP-FUNCTION] `confirm_correlation_recommendation` — implements the confirm correlation recommendation operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `recommendation_id`, `analyst`, `comments`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_confirm_correlation_recommendation; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `KeyError`, `append_activity`, `archive_duplicate_ticket`, `commit`, `connect`, `cursor`, `execute`, `get`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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

    # [FYP-DECISION] [FYP-FUNCTION] Reject Correlation Recommendation
    # [FYP-DATABASE] UPDATE correlation_recommendations SET status='rejected',
    # reviewed_by/reviewed_at/analyst_comments. Logs "correlation_rejected" on
    # the target ticket.
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

    # [FYP-DECISION] [FYP-FUNCTION] Edit Correlation Recommendation Target
    # [FYP-VALIDATION] Raises KeyError if the recommendation is unknown.
    # [FYP-DATABASE] UPDATE correlation_recommendations SET
    # target_ticket_id=%s, analyst_comments=%s. Note: unlike casework_store.py,
    # this does not also update target_incident_id or the status column, and
    # does not validate that target_ticket_id actually exists, nor does it
    # re-link the source alert onto the new target -- it only edits the
    # recommendation row.
    # [FYP-FLOW] Logs "correlation_edited" against target_ticket_id.
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

# [FYP-SECTION] Ticket merge / split / archive -- duplicate-ticket handling.

    # [FYP-FUNCTION] Move Alert To A Different Ticket
    # [FYP-DATABASE] If currently linked elsewhere, DELETE FROM ticket_alerts
    # WHERE alert_id=%s (removes ALL links for that alert, not scoped to a
    # specific source ticket_id -- differs from casework_store.py, which
    # deletes only the (source_ticket_id, alert_id) pair). Then delegates to
    # link_alert() (link_source="manual_move").
    def move_alert_to_ticket(self, alert_id: str, target_ticket_id: str, analyst: str = "SOC Analyst", reason: str = "Manual alert move") -> dict[str, Any]:
        current = self.ticket_for_alert(alert_id)
        if current:
            with self.connect() as con, con.cursor() as cur:
                cur.execute("DELETE FROM ticket_alerts WHERE alert_id=%s", (alert_id,))
                con.commit()
        return self.link_alert(target_ticket_id, alert_id, relationship=reason, linked_by=analyst, link_source="manual_move", link_reason=reason, confirmed_by=analyst)

    # [FYP-FUNCTION] Split Alert Into New Ticket
    # [FYP-PROCESS] unlink_alert()s the alert from the source ticket, then
    # create_ticket_from_alert()s a new ticket for it (owner set to `analyst`,
    # differing from casework_store.py which inherits the source ticket's
    # owner).
    # [FYP-FLOW] Logs "alert_split_to_new_ticket" on the new ticket.
    def split_alert_to_new_ticket(self, ticket_id: str, alert_id: str, analyst: str = "SOC Analyst", reason: str = "Split alert into a separate incident") -> dict[str, Any]:
        self.unlink_alert(ticket_id, alert_id, analyst=analyst, reason=reason)
        new_ticket = self.create_ticket_from_alert(alert_id, owner=analyst, status="To Parse")
        self.append_activity(new_ticket["ticket_id"], analyst, "alert_split_to_new_ticket", "completed", reason, {"source_ticket_id": ticket_id, "alert_id": alert_id})
        return new_ticket

    # [FYP-FUNCTION] Archive Ticket As Duplicate
    # [FYP-DATABASE] Via update_ticket(): archive_status="archived_duplicate",
    # merged_into_ticket_id=target, archived_by/archived_at/archive_reason,
    # status="Archived Duplicate", current_stage="case_closure". Row is kept
    # (auditable), not deleted.
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

    # [FYP-EVALUATOR] [FYP-FUNCTION] Merge Two Tickets
    # [FYP-INPUT] source_ticket_id, target_ticket_id, analyst, reason,
    # archive_duplicate (default True).
    # [FYP-VALIDATION] Raises KeyError if either ticket is missing.
    # [FYP-PROCESS] Re-links every alert on the source ticket onto the target
    # (link_source="ticket_merge"), unions affected_assets/affected_users/iocs
    # onto the target, then archives (default) or closes the source ticket.
    # [FYP-FLOW] Calls mark_context_refresh_required() on the target.
    # [FYP-OUTPUT] The merged (target) ticket.
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

# [FYP-SECTION] Core ticket read / update -- the case record itself.

    # [FYP-FUNCTION] List/Search Tickets
    # [FYP-INPUT] filters: dict -- status, stage, severity, owner ("me"/
    # "unassigned"/explicit), q, open_only, limit (default 200);
    # include_archived: bool | None -- convenience kwarg merged into filters as
    # "include_archived" (no SQLite equivalent parameter).
    # [FYP-DATABASE] Dynamic WHERE clause; when open_only is not set but
    # include_archived is explicitly False, adds
    # COALESCE(archive_status,'active')='active'.
    # [FYP-OUTPUT] list of ticket summaries via _row_ticket(include_children=
    # False).
    # [FYP-FUNCTION] `list_tickets` — implements the list tickets operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `filters`, `include_archived`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_case, soc_reporting_agent/backend/app.py:api_dashboard, soc_reporting_agent/backend/app.py:api_tickets; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_norm_status`, `_row_ticket`, `append`, `connect`, `cursor`, `execute`, `extend`, `fetchall`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-EVALUATOR] [FYP-FUNCTION] Load Single Ticket ("load case")
    # [FYP-DATABASE] SELECT * FROM tickets WHERE ticket_id=%s.
    # [FYP-OUTPUT] None if not found, else the full ticket record via
    # _row_ticket(include_children=True) -- related_alerts, activity_log,
    # correlation_recommendations, pending_correlation_count,
    # correlation_history. Canonical "load a case" entry point; used
    # extensively by backend/app.py and by nearly every other method in this
    # class after a write, so callers always see a consistent, fully-hydrated
    # shape.
    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM tickets WHERE ticket_id=%s", (ticket_id,))
            row = cur.fetchone()
        return self._row_ticket(row, include_children=True) if row else None

    # [FYP-EVALUATOR] [FYP-FUNCTION] Partial Update Ticket ("save case")
    # [FYP-INPUT] ticket_id; fields: dict of any subset of the allowed keys
    # (same allow-list as casework_store.py: title, severity, confidence,
    # status, owner, current_stage, affected_assets, affected_users, iocs,
    # every <stage>_result key, archive_status, merged_into_ticket_id,
    # archived_by, archived_at, archive_reason; also reads
    # fields.get("next_required_approval") for the workflow_state snapshot
    # below, though that key is not itself a `tickets` column); actor/action/
    # message for the activity log entry.
    # [FYP-PROCESS] Only allow-listed keys are written; if no recognised field
    # was supplied, returns the current ticket unchanged without writing
    # (short-circuit not present in casework_store.py's version). Setting
    # status to "Closed" also stamps closed_at.
    # [FYP-DATABASE] UPDATE tickets SET ... WHERE ticket_id=%s, then an
    # additional INSERT ... ON CONFLICT (ticket_id) DO UPDATE into
    # workflow_state(ticket_id, current_stage, status, next_required_approval,
    # payload_json, updated_at) -- a denormalised "latest state" snapshot table
    # that casework_store.py (SQLite) does not maintain at all.
    # [FYP-FLOW] Always calls append_activity().
    # [FYP-OUTPUT] The updated ticket via get_ticket().
    # This is the single write path nearly every other method in this class
    # (and attach_agent_result / record_approval / record_evidence_gap_decision)
    # funnels through -- the "save case" counterpart to get_ticket() above.
    # [FYP-FUNCTION] `update_ticket` — persists or updates update ticket state used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `fields`, `actor`, `action`, `message`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:_refresh_ticket_after_incident_grouping_review, soc_reporting_agent/backend/app.py:_sync_ticket_report_manifest, soc_reporting_agent/backend/app.py:api_ticket_assign; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_json`, `append`, `append_activity`, `commit`, `connect`, `cursor`, `endswith`, `execute`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

# [FYP-SECTION] Activity / audit log.

    # [FYP-FUNCTION] Append Activity Log Entry
    # [FYP-INPUT] ticket_id, actor, action, status, message, payload.
    # [FYP-DATABASE] INSERT INTO activity(...) RETURNING id; also bumps
    # tickets.updated_at for the same ticket.
    # [FYP-USED-BY] Called by nearly every mutating method in this class.
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

    # [FYP-FUNCTION] List Activity For Ticket
    # [FYP-DATABASE] SELECT * FROM activity WHERE ticket_id=%s ORDER BY id DESC
    # LIMIT %s.
    def activity(self, ticket_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM activity WHERE ticket_id=%s ORDER BY id DESC LIMIT %s", (ticket_id, limit))
            rows = cur.fetchall()
        return [self._row_activity(row) for row in rows]

# [FYP-SECTION] Dashboard aggregation -- summary counters for the SOC
# analyst landing page.

    # [FYP-FUNCTION] Compute Dashboard Summary Counters
    # [FYP-INPUT] owner: str | None -- if given, scopes counts to that
    # analyst's tickets.
    # [FYP-PROCESS] Same derivation as casework_store.py's dashboard_summary():
    # pending_correlation, new_alerts, open_tickets, critical_cases,
    # pending_approval, unassigned_cases, multi_alert_cases, closed_cases, and
    # a per-stage stage_counts breakdown.
    # [FYP-OUTPUT] dict consumed by the dashboard UI's summary tiles.
    # [FYP-CALLS] list_tickets, list_alerts, list_correlation_recommendations.
    # [FYP-USED-BY] backend/app.py (confirmed via "CASEWORK.dashboard_summary"
    # grep hits).
    # [FYP-FUNCTION] `dashboard_summary` — implements the dashboard summary operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `owner`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_case, soc_reporting_agent/backend/app.py:api_dashboard, soc_reporting_agent/backend/app.py:api_tickets; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_norm_status`, `get`, `int`, `len`, `list_alerts`, `list_correlation_recommendations`, `list_tickets`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

# [FYP-SECTION] Agent input staging -- writes the JSON files that the
# pipeline agent subprocesses read as their inputs.

    # [FYP-FUNCTION] Prepare Agent Input Files For A Ticket
    # [FYP-INPUT] ticket_id; inputs_dir: Path.
    # [FYP-VALIDATION] Raises KeyError if the ticket does not exist.
    # [FYP-PROCESS] Uses stage_workflow.output_valid() to decide, per stage,
    # whether parsing_result/triage_result/threat_intel_result/
    # investigation_result/reporting_result are current enough to hand to the
    # next stage (invalid/stale ones become {} here).
    # [FYP-OUTPUT] Writes ticket_context.json, raw_alert.json,
    # processed_alert.json, parser_result.json, triage_result.json,
    # threat_intel_result.json, enriched_alert.json, investigation_result.json,
    # approval_result.json, investigation_approval_result.json,
    # reporting_result.json. Empty/invalid payloads for files other than
    # ticket_context.json/raw_alert.json are deleted (path.unlink()) if they
    # exist, rather than being written, so a re-run cannot pick up outdated
    # files.
    # Note: this is a simpler file set than casework_store.py's version (no
    # separate outputs/<ticket_id>/parsing staging directory, no
    # input_identity.json, no grouped_incident_context.json).
    # [FYP-CALLS] stage_workflow.output_valid.
    # [FYP-USED-BY] backend/app.py before launching each pipeline agent
    # subprocess (confirmed via "CASEWORK.prepare_agent_inputs" grep hit).
    # [FYP-FUNCTION] `prepare_agent_inputs` — implements the prepare agent inputs operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `inputs_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:start_background_run; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `KeyError`, `dumps`, `exists`, `get`, `get_ticket`, `items`, `mkdir`, `output_valid`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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

# [FYP-SECTION] Agent run tracking -- per-stage execution telemetry.

    # [FYP-FUNCTION] Record Agent Run Start
    # [FYP-INPUT] run_id, ticket_id, agent_name, run_type, triggered_by,
    # rerun_of_run_id, output_path, payload.
    # [FYP-DATABASE] INSERT ... ON CONFLICT (run_id) DO UPDATE SET status,
    # progress, payload_json into agent_runs, status="running", progress=0,
    # is_rerun=(run_type=="rerun").
    # [FYP-FLOW] Logs a "<agent>_<run_type>_started" activity entry, if
    # ticket_id given.
    # [FYP-USED-BY] backend/app.py (confirmed via "CASEWORK.record_agent_run_start"
    # grep hit).
    # [FYP-FUNCTION] `record_agent_run_start` — persists or updates record agent run start state used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `run_id`, `ticket_id`, `agent_name`, `run_type`, `triggered_by`, `rerun_of_run_id`, `output_path`, `payload`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:start_background_run; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_json`, `append_activity`, `commit`, `connect`, `cursor`, `execute`, `get`, `get_ticket`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-FUNCTION] Record Agent Run Finish
    # [FYP-INPUT] run_id, status, progress, output_path, error_code,
    # error_message, output_summary (ai_used/ai_model/fallback_used), payload.
    # [FYP-PROCESS] Computes duration_seconds from the run's started_at to now
    # (best-effort).
    # [FYP-DATABASE] UPDATE agent_runs SET status/progress/completed_at/
    # duration_seconds/output_path/error_code/error_message/ai_used/ai_model/
    # fallback_used/payload_json WHERE run_id=%s.
    # [FYP-FLOW] Logs a "<agent>_finished" activity entry on the run's ticket.
    # [FYP-USED-BY] backend/app.py (confirmed via "CASEWORK.record_agent_run_finish"
    # grep hit).
    # [FYP-FUNCTION] `record_agent_run_finish` — persists or updates record agent run finish state used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `run_id`, `status`, `progress`, `output_path`, `error_code`, `error_message`, `output_summary`, `payload`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:worker; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_json`, `append_activity`, `bool`, `commit`, `connect`, `cursor`, `execute`, `fetchone`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

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

    # [FYP-FUNCTION] List Agent Runs For Ticket
    # [FYP-DATABASE] SELECT * FROM agent_runs WHERE ticket_id=%s [AND
    # agent_name=%s] ORDER BY started_at DESC LIMIT %s.
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

    # [FYP-FUNCTION] Latest Agent Run For Ticket+Agent
    # Thin wrapper over list_agent_runs(..., limit=1).
    def latest_agent_run(self, ticket_id: str, agent_name: str) -> dict[str, Any] | None:
        runs = self.list_agent_runs(ticket_id, agent_name, limit=1)
        return runs[0] if runs else None

# [FYP-SECTION] Stage output attachment -- the core write path every
# pipeline agent's JSON result flows through, and the point where the
# workflow decides which stage/status the ticket moves to next.

    # [FYP-EVALUATOR] [FYP-FUNCTION] Attach Agent Result To Ticket
    # [FYP-INPUT] ticket_id, agent: str (parsing/parsing_normalisation, triage,
    # orchestration, correlation, threat_intel/threat_intelligence,
    # investigation, reporting), data: dict -- that stage's raw JSON result.
    # [FYP-PROCESS] If `agent` matches a known workflow stage, wraps `data` via
    # stage_workflow.completed_result() first. Same per-agent field/stage/
    # status decision logic as casework_store.py's attach_agent_result() (see
    # that file for the full per-agent breakdown of stage/status transitions),
    # PLUS: generates a result_id and reads SOC_RUN_ID from the environment,
    # then calls _insert_result() to additionally persist an append-only audit
    # row into the relevant per-stage results table (triage_results,
    # correlation_results, threat_intel_results, investigation_results,
    # reporting_results) alongside the update_ticket() call that
    # casework_store.py also performs. This audit trail (and the
    # workflow_state snapshot written inside update_ticket) is the main
    # structural difference from the SQLite implementation.
    # [FYP-DATABASE] Writes via update_ticket() plus _insert_result() (see
    # below).
    # [FYP-STATE] Advances tickets.current_stage / tickets.status in response to
    # a completed pipeline stage run.
    # [FYP-USED-BY] backend/app.py after each pipeline agent subprocess
    # completes (confirmed via "CASEWORK.attach_agent_result" grep hit).
    # [FYP-FUNCTION] `attach_agent_result` — implements the attach agent result operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `agent`, `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:worker, soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py:make_ticket; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_first`, `_insert_result`, `_norm_status`, `completed_result`, `fromkeys`, `get`, `get_ticket`, `getenv`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-FUNCTION] Insert Per-Stage Result Audit Row (Postgres-only, no
    # SQLite equivalent)
    # [FYP-INPUT] table: one of triage_results/investigation_results/
    # correlation_results/threat_intel_results/reporting_results; result_id,
    # ticket_id, run_id (from SOC_RUN_ID env var, may be None), status, payload
    # (the full stage result dict, stored as payload_json); **extra -- table-
    # specific typed columns (severity/confidence/classification for
    # triage_results; source_triage_result_id/chromadb_collection/
    # chromadb_path for investigation_results; source_stage for
    # correlation_results).
    # [FYP-DATABASE] INSERT ... ON CONFLICT (result_id) DO NOTHING -- append-
    # only; a duplicate result_id is silently ignored rather than overwritten.
    # [FYP-USED-BY] attach_agent_result() only.
    # [FYP-FUNCTION] `_insert_result` — persists or updates insert result state used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `table`, `result_id`, `ticket_id`, `run_id`, `status`, `payload`, `**extra`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/postgres_casework_store.py:attach_agent_result; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_json`, `commit`, `connect`, `cursor`, `execute`, `get`, `now_iso`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-FUNCTION] Latest Triage Result Audit Row (Postgres-only)
    # [FYP-DATABASE] SELECT * FROM triage_results WHERE ticket_id=%s ORDER BY
    # created_at DESC LIMIT 1; falls back to the ticket's current
    # triage_result column if no audit row exists yet (e.g. on a ticket created
    # before this audit table existed, or written via the SQLite store).
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

    # [FYP-FUNCTION] Latest Threat-Intel Result Audit Row (Postgres-only)
    # [FYP-DATABASE] SELECT * FROM threat_intel_results WHERE ticket_id=%s
    # ORDER BY created_at DESC LIMIT 1; same ticket-column fallback as
    # latest_triage_result().
    def latest_threat_intel_result(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM threat_intel_results WHERE ticket_id=%s ORDER BY created_at DESC LIMIT 1", (ticket_id,))
            row = cur.fetchone()
        if row:
            return _loads(row.get("payload_json"), {})
        ticket = self.get_ticket(ticket_id) or {}
        return ticket.get("threat_intel_result") or None

    # [FYP-FUNCTION] Check Whether An Approval Gate Is Already Satisfied
    # (Postgres-only, no SQLite equivalent)
    # [FYP-INPUT] ticket_id, gate (default "triage_approval"; "
    # investigation_approval" reads investigation_approval_result instead of
    # approval_result).
    # [FYP-DECISION] True if the relevant result's decision/status is one of
    # approved/approve/completed/continue_to_reporting.
    # No confirmed caller found via repo grep at time of review.
    def approval_complete(self, ticket_id: str, gate: str = "triage_approval") -> bool:
        ticket = self.get_ticket(ticket_id) or {}
        key = "investigation_approval_result" if gate == "investigation_approval" else "approval_result"
        result = ticket.get(key) or {}
        decision = _norm_status(result.get("decision") or result.get("status"))
        return decision in {"approved", "approve", "completed", "continue_to_reporting"}

# [FYP-SECTION] Approval gates -- human-in-the-loop stage transitions. A
# ticket only advances past an approval_gate stage when an analyst
# explicitly records a decision here.

    # [FYP-APPROVAL] [FYP-DECISION] [FYP-FUNCTION] Record Investigation
    # Evidence-Gap Decision
    # [FYP-INPUT] ticket_id, decision (normalised to "continue_to_reporting" or
    # "return_to_triage"; anything else raises ValueError), comments, analyst.
    # [FYP-VALIDATION] Raises KeyError if the ticket does not exist.
    # [FYP-DATABASE] Persists the decision via _insert_approval(ticket_id,
    # "investigation_evidence_gap_decision", payload) (audit row -- no SQLite
    # equivalent), then writes investigation_approval_result via update_ticket();
    # on "return_to_triage" also rewrites triage_result with
    # current_stage="triage_requery_requested" and
    # investigation_throwback=True.
    # [FYP-STAGE-LOCK] "return_to_triage" moves current_stage back to "triage".
    # [FYP-USED-BY] backend/app.py (evidence-gap decision endpoint).
    # [FYP-FUNCTION] `record_evidence_gap_decision` — persists or updates record evidence gap decision state used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `decision`, `comments`, `analyst`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_ticket_evidence_gap_decision, soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py:test_decision_buttons_and_branches; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `KeyError`, `ValueError`, `_insert_approval`, `_norm_status`, `dict`, `get`, `get_ticket`, `isinstance`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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

    # [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-FUNCTION] Record Analyst Approval
    # [FYP-INPUT] ticket_id, decision (only "approved"/"approve" accepted),
    # comments, analyst, gate (defaults to the ticket's current_stage).
    # [FYP-VALIDATION] Raises KeyError if ticket missing; ValueError if the
    # resolved stage has no approval_gate, if
    # stage_workflow.can_approve(ticket, stage) rejects it, or if decision is
    # not an approval.
    # [FYP-DATABASE] Persists the decision via _insert_approval() (audit row),
    # then writes the field set from stage_workflow.approval_fields() via
    # update_ticket().
    # [FYP-CALLS] stage_workflow.stage_definition, stage_workflow.can_approve,
    # stage_workflow.approval_fields.
    # [FYP-USED-BY] record_soc_review(); backend/app.py approval endpoints.
    # [FYP-FUNCTION] `record_approval` — persists or updates record approval state used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `ticket_id`, `decision`, `comments`, `analyst`, `gate`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:api_approval, soc_reporting_agent/backend/app.py:api_ticket_approve, soc_reporting_agent/backend/app.py:api_ticket_more_evidence; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `KeyError`, `ValueError`, `_insert_approval`, `_norm_status`, `approval_fields`, `can_approve`, `get`, `get_ticket`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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

    # [FYP-FUNCTION] Insert Approval Audit Row (Postgres-only, no SQLite
    # equivalent)
    # [FYP-DATABASE] INSERT INTO approvals(approval_id, ticket_id, gate,
    # decision, status, analyst, comments, payload_json, created_at). Every
    # approval decision recorded through record_approval()/
    # record_evidence_gap_decision() is also durably logged here, separate from
    # the ticket row's own approval_result/investigation_approval_result
    # columns (which only hold the most recent decision).
    def _insert_approval(self, ticket_id: str, gate: str, payload: dict[str, Any]) -> None:
        approval_id = payload.get("approval_id") or f"APR-{uuid.uuid4().hex[:12].upper()}"
        with self.connect() as con, con.cursor() as cur:
            cur.execute(
                "INSERT INTO approvals(approval_id, ticket_id, gate, decision, status, analyst, comments, payload_json, created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (approval_id, ticket_id, gate, payload.get("decision") or "", payload.get("status") or "", payload.get("analyst") or "SOC Analyst", payload.get("comments") or "", _json(payload), payload.get("created_at") or now_iso()),
            )
            con.commit()

    # [FYP-APPROVAL] [FYP-FUNCTION] Record SOC Analyst Final Review
    # Thin wrapper over record_approval(..., gate="reporting_approval") mapping
    # "confirmed"/"approved"/"approve" to "approved" before delegating.
    def record_soc_review(self, ticket_id: str, decision: str = "confirmed", comments: str = "", analyst: str = "SOC Analyst") -> dict[str, Any]:
        mapped = "approved" if _norm_status(decision) in {"confirmed", "approved", "approve"} else decision
        return self.record_approval(ticket_id, mapped, comments=comments, analyst=analyst, gate="reporting_approval")

# [FYP-SECTION] Report availability lookup.

    # [FYP-FUNCTION] Summarise Available Reports For Ticket
    # [FYP-VALIDATION] Raises KeyError if ticket missing.
    # [FYP-OUTPUT] The ticket's reporting_result plus a fixed list of four
    # report slots (executive_summary, technical_findings, soc_analyst_review,
    # final_incident_report), each "available" once any reporting_result
    # exists, else "not_ready". Identical logic to casework_store.py.
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

# [FYP-SECTION] Row -> dict mappers. Deserialise json/jsonb columns and
# assemble the nested/derived fields (linked_ticket, related_alerts,
# activity_log, correlation_recommendations, alert_count) on top of the raw
# table columns.

    # [FYP-FUNCTION] Map Correlation Recommendation Row -> Dict
    # [FYP-DATABASE] Deserialises payload_json as the base dict, then overlays
    # the individual typed columns on top so they always win over any stale
    # copy inside the JSON blob.
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

    # [FYP-FUNCTION] Map Agent Run Row -> Dict
    # Converts the RealDictCursor row (dict-like) to a plain dict, coercing
    # boolean/None columns (is_rerun, ai_used, fallback_used) and deserialising
    # payload_json.
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

    # [FYP-FUNCTION] Map Alert Row -> Dict
    # Also runs a lookup query (ticket_alerts) to attach linked_ticket (most
    # recent ticket_id this alert is linked to, or None).
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

    # [FYP-FUNCTION] Map Activity Row -> Dict
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

    # [FYP-FUNCTION] Map Ticket Row -> Dict
    # [FYP-INPUT] row: dict-like (RealDictCursor row); include_children: bool --
    # when False (list views), only flat ticket columns + alert_count; when
    # True (get_ticket), also related_alerts (JOIN ticket_alerts+alerts),
    # activity_log, correlation_recommendations, pending_correlation_count,
    # correlation_history.
    # [FYP-DATABASE] A COUNT query against ticket_alerts, and (when
    # include_children) a JOIN query plus calls to activity() and
    # list_correlation_recommendations().
    # [FYP-USED-BY] get_ticket(), list_tickets().
    # Uses _row_keys()-based "col in keys" guards on newer columns
    # (incident_id, correlation_result_json, archive_status,
    # merged_into_ticket_id, archived_by, archived_at, archive_reason) for
    # forward/backward schema compatibility, same intent as
    # casework_store.py's row-keys guards.
    # [FYP-FUNCTION] `_row_ticket` — implements the row ticket operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `row`, `include_children`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/casework_store.py:get_ticket, soc_reporting_agent/backend/casework_store.py:list_tickets, soc_reporting_agent/backend/postgres_casework_store.py:get_ticket; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_loads`, `_norm_status`, `_row_alert`, `_row_keys`, `activity`, `append`, `connect`, `cursor`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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
