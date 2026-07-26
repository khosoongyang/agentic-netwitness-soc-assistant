"""
workflow_state_store.py — shared per-incident workflow status persistence.

Owns the `incidents` table schema in soc_db/soc_incidents.db (moved here,
unchanged, from app.py's previous db_init()) plus the workflow-status
columns added for the Triage approval flow, and (this revision) the full
Triage -> Threat Intelligence -> Investigation -> Reporting status model,
the `workflow_approvals` audit table, and the atomic approve/reject
transitions for all three mandatory-approval gates. Both app.py and
soc_workflow.py import this module so there is exactly one writer and one
schema owner.

This module is a PURE database layer: it validates and records state
transitions, but never runs a workflow stage and never spawns a worker
thread. soc_workflow.py runs stages (including the stage-claim/lease
machinery, which needs its own transactional access and lives there,
reusing `_tx()` from here); app.py starts the worker thread after a
successful approval. Keeping this boundary strict avoids a circular
import between this module and soc_workflow.py.

Not related to soc_investigation_agent_revised/sync_engine.py, which
persists Investigation-stage Incident objects + a Chroma vector index for
correlation — a different subsystem with no concept of workflow status.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOC_DB_DIR = ROOT / "soc_db"
SOC_DB_DIR.mkdir(exist_ok=True)
DB_FILE = SOC_DB_DIR / "soc_incidents.db"

_ACTIVE_WORKFLOW_STATUSES = {"Processing", "Awaiting Approval"}


class WorkflowAlreadyRunningError(Exception):
    """Raised by start_run() when a workflow is already Processing or
    Awaiting Approval for this incident and cannot be replaced."""
    def __init__(self, incident_id: str, state: dict):
        self.incident_id = incident_id
        self.state = state
        super().__init__(
            f"Workflow already {state.get('workflow_status')!r} for "
            f"incident {incident_id!r} (run_id={state.get('run_id')!r})")


class StaleWriteError(RuntimeError):
    """Raised by the guarded status setters when run_id no longer matches
    the incident's current run — a slow/abandoned run trying to write over
    a newer one."""


class ApprovalConflictError(RuntimeError):
    """Raised by every approve/reject/retry transition when the incident
    is not in the exact state that action requires — already
    approved/rejected/retried by someone else, or superseded by a newer
    run. Two analysts (or a double-click) racing on the same action can
    only have one of them succeed; the other gets this."""


def db_connect() -> sqlite3.Connection:
    """Canonical connection factory — app.py imports this instead of
    defining its own (db_upsert_incidents, db_get_incident, etc. all use it)."""
    con = sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=15)
    con.row_factory = sqlite3.Row
    return con


def _autocommit_connect() -> sqlite3.Connection:
    """Manual transaction control for the guarded read-then-write helpers
    below — isolation_level=None so an explicit BEGIN IMMEDIATE isn't
    nested inside sqlite3's own implicit transaction."""
    con = sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=15)
    con.row_factory = sqlite3.Row
    con.isolation_level = None
    return con


def _tx(fn):
    """Every guarded write in this module (and, via import, in
    soc_workflow.py's stage-claim/lease/completion machinery) follows this
    exact shape — BEGIN IMMEDIATE, do work, COMMIT; on ANY exception, roll
    back only if a transaction is actually open, then re-raise. No caller
    does its own manual conditional rollback-then-reraise."""
    con = _autocommit_connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        result = fn(con)
        con.execute("COMMIT")
        return result
    except Exception:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def db_init() -> None:
    """Full incidents + fetch_log + workflow_approvals schema — moved here
    verbatim from app.py's previous db_init(); app.py now imports this."""
    with db_connect() as con:
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        con.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id          TEXT PRIMARY KEY,
                title       TEXT,
                severity    TEXT,
                status      TEXT,
                assignee    TEXT,
                alert_count INTEGER,
                created     TEXT,
                updated     TEXT,
                raw_json    TEXT,
                first_seen  TEXT,
                last_seen   TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS fetch_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fetched_at  TEXT,
                count       INTEGER
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS workflow_approvals (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id    TEXT NOT NULL,
                run_id         TEXT NOT NULL,
                approval_stage TEXT NOT NULL,
                decision       TEXT NOT NULL,
                analyst        TEXT,
                comments       TEXT,
                decided_at     TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS global_execution_locks (
                lock_name    TEXT PRIMARY KEY,
                owner_id     TEXT,
                incident_id  TEXT,
                run_id       TEXT,
                acquired_at  TEXT,
                expires_at   TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS workflow_activity (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id  TEXT NOT NULL,
                run_id       TEXT,
                stage        TEXT,
                action       TEXT NOT NULL,
                actor        TEXT,
                comments     TEXT,
                metadata_json TEXT,
                occurred_at  TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS report_edits (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id           TEXT NOT NULL,
                run_id                TEXT NOT NULL,
                report_type           TEXT NOT NULL,
                source_report_set_id  TEXT,
                original_blocks_json  TEXT,
                edited_blocks_json    TEXT NOT NULL,
                version               INTEGER NOT NULL DEFAULT 1,
                created_at            TEXT NOT NULL,
                updated_at            TEXT NOT NULL,
                last_edited_by        TEXT,
                UNIQUE(incident_id, run_id, report_type)
            )
        """)
        con.commit()
    _ensure_workflow_columns()
    _ensure_workflow_approvals_attempt_columns()


def _ensure_workflow_columns() -> None:
    """Additive-only ALTER TABLE — same pattern app.py already used once for
    parsing_status/parsing_result_json. Never redefines the base table."""
    with db_connect() as con:
        existing = {r["name"] for r in con.execute("PRAGMA table_info(incidents)").fetchall()}
        for col, ddl in {
            "parsing_status":            "TEXT",
            "parsing_result_json":       "TEXT",
            "run_id":                    "TEXT",
            "triage_status":             "TEXT",
            "workflow_status":           "TEXT",
            "approval_stage":            "TEXT",
            "triage_result_json":        "TEXT",
            "workflow_updated_at":       "TEXT",
            "raw_incident_path":         "TEXT",
            "threat_intel_status":       "TEXT",
            "threat_intel_result_json":  "TEXT",
            "threat_intel_updated_at":   "TEXT",
            "investigation_status":        "TEXT",
            "investigation_result_json":   "TEXT",
            "investigation_updated_at":    "TEXT",
            "reporting_status":            "TEXT",
            "reporting_result_json":       "TEXT",
            "reporting_updated_at":        "TEXT",
            "approved_by":               "TEXT",
            "approved_at":               "TEXT",
            "approval_comments":         "TEXT",
            "worker_id":                 "TEXT",
            "worker_stage":              "TEXT",
            "worker_started_at":         "TEXT",
            "worker_heartbeat_at":       "TEXT",
            "worker_lease_expires_at":   "TEXT",
            "last_error":                "TEXT",
            "worker_progress_note":      "TEXT",
            "investigation_attempt":     "INTEGER NOT NULL DEFAULT 1",
            "threat_intel_attempt":      "INTEGER NOT NULL DEFAULT 1",
            "reporting_attempt":         "INTEGER NOT NULL DEFAULT 1",
            "ioc_correlation_status":       "TEXT",
            "ioc_correlation_result_json":  "TEXT",
            "ioc_correlation_updated_at":   "TEXT",
        }.items():
            if col not in existing:
                con.execute(f"ALTER TABLE incidents ADD COLUMN {col} {ddl}")
        con.commit()


def _ensure_workflow_approvals_attempt_columns() -> None:
    """Additive columns distinguishing WHICH EXECUTION of a stage produced a
    decision (stage_attempt) from WHICH DECISION NUMBER it is
    (approval_attempt) — see rerun_stage()/claim_stage(). Replaces the old
    one-decision-per-stage unique index (which required deleting a prior
    decision on rerun to avoid a constraint violation) with one scoped to
    both attempt numbers, so no approval/rejection is ever deleted."""
    with db_connect() as con:
        existing = {r["name"] for r in
                    con.execute("PRAGMA table_info(workflow_approvals)").fetchall()}
        for col in ("stage_attempt", "approval_attempt"):
            if col not in existing:
                con.execute(
                    f"ALTER TABLE workflow_approvals ADD COLUMN {col} "
                    "INTEGER NOT NULL DEFAULT 1")
        con.execute("DROP INDEX IF EXISTS ux_workflow_approvals_stage")
        con.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_workflow_approvals_stage_attempt
            ON workflow_approvals(incident_id, run_id, approval_stage,
                                  stage_attempt, approval_attempt)
        """)
        con.commit()
    _ensure_workflow_approvals_metadata_column()


def _ensure_workflow_approvals_metadata_column() -> None:
    """Additive, nullable metadata_json column — durable, per-decision
    binding metadata (report_set_id / candidate_manifest_path /
    candidate_manifest_sha256 / etc. for the Reporting gate; unused/NULL
    for every other gate). Existing rows read back as NULL. This is what
    lets an approved Reporting candidate set stay provably identifiable
    even after a later rerun clears the working reporting_result_json —
    see commit_reporting_approval()/get_approved_reporting_sets()."""
    with db_connect() as con:
        existing = {r["name"] for r in
                    con.execute("PRAGMA table_info(workflow_approvals)").fetchall()}
        if "metadata_json" not in existing:
            con.execute("ALTER TABLE workflow_approvals ADD COLUMN metadata_json TEXT")
        con.commit()


def start_run(incident_id: str, *, allow_retry: bool = False) -> str:
    """Atomically checks for an already-active run (BEGIN IMMEDIATE takes
    SQLite's write lock before the read, so two sessions racing on the same
    incident can't both pass). ``allow_retry`` permits replacing an
    Awaiting Approval run, but never a run that is already Processing.
    Every
    status column is set to an explicit, meaningful value (never left
    NULL) — Parsing starts Processing immediately; every later stage
    starts Pending; the workflow itself starts Processing."""
    db_init()

    def _do(con):
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        current_status = row["workflow_status"] if row else None
        if (current_status == "Processing"
                or (current_status == "Awaiting Approval" and not allow_retry)):
            raise WorkflowAlreadyRunningError(incident_id, dict(row))

        run_id = f"{incident_id}@{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc).isoformat()
        fields = {
            "id": str(incident_id), "run_id": run_id,
            "parsing_status": "Processing", "parsing_result_json": None,
            "triage_status": "Pending", "triage_result_json": None,
            "raw_incident_path": None,
            "threat_intel_status": "Pending", "threat_intel_result_json": None,
            "threat_intel_updated_at": None,
            "investigation_status": "Pending", "investigation_result_json": None,
            "investigation_updated_at": None,
            "reporting_status": "Pending", "reporting_result_json": None,
            "reporting_updated_at": None,
            "workflow_status": "Processing", "approval_stage": None,
            "approved_by": None, "approved_at": None, "approval_comments": None,
            "worker_id": None, "worker_stage": None, "worker_started_at": None,
            "worker_heartbeat_at": None, "worker_lease_expires_at": None,
            "worker_progress_note": None,
            "last_error": None, "workflow_updated_at": now,
            "investigation_attempt": 1, "threat_intel_attempt": 1, "reporting_attempt": 1,
            "ioc_correlation_status": "Pending", "ioc_correlation_result_json": None,
            "ioc_correlation_updated_at": None,
        }
        cols = ", ".join(fields)
        placeholders = ", ".join("?" for _ in fields)
        updates = ", ".join(f"{k}=excluded.{k}" for k in fields if k != "id")
        con.execute(
            f"INSERT INTO incidents ({cols}) VALUES ({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {updates}",
            tuple(fields.values()))
        return run_id

    return _tx(_do)


def _guarded_update(incident_id: str, run_id: str | None, sets: dict) -> None:
    """Rejects the write if run_id doesn't match the row's current run_id —
    guards against a slow/abandoned run overwriting a newer run's status.
    Used for simple, non-ownership-critical single-column writes; stage
    *completion* (result + status together) goes through
    soc_workflow.complete_stage() instead, which additionally checks
    worker ownership, not just run_id."""
    con = _autocommit_connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        if run_id is not None:
            row = con.execute("SELECT run_id FROM incidents WHERE id=?",
                              (str(incident_id),)).fetchone()
            if row is not None and row["run_id"] and row["run_id"] != run_id:
                con.execute("ROLLBACK")
                raise StaleWriteError(
                    f"workflow_state_store: stale write refused for incident "
                    f"{incident_id!r} (run_id {run_id!r} != current "
                    f"{row['run_id']!r})")
        sets = dict(sets)
        sets["workflow_updated_at"] = datetime.now(timezone.utc).isoformat()
        cols = ", ".join(f"{k}=?" for k in sets)
        con.execute(f"UPDATE incidents SET {cols} WHERE id=?",
                   (*sets.values(), str(incident_id)))
        con.execute("COMMIT")
    except StaleWriteError:
        raise
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def set_parsing_status(incident_id: str, run_id: str, status: str) -> None:
    _guarded_update(incident_id, run_id, {"parsing_status": status})


def set_triage_status(incident_id: str, run_id: str, status: str) -> None:
    _guarded_update(incident_id, run_id, {"triage_status": status})


def set_workflow_status(incident_id: str, run_id: str, status: str, *,
                        approval_stage: str | None = None) -> None:
    sets = {"workflow_status": status}
    if approval_stage is not None:
        sets["approval_stage"] = approval_stage
    _guarded_update(incident_id, run_id, sets)


def save_triage_result(incident_id: str, run_id: str, triage_result: dict) -> None:
    _guarded_update(incident_id, run_id,
                    {"triage_result_json": json.dumps(triage_result, default=str)})


def save_parsing_result(incident_id: str, run_id: str, summary: dict) -> None:
    """Persists the run-scoped compact parsing summary (status,
    parser_confidence, output_files paths, run_id) — the ACTUAL writer
    for parsing_result_json in the live pipeline. app.py's older
    db_save_parsing_result()/db_load_parsed_context() are never called by
    the live workflow and are not used by this plan's durable-resume
    path."""
    _guarded_update(incident_id, run_id,
                    {"parsing_result_json": json.dumps(summary, default=str)})


def save_stage_ai_summary(
    incident_id: str,
    run_id: str,
    stage: str,
    summary_fields: dict,
) -> bool:
    """Merge generated AI-summary metadata into the current stage result.

    This supports one-time backfill for results created before every workflow
    stage stored ``ai_summary``. The merge reads the latest JSON inside the
    same transaction, so a page holding an older copy cannot overwrite newer
    native stage output. Returns False when the run was superseded or no
    stage result exists to enrich.
    """
    key = str(stage or "").strip().lower().replace(" ", "_")
    aliases = {
        "parsing_and_normalisation": "parsing",
        "parsing_normalisation": "parsing",
        "threat_intelligence_enrichment": "threat_intel",
        "threat_intelligence": "threat_intel",
    }
    key = aliases.get(key, key)
    result_column = {
        "parsing": "parsing_result_json",
        "triage": "triage_result_json",
        "threat_intel": "threat_intel_result_json",
        "investigation": "investigation_result_json",
        "reporting": "reporting_result_json",
    }.get(key)
    if not result_column:
        raise ValueError(f"Unsupported workflow stage for AI summary: {stage!r}")

    allowed_fields = {
        name: value for name, value in dict(summary_fields or {}).items()
        if name in {
            "ai_summary", "ai_summary_model", "ai_summary_generated_at",
            "ai_thinking",
        }
    }
    if not allowed_fields:
        return False

    def _do(con):
        row = con.execute(
            f"SELECT run_id, {result_column} AS result_json "
            "FROM incidents WHERE id=?",
            (str(incident_id),),
        ).fetchone()
        if row is None or row["run_id"] != run_id or not row["result_json"]:
            return False
        try:
            current = json.loads(row["result_json"])
        except Exception:
            return False
        if not isinstance(current, dict):
            return False
        current.update(allowed_fields)
        con.execute(
            f"UPDATE incidents SET {result_column}=?, workflow_updated_at=? "
            "WHERE id=? AND run_id=?",
            (
                json.dumps(current, default=str),
                datetime.now(timezone.utc).isoformat(),
                str(incident_id),
                run_id,
            ),
        )
        return True

    return bool(_tx(_do))


def save_raw_incident_path(incident_id: str, run_id: str, path: str) -> None:
    _guarded_update(incident_id, run_id, {"raw_incident_path": path})


def set_last_error(incident_id: str, run_id: str, message: str) -> None:
    _guarded_update(incident_id, run_id, {"last_error": message})


def save_ioc_correlation_result(incident_id: str, run_id: str, *, status: str,
                                result: dict) -> None:
    """Persists a ONE-TIME internal IOC correlation snapshot for this run
    (computed right after Triage completes — see
    soc_workflow.run_until_triage_approval) so the case page and Unified
    Verdict read a stable, run-scoped result instead of recomputing a live
    corpus scan on every render, which could change the Unified
    Verdict/Key Findings/Evidence tab with no workflow stage ever running."""
    _guarded_update(incident_id, run_id, {
        "ioc_correlation_status": status,
        "ioc_correlation_result_json": json.dumps(result, default=str),
        "ioc_correlation_updated_at": datetime.now(timezone.utc).isoformat(),
    })


def get_state(incident_id: str) -> dict | None:
    db_init()
    with db_connect() as con:
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        return dict(row) if row else None


def get_approval_history(incident_id: str, run_id: str | None = None) -> list[dict]:
    """Reads the permanent workflow_approvals audit trail — previously
    write-only (never surfaced anywhere in the UI). Returns every decision
    ever recorded for this incident (optionally scoped to one run_id),
    oldest first. Never deletes anything; rerun_stage() no longer clears
    prior rows, so this is a complete history across every stage_attempt."""
    db_init()
    with db_connect() as con:
        if run_id is not None:
            rows = con.execute(
                "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
                "ORDER BY decided_at ASC", (str(incident_id), run_id)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM workflow_approvals WHERE incident_id=? "
                "ORDER BY decided_at ASC", (str(incident_id),)).fetchall()
        return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
# Atomic approval / rejection transitions — one gate each for Triage,
# Investigation, and Reporting. Every function here is a PURE database
# transition: it validates preconditions and records the decision; it
# never spawns a worker thread. app.py spawns soc_workflow.run_stage_chain
# immediately after a successful approve_*() call — see app.py's approval
# button handlers for the actual thread spawn.
# ══════════════════════════════════════════════════════════════════════════

# approval_stage -> the incidents column tracking how many times THAT stage
# has been started/rerun. Triage has no such column: its retry path is a
# fresh start_run(allow_retry=True), so every Triage decision is inherently
# scoped to a distinct run_id already — stage_attempt is always 1 for it.
_APPROVAL_STAGE_ATTEMPT_COLUMN = {
    "investigation": "investigation_attempt",
    "reporting": "reporting_attempt",
}


def _atomic_stage_transition(incident_id: str, run_id: str, *, expect: dict,
                             sets: dict, approval_stage: str, decision: str,
                             analyst: str, comments: str = "",
                             metadata: dict | None = None) -> dict:
    """Shared compare-and-swap engine for every approve/reject action at
    every gate. `expect` = required current column values (else
    ApprovalConflictError); `sets` = columns to write on success. Writes
    the permanent workflow_approvals row in the SAME transaction, stamped
    with (stage_attempt, approval_attempt) so a rerun's later decision is
    never confused with — or forced to overwrite/delete — an earlier
    attempt's decision (see rerun_stage() / claim_stage()). `metadata`, if
    given, is stored verbatim (JSON-encoded) in that same row's
    metadata_json column — used only by the Reporting gate today (see
    commit_reporting_approval()) to durably bind the decision to an exact
    candidate manifest; every other caller omits it and gets NULL."""
    def _do(con):
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        if row is None or any(row[k] != v for k, v in expect.items()):
            got = {k: (row[k] if row else None) for k in expect}
            raise ApprovalConflictError(
                f"{approval_stage} {decision}: expected {expect}, got {got}"
                if row else f"incident {incident_id!r} has no workflow state")
        now = datetime.now(timezone.utc).isoformat()
        full_sets = dict(sets)
        full_sets["workflow_updated_at"] = now
        if decision == "approved":
            full_sets.setdefault("approved_by", analyst)
            full_sets.setdefault("approved_at", now)
            full_sets.setdefault("approval_comments", comments)
        cols = ", ".join(f"{k}=?" for k in full_sets)
        con.execute(f"UPDATE incidents SET {cols} WHERE id=? AND run_id=?",
                   (*full_sets.values(), str(incident_id), run_id))
        attempt_col = _APPROVAL_STAGE_ATTEMPT_COLUMN.get(approval_stage)
        stage_attempt = int(row[attempt_col]) if attempt_col else 1
        # Scoped to THIS stage_attempt, not a running total across every
        # execution ever — each rerun is a fresh execution with its own
        # decision count (almost always 1, since a decision immediately
        # moves the stage out of "Awaiting Approval"; the only way it could
        # be >1 is two near-simultaneous decisions racing for the SAME
        # execution, which the unique index below still serializes).
        approval_attempt = 1 + (con.execute(
            "SELECT COALESCE(MAX(approval_attempt), 0) FROM workflow_approvals "
            "WHERE incident_id=? AND run_id=? AND approval_stage=? AND stage_attempt=?",
            (str(incident_id), run_id, approval_stage, stage_attempt)).fetchone()[0])
        try:
            con.execute(
                "INSERT INTO workflow_approvals (incident_id, run_id, approval_stage, "
                "decision, analyst, comments, decided_at, stage_attempt, "
                "approval_attempt, metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(incident_id), run_id, approval_stage, decision, analyst,
                 comments, now, stage_attempt, approval_attempt,
                 json.dumps(metadata, default=str) if metadata is not None else None))
        except sqlite3.IntegrityError as exc:
            raise ApprovalConflictError(
                f"{approval_stage} was already decided for run {run_id!r}") from exc
        return {"incident_id": str(incident_id), "run_id": run_id, "decided_at": now}
    return _tx(_do)


def approve_triage(incident_id: str, run_id: str, *, approved_by: str,
                   comments: str = "") -> dict:
    """Approving Triage starts Threat Intelligence — this transition ONLY
    flips the status columns; app.py spawns soc_workflow.run_stage_chain
    right after this call succeeds."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "triage", "triage_status": "Awaiting Approval"},
        sets={"triage_status": "Approved", "threat_intel_status": "Processing",
             "workflow_status": "Processing", "approval_stage": None},
        approval_stage="triage", decision="approved",
        analyst=approved_by, comments=comments)


def reject_triage(incident_id: str, run_id: str, *, rejected_by: str,
                  reason: str) -> dict:
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "triage", "triage_status": "Awaiting Approval"},
        sets={"triage_status": "Rejected", "threat_intel_status": "Blocked",
             "workflow_status": "Rejected", "approval_stage": None},
        approval_stage="triage", decision="rejected",
        analyst=rejected_by, comments=reason)


def approve_investigation(incident_id: str, run_id: str, *, approved_by: str,
                          comments: str = "") -> dict:
    """Approving Investigation starts Reporting — pure DB transition, no
    thread spawn (see module docstring); app.py spawns
    soc_workflow.run_stage_chain right after this call succeeds, exactly
    like approve_triage()."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "investigation",
               "investigation_status": "Awaiting Approval"},
        sets={"investigation_status": "Approved", "reporting_status": "Processing",
             "workflow_status": "Processing", "approval_stage": None},
        approval_stage="investigation", decision="approved",
        analyst=approved_by, comments=comments)


def reject_investigation(incident_id: str, run_id: str, *, rejected_by: str,
                         reason: str) -> dict:
    """Rejecting Investigation must block Reporting explicitly — previously
    reporting_status was left untouched (still "Pending"), which didn't
    read as blocked anywhere downstream."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "investigation",
               "investigation_status": "Awaiting Approval"},
        sets={"investigation_status": "Rejected", "reporting_status": "Blocked",
             "workflow_status": "Rejected", "approval_stage": None},
        approval_stage="investigation", decision="rejected",
        analyst=rejected_by, comments=reason)


def commit_reporting_approval(incident_id: str, run_id: str, *,
                              expected_reporting_attempt: int,
                              expected_reporting_result_json: str,
                              metadata: dict, approved_by: str,
                              comments: str = "") -> dict:
    """The final gate — this is the ONLY transition that ever sets
    workflow_status to 'Complete'.

    Pure database transition ONLY — no filesystem access, no manifest
    parsing, no hashing. The caller (reporting_approval.
    approve_reporting_candidate(), which lives outside this module
    precisely so this one stays a pure DB layer) must have already: loaded
    the candidate manifest, re-verified every structured-content/DOCX/PDF
    hash against it, confirmed no report's validation.status is "error",
    and captured the exact current `reporting_result_json` string it
    reviewed. That captured string and the attempt number it was reviewed
    against are passed back here as `expected_reporting_result_json`/
    `expected_reporting_attempt` and included in `expect`, so the existing
    compare-and-swap in _atomic_stage_transition() fails closed (raises
    ApprovalConflictError) if a concurrent rerun changed either between
    the caller's validation pass and this call — the DB-state half of the
    "approval must bind to the exact reviewed set" requirement.
    `metadata` (report_set_id / candidate_manifest_path /
    candidate_manifest_sha256 / reporting_stage_attempt /
    validation_status / warning_count) is written into this decision's own
    workflow_approvals.metadata_json row — the durable record that
    survives even after a later rerun clears reporting_result_json (see
    get_latest_approved_reporting_set()/get_approved_reporting_sets())."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "reporting", "reporting_status": "Awaiting Approval",
               "reporting_attempt": expected_reporting_attempt,
               "reporting_result_json": expected_reporting_result_json},
        sets={"reporting_status": "Approved", "workflow_status": "Complete",
             "approval_stage": None},
        approval_stage="reporting", decision="approved",
        analyst=approved_by, comments=comments, metadata=metadata)


def reject_reporting(incident_id: str, run_id: str, *, rejected_by: str,
                     reason: str) -> dict:
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "reporting", "reporting_status": "Awaiting Approval"},
        sets={"reporting_status": "Rejected", "workflow_status": "Rejected",
             "approval_stage": None},
        approval_stage="reporting", decision="rejected",
        analyst=rejected_by, comments=reason)


def _reporting_approved_set_from_row(row: dict) -> dict:
    """Shape a workflow_approvals row (approval_stage='reporting',
    decision='approved') into the record callers actually want: the
    decision's own identity plus whatever binding metadata
    commit_reporting_approval() stored with it. metadata_json is NULL for
    any row written before this column existed (or, in principle, if
    `metadata` was omitted) — callers must not assume every key is
    present."""
    try:
        metadata = json.loads(row["metadata_json"]) if row.get("metadata_json") else {}
    except (TypeError, ValueError):
        metadata = {}
    return {
        "decision_id": row["id"],
        "incident_id": row["incident_id"],
        "run_id": row["run_id"],
        "stage_attempt": row["stage_attempt"],
        "approval_attempt": row["approval_attempt"],
        "approved_by": row["analyst"],
        "approved_at": row["decided_at"],
        "comments": row["comments"],
        "report_set_id": metadata.get("report_set_id"),
        "candidate_manifest_path": metadata.get("candidate_manifest_path"),
        "candidate_manifest_sha256": metadata.get("candidate_manifest_sha256"),
        "reporting_stage_attempt": metadata.get("reporting_stage_attempt", row["stage_attempt"]),
        "validation_status": metadata.get("validation_status"),
        "warning_count": metadata.get("warning_count"),
    }


def get_approved_reporting_sets(incident_id: str, run_id: str) -> list[dict]:
    """Every approved Reporting decision ever recorded for this run,
    chronological — each one derived from an actual workflow_approvals
    row (never a guessed/reconstructed path), because a stage_attempt
    number alone does not prove which exact candidate manifest an analyst
    reviewed. Used to render "Previously Approved Packages" (§ historical
    approved sets) distinctly from whatever the current attempt is."""
    db_init()
    with db_connect() as con:
        rows = con.execute(
            "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
            "AND approval_stage='reporting' AND decision='approved' "
            "ORDER BY decided_at ASC", (str(incident_id), run_id)).fetchall()
        return [_reporting_approved_set_from_row(dict(r)) for r in rows]


def get_latest_approved_reporting_set(incident_id: str, run_id: str) -> dict | None:
    """The most recently approved Reporting decision for this run, or None
    if Reporting has never been approved. This — not the mutable, rerun-
    clearable reporting_result_json column — is the authoritative source
    for "what is currently the approved/exportable report set"."""
    sets = get_approved_reporting_sets(incident_id, run_id)
    return sets[-1] if sets else None


def rerun_stage(incident_id: str, run_id: str, stage: str) -> dict:
    """Atomically invalidate and restart a completed downstream stage.

    Parsing and Triage use ``start_run(..., allow_retry=True)`` because the
    existing entry point runs those two stages as one fresh, run-scoped
    process. This transition handles the remaining agent stages and leaves
    their status at ``Processing`` for ``soc_workflow.run_stage_chain()``.
    """
    stage = str(stage or "").strip().lower()
    if stage not in {"threat_intel", "investigation", "reporting"}:
        raise ApprovalConflictError(
            f"{stage or 'stage'} cannot be re-run with this transition")

    status_column = f"{stage}_status"
    result_column = f"{stage}_result_json"
    updated_column = f"{stage}_updated_at"

    def _do(con):
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        if row is None or row["run_id"] != run_id:
            raise ApprovalConflictError(
                f"{stage} cannot be re-run because this workflow run is stale")
        if row["workflow_status"] == "Processing":
            raise ApprovalConflictError(
                f"{stage} cannot be re-run while another stage is processing")

        allowed_current_statuses = {
            "threat_intel": {
                "Complete", "Complete with Warnings", "Failed",
            },
            "investigation": {
                "Awaiting Approval", "Approved", "Failed",
            },
            "reporting": {
                # "Rejected" is included so a rejected Reporting attempt can
                # be re-run (Reject -> Re-run is a required analyst path;
                # without this, rerun_stage() would refuse it and leave the
                # workflow stuck at Rejected with no way forward).
                "Awaiting Approval", "Approved", "Failed", "Rejected",
            },
        }
        upstream_ready = {
            "threat_intel": row["triage_status"] == "Approved",
            "investigation": row["threat_intel_status"]
                in {"Complete", "Complete with Warnings"},
            "reporting": row["investigation_status"] == "Approved",
        }
        if (row[status_column] not in allowed_current_statuses[stage]
                or not upstream_ready[stage]):
            got = {
                "run_id": row["run_id"] if row else None,
                "workflow_status": row["workflow_status"] if row else None,
                "approval_stage": row["approval_stage"] if row else None,
                status_column: row[status_column] if row else None,
            }
            raise ApprovalConflictError(
                f"{stage} cannot be re-run from the current workflow state: {got}")

        now = datetime.now(timezone.utc).isoformat()
        sets = {
            status_column: "Processing",
            result_column: None,
            updated_column: None,
            "workflow_status": "Processing",
            "approval_stage": None,
            "approved_by": None,
            "approved_at": None,
            "approval_comments": None,
            "worker_id": None,
            "worker_stage": None,
            "worker_started_at": None,
            "worker_heartbeat_at": None,
            "worker_lease_expires_at": None,
            "last_error": None,
            "workflow_updated_at": now,
        }
        if stage == "threat_intel":
            sets.update({
                "investigation_status": "Pending",
                "investigation_result_json": None,
                "investigation_updated_at": None,
                "reporting_status": "Pending",
                "reporting_result_json": None,
                "reporting_updated_at": None,
            })
        elif stage == "investigation":
            sets.update({
                "reporting_status": "Pending",
                "reporting_result_json": None,
                "reporting_updated_at": None,
            })

        # Bump this stage's attempt counter — start_run() sets it to 1 for a
        # fresh run's first execution; every rerun/retry is a genuinely new
        # execution, so it increments here. claim_stage() only READS this
        # value (to stamp stage_attempt on whatever gets persisted), it
        # never increments it itself — this is the one place a stage's
        # attempt count actually advances.
        attempt_col = {"threat_intel": "threat_intel_attempt",
                      "investigation": "investigation_attempt",
                      "reporting": "reporting_attempt"}[stage]
        sets[attempt_col] = int(row[attempt_col] or 1) + 1

        columns = ", ".join(f"{key}=?" for key in sets)
        con.execute(
            f"UPDATE incidents SET {columns} WHERE id=? AND run_id=?",
            (*sets.values(), str(incident_id), run_id))

        # NOTE: prior decisions in workflow_approvals are DELIBERATELY never
        # deleted here (they were previously, to dodge the old
        # one-row-per-stage unique index — that destroyed audit history).
        # The (incident_id, run_id, approval_stage, stage_attempt,
        # approval_attempt) unique index means the NEXT decision for this
        # stage naturally lands on a new stage_attempt without colliding
        # with any prior row.
        return {"incident_id": str(incident_id), "run_id": run_id,
                "stage": stage}

    return _tx(_do)


def rerun_pending_stage(incident_id: str, run_id: str, stage: str) -> dict:
    """Backward-compatible alias for the previous UI-only entry point."""
    return rerun_stage(incident_id, run_id, stage)


def retry_threat_intel(incident_id: str, run_id: str) -> dict:
    """Atomically resets Threat Intelligence from Failed back to
    Processing (and Investigation from Blocked back to Pending) for the
    current run — never touches Parsing or Triage. Does not itself
    re-run anything; the caller (app.py) spawns
    soc_workflow.run_stage_chain() afterward, which — being a state-aware
    dispatcher — naturally resumes from Threat Intelligence and continues
    into Investigation/Reporting on success, exactly like the first
    attempt."""
    def _do(con):
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        if (row is None or row["run_id"] != run_id
                or row["threat_intel_status"] != "Failed"):
            got = {"run_id": row["run_id"] if row else None,
                  "threat_intel_status": row["threat_intel_status"] if row else None}
            raise ApprovalConflictError(
                f"retry_threat_intel: not eligible (expected run_id={run_id!r} "
                f"and threat_intel_status='Failed', got {got})")
        now = datetime.now(timezone.utc).isoformat()
        con.execute(
            "UPDATE incidents SET threat_intel_status=?, investigation_status=?, "
            "workflow_status=?, last_error=NULL, workflow_updated_at=? "
            "WHERE id=? AND run_id=?",
            ("Processing", "Pending", "Processing", now, str(incident_id), run_id))
        return {"incident_id": str(incident_id), "run_id": run_id}
    return _tx(_do)


# ══════════════════════════════════════════════════════════════════════════
# STAGE CLAIM / LEASE  (relocated from soc_workflow.py — pure database
# transactions only; no threading, no subprocess/stage execution here. The
# background renewal THREAD (soc_workflow.LeaseRenewer) still lives in
# soc_workflow.py, which owns worker execution — it just calls the
# renew_stage_lease()/renew_global_lock() functions below on its own
# heartbeat. This module must never import threading or spawn a thread;
# see tests/test_investigation_stage.py::test_workflow_state_store_has_no_threading_import.
# ══════════════════════════════════════════════════════════════════════════

_LEASE_DURATION_SECONDS  = 45   # a claim is valid this long without renewal
_HEARTBEAT_RENEW_SECONDS = 15   # renewed this often while a stage actually runs

_STAGE_ATTEMPT_COLUMN = {
    "threat_intel": "threat_intel_attempt",
    "investigation": "investigation_attempt",
    "reporting": "reporting_attempt",
}


class StageClaimError(RuntimeError):
    """Another worker holds a live lease, the row/run/status preconditions
    don't match, or a shared-workspace lock could not be acquired within
    its bounded wait. Distinct from ApprovalConflictError: this means
    'someone/something else already has this', not 'the analyst decision
    doesn't match the current state'. GlobalLockBusyError is a subclass so
    existing `except StageClaimError` handling (e.g. in
    soc_workflow.run_stage_chain) already covers shared-workspace
    contention without special-casing it."""


class GlobalLockBusyError(StageClaimError):
    """A different owner_id currently holds the named global_execution_locks
    row with an unexpired expires_at."""


def claim_stage(incident_id: str, run_id: str, *, stage: str,
               status_column: str, expect_status: str) -> tuple[str, int]:
    """Atomically claim `stage`. Reading `expect_status` alone is NOT
    sufficient — two workers can both observe it before either writes — so
    this additionally requires no live, unexpired lease exists, checked and
    written in the SAME transaction. Returns (worker_id, stage_attempt) —
    stage_attempt is READ (never incremented here; only rerun_stage()
    advances it) so the caller can stamp it on whatever gets persisted."""
    worker_id = uuid.uuid4().hex
    attempt_col = _STAGE_ATTEMPT_COLUMN.get(stage)

    def _do(con):
        now = datetime.now(timezone.utc)
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        if row is None or row["run_id"] != run_id or row[status_column] != expect_status:
            raise StageClaimError(
                f"{stage}: not eligible (run_id={row['run_id'] if row else None!r}, "
                f"{status_column}={row[status_column] if row else None!r})")
        lease = row["worker_lease_expires_at"]
        if lease and datetime.fromisoformat(lease) > now:
            raise StageClaimError(
                f"{stage}: live lease held by worker {row['worker_id']!r} until {lease}")
        new_expiry = (now + timedelta(seconds=_LEASE_DURATION_SECONDS)).isoformat()
        con.execute(
            "UPDATE incidents SET worker_id=?, worker_stage=?, worker_started_at=?, "
            "worker_heartbeat_at=?, worker_lease_expires_at=?, worker_progress_note=NULL "
            "WHERE id=? AND run_id=?",
            (worker_id, stage, now.isoformat(), now.isoformat(), new_expiry,
             str(incident_id), run_id))
        stage_attempt = int(row[attempt_col]) if attempt_col else 1
        _insert_activity_row(con, incident_id=incident_id, run_id=run_id, stage=stage,
                             action="stage_started", metadata={"stage_attempt": stage_attempt,
                                                                "worker_id": worker_id})
        return stage_attempt

    stage_attempt = _tx(_do)
    return worker_id, stage_attempt


def renew_stage_lease(incident_id: str, run_id: str, worker_id: str) -> bool:
    """Called every _HEARTBEAT_RENEW_SECONDS while a stage's real work is in
    progress, not just once at stage start. Returns False if this worker no
    longer owns the lease (caller should stop)."""
    def _do(con):
        now = datetime.now(timezone.utc)
        row = con.execute("SELECT worker_id FROM incidents WHERE id=? AND run_id=?",
                          (str(incident_id), run_id)).fetchone()
        if row is None or row["worker_id"] != worker_id:
            return False
        con.execute(
            "UPDATE incidents SET worker_heartbeat_at=?, worker_lease_expires_at=? "
            "WHERE id=? AND run_id=?",
            (now.isoformat(),
             (now + timedelta(seconds=_LEASE_DURATION_SECONDS)).isoformat(),
             str(incident_id), run_id))
        return True
    try:
        return _tx(_do)
    except Exception:
        return False


def release_stage_lease(incident_id: str, run_id: str, worker_id: str) -> None:
    """Called in a `finally` on every exit path (success, approval-gate
    reached, failure, superseded). Only clears if this worker still owns
    it — a lease that already expired and was reassigned to a newer worker
    must NOT be cleared by the old one. Safe to call even after
    complete_stage() already cleared it (no-op in that case)."""
    def _do(con):
        row = con.execute("SELECT worker_id FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        if row is not None and row["worker_id"] == worker_id:
            con.execute(
                "UPDATE incidents SET worker_id=NULL, worker_stage=NULL, "
                "worker_lease_expires_at=NULL, worker_progress_note=NULL "
                "WHERE id=? AND run_id=?",
                (str(incident_id), run_id))
    try:
        _tx(_do)
    except Exception:
        pass   # best-effort cleanup; a stuck lease still self-expires via TTL


def set_worker_progress_note(incident_id: str, run_id: str, note: str | None) -> None:
    """Persisted, human-readable progress note shown by the Output tab while
    Processing — e.g. "Waiting for Investigation capacity" during global-lock
    contention (see soc_workflow.run_investigation_stage). Best-effort; a
    failure here must never abort the caller's real work."""
    try:
        _guarded_update(incident_id, run_id, {"worker_progress_note": note})
    except Exception:
        pass


def complete_stage(incident_id: str, run_id: str, worker_id: str, *,
                   stage: str, result_column: str, result: dict,
                   status_updates: dict,
                   expected_stage_attempt: int | None = None) -> bool:
    """The ONLY way a stage's result/status is ever written. In one
    transaction: confirms run_id matches, worker_id matches the row's
    CURRENT worker_id, worker_stage still equals `stage`, the stage's own
    status column is still "Processing", AND worker_lease_expires_at is
    still in the future.

    That last check is the fix for a real bug: worker_id/worker_stage alone
    do NOT change merely because a lease expires — they only change when a
    DIFFERENT worker's claim_stage() call overwrites them. Without an
    explicit lease-liveness check, a worker whose lease expired (but that
    no one else has re-claimed yet) would still pass every other check and
    be wrongly allowed to save. If ownership is stale OR the lease has
    expired, the result is rejected (returns False; caller does NOT raise —
    a late/expired finish losing to a faster worker, or to nothing at all
    yet, is expected, not exceptional). On success: saves the result,
    applies status_updates, clears the lease fields, and records the
    activity row — all one write, one transaction.

    `expected_stage_attempt`, when given, additionally requires the row's
    current `{stage}_attempt` column to still equal it — the late-worker
    guard for stages with a candidate-set concept (Reporting): worker_id/
    worker_stage/lease alone don't catch a worker from a SUPERSEDED attempt
    (e.g. a crashed-and-resumed process from attempt 1) trying to save its
    result after rerun_stage() has already bumped the row to attempt 2 and
    reset worker_id to NULL — by the time that late worker calls this, a
    brand-new claim_stage() for attempt 2 may have already set worker_id/
    worker_stage/lease to values that happen to look "live" again. Passing
    the attempt number the caller was actually claimed for closes that gap.
    Optional so every other existing caller (which doesn't pass it) is
    unaffected."""
    status_column = f"{stage}_status"
    updated_at_col = {
        "threat_intel": "threat_intel_updated_at",
        "investigation": "investigation_updated_at",
        "reporting": "reporting_updated_at",
    }[stage]
    attempt_col = _STAGE_ATTEMPT_COLUMN.get(stage)

    def _do(con):
        select_cols = (f"worker_id, worker_stage, run_id, worker_lease_expires_at, "
                      f"{status_column} AS stage_status")
        if expected_stage_attempt is not None and attempt_col:
            select_cols += f", {attempt_col} AS current_stage_attempt"
        row = con.execute(
            f"SELECT {select_cols} FROM incidents WHERE id=?",
            (str(incident_id),)).fetchone()
        if row is None or row["run_id"] != run_id:
            return False
        if row["worker_id"] != worker_id or row["worker_stage"] != stage:
            return False   # stale — someone else already owns/owned this stage
        if row["stage_status"] != "Processing":
            return False   # stage already moved on (e.g. a faster worker completed it)
        if (expected_stage_attempt is not None and attempt_col
                and int(row["current_stage_attempt"]) != int(expected_stage_attempt)):
            return False   # a late worker from a superseded attempt — refuse
        lease = row["worker_lease_expires_at"]
        lease_live = bool(lease) and datetime.fromisoformat(lease) > datetime.now(timezone.utc)
        if not lease_live:
            return False   # the actual fix: an expired lease must not be honored
        now = datetime.now(timezone.utc).isoformat()
        sets = {
            result_column: json.dumps(result, default=str),
            updated_at_col: now,
            **status_updates,
            "worker_id": None, "worker_stage": None, "worker_lease_expires_at": None,
            "worker_progress_note": None,
            "workflow_updated_at": now,
        }
        cols = ", ".join(f"{k}=?" for k in sets)
        con.execute(f"UPDATE incidents SET {cols} WHERE id=? AND run_id=?",
                   (*sets.values(), str(incident_id), run_id))
        action = "stage_failed" if status_updates.get(status_column) == "Failed" \
            else "stage_succeeded"
        _insert_activity_row(con, incident_id=incident_id, run_id=run_id, stage=stage,
                             action=action, metadata={"status_updates": status_updates})
        return True
    return _tx(_do)


def acquire_global_lock(lock_name: str, *, owner_id: str, incident_id: str, run_id: str,
                        ttl_seconds: int = _LEASE_DURATION_SECONDS) -> None:
    """Cross-process, cross-incident lock over a shared filesystem workspace
    (the Investigation Agent's triaged_alerts/incident_reports tree, or the
    Reporting Agent's inputs/outputs tree) — per-incident stage leases alone
    do not stop two DIFFERENT incidents from entering the same shared
    directory at once. BEGIN IMMEDIATE; raises GlobalLockBusyError if a live
    (unexpired) row exists under a different owner_id; otherwise writes a
    fresh row with this owner_id."""
    def _do(con):
        now = datetime.now(timezone.utc)
        row = con.execute("SELECT owner_id, expires_at FROM global_execution_locks "
                          "WHERE lock_name=?", (lock_name,)).fetchone()
        if row is not None and row["owner_id"] != owner_id and row["expires_at"]:
            if datetime.fromisoformat(row["expires_at"]) > now:
                raise GlobalLockBusyError(
                    f"{lock_name}: held by {row['owner_id']!r} until {row['expires_at']}")
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
        con.execute(
            "INSERT INTO global_execution_locks (lock_name, owner_id, incident_id, "
            "run_id, acquired_at, expires_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(lock_name) DO UPDATE SET owner_id=excluded.owner_id, "
            "incident_id=excluded.incident_id, run_id=excluded.run_id, "
            "acquired_at=excluded.acquired_at, expires_at=excluded.expires_at",
            (lock_name, owner_id, str(incident_id), run_id, now.isoformat(), expires_at))
    _tx(_do)


def renew_global_lock(lock_name: str, owner_id: str) -> bool:
    """Extends expires_at iff the row's owner_id still matches this
    owner_id. Returns False (caller must treat the lock as lost) otherwise
    — used both as a periodic heartbeat renewal AND, during subprocess
    execution, as a watchdog check whose False return should terminate the
    still-running child process before anyone else is allowed to proceed
    (see soc_workflow._run_subprocess_streaming's watchdog_cb)."""
    def _do(con):
        now = datetime.now(timezone.utc)
        row = con.execute("SELECT owner_id FROM global_execution_locks WHERE lock_name=?",
                          (lock_name,)).fetchone()
        if row is None or row["owner_id"] != owner_id:
            return False
        con.execute(
            "UPDATE global_execution_locks SET expires_at=? WHERE lock_name=? AND owner_id=?",
            ((now + timedelta(seconds=_LEASE_DURATION_SECONDS)).isoformat(),
             lock_name, owner_id))
        return True
    try:
        return _tx(_do)
    except Exception:
        return False


def release_global_lock(lock_name: str, owner_id: str) -> None:
    """DELETE iff owner_id still matches. Best-effort, called in a finally —
    a lock that already expired and was reclaimed by someone else must not
    be deleted out from under them."""
    def _do(con):
        con.execute(
            "DELETE FROM global_execution_locks WHERE lock_name=? AND owner_id=?",
            (lock_name, owner_id))
    try:
        _tx(_do)
    except Exception:
        pass


def _insert_activity_row(con, *, incident_id: str, run_id: str | None, stage: str | None,
                         action: str, actor: str | None = None, comments: str = "",
                         metadata: dict | None = None) -> None:
    """Inserts into workflow_activity using the CALLER's already-open
    transaction (`con`) — never opens its own BEGIN/COMMIT. This is what
    makes activity logging atomic with the state change it documents: if
    the surrounding transaction rolls back, the activity row never
    committed either, and vice versa. Only report-download events (not a
    workflow-state transition) use the separate top-level record_activity()
    below instead."""
    con.execute(
        "INSERT INTO workflow_activity (incident_id, run_id, stage, action, actor, "
        "comments, metadata_json, occurred_at) VALUES (?,?,?,?,?,?,?,?)",
        (str(incident_id), run_id, stage, action, actor, comments,
         json.dumps(metadata or {}, default=str),
         datetime.now(timezone.utc).isoformat()))


def record_activity(incident_id: str, run_id: str | None, stage: str | None, action: str,
                    *, actor: str | None = None, comments: str = "",
                    metadata: dict | None = None) -> None:
    """Top-level, standalone-transaction activity write — used ONLY for
    actions that are not themselves a workflow-state transition (e.g.
    "Export Word"/"Export PDF" report downloads), since there is no
    surrounding state-change transaction to piggyback on for those."""
    def _do(con):
        _insert_activity_row(con, incident_id=incident_id, run_id=run_id, stage=stage,
                             action=action, actor=actor, comments=comments,
                             metadata=metadata)
    _tx(_do)


def get_activity(incident_id: str, run_id: str | None = None) -> list[dict]:
    """Reads workflow_activity rows (chronological). Does not include
    workflow_approvals decisions — callers (case_view.build_activity) union
    those in separately via get_approval_history() to keep the two tables'
    distinct semantics (activity = what happened; approvals = analyst
    decisions) visible rather than silently merged at write time."""
    db_init()
    with db_connect() as con:
        if run_id is not None:
            rows = con.execute(
                "SELECT * FROM workflow_activity WHERE incident_id=? AND run_id=? "
                "ORDER BY occurred_at ASC", (str(incident_id), run_id)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM workflow_activity WHERE incident_id=? "
                "ORDER BY occurred_at ASC", (str(incident_id),)).fetchall()
        return [dict(r) for r in rows]


# ── Analyst report edits (Reports tab "Open & Edit") ─────────────────────────
# One row per (incident_id, run_id, report_type) — the analyst's saved edit of
# a Reporting-stage report, layered ON TOP OF the immutable, hash-verified
# candidate_manifest.json produced by the Reporting pipeline (see
# report_editing.py). Never overwrites, and is never read by, anything in
# soc_reporting_agent or the existing whole-attempt approval flow.

def upsert_report_edit(incident_id: str, run_id: str, report_type: str, *,
                       edited_blocks: list, original_blocks: list | None,
                       source_report_set_id: str | None, analyst: str) -> dict:
    """Insert the first saved edit for this (incident, run, report_type), or
    update it in place and bump ``version``. ``original_blocks`` is only
    written on the FIRST save (a later save must not overwrite the
    traceability snapshot of what the AI originally produced)."""
    def _do(con):
        now = datetime.now(timezone.utc).isoformat()
        existing = con.execute(
            "SELECT * FROM report_edits WHERE incident_id=? AND run_id=? AND report_type=?",
            (str(incident_id), run_id, report_type)).fetchone()
        edited_json = json.dumps(edited_blocks or [], default=str)
        if existing is None:
            con.execute(
                "INSERT INTO report_edits (incident_id, run_id, report_type, "
                "source_report_set_id, original_blocks_json, edited_blocks_json, "
                "version, created_at, updated_at, last_edited_by) "
                "VALUES (?,?,?,?,?,?,1,?,?,?)",
                (str(incident_id), run_id, report_type, source_report_set_id,
                 json.dumps(original_blocks or [], default=str), edited_json,
                 now, now, analyst))
        else:
            con.execute(
                "UPDATE report_edits SET edited_blocks_json=?, source_report_set_id=?, "
                "version=version+1, updated_at=?, last_edited_by=? "
                "WHERE incident_id=? AND run_id=? AND report_type=?",
                (edited_json, source_report_set_id, now, analyst,
                 str(incident_id), run_id, report_type))
        row = con.execute(
            "SELECT * FROM report_edits WHERE incident_id=? AND run_id=? AND report_type=?",
            (str(incident_id), run_id, report_type)).fetchone()
        return dict(row)
    return _tx(_do)


def get_report_edit(incident_id: str, run_id: str, report_type: str) -> dict | None:
    db_init()
    with db_connect() as con:
        row = con.execute(
            "SELECT * FROM report_edits WHERE incident_id=? AND run_id=? AND report_type=?",
            (str(incident_id), run_id, report_type)).fetchone()
        return dict(row) if row else None


def list_report_edits(incident_id: str, run_id: str) -> list[dict]:
    db_init()
    with db_connect() as con:
        rows = con.execute(
            "SELECT * FROM report_edits WHERE incident_id=? AND run_id=?",
            (str(incident_id), run_id)).fetchall()
        return [dict(r) for r in rows]


def discard_report_edit(incident_id: str, run_id: str, report_type: str) -> None:
    """"Replace with latest AI version" — deletes the saved edit row so the
    report reverts to showing the (current) AI-generated original. Does not
    touch any file on disk; the edited docx/pdf export (if one was ever
    generated) is simply orphaned, not deleted, for traceability."""
    def _do(con):
        con.execute(
            "DELETE FROM report_edits WHERE incident_id=? AND run_id=? AND report_type=?",
            (str(incident_id), run_id, report_type))
    _tx(_do)
