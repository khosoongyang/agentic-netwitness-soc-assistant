# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, json, pathlib, sqlite3, uuid.
# =============================================================================
# File: workflow_state_store.py  (repo root — ~1,382 lines before this
#   documentation pass)
# Purpose: THE single source of truth for per-incident workflow state. Owns
#   the SQLite `incidents` table schema (every stage-status / approval-status
#   / rerun-attempt / worker-lease column lives here) plus the permanent
#   `workflow_approvals` (analyst decision audit trail), `workflow_activity`
#   (event log), `global_execution_locks` (cross-incident shared-workspace
#   locking), and `report_edits` (analyst "Open & Edit" saves) tables. This
#   is a PURE DATABASE LAYER: every function either reads or atomically
#   writes SQLite rows — none of them run a workflow stage, call an LLM,
#   spawn a thread, or touch any file other than DB_FILE itself. Stage
#   EXECUTION (subprocess calls into soc_triage_agent /
#   soc_investigation_agent_revised / soc_reporting_agent) lives entirely in
#   soc_workflow.py; this module only records the outcome.
# Main functionalities:
#   1. [FYP-DATABASE] Schema ownership & additive migrations — db_init(),
#      _ensure_workflow_columns(), _ensure_workflow_approvals_attempt_columns(),
#      _ensure_workflow_approvals_metadata_column().
#   2. [FYP-STATE] Run lifecycle — start_run() (fresh run / Awaiting-Approval
#      retry), simple guarded status/result setters (set_parsing_status,
#      set_triage_status, set_workflow_status, save_*_result, set_last_error).
#   3. [FYP-APPROVAL] Atomic approve/reject transitions for the THREE
#      mandatory human approval gates — Triage (approve_triage/reject_triage),
#      Investigation (approve_investigation/reject_investigation), Reporting
#      (commit_reporting_approval/reject_reporting) — all built on the shared
#      compare-and-swap engine _atomic_stage_transition().
#   4. [FYP-RERUN] [FYP-STAGE-LOCK] Re-run / retry transitions — rerun_stage()
#      (the ONLY way to re-execute a completed Threat-Intel/Investigation/
#      Reporting stage; see its own docstring for exactly which downstream
#      columns it clears vs. leaves alone), rerun_pending_stage() (alias),
#      retry_threat_intel() (Failed -> Processing recovery), begin_stage()
#      (the ONLY function that starts a stage a prior approval unlocked but
#      deliberately left "Pending").
#   5. [FYP-STATE] [FYP-STAGE-LOCK] Stage claim/lease machinery — claim_stage()
#      (single-worker lock via a TTL lease), renew_stage_lease(),
#      release_stage_lease(), complete_stage() (the ONLY function that ever
#      writes a stage's result+status together), plus cross-incident
#      global_execution_locks (acquire_global_lock/renew_global_lock/
#      release_global_lock()) for shared on-disk workspaces.
#   6. [FYP-DATABASE] Activity/audit trails — get_approval_history(),
#      record_activity()/get_activity()/_insert_activity_row().
#   7. [FYP-DATABASE] Analyst report edits — upsert_report_edit(),
#      get_report_edit(), list_report_edits(), discard_report_edit().
# Inputs: incident_id, run_id (str — identify one workflow run), stage names
#   ("threat_intel"/"investigation"/"reporting"), status strings, result
#   dicts (JSON-serialised into *_result_json columns), analyst identity +
#   free-text comments for approvals/rejections.
# Outputs: dict / list[dict] snapshots of DB rows; raises
#   WorkflowAlreadyRunningError / StaleWriteError / ApprovalConflictError /
#   StageClaimError / GlobalLockBusyError on precondition failures — every
#   write here is fail-closed (compare-and-swap), never a silent partial
#   write.
# Workflow position: Underlies EVERY stage transition in the Parsing ->
#   Triage -> Threat Intel -> Investigation -> Reporting pipeline.
#   soc_workflow.py calls it to record stage progress/results and to
#   claim/renew/release stage leases; app.py calls it directly for the
#   approve/reject/rerun/begin_stage button handlers; reporting_approval.py
#   and report_editing.py each import it for their own narrower slice
#   (final Reporting approval, and analyst report edits, respectively).
# Called by: app.py, soc_workflow.py, reporting_approval.py, report_editing.py,
#   case_view.py, and several files under tests/ — confirmed via
#   `grep -rn "import workflow_state_store\|from workflow_state_store"` from
#   the repo root against the current merge-final-evaluation branch content.
# Calls: Python stdlib only (sqlite3, json, uuid, datetime, pathlib) — no
#   import of any other project module, which is what keeps this the
#   dependency-free base layer soc_workflow.py can safely import without a
#   circular-import risk (soc_workflow.py imports this; this file must never
#   import soc_workflow.py back).
# Key evaluator search terms: WorkflowAlreadyRunningError, StaleWriteError,
#   ApprovalConflictError, StageClaimError, GlobalLockBusyError,
#   _atomic_stage_transition, approve_triage, approve_investigation,
#   commit_reporting_approval, rerun_stage, begin_stage, claim_stage,
#   complete_stage, "Awaiting Approval", "Processing", "Pending", "Blocked",
#   "Rejected", "Complete", stage_attempt, approval_attempt,
#   worker_lease_expires_at.
# =============================================================================
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
reusing `_tx()` from here). Approving a stage only unlocks the next one
(leaves it "Pending") — it never starts it; app.py starts the worker
thread only when the analyst explicitly clicks that next stage's own
Start Process button (see begin_stage()). Keeping this boundary strict
avoids a circular import between this module and soc_workflow.py.

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

# [FYP-CONFIG] [FYP-DATABASE] soc_db/soc_incidents.db — the single SQLite
# file every function in this module reads/writes. Created relative to this
# file's own location (repo root), independent of the process's cwd.
ROOT = Path(__file__).resolve().parent
SOC_DB_DIR = ROOT / "soc_db"
SOC_DB_DIR.mkdir(exist_ok=True)
DB_FILE = SOC_DB_DIR / "soc_incidents.db"

# [FYP-STATE] The two workflow_status values that mean "a run is currently
# in flight" — used by start_run() to decide whether a fresh run may replace
# the row. Not currently read anywhere else in this module (informational /
# reserved for future guards), but documents the two "busy" values alongside
# "Pending" / "Awaiting Action" / "Rejected" / "Complete".
_ACTIVE_WORKFLOW_STATUSES = {"Processing", "Awaiting Approval"}


class WorkflowAlreadyRunningError(Exception):
    """[FYP-CLASS] WorkflowAlreadyRunningError
    [FYP-STATE] [FYP-ERROR]
    Raised by start_run() when a workflow is already Processing or Awaiting
    Approval for this incident and cannot be replaced. Carries incident_id
    and the full current state dict so the caller (app.py / soc_workflow.py)
    can report exactly what is already running instead of a generic error."""
    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `incident_id`, `state`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `__init__`, `get`, `super`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __init__(self, incident_id: str, state: dict):
        self.incident_id = incident_id
        self.state = state
        super().__init__(
            f"Workflow already {state.get('workflow_status')!r} for "
            f"incident {incident_id!r} (run_id={state.get('run_id')!r})")


class StaleWriteError(RuntimeError):
    """[FYP-CLASS] StaleWriteError
    [FYP-STATE] [FYP-ERROR]
    Raised by _guarded_update() — and therefore by every simple status
    setter built on it (set_parsing_status, set_triage_status,
    set_workflow_status, save_triage_result, save_parsing_result,
    save_raw_incident_path, set_last_error, save_ioc_correlation_result,
    set_worker_progress_note) — when the caller's run_id no longer matches
    the incidents row's CURRENT run_id: a slow or abandoned run (from before
    a rerun_stage() / start_run(allow_retry=True) call replaced it) trying
    to write status for a run that is no longer the live one. This is the
    guard that stops a straggling background write from corrupting a newer
    run's state."""


class ApprovalConflictError(RuntimeError):
    """[FYP-CLASS] ApprovalConflictError
    [FYP-APPROVAL] [FYP-RERUN] [FYP-STATE] [FYP-ERROR]
    Raised by EVERY approve/reject/rerun/retry/begin_stage transition in
    this module (via _atomic_stage_transition(), rerun_stage(),
    retry_threat_intel(), begin_stage()) when the incident's row is not in
    the EXACT state that action requires — already approved/rejected by
    someone else, superseded by a newer run/rerun, an invalid stage name, or
    an upstream stage not yet in the required state. This is the
    compare-and-swap failure signal: two analysts (or a double-click) racing
    on the same action can only have one succeed; the loser gets this
    exception with a message showing both what was expected and what the
    row actually contained. Two analysts (or a double-click) racing on the
    same action can only have one of them succeed; the other gets this."""


def db_connect() -> sqlite3.Connection:
    """[FYP-FUNCTION] Canonical DB Connection Factory
    [FYP-DATABASE]
    Params: none. Returns: sqlite3.Connection to DB_FILE, with
    row_factory=sqlite3.Row (so rows can be read like dicts),
    check_same_thread=False (required — Streamlit reruns and the background
    worker thread in app.py/soc_workflow.py share connections across
    threads), timeout=15s (waits out short writer locks instead of failing
    immediately with "database is locked").
    Called by: db_init(), get_state(), get_approval_history(),
    get_approved_reporting_sets(), get_activity(), get_report_edit(),
    list_report_edits() (all in this file), and directly by app.py
    (confirmed via grep, `from workflow_state_store import db_connect`)
    instead of app.py defining its own connection helper.
    Canonical connection factory — app.py imports this instead of
    defining its own (db_upsert_incidents, db_get_incident, etc. all use it)."""
    con = sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=15)
    con.row_factory = sqlite3.Row
    return con


def _autocommit_connect() -> sqlite3.Connection:
    """[FYP-FUNCTION] Manual-Transaction DB Connection Factory
    [FYP-DATABASE]
    Params: none. Returns: sqlite3.Connection with isolation_level=None
    (autocommit mode) so this module's own explicit `BEGIN IMMEDIATE` (used
    by _tx() and every _guarded_update()-style function) is not silently
    nested inside sqlite3's default implicit transaction wrapping.
    Called by: _tx() and _guarded_update().
    Manual transaction control for the guarded read-then-write helpers
    below — isolation_level=None so an explicit BEGIN IMMEDIATE isn't
    nested inside sqlite3's own implicit transaction."""
    con = sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=15)
    con.row_factory = sqlite3.Row
    con.isolation_level = None
    return con


def _tx(fn):
    """[FYP-FUNCTION] Shared Atomic-Transaction Wrapper
    [FYP-DATABASE] [FYP-STATE]
    Params: fn — a callable taking one `con` (sqlite3.Connection) argument
    that does all its reads/writes on it and returns whatever _tx()'s caller
    should get back.
    Returns: whatever fn(con) returned.
    Side effects: opens a fresh autocommit connection, runs `BEGIN IMMEDIATE`
    (acquires SQLite's write lock up front — this is what makes the
    read-then-write sequences inside fn atomic against concurrent writers,
    i.e. the compare-and-swap pattern every approval/rerun/claim function in
    this module relies on), calls fn(con), then COMMITs. On ANY exception
    from fn, rolls back (only if a transaction is actually still open) and
    re-raises; always closes the connection in a `finally`.
    Called by: nearly every write function in this module — start_run(),
    save_stage_ai_summary(), _atomic_stage_transition(), rerun_stage(),
    retry_threat_intel(), begin_stage(), claim_stage(), renew_stage_lease(),
    release_stage_lease(), complete_stage(), acquire_global_lock(),
    renew_global_lock(), release_global_lock(), record_activity(),
    upsert_report_edit(), discard_report_edit(). Also reused, via import, by
    soc_workflow.py's own stage-claim/lease code.
    Key decision: this is the ONE shared transaction shape in the whole
    module — no caller writes its own manual conditional
    rollback-then-reraise, which is what keeps every atomic write in this
    file provably all-or-nothing.
    Every guarded write in this module (and, via import, in
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
    """[FYP-FUNCTION] Initialise / Migrate Full DB Schema
    [FYP-DATABASE] [FYP-ENTRY-POINT]
    Params: none. Returns: None.
    Side effects: CREATE TABLE IF NOT EXISTS for `incidents`, `fetch_log`,
    `workflow_approvals`, `global_execution_locks`, `workflow_activity`,
    `report_edits` (base schemas only — never redefines an existing table);
    sets PRAGMA journal_mode=WAL / synchronous=NORMAL (best-effort, ignored
    on failure); then calls _ensure_workflow_columns() and
    _ensure_workflow_approvals_attempt_columns() to additively migrate any
    columns added after the base CREATE TABLE was first written.
    Called by: start_run(), get_state(), get_approval_history(),
    get_approved_reporting_sets(), get_activity(), get_report_edit(),
    list_report_edits() (every read/entry-point function in this module
    calls db_init() first to guarantee the schema exists) — plus directly by
    app.py and soc_workflow.py at startup (confirmed via grep).
    Calls: db_connect(), _ensure_workflow_columns(),
    _ensure_workflow_approvals_attempt_columns() (which itself calls
    _ensure_workflow_approvals_metadata_column()).
    Full incidents + fetch_log + workflow_approvals schema — moved here
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
    """[FYP-FUNCTION] Additive Schema Migration — incidents Table
    [FYP-DATABASE] [FYP-STATE]
    Reads PRAGMA table_info(incidents) and ALTER TABLE ADD COLUMN for any
    column in the dict below not already present. This is the single place
    every stage-status column (parsing_status, triage_status,
    threat_intel_status, investigation_status, reporting_status,
    workflow_status, approval_stage), every *_result_json column, every
    *_attempt counter (investigation_attempt/threat_intel_attempt/
    reporting_attempt), and every worker-lease column
    (worker_id/worker_stage/worker_lease_expires_at/etc.) is defined.
    Never redefines or drops an existing column — additive-only, so it is
    always safe to call on an already-migrated DB.
    Called by: db_init().
    Additive-only ALTER TABLE — same pattern app.py already used once for
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
    """[FYP-FUNCTION] Additive Schema Migration — workflow_approvals Attempt Columns
    [FYP-DATABASE] [FYP-RERUN] [FYP-STATE]
    Adds stage_attempt and approval_attempt columns (INTEGER NOT NULL
    DEFAULT 1) to workflow_approvals if missing — distinguishing WHICH
    EXECUTION of a stage produced a decision (stage_attempt, bumped only by
    rerun_stage()) from WHICH DECISION NUMBER it is within that execution
    (approval_attempt, computed in _atomic_stage_transition()). Also drops
    the OLD one-row-per-stage unique index (ux_workflow_approvals_stage) and
    replaces it with ux_workflow_approvals_stage_attempt scoped to
    (incident_id, run_id, approval_stage, stage_attempt, approval_attempt).
    This is what makes it safe for rerun_stage() to NEVER delete a prior
    decision on rerun (the old index required deleting the previous decision
    to avoid a UNIQUE constraint violation, which destroyed audit history;
    the new index naturally gives each rerun's decision its own row).
    Called by: db_init(); itself calls
    _ensure_workflow_approvals_metadata_column() afterward.
    Additive columns distinguishing WHICH EXECUTION of a stage produced a
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
    """[FYP-FUNCTION] Additive Schema Migration — workflow_approvals Metadata Column
    [FYP-DATABASE] [FYP-APPROVAL] [FYP-STATE]
    Adds the nullable metadata_json TEXT column to workflow_approvals if
    missing. Called by: _ensure_workflow_approvals_attempt_columns().
    Additive, nullable metadata_json column — durable, per-decision
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
    """[FYP-FUNCTION] Start / Restart a Workflow Run
    [FYP-STATE] [FYP-ENTRY-POINT] [FYP-RERUN]
    Params: incident_id (str, source: the incident row selected by the
    analyst/app.py), allow_retry (bool, default False — if True, permits
    replacing a run currently "Awaiting Approval"; a "Processing" run can
    NEVER be replaced regardless of this flag).
    Returns: the newly generated run_id (str,
    "{incident_id}@{timestamp}-{6 hex chars}").
    Side effects: INSERT-or-UPSERT of the entire `incidents` row for this
    incident_id — every workflow column is (re)initialised to an explicit
    value, never left NULL: parsing_status="Processing" (Parsing begins
    immediately), triage_status/threat_intel_status/investigation_status/
    reporting_status all "Pending", workflow_status="Processing",
    approval_stage=None, every *_result_json/*_updated_at cleared to None,
    every *_attempt counter reset to 1, ioc_correlation_status="Pending".
    This is the ONLY function that runs Parsing+Triage as one fresh,
    run-scoped process (used both for a brand-new run and, via
    allow_retry=True, to fully restart Parsing/Triage after an Awaiting
    Approval run is abandoned — see rerun_stage()'s own docstring for why
    Parsing/Triage are NOT handled by rerun_stage() itself).
    Called by: soc_workflow.py (confirmed via grep,
    `wss.start_run(...)`) when a new workflow run is kicked off or Parsing/
    Triage is retried.
    Calls: db_init(), WorkflowAlreadyRunningError, _tx().
    Key decision: atomically checks for an already-active run — BEGIN
    IMMEDIATE takes SQLite's write lock before the read, so two sessions
    racing on the same incident can't both pass.
    Error handling: raises WorkflowAlreadyRunningError if workflow_status is
    already "Processing", or "Awaiting Approval" with allow_retry=False.
    Atomically checks for an already-active run (BEGIN IMMEDIATE takes
    SQLite's write lock before the read, so two sessions racing on the same
    incident can't both pass). ``allow_retry`` permits replacing an
    Awaiting Approval run, but never a run that is already Processing.
    Every
    status column is set to an explicit, meaningful value (never left
    NULL) — Parsing starts Processing immediately; every later stage
    starts Pending; the workflow itself starts Processing."""
    db_init()

    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `WorkflowAlreadyRunningError`, `dict`, `execute`, `fetchone`, `isoformat`, `join`, `now`, `str`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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
    """[FYP-FUNCTION] Guarded Single-Row Column Update
    [FYP-STATE]
    Params: incident_id (str), run_id (str | None — if given, the update is
    refused unless it matches the row's current run_id; pass None to skip
    the check), sets (dict of column -> new value to write).
    Returns: None. Side effects: UPDATE incidents SET ... WHERE id=?; also
    stamps workflow_updated_at=now on every call.
    Called by: set_parsing_status(), set_triage_status(),
    set_workflow_status(), save_triage_result(), save_parsing_result(),
    save_raw_incident_path(), set_last_error(), save_ioc_correlation_result(),
    set_worker_progress_note() — every "simple" single/few-column status or
    result writer in this module.
    Error handling: raises StaleWriteError (not caught here — propagates to
    the caller) if run_id is given and doesn't match the row's current
    run_id.
    Rejects the write if run_id doesn't match the row's current run_id —
    guards against a slow/abandoned run overwriting a newer run's status.
    Used for simple, non-ownership-critical single-column writes; stage
    *completion* (result + status together) goes through
    complete_stage() instead (this module's own, not soc_workflow's), which
    additionally checks worker ownership, not just run_id."""
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


# [FYP-FUNCTION] Simple Guarded Status/Result Setters
# [FYP-STATE]
# The next several one-line functions all just forward to _guarded_update()
# with one or two columns — kept deliberately trivial so the compare-and-swap
# guard (run_id must match) lives in exactly one place. Called by
# soc_workflow.py as it progresses each stage (Processing -> Complete/Failed
# is written via complete_stage() instead — these setters are for the
# lighter-weight interim/status-only writes and for triage's own path, which
# predates complete_stage()).
def set_parsing_status(incident_id: str, run_id: str, status: str) -> None:
    """[FYP-FUNCTION] Set Parsing Status
    [FYP-STATE] Params: incident_id, run_id (str), status (str — e.g.
    "Processing"/"Completed"/"Failed", source: the parsing stage runner in
    soc_workflow.py). Writes incidents.parsing_status. Calls:
    _guarded_update()."""
    _guarded_update(incident_id, run_id, {"parsing_status": status})


def set_triage_status(incident_id: str, run_id: str, status: str) -> None:
    """[FYP-FUNCTION] Set Triage Status
    [FYP-STATE] Params: incident_id, run_id (str), status (str — e.g.
    "Processing"/"Awaiting Approval"/"Approved"/"Rejected", source: the
    triage stage runner in soc_workflow.py). Writes incidents.triage_status.
    Calls: _guarded_update()."""
    _guarded_update(incident_id, run_id, {"triage_status": status})


def set_workflow_status(incident_id: str, run_id: str, status: str, *,
                        approval_stage: str | None = None) -> None:
    """[FYP-FUNCTION] Set Overall Workflow Status (+ optional Approval Gate)
    [FYP-STATE] [FYP-APPROVAL] Params: incident_id, run_id (str), status
    (str — one of "Processing"/"Awaiting Approval"/"Awaiting Action"/
    "Rejected"/"Complete", source: the calling stage runner in
    soc_workflow.py), approval_stage (str | None — when given, also writes
    incidents.approval_stage, e.g. "triage"/"investigation"/"reporting",
    identifying WHICH gate the run is waiting on when status is "Awaiting
    Approval"). Writes incidents.workflow_status (+ approval_stage if
    given). Calls: _guarded_update()."""
    sets = {"workflow_status": status}
    if approval_stage is not None:
        sets["approval_stage"] = approval_stage
    _guarded_update(incident_id, run_id, sets)


def save_triage_result(incident_id: str, run_id: str, triage_result: dict) -> None:
    """[FYP-FUNCTION] Save Triage Result
    [FYP-STATE] Params: incident_id, run_id (str), triage_result (dict,
    source: TriageAgent.triage() output in soc_triage_agent). Writes
    incidents.triage_result_json (JSON-serialised, default=str for
    non-JSON-native values). Calls: _guarded_update()."""
    _guarded_update(incident_id, run_id,
                    {"triage_result_json": json.dumps(triage_result, default=str)})


def save_parsing_result(incident_id: str, run_id: str, summary: dict) -> None:
    """[FYP-FUNCTION] Save Parsing Result
    [FYP-STATE]
    Persists the run-scoped compact parsing summary (status,
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
    """[FYP-FUNCTION] Merge AI-Summary Fields into an Existing Stage Result
    [FYP-STATE] [FYP-LLM]
    Params: incident_id, run_id (str), stage (str — a workflow stage name or
    alias, e.g. "parsing_and_normalisation"; normalised via `aliases` to
    "parsing"/"triage"/"threat_intel"/"investigation"/"reporting"),
    summary_fields (dict, source: an LLM-generated summary; only the keys
    "ai_summary"/"ai_summary_model"/"ai_summary_generated_at"/"ai_thinking"
    are accepted — anything else is silently dropped).
    Returns: bool — True if the merge was applied, False if the run was
    superseded (run_id mismatch), no result JSON exists yet for that stage,
    the existing JSON doesn't parse/isn't a dict, or no allowed field was
    present in summary_fields.
    Side effects: UPDATE incidents SET {stage}_result_json=... — merges
    (dict.update) allowed_fields into the CURRENT result JSON read inside
    the SAME transaction, never overwriting the whole result.
    Called by: soc_workflow.py's AI-summary generation helpers (confirmed
    via grep, `wss.save_stage_ai_summary(...)`).
    Calls: _tx().
    Error handling: raises ValueError if `stage` doesn't map to a known
    result column; returns False (never raises) for every other failure
    mode described above — this is a best-effort enrichment, not a required
    write.
    Merge generated AI-summary metadata into the current stage result.

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

    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `dumps`, `execute`, `fetchone`, `isinstance`, `isoformat`, `loads`, `now`, `str`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

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
    """[FYP-FUNCTION] Save Raw Incident File Path
    [FYP-STATE] Params: incident_id, run_id (str), path (str, the on-disk
    location of the raw fetched incident used by Parsing). Writes
    incidents.raw_incident_path. Calls: _guarded_update()."""
    _guarded_update(incident_id, run_id, {"raw_incident_path": path})


def set_last_error(incident_id: str, run_id: str, message: str) -> None:
    """[FYP-FUNCTION] Set Last Error Message
    [FYP-STATE] [FYP-ERROR] Params: incident_id, run_id (str), message (str,
    a human-readable failure description). Writes incidents.last_error —
    surfaced in the UI's Output tab. Cleared to NULL by retry_threat_intel()
    and by rerun_stage() on any stage restart. Calls: _guarded_update()."""
    _guarded_update(incident_id, run_id, {"last_error": message})


def save_ioc_correlation_result(incident_id: str, run_id: str, *, status: str,
                                result: dict) -> None:
    """[FYP-FUNCTION] Save IOC Correlation Snapshot
    [FYP-STATE]
    Persists a ONE-TIME internal IOC correlation snapshot for this run
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
    """[FYP-FUNCTION] Read Current Workflow State
    [FYP-STATE] [FYP-ENTRY-POINT]
    Params: incident_id (str). Returns: dict snapshot of the entire
    `incidents` row (every stage-status/approval-status/attempt/worker-lease
    column at once), or None if the incident has no row yet.
    Called by: reporting_approval.py (approve_reporting_candidate(),
    resolve_approved_report_file() via get_latest_approved_reporting_set()),
    app.py, case_view.py, soc_workflow.py — the primary read entry point for
    "what is this incident's workflow state right now" (confirmed via grep).
    Calls: db_init(), db_connect()."""
    db_init()
    with db_connect() as con:
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        return dict(row) if row else None


def get_approval_history(incident_id: str, run_id: str | None = None) -> list[dict]:
    """[FYP-FUNCTION] Read Approval Audit Trail
    [FYP-APPROVAL] [FYP-DATABASE]
    Params: incident_id (str), run_id (str | None — if given, scopes to one
    run; if None, returns every run's history for this incident).
    Returns: list[dict] of workflow_approvals rows, oldest decided_at first.
    Called by: case_view.py's activity/history rendering (confirmed via
    grep) to show every approve/reject decision ever made, across every
    stage_attempt of every stage.
    Calls: db_init(), db_connect().
    Reads the permanent workflow_approvals audit trail — previously
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
# [FYP-SECTION] ATOMIC APPROVAL / REJECTION TRANSITIONS
# Atomic approval / rejection transitions — one gate each for Triage,
# Investigation, and Reporting. Every function here is a PURE database
# transition: it validates preconditions and records the decision; it
# never spawns a worker thread. app.py spawns soc_workflow.run_stage_chain
# immediately after a successful approve_*() call — see app.py's approval
# button handlers for the actual thread spawn. [FYP-APPROVAL] [FYP-DECISION]
# ══════════════════════════════════════════════════════════════════════════

# [FYP-STATE] [FYP-RERUN] approval_stage -> the incidents column tracking how
# many times THAT stage has been started/rerun. Triage has no such column:
# its retry path is a fresh start_run(allow_retry=True), so every Triage
# decision is inherently scoped to a distinct run_id already — stage_attempt
# is always 1 for it.
_APPROVAL_STAGE_ATTEMPT_COLUMN = {
    "investigation": "investigation_attempt",
    "reporting": "reporting_attempt",
}


def _atomic_stage_transition(incident_id: str, run_id: str, *, expect: dict,
                             sets: dict, approval_stage: str, decision: str,
                             analyst: str, comments: str = "",
                             metadata: dict | None = None) -> dict:
    """[FYP-FUNCTION] Atomic Approve/Reject Compare-and-Swap Engine
    [FYP-APPROVAL] [FYP-DECISION] [FYP-STATE] [FYP-EVALUATOR]
    This IS the exact approval-state-transition function every gate is built
    on — approve_triage/reject_triage, approve_investigation/
    reject_investigation, commit_reporting_approval/reject_reporting all
    call through here; there is no other place in the codebase that writes
    a row to workflow_approvals or transitions an approval_stage.
    Params: incident_id, run_id (str, source: the caller's own params,
    ultimately from app.py's approval button handlers), expect (dict of
    column -> required current value — e.g. {"workflow_status": "Awaiting
    Approval", "triage_status": "Awaiting Approval"} — read-then-compare
    inside the transaction; if the row doesn't match on EVERY key,
    ApprovalConflictError is raised and NOTHING is written), sets (dict of
    column -> new value, applied only if `expect` matched), approval_stage
    (str, "triage"/"investigation"/"reporting"), decision (str, "approved"
    or "rejected" — stored verbatim in workflow_approvals.decision), analyst
    (str, the deciding user), comments (str, free text), metadata (dict |
    None, JSON-encoded verbatim into workflow_approvals.metadata_json — only
    commit_reporting_approval() passes this; every other caller gets NULL).
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    Side effects, all in ONE transaction: (1) UPDATE incidents SET {sets}
    WHERE id=? AND run_id=? — also stamps approved_by/approved_at/
    approval_comments if decision=="approved" and those keys aren't already
    in `sets`; (2) INSERT one new row into workflow_approvals, stamped with
    the CURRENT stage_attempt (read from the incidents row, never
    incremented here — only rerun_stage() advances it) and a freshly
    computed approval_attempt (1 + the max approval_attempt already recorded
    for this exact stage_attempt).
    Called by: approve_triage(), reject_triage(), approve_investigation(),
    reject_investigation(), commit_reporting_approval(), reject_reporting()
    (all in this file).
    Calls: _tx().
    Error handling: raises ApprovalConflictError if `expect` doesn't match
    the current row (or the row doesn't exist), or if the INSERT into
    workflow_approvals violates the (incident_id, run_id, approval_stage,
    stage_attempt, approval_attempt) unique index (a near-simultaneous
    duplicate decision on the same stage_attempt).
    Key decision: workflow_approvals rows are NEVER deleted or overwritten
    by this function — every decision, including ones later superseded by a
    rerun, stays in the audit trail permanently (see get_approval_history()).
    Shared compare-and-swap engine for every approve/reject action at
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
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `ApprovalConflictError`, `any`, `dict`, `dumps`, `execute`, `fetchone`, `get`, `int`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

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
    """[FYP-FUNCTION] Approve Triage (Gate 1 of 3)
    [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-DECISION] [FYP-EVALUATOR]
    Params: incident_id, run_id (str), approved_by (str, the analyst
    identity — source: app.py's logged-in user), comments (str, optional).
    Requires (via `expect`): workflow_status=="Awaiting Approval",
    approval_stage=="triage", triage_status=="Awaiting Approval", and
    run_id matching the row's current run_id.
    Writes (via `sets`): triage_status="Approved",
    threat_intel_status="Pending" (NOT "Processing" — see key decision
    below), workflow_status="Awaiting Action", approval_stage=None.
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    Called by: app.py's Triage tab "Approve" button handler (confirmed via
    grep, `wss.approve_triage(...)`).
    Calls: _atomic_stage_transition().
    [FYP-EVALUATOR] Key decision — approval only UNLOCKS the next stage, it
    never STARTS it: this leaves threat_intel_status "Pending" and
    workflow_status "Awaiting Action" (the same idiom
    run_until_triage_approval() uses for a parsing-only completion). Threat
    Intelligence does NOT begin automatically; the analyst must explicitly
    click that stage's own Start Process button, which calls begin_stage()
    to flip threat_intel_status to "Processing" and only then spawns
    soc_workflow.run_stage_chain. This lock — "approved" is not the same
    state as "running" — is what stage-lock means throughout this module.
    Error handling: raises ApprovalConflictError (via
    _atomic_stage_transition) if the current state doesn't match `expect` —
    e.g. already decided, or a stale run_id.
    Approving Triage only unlocks Threat Intelligence — it leaves
    threat_intel_status "Pending" and workflow_status "Awaiting Action"
    (the same idiom run_until_triage_approval() uses for a parsing-only
    completion). It never starts Threat Intelligence; the analyst must
    explicitly click that stage's own Start Process button, which calls
    begin_stage() to flip it to Processing and only then spawns
    soc_workflow.run_stage_chain."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "triage", "triage_status": "Awaiting Approval"},
        sets={"triage_status": "Approved", "threat_intel_status": "Pending",
             "workflow_status": "Awaiting Action", "approval_stage": None},
        approval_stage="triage", decision="approved",
        analyst=approved_by, comments=comments)


def reject_triage(incident_id: str, run_id: str, *, rejected_by: str,
                  reason: str) -> dict:
    """[FYP-FUNCTION] Reject Triage (Gate 1 of 3)
    [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-DECISION] [FYP-EVALUATOR]
    Params: incident_id, run_id (str), rejected_by (str, analyst), reason
    (str, required free-text rejection rationale — stored as `comments`).
    Requires: same preconditions as approve_triage().
    Writes: triage_status="Rejected", threat_intel_status="Blocked" (the
    exact line/state value that marks the downstream stage as blocked —
    Threat Intelligence can never be started or claimed while it reads
    "Blocked"; see begin_stage()'s upstream-ready check), workflow_status=
    "Rejected", approval_stage=None.
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    Called by: app.py's Triage tab "Reject" button handler (confirmed via
    grep, `wss.reject_triage(...)`).
    Calls: _atomic_stage_transition().
    Error handling: raises ApprovalConflictError if the current state
    doesn't match the required preconditions."""
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
    """[FYP-FUNCTION] Approve Investigation (Gate 2 of 3)
    [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-DECISION]
    Params: incident_id, run_id (str), approved_by (str), comments (str).
    Requires: workflow_status=="Awaiting Approval",
    approval_stage=="investigation", investigation_status=="Awaiting
    Approval".
    Writes: investigation_status="Approved", reporting_status="Pending",
    workflow_status="Awaiting Action", approval_stage=None. Same
    unlock-but-don't-start pattern as approve_triage() — Reporting stays
    "Pending" until the analyst clicks its own Start Process button (see
    begin_stage()).
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    Called by: app.py's Investigation tab "Approve" button handler
    (confirmed via grep, `wss.approve_investigation(...)`).
    Calls: _atomic_stage_transition().
    Approving Investigation only unlocks Reporting — it leaves
    reporting_status "Pending" and workflow_status "Awaiting Action",
    exactly like approve_triage(). It never starts Reporting; the
    analyst must explicitly click that stage's own Start Process button
    (see begin_stage())."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "investigation",
               "investigation_status": "Awaiting Approval"},
        sets={"investigation_status": "Approved", "reporting_status": "Pending",
             "workflow_status": "Awaiting Action", "approval_stage": None},
        approval_stage="investigation", decision="approved",
        analyst=approved_by, comments=comments)


def reject_investigation(incident_id: str, run_id: str, *, rejected_by: str,
                         reason: str) -> dict:
    """[FYP-FUNCTION] Reject Investigation (Gate 2 of 3)
    [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-DECISION] [FYP-EVALUATOR]
    Params: incident_id, run_id (str), rejected_by (str), reason (str,
    required rejection rationale).
    Requires: same preconditions as approve_investigation().
    Writes: investigation_status="Rejected", reporting_status="Blocked" (the
    exact line/state value that blocks the downstream stage), workflow_
    status="Rejected", approval_stage=None.
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    Called by: app.py's Investigation tab "Reject" button handler
    (confirmed via grep, `wss.reject_investigation(...)`).
    Calls: _atomic_stage_transition().
    [FYP-EVALUATOR] Historical note preserved from the original author,
    documenting a real fix: rejecting Investigation must block Reporting
    EXPLICITLY — previously reporting_status was left untouched (still
    "Pending"), which didn't read as blocked anywhere downstream. This is a
    concrete example of "does an upstream rejection actually invalidate a
    downstream stage's eligibility" — yes, via an explicit status write, not
    an implicit inference.
    Error handling: raises ApprovalConflictError if the current state
    doesn't match the required preconditions."""
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
    """[FYP-FUNCTION] Commit Reporting Approval (Gate 3 of 3 — the final gate)
    [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-DECISION] [FYP-EVALUATOR]
    Params: incident_id, run_id (str); expected_reporting_attempt (int) and
    expected_reporting_result_json (str) — the EXACT reporting_attempt /
    reporting_result_json the caller already validated (see below), folded
    into `expect` as extra compare-and-swap fields; metadata (dict —
    report_set_id / candidate_manifest_path / candidate_manifest_sha256 /
    reporting_stage_attempt / validation_status / warning_count);
    approved_by (str, analyst identity); comments (str, optional).
    Requires (via `expect`): workflow_status=="Awaiting Approval",
    approval_stage=="reporting", reporting_status=="Awaiting Approval",
    run_id matching the row's current run_id, AND reporting_attempt /
    reporting_result_json still equal to the expected_* values passed in —
    this extra pair (beyond the usual status fields every other gate
    checks) is what makes this the ONLY gate that also guards against a
    concurrent rerun swapping the candidate set out from under an
    in-flight approval.
    Writes (via `sets`): reporting_status="Approved",
    workflow_status="Complete" (the ONLY transition anywhere in this
    module that ever writes "Complete" — every other approve_* leaves
    workflow_status "Awaiting Action" and only unlocks the next stage),
    approval_stage=None.
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    Called by: reporting_approval.approve_reporting_candidate() only —
    confirmed via grep (`wss.commit_reporting_approval(`), the sole call
    site in the codebase outside tests/test_reporting_stage.py and
    tests/test_stage_rerun.py. Pure database transition ONLY — no
    filesystem access, no manifest parsing, no hashing here. The caller
    lives OUTSIDE this module precisely so this one stays a pure DB layer;
    by the time this function runs, approve_reporting_candidate() has
    already: loaded the candidate manifest, re-verified every
    structured-content/DOCX/PDF hash against it, confirmed no report's
    validation.status is "error", and captured the exact
    reporting_result_json string + attempt number it reviewed — passed
    back here as expected_reporting_result_json/expected_reporting_attempt.
    Calls: _atomic_stage_transition().
    [FYP-EVALUATOR] Key decision — binding an approval to an exact
    reviewed candidate set: `metadata` is written into this decision's own
    workflow_approvals.metadata_json row, the durable record that survives
    even after a LATER rerun clears reporting_result_json (see
    get_latest_approved_reporting_set()/get_approved_reporting_sets()) —
    the mutable incidents.reporting_result_json column is never itself the
    source of truth for "what was approved".
    Error handling: raises ApprovalConflictError (via
    _atomic_stage_transition) if workflow/approval/reporting status don't
    match, OR if reporting_attempt/reporting_result_json changed between
    the caller's validation pass and this call (i.e. a concurrent
    rerun_stage() raced it) — the DB-state half of "approval must bind to
    the exact reviewed set"; the filesystem/hash half is
    reporting_approval.py's own job."""
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
    """[FYP-FUNCTION] Reject Reporting (Gate 3 of 3 — the final gate)
    [FYP-APPROVAL] [FYP-STAGE-LOCK] [FYP-DECISION] [FYP-EVALUATOR]
    Params: incident_id, run_id (str), rejected_by (str, analyst), reason
    (str, required rejection rationale — stored as `comments`).
    Requires (via `expect`): workflow_status=="Awaiting Approval",
    approval_stage=="reporting", reporting_status=="Awaiting Approval",
    run_id matching the row's current run_id. Unlike
    commit_reporting_approval(), this does NOT also pin
    reporting_attempt/reporting_result_json in `expect` — a rejection
    doesn't need to prove which exact candidate set was reviewed, only
    that Reporting is still awaiting a decision.
    Writes (via `sets`): reporting_status="Rejected",
    workflow_status="Rejected", approval_stage=None. There is no further
    downstream stage to explicitly block (Reporting is the last stage in
    the pipeline), unlike reject_triage()/reject_investigation() which
    must also flip the NEXT stage's status to "Blocked".
    Returns: dict {"incident_id", "run_id", "decided_at"}.
    [FYP-EVALUATOR] Called by: NO production caller currently exists —
    confirmed via grep (`reject_reporting`) across the full repo: app.py's
    Reporting tab only ever wires an Approve action
    (approve_reporting_candidate(), app.py's Reporting-tab approval
    button handler) — there is no "Reject Reporting" button/handler in
    app.py, unlike Triage and Investigation which both have a paired
    Approve/Reject control (see _reject_with_reason() in app.py). This
    function is exercised only by tests/test_reporting_stage.py
    (`wss.reject_reporting("INC-1", run_id, ...)`), which does prove it
    works and interoperates with rerun_stage() (a rejected Reporting
    attempt is one of the states rerun_stage()'s allowed_current_statuses
    permits re-running from), but it is effectively dead/unreached code
    from the UI's perspective as of this documentation pass — a gap an
    evaluator may want to flag, not a bug in this function itself.
    Calls: _atomic_stage_transition().
    Error handling: raises ApprovalConflictError if the current state
    doesn't match the required preconditions (already decided, stale
    run_id, etc.)."""
    return _atomic_stage_transition(
        incident_id, run_id,
        expect={"run_id": run_id, "workflow_status": "Awaiting Approval",
               "approval_stage": "reporting", "reporting_status": "Awaiting Approval"},
        sets={"reporting_status": "Rejected", "workflow_status": "Rejected",
             "approval_stage": None},
        approval_stage="reporting", decision="rejected",
        analyst=rejected_by, comments=reason)


def _reporting_approved_set_from_row(row: dict) -> dict:
    """[FYP-FUNCTION] Shape a workflow_approvals Row into an Approved-Set Record
    [FYP-APPROVAL] [FYP-DATABASE]
    Params: row (dict — one workflow_approvals row, approval_stage=
    'reporting', decision='approved').
    Returns: dict with the decision's own identity (decision_id,
    incident_id, run_id, stage_attempt, approval_attempt, approved_by,
    approved_at, comments) plus whatever binding metadata
    commit_reporting_approval() stored with it (report_set_id,
    candidate_manifest_path, candidate_manifest_sha256,
    reporting_stage_attempt, validation_status, warning_count) — the
    decision + metadata joined into ONE flat record callers actually want,
    rather than a raw DB row plus a separate JSON blob to unpack.
    Called by: get_approved_reporting_sets() (only call site, in this
    file).
    Calls: json.loads() on row["metadata_json"].
    Error handling: metadata_json is NULL for any row written before this
    column existed (or, in principle, if `metadata` was omitted at
    commit_reporting_approval() time) — a bad/missing JSON string is
    swallowed (TypeError/ValueError caught, falls back to {}) so callers
    must not assume every metadata key is present; row["id"]/["stage_attempt"]/
    etc. are always present since those are non-nullable workflow_approvals
    columns."""
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
    """[FYP-FUNCTION] Read Every Approved Reporting Decision for a Run
    [FYP-APPROVAL] [FYP-DATABASE]
    Params: incident_id, run_id (str).
    Returns: list[dict] — every approved Reporting decision ever recorded
    for this run, chronological (ORDER BY decided_at ASC), each one
    derived from an actual workflow_approvals row (never a
    guessed/reconstructed path), because a stage_attempt number alone
    does not prove which exact candidate manifest an analyst reviewed.
    Called by: case_view.py (confirmed via grep,
    `wss.get_approved_reporting_sets(incident_id, run_id)`) to render
    "Previously Approved Packages" — the historical approved sets —
    distinctly from whatever reporting_result_json currently holds (which
    may already belong to a later, not-yet-approved rerun).
    Calls: db_init(), db_connect(), _reporting_approved_set_from_row()."""
    db_init()
    with db_connect() as con:
        rows = con.execute(
            "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
            "AND approval_stage='reporting' AND decision='approved' "
            "ORDER BY decided_at ASC", (str(incident_id), run_id)).fetchall()
        return [_reporting_approved_set_from_row(dict(r)) for r in rows]


def get_latest_approved_reporting_set(incident_id: str, run_id: str) -> dict | None:
    """[FYP-FUNCTION] Read the Current Authoritative Approved Report Set
    [FYP-APPROVAL] [FYP-DATABASE] [FYP-EVALUATOR]
    Params: incident_id, run_id (str).
    Returns: dict (the most recently approved Reporting decision for this
    run, i.e. get_approved_reporting_sets()[-1]) or None if Reporting has
    never been approved for this run.
    Called by: reporting_approval.resolve_approved_report_file() and
    reporting_approval.build_export_all_zip() (confirmed via grep,
    `wss.get_latest_approved_reporting_set(...)`) — both re-resolve
    downloads from THIS, never from whatever reporting_result_json
    currently holds.
    Calls: get_approved_reporting_sets().
    [FYP-EVALUATOR] Key decision: this — not the mutable, rerun-clearable
    incidents.reporting_result_json column — is the authoritative source
    for "what is currently the approved/exportable report set". A later
    rerun_stage("reporting") nulls out reporting_result_json for the new
    attempt, but the workflow_approvals row this reads from is never
    touched, so a previously-approved set stays resolvable/downloadable
    even while a fresh Reporting attempt is in flight or has itself
    failed."""
    sets = get_approved_reporting_sets(incident_id, run_id)
    return sets[-1] if sets else None


def rerun_stage(incident_id: str, run_id: str, stage: str) -> dict:
    """[FYP-FUNCTION] Re-run a Completed/Terminal Downstream Stage
    [FYP-RERUN] [FYP-STAGE-LOCK] [FYP-STATE] [FYP-EVALUATOR]
    Params: incident_id, run_id (str), stage (str — one of "threat_intel",
    "investigation", "reporting"; anything else raises immediately).
    Requires: run_id matches the row's current run_id, workflow_status !=
    "Processing" (can't rerun while another stage is actively running),
    `stage`'s own status column is one of that stage's
    allowed_current_statuses (Threat Intel: Complete/Complete with
    Warnings/Failed; Investigation: Awaiting Approval/Approved/Failed;
    Reporting: Awaiting Approval/Approved/Failed/Rejected — "Rejected" is
    deliberately included so Reject -> Re-run is a reachable analyst path;
    without it a rejected Reporting attempt would be stuck with no way
    forward), AND the stage's own upstream prerequisite still holds
    (threat_intel needs triage_status=="Approved"; investigation needs
    threat_intel_status in Complete/Complete with Warnings; reporting needs
    investigation_status=="Approved").
    Writes: `stage`_status="Processing", `stage`_result_json=None,
    `stage`_updated_at=None, workflow_status="Processing",
    approval_stage=None, approved_by/approved_at/approval_comments=None,
    every worker_* lease column=None, last_error=None,
    workflow_updated_at=now. If stage=="threat_intel", ALSO clears
    investigation_status/investigation_result_json/investigation_updated_at
    and reporting_status/reporting_result_json/reporting_updated_at back to
    Pending/None (both downstream stages invalidated). If
    stage=="investigation", ALSO clears reporting_status/
    reporting_result_json/reporting_updated_at back to Pending/None. If
    stage=="reporting", no further downstream columns to clear (it's the
    last stage). Also increments `stage`_attempt (threat_intel_attempt /
    investigation_attempt / reporting_attempt) by 1 — the ONE place in this
    module a stage's attempt counter actually advances; claim_stage() only
    ever READS it.
    Returns: dict {"incident_id", "run_id", "stage"}.
    Called by: app.py's stage rerun button handlers (confirmed via grep,
    `wss.rerun_stage(`, multiple call sites) and rerun_pending_stage()
    (its backward-compatible alias).
    Calls: _tx().
    Error handling: raises ApprovalConflictError if run_id is stale,
    workflow_status=="Processing", the current stage status isn't in
    allowed_current_statuses, or the upstream prerequisite doesn't hold.
    [FYP-EVALUATOR] Key decision, preserved from the original author's own
    note: prior workflow_approvals decisions for this stage are
    DELIBERATELY NEVER deleted here (an earlier version did, to dodge a
    now-replaced one-row-per-stage unique index — that destroyed audit
    history). The (incident_id, run_id, approval_stage, stage_attempt,
    approval_attempt) unique index means the NEXT decision for this stage
    naturally lands on a new stage_attempt without colliding with any
    prior row, so every past decision (including ones later superseded by
    a rerun) stays permanently visible in get_approval_history().
    [FYP-STAGE-LOCK] Parsing and Triage do NOT go through this function —
    they use start_run(..., allow_retry=True) instead, because the
    existing entry point runs those two stages as one fresh, run-scoped
    process; this transition only ever handles the three post-approval
    agent stages, and always leaves the restarted stage's status at
    "Processing" (not "Pending") for soc_workflow.run_stage_chain() to
    pick straight up without a separate begin_stage() call."""
    stage = str(stage or "").strip().lower()
    if stage not in {"threat_intel", "investigation", "reporting"}:
        raise ApprovalConflictError(
            f"{stage or 'stage'} cannot be re-run with this transition")

    status_column = f"{stage}_status"
    result_column = f"{stage}_result_json"
    updated_column = f"{stage}_updated_at"

    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `ApprovalConflictError`, `execute`, `fetchone`, `int`, `isoformat`, `join`, `now`, `str`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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
    """[FYP-FUNCTION] rerun_stage() Alias (Backward Compatibility)
    [FYP-RERUN] [FYP-STAGE-LOCK]
    Params/Returns/Error handling: identical to rerun_stage() — this is a
    pure pass-through, kept only so any older caller/import spelled
    `rerun_pending_stage` (the previous UI-only entry point's name) still
    resolves without needing to be renamed everywhere.
    Called by: no confirmed production call site found via grep in app.py/
    soc_workflow.py/case_view.py as of this documentation pass (only
    rerun_stage() itself is called directly there); kept for backward
    compatibility per its own docstring.
    Calls: rerun_stage()."""
    return rerun_stage(incident_id, run_id, stage)


def retry_threat_intel(incident_id: str, run_id: str) -> dict:
    """[FYP-FUNCTION] Retry Threat Intelligence After a Failure
    [FYP-RERUN] [FYP-STAGE-LOCK] [FYP-STATE]
    Params: incident_id, run_id (str).
    Requires: run_id matches the row's current run_id AND
    threat_intel_status=="Failed" — this is a narrower, Failed-specific
    recovery path, distinct from rerun_stage("threat_intel") which accepts
    a wider set of current statuses (Complete/Complete with
    Warnings/Failed) for re-running an already-finished stage on purpose.
    Writes: threat_intel_status="Processing", investigation_status=
    "Pending" (recovers it from whatever "Blocked" it was left in by the
    failure), workflow_status="Processing", last_error=NULL,
    workflow_updated_at=now. Never touches Parsing or Triage, and — unlike
    rerun_stage() — does NOT clear threat_intel_result_json,
    threat_intel_updated_at, or bump threat_intel_attempt, since a Failed
    attempt has no completed result to invalidate and this is resuming the
    SAME attempt rather than starting a new one.
    Returns: dict {"incident_id", "run_id"}.
    Called by: app.py's Threat Intelligence retry button handler
    (confirmed via grep, `wss.retry_threat_intel(_sel_id, _wf_run_id)`).
    Calls: _tx().
    Error handling: raises ApprovalConflictError if run_id is stale or
    threat_intel_status isn't "Failed".
    Does not itself re-run anything; the caller (app.py) spawns
    soc_workflow.run_stage_chain() afterward, which — being a state-aware
    dispatcher — naturally resumes from Threat Intelligence and continues
    into Investigation/Reporting on success, exactly like the first
    attempt."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `ApprovalConflictError`, `execute`, `fetchone`, `isoformat`, `now`, `str`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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


# [FYP-STATE] Per-stage "is the upstream prerequisite satisfied" predicate,
# shared by begin_stage() (below) and mirrored (duplicated, not imported —
# kept a plain dict of column checks in each place) by rerun_stage()'s own
# upstream_ready dict. threat_intel needs Triage approved; investigation
# needs Threat Intel finished (successfully or with warnings); reporting
# needs Investigation approved.
_STAGE_UPSTREAM_READY = {
    "threat_intel": lambda row: row["triage_status"] == "Approved",
    "investigation": lambda row: row["threat_intel_status"]
        in {"Complete", "Complete with Warnings"},
    "reporting": lambda row: row["investigation_status"] == "Approved",
}


def begin_stage(incident_id: str, run_id: str, stage: str) -> dict:
    """[FYP-FUNCTION] Start a Stage a Prior Approval Unlocked but Left Pending
    [FYP-STAGE-LOCK] [FYP-STATE] [FYP-EVALUATOR]
    Params: incident_id, run_id (str), stage (str — one of "threat_intel",
    "investigation", "reporting"; anything else raises immediately).
    Requires: run_id matches the row's current run_id, workflow_status !=
    "Processing", `stage`'s own status column =="Pending" (i.e. an
    approve_*() call already unlocked it but nothing has started it yet),
    AND _STAGE_UPSTREAM_READY[stage](row) holds (re-checked here
    independently — see key decision below).
    Writes: `stage`_status="Processing", workflow_status="Processing",
    workflow_updated_at=now. Nothing else — no result columns, no worker
    lease columns (those are claim_stage()'s job once
    soc_workflow.run_stage_chain() actually starts the worker).
    Returns: dict {"incident_id", "run_id", "stage"}.
    Called by: app.py's stage "Start Process" button handler (confirmed
    via grep, `wss.begin_stage(`).
    Calls: _tx().
    Error handling: raises ApprovalConflictError if run_id is stale,
    workflow_status=="Processing", `stage`_status != "Pending", or the
    upstream prerequisite doesn't hold.
    [FYP-EVALUATOR] Key decision — approval only UNLOCKS the next stage,
    it must NEVER itself START it: this is the ONLY transition that flips
    a newly-unlocked, never-yet-attempted stage from "Pending" to
    "Processing", and it must only be called in direct response to the
    analyst clicking that stage's own Start Process button — never from
    an approval handler, a rerun, a navigation click, or a background
    poll. Re-checking the upstream prerequisite here (not just trusting
    that "Pending" implies it) closes a gap: without it, a stage left
    "Pending" by one run could, in principle, be started even if a later
    event downgraded the upstream stage's status before Start Process was
    clicked. Pure DB transition, like every other function in this
    module — the caller spawns soc_workflow.run_stage_chain() afterward to
    actually do the work."""
    stage = str(stage or "").strip().lower()
    if stage not in _STAGE_UPSTREAM_READY:
        raise ApprovalConflictError(
            f"{stage or 'stage'} cannot be started with this transition")
    status_column = f"{stage}_status"
    upstream_ready = _STAGE_UPSTREAM_READY[stage]

    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `ApprovalConflictError`, `execute`, `fetchone`, `isoformat`, `now`, `str`, `upstream_ready`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

    def _do(con):
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        if (row is None or row["run_id"] != run_id
                or row["workflow_status"] == "Processing"
                or row[status_column] != "Pending"
                or not upstream_ready(row)):
            got = {
                "run_id": row["run_id"] if row else None,
                "workflow_status": row["workflow_status"] if row else None,
                status_column: row[status_column] if row else None,
            }
            raise ApprovalConflictError(
                f"{stage} cannot be started from the current workflow "
                f"state: {got}")
        now = datetime.now(timezone.utc).isoformat()
        con.execute(
            f"UPDATE incidents SET {status_column}=?, workflow_status=?, "
            "workflow_updated_at=? WHERE id=? AND run_id=?",
            ("Processing", "Processing", now, str(incident_id), run_id))
        return {"incident_id": str(incident_id), "run_id": run_id, "stage": stage}

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
    """[FYP-CLASS] StageClaimError
    [FYP-STAGE-LOCK] [FYP-STATE] [FYP-ERROR]
    Raised by claim_stage() when another worker holds a live lease, the
    row/run/status preconditions don't match, or (via its GlobalLockBusyError
    subclass) a shared-workspace lock could not be acquired within its
    bounded wait. Distinct from ApprovalConflictError: this means
    'someone/something else already has this', not 'the analyst decision
    doesn't match the current state'. GlobalLockBusyError is a subclass so
    existing `except StageClaimError` handling (e.g. in
    soc_workflow.run_stage_chain) already covers shared-workspace
    contention without special-casing it."""


class GlobalLockBusyError(StageClaimError):
    """[FYP-CLASS] GlobalLockBusyError
    [FYP-STAGE-LOCK] [FYP-STATE] [FYP-ERROR]
    Raised by acquire_global_lock() when a different owner_id currently
    holds the named global_execution_locks row with an unexpired
    expires_at. Subclass of StageClaimError so callers that only catch the
    parent (e.g. soc_workflow.run_stage_chain) already handle this case."""


def claim_stage(incident_id: str, run_id: str, *, stage: str,
               status_column: str, expect_status: str) -> tuple[str, int]:
    """[FYP-FUNCTION] Atomically Claim a Stage via TTL Lease
    [FYP-STAGE-LOCK] [FYP-STATE]
    Params: incident_id, run_id (str), stage (str, e.g. "threat_intel" —
    stamped as worker_stage and used to look up the attempt column), status_
    column (str, e.g. "threat_intel_status" — the column expect_status is
    checked against), expect_status (str, e.g. "Processing" — the required
    current value of status_column).
    Requires: run_id matches the row's current run_id, row[status_column]
    == expect_status, AND no live (unexpired) worker_lease_expires_at
    exists — checked and written in the SAME transaction, which is the
    actual fix: reading expect_status alone is NOT sufficient, since two
    workers could both observe it true before either one writes.
    Writes: worker_id=<a fresh uuid4 hex>, worker_stage=stage,
    worker_started_at=now, worker_heartbeat_at=now,
    worker_lease_expires_at=now+_LEASE_DURATION_SECONDS (45s),
    worker_progress_note=NULL. Also inserts a "stage_started"
    workflow_activity row via _insert_activity_row() in the same
    transaction.
    Returns: tuple (worker_id: str, stage_attempt: int) — stage_attempt is
    READ from the row's own `{stage}_attempt` column (never incremented
    here; only rerun_stage() ever advances it) so the caller can stamp it
    on whatever result gets persisted via complete_stage().
    Called by: soc_workflow.py's per-stage runner functions (confirmed via
    grep, `claim_stage(` — run_threat_intel_stage/run_investigation_stage/
    run_reporting_stage-equivalent dispatchers) right after begin_stage()/
    rerun_stage() has flipped the stage to "Processing", and by
    tests/test_investigation_stage.py, tests/test_threat_intel_workflow.py,
    tests/test_reporting_stage.py.
    Calls: _tx(), _insert_activity_row().
    Error handling: raises StageClaimError if run_id/status_column don't
    match expect_status, or if a live lease is already held by another
    worker_id (message includes which worker and until when)."""
    worker_id = uuid.uuid4().hex
    attempt_col = _STAGE_ATTEMPT_COLUMN.get(stage)

    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `StageClaimError`, `_insert_activity_row`, `execute`, `fetchone`, `fromisoformat`, `int`, `isoformat`, `now`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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
    """[FYP-FUNCTION] Renew (Heartbeat) a Held Stage Lease
    [FYP-STAGE-LOCK] [FYP-STATE]
    Params: incident_id, run_id (str), worker_id (str — must equal the
    row's current worker_id to succeed).
    Requires: nothing hard — a mismatch or missing row is handled by
    returning False rather than raising, since this runs on an unattended
    heartbeat timer.
    Writes (only if worker_id matches): worker_heartbeat_at=now,
    worker_lease_expires_at=now+_LEASE_DURATION_SECONDS (45s) — extends
    the lease so claim_stage()'s live-lease check keeps treating this
    worker as the current owner.
    Returns: bool — True if renewed, False if this worker no longer owns
    the lease (row missing, or worker_id doesn't match) OR if the renewal
    transaction itself raised (caught and turned into False here) — either
    way the caller (soc_workflow.LeaseRenewer's heartbeat thread) must
    treat False as "stop, someone/something else may now own this stage".
    Called by: soc_workflow.LeaseRenewer (confirmed via grep,
    `renew_stage_lease(self._incident_id, self._run_id, self._worker_id)`)
    — called every _HEARTBEAT_RENEW_SECONDS (15s) while a stage's real
    work is in progress, not just once at stage start.
    Calls: _tx()."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `execute`, `fetchone`, `isoformat`, `now`, `str`, `timedelta`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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
    """[FYP-FUNCTION] Release a Held Stage Lease (Best-Effort Cleanup)
    [FYP-STAGE-LOCK] [FYP-STATE]
    Params: incident_id, run_id (str), worker_id (str — must equal the
    row's current worker_id for the clear to happen).
    Requires: nothing hard — every failure mode is swallowed (see error
    handling) since this is cleanup, not a state transition that anything
    depends on succeeding.
    Writes (only if worker_id still matches the row's current worker_id):
    worker_id=NULL, worker_stage=NULL, worker_lease_expires_at=NULL,
    worker_progress_note=NULL. Deliberately does NOT touch worker_started_at
    or worker_heartbeat_at.
    Returns: None.
    Called by: soc_workflow.py's per-stage runners, in a `finally` block on
    EVERY exit path — success, approval-gate reached, failure, superseded
    (confirmed via grep, `release_stage_lease(incident_id, run_id,
    worker_id)`) — so the lease is always released regardless of how the
    stage ended.
    Calls: _tx().
    Error handling: any exception from _tx() is caught and silently
    ignored (`except Exception: pass`) — a stuck lease still self-expires
    via its TTL, so failing to release here is degraded, not broken.
    Only clears if this worker still owns it — a lease that already
    expired and was reassigned to a newer worker must NOT be cleared by
    the old one. Safe to call even after complete_stage() already cleared
    it (no-op in that case, since worker_id will already be NULL)."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `execute`, `fetchone`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# [FYP-FUNCTION] `set_worker_progress_note` — implements the set worker progress note operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `note`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_investigation_stage, soc_workflow.py:run_reporting_stage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_guarded_update`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def set_worker_progress_note(incident_id: str, run_id: str, note: str | None) -> None:
    """Persisted, human-readable progress note shown by the Output tab while
    Processing — e.g. "Waiting for Investigation capacity" during global-lock
    contention (see soc_workflow.run_investigation_stage). Best-effort; a
    failure here must never abort the caller's real work."""
    try:
        _guarded_update(incident_id, run_id, {"worker_progress_note": note})
    except Exception:
        pass


# [FYP-FUNCTION] `complete_stage` — implements the complete stage operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `worker_id`, `stage`, `result_column`, `result`, `status_updates`, `expected_stage_attempt`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:resume_after_triage_approval, soc_workflow.py:run_investigation_stage, soc_workflow.py:run_reporting_stage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `_insert_activity_row`, `bool`, `dumps`, `execute`, `fetchone`, `fromisoformat`, `get`, `int`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# [FYP-FUNCTION] `acquire_global_lock` — implements the acquire global lock operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `lock_name`, `owner_id`, `incident_id`, `run_id`, `ttl_seconds`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_investigation_stage, soc_workflow.py:run_reporting_stage, tests/test_investigation_stage.py:test_release_global_lock_is_owner_scoped; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def acquire_global_lock(lock_name: str, *, owner_id: str, incident_id: str, run_id: str,
                        ttl_seconds: int = _LEASE_DURATION_SECONDS) -> None:
    """Cross-process, cross-incident lock over a shared filesystem workspace
    (the Investigation Agent's triaged_alerts/incident_reports tree, or the
    Reporting Agent's inputs/outputs tree) — per-incident stage leases alone
    do not stop two DIFFERENT incidents from entering the same shared
    directory at once. BEGIN IMMEDIATE; raises GlobalLockBusyError if a live
    (unexpired) row exists under a different owner_id; otherwise writes a
    fresh row with this owner_id."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `GlobalLockBusyError`, `execute`, `fetchone`, `fromisoformat`, `isoformat`, `now`, `str`, `timedelta`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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


# [FYP-FUNCTION] `renew_global_lock` — implements the renew global lock operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `lock_name`, `owner_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:_run, soc_workflow.py:run_investigation_stage, tests/test_investigation_stage.py:test_renew_global_lock_fails_after_reassignment; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def renew_global_lock(lock_name: str, owner_id: str) -> bool:
    """Extends expires_at iff the row's owner_id still matches this
    owner_id. Returns False (caller must treat the lock as lost) otherwise
    — used both as a periodic heartbeat renewal AND, during subprocess
    execution, as a watchdog check whose False return should terminate the
    still-running child process before anyone else is allowed to proceed
    (see soc_workflow._run_subprocess_streaming's watchdog_cb)."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `execute`, `fetchone`, `isoformat`, `now`, `timedelta`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# [FYP-FUNCTION] `release_global_lock` — implements the release global lock operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `lock_name`, `owner_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_investigation_stage, soc_workflow.py:run_reporting_stage, tests/test_investigation_stage.py:test_release_global_lock_is_owner_scoped; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def release_global_lock(lock_name: str, owner_id: str) -> None:
    """DELETE iff owner_id still matches. Best-effort, called in a finally —
    a lock that already expired and was reclaimed by someone else must not
    be deleted out from under them."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `execute`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _do(con):
        con.execute(
            "DELETE FROM global_execution_locks WHERE lock_name=? AND owner_id=?",
            (lock_name, owner_id))
    try:
        _tx(_do)
    except Exception:
        pass


# [FYP-FUNCTION] `_insert_activity_row` — persists or updates insert activity row state used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `con`, `incident_id`, `run_id`, `stage`, `action`, `actor`, `comments`, `metadata`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include workflow_state_store.py:_do; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `execute`, `isoformat`, `now`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# [FYP-FUNCTION] `record_activity` — persists or updates record activity state used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `stage`, `action`, `actor`, `comments`, `metadata`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include app.py:_record_export_all_download, app.py:_record_report_download, report_editing.py:discard_report_edit; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def record_activity(incident_id: str, run_id: str | None, stage: str | None, action: str,
                    *, actor: str | None = None, comments: str = "",
                    metadata: dict | None = None) -> None:
    """Top-level, standalone-transaction activity write — used ONLY for
    actions that are not themselves a workflow-state transition (e.g.
    "Export Word"/"Export PDF" report downloads), since there is no
    surrounding state-change transaction to piggyback on for those."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `_insert_activity_row`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _do(con):
        _insert_activity_row(con, incident_id=incident_id, run_id=run_id, stage=stage,
                             action=action, actor=actor, comments=comments,
                             metadata=metadata)
    _tx(_do)


# [FYP-FUNCTION] `get_activity` — retrieves get activity data for the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, case_view.py:build_activity; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `db_connect`, `db_init`, `dict`, `execute`, `fetchall`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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

# [FYP-FUNCTION] `upsert_report_edit` — implements the upsert report edit operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `edited_blocks`, `original_blocks`, `source_report_set_id`, `analyst`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include report_editing.py:save_report_edit, triage_ticket_editing.py:save_report_edit; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def upsert_report_edit(incident_id: str, run_id: str, report_type: str, *,
                       edited_blocks: list, original_blocks: list | None,
                       source_report_set_id: str | None, analyst: str) -> dict:
    """Insert the first saved edit for this (incident, run, report_type), or
    update it in place and bump ``version``. ``original_blocks`` is only
    written on the FIRST save (a later save must not overwrite the
    traceability snapshot of what the AI originally produced)."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `dict`, `dumps`, `execute`, `fetchone`, `isoformat`, `now`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# [FYP-FUNCTION] `get_report_edit` — retrieves get report edit data for the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include report_editing.py:report_row_state, triage_ticket_editing.py:ticket_row_state; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `db_connect`, `db_init`, `dict`, `execute`, `fetchone`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def get_report_edit(incident_id: str, run_id: str, report_type: str) -> dict | None:
    db_init()
    with db_connect() as con:
        row = con.execute(
            "SELECT * FROM report_edits WHERE incident_id=? AND run_id=? AND report_type=?",
            (str(incident_id), run_id, report_type)).fetchone()
        return dict(row) if row else None


# [FYP-FUNCTION] `list_report_edits` — implements the list report edits operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `db_connect`, `db_init`, `dict`, `execute`, `fetchall`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def list_report_edits(incident_id: str, run_id: str) -> list[dict]:
    db_init()
    with db_connect() as con:
        rows = con.execute(
            "SELECT * FROM report_edits WHERE incident_id=? AND run_id=?",
            (str(incident_id), run_id)).fetchall()
        return [dict(r) for r in rows]


# [FYP-FUNCTION] `discard_report_edit` — implements the discard report edit operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_render_report_editor, app.py:_render_reports_workspace; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_tx`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def discard_report_edit(incident_id: str, run_id: str, report_type: str) -> None:
    """"Replace with latest AI version" — deletes the saved edit row so the
    report reverts to showing the (current) AI-generated original. Does not
    touch any file on disk; the edited docx/pdf export (if one was ever
    generated) is simply orphaned, not deleted, for traceability."""
    # [FYP-FUNCTION] `_do` — implements the do operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `execute`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _do(con):
        con.execute(
            "DELETE FROM report_edits WHERE incident_id=? AND run_id=? AND report_type=?",
            (str(incident_id), run_id, report_type))
    _tx(_do)
