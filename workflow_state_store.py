"""
workflow_state_store.py — shared per-incident workflow status persistence.

Owns the `incidents` table schema in soc_db/soc_incidents.db (moved here,
unchanged, from app.py's previous db_init()) plus the workflow-status
columns added for the Triage approval flow. Both app.py and soc_workflow.py
import this module so there is exactly one writer and one schema owner.

Not related to soc_investigation_agent_revised/sync_engine.py, which
persists Investigation-stage Incident objects + a Chroma vector index for
correlation — a different subsystem with no concept of workflow status.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOC_DB_DIR = ROOT / "soc_db"
SOC_DB_DIR.mkdir(exist_ok=True)
DB_FILE = SOC_DB_DIR / "soc_incidents.db"

_ACTIVE_WORKFLOW_STATUSES = {"Processing", "Awaiting Approval"}


class WorkflowAlreadyRunningError(Exception):
    """Raised by start_run() when a workflow is already Processing or
    Awaiting Approval for this incident and allow_retry was not set."""
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


def db_init() -> None:
    """Full incidents + fetch_log schema — moved here verbatim from
    app.py's previous db_init(); app.py now imports this."""
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
        con.commit()
    _ensure_workflow_columns()


def _ensure_workflow_columns() -> None:
    """Additive-only ALTER TABLE — same pattern app.py already used once for
    parsing_status/parsing_result_json. Never redefines the base table."""
    with db_connect() as con:
        existing = {r["name"] for r in con.execute("PRAGMA table_info(incidents)").fetchall()}
        for col, ddl in {
            "parsing_status":      "TEXT",
            "parsing_result_json": "TEXT",
            "run_id":              "TEXT",
            "triage_status":       "TEXT",
            "workflow_status":     "TEXT",
            "approval_stage":      "TEXT",
            "triage_result_json":  "TEXT",
            "workflow_updated_at": "TEXT",
        }.items():
            if col not in existing:
                con.execute(f"ALTER TABLE incidents ADD COLUMN {col} {ddl}")
        con.commit()


def start_run(incident_id: str, *, allow_retry: bool = False) -> str:
    """Atomically checks for an already-active run (BEGIN IMMEDIATE takes
    SQLite's write lock before the read, so two sessions racing on the same
    incident can't both pass) and, if none (or allow_retry=True), resets
    this incident's row to a fresh run in the same transaction — clearing
    any previous parsing_status/triage_status/approval_stage/
    triage_result_json so no stale state lingers while the new run is
    in flight."""
    db_init()
    con = _autocommit_connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        current_status = row["workflow_status"] if row else None
        if current_status in _ACTIVE_WORKFLOW_STATUSES and not allow_retry:
            state = dict(row)
            con.execute("ROLLBACK")
            raise WorkflowAlreadyRunningError(incident_id, state)

        run_id = f"{incident_id}@{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc).isoformat()
        con.execute(
            "INSERT INTO incidents (id, run_id, parsing_status, triage_status, "
            "workflow_status, approval_stage, triage_result_json, workflow_updated_at) "
            "VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "run_id=excluded.run_id, parsing_status=excluded.parsing_status, "
            "triage_status=excluded.triage_status, workflow_status=excluded.workflow_status, "
            "approval_stage=excluded.approval_stage, "
            "triage_result_json=excluded.triage_result_json, "
            "workflow_updated_at=excluded.workflow_updated_at",
            (str(incident_id), run_id, "Processing", "Pending",
             "Processing", None, None, now))
        con.execute("COMMIT")
    except WorkflowAlreadyRunningError:
        raise
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    return run_id


def _guarded_update(incident_id: str, run_id: str | None, sets: dict) -> None:
    """Rejects the write if run_id doesn't match the row's current run_id —
    guards against a slow/abandoned run overwriting a newer run's status."""
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


def get_state(incident_id: str) -> dict | None:
    db_init()
    with db_connect() as con:
        row = con.execute("SELECT * FROM incidents WHERE id=?",
                          (str(incident_id),)).fetchone()
        return dict(row) if row else None
