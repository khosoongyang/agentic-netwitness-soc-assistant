"""Agent Activity persistence: ``soc_db/agent_activity.db`` (separate file).

Design constraints (approved):
  * Never the workflow database - detailed events must not land in
    ``workflow_activity`` and must never contend for soc_incidents.db's
    write lock with stage claims/leases.
  * The workflow thread only ever does ``queue.put_nowait`` (microseconds,
    never blocks, never raises into the caller). One daemon writer thread
    owns every SQLite write. A full queue drops the event and counts it.
  * ``sequence`` (SQLite AUTOINCREMENT) is the authoritative ordering; it is
    assigned in queue (= emission) order by the single writer.
  * Readers (the history endpoint, the SSE stream) open their own short
    connections; WAL lets them read while the writer writes.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "soc_db" / "agent_activity.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_activity_events (
    sequence        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    case_id         TEXT NOT NULL,
    run_id          TEXT,
    stage           TEXT,
    stage_attempt   INTEGER,
    span_id         TEXT,
    parent_span_id  TEXT,
    source          TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    status          TEXT NOT NULL,
    title           TEXT NOT NULL,
    detail          TEXT,
    ai_content_kind TEXT,
    origin          TEXT NOT NULL,
    metadata_json   TEXT,
    occurred_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_activity_case_run
    ON agent_activity_events (case_id, run_id, sequence);
"""

_COLUMNS = (
    "sequence", "event_id", "case_id", "run_id", "stage", "stage_attempt",
    "span_id", "parent_span_id", "source", "event_type", "status", "title",
    "detail", "ai_content_kind", "origin", "metadata_json", "occurred_at",
)

_STOP = object()


def resolve_db_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path)
    override = os.environ.get("AEGIS_AGENT_ACTIVITY_DB", "").strip()
    return Path(override) if override else DEFAULT_DB_PATH


def _connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path), timeout=5, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def ensure_schema(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = _connect(path)
    try:
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error:
            pass
        con.executescript(_SCHEMA)
        con.commit()
    finally:
        con.close()


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    try:
        metadata = json.loads(row["metadata_json"] or "{}")
    except (TypeError, ValueError):
        metadata = {}
    return {
        "event_id": row["event_id"],
        "sequence": row["sequence"],
        "case_id": row["case_id"],
        "run_id": row["run_id"],
        "stage": row["stage"],
        "stage_attempt": row["stage_attempt"],
        "span_id": row["span_id"],
        "parent_span_id": row["parent_span_id"],
        "source": row["source"],
        "event_type": row["event_type"],
        "status": row["status"],
        "title": row["title"],
        "detail": row["detail"] or "",
        "ai_content_kind": row["ai_content_kind"],
        "origin": row["origin"],
        "metadata": metadata,
        "timestamp": row["occurred_at"],
    }


def query_events(
    *,
    case_id: str,
    run_id: str | None = None,
    stage: str | None = None,
    after: int = 0,
    limit: int = 500,
    path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Read events in sequence order. A missing database simply means no
    activity was ever recorded - returns []."""
    db = resolve_db_path(path)
    if not db.exists():
        return []
    sql = ["SELECT * FROM agent_activity_events WHERE case_id = ? AND sequence > ?"]
    params: list[Any] = [str(case_id), int(after or 0)]
    if run_id is not None:
        sql.append("AND run_id = ?")
        params.append(run_id)
    if stage is not None:
        sql.append("AND stage = ?")
        params.append(stage)
    sql.append("ORDER BY sequence ASC LIMIT ?")
    params.append(max(1, min(int(limit or 500), 2000)))
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        try:
            rows = con.execute(" ".join(sql), params).fetchall()
        except sqlite3.OperationalError:
            return []  # schema not created yet
        return [_row_to_event(row) for row in rows]
    finally:
        con.close()


class ActivityStore:
    """Owns the writer thread and the "new events committed" notification."""

    def __init__(self, path: str | Path | None = None, *, max_queue: int = 10_000):
        self.path = resolve_db_path(path)
        ensure_schema(self.path)
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._condition = threading.Condition()
        self._latest_sequence = 0
        self.dropped = 0
        self.write_errors = 0
        self._thread = threading.Thread(
            target=self._run, name="aegis-agent-activity-writer", daemon=True)
        self._thread.start()

    # -- producer side (workflow threads) ---------------------------------

    def enqueue(self, event: dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    # -- consumer side (writer thread) -------------------------------------

    def _run(self) -> None:
        con = None
        while True:
            item = self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                break
            batch = [item]
            # Drain whatever else is already waiting so bursts commit together.
            while len(batch) < 200:
                try:
                    nxt = self._queue.get_nowait()
                except queue.Empty:
                    break
                if nxt is _STOP:
                    self._queue.put_nowait(_STOP)  # re-queue; handled next loop
                    self._queue.task_done()
                    break
                batch.append(nxt)
            try:
                if con is None:
                    con = _connect(self.path)
                latest = self._write_batch(con, batch)
                if latest:
                    with self._condition:
                        self._latest_sequence = max(self._latest_sequence, latest)
                        self._condition.notify_all()
            except Exception:
                self.write_errors += len(batch)
                try:
                    if con is not None:
                        con.close()
                except Exception:
                    pass
                con = None
            finally:
                for _ in batch:
                    self._queue.task_done()
        if con is not None:
            try:
                con.close()
            except Exception:
                pass

    @staticmethod
    def _write_batch(con: sqlite3.Connection, batch: list[dict[str, Any]]) -> int:
        latest = 0
        with con:
            for event in batch:
                cursor = con.execute(
                    "INSERT OR IGNORE INTO agent_activity_events (event_id, case_id, run_id, "
                    "stage, stage_attempt, span_id, parent_span_id, source, event_type, status, "
                    "title, detail, ai_content_kind, origin, metadata_json, occurred_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (event["event_id"], event["case_id"], event.get("run_id"), event.get("stage"),
                     event.get("stage_attempt"), event.get("span_id"), event.get("parent_span_id"),
                     event["source"], event["event_type"], event["status"], event["title"],
                     event.get("detail") or "", event.get("ai_content_kind"), event["origin"],
                     json.dumps(event.get("metadata") or {}, default=str), event["timestamp"]))
                if cursor.lastrowid:
                    latest = max(latest, int(cursor.lastrowid))
        return latest

    # -- readers -----------------------------------------------------------

    @property
    def latest_sequence(self) -> int:
        return self._latest_sequence

    def wait_for_new(self, after_sequence: int, timeout: float) -> bool:
        """Block (a reader thread, never a workflow thread) until something
        newer than ``after_sequence`` has been committed, or ``timeout``."""
        with self._condition:
            if self._latest_sequence > after_sequence:
                return True
            self._condition.wait(timeout)
            return self._latest_sequence > after_sequence

    def flush(self, timeout: float = 5.0) -> bool:
        """Test helper: wait until every queued event has been written."""
        done = threading.Event()

        def _join() -> None:
            self._queue.join()
            done.set()

        threading.Thread(target=_join, daemon=True).start()
        return done.wait(timeout)

    def close(self, timeout: float = 5.0) -> None:
        try:
            self._queue.put(_STOP, timeout=timeout)
        except queue.Full:
            return
        self._thread.join(timeout)
