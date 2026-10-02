"""Read side of Agent Activity: history and the live SSE stream.

Both read only ``soc_db/agent_activity.db`` (observability.store); the
workflow database is consulted solely to resolve a case's current run id.
"""

from __future__ import annotations

import json
import time
from typing import Any, Iterator

import observability
from observability.store import query_events
from workflow import state_store as wss

STREAM_MAX_SECONDS = 120     # the browser's EventSource reconnects transparently
HEARTBEAT_SECONDS = 15
RETRY_MILLISECONDS = 2000


class CaseNotFound(LookupError):
    pass


def _resolve_run(case_id: str, run_id: str | None) -> str | None:
    state = wss.get_state(str(case_id))
    if state is None:
        raise CaseNotFound(case_id)
    return run_id or state.get("run_id")


def list_events(case_id: str, *, run_id: str | None = None, stage: str | None = None,
                after: int = 0, limit: int = 500, db_path: str | None = None) -> dict[str, Any]:
    run = _resolve_run(case_id, run_id)
    events = query_events(case_id=str(case_id), run_id=run, stage=stage, after=after,
                          limit=limit, path=db_path) if run else []
    return {
        "case_id": str(case_id),
        "run_id": run,
        "stage": stage,
        "events": events,
        "last_sequence": events[-1]["sequence"] if events else int(after or 0),
        "observability": {k: v for k, v in observability.status().items()
                          if k in ("enabled", "coverage")},
    }


def _sse(event: dict[str, Any]) -> str:
    return (f"id: {event['sequence']}\nevent: activity\n"
            f"data: {json.dumps(event, separators=(',', ':'), default=str)}\n\n")


def stream_events(case_id: str, *, run_id: str | None = None, stage: str | None = None,
                  after: int = 0, db_path: str | None = None,
                  max_seconds: float = STREAM_MAX_SECONDS,
                  heartbeat_seconds: float = HEARTBEAT_SECONDS) -> Iterator[str]:
    """Yield SSE frames for events newer than ``after`` (the client's
    Last-Event-ID), in sequence order, then close after ``max_seconds`` so
    no server thread is held indefinitely - EventSource reconnects with the
    last id it saw, so nothing is duplicated or lost."""
    run = _resolve_run(case_id, run_id)
    last = int(after or 0)
    yield f"retry: {RETRY_MILLISECONDS}\n\n"
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
        store = observability.get_store()
        # Read the committed high-water mark BEFORE querying, so anything
        # committed after the query wakes the wait below immediately.
        baseline = store.latest_sequence if store is not None else 0
        events = query_events(case_id=str(case_id), run_id=run, stage=stage, after=last,
                              path=db_path) if run else []
        for event in events:
            last = max(last, int(event["sequence"]))
            yield _sse(event)
        if events:
            continue
        remaining = max(0.0, deadline - time.monotonic())
        wait = min(heartbeat_seconds, remaining)
        if store is not None:
            arrived = store.wait_for_new(baseline, wait)
        else:
            time.sleep(min(wait, 2.0))
            arrived = False
        if not arrived:
            yield ": keepalive\n\n"
