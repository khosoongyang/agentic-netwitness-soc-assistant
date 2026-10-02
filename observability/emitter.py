"""The single emit() entry point used by every adapter.

emit() never raises and never blocks: it validates/sanitises the event and
hands it to the store's queue. With no store attached (instrumentation not
installed, or the activity database could not be opened) it is a no-op.
"""

from __future__ import annotations

import threading
from typing import Any

from . import context
from .events import build_event
from .sanitize import sanitize_text, sanitize_value

_LOCK = threading.Lock()
_STORE = None  # observability.store.ActivityStore | None
_FAILURES = {"emit": 0}


def attach_store(store) -> None:
    global _STORE
    with _LOCK:
        _STORE = store


def detach_store():
    global _STORE
    with _LOCK:
        store, _STORE = _STORE, None
    return store


def get_store():
    return _STORE


def emit(
    *,
    source: str,
    event_type: str,
    status: str,
    title: str,
    detail: str = "",
    ai_content_kind: str | None = None,
    span_id: str | None = None,
    parent_span_id: str | None = None,
    origin: str = "wrapper",
    metadata: dict[str, Any] | None = None,
    case_id: str | None = None,
    run_id: str | None = None,
    stage: str | None = None,
    stage_attempt: int | None = None,
) -> dict[str, Any] | None:
    """Record one observed fact. Identity defaults to the active RunScope;
    explicit ids are used by callers outside a worker scope (e.g. an
    analyst's approval request thread)."""
    try:
        store = _STORE
        if store is None:
            return None
        scope = context.current_scope()
        if case_id is None and scope is not None:
            case_id = scope.case_id
            run_id = scope.run_id if run_id is None else run_id
            stage = scope.stage if stage is None else stage
            stage_attempt = scope.stage_attempt if stage_attempt is None else stage_attempt
        if not case_id:
            return None
        event = build_event(
            case_id=case_id, run_id=run_id, stage=stage, stage_attempt=stage_attempt,
            source=source, event_type=event_type, status=status,
            title=sanitize_text(title, max_len=300),
            detail=sanitize_text(detail, max_len=2000),
            ai_content_kind=ai_content_kind, span_id=span_id,
            parent_span_id=parent_span_id, origin=origin,
            metadata=sanitize_value(metadata or {}),
        )
        store.enqueue(event)
        return event
    except Exception:
        _FAILURES["emit"] += 1
        return None


def failure_counts() -> dict[str, int]:
    return dict(_FAILURES)
