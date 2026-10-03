"""Agent Activity event contract.

One event = one genuinely observed runtime fact. Every field below is filled
from real execution (a wrapped call's arguments/return value, a LangChain
callback, or a persisted workflow transition) - never from a script of what a
stage "usually" does.

Labelling discipline (see the Phase 1-6 analysis): the current Aegis model
configuration exposes neither raw reasoning nor reasoning summaries, so the
only AI content kinds that may be emitted are ``assessment`` (an AI call and
its outcome), ``explanation`` (explanation fields the model itself returned
as part of its normal output) and ``summary`` (a post-stage AI summary that
did not take part in the stage's decisions).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

SOURCES = frozenset({
    "system",         # ordinary application/workflow operations
    "rule",           # deterministic code-enforced logic
    "tool",           # internal/external tool or API execution
    "ai",             # only when an LLM call actually happened
    "decision",       # a completed stage result
    "orchestration",  # workflow routing / stage lifecycle
    "human",          # analyst actions and approval gates
})

STATUSES = frozenset({"running", "completed", "warning", "failed", "waiting", "info"})

# Deliberately no "reasoning" / "reasoning_summary": the providers Aegis
# currently uses do not return either (see docs in observability/__init__.py).
AI_CONTENT_KINDS = frozenset({"assessment", "explanation", "summary"})

ORIGINS = frozenset({
    "wrapper",             # pass-through wrapper around a real function call
    "langchain_callback",  # LangChain callback fired by the real model call
    "state_transition",    # wrapped workflow-state write (claim/complete/approve)
    "subprocess_log",      # a known, structured line printed by an agent subprocess
})


def new_span_id() -> str:
    return uuid.uuid4().hex[:16]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def build_event(
    *,
    case_id: str,
    run_id: str | None,
    stage: str | None,
    stage_attempt: int | None,
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
) -> dict[str, Any]:
    """Validate and assemble one event. Raises ValueError on a contract
    violation - callers (emitter.emit) swallow it, so a bad event can never
    reach the workflow, it is simply not recorded."""
    if not case_id:
        raise ValueError("case_id is required")
    if source not in SOURCES:
        raise ValueError(f"unknown source {source!r}")
    if status not in STATUSES:
        raise ValueError(f"unknown status {status!r}")
    if origin not in ORIGINS:
        raise ValueError(f"unknown origin {origin!r}")
    if ai_content_kind is not None:
        if source != "ai":
            raise ValueError("ai_content_kind is only valid for source='ai'")
        if ai_content_kind not in AI_CONTENT_KINDS:
            raise ValueError(f"unknown ai_content_kind {ai_content_kind!r}")
    if source == "ai" and ai_content_kind is None:
        raise ValueError("source='ai' events must declare ai_content_kind")
    if not title:
        raise ValueError("title is required")
    return {
        "event_id": uuid.uuid4().hex,
        "sequence": None,  # assigned by the store at insert time
        "case_id": str(case_id),
        "run_id": run_id,
        "stage": stage,
        "stage_attempt": int(stage_attempt) if stage_attempt is not None else None,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "source": source,
        "event_type": event_type,
        "status": status,
        "title": title,
        "detail": detail or "",
        "ai_content_kind": ai_content_kind,
        "origin": origin,
        "metadata": metadata or {},
        "timestamp": utc_now_iso(),
    }
