"""Per-run observation scope.

A scope is opened by the wrapper around a stage's entry point (e.g.
``workflow.engine.run_triage_stage``) in the worker thread that executes it,
and identifies which case/run/stage the events emitted further down that
call stack belong to. ContextVars are thread-local in practice here (each
stage runs in its own worker thread) and do not leak into other threads, so
two incidents executing at the same time can never cross-attribute events.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RunScope:
    case_id: str
    run_id: str | None
    stage: str
    stage_attempt: int | None = None
    # Small per-scope scratch area for adapters (e.g. values the model
    # returned in one phase, compared against code-normalised values later).
    data: dict[str, Any] = field(default_factory=dict)


_SCOPE: ContextVar[RunScope | None] = ContextVar("aegis_activity_scope", default=None)
_PARENT_SPAN: ContextVar[str | None] = ContextVar("aegis_activity_parent_span", default=None)


def current_scope() -> RunScope | None:
    return _SCOPE.get()


def set_scope(scope: RunScope):
    return _SCOPE.set(scope)


def reset_scope(token) -> None:
    _SCOPE.reset(token)


def current_parent_span() -> str | None:
    return _PARENT_SPAN.get()


def set_parent_span(span_id: str | None):
    return _PARENT_SPAN.set(span_id)


def reset_parent_span(token) -> None:
    _PARENT_SPAN.reset(token)
