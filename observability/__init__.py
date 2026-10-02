"""Aegis Agent Activity - runtime observability for workflow stages.

    REAL EXECUTION -> pass-through wrapper / LangChain callback -> event
                   -> soc_db/agent_activity.db -> SSE -> Agent Activity UI

Nothing here changes what the workflow does: wrappers forward the original
arguments, return the original objects and re-raise the original exceptions;
every observation step is exception-isolated; and the workflow thread only
ever enqueues (never blocks on I/O). ``uninstall()`` restores every original
function object.

AI content labelling under the current Aegis model configuration: neither
the Chat Completions calls (Triage, LangChain ChatOpenAI) nor the Responses
API calls (stage summaries, no ``reasoning`` parameter) return reasoning
content or reasoning summaries, so events are only ever labelled AI
ASSESSMENT / AI EXPLANATION / AI SUMMARY. A reasoning *token count* may be
shown as metadata when the API reports it; it reveals nothing of content.

Coverage: Parsing & Normalisation, Triage and Threat Intelligence Enrichment.
Investigation and Reporting emit nothing yet.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from . import emitter
from .instrument import Patcher

_LOCK = threading.Lock()
_STATE: dict[str, Any] = {"patcher": None, "store": None, "error": None}


def _disabled_by_env() -> bool:
    return os.environ.get("AEGIS_AGENT_ACTIVITY", "on").strip().lower() in {"0", "off", "false", "no"}


def install(db_path: str | None = None) -> dict[str, Any]:
    """Idempotently install instrumentation. Never raises: any failure leaves
    the workflow completely un-instrumented and is reported in status()."""
    with _LOCK:
        if _STATE["patcher"] is not None:
            return status()
        if _disabled_by_env():
            _STATE["error"] = "disabled via AEGIS_AGENT_ACTIVITY"
            return status()
        patcher = Patcher()
        try:
            from .store import ActivityStore
            from .adapters import langchain_adapter, parsing_adapter, threat_intel_adapter, triage_adapter

            store = ActivityStore(db_path)
            emitter.attach_store(store)
            _STATE["store"] = store
            langchain_adapter.install()
            parsing_adapter.install(patcher)
            triage_adapter.install(patcher)
            threat_intel_adapter.install(patcher)
            _STATE["patcher"] = patcher
            _STATE["error"] = None
        except Exception as exc:  # leave nothing half-installed
            _STATE["error"] = f"{type(exc).__name__}: {exc}"
            try:
                patcher.restore()
            except Exception:
                pass
            _teardown_store_and_hooks()
        return status()


def _teardown_store_and_hooks() -> None:
    try:
        from .adapters import langchain_adapter

        langchain_adapter.uninstall()
    except Exception:
        pass
    store = emitter.detach_store()
    _STATE["store"] = None
    if store is not None:
        try:
            store.close()
        except Exception:
            pass


def uninstall() -> list[str]:
    """Restore every wrapped function to its original object. Returns the
    labels of any wrapper that could not be restored because something else
    replaced it in the meantime."""
    with _LOCK:
        patcher = _STATE["patcher"]
        _STATE["patcher"] = None
        not_restored = patcher.restore() if patcher is not None else []
        _teardown_store_and_hooks()
        return not_restored


def is_enabled() -> bool:
    return _STATE["patcher"] is not None and emitter.get_store() is not None


def get_store():
    return emitter.get_store()


def status() -> dict[str, Any]:
    patcher = _STATE["patcher"]
    store = emitter.get_store()
    return {
        "enabled": patcher is not None and store is not None,
        "error": _STATE["error"],
        "coverage": ["parsing", "triage", "threat_intel"] if patcher is not None else [],
        "wrappers": dict(patcher.report) if patcher is not None else {},
        "dropped_events": getattr(store, "dropped", 0) if store else 0,
        "write_errors": getattr(store, "write_errors", 0) if store else 0,
    }
