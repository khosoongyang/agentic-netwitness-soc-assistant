"""LangChain callback adapter - observes real model invocations.

Registered through LangChain's own ``register_configure_hook`` with a
ContextVar that is only set while an observed stage scope is open, so the
handler attaches to model calls made *inside* an observed Aegis stage run
and to nothing else (Ask Aegis chat, other processes, tests).

What it can truthfully report, from the callback payloads alone:
  * the requested model name (``ls_model_name``) and the model version the
    API reports back (``response_metadata.model_name``);
  * wall-clock duration of the call;
  * token usage, including the *count* of reasoning tokens when the API
    reports it (``usage_metadata.output_token_details.reasoning``) - the
    reasoning *content* is not returned by the API and is never implied;
  * the finish reason (e.g. ``length`` = output cut off at the limit);
  * call failures.

It never records prompts, messages or raw model output. It is a plain
BaseCallbackHandler (not a streaming handler), so attaching it cannot
switch a model call to the streaming API (langchain_core
BaseChatModel._should_stream only reacts to _StreamingCallbackHandler).
"""

from __future__ import annotations

import threading
import time
from contextvars import ContextVar
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from .. import context, details
from ..emitter import emit
from ..sanitize import describe_exception

_HANDLER: ContextVar[BaseCallbackHandler | None] = ContextVar(
    "aegis_activity_langchain_handler", default=None)
_REGISTERED = {"value": False}


def _usage_from(response) -> tuple[dict[str, int], str | None, str | None]:
    usage: dict[str, int] = {}
    response_model = None
    finish_reason = None
    try:
        generation = response.generations[0][0]
        message = getattr(generation, "message", None)
        meta = getattr(message, "usage_metadata", None) or {}
        if meta:
            for src, dst in (("input_tokens", "input"), ("output_tokens", "output"),
                             ("total_tokens", "total")):
                if meta.get(src) is not None:
                    usage[dst] = int(meta[src])
            reasoning = (meta.get("output_token_details") or {}).get("reasoning")
            if reasoning is not None:
                usage["reasoning"] = int(reasoning)
        response_meta = getattr(message, "response_metadata", None) or {}
        response_model = response_meta.get("model_name") or response_meta.get("model")
        finish_reason = response_meta.get("finish_reason")
        if finish_reason is None:
            finish_reason = (getattr(generation, "generation_info", None) or {}).get("finish_reason")
    except Exception:
        pass
    if not usage:
        try:
            raw = (response.llm_output or {}).get("token_usage") or {}
            for src, dst in (("prompt_tokens", "input"), ("completion_tokens", "output"),
                             ("total_tokens", "total")):
                if raw.get(src) is not None:
                    usage[dst] = int(raw[src])
            reasoning = (raw.get("completion_tokens_details") or {}).get("reasoning_tokens")
            if reasoning is not None:
                usage["reasoning"] = int(reasoning)
            response_model = response_model or (response.llm_output or {}).get("model_name")
        except Exception:
            pass
    return usage, response_model, finish_reason


def _usage_text(usage: dict[str, int]) -> str:
    parts = []
    for key, label in (("input", "input"), ("output", "output"), ("total", "total")):
        if key in usage:
            parts.append(f"{details.format_count(usage[key])} {label}")
    return " · ".join(parts)


class AgentActivityCallbackHandler(BaseCallbackHandler):
    """One instance per observed stage scope."""

    raise_error = False
    run_inline = True
    ignore_chain = True
    ignore_agent = True
    ignore_retriever = True
    ignore_retry = True
    ignore_custom_event = True

    def __init__(self, scope: context.RunScope):
        super().__init__()
        self._scope = scope
        self._calls: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _ids(self) -> dict[str, Any]:
        s = self._scope
        return {"case_id": s.case_id, "run_id": s.run_id, "stage": s.stage,
                "stage_attempt": s.stage_attempt}

    def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None,
                            tags=None, metadata=None, **kwargs) -> None:
        try:
            meta = metadata or {}
            invocation = kwargs.get("invocation_params") or {}
            model = (meta.get("ls_model_name") or invocation.get("model")
                     or invocation.get("model_name") or "unknown")
            provider = meta.get("ls_provider")
            with self._lock:
                index = self._scope.data.get("llm_call_count", 0) + 1
                self._scope.data["llm_call_count"] = index
                record = {"start": time.monotonic(), "model": model, "provider": provider,
                          "parent": context.current_parent_span(), "index": index}
                self._calls[str(run_id)] = record
            message_count = sum(len(batch) for batch in (messages or []))
            emit(source="ai", ai_content_kind="assessment", event_type="llm_call",
                 status="running", title="Model call started", detail=f"Model: {model}",
                 span_id=f"llm-{str(run_id)[:16]}", parent_span_id=record["parent"],
                 origin="langchain_callback",
                 metadata={"model": model, "provider": provider, "call_index": index,
                           "message_count": message_count,
                           "details": details.blocks(details.fields([("Model", model)]))},
                 **self._ids())
        except Exception:
            pass

    def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs) -> None:
        try:
            with self._lock:
                record = self._calls.pop(str(run_id), None)
            if record is None:
                return
            duration_ms = int((time.monotonic() - record["start"]) * 1000)
            usage, response_model, finish_reason = _usage_from(response)
            truncated = finish_reason == "length"
            model = record["model"]
            reasoning_value = (f"{details.format_count(usage['reasoning'])} "
                               "(count reported by the API; reasoning content is not exposed)"
                               if "reasoning" in usage else None)
            detail_blocks = details.blocks(details.fields([
                ("Model", model),
                ("Model version reported by API",
                 response_model if response_model and response_model != model else None),
                ("Duration", details.format_duration_ms(duration_ms)),
                ("Token usage", _usage_text(usage)),
                ("Reasoning tokens", reasoning_value),
                ("Finish reason", finish_reason),
            ]))
            emit(source="ai", ai_content_kind="assessment", event_type="llm_call",
                 status="warning" if truncated else "completed",
                 title=("Model call ended at the output length limit" if truncated
                        else "Model call completed"),
                 detail=f"Model: {model} · {details.format_duration_ms(duration_ms)}",
                 span_id=f"llm-{str(run_id)[:16]}", parent_span_id=record["parent"],
                 origin="langchain_callback",
                 metadata={"model": model, "response_model": response_model,
                           "provider": record["provider"], "call_index": record["index"],
                           "duration_ms": duration_ms, "usage": usage,
                           "finish_reason": finish_reason, "details": detail_blocks},
                 **self._ids())
        except Exception:
            pass

    def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs) -> None:
        try:
            with self._lock:
                record = self._calls.pop(str(run_id), None) or {}
            duration_ms = (int((time.monotonic() - record["start"]) * 1000)
                           if record.get("start") else None)
            emit(source="ai", ai_content_kind="assessment", event_type="llm_call",
                 status="failed", title="Model call failed", detail=describe_exception(error),
                 span_id=f"llm-{str(run_id)[:16]}", parent_span_id=record.get("parent"),
                 origin="langchain_callback",
                 metadata={"model": record.get("model"), "duration_ms": duration_ms,
                           "call_index": record.get("index"),
                           "details": details.blocks(details.fields([
                               ("Model", record.get("model")),
                               ("Duration", details.format_duration_ms(duration_ms)),
                           ]))},
                 **self._ids())
        except Exception:
            pass


def _activate(scope: context.RunScope):
    token = _HANDLER.set(AgentActivityCallbackHandler(scope))
    return lambda: _HANDLER.reset(token)


def install() -> bool:
    from langchain_core.tracers.context import register_configure_hook
    from .. import instrument

    if not _REGISTERED["value"]:
        register_configure_hook(_HANDLER, True)
        _REGISTERED["value"] = True
    instrument.register_scope_activator(_activate)
    return True


def uninstall() -> None:
    from .. import instrument

    instrument.unregister_scope_activator(_activate)
    if _REGISTERED["value"]:
        try:
            from langchain_core.tracers import context as lc_context

            lc_context._configure_hooks[:] = [
                hook for hook in lc_context._configure_hooks if hook[0] is not _HANDLER
            ]
        except Exception:
            pass
        _REGISTERED["value"] = False
