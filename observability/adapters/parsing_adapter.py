"""Parsing & Normalisation observability.

Parsing is a deterministic stage: the parser (agents.parsing) is rule-based
and makes every parsing decision without AI. The only AI call in the stage
is the post-parser summary (workflow.stage_summaries.generate_parsing_ai_summary),
which runs after the parser returned and is not used by any parsing decision
or by the workflow's validation. Events are labelled accordingly:

  * NetWitness telemetry retrieval -> TOOL (live API calls) / SYSTEM (a
    local export file), with the real source determined from which
    functions actually ran;
  * the parser call -> SYSTEM. It is a single function call, so only its
    start and end are live. Everything listed on its completion row is
    read from the result it returned and is marked as such - never shown
    as individually timed steps;
  * workflow validation of the normalised alert -> RULE;
  * the stage outcome -> DECISION; routing -> ORCHESTRATION;
  * the post-parser summary -> AI SUMMARY, explicitly marked post-stage.

Each Parsing run creates a new workflow run, so the run id only becomes
known when wss.start_run() returns; the scope is opened at the entry point
and its run id filled in from that real return value.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from .. import context, details
from ..emitter import emit
from ..events import new_span_id
from ..instrument import Hooks, Patcher, Target
from ..sanitize import describe_exception

STAGE = "parsing"

_POST_STAGE_NOTE = ("Generated after the parser returned. Not used in parsing decisions "
                    "or in the workflow's validation of the parsed result.")
_RESULT_NOTE = ("Reported by the parser in the result it returned; these values were not "
                "observed as individually timed steps.")


def _scope() -> context.RunScope | None:
    scope = context.current_scope()
    return scope if scope is not None and scope.stage == STAGE else None


def _active() -> context.RunScope | None:
    """A parsing scope whose run id is known (events need it to be found)."""
    scope = _scope()
    return scope if scope is not None and scope.run_id else None


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _humanise(value: Any) -> str:
    return _str(value).replace("_", " ")


# ── Entry point: run_until_triage_approval(incident, ...) ───────────────────

def _entry_scope(call: dict) -> context.RunScope | None:
    incident = call.get("incident") or {}
    case_id = _str(incident.get("id") or incident.get("incidentId"))
    if not case_id:
        return None
    return context.RunScope(case_id=case_id, run_id=None, stage=STAGE, stage_attempt=1,
                            data={"parsing_only": bool(call.get("parsing_only"))})


def _emit_outcome(scope: context.RunScope, completed: bool, reason: str = "") -> None:
    if scope.data.get("outcome_emitted"):
        return
    scope.data["outcome_emitted"] = True
    facts = scope.data.get("parser_facts") or {}
    if completed:
        emit(source="decision", event_type="stage_result", status="completed",
             title="Parsing & Normalisation completed",
             detail=" · ".join(p for p in (
                 f"Parser confidence {facts['confidence']}" if facts.get("confidence") else "",
                 f"{facts['ioc_count']} observable indicator(s)" if facts.get("ioc_count") is not None else "",
                 "normalised alert validated") if p))
    else:
        # Prefer the parser's own stated reason (e.g. its identity guard) over
        # the workflow's generic "non-completed status" wording.
        specific = scope.data.get("parser_failure")
        emit(source="decision", event_type="stage_result", status="failed",
             title="Parsing & Normalisation failed",
             detail=specific or reason or "The Parsing stage did not complete.",
             metadata={"workflow_error": reason} if specific and reason else None)


def _entry_after(call: dict, token: Any, ctx: Any) -> None:
    scope = _active()
    if scope is None or not isinstance(ctx, dict):
        return
    stages = ctx.get("stages") or {}
    state = stages.get("parsing")
    if state == "completed":
        _emit_outcome(scope, True)
        if not scope.data.get("settled"):
            scope.data["settled"] = True
            emit(source="orchestration", event_type="stage_settled", status="completed",
                 origin="state_transition", title="Parsing finished",
                 detail="Workflow is waiting for an analyst to start Triage."
                 if stages.get("triage") == "pending" else "Parsing result is available.")
    elif state == "failed":
        _emit_outcome(scope, False, _str((ctx.get("errors") or {}).get("parsing")))
        if not scope.data.get("settled"):
            scope.data["settled"] = True
            emit(source="orchestration", event_type="stage_settled", status="failed",
                 origin="state_transition", title="Parsing stage marked Failed",
                 detail="Triage is blocked until Parsing is re-run.")


def _entry_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _active()
    if scope is None:
        return
    _emit_outcome(scope, False, describe_exception(exc))


# ── Run identity: wss.start_run(incident_id, *, allow_retry) ───────────────

def _start_run_after(call: dict, token: Any, run_id: Any) -> None:
    scope = _scope()
    if scope is None or not run_id:
        return
    scope.run_id = str(run_id)
    emit(source="orchestration", event_type="stage_requested", status="completed",
         origin="state_transition", title="Parsing run started",
         detail="A new workflow run was created for this case and Parsing set to Processing"
                + (" (re-run of a previous run)." if call.get("allow_retry") else "."))


# ── NetWitness telemetry retrieval ─────────────────────────────────────────

def _enrich_before(call: dict):
    scope = _active()
    if scope is None:
        return None
    span = new_span_id()
    scope.data["nw"] = {"live_calls": 0, "live_failures": 0, "token": None, "export": None}
    emit(source="tool", event_type="telemetry_fetch", status="running",
         title="Retrieving incident telemetry",
         detail="Checks for a local NetWitness export first; the live NetWitness API is used "
                "only if no export exists and a session token is available.",
         span_id=span)
    return {"span": span, "parent_token": context.set_parent_span(span), "start": time.monotonic(),
            "alerts_before": len((call.get("incident") or {}).get("alerts") or [])}


def _enrich_after(call: dict, token: Any, result: Any) -> None:
    scope = _active()
    if scope is None or not token:
        return
    nw = scope.data.get("nw") or {}
    elapsed = details.format_duration_ms((time.monotonic() - token["start"]) * 1000)
    source = ("live NetWitness API" if nw.get("live_calls") else
              "local NetWitness export" if nw.get("export") else None)
    enriched = isinstance(result, dict) and result is not call.get("incident")
    if enriched:
        count = len(result.get("alerts") or [])
        emit(source="tool", event_type="telemetry_fetch", status="completed",
             title="Incident telemetry retrieved",
             detail=f"{count} raw alert record(s) merged into the incident"
                    + (f" from the {source}" if source else "") + f" · {elapsed}",
             span_id=token["span"], metadata={"alert_records": count, "source": source})
        return
    if nw.get("live_failures"):
        reason = "the live NetWitness API call failed"
    elif nw.get("export") == "empty":
        reason = "the local export contained no alert records"
    elif nw.get("token") is False:
        reason = "no local export was found and no NetWitness session token is available"
    elif nw.get("live_calls"):
        reason = "the live NetWitness API returned no alert records"
    else:
        reason = "no additional alert records were returned"
    emit(source="tool", event_type="telemetry_fetch", status="warning",
         title="No additional telemetry retrieved",
         detail=f"Continuing with the incident data already held — {reason}. · {elapsed}",
         span_id=token["span"], metadata={"source": source})


def _enrich_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None or not token:
        return
    emit(source="tool", event_type="telemetry_fetch", status="failed",
         title="Telemetry retrieval raised an error", detail=describe_exception(exc),
         span_id=token["span"])


def _cleanup_parent(call: dict, token: Any) -> None:
    if token and token.get("parent_token") is not None:
        context.reset_parent_span(token["parent_token"])


def _payload_after(call: dict, token: Any, payload: Any) -> None:
    scope = _active()
    if scope is None:
        return
    nw = scope.data.setdefault("nw", {})
    if nw.get("live_calls"):
        return  # the live-call wrappers already reported what happened
    if isinstance(payload, dict) and payload:
        alerts = payload.get("alerts") or payload.get("alerts_full_raw") or []
        nw["export"] = "loaded" if alerts else "empty"
        emit(source="system", event_type="telemetry_export", status="completed",
             title="Local NetWitness export loaded",
             detail=f"{len(alerts) if isinstance(alerts, list) else 0} alert record(s) in the export file.",
             parent_span_id=context.current_parent_span())


def _payload_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None:
        return
    emit(source="tool", event_type="telemetry_lookup", status="failed",
         title="Telemetry lookup raised an error", detail=describe_exception(exc),
         parent_span_id=context.current_parent_span())


def _auth_after(call: dict, token: Any, result: Any) -> None:
    scope = _active()
    if scope is None or "nw" not in scope.data:
        return
    nw = scope.data["nw"]
    available = bool(result)
    if nw.get("token") is not None and (nw["token"] or not available):
        return  # report the first outcome, and a later loss of the token
    nw["token"] = available
    emit(source="tool", event_type="netwitness_auth",
         status="completed" if available else "warning",
         title="NetWitness session token available" if available
         else "No NetWitness session token available",
         detail="" if available else "Live NetWitness retrieval cannot be attempted without a token.",
         parent_span_id=context.current_parent_span())


def _live_call(label: str, kind: str):
    def before(call: dict):
        scope = _active()
        if scope is None or "nw" not in scope.data:
            return None
        scope.data["nw"]["live_calls"] += 1
        span = new_span_id()
        emit(source="tool", event_type="netwitness_api", status="running",
             title=f"NetWitness API: {label}", span_id=span,
             parent_span_id=context.current_parent_span())
        return {"span": span, "start": time.monotonic()}

    def after(call: dict, token: Any, result: Any) -> None:
        if _active() is None or not token:
            return
        elapsed = details.format_duration_ms((time.monotonic() - token["start"]) * 1000)
        if kind == "alerts":
            records = result[0] if isinstance(result, tuple) else result
            count = len(records or []) if isinstance(records, list) else 0
            text = f"{count} alert record(s) returned · {elapsed}"
        else:
            text = ("Incident details returned" if result else "No incident details returned") + f" · {elapsed}"
        emit(source="tool", event_type="netwitness_api", status="completed",
             title=f"NetWitness API: {label}", detail=text, span_id=token["span"],
             parent_span_id=context.current_parent_span())

    def error(call: dict, token: Any, exc: BaseException) -> None:
        scope = _active()
        if scope is None or not token:
            return
        scope.data["nw"]["live_failures"] += 1
        emit(source="tool", event_type="netwitness_api", status="failed",
             title=f"NetWitness API: {label} failed", detail=describe_exception(exc),
             span_id=token["span"], parent_span_id=context.current_parent_span())

    return Hooks(before=before, after=after, error=error)


# ── Raw incident artifact ──────────────────────────────────────────────────

def _artifact_after(call: dict, token: Any, path: Any) -> None:
    if _active() is None or call.get("artifact_type") != "raw_incident":
        return
    payload = call.get("payload") or {}
    availability = payload.get("data_availability") or {}
    emit(source="system", event_type="raw_incident_saved", status="completed",
         title="Raw incident saved for this run",
         detail=" · ".join(p for p in (
             f"{availability.get('alerts_count')} raw alert record(s)" if availability.get("alerts_count") is not None else "",
             # The workflow's own data-availability field, quoted as recorded
             # (it is derived from the incident's shape, not from where the
             # alert records were actually obtained - see the retrieval row).
             f"workflow data-availability record: incident_source={availability.get('incident_source')}"
             if availability.get("incident_source") else "",
         ) if p),
         metadata={"details": details.blocks(details.fields([
             ("incident_source (as recorded by the workflow)", availability.get("incident_source")),
             ("Alert fetch attempted", availability.get("alerts_fetch_attempted")),
             ("Alert fetch succeeded", availability.get("alerts_fetch_succeeded")),
             ("Raw alert records", availability.get("alerts_count")),
         ], label="Data availability"), details.items("Warnings", availability.get("warnings")))})


def _artifact_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None or call.get("artifact_type") != "raw_incident":
        return
    emit(source="system", event_type="raw_incident_saved", status="warning",
         title="Raw incident could not be saved for this run",
         detail=f"{describe_exception(exc)} — this run continues; later stages cannot reload it.")


# ── The parser itself (single deterministic call) ──────────────────────────

def _parser_facts(result: dict) -> dict:
    normalised = result.get("normalised_alert") or {}
    meta = normalised.get("parser_metadata") or {}
    card = result.get("parser_summary_card") or {}
    processed = result.get("processed_alert") or {}
    iocs = processed.get("iocs") if isinstance(processed, dict) else None
    types = Counter(str(i.get("type")) for i in (iocs or []) if isinstance(i, dict))
    confidence = result.get("parser_confidence") or meta.get("parser_confidence")
    score = result.get("parser_confidence_score")
    return {
        "status": result.get("status"),
        "input_format": meta.get("input_format"),
        "parser_version": meta.get("parser_version"),
        "alert_records": result.get("normalised_alert_count", meta.get("alert_count")),
        "raw_events": result.get("event_count", card.get("raw_events_retrieved")),
        "raw_meta_keys": meta.get("raw_meta_key_count"),
        "fields_extracted": card.get("important_fields_extracted"),
        "ioc_count": len(iocs) if isinstance(iocs, list) else card.get("ioc_count"),
        "ioc_types": ", ".join(f"{t.replace('_', ' ')} ×{n}" for t, n in sorted(types.items())),
        "powershell": card.get("powershell_decode_status"),
        "confidence": confidence,
        "confidence_text": f"{confidence} ({score}/100)" if confidence and score not in (None, "") else confidence,
        "missing": result.get("missing_important_fields") or [],
        "warnings": result.get("warnings") or [],
        "identity": result.get("identity_validation") or {},
    }


def _parser_before(call: dict):
    if _active() is None:
        return None
    span = new_span_id()
    emit(source="system", event_type="parser", status="running",
         title="Parsing and normalising incident data",
         detail="Rule-based parser running — no AI is used for parsing or extraction.",
         span_id=span)
    return {"span": span, "start": time.monotonic()}


def _parser_after(call: dict, token: Any, result: Any) -> None:
    scope = _active()
    if scope is None or not token or not isinstance(result, dict):
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    facts = _parser_facts(result)
    scope.data["parser_facts"] = facts
    identity = facts["identity"]
    identity_text = None
    if identity:
        identity_text = ("passed" if identity.get("passed") else "failed") + (
            f" — {identity.get('message')}" if identity.get("message") else "")
    completed = facts["status"] == "completed"
    if not completed:
        scope.data["parser_failure"] = _str(result.get("summary")) or "Parser status: failed"
    summary = " · ".join(p for p in (
        f"format {_humanise(facts['input_format'])}" if facts["input_format"] else "",
        f"{facts['alert_records']} alert record(s)" if facts["alert_records"] is not None else "",
        f"{facts['ioc_count']} observable indicator(s)" if facts["ioc_count"] is not None else "",
        f"confidence {facts['confidence']}" if facts["confidence"] else "",
    ) if p)
    emit(source="system", event_type="parser", status="completed" if completed else "failed",
         title="Parsing and normalisation completed" if completed
         else "Parser returned a failed result",
         detail=(summary if completed else _str(result.get("summary")) or "Parser status: failed"),
         span_id=token["span"],
         metadata={"result_derived": True, "duration_ms": elapsed_ms,
                   "details": details.blocks(
                       details.note(_RESULT_NOTE),
                       details.fields([
                           ("Parser status", facts["status"]),
                           ("Input format", _humanise(facts["input_format"])),
                           ("Alert records normalised", facts["alert_records"]),
                           ("Raw events processed", facts["raw_events"]),
                           ("Raw metadata keys read", facts["raw_meta_keys"]),
                           ("Important fields extracted", facts["fields_extracted"]),
                           ("Observable indicators", facts["ioc_count"]),
                           ("Indicator types", facts["ioc_types"]),
                           ("PowerShell decoding", _humanise(facts["powershell"])),
                           ("Parser confidence (rule-based score)", facts["confidence_text"]),
                           ("Identity guard", identity_text),
                           ("Parser version", facts["parser_version"]),
                           ("Parser run time", details.format_duration_ms(elapsed_ms)),
                       ], label="Parser result"),
                       details.items("Missing fields", facts["missing"]),
                       details.items("Parser warnings", facts["warnings"]),
                   )})


def _parser_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None or not token:
        return
    emit(source="system", event_type="parser", status="failed",
         title="Parser raised an error", detail=describe_exception(exc), span_id=token["span"])


# ── Post-parser AI summary (raw OpenAI SDK call) ───────────────────────────

def _summary_before(call: dict):
    scope = _active()
    if scope is None:
        return None
    span = new_span_id()
    scope.data["summary_span"] = span
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="running",
         title="Post-stage AI summary started", detail=_POST_STAGE_NOTE, span_id=span,
         metadata={"post_stage": True})
    return {"span": span, "parent_token": context.set_parent_span(span), "start": time.monotonic()}


def _summary_after(call: dict, token: Any, result: Any) -> None:
    scope = _active()
    if scope is None or not token or not isinstance(result, dict):
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    summary = _str(result.get("ai_summary"))
    unavailable = summary.lower().startswith("ai summary unavailable")
    bullets = [line.strip(" -•*\t") for line in _str(result.get("ai_thinking")).splitlines()
               if line.strip(" -•*\t")]
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary",
         status="warning" if unavailable else "completed",
         title="Post-stage AI summary unavailable" if unavailable else "Post-stage AI summary generated",
         detail=summary, span_id=token["span"],
         metadata={"post_stage": True, "model": result.get("ai_summary_model"), "duration_ms": elapsed_ms,
                   "details": details.blocks(
                       details.note(_POST_STAGE_NOTE),
                       details.text("Summary", summary),
                       None if unavailable else details.items(
                           "Key indicators noted by the model (model-written output)", bullets),
                       details.fields([("Model", result.get("ai_summary_model")),
                                       ("Duration", details.format_duration_ms(elapsed_ms))]),
                   )})


def _summary_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="failed",
         title="Post-stage AI summary failed", detail=describe_exception(exc),
         span_id=token["span"], metadata={"post_stage": True})


def _summary_cleanup(call: dict, token: Any) -> None:
    scope = _scope()
    if scope is not None:
        scope.data.pop("summary_span", None)
    _cleanup_parent(call, token)


def _model_request_before(call: dict):
    """The raw-SDK request made by the post-parser summary. Only the model
    argument actually passed and the call's duration/outcome are recorded -
    never the prompt."""
    scope = _active()
    if scope is None or not scope.data.get("summary_span"):
        return None
    model = _str(call.get("model")) or "default (OPENAI_MODEL)"
    span = new_span_id()
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="running",
         title="Model request sent", detail=f"Model: {model}", span_id=span,
         parent_span_id=scope.data["summary_span"],
         metadata={"model": model, "details": details.blocks(details.fields([("Model", model)]))})
    return {"span": span, "model": model, "parent": scope.data["summary_span"],
            "start": time.monotonic()}


def _model_request_after(call: dict, token: Any, result: Any) -> None:
    if _active() is None or not token:
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="completed",
         title="Model response received",
         detail=f"Model: {token['model']} · {details.format_duration_ms(elapsed_ms)}",
         span_id=token["span"], parent_span_id=token["parent"],
         metadata={"model": token["model"], "duration_ms": elapsed_ms,
                   "details": details.blocks(details.fields([
                       ("Model", token["model"]),
                       ("Duration", details.format_duration_ms(elapsed_ms)),
                       ("Token usage", "not returned through this call path"),
                   ]))})


def _model_request_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None or not token:
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="failed",
         title="Model request failed", detail=describe_exception(exc),
         span_id=token["span"], parent_span_id=token["parent"],
         metadata={"model": token["model"], "duration_ms": elapsed_ms})


# ── Persistence, status and validation ─────────────────────────────────────

def _saved_after(call: dict, token: Any, result: Any) -> None:
    if _active() is None:
        return
    emit(source="system", event_type="result_saved", status="completed",
         origin="state_transition", title="Parsing result saved for this run")


def _saved_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None:
        return
    emit(source="system", event_type="result_saved", status="failed", origin="state_transition",
         title="Saving the Parsing result failed", detail=describe_exception(exc))


def _parsing_status_after(call: dict, token: Any, result: Any) -> None:
    if _active() is None or call.get("status") != "Complete":
        return
    emit(source="orchestration", event_type="status_update", status="completed",
         origin="state_transition", title="Parsing status set to Complete")


def _validation_after(call: dict, token: Any, result: Any) -> None:
    if _active() is None or not isinstance(result, dict):
        return
    checks = [_humanise(c) for c in (result.get("checks_passed") or [])]
    emit(source="rule", event_type="validation", status="completed",
         title="Normalised alert passed workflow validation",
         detail="; ".join(checks),
         metadata={"details": details.blocks(details.items("Checks passed", checks))})


def _validation_error(call: dict, token: Any, exc: BaseException) -> None:
    if _active() is None:
        return
    emit(source="rule", event_type="validation", status="failed",
         title="Normalised alert failed workflow validation", detail=describe_exception(exc))


def _triage_status_after(call: dict, token: Any, result: Any) -> None:
    scope = _active()
    if scope is None:
        return
    status = call.get("status")
    if status == "Pending":
        emit(source="orchestration", event_type="routing", status="info",
             origin="state_transition", title="Triage unlocked",
             detail="Triage status: Pending — it runs only when an analyst starts it.")
    elif status == "Processing":
        # Combined Parsing -> Triage entry point: Parsing has finished here.
        _emit_outcome(scope, True)
        scope.data["settled"] = True
        emit(source="orchestration", event_type="stage_settled", status="completed",
             origin="state_transition", title="Parsing finished",
             detail="Triage starts immediately in this run.")


def install(patcher: Patcher) -> None:
    engine = "workflow.engine"
    patcher.wrap(Target(engine, "run_until_triage_approval",
                        ("incident", "use_mock_triage", "force_triage", "allow_retry",
                         "progress_fn", "parsing_only", "host", "token")),
                 Hooks(scope=_entry_scope, after=_entry_after, error=_entry_error))
    patcher.wrap(Target("workflow.state_store", "start_run", ("incident_id", "allow_retry")),
                 Hooks(after=_start_run_after))
    patcher.wrap(Target(engine, "enrich_incident_with_apiretrieval_fetch", ("incident", "host", "token")),
                 Hooks(before=_enrich_before, after=_enrich_after, error=_enrich_error,
                       cleanup=_cleanup_parent))
    fetch = "integrations.netwitness.fetch_api"
    patcher.wrap(Target(fetch, "get_comprehensive_incident_payload", ("incident_id", "host", "token")),
                 Hooks(after=_payload_after, error=_payload_error))
    patcher.wrap(Target(fetch, "get_auth_token", ("host", "token", "force_refresh")),
                 Hooks(after=_auth_after))
    patcher.wrap(Target(fetch, "fetch_incident_via_fetch_api",
                        ("host", "token", "incident_id", "auto_refresh")),
                 _live_call("incident details (FETCH API)", "incident"))
    patcher.wrap(Target(fetch, "fetch_incident_details", ("host", "headers", "incident_id", "auto_refresh")),
                 _live_call("incident details (Respond API)", "incident"))
    patcher.wrap(Target(fetch, "fetch_alerts_via_fetch_api",
                        ("host", "token", "incident_id", "count", "auto_refresh")),
                 _live_call("alert records (FETCH API)", "alerts"))
    patcher.wrap(Target(fetch, "fetch_all_alerts_and_endpoint_events",
                        ("host", "headers", "incident_id", "auto_refresh")),
                 _live_call("alert records and endpoint events (Respond API)", "alerts"))
    patcher.wrap(Target(engine, "_save_run_artifact",
                        ("incident_id", "run_id", "filename", "artifact_type", "payload")),
                 Hooks(after=_artifact_after, error=_artifact_error))
    patcher.wrap(Target("agents.parsing", "run_parser_normalisation_for_dashboard",
                        ("raw_alert", "output_dir", "expected_case_id")),
                 Hooks(before=_parser_before, after=_parser_after, error=_parser_error))
    patcher.wrap(Target(engine, "generate_parsing_ai_summary", ("parsing_result", "model")),
                 Hooks(before=_summary_before, after=_summary_after, error=_summary_error,
                       cleanup=_summary_cleanup))
    patcher.wrap(Target("integrations.openai.client", "invoke_openai_text",
                        ("prompt", "system", "model", "temperature", "max_output_tokens",
                         "timeout", "text_format")),
                 Hooks(before=_model_request_before, after=_model_request_after,
                       error=_model_request_error))
    patcher.wrap(Target("workflow.state_store", "save_parsing_result", ("incident_id", "run_id", "summary")),
                 Hooks(after=_saved_after, error=_saved_error))
    patcher.wrap(Target("workflow.state_store", "set_parsing_status", ("incident_id", "run_id", "status")),
                 Hooks(after=_parsing_status_after))
    patcher.wrap(Target("workflow.validation", "validate_parsing_result",
                        ("incident_id", "parsing_result", "skip")),
                 Hooks(after=_validation_after, error=_validation_error))
    patcher.wrap(Target("workflow.state_store", "set_triage_status", ("incident_id", "run_id", "status")),
                 Hooks(after=_triage_status_after))
