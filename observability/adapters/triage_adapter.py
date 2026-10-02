"""Triage-stage observability (proof of concept).

Every event below is derived from a real call's arguments or return value at
the moment that call happens. Nothing is emitted for a step that did not run.

Source labelling follows what the code actually does (see the Phase 1-6
analysis):
  * three LLM phases (IOC checklist, risk rating, classification) -> AI;
    their returned explanation fields (per-category ``reasoning``, risk
    ``rationale``, classification ``summary``/actions) -> AI EXPLANATION;
  * overall risk = highest likelihood, classification level = overall risk,
    response time from the classification table, MITRE snapped to the
    canonical list -> RULE (computed in code, not by the model);
  * the post-stage ``generate_triage_ai_summary`` call -> AI SUMMARY, marked
    post-stage (it does not take part in any triage decision); its
    "thinking process" text is rendered from the trace without AI -> SYSTEM.
Triage produces no "true positive" verdict and no confidence value, so none
is ever shown.
"""

from __future__ import annotations

import time
from typing import Any

from .. import context, details
from ..emitter import emit
from ..events import new_span_id
from ..instrument import Hooks, Patcher, Target
from ..sanitize import describe_exception

STAGE = "triage"

_STAGE_NAMES = {
    "threat_intelligence": "Threat Intelligence Enrichment",
    "threat_intel": "Threat Intelligence Enrichment",
    "investigation": "Investigation",
    "reporting": "Reporting",
}

_PHASES = {
    "_run_ioc": ("ioc_checklist", "IOC checklist assessment"),
    "_run_risk": ("risk_rating", "Risk rating assessment"),
    "_run_cls": ("classification", "Classification assessment"),
}

_IOC_CATEGORIES = (("availability", "Availability"),
                   ("confidentiality", "Confidentiality"),
                   ("integrity", "Integrity"))

_LIKELIHOODS = (("likelihood_initiation", "Likelihood of initiation"),
                ("likelihood_occurrence", "Likelihood of occurrence"),
                ("likelihood_adverse_impact", "Likelihood of adverse impact"))


def _scope() -> context.RunScope | None:
    scope = context.current_scope()
    return scope if scope is not None and scope.stage == STAGE else None


def _approval_span(run_id: Any, attempt: Any) -> str:
    return f"approval:{run_id}:{STAGE}:{attempt or 1}"


def _state(incident_id: str) -> dict:
    from workflow import state_store

    return state_store.get_state(str(incident_id)) or {}


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


# ── Stage entry: run_triage_stage(incident_id, run_id) ─────────────────────

def _stage_scope(call: dict) -> context.RunScope:
    return context.RunScope(case_id=str(call.get("incident_id")), run_id=call.get("run_id"),
                            stage=STAGE)


def _stage_after(call: dict, token: Any, result: Any) -> None:
    if isinstance(result, dict) and result.get("status") == "failed":
        errors = result.get("errors") or []
        emit(source="decision", event_type="stage_result", status="failed",
             title="Triage failed", detail=_str(errors[0] if errors else "Triage returned a failed status"))


def _stage_error(call: dict, token: Any, exc: BaseException) -> None:
    if type(exc).__name__ == "StageClaimError":
        emit(source="orchestration", event_type="worker_stopped", status="warning",
             title="Triage worker stopped without saving a result",
             detail="The stage lease was not held by this worker (another worker owns it, or the run was superseded).")
    else:
        emit(source="orchestration", event_type="worker_stopped", status="failed",
             title="Triage worker raised an error", detail=describe_exception(exc))


# ── Stage lifecycle (state transitions) ────────────────────────────────────

def _claim_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    try:
        scope.stage_attempt = int(result[1])
    except Exception:
        pass
    emit(source="orchestration", event_type="stage_claimed", status="completed",
         origin="state_transition", title="Triage stage claimed by a worker",
         detail=f"Attempt {scope.stage_attempt or '—'} · worker lease acquired")


def _claim_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_claimed", status="warning",
         origin="state_transition", title="Triage stage could not be claimed",
         detail=describe_exception(exc))


def _complete_after(call: dict, token: Any, ok: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    updates = call.get("status_updates") or {}
    status = updates.get("triage_status")
    if not ok:
        emit(source="orchestration", event_type="stage_settled", status="warning",
             origin="state_transition", title="Triage result was not saved",
             detail="The stage lease was reassigned before the result could be written.")
        return
    if status == "Awaiting Approval":
        emit(source="orchestration", event_type="stage_settled", status="completed",
             origin="state_transition", title="Triage result saved",
             detail="Workflow paused at the SOC analyst approval gate.",
             metadata={"status_updates": updates})
        emit(source="human", event_type="approval_required", status="waiting",
             origin="state_transition", title="SOC analyst approval required",
             detail="Waiting for an analyst to approve or reject the Triage result.",
             span_id=_approval_span(scope.run_id, scope.stage_attempt))
    elif status == "Failed":
        result = call.get("result") or {}
        error = result.get("error") or "; ".join(str(e) for e in (result.get("errors") or []))
        emit(source="orchestration", event_type="stage_settled", status="failed",
             origin="state_transition", title="Triage marked Failed",
             detail=_str(error) or "The stage ended with a failure status.",
             metadata={"status_updates": updates})
    else:
        emit(source="orchestration", event_type="stage_settled", status="info",
             origin="state_transition", title="Triage stage status updated",
             detail=f"Triage status: {status or 'unchanged'}", metadata={"status_updates": updates})


def _complete_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_settled", status="failed",
         origin="state_transition", title="Saving the Triage result failed",
         detail=describe_exception(exc))


# ── Context loading ────────────────────────────────────────────────────────

def _parsing_loaded(call: dict, token: Any, result: Any) -> None:
    if _scope() is None:
        return
    processed = (result or {}).get("processed_alert") if isinstance(result, dict) else None
    if not processed:
        emit(source="system", event_type="context_loaded", status="warning",
             title="No persisted Parsing context for this run",
             detail="Triage will work from the raw incident only (no parsed context supplied).")
        return
    ioc_count = len(processed.get("iocs") or []) if isinstance(processed, dict) else None
    confidence = result.get("parser_confidence")
    emit(source="system", event_type="context_loaded", status="completed",
         title="Loaded normalised incident context from Parsing",
         detail=" · ".join(p for p in (
             f"{ioc_count} indicator(s) in the processed alert" if ioc_count is not None else "",
             f"parser confidence {confidence}" if confidence else "") if p),
         metadata={"ioc_count": ioc_count, "parser_confidence": confidence})


def _raw_loaded(call: dict, token: Any, result: Any) -> None:
    if _scope() is None:
        return
    if not isinstance(result, dict) or not result:
        emit(source="system", event_type="context_loaded", status="warning",
             title="Raw incident artifact unavailable for this run",
             detail="The persisted raw incident could not be loaded.")
        return
    title = result.get("title") or result.get("name")
    if isinstance(result.get("alerts"), list):
        alerts_text = f"{len(result['alerts'])} raw alert record(s) included"
        count = len(result["alerts"])
    else:
        # Distinguish "no alerts" from "alert records not part of this artifact".
        reported = result.get("alertCount")
        alerts_text = (f"incident reports {reported} alert(s); raw alert records not included"
                       if reported is not None else "raw alert records not included")
        count = None
    emit(source="system", event_type="context_loaded", status="completed",
         title="Loaded raw incident",
         detail=" · ".join(p for p in (_str(title), alerts_text) if p),
         metadata={"raw_alert_records": count, "reported_alert_count": result.get("alertCount")})


# ── Triage agent entry: engine.run_triage(...) ─────────────────────────────

def _run_triage_scope(call: dict) -> context.RunScope | None:
    """Only used when run_triage is reached outside run_triage_stage (the
    combined Parsing->Triage entry point). The run id is read back from the
    persisted state - never guessed."""
    if context.current_scope() is not None:
        return None
    incident = call.get("incident") or {}
    case_id = _str(incident.get("id") or incident.get("incidentId"))
    if not case_id:
        return None
    state = _state(case_id)
    return context.RunScope(case_id=case_id, run_id=state.get("run_id"), stage=STAGE,
                            stage_attempt=state.get("triage_attempt"))


def _run_triage_before(call: dict) -> None:
    if _scope() is None:
        return
    supplied = bool(call.get("parsed_context"))
    if call.get("force"):
        emit(source="system", event_type="cache_bypassed", status="info",
             title="Triage result cache bypassed",
             detail="This run executes fresh model calls (explicit Run / Re-run)."
                    + (" Parsed context supplied to the agent." if supplied else
                       " No parsed context supplied to the agent."),
             metadata={"parsed_context_supplied": supplied})
    else:
        emit(source="system", event_type="agent_started", status="info",
             title="Triage agent started",
             detail="Result cache may be reused for identical incident content."
                    + (" Parsed context supplied." if supplied else " No parsed context supplied."),
             metadata={"parsed_context_supplied": supplied})


def _run_triage_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(result, dict):
        return
    if result.get("error"):
        emit(source="decision", event_type="stage_result", status="failed",
             title="Triage agent returned an error", detail=_str(result.get("error")))
        return
    ticket = result.get("ticket") or {}
    if result.get("cached"):
        emit(source="system", event_type="cache_hit", status="completed",
             title="Cached Triage result reused",
             detail="An identical incident fingerprint was found; no model calls were made.")
    classification = _str(ticket.get("classification"))
    risk = ticket.get("risk_rating") or {}
    overall = _str(risk.get("overall_risk"))
    response_time = _str(ticket.get("initial_response_time"))
    proposed = _str(scope.data.get("model_classification"))
    if classification and not result.get("cached"):
        note = ""
        if proposed and proposed.lower() != classification.lower():
            note = f" The model's own proposed value ({proposed}) was not used."
        emit(source="rule", event_type="classification_mapping", status="completed",
             title="Classification level mapped from overall risk",
             detail=(f"Overall risk {overall or '—'} → classification {classification} "
                     f"via the SOC classification table"
                     + (f"; initial response time {response_time}." if response_time else ".")
                     + note),
             metadata={"classification": classification, "overall_risk": overall,
                       "initial_response_time": response_time,
                       "model_proposed_classification": proposed or None})
        changes = []
        for key, label in (("mitre_tactic", "tactic"), ("mitre_technique", "technique")):
            raw = _str(scope.data.get(f"model_{key}"))
            final = _str(ticket.get(key))
            if raw and final and raw != final:
                changes.append(f"{label} '{raw}' → '{final}'")
        if changes:
            emit(source="rule", event_type="mitre_normalisation", status="completed",
                 title="MITRE ATT&CK mapping normalised to the canonical list",
                 detail="; ".join(changes))
    if ticket.get("unc") and not result.get("cached"):
        emit(source="system", event_type="ticket_created", status="completed",
             title=f"Triage ticket {ticket.get('unc')} recorded",
             detail="Ticket stored in the SOC ticket register.")
    ioc_count = ticket.get("matched_ioc_count")
    emit(source="decision", event_type="stage_result", status="completed",
         title=f"Triage result: {classification or '—'} classification",
         detail=" · ".join(p for p in (
             f"Overall risk {overall}" if overall else "",
             _str(ticket.get("incident_category")) if _str(ticket.get("incident_category")) not in ("", "—") else "",
             _str(ticket.get("mitre_technique")) if _str(ticket.get("mitre_technique")) not in ("", "Unknown") else "",
             f"{ioc_count} IOC(s) matched" if ioc_count is not None else "") if p),
         metadata={"details": details.blocks(details.fields([
             ("Classification", classification),
             ("Overall risk", overall),
             *[(label, risk.get(key)) for key, label in _LIKELIHOODS],
             ("Incident category", ticket.get("incident_category")),
             ("MITRE tactic", ticket.get("mitre_tactic")),
             ("MITRE technique", ticket.get("mitre_technique")),
             ("Initial response time", response_time),
             ("Matched IOCs", ioc_count),
             ("Ticket", ticket.get("unc")),
         ]))})


def _run_triage_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None:
        return
    emit(source="decision", event_type="stage_result", status="failed",
         title="Triage agent raised an error", detail=describe_exception(exc))


# ── TriageAgent LLM phases ─────────────────────────────────────────────────

def _phase_before(method: str):
    phase_key, label = _PHASES[method]

    def before(call: dict):
        scope = _scope()
        if scope is None:
            return None
        if method == "_run_cls":
            _emit_overall_risk_rule(scope, call.get("risk_level"))
        span = new_span_id()
        emit(source="ai", ai_content_kind="assessment", event_type="ai_phase",
             status="running", title=f"{label} started", span_id=span,
             metadata={"phase": phase_key})
        parent_token = context.set_parent_span(span)
        return {"span": span, "parent_token": parent_token, "start": time.monotonic()}

    return before


def _phase_cleanup(call: dict, token: Any) -> None:
    if token and token.get("parent_token") is not None:
        context.reset_parent_span(token["parent_token"])


def _emit_overall_risk_rule(scope: context.RunScope, risk_level: Any) -> None:
    if not risk_level:
        return
    model_dims = scope.data.get("model_likelihoods") or {}
    shown = " · ".join(f"{label.replace('Likelihood of ', '')} {model_dims[key]}"
                       for key, label in _LIKELIHOODS if model_dims.get(key))
    emit(source="rule", event_type="overall_risk", status="completed",
         title="Overall risk determined from the likelihood ratings",
         detail=(f"Overall risk {str(risk_level).upper()} = highest of the three likelihood ratings"
                 + (f" ({shown})" if shown else "") + ". Computed in code, not by the model."),
         metadata={"overall_risk": str(risk_level), "model_likelihoods": model_dims})


def _ioc_after(scope, span, elapsed_ms, result) -> None:
    per_category = result.get("per_category") or {}
    total = result.get("total_ioc_count")
    counts = []
    blocks = []
    for key, label in _IOC_CATEGORIES:
        cat = per_category.get(key) or {}
        names = cat.get("matched_ioc_names") or []
        counts.append(f"{label.lower()} {len(names)}")
        blocks.append(details.items(f"{label} — matched IOCs", names))
        blocks.append(details.text(f"{label} — model explanation", cat.get("reasoning")))
    warning = result.get("debug_note")
    blocks.append(details.text("Note", warning))
    emit(source="ai", ai_content_kind="explanation", event_type="ai_phase",
         status="warning" if warning else "completed",
         title="IOC checklist assessment completed",
         detail=f"{total if total is not None else '—'} IOC(s) matched ({', '.join(counts)})",
         span_id=span,
         metadata={"phase": "ioc_checklist", "total_ioc_count": total,
                   "duration_ms": elapsed_ms, "details": details.blocks(*blocks)})


def _risk_after(scope, span, elapsed_ms, result) -> None:
    likelihoods = {key: _str(result.get(key)) for key, _ in _LIKELIHOODS if _str(result.get(key))}
    scope.data["model_likelihoods"] = likelihoods
    rationale = _str(result.get("rationale"))
    missing = not result.get("overall_risk")
    emit(source="ai", ai_content_kind="explanation", event_type="ai_phase",
         status="warning" if missing else "completed",
         title="Risk rating assessment completed",
         detail=rationale or "The model returned no rationale.",
         span_id=span,
         metadata={"phase": "risk_rating", "duration_ms": elapsed_ms,
                   "model_likelihoods": likelihoods,
                   "details": details.blocks(
                       details.text("Model rationale", rationale),
                       details.fields([(label, likelihoods.get(key)) for key, label in _LIKELIHOODS]
                                      + [("Overall risk stated by the model", result.get("overall_risk"))],
                                      label="Ratings returned by the model"),
                   )})


def _cls_after(scope, span, elapsed_ms, result) -> None:
    for key in ("classification", "mitre_tactic", "mitre_technique"):
        scope.data[f"model_{key}"] = result.get(key)
    actions = result.get("recommended_actions") or []
    if isinstance(actions, str):
        actions = [actions]
    summary = _str(result.get("summary"))
    missing = not result.get("classification")
    emit(source="ai", ai_content_kind="explanation", event_type="ai_phase",
         status="warning" if missing else "completed",
         title="Classification assessment completed",
         detail=summary or "The model returned no summary.",
         span_id=span,
         metadata={"phase": "classification", "duration_ms": elapsed_ms,
                   "details": details.blocks(
                       details.text("Model summary", summary),
                       details.fields([
                           ("Incident category", result.get("incident_category")),
                           ("MITRE tactic (as returned)", result.get("mitre_tactic")),
                           ("MITRE technique (as returned)", result.get("mitre_technique")),
                           ("Classification proposed by the model", result.get("classification")),
                       ], label="Values returned by the model"),
                       details.items("Recommended actions", actions),
                       details.note("The classification level itself is derived in code from the "
                                    "overall risk; the model's proposed value is shown for transparency."),
                   )})


_PHASE_AFTER = {"_run_ioc": _ioc_after, "_run_risk": _risk_after, "_run_cls": _cls_after}


def _phase_after(method: str):
    def after(call: dict, token: Any, result: Any) -> None:
        scope = _scope()
        if scope is None or not token or not isinstance(result, dict):
            return
        elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
        _PHASE_AFTER[method](scope, token["span"], elapsed_ms, result)

    return after


def _phase_error(method: str):
    _, label = _PHASES[method]

    def error(call: dict, token: Any, exc: BaseException) -> None:
        if _scope() is None or not token:
            return
        emit(source="ai", ai_content_kind="assessment", event_type="ai_phase", status="failed",
             title=f"{label} failed", detail=describe_exception(exc), span_id=token["span"])

    return error


def _repair_before(call: dict):
    if _scope() is None:
        return None
    keys = call.get("required_keys") or []
    span = new_span_id()
    emit(source="ai", ai_content_kind="assessment", event_type="ai_repair", status="running",
         title="Model output lacked required fields — follow-up repair call issued",
         detail=f"Required fields: {', '.join(str(k) for k in keys)}" if keys else "",
         span_id=span, parent_span_id=context.current_parent_span())
    return {"span": span}


def _repair_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not token:
        return
    ok = isinstance(result, dict) and bool(result)
    emit(source="ai", ai_content_kind="assessment", event_type="ai_repair",
         status="completed" if ok else "warning",
         title="Repair call returned the required fields" if ok
         else "Repair call did not return usable fields",
         span_id=token["span"], parent_span_id=context.current_parent_span())


# ── Post-stage AI summary ──────────────────────────────────────────────────

_POST_STAGE_NOTE = "Generated after Triage completed. Not used in triage decisions."


def _summary_before(call: dict):
    if _scope() is None:
        return None
    span = new_span_id()
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="running",
         title="AI summary of the Triage result started", detail=_POST_STAGE_NOTE, span_id=span,
         metadata={"post_stage": True})
    return {"span": span, "start": time.monotonic()}


def _summary_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not token or not isinstance(result, dict):
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    summary = _str(result.get("ai_summary"))
    unavailable = summary.lower().startswith("ai summary unavailable")
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary",
         status="warning" if unavailable else "completed",
         title="AI summary unavailable" if unavailable else "AI summary generated",
         detail=summary, span_id=token["span"],
         metadata={"post_stage": True, "model": result.get("ai_summary_model"),
                   "duration_ms": elapsed_ms,
                   "details": details.blocks(
                       details.note(_POST_STAGE_NOTE),
                       details.text("Summary", summary),
                       details.fields([("Model", result.get("ai_summary_model")),
                                       ("Duration", details.format_duration_ms(elapsed_ms))]),
                   )})
    if _str(result.get("ai_thinking")):
        emit(source="system", event_type="thinking_narrative", status="info",
             title="Thinking-process narrative rendered from the Triage trace",
             detail="Deterministic rendering of the agent's own recorded trace — no AI call.")


def _summary_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="failed",
         title="AI summary failed", detail=describe_exception(exc), span_id=token["span"],
         metadata={"post_stage": True})


# ── Internal IOC correlation (tool) ────────────────────────────────────────

def _correlation_before(call: dict):
    if _scope() is None:
        return None
    span = new_span_id()
    emit(source="tool", event_type="ioc_correlation", status="running",
         title="Internal IOC correlation started",
         detail="Read-only search of local case history for the incident's indicators.",
         span_id=span)
    return {"span": span}


def _correlation_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not token or not isinstance(result, dict):
        return
    if not result.get("available"):
        emit(source="tool", event_type="ioc_correlation", status="warning",
             title="Internal IOC correlation unavailable",
             detail=_str(result.get("reason")) or "The correlation corpus could not be used.",
             span_id=token["span"])
        return
    stats = result.get("stats") or {}
    results = result.get("results") or []
    seen = [r for r in results if str(r.get("confidence") or "none").lower() != "none"]
    flags = [text for flag, text in ((stats.get("deadline_hit"), "time budget reached"),
                                     (stats.get("truncated"), "indicator list truncated")) if flag]
    emit(source="tool", event_type="ioc_correlation",
         status="warning" if flags else "completed",
         title="Internal IOC correlation completed",
         detail=(f"{stats.get('iocs_correlated', len(results))} indicator(s) checked · "
                 f"{len(seen)} with prior sightings · {stats.get('subnets_analysed', 0)} subnet(s) analysed"
                 + (f" ({'; '.join(flags)})" if flags else "")),
         span_id=token["span"],
         metadata={"details": details.blocks(details.fields([
             ("Indicators checked", stats.get("iocs_correlated")),
             ("With prior sightings", len(seen)),
             ("Subnets analysed", stats.get("subnets_analysed")),
             ("Duration", f"{stats.get('seconds')} s" if stats.get("seconds") is not None else None),
         ]), details.items("Indicators with prior sightings",
                           [f"{r.get('value')} — {str(r.get('confidence')).upper()} "
                            f"({r.get('raw_mentions', 0)} mention(s))" for r in seen[:10]]))})


def _correlation_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="tool", event_type="ioc_correlation", status="failed",
         title="Internal IOC correlation failed", detail=describe_exception(exc),
         span_id=token["span"])


# ── Approval policy (rule) ─────────────────────────────────────────────────

def _approval_policy_after(call: dict, token: Any, gate: Any) -> None:
    if _scope() is None or not isinstance(gate, dict):
        return
    emit(source="rule", event_type="approval_policy", status="completed",
         title="SOC analyst approval policy applied",
         detail=_str(gate.get("reason")),
         metadata={"approval_required": gate.get("approval_required")})
    nxt = _str(gate.get("next_stage_after_approval"))
    if nxt:
        emit(source="orchestration", event_type="routing", status="info",
             title="Next stage after approval determined",
             detail=f"Next stage after analyst approval: {_STAGE_NAMES.get(nxt, nxt)}",
             metadata={"next_stage": nxt})


# ── Analyst-initiated transitions (request threads, no worker scope) ───────

def _request_after(kind: str):
    def after(call: dict, token: Any, result: Any) -> None:
        if call.get("stage") != STAGE:
            return
        incident_id = str(call.get("incident_id"))
        attempt = _state(incident_id).get("triage_attempt")
        emit(source="orchestration", event_type="stage_requested", status="completed",
             origin="state_transition",
             title="Triage re-run requested" if kind == "rerun" else "Triage run requested",
             detail=f"Attempt {attempt or '—'} · stage set to Processing and a worker dispatched.",
             case_id=incident_id, run_id=call.get("run_id"), stage=STAGE, stage_attempt=attempt)

    return after


def _decision_after(decision: str):
    def after(call: dict, token: Any, result: Any) -> None:
        incident_id = str(call.get("incident_id"))
        state = _state(incident_id)
        attempt = state.get("triage_attempt")
        analyst = _str(call.get("approved_by") if decision == "approve" else call.get("rejected_by"))
        comment = _str(call.get("comments") if decision == "approve" else call.get("reason"))
        ids = {"case_id": incident_id, "run_id": call.get("run_id"), "stage": STAGE,
               "stage_attempt": attempt}
        emit(source="human", event_type="approval_decision", status="completed",
             origin="state_transition",
             title=f"Triage {'approved' if decision == 'approve' else 'rejected'} by {analyst or 'analyst'}",
             detail=comment or ("No comment provided." if decision == "approve" else ""),
             span_id=_approval_span(call.get("run_id"), attempt),
             metadata={"decision": decision, "analyst": analyst}, **ids)
        if decision == "approve" and state.get("threat_intel_status"):
            emit(source="orchestration", event_type="routing", status="info",
                 origin="state_transition", title="Threat Intelligence Enrichment unlocked",
                 detail=f"Threat Intelligence Enrichment status: {state.get('threat_intel_status')} "
                        "(it runs only when an analyst starts it).", **ids)

    return after


def _wrap_phase(patcher: Patcher, method: str, params: tuple[str, ...]) -> None:
    patcher.wrap(Target("agents.triage.soc_triage_agent", method, params, owner="TriageAgent"),
                 Hooks(before=_phase_before(method), after=_phase_after(method),
                       error=_phase_error(method), cleanup=_phase_cleanup))


def install(patcher: Patcher) -> None:
    engine = "workflow.engine"
    patcher.wrap(Target(engine, "run_triage_stage", ("incident_id", "run_id")),
                 Hooks(scope=_stage_scope, after=_stage_after, error=_stage_error))
    patcher.wrap(Target(engine, "claim_stage",
                        ("incident_id", "run_id", "stage", "status_column", "expect_status")),
                 Hooks(after=_claim_after, error=_claim_error))
    patcher.wrap(Target(engine, "complete_stage",
                        ("incident_id", "run_id", "worker_id", "stage", "result_column", "result",
                         "status_updates", "expected_stage_attempt")),
                 Hooks(after=_complete_after, error=_complete_error))
    patcher.wrap(Target(engine, "load_parsing_result_for_run", ("incident_id", "run_id")),
                 Hooks(after=_parsing_loaded))
    patcher.wrap(Target(engine, "load_raw_incident_for_run", ("incident_id", "run_id")),
                 Hooks(after=_raw_loaded))
    patcher.wrap(Target(engine, "run_triage", ("incident", "progress_fn", "parsed_context", "force")),
                 Hooks(scope=_run_triage_scope, before=_run_triage_before,
                       after=_run_triage_after, error=_run_triage_error))
    patcher.wrap(Target(engine, "generate_triage_ai_summary", ("triage_result", "model")),
                 Hooks(before=_summary_before, after=_summary_after, error=_summary_error))
    _wrap_phase(patcher, "_run_ioc", ("self", "incident", "parsed_context"))
    _wrap_phase(patcher, "_run_risk", ("self", "incident", "ioc_summary", "parsed_context"))
    _wrap_phase(patcher, "_run_cls", ("self", "incident", "risk_level", "ioc_summary", "parsed_context"))
    patcher.wrap(Target("agents.triage.soc_triage_agent", "_repair_json",
                        ("raw_text", "required_keys", "llm")),
                 Hooks(before=_repair_before, after=_repair_after))
    patcher.wrap(Target("agents.investigation.tools.ioc_correlation", "correlate_iocs",
                        ("incident", "triage_result", "incidents_db", "pipeline_db", "tickets_db",
                         "max_iocs", "sample_cap", "deadline_seconds")),
                 Hooks(before=_correlation_before, after=_correlation_after, error=_correlation_error))
    patcher.wrap(Target("workflow.validation", "mandatory_triage_approval",
                        ("incident_id", "triage_result")),
                 Hooks(after=_approval_policy_after))
    patcher.wrap(Target("workflow.state_store", "begin_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("start")))
    patcher.wrap(Target("workflow.state_store", "rerun_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("rerun")))
    patcher.wrap(Target("workflow.state_store", "approve_triage",
                        ("incident_id", "run_id", "approved_by", "comments")),
                 Hooks(after=_decision_after("approve")))
    patcher.wrap(Target("workflow.state_store", "reject_triage",
                        ("incident_id", "run_id", "rejected_by", "reason")),
                 Hooks(after=_decision_after("reject")))
