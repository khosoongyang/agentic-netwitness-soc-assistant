"""Reporting observability.

Reporting runs mostly OUT of process, and its agent is NOT streamed:

  in the Flask worker (observed directly, origin=wrapper/state_transition):
    stage claim, the shared Reporting workspace lock, the context the stage
    loaded, the hand-off files and their manifest, the hand-off manifest
    verification, the Reporting Agent subprocess (start, exit, duration),
    reading back final_report.json, DOCX/PDF export (a second subprocess),
    the candidate-manifest identity check, the post-stage summary, result
    persistence and the approval gate;

  inside the Reporting Agent subprocess (adapters/run_reporting.py ->
  agents/reporting_agent.py, run with captured output, never streamed):
    deterministic fact assembly, RAG status, AI narrative enhancement of the
    narrative sections (run in parallel by the agent), guardrail checks,
    fallbacks, validation, completeness scoring and Jinja2 rendering.

Nothing that happens inside the agent process is visible while it runs, so
the only live row for it is "Reporting Agent running" (the UI shows elapsed
time; there are no percentages and no invented steps). Everything the agent
did is reported AFTER it exits, from its own final_report.json, as
RESULT-DERIVED events (metadata.result_derived=True). Per-section AI
results are listed in the agent's own field order - never completion order,
which is not observable - and carry no timing.

Prompts, knowledge-base documents and report text are never emitted; file
locations are reported as relative names only.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .. import context, details
from ..emitter import emit
from ..events import new_span_id
from ..instrument import Hooks, Patcher, Target
from ..sanitize import describe_exception, sanitize_text

STAGE = "reporting"
_LOCK_NAME = "reporting_workspace"
_POST_STAGE_NOTE = "Generated after Reporting. Not used to construct or validate the report."
_RESULT_NOTE = ("Result-derived: read from the Reporting Agent's final_report.json after the agent process "
                "exited. Not observed while it happened.")
_SECTION_NOTE = ("Result-derived from llm_section_results after the Reporting Agent finished. Sections may be "
                 "enhanced in parallel inside the agent; their order and timing were not observable, so they "
                 "are listed in the agent's own field order with no per-section duration.")
_RAG_NOTE = ("This is the RAG status string recorded in the Reporting result. Retrieval itself is not observable "
             "from outside the agent process, and no knowledge-base content is shown.")
_SECTION_LABELS = {
    "executive_summary": "Executive summary",
    "technical_analysis": "Technical analysis",
    "business_impact_explanation": "Business impact explanation",
    "attack_narrative": "Attack narrative",
    "conclusion": "Conclusion",
    "analyst_friendly_explanation": "Analyst-friendly explanation",
    "soc_analyst_review_checklist": "SOC analyst review checklist",
}
_REPORT_LABELS = {
    "executive_summary": "Executive Summary",
    "technical_findings": "Technical Findings",
    "soc_analyst_review": "SOC Analyst Review",
    "soc_triage_review": "SOC Triage Review",
    "final_incident_report": "Final Incident Report",
}


def _scope() -> context.RunScope | None:
    scope = context.current_scope()
    return scope if scope is not None and scope.stage == STAGE else None


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _words(value: Any) -> str:
    return _str(value).replace("_", " ")


def _state(incident_id: str) -> dict:
    from workflow import state_store

    return state_store.get_state(str(incident_id)) or {}


def _approval_span(run_id: Any, attempt: Any) -> str:
    return f"approval:{run_id}:{STAGE}:{attempt or 1}"


def _derived(extra: dict | None = None) -> dict:
    return {"result_derived": True, **(extra or {})}


def _short_hash(value: Any) -> str | None:
    text = _str(value)
    return f"{text[:12]}…" if len(text) > 12 else (text or None)


def _accepted(state: str) -> bool:
    # llm_used, llm_used_after_*_repair, llm_retry_successful[_after_repair],
    # each optionally suffixed _with_warning (reporting/llm_narrative.py).
    return state.startswith("llm_used") or state.startswith("llm_retry_successful")


def _issues(values: Any, cap: int = 8) -> list[str]:
    return [sanitize_text(str(v), max_len=200) for v in (values or [])[:cap]]


# ── Stage entry and lifecycle ───────────────────────────────────────────────

def _stage_scope(call: dict) -> context.RunScope:
    return context.RunScope(case_id=str(call.get("incident_id")), run_id=call.get("run_id"), stage=STAGE)


def _stage_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _scope()
    if scope is None:
        return
    message = str(exc)
    if type(exc).__name__ in ("StageClaimError", "GlobalLockBusyError"):
        lock = scope.data.get("lock") or {}
        if "could not acquire the shared workspace" in message:
            title, detail = "Gave up waiting for Reporting capacity", sanitize_text(message, 300)
        elif "lock lost" in message:
            title, detail = ("Shared Reporting workspace lock lost — this run's result was discarded",
                             "The stage stays Processing and can be resumed.")
        else:
            title, detail = ("Reporting worker stopped without saving a result",
                             "The stage lease was not held by this worker (another worker owns it, or the run was superseded).")
        if lock.get("span") and not lock.get("acquired"):
            emit(source="orchestration", event_type="workspace_lock", status="failed",
                 title="Reporting capacity not acquired", span_id=lock["span"])
        emit(source="orchestration", event_type="worker_stopped", status="warning", title=title, detail=detail)
    else:
        emit(source="orchestration", event_type="worker_stopped", status="failed",
             title="Reporting worker raised an error", detail=describe_exception(exc))


def _claim_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    try:
        scope.stage_attempt = int(result[1])
    except Exception:
        pass
    emit(source="orchestration", event_type="stage_claimed", status="completed",
         origin="state_transition", title="Reporting stage claimed by a worker",
         detail=f"Attempt {scope.stage_attempt or '—'} · worker lease acquired")


def _claim_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_claimed", status="warning", origin="state_transition",
         title="Reporting stage could not be claimed", detail=describe_exception(exc))


def _lock_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or call.get("lock_name") != _LOCK_NAME:
        return
    lock = scope.data.setdefault("lock", {})
    lock["acquired"] = True
    if lock.get("span"):
        waited = details.format_duration_ms((time.monotonic() - lock["since"]) * 1000)
        emit(source="orchestration", event_type="workspace_lock", status="completed",
             origin="state_transition", title="Reporting capacity acquired",
             detail=f"Shared Reporting workspace acquired after waiting {waited} ({lock['attempts']} busy check(s)).",
             span_id=lock["span"])
    else:
        emit(source="orchestration", event_type="workspace_lock", status="completed",
             origin="state_transition", title="Reporting workspace acquired",
             detail="The shared Reporting workspace was free — no wait.")


def _lock_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _scope()
    if scope is None or call.get("lock_name") != _LOCK_NAME or type(exc).__name__ != "GlobalLockBusyError":
        return
    lock = scope.data.setdefault("lock", {})
    lock["attempts"] = lock.get("attempts", 0) + 1
    if not lock.get("span"):
        lock["span"] = new_span_id()
        lock["since"] = time.monotonic()
        emit(source="orchestration", event_type="workspace_lock", status="running",
             origin="state_transition", title="Waiting for Reporting capacity",
             detail="Another report is being generated in the shared Reporting workspace; only one runs at a time.",
             span_id=lock["span"])


# ── Context and hand-off ───────────────────────────────────────────────────

def _raw_incident_after(call: dict, token: Any, incident: Any) -> None:
    scope = _scope()
    if scope is None or scope.data.get("raw_reported"):
        return
    scope.data["raw_reported"] = True
    incident = incident if isinstance(incident, dict) else {}
    emit(source="system", event_type="context_loaded", status="completed" if incident else "warning",
         title="Loaded raw incident" if incident else "Raw incident artifact unavailable",
         detail=_str(incident.get("title") or incident.get("name")) if incident
         else "The hand-off continues with an empty incident record.")


def _artifact_before(call: dict):
    """The stage persists exactly the context it loaded from workflow state as
    reporting_handoff.json; report what that payload contained."""
    scope = _scope()
    if scope is None or call.get("artifact_type") != "reporting_handoff":
        return None
    payload = call.get("payload") or {}
    triage = payload.get("triage_result") or {}
    ticket = triage.get("ticket") or {}
    inv = payload.get("investigation_result") or {}
    ti = payload.get("threat_intel_result") or {}
    emit(source="system", event_type="context_loaded", status="completed" if ticket else "warning",
         title="Loaded Triage result" if ticket else "No Triage result available",
         detail=" · ".join(p for p in (f"classification {ticket.get('classification')}" if ticket.get("classification") else "",
                                        f"ticket {ticket.get('unc')}" if ticket.get("unc") else "") if p))
    inv_ok = bool(inv) and inv.get("status") != "failed"
    emit(source="system", event_type="context_loaded", status="completed" if inv_ok else "warning",
         title="Loaded Investigation result" if inv_ok else "No usable Investigation result available",
         detail=" · ".join(p for p in (f"severity {inv.get('severity')}" if inv.get("severity") else "",
                                        f"confidence {inv.get('confidence')}" if inv.get("confidence") else "",
                                        _words(inv.get("status")) if inv.get("status") else "") if p)
         if inv else "Reporting will record the Investigation as skipped or missing.")
    ti_ok = bool(ti.get("status")) and ti.get("status") != "failed"
    emit(source="system", event_type="context_loaded", status="completed" if ti_ok else "warning",
         title="Loaded Threat Intelligence result" if ti_ok else "No usable Threat Intelligence result available",
         detail=(f"enrichment risk {ti.get('enrichment_risk_level')} (score {ti.get('enrichment_risk_score')})"
                 if ti.get("enrichment_risk_level") else ""))
    return None


def _handoff_after(call: dict, token: Any, ticket_id: Any) -> None:
    scope = _scope()
    if scope is None:
        return
    scope.data["ticket_id"] = _str(ticket_id)
    files: list[str] = []
    parsing_included = None
    approvals = None
    try:
        from workflow import engine

        attempt_dir = engine.reporting_attempt_dir(call.get("incident_id"), call.get("run_id"),
                                                   call.get("reporting_stage_attempt"))
        manifest = json.loads((attempt_dir / "inputs" / "handoff_manifest.json").read_text(encoding="utf-8"))
        files = sorted(str(rel).replace("\\", "/") for rel in (manifest.get("files") or {}))
        scope.data["handoff_manifest"] = {"files": len(files), "incident_id": manifest.get("incident_id"),
                                          "run_id": manifest.get("run_id"),
                                          "attempt": manifest.get("reporting_stage_attempt")}
        parsing_included = (attempt_dir / "inputs" / "processed_alert.json").exists()
        history = json.loads((attempt_dir / "inputs" / "approval_history.json").read_text(encoding="utf-8"))
        approvals = len(history) if isinstance(history, list) else None
    except Exception:
        pass
    emit(source="system", event_type="handoff", status="completed",
         title="Reporting hand-off written",
         detail=" · ".join(p for p in (f"ticket {ticket_id}" if ticket_id else "",
                                        f"{len(files)} input file(s) recorded in the hand-off manifest" if files else "") if p),
         metadata={"details": details.blocks(
             details.fields([
                 ("Investigation result included", "yes" if call.get("investigation_result") is not None
                  else "no — recorded as skipped"),
                 ("Threat Intelligence result included", "yes" if call.get("threat_intel_result") is not None else "no"),
                 ("Parsing result (processed_alert.json) included",
                  None if parsing_included is None else ("yes" if parsing_included
                                                         else "no — not found for this run")),
                 ("Approval decisions included", approvals),
             ]),
             details.items("Files in the hand-off manifest (SHA-256 + size recorded per file)", files),
         )})
    if parsing_included is False:
        emit(source="system", event_type="handoff", status="warning",
             title="Parsing result not included in the hand-off",
             detail="processed_alert.json was not available for this run; the Reporting Agent decides how to "
                    "proceed without it.")


def _handoff_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None:
        return
    emit(source="system", event_type="handoff", status="failed", title="Reporting hand-off failed",
         detail=describe_exception(exc))


# ── Reporting Agent run, result read-back, export ───────────────────────────

def _run_reporting_before(call: dict):
    scope = _scope()
    if scope is None:
        return None
    # run_reporting() is reached only after the stage re-hashed every hand-off
    # file against handoff_manifest.json (any mismatch raises before this).
    manifest = scope.data.get("handoff_manifest") or {}
    emit(source="rule", event_type="handoff_verification", status="completed",
         title="Hand-off manifest verified",
         detail=(f"{manifest.get('files')} file(s) re-hashed (SHA-256 and size) and identity matched before the "
                 "Reporting Agent was launched." if manifest.get("files") is not None
                 else "Every hand-off file was re-hashed and the identity matched before the Reporting Agent was launched."),
         metadata={"details": details.blocks(details.fields([
             ("Incident", manifest.get("incident_id")),
             ("Reporting attempt", manifest.get("attempt")),
             ("Check", "incident/run/attempt identity · per-file SHA-256 · per-file size · path inside the attempt folder"),
         ]))})
    scope.data["result_read"] = False
    return {"start": time.monotonic()}


def _subprocess_before(call: dict):
    scope = _scope()
    if scope is None:
        return None
    cmd = call.get("cmd") or []
    script = Path(str(cmd[-1])).name if cmd else ""
    if script != "run_reporting.py":
        return None
    env = call.get("extra_env") or {}
    span = new_span_id()
    scope.data["agent_span"] = span
    emit(source="system", event_type="agent_run", status="running", title="Reporting Agent running",
         detail="Separate process (adapters/run_reporting.py → agents/reporting_agent.py). Its internal progress "
                "is not streamed; what it did is shown when it finishes.",
         span_id=span,
         metadata={"details": details.blocks(
             details.fields([
                 ("AI narrative enhancement requested", "yes" if env.get("REPORTING_USE_LLM") == "true" else "no"),
                 ("Provider", env.get("REPORTING_LLM_PROVIDER")),
                 ("Model", env.get("REPORTING_LLM_MODEL")),
                 ("Parallel narrative sections (max)", env.get("REPORTING_LLM_PARALLEL")),
                 ("Quality retry policy", _words(env.get("REPORTING_QUALITY_RETRY"))),
                 ("Temperature", env.get("REPORTING_LLM_TEMPERATURE")),
                 ("Timeout", f"{call.get('timeout')} s" if call.get("timeout") else None),
             ], label="Settings passed to the agent process"),
             details.note("Settings as handed to the subprocess; the agent can still fall back to deterministic text "
                          "(for example when no usable API key is configured)."))})
    return {"span": span, "start": time.monotonic()}


def _subprocess_after(call: dict, token: Any, run: Any) -> None:
    scope = _scope()
    if scope is None or not token or not isinstance(run, dict):
        return
    elapsed = details.format_duration_ms((time.monotonic() - token["start"]) * 1000)
    timed_out = run.get("status") == "timeout"
    ok = bool(run.get("success"))
    stderr_tail = [line for line in (_str(run.get("stderr"))).splitlines() if line.strip()]
    scope.data["agent_exit"] = {"ok": ok, "error": stderr_tail[-1] if stderr_tail else ""}
    emit(source="system", event_type="agent_run", status="completed" if ok else "failed",
         title=("Reporting Agent finished" if ok else
                "Reporting Agent timed out" if timed_out else "Reporting Agent exited with an error"),
         detail=" · ".join(p for p in (f"exit code {run.get('returncode')}" if run.get("returncode") is not None else "",
                                        elapsed) if p),
         span_id=token["span"],
         metadata={"details": details.blocks(
             details.text("Last error line (sanitised)",
                          sanitize_text(stderr_tail[-1], max_len=300) if stderr_tail and not ok else None))})


def _subprocess_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="system", event_type="agent_run", status="failed", title="Reporting Agent could not be run",
         detail=describe_exception(exc), span_id=token["span"])


def _read_json_after(call: dict, token: Any, final: Any) -> None:
    scope = _scope()
    if scope is None or scope.data.get("result_read") is not False:
        return
    try:
        if Path(str(call.get("path"))).name != "final_report.json":
            return
    except Exception:
        return
    scope.data["result_read"] = True
    if not isinstance(final, dict) or not final:
        emit(source="system", event_type="agent_result", status="failed",
             title="No final_report.json produced by the Reporting Agent",
             detail="Reporting cannot continue without the agent's result.")
        return
    try:
        _emit_result_derived(scope, final)
    except Exception:
        pass


def _emit_result_derived(scope: context.RunScope, final: dict) -> None:
    status = _str(final.get("status"))
    scope.data["agent_status"] = status
    emit(source="system", event_type="agent_result",
         status={"completed": "completed", "completed_with_warnings": "warning"}.get(status, "failed"),
         title=("Reporting Agent result read" if status == "completed" else
                "Reporting Agent result read — completed with warnings" if status == "completed_with_warnings"
                else "Reporting Agent reported a failure"),
         detail=" · ".join(p for p in (_str(final.get("report_status")), f"mode {_words(final.get('reporting_mode'))}"
                                        if final.get("reporting_mode") else "") if p),
         metadata=_derived({"details": details.blocks(
             details.text("Error summary", sanitize_text(final.get("error_summary"), 400) if status == "failed" else None),
             details.note(_RESULT_NOTE))}))
    if status == "failed":
        return
    if "real_reporting_result_path" not in final:
        emit(source="system", event_type="fallback", status="warning",
             title="Result reconstructed from report artefacts",
             detail="The agent's own reporting_result.json was not found; the adapter built the result from the "
                    "report files it could find. AI, validation and completeness details are not recorded.",
             metadata=_derived({"fallback": True}))
        return

    checks = final.get("quality_checks") or {}
    emit(source="system", event_type="deterministic_facts", status="completed",
         title="Deterministic report facts assembled",
         detail=_words(final.get("report_generation_mode")) or "Facts built from the hand-off inputs",
         metadata=_derived({"details": details.blocks(
             details.fields([
                 ("Generation mode", _words(final.get("report_generation_mode"))),
                 ("Fields recovered from earlier stage outputs", len(final.get("recovered_fields") or [])),
                 ("Triage result available", checks.get("triage_result_available")),
                 ("Investigation result available", checks.get("investigation_result_available")),
                 ("Threat Intelligence result available", checks.get("threat_intelligence_result_available")),
                 ("Fallback logic used for facts", checks.get("fallback_logic_used")),
             ]),
             details.items("Recovered fields", [f"{f.get('field')} — from {f.get('recovered_from')}"
                                                for f in (final.get("recovered_fields") or [])[:12]
                                                if isinstance(f, dict)]),
             details.note(_RESULT_NOTE))}))

    if final.get("rag_status") or final.get("rag_used") is not None:
        emit(source="system", event_type="rag_status", status="info",
             title=f"RAG status recorded: {_str(final.get('rag_status')) or 'not recorded'}",
             detail=f"rag_used = {final.get('rag_used')!s}",
             metadata=_derived({"details": details.blocks(details.note(_RAG_NOTE))}))

    _emit_narrative(final)
    _emit_validation(final, checks)

    reports = final.get("generated_reports") or {}
    names = [_REPORT_LABELS.get(k, _words(k)) for k in reports
             if not k.endswith("_structured") and k not in ("final_report_text", "report_manifest")]
    if names:
        emit(source="system", event_type="templates_rendered", status="completed",
             title=f"{len(names)} report document(s) rendered from Jinja2 templates",
             detail=", ".join(names),
             metadata=_derived({"details": details.blocks(
                 details.items("Rendered reports", names),
                 details.fields([("Structured (JSON) variants", sum(1 for k in reports if k.endswith("_structured")) or None),
                                 ("Plain-text final report", "yes" if reports.get("final_report_text") else None)]),
                 details.note("Deterministic template rendering inside the agent process; " + _RESULT_NOTE))}))


def _emit_narrative(final: dict) -> None:
    sections = final.get("llm_section_results") or {}
    llm_status = _str(final.get("llm_status"))
    cache = _str(final.get("llm_cache_status"))
    if llm_status == "llm_disabled_deterministic_generation" or (sections and all(
            (v or {}).get("status") == "not_used" for v in sections.values())):
        emit(source="system", event_type="fallback", status="info",
             title="AI narrative enhancement disabled — deterministic narrative used",
             detail="No model calls were made for the report narrative.",
             metadata=_derived({"fallback": True}))
        return
    if not sections:
        return
    span = new_span_id()
    counts: dict[str, int] = {}
    for result in sections.values():
        key = _str((result or {}).get("status")) or "not recorded"
        counts[key] = counts.get(key, 0) + 1
    accepted = sum(n for k, n in counts.items() if _accepted(k))
    fallback = sum(n for k, n in counts.items() if k.startswith("fallback_used"))
    warned = sum(n for k, n in counts.items() if _accepted(k) and k.endswith("_with_warning"))
    emit(source="ai", ai_content_kind="explanation", event_type="narrative_enhancement",
         status="warning" if fallback or warned or cache == "cached_report_used" else "completed",
         title="AI narrative enhancement results",
         detail=f"{accepted} of {len(sections)} section(s) used AI-enhanced text"
                + (f" · {fallback} kept deterministic text" if fallback else "")
                + (f" · {warned} accepted with warnings" if warned else ""),
         span_id=span,
         metadata=_derived({"group": "AI narrative enhancement (result-derived)", "details": details.blocks(
             details.fields([
                 ("Overall status", _words(llm_status)),
                 ("Quality status", _words(final.get("llm_quality_status"))),
                 ("Provider", final.get("llm_provider")),
                 ("Model", final.get("llm_model")),
                 ("Model attempts (all sections)", final.get("llm_attempt_count")),
                 ("Narrative cache", _words(cache)),
                 ("Enhancement score", f"{final.get('llm_enhancement_score')}/100"
                  if final.get("llm_enhancement_score") is not None else None),
             ]),
             details.items("Section outcomes", [f"{_SECTION_LABELS.get(k, _words(k))}: {_words((v or {}).get('status'))}"
                                                for k, v in sections.items()]),
             details.items("Quality issues recorded", _issues(final.get("llm_quality_issues"))),
             details.note(_SECTION_NOTE))}))
    for key, result in sections.items():
        result = result or {}
        state = _str(result.get("status"))
        label = _SECTION_LABELS.get(key, _words(key))
        repairs = result.get("repair_actions") or []
        blocks = details.blocks(
            details.items("Guardrail failures", _issues(result.get("hard_fail_issues"))),
            details.items("Soft warnings", _issues(result.get("soft_warnings"))),
            details.items("Deterministic repairs applied", _issues(repairs)),
            details.fields([("Quality retry attempted", "yes" if result.get("retry_attempted") else None)]))
        common = {"span_id": new_span_id(), "parent_span_id": span,
                  "metadata": _derived({"section": key, "section_status": state, "details": blocks})}
        if state.startswith("fallback_used"):
            emit(source="system", event_type="narrative_section", status="warning",
                 title=f"{label}: deterministic text kept (fallback)",
                 detail="AI text was rejected by a guardrail or the model call failed"
                        + (" after a quality retry" if state == "fallback_used_after_retry_failed" else ""),
                 **{**common, "metadata": {**common["metadata"], "fallback": True}})
        elif state == "deterministic_locked":
            emit(source="rule", event_type="narrative_section", status="info",
                 title=f"{label}: deterministic text (locked — no model call)", **common)
        elif state == "not_used":
            emit(source="system", event_type="narrative_section", status="info",
                 title=f"{label}: deterministic text (AI not used)", **common)
        elif _accepted(state):
            warning = state.endswith("_with_warning")
            emit(source="ai", ai_content_kind="explanation", event_type="narrative_section",
                 status="warning" if warning else "completed",
                 title=f"{label}: AI-enhanced text accepted"
                       + (" after a retry" if state.startswith("llm_retry_successful") else "")
                       + (" after deterministic repair" if "repair" in state else "")
                       + (" with warnings" if warning else ""),
                 **common)
        else:
            emit(source="system", event_type="narrative_section", status="info",
                 title=f"{label}: {_words(state) or 'status not recorded'}", **common)
    if cache == "cached_report_used":
        emit(source="system", event_type="fallback", status="warning",
             title="Earlier cached AI narrative reused",
             detail="The model results for this run were not usable; a previously accepted narrative for the same "
                    "input context was reused.", metadata=_derived({"fallback": True}))
    elif fallback and fallback == len(sections):
        emit(source="system", event_type="fallback", status="warning",
             title="All narrative sections kept deterministic text",
             detail=_words(final.get("llm_quality_status")), metadata=_derived({"fallback": True}))


def _emit_validation(final: dict, checks: dict) -> None:
    missing = final.get("missing_required_fields") or []
    warnings = final.get("warnings") or []
    consistency = _str(final.get("data_consistency_status"))
    issues = (final.get("data_consistency") or {}).get("issues") or []
    conflicts = [label for key, label in (("conflicting_severity_values_detected", "Conflicting severity values"),
                                           ("conflicting_confidence_values_detected", "Conflicting confidence values"),
                                           ("stale_context_detected", "Stale context"))
                 if _str(checks.get(key)) and _str(checks.get(key)).lower() != "not detected"]
    problem = bool(missing or conflicts or (consistency and consistency != "passed"))
    score = final.get("report_completeness_score")
    emit(source="rule", event_type="report_validation", status="warning" if problem or warnings else "completed",
         title=f"Report validation: {_str(final.get('validation_status')) or 'not recorded'}",
         detail=" · ".join(p for p in (
             f"{len(missing)} required field(s) missing" if missing else "no required fields missing",
             f"data consistency {_words(consistency)}" if consistency else "",
             f"completeness {score}/100" if score is not None
             else f"completeness {_words(final.get('report_completeness_status')) or 'not recorded'}",
             f"{len(warnings)} warning(s)" if warnings else "") if p),
         metadata=_derived({"details": details.blocks(
             details.fields([
                 ("Validation status", final.get("validation_status")),
                 ("Completeness score", f"{score}/100" if score is not None else "not recorded"),
                 ("Completeness status", _words(final.get("report_completeness_status"))),
                 ("Data consistency", _words(consistency)),
                 ("Conflicts detected", ", ".join(conflicts) if conflicts else "none"),
                 ("Fields still unavailable from source telemetry", checks.get("fields_still_unavailable_from_source_telemetry")),
             ]),
             details.items("Missing required fields", _issues(missing, 20)),
             details.items("Data consistency issues", [sanitize_text(f"{i.get('field')}: {i.get('issue')}", 200)
                                                       for i in issues[:10] if isinstance(i, dict)]),
             details.items("Warnings", _issues(warnings, 10)),
             details.note("Deterministic checks inside the agent process; " + _RESULT_NOTE))}))


def _export_before(call: dict):
    scope = _scope()
    if scope is None:
        return None
    span = new_span_id()
    emit(source="system", event_type="document_export", status="running",
         title="Exporting report documents (DOCX/PDF)",
         detail="Separate process (adapters/export_documents.py): combined and per-section documents, then the "
                "candidate manifest.", span_id=span)
    return {"span": span, "start": time.monotonic()}


def _export_after(call: dict, token: Any, out: Any) -> None:
    scope = _scope()
    if scope is None or not token or not isinstance(out, dict):
        return
    elapsed = details.format_duration_ms((time.monotonic() - token["start"]) * 1000)
    if set(out) == {"error"}:
        emit(source="system", event_type="document_export", status="failed",
             title="Document export produced no result", detail=sanitize_text(out.get("error"), 300),
             span_id=token["span"])
        return
    formats = [("Combined report (DOCX)", "docx"), ("Combined report (PDF)", "pdf")]
    for key in ("executive_summary", "technical_findings", "soc_analyst_review"):
        formats += [(f"{_REPORT_LABELS[key]} (DOCX)", f"{key}_docx"), (f"{_REPORT_LABELS[key]} (PDF)", f"{key}_pdf")]
    rows, made, errors = [], 0, []
    for label, key in formats:
        if out.get(key):
            made += 1
            rows.append((label, f"generated · {Path(str(out[key])).name}"))
        elif out.get(f"{key}_error"):
            errors.append(label)
            rows.append((label, f"not generated — {sanitize_text(out[f'{key}_error'], 160)}"))
    published = bool(out.get("candidate_manifest_path"))
    manifest_error = out.get("candidate_manifest_error")
    failed_all = not out.get("docx") and not out.get("pdf")
    emit(source="system", event_type="document_export",
         status="failed" if failed_all else ("warning" if errors or manifest_error else "completed"),
         title="Report documents exported" if not failed_all else "Report document export failed",
         detail=f"{made} document(s) generated" + (f" · {len(errors)} not generated" if errors else "")
                + (" · candidate manifest published" if published else " · no candidate manifest") + f" · {elapsed}",
         span_id=token["span"],
         metadata={"details": details.blocks(
             details.fields(rows, label="Documents"),
             details.fields([("Report set", out.get("report_set_id")),
                             ("Candidate manifest SHA-256", _short_hash(out.get("candidate_manifest_sha256")))]),
             details.text("Candidate manifest error", sanitize_text(manifest_error, 300) if manifest_error else None),
             details.text("Report-set registration note",
                          sanitize_text(out.get("report_set_registration_note"), 300)
                          if out.get("report_set_registration_note") else None))})
    _report_candidate_manifest(scope, out)


def _report_candidate_manifest(scope: context.RunScope, out: dict) -> None:
    path = out.get("candidate_manifest_path")
    if not path:
        scope.data["candidate"] = {"readable": False}
        return
    try:
        manifest = json.loads(Path(str(path)).read_text(encoding="utf-8"))
    except Exception:
        scope.data["candidate"] = {"readable": False}
        return
    scope.data["candidate"] = {"readable": True, "incident_id": manifest.get("incident_id"),
                               "run_id": manifest.get("run_id"),
                               "attempt": manifest.get("reporting_stage_attempt"),
                               "report_set_id": manifest.get("report_set_id"),
                               "sha256": manifest.get("candidate_manifest_sha256"),
                               "reports": len(manifest.get("reports") or [])}
    reports = [r for r in manifest.get("reports") or [] if isinstance(r, dict)]
    bad = [r for r in reports if (r.get("validation") or {}).get("status") not in ("valid", None)
           or (r.get("validation") or {}).get("errors")]
    warned = sum(len((r.get("validation") or {}).get("warnings") or []) for r in reports)
    emit(source="rule", event_type="document_validation", status="warning" if bad or warned else "completed",
         title=f"Exported documents validated: {len(reports) - len(bad)} of {len(reports)} valid",
         detail=f"{warned} validation warning(s)" if warned else "No validation errors or warnings",
         metadata={"details": details.blocks(
             details.items("Per-report validation (from the candidate manifest)", [
                 f"{r.get('title') or _words(r.get('report_type'))}: {(r.get('validation') or {}).get('status')}"
                 f" · template {r.get('template')}"
                 + (f" · {len((r.get('validation') or {}).get('warnings') or [])} warning(s)"
                    if (r.get("validation") or {}).get("warnings") else "")
                 + (f" · {len((r.get('validation') or {}).get('errors') or [])} error(s)"
                    if (r.get("validation") or {}).get("errors") else "")
                 for r in reports]),
             details.note("Each report's DOCX, PDF and structured content is recorded with its SHA-256 and size."))})


def _export_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="system", event_type="document_export", status="failed", title="Document export raised an error",
         detail=describe_exception(exc), span_id=token["span"])


def _run_reporting_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(result, dict):
        return
    expected = scope.data.get("ticket_id")
    actual = _str(result.get("ticket_id") or (result.get("triage") or {}).get("ticket_id"))
    if expected and actual:
        emit(source="rule", event_type="ticket_identity", status="completed" if actual == expected else "warning",
             title="Report ticket ID matches the hand-off" if actual == expected
             else "Report ticket ID differs from the hand-off",
             detail=f"ticket {actual}" if actual == expected
             else f"report {actual} vs hand-off {expected} (logged as a warning by the stage; not blocking)")


def _run_reporting_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _scope()
    if scope is None:
        return
    span = scope.data.get("agent_span")
    emit(source="system", event_type="agent_run", status="failed", title="Reporting run raised an error",
         detail=describe_exception(exc), span_id=span)


# ── Identity, decision, post-stage summary ─────────────────────────────────

def _emit_identity_and_decision(scope: context.RunScope, result: dict | None) -> None:
    if scope.data.get("decided"):
        return
    scope.data["decided"] = True
    cand = scope.data.get("candidate") or {}
    if cand.get("readable"):
        emit(source="rule", event_type="manifest_identity", status="completed",
             title="Candidate manifest identity verified",
             detail="Incident, run and Reporting attempt in the candidate manifest match this run.",
             metadata={"details": details.blocks(details.fields([
                 ("Reporting attempt", cand.get("attempt")),
                 ("Report set", cand.get("report_set_id")),
                 ("Manifest SHA-256", _short_hash(cand.get("sha256"))),
                 ("Reports in the set", cand.get("reports")),
             ]))})
    else:
        emit(source="rule", event_type="manifest_identity", status="warning",
             title="Candidate manifest identity check skipped",
             detail="No readable candidate manifest was published, so the stage could not check its identity. "
                    "Approval re-verifies the candidate set and will be blocked if none exists.")
    result = result or {}
    status = _str(result.get("status") or scope.data.get("agent_status"))
    warn = status == "completed_with_warnings" or not cand.get("readable")
    emit(source="decision", event_type="stage_result", status="warning" if warn else "completed",
         title="Reporting completed" + (" with warnings" if warn else ""),
         detail=" · ".join(p for p in (_str(result.get("report_status")),
                                        _str(result.get("validation_status")),
                                        f"report set {cand.get('report_set_id')}" if cand.get("report_set_id") else "") if p),
         metadata={"details": details.blocks(details.fields([
             ("Status", _words(status)),
             ("Report status", result.get("report_status")),
             ("Validation", result.get("validation_status")),
             ("AI narrative", _words(result.get("llm_status"))),
             ("Next step", "SOC analyst review and approval of the candidate report set"),
         ]))})


def _summary_before(call: dict):
    scope = _scope()
    if scope is None or _str(call.get("stage")) != "Reporting":
        return None
    try:
        _emit_identity_and_decision(scope, call.get("stage_result"))
    except Exception:
        pass
    span = new_span_id()
    scope.data["summary_span"] = span
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="running",
         title="Post-stage AI summary started", detail=_POST_STAGE_NOTE, span_id=span,
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
         title="Post-stage AI summary unavailable" if unavailable else "Post-stage AI summary generated",
         detail=summary, span_id=token["span"],
         metadata={"post_stage": True, "model": result.get("ai_summary_model"), "duration_ms": elapsed_ms,
                   "details": details.blocks(details.note(_POST_STAGE_NOTE), details.text("Summary", summary),
                                             details.fields([("Model", result.get("ai_summary_model")),
                                                             ("Duration", details.format_duration_ms(elapsed_ms))]))})


def _summary_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="failed",
         title="Post-stage AI summary failed", detail=describe_exception(exc), span_id=token["span"],
         metadata={"post_stage": True})


def _summary_cleanup(call: dict, token: Any) -> None:
    scope = _scope()
    if scope is not None:
        scope.data.pop("summary_span", None)


def _model_request_before(call: dict):
    scope = _scope()
    if scope is None or not scope.data.get("summary_span"):
        return None
    model = _str(call.get("model")) or "default (OPENAI_MODEL)"
    span = new_span_id()
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="running",
         title="Model request sent", detail=f"Model: {model}", span_id=span,
         parent_span_id=scope.data["summary_span"], metadata={"model": model})
    return {"span": span, "model": model, "parent": scope.data["summary_span"], "start": time.monotonic()}


def _model_request_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not token:
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="completed",
         title="Model response received",
         detail=f"Model: {token['model']} · {details.format_duration_ms(elapsed_ms)}",
         span_id=token["span"], parent_span_id=token["parent"],
         metadata={"model": token["model"], "duration_ms": elapsed_ms})


def _model_request_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="failed",
         title="Model request failed", detail=describe_exception(exc),
         span_id=token["span"], parent_span_id=token["parent"], metadata={"model": token["model"]})


# ── Result persistence ─────────────────────────────────────────────────────

def _complete_after(call: dict, token: Any, ok: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    updates = call.get("status_updates") or {}
    status = updates.get("reporting_status")
    result = call.get("result") if isinstance(call.get("result"), dict) else {}
    if status == "Awaiting Approval":
        try:
            _emit_identity_and_decision(scope, result)
        except Exception:
            pass
    elif status == "Failed":
        error = _str(result.get("error") or result.get("error_summary"))
        if error.startswith("reporting hand-off verification failed"):
            emit(source="rule", event_type="handoff_verification", status="failed",
                 title="Hand-off manifest verification failed",
                 detail=sanitize_text(error.split(":", 1)[-1], 300) + " — the Reporting Agent was not launched.")
        elif error == "candidate manifest identity mismatch":
            cand = scope.data.get("candidate") or {}
            emit(source="rule", event_type="manifest_identity", status="failed",
                 title="Candidate manifest identity mismatch",
                 detail=f"Manifest records attempt {cand.get('attempt')!s}; this run is attempt "
                        f"{scope.stage_attempt!s}. The attempt is treated as a generation failure.")
        if not scope.data.get("decided"):
            scope.data["decided"] = True
            emit(source="decision", event_type="stage_result", status="failed", title="Reporting failed",
                 detail=sanitize_text(error, 400) if error else "The Reporting Agent did not produce a usable result.")
    if not ok:
        emit(source="orchestration", event_type="stage_settled", status="warning", origin="state_transition",
             title="Reporting result was not saved",
             detail="The stage lease was reassigned before the result could be written.")
        return
    if status == "Awaiting Approval":
        emit(source="orchestration", event_type="stage_settled", status="completed", origin="state_transition",
             title="Reporting result saved", detail="Workflow paused at the SOC analyst approval gate.",
             metadata={"status_updates": updates})
        emit(source="human", event_type="approval_required", status="waiting", origin="state_transition",
             title="SOC analyst approval required",
             detail="Waiting for an analyst to approve or reject the candidate report set.",
             span_id=_approval_span(scope.run_id, scope.stage_attempt))
    elif status == "Failed":
        emit(source="orchestration", event_type="stage_settled", status="failed", origin="state_transition",
             title="Reporting marked Failed", detail="Re-run Reporting to generate a new candidate report set.",
             metadata={"status_updates": updates})


def _complete_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_settled", status="failed", origin="state_transition",
         title="Saving the Reporting result failed", detail=describe_exception(exc))


# ── Analyst actions ────────────────────────────────────────────────────────

def _request_after(kind: str):
    def after(call: dict, token: Any, result: Any) -> None:
        if call.get("stage") != STAGE:
            return
        incident_id = str(call.get("incident_id"))
        attempt = _state(incident_id).get("reporting_attempt")
        emit(source="orchestration", event_type="stage_requested", status="completed", origin="state_transition",
             title="Reporting re-run requested" if kind == "rerun" else "Reporting run requested",
             detail=f"Attempt {attempt or '—'} · stage set to Processing and a worker dispatched.",
             case_id=incident_id, run_id=call.get("run_id"), stage=STAGE, stage_attempt=attempt)

    return after


def _ids(incident_id: str, run_id: Any, attempt: Any) -> dict:
    return {"case_id": incident_id, "run_id": run_id, "stage": STAGE, "stage_attempt": attempt}


def _commit_before(call: dict):
    # commit_reporting_approval() is called only after
    # approve_reporting_candidate() fully re-verified the candidate set.
    incident_id = str(call.get("incident_id"))
    attempt = call.get("expected_reporting_attempt")
    meta = call.get("metadata") or {}
    emit(source="rule", event_type="approval_verification", status="completed", origin="state_transition",
         title="Candidate report set re-verified for approval",
         detail="Identity, every file's SHA-256, the manifest's own hash and blocking validation errors were "
                "re-checked before committing the decision.",
         metadata={"details": details.blocks(details.fields([
             ("Report set", meta.get("report_set_id")),
             ("Manifest SHA-256", _short_hash(meta.get("candidate_manifest_sha256"))),
             ("Validation", meta.get("validation_status")),
             ("Validation warnings", meta.get("warning_count")),
         ]))}, **_ids(incident_id, call.get("run_id"), attempt))
    return None


def _commit_after(call: dict, token: Any, result: Any) -> None:
    incident_id = str(call.get("incident_id"))
    attempt = call.get("expected_reporting_attempt")
    analyst = _str(call.get("approved_by"))
    ids = _ids(incident_id, call.get("run_id"), attempt)
    emit(source="human", event_type="approval_decision", status="completed", origin="state_transition",
         title=f"Reporting approved by {analyst or 'analyst'}",
         detail=_str(call.get("comments")) or "No comment provided.",
         span_id=_approval_span(call.get("run_id"), attempt),
         metadata={"decision": "approve", "analyst": analyst}, **ids)
    workflow_status = _state(incident_id).get("workflow_status")
    if workflow_status:
        emit(source="orchestration", event_type="routing", status="info", origin="state_transition",
             title=f"Workflow status: {workflow_status}", **ids)


def _approve_error(call: dict, token: Any, exc: BaseException) -> None:
    incident_id = str(call.get("incident_id"))
    attempt = _state(incident_id).get("reporting_attempt")
    blocked = type(exc).__name__ == "ReportValidationError"
    emit(source="human", event_type="approval_decision", status="warning", origin="state_transition",
         title="Reporting approval blocked by candidate-set validation" if blocked
         else "Reporting approval was not committed",
         detail=describe_exception(exc),
         metadata={"decision": "approve", "analyst": _str(call.get("analyst"))},
         **_ids(incident_id, call.get("run_id"), attempt))


def _reject_after(call: dict, token: Any, result: Any) -> None:
    incident_id = str(call.get("incident_id"))
    attempt = _state(incident_id).get("reporting_attempt")
    analyst = _str(call.get("rejected_by"))
    emit(source="human", event_type="approval_decision", status="completed", origin="state_transition",
         title=f"Reporting rejected by {analyst or 'analyst'}", detail=_str(call.get("reason")),
         span_id=_approval_span(call.get("run_id"), attempt),
         metadata={"decision": "reject", "analyst": analyst}, **_ids(incident_id, call.get("run_id"), attempt))


# ── Canonical audit Phase 6: the worker's prerequisite (readiness) gate ────

def _readiness_error(call: dict, token: Any, exc: BaseException) -> None:
    """The stage's canonical prerequisites were refused before the shared
    workspace, the attempt directory, the handoff or the agent."""
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="rule", event_type="input_validation", status="failed",
         title="Stage prerequisites are not satisfied", detail=describe_exception(exc))
    emit(source="decision", event_type="stage_result", status="failed",
         title="Reporting failed", detail=describe_exception(exc))


def install(patcher: Patcher) -> None:
    engine = "workflow.engine"
    patcher.wrap(Target(engine, "_require_stage_ready", ("incident_id", "stage", "run_id")),
                 Hooks(error=_readiness_error))
    patcher.wrap(Target(engine, "run_reporting_stage", ("incident_id", "run_id")),
                 Hooks(scope=_stage_scope, error=_stage_error))
    patcher.wrap(Target(engine, "claim_stage",
                        ("incident_id", "run_id", "stage", "status_column", "expect_status")),
                 Hooks(after=_claim_after, error=_claim_error))
    patcher.wrap(Target(engine, "acquire_global_lock",
                        ("lock_name", "owner_id", "incident_id", "run_id", "ttl_seconds")),
                 Hooks(after=_lock_after, error=_lock_error))
    patcher.wrap(Target(engine, "load_raw_incident_for_run", ("incident_id", "run_id")),
                 Hooks(after=_raw_incident_after))
    patcher.wrap(Target(engine, "_save_run_artifact",
                        ("incident_id", "run_id", "filename", "artifact_type", "payload")),
                 Hooks(before=_artifact_before))
    patcher.wrap(Target(engine, "handoff_to_reporting",
                        ("triage_result", "incident", "investigation_result", "threat_intel_result",
                         "incident_id", "run_id", "reporting_stage_attempt")),
                 Hooks(after=_handoff_after, error=_handoff_error))
    patcher.wrap(Target(engine, "run_reporting",
                        ("ticket_id", "timeout", "run_stamp", "line_cb", "reporting_input_dir",
                         "reporting_output_dir", "run_id", "reporting_stage_attempt")),
                 Hooks(before=_run_reporting_before, after=_run_reporting_after, error=_run_reporting_error))
    patcher.wrap(Target(engine, "_run_subprocess", ("cmd", "cwd", "timeout", "extra_env")),
                 Hooks(before=_subprocess_before, after=_subprocess_after, error=_subprocess_error))
    patcher.wrap(Target(engine, "_read_json", ("path", "default")), Hooks(after=_read_json_after))
    patcher.wrap(Target(engine, "export_report_documents",
                        ("incident_id", "timeout", "reporting_output_dir", "run_id", "reporting_stage_attempt")),
                 Hooks(before=_export_before, after=_export_after, error=_export_error))
    patcher.wrap(Target(engine, "generate_stage_ai_summary", ("stage", "stage_result", "model")),
                 Hooks(before=_summary_before, after=_summary_after, error=_summary_error,
                       cleanup=_summary_cleanup))
    patcher.wrap(Target("integrations.openai.client", "invoke_openai_text",
                        ("prompt", "system", "model", "temperature", "max_output_tokens", "timeout", "text_format")),
                 Hooks(before=_model_request_before, after=_model_request_after, error=_model_request_error))
    patcher.wrap(Target(engine, "complete_stage",
                        ("incident_id", "run_id", "worker_id", "stage", "result_column", "result",
                         "status_updates", "expected_stage_attempt")),
                 Hooks(after=_complete_after, error=_complete_error))
    patcher.wrap(Target("workflow.state_store", "begin_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("start")))
    patcher.wrap(Target("workflow.state_store", "rerun_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("rerun")))
    patcher.wrap(Target("agents.reporting.reporting_approval", "approve_reporting_candidate",
                        ("incident_id", "run_id", "analyst", "comments")),
                 Hooks(error=_approve_error))
    patcher.wrap(Target("workflow.state_store", "commit_reporting_approval",
                        ("incident_id", "run_id", "expected_reporting_attempt", "expected_reporting_result_json",
                         "metadata", "approved_by", "comments")),
                 Hooks(before=_commit_before, after=_commit_after))
    patcher.wrap(Target("workflow.state_store", "reject_reporting",
                        ("incident_id", "run_id", "rejected_by", "reason")),
                 Hooks(after=_reject_after))
