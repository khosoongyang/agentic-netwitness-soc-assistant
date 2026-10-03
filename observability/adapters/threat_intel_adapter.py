"""Threat Intelligence Enrichment observability.

The enrichment itself is tool- and rule-driven (agents.threat_intelligence.
threat_intel): IOC extraction is rule-based, every reputation lookup is an
HTTP call to VirusTotal / AbuseIPDB / AlienVault OTX, and the enrichment risk
score, level, warnings, stage status and recommended next action are all
computed in code. No LLM takes part in any of it. The only AI call in the
stage is the post-stage summary (workflow.stage_summaries.
generate_stage_ai_summary), which runs after the enrichment result exists.

Labelling therefore follows the code:
  * stage claim / persistence / routing        -> ORCHESTRATION
  * loading context, assembling the input,
    IOC extraction, recording results           -> SYSTEM
  * each provider lookup                        -> TOOL (one span per real call)
  * risk scoring, recommended next action,
    input identity check                        -> RULE
  * the enrichment outcome                      -> DECISION
  * the post-stage summary                      -> AI SUMMARY (post-stage)

Provider lookups execute sequentially inside enrich_alert(), one indicator
at a time. Each lookup is recorded as its own event in the real order; they
are children of the enclosing "provider lookups" operation (enrich_alert),
so the timeline groups them under one row without changing or reordering
the underlying events. A lookup function that returns "skipped" sent no
request (missing API key) and is reported exactly that way.

Only providers that are actually called produce events - nothing is listed
for a provider the current code path did not invoke.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from .. import context, details
from ..emitter import emit
from ..events import new_span_id
from ..instrument import Hooks, Patcher, Target
from ..sanitize import describe_exception, sanitize_text

STAGE = "threat_intel"

_POST_STAGE_NOTE = ("Generated after enrichment. Not used in provider queries, risk scoring "
                    "or enrichment decisions.")

_PROVIDERS = {
    "query_virustotal_file_hash": ("VirusTotal", "file hash"),
    "query_virustotal_ip": ("VirusTotal", "IP address"),
    "query_virustotal_domain": ("VirusTotal", "domain"),
    "query_abuseipdb": ("AbuseIPDB", "IP address"),
}
_OTX_KINDS = {"file": "file hash", "IPv4": "IP address", "IPv6": "IP address", "domain": "domain"}


def _scope() -> context.RunScope | None:
    scope = context.current_scope()
    return scope if scope is not None and scope.stage == STAGE else None


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _hash_label(value: str) -> str:
    value = _str(value)
    kind = {64: "SHA-256", 40: "SHA-1", 32: "MD5"}.get(len(value), "hash")
    short = f"{value[:8]}…{value[-4:]}" if len(value) > 16 else value
    return f"{kind} {short}"


def _indicator_text(kind: str, value: Any) -> str:
    return _hash_label(value) if kind == "file hash" else f"{kind} {_str(value)}"


def _state(incident_id: str) -> dict:
    from workflow import state_store

    return state_store.get_state(str(incident_id)) or {}


# ── Stage entry: resume_after_triage_approval(incident_id, run_id) ─────────

def _stage_scope(call: dict) -> context.RunScope:
    return context.RunScope(case_id=str(call.get("incident_id")), run_id=call.get("run_id"),
                            stage=STAGE)


def _stage_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(result, dict) or result.get("status") != "failed":
        return
    if not scope.data.get("decision_emitted"):
        scope.data["decision_emitted"] = True
        errors = result.get("errors") or []
        emit(source="decision", event_type="stage_result", status="failed",
             title="Threat Intelligence enrichment failed",
             detail=_str(errors[0] if errors else "The stage returned a failed status."))


def _stage_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None:
        return
    if type(exc).__name__ == "StageClaimError":
        emit(source="orchestration", event_type="worker_stopped", status="warning",
             title="Threat Intelligence worker stopped without saving a result",
             detail="The stage lease was not held by this worker (another worker owns it, or the run was superseded).")
    else:
        emit(source="orchestration", event_type="worker_stopped", status="failed",
             title="Threat Intelligence worker raised an error", detail=describe_exception(exc))


# ── Shared lifecycle points (also used by other stages; gated by scope) ────

def _claim_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    try:
        scope.stage_attempt = int(result[1])
    except Exception:
        pass
    emit(source="orchestration", event_type="stage_claimed", status="completed",
         origin="state_transition", title="Threat Intelligence stage claimed by a worker",
         detail=f"Attempt {scope.stage_attempt or '—'} · worker lease acquired")


def _claim_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_claimed", status="warning",
         origin="state_transition", title="Threat Intelligence stage could not be claimed",
         detail=describe_exception(exc))


def _parsing_loaded(call: dict, token: Any, result: Any) -> None:
    if _scope() is None:
        return
    processed = (result or {}).get("processed_alert") if isinstance(result, dict) else None
    if not processed:
        emit(source="system", event_type="context_loaded", status="warning",
             title="No persisted Parsing context for this run",
             detail="Enrichment input will rely on the raw incident's alert metadata only.")
        return
    emit(source="system", event_type="context_loaded", status="completed",
         title="Loaded normalised incident context from Parsing",
         detail=f"{len(processed.get('iocs') or [])} indicator(s) in the processed alert")


def _raw_loaded(call: dict, token: Any, result: Any) -> None:
    if _scope() is None:
        return
    if not isinstance(result, dict) or not result:
        emit(source="system", event_type="context_loaded", status="warning",
             title="Raw incident artifact unavailable for this run",
             detail="Enrichment cannot use the raw incident's alert metadata as a fallback.")
        return
    emit(source="system", event_type="context_loaded", status="completed",
         title="Loaded raw incident",
         detail=_str(result.get("title") or result.get("name")) or "Raw incident available")


def _complete_after(call: dict, token: Any, ok: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    updates = call.get("status_updates") or {}
    status = updates.get("threat_intel_status")
    if not ok:
        emit(source="orchestration", event_type="stage_settled", status="warning",
             origin="state_transition", title="Threat Intelligence result was not saved",
             detail="The stage lease was reassigned before the result could be written.")
        return
    if status in ("Complete", "Complete with Warnings"):
        nxt = updates.get("investigation_status")
        emit(source="orchestration", event_type="stage_settled",
             status="warning" if status == "Complete with Warnings" else "completed",
             origin="state_transition", title=f"Threat Intelligence result saved — {status}",
             detail=(f"Investigation status: {nxt} — it runs only when an analyst starts it."
                     if nxt else ""),
             metadata={"status_updates": updates})
    elif status == "Failed":
        result = call.get("result") or {}
        errors = result.get("errors") or []
        emit(source="orchestration", event_type="stage_settled", status="failed",
             origin="state_transition", title="Threat Intelligence marked Failed",
             detail=_str(errors[0] if errors else "") or "Investigation is blocked until it is re-run.",
             metadata={"status_updates": updates})


def _complete_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_settled", status="failed",
         origin="state_transition", title="Saving the Threat Intelligence result failed",
         detail=describe_exception(exc))


def _request_after(kind: str):
    def after(call: dict, token: Any, result: Any) -> None:
        if call.get("stage") != STAGE:
            return
        incident_id = str(call.get("incident_id"))
        attempt = _state(incident_id).get("threat_intel_attempt")
        emit(source="orchestration", event_type="stage_requested", status="completed",
             origin="state_transition",
             title=("Threat Intelligence re-run requested" if kind == "rerun"
                    else "Threat Intelligence run requested"),
             detail=f"Attempt {attempt or '—'} · stage set to Processing and a worker dispatched.",
             case_id=incident_id, run_id=call.get("run_id"), stage=STAGE, stage_attempt=attempt)

    return after


# ── Stage input: run_threat_intel(...) and _build_flat_alert(...) ──────────

def _run_ti_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _scope()
    if scope is None:
        return
    if type(exc).__name__ == "ThreatIntelValidationError":
        emit(source="rule", event_type="input_validation", status="failed",
             title="Stage inputs do not belong to this incident",
             detail=describe_exception(exc))
    if not scope.data.get("decision_emitted"):
        scope.data["decision_emitted"] = True
        emit(source="decision", event_type="stage_result", status="failed",
             title="Threat Intelligence enrichment failed", detail=describe_exception(exc))


def _run_ti_after(call: dict, token: Any, result: Any) -> None:
    """The enrichment outcome, as returned to the workflow (before the
    post-stage summary and before the result is saved)."""
    scope = _scope()
    if scope is None or not isinstance(result, dict) or scope.data.get("decision_emitted"):
        return
    scope.data["decision_emitted"] = True
    status = _str(result.get("status"))
    level = _str(result.get("enrichment_risk_level"))
    score = result.get("enrichment_risk_score")
    warnings = result.get("warnings") or []
    if status == "failed":
        emit(source="decision", event_type="stage_result", status="failed",
             title="Threat Intelligence enrichment failed",
             detail=_str(result.get("summary")) or "The enrichment engine returned a failed status.")
        return
    emit(source="decision", event_type="stage_result",
         status="warning" if status == "completed_with_warnings" else "completed",
         title=("Threat Intelligence enrichment completed with warnings"
                if status == "completed_with_warnings" else "Threat Intelligence enrichment completed"),
         detail=" · ".join(p for p in (
             f"Enrichment risk {level} (score {score})" if level else "",
             f"{len(warnings)} warning(s)" if warnings else "") if p),
         metadata={"details": details.blocks(details.fields([
             ("Stage status", status.replace("_", " ")),
             ("Enrichment risk level", level),
             ("Enrichment risk score", score),
         ]), details.items("Warnings", warnings))})


def _flat_alert_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not isinstance(result, dict):
        return
    base = call.get("normalised_alert") or {}
    filled = [field.replace("_", " ") for field in ("source_ip", "destination_ip", "event_domain", "file_hash")
              if not base.get(field) and result.get(field)]
    emit(source="system", event_type="input_assembled", status="completed",
         title="Enrichment input assembled",
         detail=("Built from the Parsing output"
                 + (f"; filled from the raw incident's alert metadata: {', '.join(filled)}" if filled else "")
                 + "."))


# ── IOC extraction (rule-based, runs inside the TI engine) ─────────────────

def _selection_after(call: dict, token: Any, result: Any) -> None:
    """Keep the engine's own indicator selection (eligible / excluded /
    limit-skipped, with reasons) for the extraction event below — the
    adapter records it, it never re-derives it."""
    scope = _scope()
    if scope is not None and isinstance(result, dict):
        scope.data["selection"] = result


def _candidate_line(candidate: dict) -> str:
    kind = _str(candidate.get("type"))
    value = _hash_label(candidate.get("value")) if kind == "hash" else _str(candidate.get("value"))
    reason = _str(candidate.get("exclusion_reason") or candidate.get("skip_reason"))
    return f"{value} — {reason}" if reason else value


def _iocs_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(result, dict):
        return
    hashes = tuple(result.get("file_hashes") or ([result["file_hash"]] if result.get("file_hash") else []))
    signature = (hashes, tuple(sorted(result.get("ip_indicators") or [])),
                 tuple(sorted(result.get("domain_indicators") or [])),
                 tuple(sorted(result.get("url_indicators") or [])))
    # extract_iocs() runs twice on the same flattened alert (a preview that
    # decides which providers apply, then again inside enrich_alert). Record
    # the extraction once; record a second time only if the result differs.
    if scope.data.get("ioc_signature") == signature:
        return
    scope.data["ioc_signature"] = signature
    hashes, ips, domains, urls = list(signature[0]), list(signature[1]), list(signature[2]), list(signature[3])
    candidates = (scope.data.get("selection") or {}).get("candidates") or []
    # URLs and file names are listed in their own rows above, so only
    # indicators deliberately kept from the providers are counted here.
    excluded = [_candidate_line(c) for c in candidates
                if c.get("selection") == "excluded" and c.get("exclusion_category") != "unsupported_type"]
    skipped = [_candidate_line(c) for c in candidates if c.get("selection") == "skipped"]
    total = len(hashes) + len(ips) + len(domains)
    emit(source="system", event_type="ioc_extraction", status="completed",
         title=("Observable extraction completed" if total
                else "No supported observable indicators found"),
         detail=(" · ".join(p for p in (
             (f"{len(hashes)} file hash" if len(hashes) == 1 else f"{len(hashes)} file hashes") if hashes else "",
             f"{len(ips)} public IP address(es)" if ips else "",
             f"{len(domains)} external domain(s)" if domains else "",
             f"{len(urls)} URL(s) (not enriched)" if urls else "",
             f"{len(excluded)} excluded" if excluded else "",
             f"{len(skipped)} skipped by enrichment limit" if skipped else "") if p)
             if total or urls else "No file hash, public IP or external domain to look up — no provider lookups will run."),
         metadata={"details": details.blocks(
             details.items("File hashes", [_hash_label(h) for h in hashes]),
             details.fields([
                 ("Possible file name", result.get("possible_file_name") if not hashes else None),
             ]),
             details.items("Public IP addresses", ips),
             details.items("External domains", domains),
             details.items("URLs (not enriched — provider support not implemented)", urls),
             details.items("Excluded — not sent to providers", excluded),
             details.items("Skipped — enrichment limit reached", skipped),
         )})


# ── Provider lookups ───────────────────────────────────────────────────────

def _lookups_before(call: dict):
    scope = _scope()
    if scope is None:
        return None
    span = new_span_id()
    scope.data["lookups"] = Counter()
    # enrich_alert() always runs; whether any lookup happens depends on the
    # extracted indicators, so the wording makes no claim that one will.
    emit(source="tool", event_type="provider_lookups", status="running",
         title="Provider lookup phase started",
         detail="Each lookup for an extracted indicator runs one at a time, in the order the "
                "enrichment engine issues it.",
         span_id=span)
    return {"span": span, "parent_token": context.set_parent_span(span), "start": time.monotonic()}


def _lookups_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not token:
        return
    counts: Counter = scope.data.get("lookups") or Counter()
    total = sum(counts[k] for k in ("completed", "not_found", "skipped", "error", "raised"))
    elapsed = details.format_duration_ms((time.monotonic() - token["start"]) * 1000)
    if not total:
        emit(source="tool", event_type="provider_lookups", status="completed",
             title="No provider lookups were run",
             detail="No supported indicator was available to look up.", span_id=token["span"])
        return
    answered = counts["completed"] + counts["not_found"]
    problems = counts["skipped"] + counts["error"] + counts["raised"]
    emit(source="tool", event_type="provider_lookups", status="warning" if problems else "completed",
         title=f"Provider lookups finished — {answered} of {total} answered",
         detail=" · ".join(p for p in (
             f"{counts['completed']} returned data" if counts["completed"] else "",
             f"{counts['not_found']} not found" if counts["not_found"] else "",
             f"{counts['skipped']} skipped (no API key)" if counts["skipped"] else "",
             f"{counts['error'] + counts['raised']} failed" if counts["error"] or counts["raised"] else "",
             elapsed) if p),
         span_id=token["span"],
         metadata={"outcomes": dict(counts), "providers": dict(scope.data.get("providers") or {})})


def _lookups_cleanup(call: dict, token: Any) -> None:
    if token and token.get("parent_token") is not None:
        context.reset_parent_span(token["parent_token"])


def _provider_fields(provider: str, result: dict) -> list[tuple[str, Any]]:
    if provider == "VirusTotal":
        return [("Malicious detections", result.get("malicious")),
                ("Suspicious detections", result.get("suspicious")),
                ("Harmless", result.get("harmless")), ("Undetected", result.get("undetected")),
                ("Reputation", result.get("reputation")), ("Name", result.get("meaningful_name")),
                ("Country", result.get("country")), ("AS owner", result.get("as_owner")),
                ("Registrar", result.get("registrar"))]
    if provider == "AbuseIPDB":
        return [("Abuse confidence", result.get("abuse_confidence_score")),
                ("Total reports", result.get("total_reports")), ("Country", result.get("country_code")),
                ("ISP", result.get("isp")), ("Usage type", result.get("usage_type")),
                ("Last reported", result.get("last_reported_at"))]
    return [("Pulses", result.get("pulse_count"))]


def _provider_summary(provider: str, result: dict) -> str:
    if provider == "VirusTotal":
        text = f"{result.get('malicious', 0)} malicious · {result.get('suspicious', 0)} suspicious"
        return text + (f" · reputation {result['reputation']}" if result.get("reputation") is not None else "")
    if provider == "AbuseIPDB":
        return (f"abuse confidence {result.get('abuse_confidence_score')}"
                f" · {result.get('total_reports')} report(s)")
    return f"{result.get('pulse_count', 0)} related pulse(s)"


def _lookup_hooks(provider: str, kind_from_call):
    def before(call: dict):
        scope = _scope()
        if scope is None:
            return None
        kind, value = kind_from_call(call)
        span = new_span_id()
        indicator = _indicator_text(kind, value)
        emit(source="tool", event_type="provider_lookup", status="running",
             title=f"{provider} lookup started", detail=indicator, span_id=span,
             parent_span_id=context.current_parent_span(),
             metadata={"provider": provider, "indicator_type": kind})
        return {"span": span, "indicator": indicator, "kind": kind, "start": time.monotonic(),
                "parent": context.current_parent_span()}

    def after(call: dict, token: Any, result: Any) -> None:
        scope = _scope()
        if scope is None or not token or not isinstance(result, dict):
            return
        elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
        outcome = _str(result.get("status")) or "unknown"
        counts = scope.data.setdefault("lookups", Counter())
        counts[outcome if outcome in ("completed", "not_found", "skipped", "error") else "error"] += 1
        scope.data.setdefault("providers", Counter())[provider] += 1
        base = {"span_id": token["span"], "parent_span_id": token["parent"]}
        meta = {"provider": provider, "indicator_type": token["kind"], "outcome": outcome,
                "duration_ms": elapsed_ms}
        if outcome == "completed":
            emit(source="tool", event_type="provider_lookup", status="completed",
                 title=f"{provider} · {token['indicator']}",
                 detail=f"{_provider_summary(provider, result)} · {details.format_duration_ms(elapsed_ms)}",
                 metadata={**meta, "details": details.blocks(
                     details.fields(_provider_fields(provider, result) + [
                         ("Duration", details.format_duration_ms(elapsed_ms))], label=f"{provider} result"),
                     details.items("Related pulses", result.get("related_pulses")))}, **base)
        elif outcome == "not_found":
            emit(source="tool", event_type="provider_lookup", status="completed",
                 title=f"{provider} · {token['indicator']}",
                 detail=f"No record found · {details.format_duration_ms(elapsed_ms)}",
                 metadata=meta, **base)
        elif outcome == "skipped":
            emit(source="tool", event_type="provider_lookup", status="warning",
                 title=f"{provider} lookup skipped · {token['indicator']}",
                 detail=f"No request sent — {_str(result.get('reason')) or 'provider not configured'}",
                 metadata=meta, **base)
        else:
            code = result.get("status_code")
            reason = (f"HTTP {code}" if code else "") or sanitize_text(result.get("reason"), max_len=200)
            body = sanitize_text(result.get("response"), max_len=160) if code else ""
            emit(source="tool", event_type="provider_lookup", status="warning",
                 title=f"{provider} lookup failed · {token['indicator']}",
                 detail=" · ".join(p for p in (reason or "Provider returned an error",
                                               details.format_duration_ms(elapsed_ms)) if p),
                 metadata={**meta, "status_code": code, "details": details.blocks(
                     details.text("Provider response (truncated)", body))}, **base)

    def error(call: dict, token: Any, exc: BaseException) -> None:
        scope = _scope()
        if scope is None or not token:
            return
        scope.data.setdefault("lookups", Counter())["raised"] += 1
        emit(source="tool", event_type="provider_lookup", status="failed",
             title=f"{provider} lookup raised an error · {token['indicator']}",
             detail=describe_exception(exc), span_id=token["span"], parent_span_id=token["parent"],
             metadata={"provider": provider})

    return Hooks(before=before, after=after, error=error)


# ── Deterministic risk scoring, warnings, next action ──────────────────────

def _risk_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not isinstance(result, dict):
        return
    reasons = result.get("enrichment_risk_reasons") or []
    emit(source="rule", event_type="risk_scoring", status="completed",
         title="Enrichment risk evaluated",
         detail=(f"Risk score {result.get('enrichment_risk_score')} → level "
                 f"{result.get('enrichment_risk_level')} (rule-based, computed in code)"),
         metadata={"details": details.blocks(
             details.fields([("Risk score", result.get("enrichment_risk_score")),
                             ("Risk level", result.get("enrichment_risk_level"))]),
             details.items("Factors recorded by the scoring rules", reasons))})


def _engine_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not isinstance(result, dict):
        return
    warnings = result.get("warnings") or []
    notes = result.get("notes") or []
    emit(source="system", event_type="enrichment_recorded",
         status="warning" if warnings else "completed",
         title=("Enrichment completed with warnings" if warnings
                else "Enrichment completed without provider warnings"),
         detail=(f"{len(warnings)} warning(s): {warnings[0]}" + (" …" if len(warnings) > 1 else "")
                 if warnings else "Results written for this run."),
         metadata={"details": details.blocks(details.items("Warnings", warnings),
                                             details.items("Notes from the enrichment engine", notes))})
    action = _str(result.get("recommended_next_action"))
    if action:
        emit(source="rule", event_type="recommended_action", status="completed",
             title="Recommended next action determined", detail=action)


def _engine_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None:
        return
    emit(source="system", event_type="enrichment_recorded", status="failed",
         title="Enrichment engine raised an error", detail=describe_exception(exc))


# ── Post-stage AI summary ──────────────────────────────────────────────────

def _summary_before(call: dict):
    scope = _scope()
    if scope is None or "Threat Intelligence" not in _str(call.get("stage")):
        return None
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
                   "details": details.blocks(
                       details.note(_POST_STAGE_NOTE), details.text("Summary", summary),
                       details.fields([("Model", result.get("ai_summary_model")),
                                       ("Duration", details.format_duration_ms(elapsed_ms))]))})


def _summary_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="failed",
         title="Post-stage AI summary failed", detail=describe_exception(exc),
         span_id=token["span"], metadata={"post_stage": True})


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
         metadata={"model": token["model"], "duration_ms": elapsed_ms,
                   "details": details.blocks(details.fields([
                       ("Model", token["model"]), ("Duration", details.format_duration_ms(elapsed_ms)),
                       ("Token usage", "not returned through this call path")]))})


def _model_request_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="failed",
         title="Model request failed", detail=describe_exception(exc),
         span_id=token["span"], parent_span_id=token["parent"], metadata={"model": token["model"]})


def install(patcher: Patcher) -> None:
    engine = "workflow.engine"
    ti = "agents.threat_intelligence.threat_intel"
    patcher.wrap(Target(engine, "resume_after_triage_approval", ("incident_id", "run_id")),
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
    patcher.wrap(Target(engine, "run_threat_intel",
                        ("incident_id", "run_id", "normalised_alert", "triage_result", "incident")),
                 Hooks(after=_run_ti_after, error=_run_ti_error))
    patcher.wrap(Target(ti, "_build_flat_alert", ("incident", "triage_result", "normalised_alert")),
                 Hooks(after=_flat_alert_after))
    patcher.wrap(Target(ti, "run_threat_intel_for_dashboard", ("alert", "output_dir")),
                 Hooks(after=_engine_after, error=_engine_error))
    patcher.wrap(Target(ti, "select_indicators", ("alert",)), Hooks(after=_selection_after))
    patcher.wrap(Target(ti, "extract_iocs", ("alert",)), Hooks(after=_iocs_after))
    patcher.wrap(Target(ti, "enrich_alert", ("alert",)),
                 Hooks(before=_lookups_before, after=_lookups_after, cleanup=_lookups_cleanup))
    for name, (provider, kind) in _PROVIDERS.items():
        param = {"query_virustotal_file_hash": "file_hash", "query_virustotal_domain": "domain"}.get(name, "ip_address")
        patcher.wrap(Target(ti, name, (param,)),
                     _lookup_hooks(provider, lambda call, k=kind, p=param: (k, call.get(p))))
    patcher.wrap(Target(ti, "query_otx_indicator", ("indicator_type", "indicator_value")),
                 _lookup_hooks("AlienVault OTX", lambda call: (
                     _OTX_KINDS.get(_str(call.get("indicator_type")), _str(call.get("indicator_type"))),
                     call.get("indicator_value"))))
    patcher.wrap(Target(ti, "calculate_enrichment_risk", ("threat_intel",)), Hooks(after=_risk_after))
    patcher.wrap(Target(engine, "generate_stage_ai_summary", ("stage", "stage_result", "model")),
                 Hooks(before=_summary_before, after=_summary_after, error=_summary_error,
                       cleanup=_summary_cleanup))
    patcher.wrap(Target("integrations.openai.client", "invoke_openai_text",
                        ("prompt", "system", "model", "temperature", "max_output_tokens",
                         "timeout", "text_format")),
                 Hooks(before=_model_request_before, after=_model_request_after,
                       error=_model_request_error))
    patcher.wrap(Target("workflow.state_store", "begin_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("start")))
    patcher.wrap(Target("workflow.state_store", "rerun_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("rerun")))
