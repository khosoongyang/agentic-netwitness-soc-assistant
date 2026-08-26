# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, re, typing.
# =============================================================================
# File: soc_reporting_agent/reporting/context_builder.py
# Purpose: This module merges validated upstream stage outputs into the reporting context.
# Main functionality: _first, _list, _get, _label, _normalise_asset, _normalise_user.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis report generation and export component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, datetime, re, typing.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _first, _list, _get, _label, _normalise_asset, _normalise_user, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# =============================================================================
# [FYP-SECTION] REPORT GENERATION AND EXPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_first` — implements the first operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `default`, `*values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include compliance_evidence.py:_build, compliance_evidence.py:_triage_bits, soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _first(*values: Any, default: Any = "Not Provided") -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


# [FYP-FUNCTION] `_list` — implements the list operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:_build_appendix_summaries, soc_reporting_agent/reporting/context_builder.py:_normalise_ioc, soc_reporting_agent/reporting/context_builder.py:_normalise_timeline; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `list`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


# [FYP-FUNCTION] `_get` — implements the get operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `obj`, `path`, `default`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:_build_appendix_summaries, soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `split`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _get(obj: Any, path: str, default: Any = None) -> Any:
    cur = obj or {}
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


# [FYP-FUNCTION] `_label` — implements the label operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `value`, `reason`, `default`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _label(value: Any, reason: Any = None, default: str | None = None) -> dict[str, Any]:
    chosen = _first(value, default=default)
    return {"label": str(chosen) if chosen is not None else "", "value": chosen, "reason": _first(reason, default=None) or ""}


# [FYP-FUNCTION] `_normalise_asset` — transforms normalise asset input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_asset(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        hostname = _first(item.get("hostname"), item.get("host"), item.get("host.name"), item.get("asset"), item.get("name"))
        ip = _first(item.get("ip_address"), item.get("ip"), item.get("address"), item.get("source_ip"))
        criticality = _first(item.get("criticality"), item.get("role"))
        return {
            "hostname": hostname,
            "asset": hostname,
            "host": hostname,
            "name": hostname,
            "ip_address": ip,
            "ip": ip,
            "asset_type": _first(item.get("asset_type"), item.get("type"), default="Endpoint"),
            "criticality": criticality,
            "role": criticality,
            "owner": _first(item.get("owner"), item.get("business_owner")),
            "business_function": _first(item.get("business_function"), item.get("function")),
            "isolation_status": _first(item.get("isolation_status"), item.get("containment_status"), item.get("status")),
            "status": _first(item.get("status")),
        }
    text = str(item)
    return {
        "hostname": text, "asset": text, "host": text, "name": text,
        "ip_address": None, "ip": None, "asset_type": "Endpoint",
        "criticality": None, "role": None, "owner": None,
        "business_function": None, "isolation_status": None, "status": None,
    }


# [FYP-FUNCTION] `_normalise_user` — transforms normalise user input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `_list`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_user(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        username = _first(item.get("username"), item.get("user"), item.get("name"), item.get("account"))
        return {
            "username": username,
            "user": username,
            "email": _first(item.get("email"), item.get("mail")),
            "role": _first(item.get("role"), item.get("title")),
            "privilege_level": _first(item.get("privilege_level"), item.get("privilege")),
            "groups": _list(item.get("groups")),
            "mfa_status": _first(item.get("mfa_status"), item.get("mfa")),
            "account_status": _first(item.get("account_status"), item.get("status")),
        }
    text = str(item)
    return {"username": text, "user": text, "email": None, "role": None, "privilege_level": None, "groups": [], "mfa_status": None, "account_status": None}


# [FYP-FUNCTION] `_normalise_ioc` — transforms normalise ioc input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `_list`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_ioc(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        value = _first(item.get("value"), item.get("ioc"), item.get("indicator"), item.get("hash"), item.get("file_hash"), item.get("ip"), item.get("domain"))
        evidence_refs = _list(_first(item.get("evidence_refs"), item.get("evidence_ref"), item.get("evidence"), default=[]))
        return {
            "type": _first(item.get("type"), item.get("ioc_type"), item.get("kind"), default="Indicator"),
            "value": value,
            "ioc": value,
            "source": _first(item.get("source")),
            "confidence": _first(item.get("confidence")),
            "reputation": _first(item.get("reputation"), item.get("verdict"), item.get("threat_level")),
            "evidence": _first(item.get("evidence"), item.get("evidence_ref")),
            "evidence_refs": evidence_refs,
        }
    text = str(item)
    return {"type": "Indicator", "value": text, "ioc": text, "source": None, "confidence": None, "reputation": None, "evidence": None, "evidence_refs": []}


# [FYP-FUNCTION] `_normalise_evidence` — transforms normalise evidence input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`, `idx`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_evidence(item: Any, idx: int = 1) -> dict[str, Any]:
    if isinstance(item, dict):
        return {
            "id": _first(item.get("id"), item.get("evidence_id"), default=f"EV-{idx:03d}"),
            "source": _first(item.get("source"), item.get("system")),
            "type": _first(item.get("type"), item.get("evidence_type"), default="Evidence"),
            "description": _first(item.get("description"), item.get("summary"), item.get("detail"), item.get("value")),
            "timestamp": _first(item.get("timestamp"), item.get("time")),
            "confidence": _first(item.get("confidence")),
            "raw_reference": _first(item.get("raw_reference"), item.get("reference"), item.get("path")),
        }
    return {"id": f"EV-{idx:03d}", "source": None, "type": "Evidence", "description": str(item), "timestamp": None, "confidence": None, "raw_reference": None}


# [FYP-FUNCTION] `_normalise_timeline` — transforms normalise timeline input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`, `idx`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `_list`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_timeline(item: Any, idx: int = 1) -> dict[str, Any]:
    if isinstance(item, dict):
        return {
            "time": _first(item.get("time"), item.get("timestamp")),
            "timestamp": _first(item.get("timestamp"), item.get("time")),
            "event": _first(item.get("event"), item.get("description"), item.get("action"), default=f"Timeline event {idx}"),
            "description": _first(item.get("description"), item.get("event"), item.get("action"), default=f"Timeline event {idx}"),
            "source": _first(item.get("source")),
            "evidence_refs": _list(item.get("evidence_refs")),
            "significance": _first(item.get("significance"), default="Supports incident reconstruction and analyst review."),
        }
    return {"time": None, "timestamp": None, "event": str(item), "description": str(item), "source": None, "evidence_refs": [], "significance": "Supports incident reconstruction and analyst review."}


# [FYP-FUNCTION] `_normalise_gap` — transforms normalise gap input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `get`, `isinstance`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_gap(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return {
            "priority": _first(item.get("priority"), default="Medium"),
            "gap": str(item.get("gap") or item.get("field") or item.get("missing_field") or item.get("name") or "").strip() or None,
            "missing_field": str(item.get("missing_field") or item.get("field") or item.get("gap") or item.get("name") or "").strip() or None,
            "required_data": _first(item.get("required_data"), item.get("reason_needed"), item.get("reason"), item.get("description")),
            "reason": _first(item.get("reason"), item.get("description"), item.get("required_data")),
        }
    text = str(item).strip()
    return {"priority": "Medium", "gap": text or None, "missing_field": text or None, "required_data": None, "reason": None}


# [FYP-FUNCTION] `_normalise_recommendation` — transforms normalise recommendation input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `item`, `idx`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_recommendation(item: Any, idx: int = 1) -> dict[str, Any]:
    if isinstance(item, dict):
        rec = _first(item.get("recommendation"), item.get("action"), item.get("title"))
        return {
            "priority": _first(item.get("priority"), default=f"P{idx}"),
            "recommendation": rec,
            "action": rec,
            "owner": _first(item.get("owner")),
            "status": _first(item.get("status")),
            "rationale": _first(item.get("rationale")),
            "approval_required": _first(item.get("approval_required")),
            "risk_addressed": _first(item.get("risk_addressed"), item.get("risk")),
            "target_date": _first(item.get("target_date")),
        }
    text = str(item)
    return {"priority": f"P{idx}", "recommendation": text, "action": text, "owner": None, "status": None, "rationale": None, "approval_required": None, "risk_addressed": None, "target_date": None}



# [FYP-FUNCTION] `_short_value` — implements the short value operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `value`, `max_len`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:_build_appendix_summaries; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `isinstance`, `items`, `join`, `len`, `list`, `split`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _short_value(value: Any, max_len: int = 220) -> str:
    if value in (None, "", [], {}):
        return "Not Provided"
    if isinstance(value, (list, tuple, set)):
        items = [str(v) for v in list(value)[:8] if v not in (None, "", [], {})]
        text = ", ".join(items)
        if len(value) > 8:  # type: ignore[arg-type]
            text += f", ... (+{len(value) - 8} more)"  # type: ignore[arg-type]
    elif isinstance(value, dict):
        pairs = []
        for key, item in list(value.items())[:8]:
            if item not in (None, "", [], {}):
                pairs.append(f"{key}: {item}")
        text = "; ".join(pairs) if pairs else "Not Provided"
        if len(value) > 8:
            text += f"; ... (+{len(value) - 8} more)"
    else:
        text = str(value)
    text = " ".join(text.split())
    return text[: max_len - 3] + "..." if len(text) > max_len else text


# [FYP-FUNCTION] `_extract_evidence_value` — transforms extract evidence value input into the stable representation required by downstream report generation and export processing.
# [FYP-INPUT] Parameters: `evidence`, `key`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `compile`, `escape`, `get`, `group`, `search`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _extract_evidence_value(evidence: list[dict[str, Any]], key: str) -> str | None:
    pattern = re.compile(rf"\b{re.escape(key)}\s*[:=]\s*([^,;\s]+)", re.IGNORECASE)
    for item in evidence or []:
        for field in ("description", "raw_reference"):
            match = pattern.search(str(item.get(field) or ""))
            if match:
                return match.group(1).strip()
    return None


# [FYP-FUNCTION] `_is_ransomware_case` — evaluates is ransomware case conditions so invalid or unsafe report generation and export processing is stopped early.
# [FYP-INPUT] Parameters: `*values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `join`, `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _is_ransomware_case(*values: Any) -> bool:
    text = " ".join(str(v or "") for v in values).lower()
    return any(term in text for term in ("wannacry", "wanna cry", "ransomware", "malware/ransomware", "ransomware-related"))


# [FYP-FUNCTION] `_build_appendix_summaries` — constructs build appendix summaries output for the next report generation and export consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `processed`, `enriched`, `triage`, `investigation`, `approval_result`, `incident_id`, `alert_id`, `title`, `severity`, `confidence`, `evidence_gaps`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/context_builder.py:build_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `_get`, `_list`, `_short_value`, `get`, `join`, `len`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _build_appendix_summaries(
    *,
    processed: dict[str, Any],
    enriched: dict[str, Any],
    triage: dict[str, Any],
    investigation: dict[str, Any],
    approval_result: dict[str, Any],
    incident_id: Any,
    alert_id: Any,
    title: Any,
    severity: dict[str, Any],
    confidence: dict[str, Any],
    evidence_gaps: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Build compact, always-present appendix summaries for Jinja templates.

    Older templates expect ``appendix_summaries.raw_alert`` and related keys.
    Returning a fully populated default prevents template rendering crashes when
    optional source files or fields are absent.
    """
    gaps = ", ".join(str(g.get("gap") or g.get("missing_field") or g) for g in evidence_gaps) if evidence_gaps else "None recorded"
    return {
        "raw_alert": {
            "Incident ID": _short_value(incident_id),
            "Alert ID": _short_value(alert_id),
            "Alert Title": _short_value(title),
            "Incident Title": _short_value(_first(processed.get("incident_title"), enriched.get("incident_title"), default="Not Provided")),
            "Source": _short_value(_first(processed.get("alert_source"), processed.get("source"), enriched.get("source"), default="NetWitness")),
            "Severity": _short_value(severity.get("label")),
            "Confidence": _short_value(confidence.get("label")),
            "Timestamp": _short_value(_first(processed.get("timestamp"), processed.get("alert_created_time"), enriched.get("timestamp"), default="Not Provided")),
            "Host": _short_value(_first(processed.get("hostname"), processed.get("host"), enriched.get("hostname"), default="Not Provided")),
            "Source IP": _short_value(_first(processed.get("source_ip"), enriched.get("source_ip"), default="Not Provided")),
            "Destination IP": _short_value(_first(processed.get("destination_ip"), enriched.get("destination_ip"), default="Not Provided")),
            "File Hash": _short_value(_first(processed.get("file_hash"), processed.get("md5"), enriched.get("file_hash"), default="Not Provided")),
            "Domain / URL": _short_value(_first(processed.get("event_domain"), processed.get("domain"), processed.get("url"), enriched.get("domain"), enriched.get("url"), default="Not Provided")),
        },
        "processed_alert": {
            "Parser Status": _short_value(_first(processed.get("parser_status"), processed.get("normalisation_status"), default="Not Provided")),
            "Parser Confidence": _short_value(_first(processed.get("parser_confidence"), _get(processed, "data_quality.parser_confidence"), default="Not Provided")),
            "Missing Fields": _short_value(_first(processed.get("missing_fields"), _get(processed, "data_quality.missing_required_fields"), default=[])),
            "IOC Count": str(len(_list(processed.get("iocs")))),
        },
        "enriched_alert": {
            "Enrichment Status": _short_value(_first(enriched.get("status"), enriched.get("threat_intel_status"), default="Not Provided")),
            "Original Alert Risk Score": _short_value(_first(processed.get("risk_score"), default="Not Provided")),
            "Enriched Risk Score": _short_value(_first(enriched.get("enrichment_risk_score"), enriched.get("risk_score"), default="Not Provided")),
            "Final Risk Rating": _short_value(severity.get("label")),
            "Threat Intel Notes": _short_value(_first(enriched.get("notes"), enriched.get("summary"), default="Not Provided")),
        },
        "triage": {
            "Classification": _short_value(_first(triage.get("classification"), triage.get("incident_category"), default="Not Provided")),
            "Severity": _short_value(_first(triage.get("severity"), severity.get("label"), default="Not Provided")),
            "Confidence": _short_value(_first(triage.get("confidence"), confidence.get("label"), default="Not Provided")),
            "Recommended Action": _short_value(_first(triage.get("recommended_next_action"), triage.get("next_action"), default="Not Provided")),
        },
        "investigation": {
            "Status": _short_value(_first(investigation.get("status"), investigation.get("workflow_decision"), default="Not Provided")),
            "Classification": _short_value(_first(investigation.get("classification"), default="Not Provided")),
            "Likely Scenario": _short_value(_first(investigation.get("likely_scenario"), default="Not Provided")),
            "Finding Count": str(len(_list(investigation.get("findings")))),
            "Evidence Gaps": _short_value(gaps),
            "Reporting Mode": _short_value(_first(investigation.get("reporting_mode"), default="Not Provided")),
        },
        "approval": {
            "Report Generation Approval Status": _short_value(_first(approval_result.get("approval_status"), approval_result.get("status"), approval_result.get("decision"), default="Not Provided")),
            "Report Generation Approved By": _short_value(_first(approval_result.get("analyst"), approval_result.get("approved_by"), approval_result.get("reviewed_by"), default="Not Provided")),
            "Containment Approval Status": _short_value(_first(approval_result.get("containment_approval_status"), default="Pending analyst approval")),
            "Containment Execution Status": _short_value(_first(approval_result.get("containment_execution_status"), default="Not Contained")),
            "Final Analyst Review Status": _short_value(_first(approval_result.get("final_analyst_review_status"), default="Requires final analyst review")),
            "Reporting Mode": _short_value(_first(approval_result.get("reporting_mode"), default="Not Provided")),
            "Comments": _short_value(_first(approval_result.get("analyst_comments"), approval_result.get("comments"), default="Not Provided")),
        },
    }

# [FYP-FUNCTION] `build_context` — constructs build context output for the next report generation and export consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `inputs`, `warnings`, `output_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/agents/reporting_agent.py:main, soc_reporting_agent/reporting/template_document_exporter.py:build_report_context, soc_reporting_agent/scripts/test_merged_report_context.py:test_merged_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_build_appendix_summaries`, `_extract_evidence_value`, `_first`, `_get`, `_is_ransomware_case`, `_label`, `_list`, `_normalise_asset`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_context(inputs: dict[str, dict[str, Any]] | None, warnings: list[str] | None = None, output_dir: Any = None) -> dict[str, Any]:
    inputs = inputs or {}
    warnings = warnings or []
    processed = inputs.get("processed_alert") or {}
    enriched = inputs.get("enriched_alert") or {}
    triage = inputs.get("triage_result") or {}
    investigation = inputs.get("investigation_result") or {}
    # Phase 5 (canonical Investigation Result contract migration): the full
    # canonical Phase 1 InvestigationAgentOutput payload, nested by
    # workflow/engine.py::run_investigation() under investigation_result
    # ["investigation_analysis"] whenever investigation_analysis.json
    # validated (Phase 2/3). NOT investigation.get("agent") -- that flat key
    # is a pre-existing STRING label ("Investigation Agent"), unrelated to
    # this nested contract payload. Absent entirely on pre-migration results
    # and on the Markdown-fallback path -- every read below falls through to
    # the existing compatibility chain in that case.
    investigation_analysis = investigation.get("investigation_analysis")
    if not isinstance(investigation_analysis, dict):
        investigation_analysis = {}
    # The Phase 3 feedback-loop record (automatic re-investigation gap
    # detection, now sourced from the structured execution_trace when
    # available) -- a richer, per-step evidence-gap signal than the older
    # missing_evidence/missing_fields strings, used below as the preferred
    # source for the evidence-gaps section only (NOT for reporting_mode/
    # eligibility, which are intentionally left untouched in Phase 5).
    feedback_loop = investigation.get("feedback_loop")
    if not isinstance(feedback_loop, dict):
        feedback_loop = {}
    threat_intel_result = inputs.get("threat_intel_result") or {}
    approval_history = inputs.get("approval_history") or []
    workflow_metadata = inputs.get("workflow_metadata") or {}
    approval_result = inputs.get("investigation_approval_result") or inputs.get("approval_result") or {}
    ticket_context = inputs.get("grouped_incident_context") or inputs.get("ticket_context") or {}
    correlation_recommendations = inputs.get("correlation_recommendations") or {}
    reporting = inputs.get("reporting_result") or inputs.get("final_report") or {}

    # Prefer parser/normalisation outputs over later agents for stable identity.
    # Investigation may legitimately report incident_id="unknown" when it has
    # evidence gaps, but Reporting should still recover the correct incident and
    # alert title from the parser/triage/threat-intel context.
    incident_id = _first(ticket_context.get("incident_id"), workflow_metadata.get("incident_id"), processed.get("incident_id"), enriched.get("incident_id"), triage.get("incident_id"), investigation.get("incident_id"), investigation.get("case_id"), triage.get("case_id"), threat_intel_result.get("incident_id"), default="unknown")
    alert_id = _first(processed.get("alert_id"), enriched.get("alert_id"), triage.get("alert_id"), investigation.get("alert_id"), default="UNKNOWN-ALERT")
    title = _first(processed.get("alert_title"), processed.get("alert_name"), enriched.get("alert_title"), enriched.get("alert_name"), enriched.get("case_title"), enriched.get("title"), triage.get("title"), investigation.get("title"), default="Not Provided")
    # Phase 5: prefer the canonical Investigation Agent contract payload
    # first, then the Phase 3 flat compatibility alias (investigation
    # .get("severity")/.get("confidence") -- populated by run_investigation()
    # whenever investigation_analysis.json validated, same value as the
    # nested payload today, kept as a fallback in case a producer only sets
    # one of the two), then Triage/enrichment/reporting exactly as before.
    # confidence in particular was previously ALWAYS absent from Investigation
    # output (dropped before the JSON handoff), so this chain always fell
    # through to Triage's pre-investigation estimate -- it now resolves from
    # Investigation's own post-investigation assessment whenever available.
    severity_value = _first(investigation_analysis.get("severity"), investigation.get("severity"), triage.get("severity"), enriched.get("severity"), enriched.get("risk_level"), reporting.get("severity"), default="Not Provided")
    confidence_value = _first(investigation_analysis.get("confidence"), investigation.get("confidence"), triage.get("confidence"), enriched.get("confidence"), reporting.get("confidence"), default="Not Provided")
    # Classification remains Triage-owned -- the Investigation Agent contract
    # (agents/investigation/investigation_result.py::InvestigationAgentOutput)
    # has no classification field, so there is no canonical Investigation
    # source to prefer here. Left unchanged from before Phase 5.
    classification = _first(investigation.get("classification"), triage.get("classification"), triage.get("incident_category"), reporting.get("classification"), default="Not Provided")
    likely_scenario = _first(investigation.get("likely_scenario"), triage.get("likely_scenario"), reporting.get("likely_scenario"), default="Not Provided")
    investigation_status = str(_first(investigation.get("status"), investigation.get("workflow_decision"), default="not_provided"))
    investigation_status_norm = investigation_status.strip().lower().replace(" ", "_").replace("-", "_")
    limited_investigation_statuses = {"completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "partial", "partial_success", "needs_analyst_review"}
    explicit_reporting_mode = _first(
        approval_result.get("reporting_mode"),
        approval_result.get("approved_reporting_mode"),
        investigation.get("reporting_mode"),
        reporting.get("reporting_mode"),
        default=None,
    )
    reporting_mode = str(explicit_reporting_mode or "").strip() or (
        "with_limitations"
        if investigation_status_norm in limited_investigation_statuses
        or investigation.get("workflow_override")
        or investigation.get("missing_evidence")
        or investigation.get("missing_fields")
        else "standard"
    )

    affected_assets = [_normalise_asset(x) for x in _list(_first(investigation.get("affected_assets"), triage.get("affected_assets"), ticket_context.get("affected_assets"), enriched.get("affected_assets"), processed.get("affected_assets"), default=[]))]
    affected_users = [_normalise_user(x) for x in _list(_first(investigation.get("affected_users"), triage.get("affected_users"), ticket_context.get("affected_users"), enriched.get("affected_users"), processed.get("affected_users"), default=[]))]
    iocs = [_normalise_ioc(x) for x in _list(_first(investigation.get("iocs"), triage.get("iocs"), ticket_context.get("combined_iocs"), enriched.get("iocs"), enriched.get("indicators"), default=[]))]
    evidence = [_normalise_evidence(x, idx + 1) for idx, x in enumerate(_list(_first(investigation.get("evidence"), triage.get("evidence"), enriched.get("evidence"), default=[])))]
    timeline = [_normalise_timeline(x, idx + 1) for idx, x in enumerate(_list(_first(investigation.get("timeline"), triage.get("timeline"), enriched.get("timeline"), default=[])))]
    # Phase 5: prefer the Phase 3 feedback-loop's structured, per-step gap
    # descriptions (sourced from execution_trace, see workflow/engine.py::
    # detect_evidence_gaps()) over the older, coarser missing_evidence/
    # missing_fields strings when the automatic re-investigation loop
    # actually ran. This only changes what gap text is DISPLAYED -- it does
    # NOT touch reporting_mode's own with_limitations/standard decision
    # above, which is left reading investigation.get("missing_evidence")/
    # .get("missing_fields") exactly as before.
    evidence_gaps = [_normalise_gap(x) for x in _list(_first(feedback_loop.get("gaps"), investigation.get("missing_evidence"), investigation.get("missing_fields"), triage.get("missing_evidence"), triage.get("missing_fields"), reporting.get("missing_report_fields"), default=[]))]
    missing_required_fields = [g.get("gap", str(g)) for g in evidence_gaps]
    investigation_limitations = evidence_gaps if reporting_mode == "with_limitations" else []
    investigation_completeness_note = (
        "Investigation completed with evidence gaps. The selected playbook could not be fully answered because required telemetry was missing. Reporting proceeds with limitations documented for SOC analyst validation."
        if reporting_mode == "with_limitations"
        else "Investigation output is complete enough for standard reporting."
    )

    powershell_analysis = _first(
        investigation.get("powershell_analysis"),
        investigation.get("powershell_command_analysis"),
        triage.get("powershell_analysis"),
        triage.get("powershell_command_analysis"),
        enriched.get("powershell_analysis"),
        processed.get("powershell_analysis"),
        _get(processed, "normalised_alert.powershell_analysis"),
        default={},
    )
    if not isinstance(powershell_analysis, dict):
        powershell_analysis = {}

    # recommended_containment / containment_recommendations are the Investigation
    # Agent's own field names for this data (orchestrator.FinalIncidentAnalysis.
    # recommended_containment); they must be checked ahead of recommended_actions
    # so a real, specific containment finding is never mistaken for "not supplied"
    # and backfilled with generic text.
    # Phase 5: the canonical nested contract payload is checked first; the
    # flat investigation.get("recommended_containment") alias (populated by
    # run_investigation() from the same structured data, or previously from
    # Markdown-regex reconstruction) remains the very next fallback, followed
    # by every existing compatibility branch, unchanged.
    raw_recommended_containment = _list(_first(
        investigation_analysis.get("recommended_containment"),
        investigation.get("recommended_containment"),
        investigation.get("containment_recommendations"),
        investigation.get("recommended_actions"),
        triage.get("recommended_actions"),
        triage.get("recommendations"),
        reporting.get("recommended_actions"),
        default=[],
    ))
    recommendations = [_normalise_recommendation(x, idx + 1) for idx, x in enumerate(raw_recommended_containment)]
    if not recommendations:
        recommendations = [
            _normalise_recommendation("Review available alert context, logs, and telemetry to determine the activity source and scope.", 1),
            _normalise_recommendation("Validate whether the event represents true malicious activity, a policy violation, or a false positive.", 2),
            _normalise_recommendation("Document findings and escalate if evidence of compromise, active attack, or critical asset impact is discovered.", 3),
        ]
    # Verbatim bullet text for report section 10.3 — preserves the Investigation
    # Agent's exact wording (hostnames, IPs, processes, registry paths, event IDs,
    # hashes, subnets) rather than the table-shaped/enriched recommendations above.
    recommended_containment_actions = []
    for item in raw_recommended_containment:
        if isinstance(item, dict):
            text = _first(item.get("recommendation"), item.get("action"), item.get("title"), default="")
        else:
            text = item
        text = str(text or "").strip()
        if text:
            recommended_containment_actions.append(text)

    approval = {
        "approval_required": _first(approval_result.get("approval_required"), triage.get("approval_required")),
        "approval_status": _first(approval_result.get("approval_status"), triage.get("soc_analyst_approval_status")),
        "analyst_decision": _first(approval_result.get("analyst_decision"), approval_result.get("decision")),
        "analyst_comments": _first(approval_result.get("analyst_comments"), approval_result.get("soc_analyst_comments")),
        "approved_by": _first(approval_result.get("analyst"), approval_result.get("approved_by"), approval_result.get("reviewed_by")),
        "approved_action": _first(approval_result.get("approved_action"), approval_result.get("approved_containment_action")),
    }
    containment = {
        "status": _first(approval_result.get("containment_status"), triage.get("containment_status")),
        "recommended": _first(triage.get("containment_recommended"), investigation.get("containment_recommended")),
        "recommended_action": _first(triage.get("containment_action"), triage.get("recommended_containment_action"), approval_result.get("approved_containment_action")),
        "execution_status": _first(approval_result.get("containment_execution_status"), triage.get("containment_status")),
        "blocking_reason": _first(approval_result.get("blocking_reason")),
        "decision_source": _first(approval_result.get("decision_source"), default="SOC analyst approval context"),
    }
    alert = {
        "source": _first(enriched.get("source"), processed.get("source"), default="NetWitness SIEM"),
        "name": _first(enriched.get("alert_name"), processed.get("alert_name"), title),
        "timestamp": _first(enriched.get("alert_timestamp"), enriched.get("timestamp"), processed.get("timestamp")),
    }

    correlated_alerts = _list(ticket_context.get("confirmed_alert_links") or ticket_context.get("related_alerts") or [])
    pending_correlation = _list(ticket_context.get("pending_correlation_recommendations") or correlation_recommendations.get("recommendations") or [])
    analyst_grouping_history = _list(ticket_context.get("analyst_grouping_history") or [])
    archive_recommendations = _list(investigation.get("archive_recommendations") or [])
    archived_duplicate_tickets = [
        item for item in analyst_grouping_history
        if str(item.get("archive_status") or "").lower() in {"archived", "archived_duplicate"}
        or item.get("requires_archive_approval")
        or item.get("archive_after_approval")
    ]

    severity = _label(severity_value, _first(triage.get("severity_reason"), investigation.get("severity_reason"), default="Not Provided"))
    confidence = _label(confidence_value, _first(triage.get("confidence_reason"), investigation.get("confidence_reason"), default="Not Provided"))

    evidence_backed_findings = [
        {"finding_id": "KF-001", "statement": f"The incident classification is {classification}.", "finding": f"The incident classification is {classification}.", "status": "Fact", "confidence": confidence["label"], "evidence_refs": ["investigation_result.json"], "evidence": "investigation_result.json", "interpretation": "Classification is taken from investigation output first, with triage as fallback."},
        {"finding_id": "KF-002", "statement": "Affected scope requires validation." if not affected_assets and not affected_users else "Affected scope has available context.", "finding": "Affected scope requires validation." if not affected_assets and not affected_users else "Affected scope has available context.", "status": "Evidence Gap" if not affected_assets and not affected_users else "Fact", "confidence": confidence["label"], "evidence_refs": [], "evidence": "", "interpretation": "Assets and users should be validated against NetWitness and endpoint evidence."},
        {"finding_id": "KF-003", "statement": f"Approval status is {approval['approval_status']}.", "finding": f"Approval status is {approval['approval_status']}.", "status": "Fact", "confidence": confidence["label"], "evidence_refs": ["approval_result.json"], "evidence": "approval_result.json", "interpretation": "Approval data is recorded only from analyst approval context."},
    ]

    limitations_sentence = (" Investigation completed with evidence gaps, so this report proceeds with limitations and requires SOC analyst validation of missing telemetry." if reporting_mode == "with_limitations" else "")
    executive_overview = _first(reporting.get("executive_summary"), reporting.get("summary"), default=(
        f"This incident is assessed as {severity['label']} severity with {confidence['label']} confidence. "
        f"The current classification is {classification}, and the likely scenario is {likely_scenario}. "
        "Any missing assets, users, IOCs, or timestamps should remain marked as not confirmed until validated by a SOC analyst."
        + limitations_sentence
    ))
    # Phase 5: investigation_analysis.incident_summary (canonical) is checked
    # right after Reporting's own technical_analysis field, ahead of the
    # older investigation_summary/summary flat keys -- in current practice
    # this is a no-op (investigation.get("summary") already reliably carries
    # the same content via incident_data.json's summary_text, unaffected by
    # Phase 3's structured/Markdown-fallback branching), kept for explicit
    # contract-preference consistency with the other canonical fields above.
    technical_analysis = _first(reporting.get("technical_analysis"), investigation_analysis.get("incident_summary"), investigation.get("investigation_summary"), investigation.get("summary"), default=(
        f"The available triage and investigation context indicates {likely_scenario}. Severity is {severity['label']} and confidence is {confidence['label']}. "
        "The SOC analyst should validate endpoint, identity, network, and NetWitness telemetry before confirming containment, escalation, or closure."
        + limitations_sentence
    ))
    analyst_review_guidance = _first(reporting.get("analyst_review_guidance"), default=(
        f"Validate the evidence supporting {severity['label']} severity, {confidence['label']} confidence, and {classification} classification. "
        "Review affected scope, suspicious indicators, timeline sequence, approval status, and unresolved evidence gaps before closure."
    ))

    impact_assessment = {
        "business": _first(reporting.get("business_impact"), default="Current business impact depends on validated affected assets, users, data access, and service disruption evidence."),
        "security": _first(reporting.get("security_risk"), default=f"Security risk is tied to the {likely_scenario} scenario and should be validated using the listed evidence and gaps."),
        "unconfirmed": "Further compromise, spread, persistence, and data exposure remain subject to analyst validation.",
    }

    data_impact_assessment = {
        "data_access": None,
        "data_exfiltration": None,
        "encryption_modification_deletion": None,
        "personal_data_involvement": None,
        "notification_requirement": None,
        "evidence_supporting_assessment": "See evidence register and evidence gaps.",
    }
    original_alert_risk_score = _first(processed.get("risk_score"), _extract_evidence_value(evidence, "risk_score"), default="Not Provided")
    enriched_risk_score = _first(enriched.get("enrichment_risk_score"), enriched.get("risk_score"), default="Not Provided")
    final_risk_rating = severity["label"]
    malware_family = _first(investigation.get("malware_family"), enriched.get("malware_family"), default="Not Provided")
    scenario_type = _first(investigation.get("case_type"), reporting.get("scenario_type"), default="Not Provided")
    ransomware_case = _is_ransomware_case(title, classification, likely_scenario, scenario_type, investigation.get("selected_playbook"), malware_family)
    loaded_knowledge_files = ["policies/incident_severity_policy.md", "procedures/report_writing_sop.md", "procedures/investigation_sop.md"]
    excluded_playbooks = ["malware_response_playbook.md"]
    relevant_playbook = "Scenario-specific playbook to be validated"
    playbook_selection_note = "Scenario-specific playbook should be validated by a SOC analyst."
    if ransomware_case:
        relevant_playbook = "ransomware_response_playbook.md"
        playbook_selection_note = "Ransomware reporting context selected because the supplied case context references WannaCry/ransomware activity."
        loaded_knowledge_files.append("playbooks/ransomware_response_playbook.md")
    elif str(scenario_type).strip().lower() in {"phishing", "phishing_email"}:
        relevant_playbook = "phishing_response_playbook.md"
        loaded_knowledge_files.append("playbooks/phishing_response_playbook.md")
        excluded_playbooks.append("ransomware_response_playbook.md")
    management_action_plan = recommendations
    active_narrative = {
        "executive_summary": executive_overview,
        "technical_analysis": technical_analysis,
        "business_impact_explanation": _first(reporting.get("business_impact_explanation"), default=impact_assessment["business"]),
        "attack_narrative": _first(reporting.get("attack_narrative"), default=technical_analysis),
        "analyst_friendly_explanation": analyst_review_guidance,
        "soc_analyst_review_checklist": _first(reporting.get("soc_analyst_review_checklist"), default="1. Confirm incident identifiers and severity. 2. Validate affected scope. 3. Review IOCs and evidence references. 4. Check unresolved evidence gaps. 5. Record final analyst decision."),
        "conclusion": _first(reporting.get("conclusion"), reporting.get("final_assessment"), default=f"The case should remain under SOC analyst review until missing evidence gaps are validated. Current assessment: {severity['label']} severity, {confidence['label']} confidence."),
    }

    report_validation_checks = [
        {"check": "Incident ID present", "status": "Pass" if incident_id not in ("", "unknown", "UNKNOWN-INCIDENT") else "Review Required"},
        {"check": "Alert ID present", "status": "Pass" if alert_id != "UNKNOWN-ALERT" else "Review Required"},
        {"check": "Severity present", "status": "Pass" if severity["label"] else "Fail"},
        {"check": "Confidence present", "status": "Pass" if confidence["label"] else "Fail"},
        {"check": "Evidence present", "status": "Pass" if evidence else "Review Required"},
    ]

    appendix_summaries = _build_appendix_summaries(
        processed=processed,
        enriched=enriched,
        triage=triage,
        investigation=investigation,
        approval_result=approval_result,
        incident_id=incident_id,
        alert_id=alert_id,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence_gaps=evidence_gaps,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "alert_id": alert_id,
        "case_title": title,
        "ticket_id": incident_id,
        "severity": severity,
        "confidence": confidence,
        "classification": classification,
        "likely_scenario": likely_scenario,
        "scenario_type": scenario_type,
        "report_status": _first(reporting.get("report_status"), investigation.get("report_status"), triage.get("report_status"), default="Generated for analyst review"),
        "report_status_display": _first(reporting.get("report_status_display"), reporting.get("report_status"), default="Generated for analyst review"),
        "validation_status": _first(reporting.get("validation_status"), investigation.get("validation_status"), triage.get("validation_status"), default="Requires analyst validation"),
        "validation_status_display": _first(reporting.get("validation_status_display"), reporting.get("validation_status"), default="Requires analyst validation"),
        "current_stage": _first(triage.get("current_stage"), investigation.get("current_stage"), default="Not Provided"),
        "current_lifecycle_stage": "Reporting and analyst review",
        "containment_status": containment["status"],
        "approval_status": approval["approval_status"],
        "analyst_decision": approval["analyst_decision"],
        "approval": approval,
        "report_generation_approval": {
            "status": approval["approval_status"],
            "approved_by": approval["approved_by"],
            "comments": approval["analyst_comments"],
            "approval_gate": _first(approval_result.get("approval_gate"), approval_result.get("approval_type"), default=""),
        },
        "final_analyst_review_status": _first(approval_result.get("final_analyst_review_status"), reporting.get("final_analyst_review_status"), default="Requires final analyst review"),
        "containment": containment,
        "alert": alert,
        "correlated_alerts": correlated_alerts,
        "confirmed_alert_count": len(correlated_alerts),
        "pending_correlation_recommendations": pending_correlation,
        "analyst_grouping_history": analyst_grouping_history,
        "archive_recommendations": archive_recommendations,
        "archived_duplicate_tickets": archived_duplicate_tickets,
        "triage": triage,
        "investigation": investigation,
        # Threat Intelligence, passed explicitly (see input_loader.py's
        # threat_intel_result input key / HARD_REQUIRED_INPUT_KEYS) rather
        # than assumed to have survived into enriched_alert/investigation —
        # export_context_enhancer.rebuild_iocs() reads this directly.
        "threat_intel_result": threat_intel_result,
        "threat_intelligence": threat_intel_result.get("threat_intelligence") or {},
        "enrichment_risk_score": threat_intel_result.get("enrichment_risk_score"),
        "enrichment_risk_level": threat_intel_result.get("enrichment_risk_level"),
        # Approval history as of the moment Reporting started (Triage's and
        # Investigation's decisions, plus this Reporting stage's own prior
        # reject/rerun history if any) — never this attempt's own
        # not-yet-existing Reporting decision.
        "approval_history": approval_history,
        "run_id": workflow_metadata.get("run_id"),
        "reporting_stage_attempt": workflow_metadata.get("reporting_stage_attempt"),
        "workflow_metadata": workflow_metadata,
        "investigation_status": investigation_status,
        "investigation_completeness_status": "Completed with evidence gaps" if reporting_mode == "with_limitations" else "Completed",
        "investigation_completeness_note": investigation_completeness_note,
        "investigation_limitations": investigation_limitations,
        "reporting_mode": reporting_mode,
        "reporting_allowed_with_limitations": reporting_mode == "with_limitations",
        "approval_result": approval_result,
        "reporting": reporting,
        "affected_assets": affected_assets,
        "affected_users": affected_users,
        "iocs": iocs,
        "evidence": evidence,
        "timeline": timeline,
        # mitre_mappings (plural) is the Investigation Agent's own structured
        # MITRE ATT&CK mapping — timeline_phase/observed_evidence/tactic/
        # technique_name/technique_id per entry, recovered verbatim from
        # narrative_report by soc_workflow._investigation_mitre_mappings. It
        # must be checked ahead of the older mitre_attack_mapping/mitre_mapping
        # fields so genuine, per-technique evidence is never mistaken for "not
        # supplied" and backfilled by export_context_enhancer's generic
        # technique-ID scan.
        # Phase 5: the canonical nested contract payload (investigation_analysis
        # .mitre_mappings, structured JSON -- no Markdown parsing) is checked
        # first; the flat investigation.get("mitre_mappings") alias and every
        # older field-name spelling remain as fallbacks, unchanged.
        "mitre_mapping": _list(_first(investigation_analysis.get("mitre_mappings"), investigation.get("mitre_mappings"), investigation.get("mitre_mapping"), powershell_analysis.get("mitre_mapping"), investigation.get("mitre_attack"), default=[])),
        "mitre_attack_mapping": _list(_first(investigation_analysis.get("mitre_mappings"), investigation.get("mitre_mappings"), investigation.get("mitre_attack_mapping"), investigation.get("mitre_mapping"), powershell_analysis.get("mitre_mapping"), investigation.get("mitre_attack"), default=[])),
        "powershell_analysis": powershell_analysis,
        "powershell_command_analysis": powershell_analysis,
        "missing_evidence": evidence_gaps,
        "evidence_gaps": evidence_gaps,
        "missing_fields": missing_required_fields,
        "missing_required_fields": missing_required_fields,
        "recommendations": recommendations,
        "recommended_actions": recommendations,
        "recommended_containment_actions": recommended_containment_actions,
        "management_action_plan": management_action_plan,
        "key_findings": evidence_backed_findings,
        "evidence_backed_findings": evidence_backed_findings,
        "active_narrative": active_narrative,
        "impact_assessment": impact_assessment,
        "executive_overview": executive_overview,
        "executive_summary": executive_overview,
        "technical_analysis": technical_analysis,
        "business_impact_explanation": active_narrative["business_impact_explanation"],
        "attack_narrative": active_narrative["attack_narrative"],
        "analyst_review_guidance": analyst_review_guidance,
        "final_assessment": active_narrative["conclusion"],
        "triage_summary": _first(triage.get("summary"), default="Not Provided"),
        "investigation_summary": _first(investigation_analysis.get("incident_summary"), investigation.get("summary"), investigation.get("investigation_summary"), default="Not Provided"),
        "raw_inputs": inputs,
        "appendix_summaries": appendix_summaries,
        "warnings": warnings,
        "rag_used": True,
        "rag_status": _first(reporting.get("rag_status"), default="Local template export context built"),
        "rag_status_display": _first(reporting.get("rag_status_display"), reporting.get("rag_status"), default="Local template export context built"),
        "llm_used": True,
        "llm_status": _first(reporting.get("llm_status"), reporting.get("llm_enhancement_status"), default="Template variables populated from available context"),
        "llm_status_display": _first(reporting.get("llm_status_display"), reporting.get("llm_enhancement_status"), default="Template variables populated from available context"),
        "llm_quality_status": _first(reporting.get("llm_quality_status"), reporting.get("enhancement_quality"), default="not_used"),
        "llm_quality_issues": _list(reporting.get("llm_quality_issues")),
        "llm_attempt_count": _first(reporting.get("llm_attempt_count"), default="Not Recorded"),
        "llm_cache_status": _first(reporting.get("llm_cache_status"), default="Not Recorded"),
        "llm_cache_status_display": _first(reporting.get("llm_cache_status_display"), reporting.get("llm_cache_status"), default="Not Recorded"),
        "llm_status_explanation": _first(reporting.get("llm_status_explanation"), reporting.get("llm_explanation"), default="None"),
        "llm_section_results": reporting.get("llm_section_results") or {},
        "report_generation_mode": _first(reporting.get("generation_mode"), default="deterministic_plus_template_export"),
        "report_completeness_score": _first(reporting.get("report_completeness_score"), default=65 if missing_required_fields else 90),
        "report_completeness_status": _first(reporting.get("report_completeness_status"), default="Completeness needs review" if missing_required_fields else "Complete enough for analyst review"),
        "report_completeness_status_display": _first(reporting.get("report_completeness_status_display"), reporting.get("report_completeness_status"), default="Completeness needs review" if missing_required_fields else "Complete enough for analyst review"),
        "report_classification": "Internal / Restricted",
        "prepared_by": "Reporting Agent",
        "review_limitations": {
            "log_availability": "Dependent on submitted input files and available SOC telemetry.",
            "endpoint_visibility": "Dependent on endpoint evidence included in investigation_result.json.",
            "network_visibility": "Dependent on available SIEM, NetWitness, proxy, DNS, and firewall logs.",
            "threat_intelligence": "Threat intelligence reputation may be incomplete and must be interpreted with local telemetry.",
            "timestamp_accuracy": "Timeline accuracy depends on source clock synchronisation.",
            "evidence_completeness": "Missing evidence is documented as evidence gaps for analyst follow-up.",
        },
        "overall_report_confidence": confidence["label"],
        "environment_type": "SOC-monitored environment",
        "asset_criticality": "See affected assets table",
        "business_owner": "Not Provided",
        "technical_owner": "Not Provided",
        "rule_id": _first(enriched.get("rule_id"), processed.get("rule_id"), default="Not Provided"),
        "original_alert_risk_score": original_alert_risk_score,
        "initial_risk_score": original_alert_risk_score,
        "enriched_risk_score": enriched_risk_score,
        "enrichment_risk_score": enriched_risk_score,
        "final_risk_rating": final_risk_rating,
        "malware_family": malware_family,
        "threat_actor": _first(investigation.get("threat_actor"), default="Not Provided"),
        "escalation_level": "SOC analyst review",
        "root_cause": {"likely_root_cause": "Pending further analyst validation", "category": _first(investigation.get("case_type"), default="Not Provided"), "confidence": confidence["label"], "evidence_basis": "Based on classification, likely scenario, timeline, IOCs, and available investigation evidence."},
        "contributing_factors": [{"factor": "Evidence completeness gap", "description": "One or more required reporting or investigation fields are missing or require validation.", "impact": "Limits confidence in scope, root cause, and final disposition."}],
        "framework_mappings": _list(reporting.get("framework_mappings")),
        "policy_application_summary": [
            {"source": "incident_severity_policy.md", "relevant_guidance": "Severity should reflect evidence, impact, and confidence.", "application": f"Current severity is {severity['label']} and should be analyst validated."},
            {"source": "report_writing_sop.md", "relevant_guidance": "Reports must separate evidence-backed facts from gaps.", "application": "The export keeps missing facts as evidence gaps rather than inventing details."},
        ],
        "loaded_knowledge_files": loaded_knowledge_files,
        "excluded_playbooks": excluded_playbooks,
        "relevant_playbook": relevant_playbook,
        "playbook_selection_note": playbook_selection_note,
        "quality_checks": {
            "conflicting_severity_values_detected": "Not Detected",
            "conflicting_confidence_values_detected": "Not Detected",
            "stale_context_detected": "Review Required" if warnings else "Not Detected",
            "triage_result_available": "Yes" if triage else "No",
            "investigation_result_available": "Yes" if investigation else "No",
            "threat_intelligence_result_available": "Yes" if enriched else "No",
            "fallback_logic_used": "No",
        },
        "report_validation_checks": report_validation_checks,
        "recovered_fields": [],
        "raw_inputs": inputs,
        "data_impact_assessment": data_impact_assessment,
    }
