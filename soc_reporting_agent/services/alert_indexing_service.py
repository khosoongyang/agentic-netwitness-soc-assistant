# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, json, re, typing.
# =============================================================================
# File: soc_reporting_agent/services/alert_indexing_service.py
# Purpose: This module indexes normalised alerts for retrieval and downstream case correlation.
# Main functionality: _text, _lower, _unique, flatten_strings, parse_timestamp, extract_iocs.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis parsing and reporting service component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, datetime, json, re, typing.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _text, _lower, _unique, flatten_strings, parse_timestamp, extract_iocs, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any


# =============================================================================
# [FYP-SECTION] PARSING AND REPORTING SERVICE EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_text` — implements the text operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:_lower, soc_reporting_agent/services/alert_indexing_service.py:_unique, soc_reporting_agent/services/alert_indexing_service.py:alert_features; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _text(value: Any) -> str:
    return str(value or "").strip()


# [FYP-FUNCTION] `_lower` — implements the lower operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_text`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _lower(value: Any) -> str:
    return _text(value).lower()


# [FYP-FUNCTION] `_unique` — implements the unique operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:extract_iocs; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_text`, `add`, `append`, `dumps`, `get`, `isinstance`, `lower`, `set`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _unique(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("value") or value.get("indicator") or value.get("ioc") or json.dumps(value, sort_keys=True)
        text = _text(value).strip().strip('"\'.,;:()[]{}')
        if not text:
            continue
        key = text.lower()
        # Avoid treating flattened JSON key paths such as raw.hostname as IOCs.
        if key.startswith(("raw.", "alert.", "incident.", "metakeys.", "original.")):
            continue
        if key in {"hostname", "severity", "source", "status", "username", "timestamp"}:
            continue
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


# [FYP-FUNCTION] `flatten_strings` — implements the flatten strings operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `value`, `limit`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:alert_narrative, soc_reporting_agent/services/alert_indexing_service.py:extract_iocs; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `walk`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def flatten_strings(value: Any, *, limit: int = 300) -> list[str]:
    """Flatten JSON-like telemetry into short strings for narrative search.

    This is adapted from the investigation feature branch's ingest_pipeline idea,
    but it works directly with dashboard ticket/alert dictionaries instead of
    triaged_alerts/*.json files.
    """
    out: list[str] = []

    # [FYP-FUNCTION] `walk` — implements the walk operation used by the surrounding parsing and reporting service workflow.
    # [FYP-INPUT] Parameters: `obj`, `prefix`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:_flatten_values, soc_reporting_agent/reporting/export_context_enhancer.py:_threat_intel_index, soc_reporting_agent/reporting/export_context_enhancer.py:walk; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_text`, `append`, `enumerate`, `isinstance`, `items`, `len`, `str`, `walk`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def walk(obj: Any, prefix: str = "") -> None:
        if len(out) >= limit:
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key in {"raw_json", "payload_json"}:
                    continue
                walk(val, f"{prefix}.{key}" if prefix else str(key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj[:80]):
                walk(item, f"{prefix}[{idx}]")
        else:
            text = _text(obj)
            if text:
                out.append(f"{prefix} is {text}" if prefix else text)

    walk(value)
    return out[:limit]


# [FYP-FUNCTION] `parse_timestamp` — transforms parse timestamp input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:alert_features; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_text`, `float`, `fromisoformat`, `fromtimestamp`, `isinstance`, `replace`, `strptime`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, (int, float)):
        try:
            # Support both seconds and milliseconds.
            if value > 10_000_000_000:
                value = value / 1000
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    text = _text(value)
    if not text:
        return None
    # ISO style is the common case in current project test data.
    for candidate in [text, text.replace("Z", "+00:00")]:
        try:
            return datetime.fromisoformat(candidate)
        except Exception:
            pass
    # Fallback for common NetWitness-ish timestamps.
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


# [FYP-FUNCTION] `extract_iocs` — transforms extract iocs input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:alert_features, tests/test_threat_intel_workflow.py:test_external_domain_extracted, tests/test_threat_intel_workflow.py:test_internal_hostname_without_dot_ignored; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_unique`, `append`, `extend`, `findall`, `flatten_strings`, `get`, `isinstance`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def extract_iocs(alert: dict[str, Any]) -> list[str]:
    alert = alert or {}
    raw = alert.get("raw") if isinstance(alert.get("raw"), dict) else {}
    candidates: list[Any] = []
    for source in (alert, raw):
        if not isinstance(source, dict):
            continue
        for key in (
            "iocs", "indicators", "matched_iocs", "file_hash", "sha256", "sha1", "md5",
            "source_ip", "destination_ip", "src_ip", "dst_ip", "domain", "url", "fqdn",
            "email", "sender_email", "receiver_email", "process_name", "process", "command_line",
        ):
            if source.get(key) not in (None, "", [], {}):
                candidates.append(source.get(key))
    blob = " ".join(flatten_strings([alert, raw], limit=500))
    candidates.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob))
    candidates.extend(re.findall(r"\b[a-fA-F0-9]{32,64}\b", blob))
    candidates.extend(re.findall(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b", blob))
    candidates.extend(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", blob))
    return _unique(candidates)[:80]


# [FYP-FUNCTION] `pick_value` — implements the pick value operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `source`, `*keys`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:alert_features; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def pick_value(source: dict[str, Any], *keys: str) -> Any:
    raw = source.get("raw") if isinstance(source.get("raw"), dict) else {}
    for key in keys:
        if source.get(key) not in (None, "", [], {}):
            return source.get(key)
        if raw.get(key) not in (None, "", [], {}):
            return raw.get(key)
    return None


# [FYP-FUNCTION] `_powershell_from_alert` — implements the powershell from alert operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:alert_features, soc_reporting_agent/services/alert_indexing_service.py:build_ticket_incident_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _powershell_from_alert(alert: dict[str, Any]) -> dict[str, Any]:
    raw = alert.get("raw") if isinstance(alert.get("raw"), dict) else {}
    normalised = alert.get("normalised_alert") if isinstance(alert.get("normalised_alert"), dict) else {}
    for source in (alert, raw, normalised):
        if isinstance(source, dict) and isinstance(source.get("powershell_analysis"), dict):
            return source.get("powershell_analysis") or {}
    return {}


# [FYP-FUNCTION] `alert_features` — implements the alert features operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:alert_narrative, soc_reporting_agent/services/alert_indexing_service.py:build_ticket_incident_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_powershell_from_alert`, `_text`, `extract_iocs`, `get`, `int`, `isinstance`, `parse_timestamp`, `pick_value`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def alert_features(alert: dict[str, Any]) -> dict[str, Any]:
    alert = alert or {}
    ps = _powershell_from_alert(alert)
    ts = pick_value(alert, "first_seen", "last_seen", "timestamp", "time", "event_time", "eventTime", "created_at", "createdTime")
    parsed_ts = parse_timestamp(ts)
    return {
        "alert_id": pick_value(alert, "alert_id", "id", "event_id") or alert.get("alert_id"),
        "title": _text(pick_value(alert, "alert_name", "name", "title", "alert_title", "event_name")),
        "hostname": _text(pick_value(alert, "hostname", "host", "device_host", "deviceHost", "endpoint", "computer_name", "computerName")),
        "username": _text(pick_value(alert, "username", "user", "user_name", "userName", "account", "src_user", "source_user")),
        "source_ip": _text(pick_value(alert, "source_ip", "src_ip", "ip_src", "sourceAddress", "source.address", "ip")),
        "destination_ip": _text(pick_value(alert, "destination_ip", "dst_ip", "ip_dst", "destinationAddress", "destination.address")),
        "domain": _text(pick_value(alert, "domain", "fqdn", "host_name", "url_domain", "destination_domain")),
        "process": _text(pick_value(alert, "process", "process_name", "processName", "image", "exe", "command")),
        "parent_process": _text(pick_value(alert, "parent_process", "parentProcess", "parent_image", "parentImage")),
        "mitre": _text(pick_value(alert, "mitre", "mitre_technique", "technique", "attack_technique", "tactic")),
        "powershell_decode_status": ps.get("decode_status"),
        "powershell_behaviours": [b.get("behaviour") for b in (ps.get("suspicious_behaviours") or []) if isinstance(b, dict)],
        "powershell_risk": (ps.get("risk_assessment") or {}).get("risk_level") if isinstance(ps.get("risk_assessment"), dict) else None,
        "severity": _text(pick_value(alert, "severity", "priority")),
        "timestamp": _text(ts),
        "timestamp_epoch": int(parsed_ts.timestamp()) if parsed_ts else None,
        "iocs": extract_iocs(alert),
    }


# [FYP-FUNCTION] `alert_narrative` — implements the alert narrative operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/alert_indexing_service.py:build_ticket_incident_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `alert_features`, `endswith`, `extend`, `flatten_strings`, `get`, `isinstance`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def alert_narrative(alert: dict[str, Any]) -> str:
    f = alert_features(alert)
    parts = [
        f"Alert {f.get('alert_id')}: {f.get('title')}",
        f"severity {f.get('severity')}",
        f"host {f.get('hostname')}",
        f"user {f.get('username')}",
        f"source IP {f.get('source_ip')}",
        f"destination IP {f.get('destination_ip')}",
        f"domain {f.get('domain')}",
        f"process {f.get('process')}",
        f"parent process {f.get('parent_process')}",
        f"MITRE {f.get('mitre')}",
        f"PowerShell decode status {f.get('powershell_decode_status')}",
        f"PowerShell behaviours {', '.join(f.get('powershell_behaviours') or [])}",
        f"PowerShell risk {f.get('powershell_risk')}",
        f"timestamp {f.get('timestamp')}",
        f"IOCs {', '.join(f.get('iocs') or [])}",
    ]
    raw = alert.get("raw") if isinstance(alert.get("raw"), dict) else {}
    parts.extend(flatten_strings(raw, limit=120))
    return "\n".join([p for p in parts if p and not p.endswith(" ")])


# [FYP-FUNCTION] `build_ticket_incident_context` — constructs build ticket incident context output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `ticket`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_powershell_from_alert`, `alert_features`, `alert_narrative`, `append`, `get`, `isinstance`, `join`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_ticket_incident_context(ticket: dict[str, Any]) -> dict[str, Any]:
    alerts = ticket.get("related_alerts") or []
    features = [alert_features(a) for a in alerts if isinstance(a, dict)]
    timeline = sorted(
        [
            {
                "alert_id": f.get("alert_id"),
                "title": f.get("title"),
                "timestamp": f.get("timestamp"),
                "timestamp_epoch": f.get("timestamp_epoch"),
                "host": f.get("hostname"),
                "user": f.get("username"),
                "severity": f.get("severity"),
            }
            for f in features
        ],
        key=lambda x: x.get("timestamp_epoch") or 0,
    )
    powershell_analyses = []
    for alert in alerts:
        if isinstance(alert, dict):
            ps = _powershell_from_alert(alert)
            if ps:
                powershell_analyses.append(ps)
    return {
        "ticket_id": ticket.get("ticket_id"),
        "incident_id": ticket.get("incident_id"),
        "title": ticket.get("title"),
        "severity": ticket.get("severity"),
        "confidence": ticket.get("confidence"),
        "alert_count": len(alerts),
        "confirmed_alerts": alerts,
        "features": features,
        "timeline": timeline,
        "affected_assets": ticket.get("affected_assets") or [],
        "affected_users": ticket.get("affected_users") or [],
        "combined_iocs": ticket.get("iocs") or [],
        "narrative": "\n\n".join(alert_narrative(a) for a in alerts if isinstance(a, dict)),
    }
