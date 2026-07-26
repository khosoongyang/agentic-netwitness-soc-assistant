from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from reporting.llm_narrative import enhance_narrative
from reporting.compact_renderer import (
    approval_summary_table,
    build_approval_summary,
    build_chain_of_custody_note,
    build_data_impact_summary,
    build_evidence_register_summary,
    compact_table,
    count_placeholders,
    is_placeholder,
    split_into_sentences,
    split_numbered_items,
)

UNKNOWN_VALUES = {
    "", "unknown", "unknown-alert", "unknown-incident", "not provided", "none", "null", "n/a", "na", "-", "—"
}
UNKNOWN_VALUES.update({"to be validated", "not linked", "pending", "not recorded"})

OWNER_PLACEHOLDER = "To be assigned"
VALIDATION_PLACEHOLDER = "Pending analyst validation"
TELEMETRY_PLACEHOLDER = "Unavailable from source telemetry"
EVIDENCE_PLACEHOLDER = "Evidence link unavailable"
NOT_EVIDENCED = "Not evidenced in source telemetry"

MITRE_LOCAL_MAPPING = {
    "T1486": {"technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1210": {"technique_name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1046": {"technique_name": "Network Service Discovery", "tactic": "Discovery"},
}

PLACEHOLDER_VALUES = {
    "unavailable from source telemetry",
    "not provided",
    "to be validated",
    "pending analyst validation",
    "evidence link unavailable",
    "to be assigned",
    "pending",
    "not linked",
}


def is_unknown(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return str(value).strip().lower() in UNKNOWN_VALUES


def first_present(*values: Any, default: Any = "Not Provided") -> Any:
    for value in values:
        if not is_unknown(value):
            return value
    return default


def as_list(value: Any) -> list[Any]:
    if is_unknown(value):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def get_path(obj: Any, path: str, default: Any = None) -> Any:
    cur = obj or {}
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _normalise_lookup(value: Any) -> str:
    text = _clean_text(value).strip("`'\".,;()[]{}")
    return text.replace("\\\\", "\\").lower()


def _quality(context: dict[str, Any]) -> dict[str, Any]:
    checks = context.setdefault("quality_checks", {})
    for key in (
        "fields_recovered_from_fallback_sources",
        "iocs_deduplicated",
        "evidence_links_recovered",
        "placeholders_reduced",
        "fields_still_unavailable_from_source_telemetry",
    ):
        checks.setdefault(key, 0)
    checks.setdefault("fallback_logic_used", "No")
    return checks


def _bump(context: dict[str, Any], key: str, count: int = 1) -> None:
    if count <= 0:
        return
    checks = _quality(context)
    checks[key] = int(checks.get(key) or 0) + count
    checks["fallback_logic_used"] = "Yes"


def _parse_key_value(text: Any) -> tuple[str | None, str | None]:
    raw = _clean_text(text)
    if ":" not in raw:
        return None, raw or None
    key, value = raw.split(":", 1)
    return _clean_text(key) or None, _clean_text(value) or None


def _add_index(index: dict[str, list[str]], value: Any, evidence_id: str) -> None:
    key = _normalise_lookup(value)
    if not key or not evidence_id:
        return
    refs = index.setdefault(key, [])
    if evidence_id not in refs:
        refs.append(evidence_id)


def build_evidence_index(evidence: list[dict[str, Any]]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("id") or item.get("evidence_id") or "").strip()
        if not evidence_id:
            continue
        description = item.get("description") or item.get("summary") or item.get("value") or ""
        _add_index(index, description, evidence_id)
        key, value = _parse_key_value(description)
        if value:
            _add_index(index, value, evidence_id)
        if key and value:
            _add_index(index, f"{key}: {value}", evidence_id)
    return index


def _first_evidence_id(value: Any, evidence_index: dict[str, list[str]]) -> str | None:
    keys = [_normalise_lookup(value)]
    parsed_key, parsed_value = _parse_key_value(value)
    if parsed_value:
        keys.append(_normalise_lookup(parsed_value))
    if parsed_key and parsed_value:
        keys.append(_normalise_lookup(f"{parsed_key}: {parsed_value}"))
    for key in keys:
        refs = evidence_index.get(key) or []
        if refs:
            return refs[0]
    return None


def _evidence_refs(value: Any, evidence_index: dict[str, list[str]]) -> list[str]:
    evidence_id = _first_evidence_id(value, evidence_index)
    return [evidence_id] if evidence_id else []


def _record_recovery(
    context: dict[str, Any],
    *,
    field: str,
    value: Any,
    source: str,
    source_path: str,
    confidence: str = "High",
    evidence_id: str | None = None,
    reason: str = "Recovered from deterministic merged report context.",
) -> None:
    context.setdefault("field_provenance", {})[field] = {
        "value": value,
        "source": source,
        "source_path": source_path,
        "confidence": confidence,
        "evidence_id": evidence_id,
    }
    recovered = context.setdefault("recovered_fields", [])
    key = (field, str(value), source, source_path)
    seen = {
        (item.get("field"), str(item.get("value")), item.get("recovered_from"), item.get("source_path"))
        for item in recovered
        if isinstance(item, dict)
    }
    if key not in seen:
        recovered.append({
            "field": field,
            "value": value,
            "recovered_from": source,
            "source_path": source_path,
            "confidence": confidence,
            "evidence_id": evidence_id,
            "reason": reason,
        })


def first_available(
    context: dict[str, Any],
    field: str,
    candidates: list[tuple[str, str, Any]],
    *,
    evidence_index: dict[str, list[str]] | None = None,
    default: Any = None,
    confidence: str = "High",
) -> Any:
    for source, source_path, value in candidates:
        if is_unknown(value):
            continue
        evidence_id = _first_evidence_id(value, evidence_index or {})
        _record_recovery(
            context,
            field=field,
            value=value,
            source=source,
            source_path=source_path,
            confidence=confidence,
            evidence_id=evidence_id,
        )
        return value
    return default


def _flatten_values(value: Any, prefix: str = "", limit: int = 1000) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []

    def walk(obj: Any, path: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(obj, dict):
            for key, item in obj.items():
                walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj[:100]):
                walk(item, f"{path}[{idx}]")
        elif not is_unknown(obj):
            out.append((path, obj))

    walk(value, prefix)
    return out


def _classify_ioc(value: Any, hinted_type: Any = None) -> str:
    text = _clean_text(value)
    hint = str(hinted_type or "").strip().lower()
    domain_pattern = r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
    if re.search(r"(?:^|\s)(?:[A-Za-z]:\\|\\\\|/).+\.exe(?:\s+.+)$", text, re.IGNORECASE):
        return "command_line"
    if re.search(r"(?:[A-Za-z]:\\|\\\\|/).+\.exe$", text, re.IGNORECASE):
        return "process_path"
    if re.fullmatch(r"[\w.-]+\.exe", text, re.IGNORECASE):
        return "file_name"
    if hint in {"sha256", "sha1", "md5"}:
        return hint
    if hint in {"file_hash", "hash", "hashes"}:
        if re.fullmatch(r"[a-fA-F0-9]{64}", text):
            return "sha256"
        if re.fullmatch(r"[a-fA-F0-9]{40}", text):
            return "sha1"
        if re.fullmatch(r"[a-fA-F0-9]{32}", text):
            return "md5"
        return "file_hash"
    if hint in {"destination_ip", "source_ip", "ip", "ip_address", "ips", "public_ip"}:
        return "ip"
    if hint in {"url", "urls"}:
        return "url"
    if hint in {"domain", "domains", "event_domain"} and re.fullmatch(domain_pattern, text):
        return "domain"
    if hint in {"host", "hostname", "hostnames"}:
        return "hostname"
    if hint in {"process_path", "file_path", "path"}:
        return "process_path"
    if hint in {"command_line", "cmdline", "process_command_line"}:
        return "command_line"
    if hint in {"process_name", "process", "file_name", "filename", "files"}:
        return "file_name"
    if hint in {"registry_key", "registry"}:
        return "registry_key"
    if text.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{64}", text):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", text):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", text):
        return "md5"
    if re.fullmatch(domain_pattern, text):
        return "domain"
    return hint or "indicator"


def _canonical_ioc_key(value: Any, ioc_type: str) -> str:
    text = _normalise_lookup(value)
    if ioc_type in {"sha256", "sha1", "md5", "file_hash"}:
        return f"hash:{text}"
    if ioc_type in {"destination_ip", "source_ip", "ip", "ip_address"}:
        return f"ip:{text}"
    return f"{ioc_type}:{text}"


def _looks_like_bad_file_ioc(value: Any, ioc_type: str, context: dict[str, Any]) -> bool:
    text = _clean_text(value)
    if ioc_type != "file_name":
        return False
    title = _clean_text(context.get("case_title") or get_path(context, "alert.name") or "")
    if title and text.lower() == title.lower():
        return True
    if " " in text and not re.fullmatch(r"[\w.-]+\.(?:exe|dll|ps1|bat|cmd|scr|js|vbs|bin)", text, re.IGNORECASE):
        return True
    return False


def _known_non_ioc_values(context: dict[str, Any]) -> set[str]:
    raw = context.get("raw_inputs") or {}
    values: set[str] = set()
    candidate_paths = [
        context.get("alert_id"),
        context.get("case_title"),
        get_path(context, "alert.id"),
        get_path(context, "alert.name"),
        get_path(context, "severity.label"),
        get_path(context, "confidence.label"),
    ]
    for source in raw.values():
        if not isinstance(source, dict):
            continue
        candidate_paths.extend([
            source.get("alert_id"),
            source.get("alert_title"),
            source.get("alert_name"),
            source.get("case_title"),
            source.get("title"),
            source.get("severity"),
            source.get("confidence"),
        ])
    for value in candidate_paths:
        if not is_unknown(value):
            text = _normalise_lookup(value)
            values.add(text)
            values.add(f"{text} severity")
            values.add(f"{text} confidence")
    return values


def _looks_like_user_or_account(value: Any) -> bool:
    text = _clean_text(value)
    upper = text.upper()
    if upper.startswith("NT AUTHORITY\\"):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]+\\[A-Za-z0-9$_.-]+", text):
        return True
    return False


def _looks_like_alert_id(value: Any, context: dict[str, Any]) -> bool:
    text = _clean_text(value)
    if text.upper() == _clean_text(context.get("alert_id")).upper():
        return True
    return bool(re.fullmatch(r"[A-Z]{2,}(?:-[A-Z0-9]{2,})+-\d{3,}(?:-\d+)?", text))


def _is_rejected_ioc(value: Any, ioc_type: str, context: dict[str, Any]) -> bool:
    text = _clean_text(value)
    normalised = _normalise_lookup(text)
    if not text:
        return True
    if normalised in _known_non_ioc_values(context):
        return True
    if _looks_like_alert_id(text, context):
        return True
    if _looks_like_user_or_account(text):
        return True
    if re.fullmatch(r"(critical|high|medium|low|informational)(?:\s+(?:severity|confidence))?", text, re.IGNORECASE):
        return True
    if ioc_type == "domain" and not re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", text):
        return True
    return _looks_like_bad_file_ioc(text, ioc_type, context)


def _clean_text(value: Any) -> str:
    text = str(value or "").strip()
    return " ".join(text.split())


def _source_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "Reporting Context"
    if "netwitness" in text or text in {"processed_alert", "raw_alert", "alert"}:
        return "NetWitness Alert"
    if "triage" in text:
        return "Triage Agent"
    if "investigation" in text:
        return "Investigation Agent"
    if "threat" in text or "virustotal" in text or "otx" in text or "abuseipdb" in text:
        return "Threat Intelligence Agent"
    if "approval" in text:
        return "SOC Analyst Approval"
    if "report" in text or "merged" in text or "evidence" in text:
        return "Reporting Context"
    return str(value)


def _dedupe(items: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = "|".join(str(item.get(field, "")).strip().lower() for field in key_fields)
        if not key or key in seen or all(is_unknown(item.get(field)) for field in key_fields):
            continue
        seen.add(key)
        out.append(item)
    return out


def _candidate_ioc_items(context: dict[str, Any]) -> list[tuple[Any, str | None, str, str]]:
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    candidates: list[tuple[Any, str | None, str, str]] = []

    def add(value: Any, hinted_type: str | None, source: str, source_path: str) -> None:
        for item in as_list(value):
            if isinstance(item, dict):
                item_value = first_present(
                    item.get("value"), item.get("ioc"), item.get("indicator"),
                    item.get("hash"), item.get("file_hash"), item.get("ip"), item.get("domain"),
                    default=None,
                )
                item_type = item.get("type") or item.get("ioc_type") or item.get("kind") or hinted_type
                if not is_unknown(item_value):
                    candidates.append((item_value, item_type, source, source_path))
            elif not is_unknown(item):
                candidates.append((item, hinted_type, source, source_path))

    for idx, item in enumerate(context.get("iocs") or []):
        add(item, item.get("type") if isinstance(item, dict) else None, "report_context", f"iocs[{idx}]")
    for source_name, source in [("processed_alert", processed), ("enriched_alert", enriched), ("triage_result", triage), ("investigation_result", investigation)]:
        for key in ("iocs", "matched_iocs", "extracted_iocs", "final_iocs", "indicators"):
            add(source.get(key), None, source_name, key)
        for key in ("source_ip", "destination_ip", "domain", "event_domain", "url", "sha256", "sha1", "md5", "file_hash", "process_name", "process_path", "command_line", "file_name", "registry_key", "hostname", "host"):
            add(source.get(key), key, source_name, key)
        meta = source.get("metakeys_payload") if isinstance(source.get("metakeys_payload"), dict) else {}
        for key in ("source_ip", "destination_ip", "domain", "url", "sha256", "file_name", "process_name", "process_path", "command_line", "hostname", "host"):
            add(meta.get(key), key, source_name, f"metakeys_payload.{key}")
    for group, values in (enriched.get("ioc_summary") or {}).items():
        add(values, group, "enriched_alert", f"ioc_summary.{group}")
    for item in context.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        key, value = _parse_key_value(item.get("description"))
        if key and value and key.lower() not in {"severity", "risk_score", "username", "user", "account", "execution_context", "destination_port", "protocol", "analyst_summary", "mitre_technique_id"}:
            add(value, key, "evidence", f"evidence.{item.get('id')}")
    for finding in as_list(investigation.get("findings")):
        if isinstance(finding, dict):
            for evidence_item in as_list(finding.get("evidence")):
                key, value = _parse_key_value(evidence_item)
                if key and value:
                    add(value, key, "investigation_result", "findings.evidence")
    return candidates


def _threat_intel_index(enriched: dict[str, Any]) -> dict[str, dict[str, Any]]:
    ti = enriched.get("threat_intelligence") if isinstance(enriched.get("threat_intelligence"), dict) else {}
    index: dict[str, dict[str, Any]] = {}
    source_names = {
        "virustotal": "VirusTotal",
        "abuseipdb": "AbuseIPDB",
        "alienvault_otx": "AlienVault OTX",
        "otx": "AlienVault OTX",
    }

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            indicator = first_present(obj.get("indicator"), obj.get("value"), obj.get("ioc"), default=None)
            if indicator:
                source = "Threat Intelligence"
                for token, label in source_names.items():
                    if token in path.lower():
                        source = label
                        break
                malicious = obj.get("malicious")
                suspicious = obj.get("suspicious")
                pulse_count = obj.get("pulse_count")
                abuse_score = obj.get("abuse_confidence_score")
                reputation = first_present(
                    obj.get("verdict"), obj.get("reputation"), obj.get("risk_level"),
                    f"{malicious} malicious detection(s)" if malicious not in (None, "") else None,
                    f"{pulse_count} OTX pulse(s)" if pulse_count not in (None, "") else None,
                    f"Abuse confidence {abuse_score}" if abuse_score not in (None, "") else None,
                    default=VALIDATION_PLACEHOLDER,
                )
                confidence = "High" if any(int(x or 0) > 0 for x in (malicious, suspicious, pulse_count)) else "Medium"
                if abuse_score not in (None, "") and int(abuse_score or 0) >= 50:
                    confidence = "High"
                existing = index.get(_normalise_lookup(indicator))
                entry = {"source": source, "reputation": reputation, "confidence": confidence, "source_path": path}
                if not existing or existing.get("confidence") != "High":
                    index[_normalise_lookup(indicator)] = entry
            for key, item in obj.items():
                walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{path}[{idx}]")

    walk(ti, "threat_intelligence")
    return index


def rebuild_iocs(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    # Threat Intelligence is passed explicitly via threat_intel_result.json
    # (see input_loader.py/context_builder.py) rather than assumed to have
    # survived into enriched_alert.json — that file is a separate,
    # hand-rolled harvest built at handoff time and does not reliably carry
    # the real computed threat_intelligence payload. Prefer the explicit
    # threat_intel_result; fall back to enriched_alert only for legacy
    # inputs that predate this wiring.
    ti_source = context.get("threat_intel_result") or enriched
    ti_index = _threat_intel_index(ti_source)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_candidates = 0
    links_recovered = 0
    placeholders_reduced = 0

    for value, hinted_type, source, source_path in _candidate_ioc_items(context):
        if is_unknown(value):
            continue
        total_candidates += 1
        ioc_type = _classify_ioc(value, hinted_type)
        if ioc_type in {"indicator", "mitre_technique_id"}:
            continue
        if _is_rejected_ioc(value, ioc_type, context):
            continue
        key = _canonical_ioc_key(value, ioc_type)
        if key in seen:
            continue
        seen.add(key)
        refs = _evidence_refs(value, evidence_index)
        if refs:
            links_recovered += 1
        ti = ti_index.get(_normalise_lookup(value), {})
        if ti:
            placeholders_reduced += 3
        out.append({
            "type": ioc_type,
            "value": _clean_text(value),
            "ioc": _clean_text(value),
            "source": ti.get("source") or _source_label(source),
            "confidence": ti.get("confidence") or "Observed",
            "reputation": ti.get("reputation") or "No external reputation supplied",
            "evidence": ", ".join(refs) if refs else "",
            "evidence_refs": refs,
            "source_path": ti.get("source_path") or source_path,
        })
    _bump(context, "iocs_deduplicated", max(0, total_candidates - len(out)))
    _bump(context, "evidence_links_recovered", links_recovered)
    _bump(context, "placeholders_reduced", placeholders_reduced + links_recovered)
    return out


def repair_evidence_rows(context: dict[str, Any]) -> None:
    changed = 0
    for item in context.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if is_unknown(item.get("source")):
            item["source"] = "Reporting Context"
            changed += 1
        else:
            item["source"] = _source_label(item.get("source"))
        if is_unknown(item.get("timestamp")):
            item["timestamp"] = ""
            changed += 1
        if is_unknown(item.get("confidence")):
            item["confidence"] = ""
            changed += 1
        if is_unknown(item.get("raw_reference")):
            item["raw_reference"] = ""
            changed += 1
    _bump(context, "placeholders_reduced", changed)


def _asset(hostname: Any, source: str = "Derived from ticket context", confidence: str = "High") -> dict[str, Any] | None:
    host = _clean_text(hostname)
    if is_unknown(host) or host.lower() in {"unknown-host", "localhost"}:
        return None
    return {
        "hostname": host,
        "asset": host,
        "host": host,
        "name": host,
        "ip_address": "Not Provided",
        "ip": "Not Provided",
        "asset_type": "Endpoint",
        "criticality": VALIDATION_PLACEHOLDER,
        "role": VALIDATION_PLACEHOLDER,
        "owner": OWNER_PLACEHOLDER,
        "business_function": VALIDATION_PLACEHOLDER,
        "isolation_status": VALIDATION_PLACEHOLDER,
        "status": VALIDATION_PLACEHOLDER,
        "source": source,
        "confidence": confidence,
    }


def _recover_asset_ip(context: dict[str, Any], asset: dict[str, Any], evidence_index: dict[str, list[str]]) -> str:
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    ticket = context.get("ticket") or {}
    meta = triage.get("metakeys_payload") if isinstance(triage.get("metakeys_payload"), dict) else {}
    current = first_present(asset.get("ip_address"), asset.get("ip"), default=None)
    value = first_available(context, "asset_ip", [
        ("affected_assets", "asset.ip_address", current),
        ("ticket_context", "host_ip", ticket.get("host_ip")),
        ("ticket_context", "asset_ip", ticket.get("asset_ip")),
        ("ticket_context", "endpoint_ip", ticket.get("endpoint_ip")),
        ("enriched_alert", "host_ip", enriched.get("host_ip")),
        ("enriched_alert", "source_ip", enriched.get("source_ip")),
        ("enriched_alert", "asset_ip", enriched.get("asset_ip")),
        ("enriched_alert", "endpoint_ip", enriched.get("endpoint_ip")),
        ("processed_alert", "source_ip", processed.get("source_ip")),
        ("processed_alert", "host_ip", processed.get("host_ip")),
        ("triage_result", "metakeys_payload.source_ip", meta.get("source_ip")),
        ("triage_result", "host_ip", triage.get("host_ip")),
        ("triage_result", "source_ip", triage.get("source_ip")),
        ("investigation_result", "source_ip", investigation.get("source_ip")),
        ("investigation_result", "host_ip", investigation.get("host_ip")),
    ], evidence_index=evidence_index, default=None)
    if not is_unknown(value):
        return _clean_text(value)
    for item in context.get("evidence") or []:
        key, evidence_value = _parse_key_value(item.get("description") if isinstance(item, dict) else item)
        if key and key.lower() in {"ip", "source_ip", "host_ip", "asset_ip", "endpoint_ip"} and evidence_value:
            _record_recovery(
                context,
                field="asset_ip",
                value=evidence_value,
                source="evidence",
                source_path=f"evidence.{item.get('id')}" if isinstance(item, dict) else "evidence",
                confidence="High",
                evidence_id=item.get("id") if isinstance(item, dict) else _first_evidence_id(evidence_value, evidence_index),
            )
            return _clean_text(evidence_value)
    _bump(context, "fields_still_unavailable_from_source_telemetry", 1)
    return TELEMETRY_PLACEHOLDER


def derive_affected_assets(context: dict[str, Any], ticket: dict[str, Any] | None, evidence_index: dict[str, list[str]] | None = None) -> list[dict[str, Any]]:
    evidence_index = evidence_index or {}
    assets = list(context.get("affected_assets") or [])
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    ticket = ticket or context.get("ticket") or {}

    candidates = [
        ticket.get("host"), ticket.get("hostname"), ticket.get("host_name"), ticket.get("asset"),
        enriched.get("host"), enriched.get("hostname"), enriched.get("host.name"), enriched.get("asset"), enriched.get("device"),
        processed.get("host"), processed.get("hostname"), processed.get("host.name"), processed.get("asset"),
        get_path(enriched, "ticket_context.host"), get_path(enriched, "ticket_context.hostname"),
        get_path(investigation, "available_evidence.host"), get_path(investigation, "available_evidence.hostname"),
        get_path(triage, "metakeys_payload.metakey_values.host.name"),
        get_path(triage, "raw_agent_result.ticket.host"), get_path(triage, "ticket.host"),
    ]
    for item in as_list(enriched.get("affected_assets")) + as_list(investigation.get("affected_assets")) + as_list(ticket.get("affected_assets")):
        if isinstance(item, dict):
            candidates.extend([item.get("hostname"), item.get("host"), item.get("host.name"), item.get("name")])
        else:
            candidates.append(item)
    for host in candidates:
        asset = _asset(host)
        if asset:
            assets.append(asset)

    repaired: list[dict[str, Any]] = []
    for asset in _dedupe(assets, ("hostname",)):
        if is_unknown(asset.get("ip_address")):
            ip = _recover_asset_ip(context, asset, evidence_index)
            if ip != TELEMETRY_PLACEHOLDER:
                _bump(context, "fields_recovered_from_fallback_sources", 1)
                _bump(context, "placeholders_reduced", 1)
            asset["ip_address"] = ip
            asset["ip"] = ip
        for owner_key in ("owner",):
            if is_unknown(asset.get(owner_key)):
                asset[owner_key] = OWNER_PLACEHOLDER
        for validation_key in ("criticality", "role", "business_function", "isolation_status", "status"):
            if is_unknown(asset.get(validation_key)):
                asset[validation_key] = VALIDATION_PLACEHOLDER
        repaired.append(asset)
    return repaired


def derive_affected_users(context: dict[str, Any], ticket: dict[str, Any] | None) -> list[dict[str, Any]]:
    users = list(context.get("affected_users") or [])
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    ticket = ticket or context.get("ticket") or {}
    candidates = [
        ticket.get("user"), ticket.get("username"), ticket.get("account"),
        enriched.get("user"), enriched.get("username"), enriched.get("account"),
        processed.get("user"), processed.get("username"), processed.get("account"),
        get_path(investigation, "available_evidence.user"), get_path(investigation, "available_evidence.username"),
    ]
    for user in candidates:
        if not is_unknown(user):
            username = _clean_text(user)
            users.append({
                "username": username,
                "user": username,
                "email": TELEMETRY_PLACEHOLDER,
                "role": VALIDATION_PLACEHOLDER,
                "privilege_level": VALIDATION_PLACEHOLDER,
                "groups": [],
                "mfa_status": VALIDATION_PLACEHOLDER,
                "account_status": VALIDATION_PLACEHOLDER,
            })
    repaired: list[dict[str, Any]] = []
    for user in _dedupe(users, ("username",)):
        if is_unknown(user.get("email")):
            user["email"] = TELEMETRY_PLACEHOLDER
        if is_unknown(user.get("role")):
            user["role"] = VALIDATION_PLACEHOLDER
        for key in ("privilege_level", "mfa_status", "account_status"):
            if is_unknown(user.get(key)):
                user[key] = VALIDATION_PLACEHOLDER
        repaired.append(user)
    return repaired


def _approval_decision(approval_result: dict[str, Any]) -> str:
    return str(first_present(
        approval_result.get("analyst_decision"),
        approval_result.get("decision"),
        approval_result.get("approval_status"),
        default="Not Provided",
    )).strip().lower()


def _looks_like_containment_action(value: Any) -> bool:
    text = _clean_text(value).lower()
    return bool(text) and any(token in text for token in (
        "isolate", "contain", "quarantine", "block", "disable", "disconnect", "terminate"
    ))


def _find_recommended_containment_action(context: dict[str, Any]) -> Any:
    raw = context.get("raw_inputs") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    approval = context.get("approval_result") or {}

    explicit = first_present(
        approval.get("approved_containment_action"),
        approval.get("approved_action") if _looks_like_containment_action(approval.get("approved_action")) else None,
        investigation.get("recommended_containment_action"),
        investigation.get("containment_action"),
        triage.get("recommended_containment_action"),
        triage.get("containment_action"),
        default=None,
    )
    if not is_unknown(explicit):
        return explicit

    for source in (investigation, triage, context):
        for item in as_list(source.get("containment_recommendations")) + as_list(source.get("recommended_actions")) + as_list(source.get("recommendations")):
            action = item
            if isinstance(item, dict):
                action = first_present(item.get("action"), item.get("recommendation"), item.get("title"), default=None)
            if _looks_like_containment_action(action):
                return action
    return None


def normalise_approval(context: dict[str, Any]) -> None:
    approval_result = context.get("approval_result") or {}
    triage = context.get("triage") or {}
    approval = context.setdefault("approval", {})
    containment = context.setdefault("containment", {})

    decision = _approval_decision(approval_result)
    analyst_name = first_present(approval_result.get("analyst"), approval_result.get("approved_by"), approval_result.get("reviewed_by"), default="SOC Analyst")

    approval_gate = first_present(approval_result.get("approval_gate"), approval_result.get("approval_type"), default=None)
    recommended_containment = _find_recommended_containment_action(context)

    if decision in {"approved", "approve", "accepted", "accept"}:
        approval["approval_status"] = "approved"
        approval["analyst_decision"] = "approved"
        approval["approved_by"] = analyst_name
        context["approval_status"] = "approved"
        context["analyst_decision"] = "approved"
    elif decision in {"rejected", "reject", "declined", "deny", "denied"}:
        approval["approval_status"] = "rejected"
        approval["analyst_decision"] = "rejected"
        approval["approved_by"] = analyst_name
        context["approval_status"] = "rejected"
        context["analyst_decision"] = "rejected"
        containment["status"] = "rejected"
        containment["execution_status"] = "not_executed"
        context["containment_status"] = "rejected"
    else:
        approval["approval_status"] = first_present(approval.get("approval_status"), triage.get("soc_analyst_approval_status"), default="pending")
        approval["analyst_decision"] = first_present(approval.get("analyst_decision"), default="pending")
        approval["approved_by"] = first_present(approval.get("approved_by"), default="")
        context["approval_status"] = approval["approval_status"]
        context["analyst_decision"] = approval["analyst_decision"]

    approval["analyst_comments"] = first_present(approval_result.get("comments"), approval_result.get("analyst_comments"), approval.get("analyst_comments"), default="No approval comments supplied.")
    approval["approval_type"] = first_present(approval_result.get("approval_type"), approval_gate, default="")
    approval["approved_action"] = first_present(approval_result.get("approved_action"), approval_result.get("approved_containment_action"), default="")

    is_containment_approval = any(token in str(approval_gate or "").lower() for token in ("containment", "response_action"))
    is_report_approval = any(token in str(approval_gate or "").lower() for token in ("report", "investigation", "evidence_gap"))

    final_review_status = first_present(
        approval_result.get("final_analyst_review_status"),
        approval_result.get("analyst_review_status"),
        context.get("final_analyst_review_status") if _analyst_review_completed(context) else None,
        default="Requires final analyst review",
    )
    if str(final_review_status).strip().lower() in {"approved", "confirmed", "completed", "closed", "reviewed", "final_review_completed"}:
        context["final_analyst_review_status"] = final_review_status
    else:
        context["final_analyst_review_status"] = "Requires final analyst review"

    report_generation_status = approval["approval_status"] if is_report_approval or not is_containment_approval else ""
    context["report_generation_approval"] = {
        "status": report_generation_status,
        "approved_by": approval.get("approved_by", ""),
        "approval_gate": approval_gate or "",
        "comments": approval.get("analyst_comments", ""),
    }
    approval["report_generation_approval_status"] = report_generation_status
    approval["report_generation_approved_by"] = approval.get("approved_by", "")
    approval["final_analyst_review_status"] = context["final_analyst_review_status"]
    containment["recommended_action"] = first_present(containment.get("recommended_action"), recommended_containment, default="")
    containment["approval_status"] = first_present(
        approval_result.get("containment_approval_status"),
        approval_result.get("containment_status") if is_containment_approval else None,
        default="approved" if is_containment_approval and decision in {"approved", "approve", "accepted", "accept"} else "Pending analyst approval" if _looks_like_containment_action(recommended_containment) else "not_required",
    )
    execution = first_present(
        approval_result.get("containment_execution_status"),
        approval_result.get("execution_status"),
        context.get("containment_execution_status"),
        default=None,
    )
    containment["execution_status"] = execution if not is_unknown(execution) else "not_contained"
    containment["status"] = first_present(containment.get("status"), triage.get("containment_status"), default=containment["execution_status"])
    if str(containment["status"]).lower() in {"approved_pending_execution", "pending_execution"}:
        containment["status"] = "not_contained"
    context["containment_status"] = containment["status"]
    context["containment_approval_status"] = containment["approval_status"]
    context["containment_execution_status"] = containment["execution_status"]
    context["approval_type_validation_note"] = "" if approval.get("approval_type") else "Approval record exists, but approval type requires analyst validation."
    approval["approval_required"] = first_present(
        approval.get("approval_required"),
        approval_result.get("approval_required"),
        "Yes" if _looks_like_containment_action(recommended_containment) else "No",
        default="",
    )


def replace_low_value_placeholders(context: dict[str, Any]) -> None:
    severity = context.get("severity") if isinstance(context.get("severity"), dict) else {}
    confidence = context.get("confidence") if isinstance(context.get("confidence"), dict) else {}
    if is_unknown(severity.get("reason")):
        severity["reason"] = "No explicit severity rationale was supplied; validate against triage and investigation evidence."
    if is_unknown(confidence.get("reason")):
        confidence["reason"] = "No explicit confidence rationale was supplied; validate against evidence completeness and source telemetry."
    context["severity"] = severity
    context["confidence"] = confidence

    replacements = {
        "business_owner": "",
        "technical_owner": "",
        "rule_id": "",
        "initial_risk_score": "",
        "enrichment_risk_score": "",
        "malware_family": "",
        "threat_actor": "",
        "scenario_type": "Requires analyst validation",
        "triage_summary": "No standalone triage summary was supplied.",
        "investigation_summary": "No standalone investigation summary was supplied.",
    }
    for key, replacement in replacements.items():
        if is_unknown(context.get(key)):
            context[key] = replacement

    root_cause = context.get("root_cause") if isinstance(context.get("root_cause"), dict) else {}
    if is_unknown(root_cause.get("category")):
        root_cause["category"] = "Requires analyst validation"
    context["root_cause"] = root_cause

    alert = context.get("alert") if isinstance(context.get("alert"), dict) else {}
    if is_unknown(alert.get("timestamp")):
        alert["timestamp"] = ""
    context["alert"] = alert


def _timeline_event(time_value: Any, event: str, source: str, evidence_refs: list[str] | None = None) -> dict[str, Any] | None:
    if is_unknown(time_value) and is_unknown(event):
        return None
    return {
        "time": first_present(time_value, default=""),
        "timestamp": first_present(time_value, default=""),
        "event": event,
        "description": event,
        "source": source,
        "evidence_refs": evidence_refs or [],
        "significance": "Supports analyst timeline reconstruction.",
    }


def _is_placeholder_timeline_event(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    event = first_present(item.get("event"), item.get("description"), default="")
    return bool(re.fullmatch(r"Timeline event \d+", str(event).strip(), re.IGNORECASE))


def derive_timeline(context: dict[str, Any]) -> list[dict[str, Any]]:
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    approval_result = context.get("approval_result") or {}
    timeline = list(context.get("timeline") or [])

    candidates = [
        _timeline_event(first_present(enriched.get("first_seen"), enriched.get("firstAlertTime"), enriched.get("alert_timestamp"), processed.get("timestamp"), default=None), "Alert first observed by monitoring source", first_present(context.get("alert", {}).get("source"), default="NetWitness"), ["enriched_alert"]),
        _timeline_event(triage.get("created_at"), "Triage completed and severity/confidence assigned", "Triage Agent", ["triage_result.json"]),
        _timeline_event(investigation.get("created_at"), "Investigation completed or completed with limitations", "Investigation Agent", ["investigation_result.json"]),
        _timeline_event(approval_result.get("created_at"), "SOC analyst approval decision recorded", "SOC Analyst", ["approval_result.json"]),
        _timeline_event(context.get("created_at") or context.get("generated_at"), "Report generated for SOC analyst review", "Reporting Agent", ["final_report"]),
    ]
    for item in candidates:
        if item:
            timeline.append(item)

    activity_log = get_path(enriched, "ticket_context.activity_log", []) or get_path(context.get("ticket"), "activity_log", []) or []
    for item in as_list(activity_log):
        if not isinstance(item, dict):
            continue
        event = first_present(item.get("message"), item.get("action"), default="Ticket activity recorded")
        timeline.append({
            "time": first_present(item.get("created_at"), item.get("timestamp"), default=""),
            "timestamp": first_present(item.get("created_at"), item.get("timestamp"), default=""),
            "event": event,
            "description": event,
            "source": first_present(item.get("actor"), default="Ticket Workflow"),
            "evidence_refs": ["ticket_activity_log"],
            "significance": "Ticket workflow event used for case reconstruction.",
        })

    deduped = _dedupe(timeline, ("time", "event"))
    better_events = [item for item in deduped if not _is_placeholder_timeline_event(item)]
    if better_events:
        return better_events
    return deduped


def _apply_field_provenance(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> None:
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    approval = context.get("approval_result") or {}
    ticket = context.get("ticket") or {}
    triage_meta = triage.get("metakeys_payload") if isinstance(triage.get("metakeys_payload"), dict) else {}
    fields = {
        "host": [
            ("enriched_alert", "host", enriched.get("host")),
            ("enriched_alert", "hostname", enriched.get("hostname")),
            ("triage_result", "metakeys_payload.host", triage_meta.get("host")),
            ("processed_alert", "hostname", processed.get("hostname")),
            ("ticket_context", "host", ticket.get("host")),
        ],
        "source_ip": [
            ("enriched_alert", "source_ip", enriched.get("source_ip")),
            ("triage_result", "metakeys_payload.source_ip", triage_meta.get("source_ip")),
            ("processed_alert", "source_ip", processed.get("source_ip")),
        ],
        "destination_ip": [
            ("enriched_alert", "destination_ip", enriched.get("destination_ip")),
            ("triage_result", "metakeys_payload.destination_ip", triage_meta.get("destination_ip")),
            ("processed_alert", "destination_ip", processed.get("destination_ip")),
        ],
        "domain": [
            ("enriched_alert", "domain", enriched.get("domain")),
            ("enriched_alert", "event_domain", enriched.get("event_domain")),
            ("triage_result", "metakeys_payload.domain", triage_meta.get("domain")),
        ],
        "url": [
            ("enriched_alert", "url", enriched.get("url")),
            ("triage_result", "metakeys_payload.url", triage_meta.get("url")),
            ("processed_alert", "url", processed.get("url")),
        ],
        "sha256": [
            ("enriched_alert", "sha256", enriched.get("sha256")),
            ("enriched_alert", "file_hash", enriched.get("file_hash")),
            ("triage_result", "metakeys_payload.sha256", triage_meta.get("sha256")),
            ("processed_alert", "file_hash", processed.get("file_hash")),
        ],
        "process_name": [
            ("enriched_alert", "process_name", enriched.get("process_name")),
            ("enriched_alert", "file_name", enriched.get("file_name")),
            ("triage_result", "metakeys_payload.file_name", triage_meta.get("file_name")),
        ],
        "process_path": [
            ("enriched_alert", "process_path", enriched.get("process_path")),
            ("enriched_alert", "command_line", enriched.get("command_line")),
        ],
        "mitre_technique_id": [
            ("enriched_alert", "mitre_technique_id", enriched.get("mitre_technique_id")),
            ("triage_result", "metakeys_payload.mitre_technique_id", triage_meta.get("mitre_technique_id")),
            ("investigation_result", "mitre_technique_id", investigation.get("mitre_technique_id")),
        ],
        "severity": [
            ("investigation_result", "severity", investigation.get("severity")),
            ("triage_result", "severity", triage.get("severity")),
            ("enriched_alert", "severity", enriched.get("severity")),
        ],
        "confidence": [
            ("investigation_result", "confidence", investigation.get("confidence")),
            ("triage_result", "confidence", triage.get("confidence")),
            ("enriched_alert", "confidence", enriched.get("confidence")),
        ],
        "classification": [
            ("investigation_result", "classification", investigation.get("classification")),
            ("triage_result", "classification", triage.get("classification")),
            ("approval_result", "classification", approval.get("classification")),
        ],
        "approval_status": [
            ("approval_result", "approval_status", approval.get("approval_status")),
            ("approval_result", "decision", approval.get("decision")),
            ("triage_result", "soc_analyst_approval_status", triage.get("soc_analyst_approval_status")),
        ],
        "analyst_decision": [
            ("approval_result", "analyst_decision", approval.get("analyst_decision")),
            ("approval_result", "decision", approval.get("decision")),
        ],
        "approved_by": [
            ("approval_result", "analyst", approval.get("analyst")),
            ("approval_result", "approved_by", approval.get("approved_by")),
            ("approval_result", "reviewed_by", approval.get("reviewed_by")),
        ],
        "containment_status": [
            ("approval_result", "containment_status", approval.get("containment_status")),
            ("triage_result", "containment_status", triage.get("containment_status")),
        ],
        "recommended_containment_action": [
            ("approval_result", "approved_action", approval.get("approved_action")),
            ("triage_result", "containment_action", triage.get("containment_action")),
            ("triage_result", "recommended_containment_action", triage.get("recommended_containment_action")),
            ("investigation_result", "containment_action", investigation.get("containment_action")),
            ("investigation_result", "recommended_containment_action", investigation.get("recommended_containment_action")),
            ("approval_result", "approved_containment_action", approval.get("approved_containment_action")),
        ],
        "containment_execution_status": [
            ("approval_result", "containment_execution_status", approval.get("containment_execution_status")),
        ],
    }
    for field, candidates in fields.items():
        first_available(context, field, candidates, evidence_index=evidence_index, default=None)


def _mitre_candidates(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    raw = context.get("raw_inputs") or {}
    sources = [
        ("context", context),
        ("enriched_alert", raw.get("enriched_alert") or {}),
        ("triage_result", raw.get("triage_result") or context.get("triage") or {}),
        ("investigation_result", raw.get("investigation_result") or context.get("investigation") or {}),
    ]
    found: dict[str, dict[str, Any]] = {}

    for source_name, source in sources:
        meta = source.get("metakeys_payload") if isinstance(source, dict) and isinstance(source.get("metakeys_payload"), dict) else {}
        technique_name = first_present(source.get("mitre_technique"), meta.get("mitre_technique"), source.get("technique_name"), default="")
        for path, value in _flatten_values(source, source_name):
            for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(value)):
                entry = found.setdefault(technique_id, {
                    "tactic": first_present(source.get("mitre_tactic"), meta.get("mitre_tactic"), default=VALIDATION_PLACEHOLDER),
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "reason": "Recovered from deterministic report context.",
                    "confidence": "High",
                    "evidence_refs": _evidence_refs(technique_id, evidence_index),
                    "source": source_name,
                    "source_path": path,
                })
                if not entry.get("technique_name") and technique_name:
                    entry["technique_name"] = technique_name
        direct = first_present(source.get("mitre_technique_id"), meta.get("mitre_technique_id"), default=None)
        if direct:
            for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(direct)):
                found.setdefault(technique_id, {
                    "tactic": first_present(source.get("mitre_tactic"), meta.get("mitre_tactic"), default=VALIDATION_PLACEHOLDER),
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "reason": "Recovered from deterministic report context.",
                    "confidence": "High",
                    "evidence_refs": _evidence_refs(technique_id, evidence_index),
                    "source": source_name,
                    "source_path": "mitre_technique_id",
                })
    for item in context.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get("description") or "")
        for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text):
            found.setdefault(technique_id, {
                "tactic": VALIDATION_PLACEHOLDER,
                "technique_id": technique_id,
                "technique_name": "",
                "reason": f"Evidence register contains {technique_id}.",
                "confidence": "High",
                "evidence_refs": [item.get("id")],
                "source": "evidence",
                "source_path": f"evidence.{item.get('id')}",
            })
    return list(found.values())


def _normalise_mitre_item(item: dict[str, Any], evidence_index: dict[str, list[str]], context: dict[str, Any]) -> dict[str, Any] | None:
    technique_id = first_present(item.get("technique_id"), item.get("technique"), default="")
    match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", str(technique_id))
    if not match:
        return None
    technique_id = match.group(0)
    refs = as_list(item.get("evidence_refs")) or _evidence_refs(technique_id, evidence_index)
    if refs and not item.get("evidence_refs"):
        _bump(context, "evidence_links_recovered", 1)
    mapped = MITRE_LOCAL_MAPPING.get(technique_id)
    tactic = item.get("tactic")
    technique_name = first_present(item.get("technique_name"), item.get("name"), default="")
    if mapped:
        tactic = mapped["tactic"]
        technique_name = mapped["technique_name"]
    return {
        **item,
        "tactic": first_present(tactic, default=VALIDATION_PLACEHOLDER),
        "technique_id": technique_id,
        "technique_name": technique_name,
        "reason": first_present(item.get("reason"), default="Recovered from deterministic report context."),
        "confidence": first_present(item.get("confidence"), default=VALIDATION_PLACEHOLDER),
        "evidence_refs": refs,
    }


def repair_mitre_mapping(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    existing = context.get("mitre_attack_mapping") or context.get("mitre_mapping") or []
    recovered = _mitre_candidates(context, evidence_index)
    repaired: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in as_list(existing) + recovered:
        if not isinstance(item, dict):
            continue
        normalised = _normalise_mitre_item(item, evidence_index, context)
        if not normalised:
            continue
        technique_id = normalised["technique_id"]
        if technique_id in seen:
            existing_item = next((row for row in repaired if row.get("technique_id") == technique_id), None)
            if existing_item is not None and not existing_item.get("evidence_refs") and normalised.get("evidence_refs"):
                existing_item["evidence_refs"] = normalised["evidence_refs"]
            continue
        seen.add(technique_id)
        repaired.append(normalised)
    if repaired:
        if not existing:
            _bump(context, "fields_recovered_from_fallback_sources", len(repaired))
            _bump(context, "placeholders_reduced", len(repaired))
        return repaired
    return []


def _refs_for_text(text: Any, evidence_index: dict[str, list[str]]) -> list[str]:
    refs: list[str] = []
    for key, linked in evidence_index.items():
        if key and key in _normalise_lookup(text):
            for ref in linked:
                if ref not in refs:
                    refs.append(ref)
    return refs[:5]


def _all_evidence_ids(context: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for item in context.get("evidence") or []:
        if isinstance(item, dict) and item.get("id"):
            ids.append(str(item["id"]))
    return ids


def _fallback_recommendation_refs(context: dict[str, Any]) -> list[str]:
    preferred = {"EV-003", "EV-006", "EV-010", "EV-013", "EV-015"}
    available = _all_evidence_ids(context)
    refs = [ref for ref in available if ref in preferred]
    return refs[:3] or available[:3] or ["investigation_result.json"]


def _recommendation_owner(action: str) -> str:
    text = action.lower()
    if any(token in text for token in ("endpoint", "host", "isolate", "quarantine", "process", "file", "malware")):
        return "Endpoint Response Team"
    if any(token in text for token in ("network", "firewall", "proxy", "dns", "ip", "domain", "url", "block", "traffic")):
        return "Network Security Team"
    if any(token in text for token in ("review", "validate", "hunt", "document", "escalate", "evidence", "confirm")):
        return "SOC Analyst"
    return OWNER_PLACEHOLDER


def _recommendation_approval_required(action: str) -> str:
    text = action.lower()
    if any(token in text for token in ("isolate", "contain", "block", "disable", "quarantine", "disconnect", "terminate", "remove")):
        return "Yes"
    if any(token in text for token in ("validate", "review", "hunt", "document", "collect", "confirm", "search")):
        return "No"
    return "No"


def _recommendation_risk(action: str) -> str:
    text = action.lower()
    if any(token in text for token in ("isolate", "contain", "endpoint", "host", "malware", "file", "process")):
        return "Endpoint compromise or malware execution"
    if any(token in text for token in ("network", "block", "ip", "domain", "url", "traffic", "dns", "proxy", "firewall")):
        return "Potential malicious network activity"
    if any(token in text for token in ("validate", "review", "evidence", "document", "confirm")):
        return "Unvalidated incident scope and evidence completeness"
    return "Incident response follow-up"


def _recommendation_rationale(action: str, context: dict[str, Any], refs: list[str]) -> str:
    severity = get_path(context, "severity.label", "Not Provided")
    classification = context.get("classification", "Not Provided")
    asset = first_present(*(a.get("hostname") for a in context.get("affected_assets") or [] if isinstance(a, dict)), default="affected asset")
    ioc_count = len(context.get("iocs") or [])
    ref_text = ", ".join(refs)
    return (
        f"Based on {severity} severity, {classification} classification, {asset} scope, "
        f"and {ioc_count} technical indicator(s) linked to evidence ({ref_text})."
    )


def enrich_recommendations(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for idx, item in enumerate(as_list(context.get("recommended_actions") or context.get("recommendations")), start=1):
        if not isinstance(item, dict):
            item = {"priority": f"P{idx}", "recommendation": str(item), "action": str(item)}
        action = first_present(item.get("action"), item.get("recommendation"), item.get("title"), default=f"Recommendation {idx}")
        refs = as_list(item.get("evidence_refs")) or _refs_for_text(action, evidence_index) or _fallback_recommendation_refs(context)
        owner = first_present(item.get("owner"), default=_recommendation_owner(action))
        if is_unknown(owner):
            owner = _recommendation_owner(action)
        approval_required = first_present(item.get("approval_required"), default=_recommendation_approval_required(action))
        if is_unknown(approval_required):
            approval_required = _recommendation_approval_required(action)
        risk_addressed = first_present(item.get("risk_addressed"), item.get("risk"), default=_recommendation_risk(action))
        rationale = first_present(item.get("rationale"), default=_recommendation_rationale(action, context, refs))
        if is_unknown(rationale):
            rationale = _recommendation_rationale(action, context, refs)
        enriched.append({
            **item,
            "priority": first_present(item.get("priority"), default=f"P{idx}"),
            "recommendation": action,
            "action": action,
            "owner": owner,
            "status": first_present(item.get("status"), default="Open for analyst review"),
            "rationale": rationale,
            "approval_required": approval_required,
            "risk_addressed": risk_addressed,
            "target_date": first_present(item.get("target_date"), default=""),
            "evidence_refs": refs,
        })
    context["recommendations"] = enriched
    context["recommended_actions"] = enriched
    context["management_action_plan"] = enriched
    return enriched


def build_compact_render_tables(context: dict[str, Any]) -> dict[str, Any]:
    assets = context.get("affected_assets") or []
    users = context.get("affected_users") or []
    iocs = context.get("iocs") or []
    timeline = context.get("timeline") or []
    mitre = context.get("mitre_attack_mapping") or []
    recommendations = context.get("recommended_actions") or []
    gaps = context.get("evidence_gaps") or []

    tables = {
        "assets": compact_table(
            ["Hostname", "IP Address", "Type", "Criticality", "Owner", "Business Function", "Isolation Status"],
            [[a.get("hostname"), a.get("ip_address"), a.get("asset_type"), a.get("criticality"), a.get("owner"), a.get("business_function"), a.get("isolation_status")] for a in assets if isinstance(a, dict)],
            "Affected assets",
            gaps,
        ),
        "users": compact_table(
            ["Username", "Email", "Role", "Privilege", "Groups", "MFA", "Status"],
            [[u.get("username"), u.get("email"), u.get("role"), u.get("privilege_level"), ", ".join(as_list(u.get("groups"))), u.get("mfa_status"), u.get("account_status")] for u in users if isinstance(u, dict)],
            "Affected users",
            gaps,
        ),
        "iocs": compact_table(
            ["IOC", "Type", "Reputation", "Confidence", "Source", "Evidence"],
            [[f"`{i.get('value')}`", i.get("type"), i.get("reputation"), i.get("confidence"), i.get("source"), ", ".join(as_list(i.get("evidence_refs")))] for i in iocs if isinstance(i, dict)],
            "IOC analysis",
            gaps,
        ),
        "timeline": compact_table(
            ["Time", "Event", "Source", "Evidence", "Significance"],
            [[e.get("time") or e.get("timestamp"), e.get("event") or e.get("description"), e.get("source"), ", ".join(as_list(e.get("evidence_refs"))), e.get("significance")] for e in timeline if isinstance(e, dict)],
            "Incident timeline",
            gaps,
        ),
        "mitre": compact_table(
            ["Tactic", "Technique", "Reason / Evidence", "Confidence"],
            [[m.get("tactic"), " ".join(str(x) for x in [m.get("technique_id"), m.get("technique_name")] if x), m.get("reason") or ", ".join(as_list(m.get("evidence_refs"))), m.get("confidence")] for m in mitre if isinstance(m, dict)],
            "MITRE ATT&CK mapping",
            gaps,
        ),
        "recommendations": compact_table(
            ["Priority", "Action", "Owner", "Approval Required", "Rationale"],
            [[r.get("priority"), r.get("action") or r.get("recommendation"), r.get("owner"), r.get("approval_required"), r.get("rationale")] for r in recommendations if isinstance(r, dict)],
            "Recommended actions",
            gaps,
        ),
    }
    return tables


def _number_or_none(value: Any) -> float | None:
    try:
        if is_unknown(value):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _analyst_review_completed(context: dict[str, Any]) -> bool:
    review = str(first_present(context.get("final_analyst_review_status"), context.get("analyst_review_status"), default="")).lower()
    return review in {"approved", "confirmed", "completed", "closed", "reviewed", "final_review_completed"}


def set_report_title(context: dict[str, Any]) -> None:
    report_status = str(context.get("report_status") or "").lower()
    validation_status = str(context.get("validation_status") or "").lower()
    score = _number_or_none(first_present(context.get("report_completeness_score"), context.get("report_quality_score"), default=None))
    draft_required = (
        report_status == "generated for analyst review"
        or "requires analyst validation" in validation_status
        or score is None
        or score < 80
        or not _analyst_review_completed(context)
    )
    context["report_title"] = "Draft Incident Report for SOC Analyst Review" if draft_required else "Final Incident Report"


def _count_placeholders(value: Any, *, key: str = "") -> int:
    if key in {"raw_inputs", "evidence_index", "field_provenance", "recovered_fields"}:
        return 0
    if isinstance(value, dict):
        return sum(_count_placeholders(item, key=str(item_key)) for item_key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return sum(_count_placeholders(item, key=key) for item in value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in PLACEHOLDER_VALUES:
            return 1
        return sum(1 for placeholder in PLACEHOLDER_VALUES if placeholder in normalised)
    return 0


def finalise_quality_counters(context: dict[str, Any]) -> None:
    checks = _quality(context)
    placeholder_count = _count_placeholders(context)
    checks["final_placeholder_count"] = placeholder_count
    checks["fields_still_unavailable_from_source_telemetry"] = placeholder_count


def finalise_section_placeholder_counts(context: dict[str, Any]) -> None:
    compact_tables = context.get("compact_tables") or {}
    hidden_columns = sum(len((table or {}).get("hidden_columns") or []) for table in compact_tables.values() if isinstance(table, dict))
    hidden_rows = sum(int((table or {}).get("hidden_rows") or 0) for table in compact_tables.values() if isinstance(table, dict))
    evidence_register = context.get("compact_evidence_register") or {}
    section_map = {
        "evidence_register_placeholders": evidence_register.get("placeholder_ratio", 0),
        "approval_section_placeholders": 0,
        "containment_section_placeholders": 0,
        "data_impact_placeholders": 1.0 if context.get("data_impact_summary") else 0.0,
        "chain_of_custody_placeholders": 1.0 if context.get("chain_of_custody_compact") else 0.0,
        "columns_hidden_due_to_low_information_value": hidden_columns + len(evidence_register.get("hidden_columns") or []),
        "rows_hidden_due_to_no_useful_values": hidden_rows + int(evidence_register.get("hidden_rows") or 0),
        "missing_fields_summarised_into_evidence_gaps": len(context.get("evidence_gaps") or []),
        "ai_narrative_sections_used_to_reduce_placeholder_repetition": len([k for k, v in (context.get("llm_section_results") or {}).items() if isinstance(v, dict) and str(v.get("status", "")).startswith("llm")]),
    }
    approval = context.get("approval") or {}
    containment = context.get("containment") or {}
    section_map["approval_section_placeholders"] = count_placeholders(approval) / max(1, len(approval))
    section_map["containment_section_placeholders"] = count_placeholders(containment) / max(1, len(containment))
    context.setdefault("quality_checks", {}).update(section_map)


def build_appendix_summaries(context: dict[str, Any]) -> dict[str, Any]:
    triage = context.get("triage") or {}
    investigation = context.get("investigation") or {}
    approval_result = context.get("approval_result") or {}
    alert = context.get("alert") or {}
    assets = context.get("affected_assets") or []
    iocs = context.get("iocs") or []
    recommendations = context.get("recommended_actions") or []
    gaps = context.get("evidence_gaps") or []

    first_asset = assets[0].get("hostname") if assets else ""
    first_ioc = iocs[0].get("value") if iocs else ""

    return {
        "raw_alert": {
            "Alert ID": context.get("alert_id"),
            "Source": alert.get("source"),
            "Alert Name": alert.get("name"),
            "First Seen": alert.get("timestamp"),
            "Host": first_asset,
            "Severity": get_path(context, "severity.label", ""),
            "Confidence": get_path(context, "confidence.label", ""),
            "Original Alert Risk Score": first_present(context.get("original_alert_risk_score"), context.get("initial_risk_score"), default=""),
            "Enriched Risk Score": first_present(context.get("enriched_risk_score"), context.get("enrichment_risk_score"), default=""),
            "Final Risk Rating": first_present(context.get("final_risk_rating"), get_path(context, "severity.label", ""), default=""),
            "Primary IOC": first_ioc,
        },
        "triage": {
            "Classification": first_present(triage.get("classification"), context.get("classification")),
            "Severity": get_path(context, "severity.label", ""),
            "Confidence": get_path(context, "confidence.label", ""),
            "Next Action": first_present(triage.get("next_action"), default="No standalone next action supplied."),
            "Containment Status": context.get("containment_status"),
            "Recommended Action Count": len(recommendations),
        },
        "investigation": {
            "Classification": context.get("classification"),
            "Likely Scenario": context.get("likely_scenario"),
            "Status": first_present(investigation.get("status"), default=""),
            "Finding Count": len(as_list(investigation.get("findings"))),
            "Missing Evidence": ", ".join(str(g.get("gap", g)) for g in gaps) if gaps else "None recorded",
            "Recommended Next Action": first_present(investigation.get("recommended_next_action"), default="No standalone investigation next action supplied."),
        },
        "approval": {
            "Report Generation Approval Status": get_path(context, "report_generation_approval.status", ""),
            "Report Generation Approved By": get_path(context, "report_generation_approval.approved_by", ""),
            "Containment Approval Status": get_path(context, "containment.approval_status", ""),
            "Containment Execution Status": get_path(context, "containment.execution_status", ""),
            "Final Analyst Review Status": context.get("final_analyst_review_status", ""),
            "Comments": first_present(approval_result.get("comments"), approval_result.get("analyst_comments"), default="No approval comments supplied."),
        },
    }


def apply_llm_narrative(context: dict[str, Any]) -> None:
    llm_result = enhance_narrative(context)
    enhanced = llm_result.get("llm_enhanced_narrative") or llm_result.get("deterministic_narrative") or {}
    active = context.setdefault("active_narrative", {})
    mapping = {
        "executive_summary": "executive_summary",
        "technical_analysis": "technical_analysis",
        "business_impact_explanation": "business_impact_explanation",
        "attack_narrative": "attack_narrative",
        "conclusion": "conclusion",
        "analyst_friendly_explanation": "analyst_friendly_explanation",
        "soc_analyst_review_checklist": "soc_analyst_review_checklist",
    }
    for source_key, target_key in mapping.items():
        if not is_unknown(enhanced.get(source_key)):
            active[target_key] = enhanced[source_key]
            context[target_key] = enhanced[source_key]

    context["llm"] = enhanced
    context["llm_used"] = bool(llm_result.get("llm_used"))
    context["llm_provider"] = llm_result.get("llm_provider", "not_used")
    context["llm_model"] = llm_result.get("llm_model", "not_used")
    context["llm_status"] = llm_result.get("llm_status", "not_used")
    context["llm_status_display"] = llm_result.get("llm_status", "not_used")
    context["llm_quality_status"] = llm_result.get("llm_quality_status", "not_used")
    context["llm_quality_issues"] = llm_result.get("llm_quality_issues", [])
    context["llm_section_results"] = llm_result.get("llm_section_results", {})
    context["llm_attempt_count"] = llm_result.get("llm_attempt_count", 0)
    context["llm_cache_status"] = llm_result.get("llm_cache_status", "not_used")
    context["llm_cache_status_display"] = llm_result.get("llm_cache_status", "not_used")
    context["llm_status_explanation"] = (
        "LLM narrative fields generated from locked incident facts."
        if context["llm_used"] else
        "LLM disabled or unavailable; deterministic fallback narrative was used."
    )
    context["report_generation_mode"] = "deterministic_facts_plus_llm_narrative" if context["llm_used"] else "deterministic_facts_plus_template_export"
    checks = context.setdefault("quality_checks", {})
    if not context["llm_used"] or checks.get("fallback_logic_used") == "Yes":
        checks["fallback_logic_used"] = "Yes"
    else:
        checks["fallback_logic_used"] = "No"


def build_readable_narrative_sections(context: dict[str, Any]) -> None:
    """Pre-split long free-text narrative fields into presentation-ready
    lists so templates can render bullets/tables instead of dense paragraphs.
    Does not alter any narrative wording — only how it is broken up for
    display in the exported report."""
    active = context.get("active_narrative") or {}
    context["analyst_guidance_bullets"] = split_into_sentences(
        active.get("analyst_friendly_explanation"))
    context["soc_analyst_review_checklist_items"] = split_numbered_items(
        active.get("soc_analyst_review_checklist"))


def enhance_export_context(context: dict[str, Any], ticket: dict[str, Any] | None = None) -> dict[str, Any]:
    ticket = ticket or context.get("ticket") or {}
    _quality(context)
    evidence_index = build_evidence_index(context.get("evidence") or [])
    context["evidence_index"] = evidence_index
    repair_evidence_rows(context)
    _apply_field_provenance(context, evidence_index)

    ticket_id = first_present(ticket.get("ticket_id"), context.get("ticket_id"), context.get("incident_id"), default="unknown")
    if is_unknown(context.get("incident_id")):
        context["incident_id"] = ticket_id
    context["ticket_id"] = ticket_id
    if not is_unknown(ticket.get("title")):
        context["case_title"] = ticket.get("title")

    context["affected_assets"] = derive_affected_assets(context, ticket, evidence_index)
    context["affected_users"] = derive_affected_users(context, ticket)
    context["iocs"] = rebuild_iocs(context, evidence_index)
    mitre_mapping = repair_mitre_mapping(context, evidence_index)
    context["mitre_mapping"] = mitre_mapping
    context["mitre_attack_mapping"] = mitre_mapping
    context["timeline"] = derive_timeline(context)
    normalise_approval(context)
    replace_low_value_placeholders(context)
    enrich_recommendations(context, evidence_index)
    set_report_title(context)

    # Rebuild findings after factual correction.
    confidence_label = get_path(context, "confidence.label", "Not Provided")
    classification = context.get("classification", "Not Provided")
    asset_refs: list[str] = []
    for asset in context.get("affected_assets") or []:
        asset_refs.extend(_evidence_refs(asset.get("hostname"), evidence_index))
        asset_refs.extend(_evidence_refs(asset.get("ip_address"), evidence_index))
    asset_refs = list(dict.fromkeys(asset_refs))
    classification_refs = _refs_for_text(classification, evidence_index) or ["investigation_result.json"]
    approval_refs = ["approval_result.json"]
    context["evidence_backed_findings"] = [
        {"finding_id": "KF-001", "statement": f"The incident classification is {classification}.", "finding": f"The incident classification is {classification}.", "status": "Fact", "confidence": confidence_label, "evidence_refs": classification_refs, "evidence": ", ".join(classification_refs), "interpretation": "Classification is taken from investigation output first, with triage as fallback."},
        {"finding_id": "KF-002", "statement": "Affected scope has available context." if context["affected_assets"] or context["affected_users"] else "Affected scope requires validation.", "finding": "Affected scope has available context." if context["affected_assets"] or context["affected_users"] else "Affected scope requires validation.", "status": "Fact" if context["affected_assets"] or context["affected_users"] else "Evidence Gap", "confidence": confidence_label, "evidence_refs": asset_refs or ["enriched_alert", "investigation_result.json"], "evidence": ", ".join(asset_refs or ["enriched_alert", "investigation_result.json"]), "interpretation": "Assets and users are derived only from supplied ticket, alert, triage, and investigation context."},
        {"finding_id": "KF-003", "statement": f"Approval status is {get_path(context, 'approval.approval_status', 'Not Provided')}.", "finding": f"Approval status is {get_path(context, 'approval.approval_status', 'Not Provided')}.", "status": "Fact", "confidence": confidence_label, "evidence_refs": approval_refs, "evidence": ", ".join(approval_refs), "interpretation": "Approval data is recorded only from analyst approval context."},
    ]
    if asset_refs:
        _bump(context, "evidence_links_recovered", len(asset_refs))
    context["key_findings"] = context["evidence_backed_findings"]

    context["appendix_summaries"] = build_appendix_summaries(context)

    # Recompute validation checks after fallback fixes.
    context["report_validation_checks"] = [
        {"check": "Incident ID present", "status": "Pass" if not is_unknown(context.get("incident_id")) else "Review Required"},
        {"check": "Alert ID present", "status": "Pass" if not is_unknown(context.get("alert_id")) and str(context.get("alert_id")).upper() != "UNKNOWN-ALERT" else "Review Required"},
        {"check": "Severity present", "status": "Pass" if not is_unknown(get_path(context, "severity.label")) else "Fail"},
        {"check": "Confidence present", "status": "Pass" if not is_unknown(get_path(context, "confidence.label")) else "Fail"},
        {"check": "Affected asset context present", "status": "Pass" if context.get("affected_assets") else "Review Required"},
        {"check": "Timeline reconstructed", "status": "Pass" if context.get("timeline") else "Review Required"},
        {"check": "Evidence present", "status": "Pass" if context.get("evidence") else "Review Required"},
        {"check": "IOC evidence links recovered", "status": "Pass" if int(context.get("quality_checks", {}).get("evidence_links_recovered") or 0) else "Review Required"},
        {"check": "MITRE mapping present", "status": "Pass" if context.get("mitre_attack_mapping") else "Review Required"},
    ]

    # Build compact summaries before LLM narrative so the LLM sees concise locked facts.
    evidence = context.get("evidence") or []
    evidence_gaps = context.get("evidence_gaps") or []
    context["compact_evidence_register"] = build_evidence_register_summary(evidence, evidence_gaps)
    context["compact_tables"] = build_compact_render_tables(context)
    context["data_impact_summary"] = build_data_impact_summary(context)
    chain_note = build_chain_of_custody_note(evidence)
    if chain_note:
        context["chain_of_custody_note"] = chain_note
        context["chain_of_custody_compact"] = True
    else:
        context["chain_of_custody_note"] = ""
        context["chain_of_custody_compact"] = False
    approval = context.get("approval") or {}
    containment = context.get("containment") or {}
    context["approval_summary"] = build_approval_summary(approval, containment)
    context["approval_summary_table"] = approval_summary_table(context["approval_summary"])

    apply_llm_narrative(context)
    build_readable_narrative_sections(context)
    finalise_quality_counters(context)
    finalise_section_placeholder_counts(context)
    return context
