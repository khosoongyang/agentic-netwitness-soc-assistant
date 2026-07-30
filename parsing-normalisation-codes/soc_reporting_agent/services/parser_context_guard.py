# [FYP-FILE] NOTE: This is a superseded/duplicate pre-merge copy of the equivalent
# file in soc_reporting_agent/services/parser_context_guard.py. The canonical,
# actively-used implementation is soc_reporting_agent/services/parser_context_guard.py
# (documented separately). This copy is not imported anywhere else in the
# repository and is retained here only as a historical snapshot.
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any


def _is_useful(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "none", "null", "unknown", "n/a", "na"}
    return True


def _first(*values: Any, default: Any = None) -> Any:
    for value in values:
        if isinstance(value, list):
            for item in value:
                if _is_useful(item):
                    return item
        elif _is_useful(value):
            return value
    return default


def _clean(value: Any) -> str | None:
    if not _is_useful(value):
        return None
    return str(value).strip()


def _normalise_for_compare(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _dig(data: Any, *path: Any) -> Any:
    cur = data
    for part in path:
        if isinstance(part, int):
            if not isinstance(cur, list) or len(cur) <= part:
                return None
            cur = cur[part]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
    return cur


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _raw_source(data: dict[str, Any]) -> dict[str, Any]:
    """Return the true raw NetWitness object when a dashboard DB wrapper is used."""
    raw = data.get("raw") if isinstance(data, dict) else None
    if isinstance(raw, dict) and ("incident" in raw or "alerts" in raw or "originalAlert" in raw or "originalHeaders" in raw):
        return raw
    raw_alert = data.get("raw_alert") if isinstance(data, dict) else None
    if isinstance(raw_alert, dict) and ("incident" in raw_alert or "alerts" in raw_alert or "originalAlert" in raw_alert or "originalHeaders" in raw_alert):
        return raw_alert
    return data


def _title_clean(value: Any) -> str | None:
    text = _clean(value)
    if not text:
        return None
    return re.sub(r"\s+", " ", text).strip()


def _walk_values(data: Any, wanted_keys: set[str]) -> list[Any]:
    values: list[Any] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in wanted_keys and _is_useful(value):
                if isinstance(value, list):
                    values.extend([item for item in value if _is_useful(item)])
                else:
                    values.append(value)
            values.extend(_walk_values(value, wanted_keys))
    elif isinstance(data, list):
        for item in data:
            values.extend(_walk_values(item, wanted_keys))
    return values


def extract_alert_identity(raw_alert: Any) -> dict[str, Any]:
    """Extract the selected raw alert identity before parsing.

    The dashboard may store a ticket wrapper such as {"alert_id": ..., "raw":
    {"incident": ..., "alerts": [...]}}. Identity checks must use the true raw
    NetWitness object where possible, then fall back to wrapper fields.
    """
    wrapper = raw_alert if isinstance(raw_alert, dict) else {}
    data = _raw_source(wrapper)
    data = data if isinstance(data, dict) else {}

    alerts = data.get("alerts") if isinstance(data.get("alerts"), list) else []
    primary_alert = next((alert for alert in alerts if isinstance(alert, dict)), None)
    if not primary_alert and isinstance(data.get("alert"), dict):
        primary_alert = data.get("alert")
    if not primary_alert and ("originalAlert" in data or "originalHeaders" in data):
        primary_alert = data
    primary_alert = primary_alert or {}

    incident = _as_dict(data.get("incident"))
    incident_raw = _as_dict(data.get("incident_raw"))
    incident_details = _as_dict(data.get("incident_details"))

    original_headers = _as_dict(primary_alert.get("originalHeaders"))
    original_alert = _as_dict(primary_alert.get("originalAlert"))

    host_values = []
    source_ip_values = []
    destination_ip_values = []
    user_values = []
    for container in (incident, incident_raw, incident_details):
        meta = _as_dict(container.get("alertMeta"))
        host_values.append(_first(meta.get("HostName"), meta.get("hostname"), meta.get("host")))
        user_values.append(_first(meta.get("UserName"), meta.get("username"), meta.get("user")))
        source_ip_values.append(_first(meta.get("SourceIp"), meta.get("source_ip"), meta.get("ip_src")))
        destination_ip_values.append(_first(meta.get("DestinationIp"), meta.get("destination_ip"), meta.get("ip_dst")))
    host_values.extend(_walk_values(primary_alert, {"alias_host", "hostname", "host", "host_name"}))
    user_values.extend(_walk_values(primary_alert, {"username", "user", "user_name"}))
    source_ip_values.extend(_walk_values(primary_alert, {"ip_src", "source_ip", "src_ip", "ip.src"}))
    destination_ip_values.extend(_walk_values(primary_alert, {"ip_dst", "destination_ip", "dst_ip", "ip.dst"}))

    incident_title = _title_clean(_first(
        incident.get("title"), incident_raw.get("title"), incident_details.get("title"),
        wrapper.get("incident_title"), wrapper.get("incident_name"),
    ))
    alert_title = _title_clean(_first(
        primary_alert.get("title"),
        original_headers.get("name"),
        original_alert.get("name"),
        primary_alert.get("alert_title"), primary_alert.get("alert_name"), primary_alert.get("name"),
        wrapper.get("alert_title"), wrapper.get("alert_name"), wrapper.get("name"), wrapper.get("title"),
        original_alert.get("moduleName"),
        incident_title,
    ))

    return {
        "incident_id": _clean(_first(
            incident.get("id"), incident_raw.get("id"), incident_details.get("id"),
            wrapper.get("incident_id"), wrapper.get("incidentId"), wrapper.get("ticket_id"),
        )),
        "alert_id": _clean(_first(
            primary_alert.get("id"), primary_alert.get("_id"), primary_alert.get("alert_id"), primary_alert.get("alertId"),
            wrapper.get("alert_id"), wrapper.get("alertId"), wrapper.get("id"),
        )),
        "alert_title": alert_title,
        "incident_title": incident_title,
        "hostname": _clean(_first(host_values, wrapper.get("hostname"), wrapper.get("host"))),
        "username": _clean(_first(user_values, wrapper.get("username"), wrapper.get("user"))),
        "source_ip": _clean(_first(source_ip_values, wrapper.get("source_ip"), wrapper.get("ip_src"))),
        "destination_ip": _clean(_first(destination_ip_values, wrapper.get("destination_ip"), wrapper.get("ip_dst"))),
    }

def extract_parser_output_identity(parser_result: Any) -> dict[str, Any]:
    data = parser_result if isinstance(parser_result, dict) else {}
    processed = data.get("processed_alert") if isinstance(data.get("processed_alert"), dict) else {}
    normalised = data.get("normalised_alert") if isinstance(data.get("normalised_alert"), dict) else {}
    summary = normalised.get("alert_summary") if isinstance(normalised.get("alert_summary"), dict) else {}
    important = data.get("important_extracted_fields") if isinstance(data.get("important_extracted_fields"), dict) else {}
    return {
        "incident_id": _clean(_first(
            important.get("incident_id"), processed.get("incident_id"), summary.get("incident_id"), data.get("incident_id")
        )),
        "alert_id": _clean(_first(
            data.get("selected_alert_id"), important.get("alert_id"), processed.get("alert_id"), summary.get("alert_id")
        )),
        "alert_title": _clean(_first(
            important.get("alert_name"), processed.get("alert_name"), processed.get("alert_title"), summary.get("alert_name"), data.get("summary")
        )),
        "hostname": _clean(_first(
            important.get("hosts"), processed.get("hostname"), processed.get("host")
        )),
        "username": _clean(_first(
            important.get("users"), processed.get("username")
        )),
        "source_ip": _clean(_first(
            important.get("source_ips"), processed.get("source_ip")
        )),
        "destination_ip": _clean(_first(
            important.get("destination_ips"), processed.get("destination_ip")
        )),
    }


def validate_parser_identity(input_identity: dict[str, Any], parser_result: dict[str, Any]) -> dict[str, Any]:
    """Validate that parser output belongs to the selected raw alert.

    Hard failures are limited to stable identifiers. Titles, hostnames, users,
    and IPs can legitimately differ between incident-level and alert-level
    fields, so those are warnings only.
    """
    parsed = extract_parser_output_identity(parser_result)
    checks: list[dict[str, Any]] = []
    hard_failures: list[str] = []
    warnings: list[str] = []

    def add_check(field: str, hard: bool = False) -> None:
        expected = input_identity.get(field)
        actual = parsed.get(field)
        if not expected or not actual:
            checks.append({"field": field, "expected": expected, "actual": actual, "matched": None, "reason": "not_enough_information"})
            return
        matched = _normalise_for_compare(expected) == _normalise_for_compare(actual)
        record = {"field": field, "expected": expected, "actual": actual, "matched": matched}
        if not matched and not hard:
            record["severity"] = "warning"
            warnings.append(field)
        checks.append(record)
        if hard and not matched:
            hard_failures.append(field)

    # Alert ID is the strongest stale-context guard.
    add_check("alert_id", hard=True)
    # Incident ID is also stable when both sides expose it.
    add_check("incident_id", hard=True)
    # Everything below is useful for debugging but must not block a valid parse.
    for field in ("alert_title", "hostname", "username", "source_ip", "destination_ip"):
        add_check(field, hard=False)

    passed = not hard_failures
    status = "passed" if passed and not warnings else ("passed_with_warnings" if passed else "failed")
    message = "Parser identity check passed."
    if passed and warnings:
        message = "Parser identity check passed with non-blocking field warnings."
    if not passed:
        message = "Parser input mismatch. Selected ticket raw alert does not match generated parser output."
    return {
        "passed": passed,
        "status": status,
        "input_identity": input_identity,
        "parsed_identity": parsed,
        "checks": checks,
        "hard_failures": hard_failures,
        "warnings": warnings,
        "message": message,
    }

def clear_stale_parser_outputs(project_root: Path, ticket_id: str | None = None) -> list[str]:
    """Remove parser outputs that can leak stale alert context into a new run."""
    project_root = Path(project_root)
    outputs = project_root / "outputs"
    inputs = project_root / "inputs"
    removed: list[str] = []
    targets: list[Path] = [
        outputs / "parser_result.json",
        outputs / "processed_alert.json",
        outputs / "soc_context_parser",
        inputs / "parser_result.json",
        inputs / "processed_alert.json",
    ]
    if ticket_id:
        targets.append(outputs / ticket_id / "parsing")
    for target in targets:
        try:
            if target.is_dir():
                shutil.rmtree(target)
                removed.append(str(target))
            elif target.exists():
                target.unlink()
                removed.append(str(target))
        except Exception:
            pass
    return removed
