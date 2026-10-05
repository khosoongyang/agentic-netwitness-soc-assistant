"""agents/triage/incident_fields.py -- Incident-field extraction: incident time (converted to UTC), NetWitness
meta-key values (observed keys only) and resolution of the model's IOC matches.

[AUDIT T-22] Moved verbatim out of soc_triage_agent.py (2,500+ lines) to
split it by responsibility. soc_triage_agent re-exports every name
defined here, so existing imports and behaviour are unchanged.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# 7.  INCIDENT TIME EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

_TIME_FIELDS = [
    "created", "createdAt", "created_at", "timestamp", "alertTime",
    "eventTime", "event_time", "occurredTime", "detectedTime", "time",
]


# [FYP-FUNCTION] `_flatten` — implements the flatten operation used by the surrounding triage workflow.
# [FYP-INPUT] Parameters: `d`, `prefix`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:_extract_incident_time, agents/triage/soc_triage_agent.py:_extract_metakey_values, agents/triage/soc_triage_agent.py:_flatten; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_flatten`, `enumerate`, `isinstance`, `items`, `str`, `update`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _flatten(d: Any, prefix: str = "") -> dict:
    items: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            nk = f"{prefix}.{k}" if prefix else str(k)
            items.update(_flatten(v, nk))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = d
    return items


# [FYP-FUNCTION] `_extract_incident_time` — transforms extract incident time input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:triage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_flatten`, `get`, `len`, `str`, `strftime`, `strip`, `strptime`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _parse_time_utc(value: Any) -> datetime | None:
    """[AUDIT T-13] Parse an incident timestamp and CONVERT it to UTC.
    Offsets are honoured ("+08:00" -> minus 8 h); naive values are treated
    as UTC (NetWitness emits UTC); epoch seconds / milliseconds (int or
    digit string) are supported. Returns None when unparseable."""
    if isinstance(value, bool):
        return None
    raw = str(value).strip()
    if isinstance(value, (int, float)) or re.fullmatch(r"\d{9,13}(?:\.\d+)?", raw):
        try:
            num = float(raw)
            return datetime.fromtimestamp(num / 1000 if num > 1e11 else num, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    text = raw.replace(" ", "T", 1) if "T" not in raw and " " in raw else raw
    text = re.sub(r"(?i)z$", "+00:00", text)
    # Python 3.10 fromisoformat only accepts 3- or 6-digit fractions.
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", text)
    if m and m.group(2):
        frac = (m.group(2)[1:] + "000000")[:6]
        text = f"{m.group(1)}.{frac}{m.group(3)}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_incident_time(incident: dict) -> str:
    flat = _flatten(incident)
    for field in _TIME_FIELDS:
        val = flat.get(field) or incident.get(field)
        if val:
            raw = str(val).strip()
            dt = _parse_time_utc(val)
            if dt is not None:
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            if len(raw) >= 8:
                return raw
    return "—"


# ══════════════════════════════════════════════════════════════════════════════
# 8.  META-KEY EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

_METAKEY_MAP: dict[str, list[str]] = {
    "ip.src":       ["sourceIp", "source_ip", "srcIp", "source.ip",
                     "source.device.ipAddress", "ipSrc", "ip_src"],
    "ip.dst":       ["destinationIp", "dest_ip", "dstIp", "destination.ip",
                     "destination.device.ipAddress", "ipDst", "ip_dst"],
    "host.name":    ["hostname", "host", "deviceName", "computerName",
                     "machineName", "hostName", "dnsHostname", "device.name"],
    "user.name":    ["username", "user", "userName", "targetUser", "userDst",
                     "userSrc", "user_name", "accountName"],
    "domain":       ["domain", "fqdn", "eventDomain"],
    "event.type":   ["type", "eventType", "event_type"],
    "bytes.out":    ["bytesOut", "bytes_out", "egress_bytes"],
    "protocol":     ["protocol", "networkProtocol"],
    "geo.country":  ["country", "geoCountry"],
    "file.name":    ["fileName", "file_name"],
    "file.hash":    ["fileHash", "md5", "sha256"],
    "process.name": ["processName", "process_name"],
    "os.version":   ["osVersion", "os_version", "operatingSystem", "osType"],
}
# [AUDIT T-17] Every IOC-checklist meta key gets a mapping. Aliases are
# APPENDED (earlier aliases still win, so existing extractions are
# unchanged) and use the NetWitness field names measured in demo/*.json and
# soc_db incidents (events.port_dst, ip_proto, filename_src, checksum_src,
# dir_path_src, cert_thumbprint, device_type, event_time, OS, size, ...).
# A leading "=" means "exact last path segment only" so short names (OS,
# size, pid, service) cannot match unrelated keys by suffix. Keys with no
# real field in the data (cpu.usage, packets.*, boot.config, ...) map only
# to their literal spellings: they are never invented, and the ticket only
# lists keys actually observed (see _observed_metakeys).
for _mk, _aliases in {
    "ip.src":            ["ipSrc"],
    "protocol":          ["ip_proto", "ipProto"],
    "geo.country":       ["country_src", "country_dst"],
    "file.name":         ["filename_src", "filename_dst", "=filename"],
    "file.hash":         ["checksum_src", "checksum_dst", "file_SHA256"],
    "process.name":      ["filename_src"],
    "os.version":        ["=OS"],
    "port.dst":          ["port_dst", "dstPort", "destinationPort", "destination.port"],
    "device.type":       ["device_type", "deviceType"],
    "event.time":        ["event_time", "eventTime"],
    "file.path":         ["file_path", "filePath", "dir_path_src", "dir_path_dst"],
    "file.size":         ["file_size", "fileSize", "size_bytes", "=size"],
    "cert.hash":         ["cert_thumbprint", "certThumbprint", "cert_hash"],
    "cert.issuer":       ["cert_issuer", "certIssuer"],
    "alert.type":        ["alert_type", "alertType", "moduleType"],
    "network.service":   ["network_service", "=service"],
    "process.path":      ["process_path", "processPath", "dir_path_src"],
    "process.pid":       ["process_id", "processId", "=pid"],
    "user.role":         ["user_role", "userRole"],
    "account.action":    ["account_action", "accountAction"],
    "change.type":       ["change_type", "changeType"],
    "config.change":     ["config_change", "configChange"],
    "permission.change": ["permission_change", "permissionChange"],
    "firmware.version":  ["firmware_version", "firmwareVersion"],
    "boot.config":       ["boot_config", "bootConfig"],
    "bytes.in":          ["bytes_in", "bytesIn"],
    "bytes.transferred": ["bytes_transferred", "bytesTransferred"],
    "network.interface": ["network_interface", "networkInterface"],
    "packets.in":        ["packets_in", "packetsIn"],
    "packets.out":       ["packets_out", "packetsOut"],
    "packets.malformed": ["packets_malformed", "malformedPackets"],
    "cpu.usage":         ["cpu_usage", "cpuUsage"],
}.items():
    _existing = _METAKEY_MAP.setdefault(_mk, [])
    _existing.extend(a for a in _aliases if a not in _existing)
del _mk, _aliases, _existing   # loop temporaries, not module API

# Values that carry no forensic information — never surface them as extracted
# metakey values (they'd feed "Unknown" straight into the investigation agent).
_METAKEY_NOISE = {"", "unknown", "none", "null", "n/a", "-", "0.0.0.0",
                  "localhost", "127.0.0.1"}


# [FYP-FUNCTION] `_extract_metakey_values` — transforms extract metakey values input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `incident`, `metakeys`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:triage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_flatten`, `append`, `endswith`, `get`, `isdigit`, `join`, `keys`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _extract_metakey_values(incident: dict, metakeys: list[str]) -> dict:
    """Deep metakey extraction.

    NetWitness incidents nest the interesting fields under alerts[N].events[N]
    (source.device.ipAddress, …), so exact top-level lookups almost always
    missed. Match flattened key PATHS case-insensitively by suffix instead,
    walking keys in sorted order so repeat runs stay deterministic. Multiple
    distinct hits are kept (capped) — downstream consumers accept lists.
    """
    flat = _flatten(incident)

    # [FYP-FUNCTION] `norm` — implements the norm operation used by the surrounding triage workflow.
    # [FYP-INPUT] Parameters: `s`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include orchestration_service.py (removed):_decision, orchestration_service.py (removed):_legacy_build_orchestration_decision, orchestration_service.py (removed):_legacy_can_run_agent; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `lower`, `str`, `sub`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(s).lower())

    # Pre-normalize once: the last three path segments cover keys like
    # "source.device.ipAddress" while ignoring the alerts[3].events[0] prefix.
    norm_flat = []
    for key in sorted(flat.keys()):
        val = flat[key]
        if val in (None, "", [], {}) or str(val).strip().lower() in _METAKEY_NOISE:
            continue
        segs = [s for s in re.split(r"[.\[\]]", key) if s and not s.isdigit()]
        tail = norm("".join(segs[-3:]))
        norm_flat.append((tail, norm(segs[-1] if segs else key), val))

    values: dict = {}
    for mk in metakeys:
        hits: list = []
        for cand in _METAKEY_MAP.get(mk, []):
            exact = cand.startswith("=")
            nc = norm(cand.lstrip("="))
            for tail, last, val in norm_flat:
                if (last == nc or (not exact and tail.endswith(nc))) and val not in hits:
                    hits.append(val)
                if len(hits) >= 5:
                    break
            if hits:
                break
        if hits:
            values[mk] = hits[0] if len(hits) == 1 else hits
    return values


def _observed_metakeys(incident: dict, implied: list[str]) -> tuple[list[str], dict]:
    """[AUDIT T-17] (keys, values) for the checklist-implied meta keys that
    actually carry a value in this incident. The ticket's "Matched
    Meta-Keys" must never name a field the incident does not have."""
    values = _extract_metakey_values(incident, list(implied))
    return sorted(k for k in set(implied) if k in values), values


# ══════════════════════════════════════════════════════════════════════════════
# 8b.  IOC MATCH RESOLUTION
# ══════════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `_resolve_ioc_matches` — implements the resolve ioc matches operation used by the surrounding triage workflow.
# [FYP-INPUT] Parameters: `raw_items`, `ioc_list`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:_run_ioc; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_add`, `enumerate`, `findall`, `fullmatch`, `group`, `int`, `isinstance`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _resolve_ioc_matches(raw_items: Any, ioc_list: list[dict]) -> list[int]:
    """
    Resolve the model's matched_iocs entries to 0-based positions in ioc_list.

    The prompt demands integer indices, but the model doesn't always comply —
    it may emit "3", "[3]", "IOC 3", or the IOC's NAME. The old int(idx)-only
    path silently dropped everything non-integer, which read as "0 IOCs
    matched" even when the model had clearly identified matches.
    """
    if raw_items is None:
        return []
    if not isinstance(raw_items, (list, tuple)):
        raw_items = [raw_items]

    resolved: list[int] = []

    # [FYP-FUNCTION] `_add` — implements the add operation used by the surrounding triage workflow.
    # [FYP-INPUT] Parameters: `pos`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include nw_alerts.py:_add, nw_alerts.py:_distill_alerts, skills_sidecar.py:_assets_from_skills; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `len`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _add(pos: int) -> None:
        if 0 <= pos < len(ioc_list) and pos not in resolved:
            resolved.append(pos)

    for item in raw_items:
        if isinstance(item, bool):        # bool is an int subclass — skip
            continue
        if isinstance(item, (int, float)):
            _add(int(item) - 1)
            continue
        s = str(item).strip()
        if not s:
            continue
        # "3", "[3]", "IOC 3", "#3" — a lone number anywhere in a short token
        m = re.fullmatch(r"[^\d]{0,6}(\d{1,2})[^\d]{0,2}", s)
        if m:
            _add(int(m.group(1)) - 1)
            continue
        # "1, 4" / "2 and 5" — numbers-only token with separators
        if not re.search(r"[a-zA-Z]{4,}", s):
            nums = re.findall(r"\d{1,2}", s)
            if nums:
                for n in nums:
                    _add(int(n) - 1)
                continue
        # Otherwise treat it as an IOC name (exact, then substring, either way)
        s_low = s.lower()
        for j, entry in enumerate(ioc_list):
            name = entry["ioc"].lower()
            if s_low == name or s_low in name or name in s_low:
                _add(j)
                break

    return resolved


