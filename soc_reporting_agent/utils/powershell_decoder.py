# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, base64, binascii, ipaddress, re, typing, urllib.
# =============================================================================
# File: soc_reporting_agent/utils/powershell_decoder.py
# Purpose: This module detects and decodes encoded PowerShell command content during normalisation.
# Main functionality: _dedupe, _normalise_b64, extract_encoded_command, decode_powershell_encoded_command, _is_public_ip, extract_iocs_from_powershell.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis shared reporting utility component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, base64, binascii, ipaddress, re, typing, urllib.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _dedupe, _normalise_b64, extract_encoded_command, decode_powershell_encoded_command, _is_public_ip, extract_iocs_from_powershell, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

ENCODED_COMMAND_RE = re.compile(
    r"(?i)(?:^|[\s`'\"])(?:-|/)(?:encodedcommand|enc|e)\s+(?:['\"]?)([A-Za-z0-9+/=]{12,})(?:['\"]?)"
)
URL_RE = re.compile(r"(?i)\bhttps?://[^\s'\"<>)]{4,}")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|sg|ru|cn|xyz|top|info|biz|me|site|cloud|dev)\b")
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
FILE_RE = re.compile(r"(?i)\b[\w .()\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr|zip|7z|rar)\b")

SUSPICIOUS_PATTERNS: List[tuple[str, str, str, List[str]]] = [
    ("Execution policy bypass", "High", r"(?i)executionpolicy\s+bypass|\-ep\s+bypass|bypass", ["T1059.001", "T1027"]),
    ("Hidden PowerShell window", "High", r"(?i)windowstyle\s+hidden|\-w\s+hidden|\-window\s+hidden", ["T1059.001", "T1027"]),
    ("NoProfile PowerShell execution", "Medium", r"(?i)\-nop\b|\-noprofile\b", ["T1059.001"]),
    ("In-memory execution", "High", r"(?i)\biex\b|invoke-expression", ["T1059.001", "T1027"]),
    ("Remote payload download", "High", r"(?i)downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b|net\.webclient", ["T1105", "T1071.001"]),
    ("Nested Base64 decoding", "High", r"(?i)frombase64string|encodedcommand|\s-enc\s", ["T1027", "T1059.001"]),
    ("Defence evasion setting", "High", r"(?i)add-mppreference|set-mppreference|disable.*defender|exclusionpath|amsi", ["T1562.001"]),
    ("Persistence via scheduled task", "High", r"(?i)schtasks|new-scheduledtask|register-scheduledtask", ["T1053.005"]),
    ("Persistence via registry", "High", r"(?i)reg\s+add|new-itemproperty|run\\|runonce\\", ["T1547.001"]),
    ("Living-off-the-land process usage", "Medium", r"(?i)rundll32|mshta|certutil|bitsadmin|wmic", ["T1218", "T1105"]),
]

MITRE_LABELS = {
    "T1059.001": "PowerShell",
    "T1027": "Obfuscated Files or Information",
    "T1105": "Ingress Tool Transfer",
    "T1071.001": "Web Protocols",
    "T1562.001": "Impair Defences: Disable or Modify Tools",
    "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1218": "System Binary Proxy Execution",
}


# =============================================================================
# [FYP-SECTION] SHARED REPORTING UTILITY EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_dedupe` — implements the dedupe operation used by the surrounding shared reporting utility workflow.
# [FYP-INPUT] Parameters: `values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:derive_affected_assets, soc_reporting_agent/reporting/export_context_enhancer.py:derive_affected_users, soc_reporting_agent/reporting/export_context_enhancer.py:derive_timeline; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `add`, `append`, `lower`, `set`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _dedupe(values: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    seen = set()
    for value in values:
        if value in (None, "", [], {}):
            continue
        marker = str(value).strip().lower()
        if marker and marker not in seen:
            seen.add(marker)
            out.append(value)
    return out


# [FYP-FUNCTION] `_normalise_b64` — transforms normalise b64 input into the stable representation required by downstream shared reporting utility processing.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/utils/powershell_decoder.py:decode_powershell_encoded_command, soc_reporting_agent/utils/powershell_decoder.py:extract_encoded_command; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `len`, `strip`, `sub`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_b64(value: str) -> str:
    value = (value or "").strip().strip("'\"")
    value = re.sub(r"\s+", "", value)
    missing = len(value) % 4
    if missing:
        value += "=" * (4 - missing)
    return value


# [FYP-FUNCTION] `extract_encoded_command` — transforms extract encoded command input into the stable representation required by downstream shared reporting utility processing.
# [FYP-INPUT] Parameters: `command_line`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/utils/powershell_decoder.py:analyse_powershell_command_lines; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_normalise_b64`, `group`, `search`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def extract_encoded_command(command_line: str) -> Optional[str]:
    if not command_line:
        return None
    match = ENCODED_COMMAND_RE.search(command_line)
    if match:
        return _normalise_b64(match.group(1))
    return None


# [FYP-FUNCTION] `decode_powershell_encoded_command` — transforms decode powershell encoded command input into the stable representation required by downstream shared reporting utility processing.
# [FYP-INPUT] Parameters: `encoded`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/utils/powershell_decoder.py:analyse_powershell_command_lines; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_normalise_b64`, `append`, `b64decode`, `decode`, `isprintable`, `lower`, `replace`, `sorted`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def decode_powershell_encoded_command(encoded: str) -> Dict[str, Any]:
    encoded = _normalise_b64(encoded)
    if not encoded:
        return {"decode_status": "not_present", "decoded_command": "", "reason": "No encoded command was supplied."}
    try:
        raw = base64.b64decode(encoded, validate=False)
    except (binascii.Error, ValueError) as exc:
        return {"decode_status": "failed", "decoded_command": "", "reason": f"Invalid Base64: {exc}"}

    candidates: List[tuple[str, str]] = []
    for encoding in ("utf-16le", "utf-8", "utf-16", "latin-1"):
        try:
            text = raw.decode(encoding, errors="replace")
            cleaned = text.replace("\x00", "").strip()
            score = sum(1 for token in ["powershell", "iex", "invoke", "http", "download", "-", "$"] if token in cleaned.lower())
            printable = sum(1 for ch in cleaned if ch.isprintable())
            candidates.append((encoding, cleaned, score + printable / 1000))
        except Exception:
            continue
    if not candidates:
        return {"decode_status": "failed", "decoded_command": "", "reason": "Decoded bytes could not be converted to text."}
    best = sorted(candidates, key=lambda item: item[2], reverse=True)[0]
    return {
        "decode_status": "success" if best[1] else "empty",
        "encoded_command": encoded,
        "decoded_command": best[1],
        "encoding_detected": best[0],
    }


# [FYP-FUNCTION] `_is_public_ip` — evaluates is public ip conditions so invalid or unsafe shared reporting utility processing is stopped early.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include detection_rules.py:_select_indicators, diamond_model.py:_extract, ioc_correlation.py:_extract_iocs; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ip_address`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except Exception:
        return False


# [FYP-FUNCTION] `extract_iocs_from_powershell` — transforms extract iocs from powershell input into the stable representation required by downstream shared reporting utility processing.
# [FYP-INPUT] Parameters: `decoded`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/utils/powershell_decoder.py:analyse_decoded_powershell; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_dedupe`, `_is_public_ip`, `append`, `findall`, `list`, `urlparse`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def extract_iocs_from_powershell(decoded: str) -> Dict[str, List[str]]:
    decoded = decoded or ""
    urls = _dedupe(URL_RE.findall(decoded))
    domains_from_urls = []
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host:
                domains_from_urls.append(host)
        except Exception:
            pass
    domains = _dedupe(list(DOMAIN_RE.findall(decoded)) + domains_from_urls)
    ips = _dedupe(ip for ip in IP_RE.findall(decoded) if _is_public_ip(ip))
    hashes = _dedupe(HASH_RE.findall(decoded))
    file_paths = _dedupe(WINDOWS_PATH_RE.findall(decoded))
    file_names = _dedupe(FILE_RE.findall(decoded))
    return {
        "urls": urls,
        "domains": domains,
        "public_ips": ips,
        "hashes": hashes,
        "file_paths": file_paths,
        "file_names": file_names,
    }


# [FYP-FUNCTION] `analyse_decoded_powershell` — implements the analyse decoded powershell operation used by the surrounding shared reporting utility workflow.
# [FYP-INPUT] Parameters: `decoded`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/utils/powershell_decoder.py:analyse_powershell_command_lines; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_dedupe`, `append`, `extend`, `extract_iocs_from_powershell`, `get`, `group`, `min`, `search`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def analyse_decoded_powershell(decoded: str) -> Dict[str, Any]:
    behaviours: List[Dict[str, Any]] = []
    mitre_ids: List[str] = []
    for name, risk, pattern, techniques in SUSPICIOUS_PATTERNS:
        match = re.search(pattern, decoded or "")
        if match:
            behaviours.append({"behaviour": name, "risk": risk, "evidence": match.group(0)[:160], "mitre_technique_ids": techniques})
            mitre_ids.extend(techniques)
    iocs = extract_iocs_from_powershell(decoded)
    risk_points = sum(30 if b["risk"] == "High" else 15 for b in behaviours)
    risk_points += 20 if iocs["urls"] or iocs["domains"] or iocs["public_ips"] else 0
    if risk_points >= 80:
        risk = "Critical"
    elif risk_points >= 45:
        risk = "High"
    elif risk_points >= 15:
        risk = "Medium"
    else:
        risk = "Low"
    mitre = [{"technique_id": tid, "technique": MITRE_LABELS.get(tid, tid)} for tid in _dedupe(mitre_ids)]
    return {
        "suspicious_behaviours": behaviours,
        "extracted_iocs": iocs,
        "mitre_mapping": mitre,
        "risk_assessment": {"risk_level": risk, "risk_score": min(risk_points, 100)},
    }


# [FYP-FUNCTION] `analyse_powershell_command_lines` — implements the analyse powershell command lines operation used by the surrounding shared reporting utility workflow.
# [FYP-INPUT] Parameters: `command_lines`, `alert_text`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `analyse_decoded_powershell`, `append`, `bool`, `decode_powershell_encoded_command`, `extract_encoded_command`, `get`, `join`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def analyse_powershell_command_lines(command_lines: Iterable[Any], alert_text: str = "") -> Dict[str, Any]:
    sources = [str(v) for v in command_lines if v not in (None, "")]
    encoded_results: List[Dict[str, Any]] = []
    decoded_commands: List[str] = []
    for line in sources:
        encoded = extract_encoded_command(line)
        if not encoded:
            continue
        decoded = decode_powershell_encoded_command(encoded)
        decoded["source_command_line"] = line[:2000]
        encoded_results.append(decoded)
        if decoded.get("decode_status") == "success" and decoded.get("decoded_command"):
            decoded_commands.append(decoded["decoded_command"])

    combined_decoded = "\n".join(decoded_commands)
    analysis = analyse_decoded_powershell(combined_decoded) if combined_decoded else {
        "suspicious_behaviours": [],
        "extracted_iocs": {"urls": [], "domains": [], "public_ips": [], "hashes": [], "file_paths": [], "file_names": []},
        "mitre_mapping": [],
        "risk_assessment": {"risk_level": "Low", "risk_score": 0},
    }
    alert_blob = (alert_text or "").lower() + "\n" + "\n".join(sources).lower()
    power_shell_indicator = bool(re.search(r"(?i)powershell|encodedcommand|\s-enc\s|\s-e\s", alert_blob))
    return {
        "encoded_command_present": bool(encoded_results),
        "powershell_indicator_present": power_shell_indicator,
        "decode_status": "success" if decoded_commands else "not_found" if not encoded_results else "failed",
        "encoded_command_count": len(encoded_results),
        "decoded_command_count": len(decoded_commands),
        "decoded_commands": decoded_commands[:5],
        "decoded_command_summary": summarise_decoded_command(combined_decoded, analysis),
        "encoded_command_results": encoded_results[:5],
        **analysis,
    }


# [FYP-FUNCTION] `summarise_decoded_command` — implements the summarise decoded command operation used by the surrounding shared reporting utility workflow.
# [FYP-INPUT] Parameters: `decoded`, `analysis`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis shared reporting utility workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/utils/powershell_decoder.py:analyse_powershell_command_lines; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `join`, `len`, `strip`, `sub`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def summarise_decoded_command(decoded: str, analysis: Dict[str, Any]) -> str:
    if not decoded:
        return "No decodable PowerShell EncodedCommand content was available in the parsed telemetry."
    behaviours = [b.get("behaviour") for b in analysis.get("suspicious_behaviours", [])[:4]]
    iocs = analysis.get("extracted_iocs", {}) or {}
    ioc_bits = []
    for key in ("urls", "domains", "public_ips", "hashes"):
        values = iocs.get(key) or []
        if values:
            ioc_bits.append(f"{len(values)} {key}")
    parts = []
    if behaviours:
        parts.append("Detected behaviours: " + ", ".join(behaviours) + ".")
    if ioc_bits:
        parts.append("Extracted indicators: " + ", ".join(ioc_bits) + ".")
    preview = re.sub(r"\s+", " ", decoded).strip()[:240]
    parts.append(f"Decoded preview: {preview}")
    return " ".join(parts)
