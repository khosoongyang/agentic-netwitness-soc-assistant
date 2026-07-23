"""
detection_rules.py — auto-generated detection content (post-triage,
pre-investigation).

Adapted from the log-analysis (12) and blue-team-defense (15) skills in
Masriyan/Claude-Code-CyberSecurity-Skill: turn a triaged incident's
indicators into portable, deployable DETECTION content — the one
forward-looking artifact the pipeline lacked. Every other stage explains
what happened; this one answers "how do we catch it automatically next
time?"

Deterministic, no LLM, no network, no new dependencies (the Sigma YAML is
hand-emitted for the fixed rule shape, so we don't pull in PyYAML).

Produces, from the incident's structured indicators (public destination
IPs from alertMeta + threat-intel MALICIOUS verdicts, entity, MITRE
technique, asset tier):
  * a valid Sigma rule (vendor-neutral YAML) with a deterministic UUID,
    logsource, detection selection, MITRE tags, false-positive notes and
    a severity level derived from asset tier + TI verdict
  * Splunk SPL and Microsoft Sentinel KQL translations of the selection
  * MITRE D3FEND defensive countermeasures paired to the ATT&CK technique
    (offense → defense)

Today's incidents carry IP-level indicators, so the generated rules are
network-detection rules (logsource category: firewall). The moment the
per-incident alerts fetch is fixed and endpoint meta (process names,
hashes) arrives, `_select_indicators` picks those up and the same
generator emits richer endpoint rules — no code change, same design as
the incident-map event-walker.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import date

# stable namespace so the same incident always yields the same rule UUID
_RULE_NS = uuid.UUID("5f6c0a3e-9b2d-4e71-8a44-7c1e2d3f4a5b")

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")

# MITRE tactic name → sigma tag stub
_TACTIC_TAG = {
    "reconnaissance": "reconnaissance", "resource development": "resource_development",
    "initial access": "initial_access", "execution": "execution",
    "persistence": "persistence", "privilege escalation": "privilege_escalation",
    "defense evasion": "defense_evasion", "credential access": "credential_access",
    "discovery": "discovery", "lateral movement": "lateral_movement",
    "collection": "collection", "command and control": "command_and_control",
    "exfiltration": "exfiltration", "impact": "impact",
}

# ATT&CK technique → D3FEND countermeasures (small curated table; offense→defense)
_D3FEND = {
    "T1071": [("D3-NTA", "Network Traffic Analysis"),
              ("D3-ISVA", "Inbound Session Volume Analysis")],
    "T1071.001": [("D3-NTA", "Network Traffic Analysis")],
    "T1059": [("D3-PSA", "Process Spawn Analysis"),
              ("D3-SCA", "Script Execution Analysis")],
    "T1059.001": [("D3-SCA", "Script Execution Analysis")],
    "T1566": [("D3-MA", "Message Analysis"), ("D3-UA", "User Behavior Analysis")],
    "T1078": [("D3-UBA", "User Behavior Analysis"),
              ("D3-ANCI", "Authentication Cache Invalidation")],
    "T1021": [("D3-NTA", "Network Traffic Analysis"),
              ("D3-RTSD", "Remote Terminal Session Detection")],
    "T1486": [("D3-FBA", "File Access Pattern Analysis"),
              ("D3-BA", "Backup and Recovery")],
    "T1490": [("D3-BA", "Backup and Recovery")],
    "T1055": [("D3-PSA", "Process Spawn Analysis")],
    "T1003": [("D3-PSA", "Process Spawn Analysis"),
              ("D3-CBAN", "Credential Compromise Scope Analysis")],
}


def _is_public_ip(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def _select_indicators(incident: dict, triage_result: dict | None,
                       threat_intel: dict | None) -> dict:
    """Pull the detectable indicators. Prefers threat-intel MALICIOUS/
    SUSPICIOUS IOCs; falls back to public destination IPs from alertMeta.
    Also collects endpoint indicators (process/hash) when present — dormant
    until the alerts fetch is fixed."""
    dst_ips: list[str] = []
    domains: list[str] = []
    hashes: list[str] = []
    processes: list[str] = []

    ti_flagged = set()
    if threat_intel:
        for r in threat_intel.get("results", []):
            if r.get("verdict", "").startswith(("MALICIOUS", "SUSPICIOUS")):
                ti_flagged.add(r["value"])

    am = incident.get("alertMeta") or {}
    for v in am.get("DestinationIp") or []:
        if isinstance(v, str) and _IP_RE.match(v) and _is_public_ip(v):
            dst_ips.append(v)

    # triage metakeys may carry domains / hashes / process names
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    for key, vals in mkv.items():
        k = key.lower()
        for val in (vals if isinstance(vals, list) else [vals]):
            val = str(val or "").strip()
            if not val:
                continue
            if _HASH_RE.match(val):
                hashes.append(val)
            elif ("domain" in k or "fqdn" in k) and "." in val:
                domains.append(val)
            elif "process" in k or "filename" in k:
                processes.append(val)

    def dedup(seq):
        return list(dict.fromkeys(seq))

    # rank flagged indicators first
    dst_ips = dedup([i for i in dst_ips if i in ti_flagged]
                    + [i for i in dst_ips if i not in ti_flagged])
    return {
        "dst_ips": dst_ips[:15], "domains": dedup(domains)[:15],
        "hashes": dedup(hashes)[:10], "processes": dedup(processes)[:10],
        "ti_flagged": ti_flagged,
        "endpoint": bool(hashes or processes),
    }


def _severity_level(asset: dict | None, threat_intel: dict | None) -> str:
    """Sigma level from asset tier + TI verdict (deterministic)."""
    rank = (asset or {}).get("highest_rank", 0)
    has_malicious = bool(threat_intel and any(
        r.get("verdict", "").startswith("MALICIOUS")
        for r in threat_intel.get("results", [])))
    if has_malicious and rank >= 2:
        return "critical"
    if has_malicious or rank >= 3:
        return "high"
    if rank >= 1:
        return "medium"
    return "low"


# ── YAML emit (hand-rolled for the fixed Sigma shape — no PyYAML) ────────────

def _yq(v: str) -> str:
    """Quote a scalar for YAML when needed."""
    s = str(v)
    if s and re.match(r"^[A-Za-z0-9_.:/\- ]+$", s) and not s[0].isdigit():
        return s
    return "'" + s.replace("'", "''") + "'"


def build_sigma_rule(incident: dict, triage_result: dict | None = None,
                     threat_intel: dict | None = None,
                     asset: dict | None = None) -> dict:
    """Deterministic Sigma rule (as a dict) for one incident."""
    inc_id = str(incident.get("id") or "UNKNOWN")
    title_entity = ""
    m = _TITLE_ENTITY_RE.search(str(incident.get("title") or ""))
    if m:
        title_entity = m.group(1).strip()

    ind = _select_indicators(incident, triage_result, threat_intel)
    ticket = (triage_result or {}).get("ticket", {})
    tactic = str(((triage_result or {}).get("metakeys_payload") or {}).get("mitre_tactic")
                 or ticket.get("mitre_tactic") or incident.get("mitre_tactic") or "")
    technique = str(((triage_result or {}).get("metakeys_payload") or {}).get("mitre_technique")
                    or ticket.get("mitre_technique") or incident.get("mitre_technique") or "")

    tags = []
    tac_tag = _TACTIC_TAG.get(tactic.lower())
    if tac_tag:
        tags.append(f"attack.{tac_tag}")
    if re.match(r"^T\d{4}", technique):
        tags.append(f"attack.{technique.split('.')[0].lower()}")

    # detection selection: endpoint-flavoured when we have process/hash,
    # else network-flavoured on destination IPs / domains
    if ind["endpoint"]:
        logsource = {"category": "process_creation", "product": "windows"}
        selection: dict = {}
        if ind["processes"]:
            selection["Image|endswith"] = ind["processes"]
        if ind["hashes"]:
            selection["Hashes|contains"] = ind["hashes"]
    else:
        logsource = {"category": "firewall", "product": "network"}
        selection = {}
        if ind["dst_ips"]:
            selection["dst_ip"] = ind["dst_ips"]
        if ind["domains"]:
            selection["dst_domain"] = ind["domains"]

    level = _severity_level(asset, threat_intel)
    rule = {
        "title": f"NetWitness {inc_id} — auto-generated detection"
                 + (f" ({title_entity})" if title_entity else ""),
        "id": str(uuid.uuid5(_RULE_NS, inc_id)),
        "status": "experimental",
        "description": (f"Auto-generated by the SOC triage pipeline from incident "
                        f"{inc_id}. Detects the observed indicators; review and "
                        f"tune before production deployment."),
        "author": "SOC Triage Agent (auto-generated)",
        "date": date.today().strftime("%Y/%m/%d"),
        "references": [f"Incident {inc_id}"],
        "tags": tags,
        "logsource": logsource,
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": ["Legitimate traffic/activity involving these indicators — "
                           "verify against asset inventory and business context"],
        "level": level,
    }
    return {"rule": rule, "indicators": ind, "technique": technique,
            "has_selection": bool(selection)}


def sigma_to_yaml(rule: dict) -> str:
    """Emit the Sigma rule dict as YAML text (fixed shape)."""
    out: list[str] = []
    for k in ("title", "id", "status", "description", "author", "date"):
        out.append(f"{k}: {_yq(rule[k])}")
    out.append("references:")
    for r in rule["references"]:
        out.append(f"    - {_yq(r)}")
    if rule["tags"]:
        out.append("tags:")
        for t in rule["tags"]:
            out.append(f"    - {t}")
    out.append("logsource:")
    for k, v in rule["logsource"].items():
        out.append(f"    {k}: {_yq(v)}")
    out.append("detection:")
    sel = rule["detection"]["selection"]
    if not sel:
        out.append("    selection: {}  # no concrete indicators available")
    else:
        out.append("    selection:")
        for field, vals in sel.items():
            if isinstance(vals, list):
                out.append(f"        {field}:")
                for v in vals:
                    out.append(f"            - {_yq(v)}")
            else:
                out.append(f"        {field}: {_yq(vals)}")
    out.append(f"    condition: {rule['detection']['condition']}")
    out.append("falsepositives:")
    for fp in rule["falsepositives"]:
        out.append(f"    - {_yq(fp)}")
    out.append(f"level: {rule['level']}")
    return "\n".join(out)


def to_splunk(built: dict) -> str:
    """Splunk SPL translation of the Sigma selection."""
    sel = built["rule"]["detection"]["selection"]
    if not sel:
        return "(no concrete indicators to query)"
    clauses = []
    field_map = {"dst_ip": "dest_ip", "dst_domain": "query",
                 "Image|endswith": "Image", "Hashes|contains": "Hashes"}
    for field, vals in sel.items():
        f = field_map.get(field, field.split("|")[0])
        vals = vals if isinstance(vals, list) else [vals]
        clauses.append("(" + " OR ".join(f'{f}="{v}"' for v in vals) + ")")
    return "index=* " + " ".join(clauses) + " | stats count by _time, host"


def to_sentinel_kql(built: dict) -> str:
    """Microsoft Sentinel KQL translation of the Sigma selection."""
    sel = built["rule"]["detection"]["selection"]
    if not sel:
        return "// no concrete indicators to query"
    endpoint = built["rule"]["logsource"]["category"] == "process_creation"
    table = "DeviceProcessEvents" if endpoint else "CommonSecurityLog"
    kmap = {"dst_ip": "DestinationIP", "dst_domain": "DestinationHostName",
            "Image|endswith": "FolderPath", "Hashes|contains": "SHA256"}
    clauses = []
    for field, vals in sel.items():
        col = kmap.get(field, field.split("|")[0])
        vals = vals if isinstance(vals, list) else [vals]
        quoted = ", ".join(f'"{v}"' for v in vals)
        clauses.append(f"{col} in ({quoted})")
    return f"{table}\n| where " + "\n    or ".join(clauses)


def d3fend_for(technique: str) -> list[tuple[str, str]]:
    """MITRE D3FEND countermeasures for an ATT&CK technique (offense→defense)."""
    if not technique:
        return []
    return _D3FEND.get(technique) or _D3FEND.get(technique.split(".")[0]) or []


def build_detection(incident: dict, triage_result: dict | None = None,
                    threat_intel: dict | None = None,
                    asset: dict | None = None) -> dict:
    """Full detection package: Sigma + SPL + KQL + D3FEND. Never raises on
    bad input beyond what the caller guards."""
    built = build_sigma_rule(incident, triage_result, threat_intel, asset)
    return {
        "sigma": built["rule"],
        "sigma_yaml": sigma_to_yaml(built["rule"]),
        "splunk_spl": to_splunk(built),
        "sentinel_kql": to_sentinel_kql(built),
        "d3fend": [{"id": i, "name": n} for i, n in d3fend_for(built["technique"])],
        "has_selection": built["has_selection"],
        "indicator_count": (len(built["indicators"]["dst_ips"])
                            + len(built["indicators"]["domains"])
                            + len(built["indicators"]["hashes"])
                            + len(built["indicators"]["processes"])),
        "endpoint_rule": built["indicators"]["endpoint"],
    }


def format_detection(det: dict) -> str:
    """Plain-text block for the investigation alert / LLM prompt / UI."""
    lines = ["RECOMMENDED DETECTION (auto-generated Sigma rule + SIEM queries; "
             "review before deploying)"]
    if not det["has_selection"]:
        lines.append("  (no concrete external indicators available to build a "
                     "detection rule for this incident)")
        return "\n".join(lines)
    lines.append(f"  rule level: {det['sigma']['level']}  ·  "
                 f"{det['indicator_count']} indicator(s)  ·  "
                 + ("endpoint rule" if det["endpoint_rule"] else "network rule"))
    lines.append("  --- Sigma (YAML) ---")
    for ln in det["sigma_yaml"].splitlines():
        lines.append("  " + ln)
    lines.append("  --- Splunk SPL ---")
    lines.append("  " + det["splunk_spl"])
    lines.append("  --- Microsoft Sentinel KQL ---")
    for ln in det["sentinel_kql"].splitlines():
        lines.append("  " + ln)
    if det["d3fend"]:
        lines.append("  --- MITRE D3FEND countermeasures ---")
        for c in det["d3fend"]:
            lines.append(f"    {c['id']} {c['name']}")
    return "\n".join(lines)
