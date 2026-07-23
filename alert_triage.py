"""
alert_triage.py — multi-source alert triage & normalization for the triage
agent.

Faithful adaptation of the `analyze_alert` operation from the
defensive-security skill (pluginagentmarketplace/custom-plugin-cyber-security,
skills/defensive), which triages an alert from a siem/edr/ndr/custom source.
This lets the triage agent — until now NetWitness-shaped only — ingest and
triage alerts from ANY source.

Parity with the source skill:
  * validate_alert enforces the skill's rule
    `alert_data.has_keys(['timestamp','source','message'])`, returning the
    skill's error code E_INVALID_ALERT (2001) when a field is absent (aliases
    accepted so real-world alerts aren't rejected on field-name cosmetics)
  * `context` is the skill's enum: siem | edr | ndr | custom
  * the deterministic indicator scan extends the skill's log_analyzer.py
    regexes (failed_login / privilege_escalation / suspicious_ip) and maps
    them onto the skill's MITRE coverage table (T1566/T1059/T1547/T1021, +)
  * analyze_alert returns the skill's exact output schema:
    classification, severity, is_true_positive, recommended_actions

Plus `normalize_to_incident`, which maps an arbitrary alert into the incident
schema the existing NetWitness triage/investigation pipeline consumes
(alertMeta.SourceIp/DestinationIp, id, title, createdBy, …) so a Splunk
alert, a CrowdStrike detection, an NDR event or a raw syslog line flows
through the whole pipeline unchanged.

Deterministic: no LLM, no network. Never mutates NetWitness-shaped input
destructively — normalization only fills fields that are absent.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

CONTEXTS = ("siem", "edr", "ndr", "custom")

# skill validation rule: alert_data.has_keys(['timestamp','source','message'])
# — accept common real-world aliases so we don't reject on cosmetics
_FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "@timestamp", "eventtime", "event_time",
                  "_time", "created", "createddate", "date", "occurred"),
    "source": ("source", "src", "sensor", "host", "hostname", "device",
               "product", "log_source", "sourcetype", "vendor"),
    "message": ("message", "msg", "description", "raw", "raw_log", "text",
                "signature", "rule", "rule_name", "name", "title", "alert",
                "detail", "summary"),
}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_USER_RE = re.compile(r"(?:user(?:name)?|account)[=:\s]+([A-Za-z0-9._\\-]{2,40})", re.I)
_HOST_RE = re.compile(r"(?:host(?:name)?|computer|machine)[=:\s]+([A-Za-z0-9._\-]{2,60})", re.I)

# indicator regexes — extend the skill's log_analyzer.py set and map each to
# a MITRE technique from the skill's coverage table. (label, regex, category,
# tactic, technique, weight)
_INDICATORS: list[tuple[str, str, str, str, str, int]] = [
    ("failed_login", r"failed|invalid password|authentication fail|logon failure|"
     r"bad password|access denied", "Brute Force", "Credential Access", "T1110", 2),
    ("privilege_escalation", r"sudo|su\s+-|escalat|runas|uac bypass|token impersonat|"
     r"getsystem", "Privilege Escalation", "Privilege Escalation", "T1548", 3),
    ("malware", r"malware|trojan|ransomware|\bvirus\b|backdoor|\bc2\b|beacon|"
     r"cobalt strike|meterpreter", "Malware", "Execution", "T1059", 4),
    ("lateral_movement", r"psexec|\bwmic\b|\bsmb\b|\brdp\b|pass-the-hash|"
     r"remote exec|winrm", "Lateral Movement", "Lateral Movement", "T1021", 3),
    ("persistence", r"registry run|scheduled task|autorun|startup folder|"
     r"crontab|new service|\bwmi\b subscription", "Persistence", "Persistence", "T1547", 2),
    ("phishing", r"phish|malicious attachment|suspicious email|spoofed sender|"
     r"credential harvest", "Phishing", "Initial Access", "T1566", 2),
    ("exfiltration", r"exfiltrat|data transfer to|large upload|dns tunnel",
     "Exfiltration", "Exfiltration", "T1048", 3),
    ("suspicious_ip", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "Network Indicator",
     "Command and Control", "T1071", 1),
]

_SEVERITY_BY_SCORE = [(9, "Critical"), (6, "High"), (3, "Medium"), (1, "Low"), (0, "Informational")]

_ACTIONS = {
    "failed_login": "Review authentication logs for the source account; enforce lockout / MFA",
    "privilege_escalation": "Isolate the host and audit privileged group membership and token use",
    "malware": "Quarantine the endpoint; capture a memory image; hunt the sample hash fleet-wide",
    "lateral_movement": "Segment the network; review remote-execution and admin-share access logs",
    "persistence": "Audit scheduled tasks / registry run keys / services for unauthorized entries",
    "phishing": "Pull the message from mailboxes; reset the targeted user's credentials",
    "exfiltration": "Block the destination; quantify data moved; engage DLP and legal/notification",
    "suspicious_ip": "Enrich the IP against threat intel and block at the perimeter if malicious",
}


def _is_private_ip(v: str) -> bool:
    try:
        parts = [int(x) for x in v.split(".")]
        if len(parts) != 4 or any(p > 255 for p in parts):
            return None  # not a valid IP → excluded by caller
        return (parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31)
                or (parts[0] == 192 and parts[1] == 168) or parts[0] == 127
                or parts[0] == 169 and parts[1] == 254)
    except Exception:
        return None


def _resolve(alert: dict, canonical: str) -> Any:
    """Return the first present alias value for a canonical field."""
    low = {str(k).lower(): v for k, v in alert.items()}
    for alias in _FIELD_ALIASES[canonical]:
        if low.get(alias) not in (None, "", [], {}):
            return low[alias]
    return None


def validate_alert(alert: dict) -> dict:
    """Skill rule `alert_structure`: alert must resolve timestamp, source,
    message. Returns {ok, error_code, error, missing}."""
    if not isinstance(alert, dict):
        return {"ok": False, "error_code": "E_INVALID_ALERT",
                "error": "Alert data missing required fields", "missing": list(_FIELD_ALIASES)}
    missing = [f for f in _FIELD_ALIASES if _resolve(alert, f) is None]
    if missing:
        return {"ok": False, "error_code": "E_INVALID_ALERT", "code": 2001,
                "error": "Alert data missing required fields "
                         f"({', '.join(missing)}). Ensure alert contains "
                         "timestamp, source, message.",
                "missing": missing}
    return {"ok": True, "error_code": None, "error": None, "missing": []}


def _scan_text(text: str) -> list[dict]:
    hits = []
    for label, pat, cat, tactic, tech, weight in _INDICATORS:
        n = len(re.findall(pat, text, re.I))
        if n:
            hits.append({"label": label, "count": n, "category": cat,
                         "tactic": tactic, "technique": tech, "weight": weight})
    return hits


def analyze_alert(alert: dict, context: str = "siem") -> dict:
    """The skill's `analyze_alert` operation. Deterministic triage of a single
    alert. Output schema matches the skill exactly:
    {classification, severity, is_true_positive, recommended_actions} (plus
    supporting detail: matched indicators, MITRE, validation)."""
    context = context if context in CONTEXTS else "custom"
    val = validate_alert(alert)
    if not val["ok"]:
        return {"classification": "invalid", "severity": "Informational",
                "is_true_positive": False,
                "recommended_actions": [val["error"]],
                "indicators": [], "mitre": [], "validation": val, "context": context}

    # scan the message + every scalar field value
    blob_parts = [str(_resolve(alert, "message") or "")]
    for k, v in alert.items():
        if isinstance(v, (str, int, float)):
            blob_parts.append(f"{k}={v}")
    blob = " \n".join(blob_parts)
    hits = _scan_text(blob)

    # score = sum of weights of the strongest hit per category (dedup on label)
    by_label = {}
    for h in hits:
        if h["label"] not in by_label or h["weight"] > by_label[h["label"]]["weight"]:
            by_label[h["label"]] = h
    score = sum(h["weight"] for h in by_label.values())
    strong = [h for h in by_label.values() if h["weight"] >= 3]

    severity = next(s for thr, s in _SEVERITY_BY_SCORE if score >= thr)
    # a confirmed strong TTP (priv-esc, malware, lateral movement, exfil)
    # floors severity at High regardless of raw score; two of them -> Critical
    _RANK = ["Informational", "Low", "Medium", "High", "Critical"]
    if strong and _RANK.index(severity) < _RANK.index("High"):
        severity = "High"
    if len(strong) >= 2 and _RANK.index(severity) < _RANK.index("Critical"):
        severity = "Critical"
    # true-positive heuristic: any strong indicator, or ≥2 corroborating
    # indicators — a single suspicious_ip alone stays "needs review"
    is_tp = bool(strong) or len([h for h in by_label if h != "suspicious_ip"]) >= 2

    if not by_label:
        classification = "no_indicators"
    elif strong:
        classification = strong[0]["category"].lower().replace(" ", "_")
    else:
        classification = next(iter(by_label.values()))["category"].lower().replace(" ", "_")

    actions = [_ACTIONS[l] for l in by_label if l in _ACTIONS]
    if not actions:
        actions = ["No high-confidence indicators; correlate with other sources before closing"]

    mitre = sorted({(h["tactic"], h["technique"]) for h in by_label.values()})
    return {
        "classification": classification,
        "severity": severity,
        "is_true_positive": is_tp,
        "recommended_actions": actions,
        "indicators": sorted(by_label.values(), key=lambda h: -h["weight"]),
        "mitre": [{"tactic": t, "technique": q} for t, q in mitre],
        "score": score,
        "validation": val,
        "context": context,
    }


def _extract_iocs(alert: dict) -> dict:
    blob = " ".join(f"{k}={v}" for k, v in alert.items()
                    if isinstance(v, (str, int, float)))
    ips = [ip for ip in dict.fromkeys(_IPV4_RE.findall(blob))
           if _is_private_ip(ip) is not None]   # valid IPs only
    # explicit src/dst fields win for direction
    low = {str(k).lower(): str(v) for k, v in alert.items() if isinstance(v, (str, int, float))}
    src = next((low[k] for k in ("src_ip", "source_ip", "src", "sourceip") if k in low
                and _IPV4_RE.match(low[k] or "")), None)
    dst = next((low[k] for k in ("dst_ip", "dest_ip", "destination_ip", "dstip") if k in low
                and _IPV4_RE.match(low[k] or "")), None)
    src_ips = [src] if src else [ip for ip in ips if _is_private_ip(ip)][:1]
    dst_ips = [dst] if dst else [ip for ip in ips if ip not in src_ips]
    users = dict.fromkeys(_USER_RE.findall(blob))
    hosts = dict.fromkeys(_HOST_RE.findall(blob))
    hashes = dict.fromkeys(_HASH_RE.findall(blob))
    return {"src_ips": [i for i in src_ips if i], "dst_ips": dst_ips[:20],
            "users": list(users)[:5], "hosts": list(hosts)[:5],
            "hashes": list(hashes)[:5]}


def normalize_to_incident(alert: dict, context: str = "siem") -> dict:
    """Map an arbitrary alert into the NetWitness incident schema the triage
    pipeline consumes. Additive: if the alert is already NetWitness-shaped
    (has alertMeta), the original fields are preserved and only gaps filled."""
    context = context if context in CONTEXTS else "custom"
    verdict = analyze_alert(alert, context)
    iocs = _extract_iocs(alert)

    msg = str(_resolve(alert, "message") or "").strip()
    ts = str(_resolve(alert, "timestamp") or datetime.now(timezone.utc).isoformat())
    src = str(_resolve(alert, "source") or context.upper())

    # stable id from content when the alert has none
    raw_id = (alert.get("id") or alert.get("_id") or alert.get("eventID")
              or alert.get("alert_id"))
    inc_id = str(raw_id) if raw_id else (
        "ALERT-" + hashlib.sha1(f"{ts}|{src}|{msg}".encode()).hexdigest()[:10].upper())

    inc = dict(alert)  # preserve everything the caller gave us
    inc.setdefault("id", inc_id)
    inc.setdefault("title", (msg[:120] or f"{context.upper()} alert from {src}"))
    inc.setdefault("created", ts)
    inc.setdefault("firstAlertTime", ts)
    inc.setdefault("priority", verdict["severity"])
    inc.setdefault("createdBy", f"Uploaded {context.upper()} alert")

    # only build alertMeta if absent (never clobber NetWitness's)
    if not isinstance(inc.get("alertMeta"), dict) or not inc.get("alertMeta"):
        meta: dict = {}
        if iocs["src_ips"]:
            meta["SourceIp"] = iocs["src_ips"]
        if iocs["dst_ips"]:
            meta["DestinationIp"] = iocs["dst_ips"]
        if meta:
            inc["alertMeta"] = meta

    # carry MITRE if triage doesn't already have it
    if verdict["mitre"]:
        inc.setdefault("mitre_tactic", verdict["mitre"][0]["tactic"])
        inc.setdefault("mitre_technique", verdict["mitre"][0]["technique"])

    inc["_source_format"] = context
    inc["_normalized_from_alert"] = True
    inc["_analyze_alert"] = verdict
    inc["_extracted_iocs"] = iocs
    return inc


def format_analysis(verdict: dict) -> str:
    """Plain-text rendering of an analyze_alert verdict (UI / logs)."""
    lines = [
        f"ALERT TRIAGE ({verdict['context'].upper()} source) — "
        f"classification: {verdict['classification']}, severity: {verdict['severity']}, "
        f"true-positive: {verdict['is_true_positive']}",
    ]
    for ind in verdict["indicators"][:8]:
        lines.append(f"  · {ind['label']} ×{ind['count']} → {ind['tactic']} "
                     f"({ind['technique']})")
    if verdict["recommended_actions"]:
        lines.append("  recommended actions:")
        for a in verdict["recommended_actions"]:
            lines.append(f"    - {a}")
    return "\n".join(lines)
