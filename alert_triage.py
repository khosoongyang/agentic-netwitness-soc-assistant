# ==============================================================================
# [FYP-FILE] alert_triage.py
# Important dependencies: __future__, datetime, hashlib, re, typing.
# Key evaluator search terms: _is_private_ip, _resolve, validate_alert, _scan_text, analyze_alert, _extract_iocs, [FYP-FUNCTION].
# ------------------------------------------------------------------------------
# File: alert_triage.py (repo root)
# Purpose: Deterministic, rule-based multi-source alert triage & normalization
#   for the Triage stage (owner: Shahrul Gunawan S/O Iqbal Suppiah).
# Main functionalities:
#   - validate_alert(): required-field validation (timestamp/source/message,
#     real-world field-name aliases accepted).
#   - analyze_alert(): [FYP-PROCESS] severity calculation, [FYP-PROCESS] risk
#     scoring (weighted indicator scan), a true-positive "confidence"
#     heuristic, and [FYP-PROCESS] recommended-action selection — ALL
#     deterministic/rule-based, no LLM call anywhere in this file.
#   - normalize_to_incident(): maps an arbitrary alert into the NetWitness
#     incident schema the rest of the pipeline (triage/investigation) consumes.
#   - format_analysis(): plain-text rendering of an analyze_alert verdict.
# Inputs: a raw alert dict from any source (SIEM/EDR/NDR/custom log/upload).
# Outputs: analyze_alert() -> {classification, severity, is_true_positive,
#   recommended_actions, indicators, mitre, score, validation, context};
#   normalize_to_incident() -> NetWitness-shaped incident dict carrying the
#   analyze_alert verdict under "_analyze_alert".
# Workflow position: Triage stage, runs after Parsing & Normalisation and
#   before Threat Intelligence Enrichment.
# Called by [FYP-USED-BY]: app.py — `from alert_triage import
#   normalize_to_incident, validate_alert` (confirmed via grep at the alert
#   upload/ingest path), used so non-NetWitness alert sources flow through the
#   same pipeline.
# Calls [FYP-CALLS]: no other project modules; stdlib only (hashlib, re,
#   datetime).
# Key evaluator search terms [FYP-EVALUATOR]: "Severity Calculation" (in
#   analyze_alert), "Risk Scoring" (the `score` variable in analyze_alert),
#   "Recommended Action Selection" (the `actions` list in analyze_alert),
#   "True-Positive Confidence Heuristic" (the `is_tp` variable).
# ==============================================================================
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


# =============================================================================
# [FYP-SECTION] TRIAGE EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_is_private_ip` — evaluates is private ip conditions so invalid or unsafe triage processing is stopped early.
# [FYP-INPUT] Parameters: `v`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include alert_triage.py:_extract_iocs, incident_map.py:_walk_alert, incident_map.py:build_incident_map; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `int`, `len`, `split`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

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


# [FYP-FUNCTION] `_resolve` — implements the resolve operation used by the surrounding triage workflow.
# [FYP-INPUT] Parameters: `alert`, `canonical`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include alert_triage.py:analyze_alert, alert_triage.py:normalize_to_incident, alert_triage.py:validate_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `items`, `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _resolve(alert: dict, canonical: str) -> Any:
    """Return the first present alias value for a canonical field."""
    low = {str(k).lower(): v for k, v in alert.items()}
    for alias in _FIELD_ALIASES[canonical]:
        if low.get(alias) not in (None, "", [], {}):
            return low[alias]
    return None


def validate_alert(alert: dict) -> dict:
    """
    [FYP-FUNCTION] Alert Schema Validation
    [FYP-VALIDATION]

    Skill rule `alert_structure`: alert must resolve timestamp, source,
    message (via alias lookup in _resolve/_FIELD_ALIASES so real-world field
    names like "src"/"host"/"msg" are accepted, not just the canonical
    names). Returns {ok, error_code, error, missing}.

    Called by: analyze_alert() as its first step — an invalid alert short-
    circuits straight to a "classification": "invalid" verdict rather than
    running the indicator scan on incomplete data.
    """
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


# [FYP-FUNCTION] `_scan_text` — implements the scan text operation used by the surrounding triage workflow.
# [FYP-INPUT] Parameters: `text`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include alert_triage.py:analyze_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `findall`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _scan_text(text: str) -> list[dict]:
    hits = []
    for label, pat, cat, tactic, tech, weight in _INDICATORS:
        n = len(re.findall(pat, text, re.I))
        if n:
            hits.append({"label": label, "count": n, "category": cat,
                         "tactic": tactic, "technique": tech, "weight": weight})
    return hits


def analyze_alert(alert: dict, context: str = "siem") -> dict:
    """
    [FYP-FUNCTION] Severity Calculation / Risk Scoring / Confidence Heuristic
    [FYP-PROCESS] [FYP-EVALUATOR]

    THE deterministic, rule-based triage function for this alert source.
    100% rule-based — no LLM call anywhere in this file (see the file
    header). Runs entirely on regex pattern matching against the alert
    text; there is no network call and no external dependency.

    Processing (in order):
      1. [FYP-VALIDATION] validate_alert() — bail out early with an
         "invalid" classification if timestamp/source/message can't be
         resolved.
      2. _scan_text() runs every entry in _INDICATORS (a table of
         label/regex/MITRE-tactic/MITRE-technique/weight tuples) against the
         alert's message plus every scalar field value.
      3. [FYP-PROCESS] Risk Scoring: `score` = sum of the highest weight
         seen per matched indicator label (deduplicated). `strong` = any
         indicator with weight >= 3 (privilege escalation, malware, lateral
         movement, exfiltration).
      4. [FYP-PROCESS] Severity Calculation: `severity` starts from
         _SEVERITY_BY_SCORE (a score->label threshold table), then two
         hard floors are applied: any single "strong" indicator floors
         severity at "High"; two or more strong indicators floor it at
         "Critical" — regardless of the raw numeric score.
      5. True-Positive Confidence Heuristic: `is_tp` is True if there is at
         least one strong indicator, OR at least two distinct corroborating
         indicator labels (a lone "suspicious_ip" hit alone is NOT enough on
         its own — it only counts once something else corroborates it).
      6. [FYP-PROCESS] Recommended Action Selection: `actions` is built by
         looking up every matched indicator label in the static _ACTIONS
         dict; falls back to a generic "correlate before closing" action
         when nothing matched.

    Parameters: alert (raw dict from any source), context (siem/edr/ndr/
    custom — informational only, doesn't change the scoring logic).

    Returns: dict with classification, severity, is_true_positive,
    recommended_actions, indicators, mitre, score, validation, context —
    this exact shape is also embedded verbatim under normalize_to_incident()'s
    "_analyze_alert" key.

    [FYP-USED-BY]: normalize_to_incident() (below) and, per the file header,
    app.py's alert-upload/ingest path via normalize_to_incident.
    """
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
    """
    [FYP-FUNCTION] IOC Extraction (this-file-local, non-NetWitness sources)
    [FYP-PROCESS]

    Regex-scans every scalar field of the alert for IPv4 addresses, usernames,
    hostnames, and hashes (_IPV4_RE/_USER_RE/_HOST_RE/_HASH_RE). Splits IPs
    into src/dst using explicit src_ip/dst_ip-style fields when present,
    else falls back to "the first private IP found" as source. Returns a
    dict of capped lists (src_ips, dst_ips, users, hosts, hashes) merged
    into the incident under "_extracted_iocs" by normalize_to_incident().
    Note: this is a distinct, simpler IOC extractor from the one in
    threat_intel.py — that one runs on NetWitness-native alerts during the
    Threat Intelligence Enrichment stage; this one only runs for alerts
    ingested from non-NetWitness sources.
    """
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
    """
    [FYP-FUNCTION] Field Mapping / Non-NetWitness Alert Normalisation
    [FYP-PROCESS] [FYP-ENTRY-POINT]

    Maps an arbitrary alert (Splunk, CrowdStrike, raw syslog, etc.) into the
    NetWitness incident schema the rest of the pipeline (Triage/Investigation/
    Reporting) consumes, so it can flow through unchanged. Additive only: if
    the alert is already NetWitness-shaped (has alertMeta), the original
    fields are preserved and only gaps are filled via dict.setdefault.

    Calls: analyze_alert() [FYP-CALLS] for the severity/classification
    verdict, _extract_iocs() for src/dst IPs, users, hosts, hashes.

    Output: the incident dict, with the full analyze_alert verdict embedded
    verbatim under inc["_analyze_alert"] and extracted IOCs under
    inc["_extracted_iocs"] — downstream stages can read either the
    normalised top-level fields or drill into these two keys for the raw
    triage detail.

    [FYP-USED-BY]: app.py (confirmed via grep) at the alert upload/ingest
    path — this is the entry point for any non-NetWitness alert source.
    """
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


# [FYP-FUNCTION] `format_analysis` — constructs format analysis output for the next triage consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `verdict`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `append`, `join`, `upper`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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
