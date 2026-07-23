"""
threat_hunting.py — proactive threat-hunting analyzer (standalone).

Faithful adaptation of the threat-detection skill
(github.com/alirezarezvani/claude-skills →
engineering-team/skills/threat-detection/scripts/threat_signal_analyzer.py).
Ports its three deterministic modes verbatim:

  * score_hypothesis — hunt-hypothesis scoring
        priority = base(keywords×2 + T-codes×3)
                   + actor_relevance×3 + control_gap×2 + data_availability×1
    with the skill's keyword→MITRE map and per-tactic data sources
  * detect_anomalies — z-score behavioural anomaly detection
        z<2 normal · 2.0–2.9 soft (monitor) · ≥3.0 hard (escalate)
        + suspicious-hours (22:00–06:00) flag
  * ioc_sweep_plan — IOC sweep targets + 30-day staleness / coverage

`build_hunt_package(incident, triage_result, db_path)` is the investigation
entry point: it (1) generates and scores follow-up hunt hypotheses from the
incident's observed MITRE tactic/technique + focus entity, and (2) runs the
skill's z-score anomaly detection over that entity's per-day activity in the
corpus (read-only) versus its OWN baseline — turning "48 incidents on
2025-06-19" into "z=3.2, hard anomaly, escalate".

NOTE (design constraint): this module is entirely self-contained — it does
NOT edit or import the investigation agent's internals. It is surfaced
through the app UI (a 🎯 Map panel). Deterministic: no LLM, no network.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from statistics import mean, pstdev

MITRE_PATTERN = r'T\d{4}(?:\.\d{3})?'

# ── skill tables (verbatim) ──────────────────────────────────────────────────

HUNT_DATA_SOURCES = {
    "initial_access": ["web_proxy_logs", "email_gateway_logs", "firewall_logs", "dns_logs"],
    "execution": ["edr_process_logs", "sysmon_event_1", "windows_event_4688", "auditd"],
    "persistence": ["windows_event_4698", "registry_logs", "cron_logs", "systemd_logs"],
    "privilege_escalation": ["windows_event_4672", "sudo_logs", "auditd", "edr_process_logs"],
    "defense_evasion": ["edr_process_logs", "windows_event_4663", "sysmon_event_11", "antivirus_logs"],
    "credential_access": ["windows_event_4625", "windows_event_4648", "lsass_access_events", "vault_audit_logs"],
    "discovery": ["windows_event_4688", "auditd", "network_flow_logs", "dns_logs"],
    "lateral_movement": ["windows_event_4624", "smb_logs", "winrm_logs", "network_flow_logs"],
    "collection": ["dlp_alerts", "file_access_logs", "clipboard_monitoring", "screen_capture_logs"],
    "command_and_control": ["dns_logs", "proxy_logs", "firewall_logs", "netflow_records"],
    "exfiltration": ["dlp_alerts", "firewall_logs", "proxy_logs", "dns_logs"],
    "impact": ["edr_process_logs", "backup_logs", "file_integrity_monitoring"],
}

IOC_SWEEP_TARGETS = {
    "ip": ["firewall_logs", "netflow_records", "proxy_logs", "threat_intel_platform"],
    "domain": ["dns_logs", "proxy_logs", "email_gateway_logs", "threat_intel_platform"],
    "hash": ["edr_hash_scanning", "antivirus_logs", "file_integrity_monitoring", "threat_intel_platform"],
    "url": ["proxy_logs", "email_gateway_logs", "browser_history_logs"],
    "email": ["email_gateway_logs", "dlp_alerts"],
    "user_agent": ["proxy_logs", "web_application_logs"],
}

IOC_MAX_AGE_DAYS = 30

HUNT_KEYWORDS = {
    "wmi": {"tactic": "lateral_movement", "mitre": "T1047", "data_source_key": "lateral_movement"},
    "powershell": {"tactic": "execution", "mitre": "T1059.001", "data_source_key": "execution"},
    "lolbin": {"tactic": "defense_evasion", "mitre": "T1218", "data_source_key": "defense_evasion"},
    "lolbas": {"tactic": "defense_evasion", "mitre": "T1218", "data_source_key": "defense_evasion"},
    "pass-the-hash": {"tactic": "lateral_movement", "mitre": "T1550.002", "data_source_key": "lateral_movement"},
    "pth": {"tactic": "lateral_movement", "mitre": "T1550.002", "data_source_key": "lateral_movement"},
    "credential dump": {"tactic": "credential_access", "mitre": "T1003", "data_source_key": "credential_access"},
    "mimikatz": {"tactic": "credential_access", "mitre": "T1003.001", "data_source_key": "credential_access"},
    "lateral": {"tactic": "lateral_movement", "mitre": "T1021", "data_source_key": "lateral_movement"},
    "persistence": {"tactic": "persistence", "mitre": "T1053", "data_source_key": "persistence"},
    "exfil": {"tactic": "exfiltration", "mitre": "T1041", "data_source_key": "exfiltration"},
    "beacon": {"tactic": "command_and_control", "mitre": "T1071", "data_source_key": "command_and_control"},
    "c2": {"tactic": "command_and_control", "mitre": "T1071", "data_source_key": "command_and_control"},
    "ransomware": {"tactic": "impact", "mitre": "T1486", "data_source_key": "execution"},
    "privilege": {"tactic": "privilege_escalation", "mitre": "T1068", "data_source_key": "privilege_escalation"},
    "injection": {"tactic": "defense_evasion", "mitre": "T1055", "data_source_key": "defense_evasion"},
    "apt": {"tactic": "initial_access", "mitre": "T1190", "data_source_key": "initial_access"},
    "supply chain": {"tactic": "initial_access", "mitre": "T1195", "data_source_key": "initial_access"},
    "phishing": {"tactic": "initial_access", "mitre": "T1566", "data_source_key": "initial_access"},
    "scheduled task": {"tactic": "persistence", "mitre": "T1053", "data_source_key": "persistence"},
}

ANOMALY_TIME_HOURS_SUSPICIOUS = list(range(0, 6)) + list(range(22, 24))

# MITRE tactic name (as our triage emits it) → skill's snake_case data-source key
_TACTIC_KEY = {
    "initial access": "initial_access", "execution": "execution",
    "persistence": "persistence", "privilege escalation": "privilege_escalation",
    "defense evasion": "defense_evasion", "credential access": "credential_access",
    "discovery": "discovery", "lateral movement": "lateral_movement",
    "collection": "collection", "command and control": "command_and_control",
    "exfiltration": "exfiltration", "impact": "impact",
}
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")


# ── mode 1: hunt-hypothesis scoring (skill's hunt_mode, refactored) ──────────

def score_hypothesis(hypothesis: str, actor_relevance: int = 2,
                     control_gap: int = 2, data_availability: int = 2) -> dict:
    """Skill's hunt-mode scoring for a single hypothesis string."""
    hypothesis = hypothesis or ""
    low = hypothesis.lower()
    matched_tcodes = list(set(re.findall(MITRE_PATTERN, hypothesis, re.IGNORECASE)))

    matched_keywords, seen = [], set()
    for kw in sorted(HUNT_KEYWORDS.keys(), key=lambda k: -len(k)):
        if kw in low and kw not in seen:
            matched_keywords.append(kw)
            seen.add(kw)

    tactics = {HUNT_KEYWORDS[kw]["tactic"] for kw in matched_keywords}
    for tcode in matched_tcodes:
        for d in HUNT_KEYWORDS.values():
            if d["mitre"].upper() == tcode.upper():
                tactics.add(d["tactic"])
                break

    data_sources, seen_src = [], set()
    for t in tactics:
        for s in HUNT_DATA_SOURCES.get(t, []):
            if s not in seen_src:
                seen_src.add(s)
                data_sources.append(s)

    base = len(matched_keywords) * 2 + len(matched_tcodes) * 3
    priority = base + actor_relevance * 3 + control_gap * 2 + data_availability
    return {
        "hypothesis": hypothesis,
        "matched_keywords": matched_keywords,
        "matched_tcodes": matched_tcodes,
        "tactics": sorted(tactics),
        "data_sources_required": data_sources,
        "priority_score": priority,
        "pursue_recommendation": priority >= 5,
        "data_quality_check_required": len(data_sources) == 0 or data_availability < 2,
    }


# ── mode 2: z-score anomaly detection (skill's anomaly_mode, refactored) ─────

def detect_anomalies(events: list, baseline_mean: float, baseline_std: float) -> dict:
    """Skill's z-score anomaly detection over a list of {volume,timestamp,
    entity,action} events against a baseline."""
    if baseline_std <= 0:
        return {"error": "baseline_std must be > 0", "anomaly_events": [],
                "hard_flag_count": 0, "soft_flag_count": 0}
    anomaly_events, soft, hard, time_anom = [], 0, 0, 0
    entity_counts: dict = {}
    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        volume = ev.get("volume")
        ts = ev.get("timestamp", "")
        entity = ev.get("entity", f"unknown_{idx}")
        z = None
        sf = hf = False
        if volume is not None:
            try:
                volume = float(volume)
                z = (volume - baseline_mean) / baseline_std
                if z >= 3.0:
                    hf = True; hard += 1
                    entity_counts[entity] = entity_counts.get(entity, 0) + 1
                elif z >= 2.0:
                    sf = True; soft += 1
                    entity_counts[entity] = entity_counts.get(entity, 0) + 1
            except (TypeError, ValueError):
                pass
        hour = None
        if ts:
            try:
                hour = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).hour
            except ValueError:
                for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        hour = datetime.strptime(str(ts), fmt).hour
                        break
                    except ValueError:
                        continue
        ta = hour is not None and hour in ANOMALY_TIME_HOURS_SUSPICIOUS
        if ta:
            time_anom += 1
        if sf or hf or ta:
            anomaly_events.append({
                "entity": entity, "timestamp": ts, "volume": volume,
                "z_score": round(z, 4) if z is not None else None,
                "soft_flag": sf, "hard_flag": hf, "time_anomaly": ta, "hour": hour})
    total = len(events)
    top = sorted(entity_counts.items(), key=lambda x: -x[1])[:5]
    if hard:
        action = (f"{hard} hard anomaly(ies) (z>=3.0) — initiate threat hunt on "
                  + (", ".join(e for e, _ in top[:3]) or "affected entities")
                  + "; escalate if the entity is high-value.")
    elif soft:
        action = (f"{soft} soft anomaly(ies) (z>=2.0) — investigate "
                  + (", ".join(e for e, _ in top[:3]) or "affected entities")
                  + " and cross-correlate with other log sources.")
    elif time_anom:
        action = (f"No volume anomalies, but {time_anom} event(s) during suspicious "
                  "hours (22:00-06:00) — verify whether expected.")
    else:
        action = "No anomalies detected; baseline stable for the provided set."
    return {"total_events": total, "baseline_mean": round(baseline_mean, 2),
            "baseline_std": round(baseline_std, 2),
            "anomaly_events": anomaly_events, "soft_flag_count": soft,
            "hard_flag_count": hard, "time_anomaly_count": time_anom,
            "risk_score": round(hard / total, 4) if total else 0.0,
            "top_anomalous_entities": [{"entity": e, "anomaly_count": c} for e, c in top],
            "recommended_action": action}


# ── mode 3: IOC sweep plan (skill's ioc_mode, refactored) ────────────────────

def ioc_sweep_plan(iocs: dict, ioc_date: str | None = None) -> dict:
    type_keys = {"ip": ["ip", "ips"], "domain": ["domain", "domains"],
                 "hash": ["hash", "hashes"], "url": ["url", "urls"],
                 "email": ["email", "emails"], "user_agent": ["user_agent", "user_agents"]}
    counts = {}
    for t, keys in type_keys.items():
        for k in keys:
            v = iocs.get(k)
            if isinstance(v, list) and v:
                counts[t] = len(v)
                break
    stale = False
    age = None
    if ioc_date:
        try:
            d = datetime.strptime(ioc_date, "%Y-%m-%d")
            age = (datetime.now() - d).days
            stale = age > IOC_MAX_AGE_DAYS
        except ValueError:
            pass
    plan = {t: {"count": c, "targets": IOC_SWEEP_TARGETS.get(t, []), "stale": stale}
            for t, c in counts.items()}
    coverage = round(len(counts) / len(IOC_SWEEP_TARGETS), 4) if IOC_SWEEP_TARGETS else 0.0
    return {"ioc_counts": counts, "sweep_plan": plan, "coverage_score": coverage,
            "freshness_warning": stale, "ioc_age_days": age}


# ── investigation entry point ────────────────────────────────────────────────

def _entity_daily_counts(db_path: str, entity: str, max_rows: int = 3000) -> list:
    """Per-day incident counts for `entity` across the corpus (read-only)."""
    boundary = re.compile(r"(?<![0-9A-Za-z.])" + re.escape(entity) + r"(?![0-9A-Za-z.])")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    try:
        rows = con.execute(
            "SELECT raw_json FROM incidents WHERE instr(raw_json, ?) > 0 LIMIT ?",
            (entity, max_rows)).fetchall()
    finally:
        con.close()
    per_day: dict = {}
    for (raw,) in rows:
        if not boundary.search(raw):
            continue
        try:
            d = json.loads(raw)
        except Exception:
            continue
        day = str(d.get("created") or "")[:10]
        if day:
            per_day[day] = per_day.get(day, 0) + 1
    return sorted(({"timestamp": k + "T12:00:00Z", "entity": entity,
                    "action": "incident", "volume": v}
                   for k, v in per_day.items()), key=lambda e: e["timestamp"])


def build_hunt_package(incident: dict, triage_result: dict | None = None,
                       db_path: str | None = None) -> dict:
    """Proactive hunt package for one incident: scored follow-up hunt
    hypotheses + statistical anomaly detection over the focus entity."""
    ticket = (triage_result or {}).get("ticket", {})
    tactic = str(((triage_result or {}).get("metakeys_payload") or {}).get("mitre_tactic")
                 or ticket.get("mitre_tactic") or incident.get("mitre_tactic") or "").strip()
    technique = str(((triage_result or {}).get("metakeys_payload") or {}).get("mitre_technique")
                    or ticket.get("mitre_technique") or incident.get("mitre_technique") or "").strip()
    m = _TITLE_ENTITY_RE.search(str(incident.get("title") or ""))
    entity = m.group(1).strip() if m else ""

    # 1. hunt hypotheses — seed from the observed tactic + tactic playbooks
    hyps = []
    tkey = _TACTIC_KEY.get(tactic.lower())
    if tactic and entity:
        seed = f"{tactic} activity involving {entity}" + (f" ({technique})" if technique else "")
        hyps.append(score_hypothesis(seed, actor_relevance=2, control_gap=2, data_availability=2))
    # tactic-specific playbook hunts (from the skill's high-value hypotheses)
    _PLAYBOOK = {
        "lateral_movement": ["Pass-the-Hash lateral movement from an unexpected source host",
                             "WMI remote execution with unusual parent-child chain"],
        "command_and_control": ["Beaconing C2 via jitter-heavy intervals in DNS/proxy logs"],
        "credential_access": ["LSASS memory access from a non-system process",
                              "Kerberoasting: high-volume TGS requests for service accounts"],
        "persistence": ["Scheduled task created in a non-standard directory"],
        "execution": ["PowerShell with DownloadString/IEX or encoded command"],
        "defense_evasion": ["LOLBin execution (certutil/regsvr32/mshta) with network activity"],
        "impact": ["Mass file modification / shadow-copy deletion (ransomware precursor)"],
        "exfiltration": ["Unusual outbound data volume or DNS tunnelling"],
    }
    for pb in _PLAYBOOK.get(tkey or "", []):
        hyps.append(score_hypothesis(pb + (f" — pivot on {entity}" if entity else ""),
                                     actor_relevance=2, control_gap=2, data_availability=2))
    hyps.sort(key=lambda h: -h["priority_score"])

    # 2. anomaly detection over the focus entity's per-day activity
    anomalies = None
    if entity and db_path:
        try:
            series = _entity_daily_counts(db_path, entity)
            vols = [e["volume"] for e in series]
            if len(vols) >= 14:                      # skill: ≥14 days baseline
                mu, sd = mean(vols), pstdev(vols)
                if sd > 0:
                    anomalies = detect_anomalies(series, mu, sd)
                    anomalies["baseline_days"] = len(vols)
                else:
                    anomalies = {"insufficient": f"flat activity ({len(vols)} days, no variance)"}
            else:
                anomalies = {"insufficient":
                             f"only {len(vols)} active day(s); need >=14 for a baseline"}
        except Exception as exc:
            anomalies = {"error": str(exc)}

    if not hyps and not anomalies:
        return {"available": False, "reason": "no MITRE tactic or focus entity to hunt on"}
    return {"available": True, "entity": entity, "tactic": tactic,
            "technique": technique, "hypotheses": hyps[:6], "anomalies": anomalies}


def format_hunt(pkg: dict) -> str:
    """Plain-text rendering for the UI."""
    if not pkg.get("available"):
        return "THREAT HUNTING: " + pkg.get("reason", "unavailable")
    lines = ["PROACTIVE THREAT HUNTING (recommended follow-up hunts + statistical "
             "anomaly detection — hunts are prioritised recommendations)"]
    if pkg["hypotheses"]:
        lines.append("  recommended hunts (priority order):")
        for h in pkg["hypotheses"]:
            go = "PURSUE" if h["pursue_recommendation"] else "hold"
            ds = ", ".join(h["data_sources_required"][:4]) or "n/a"
            lines.append(f"    [{h['priority_score']:>2} · {go}] {h['hypothesis']}")
            lines.append(f"         data sources: {ds}")
    a = pkg.get("anomalies")
    if isinstance(a, dict) and a.get("total_events") is not None:
        lines.append(f"  entity activity anomalies ({pkg['entity']}, baseline "
                     f"{a.get('baseline_days','?')} days, mean {a['baseline_mean']}, "
                     f"std {a['baseline_std']}):")
        lines.append(f"      {a['hard_flag_count']} hard (z>=3.0), "
                     f"{a['soft_flag_count']} soft (z>=2.0)")
        for e in sorted(a["anomaly_events"], key=lambda x: -(x["z_score"] or 0))[:5]:
            tag = "HARD" if e["hard_flag"] else ("soft" if e["soft_flag"] else "time")
            lines.append(f"      {e['timestamp'][:10]}: volume {int(e['volume'])} "
                         f"(z={e['z_score']}) [{tag}]")
        lines.append(f"      → {a['recommended_action']}")
    elif isinstance(a, dict) and a.get("insufficient"):
        lines.append(f"  entity activity anomalies: {a['insufficient']}")
    return "\n".join(lines)
