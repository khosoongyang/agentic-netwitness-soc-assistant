# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, hashlib, json, re, datetime, pathlib.
# =============================================================================
# File: scripts/wazuh_alert_to_incident.py
# Purpose: Triage Step 2 (X8) -- Wazuh LAB REPLAY path. Converts alerts
#   exported from a Wazuh lab (index wazuh-alerts-*, Windows eventchannel /
#   Sysmon) into the same NetWitness-like incident/event shape Triage reads
#   (alerts[].originalAlert.events[] with filename_src, param_src,
#   directory_src, user_src, alias_host, checksum_src, ...), detection
#   source "Wazuh", so lab canary runs can be fed to scripts/eval_triage.py.
# Inputs: a JSON array of Wazuh alerts, an OpenSearch/Elasticsearch search
#   response ({hits:{hits:[{_source:...}]}}), or NDJSON (one alert per line,
#   e.g. /var/ossec/logs/alerts/alerts.json).
# Outputs: an eval case file (default tests/triage_eval/lab/<name>.json)
#   with label.source = lab_ground_truth (you ran the technique yourself).
# Key evaluator search terms: wazuh_alert_to_incident, lab_ground_truth,
#   canary, [FYP-TRIAGE-STEP2].
# =============================================================================
"""Usage:
  python scripts/wazuh_alert_to_incident.py wazuh_export.json --name lab_T1105_certutil \\
      --label true_positive --technique T1105 --labeller "<your name>" \\
      [--rationale "Invoke-AtomicTest T1105 -TestNumbers 7 on LAB-WIN10 at 02:20"] \\
      [--host LAB-WIN10] [--since 2026-09-30T02:00:00Z] [--until 2026-09-30T03:00:00Z]

Lab VMs only -- never run the techniques on corporate or production machines
(see docs/triage-evaluation.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / "tests" / "triage_eval" / "lab"
DETECTION_SOURCE = "Wazuh"
DISPOSITIONS = ("true_positive", "false_positive", "benign_expected", "needs_info")
EXPECTED_BY_LABEL = {
    "true_positive": {"disposition_acceptable": ["true_positive", "needs_info"],
                      "must_not": ["false_positive", "benign_expected"]},
    "benign_expected": {"disposition_acceptable": ["needs_info", "benign_expected"], "must_not": []},
    "false_positive": {"disposition_acceptable": ["false_positive", "needs_info"], "must_not": []},
    "needs_info": {"disposition_acceptable": ["needs_info"], "must_not": []},
}
# Wazuh rule level (0-15) -> NetWitness-like 0-100 risk score / priority.
_PRIORITY = ((12, "CRITICAL"), (9, "HIGH"), (5, "MEDIUM"), (0, "LOW"))


# =============================================================================
# [FYP-SECTION] INPUT
# =============================================================================

def load_wazuh_alerts(path: Path) -> list[dict]:
    """JSON array, OpenSearch search response, a single alert, or NDJSON."""
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict) and isinstance((data.get("hits") or {}).get("hits"), list):
        return [h.get("_source") or {} for h in data["hits"]["hits"]]
    if isinstance(data, dict):
        return [data]
    return [a for a in data if isinstance(a, dict)]


# =============================================================================
# [FYP-SECTION] FIELD MAPPING
# =============================================================================

def _ci(d: dict, *keys: str) -> Any:
    """Case-insensitive lookup (Wazuh camelCase vs raw Sysmon PascalCase)."""
    if not isinstance(d, dict):
        return None
    lower = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
    return None


def _split_path(image: str | None) -> tuple[str | None, str | None]:
    if not image:
        return None, None
    image = str(image).strip().strip('"')
    if "\\" not in image and "/" not in image:
        return image, None
    i = max(image.rfind("\\"), image.rfind("/"))
    return image[i + 1:] or None, image[: i + 1]


def _hashes(value: str | None) -> list[str]:
    """Sysmon 'SHA1=..,MD5=..,SHA256=..,IMPHASH=..' -> [sha256, md5, sha1]
    (NetWitness checksum_src order: strongest first; IMPHASH dropped)."""
    if not value:
        return []
    parts = dict(p.split("=", 1) for p in str(value).split(",") if "=" in p)
    order = ("SHA256", "MD5", "SHA1")
    return [parts[k].lower() for k in order if parts.get(k)]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _event_time_ms(alert: dict) -> int | None:
    ts = alert.get("timestamp") or _ci(((alert.get("data") or {}).get("win") or {}).get("system") or {},
                                       "systemTime")
    if not ts:
        return None
    s = str(ts).replace("Z", "+00:00")
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)          # +0000 -> +00:00
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)                    # 7-digit .NET ticks -> micro
    try:
        return int(datetime.fromisoformat(s).timestamp() * 1000)
    except ValueError:
        return None


def wazuh_alert_to_event(alert: dict) -> dict:
    """[FYP-FUNCTION] One Wazuh alert -> one NetWitness-like flat event."""
    win = ((alert.get("data") or {}).get("win") or {})
    sysd = win.get("system") or {}
    ed = win.get("eventdata") or {}
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    mitre = rule.get("mitre") or {}

    ev: dict[str, Any] = {"device_type": "wazuh", "category": "Process Event" if
                          str(_ci(sysd, "eventID")) == "1" else "Wazuh Event"}
    host = _ci(sysd, "computer") or agent.get("name")
    if host:
        ev["alias_host"] = [str(host).split(".")[0]]
    if agent.get("ip"):
        ev["alias_ip"] = [agent["ip"]]

    image = _ci(ed, "image", "Image")
    parent = _ci(ed, "parentImage", "ParentImage")
    if parent:
        # NetWitness Endpoint semantics: *_src = the ACTING (parent) process,
        # *_dst = the process it created.
        p_name, p_dir = _split_path(parent)
        ev["filename_src"] = [p_name]
        if p_dir:
            ev["directory_src"] = [p_dir]
        if _ci(ed, "parentCommandLine"):
            ev["param_src"] = [_ci(ed, "parentCommandLine")]
        c_name, c_dir = _split_path(image)
        if c_name:
            ev["filename_dst"] = [c_name]
        if c_dir:
            ev["directory_dst"] = [c_dir]
        if _ci(ed, "commandLine"):
            ev["param_dst"] = [_ci(ed, "commandLine")]
        if _hashes(_ci(ed, "hashes")):
            ev["checksum_dst"] = _hashes(_ci(ed, "hashes"))
        ev["action"] = ["createProcess"]
    elif image:
        name, directory = _split_path(image)
        ev["filename_src"] = [name]
        if directory:
            ev["directory_src"] = [directory]
        if _ci(ed, "commandLine"):
            ev["param_src"] = [_ci(ed, "commandLine")]
        if _hashes(_ci(ed, "hashes")):
            ev["checksum_src"] = _hashes(_ci(ed, "hashes"))
    user = _ci(ed, "parentUser", "user", "User") if parent else _ci(ed, "user", "User")
    if user:
        ev["user_src"] = user
    if _ci(ed, "user") and parent:
        ev["user_dst"] = _ci(ed, "user")
    for wk, nk in (("sourceIp", "ip_src"), ("destinationIp", "ip_dst"),
                   ("sourcePort", "port_src"), ("destinationPort", "port_dst"),
                   ("destinationHostname", "domain_dst")):
        if _ci(ed, wk):
            ev[nk] = _ci(ed, wk)
    # MITRE + rule context. Wazuh carries no signer thumbprint for Sysmon
    # EID 1, so cert_thumbprint is simply absent (signed status unknown --
    # never assumed either way).
    if mitre.get("tactic"):
        ev["attack_tactic"] = ", ".join(t.lower() for t in _as_list(mitre["tactic"]))
    if mitre.get("id"):
        ev["mitre_technique"] = _as_list(mitre["id"])
    if rule.get("groups"):
        ev["context"] = [f"wazuh.{g}" for g in _as_list(rule["groups"])]
    if _ci(sysd, "eventID"):
        ev["event_id"] = str(_ci(sysd, "eventID"))
    ms = _event_time_ms(alert)
    if ms is not None:
        ev["time"] = ms // 1000
    ev["wazuh_rule"] = {"id": rule.get("id"), "level": rule.get("level"),
                        "description": rule.get("description")}
    return ev


def _alert_id(alert: dict) -> str:
    if alert.get("id"):
        return f"wazuh-{alert['id']}"
    return "wazuh-" + hashlib.sha1(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:16]


def convert(alerts: list[dict], incident_id: str, title: str | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Wazuh alerts -> one NetWitness-like
    incident (detection source "Wazuh") with alerts[].originalAlert.events[]."""
    out_alerts, tactics, techniques, hosts, levels, times = [], set(), set(), [], [], []
    for a in alerts:
        rule = a.get("rule") or {}
        mitre = rule.get("mitre") or {}
        ev = wazuh_alert_to_event(a)
        name = rule.get("description") or "Wazuh alert"
        level = int(rule.get("level") or 0)
        levels.append(level)
        t = _as_list(mitre.get("tactic"))
        k = _as_list(mitre.get("id"))
        tactics.update(t)
        techniques.update(k)
        hosts.extend(ev.get("alias_host") or [])
        ms = _event_time_ms(a)
        if ms is not None:
            times.append(ms)
        out_alerts.append({
            "_id": _alert_id(a),
            "receivedTime": ms,
            "originalHeaders": {"name": name, "severity": min(10, round(level * 10 / 15)),
                                "deviceVendor": "Wazuh", "deviceProduct": "Wazuh",
                                "signatureId": str(rule.get("id") or "")},
            "alert": {"name": name, "risk_score": round(level * 100 / 15, 1), "source": DETECTION_SOURCE,
                      "type": ["Endpoint"], "host_summary": ev.get("alias_host") or []},
            "originalAlert": {"moduleName": name, "events": [ev]},
            "tactics": t, "techniques": k,
        })
    host = max(set(hosts), key=hosts.count) if hosts else "unknown-host"
    top = max(levels) if levels else 0
    created = (datetime.utcfromtimestamp(min(times) / 1000).strftime("%Y-%m-%dT%H:%M:%S.000Z")
               if times else None)
    return {
        "id": incident_id,
        "title": title or f"Wazuh Lab Alerts for {host}",
        "name": title or f"Wazuh Lab Alerts for {host}",
        "summary": "", "created": created,
        "createdBy": f"{DETECTION_SOURCE} (lab replay)", "ruleId": "wazuh-lab-replay",
        "sources": [DETECTION_SOURCE],
        "priority": next(p for floor, p in _PRIORITY if top >= floor),
        "riskScore": round(top * 100 / 15),
        "status": "NEW", "alertCount": len(out_alerts), "eventCount": len(out_alerts),
        "tactics": sorted(tactics), "techniques": sorted(techniques),
        "alerts": out_alerts,
    }


def _filter(alerts: list[dict], host: str | None, since: str | None, until: str | None) -> list[dict]:
    def ok(a: dict) -> bool:
        if host:
            h = (_ci(((a.get("data") or {}).get("win") or {}).get("system") or {}, "computer")
                 or (a.get("agent") or {}).get("name") or "")
            if str(h).split(".")[0].lower() != host.lower():
                return False
        ms = _event_time_ms(a)
        for bound, cmp in ((since, lambda x, b: x >= b), (until, lambda x, b: x <= b)):
            if bound and ms is not None:
                b = _event_time_ms({"timestamp": bound})
                if b is not None and not cmp(ms, b):
                    return False
        return True
    return [a for a in alerts if ok(a)]


def build_case(alerts: list[dict], name: str, label: str, labeller: str, technique: str | None,
               rationale: str | None, role: str | None = None) -> dict:
    if label not in DISPOSITIONS:
        raise ValueError(f"label must be one of {DISPOSITIONS}")
    incident = convert(alerts, incident_id=f"LAB-{re.sub(r'[^A-Za-z0-9]+', '-', name).upper()}")
    case = {
        "name": name,
        "description": f"Wazuh lab replay ({len(alerts)} alert(s)) converted by "
                       "scripts/wazuh_alert_to_incident.py.",
        "incident": incident,
        "data_availability": {"incident_source": "wazuh_lab_export", "alerts_fetch_attempted": True,
                              "alerts_fetch_succeeded": bool(alerts), "alerts_complete": True,
                              "alerts_count": len(alerts), "journal_fetch_succeeded": None,
                              "warnings": []},
        "expected": EXPECTED_BY_LABEL[label],
        "label": {"value": label, "source": "lab_ground_truth", "labeller": labeller,
                  "date": date.today().isoformat(),
                  "rationale": rationale or (f"Technique {technique} executed deliberately in an isolated "
                                             "lab VM by the labeller (ground truth by construction).")},
    }
    if technique or role:
        case["canary"] = {"role": role or ("malicious" if label == "true_positive" else "benign_pair"),
                          "technique": technique, "pair": None, "source": "wazuh_lab"}
    return case


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export", type=Path)
    ap.add_argument("--name", required=True)
    ap.add_argument("--label", required=True, choices=DISPOSITIONS)
    ap.add_argument("--labeller", required=True)
    ap.add_argument("--technique")
    ap.add_argument("--rationale")
    ap.add_argument("--role", choices=("malicious", "benign_pair"))
    ap.add_argument("--host")
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = ap.parse_args(argv)
    alerts = _filter(load_wazuh_alerts(args.export), args.host, args.since, args.until)
    if not alerts:
        print("[wazuh] no alerts left after filtering -- nothing written", file=sys.stderr)
        return 1
    case = build_case(alerts, args.name, args.label, args.labeller, args.technique,
                      args.rationale, args.role)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.name}.json"
    out.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[wazuh] {len(alerts)} alert(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
