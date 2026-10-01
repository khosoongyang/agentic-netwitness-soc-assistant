# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, re, typing, agents.triage.alert_triage.
# =============================================================================
# File: agents/triage/raw_alerts.py
# Purpose: Triage Step 2 (P1) -- turns the RAW NetWitness alerts/events that
#   ingestion already fetched into a deterministic, citable digest for the
#   evidence packet (section `raw_alerts`), and ranks duplicate-grouped alert
#   "signatures" for the LLM prompt (replacing "first 12 alerts by position").
# Main functionality: build_raw_alerts_section(), digest_alerts(),
#   group_signatures(), rank_signatures(), iter_alert_events(),
#   resolve_data_availability().
# Inputs: incident dict (with `alerts` when ingestion fetched them) and the
#   optional `data_availability` dict recorded by workflow/engine.py
#   (_data_availability / load_data_availability_for_run).
# Outputs: plain dicts of evidence leaves {value, status, source}.
# Workflow position: Triage stage, Phase 0 (pure code, before any LLM call).
# Called by: agents/triage/evidence_packet.py (build_evidence_packet),
#   agents/triage/soc_triage_agent.py (_compact_incident).
# Important side effects: none (pure functions, no I/O, no network).
# Error and fallback behaviour: absent/odd shapes are skipped, never guessed;
#   no alerts or a sqlite_slim source -> every digest leaf is "missing".
# Key evaluator search terms: raw_alerts, [FYP-TRIAGE-STEP2], digest_alerts,
#   rank_signatures, raw_alerts_available.
# =============================================================================
"""
Raw-alert digest  --  raw_alerts.py
===================================
[FYP-TRIAGE-STEP2] SOC triage workflow, Step 2: "pull the raw log, never
trust the alert summary alone". The incident title/summary is NetWitness's
own aggregation; the evidence is in the raw events (process, command line,
directory, hash, signer, user, host, MITRE, threat_desc, context tags).

This module reads ALL alerts and events the ingestion stage already fetched
(no new network calls) and produces:

  * fetch-status leaves (incident_source, fetch_succeeded, alerts_count,
    declared_alert_count, coverage_ratio, available). Missing evidence is
    UNKNOWN, not safe: a slim SQLite copy, a failed fetch or zero alerts give
    status "missing", which agents/triage/guards.py turns into "cannot close
    as benign" (MANDATORY_EVIDENCE raw_alerts_available).
  * a deterministic digest over every alert/event, with every list capped by
    a named constant and the truncation stated explicitly ("showing 20 of
    312 unique command lines").
  * duplicate-grouped "signatures" (alert name + process + normalised command
    line) and a ranking for the prompt: abused-tool / strong rule hits >
    threat_desc present > alert risk score > rarity > off-hour context.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Callable, Iterable, Iterator

from .alert_triage import _INDICATORS

# =============================================================================
# [FYP-SECTION] CAPS (named so truncation is explicit and testable)
# =============================================================================

MAX_ALERT_NAMES = 20
MAX_SIGNATURES = 25
MAX_PROCESSES = 30
MAX_COMMAND_LINES = 20
MAX_HASHES = 20
MAX_SIGNERS = 15
MAX_USERS = 15
MAX_HOSTS = 15
MAX_IPS = 25
MAX_MITRE = 20
MAX_THREAT_DESC = 10
MAX_CONTEXT_TAGS = 25
MAX_BEHAVIORS = 15
MAX_EXAMPLE_ALERT_IDS = 3
MAX_CHILD_PROCESSES_PER_SIGNATURE = 5
MAX_CMDLINE_CHARS = 400

OFF_HOUR_TAG = "network.offhour"

_SOURCE_PREFIX = "incident.alerts[*]"

# Event field groups (NetWitness Endpoint / ESA meta keys; the Wazuh converter
# emits the same keys -- see scripts/wazuh_alert_to_incident.py).
_PROC_SIDES = (("filename_src", "directory_src", "param_src", "checksum_src"),
               ("filename_dst", "directory_dst", "param_dst", "checksum_dst"))
_USER_KEYS = ("user_src", "user_dst", "owner")
_HOST_KEYS = ("alias_host", "host_src", "host_dst")
_IP_KEYS = ("ip_src", "ip_dst", "alias_ip")
_HASH_KEYS = ("checksum_src", "checksum_dst", "checksum")


# =============================================================================
# [FYP-SECTION] SMALL HELPERS
# =============================================================================

def _leaf(value: Any, status: str, source: str) -> dict:
    return {"value": value, "status": status, "source": source}


def _missing(source: str) -> dict:
    return _leaf(None, "missing", source)


def _as_list(value: Any) -> list[str]:
    """NetWitness meta values are scalars OR lists; normalise to non-empty strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip():
                out.append(str(v).strip())
        return out
    if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value).strip():
        return [str(value).strip()]
    return []


def _first(value: Any) -> str | None:
    vals = _as_list(value)
    return vals[0] if vals else None


def _basename(name: str | None) -> str | None:
    if not name:
        return None
    return re.split(r"[\\/]", name.strip().strip('"'))[-1] or None


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


_GUID_RE = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{8,12}\}?", re.I)
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-f]{12,}\b", re.I)
_DIGITS_RE = re.compile(r"\d+")
_WS_RE = re.compile(r"\s+")


def normalise_command_line(cmd: str | None) -> str:
    """Grouping key for a command line: case-folded, whitespace-collapsed,
    GUIDs / long hex / digit runs replaced, so the same command with a new
    PID, port or build number groups into one signature. The ORIGINAL text
    of the first occurrence is kept for display and LOLBAS matching."""
    if not cmd:
        return ""
    s = _GUID_RE.sub("{guid}", cmd.lower())
    s = _HEX_RE.sub("<hex>", s)
    s = _DIGITS_RE.sub("#", s)
    return _WS_RE.sub(" ", s).strip()


def _clip(text: str, limit: int = MAX_CMDLINE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _capped(items: list[dict], cap: int, noun: str) -> dict:
    """Uniform capped-list value with an explicit truncation statement."""
    total = len(items)
    shown = items[:cap]
    if total > cap:
        note = f"showing {cap} of {total} unique {noun}"
    else:
        note = f"all {total} unique {noun} shown"
    return {"total_unique": total, "shown": len(shown), "truncated": total > cap,
            "note": note, "items": shown}


def _counter_items(counter: Counter, key: str = "value") -> list[dict]:
    return [{key: k, "count": n} for k, n in
            sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0]).lower()))]


# =============================================================================
# [FYP-SECTION] ALERT / EVENT EXTRACTION
# =============================================================================

def alert_id(alert: dict, index: int) -> str:
    for key in ("_id", "id", "alertId"):
        if alert.get(key) not in (None, ""):
            return str(alert[key])
    oa = alert.get("originalAlert")
    if isinstance(oa, dict) and oa.get("id"):
        return str(oa["id"])
    return f"alert#{index}"


def alert_name(alert: dict) -> str:
    hdr = alert.get("originalHeaders") if isinstance(alert.get("originalHeaders"), dict) else {}
    body = alert.get("alert") if isinstance(alert.get("alert"), dict) else {}
    oa = alert.get("originalAlert") if isinstance(alert.get("originalAlert"), dict) else {}
    for v in (hdr.get("name"), body.get("name"), oa.get("moduleName"),
              alert.get("name"), alert.get("title"), alert.get("signature")):
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "(unnamed alert)"


def alert_risk_score(alert: dict) -> float | None:
    body = alert.get("alert") if isinstance(alert.get("alert"), dict) else {}
    for v in (body.get("risk_score"), body.get("severity"), alert.get("riskScore"),
              alert.get("risk_score"), alert.get("risk")):
        n = _num(v)
        if n is not None:
            return n
    hdr = alert.get("originalHeaders") if isinstance(alert.get("originalHeaders"), dict) else {}
    sev = _num(hdr.get("severity"))
    # Respond-API header severity is on a 0-10 scale; risk scores are 0-100.
    return sev * 10 if sev is not None else None


def _respond_event_to_flat(ev: dict) -> dict:
    """Map the Respond-API normalised `alert.events[]` shape (source/
    destination objects) onto the flat meta keys, for exports that lack
    `originalAlert.events`."""
    flat: dict = {}
    for side, suffix in (("source", "src"), ("destination", "dst")):
        node = ev.get(side) if isinstance(ev.get(side), dict) else {}
        dev = node.get("device") if isinstance(node.get("device"), dict) else {}
        if node.get("filename"):
            flat[f"filename_{suffix}"] = [node["filename"]]
        if node.get("launch_argument"):
            flat[f"param_{suffix}"] = [node["launch_argument"]]
        if node.get("path"):
            flat[f"directory_{suffix}"] = [node["path"]]
        if node.get("file_SHA256"):
            flat[f"checksum_{suffix}"] = [node["file_SHA256"]]
        if dev.get("ip_address"):
            flat[f"ip_{suffix}"] = dev["ip_address"]
        user = node.get("user") if isinstance(node.get("user"), dict) else {}
        if user.get("username"):
            flat[f"user_{suffix}"] = user["username"]
    return flat


def iter_alert_events(alert: dict) -> Iterator[dict]:
    """Yield flat event dicts for one alert: originalAlert.events[] (the raw
    NetWitness meta), else a flat alert.events[] / events[], else the
    Respond-normalised alert.events[] mapped to flat keys."""
    oa = alert.get("originalAlert")
    if isinstance(oa, dict) and isinstance(oa.get("events"), list) and oa["events"]:
        for ev in oa["events"]:
            if isinstance(ev, dict):
                yield ev
        return
    if isinstance(alert.get("events"), list) and alert["events"]:
        for ev in alert["events"]:
            if isinstance(ev, dict):
                yield ev
        return
    body = alert.get("alert") if isinstance(alert.get("alert"), dict) else {}
    if isinstance(body.get("events"), list):
        for ev in body["events"]:
            if isinstance(ev, dict):
                yield _respond_event_to_flat(ev)


def _alert_mitre(alert: dict, events: list[dict]) -> tuple[list[str], list[str]]:
    tactics: list[str] = []
    techniques: list[str] = []
    for v in _as_list(alert.get("tactics")):
        tactics.append(v)
    for v in _as_list(alert.get("techniques")):
        techniques.append(v)
    for t in (alert.get("tactics") or []) if isinstance(alert.get("tactics"), list) else []:
        if isinstance(t, dict) and t.get("name"):
            tactics.append(str(t["name"]))
    for t in (alert.get("techniques") or []) if isinstance(alert.get("techniques"), list) else []:
        if isinstance(t, dict) and (t.get("id") or t.get("name")):
            techniques.append(str(t.get("id") or t.get("name")))
    for ev in events:
        tactics.extend(_as_list(ev.get("attack_tactic")))
        techniques.extend(_as_list(ev.get("attack_technique")))
        techniques.extend(_as_list(ev.get("mitre_technique")))
    dedup = lambda xs: sorted({x for x in xs if x}, key=str.lower)  # noqa: E731
    return dedup(tactics), dedup(techniques)


# =============================================================================
# [FYP-SECTION] SIGNATURES (duplicate grouping) + RANKING
# =============================================================================

def _primary_process(events: list[dict]) -> tuple[str | None, str | None, str | None]:
    """(process basename, directory, command line) of the acting process.
    NetWitness Endpoint puts the actor in *_src; a meta-only ESA alert may
    have no process at all (then all three are None)."""
    for ev in events:
        name = _basename(_first(ev.get("filename_src")))
        if name:
            return name, _first(ev.get("directory_src")), _first(ev.get("param_src"))
    for ev in events:
        name = _basename(_first(ev.get("filename_dst")))
        if name:
            return name, _first(ev.get("directory_dst")), _first(ev.get("param_dst"))
    return None, None, None


def group_signatures(alerts: list) -> list[dict]:
    """[FYP-FUNCTION] Group ALL alerts into signatures keyed by (alert name,
    process basename, normalised command line). Each signature keeps its
    count, example alert ids, child processes / command lines, threat_desc,
    max risk score, MITRE, context tags and signer state. Order: first seen."""
    sigs: dict[tuple, dict] = {}
    for i, alert in enumerate(alerts or []):
        if not isinstance(alert, dict):
            continue
        events = list(iter_alert_events(alert))
        name = alert_name(alert)
        proc, directory, cmd = _primary_process(events)
        key = (name, (proc or "").lower(), normalise_command_line(cmd))
        sig = sigs.get(key)
        if sig is None:
            sig = sigs[key] = {
                "signature_id": f"sig{len(sigs) + 1}",
                "alert_name": name, "process": proc, "directory": directory,
                "command_line": _clip(cmd) if cmd else None,
                "count": 0, "example_alert_ids": [],
                "child_processes": [], "child_command_lines": [],
                "threat_desc": [], "max_risk_score": None,
                "tactics": [], "techniques": [], "context_tags": [],
                "signed_events": 0, "unsigned_events": 0,
                "_texts": set(),
            }
        sig["count"] += 1
        aid = alert_id(alert, i)
        if len(sig["example_alert_ids"]) < MAX_EXAMPLE_ALERT_IDS:
            sig["example_alert_ids"].append(aid)
        risk = alert_risk_score(alert)
        if risk is not None and (sig["max_risk_score"] is None or risk > sig["max_risk_score"]):
            sig["max_risk_score"] = risk
        tactics, techniques = _alert_mitre(alert, events)
        for t in tactics:
            if t not in sig["tactics"]:
                sig["tactics"].append(t)
        for t in techniques:
            if t not in sig["techniques"]:
                sig["techniques"].append(t)
        for ev in events:
            for td in _as_list(ev.get("threat_desc")):
                if td not in sig["threat_desc"]:
                    sig["threat_desc"].append(td)
            for tag in _as_list(ev.get("context")):
                if tag not in sig["context_tags"]:
                    sig["context_tags"].append(tag)
            if _as_list(ev.get("filename_src")) or _as_list(ev.get("checksum_src")):
                if _as_list(ev.get("cert_thumbprint")):
                    sig["signed_events"] += 1
                else:
                    sig["unsigned_events"] += 1
            for child in _as_list(ev.get("filename_dst")):
                child = _basename(child)
                if child and child not in sig["child_processes"] \
                        and len(sig["child_processes"]) < MAX_CHILD_PROCESSES_PER_SIGNATURE:
                    sig["child_processes"].append(child)
            for pd in _as_list(ev.get("param_dst")):
                if pd not in sig["child_command_lines"] \
                        and len(sig["child_command_lines"]) < MAX_CHILD_PROCESSES_PER_SIGNATURE:
                    sig["child_command_lines"].append(_clip(pd))
    out = []
    for sig in sigs.values():
        sig.pop("_texts", None)
        out.append(sig)
    return out


def signature_text(sig: dict) -> str:
    """All attacker-influenced text of a signature (for rule scanning)."""
    parts = [sig.get("alert_name") or "", sig.get("process") or "", sig.get("command_line") or ""]
    parts += sig.get("child_processes") or []
    parts += sig.get("child_command_lines") or []
    parts += sig.get("threat_desc") or []
    return "\n".join(p for p in parts if p)


def signature_rule_hits(sig: dict, strong_labels: Iterable[str]) -> list[str]:
    """Strong deterministic indicator labels (alert_triage._INDICATORS) found
    in the signature's own text. For RANKING only, a match must be a whole
    word (or one of the scanner's deliberate stems such as "escalat"): the
    shared scanner reads "Microsoft-Antimalware-RTP.man" (a Defender
    manifest) as "malware" and "NWEAgent.exe /runasservice" as "runas",
    which would float routine agent/Defender activity above genuinely rare
    alerts. The packet's rule_signals section keeps the original scanner."""
    strong = set(strong_labels)
    text = signature_text(sig)
    hits = set()
    for label, pattern, *_rest in _INDICATORS:
        if label not in strong:
            continue
        for m in re.finditer(pattern, text, re.I):
            start_ok = m.start() == 0 or not text[m.start() - 1].isalpha()
            end_ok = (m.end() >= len(text) or not text[m.end()].isalpha()
                      or m.group(0).lower().endswith(_RULE_STEMS))
            if start_ok and end_ok:
                hits.add(label)
                break
    return sorted(hits)


# Scanner patterns that are intentionally word stems (match "escalation",
# "exfiltration", ...), so a trailing letter is expected.
_RULE_STEMS = ("escalat", "exfiltrat", "phish", "autorun")


def rank_signatures(signatures: list[dict], strong_labels: Iterable[str] = (),
                    abused_tool_hits: dict[str, list[str]] | None = None) -> list[dict]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Rank signatures for the prompt.

    Order (each a tie-breaker for the previous):
      1. abused-tool (LOLBAS) or strong rule hits present
      2. threat_desc present (the endpoint agent named a threat)
      3. alert risk score (higher first)
      4. rarity, LOWER count first: first the number of alerts sharing the
         signature's alert NAME, then the signature's own count -- so the
         2 "Disables UAC" alerts outrank one-off variants of a rule that
         fired 998 times
      5. off-hour context tag present
    Returns NEW dicts with `rank` and `rank_reasons` added."""
    abused_tool_hits = abused_tool_hits or {}
    strong_labels = tuple(strong_labels)
    name_counts: Counter = Counter()
    for sig in signatures:
        name_counts[sig.get("alert_name")] += sig["count"]
    scored = []
    for sig in signatures:
        rule_hits = signature_rule_hits(sig, strong_labels) if strong_labels else []
        tool_hits = list(abused_tool_hits.get(sig["signature_id"], []))
        off_hour = any(t.lower() == OFF_HOUR_TAG for t in sig.get("context_tags") or [])
        name_n = name_counts[sig.get("alert_name")]
        reasons = []
        if tool_hits:
            reasons.append("abused-tool: " + ", ".join(tool_hits))
        if rule_hits:
            reasons.append("strong rule signal: " + ", ".join(rule_hits))
        if sig.get("threat_desc"):
            reasons.append("threat_desc: " + ", ".join(sig["threat_desc"]))
        if sig.get("max_risk_score") is not None:
            reasons.append(f"risk {sig['max_risk_score']:g}")
        reasons.append(f"count {sig['count']} (alert name fired {name_n}x)")
        if off_hour:
            reasons.append("off-hour")
        key = (0 if (tool_hits or rule_hits) else 1,
               0 if sig.get("threat_desc") else 1,
               -(sig.get("max_risk_score") or 0.0),
               name_n,
               sig["count"],
               0 if off_hour else 1,
               sig["signature_id"])
        scored.append((key, dict(sig, rank_reasons=reasons)))
    scored.sort(key=lambda kv: kv[0])
    out = []
    for rank, (_k, sig) in enumerate(scored, start=1):
        sig["rank"] = rank
        out.append(sig)
    return out


# =============================================================================
# [FYP-SECTION] FULL DIGEST
# =============================================================================

def digest_alerts(alerts: list) -> dict:
    """[FYP-FUNCTION] Deterministic digest over EVERY alert and event.
    Returns plain values (not leaves); build_raw_alerts_section wraps them."""
    names: Counter = Counter()
    processes: dict[tuple, dict] = {}
    cmdlines: dict[str, dict] = {}
    hashes: Counter = Counter()
    signer_tp: dict[str, dict] = {}
    unsigned_procs: Counter = Counter()
    signed_events = unsigned_events = 0
    users: Counter = Counter()
    hosts: Counter = Counter()
    ips: Counter = Counter()
    tactics: Counter = Counter()
    techniques: Counter = Counter()
    per_alert_mitre: list[dict] = []
    threats: dict[str, dict] = {}
    ctx: Counter = Counter()
    file_ctx: Counter = Counter()
    behaviors: Counter = Counter()
    n_alerts = n_events = 0

    for i, alert in enumerate(alerts or []):
        if not isinstance(alert, dict):
            continue
        n_alerts += 1
        aid = alert_id(alert, i)
        names[alert_name(alert)] += 1
        events = list(iter_alert_events(alert))
        n_events += len(events)
        a_tac, a_tech = _alert_mitre(alert, events)
        tactics.update(a_tac)
        techniques.update(a_tech)
        if a_tac or a_tech:
            per_alert_mitre.append({"alert_id": aid, "tactics": a_tac, "techniques": a_tech})
        for ev in events:
            for fkey, dkey, pkey, _hkey in _PROC_SIDES:
                for fname in _as_list(ev.get(fkey)):
                    base = _basename(fname)
                    if not base:
                        continue
                    directory = _first(ev.get(dkey))
                    pk = (base.lower(), (directory or "").lower())
                    p = processes.setdefault(pk, {"name": base, "directory": directory,
                                                  "count": 0, "example_alert_id": aid})
                    p["count"] += 1
                for cmd in _as_list(ev.get(pkey)):
                    norm = normalise_command_line(cmd)
                    c = cmdlines.setdefault(norm, {"command_line": _clip(cmd), "count": 0,
                                                   "field": pkey, "example_alert_id": aid})
                    c["count"] += 1
            for hk in _HASH_KEYS:
                hashes.update(h.lower() for h in _as_list(ev.get(hk)))
            # Signer state of the ACTING (source) process. Recorded as an
            # observation only: a valid signature is NEVER evidence of benign
            # (adversarial mimicry -- LOLBins are Microsoft-signed).
            src_name = _basename(_first(ev.get("filename_src")))
            if src_name:
                tps = _as_list(ev.get("cert_thumbprint"))
                if tps:
                    signed_events += 1
                    for tp in tps:
                        s = signer_tp.setdefault(tp.lower(), {"thumbprint": tp.lower(),
                                                              "count": 0, "processes": []})
                        s["count"] += 1
                        if src_name not in s["processes"] and len(s["processes"]) < 5:
                            s["processes"].append(src_name)
                else:
                    unsigned_events += 1
                    unsigned_procs[src_name] += 1
            for k in _USER_KEYS:
                users.update(_as_list(ev.get(k)))
            for k in _HOST_KEYS:
                hosts.update(_as_list(ev.get(k)))
            for k in _IP_KEYS:
                ips.update(_as_list(ev.get(k)))
            for td in _as_list(ev.get("threat_desc")):
                t = threats.setdefault(td, {"threat_desc": td, "count": 0, "processes": [],
                                            "example_alert_ids": []})
                t["count"] += 1
                if src_name and src_name not in t["processes"]:
                    t["processes"].append(src_name)
                if aid not in t["example_alert_ids"] and \
                        len(t["example_alert_ids"]) < MAX_EXAMPLE_ALERT_IDS:
                    t["example_alert_ids"].append(aid)
            ctx.update(_as_list(ev.get("context")))
            file_ctx.update(_as_list(ev.get("context_src")) + _as_list(ev.get("context_dst")))
            behaviors.update(b.lower() for b in _as_list(ev.get("boc")))

    by_count = lambda d: sorted(d, key=lambda x: (-x["count"], str(next(iter(x.values()))).lower()))  # noqa: E731
    return {
        "alerts_digested": n_alerts,
        "events_digested": n_events,
        "alert_names": _capped(_counter_items(names, "alert_name"), MAX_ALERT_NAMES, "alert names"),
        "processes": _capped(by_count(processes.values()), MAX_PROCESSES, "processes (name + directory)"),
        "command_lines": _capped(by_count(cmdlines.values()), MAX_COMMAND_LINES, "command lines"),
        "hashes": _capped(_counter_items(hashes, "hash"), MAX_HASHES, "hashes"),
        "signers": {
            "signed_events": signed_events, "unsigned_events": unsigned_events,
            "note": ("signer presence is recorded, never treated as evidence of benign "
                     "(adversarial mimicry: abused Windows tools are Microsoft-signed)"),
            "thumbprints": _capped(by_count(signer_tp.values()), MAX_SIGNERS, "signer thumbprints"),
            "unsigned_processes": _capped(_counter_items(unsigned_procs, "process"),
                                          MAX_SIGNERS, "unsigned processes"),
        },
        "users": _capped(_counter_items(users, "user"), MAX_USERS, "users"),
        "hosts": _capped(_counter_items(hosts, "host"), MAX_HOSTS, "hosts"),
        "ips": _capped(_counter_items(ips, "ip"), MAX_IPS, "IPs"),
        "mitre": {
            "tactics": _capped(_counter_items(tactics, "tactic"), MAX_MITRE, "tactics"),
            "techniques": _capped(_counter_items(techniques, "technique"), MAX_MITRE, "techniques"),
            "per_alert": _capped(per_alert_mitre, MAX_MITRE, "alerts with MITRE tags"),
        },
        "threat_desc": _capped(by_count(threats.values()), MAX_THREAT_DESC, "threat descriptions"),
        "context_tags": _capped(_counter_items(ctx, "tag"), MAX_CONTEXT_TAGS, "event context tags"),
        "file_context_tags": _capped(_counter_items(file_ctx, "tag"), MAX_CONTEXT_TAGS,
                                     "file context tags"),
        "behaviors": _capped(_counter_items(behaviors, "behavior"), MAX_BEHAVIORS,
                             "behaviours of compromise"),
    }


# =============================================================================
# [FYP-SECTION] FETCH STATUS + SECTION BUILDER
# =============================================================================

def resolve_data_availability(incident: dict, data_availability: dict | None) -> tuple[dict, str]:
    """Return (availability dict, provenance).

    provenance "measured": ingestion recorded it and the caller passed it in.
    provenance "inferred": the caller passed None. Then the incident source
    is inferred from the same markers workflow/engine.py::_data_availability
    uses, but the FETCH OUTCOME is left unknown (alerts_fetch_succeeded =
    None): "None = unknown", and missing evidence is unknown, not safe."""
    if isinstance(data_availability, dict) and data_availability:
        return data_availability, "measured"
    if "_alerts_stripped" in incident:
        source = "sqlite_slim"
    elif "alerts" in incident:
        source = "netwitness_live"
    else:
        source = "other"
    return {"incident_source": source, "alerts_fetch_succeeded": None,
            "alerts_count": len(incident.get("alerts") or [])
            if isinstance(incident.get("alerts"), list) else 0}, "inferred"


_DIGEST_KEYS = ("alert_names", "signatures", "processes", "command_lines", "hashes",
                "signers", "users", "hosts", "ips", "mitre", "threat_desc",
                "context_tags", "file_context_tags", "behaviors")


def build_raw_alerts_section(incident: dict, data_availability: dict | None,
                             strong_labels: Iterable[str] = (),
                             abused_tool_hits_fn: Callable[[list[dict]], dict] | None = None,
                             ) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] The `raw_alerts` evidence-packet section.

    Every value is a leaf {value, status, source}. Status rules:
      * incident_source / fetch_succeeded / alerts_count: "measured" when
        ingestion's data_availability was supplied, "inferred" when it had
        to be derived from the incident (caller passed None).
      * available: value True only if the fetch succeeded AND alerts_count
        > 0; otherwise status "missing" (unknown, never safe). A sqlite_slim
        source is always missing: the slim copy has had its alerts stripped.
      * digest leaves: "measured" from the alerts in hand; "missing" when
        there are none (or the source is the slim copy).
    """
    incident = incident if isinstance(incident, dict) else {}
    avail, prov = resolve_data_availability(incident, data_availability)
    da_src = ("data_availability (recorded by ingestion: workflow/engine.py::_data_availability)"
              if prov == "measured" else
              "derived from the incident (data_availability not supplied: alerts key, "
              "_alerts_stripped / alerts_fetch_error markers)")
    alerts = incident.get("alerts") if isinstance(incident.get("alerts"), list) else []
    source = avail.get("incident_source")
    fetch_ok = avail.get("alerts_fetch_succeeded")
    count = avail.get("alerts_count")
    if not isinstance(count, int) or isinstance(count, bool):
        count = len(alerts)
    declared = _num(incident.get("alertCount"))

    out: dict[str, dict] = {}
    out["incident_source"] = (_leaf(source, prov, f"{da_src}.incident_source")
                              if source else _missing(f"{da_src}: incident_source absent"))
    out["fetch_succeeded"] = (_leaf(bool(fetch_ok), prov, f"{da_src}.alerts_fetch_succeeded")
                              if fetch_ok is not None
                              else _missing(f"{da_src}: fetch outcome not recorded (unknown)"))
    out["alerts_count"] = (_leaf(count, prov, f"{da_src}.alerts_count") if prov == "measured"
                           else _leaf(count, "measured", "len(incident.alerts) in hand"))
    out["declared_alert_count"] = (_leaf(int(declared), "measured", "incident.alertCount")
                                   if declared is not None
                                   else _missing("incident.alertCount (absent)"))
    if declared and declared > 0:
        ratio = round(count / declared, 3)
        out["coverage_ratio"] = _leaf(
            ratio, "inferred",
            f"alerts_count / incident.alertCount = {count}/{int(declared)}"
            + (" (fetch did not return every alert NetWitness counted)" if ratio < 1 else ""))
    else:
        out["coverage_ratio"] = _missing("needs incident.alertCount > 0")

    reasons = []
    if source == "sqlite_slim":
        reasons.append("incident_source is sqlite_slim (alerts were stripped before storage)")
    if fetch_ok is None:
        reasons.append("fetch outcome unknown (data_availability not supplied)")
    elif fetch_ok is not True:
        reasons.append("alert fetch did not succeed or was not attempted")
    if count <= 0 or not alerts:
        reasons.append("no raw alerts in hand")
    if reasons:
        why = "; ".join(reasons) + " -- missing raw evidence is unknown, not safe"
        out["available"] = _missing(why)
    else:
        out["available"] = _leaf(True, prov, f"{da_src}: fetch succeeded and alerts_count={count} > 0")

    usable = bool(alerts) and source != "sqlite_slim"
    if not usable:
        why = ("raw alerts unavailable: " + ("; ".join(reasons) or "no alerts")
               + " (Step 2: never triage on the alert summary alone)")
        for key in ("events_digested",) + _DIGEST_KEYS:
            out[key] = _missing(why)
        return out

    digest = digest_alerts(alerts)
    signatures = group_signatures(alerts)
    tool_hits = abused_tool_hits_fn(signatures) if abused_tool_hits_fn else {}
    ranked = rank_signatures(signatures, strong_labels, tool_hits)
    digest["signatures"] = _capped(ranked, MAX_SIGNATURES, "alert signatures (alert name + "
                                   "process + command line), ranked")
    digest["signatures"]["alerts_covered_by_shown"] = sum(s["count"] for s in digest["signatures"]["items"])

    src = (f"{_SOURCE_PREFIX}.originalAlert.events[*] -- all {digest['alerts_digested']} alerts / "
           f"{digest['events_digested']} events digested")
    out["events_digested"] = _leaf(digest["events_digested"], "measured", src)
    for key in _DIGEST_KEYS:
        out[key] = _leaf(digest[key], "measured", src)
    return out


__all__ = [
    "MAX_ALERT_NAMES", "MAX_SIGNATURES", "MAX_PROCESSES", "MAX_COMMAND_LINES",
    "MAX_HASHES", "MAX_SIGNERS", "MAX_USERS", "MAX_HOSTS", "MAX_IPS", "MAX_MITRE",
    "MAX_THREAT_DESC", "MAX_CONTEXT_TAGS", "MAX_BEHAVIORS", "MAX_EXAMPLE_ALERT_IDS",
    "MAX_CMDLINE_CHARS", "OFF_HOUR_TAG",
    "alert_id", "alert_name", "alert_risk_score", "iter_alert_events",
    "normalise_command_line", "group_signatures", "signature_text",
    "signature_rule_hits", "rank_signatures", "digest_alerts",
    "resolve_data_availability", "build_raw_alerts_section",
]
