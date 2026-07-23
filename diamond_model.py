"""
diamond_model.py — Diamond Model of Intrusion Analysis for one incident
(investigation-agent skill, standalone).

Adapted from mukul975/Anthropic-Cybersecurity-Skills'
`implementing-diamond-model-analysis` skill (by mahipal) — its DiamondEvent data
structure (Adversary / Capability / Infrastructure / Victim + meta-features), its
find_pivots logic, and its activity-thread concept. That skill ingests MISP/
OpenCTI events; we adapt the *framework* to structure ONE NetWitness incident:
its IOCs, host and MITRE TTP are organised into the four Diamond vertices plus
meta-features, giving the investigation a recognised analytic backbone that the
raw entity graph (incident_map) doesn't encode.

Vertex mapping (from the incident's own evidence — an analytic structuring, not
new intelligence):
  * Victim         — focus host/entity + asset-criticality tier + internal IPs
  * Infrastructure — external IPs (alertMeta) + domains (triage metakeys)
  * Capability     — file hashes + the MITRE technique/tactic (the TTP)
  * Adversary      — UNATTRIBUTED (we hold no actor intel; the Diamond Model
                     explicitly allows an unknown adversary — stated plainly)
Meta-features: timestamp, phase (MITRE tactic -> Lockheed-Martin Kill Chain
phase, a deterministic crosswalk — this folds the Cyber Kill Chain in as the
Diamond "phase" meta-feature), result, methodology, direction.

Pivots are the Diamond Model's signature: each populated Infrastructure/
Capability element is a pivot point to discover related activity. Optional
corpus-backed pivot counts fold in ioc_correlation when enrich_pivots=True
(kept off by default so the panel stays instant).

Standalone per the rule — NO edits to soc_investigation_agent/. Deterministic,
read-only, no network of its own (asset_criticality import is instant).
Kill switch: NW_DISABLE_DIAMOND=1.

Usage:
    d = build_diamond(incident, triage_result)
    print(format_diamond(d)); print(to_dot(d))
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")

# MITRE ATT&CK tactic -> Lockheed-Martin Cyber Kill Chain phase (the Diamond
# "phase" meta-feature). Deterministic crosswalk.
_TACTIC_TO_KILLCHAIN = {
    "reconnaissance": "Reconnaissance",
    "resource development": "Weaponization",
    "initial access": "Delivery",
    "execution": "Exploitation",
    "persistence": "Installation",
    "privilege escalation": "Installation",
    "defense evasion": "Installation",
    "credential access": "Actions on Objectives",
    "discovery": "Reconnaissance (internal)",
    "lateral movement": "Actions on Objectives",
    "collection": "Actions on Objectives",
    "command and control": "Command & Control",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
}


def _is_public_ip(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def _focus_host(incident: dict, triage_result: dict | None) -> str | None:
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    for key, vals in mkv.items():
        klow = key.lower()
        if any(n in klow for n in ("host", "computer", "hostname", "machine", "device")):
            for v in (vals if isinstance(vals, list) else [vals]):
                v = str(v or "").strip()
                if v and not _IP_RE.match(v) and "." not in v:  # bare NetBIOS = endpoint
                    return v
    m = _TITLE_ENTITY_RE.search(str(incident.get("title") or ""))
    if m:
        e = m.group(1).strip()
        if e and not _IP_RE.match(e):
            return e
    return None


def _extract(incident: dict, triage_result: dict | None) -> dict:
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    am = incident.get("alertMeta") or {}
    pub_ips, priv_ips, hashes, domains = [], [], [], []
    for field in ("DestinationIp", "SourceIp"):
        for v in am.get(field) or []:
            if isinstance(v, str) and _IP_RE.match(v):
                (pub_ips if _is_public_ip(v) else priv_ips).append(v)
    for key, vals in mkv.items():
        klow = key.lower()
        for v in (vals if isinstance(vals, list) else [vals]):
            v = str(v or "").strip()
            if _HASH_RE.match(v):
                hashes.append(v)
            elif (("domain" in klow or "fqdn" in klow or "host" in klow)
                  and "." in v and not _IP_RE.match(v)):
                domains.append(v)

    # distilled per-alert evidence (from _distill_alerts in app.py): the alert
    # titles ARE behavioural capability evidence, and the user is a victim detail.
    # For this NetWitness deployment the endpoint host-snapshot API returns no
    # data (empty inventory), so these distilled fields are the richest real
    # Capability/Victim evidence available — the Diamond Model should use them.
    alert_titles = [str(t).strip() for t in (am.get("AlertTitles") or []) if str(t).strip()]
    users = [str(u).strip() for u in ((am.get("User") or []) + (am.get("AdUser") or []))
             if str(u).strip()]

    def dedup(seq):
        return list(dict.fromkeys(seq))

    return {"pub_ips": dedup(pub_ips), "priv_ips": dedup(priv_ips),
            "hashes": dedup(hashes), "domains": dedup(domains),
            "alert_titles": dedup(alert_titles), "users": dedup(users)}


# alert-title keyword → (technique, technique_name, tactic). Lets the Capability
# vertex + phase meta-feature populate from behavioural alert titles even when no
# structured MITRE technique is present (the common case for these ECAT alerts).
_TITLE_TO_MITRE: list[tuple[tuple[str, ...], str, str, str]] = [
    (("hta", "mshta"), "T1218.005", "Mshta", "Execution"),
    (("autorun", "run key", "startup", "scheduled task"), "T1547", "Boot/Logon Autostart", "Persistence"),
    (("powershell", "script", "macro", "wscript", "cscript"), "T1059", "Command and Scripting Interpreter", "Execution"),
    (("credential", "mimikatz", "lsass", "dump"), "T1003", "OS Credential Dumping", "Credential Access"),
    (("lateral", "psexec", "wmi", "rdp", "smb"), "T1021", "Remote Services", "Lateral Movement"),
    (("c2", "command and control", "command & control", "beacon", "callback"), "T1071", "Application Layer Protocol", "Command and Control"),
    (("exfil", "exfiltration", "data transfer", "upload"), "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    (("phishing", "spearphish", "malicious attachment", "malicious link"), "T1566", "Phishing", "Initial Access"),
    (("ransom", "encrypt"), "T1486", "Data Encrypted for Impact", "Impact"),
    (("privilege", "uac", "elevation"), "T1548", "Abuse Elevation Control", "Privilege Escalation"),
]


def _infer_mitre_from_titles(titles: list) -> tuple[str, str, str]:
    """First keyword hit across the alert titles → (technique, name, tactic)."""
    joined = " ".join(titles).lower()
    for needles, tid, name, tactic in _TITLE_TO_MITRE:
        if any(n in joined for n in needles):
            return tid, name, tactic
    return "", "", ""


def _mitre(incident: dict, triage_result: dict | None) -> dict:
    mk = (triage_result or {}).get("metakeys_payload") or {}
    tech = str(mk.get("mitre_technique") or "").strip()
    tactic = str(mk.get("mitre_tactic") or "").strip()
    if not tech:
        techs = incident.get("techniques") or []
        if techs:
            tech = str(techs[0].get("id") if isinstance(techs[0], dict) else techs[0]).strip()
    if not tactic:
        tacs = incident.get("tactics") or []
        if tacs:
            tactic = str(tacs[0].get("name") if isinstance(tacs[0], dict) else tacs[0]).strip()
    return {"technique": tech, "tactic": tactic}


def _asset_tier(incident: dict, triage_result: dict | None) -> str:
    try:
        from asset_criticality import assess_incident
        cls = ((triage_result or {}).get("ticket") or {}).get("classification")
        return str(assess_incident(incident, triage_classification=cls).get("highest_tier", "unclassified"))
    except Exception:
        return "unclassified"


def _ti_flags(ti_result: dict | None) -> dict:
    """value -> worst verdict, from a passed-in threat_intel enrichment (optional)."""
    flags: dict[str, str] = {}
    for r in (ti_result or {}).get("results", []):
        v = r.get("value")
        verdict = str(r.get("verdict", "")).split(" ")[0]
        if v and verdict in ("MALICIOUS", "SUSPICIOUS"):
            flags[v] = verdict
    return flags


def build_diamond(incident: dict, triage_result: dict | None = None,
                  ti_result: dict | None = None,
                  enrich_pivots: bool = False) -> dict:
    """Structure the incident as a Diamond Model event. Deterministic, read-only,
    never raises. Returns {"available": bool, ...}."""
    if os.environ.get("NW_DISABLE_DIAMOND"):
        return {"available": False, "reason": "disabled via NW_DISABLE_DIAMOND"}

    host = _focus_host(incident, triage_result)
    ext = _extract(incident, triage_result)
    mitre = _mitre(incident, triage_result)
    tier = _asset_tier(incident, triage_result)
    ti = _ti_flags(ti_result)

    # if triage gave no MITRE, infer one from the behavioural alert titles so the
    # Capability vertex + phase meta-feature can still populate.
    if not mitre["technique"] and ext["alert_titles"]:
        tid, _tname, ttac = _infer_mitre_from_titles(ext["alert_titles"])
        if tid:
            mitre = {"technique": tid, "tactic": ttac}

    # ── vertices ────────────────────────────────────────────────────────────
    victim = {
        "host": host, "asset_tier": tier, "internal_ips": ext["priv_ips"],
        "users": ext["users"],
        "confidence": (80 if host else (40 if ext["priv_ips"] else 10))
                      + (10 if ext["users"] else 0),
    }
    infra_items = [{"value": ip, "kind": "external IP",
                    "ti": ti.get(ip)} for ip in ext["pub_ips"]]
    infra_items += [{"value": d, "kind": "domain", "ti": ti.get(d)} for d in ext["domains"]]
    infrastructure = {
        "items": infra_items,
        "confidence": 70 if infra_items else 0,
    }
    # Capability = file hashes (if any) + the behavioural capabilities named by
    # the alert titles ("Malicious HTA file detected", "Potential C2 Connection"…).
    cap_items = [{"value": h, "kind": "file hash", "ti": ti.get(h)} for h in ext["hashes"]]
    cap_items += [{"value": t, "kind": "behaviour", "ti": None} for t in ext["alert_titles"]]
    capability = {
        "items": cap_items,
        "mitre_technique": mitre["technique"], "mitre_tactic": mitre["tactic"],
        "confidence": (60 if cap_items else 0) + (30 if mitre["technique"] else 0),
    }
    adversary = {
        "label": "unattributed",
        "note": "no threat-actor intelligence available for this incident — "
                "the Diamond Model permits an unknown adversary vertex",
        "confidence": 0,
    }

    # ── meta-features ─────────────────────────────────────────────────────────
    phase = _TACTIC_TO_KILLCHAIN.get(mitre["tactic"].lower(), "unknown") if mitre["tactic"] else "unknown"
    ts = (incident.get("created") or incident.get("firstAlertTime")
          or incident.get("first_seen") or "")
    status = str(incident.get("status") or "").strip()
    result = ("unresolved (status=New)" if status.lower() == "new"
              else (status or "unknown"))
    methodology = "technical exploit"
    if infra_items:
        methodology = "external infrastructure / C2"
    direction = "infrastructure → victim" if infra_items else "internal"
    meta = {"timestamp": str(ts)[:19], "phase": phase, "result": result,
            "methodology": methodology, "direction": direction,
            "mitre_technique": mitre["technique"], "mitre_tactic": mitre["tactic"]}

    # ── pivots (Diamond Model signature) ──────────────────────────────────────
    pivots: list[dict] = []
    for it in infra_items:
        pivots.append({"vertex": "infrastructure", "value": it["value"],
                       "question": "which other victims contacted this infrastructure?"})
    for it in cap_items:
        pivots.append({"vertex": "capability", "value": it["value"],
                       "question": "which other incidents used this capability (hash)?"})
    if capability["mitre_technique"]:
        pivots.append({"vertex": "capability", "value": capability["mitre_technique"],
                       "question": "which other incidents share this TTP?"})

    if enrich_pivots and pivots:
        try:
            from ioc_correlation import correlate_iocs
            corr = correlate_iocs(incident, triage_result)
            by_value = {r["value"]: r for r in corr.get("results", [])}
            for p in pivots:
                r = by_value.get(p["value"])
                if r:
                    p["corpus_mentions"] = r.get("raw_mentions")
                    p["confidence_hint"] = r.get("confidence")
        except Exception:
            pass

    # ── overall completeness ──────────────────────────────────────────────────
    populated = sum(1 for c in (victim["confidence"], infrastructure["confidence"],
                                capability["confidence"]) if c > 0)
    completeness = round(100 * populated / 3)

    return {
        "available": True,
        "victim": victim, "infrastructure": infrastructure,
        "capability": capability, "adversary": adversary,
        "meta": meta, "pivots": pivots,
        "stats": {"vertices_populated": populated, "completeness_pct": completeness,
                  "infrastructure_count": len(infra_items),
                  "capability_count": len(cap_items),
                  "malicious_flagged": sum(1 for it in infra_items + cap_items if it.get("ti") == "MALICIOUS")},
    }


def _dot_escape(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def to_dot(d: dict) -> str:
    """Graphviz diamond: Adversary (top) · Capability (left) · Infrastructure
    (right) · Victim (bottom) — the classic Diamond Model layout."""
    if not d.get("available"):
        return 'digraph G { label="Diamond Model unavailable"; }'
    vic, inf, cap, adv = d["victim"], d["infrastructure"], d["capability"], d["adversary"]

    def _lines(items, cap_n=3):
        vals = [it["value"] + (" ⚠" if it.get("ti") else "") for it in items[:cap_n]]
        extra = len(items) - cap_n
        if extra > 0:
            vals.append(f"+{extra} more")
        return "\\n".join(_dot_escape(v) for v in vals) or "—"

    adv_lbl = f"ADVERSARY\\n{adv['label']}"
    cap_extra = (cap["mitre_technique"] or "") + ((" " + cap["mitre_tactic"]) if cap["mitre_tactic"] else "")
    cap_lbl = "CAPABILITY\\n" + (_lines(cap["items"]) if cap["items"] else "—")
    if cap_extra.strip():
        cap_lbl += "\\n" + _dot_escape(cap_extra.strip())
    inf_lbl = "INFRASTRUCTURE\\n" + _lines(inf["items"])
    vic_lbl = "VICTIM\\n" + _dot_escape(vic["host"] or "(no named host)") + \
              f"\\n[{_dot_escape(vic['asset_tier'])}]"
    if vic.get("users"):
        vic_lbl += "\\n" + _dot_escape(", ".join(vic["users"][:2]))

    return (
        "digraph Diamond {\n"
        '  bgcolor="transparent"; node [style=filled, fontname="Helvetica", fontsize=10];\n'
        f'  A [label="{adv_lbl}", shape=box, fillcolor="#3a1f1f", fontcolor="#E0E0E0"];\n'
        f'  C [label="{cap_lbl}", shape=box, fillcolor="#1f2f3a", fontcolor="#E0E0E0"];\n'
        f'  I [label="{inf_lbl}", shape=box, fillcolor="#1f3a2f", fontcolor="#E0E0E0"];\n'
        f'  V [label="{vic_lbl}", shape=box, fillcolor="#3a331f", fontcolor="#E0E0E0"];\n'
        "  A -> C [dir=none]; A -> I [dir=none];\n"
        "  C -> V [dir=none]; I -> V [dir=none];\n"
        "  C -> I [dir=none, style=dashed, color=gray]; A -> V [dir=none, style=dashed, color=gray];\n"
        "}"
    )


def format_diamond(d: dict) -> str:
    if not d.get("available"):
        return "DIAMOND MODEL unavailable: " + d.get("reason", "unknown")
    vic, inf, cap, adv, m = d["victim"], d["infrastructure"], d["capability"], d["adversary"], d["meta"]
    st = d["stats"]
    lines = [
        "DIAMOND MODEL OF INTRUSION ANALYSIS (analytic structuring of this "
        "incident's evidence — not new intelligence)",
        f"  completeness: {st['completeness_pct']}% "
        f"({st['vertices_populated']}/3 evidence vertices populated)"
        + (f"   ·   {st['malicious_flagged']} element(s) flagged malicious" if st["malicious_flagged"] else ""),
        "",
        f"  ● ADVERSARY:      {adv['label']} — {adv['note']}",
        "  ● CAPABILITY:     " + (", ".join(
            (it["value"][:44] + ("…" if len(it["value"]) > 44 else ""))
            + (" ⚠" + it["ti"] if it.get("ti") else "") for it in cap["items"]) or "—")
        + (f"   |   TTP: {cap['mitre_technique']} / {cap['mitre_tactic']}"
           if cap["mitre_technique"] else "   |   TTP: —"),
        "  ● INFRASTRUCTURE: " + (", ".join(
            f"{it['value']} ({it['kind']})" + (" ⚠" + it["ti"] if it.get("ti") else "")
            for it in inf["items"]) or "—"),
        f"  ● VICTIM:         {vic['host'] or '(no named host)'} "
        f"[{vic['asset_tier']} asset]"
        + (f"   user: {', '.join(vic['users'][:2])}" if vic.get("users") else "")
        + (f"   internal IPs: {', '.join(vic['internal_ips'][:4])}" if vic["internal_ips"] else ""),
        "",
        f"  meta-features: phase={m['phase']} (kill chain) · result={m['result']} · "
        f"methodology={m['methodology']} · direction={m['direction']}"
        + (f" · when={m['timestamp']}" if m["timestamp"] else ""),
    ]
    if d["pivots"]:
        lines.append("  pivots (Diamond Model discovery points):")
        for p in d["pivots"][:8]:
            extra = ""
            if p.get("corpus_mentions") is not None:
                extra = f"  [{p['corpus_mentions']} corpus mentions, {p.get('confidence_hint','?')} conf]"
            lines.append(f"      · {p['vertex']}: {p['value']} — {p['question']}{extra}")
    return "\n".join(lines)
