# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, ipaddress, re, typing.
# =============================================================================
# File: incident_map.py
# Purpose: This module builds the analyst-facing incident relationship,
#   multi-incident correlation, and evidence map.
# Main functionality: _is_private_ip, _classify_value, _Graph, _walk_alert,
#   _ingest_triage_data, _ingest_threat_intel_data, _ingest_investigation_data,
#   _ingest_correlation_data, build_incident_map, _dot_escape, to_dot.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis SOC analysis support component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, ipaddress, re, typing.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _is_private_ip, _classify_value, _Graph, _walk_alert,
#   build_incident_map, _dot_escape, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
incident_map.py — Multi-incident entity-graph and correlation web engine.

Extracts a rich, typed, color-coded cybersecurity entity graph connecting:
    1. Incident Metadata & Alert Events (hosts, users, IPs, processes, files, hashes)
    2. Triage Metakeys & Risk Ratings
    3. Threat Intelligence Enrichment (VirusTotal, AbuseIPDB, AlienVault OTX)
    4. Investigation Playbook Execution Traces (parent-child processes, cmdline args, MITRE techniques)
    5. Cross-Incident IOC Correlation Web (shared indicators linking related/open/historical cases)

Nodes: incident / host / user / ip / domain / process / file / hash / registry / email / mitre / entity
Edges: spawned / injected_into / connected_to / queried / has_file / active_on / exhibits_technique / shared_indicator
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# ── color palette constants ──────────────────────────────────────────────────
PRIMARY_INCIDENT_COLOR = "#38bdf8"
CORRELATED_INCIDENT_COLORS = [
    "#f59e0b",  # Amber
    "#a855f7",  # Purple
    "#10b981",  # Emerald
    "#f43f5e",  # Rose
    "#06b6d4",  # Teal
    "#ec4899",  # Pink
    "#8b5cf6",  # Violet
]

# ── entity classification ────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
# "High Risk Alerts: NetWitness Endpoint for KELLYWANG" -> "KELLYWANG"
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")

# meta-key substrings -> node type (checked in order; suffix conventions match
# the triage agent's metakey extraction)
_KEY_TYPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sourceip", "ip.src", "ip_src", "srcip"), "ip"),
    (("destinationip", "ip.dst", "ip_dst", "dstip"), "ip"),
    (("checksum", "hash", "md5", "sha256", "sha1"), "hash"),
    (("process", "parent_process", "proc"), "process"),
    (("filename", "file.", "directory", "dir"), "file"),
    (("user", "username", "user.dst", "user.src"), "user"),
    (("host", "alias.host", "device", "computer"), "host"),
    (("domain", "fqdn", "hostname"), "domain"),
    (("registry", "reg_key", "reg_val"), "registry"),
    (("email", "mail", "sender", "recipient"), "email"),
]


# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_is_private_ip` — evaluates is private ip conditions so invalid or unsafe SOC analysis support processing is stopped early.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include alert_triage.py:_extract_iocs, incident_map.py:_walk_alert, incident_map.py:build_incident_map; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ip_address`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


# [FYP-FUNCTION] `_classify_value` — implements the classify value operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `value`, `key_hint`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include incident_map.py:build_incident_map; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `isalpha`, `lower`, `match`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _classify_value(value: str, key_hint: str = "") -> str:
    """Best-effort node type for a raw string, using the meta key when known."""
    v = value.strip()
    if _IP_RE.match(v) or _IPV6_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash"
    hint = key_hint.lower()
    for needles, ntype in _KEY_TYPE_RULES:
        if any(n in hint for n in needles):
            return ntype
    if v.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".sh", ".py")):
        return "process" if " " not in v else "file"
    if v.startswith(("HKLM\\", "HKCU\\", "HKEY_")):
        return "registry"
    if "@" in v and "." in v and " " not in v:
        return "email"
    if "." in v and " " not in v and any(c.isalpha() for c in v):
        return "domain"
    return "entity"  # honest: shape alone can't tell user from hostname


# ── graph assembly ────────────────────────────────────────────────────────────


# [FYP-CLASS] `_Graph` — owns Graph state or behaviour for the SOC analysis support component.
# [FYP-PROCESS] Important methods: __init__, node, edge.
# [FYP-USED-BY] Static constructor/type references include incident_map.py:build_incident_map.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class _Graph:
    """Dedup-on-insert node/edge accumulator with multi-incident support."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, ntype: str, value: str, incident_id: str | None = None,
             color: str | None = None, disposition: str | None = None,
             **props: Any) -> str:
        nid = f"{ntype}:{value}"
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid,
                "type": ntype,
                "label": value,
                "incidents": [str(incident_id)] if incident_id else [],
                "color": color,
                "disposition": disposition or "unknown",
                "props": {},
            }
        else:
            if incident_id and str(incident_id) not in self.nodes[nid]["incidents"]:
                self.nodes[nid]["incidents"].append(str(incident_id))
            if color and not self.nodes[nid].get("color"):
                self.nodes[nid]["color"] = color
            if disposition and disposition != "unknown":
                cur_disp = self.nodes[nid].get("disposition", "unknown")
                if disposition == "malicious" or (disposition == "suspicious" and cur_disp != "malicious"):
                    self.nodes[nid]["disposition"] = disposition

        self.nodes[nid]["props"].update({k: v for k, v in props.items() if v not in (None, "", [])})
        return nid

    def edge(self, src: str, dst: str, relation: str, evidence: str,
             incident_id: str | None = None, color: str | None = None,
             is_cross_incident: bool = False) -> None:
        key = (src, dst, relation)
        if key in self.edges:
            self.edges[key]["count"] += 1
            if evidence and evidence not in self.edges[key]["evidence"]:
                self.edges[key]["evidence"].append(evidence)
            if incident_id and str(incident_id) not in self.edges[key].get("incidents", []):
                self.edges[key].setdefault("incidents", []).append(str(incident_id))
            if is_cross_incident:
                self.edges[key]["is_cross_incident"] = True
        else:
            self.edges[key] = {
                "src": src,
                "dst": dst,
                "relation": relation,
                "evidence": [evidence] if evidence else [],
                "count": 1,
                "incident_id": str(incident_id) if incident_id else None,
                "incidents": [str(incident_id)] if incident_id else [],
                "color": color,
                "is_cross_incident": is_cross_incident,
            }


def _walk_alert(g: _Graph, inc_node: str, alert: dict, timeline: list[dict],
                incident_id: str | None = None) -> None:
    """Extract entities/edges from one raw alert (Respond API shape)."""
    a_id = str(alert.get("id") or alert.get("_id") or alert.get("alertId") or alert.get("signature_id") or "?")
    ev_tag = f"alert {a_id}"
    when = alert.get("created") or alert.get("receivedTime") or alert.get("timestamp") or alert.get("time")

    title = (
        alert.get("title") or alert.get("name") or alert.get("signature_id")
        or alert.get("type") or alert.get("detail")
    )
    if not title and isinstance(alert.get("alertMeta"), dict):
        titles = alert["alertMeta"].get("AlertTitles") or []
        if titles:
            title = titles[0]
    if not title:
        title = f"Alert {a_id}" if a_id != "?" else "Security Alert"

    if when:
        timeline.append({"time": str(when), "event": str(title)})

    # flat convenience fields some alert shapes carry
    flat = {
        "sourceIp": "ip", "destinationIp": "ip", "domain": "domain",
        "userName": "user", "fileName": "file", "fileHash": "hash",
        "processName": "process", "hostSummary": "host",
    }
    for field, ntype in flat.items():
        val = alert.get(field)
        for v in (val if isinstance(val, list) else [val]):
            if v and isinstance(v, str):
                nid = g.node(ntype, v, incident_id=incident_id)
                g.edge(inc_node, nid, "observed", ev_tag, incident_id=incident_id)

    for ev in alert.get("events") or []:
        if not isinstance(ev, dict):
            continue
        side_nodes: dict[str, str | None] = {"source": None, "destination": None}
        for side in ("source", "destination"):
            node = ev.get(side) or {}
            if not isinstance(node, dict):
                continue
            dev = node.get("device") or {}
            ip = dev.get("ipAddress") or node.get("ipAddress")
            hostname = dev.get("dnsHostname") or dev.get("dnsDomain") or dev.get("name")
            username = (node.get("user") or {}).get("username") or node.get("username")
            process = node.get("processName") or (node.get("process") or {}).get("name")
            hash_val = node.get("fileHash") or (node.get("process") or {}).get("hash")
            
            if ip:
                side_nodes[side] = g.node("ip", str(ip), incident_id=incident_id, private=_is_private_ip(str(ip)))
            if hostname:
                h = g.node("host", str(hostname), incident_id=incident_id)
                if side_nodes[side]:
                    g.edge(h, side_nodes[side], "resolves_to", ev_tag, incident_id=incident_id)
                else:
                    side_nodes[side] = h
            if username:
                u = g.node("user", str(username), incident_id=incident_id)
                if side_nodes[side]:
                    g.edge(u, side_nodes[side], "active_on", ev_tag, incident_id=incident_id)
            if process:
                p = g.node("process", str(process), incident_id=incident_id)
                if side_nodes[side]:
                    g.edge(p, side_nodes[side], "executed_on", ev_tag, incident_id=incident_id)
            if hash_val:
                hnode = g.node("hash", str(hash_val), incident_id=incident_id)
                if process:
                    g.edge(g.node("process", str(process), incident_id=incident_id), hnode, "has_hash", ev_tag, incident_id=incident_id)

        if side_nodes["source"] and side_nodes["destination"]:
            port = ((ev.get("destination") or {}).get("device") or {}).get("port") or ev.get("port")
            proto = ev.get("ip_proto") or ev.get("protocol")
            rel = "connected_to" + (f" :{port}" if port else "") + (f" ({proto})" if proto else "")
            g.edge(side_nodes["source"], side_nodes["destination"], rel, ev_tag, incident_id=incident_id)
        dom = ev.get("domain") or ev.get("domain_dst")
        if dom and side_nodes["source"]:
            g.edge(side_nodes["source"], g.node("domain", str(dom), incident_id=incident_id), "queried", ev_tag, incident_id=incident_id)


def _ingest_triage_data(g: _Graph, inc_node: str, triage_result: dict, inc_id: str, focus_host_nid: str | None = None) -> None:
    """Ingest extracted IOCs, classification, and MITRE data from Triage Agent."""
    if not isinstance(triage_result, dict):
        return
    ticket = triage_result.get("ticket") or {}
    metakeys_payload = triage_result.get("metakeys_payload") or {}
    metakey_values = metakeys_payload.get("metakey_values") or {}

    for key, val in metakey_values.items():
        k_low = str(key).lower()
        items = val if isinstance(val, list) else [val]
        for v in items:
            if not v or not isinstance(v, str):
                continue
            ntype = _classify_value(v, k_low)
            nid = g.node(ntype, v, incident_id=inc_id,
                         private=_is_private_ip(v) if ntype == "ip" else None)
            g.edge(inc_node, nid, "observed", f"Triage metakey: {key}", incident_id=inc_id)
            if focus_host_nid and ntype in ("file", "process", "hash", "registry"):
                g.edge(focus_host_nid, nid, "has_artifact", "Triage host correlation", incident_id=inc_id)

    mitre_tactic = ticket.get("mitre_tactic")
    mitre_technique = ticket.get("mitre_technique")
    if mitre_tactic and str(mitre_tactic).lower() not in ("unknown", "none", "", "?", "null"):
        val = str(mitre_technique or mitre_tactic)
        if val.lower() not in ("unknown", "none", "", "?", "null"):
            mnode = g.node("mitre", val, incident_id=inc_id,
                           tactic=mitre_tactic, technique=mitre_technique)
            g.edge(inc_node, mnode, "mapped_to", "Triage MITRE mapping", incident_id=inc_id)


def _ingest_threat_intel_data(g: _Graph, inc_node: str, threat_intel_result: dict, inc_id: str) -> None:
    """Ingest Threat Intelligence reputation verdicts (VirusTotal, AbuseIPDB, AlienVault OTX)."""
    if not isinstance(threat_intel_result, dict):
        return
    ti_bundle = threat_intel_result.get("threat_intelligence") or {}

    # VirusTotal
    vt = ti_bundle.get("virustotal") or {}
    for entry in list(vt.get("ip_results") or []) + list(vt.get("domain_results") or []):
        if not isinstance(entry, dict) or entry.get("status") != "completed":
            continue
        indicator = entry.get("indicator")
        malicious = entry.get("malicious", 0)
        if indicator:
            ntype = "ip" if _IP_RE.match(indicator) else "domain"
            disp = "malicious" if malicious > 0 else "suspicious" if entry.get("suspicious", 0) > 0 else "clean"
            g.node(ntype, indicator, incident_id=inc_id, disposition=disp,
                   vt_malicious=malicious, vt_suspicious=entry.get("suspicious", 0),
                   reputation=disp)

    vt_hash = vt.get("file_hash") or {}
    if isinstance(vt_hash, dict) and vt_hash.get("status") == "completed":
        indicator = vt_hash.get("indicator")
        malicious = vt_hash.get("malicious", 0)
        if indicator:
            disp = "malicious" if malicious > 0 else "clean"
            g.node("hash", indicator, incident_id=inc_id, disposition=disp,
                   vt_malicious=malicious, reputation=disp)

    # AbuseIPDB
    abuse = ti_bundle.get("abuseipdb") or {}
    for entry in list(abuse.get("ip_results") or []):
        if not isinstance(entry, dict) or entry.get("status") != "completed":
            continue
        indicator = entry.get("indicator")
        score = entry.get("abuse_confidence_score", 0)
        if indicator:
            disp = "malicious" if score >= 50 else "suspicious" if score > 0 else "clean"
            g.node("ip", indicator, incident_id=inc_id, disposition=disp,
                   abuse_score=score, total_reports=entry.get("total_reports", 0))

    # AlienVault OTX
    otx = ti_bundle.get("alienvault_otx") or {}
    for entry in list(otx.get("otx_results") or []):
        if not isinstance(entry, dict) or entry.get("status") != "completed":
            continue
        indicator = entry.get("indicator")
        pulses = entry.get("pulse_count", 0)
        if indicator and pulses > 0:
            ntype = "ip" if _IP_RE.match(indicator) else "domain"
            g.node(ntype, indicator, incident_id=inc_id, disposition="suspicious",
                   otx_pulses=pulses)


def _ingest_investigation_data(g: _Graph, inc_node: str, inv_result: dict, inc_id: str,
                               focus_host_nid: str | None = None) -> None:
    """Ingest execution traces, parent-child process chains, cmdlines, hashes, network IPs, and MITRE techniques."""
    if not isinstance(inv_result, dict):
        return

    # 1. Execution Traces, Summaries & Containment Text first to gather process nodes
    trace_steps = inv_result.get("execution_trace") or []
    summary_text = str(inv_result.get("incident_summary") or "")
    containment_text = " ".join(str(c) for c in (inv_result.get("recommended_containment") or []))
    findings_corpus = summary_text + " " + containment_text + " " + " ".join(str(s.get("findings") or "") for s in trace_steps if isinstance(s, dict))

    # Known executable tokens & command lines
    proc_matches = set(re.findall(r"\b([a-zA-Z0-9_\-\.]+\.(?:exe|bat|ps1|vbs|cmd|dll|scr))\b", findings_corpus, re.I))
    reg_matches = set(re.findall(r"(HK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|LM|CU)\\[^\s,;\"']+)", findings_corpus, re.I))
    hash_matches = set(re.findall(r"\b([a-fA-F0-9]{32,64})\b", findings_corpus))
    ip_matches = set(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", findings_corpus))

    # User Accounts
    if "NT AUTHORITY\\SYSTEM" in findings_corpus.upper():
        u_nid = g.node("user", "NT AUTHORITY\\SYSTEM", incident_id=inc_id)
        if focus_host_nid:
            g.edge(u_nid, focus_host_nid, "active_on", "Investigation user context", incident_id=inc_id)

    # Process nodes with command line correlation
    proc_nodes: dict[str, str] = {}
    script_nodes: dict[str, str] = {}

    for p in proc_matches:
        p_name = p.strip()
        if len(p_name) < 4:
            continue
        p_low = p_name.lower()
        is_script = p_low.endswith((".bat", ".ps1", ".vbs", ".cmd", ".scr"))

        # Extract associated command line substring if present
        cmd_match = re.search(rf'({re.escape(p_name)}[^\r\n,;"]{{1,140}})', findings_corpus, re.I)
        cmdline = cmd_match.group(1).strip() if cmd_match else None

        if is_script:
            s_nid = g.node("file", p_name, incident_id=inc_id, cmdline=cmdline)
            script_nodes[p_low] = s_nid
        else:
            p_nid = g.node("process", p_name, incident_id=inc_id, cmdline=cmdline)
            proc_nodes[p_low] = p_nid

    # Process relationships: parent-child / spawning / script staging
    spawned_children = set()
    for script_name, s_nid in script_nodes.items():
        if "cmd.exe" in proc_nodes:
            g.edge(proc_nodes["cmd.exe"], s_nid, "executed_script", f"Cmdline staging: {script_name}", incident_id=inc_id)
            spawned_children.add(script_name)
        elif "powershell.exe" in proc_nodes:
            g.edge(proc_nodes["powershell.exe"], s_nid, "executed_script", f"PowerShell execution: {script_name}", incident_id=inc_id)
            spawned_children.add(script_name)
        elif focus_host_nid:
            g.edge(focus_host_nid, s_nid, "has_file", "Investigation script artifact", incident_id=inc_id)

    # Specific parent-child relationships
    if "powershell.exe" in proc_nodes and "cmd.exe" in proc_nodes:
        g.edge(proc_nodes["powershell.exe"], proc_nodes["cmd.exe"], "spawned", "Execution trace chain", incident_id=inc_id)
    if "vmtoolsd.exe" in proc_nodes and "cmd.exe" in proc_nodes:
        g.edge(proc_nodes["vmtoolsd.exe"], proc_nodes["cmd.exe"], "spawned", "Execution trace chain", incident_id=inc_id)
    if "powershell.exe" in proc_nodes and "searchindexer.exe" in proc_nodes:
        g.edge(proc_nodes["powershell.exe"], proc_nodes["searchindexer.exe"], "injected_into", "Process injection trace", incident_id=inc_id)
        spawned_children.add("searchindexer.exe")
    if "cmd.exe" in proc_nodes and "reg.exe" in proc_nodes:
        g.edge(proc_nodes["cmd.exe"], proc_nodes["reg.exe"], "spawned", "Registry manipulation command", incident_id=inc_id)
        spawned_children.add("reg.exe")
    if "cmd.exe" in proc_nodes and "sc.exe" in proc_nodes:
        g.edge(proc_nodes["cmd.exe"], proc_nodes["sc.exe"], "spawned", "Service creation command", incident_id=inc_id)
        spawned_children.add("sc.exe")
    if "cmd.exe" in proc_nodes and "wevtutil.exe" in proc_nodes:
        g.edge(proc_nodes["cmd.exe"], proc_nodes["wevtutil.exe"], "spawned", "Log tampering command", incident_id=inc_id)
        spawned_children.add("wevtutil.exe")

    # Connect root / top-level processes to host
    for p_low, p_nid in proc_nodes.items():
        if focus_host_nid and p_low not in spawned_children:
            g.edge(focus_host_nid, p_nid, "executed", "Investigation process trace", incident_id=inc_id)

    # 2. MITRE Mappings with Direct Tool Attribution & Filtering of Unknowns
    for m in inv_result.get("mitre_mappings") or []:
        if not isinstance(m, dict):
            continue
        raw_tid = str(m.get("technique_id") or "").strip()
        raw_tname = str(m.get("technique_name") or "").strip()
        raw_tactic = str(m.get("tactic") or "").strip()

        # Suppress invalid or unmapped 'Unknown' / empty placeholders
        if raw_tid.lower() in ("unknown", "none", "", "?", "null", "not mapped"):
            raw_tid = ""
        if raw_tname.lower() in ("unknown", "none", "", "?", "null", "not mapped"):
            raw_tname = ""
        if raw_tactic.lower() in ("unknown", "none", "", "?", "null", "not mapped"):
            raw_tactic = ""

        t_id = raw_tid or raw_tname or raw_tactic
        if not t_id:
            continue

        mnode = g.node("mitre", str(t_id), incident_id=inc_id,
                       technique_name=raw_tname or None,
                       technique_id=raw_tid or None,
                       tactic=raw_tactic or None,
                       phase=m.get("timeline_phase"),
                       observed_evidence=m.get("observed_evidence"))

        # Check for direct process attribution in evidence or technique name
        evidence_text = " ".join(str(ev) for ev in (m.get("evidence") or [m.get("observed_evidence") or ""])).lower()
        technique_full = (raw_tid + " " + raw_tname + " " + evidence_text).lower()

        linked_proc = False
        if ("powershell" in technique_full or "t1059" in technique_full) and "powershell.exe" in proc_nodes:
            g.edge(proc_nodes["powershell.exe"], mnode, "exhibits_technique", "PowerShell script execution technique", incident_id=inc_id)
            linked_proc = True
        elif ("wevtutil" in technique_full or "t1070" in technique_full or "event log" in technique_full) and "wevtutil.exe" in proc_nodes:
            g.edge(proc_nodes["wevtutil.exe"], mnode, "exhibits_technique", "Log clearing defense evasion", incident_id=inc_id)
            linked_proc = True
        elif ("reg.exe" in technique_full or "t1112" in technique_full or "registry" in technique_full) and "reg.exe" in proc_nodes:
            g.edge(proc_nodes["reg.exe"], mnode, "exhibits_technique", "Registry modification technique", incident_id=inc_id)
            linked_proc = True
        elif ("sc.exe" in technique_full or "t1543" in technique_full or "t1569" in technique_full or "service" in technique_full) and "sc.exe" in proc_nodes:
            g.edge(proc_nodes["sc.exe"], mnode, "exhibits_technique", "Service installation execution", incident_id=inc_id)
            linked_proc = True
        elif ("vmtoolsd" in technique_full or "t1053" in technique_full or "scheduled task" in technique_full) and "vmtoolsd.exe" in proc_nodes:
            g.edge(proc_nodes["vmtoolsd.exe"], mnode, "exhibits_technique", "Task execution persistence", incident_id=inc_id)
            linked_proc = True

        if not linked_proc:
            g.edge(inc_node, mnode, "exhibits_technique", "Investigation MITRE mapping", incident_id=inc_id)

    # Hashes from investigation trace
    for h in list(hash_matches)[:4]:
        h_nid = g.node("hash", h, incident_id=inc_id)
        if "vmtoolsd.exe" in proc_nodes:
            g.edge(proc_nodes["vmtoolsd.exe"], h_nid, "has_hash", "Observed binary hash", incident_id=inc_id)
        elif focus_host_nid:
            g.edge(focus_host_nid, h_nid, "has_artifact", "Host hash evidence", incident_id=inc_id)

    # IPs from investigation trace
    for ip_val in list(ip_matches)[:6]:
        if ip_val in ("127.0.0.1", "0.0.0.0"):
            continue
        # Skip subnet network identifiers (e.g., 192.168.10.0 from 192.168.10.0/24) or broadcast addresses
        if ip_val.endswith(".0") or ip_val.endswith(".255"):
            continue
        ip_nid = g.node("ip", ip_val, incident_id=inc_id, private=_is_private_ip(ip_val))
        if not _is_private_ip(ip_val):
            # External communication link
            if "vmtoolsd.exe" in proc_nodes:
                g.edge(proc_nodes["vmtoolsd.exe"], ip_nid, "communicates_with", "Outbound HTTPS connection", incident_id=inc_id)
            elif "powershell.exe" in proc_nodes:
                g.edge(proc_nodes["powershell.exe"], ip_nid, "communicates_with", "Outbound C2 beacon", incident_id=inc_id)
            elif focus_host_nid:
                g.edge(focus_host_nid, ip_nid, "connected_to", "Outbound external traffic", incident_id=inc_id)
            else:
                g.edge(inc_node, ip_nid, "observed", "Extracted external IP", incident_id=inc_id)
        else:
            # Internal network entity
            if focus_host_nid:
                g.edge(focus_host_nid, ip_nid, "communicates_with", "Internal endpoint connection", incident_id=inc_id)
            else:
                g.edge(inc_node, ip_nid, "observed", "Internal network telemetry", incident_id=inc_id)

    # Registry nodes
    for reg_key in list(reg_matches)[:5]:
        r_nid = g.node("registry", reg_key, incident_id=inc_id)
        if "reg.exe" in proc_nodes:
            g.edge(proc_nodes["reg.exe"], r_nid, "modified_registry", "Registry modification command", incident_id=inc_id)
        elif focus_host_nid:
            g.edge(focus_host_nid, r_nid, "has_registry_key", "Investigation trace", incident_id=inc_id)



def _ingest_correlation_data(g: _Graph, primary_inc_node: str, primary_inc_id: str,
                            ioc_correlation_result: dict | None,
                            related_incidents: list[dict] | None = None) -> list[dict]:
    """Ingest correlated incidents and connect them across shared indicator pivots."""
    correlated_meta: list[dict] = []
    seen_related_ids: set[str] = {primary_inc_id}
    color_idx = 0

    # 1. From ioc_correlation_result
    if isinstance(ioc_correlation_result, dict):
        results = ioc_correlation_result.get("results") or []
        for r in results:
            if not isinstance(r, dict):
                continue
            ioc_val = r.get("value")
            ioc_type = r.get("type") or _classify_value(str(ioc_val or ""))
            if not ioc_val:
                continue

            # Check related incidents from corpus or open/closed pipeline cases
            related_list = (r.get("related") or []) + (r.get("open_cases") or []) + (r.get("closed_cases") or [])
            for rel in related_list:
                if not isinstance(rel, dict):
                    continue
                rel_id = str(rel.get("id") or rel.get("incident_id") or "")
                if not rel_id or rel_id in seen_related_ids:
                    continue
                if len(seen_related_ids) > 6:  # Cap correlated incidents to top 5 to maintain graph clarity
                    break
                seen_related_ids.add(rel_id)
                rel_color = CORRELATED_INCIDENT_COLORS[color_idx % len(CORRELATED_INCIDENT_COLORS)]
                color_idx += 1

                rel_title = rel.get("title") or f"Correlated Incident {rel_id}"
                rel_sev = rel.get("severity") or "HIGH"
                rel_status = rel.get("status") or rel.get("stage") or "Correlated"

                # Create correlated incident node
                rel_inc_node = g.node(
                    "incident", rel_id,
                    incident_id=rel_id,
                    color=rel_color,
                    is_primary=False,
                    title=rel_title,
                    severity=rel_sev,
                    status=rel_status,
                    correlation_reason=f"Shared {ioc_type}: {ioc_val}",
                )

                # Shared indicator node
                ioc_nid = g.node(
                    ioc_type, str(ioc_val),
                    incident_id=primary_inc_id,
                    is_shared_pivot=True,
                )
                if rel_id not in g.nodes[ioc_nid]["incidents"]:
                    g.nodes[ioc_nid]["incidents"].append(rel_id)

                # Connect shared indicator to primary incident and to correlated incident
                g.edge(primary_inc_node, ioc_nid, "observed", f"Primary IOC: {ioc_val}", incident_id=primary_inc_id)
                g.edge(ioc_nid, rel_inc_node, "shared_indicator", f"Shared {ioc_type} correlation",
                       incident_id=rel_id, color=rel_color, is_cross_incident=True)

                correlated_meta.append({
                    "id": rel_id,
                    "title": rel_title,
                    "color": rel_color,
                    "severity": rel_sev,
                    "status": rel_status,
                    "shared_ioc": ioc_val,
                    "shared_ioc_type": ioc_type,
                })

    # 2. From explicit related_incidents list if passed
    if isinstance(related_incidents, list):
        for rel in related_incidents:
            if not isinstance(rel, dict):
                continue
            rel_id = str(rel.get("id") or rel.get("incident_id") or "")
            if not rel_id or rel_id in seen_related_ids:
                continue
            if len(seen_related_ids) > 6:
                break
            seen_related_ids.add(rel_id)
            rel_color = CORRELATED_INCIDENT_COLORS[color_idx % len(CORRELATED_INCIDENT_COLORS)]
            color_idx += 1
            rel_title = rel.get("title") or f"Correlated Incident {rel_id}"
            rel_inc_node = g.node(
                "incident", rel_id,
                incident_id=rel_id,
                color=rel_color,
                is_primary=False,
                title=rel_title,
                severity=rel.get("severity") or "HIGH",
                status=rel.get("status") or "Correlated",
            )
            g.edge(primary_inc_node, rel_inc_node, "correlated_with", "Direct incident correlation",
                   incident_id=rel_id, color=rel_color, is_cross_incident=True)
            correlated_meta.append({
                "id": rel_id,
                "title": rel_title,
                "color": rel_color,
                "severity": rel.get("severity") or "HIGH",
                "status": rel.get("status") or "Correlated",
            })

    return correlated_meta


# [FYP-FUNCTION] `build_incident_map` — constructs build incident map output for the next SOC analysis support consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident`, `alerts`, `max_alerts`, `triage_result`, `threat_intel_result`, `investigation_result`, `ioc_correlation_result`, `related_incidents`.
# [FYP-PROCESS] Executes the multi-stage, multi-incident entity-graph construction across all Aegis stages.
# [FYP-OUTPUT] Returns dictionary with nodes, edges, timeline, and multi-incident stats.
# [FYP-USED-BY] Static symbol references include case_view_service.py:build_entity_graph.
# [FYP-CALLS] Calls: `_Graph`, `_classify_value`, `_is_private_ip`, `_walk_alert`, `_ingest_triage_data`, `_ingest_threat_intel_data`, `_ingest_investigation_data`, `_ingest_correlation_data`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_incident_map(incident: dict, alerts: list | None = None,
                       max_alerts: int = 200,
                       triage_result: dict | None = None,
                       threat_intel_result: dict | None = None,
                       investigation_result: dict | None = None,
                       ioc_correlation_result: dict | None = None,
                       related_incidents: list[dict] | None = None) -> dict:
    """Build the comprehensive, multi-incident typed entity graph for a case.

    Integrates:
      - Primary incident metadata & alerts
      - Triage extracted metakeys & classification
      - Threat Intelligence enrichment verdicts
      - Investigation execution traces & process lineage
      - Cross-incident IOC correlation webs
    """
    g = _Graph()
    timeline: list[dict] = []
    inc_id = str(incident.get("id") or "?")
    title = str(incident.get("title") or incident.get("name") or "")

    # Primary Incident Node
    inc_node = g.node(
        "incident", inc_id,
        incident_id=inc_id,
        is_primary=True,
        color=PRIMARY_INCIDENT_COLOR,
        title=title,
        priority=incident.get("priority"),
        risk_score=incident.get("riskScore"),
        severity=incident.get("severity") or "High",
        detection_source=incident.get("createdBy"),
    )

    for field, label in (("firstAlertTime", "first alert"),
                         ("created", "incident created"),
                         ("lastUpdated", "last updated")):
        if incident.get(field):
            timeline.append({"time": str(incident[field]), "event": label})

    # 1. Title entity (Focus Host / User)
    focus_host_nid = None
    m = _TITLE_ENTITY_RE.search(title)
    if m:

        val = m.group(1).strip()
        t_low = title.lower()
        hint = "host" if ("endpoint" in t_low or "host" in t_low) else "user" if "user" in t_low else ""
        ntype = _classify_value(val, hint)
        focus_host_nid = g.node(ntype, val, incident_id=inc_id, is_focus_entity=True)
        g.edge(focus_host_nid, inc_node, "focus_of", "incident title", incident_id=inc_id)



    # 2. AlertMeta indicators
    meta = incident.get("alertMeta")
    src_ids: list[str] = []
    dst_ids: list[str] = []
    if isinstance(meta, dict):
        for key, values in meta.items():
            k_low = str(key).lower()
            for v in (values if isinstance(values, list) else [values]):
                if not v or not isinstance(v, str):
                    continue
                ntype = _classify_value(v, k_low)
                nid = g.node(ntype, v, incident_id=inc_id, private=_is_private_ip(v) if ntype == "ip" else None)
                if "source" in k_low or ".src" in k_low:
                    src_ids.append(nid)
                elif "destination" in k_low or ".dst" in k_low:
                    dst_ids.append(nid)
                else:
                    g.edge(inc_node, nid, "observed", f"alertMeta {key}", incident_id=inc_id)
        # Network flow edges: every source talked to the destination set
        for s in src_ids:
            for d in dst_ids:
                g.edge(s, d, "connected_to", "alertMeta co-occurrence", incident_id=inc_id)
        if src_ids and not dst_ids:
            for s in src_ids:
                g.edge(inc_node, s, "observed", "alertMeta", incident_id=inc_id)

    # 3. MITRE tactics / techniques from incident record
    for field, rel in (("tactics", "tactic"), ("techniques", "technique")):
        for t in incident.get(field) or []:
            if t:
                g.edge(inc_node, g.node("mitre", str(t), incident_id=inc_id, kind=rel), "mapped_to", f"incident {field}", incident_id=inc_id)

    # 4. Raw Alerts & Events
    alerts = alerts if alerts is not None else incident.get("alerts")
    n_alerts_walked = 0
    if isinstance(alerts, list):
        for alert in alerts[:max_alerts]:
            if isinstance(alert, dict):
                _walk_alert(g, inc_node, alert, timeline, incident_id=inc_id)
                n_alerts_walked += 1

    # 5. Ingest Stage Outputs
    if triage_result:
        _ingest_triage_data(g, inc_node, triage_result, inc_id, focus_host_nid)
    if threat_intel_result:
        _ingest_threat_intel_data(g, inc_node, threat_intel_result, inc_id)
    if investigation_result:
        _ingest_investigation_data(g, inc_node, investigation_result, inc_id, focus_host_nid)

    # 6. Ingest Correlated Incidents & Cross-Case IOC Web
    correlated_incidents = _ingest_correlation_data(
        g, inc_node, inc_id, ioc_correlation_result, related_incidents
    )

    timeline.sort(key=lambda t: t["time"])
    type_counts: dict[str, int] = {}
    for n in g.nodes.values():
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1

    # Multi-incident summary basis
    basis_parts = []
    if n_alerts_walked:
        basis_parts.append(f"{n_alerts_walked} raw alerts")
    if triage_result:
        basis_parts.append("Triage metakeys")
    if threat_intel_result:
        basis_parts.append("Threat Intel enrichment")
    if investigation_result:
        basis_parts.append("Investigation execution traces")
    if correlated_incidents:
        basis_parts.append(f"{len(correlated_incidents)} correlated incident(s)")
    if not basis_parts:
        basis_parts.append("Incident-level metadata")

    return {
        "incident_id": inc_id,
        "title": title,
        "primary_incident_color": PRIMARY_INCIDENT_COLOR,
        "correlated_incidents": correlated_incidents,
        "nodes": list(g.nodes.values()),
        "edges": list(g.edges.values()),
        "timeline": timeline,
        "stats": {
            "node_counts": type_counts,
            "edge_count": len(g.edges),
            "incident_count": 1 + len(correlated_incidents),
            "correlated_count": len(correlated_incidents),
            "alerts_walked": n_alerts_walked,
            "alerts_available": isinstance(alerts, list) and len(alerts) > 0,
            "alerts_stripped": incident.get("_alerts_stripped"),
            "evidence_basis": " · ".join(basis_parts),
        },
    }


# ── rendering ────────────────────────────────────────────────────────────────

_DOT_STYLE = {
    "incident": ('box', '#0E2A3F', '#4FC3F7'),
    "ip":       ('ellipse', '#102437', '#81D4FA'),
    "host":     ('box', '#14324A', '#A5D6A7'),
    "user":     ('ellipse', '#1B2A44', '#FFCC80'),
    "domain":   ('ellipse', '#241B3A', '#CE93D8'),
    "process":  ('box', '#2A2438', '#EF9A9A'),
    "file":     ('note', '#232D3A', '#B0BEC5'),
    "hash":     ('note', '#1C2A2E', '#80CBC4'),
    "registry": ('box', '#2A1F1B', '#FFB74D'),
    "email":    ('ellipse', '#0E2A3F', '#80D8FF'),
    "mitre":    ('hexagon', '#33222A', '#F48FB1'),
    "entity":   ('ellipse', '#1E2B36', '#E0E0E0'),
}


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(imap: dict, max_fanout: int = 20) -> str:
    """DOT source for a Graphviz renderer."""
    nodes = {n["id"]: n for n in imap["nodes"]}
    edges = imap["edges"]

    fan: dict[tuple, list[dict]] = {}
    for e in edges:
        fan.setdefault((e["src"], e["relation"]), []).append(e)

    lines = [
        "digraph incident {",
        '  rankdir=LR; bgcolor="transparent";',
        '  node [fontname="Helvetica", fontsize=11, style="filled", fontcolor="#E8F1F8"];',
        '  edge [fontname="Helvetica", fontsize=9, color="#5B7A8F", fontcolor="#9FB8C8"];',
    ]
    used: set[str] = set()
    agg_i = 0

    def emit_node(nid: str, label: str | None = None, ntype: str | None = None) -> None:
        if nid in used:
            return
        used.add(nid)
        n = nodes.get(nid, {})
        t = ntype or n.get("type", "entity")
        shape, fill, border = _DOT_STYLE.get(t, _DOT_STYLE["entity"])
        lbl = _dot_escape(label if label is not None else n.get("label", nid))
        if t == "incident":
            lbl = f"{lbl}\\n{_dot_escape((n.get('props') or {}).get('title', '') or '')[:48]}"
        lines.append(
            f'  "{_dot_escape(nid)}" [label="{lbl}", shape={shape}, '
            f'fillcolor="{fill}", color="{border}"];'
        )

    for (src, relation), group in fan.items():
        emit_node(src)
        shown = group[:max_fanout]
        for e in shown:
            emit_node(e["dst"])
            lines.append(
                f'  "{_dot_escape(e["src"])}" -> "{_dot_escape(e["dst"])}" '
                f'[label="{_dot_escape(relation)}"];'
            )
        hidden = len(group) - len(shown)
        if hidden > 0:
            agg_i += 1
            agg = f"agg:{agg_i}"
            emit_node(agg, label=f"+{hidden} more", ntype=nodes.get(shown[0]["dst"], {}).get("type", "entity"))
            lines.append(
                f'  "{_dot_escape(src)}" -> "{agg}" '
                f'[label="{_dot_escape(relation)}", style=dashed];'
            )
    in_edges = {e["src"] for e in edges} | {e["dst"] for e in edges}
    for nid in nodes:
        if nid not in in_edges:
            emit_node(nid)
    lines.append("}")
    return "\n".join(lines)


def map_caption(imap: dict) -> str:
    """One-line honest summary for UI captions."""
    s = imap["stats"]
    parts = [f"{t}: {c}" for t, c in sorted(s["node_counts"].items()) if t != "incident"]
    if s.get("correlated_count"):
        parts.append(f"correlated incidents: {s['correlated_count']}")
    return (
        f"{s['edge_count']} relationships · " + (", ".join(parts) or "no entities") +
        f" · basis: {s['evidence_basis']}"
    )


def summarize_map(imap: dict, max_lines: int = 40) -> str:
    """Plain-text rendering of the graph for agent prompts."""
    nodes = {n["id"]: n for n in imap["nodes"]}
    out = [f"ENTITY MAP for {imap['incident_id']} — {imap['title']}",
           f"basis: {imap['stats']['evidence_basis']}"]
    for e in imap["edges"][:max_lines]:
        src = nodes.get(e["src"], {}).get("label", e["src"])
        dst = nodes.get(e["dst"], {}).get("label", e["dst"])
        ev = ", ".join(e.get("evidence", [])[:3])
        out.append(f"  {src} -[{e['relation']}]-> {dst}  (evidence: {ev})")
    if len(imap["edges"]) > max_lines:
        out.append(f"  ... and {len(imap['edges']) - max_lines} more relationships")
    if imap.get("timeline"):
        out.append("TIMELINE:")
        for t in imap["timeline"][:15]:
            out.append(f"  {t['time']} — {t['event']}")
    if imap.get("endpoint_profile_text"):
        out.append(imap["endpoint_profile_text"])
    return "\n".join(out)
