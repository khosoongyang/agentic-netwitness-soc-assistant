"""
velociraptor_investigation.py — per-incident Velociraptor DFIR collection plan
(investigation-agent skill, standalone).

Adapted from AgentSecOps/SecOpsAgentKit's `incident-response/ir-velociraptor`
Claude skill (github.com/AgentSecOps/SecOpsAgentKit) — its SKILL.md, its
`references/mitre-attack-mapping.md` (MITRE technique -> named Velociraptor
artifacts + VQL), `references/vql-patterns.md`, and the offline-collector / hunt
templates. That skill is prose+VQL guidance for an analyst driving a live
Velociraptor deployment; we have no Velociraptor server/agent on the NetWitness
endpoints, so this adapts the *content* into a deterministic generator: given one
incident it emits the Velociraptor **collection + hunt plan** an analyst would run
to preserve and hunt forensic evidence on the affected host.

Deliberately DISTINCT from osquery_investigation.py (built earlier):
  * osquery pack  = ad-hoc SQL over a host's LIVE state (processes/sockets/registry
                    — point-in-time).
  * this module   = named forensic ARTIFACTS (event logs, prefetch, LNK, MFT
                    timeline, WMI persistence) collected & preserved via VQL, plus
                    a fleet HUNT definition and an offline-collector command.
osquery answers "what's happening on this host now"; Velociraptor answers "collect
and preserve the deep forensic evidence, then hunt it across the fleet."

It also complements the other investigation-side skills (threat_hunting =
strategic hypotheses; detection_* = SIEM Sigma/EQL; endpoint_profile = corpus
history). Per the standing rule it is a STANDALONE file surfaced only via app.py's
Map panel — NO edits to soc_investigation_agent/.

Safety / honesty:
  - pure function of incident + triage result: no LLM, no network, no DB.
  - deterministic (fixed library + fixed selection) → identical plan per input.
  - Velociraptor's DFIR artifacts here are Windows; platform is inferred and
    labelled honestly.
  - the plan is GENERATED, not executed (no Velociraptor here) — clearly framed.
  - kill switch: NW_DISABLE_VR_PLAN=1 disables it.

Usage:
    plan = build_collection_plan(incident, triage_result)
    print(format_plan(plan))
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")
_WINDOWS_HOST_RE = re.compile(r"^(WIN-|DESKTOP-|LAPTOP-|SERV|FILESERV|DC\d)", re.I)


# ── Velociraptor artifact + VQL library (faithful port of the skill) ───────────
# Baseline artifacts always collected for endpoint IR triage.
_BASELINE_ARTIFACTS = [
    "Windows.System.Pslist",
    "Windows.Network.NetstatEnriched",
    "Windows.EventLogs.Evtx",
    "Windows.Forensics.Prefetch",
    "Windows.Forensics.Timeline",
    "Windows.KapeFiles.Targets",
]

# Baseline VQL patterns (from vql-patterns.md) — always useful for triage.
_BASELINE_VQL = [
    {"key": "suspicious_processes", "title": "Suspicious process parent-child / LOLBins",
     "artifacts": ["Windows.System.Pslist"],
     "vql": ("SELECT Pid, Ppid, Name, CommandLine, Username, Exe, CreateTime\n"
             "FROM pslist()\n"
             "WHERE Exe =~ \"(?i)(temp|tmp|appdata)\"\n"
             "  OR CommandLine =~ \"(?i)(iex|invoke-expression|downloadstring|webclient|hidden|bypass|encodedcommand)\"\n"
             "  OR (Name =~ \"(?i)(certutil|bitsadmin)\" AND CommandLine =~ \"(?i)(urlcache|transfer|download)\")"),
     "tactic": "Baseline"},
    {"key": "external_netstat", "title": "Established external connections with process context",
     "artifacts": ["Windows.Network.NetstatEnriched"],
     "vql": ("SELECT Laddr.IP AS LocalIP, Laddr.Port AS LocalPort,\n"
             "       Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort, Status, Pid,\n"
             "       process_tracker_get(id=Pid).Name AS ProcessName\n"
             "FROM netstat()\n"
             "WHERE Status = \"ESTABLISHED\" AND Raddr.IP =~ \"^(?!10\\.|127\\.|192\\.168\\.|172\\.)\""),
     "tactic": "Baseline"},
    {"key": "file_timeline", "title": "Recent executable drops in user profiles (24h)",
     "artifacts": ["Windows.Forensics.Timeline"],
     "vql": ("SELECT FullPath, Size, Mtime, Btime\n"
             "FROM glob(globs=\"C:/Users/*/AppData/**/*.exe\")\n"
             "WHERE Mtime > timestamp(epoch=now() - 86400)\n"
             "ORDER BY Mtime DESC"),
     "tactic": "Baseline"},
]

# MITRE-keyed VQL hunt library (ported from mitre-attack-mapping.md). Each entry
# names the Velociraptor artifacts to collect + the VQL to run.
_HUNT_VQL = [
    {"key": "valid_accounts_logons", "title": "Off-hours / remote logons (EventID 4624)",
     "artifacts": ["Windows.EventLogs.RDP", "Windows.EventLogs.Evtx"],
     "vql": ("SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS LogonTime,\n"
             "       EventData.TargetUserName AS Username, EventData.IpAddress AS SourceIP,\n"
             "       EventData.LogonType AS LogonType\n"
             "FROM parse_evtx(filename=\"C:/Windows/System32/winevt/Logs/Security.evtx\")\n"
             "WHERE System.EventID.Value = 4624 AND EventData.LogonType IN (3, 10)\n"
             "ORDER BY LogonTime DESC"),
     "technique": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access"},
    {"key": "phishing_office", "title": "Suspicious Office docs in Downloads (7d)",
     "artifacts": ["Windows.Forensics.Lnk", "Windows.Applications.Office.Keywords"],
     "vql": ("SELECT FullPath, Mtime, read_file(filename=FullPath, length=100000) AS Content\n"
             "FROM glob(globs=[\"C:/Users/*/Downloads/**/*.doc*\", \"C:/Users/*/Downloads/**/*.xls*\"])\n"
             "WHERE Content =~ \"(?i)(macro|vba|shell|exec|powershell)\"\n"
             "  AND Mtime > timestamp(epoch=now() - 604800)"),
     "technique": "T1566", "technique_name": "Phishing", "tactic": "Initial Access"},
    {"key": "powershell_scriptblock", "title": "Malicious PowerShell script blocks (EventID 4104)",
     "artifacts": ["Windows.EventLogs.PowershellScriptblock"],
     "vql": ("SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS ExecutionTime,\n"
             "       EventData.ScriptBlockText AS Command\n"
             "FROM parse_evtx(filename=\"C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx\")\n"
             "WHERE System.EventID.Value = 4104\n"
             "  AND EventData.ScriptBlockText =~ \"(?i)(invoke-expression|iex|downloadstring|webclient|bypass|hidden|encodedcommand)\"\n"
             "ORDER BY ExecutionTime DESC"),
     "technique": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
    {"key": "cmd_from_office", "title": "cmd.exe spawned by an Office app",
     "artifacts": ["Windows.System.Pslist", "Windows.EventLogs.ProcessCreation"],
     "vql": ("SELECT Pid, Ppid, Name, CommandLine, Username, CreateTime\n"
             "FROM pslist()\n"
             "WHERE Name =~ \"(?i)cmd.exe\" AND CommandLine =~ \"(?i)(/c|/k|/r)\"\n"
             "  AND Ppid IN (SELECT Pid FROM pslist() WHERE Name =~ \"(?i)(winword|excel|powerpnt|outlook)\")"),
     "technique": "T1059.003", "technique_name": "Windows Command Shell", "tactic": "Execution"},
    {"key": "scheduled_tasks", "title": "Recently created scheduled tasks (24h)",
     "artifacts": ["Windows.System.TaskScheduler", "Windows.EventLogs.ScheduledTasks"],
     "vql": ("SELECT FullPath AS TaskPath,\n"
             "       parse_xml(file=FullPath).Task.Actions.Exec.Command AS Command,\n"
             "       timestamp(epoch=Mtime) AS Created\n"
             "FROM glob(globs=\"C:/Windows/System32/Tasks/**\")\n"
             "WHERE NOT IsDir AND Mtime > timestamp(epoch=now() - 86400) AND Command != \"\"\n"
             "ORDER BY Created DESC"),
     "technique": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence"},
    {"key": "run_keys", "title": "Autorun registry entries (Run / RunOnce)",
     "artifacts": ["Windows.Persistence.PermanentRuns", "Windows.System.StartupItems"],
     "vql": ("SELECT Key.FullPath AS RegistryKey, ValueName, ValueData.value AS ExecutablePath,\n"
             "       timestamp(epoch=Key.Mtime) AS LastModified\n"
             "FROM read_reg_key(globs=[\n"
             "  \"HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*\",\n"
             "  \"HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce/*\",\n"
             "  \"HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*\"])\n"
             "WHERE ValueData.value != \"\"\nORDER BY LastModified DESC"),
     "technique": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},
    {"key": "suspicious_services", "title": "Suspicious Windows services",
     "artifacts": ["Windows.System.Services", "Windows.EventLogs.ServiceCreation"],
     "vql": ("SELECT Key.Name AS ServiceName, ImagePath.value AS ExecutablePath,\n"
             "       Start.value AS StartType, timestamp(epoch=Key.Mtime) AS LastModified\n"
             "FROM read_reg_key(globs=\"HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/*\")\n"
             "WHERE ImagePath.value != \"\"\n"
             "  AND (ImagePath.value =~ \"(?i)(temp|appdata|users|powershell|cmd|wscript)\"\n"
             "       OR Key.Mtime > timestamp(epoch=now() - 604800))"),
     "technique": "T1543.003", "technique_name": "Windows Service", "tactic": "Persistence"},
    {"key": "wmi_persistence", "title": "Malicious WMI event subscriptions",
     "artifacts": ["Windows.Persistence.PermanentWMIEvents"],
     "vql": ("SELECT Namespace, FilterName, Query, ConsumerName, ConsumerType, ConsumerData\n"
             "FROM wmi(query=\"SELECT * FROM __FilterToConsumerBinding\", namespace=\"ROOT/Subscription\")\n"
             "WHERE ConsumerData =~ \"(?i)(powershell|cmd|wscript|executable)\""),
     "technique": "T1546.003", "technique_name": "WMI Event Subscription", "tactic": "Persistence"},
    {"key": "uac_bypass", "title": "UAC-bypass process creation (EventID 4688)",
     "artifacts": ["Windows.EventLogs.EvtxHunter"],
     "vql": ("SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime,\n"
             "       EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine\n"
             "FROM parse_evtx(filename=\"C:/Windows/System32/winevt/Logs/Security.evtx\")\n"
             "WHERE System.EventID.Value = 4688\n"
             "  AND (EventData.NewProcessName =~ \"(?i)(fodhelper|computerdefaults|sdclt)\"\n"
             "       OR EventData.CommandLine =~ \"(?i)(eventvwr|ms-settings)\")"),
     "technique": "T1548.002", "technique_name": "Bypass User Account Control", "tactic": "Privilege Escalation"},
    {"key": "priv_use", "title": "Sensitive privilege use (EventID 4672)",
     "artifacts": ["Windows.EventLogs.EvtxHunter"],
     "vql": ("SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime,\n"
             "       EventData.SubjectUserName AS Username, EventData.PrivilegeList AS Privileges\n"
             "FROM parse_evtx(filename=\"C:/Windows/System32/winevt/Logs/Security.evtx\")\n"
             "WHERE System.EventID.Value = 4672\n"
             "  AND EventData.PrivilegeList =~ \"(SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege)\""),
     "technique": "T1134", "technique_name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    {"key": "rdp_lateral", "title": "RDP / remote-service lateral movement (EventID 4624 type 10)",
     "artifacts": ["Windows.EventLogs.RDP", "Windows.Network.NetstatEnriched"],
     "vql": ("SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS LogonTime,\n"
             "       EventData.TargetUserName AS Username, EventData.IpAddress AS SourceIP\n"
             "FROM parse_evtx(filename=\"C:/Windows/System32/winevt/Logs/Security.evtx\")\n"
             "WHERE System.EventID.Value = 4624 AND EventData.LogonType = 10\nORDER BY LogonTime DESC"),
     "technique": "T1021.001", "technique_name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
]


def _is_public_ip(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def _focus(incident: dict, triage_result: dict | None) -> dict:
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    host = None
    for key, vals in mkv.items():
        klow = key.lower()
        if any(n in klow for n in ("host", "computer", "hostname", "machine", "device")):
            for v in (vals if isinstance(vals, list) else [vals]):
                v = str(v or "").strip()
                # endpoint hostnames are bare NetBIOS names; a dotted value under a
                # host key is a referenced FQDN/domain (a C2 IOC), not the endpoint.
                if v and not _IP_RE.match(v) and "." not in v:
                    host = v
                    break
        if host:
            break
    title = str(incident.get("title") or incident.get("name") or "")
    title_entity = None
    m = _TITLE_ENTITY_RE.search(title)
    if m:
        title_entity = m.group(1).strip()
        if host is None and title_entity and not _IP_RE.match(title_entity):
            host = title_entity
    return {"host": host, "title_entity": title_entity}


def _infer_platform(host: str | None, incident: dict) -> tuple[str, str]:
    sources = " ".join(str(s) for s in (incident.get("sources") or [])).lower()
    if host and _WINDOWS_HOST_RE.search(host):
        return "windows", f"inferred Windows from host name '{host}'"
    if "endpoint" in sources:
        return "windows", "inferred Windows from NetWitness Endpoint source"
    if host and re.match(r"^[A-Z0-9][A-Z0-9\-]{2,}$", host) and "." not in host:
        return "windows", f"inferred Windows from endpoint host name '{host}'"
    return "unknown", ("platform unknown — no host name resolved; the ported "
                       "Velociraptor artifacts are Windows DFIR (assumed) — verify the host OS")


def _extract_iocs(incident: dict, triage_result: dict | None) -> dict:
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    am = incident.get("alertMeta") or {}
    ips, hashes, domains = [], [], []
    for field in ("DestinationIp", "SourceIp"):
        for v in am.get(field) or []:
            if isinstance(v, str) and _IP_RE.match(v):
                ips.append(v)
    for key, vals in mkv.items():
        klow = key.lower()
        for v in (vals if isinstance(vals, list) else [vals]):
            v = str(v or "").strip()
            if _HASH_RE.match(v):
                hashes.append(v)
            elif (("domain" in klow or "fqdn" in klow or "host" in klow)
                  and "." in v and not _IP_RE.match(v)):
                domains.append(v)

    def dedup(seq):
        return list(dict.fromkeys(seq))

    return {"ips": dedup(ips), "hashes": dedup(hashes), "domains": dedup(domains)}


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


def _select_hunt(mitre: dict, budget: int) -> tuple[list[dict], str]:
    tech = mitre["technique"]
    tactic = mitre["tactic"]
    base = tech.split(".")[0] if tech else ""
    chosen: list[dict] = []
    seen: set[str] = set()

    def _take(pred):
        for q in _HUNT_VQL:
            if len(chosen) >= budget:
                break
            if q["key"] in seen:
                continue
            if pred(q):
                chosen.append(q)
                seen.add(q["key"])

    basis: list[str] = []
    if tech:
        _take(lambda q: q.get("technique") == tech)
        _take(lambda q: q.get("technique", "").split(".")[0] == base)
        basis.append(f"technique {tech}")
    if tactic:
        _take(lambda q: q.get("tactic", "").lower() == tactic.lower())
        basis.append(f"tactic {tactic}")
    if not chosen:
        _take(lambda q: q["key"] in (
            "powershell_scriptblock", "run_keys", "scheduled_tasks",
            "wmi_persistence", "valid_accounts_logons", "rdp_lateral"))
        basis.append("no MITRE context — broad default DFIR sweep")
    return chosen, "; ".join(basis)


def _ioc_pivot_vql(iocs: dict) -> list[dict]:
    out: list[dict] = []
    if iocs["ips"]:
        ips = " OR ".join(f'Raddr.IP = "{ip}"' for ip in iocs["ips"][:12])
        out.append({
            "key": "ioc_ip_netstat", "title": f"Connections to incident IP(s) ({len(iocs['ips'])})",
            "artifacts": ["Windows.Network.NetstatEnriched"],
            "vql": ("SELECT Laddr.IP AS LocalIP, Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort,\n"
                    "       Status, Pid, process_tracker_get(id=Pid).Name AS ProcessName,\n"
                    "       process_tracker_get(id=Pid).CommandLine AS CommandLine\n"
                    f"FROM netstat()\nWHERE {ips}"),
            "technique": "T1071", "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control", "ioc_pivot": True})
    if iocs["hashes"]:
        hs = ", ".join(f'"{h}"' for h in iocs["hashes"][:12])
        out.append({
            "key": "ioc_hash_procs", "title": f"Running binaries matching incident hash(es) ({len(iocs['hashes'])})",
            "artifacts": ["Windows.System.Pslist"],
            "vql": ("SELECT Pid, Name, Exe, CommandLine, hash(path=Exe).SHA256 AS SHA256\n"
                    "FROM pslist()\n"
                    f"WHERE hash(path=Exe).SHA256 IN ({hs})"),
            "technique": "T1204", "technique_name": "User Execution", "tactic": "Execution", "ioc_pivot": True})
    for dom in iocs["domains"][:6]:
        out.append({
            "key": f"ioc_domain_{dom}", "title": f"DNS / hosts references to domain {dom}",
            "artifacts": ["Windows.Network.NetstatEnriched", "Windows.System.DNSCache"],
            "vql": ("SELECT Name, Record, timestamp(epoch=now()) AS Checked\n"
                    "FROM Artifact.Windows.System.DNSCache()\n"
                    f"WHERE Name =~ \"(?i){re.escape(dom)}\""),
            "technique": "T1071.001", "technique_name": "Web Protocols",
            "tactic": "Command and Control", "ioc_pivot": True})
    return out


def _collector_command(artifacts: list[str]) -> str:
    joined = " \\\n  ".join(artifacts)
    return ("velociraptor --config server.config.yaml artifacts collect \\\n  "
            + joined + " \\\n  --output /evidence/collection_$(hostname).zip")


def _hunt_yaml(host: str, mitre: dict, artifacts: list[str]) -> str:
    tech = mitre["technique"] or "unspecified"
    art_lines = "\n".join(f"    - {a}" for a in artifacts[:6])
    return (
        "# Velociraptor hunt (fleet-wide) — generated for this incident\n"
        "hunt_description: |\n"
        f"  Hunt: DFIR collection seeded by incident on {host}\n"
        f"  Hypothesis: activity consistent with MITRE {tech}\n"
        "  Priority: High\n"
        "configuration:\n"
        "  artifacts:\n"
        f"{art_lines}\n"
        "  target: all_endpoints   # scope down to the affected subnet/OU in production\n"
    )


def build_collection_plan(incident: dict, triage_result: dict | None = None,
                          max_hunt: int = 8) -> dict:
    """Assemble a per-incident Velociraptor collection + hunt plan. Deterministic,
    read-only, never raises. Returns {"available": bool, ...}."""
    if os.environ.get("NW_DISABLE_VR_PLAN"):
        return {"available": False, "reason": "disabled via NW_DISABLE_VR_PLAN"}

    focus = _focus(incident, triage_result)
    platform, platform_note = _infer_platform(focus["host"], incident)
    iocs = _extract_iocs(incident, triage_result)
    mitre = _mitre(incident, triage_result)

    hunt, hunt_basis = _select_hunt(mitre, max_hunt)
    ioc_pivot = _ioc_pivot_vql(iocs)

    # union of all artifacts referenced (baseline + selected hunt + ioc pivots),
    # deterministic order for the collector command.
    artifacts: list[str] = list(_BASELINE_ARTIFACTS)
    for q in hunt + ioc_pivot:
        for a in q.get("artifacts", []):
            if a not in artifacts:
                artifacts.append(a)

    host = focus["host"] or focus["title_entity"] or "target-host"

    def _shape(q: dict) -> dict:
        return {"key": q["key"], "title": q["title"], "vql": q["vql"],
                "artifacts": q.get("artifacts", []), "technique": q.get("technique"),
                "technique_name": q.get("technique_name"), "tactic": q.get("tactic"),
                "ioc_pivot": q.get("ioc_pivot", False)}

    return {
        "available": True,
        "host": focus["host"], "title_entity": focus["title_entity"],
        "platform": platform, "platform_note": platform_note,
        "mitre": mitre, "hunt_basis": hunt_basis, "iocs": iocs,
        "artifacts": artifacts,
        "baseline_vql": [_shape(q) for q in _BASELINE_VQL],
        "hunt_vql": [_shape(q) for q in hunt],
        "ioc_pivot_vql": [_shape(q) for q in ioc_pivot],
        "collector_command": _collector_command(artifacts),
        "hunt_yaml": _hunt_yaml(host, mitre, artifacts),
        "stats": {
            "artifacts": len(artifacts),
            "baseline_vql": len(_BASELINE_VQL),
            "hunt_vql": len(hunt),
            "ioc_pivot_vql": len(ioc_pivot),
            "total_vql": len(_BASELINE_VQL) + len(hunt) + len(ioc_pivot),
        },
    }


def format_plan(plan: dict) -> str:
    """Plain-text block for the Map panel."""
    if not plan.get("available"):
        return "VELOCIRAPTOR COLLECTION PLAN unavailable: " + plan.get("reason", "unknown")

    host = plan["host"] or plan["title_entity"] or "unresolved host"
    m = plan["mitre"]
    mitre_line = (f"{m['technique'] or '—'} / {m['tactic'] or '—'}"
                  if (m["technique"] or m["tactic"]) else "no MITRE context on incident")
    lines = [
        "VELOCIRAPTOR COLLECTION & HUNT PLAN (generated VQL/artifacts to collect on "
        "the endpoint — not executed here; adapted from SecOpsAgentKit ir-velociraptor)",
        f"  target host: {host}   ·   platform: {plan['platform']} ({plan['platform_note']})",
        f"  MITRE focus: {mitre_line}   ·   selection: {plan['hunt_basis']}",
    ]
    ic = plan["iocs"]
    if ic["ips"] or ic["hashes"] or ic["domains"]:
        lines.append(f"  IOCs pivoted: {len(ic['ips'])} IP(s), "
                     f"{len(ic['hashes'])} hash(es), {len(ic['domains'])} domain(s)")

    lines.append("")
    lines.append("── Artifacts to collect (offline collector) ──")
    lines.append("  " + ", ".join(plan["artifacts"]))
    lines.append("  $ " + plan["collector_command"].replace("\n", "\n    "))

    def _emit(header: str, queries: list[dict]) -> None:
        if not queries:
            return
        lines.append("")
        lines.append(header)
        for q in queries:
            tag = f"  [{q['technique']} {q.get('technique_name') or ''}]".rstrip() if q.get("technique") else ""
            arts = f"  «{', '.join(q['artifacts'])}»" if q.get("artifacts") else ""
            lines.append(f"  • {q['title']}{tag}{arts}")
            for ln in q["vql"].split("\n"):
                lines.append(f"      {ln}")

    _emit("── Baseline DFIR VQL (always) ──", plan["baseline_vql"])
    _emit(f"── Technique-focused hunt VQL ({plan['stats']['hunt_vql']}) ──", plan["hunt_vql"])
    _emit(f"── IOC-pivot VQL ({plan['stats']['ioc_pivot_vql']}) ──", plan["ioc_pivot_vql"])
    lines.append("")
    lines.append("── Fleet hunt (VQL artifact hunt, scope down in production) ──")
    for ln in plan["hunt_yaml"].split("\n"):
        lines.append("  " + ln)
    lines.append(f"  {plan['stats']['total_vql']} VQL queries + "
                 f"{plan['stats']['artifacts']} artifacts — run on a Velociraptor "
                 "client/offline collector on the affected host.")
    return "\n".join(lines)
