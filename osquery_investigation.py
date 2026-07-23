"""
osquery_investigation.py — per-incident osquery DFIR investigation pack
(investigation-agent skill, standalone).

Adapted from AgentSecOps/SecOpsAgentKit's `incident-response/forensics-osquery`
Claude skill (github.com/AgentSecOps/SecOpsAgentKit) — its SKILL.md, its four
forensic packs (ir-triage / credential-access / lateral-movement /
persistence-hunt .conf) and its MITRE-ATT&CK→osquery query reference. That skill
is prose+SQL guidance for an analyst driving a live osquery agent; we have no
osquery agent deployed on the NetWitness endpoints, so this adapts the *content*
into a deterministic generator: given one incident it emits the concrete,
MITRE-mapped osquery queries an analyst would RUN on the affected host to collect
evidence — a runnable investigation checklist tailored to this incident's host,
technique and IOCs.

This is the investigation agent's "how do I actually interrogate this endpoint"
step. It complements, without overlapping:
  * threat_hunting.py     — strategic hunt hypotheses / anomalies (what to look for)
  * detection_rules.py /
    detection_engineering — Sigma/EQL for the SIEM (detect in the log pipeline)
  * endpoint_profile.py   — what the corpus already knows about the host
This module = the tactical, host-level, runnable osquery to gather evidence NOW.

Per the standing rule it is a STANDALONE file surfaced only via app.py's Map
panel — it makes NO edits to soc_investigation_agent/ (see the memory note
"Standalone investigation skills").

Safety / honesty:
  - pure function of the incident + triage result: no LLM, no network, no DB.
  - deterministic (fixed library + fixed selection order) → identical pack for
    identical input.
  - platform is INFERRED (host naming / NetWitness-Endpoint source) and labelled
    honestly; queries are filtered to the inferred platform + cross-platform.
  - the pack is GENERATED, not executed — clearly framed as queries-to-run.
  - kill switch: NW_DISABLE_OSQUERY_PACK=1 disables it.

Usage:
    pack = build_investigation_pack(incident, triage_result)
    print(format_pack(pack))
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
# same title-entity convention as incident_map.py: "... for KELLYWANG" / "... for 192.168.0.19"
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")
# host names that read as Windows endpoints (corpus: KELLYWANG, DESKTOP-HU4A549,
# WIN-BGBE4DKRRAR, BETHANYCHUCHU, FILESERV02 ...)
_WINDOWS_HOST_RE = re.compile(r"^(WIN-|DESKTOP-|LAPTOP-|SERV|FILESERV|DC\d)", re.I)


# ── the osquery query library (faithful port of the skill's packs + reference) ──
# Each query: key, title, sql (single-line, as an analyst would type it), the
# MITRE technique/tactic it serves, the osquery tables it touches, and the
# platform it applies to ("all" | "windows" | "posix" | "linux" | "darwin").

_TRIAGE_QUERIES: list[dict] = [
    {"key": "system_info", "title": "System information snapshot",
     "sql": "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info;",
     "tactic": "Baseline", "tables": ["system_info"], "platform": "all"},
    {"key": "logged_in_users", "title": "Currently logged-in users",
     "sql": "SELECT user, tty, host, time, pid FROM logged_in_users;",
     "tactic": "Baseline", "tables": ["logged_in_users"], "platform": "all"},
    {"key": "last_logins", "title": "Recent login history",
     "sql": "SELECT username, tty, pid, type, time, host FROM last ORDER BY time DESC LIMIT 50;",
     "tactic": "Baseline", "tables": ["last"], "platform": "all"},
    {"key": "running_processes", "title": "All running processes with metadata",
     "sql": "SELECT pid, name, path, cmdline, cwd, uid, parent, start_time FROM processes ORDER BY start_time DESC;",
     "tactic": "Baseline", "tables": ["processes"], "platform": "all"},
    {"key": "processes_deleted_binary", "title": "Processes whose executable is deleted (malware indicator)",
     "sql": "SELECT pid, name, path, cmdline, parent FROM processes WHERE on_disk = 0;",
     "tactic": "Baseline", "tables": ["processes"], "platform": "all"},
    {"key": "external_connections", "title": "Active external network connections",
     "sql": ("SELECT p.pid, p.name, p.path, ps.local_port, ps.remote_address, ps.remote_port, ps.state "
             "FROM processes p JOIN process_open_sockets ps ON p.pid = ps.pid "
             "WHERE ps.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0');"),
     "tactic": "Baseline", "tables": ["processes", "process_open_sockets"], "platform": "all"},
    {"key": "listening_ports", "title": "Services listening on external interfaces",
     "sql": ("SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name, p.path "
             "FROM listening_ports lp LEFT JOIN processes p ON lp.pid = p.pid "
             "WHERE lp.address NOT IN ('127.0.0.1', '::1');"),
     "tactic": "Baseline", "tables": ["listening_ports", "processes"], "platform": "all"},
    {"key": "arp_cache", "title": "ARP cache (recently contacted hosts on the LAN)",
     "sql": "SELECT address, mac, interface FROM arp_cache;",
     "tactic": "Baseline", "tables": ["arp_cache"], "platform": "all"},
]

_HUNT_QUERIES: list[dict] = [
    # ── Execution ────────────────────────────────────────────────────────────
    {"key": "powershell_suspicious", "title": "Suspicious PowerShell execution",
     "sql": ("SELECT pid, name, path, cmdline, parent FROM processes WHERE name LIKE '%powershell%' "
             "AND (cmdline LIKE '%EncodedCommand%' OR cmdline LIKE '%-enc%' OR cmdline LIKE '%FromBase64String%' "
             "OR cmdline LIKE '%Invoke-Expression%' OR cmdline LIKE '%IEX%' OR cmdline LIKE '%DownloadString%' "
             "OR cmdline LIKE '%-w hidden%' OR cmdline LIKE '%-WindowStyle hidden%');"),
     "technique": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
     "tables": ["processes"], "platform": "windows"},
    {"key": "cmd_suspicious", "title": "Suspicious cmd.exe usage",
     "sql": ("SELECT pid, name, path, cmdline, parent FROM processes WHERE name = 'cmd.exe' "
             "AND (cmdline LIKE '%/c%' OR cmdline LIKE '%&%' OR cmdline LIKE '%|%' OR cmdline LIKE '%>%');"),
     "technique": "T1059.003", "technique_name": "Windows Command Shell", "tactic": "Execution",
     "tables": ["processes"], "platform": "windows"},
    {"key": "unix_shell_suspicious", "title": "Suspicious shell execution",
     "sql": ("SELECT pid, name, path, cmdline, parent, uid FROM processes "
             "WHERE name IN ('bash','sh','zsh','dash') AND (cmdline LIKE '%-i%' OR cmdline LIKE '%/dev/tcp/%' "
             "OR cmdline LIKE '%curl%' OR cmdline LIKE '%wget%');"),
     "technique": "T1059.004", "technique_name": "Unix Shell", "tactic": "Execution",
     "tables": ["processes"], "platform": "posix"},
    # ── Initial Access ─────────────────────────────────────────────────────────
    {"key": "webserver_spawned_shell", "title": "Web server process spawning a shell (webshell / exploit)",
     "sql": ("SELECT p1.name AS webserver, p1.cmdline, p2.name AS child, p2.cmdline AS child_cmdline "
             "FROM processes p1 JOIN processes p2 ON p1.pid = p2.parent "
             "WHERE p1.name IN ('httpd','nginx','apache2','w3wp.exe','java') "
             "AND p2.name IN ('bash','sh','cmd.exe','powershell.exe','python','perl');"),
     "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access",
     "tables": ["processes"], "platform": "all"},
    {"key": "unusual_valid_accounts", "title": "Unusual account usage / recent logins",
     "sql": "SELECT username, tty, host, time FROM last WHERE time > (strftime('%s','now') - 86400) ORDER BY time DESC;",
     "technique": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access",
     "tables": ["last"], "platform": "all"},
    # ── Credential Access ──────────────────────────────────────────────────────
    {"key": "mimikatz_execution", "title": "Mimikatz / LSASS credential dumping",
     "sql": ("SELECT pid, name, path, cmdline, parent FROM processes "
             "WHERE name IN ('mimikatz.exe','mimikatz','procdump.exe','procdump64.exe','pwdump.exe','gsecdump.exe') "
             "OR cmdline LIKE '%sekurlsa%' OR cmdline LIKE '%lsadump%' OR cmdline LIKE '%comsvcs.dll%MiniDump%';"),
     "technique": "T1003", "technique_name": "OS Credential Dumping", "tactic": "Credential Access",
     "tables": ["processes"], "platform": "windows"},
    {"key": "cred_file_access", "title": "Access to credential storage files (shadow / SAM)",
     "sql": (r"SELECT p.name, p.cmdline, pm.path FROM processes p JOIN process_memory_map pm ON p.pid = pm.pid "
             r"WHERE pm.path IN ('/etc/shadow','/etc/passwd','C:\Windows\System32\config\SAM','C:\Windows\System32\config\SECURITY') "
             r"AND p.name NOT IN ('sshd','login','su','sudo','lsass.exe');"),
     "technique": "T1003", "technique_name": "OS Credential Dumping", "tactic": "Credential Access",
     "tables": ["processes", "process_memory_map"], "platform": "all"},
    {"key": "browser_cred_theft", "title": "Browser credential-store access",
     "sql": ("SELECT pid, name, cmdline FROM processes WHERE cmdline LIKE '%Login Data%' OR cmdline LIKE '%logins.json%' "
             "OR cmdline LIKE '%key4.db%' OR cmdline LIKE '%Cookies%';"),
     "technique": "T1555", "technique_name": "Credentials from Password Stores", "tactic": "Credential Access",
     "tables": ["processes"], "platform": "all"},
    # ── Persistence ────────────────────────────────────────────────────────────
    {"key": "registry_run_keys", "title": "Windows registry Run keys (autostart persistence)",
     "sql": (r"SELECT key, name, path, data, mtime FROM registry "
             r"WHERE (key LIKE '%\Run' OR key LIKE '%\RunOnce') AND key NOT LIKE '%\RunOnceEx';"),
     "technique": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactic": "Persistence",
     "tables": ["registry"], "platform": "windows"},
    {"key": "scheduled_tasks", "title": "Windows scheduled tasks",
     "sql": "SELECT name, action, path, enabled, state, hidden FROM scheduled_tasks WHERE enabled = 1;",
     "technique": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence",
     "tables": ["scheduled_tasks"], "platform": "windows"},
    {"key": "suspicious_cron", "title": "Suspicious cron jobs",
     "sql": ("SELECT command, path FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%' "
             "OR command LIKE '%/tmp/%' OR command LIKE '%bash -i%' OR command LIKE '%nc %';"),
     "technique": "T1053.003", "technique_name": "Cron", "tactic": "Persistence",
     "tables": ["crontab"], "platform": "posix"},
    {"key": "non_standard_systemd", "title": "Non-standard active systemd units",
     "sql": ("SELECT name, fragment_path, active_state FROM systemd_units WHERE active_state = 'active' "
             "AND fragment_path NOT LIKE '/usr/lib/systemd/system/%' AND fragment_path NOT LIKE '/lib/systemd/system/%';"),
     "technique": "T1543.002", "technique_name": "Systemd Service", "tactic": "Persistence",
     "tables": ["systemd_units"], "platform": "linux"},
    {"key": "suspicious_launchd", "title": "Suspicious macOS launch agents",
     "sql": ("SELECT name, label, path, program FROM launchd WHERE run_at_load = 1 "
             "AND (path LIKE '%/tmp/%' OR program LIKE '%curl%' OR program LIKE '%bash%');"),
     "technique": "T1543.001", "technique_name": "Launch Agent", "tactic": "Persistence",
     "tables": ["launchd"], "platform": "darwin"},
    # ── Privilege Escalation / Defense Evasion ────────────────────────────────
    {"key": "suid_binaries", "title": "SUID/SGID binaries (privilege-escalation surface)",
     "sql": ("SELECT path, permissions, uid, gid FROM suid_bin WHERE path NOT LIKE '/usr/bin/%' "
             "AND path NOT LIKE '/bin/%';"),
     "technique": "T1548", "technique_name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
     "tables": ["suid_bin"], "platform": "posix"},
    {"key": "unsigned_temp_binaries", "title": "Processes running from temp/download paths",
     "sql": ("SELECT pid, name, path, cmdline, parent FROM processes "
             "WHERE path LIKE '%\\Temp\\%' OR path LIKE '%\\AppData\\%' OR path LIKE '/tmp/%' "
             "OR path LIKE '/var/tmp/%' OR path LIKE '/dev/shm/%';"),
     "technique": "T1036", "technique_name": "Masquerading", "tactic": "Defense Evasion",
     "tables": ["processes"], "platform": "all"},
    # ── Lateral Movement ───────────────────────────────────────────────────────
    {"key": "rdp_connections", "title": "RDP connections (inbound/outbound 3389)",
     "sql": ("SELECT p.pid, p.name, p.path, ps.remote_address, ps.remote_port, ps.state "
             "FROM processes p JOIN process_open_sockets ps ON p.pid = ps.pid "
             "WHERE ps.remote_port = 3389 OR ps.local_port = 3389 OR p.name LIKE '%mstsc%';"),
     "technique": "T1021.001", "technique_name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
     "tables": ["processes", "process_open_sockets"], "platform": "windows"},
    {"key": "psexec_wmi", "title": "PsExec / remote WMI / admin-share execution",
     "sql": ("SELECT pid, name, path, cmdline, parent FROM processes "
             "WHERE name LIKE '%psexec%' OR cmdline LIKE '%psexec%' OR (cmdline LIKE '%wmic%' AND cmdline LIKE '%/node:%') "
             "OR cmdline LIKE '%net use%' OR cmdline LIKE '%admin$%';"),
     "technique": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
     "tables": ["processes"], "platform": "windows"},
    {"key": "ssh_outbound", "title": "Outbound SSH connections",
     "sql": ("SELECT p.pid, p.name, p.cmdline, ps.remote_address, ps.remote_port, ps.state "
             "FROM processes p JOIN process_open_sockets ps ON p.pid = ps.pid WHERE ps.remote_port = 22 AND p.name = 'ssh';"),
     "technique": "T1021.004", "technique_name": "SSH", "tactic": "Lateral Movement",
     "tables": ["processes", "process_open_sockets"], "platform": "posix"},
    # ── Command and Control ────────────────────────────────────────────────────
    {"key": "c2_beacon_ports", "title": "Connections on common C2 ports",
     "sql": ("SELECT p.pid, p.name, p.path, ps.remote_address, ps.remote_port, ps.state "
             "FROM processes p JOIN process_open_sockets ps ON p.pid = ps.pid "
             "WHERE ps.remote_port IN (4444, 5555, 6666, 8080, 8443, 1337, 9001) "
             "AND ps.remote_address NOT IN ('127.0.0.1','::1');"),
     "technique": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control",
     "tables": ["processes", "process_open_sockets"], "platform": "all"},
    {"key": "ingress_tool_transfer", "title": "Ingress tool transfer (curl/wget/certutil download)",
     "sql": ("SELECT pid, name, cmdline FROM processes WHERE cmdline LIKE '%certutil%urlcache%' "
             "OR cmdline LIKE '%curl %http%' OR cmdline LIKE '%wget %http%' OR cmdline LIKE '%bitsadmin%/transfer%';"),
     "technique": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control",
     "tables": ["processes"], "platform": "all"},
    # ── Discovery ──────────────────────────────────────────────────────────────
    {"key": "discovery_recon", "title": "Host / network discovery commands",
     "sql": ("SELECT pid, name, cmdline, parent FROM processes "
             "WHERE name IN ('whoami','net.exe','net1.exe','ipconfig.exe','systeminfo.exe','nltest.exe','arp.exe') "
             "OR cmdline LIKE '%net group%' OR cmdline LIKE '%net user%' OR cmdline LIKE '%nltest%';"),
     "technique": "T1087", "technique_name": "Account Discovery", "tactic": "Discovery",
     "tables": ["processes"], "platform": "windows"},
]


def _is_public_ip(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def _focus(incident: dict, triage_result: dict | None) -> dict:
    """Best-effort focus of the investigation: the host if we can name one, plus
    the raw title entity. Mirrors incident_map's title-entity heuristic."""
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


def _infer_platform(host: str | None, incident: dict, override: str | None) -> tuple[str, str]:
    """Return (platform, note). platform ∈ {windows, posix, unknown}."""
    if override:
        return override, f"platform forced to '{override}'"
    sources = " ".join(str(s) for s in (incident.get("sources") or [])).lower()
    if host and _WINDOWS_HOST_RE.search(host):
        return "windows", f"inferred Windows from host name '{host}'"
    if "endpoint" in sources:
        return "windows", "inferred Windows from NetWitness Endpoint source"
    if host and re.match(r"^[A-Z0-9][A-Z0-9\-]{2,}$", host) and "." not in host:
        # bare uppercase NetBIOS-style name → Windows endpoint (corpus convention)
        return "windows", f"inferred Windows from endpoint host name '{host}'"
    return "unknown", ("platform unknown — no host name resolved; assuming a Windows "
                       "endpoint (corpus convention) but cross-platform queries included")


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
                # dotted FQDN under a domain/fqdn/host key = a C2 domain worth a
                # cmdline/etc_hosts pivot; the dot rule excludes bare NetBIOS names.
                domains.append(v)

    def dedup(seq):
        return list(dict.fromkeys(seq))

    return {"ips": dedup(ips), "hashes": dedup(hashes), "domains": dedup(domains)}


def _mitre(incident: dict, triage_result: dict | None) -> dict:
    mk = (triage_result or {}).get("metakeys_payload") or {}
    tech = str(mk.get("mitre_technique") or "").strip()
    tactic = str(mk.get("mitre_tactic") or "").strip()
    # NetWitness incident fields (usually empty on stored incidents, honest fallback)
    if not tech:
        techs = incident.get("techniques") or []
        if techs:
            tech = str(techs[0].get("id") if isinstance(techs[0], dict) else techs[0]).strip()
    if not tactic:
        tacs = incident.get("tactics") or []
        if tacs:
            tactic = str(tacs[0].get("name") if isinstance(tacs[0], dict) else tacs[0]).strip()
    return {"technique": tech, "tactic": tactic}


def _platform_ok(q_platform: str, inferred: str) -> bool:
    if q_platform == "all":
        return True
    if inferred == "unknown":
        # keep everything but Windows-forward; still surface posix so an analyst
        # who knows the host is Linux isn't blind.
        return True
    if inferred == "windows":
        return q_platform == "windows"
    # posix
    return q_platform in ("posix", "linux", "darwin")


def _ioc_pivot_queries(iocs: dict) -> list[dict]:
    """Queries parameterized with THIS incident's actual IOCs."""
    out: list[dict] = []
    if iocs["ips"]:
        in_list = ", ".join(f"'{ip}'" for ip in iocs["ips"][:12])
        out.append({
            "key": "ioc_ip_sockets", "title": f"Processes talking to incident IP(s) ({len(iocs['ips'])})",
            "sql": ("SELECT p.pid, p.name, p.path, p.cmdline, ps.remote_address, ps.remote_port, ps.state "
                    "FROM processes p JOIN process_open_sockets ps ON p.pid = ps.pid "
                    f"WHERE ps.remote_address IN ({in_list});"),
            "technique": "T1071", "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control", "tables": ["processes", "process_open_sockets"],
            "platform": "all", "ioc_pivot": True})
    if iocs["hashes"]:
        in_list = ", ".join(f"'{h}'" for h in iocs["hashes"][:12])
        out.append({
            "key": "ioc_hash_processes", "title": f"Running binaries matching incident hash(es) ({len(iocs['hashes'])})",
            "sql": ("SELECT p.pid, p.name, p.path, h.sha256 FROM processes p JOIN hash h ON p.path = h.path "
                    f"WHERE h.sha256 IN ({in_list});"),
            "technique": "T1204", "technique_name": "User Execution", "tactic": "Execution",
            "tables": ["processes", "hash"], "platform": "all", "ioc_pivot": True})
    for dom in iocs["domains"][:6]:
        out.append({
            "key": f"ioc_domain_{dom}", "title": f"Processes / hosts file referencing domain {dom}",
            "sql": (f"SELECT pid, name, cmdline FROM processes WHERE cmdline LIKE '%{dom}%' "
                    f"UNION SELECT NULL, address, hostnames FROM etc_hosts WHERE hostnames LIKE '%{dom}%';"),
            "technique": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control",
            "tables": ["processes", "etc_hosts"], "platform": "all", "ioc_pivot": True})
    return out


def _select_hunt(mitre: dict, inferred: str, budget: int) -> tuple[list[dict], str]:
    """Pick technique-matched queries first (exact id, then base id), then fill
    from the same tactic, respecting the platform + budget."""
    tech = mitre["technique"]
    tactic = mitre["tactic"]
    base = tech.split(".")[0] if tech else ""
    chosen: list[dict] = []
    seen: set[str] = set()

    def _take(pred):
        for q in _HUNT_QUERIES:
            if len(chosen) >= budget:
                break
            if q["key"] in seen or not _platform_ok(q["platform"], inferred):
                continue
            if pred(q):
                chosen.append(q)
                seen.add(q["key"])

    basis_parts = []
    if tech:
        _take(lambda q: q.get("technique") == tech)
        _take(lambda q: q.get("technique", "").split(".")[0] == base)
        basis_parts.append(f"technique {tech}")
    if tactic:
        _take(lambda q: q.get("tactic", "").lower() == tactic.lower())
        basis_parts.append(f"tactic {tactic}")
    if not chosen:
        # no MITRE context — give a broad, high-value default sweep
        _take(lambda q: q["key"] in (
            "powershell_suspicious", "mimikatz_execution", "unsigned_temp_binaries",
            "psexec_wmi", "c2_beacon_ports", "registry_run_keys", "ingress_tool_transfer"))
        basis_parts.append("no MITRE context — broad default sweep")
    return chosen, "; ".join(basis_parts)


def build_investigation_pack(incident: dict, triage_result: dict | None = None,
                             platform: str | None = None,
                             max_hunt_queries: int = 10) -> dict:
    """Assemble a per-incident osquery investigation pack. Deterministic,
    read-only, never raises. Returns {"available": bool, ...}."""
    if os.environ.get("NW_DISABLE_OSQUERY_PACK"):
        return {"available": False, "reason": "disabled via NW_DISABLE_OSQUERY_PACK"}

    focus = _focus(incident, triage_result)
    inferred, platform_note = _infer_platform(focus["host"], incident, platform)
    iocs = _extract_iocs(incident, triage_result)
    mitre = _mitre(incident, triage_result)

    triage = [q for q in _TRIAGE_QUERIES if _platform_ok(q["platform"], inferred)]
    hunt, hunt_basis = _select_hunt(mitre, inferred, max_hunt_queries)
    ioc_pivot = _ioc_pivot_queries(iocs)

    def _shape(q: dict) -> dict:
        return {
            "key": q["key"], "title": q["title"], "sql": q["sql"],
            "oneliner": 'osqueryi --json "' + q["sql"].replace('"', '\\"') + '"',
            "technique": q.get("technique"), "technique_name": q.get("technique_name"),
            "tactic": q.get("tactic"), "tables": q.get("tables", []),
            "platform": q["platform"], "ioc_pivot": q.get("ioc_pivot", False),
        }

    return {
        "available": True,
        "host": focus["host"], "title_entity": focus["title_entity"],
        "platform": inferred, "platform_note": platform_note,
        "mitre": mitre, "hunt_basis": hunt_basis,
        "iocs": iocs,
        "triage": [_shape(q) for q in triage],
        "hunt": [_shape(q) for q in hunt],
        "ioc_pivot": [_shape(q) for q in ioc_pivot],
        "stats": {
            "triage_queries": len(triage),
            "hunt_queries": len(hunt),
            "ioc_pivot_queries": len(ioc_pivot),
            "total_queries": len(triage) + len(hunt) + len(ioc_pivot),
        },
    }


def format_pack(pack: dict) -> str:
    """Plain-text block for the Map panel."""
    if not pack.get("available"):
        return "OSQUERY INVESTIGATION PACK unavailable: " + pack.get("reason", "unknown")

    host = pack["host"] or pack["title_entity"] or "unresolved host"
    m = pack["mitre"]
    mitre_line = (f"{m['technique'] or '—'} / {m['tactic'] or '—'}"
                  if (m["technique"] or m["tactic"]) else "no MITRE context on incident")
    lines = [
        "OSQUERY INVESTIGATION PACK (generated queries to RUN on the endpoint — "
        "not executed here; adapted from SecOpsAgentKit forensics-osquery)",
        f"  target host: {host}   ·   platform: {pack['platform']} ({pack['platform_note']})",
        f"  MITRE focus: {mitre_line}   ·   selection: {pack['hunt_basis']}",
    ]
    ic = pack["iocs"]
    if ic["ips"] or ic["hashes"] or ic["domains"]:
        lines.append(f"  IOCs pivoted: {len(ic['ips'])} IP(s), "
                     f"{len(ic['hashes'])} hash(es), {len(ic['domains'])} domain(s)")

    def _emit(header: str, queries: list[dict]) -> None:
        if not queries:
            return
        lines.append("")
        lines.append(header)
        for q in queries:
            tag = ""
            if q.get("technique"):
                tag = f"  [{q['technique']} {q.get('technique_name') or ''}]".rstrip()
            plat = "" if q["platform"] == "all" else f" ({q['platform']})"
            lines.append(f"  • {q['title']}{plat}{tag}")
            lines.append(f"      {q['sql']}")

    _emit("── IR triage baseline (always collect) ──", pack["triage"])
    _emit(f"── Technique-focused hunt ({pack['stats']['hunt_queries']}) ──", pack["hunt"])
    _emit(f"── IOC pivots ({pack['stats']['ioc_pivot_queries']}) ──", pack["ioc_pivot"])
    lines.append("")
    lines.append(f"  {pack['stats']['total_queries']} queries total — run with osqueryi "
                 "(interactive) or osqueryd (scheduled) on the affected host.")
    return "\n".join(lines)
