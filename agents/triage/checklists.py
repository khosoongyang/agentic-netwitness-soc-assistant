"""agents/triage/checklists.py -- IOC checklists (Availability / Confidentiality / Integrity), the risk-rating
guidance, the SOC classification table and MITRE tactic/technique normalisation.

[AUDIT T-22] Moved verbatim out of soc_triage_agent.py (2,500+ lines) to
split it by responsibility. soc_triage_agent re-exports every name
defined here, so existing imports and behaviour are unchanged.
"""
from __future__ import annotations

from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# 2.  IOC CHECKLISTS
# ══════════════════════════════════════════════════════════════════════════════

IOC_AVAILABILITY = [
    {"ioc": "Frequent core dump and/or traceback generation",
     "desc": "Frequent software crashes during normal device operation",
     "metakeys": ["event.type", "device.type", "host.name"]},
    {"ioc": "High CPU usage",
     "desc": "Abnormally high CPU usage caused by a malicious actor",
     "metakeys": ["cpu.usage", "process.name", "host.name"]},
    {"ioc": "Frequent rebooting",
     "desc": "Altered device software causing frequent reload",
     "metakeys": ["event.type", "device.type", "host.name"]},
    {"ioc": "Saturated interface input/output buffers",
     "desc": "High traffic volumes initiated by a malicious actor",
     "metakeys": ["network.interface", "bytes.in", "bytes.out", "packets.in", "packets.out"]},
    {"ioc": "Abnormally high malformed packet counts",
     "desc": "High numbers of malformed packets destined to a device",
     "metakeys": ["packets.malformed", "ip.dst", "ip.src"]},
    {"ioc": "Configuration changes",
     "desc": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, syslog, VPNs",
     "metakeys": ["change.type", "config.change", "user.name", "host.name"]},
    {"ioc": "Unexplained changes from privileged accounts",
     "desc": "Unusual activity from privileged accounts",
     "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"]},
]

IOC_CONFIDENTIALITY = [
    {"ioc": "Changes in network traffic telemetry (known bad IPs/domains)",
     "desc": "Traffic to/from known malicious IPs or domains; data exfiltration",
     "metakeys": ["ip.dst", "ip.src", "domain", "bytes.out", "alert.type"]},
    {"ioc": "Unknown traffic originating from/terminating on the device",
     "desc": "Unusual traffic e.g. Telnet, SSH, HTTP/HTTPS, RDP",
     "metakeys": ["ip.src", "ip.dst", "network.service", "port.dst", "protocol"]},
    {"ioc": "Anomalous file transfers",
     "desc": "Unusual file transfers via FTP/TFTP/SNMP to unexpected hosts",
     "metakeys": ["file.name", "file.size", "ip.dst", "ip.src", "protocol", "bytes.out"]},
    {"ioc": "Geographic-based anomalies",
     "desc": "Traffic to/from countries the organisation does not normally engage",
     "metakeys": ["geo.country", "ip.src", "ip.dst", "user.name", "event.type"]},
    {"ioc": "File system permissions changed",
     "desc": "Changes in file system authorisations",
     "metakeys": ["file.path", "permission.change", "user.name", "host.name"]},
    {"ioc": "Configuration changes",
     "desc": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, VPNs",
     "metakeys": ["change.type", "config.change", "user.name", "host.name"]},
    {"ioc": "Device account/password additions/deletions/changes",
     "desc": "Changes to device account or credential information",
     "metakeys": ["user.name", "event.type", "account.action", "host.name"]},
    {"ioc": "Unexplained changes from privileged accounts",
     "desc": "Unusual activity from privileged accounts",
     "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"]},
]

IOC_INTEGRITY = [
    {"ioc": "Generation of core dumps and/or tracebacks",
     "desc": "Frequent software crashes during normal device operation",
     "metakeys": ["event.type", "device.type", "host.name"]},
    {"ioc": "Odd device/platform behaviour",
     "desc": "Behaviour deviating from expected normal operation",
     "metakeys": ["event.type", "host.name", "device.type"]},
    {"ioc": "Anomalies in OS/package hash values",
     "desc": "Inconsistent hash values that deviate from expected",
     "metakeys": ["file.hash", "file.name", "host.name", "os.version"]},
    {"ioc": "Anomalies in OS/package certificate signing",
     "desc": "Bypassing code signing checks; unknown CA certificates",
     "metakeys": ["cert.issuer", "cert.hash", "file.name", "host.name"]},
    {"ioc": "Unknown binaries installed",
     "desc": "Binary files and configs not part of the OS",
     "metakeys": ["file.name", "file.path", "file.hash", "host.name", "process.name"]},
    {"ioc": "Unknown process running",
     "desc": "Processes in memory with unusual attributes or arbitrary names",
     "metakeys": ["process.name", "process.pid", "process.path", "host.name"]},
    {"ioc": "Unexpected OS/ROMMON release versions installed",
     "desc": "Presence of unexpected system software or bootstrap versions",
     "metakeys": ["os.version", "firmware.version", "host.name"]},
    {"ioc": "File system permissions changed",
     "desc": "Changes in file system authorisations",
     "metakeys": ["file.path", "permission.change", "user.name", "host.name"]},
    {"ioc": "Unexpected changes in boot sequence or boot variables",
     "desc": "Alteration of system startup files",
     "metakeys": ["boot.config", "file.path", "host.name"]},
    {"ioc": "Configuration changes",
     "desc": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, VPNs",
     "metakeys": ["change.type", "config.change", "user.name", "host.name"]},
    {"ioc": "Device account/password additions/deletions/changes",
     "desc": "Changes to device account or credential information",
     "metakeys": ["user.name", "event.type", "account.action", "host.name"]},
    {"ioc": "Unexplained changes from privileged accounts",
     "desc": "Unusual activity from privileged accounts",
     "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"]},
]

ALL_IOCS = {
    "availability":    IOC_AVAILABILITY,
    "confidentiality": IOC_CONFIDENTIALITY,
    "integrity":       IOC_INTEGRITY,
}


# ══════════════════════════════════════════════════════════════════════════════
# 3.  RISK RATING & CLASSIFICATION DATA
# ══════════════════════════════════════════════════════════════════════════════

RISK_RATING_GUIDANCE = """
LIKELIHOOD OF THREAT EVENT INITIATION:
  Critical — Adversary is almost certain to initiate the threat event
  High     — Adversary is highly likely to initiate the threat event
  Medium   — Adversary is somewhat likely to initiate the threat event
  Low      — Adversary is unlikely to initiate the threat event

LIKELIHOOD OF THREAT EVENT OCCURRENCE:
  Critical — Almost certain to occur, or occurs more than 100 times a year
  High     — Highly likely to occur, or occurs 10–100 times a year
  Medium   — Somewhat likely to occur, or occurs 1–10 times a year
  Low      — Unlikely to occur, or occurs less than once a year

LIKELIHOOD OF ADVERSE IMPACT:
  Critical — Almost certain to have adverse impacts
  High     — Highly likely to have adverse impacts
  Medium   — Somewhat likely to have adverse impacts
  Low      — Unlikely to have adverse impacts
"""

SOC_CLASSIFICATION_TABLE = {
    "critical": {
        "definition": "Urgent & high-risk security issue requiring immediate action",
        "categories": ["Internal Hacking (active)", "External Hacking (active)",
                       "Virus/Worm (outbreak)", "Destruction of property (critical)"],
        "initial_response_time": "<= 15 minutes",
    },
    "high": {
        "definition": "Significant security threats requiring investigation",
        "categories": ["Internal Hacking (inactive)", "External Hacking (inactive)",
                       "Unauthorized access", "Policy violations", "Unlawful activity",
                       "Compromised information", "Compromised asset (non-critical)"],
        "initial_response_time": "30 to 60 minutes",
    },
    "medium": {
        "definition": "Suspicious activity warranting investigation",
        "categories": ["Email Forensics Request", "Inappropriate use of property",
                       "Policy violations"],
        "initial_response_time": "~4 hours",
    },
    "low": {
        "definition": "Events with minimal immediate risk",
        "categories": ["Email", "Unknown websites", "Unknown Source IP",
                       "AV Alert with minimal consequences"],
        "initial_response_time": ">= 24 hours",
    },
}

# Canonical MITRE ATT&CK tactics (mirrors config.yaml's triage.mitre_tactics).
# The classification phase maps each incident onto one of these; downstream
# the investigation agent uses the tactic for playbook auto-selection.
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact",
]


# [FYP-FUNCTION] `_normalize_mitre_tactic` — transforms normalize mitre tactic input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:triage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `lower`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalize_mitre_tactic(value) -> str:
    """Snap free-form LLM output onto a canonical tactic, else 'Unknown'."""
    if not isinstance(value, str) or not value.strip():
        return "Unknown"
    v = value.strip().lower()
    for tactic in MITRE_TACTICS:
        if tactic.lower() == v or tactic.lower() in v or v in tactic.lower():
            return tactic
    return "Unknown"


# [FYP-FUNCTION] `_normalize_mitre_technique` — transforms normalize mitre technique input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:triage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `join`, `lower`, `split`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalize_mitre_technique(value) -> str:
    if not isinstance(value, str) or not value.strip():
        return "Unknown"
    v = " ".join(value.split())[:80]
    return v if v.lower() not in ("unknown", "none", "n/a", "-") else "Unknown"


