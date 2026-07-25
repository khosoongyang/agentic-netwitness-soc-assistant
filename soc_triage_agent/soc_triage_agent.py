"""
SOC Triage Agent  —  soc_triage_agent.py
=========================================
Architecture: 3 direct LLM calls (no LCEL pipeline, no tool wrappers).

  Call 1 — IOC Checklists   (all 27 IOCs across 3 categories in one call)
  Call 2 — Risk Rating
  Call 3 — SOC Classification

Each call: ChatPromptTemplate → ChatOpenAI → StrOutputParser → _extract_json
Repair call fires if required keys are missing from the JSON.

Public API (app.py imports):
  CiscoLLMConfig, build_llm, TriageAgent,
  soc_triage_chat_respond, _TRIAGE_TRIGGER,
  render_triage_trace, format_ticket_display
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ── LangChain imports (minimal) ───────────────────────────────────────────────
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


# ══════════════════════════════════════════════════════════════════════════════
# 1.  LLM CONFIG & BUILDER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CiscoLLMConfig:
    """LLM connection config for the triage agent.

    OPENAI_* env vars are the primary source; CISCO_LLM_* remain as an
    optional override for pointing the agent at a different OpenAI-compatible
    endpoint without touching OPENAI_API_KEY (used elsewhere by the reporting
    agent).
    """
    base_url: str = field(
        default_factory=lambda: os.environ.get("CISCO_LLM_URL", "").strip()
        or os.environ.get("OPENAI_BASE_URL", "").strip()
        or "https://api.openai.com/v1"
    )
    api_key: str = field(
        default_factory=lambda: os.environ.get("CISCO_LLM_KEY", "").strip()
        or os.environ.get("OPENAI_API_KEY", "").strip()
        or "changeme"
    )
    model: str = field(
        default_factory=lambda: os.environ.get("CISCO_LLM_MODEL", "").strip()
        or os.environ.get("OPENAI_MODEL", "").strip()
        or "gpt-4o-mini"
    )
    # temperature=0 -> greedy decoding, so the same incident produces the same
    # triage output instead of drifting between runs/users. A fixed seed is
    # sent too, since OpenAI's chat-completions API takes it for
    # reproducibility.
    temperature: float = 0.0
    seed:        int | None = field(
        default_factory=lambda: int(os.environ["CISCO_LLM_SEED"])
        if os.environ.get("CISCO_LLM_SEED") else 42
    )
    # Reasoning models spend most of their budget on chain-of-thought BEFORE
    # the final JSON. If max_tokens is too small the response is cut off
    # mid-reasoning, no JSON is ever emitted, and the IOC phase parses as
    # empty — which presents as "0 IOCs matched" on every run.
    max_tokens:  int   = 3072
    timeout:     int   = 300


def _provider_supports_json_mode(base_url: str) -> bool:
    """Providers whose chat API honours response_format json_object.
    Override with TRIAGE_JSON_MODE=always|never."""
    forced = os.environ.get("TRIAGE_JSON_MODE", "").strip().lower()
    if forced == "always":
        return True
    if forced == "never":
        return False
    url = (base_url or "").lower()
    return "openai.com" in url or "deepseek" in url


def build_llm(cfg: CiscoLLMConfig, json_mode: bool = False) -> ChatOpenAI:
    extra: dict = {}
    if cfg.seed is not None:
        # seed is a first-class ChatOpenAI param in current langchain-openai;
        # passing it via model_kwargs triggered a relocation warning.
        extra["seed"] = cfg.seed
    if json_mode:
        # Forced-JSON decoding: the provider guarantees a parseable JSON
        # object, eliminating fence/prose drift and the repair-call path.
        # Only for the triage phases — the plain Q&A chain must stay prose.
        extra["model_kwargs"] = {"response_format": {"type": "json_object"}}
    return ChatOpenAI(
        base_url     = cfg.base_url,
        api_key      = cfg.api_key,
        model        = cfg.model,
        temperature  = cfg.temperature,
        max_tokens   = cfg.max_tokens,
        timeout      = cfg.timeout,
        max_retries  = 2,
        **extra,
    )


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


def _normalize_mitre_tactic(value) -> str:
    """Snap free-form LLM output onto a canonical tactic, else 'Unknown'."""
    if not isinstance(value, str) or not value.strip():
        return "Unknown"
    v = value.strip().lower()
    for tactic in MITRE_TACTICS:
        if tactic.lower() == v or tactic.lower() in v or v in tactic.lower():
            return tactic
    return "Unknown"


def _normalize_mitre_technique(value) -> str:
    if not isinstance(value, str) or not value.strip():
        return "Unknown"
    v = " ".join(value.split())[:80]
    return v if v.lower() not in ("unknown", "none", "n/a", "-") else "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# 4.  TICKET UNC COUNTER
# ══════════════════════════════════════════════════════════════════════════════

# This module now lives in the soc_triage_agent/ subfolder, and all SQLite
# databases were consolidated into <project root>/soc_db/ — hence parent.parent.
_SOC_DB_DIR = Path(__file__).resolve().parent.parent / "soc_db"
_SOC_DB_DIR.mkdir(parents=True, exist_ok=True)
_TICKET_DB   = _SOC_DB_DIR / "soc_tickets.db"
_TICKET_LOCK = threading.Lock()


def _ticket_db_init() -> None:
    with sqlite3.connect(str(_TICKET_DB), timeout=30) as con:
        # WAL + busy-tolerance: the app UI, workflow worker and feedback
        # deep-dive all touch this DB concurrently now.
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        con.execute("""
            CREATE TABLE IF NOT EXISTS ticket_counter (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                number  INTEGER NOT NULL DEFAULT 0,
                letter  TEXT    NOT NULL DEFAULT 'A'
            )""")
        con.execute(
            "INSERT OR IGNORE INTO ticket_counter (id, number, letter) VALUES (1, 0, 'A')")
        con.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                unc TEXT PRIMARY KEY, incident_id TEXT,
                severity TEXT, created_at TEXT, payload TEXT
            )""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS triage_cache (
                fingerprint TEXT PRIMARY KEY,
                incident_id TEXT,
                created_at  TEXT,
                result_json TEXT
            )""")
        con.commit()


def _increment_suffix(s: str) -> str:
    chars = list(s)
    i = len(chars) - 1
    while i >= 0:
        if chars[i] < "Z":
            chars[i] = chr(ord(chars[i]) + 1)
            return "".join(chars)
        chars[i] = "A"
        i -= 1
    return "A" + "".join(chars)


def _next_unc() -> str:
    with _TICKET_LOCK:
        with sqlite3.connect(str(_TICKET_DB), timeout=30) as con:
            row = con.execute(
                "SELECT number, letter FROM ticket_counter WHERE id=1").fetchone()
            number, letter = row[0], row[1]
            unc = f"#{number:05d}{letter}"
            next_n = number + 1
            next_l = letter
            if next_n > 99999:
                next_n = 0
                next_l = _increment_suffix(letter)
            con.execute("UPDATE ticket_counter SET number=?,letter=? WHERE id=1",
                        (next_n, next_l))
            con.commit()
    return unc


def _store_ticket(unc: str, incident_id: str, severity: str, payload: dict) -> None:
    with sqlite3.connect(str(_TICKET_DB), timeout=30) as con:
        con.execute("INSERT OR REPLACE INTO tickets VALUES (?,?,?,?,?)",
                    (unc, incident_id, severity,
                     datetime.utcnow().isoformat(), json.dumps(payload)))
        con.commit()


def _incident_fingerprint(incident: dict) -> str:
    """
    Stable content hash of an incident, used as the triage-cache key.

    Deliberately hashes only fields that describe WHAT happened — not
    volatile bookkeeping like lastUpdated (which the 30s auto-refresh bumps
    constantly) — so re-triaging the same unchanged incident is a cache hit,
    while any real change (new alerts, changed risk score) is a miss.
    """
    alerts = incident.get("alerts") or []
    stable = {
        "id":         str(incident.get("id") or incident.get("incidentId") or ""),
        "title":      incident.get("title") or incident.get("name") or "",
        "created":    str(incident.get("created") or incident.get("createdDate") or ""),
        "risk_score": str(incident.get("riskScore") or incident.get("risk_score") or ""),
        "priority":   str(incident.get("priority") or incident.get("severity") or ""),
        "alert_n":    incident.get("alertCount") or len(alerts),
        "alert_ids":  sorted(
            str(a.get("id") or "") for a in alerts[:100] if isinstance(a, dict)
        ),
    }
    blob = json.dumps(stable, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def _cache_get(fingerprint: str) -> dict | None:
    try:
        with sqlite3.connect(str(_TICKET_DB), timeout=30) as con:
            row = con.execute(
                "SELECT result_json FROM triage_cache WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
        return json.loads(row[0]) if row else None
    except Exception:
        return None


def _cache_put(fingerprint: str, incident_id: str, result: dict) -> None:
    try:
        with sqlite3.connect(str(_TICKET_DB), timeout=30) as con:
            con.execute(
                "INSERT OR REPLACE INTO triage_cache VALUES (?,?,?,?)",
                (fingerprint, incident_id,
                 datetime.utcnow().isoformat(), json.dumps(result, default=str)),
            )
            con.commit()
    except Exception:
        pass   # cache is an optimisation — never let it break a triage


_ticket_db_init()


# ══════════════════════════════════════════════════════════════════════════════
# 5.  JSON EXTRACTION & REPAIR
# ══════════════════════════════════════════════════════════════════════════════

def _coerce_dict(parsed: Any) -> dict:
    """
    The model doesn't always emit a JSON object — sometimes it's an array
    (e.g. [{...}]) or a bare scalar. Every caller of _extract_json does
    data.get(...), so anything non-dict must be coerced here or it crashes
    with "'list' object has no attribute 'get'".
    """
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        merged: dict = {}
        for item in parsed:
            if isinstance(item, dict):
                merged.update(item)
        return merged
    return {}


def _extract_json(text: str) -> dict:
    """Extract a JSON object from raw model output (handles reasoning prose)."""
    if not text:
        return {}
    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    try:
        data = _coerce_dict(json.loads(cleaned))
        if data:
            return data
    except json.JSONDecodeError:
        pass
    last_close = cleaned.rfind("}")
    if last_close == -1:
        return {}
    depth = 0
    for i in range(last_close, -1, -1):
        if cleaned[i] == "}":
            depth += 1
        elif cleaned[i] == "{":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(cleaned[i: last_close + 1])
                except json.JSONDecodeError:
                    break
    for m in reversed(list(re.finditer(r"\{[^{}]+\}", cleaned, re.DOTALL))):
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            continue
    return {}


_VALID_LEVELS = ("critical", "high", "medium", "low")
_SEV_ORDER    = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _normalize_level(value: str | None, default: str) -> str:
    """
    Map the model's free-text level to one of the canonical SOC levels.
    Without this, phrasing drift (case, whitespace, "informational", a
    trailing period) silently falls through to the "medium" dict-lookup
    default in SOC_CLASSIFICATION_TABLE, which looks like inconsistent
    output but is really just an un-normalized string miss.
    """
    if not value:
        return default
    v = re.sub(r"[^a-z]", "", value.strip().lower())
    if v in _VALID_LEVELS:
        return v
    if v.startswith("info"):
        return "low"
    for level in _VALID_LEVELS:
        if level in v:
            return level
    return default


def _repair_json(raw_text: str, required_keys: list[str], llm: ChatOpenAI) -> dict:
    """Focused repair call when _extract_json misses required keys."""
    keys_str = ", ".join(f'"{k}"' for k in required_keys)
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are a JSON formatter. Extract or reconstruct a JSON object from "
            "the text. Return ONLY valid JSON — no prose, no markdown, no fences. "
            f"Required keys: {keys_str}"
        )),
        HumanMessage(content=f"TEXT:\n{raw_text[-2000:]}\n\nReturn ONLY JSON:"),
    ])
    try:
        chain = prompt | llm | StrOutputParser()
        raw   = chain.invoke({})
        data  = _extract_json(raw)
        if data:
            return data
    except Exception:
        pass
    return {}


# ══════════════════════════════════════════════════════════════════════════════
# 6.  STREAMING HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _stream_or_invoke(text_chain, thinking_container=None) -> str:
    """Stream tokens into a Streamlit container, or plain invoke if not provided."""
    if thinking_container is None:
        return text_chain.invoke({})

    full_text = ""
    _STYLE = (
        "background:#02040A;border-left:3px solid #1A3550;"
        "padding:8px 14px;font-family:monospace;font-size:0.62rem;"
        "color:#5A7A99;border-radius:0 4px 4px 0;margin:3px 0;"
        "word-break:break-word;line-height:1.7;white-space:pre-wrap"
    )
    try:
        for chunk in text_chain.stream({}):
            full_text += chunk if isinstance(chunk, str) else str(chunk)
            display = full_text if len(full_text) <= 600 else "…" + full_text[-600:]
            thinking_container.markdown(
                f'<div style="{_STYLE}">💭 {display}▌</div>',
                unsafe_allow_html=True,
            )
    except Exception:
        full_text = text_chain.invoke({})
    return full_text


# ══════════════════════════════════════════════════════════════════════════════
# 6b.  INCIDENT COMPACTION FOR PROMPTS
# ══════════════════════════════════════════════════════════════════════════════

_MAX_ALERTS_IN_PROMPT = 12
_MAX_PROMPT_CHARS     = 9000

_ALERT_KEEP_KEYS = (
    "id", "title", "name", "type", "source", "severity", "risk_score",
    "riskScore", "created", "receivedTime", "detail", "signature",
    "hostSummary", "sourceIp", "destinationIp", "domain", "userName",
    "fileName", "fileHash", "processName", "incident_id",
)


def _compact_incident(incident: dict, parsed_context: dict | None = None) -> str:
    """
    Compact JSON rendering of an incident for LLM prompts.

    Live incidents carry their FULL alerts array (can be 100s of alerts) plus
    journal entries — dumping that raw with indent=2 makes the prompt huge,
    slows inference, and leaves the reasoning model less budget for the answer.
    Keeps every scalar top-level field, a capped/slimmed sample of alerts, and
    hard-caps the total size.

    parsed_context, when given, is the Parsing & Normalisation stage's flat
    processed_alert (see soc_workflow.run_parsing) — already-extracted IPs,
    hashes, users, hosts, files, MITRE hints. It's folded in ahead of the raw
    alerts sample so the IOC/risk/classification phases reuse that extraction
    instead of re-deriving indicators from scratch every time.
    """
    slim: dict = {}
    if parsed_context:
        slim["parsed_alert_context"] = parsed_context
    for k, v in incident.items():
        if k in ("alerts", "journalEntries", "alertMeta"):
            continue
        if isinstance(v, str) and len(v) > 400:
            slim[k] = v[:400] + "…"
        else:
            slim[k] = v

    # alertMeta often carries the ONLY forensic indicators NetWitness gives
    # us at the incident level (SourceIp/DestinationIp lists) — dropping it
    # left the IOC phase judging an incident with zero indicators in view.
    meta = incident.get("alertMeta")
    if isinstance(meta, dict) and meta:
        slim["alertMeta"] = {
            str(k): (v[:10] if isinstance(v, list) else v)
            for k, v in list(meta.items())[:20]
        }

    alerts = incident.get("alerts") or []
    if alerts:
        slim["alert_total"] = len(alerts)
        slim_alerts = []
        for a in alerts[:_MAX_ALERTS_IN_PROMPT]:
            if not isinstance(a, dict):
                continue
            sa = {k: a[k] for k in _ALERT_KEEP_KEYS if a.get(k) not in (None, "", [], {})}
            # keep a tiny slice of the first event's source/dest for context
            events = a.get("events")
            if isinstance(events, list) and events and isinstance(events[0], dict):
                ev = events[0]
                for side in ("source", "destination"):
                    node = ev.get(side)
                    if isinstance(node, dict):
                        dev = node.get("device") or {}
                        ip  = dev.get("ipAddress") or node.get("ipAddress")
                        if ip:
                            sa[f"event_{side}_ip"] = ip
            slim_alerts.append(sa)
        slim["alerts_sample"] = slim_alerts
        if len(alerts) > _MAX_ALERTS_IN_PROMPT:
            slim["alerts_note"] = (
                f"showing first {_MAX_ALERTS_IN_PROMPT} of {len(alerts)} alerts"
            )

    text = json.dumps(slim, indent=1, default=str)
    if len(text) > _MAX_PROMPT_CHARS:
        text = text[:_MAX_PROMPT_CHARS] + "\n…(truncated)"
    return text


# ══════════════════════════════════════════════════════════════════════════════
# 7.  INCIDENT TIME EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

_TIME_FIELDS = [
    "created", "createdAt", "created_at", "timestamp", "alertTime",
    "eventTime", "event_time", "occurredTime", "detectedTime", "time",
]


def _flatten(d: Any, prefix: str = "") -> dict:
    items: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            nk = f"{prefix}.{k}" if prefix else str(k)
            items.update(_flatten(v, nk))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = d
    return items


def _extract_incident_time(incident: dict) -> str:
    flat = _flatten(incident)
    for field in _TIME_FIELDS:
        val = flat.get(field) or incident.get(field)
        if val:
            raw = str(val).strip()
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(raw[:19], fmt[:19])
                    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except ValueError:
                    continue
            if len(raw) >= 8:
                return raw
    return "—"


# ══════════════════════════════════════════════════════════════════════════════
# 8.  META-KEY EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

_METAKEY_MAP: dict[str, list[str]] = {
    "ip.src":       ["sourceIp", "source_ip", "srcIp", "source.ip",
                     "source.device.ipAddress", "ipSrc", "ip_src"],
    "ip.dst":       ["destinationIp", "dest_ip", "dstIp", "destination.ip",
                     "destination.device.ipAddress", "ipDst", "ip_dst"],
    "host.name":    ["hostname", "host", "deviceName", "computerName",
                     "machineName", "hostName", "dnsHostname", "device.name"],
    "user.name":    ["username", "user", "userName", "targetUser", "userDst",
                     "userSrc", "user_name", "accountName"],
    "domain":       ["domain", "fqdn", "eventDomain"],
    "event.type":   ["type", "eventType", "event_type"],
    "bytes.out":    ["bytesOut", "bytes_out", "egress_bytes"],
    "protocol":     ["protocol", "networkProtocol"],
    "geo.country":  ["country", "geoCountry"],
    "file.name":    ["fileName", "file_name"],
    "file.hash":    ["fileHash", "md5", "sha256"],
    "process.name": ["processName", "process_name"],
    "os.version":   ["osVersion", "os_version", "operatingSystem", "osType"],
}

# Values that carry no forensic information — never surface them as extracted
# metakey values (they'd feed "Unknown" straight into the investigation agent).
_METAKEY_NOISE = {"", "unknown", "none", "null", "n/a", "-", "0.0.0.0",
                  "localhost", "127.0.0.1"}


def _extract_metakey_values(incident: dict, metakeys: list[str]) -> dict:
    """Deep metakey extraction.

    NetWitness incidents nest the interesting fields under alerts[N].events[N]
    (source.device.ipAddress, …), so exact top-level lookups almost always
    missed. Match flattened key PATHS case-insensitively by suffix instead,
    walking keys in sorted order so repeat runs stay deterministic. Multiple
    distinct hits are kept (capped) — downstream consumers accept lists.
    """
    flat = _flatten(incident)

    def norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(s).lower())

    # Pre-normalize once: the last three path segments cover keys like
    # "source.device.ipAddress" while ignoring the alerts[3].events[0] prefix.
    norm_flat = []
    for key in sorted(flat.keys()):
        val = flat[key]
        if val in (None, "", [], {}) or str(val).strip().lower() in _METAKEY_NOISE:
            continue
        segs = [s for s in re.split(r"[.\[\]]", key) if s and not s.isdigit()]
        tail = norm("".join(segs[-3:]))
        norm_flat.append((tail, norm(segs[-1] if segs else key), val))

    values: dict = {}
    for mk in metakeys:
        hits: list = []
        for cand in _METAKEY_MAP.get(mk, []):
            nc = norm(cand)
            for tail, last, val in norm_flat:
                if (last == nc or tail.endswith(nc)) and val not in hits:
                    hits.append(val)
                if len(hits) >= 5:
                    break
            if hits:
                break
        if hits:
            values[mk] = hits[0] if len(hits) == 1 else hits
    return values


# ══════════════════════════════════════════════════════════════════════════════
# 8b.  IOC MATCH RESOLUTION
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_ioc_matches(raw_items: Any, ioc_list: list[dict]) -> list[int]:
    """
    Resolve the model's matched_iocs entries to 0-based positions in ioc_list.

    The prompt demands integer indices, but the model doesn't always comply —
    it may emit "3", "[3]", "IOC 3", or the IOC's NAME. The old int(idx)-only
    path silently dropped everything non-integer, which read as "0 IOCs
    matched" even when the model had clearly identified matches.
    """
    if raw_items is None:
        return []
    if not isinstance(raw_items, (list, tuple)):
        raw_items = [raw_items]

    resolved: list[int] = []

    def _add(pos: int) -> None:
        if 0 <= pos < len(ioc_list) and pos not in resolved:
            resolved.append(pos)

    for item in raw_items:
        if isinstance(item, bool):        # bool is an int subclass — skip
            continue
        if isinstance(item, (int, float)):
            _add(int(item) - 1)
            continue
        s = str(item).strip()
        if not s:
            continue
        # "3", "[3]", "IOC 3", "#3" — a lone number anywhere in a short token
        m = re.fullmatch(r"[^\d]{0,6}(\d{1,2})[^\d]{0,2}", s)
        if m:
            _add(int(m.group(1)) - 1)
            continue
        # "1, 4" / "2 and 5" — numbers-only token with separators
        if not re.search(r"[a-zA-Z]{4,}", s):
            nums = re.findall(r"\d{1,2}", s)
            if nums:
                for n in nums:
                    _add(int(n) - 1)
                continue
        # Otherwise treat it as an IOC name (exact, then substring, either way)
        s_low = s.lower()
        for j, entry in enumerate(ioc_list):
            name = entry["ioc"].lower()
            if s_low == name or s_low in name or name in s_low:
                _add(j)
                break

    return resolved


# ══════════════════════════════════════════════════════════════════════════════
# 9.  TRIAGE AGENT  (3 direct LLM calls — no pipeline, no tool wrappers)
# ══════════════════════════════════════════════════════════════════════════════

class TriageAgent:
    """
    SOC Triage Agent.

    Three direct LLM calls, no LCEL pipeline, no @tool decorators:
      _run_ioc()  → 1 call covering all 27 IOCs across 3 categories
      _run_risk() → 1 call for risk rating
      _run_cls()  → 1 call for SOC classification

    Parameters
    ----------
    cfg               : CiscoLLMConfig
    progress_fn       : callable(event, label, text) — live UI callbacks
    thinking_container: Streamlit st.empty() for token streaming
    """

    def __init__(
        self,
        cfg: CiscoLLMConfig | None = None,
        progress_fn=None,
        thinking_container=None,
    ) -> None:
        self.cfg               = cfg or CiscoLLMConfig()
        # Triage phases always end in a JSON object — request forced-JSON
        # decoding on providers that support it (parse drift -> zero).
        self.llm               = build_llm(
            self.cfg,
            json_mode=_provider_supports_json_mode(self.cfg.base_url))
        self.progress_fn       = progress_fn
        self.thinking_container = thinking_container

    # ── helpers ───────────────────────────────────────────────────────────────

    def _emit(self, event: str, label: str, text: str = "") -> None:
        if self.progress_fn:
            try:
                self.progress_fn(event, label, text)
            except Exception:
                pass

    def _call(self, messages: list, phase_label: str) -> tuple[str, dict]:
        """
        Build a chain, stream/invoke it, extract JSON, repair if needed.
        Returns (raw_text, data_dict).
        """
        self._emit("phase_start", phase_label)
        prompt     = ChatPromptTemplate.from_messages(messages)
        text_chain = prompt | self.llm | StrOutputParser()
        raw_text   = _stream_or_invoke(text_chain, self.thinking_container)
        return raw_text

    # ── Phase 1: IOC Checklists (single combined call) ────────────────────────

    def _run_ioc(self, incident: dict, parsed_context: dict | None = None) -> dict:
        """One LLM call covering all three IOC categories."""

        def fmt_list(ioc_list, offset=0):
            return "\n".join(
                f"  [{i+1+offset}] {e['ioc']}: {e['desc']}"
                for i, e in enumerate(ioc_list)
            )

        avail_text = fmt_list(IOC_AVAILABILITY)
        conf_text  = fmt_list(IOC_CONFIDENTIALITY)
        integ_text = fmt_list(IOC_INTEGRITY)

        messages = [
            SystemMessage(content=(
                "You are a SOC Analyst performing IOC triage across three categories. "
                "Analyse the incident and identify which IOCs are present in each category. "
                "Keep your reasoning SHORT — a few sentences per category at most — "
                "then output ONLY a single JSON object as your final answer.\n"
                "Rules for the JSON:\n"
                "- matched_iocs MUST be an array of integer indices from the checklist, "
                "e.g. [2, 5]. Never use IOC names or text there.\n"
                "- Use [] for a category with no matches.\n"
                "- An incident with high risk scores or malicious indicators almost "
                "always matches at least one IOC overall — match every IOC the "
                "evidence supports.\n"
                "Final JSON schema:\n"
                '{"availability": {"matched_iocs": [<integers>], "reasoning": "<brief>", "metakeys": [<strings>]},\n'
                ' "confidentiality": {"matched_iocs": [<integers>], "reasoning": "<brief>", "metakeys": [<strings>]},\n'
                ' "integrity": {"matched_iocs": [<integers>], "reasoning": "<brief>", "metakeys": [<strings>]}}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{_compact_incident(incident, parsed_context)}\n\n"
                f"IOC CHECKLIST — AVAILABILITY:\n{avail_text}\n\n"
                f"IOC CHECKLIST — CONFIDENTIALITY:\n{conf_text}\n\n"
                f"IOC CHECKLIST — INTEGRITY:\n{integ_text}\n\n"
                "Identify all matched IOCs across all three categories. "
                "End your response with the JSON object."
            )),
        ]

        raw_text = self._call(messages, "IOC Checklists")
        data     = _extract_json(raw_text)

        required = ["availability", "confidentiality", "integrity"]
        if not any(data.get(k) for k in required):
            data = _repair_json(raw_text, required, self.llm)

        # Resolve indices → names and metakeys
        all_metakeys: set[str] = set()
        per_category: dict     = {}
        summary_parts: list    = []

        for cat_key, ioc_list in ALL_IOCS.items():
            cat_data = data.get(cat_key) or {}
            # Same shape drift as the top level: the model sometimes emits
            # the category as a bare list of indices ("availability": [1, 2])
            # instead of the documented object.
            if isinstance(cat_data, list):
                cat_data = {"matched_iocs": cat_data}
            elif not isinstance(cat_data, dict):
                cat_data = {}
            indices = cat_data.get("matched_iocs") or []
            if isinstance(indices, (int, str)):
                indices = re.findall(r"\d+", str(indices))
            reasoning = cat_data.get("reasoning", "")
            if not isinstance(reasoning, str):
                reasoning = str(reasoning or "")
            extra_mkeys = cat_data.get("metakeys") or []
            if isinstance(extra_mkeys, str):
                extra_mkeys = [extra_mkeys]

            matched_names: list[str] = []
            cat_metakeys: set[str]   = set()
            for pos in _resolve_ioc_matches(indices, ioc_list):
                entry = ioc_list[pos]
                if entry["ioc"] not in matched_names:
                    matched_names.append(entry["ioc"])
                    cat_metakeys.update(entry["metakeys"])

            all_metakeys.update(cat_metakeys)
            all_metakeys.update(str(m) for m in extra_mkeys)

            per_category[cat_key] = {
                "matched_ioc_names": matched_names,
                "matched_indices":   indices,
                "reasoning":         reasoning,
                "category_metakeys": sorted(cat_metakeys),
            }

            if matched_names:
                summary_parts.append(
                    f"[{cat_key.upper()}] {', '.join(matched_names)}"
                    + (f" — {reasoning}" if reasoning else "")
                )

        total = sum(len(v["matched_ioc_names"]) for v in per_category.values())
        self._emit("phase_complete", "IOC Checklists", f"{total} IOC(s) matched")

        result = {
            "per_category":    per_category,
            "all_metakeys":    sorted(all_metakeys),
            "ioc_summary":     "\n".join(summary_parts) if summary_parts else "No IOCs matched.",
            "total_ioc_count": total,
        }
        if total == 0:
            # Zero matches with no parseable JSON almost always means the
            # model's response was cut off before the final answer (or came
            # back in an unparseable shape). Surface the tail of the raw
            # output in the trace so this is diagnosable from the UI instead
            # of silently reading as "nothing matched".
            if not data:
                result["debug_note"] = (
                    "Model output contained no parseable JSON — likely "
                    "truncated before the final answer (check max_tokens)."
                )
            result["raw_tail"] = raw_text[-400:] if raw_text else ""
        return result

    # ── Phase 2: Risk Rating ──────────────────────────────────────────────────

    def _run_risk(self, incident: dict, ioc_summary: str, parsed_context: dict | None = None) -> dict:
        messages = [
            SystemMessage(content=(
                "You are a SOC Risk Analyst. Apply the SOC Risk Rating Methodology. "
                "After your reasoning, output ONLY a single JSON object as your final answer.\n"
                "Final JSON schema:\n"
                '{"likelihood_initiation": "<Critical|High|Medium|Low>",\n'
                ' "likelihood_occurrence": "<Critical|High|Medium|Low>",\n'
                ' "likelihood_adverse_impact": "<Critical|High|Medium|Low>",\n'
                ' "overall_risk": "<Critical|High|Medium|Low>",\n'
                ' "rationale": "<one sentence>"}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{_compact_incident(incident, parsed_context)}\n\n"
                f"IOC FINDINGS:\n{ioc_summary}\n\n"
                f"RATING GUIDANCE:\n{RISK_RATING_GUIDANCE}\n\n"
                "Rate all three dimensions strictly against the guidance bands, "
                "anchored to concrete evidence (risk score, IOC matches, alert "
                "volume) — one short justification each, no hedging between "
                "levels. overall_risk = highest dimension. "
                "End your response with the JSON object."
            )),
        ]

        raw_text = self._call(messages, "Risk Rating")
        data     = _extract_json(raw_text)
        if not data.get("overall_risk"):
            data = _repair_json(
                raw_text,
                ["likelihood_initiation", "likelihood_occurrence",
                 "likelihood_adverse_impact", "overall_risk", "rationale"],
                self.llm,
            )
        self._emit("phase_complete", "Risk Rating",
                   f"Overall risk: {data.get('overall_risk') or '—'}")
        return data

    # ── Phase 3: SOC Classification ───────────────────────────────────────────

    def _run_cls(self, incident: dict, risk_level: str, ioc_summary: str, parsed_context: dict | None = None) -> dict:
        messages = [
            SystemMessage(content=(
                "You are a SOC Analyst applying the SOC Classification Template. "
                "After your reasoning, output ONLY a single JSON object as your final answer.\n"
                "Final JSON schema:\n"
                '{"classification": "<Critical|High|Medium|Low>",\n'
                ' "incident_category": "<best matching category>",\n'
                ' "response_time": "<initial response time>",\n'
                ' "summary": "<2-3 sentence triage summary>",\n'
                ' "recommended_actions": ["<action 1>", "<action 2>"],\n'
                ' "mitre_tactic": "<single best matching MITRE ATT&CK tactic from: '
                + ", ".join(MITRE_TACTICS) + '>",\n'
                ' "mitre_technique": "<MITRE technique id and name, e.g. '
                'T1110 Brute Force, or Unknown>"}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{_compact_incident(incident, parsed_context)}\n\n"
                f"RISK RATING RESULT: {risk_level.upper()}\n\n"
                f"IOC FINDINGS:\n{ioc_summary}\n\n"
                f"CLASSIFICATION TABLE:\n{json.dumps(SOC_CLASSIFICATION_TABLE, indent=2)}\n\n"
                "Classify this incident. End your response with the JSON object."
            )),
        ]

        raw_text = self._call(messages, "SOC Classification")
        data     = _extract_json(raw_text)
        if not data.get("classification"):
            data = _repair_json(
                raw_text,
                ["classification", "incident_category",
                 "response_time", "summary", "recommended_actions"],
                self.llm,
            )
        self._emit("phase_complete", "SOC Classification",
                   f"Classification: {data.get('classification') or '—'}")
        return data

    # ── Main entry point ──────────────────────────────────────────────────────

    def triage(self, incident: dict, force: bool = False,
               parsed_context: dict | None = None) -> dict:
        inc_id    = str(incident.get("id") or incident.get("incidentId") or "unknown")
        inc_title = incident.get("title") or incident.get("name") or "Untitled"
        timestamp = datetime.utcnow().isoformat()
        inc_time  = _extract_incident_time(incident)
        trace: list[dict] = []

        # ── Result cache: identical incident content → identical output ──────
        # Guarantees repeat triages of an unchanged incident return the exact
        # same findings (and instantly). force=True bypasses for a fresh run.
        fingerprint = _incident_fingerprint(incident)
        if not force:
            cached = _cache_get(fingerprint)
            if cached and not cached.get("error"):
                for phase in ("IOC Checklists", "Risk Rating", "SOC Classification"):
                    self._emit("phase_complete", phase, "cached")
                cached["cached"] = True
                return cached

        try:
            # Phase 1 — IOC
            ioc_data = self._run_ioc(incident, parsed_context)
            ioc_step = {
                "step": "IOC Checklist", "status": "ok",
                "matched_metakeys": ioc_data["all_metakeys"],
                "ioc_summary":      ioc_data["ioc_summary"],
                "total_ioc_count":  ioc_data["total_ioc_count"],
                "per_category":     ioc_data["per_category"],
            }
            if ioc_data.get("debug_note"):
                ioc_step["debug_note"] = ioc_data["debug_note"]
            if ioc_data.get("raw_tail"):
                ioc_step["raw_tail"] = ioc_data["raw_tail"]
            trace.append(ioc_step)

            # Phase 2 — Risk Rating
            # The LLM judges the three likelihood dimensions; everything
            # derivable from them is computed in code so it can't drift
            # between runs. overall_risk = highest dimension (the prompt
            # states this rule — now the code enforces it instead of
            # trusting the model to apply it consistently).
            risk_data = self._run_risk(incident, ioc_data["ioc_summary"], parsed_context)
            dims = {
                k: _normalize_level(risk_data.get(k), default="medium")
                for k in ("likelihood_initiation", "likelihood_occurrence",
                          "likelihood_adverse_impact")
            }
            risk_level = max(dims.values(), key=lambda v: _SEV_ORDER[v])
            for k, v in dims.items():
                risk_data[k] = v.capitalize()
            risk_data["overall_risk"] = risk_level.capitalize()
            trace.append({"step": "Risk Rating", "status": "ok", "data": risk_data})

            # Phase 3 — Classification
            # The classification LEVEL maps 1:1 onto the overall risk level
            # per the SOC Classification Template, so it's derived, not
            # re-judged — the LLM contributes only the parts that genuinely
            # need language: category, summary, recommended actions.
            cls_data       = self._run_cls(incident, risk_level, ioc_data["ioc_summary"], parsed_context)
            classification = risk_level
            cls_meta       = SOC_CLASSIFICATION_TABLE[classification]
            cls_data["classification"] = classification.capitalize()
            cls_data["response_time"]  = cls_meta["initial_response_time"]
            # MITRE mapping — snapped to the canonical tactic list in code so
            # downstream consumers (investigation playbook selection, reports)
            # never see free-form drift from the model.
            cls_data["mitre_tactic"]    = _normalize_mitre_tactic(
                cls_data.get("mitre_tactic"))
            cls_data["mitre_technique"] = _normalize_mitre_technique(
                cls_data.get("mitre_technique"))
            trace.append({"step": "SOC Classification", "status": "ok", "data": cls_data})

        except Exception as exc:
            return {
                "error": str(exc),
                "metakeys_payload": {}, "ticket": {}, "trace": trace,
            }

        matched_metakeys = ioc_data["all_metakeys"]

        # Output 1 — meta-key payload
        metakeys_payload = {
            "incident_id":      inc_id,
            "incident_title":   inc_title,
            "timestamp":        timestamp,
            "matched_metakeys": matched_metakeys,
            "metakey_values":   _extract_metakey_values(incident, matched_metakeys),
            "ioc_summary":      ioc_data["ioc_summary"],
            "risk_level":       risk_level,
            "classification":   classification,
            "mitre_tactic":     cls_data.get("mitre_tactic") or "Unknown",
            "mitre_technique":  cls_data.get("mitre_technique") or "Unknown",
        }

        # Output 2 — ticket
        unc    = _next_unc()
        ticket = {
            "unc":             unc,
            "incident_id":     inc_id,
            "title":           inc_title,
            "incident_time":   inc_time,
            "created_at":      timestamp,
            "classification":  classification.upper(),
            "risk_rating": {
                "likelihood_initiation":     risk_data.get("likelihood_initiation") or "—",
                "likelihood_occurrence":     risk_data.get("likelihood_occurrence") or "—",
                "likelihood_adverse_impact": risk_data.get("likelihood_adverse_impact") or "—",
                "overall_risk":              risk_data.get("overall_risk") or "—",
                "rationale":                 risk_data.get("rationale") or "",
            },
            "incident_category":     cls_data.get("incident_category") or "—",
            "mitre_tactic":          cls_data.get("mitre_tactic") or "Unknown",
            "mitre_technique":       cls_data.get("mitre_technique") or "Unknown",
            "initial_response_time": cls_meta["initial_response_time"],
            "summary":               cls_data.get("summary") or "",
            "recommended_actions":   (
                [ra] if isinstance(ra := (cls_data.get("recommended_actions") or []), str)
                else list(ra) if isinstance(ra, (list, tuple)) else []
            ),
            "matched_ioc_count":     ioc_data["total_ioc_count"],
            "metakeys":              matched_metakeys,
        }

        _store_ticket(unc, inc_id, classification, ticket)

        result = {
            "metakeys_payload":    metakeys_payload,
            "ticket":              ticket,
            "trace":               trace,
            "used_parsed_context": bool(parsed_context),
            "error":               None,
        }
        _cache_put(fingerprint, inc_id, result)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# 10. DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def render_triage_trace(trace: list[dict]) -> str:
    lines: list[str] = ["## 🛡️ SOC Triage Report\n"]
    for step in trace:
        name   = step.get("step", "Step")
        status = "✅" if step.get("status") == "ok" else "❌"
        lines.append(f"### {status} Phase — {name}")

        if name == "IOC Checklist":
            count   = step.get("total_ioc_count") or 0
            summary = step.get("ioc_summary") or ""
            mkeys   = step.get("matched_metakeys") or []
            lines.append(f"**Total IOCs matched:** {count}")
            if summary:
                lines.append(f"**Summary:** {summary}")
            if mkeys:
                lines.append(f"**Meta-Keys:** `{'`, `'.join(mkeys)}`")
            for cat, cat_data in (step.get("per_category") or {}).items():
                matched = cat_data.get("matched_ioc_names") or []
                if matched:
                    lines.append(f"- **{cat.capitalize()}:** {', '.join(matched)}")
            if step.get("debug_note"):
                lines.append(f"\n> ⚠️ {step['debug_note']}")
                if step.get("raw_tail"):
                    lines.append(f"> Raw model output (tail): `{step['raw_tail'][-200:]}`")

        elif name == "Risk Rating":
            d = step.get("data") or {}
            lines.extend([
                "| Dimension | Rating |",
                "|-----------|--------|",
                f"| Likelihood of Initiation | **{d.get('likelihood_initiation') or '—'}** |",
                f"| Likelihood of Occurrence | **{d.get('likelihood_occurrence') or '—'}** |",
                f"| Likelihood of Adverse Impact | **{d.get('likelihood_adverse_impact') or '—'}** |",
                f"| **Overall Risk** | **{d.get('overall_risk') or '—'}** |",
            ])
            if d.get("rationale"):
                lines.append(f"\n*{d['rationale']}*")

        elif name == "SOC Classification":
            d   = step.get("data") or {}
            cls = (d.get("classification") or "—").upper()
            lines.append(f"- **Classification:** {cls}")
            lines.append(f"- **Category:** {d.get('incident_category') or '—'}")
            lines.append(f"- **Response Time:** {d.get('response_time') or '—'}")
            if d.get("summary"):
                lines.append(f"- **Summary:** {d['summary']}")
            for a in (d.get("recommended_actions") or []):
                lines.append(f"  - {a}")

        lines.append("")
    return "\n".join(lines)


def format_ticket_display(ticket: dict) -> str:
    rr    = ticket.get("risk_rating") or {}
    unc   = ticket.get("unc") or "—"
    cls   = (ticket.get("classification") or "—").upper()
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon  = icons.get(cls, "⚪")
    lines = [
        "---",
        f"## {icon} Ticket `{unc}`",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Incident ID** | `{ticket.get('incident_id') or '—'}` |",
        f"| **Title** | {ticket.get('title') or '—'} |",
        f"| **Incident Time** | {ticket.get('incident_time') or '—'} |",
        f"| **Ticket Created** | {ticket.get('created_at') or '—'} |",
        f"| **Classification** | **{cls}** |",
        f"| **Category** | {ticket.get('incident_category') or '—'} |",
        f"| **MITRE Tactic** | {ticket.get('mitre_tactic') or 'Unknown'} |",
        f"| **MITRE Technique** | {ticket.get('mitre_technique') or 'Unknown'} |",
        f"| **Initial Response Time** | {ticket.get('initial_response_time') or '—'} |",
        f"| **IOCs Matched** | {ticket.get('matched_ioc_count', 0)} |",
        "",
        "### Risk Rating",
        "| Dimension | Rating |",
        "|-----------|--------|",
        f"| Initiation | {rr.get('likelihood_initiation') or '—'} |",
        f"| Occurrence | {rr.get('likelihood_occurrence') or '—'} |",
        f"| Adverse Impact | {rr.get('likelihood_adverse_impact') or '—'} |",
        f"| **Overall** | **{rr.get('overall_risk') or '—'}** |",
        "",
        "### Triage Summary",
        ticket.get("summary") or "—",
        "",
        "### Recommended Actions",
    ]
    for a in (ticket.get("recommended_actions") or []):
        lines.append(f"- {a}")
    mkeys = ticket.get("metakeys") or []
    if mkeys:
        lines += ["", "### Matched Meta-Keys",
                  f"`{'`, `'.join(mkeys)}`"]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 11.  TRIAGE TRIGGER & CHAT RESPOND
# ══════════════════════════════════════════════════════════════════════════════

_TRIAGE_TRIGGER = re.compile(
    r"\b(triage|re-?triage|analys[ei]s?|ioc|classify|classification|ticket|investigate)\b",
    re.IGNORECASE,
)

# Words that force a fresh LLM run instead of returning the cached result
_FORCE_TRIGGER = re.compile(r"\b(re-?triage|force|fresh|again)\b", re.IGNORECASE)


def _build_qa_chain(llm: ChatOpenAI):
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are an expert SOC Analyst. Answer questions concisely and accurately "
            "using IOC analysis, threat intelligence, and security best practices."
        )),
        HumanMessage(content="{user_input}"),
    ])
    return prompt | llm | StrOutputParser()


def deep_triage_supplement(incident: dict, gaps: list,
                           cfg: CiscoLLMConfig | None = None,
                           thinking_container=None) -> dict:
    """Second-pass triage for the investigation feedback loop.

    The investigation agent reported specific evidence gaps; this focused
    LLM pass mines the raw incident for anything that answers them. Gaps the
    incident genuinely cannot answer are explicitly marked
    'not present in incident data' so the investigation can treat them as
    CONFIRMED-absent instead of merely unexamined (and so the loop
    terminates instead of retrying forever).

    Returns gap_findings, confidence_per_gap, extracted_values, actionable_queries,
    mitre_tactic, classification, incident_category, and deep_dive_summary.
    """
    cfg = cfg or CiscoLLMConfig()
    llm = build_llm(cfg, json_mode=_provider_supports_json_mode(cfg.base_url))
    gap_lines = "\n".join(f"- {str(g)[:200]}" for g in list(gaps)[:8])

    # Use a larger context window for the deep-dive pass — the triage
    # compact view often strips the exact fields the investigation needs.
    incident_context = json.dumps(incident, indent=2)[:12000]

    messages = [
        SystemMessage(content=(
            "You are a senior SOC analyst performing a focused evidence "
            "deep-dive. The investigation team reported specific evidence "
            "gaps that prevented playbook steps from being satisfied.\n\n"
            "Your job is to:\n"
            "1. THOROUGHLY mine the raw incident data and REASON about each gap — do NOT just do literal field lookups. "
            "Apply forensic reasoning:\n"
            "  - If a gap asks about lateral vs vertical movement, REASON from "
            "    available IPs and subnet masks (e.g. same /24 = likely horizontal).\n"
            "  - If a gap asks about process trees or spawned processes, check for "
            "    any process names, command lines, parent-child references, or "
            "    execution indicators in the data.\n"
            "  - If a gap asks about user context, infer privilege levels from "
            "    username patterns (e.g. 'admin', 'svc-', 'SYSTEM').\n"
            "  - If a gap asks about OS details, check hostname patterns, alert "
            "    metadata, or any system identifiers.\n"
            "  - Extract ALL possible contextual clues, even indirect ones.\n"
            "2. For each gap, provide a confidence level: 'high' if the data "
            "   directly answers it, 'medium' if you can reasonably infer the answer, "
            "   'low' if it's speculative but grounded in available evidence, 'none' if it is missing.\n"
            "3. ACTIONABLE QUERIES: If a gap is missing ('not present in incident data') or has low confidence, "
            "   determine exactly what specific Windows Event ID, host command (e.g., netstat -ano, Get-Process, Get-Service), "
            "   EDR query, or log source is needed to retrieve this missing evidence (e.g. 'Query AD Security Logs for Event ID 4624 to find authentications for source IP 10.0.0.1').\n"
            "4. PLAYBOOK REDIRECTION / MUTATION: Carefully evaluate if the raw incident data contradicts the initial classification. "
            "   If the evidence suggests a different category or tactic (e.g., initial triage classified as Phishing, but deep-dive reveals "
            "   clear Command and Control, Lateral Movement, or Privilege Escalation activity), specify the corrected MITRE tactic, category, and classification.\n\n"
            "Output ONLY a single JSON object matching this schema:\n"
            '{\n'
            '  "gap_findings": {"<gap>": "<detailed finding with reasoning, or not present in incident data>"},\n'
            '  "confidence_per_gap": {"<gap>": "high|medium|low|none"},\n'
            '  "actionable_queries": {"<gap>": "<specific query, CLI command, Windows Event ID, or EDR search recommended to collect this evidence>"},\n'
            '  "extracted_values": {"<field e.g. user.name/host.name/os/ip.src>": "<value>"},\n'
            '  "mitre_tactic": "<Optional corrected MITRE tactic, e.g. Privilege Escalation, Command and Control, or leave null>",\n'
            '  "incident_category": "<Optional corrected category, e.g. Privilege Escalation, or leave null>",\n'
            '  "classification": "<Optional corrected classification/severity, e.g. CRITICAL, HIGH, MEDIUM, or leave null>",\n'
            '  "deep_dive_summary": "<2-3 sentences summarising what was found and what remains unknown>"\n'
            '}'
        )),
        HumanMessage(content=(
            f"EVIDENCE GAPS REPORTED BY INVESTIGATION:\n{gap_lines}\n\n"
            f"RAW INCIDENT DATA (FULL CONTEXT):\n{incident_context}\n\n"
            "Answer every gap with forensic reasoning and provide query recommendations. End your response with the JSON object."
        )),
    ]
    prompt   = ChatPromptTemplate.from_messages(messages)
    raw_text = _stream_or_invoke(prompt | llm | StrOutputParser(),
                                 thinking_container)
    data = _extract_json(raw_text)
    if not data:
        data = _repair_json(raw_text, ["gap_findings"], llm)
        
    gap_findings = data.get("gap_findings")
    if not isinstance(gap_findings, dict):
        gap_findings = {}
    extracted = data.get("extracted_values")
    if not isinstance(extracted, dict):
        extracted = {}
    confidence = data.get("confidence_per_gap")
    if not isinstance(confidence, dict):
        confidence = {}
    actionable_queries = data.get("actionable_queries")
    if not isinstance(actionable_queries, dict):
        actionable_queries = {}
        
    # Drop noise values so downstream never treats "Unknown" as evidence.
    extracted = {k: v for k, v in extracted.items()
                 if str(v).strip().lower() not in _METAKEY_NOISE}
                 
    return {
        "gap_findings": gap_findings,
        "confidence_per_gap": confidence,
        "actionable_queries": actionable_queries,
        "extracted_values": extracted,
        "mitre_tactic": data.get("mitre_tactic"),
        "incident_category": data.get("incident_category"),
        "classification": data.get("classification"),
        "deep_dive_summary": str(data.get("deep_dive_summary") or "")[:500],
    }


def soc_triage_chat_respond(
    user_msg:           str,
    incident:           dict | None = None,
    llm_config:         CiscoLLMConfig | None = None,
    progress_fn                      = None,
    thinking_container               = None,
    result_sink:        dict | None  = None,
    parsed_context:     dict | None  = None,
) -> str:
    """result_sink: optional dict — if given, the structured triage result is
    stored under result_sink["result"] so callers (e.g. the app's sequential
    agent workflow) can hand it to the investigation/reporting agents.

    parsed_context: optional processed_alert from the Parsing & Normalisation
    stage (see soc_workflow.run_parsing / app.py's db_load_parsed_context) —
    when given, triage reuses those already-extracted indicators instead of
    re-deriving them from the raw incident."""
    cfg = llm_config or CiscoLLMConfig()

    if incident and _TRIAGE_TRIGGER.search(user_msg):
        agent  = TriageAgent(
            cfg                = cfg,
            progress_fn        = progress_fn,
            thinking_container = thinking_container,
        )
        result = agent.triage(incident, force=bool(_FORCE_TRIGGER.search(user_msg)),
                              parsed_context=parsed_context)
        if result_sink is not None:
            result_sink["result"] = result

        if result.get("error"):
            return f"❌ Triage error: {result['error']}"

        trace_md  = render_triage_trace(result["trace"])
        ticket_md = format_ticket_display(result["ticket"])
        unc       = result["ticket"].get("unc", "—")
        n_keys    = len(result["metakeys_payload"].get("matched_metakeys", []))

        cached_note = ""
        if result.get("cached"):
            cached_note = (
                "♻️ **Stored result** — this incident's content is unchanged since "
                f"it was last triaged, so the identical findings (ticket `{unc}`) "
                "are returned. Type **retriage** to force a fresh analysis.\n\n"
            )

        return (
            cached_note + trace_md + "\n\n" + ticket_md + "\n\n---\n\n"
            + f"📤 **Meta-key payload queued** ({n_keys} keys)\n\n"
            + f"📋 **Ticket `{unc}` created and queued for ticketing agent.**"
        )

    # Plain Q&A fallback
    llm = build_llm(cfg)
    ctx = ""
    if incident:
        ctx = f"\n\nIncident context:\n{json.dumps(incident, indent=2)[:600]}"
    qa_chain = _build_qa_chain(llm)
    try:
        return qa_chain.invoke({"user_input": user_msg + ctx})
    except Exception as exc:
        return f"⚠️ LLM error: {exc}"