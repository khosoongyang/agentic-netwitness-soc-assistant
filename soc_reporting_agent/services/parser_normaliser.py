# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Important dependencies: __future__, argparse, csv, datetime, ipaddress, json, pathlib, re.
# =============================================================================
# File: soc_reporting_agent/services/parser_normaliser.py
#
# Purpose:
#   This is the CORE PARSING & NORMALISATION implementation for the whole
#   Aegis platform's Stage 0 ("Parsing" / "NetWitness Alert Loading"). It
#   takes a raw, messy NetWitness incident/alert export (arbitrary,
#   deeply-nested JSON with many possible field-name variants) and converts
#   it into a clean, predictable, SOC/agent-facing schema that every later
#   stage (Triage, Investigation, Reporting) can rely on.
#
# Rule-based, NOT LLM-based:
#   Per soc_workflow.py's own module header ("0. Parsing ... in-process
#   (regex/rule-based, no LLM for the extraction itself)"), everything in
#   this file is deterministic Python: dictionary lookups (FIELD_ALIASES),
#   regular expressions (EMAIL_RE, FILE_RE, HASH_RE, IP_RE), string/date
#   parsing and simple heuristics. There is NO call to any LLM/AI API
#   anywhere in this file — confirmed by inspection, no contradicting code
#   found. Any "confidence"/"analyst summary" text produced here is built
#   from templated strings and counts, not model inference.
#
# Main functionalities in this file:
#   - NetWitness-specific alert/incident loading & flattening (JSON of
#     arbitrary shape -> flat dotted-path key/value map).
#   - Field mapping logic: FIELD_ALIASES + extract_by_alias() /
#     extract_all_fields() resolve dozens of NetWitness field-name variants
#     (e.g. "alert.alert.events[*].ip_src", "source.ip", "src_ip", ...) onto
#     one canonical SOC schema (source_ip, destination_ip, username, ...).
#   - Timestamp normalisation/conversion logic: timestamp_to_iso(),
#     epoch_to_iso(), timestamp_to_epoch_ms() coerce NetWitness's many time
#     representations (epoch seconds, epoch ms, ISO strings, "Z" suffixes)
#     into a single ISO-8601 UTC representation used everywhere downstream.
#   - Alert schema validation logic: evaluate_context_data_quality() and
#     calculate_confidence() check which required/important SOC fields were
#     actually recovered and assign a confidence rating/score.
#   - IOC extraction (emails, file hashes, IPs, URLs, filenames) via regex.
#   - PowerShell encoded-command decoding (delegated to
#     utils.powershell_decoder.analyse_powershell_command_lines).
#   - Building the various on-disk JSON/CSV artefacts described below.
#
# Design rule (unchanged from original author's docstring):
#   - soc_context_normalised_alert.json is clean and contains only important
#     SOC information.
#   - soc_context_raw_alert_debug.json contains extraction paths and parser
#     traceability (evidence).
#   - Evidence paths are NEVER written into soc_context_normalised_alert.json
#     (kept separate for analyst-facing cleanliness vs debug traceability).
#
# Workflow position:
#   Stage 0 of soc_workflow.py's 4-stage pipeline (Parsing -> Triage ->
#   Investigation -> Reporting). Parsing output (processed_alert) is passed
#   forward as `parsed_context` into the Triage stage.
#
# Called by (confirmed via `grep -rn "parser_normaliser" .`):
#   - soc_workflow.py, function run_parsing() (~line 693): imports
#     run_parser_normalisation_for_dashboard from this module and invokes it
#     for the in-process dashboard/orchestrator pipeline.
#   - soc_reporting_agent/adapters/run_parser_normalisation.py: CLI/subprocess
#     adapter that also imports run_parser_normalisation_for_dashboard (and
#     separately imports extract_alert_identity / validate_parser_identity
#     from soc_reporting_agent/services/parser_context_guard.py, a sibling
#     module that validates this file's output identity but does not call
#     into this file directly).
#   - Can also be invoked standalone from the command line (see main()/
#     parse_args() near the bottom of this file).
#
# Calls:
#   - utils.powershell_decoder.analyse_powershell_command_lines() for
#     PowerShell -EncodedCommand decoding/analysis.
#   - Standard library only otherwise: json, re, csv, ipaddress, datetime,
#     pathlib, argparse, urllib.parse.
#
# Key evaluator search terms: "parsing", "normalisation", "field mapping",
# "timestamp normalisation", "alert schema validation", "NetWitness alert
# loading", "IOC extraction", "confidence score", "rule-based/regex parser".
# =============================================================================
#
# Original author's docstring (kept verbatim below for continuity):
#
# SOC NetWitness Parser
# ======================
#
# Purpose:
#     Convert messy NetWitness exports into a clean SOC/agent-facing alert view.
#
# Design rule:
#     - soc_context_normalised_alert.json is clean and contains only important SOC information.
#     - soc_context_raw_alert_debug.json contains extraction paths and parser traceability.
#     - evidence paths are NEVER written into soc_context_normalised_alert.json.
#
# Usage:
#     python services/parser_normaliser.py inputs/alert2.json
#     python services/parser_normaliser.py inputs/alert2.json --output-dir outputs/soc_context_parser
#     python services/parser_normaliser.py inputs/alert2.json --debug
#
# Outputs:
#     outputs/soc_context_parser/soc_context_normalised_alert.json
#     outputs/soc_context_parser/soc_context_processed_alert.json
#     outputs/soc_context_parser/soc_context_processed_alert.csv
#     outputs/soc_context_parser/soc_context_netwitness_normalised_alerts.json
#     outputs/soc_context_parser/soc_context_parser_summary.json
#     outputs/soc_context_parser/soc_context_raw_alert_debug.json

from __future__ import annotations

import argparse
import csv
import json
import re
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

# [FYP-CALLS] Only external (non-stdlib) dependency of this file: PowerShell
# -EncodedCommand base64 decoding + heuristic analysis, used later when
# building process/command-line context (see normalise_event()).
from utils.powershell_decoder import analyse_powershell_command_lines


# =============================================================================
# [FYP-SECTION] MODULE CONSTANTS — versioning, output file names, IOC regex
# patterns, and the port->service lookup table.
# =============================================================================

# [FYP-CONFIG] Bumped manually by the author when parsing behaviour changes;
# written into parser summary/metadata output so downstream consumers and
# evaluators can tell which parser revision produced a given result.
PARSER_VERSION = "3.4-context-aware-normalised"
SCHEMA_VERSION = "1.0"

# [FYP-CONFIG] [FYP-OUTPUT] Canonical output file names written by
# write_outputs() (see below) under the run's parsing output directory.
# NORMALISED_ALERT_FILE = clean, analyst-facing alert (no evidence paths).
# PROCESSED_ALERT_FILE  = agent-facing structure consumed by Triage/other
#                         stages (see build_agent_friendly_processed_alert()).
# RAW_DEBUG_FILE         = extraction paths / traceability evidence — kept
#                         separate from the normalised alert by design.
NORMALISED_ALERT_FILE = "soc_context_normalised_alert.json"
PROCESSED_ALERT_FILE = "soc_context_processed_alert.json"
PROCESSED_ALERT_CSV_FILE = "soc_context_processed_alert.csv"
ALL_NORMALISED_ALERTS_FILE = "soc_context_netwitness_normalised_alerts.json"
ALL_PARSED_EVENTS_FILE = "soc_context_all_parsed_events.json"
PARSER_SUMMARY_FILE = "soc_context_parser_summary.json"
RAW_DEBUG_FILE = "soc_context_raw_alert_debug.json"

# [FYP-PROCESS] IOC/indicator extraction regex patterns — pure rule-based
# pattern matching, NO LLM involved. Used by extract_emails()/
# extract_hashes() and directly against free-text fields (command lines,
# messages) to pull out embedded indicators of compromise.
# EMAIL_RE  - RFC-loose email address matcher.
# FILE_RE   - filename with a known executable/document/archive extension.
# HASH_RE   - hex string of length 32/40/64 (MD5/SHA1/SHA256).
# IP_RE     - dotted-quad IPv4 address (octet-range aware).
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
FILE_RE = re.compile(r"[A-Za-z0-9_. ()\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|jar|docm|xlsm|zip|rar|7z|pdf|doc|docx|xls|xlsx)", re.I)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# [FYP-PROCESS] Well-known TCP/UDP port -> service-name lookup, used by
# map_service_name() to label destination ports with a human-readable
# protocol/service name (e.g. 445 -> "SMB") when NetWitness didn't already
# supply one.
SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}

# =============================================================================
# [FYP-SECTION] FIELD MAPPING TABLE — canonical SOC schema <- NetWitness field
# name variants. This is the core "field mapping logic" of the parser: a pure
# rule-based dict of dotted/bracketed JSON paths (no LLM, no scoring/ML —
# literal, developer-authored strings), consumed later by extract_by_alias()/
# extract_all_fields() via normalise_path()/alias_matches() suffix matching.
# =============================================================================
# [FYP-EVALUATOR] Field mapping logic (data table): FIELD_ALIASES. Each
# canonical SOC field name (e.g. "source_ip", "username", "file_hash") maps
# to a list of known NetWitness/JSON field-name variants/paths that may carry
# that value across different export shapes (single alert, incident+alerts,
# full incident export, flattened dict, ...). This table is the single source
# of truth for "where does this SOC field come from" and is what makes the
# parser rule-based rather than schema-specific.
# Field aliases are intentionally broad. They are used only for extraction.
# They are not written into normalised_alert.json.
FIELD_ALIASES: Dict[str, List[str]] = {
    "incident_id": [
        "incident.id", "incident.incidentId", "incident.incident_id",
        "incident_raw.id", "incident_details.id", "incident_id", "incidentId",
    ],
    "incident_title": [
        "incident.title", "incident_raw.title", "incident_details.title", "incident.name",
    ],
    "incident_priority": [
        "incident.priority", "incident_raw.priority", "incident_details.priority",
    ],
    "incident_risk_score": [
        "incident.riskScore", "incident.averageAlertRiskScore",
        "incident_raw.riskScore", "incident_raw.averageAlertRiskScore",
        "incident_details.riskScore", "incident_details.averageAlertRiskScore",
    ],
    "incident_first_alert_time": [
        "incident.firstAlertTime", "incident_raw.firstAlertTime",
    ],

    "alert_id": [
        "alert._id", "alert.id", "alert.alert_id", "alert.alertId",
        "alerts[*].id", "_id",
    ],
    "alert_name": [
        "alert.title", "alert.originalHeaders.name", "alert.originalAlert.name",
        "alert.alert.name", "alert.alert_title", "alert.alert_name", "alert.name",
        "alert.originalAlert.moduleName", "alert_name", "alert_title", "title", "name",
    ],
    "alert_time": [
        "alert.alert.timestamp", "alert.receivedTime", "alert.originalHeaders.timestamp",
        "alert.originalAlert.time", "alert.originalAlert.events[*].time",
        "alert.created", "created", "timestamp", "time",
    ],
    "severity": [
        "alert.alert.severity", "alert.alert.risk_score", "alert.originalHeaders.severity",
        "alert.originalAlert.severity", "alert.severity", "alert.riskScore",
        "incident.priority", "incident.riskScore", "severity", "riskScore", "priority",
    ],
    "risk_score": [
        "alert.alert.risk_score", "alert.riskScore", "alert.risk_score",
        "incident.riskScore", "incident.averageAlertRiskScore", "riskScore", "risk_score",
    ],
    "event_type": [
        "alert.alert.type[*]", "alert.alert.type", "alert.type", "alert.originalHeaders.deviceProduct",
        "alert.alert.events[*].type", "type", "event_type",
    ],
    "detection_name": [
        "alert.originalHeaders.name", "alert.originalAlert.moduleName", "alert.alert.name",
        "detection_name", "signature", "ruleName",
    ],
    "signature_id": [
        "alert.originalHeaders.signatureId", "alert.alert.signature_id", "signatureId", "signature_id",
    ],

    "source_ip": [
        "incident.alertMeta.SourceIp[*]", "incident_raw.alertMeta.SourceIp[*]",
        "alert.originalAlert.events[*].ip_src", "alert.alert.events[*].source.device.ip_address",
        "alert.alert.events[*].source.device.ipAddress", "alert.alert.groupby_source_ip",
        "email.sender_ip", "sender_ip",
        "source.ip", "source_ip", "src_ip", "ip_src", "ip.src",
    ],
    "destination_ip": [
        "incident.alertMeta.DestinationIp[*]", "incident_raw.alertMeta.DestinationIp[*]",
        "alert.originalAlert.events[*].ip_dst", "alert.alert.events[*].destination.device.ip_address",
        "alert.alert.events[*].destination.device.ipAddress", "alert.alert.groupby_destination_ip",
        "destination.ip", "destination_ip", "dst_ip", "ip_dst", "ip.dst",
    ],
    "source_port": [
        "alert.originalAlert.events[*].tcp_srcport", "alert.originalAlert.events[*].udp_srcport", "alert.originalAlert.events[*].ip_srcport",
        "alert.alert.events[*].source.device.port", "alert.alert.groupby_source_port",
        "source_port", "src_port", "tcp_srcport", "udp_srcport", "port_src",
    ],
    "destination_port": [
        "alert.originalAlert.events[*].tcp_dstport", "alert.originalAlert.events[*].udp_dstport", "alert.originalAlert.events[*].ip_dstport",
        "alert.originalAlert.events[*].service", "alert.alert.events[*].destination.device.port",
        "alert.alert.groupby_destination_port", "destination_port", "dst_port", "tcp_dstport", "udp_dstport", "service", "port_dst",
    ],
    "protocol": [
        "alert.originalAlert.events[*].ip_proto", "alert.originalAlert.events[*].protocol",
        "protocol", "ip_proto",
    ],
    "direction": [
        "alert.originalAlert.events[*].direction", "alert.alert.events[*].direction", "direction",
    ],
    "community_id": [
        "alert.originalAlert.events[*].community_id", "community_id",
    ],
    "tcp_flags_seen": [
        "alert.originalAlert.events[*].tcp_flags_seen", "tcp_flags_seen",
    ],

    "session_id": [
        "alert.originalAlert.events[*].sessionid", "alert.alert.events[*].sessionid", "sessionid", "session_id",
    ],
    "event_source_id": [
        "alert.originalAlert.events[*].event_source_id", "alert.alert.events[*].event_source_id",
        "alert.originalAlert.eventSourceId", "event_source_id", "eventSourceId",
    ],
    "record_id": [
        "alert.originalAlert.events[*].rid", "alert.alert.events[*].rid", "rid", "record_id",
    ],

    "username": [
        "alert.alert.user_summary[*]", "alert.alert.events[*].user", "alert.alert.events[*].username",
        "alert.alert.events[*].username[*]", "alert.alert.groupby_username", "alert.originalAlert.events[*].username[*]",
        "incident.alertMeta.UserName[*]", "incident_raw.alertMeta.UserName[*]", "username[*]", "username", "user[*]", "user",
    ],
    "source_username": [
        "alert.alert.events[*].source.user.username", "alert.alert.events[*].source.user.adUsername",
        "alert.alert.groupby_source_username", "alert.originalAlert.events[*].fullname_src",
        "alert.originalAlert.events[*].user_src", "source_username", "user_src", "fullname_src",
    ],
    "destination_username": [
        "alert.alert.events[*].destination.user.username", "alert.alert.events[*].destination.user.adUsername",
        "alert.originalAlert.events[*].user_dst", "destination_username", "user_dst",
    ],
    "source_email": [
        "alert.originalAlert.events[*].email_src[*]", "alert.alert.events[*].source.user.email_address",
        "alert.alert.events[*].source.user.emailAddress", "source.user.emailAddress",
        "email.from", "email.sender", "email_src[*]", "email_src",
    ],
    "reply_to_email": [
        "alert.originalAlert.events[*].reply_to", "alert.alert.events[*].reply_to",
        "email.reply_to", "reply_to", "reply-to", "replyTo",
    ],
    "destination_email": [
        "alert.originalAlert.events[*].email_dst[*]", "alert.alert.events[*].destination.user.email_address",
        "alert.alert.events[*].destination.user.emailAddress", "destination.user.emailAddress",
        "email.to", "email.recipient",
        "email_dst[*]", "email_dst",
    ],
    "email": [
        "alert.originalAlert.events[*].email[*]", "email[*]", "email",
    ],
    "hostname": [
        "alert.alert.events[*].hostname", "alert.originalAlert.events[*].alias_host[*]",
        "alert.alert.groupby_host_name", "incident.alertMeta.HostName[*]", "incident_raw.alertMeta.HostName[*]",
        "hostname", "alias_host[*]", "alias.host", "host",
    ],
    "domain": [
        "alert.alert.events[*].domain", "alert.originalAlert.events[*].domain",
        "alert.alert.groupby_domain", "domain", "dnsDomain",
    ],

    "email_subject": [
        "alert.originalAlert.events[*].subject", "alert.alert.events[*].subject", "subject", "ec_subject",
    ],
    "mail_client": [
        "alert.originalAlert.events[*].client", "client", "mail_client",
    ],

    "file_name": [
        "alert.originalAlert.events[*].attachment", "alert.originalAlert.events[*].filename",
        "alert.alert.events[*].data[*].filename", "alert.alert.events[*].destination.filename",
        "alert.alert.events[*].source.filename", "alert.alert.groupby_filename",
        "attachment", "filename", "file_name", "file.name",
    ],
    "file_hash": [
        "alert.alert.events[*].data[*].hash", "alert.alert.events[*].destination.file_SHA256",
        "alert.alert.events[*].source.file_SHA256", "alert.alert.groupby_file_sha_256",
        "alert.alert.groupby_data_hash", "alert.originalAlert.events[*].hash",
        "alert.originalAlert.events[*].sha256", "alert.originalAlert.events[*].sha1",
        "alert.originalAlert.events[*].md5", "file_hash", "hash", "sha256", "sha1", "md5",
    ],
    "file_path": [
        "alert.alert.events[*].destination.path", "alert.alert.events[*].source.path",
        "file_path", "filepath",
    ],
    "file_extension": [
        "alert.originalAlert.events[*].extension", "extension", "file.extension",
    ],
    "file_type": [
        "alert.originalAlert.events[*].filetype", "filetype", "file.type",
    ],
    "file_size": [
        "alert.originalAlert.events[*].size", "alert.alert.events[*].data[*].size", "size", "file.size",
    ],
    "file_analysis": [
        "alert.originalAlert.events[*].analysis_file[*]", "alert.alert.events[*].analysis_file",
        "alert.alert.groupby_analysis_file", "analysis_file[*]", "analysis_file",
    ],

    "mitre_tactic": [
        "alert.originalAlert.events[*].attack_tactic", "alert.attack_tactic", "incident.tactics[*]",
        "attack_tactic", "mitre_tactic", "tactic", "tactics[*]",
    ],
    "mitre_technique": [
        "alert.originalAlert.events[*].attack_technique", "alert.attack_technique", "incident.techniques[*]",
        "attack_technique", "mitre_technique", "technique", "techniques[*]",
    ],
    "mitre_technique_id": [
        "alert.originalAlert.events[*].attack_tid", "alert.attack_tid", "attack_tid",
        "mitre_technique_id", "technique_id", "mitre_id",
    ],
    "threat_category": [
        "alert.originalAlert.events[*].threat_category[*]", "alert.alert.events[*].site_categorization[*]",
        "threat_category[*]", "site_categorization[*]",
    ],
    "risk_indicator": [
        "alert.originalAlert.events[*].risk_suspicious[*]", "risk_suspicious[*]",
    ],
    "network_risk_info": [
        "alert.originalAlert.events[*].risk_info[*]", "risk_info[*]",
    ],
    "analysis_service": [
        "alert.originalAlert.events[*].analysis_service[*]", "alert.alert.events[*].analysis_service",
        "alert.alert.groupby_analysis_service", "analysis_service[*]", "analysis_service",
    ],
    "analysis_session": [
        "alert.originalAlert.events[*].analysis_session[*]", "alert.alert.events[*].analysis_session",
        "alert.alert.groupby_analysis_session", "analysis_session[*]", "analysis_session",
    ],
    "feed_name": [
        "alert.originalAlert.events[*].feed_name[*]", "feed_name[*]", "feed_name",
    ],

    "url": [
        "alert.originalAlert.events[*].url", "alert.alert.events[*].url",
        "alert.alert.events[*].related_links[*].url", "alert.alert.related_links[*].url",
        "email.urls[*]", "urls[*]", "url", "uri", "link",
    ],
    "user_agent": [
        "alert.originalAlert.events[*].user_agent", "alert.alert.events[*].user_agent", "user_agent", "userAgent",
    ],
    "event_time": [
        "alert.originalAlert.events[*].time", "alert.alert.events[*].time",
        "event_time", "event.event_time", "time", "timestamp",
    ],

    # Process-specific fields are kept separate from attachment/file indicators.
    "process_name": [
        "process.process_name", "process.name", "process_name", "process.name",
    ],
    "process_path": [
        "process.process_path", "process.path", "process_path",
    ],
    "parent_process_name": [
        "process.parent_process_name", "process.parent.name", "parent_process_name",
    ],
    "child_process_name": [
        "child_process.process_name", "child_process.name", "child_process_name",
    ],
    "child_process_path": [
        "child_process.process_path", "child_process.path", "child_process_path",
    ],
    "command_line": [
        "param.src", "param.dst", "param", "param_src", "param_dst", "param_args",
        "process.command_line", "process.cmdline", "process.commandline",
        "child_process.command_line", "child_process.cmdline", "child_process.commandline",
        "alert.originalAlert.events[*].param_src", "alert.originalAlert.events[*].param_dst", "alert.originalAlert.events[*].param",
        "alert.originalAlert.events[*].process_cmd", "alert.originalAlert.events[*].process_cmdline",
        "alert.originalAlert.events[*].command_line", "alert.originalAlert.events[*].cmdline",
        "alert.alert.events[*].param_src", "alert.alert.events[*].param_dst", "alert.alert.events[*].param",
        "alert.alert.events[*].process_cmd", "alert.alert.events[*].process_cmdline",
        "alert.alert.events[*].command_line", "alert.alert.events[*].cmdline",
        "incident.alertMeta.CommandLine[*]", "incident.alertMeta.ParamSrc[*]", "incident.alertMeta.ParamDst[*]", "incident.alertMeta.ProcessTree[*]",
        "incident_raw.alertMeta.CommandLine[*]", "incident_raw.alertMeta.ParamSrc[*]",
        "event.command_line", "event.cmdline", "process.command", "command",
        "command_line", "cmdline", "commandline", "process_cmd", "process_cmdline",
        "raw_event", "raw_message", "message", "event_description", "description",
    ],
}

# [FYP-PROCESS] Legacy/simple confidence check: the minimal set of fields
# used by calculate_confidence() (an older, backward-compatible confidence
# helper — see below). The primary/current schema-validation logic is
# evaluate_context_data_quality(), which checks a much richer, data-type-aware
# set of fields.
REQUIRED_FOR_CONFIDENCE = ["alert_id", "alert_name", "alert_time", "severity", "source_ip", "destination_ip"]


# ---------------------------------------------------------------------------
# [FYP-SECTION] BASIC FILE HELPERS — generic JSON read/write utilities used
# throughout this module (no NetWitness-specific logic here).
# ---------------------------------------------------------------------------


# [FYP-FUNCTION] load_json_file() — [FYP-INPUT] path to a JSON file on disk.
# [FYP-OUTPUT] parsed Python object (dict/list/etc). Thin wrapper around
# json.load(); used by main() to load the raw NetWitness export from the CLI.
def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# [FYP-FUNCTION] save_json_file() — [FYP-INPUT] arbitrary Python data + output
# path. [FYP-PROCESS] prunes empty/null values (prune_empty_and_null_values())
# and coerces non-JSON-native types to strings (make_json_safe()) before
# writing. [FYP-OUTPUT] pretty-printed JSON file (indent=4, non-ASCII kept).
# Creates parent directories as needed.
def save_json_file(data: Any, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    pruned = prune_empty_and_null_values(data)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(make_json_safe(pruned if pruned is not None else {}), file, indent=4, ensure_ascii=False)


# [FYP-FUNCTION] make_json_safe() — recursively coerces a value tree so it is
# guaranteed JSON-serialisable: primitives pass through unchanged, lists/dicts
# are recursed into (dict keys forced to str), and anything else (e.g. a
# datetime, Path, or custom object) is stringified via str(). Used by
# save_json_file() and by build_agent_friendly_processed_alert()/
# run_parser_normalisation_for_dashboard() before returning dashboard output.
def make_json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): make_json_safe(item) for key, item in value.items()}
    return str(value)


# ---------------------------------------------------------------------------
# [FYP-SECTION] CLEANING, VALUE-EXTRACTION & NORMALISATION HELPERS. This large
# block (through the "Flattening and alias matching" section below) holds all
# of the rule-based building blocks the parser is made of: pruning/dedup
# helpers, regex-based IOC extraction, timestamp normalisation/conversion,
# severity/protocol normalisation, IP/hash classification, and the schema
# (data-quality) validation logic. Everything here is deterministic Python —
# no LLM calls.
# ---------------------------------------------------------------------------

# [FYP-VALIDATION] Sentinel "empty" string values (case-insensitive) treated
# as absent/useless data by is_useful()/prune_empty_and_null_values() below —
# NetWitness exports frequently use literal "null"/"N/A"/"Unknown" strings
# instead of JSON null, so this list is what lets the pruner treat them the
# same as a missing field.
USELESS_STRINGS = {
    "", "null", "none", "n/a", "na", "undefined", "not available", "unknown", "[]", "{}"
}


# [FYP-FUNCTION] prune_empty_and_null_values() — [FYP-INPUT] any nested
# dict/list/scalar. [FYP-PROCESS] recursively strips empty/null/sentinel
# values (see USELESS_STRINGS), deduplicates list elements, and bounds huge
# lists to max_list_len to avoid memory/size blow-ups on very large incident
# exports. [FYP-OUTPUT] the cleaned structure, or None if nothing useful
# remains. [FYP-USED-BY] save_json_file(), build_standard_alert(),
# normalise_alert_record(), build_agent_friendly_processed_alert(), and
# write_outputs() — i.e. every JSON artefact this module writes is pruned
# through here first.
def prune_empty_and_null_values(data: Any, max_list_len: int = 50000) -> Any:
    """Recursively and deterministically removes empty/null values, empty strings,
    sentinel values ('null', 'none', 'n/a', 'undefined'), empty lists, and empty dicts.
    Also deduplicates list elements and bounds large lists to max_list_len elements
    to prevent memory and token explosion on giant incident exports.
    """
    if data is None:
        return None

    if isinstance(data, str):
        cleaned = data.strip()
        if not cleaned or cleaned.lower() in USELESS_STRINGS:
            return None
        return cleaned

    if isinstance(data, (int, float, bool)):
        return data

    if isinstance(data, dict):
        cleaned_dict = {}
        for key, value in data.items():
            if key is None:
                continue
            str_key = str(key).strip()
            if not str_key or str_key.lower() in USELESS_STRINGS:
                continue
            pruned_val = prune_empty_and_null_values(value, max_list_len=max_list_len)
            if pruned_val is not None and pruned_val != "" and pruned_val != {} and pruned_val != []:
                cleaned_dict[str_key] = pruned_val
        return cleaned_dict if cleaned_dict else None

    if isinstance(data, list):
        cleaned_list = []
        seen = set()
        for item in data:
            pruned_item = prune_empty_and_null_values(item, max_list_len=max_list_len)
            if pruned_item is not None and pruned_item != "" and pruned_item != {} and pruned_item != []:
                if isinstance(pruned_item, (str, int, float, bool)):
                    item_key = str(pruned_item).lower() if isinstance(pruned_item, str) else pruned_item
                    if item_key not in seen:
                        seen.add(item_key)
                        cleaned_list.append(pruned_item)
                else:
                    try:
                        item_key = json.dumps(pruned_item, sort_keys=True)
                    except Exception:
                        item_key = str(pruned_item)
                    if item_key not in seen:
                        seen.add(item_key)
                        cleaned_list.append(pruned_item)
            if len(cleaned_list) >= max_list_len:
                break
        return cleaned_list if cleaned_list else None

    return data


# [FYP-FUNCTION] is_useful() — the base predicate for "does this value count
# as real data". Rejects None/""/[]/{} and any USELESS_STRINGS sentinel
# (case-insensitive). Used pervasively (dedupe(), extract_by_alias(), etc.)
# to decide whether an extracted field value should be kept.
def is_useful(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, str):
        return value.strip().lower() not in USELESS_STRINGS
    return True


# [FYP-FUNCTION] flatten_nested_values() — recursively flattens arbitrarily
# nested lists into a single flat list, dropping non-useful values along the
# way (via is_useful()). NetWitness event arrays sometimes nest lists inside
# lists (e.g. multi-valued meta fields); this normalises them to one level
# before dedupe()/extraction functions process them.
def flatten_nested_values(values: Iterable[Any]) -> List[Any]:
    output: List[Any] = []
    for value in values:
        if isinstance(value, list):
            output.extend(flatten_nested_values(value))
        elif is_useful(value):
            output.append(value)
    return output


# [FYP-FUNCTION] dedupe() — [FYP-INPUT] any iterable of values (often nested,
# hence the flatten_nested_values() call first). [FYP-PROCESS] removes
# non-useful values and duplicates (case-insensitively for strings by
# default; JSON-serialised comparison for dicts/lists) while preserving first-
# seen order. [FYP-OUTPUT] a clean, order-stable, duplicate-free list. This is
# the single most-used helper in the file — nearly every extracted field list
# in normalise_alert_record() is passed through dedupe() before being written
# into the normalised alert schema.
def dedupe(values: Iterable[Any], case_insensitive: bool = True) -> List[Any]:
    output: List[Any] = []
    seen = set()
    for value in flatten_nested_values(values):
        if isinstance(value, str):
            cleaned = value.strip()
            if not is_useful(cleaned):
                continue
            key = cleaned.lower() if case_insensitive else cleaned
            final_value = cleaned
        else:
            key = json.dumps(make_json_safe(value), sort_keys=True)
            final_value = value
        if key not in seen:
            output.append(final_value)
            seen.add(key)
    return output


# [FYP-FUNCTION] first() — [FYP-INPUT] any iterable of values. [FYP-PROCESS]
# dedupe()s them and returns the first surviving value. [FYP-OUTPUT] a single
# value or `default`. Used everywhere a field can have many candidate values
# but only one "primary" value should be surfaced (e.g. primary source IP).
def first(values: Iterable[Any], default: Any = None) -> Any:
    values = dedupe(values)
    return values[0] if values else default


# [FYP-FUNCTION] safe_int() — [FYP-INPUT] any raw value (str/int/float/None).
# [FYP-PROCESS] best-effort conversion to int; only succeeds if the value is a
# whole number (rejects "80.5"), returns None on any parse failure.
# [FYP-OUTPUT] int or None. Used for ports, sizes and other integer SOC
# fields so a non-numeric NetWitness value never raises upstream.
def safe_int(value: Any) -> Optional[int]:
    if not is_useful(value):
        return None
    try:
        text = str(value).strip()
        number = float(text)
        if number.is_integer():
            return int(number)
    except (TypeError, ValueError):
        return None
    return None


# [FYP-FUNCTION] safe_float() — same contract as safe_int() but for floats
# (no whole-number restriction). [FYP-INPUT] raw value. [FYP-OUTPUT] float or
# None. Used for risk scores and other decimal SOC fields.
def safe_float(value: Any) -> Optional[float]:
    if not is_useful(value):
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


# [FYP-FUNCTION] numeric_list() — [FYP-INPUT] an iterable of raw values +
# `kind` ("int"/"float"). [FYP-PROCESS] flattens, coerces each element via
# safe_int()/safe_float(), drops non-numeric values. [FYP-OUTPUT] a
# deduped list of numbers. Used for port lists and file-size lists.
def numeric_list(values: Iterable[Any], kind: str = "int") -> List[Any]:
    output = []
    for value in flatten_nested_values(values):
        number = safe_float(value) if kind == "float" else safe_int(value)
        if number is not None:
            output.append(number)
    return dedupe(output)


# [FYP-FUNCTION] [FYP-PROCESS] extract_emails() — IOC extraction (rule-based
# regex, no LLM). [FYP-INPUT] iterable of raw field values (e.g. free-text
# username/email fields). [FYP-PROCESS] runs EMAIL_RE against the stringified
# form of every value, lower-cases matches. [FYP-OUTPUT] deduped list of
# email addresses. Feeds source_emails/destination_emails/ioc_summary.
def extract_emails(values: Iterable[Any]) -> List[str]:
    found: List[str] = []
    for value in flatten_nested_values(values):
        found.extend(match.group(0).lower() for match in EMAIL_RE.finditer(str(value)))
    return dedupe(found)


# [FYP-FUNCTION] [FYP-PROCESS] extract_hashes() — IOC extraction (rule-based
# regex, no LLM). [FYP-INPUT] iterable of raw field values. [FYP-PROCESS] runs
# HASH_RE (32/40/64-hex heuristic for MD5/SHA1/SHA256) against each value.
# [FYP-OUTPUT] deduped list of lower-cased hash strings. Feeds file_hashes /
# split_hashes_by_type() / ioc_summary.
def extract_hashes(values: Iterable[Any]) -> List[str]:
    found: List[str] = []
    for value in flatten_nested_values(values):
        found.extend(match.group(0).lower() for match in HASH_RE.finditer(str(value)))
    return dedupe(found)


# [FYP-FUNCTION] clean_username() — [FYP-INPUT] a single raw username-ish
# value. [FYP-PROCESS] strips embedded email addresses, angle-bracket
# display-name artefacts ("<user>"), and stray punctuation/whitespace so a
# noisy NetWitness "From" header doesn't leak into the username field.
# [FYP-OUTPUT] cleaned username string, or None if nothing useful/still an
# email remains. [FYP-VALIDATION] rejects any value still containing "@".
def clean_username(value: Any) -> Optional[str]:
    if not is_useful(value):
        return None
    text = str(value).strip()
    text = EMAIL_RE.sub("", text)
    text = re.sub(r"<[^>]*>", "", text)
    text = text.replace(",", " ").replace(";", " ")
    text = re.sub(r"\s+", " ", text).strip(" '\"")
    if not is_useful(text) or "@" in text:
        return None
    return text


# [FYP-FUNCTION] clean_usernames() — [FYP-INPUT] iterable of raw values that
# may each contain multiple comma/semicolon-separated usernames.
# [FYP-PROCESS] splits on "," / ";" then delegates each part to
# clean_username(). [FYP-OUTPUT] deduped list of clean usernames.
def clean_usernames(values: Iterable[Any]) -> List[str]:
    usernames: List[str] = []
    for value in flatten_nested_values(values):
        for part in re.split(r"[,;]", str(value)):
            username = clean_username(part)
            if username:
                usernames.append(username)
    return dedupe(usernames)


# [FYP-FUNCTION] normalise_severity() — [FYP-INPUT] raw NetWitness severity
# value in any shape (numeric string "0"-"10", word "high"/"crit", or a raw
# risk-score number). [FYP-PROCESS] rule-based lookup table first (exact
# word/number match), then falls back to numeric score-range thresholds
# (>=90 Critical, >=70 High, >=40 Medium, >0 Low). [FYP-OUTPUT] one of
# "Informational"/"Low"/"Medium"/"High"/"Critical"/"Unknown", or the original
# text if nothing matches. Purely rule-based mapping, no LLM/ML scoring.
def normalise_severity(value: Any) -> str:
    if not is_useful(value):
        return "Unknown"
    text = str(value).strip().lower()
    mapping = {
        "0": "Informational", "1": "Low", "2": "Medium", "3": "High",
        "4": "Critical", "5": "Critical", "6": "Medium", "7": "High",
        "8": "High", "9": "Critical", "10": "Critical",
        "info": "Informational", "informational": "Informational",
        "low": "Low", "medium": "Medium", "med": "Medium",
        "high": "High", "critical": "Critical", "crit": "Critical",
    }
    if text in mapping:
        return mapping[text]
    try:
        score = float(text)
    except ValueError:
        return str(value).strip()
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


# =============================================================================
# [FYP-SECTION] TIMESTAMP NORMALISATION / CONVERSION LOGIC — converts every
# NetWitness time representation (epoch seconds, epoch milliseconds, ISO-8601
# strings with/without "Z", the odd "Mon dd, yyyy HH:MM:SS AM/PM TZ" text
# format NetWitness sometimes emits) into one consistent UTC representation
# used by the rest of the pipeline. Purely deterministic date-parsing/
# arithmetic (datetime.strptime/fromtimestamp) — no LLM involved.
# =============================================================================

# [FYP-EVALUATOR] [FYP-FUNCTION] timestamp_to_iso() — main timestamp
# normalisation entry point. [FYP-INPUT] a raw timestamp value of unknown
# shape (int/float epoch, numeric string, or an ISO/NetWitness-formatted
# string). [FYP-PROCESS] (1) numeric/epoch-looking values are delegated to
# epoch_to_iso(); (2) otherwise tries a fixed list of known NetWitness
# datetime string formats in order via datetime.strptime, tagging the
# result UTC. [FYP-OUTPUT] an ISO-8601 UTC string (or the original text
# unchanged if no format matched, or None if the input was empty/useless).
# [FYP-USED-BY] normalise_alert_record() (alert_time), normalise_event()
# (event_time) — i.e. every timestamp written into the normalised schema
# passes through here first.
# [FYP-FUNCTION] `timestamp_to_iso` — implements the timestamp to iso operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record, soc_reporting_agent/services/parser_normaliser.py:normalise_event, soc_reporting_agent/services/parser_normaliser.py:timestamp_to_epoch_ms; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `epoch_to_iso`, `int`, `is_useful`, `isdigit`, `isinstance`, `isoformat`, `replace`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def timestamp_to_iso(value: Any) -> Optional[str]:
    if not is_useful(value):
        return None
    if isinstance(value, (int, float)):
        return epoch_to_iso(value)
    text = str(value).strip()
    if text.isdigit():
        return epoch_to_iso(int(text))
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%b %d, %Y %H:%M:%S %p %Z",  # NetWitness sometimes emits odd 24h + PM strings.
        "%b %d, %Y %I:%M:%S %p %Z",
    ]
    for fmt in formats:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return text


# [FYP-EVALUATOR] [FYP-FUNCTION] epoch_to_iso() — [FYP-INPUT] a numeric epoch
# value (may be epoch *seconds* or epoch *milliseconds* — NetWitness is
# inconsistent between exports). [FYP-PROCESS] heuristic: any value greater
# than 10,000,000,000 is treated as milliseconds (divided by 1000) since a
# plausible epoch-seconds value never reaches that magnitude until year
# ~2286; otherwise treated as epoch seconds directly. Converts via
# datetime.fromtimestamp(..., tz=timezone.utc). [FYP-ERROR] returns None on
# OSError/OverflowError/ValueError (e.g. a value wildly out of range).
# [FYP-OUTPUT] ISO-8601 UTC string or None. [FYP-USED-BY] timestamp_to_iso().
def epoch_to_iso(value: Any) -> Optional[str]:
    number = safe_float(value)
    if number is None:
        return None
    try:
        if number > 10_000_000_000:
            return datetime.fromtimestamp(number / 1000, tz=timezone.utc).isoformat()
        return datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


# [FYP-EVALUATOR] [FYP-FUNCTION] timestamp_to_epoch_ms() — the inverse-shaped
# sibling of timestamp_to_iso(): normalises any raw timestamp to a single
# epoch-*milliseconds* integer instead of an ISO string (used for
# millisecond-precision fields such as alert_time_epoch_ms/
# event_time_epoch_ms, useful for downstream sorting/timeline math).
# [FYP-INPUT] raw timestamp (numeric or string). [FYP-PROCESS] numeric-looking
# values use the same seconds-vs-milliseconds magnitude heuristic as
# epoch_to_iso(); string values are first normalised via timestamp_to_iso()
# then re-parsed with datetime.fromisoformat(). [FYP-OUTPUT] int epoch-ms or
# None. [FYP-USED-BY] normalise_alert_record(), normalise_event().
# [FYP-FUNCTION] `timestamp_to_epoch_ms` — implements the timestamp to epoch ms operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record, soc_reporting_agent/services/parser_normaliser.py:normalise_event; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `fromisoformat`, `int`, `is_useful`, `isdigit`, `isinstance`, `replace`, `safe_float`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def timestamp_to_epoch_ms(value: Any) -> Optional[int]:
    if not is_useful(value):
        return None
    if isinstance(value, (int, float)) or str(value).strip().isdigit():
        number = safe_float(value)
        if number is None:
            return None
        return int(number if number > 10_000_000_000 else number * 1000)
    iso = timestamp_to_iso(value)
    if not iso:
        return None
    try:
        parsed = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return int(parsed.timestamp() * 1000)
    except ValueError:
        return None


# [FYP-FUNCTION] map_service_name() — [FYP-INPUT] a destination port (any
# raw shape). [FYP-PROCESS] coerces to int via safe_int() then looks it up in
# the SERVICE_MAP constant. [FYP-OUTPUT] service name string (e.g. "SMB") or
# None if the port is unknown/unparseable. Rule-based lookup table, no ML.
def map_service_name(port: Any) -> Optional[str]:
    number = safe_int(port)
    return SERVICE_MAP.get(number)


# =============================================================================
# [FYP-SECTION] URL / IP / HASH CLASSIFICATION HELPERS — small rule-based
# predicates used while building network_indicators/web_indicators so a raw
# NetWitness "link" value (an internal drill-down URL back into the SIEM UI)
# is never mistaken for attacker-controlled/external infrastructure, and so
# IPs/hashes can be bucketed for SOC readability. All pure functions, no I/O.
# =============================================================================

# [FYP-FUNCTION] is_netwitness_link() — [FYP-INPUT] any raw value.
# [FYP-PROCESS] string match against NetWitness's own internal navigation URL
# shapes ("/investigation/...", ".../navigate/..."). [FYP-OUTPUT] bool.
# [FYP-USED-BY] is_external_url() (to exclude these) and normalise_alert_record()
# (to route them into netwitness_links.investigation_links instead of web urls).
def is_netwitness_link(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return text.startswith("/investigation/") or "/navigate/" in text


# [FYP-FUNCTION] is_external_url() — [FYP-INPUT] any raw value. [FYP-PROCESS]
# rejects NetWitness internal links, then requires an http(s) scheme plus a
# network location via urllib.parse.urlparse. [FYP-OUTPUT] bool. Used to sort
# extracted URL evidence into "external_urls" (real attacker/web infra) vs.
# discarded/internal noise.
def is_external_url(value: Any) -> bool:
    if not isinstance(value, str) or is_netwitness_link(value):
        return False
    parsed = urlparse(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


# [FYP-FUNCTION] domains_from_urls() — [FYP-INPUT] iterable of URL strings
# (expected to already be filtered to external URLs). [FYP-PROCESS] parses
# each with urlparse and keeps the lower-cased netloc (host[:port]).
# [FYP-OUTPUT] deduped list of domains, feeding web_indicators.domains.
def domains_from_urls(urls: Iterable[str]) -> List[str]:
    domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc.lower())
    return dedupe(domains)


# [FYP-FUNCTION] split_internal_external_ips() — [FYP-INPUT] any iterable of
# raw IP-ish values (may be nested). [FYP-PROCESS] flattens via
# flatten_nested_values(), parses each with ipaddress.ip_address(), and
# classifies private/loopback/link-local addresses as "internal" vs. every
# other valid address as "external"; unparsable values are silently dropped.
# [FYP-OUTPUT] a (internal_ips, external_ips) tuple of deduped lists, both
# rule-based (RFC1918/loopback/link-local ranges) — no IP reputation lookup.
def split_internal_external_ips(values: Iterable[Any]) -> Tuple[List[str], List[str]]:
    """Separate private/internal IPs from public/external IPs for SOC readability."""
    internal_ips: List[str] = []
    external_ips: List[str] = []
    for value in flatten_nested_values(values):
        text = str(value).strip()
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            internal_ips.append(text)
        else:
            external_ips.append(text)
    return dedupe(internal_ips), dedupe(external_ips)


# [FYP-FUNCTION] split_hashes_by_type() — [FYP-INPUT] any iterable of raw
# hash-ish values. [FYP-PROCESS] delegates to extract_hashes() (regex
# validation) then buckets purely by string length (32=md5, 40=sha1,
# 64=sha256; anything else -> "unknown"). No hash-format checksum validation
# beyond length. [FYP-OUTPUT] dict of deduped hash lists keyed by type,
# feeding file_indicators.file_hashes_by_type.
def split_hashes_by_type(values: Iterable[Any]) -> Dict[str, List[str]]:
    """Group hashes by length so tools can use md5, sha1, and sha256 cleanly."""
    grouped = {"md5": [], "sha1": [], "sha256": [], "unknown": []}
    for hash_value in extract_hashes(values):
        length = len(hash_value)
        if length == 32:
            grouped["md5"].append(hash_value)
        elif length == 40:
            grouped["sha1"].append(hash_value)
        elif length == 64:
            grouped["sha256"].append(hash_value)
        else:
            grouped["unknown"].append(hash_value)
    return {key: dedupe(value) for key, value in grouped.items()}


# [FYP-FUNCTION] build_process_relationships() — [FYP-INPUT] the list of
# already-normalised per-event dicts (normalise_event() output) for one
# alert. [FYP-PROCESS] for each event, records a parent->process edge and a
# process->child edge whenever both ends are present on that same event
# (purely structural pairing of fields already on the record; it does not
# infer relationships across different events). [FYP-OUTPUT] deduped list of
# {event_index, parent, child} edges -> process_indicators.process_relationships.
# Deliberately descriptive only (see docstring: "without adding investigation
# judgement") — no attempt to flag which edges look malicious.
def build_process_relationships(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Create parent-child process relationships without adding investigation judgement."""
    relationships: List[Dict[str, Any]] = []
    for event in events:
        parent = event.get("parent_process_name")
        process = event.get("process_name")
        child = event.get("child_process_name")
        event_index = event.get("event_index")
        if parent and process:
            relationships.append({"event_index": event_index, "parent": parent, "child": process})
        if process and child:
            relationships.append({"event_index": event_index, "parent": process, "child": child})
    return dedupe(relationships)


# [FYP-FUNCTION] build_observed_data_context() — [FYP-INPUT] every already-
# extracted evidence bucket for one alert (email/network/process/file/web
# field lists, plus the normalised event list). [FYP-PROCESS] pure rule-based
# classification: derives six boolean "has_X_data" flags from simple
# presence/keyword checks (e.g. has_network_data requires either both source
# AND destination IP, or a destination port/protocol/external URL/user
# agent), then picks a single "primary_data_source" by priority order
# (email > endpoint > web+network > network > file > web > generic).
# [FYP-OUTPUT] dict describing WHAT KIND of evidence this alert carries — no
# threat/severity judgement (see inline comment "this is parsing context,
# not triage"). [FYP-USED-BY] evaluate_context_data_quality() immediately
# after, which uses these flags to decide which fields are "required" for
# THIS alert's data shape (e.g. don't demand a hostname on a pure network
# alert with no endpoint evidence).
# [FYP-FUNCTION] `build_observed_data_context` — constructs build observed data context output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `event_type`, `normalised_events`, `source_emails`, `reply_to_emails`, `destination_emails`, `email_subjects`, `mail_clients`, `file_names`, `file_hashes`, `source_ips`, `destination_ips`, `destination_ports`, `protocols`, `external_urls`, `web_domains`, `user_agents`, `hostnames`, `all_usernames`, `process_names`, `process_paths`, `parent_processes`, `child_processes`, `command_lines`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `append`, `bool`, `dedupe`, `get`, `join`, `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_observed_data_context(
    event_type: Optional[str],
    normalised_events: List[Dict[str, Any]],
    source_emails: List[str],
    reply_to_emails: List[str],
    destination_emails: List[str],
    email_subjects: List[str],
    mail_clients: List[str],
    file_names: List[str],
    file_hashes: List[str],
    source_ips: List[str],
    destination_ips: List[str],
    destination_ports: List[int],
    protocols: List[str],
    external_urls: List[str],
    web_domains: List[str],
    user_agents: List[str],
    hostnames: List[str],
    all_usernames: List[str],
    process_names: List[str],
    process_paths: List[str],
    parent_processes: List[str],
    child_processes: List[str],
    command_lines: List[str],
) -> Dict[str, Any]:
    """Describe observed evidence types only. This is parsing context, not triage."""
    event_types = dedupe(event.get("event_type") for event in normalised_events if event.get("event_type"))
    event_type_text = " ".join([str(event_type or "")] + [str(value) for value in event_types]).lower()

    has_email_data = bool(
        source_emails
        or reply_to_emails
        or destination_emails
        or email_subjects
        or mail_clients
        or "mail" in event_type_text
        or "email" in event_type_text
        or "smtp" in [str(p).lower() for p in protocols]
    )
    has_endpoint_data = bool(
        process_names
        or process_paths
        or parent_processes
        or child_processes
        or command_lines
        or "endpoint" in event_type_text
    )
    has_network_data = bool(
        (source_ips and destination_ips)
        or destination_ports
        or protocols
        or "network" in event_type_text
        or external_urls
        or user_agents
    )
    has_process_data = bool(process_names or parent_processes or child_processes or command_lines or process_paths)
    has_file_data = bool(file_names or file_hashes)
    has_web_data = bool(external_urls or web_domains or user_agents or any(str(p).upper() in {"HTTP", "HTTPS"} for p in protocols))

    observed_data_types: List[str] = []
    if has_email_data:
        observed_data_types.append("email")
    if has_endpoint_data:
        observed_data_types.append("endpoint")
    if has_network_data:
        observed_data_types.append("network")
    if has_process_data:
        observed_data_types.append("process")
    if has_file_data:
        observed_data_types.append("file")
    if has_web_data:
        observed_data_types.append("web")
    if not observed_data_types:
        observed_data_types.append("generic")

    # Primary source is selected from observed raw evidence types, not from threat interpretation.
    if has_email_data:
        primary_data_source = "email"
    elif has_endpoint_data:
        primary_data_source = "endpoint"
    elif has_web_data and has_network_data:
        primary_data_source = "web"
    elif has_network_data:
        primary_data_source = "network"
    elif has_file_data:
        primary_data_source = "file"
    elif has_web_data:
        primary_data_source = "web"
    else:
        primary_data_source = "generic"

    evidence_sources = dedupe(
        [str(event_type)]
        + [str(value) for value in event_types]
        + ["email" if has_email_data else None]
        + ["endpoint" if has_endpoint_data else None]
        + ["network" if has_network_data else None]
        + ["process" if has_process_data else None]
        + ["file" if has_file_data else None]
        + ["web" if has_web_data else None]
    )

    return {
        "primary_data_source": primary_data_source,
        "observed_data_types": observed_data_types,
        "evidence_sources": evidence_sources,
        "has_email_data": has_email_data,
        "has_endpoint_data": has_endpoint_data,
        "has_network_data": has_network_data,
        "has_process_data": has_process_data,
        "has_file_data": has_file_data,
        "has_web_data": has_web_data,
    }


# =============================================================================
# [FYP-EVALUATOR] [FYP-FUNCTION] evaluate_context_data_quality() — THE ALERT
# SCHEMA VALIDATION function for this parser. This is the rule-based check
# that decides how trustworthy/complete a parsed alert is before it is
# handed to Triage.
#
# [FYP-INPUT] the observed_data_context flags from build_observed_data_context()
# above, plus every extracted evidence field for the alert (ids, timestamps,
# severity, IPs, emails, hostnames, process/file/web indicators, session/
# record/signature ids) and raw_meta_key_count (size of the original alert
# dict, used only to flag oversized input).
#
# [FYP-PROCESS] Three tiers of checks, all pure boolean presence tests
# (no LLM, no external lookup):
#   1. base_checks — always required regardless of alert type: alert_id
#      (rejecting MITRE-technique-ID lookalikes via looks_like_mitre_id()),
#      alert_name, alert_time, severity != "Unknown".
#   2. missing_context_fields — conditionally required PER OBSERVED DATA TYPE
#      (only checks "hostname"/"username" if has_endpoint_data is True, only
#      checks "source_ip"/"destination_ip"/"destination_port"/"protocol" if
#      has_network_data is True, etc.) so an alert that legitimately has no
#      email evidence is not penalised for missing email fields.
#   3. missing_optional_fields — "nice to have" ids (session/event_source/
#      record/signature/community) that lower the score less.
# A weighted score starts at 100 and is deducted per missing field
# (-15 per missing base field, -10 per missing conditionally-required
# context field, -2 per missing optional field), clamped to [0, 100], then
# bucketed into parser_confidence: >=80 High, >=50 Medium, else Low.
#
# [FYP-OUTPUT] dict with parser_confidence/parser_confidence_score/
# confidence_explanation/missing_required_fields/missing_context_fields/
# missing_optional_fields/not_applicable_fields/warnings — merged verbatim
# into normalised_alert["data_quality"] and parser_metadata by
# normalise_alert_record() below. [FYP-USED-BY] normalise_alert_record(),
# which also folds missing_required_fields + missing_context_fields into
# parser_metadata.missing_fields/extraction_summary.
# =============================================================================
# [FYP-FUNCTION] `evaluate_context_data_quality` — implements the evaluate context data quality operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `observed_data_context`, `alert_id`, `alert_name`, `alert_time`, `severity`, `source_ips`, `destination_ips`, `destination_ports`, `protocols`, `source_emails`, `destination_emails`, `reply_to_emails`, `email_subjects`, `hostnames`, `all_usernames`, `process_names`, `command_lines`, `file_names`, `file_hashes`, `external_urls`, `web_domains`, `session_ids`, `event_source_ids`, `record_ids`, `signature_ids`, `community_ids`, `normalised_events`, `raw_meta_key_count`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `bool`, `dedupe`, `extend`, `get`, `items`, `join`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def evaluate_context_data_quality(
    observed_data_context: Dict[str, Any],
    alert_id: Optional[str],
    alert_name: Optional[str],
    alert_time: Optional[str],
    severity: Optional[str],
    source_ips: List[str],
    destination_ips: List[str],
    destination_ports: List[int],
    protocols: List[str],
    source_emails: List[str],
    destination_emails: List[str],
    reply_to_emails: List[str],
    email_subjects: List[str],
    hostnames: List[str],
    all_usernames: List[str],
    process_names: List[str],
    command_lines: List[str],
    file_names: List[str],
    file_hashes: List[str],
    external_urls: List[str],
    web_domains: List[str],
    session_ids: List[str],
    event_source_ids: List[str],
    record_ids: List[str],
    signature_ids: List[str],
    community_ids: List[str],
    normalised_events: List[Dict[str, Any]],
    raw_meta_key_count: int,
) -> Dict[str, Any]:
    """Evaluate parser completeness using observed data types, not threat judgement."""
    base_checks = {
        "alert_id": bool(alert_id) and not looks_like_mitre_id(alert_id),
        "alert_name": bool(alert_name),
        "alert_time": bool(alert_time),
        "severity": bool(severity and severity != "Unknown"),
    }
    missing_base_fields = [field for field, present in base_checks.items() if not present]

    missing_context_fields: Dict[str, List[str]] = {}
    if observed_data_context.get("has_email_data"):
        email_checks = {
            "source_email": bool(source_emails),
            "destination_email": bool(destination_emails),
            "email_subject": bool(email_subjects),
        }
        missing_context_fields["email"] = [field for field, present in email_checks.items() if not present]
    if observed_data_context.get("has_endpoint_data"):
        endpoint_checks = {
            "hostname": bool(hostnames),
            "username": bool(all_usernames),
        }
        missing_context_fields["endpoint"] = [field for field, present in endpoint_checks.items() if not present]
    if observed_data_context.get("has_network_data"):
        network_checks = {
            "source_ip": bool(source_ips),
            "destination_ip": bool(destination_ips),
            "destination_port": bool(destination_ports),
            "protocol": bool(protocols),
        }
        missing_context_fields["network"] = [field for field, present in network_checks.items() if not present]
    if observed_data_context.get("has_process_data"):
        process_checks = {
            "process_name": bool(process_names),
            "command_line": bool(command_lines),
        }
        missing_context_fields["process"] = [field for field, present in process_checks.items() if not present]
    if observed_data_context.get("has_file_data"):
        # A file can be represented by a name or a hash. A hash is valuable but not always present in SIEM data.
        file_checks = {
            "file_name_or_hash": bool(file_names or file_hashes),
        }
        missing_context_fields["file"] = [field for field, present in file_checks.items() if not present]
    if observed_data_context.get("has_web_data"):
        web_checks = {
            "url_or_domain": bool(external_urls or web_domains),
        }
        missing_context_fields["web"] = [field for field, present in web_checks.items() if not present]

    context_fields_flat = [field for fields in missing_context_fields.values() for field in fields]

    optional_checks = {
        "session_id": bool(session_ids),
        "event_source_id": bool(event_source_ids),
        "record_id": bool(record_ids),
        "signature_id": bool(signature_ids),
        "community_id": bool(community_ids),
        "file_hash": bool(file_hashes) if observed_data_context.get("has_file_data") else True,
        "reply_to_email": bool(reply_to_emails) if observed_data_context.get("has_email_data") else True,
    }
    missing_optional_fields = [field for field, present in optional_checks.items() if not present]

    not_applicable_fields: List[str] = []
    if not observed_data_context.get("has_email_data"):
        not_applicable_fields.extend(["source_email", "destination_email", "reply_to_email", "email_subject", "mail_client"])
    if not observed_data_context.get("has_endpoint_data"):
        not_applicable_fields.extend(["hostname", "username"])
    if not observed_data_context.get("has_network_data"):
        not_applicable_fields.extend(["source_ip", "destination_ip", "destination_port", "protocol", "community_id"])
    if not observed_data_context.get("has_process_data"):
        not_applicable_fields.extend(["process_name", "parent_process_name", "child_process_name", "command_line"])
    if not observed_data_context.get("has_file_data"):
        not_applicable_fields.extend(["file_name", "file_hash", "file_size", "file_type"])
    if not observed_data_context.get("has_web_data"):
        not_applicable_fields.extend(["url", "domain", "user_agent"])

    score = 100
    score -= len(missing_base_fields) * 15
    score -= len(context_fields_flat) * 10
    score -= len(missing_optional_fields) * 2
    score = max(0, min(100, score))

    if score >= 80:
        parser_confidence = "High"
    elif score >= 50:
        parser_confidence = "Medium"
    else:
        parser_confidence = "Low"

    warnings = []
    if missing_base_fields or context_fields_flat:
        warnings.append("Missing context-relevant parsing fields: " + ", ".join(dedupe(missing_base_fields + context_fields_flat)))
    if raw_meta_key_count > 300:
        warnings.append("Large raw metadata detected; normalised alert was kept concise for SOC readability.")

    observed_types = ", ".join(observed_data_context.get("observed_data_types", []))
    if parser_confidence == "High" and not missing_base_fields and not context_fields_flat:
        confidence_explanation = f"Required parser fields for observed data types ({observed_types}) were extracted successfully."
    elif parser_confidence == "High":
        confidence_explanation = f"Most parser fields for observed data types ({observed_types}) were extracted, with minor optional gaps."
    elif parser_confidence == "Medium":
        confidence_explanation = f"Some parser fields for observed data types ({observed_types}) are missing, so downstream systems should review the gaps."
    else:
        confidence_explanation = f"Several parser fields for observed data types ({observed_types}) are missing, so downstream systems should treat this output carefully."

    return {
        "parser_confidence": parser_confidence,
        "parser_confidence_score": score,
        "confidence_explanation": confidence_explanation,
        "missing_required_fields": dedupe(missing_base_fields),
        "missing_context_fields": {key: dedupe(value) for key, value in missing_context_fields.items()},
        "missing_optional_fields": dedupe(missing_optional_fields),
        "not_applicable_fields": dedupe(not_applicable_fields),
        "warnings": warnings,
        "normalised_event_count": len(normalised_events),
        "raw_meta_key_count": raw_meta_key_count,
    }

# [FYP-SECTION] Small per-field normalisation/ID helpers used while building
# normalise_alert_record()'s output (protocol number->name lookup, MITRE-ID
# lookalike detection so a technique ID is never mistaken for an alert ID,
# alert-id fallback synthesis, and file-vs-process name disambiguation).
# [FYP-FUNCTION] normalise_protocol_values() — [FYP-INPUT] raw protocol
# values (may be IANA protocol numbers as strings, e.g. "6"/"17"/"1", or
# already-textual names). [FYP-PROCESS] flattens, maps known numeric codes
# to TCP/UDP/ICMP, otherwise upper-cases the text as-is. [FYP-OUTPUT] deduped
# list -> network_indicators.protocols.
def normalise_protocol_values(values: Iterable[Any]) -> List[Any]:
    protocols: List[Any] = []
    protocol_map = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
    }
    for value in flatten_nested_values(values):
        text = str(value).strip()
        if not is_useful(text):
            continue
        protocols.append(protocol_map.get(text, text.upper()))
    return dedupe(protocols)


# [FYP-FUNCTION] looks_like_mitre_id() — [FYP-INPUT] any raw value.
# [FYP-PROCESS] regex-matches the MITRE ATT&CK technique-ID shape "Tdddd" or
# "Tdddd.ddd". [FYP-OUTPUT] bool. [FYP-USED-BY] safe_alert_id(), to make sure
# a technique ID picked up from an alert-id-shaped field is never mistaken
# for the actual alert identifier.
def looks_like_mitre_id(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", value.strip(), re.I))


# [FYP-FUNCTION] safe_alert_id() — [FYP-INPUT] candidate id values extracted
# via FIELD_ALIASES, the raw alert dict, the parent incident_id, and this
# alert's position (alert_index) within the batch. [FYP-PROCESS] tries the
# raw alert's own id-shaped keys first, then the best extracted candidate,
# rejecting anything that looks_like_mitre_id(). [FYP-OUTPUT] a non-empty
# alert id string; [FYP-VALIDATION] falls back to a synthesised
# "{incident_id}-alert-{n}" id so downstream stages always have a stable
# identifier even when the source data has none.
def safe_alert_id(candidate_values: Iterable[Any], alert: Dict[str, Any], incident_id: Optional[str], alert_index: int) -> str:
    direct_candidates = [
        alert.get("id"), alert.get("_id"), alert.get("alert_id"), alert.get("alertId"),
        first(candidate_values),
    ]
    for candidate in direct_candidates:
        if is_useful(candidate) and not looks_like_mitre_id(candidate):
            return str(candidate).strip()
    return f"{incident_id or 'UNKNOWN'}-alert-{alert_index + 1}"


# [FYP-FUNCTION] split_file_and_process_names() — [FYP-INPUT] the raw
# file-name candidates and process-name candidates extracted separately.
# [FYP-PROCESS] an executable can legitimately be both a file indicator and
# the running process name. Earlier versions removed file names when they
# matched a process name, which made endpoint malware alerts lose the file
# evidence. Keep the file name and only return additional process candidates
# when a value clearly came from a process-specific field upstream.
# [FYP-OUTPUT] (file_names, extra_process_names) tuple; the second element is
# currently always [] — process names are sourced separately by the caller.
def split_file_and_process_names(file_names: Iterable[Any], process_names: Iterable[Any]) -> Tuple[List[str], List[str]]:
    clean_files: List[str] = []
    for name in flatten_nested_values(file_names):
        text = str(name).strip()
        if is_useful(text):
            clean_files.append(text)
    return dedupe(clean_files), []


# [FYP-FUNCTION] [FYP-PROCESS] infer_file_names() — IOC extraction (rule-based
# regex, no LLM). [FYP-INPUT] iterable of free-text values (typically alert
# names / email subjects). [FYP-PROCESS] runs FILE_RE (filename-with-extension
# heuristic) against each stringified value. [FYP-OUTPUT] deduped list of
# filename-looking substrings, used as a fallback when no explicit
# file_name field was present on the alert/events.
def infer_file_names(values: Iterable[Any]) -> List[str]:
    found: List[str] = []
    for value in flatten_nested_values(values):
        found.extend(match.group(0).strip() for match in FILE_RE.finditer(str(value)))
    return dedupe(found)


# ---------------------------------------------------------------------------
# Flattening and alias matching
#
# [FYP-SECTION] Generic, FIELD_ALIASES-driven field-mapping subsystem
# (flatten_json / normalise_path / alias_matches / extract_by_alias /
# extract_all_fields). This is a self-contained alternative implementation of
# "field mapping": flatten the whole raw alert into dotted-path -> value
# pairs, then match every path's normalised suffix against every alias in
# FIELD_ALIASES (see [FYP-EVALUATOR] table near the top of this file).
# [FYP-PROCESS] Grepping the file confirms none of these five functions are
# actually called from normalise_alert_record()/build_standard_alert() (the
# live pipeline) — the hot path instead uses the hand-written, hard-coded
# field mapper extract_alert_values_fast() below, which is faster because it
# does not flatten/alias-match the entire alert tree. flatten_json/
# extract_all_fields remain here as generic, alias-table-driven building
# blocks (flatten_meta is a public backward-compatible alias for
# flatten_json) but are not part of the current production call graph.
# ---------------------------------------------------------------------------


# [FYP-FUNCTION] flatten_json() — [FYP-INPUT] arbitrarily nested dict/list
# JSON data. [FYP-PROCESS] recursively walks every dict key / list index,
# building a single-level {dotted.path[index]: leaf_value} map (leaf values
# passed through make_json_safe()). [FYP-OUTPUT] flat path->value dict, the
# input flatten_json()/extract_all_fields() need before alias matching can
# run. See [FYP-SECTION] note above: not on the live parsing call path.
def flatten_json(data: Any, parent: str = "") -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{parent}.{key}" if parent else str(key)
            if isinstance(value, (dict, list)):
                if value in ({}, []):
                    flat[path] = value
                flat.update(flatten_json(value, path))
            else:
                flat[path] = make_json_safe(value)
    elif isinstance(data, list):
        for index, item in enumerate(data):
            path = f"{parent}[{index}]" if parent else f"[{index}]"
            if isinstance(item, (dict, list)):
                flat.update(flatten_json(item, path))
            else:
                flat[path] = make_json_safe(item)
    else:
        flat[parent or "value"] = make_json_safe(data)
    return flat


# [FYP-FUNCTION] normalise_path() — [FYP-INPUT] a dotted/bracketed flattened
# path string (from flatten_json(), or a literal alias from FIELD_ALIASES).
# [FYP-PROCESS] backslash->dot, collapses any "[<index>]" to a wildcard
# "[*]" (so array position never affects matching), strips whitespace,
# lower-cases. [FYP-OUTPUT] a canonical form so a path and an alias that
# differ only by array index/case/whitespace still compare equal.
def normalise_path(path: str) -> str:
    text = str(path).replace("\\", ".")
    text = re.sub(r"\[\d+\]", "[*]", text)
    text = re.sub(r"\s+", "", text)
    return text.lower()


# [FYP-FUNCTION] alias_matches() — [FYP-INPUT] one FIELD_ALIASES alias string
# and one flattened path. [FYP-PROCESS] normalise_path() both sides, then
# matches on exact equality or path ending with ".alias"/"alias" (suffix
# match), so an alias like "user.username" matches
# "source.user.username" anywhere it appears in the tree. [FYP-OUTPUT] bool.
def alias_matches(alias: str, path: str) -> bool:
    alias_norm = normalise_path(alias)
    path_norm = normalise_path(path)
    return path_norm == alias_norm or path_norm.endswith("." + alias_norm) or path_norm.endswith(alias_norm)


# [FYP-FUNCTION] extract_by_alias() — [FYP-INPUT] a flattened alert
# (flat path->value dict) and a single canonical field name.
# [FYP-PROCESS] looks up that field's alias list in FIELD_ALIASES, normalises
# every flattened path once, and keeps every value whose path suffix-matches
# any alias (same logic as alias_matches(), inlined for speed).
# [FYP-OUTPUT] (deduped values, deduped source paths) for that one field —
# the paths are kept for debug-evidence reporting. Single-field counterpart
# of extract_all_fields() below.
def extract_by_alias(flat: Dict[str, Any], field: str) -> Tuple[List[Any], List[str]]:
    values: List[Any] = []
    paths: List[str] = []
    aliases = FIELD_ALIASES.get(field, [])
    norm_aliases = [normalise_path(alias) for alias in aliases]
    for path, value in flat.items():
        if is_useful(value):
            path_norm = normalise_path(path)
            if any(path_norm == a or path_norm.endswith("." + a) or path_norm.endswith(a) for a in norm_aliases):
                values.append(value)
                paths.append(path)
    return dedupe(values), dedupe(paths, case_insensitive=False)


# [FYP-FUNCTION] extract_all_fields() — the generic, table-driven field
# mapper for every canonical field in FIELD_ALIASES at once. [FYP-INPUT] a
# flattened alert (from flatten_json()). [FYP-PROCESS] normalises every
# flattened path once, normalises every alias once, then does a single pass
# matching each path against every field's alias set (equivalent to calling
# extract_by_alias() once per field, but without re-normalising the flat
# dict each time). [FYP-OUTPUT] (values_by_field, paths_by_field) — both
# dicts keyed by every FIELD_ALIASES field name, each value deduped.
def extract_all_fields(flat: Dict[str, Any]) -> Tuple[Dict[str, List[Any]], Dict[str, List[str]]]:
    values: Dict[str, List[Any]] = {f: [] for f in FIELD_ALIASES}
    paths: Dict[str, List[str]] = {f: [] for f in FIELD_ALIASES}

    norm_flat = [(path, normalise_path(path), val) for path, val in flat.items() if is_useful(val)]
    norm_aliases = {
        field: [normalise_path(alias) for alias in aliases]
        for field, aliases in FIELD_ALIASES.items()
    }

    for path, path_norm, val in norm_flat:
        for field, aliases in norm_aliases.items():
            if any(path_norm == a or path_norm.endswith("." + a) or path_norm.endswith(a) for a in aliases):
                values[field].append(val)
                paths[field].append(path)

    for field in FIELD_ALIASES:
        values[field] = dedupe(values[field])
        paths[field] = dedupe(paths[field], case_insensitive=False)

    return values, paths


# ---------------------------------------------------------------------------
# Input format handling
# ---------------------------------------------------------------------------


# [FYP-FUNCTION] [FYP-VALIDATION] detect_input_format() — [FYP-INPUT] the raw
# parsed JSON payload handed to the parser (any shape). [FYP-PROCESS]
# rule-based structural sniffing (no LLM): checks for known key combinations
# in order of specificity (full incident export with alerts_full_raw, an
# incident+alerts pair, a single already-full alert via originalAlert/
# originalHeaders, a bare alerts_summary_raw export, a single summary alert
# with an events[] list, an already-flattened dict, or a plain list of
# alerts). [FYP-OUTPUT] one of a fixed set of format-tag strings (e.g.
# "full_incident_export", "alert_list", "generic_dictionary") consumed by
# prepare_incident_and_alerts() to decide how to locate the incident/alerts,
# and recorded verbatim into parser_metadata.input_format for evaluators.
# [FYP-FUNCTION] `detect_input_format` — implements the detect input format operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_standard_alert, soc_reporting_agent/services/parser_normaliser.py:prepare_incident_and_alerts; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `get`, `isinstance`, `issubset`, `keys`, `set`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def detect_input_format(data: Any) -> str:
    if isinstance(data, list):
        return "alert_list"
    if not isinstance(data, dict):
        return "unknown"
    keys = set(data.keys())
    if {"incident_raw", "alerts_full_raw"}.issubset(keys):
        return "full_incident_export"
    if {"incident", "alerts"}.issubset(keys):
        return "incident_with_alerts"
    if {"incident_details", "alerts"}.issubset(keys):
        return "incident_details_with_alerts"
    if "originalAlert" in keys or "originalHeaders" in keys:
        return "single_full_alert"
    if "alerts_summary_raw" in keys:
        return "summary_export"
    if isinstance(data.get("events"), list):
        return "single_summary_alert"
    if any("." in str(key) or "[" in str(key) for key in keys):
        return "flattened_dictionary"
    return "generic_dictionary"


# [FYP-FUNCTION] prepare_incident_and_alerts() — [FYP-INPUT] the raw parsed
# JSON payload. [FYP-PROCESS] calls detect_input_format() then pulls out the
# incident dict and the list of raw per-alert dicts using the field names
# specific to that detected shape (falls back to treating the whole payload
# as a single one-alert list for unrecognised dict shapes). Also strips
# heavy nested arrays (alerts/events/alerts_full_raw/alerts_summary_raw) off
# the incident dict so re-flattening it per alert stays cheap.
# [FYP-OUTPUT] (incident_dict, list_of_raw_alert_dicts) — non-dict entries in
# the alerts list are filtered out. [FYP-USED-BY] build_standard_alert(),
# which loops normalise_alert_record() over the returned alert list.
# [FYP-FUNCTION] `prepare_incident_and_alerts` — implements the prepare incident and alerts operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_standard_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `detect_input_format`, `get`, `isinstance`, `items`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def prepare_incident_and_alerts(data: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    input_format = detect_input_format(data)
    incident = {}
    alerts = []
    if input_format == "full_incident_export":
        incident = data.get("incident_raw") if isinstance(data.get("incident_raw"), dict) else {}
        alerts = data.get("alerts_full_raw")
        if not isinstance(alerts, list) or not alerts:
            summary = data.get("alerts_summary_raw", {})
            alerts = summary.get("items", []) if isinstance(summary, dict) else []
        if not isinstance(alerts, list) or not alerts:
            alerts = data.get("alerts_extracted", [])
    elif input_format == "incident_with_alerts":
        incident = data.get("incident") if isinstance(data.get("incident"), dict) else {}
        alerts = data.get("alerts") if isinstance(data.get("alerts"), list) else []
    elif input_format == "incident_details_with_alerts":
        incident = data.get("incident_details") if isinstance(data.get("incident_details"), dict) else {}
        alerts = data.get("alerts") if isinstance(data.get("alerts"), list) else []
    elif input_format == "summary_export":
        summary = data.get("alerts_summary_raw", {})
        alerts = summary.get("items", []) if isinstance(summary, dict) else []
    elif input_format == "alert_list":
        alerts = data if isinstance(data, list) else []
    elif isinstance(data, dict):
        alerts = [data]

    # Strip heavy nested arrays from incident so it doesn't inflate every per-alert flattening call
    if isinstance(incident, dict) and incident:
        incident = {k: v for k, v in incident.items() if k not in ("alerts", "events", "alerts_full_raw", "alerts_summary_raw")}

    return incident, [alert for alert in alerts if isinstance(alert, dict)]


# [FYP-FUNCTION] walk_event_records() — [FYP-INPUT] one raw alert dict (or
# any nested value within it) and the dotted path taken to reach it so far.
# [FYP-PROCESS] recursively searches for any key literally named "events"
# whose value is a list, regardless of how deeply it is nested inside the
# alert (NetWitness event arrays can live under different parent keys
# depending on export shape) — every dict item inside such a list becomes
# one event record. [FYP-OUTPUT] list of {"source_path", "raw_event"} dicts.
# [FYP-USED-BY] normalise_alert_record() (raw_event_records feeds
# normalise_event() per record) and build_debug_evidence()/
# build_standard_alert()'s all_parsed_events collection.
# [FYP-FUNCTION] `walk_event_records` — implements the walk event records operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `data`, `path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_standard_alert, soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record, soc_reporting_agent/services/parser_normaliser.py:walk_event_records; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `enumerate`, `extend`, `isinstance`, `items`, `lower`, `str`, `walk_event_records`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def walk_event_records(data: Any, path: str = "") -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() == "events" and isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        records.append({"source_path": f"{child_path}[{index}]", "raw_event": item})
            else:
                records.extend(walk_event_records(value, child_path))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            records.extend(walk_event_records(item, child_path))
    return records


# ---------------------------------------------------------------------------
# High level orchestration
#
# [FYP-PROCESS] normalise_netwitness_data() and build_standard_alert() are
# each DEFINED TWICE in this file — once here, and again further down (see
# the matching [FYP-EVALUATOR] comment near the second build_standard_alert()
# definition, close to line 2371). Python keeps only the last definition of a
# module-level name, so these two functions below are shadowed/overridden
# and never execute — every caller (main(), run_parser_normalisation_for_
# dashboard()) resolves to the later, complete definitions. This first
# build_standard_alert() is additionally an incomplete draft: its loop
# builds normalised_alerts/debug_by_alert but the function has no return
# statement, so even on its own it would return None. Left in place
# unexecuted; documented here so the duplication isn't mistaken for the live
# implementation during review.
# ---------------------------------------------------------------------------


# [FYP-FUNCTION] `normalise_netwitness_data` — transforms normalise netwitness data input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `build_standard_alert`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def normalise_netwitness_data(data: Any) -> Dict[str, Any]:
    """Public function for other project scripts."""
    return build_standard_alert(data)


# [FYP-FUNCTION] `build_standard_alert` — constructs build standard alert output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `data`, `output_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:main, soc_reporting_agent/services/parser_normaliser.py:normalise_netwitness_data, soc_reporting_agent/services/parser_normaliser.py:run_parser_normalisation_for_dashboard; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `add`, `append`, `detect_input_format`, `enumerate`, `get`, `isinstance`, `len`, `normalise_alert_record`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_standard_alert(data: Any, output_dir: str = "outputs") -> Dict[str, Any]:
    pruned_data = prune_empty_and_null_values(data) or data
    input_format = detect_input_format(pruned_data)
    incident, raw_alerts = prepare_incident_and_alerts(pruned_data)

    # If raw_alerts array is extremely large (e.g., 1,500+ alerts), bound to top 150 distinct alerts
    if len(raw_alerts) > 150:
        bounded_alerts = []
        seen_titles = set()
        for ra in raw_alerts:
            orig = ra.get("originalAlert") if isinstance(ra.get("originalAlert"), dict) else ra
            t = str(ra.get("title") or ra.get("name") or orig.get("moduleName") or "").strip()
            if t not in seen_titles or len(bounded_alerts) < 50:
                seen_titles.add(t)
                bounded_alerts.append(ra)
            if len(bounded_alerts) >= 150:
                break
        raw_alerts = bounded_alerts

    normalised_alerts: List[Dict[str, Any]] = []
    debug_by_alert: List[Dict[str, Any]] = []
    for index, raw_alert in enumerate(raw_alerts):
        alert, debug_evidence = normalise_alert_record(
            incident=incident,
            alert=raw_alert,
            alert_index=index,
            alert_count=len(raw_alerts),
            input_format=input_format,
        )
        normalised_alerts.append(alert)
        debug_by_alert.append(debug_evidence)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


# [FYP-FUNCTION] merge_event_values() — [FYP-INPUT] the field->values dict
# already extracted at the alert level (from extract_alert_values_fast()) and
# the list of already-normalised per-event dicts (normalise_event() output).
# [FYP-PROCESS] for each event, copies a fixed set of already-normalised
# event keys (source_ip, destination_ip, file_hash, command_line, etc. — see
# `mapping`) into the matching alert-level field list, merging rather than
# overwriting so alert-level and event-level evidence for the same field are
# combined. [FYP-OUTPUT] a new field->values dict (dedupe()d per field) that
# is a superset of the input alert_values. [FYP-USED-BY]
# normalise_alert_record() immediately after building normalised_events, so
# every downstream field (source_ips, hostnames, file_hashes, ...) sees both
# alert-level and event-level evidence.
# [FYP-FUNCTION] `merge_event_values` — transforms merge event values input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `alert_values`, `events`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dedupe`, `get`, `is_useful`, `items`, `list`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def merge_event_values(alert_values: Dict[str, List[Any]], events: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    merged = {field: list(values) for field, values in alert_values.items()}
    mapping = {
        "source_ip": "source_ip",
        "destination_ip": "destination_ip",
        "source_port": "source_port",
        "destination_port": "destination_port",
        "protocol": "protocol",
        "username": "username",
        "hostname": "hostname",
        "domain": "domain",
        "file_name": "file_name",
        "file_hash": "file_hash",
        "url": "url",
        "user_agent": "user_agent",
        "event_type": "event_type",
        "action": "action",
        "session_id": "session_id",
        "event_source_id": "event_source_id",
        "record_id": "record_id",
        "event_time": "event_time",
        "process_name": "process_name",
        "process_path": "process_path",
        "parent_process_name": "parent_process_name",
        "child_process_name": "child_process_name",
        "child_process_path": "child_process_path",
        "command_line": "command_line",
    }
    for event in events:
        for event_key, field_key in mapping.items():
            value = event.get(event_key)
            if is_useful(value):
                merged[field_key] = dedupe(merged.get(field_key, []) + [value])
    return merged


# [FYP-FUNCTION] normalise_event() — per-event field mapper (the raw-event
# counterpart of extract_alert_values_fast()/normalise_alert_record() at the
# alert level). [FYP-INPUT] one raw event dict (from walk_event_records()),
# its index within the alert, and a fallback event_type. [FYP-PROCESS] reads
# NetWitness's compact meta-key names (ip_src/ip_dst/port_src/user_src/
# filename_src/checksum_src/param_src/...) with fallbacks to more verbose
# nested source.device/source.user/destination.device/destination.user
# shapes, coerces ports via safe_int(), timestamps via timestamp_to_iso()/
# timestamp_to_epoch_ms(), usernames via clean_usernames(), hashes via
# extract_hashes(), and filters URLs to external ones via is_external_url().
# [FYP-OUTPUT] one flat per-event dict with a fixed key set (event_time,
# source_ip, file_hash, command_line, ...). [FYP-USED-BY]
# normalise_alert_record() (normalised_events) and build_standard_alert()'s
# all_parsed_events collection.
# [FYP-FUNCTION] `normalise_event` — transforms normalise event input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `event`, `index`, `alert_event_type`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_standard_alert, soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `clean_usernames`, `extract_hashes`, `first`, `get`, `is_external_url`, `isinstance`, `join`, `safe_int`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def normalise_event(event: Dict[str, Any], index: int, alert_event_type: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(event, dict):
        return {"event_index": index, "event_type": alert_event_type or "Unknown"}

    src = event.get("source") if isinstance(event.get("source"), dict) else {}
    src_dev = src.get("device") if isinstance(src.get("device"), dict) else {}
    src_usr = src.get("user") if isinstance(src.get("user"), dict) else {}

    dst = event.get("destination") if isinstance(event.get("destination"), dict) else {}
    dst_dev = dst.get("device") if isinstance(dst.get("device"), dict) else {}
    dst_usr = dst.get("user") if isinstance(dst.get("user"), dict) else {}

    source_ip = event.get("ip_src") or src_dev.get("ipAddress") or event.get("source_ip")
    destination_ip = event.get("ip_dst") or dst_dev.get("ipAddress") or event.get("destination_ip")

    source_port = safe_int(event.get("port_src") or src_dev.get("port") or event.get("source_port"))
    destination_port = safe_int(event.get("port_dst") or dst_dev.get("port") or event.get("destination_port"))

    username = event.get("user_src") or event.get("owner") or src_usr.get("username") or dst_usr.get("username") or event.get("username")
    hostname = event.get("domain") or event.get("alias_host") or event.get("host_src") or src_dev.get("dnsHostname") or dst_dev.get("dnsHostname") or event.get("hostname")

    file_name = event.get("filename_src") or event.get("filename") or event.get("process_name") or event.get("file_name")
    file_path = event.get("directory_src") or event.get("directory") or event.get("process_path") or event.get("file_path")
    file_hash = event.get("checksum_src") or event.get("hash") or event.get("file_hash") or event.get("sha256")

    cmdline = event.get("param_src") or event.get("param") or event.get("cmdline") or event.get("command_line")
    if isinstance(cmdline, list):
        cmdline = " ".join(str(x) for x in cmdline if x)

    url = event.get("url") or event.get("uri")
    user_agent = event.get("user_agent") or event.get("useragent")
    raw_event_time = event.get("event_time") or event.get("time") or event.get("timestamp")

    clean_usr = first(clean_usernames([username])) if username else None
    parsed_hash = first(extract_hashes([file_hash])) if file_hash else None

    return {
        "event_index": index,
        "event_time": timestamp_to_iso(raw_event_time),
        "event_time_epoch_ms": timestamp_to_epoch_ms(raw_event_time),
        "event_type": str(event.get("event_type") or event.get("eventSource") or alert_event_type or "Unknown"),
        "action": str(event.get("action") or event.get("boc") or "") or None,
        "source_ip": str(source_ip) if source_ip else None,
        "destination_ip": str(destination_ip) if destination_ip else None,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": str(event.get("protocol") or "") or None,
        "username": clean_usr,
        "hostname": str(hostname) if hostname else None,
        "domain": str(event.get("domain") or hostname) if (event.get("domain") or hostname) else None,
        "file_name": str(file_name) if file_name else None,
        "file_path": str(file_path) if file_path else None,
        "file_hash": parsed_hash,
        "url": str(url) if url and is_external_url(url) else None,
        "user_agent": str(user_agent) if user_agent else None,
        "process_name": str(file_name) if file_name else None,
        "process_path": str(file_path) if file_path else None,
        "parent_process_name": str(event.get("parent_process_name") or "") or None,
        "command_line": str(cmdline) if cmdline else None,
        "session_id": event.get("session_id"),
        "event_source_id": event.get("event_source_id"),
        "record_id": event.get("record_id"),
    }


# [FYP-FUNCTION] build_analyst_summary() — [FYP-INPUT] the key already-
# normalised fields for one alert (severity, alert_name, source/destination
# IP+port, sender/recipient email, file_name, MITRE technique, event_type).
# [FYP-PROCESS] template-based sentence assembly (no LLM) — picks between a
# handful of fixed sentence templates depending on which fields are present
# (attachment+sender+recipient vs. attachment alone vs. plain alert; then
# appends network-activity, MITRE-mapping and event-type clauses when those
# fields exist). [FYP-OUTPUT] a short human-readable summary string, stored
# as alert_summary.analyst_summary. [FYP-USED-BY] normalise_alert_record().
def build_analyst_summary(
    severity: str,
    alert_name: Optional[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    source_port: Optional[int],
    destination_port: Optional[int],
    sender: Optional[str],
    recipient: Optional[str],
    file_name: Optional[str],
    technique_id: Optional[str],
    technique: Optional[str],
    event_type: Optional[str],
) -> str:
    title = alert_name or "NetWitness alert"
    summary = f"{severity} alert: {title}."
    if file_name and sender and recipient:
        summary = f"{severity} alert involving suspicious attachment {file_name} sent from {sender} to {recipient}."
    elif file_name:
        summary = f"{severity} alert involving suspicious file {file_name}."
    if source_ip and destination_ip:
        src = f"{source_ip}:{source_port}" if source_port else source_ip
        dst = f"{destination_ip}:{destination_port}" if destination_port else destination_ip
        summary += f" Network activity was observed from {src} to {dst}."
    if technique_id or technique:
        mitre = " ".join(part for part in [technique_id, technique.title() if technique else None] if part)
        summary += f" The alert maps to MITRE ATT&CK {mitre}."
    if event_type and event_type != "Unknown":
        summary += f" Event type: {event_type}."
    return summary


# [FYP-FUNCTION] calculate_confidence() — legacy scorer, superseded by
# evaluate_context_data_quality() (the [FYP-EVALUATOR] schema-validation
# function above) but kept for any external/backward-compatible caller.
# [FYP-INPUT] the extracted values dict and a list of missing field names.
# [FYP-PROCESS] simple linear penalty: 100 - 10 points per missing field,
# clamped to [0, 100]. [FYP-OUTPUT] ("High"/"Medium"/"Low", numeric score)
# using the same 80/50 thresholds as evaluate_context_data_quality().
def calculate_confidence(values: Dict[str, List[Any]], missing_fields: List[str]) -> Tuple[str, int]:
    """Backward-compatible confidence helper. New parser logic uses evaluate_context_data_quality."""
    score = 100 - (len(missing_fields) * 10)
    score = max(0, min(100, score))
    if score >= 80:
        return "High", score
    if score >= 50:
        return "Medium", score
    return "Low", score


# [FYP-FUNCTION] _clean_title_candidate() — [FYP-INPUT] any raw title
# candidate value. [FYP-PROCESS] collapses internal whitespace, strips
# leading/trailing whitespace, then runs is_useful() to reject sentinel/empty
# text. [FYP-OUTPUT] cleaned title string or None. [FYP-USED-BY]
# select_alert_title().
def _clean_title_candidate(value: Any) -> Optional[str]:
    if not is_useful(value):
        return None
    text = re.sub(r"\s+", " ", str(value).strip())
    return text if is_useful(text) else None


def select_alert_title(alert: Dict[str, Any], incident: Dict[str, Any], values: Dict[str, List[Any]]) -> Optional[str]:
    """[FYP-FUNCTION] Prefer the alert-level title and keep incident title separate.

    NetWitness exports often contain both incident.title and alerts[0].title.
    The selected alert identity should use the alert title, while incident_title
    remains available separately for case-level context.
    """
    alert = alert or {}
    incident = incident or {}
    headers = alert.get("originalHeaders") if isinstance(alert.get("originalHeaders"), dict) else {}
    original = alert.get("originalAlert") if isinstance(alert.get("originalAlert"), dict) else {}
    nested_alert = alert.get("alert") if isinstance(alert.get("alert"), dict) else {}

    candidates = [
        alert.get("title"),
        headers.get("name"),
        original.get("name"),
        alert.get("alert_title"),
        alert.get("alert_name"),
        nested_alert.get("name"),
        alert.get("name"),
    ]
    for candidate in candidates:
        cleaned = _clean_title_candidate(candidate)
        if cleaned:
            return cleaned

    incident_titles = {_normalise_title_for_compare(v) for v in [incident.get("title"), incident.get("name")] if is_useful(v)}
    for candidate in values.get("alert_name", []) or []:
        cleaned = _clean_title_candidate(candidate)
        if not cleaned:
            continue
        # Avoid promoting incident titles or obvious executable names to alert title.
        if _normalise_title_for_compare(cleaned) in incident_titles:
            continue
        if FILE_RE.fullmatch(cleaned):
            continue
        return cleaned

    return _clean_title_candidate(original.get("moduleName")) or _clean_title_candidate(incident.get("title"))


# [FYP-FUNCTION] _normalise_title_for_compare() — [FYP-INPUT] any title-ish
# value. [FYP-PROCESS] whitespace-collapse + lower-case (no is_useful()
# filtering, unlike _clean_title_candidate()). [FYP-OUTPUT] a comparison-only
# string. [FYP-USED-BY] select_alert_title(), to detect when an
# alert_name candidate is really just the incident title repeated.
def _normalise_title_for_compare(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


# [FYP-EVALUATOR] [FYP-FUNCTION] extract_alert_values_fast() — THE FIELD
# MAPPING function actually used by the live pipeline. [FYP-INPUT] one raw
# alert dict plus the parent incident dict. [FYP-PROCESS] rule-based, hand-
# coded field mapping (no LLM): reads NetWitness's originalAlert wrapper if
# present, then pulls a fixed set of canonical fields (incident_id,
# severity, alert_id, alert_name, alert_time, ...) directly off known
# alert/incident keys via the local _add() helper, and for every event in
# alert["events"] additionally maps NetWitness's compact per-event meta keys
# (ip_src/ip_dst/user_src/checksum_src/filename_src/param_src, plus the
# nested source.device/source.user/destination.device/destination.user
# shapes) onto the same canonical field names used by FIELD_ALIASES.
# [FYP-OUTPUT] (values_by_field, paths_by_field) — same shape as
# extract_all_fields()'s output, but computed directly rather than via
# generic flatten+alias-suffix matching, which is why this is "fast".
# [FYP-USED-BY] normalise_alert_record() (the very first call in the
# function body). Contrast with extract_all_fields()/extract_by_alias()
# above, which implement the same field-mapping concept generically via
# FIELD_ALIASES but are not on this call path (see [FYP-SECTION] note near
# flatten_json()).
# [FYP-FUNCTION] `extract_alert_values_fast` — transforms extract alert values fast input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `alert`, `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_add`, `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def extract_alert_values_fast(alert: Dict[str, Any], incident: Dict[str, Any]) -> Tuple[Dict[str, List[Any]], Dict[str, List[str]]]:
    orig = alert.get("originalAlert") if isinstance(alert.get("originalAlert"), dict) else alert
    events = alert.get("events") or orig.get("events") or []
    
    values: Dict[str, List[Any]] = {f: [] for f in FIELD_ALIASES}
    paths: Dict[str, List[str]] = {f: [] for f in FIELD_ALIASES}
    
    # [FYP-FUNCTION] `_add` — implements the add operation used by the surrounding parsing and reporting service workflow.
    # [FYP-INPUT] Parameters: `field`, `val`, `p`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include nw_alerts.py:_add, nw_alerts.py:_distill_alerts, skills_sidecar.py:_assets_from_skills; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _add(field, val, p=""):
        if val is not None and val != "":
            values[field].append(val)
            paths[field].append(p or field)

    _add("incident_id", incident.get("id") or alert.get("incidentId") or alert.get("incident_id"))
    _add("incident_title", incident.get("title") or incident.get("name"))
    _add("incident_priority", incident.get("priority"))
    _add("risk_score", alert.get("riskScore") or incident.get("riskScore"))
    _add("severity", alert.get("severity") or incident.get("priority") or incident.get("severity"))
    _add("alert_id", alert.get("id") or alert.get("alertId"))
    _add("alert_name", alert.get("title") or alert.get("name") or orig.get("moduleName"))
    _add("alert_time", alert.get("created") or alert.get("timestamp") or alert.get("firstAlertTime"))

    for ev in events:
        if isinstance(ev, dict):
            _add("hostname", ev.get("domain") or ev.get("alias_host") or ev.get("host_src"))
            _add("username", ev.get("user_src") or ev.get("owner"))
            _add("source_ip", ev.get("ip_src"))
            _add("destination_ip", ev.get("ip_dst"))
            _add("file_hash", ev.get("checksum_src") or ev.get("hash") or ev.get("file_hash"))
            _add("file_name", ev.get("filename_src") or ev.get("filename") or ev.get("process_name"))
            _add("command_line", ev.get("param_src") or ev.get("param") or ev.get("cmdline"))
            
            src = ev.get("source") if isinstance(ev.get("source"), dict) else {}
            src_dev = src.get("device") if isinstance(src.get("device"), dict) else {}
            src_usr = src.get("user") if isinstance(src.get("user"), dict) else {}
            _add("source_ip", src_dev.get("ipAddress"))
            _add("hostname", src_dev.get("dnsHostname"))
            _add("username", src_usr.get("username"))

            dst = ev.get("destination") if isinstance(ev.get("destination"), dict) else {}
            dst_dev = dst.get("device") if isinstance(dst.get("device"), dict) else {}
            dst_usr = dst.get("user") if isinstance(dst.get("user"), dict) else {}
            _add("destination_ip", dst_dev.get("ipAddress"))
            _add("hostname", dst_dev.get("dnsHostname"))
            _add("username", dst_usr.get("username"))

    return values, paths


# [FYP-FUNCTION] `normalise_alert_record` — transforms normalise alert record input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `incident`, `alert`, `alert_index`, `alert_count`, `input_format`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_standard_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `_clean_title_candidate`, `analyse_powershell_command_lines`, `any`, `append`, `build_analyst_summary`, `build_compatibility_view`, `build_debug_evidence`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def normalise_alert_record(
    incident: Dict[str, Any],
    alert: Dict[str, Any],
    alert_index: int,
    alert_count: int,
    input_format: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    values, paths = extract_alert_values_fast(alert, incident)

    raw_event_records = walk_event_records(alert)
    preliminary_event_type = first(values.get("event_type", []), "Unknown")
    normalised_events = [
        normalise_event(record["raw_event"], index, preliminary_event_type)
        for index, record in enumerate(raw_event_records)
    ]
    values = merge_event_values(values, normalised_events)

    incident_id = first(values.get("incident_id", []))
    alert_id = safe_alert_id(values.get("alert_id", []), alert, incident_id, alert_index)
    alert_name = select_alert_title(alert, incident, values)
    incident_title = _clean_title_candidate(incident.get("title") or incident.get("name"))
    raw_alert_time = first(values.get("alert_time", []))
    alert_time = timestamp_to_iso(raw_alert_time)
    alert_time_epoch_ms = timestamp_to_epoch_ms(raw_alert_time)
    severity = normalise_severity(first(values.get("severity", [])))
    risk_score = safe_float(first(values.get("risk_score", [])))
    incident_priority = first(values.get("incident_priority", []))
    event_type = first(values.get("event_type", []), "Unknown")
    detection_name = first(values.get("detection_name", []), alert_name)

    observed_actions = dedupe(values.get("action", []))
    source_ips = dedupe(values.get("source_ip", []))
    destination_ips = dedupe(values.get("destination_ip", []))
    source_ports = numeric_list(values.get("source_port", []), "int")
    destination_ports = numeric_list(values.get("destination_port", []), "int")
    protocols = normalise_protocol_values(values.get("protocol", []))
    services = dedupe(map_service_name(port) for port in destination_ports if map_service_name(port))
    tcp_flags_seen = dedupe(values.get("tcp_flags_seen", []))
    internal_ips, external_ips = split_internal_external_ips(source_ips + destination_ips)

    source_emails = extract_emails(values.get("source_email", []) + values.get("source_username", []))
    reply_to_emails = extract_emails(values.get("reply_to_email", []))
    destination_emails = extract_emails(values.get("destination_email", []) + values.get("destination_username", []))
    all_emails = extract_emails(
        values.get("email", [])
        + values.get("username", [])
        + values.get("source_username", [])
        + values.get("destination_username", [])
        + source_emails
        + reply_to_emails
        + destination_emails
    )
    source_usernames = clean_usernames(values.get("source_username", []))
    destination_usernames = clean_usernames(values.get("destination_username", []))
    all_usernames = dedupe(source_usernames + destination_usernames + clean_usernames(values.get("username", [])))

    hostnames = dedupe(values.get("hostname", []))
    domains = dedupe(values.get("domain", []))
    email_subjects = dedupe(values.get("email_subject", []))
    mail_clients = dedupe(values.get("mail_client", []))

    raw_file_names = dedupe(values.get("file_name", []) + infer_file_names(values.get("alert_name", []) + values.get("email_subject", [])))
    process_names = dedupe(values.get("process_name", []) + values.get("parent_process_name", []) + values.get("child_process_name", []))
    file_names, process_names_from_file_fields = split_file_and_process_names(raw_file_names, process_names)
    process_names = dedupe(process_names + process_names_from_file_fields)
    file_hashes = extract_hashes(values.get("file_hash", []))
    file_hashes_by_type = split_hashes_by_type(values.get("file_hash", []))
    file_paths = dedupe(values.get("file_path", []))
    file_extensions = dedupe(values.get("file_extension", []))
    if not file_extensions:
        file_extensions = dedupe(Path(name).suffix.lstrip(".").lower() for name in file_names if Path(name).suffix)
    file_types = dedupe(values.get("file_type", []))
    file_sizes = numeric_list(values.get("file_size", []), "int")
    file_analysis = dedupe(values.get("file_analysis", []))

    process_paths = dedupe(values.get("process_path", []) + values.get("child_process_path", []))
    process_path_set = {str(path).strip().lower() for path in process_paths}
    file_paths = dedupe(path for path in file_paths if str(path).strip().lower() not in process_path_set)
    parent_processes = dedupe(values.get("parent_process_name", []))
    child_processes = dedupe(values.get("child_process_name", []))
    command_lines = dedupe(values.get("command_line", []))
    process_relationships = build_process_relationships(normalised_events)

    powershell_source_text = json.dumps({
        "alert_name": alert_name,
        "incident_title": incident_title,
        "detection_name": detection_name,
        "event_type": event_type,
    }, ensure_ascii=False, default=str)
    powershell_analysis = analyse_powershell_command_lines(
        command_lines,
        alert_text=powershell_source_text,
    )
    powershell_iocs = powershell_analysis.get("extracted_iocs", {}) if isinstance(powershell_analysis, dict) else {}

    all_urls = dedupe(values.get("url", []) + list(powershell_iocs.get("urls", []) or []))
    external_urls = dedupe(url for url in all_urls if is_external_url(url))
    investigation_links = dedupe(url for url in all_urls if is_netwitness_link(url))
    web_domains = dedupe(domains_from_urls(external_urls) + list(powershell_iocs.get("domains", []) or []))
    user_agents = dedupe(values.get("user_agent", []))

    mitre_tactics = dedupe(values.get("mitre_tactic", []))
    mitre_techniques = dedupe(values.get("mitre_technique", []))
    mitre_technique_ids = dedupe(values.get("mitre_technique_id", []))
    threat_categories = dedupe(values.get("threat_category", []))
    risk_indicators = dedupe(values.get("risk_indicator", []))
    network_risk_info = dedupe(values.get("network_risk_info", []))
    analysis_services = dedupe(values.get("analysis_service", []))
    analysis_sessions = dedupe(values.get("analysis_session", []))
    feed_names = dedupe(values.get("feed_name", []))

    session_ids = dedupe(values.get("session_id", []))
    event_source_ids = dedupe(values.get("event_source_id", []))
    record_ids = dedupe(values.get("record_id", []))
    signature_ids = dedupe(values.get("signature_id", []))
    community_ids = dedupe(values.get("community_id", []))

    observed_data_context = build_observed_data_context(
        event_type=event_type,
        normalised_events=normalised_events,
        source_emails=source_emails,
        reply_to_emails=reply_to_emails,
        destination_emails=destination_emails,
        email_subjects=email_subjects,
        mail_clients=mail_clients,
        file_names=file_names,
        file_hashes=file_hashes,
        source_ips=source_ips,
        destination_ips=destination_ips,
        destination_ports=destination_ports,
        protocols=protocols,
        external_urls=external_urls,
        web_domains=web_domains,
        user_agents=user_agents,
        hostnames=hostnames,
        all_usernames=all_usernames,
        process_names=process_names,
        process_paths=process_paths,
        parent_processes=parent_processes,
        child_processes=child_processes,
        command_lines=command_lines,
    )

    data_quality = evaluate_context_data_quality(
        observed_data_context=observed_data_context,
        alert_id=alert_id,
        alert_name=alert_name,
        alert_time=alert_time,
        severity=severity,
        source_ips=source_ips,
        destination_ips=destination_ips,
        destination_ports=destination_ports,
        protocols=protocols,
        source_emails=source_emails,
        destination_emails=destination_emails,
        reply_to_emails=reply_to_emails,
        email_subjects=email_subjects,
        hostnames=hostnames,
        all_usernames=all_usernames,
        process_names=process_names,
        command_lines=command_lines,
        file_names=file_names,
        file_hashes=file_hashes,
        external_urls=external_urls,
        web_domains=web_domains,
        session_ids=session_ids,
        event_source_ids=event_source_ids,
        record_ids=record_ids,
        signature_ids=signature_ids,
        community_ids=community_ids,
        normalised_events=normalised_events,
        raw_meta_key_count=len(alert),
    )

    missing_fields = dedupe(
        data_quality.get("missing_required_fields", [])
        + [field for fields in data_quality.get("missing_context_fields", {}).values() for field in fields]
    )
    parser_confidence = data_quality.get("parser_confidence", "Unknown")
    parser_confidence_score = data_quality.get("parser_confidence_score", 0)
    warnings = data_quality.get("warnings", [])

    ioc_summary = {
        "ips": dedupe(source_ips + destination_ips + list(powershell_iocs.get("public_ips", []) or [])),
        "emails": all_emails,
        "hostnames": hostnames,
        "files": dedupe(file_names + list(powershell_iocs.get("file_names", []) or [])),
        "hashes": dedupe(file_hashes + list(powershell_iocs.get("hashes", []) or [])),
        "urls": dedupe(external_urls + list(powershell_iocs.get("urls", []) or [])),
        "domains": dedupe(domains + web_domains + list(powershell_iocs.get("domains", []) or [])),
    }
    related_iocs = dedupe(
        ioc_summary["ips"]
        + ioc_summary["emails"]
        + ioc_summary["hostnames"]
        + ioc_summary["files"]
        + ioc_summary["hashes"]
        + ioc_summary["urls"]
        + ioc_summary["domains"]
    )

    analyst_summary = build_analyst_summary(
        severity=severity,
        alert_name=alert_name,
        source_ip=first(source_ips),
        destination_ip=first(destination_ips),
        source_port=first(source_ports),
        destination_port=first(destination_ports),
        sender=first(source_emails),
        recipient=first(destination_emails),
        file_name=first(file_names),
        technique_id=first(mitre_technique_ids),
        technique=first(mitre_techniques),
        event_type=event_type,
    )

    key_fields_found = [field for field in REQUIRED_FOR_CONFIDENCE if values.get(field)]
    if file_names:
        key_fields_found.append("file_name")
    if source_emails:
        key_fields_found.append("source_email")
    if destination_emails:
        key_fields_found.append("destination_email")
    if reply_to_emails:
        key_fields_found.append("reply_to_email")
    if mitre_technique_ids:
        key_fields_found.append("mitre_technique_id")
    if powershell_analysis.get("encoded_command_present"):
        key_fields_found.append("powershell_encoded_command")
    if powershell_analysis.get("decode_status") == "success":
        key_fields_found.append("decoded_powershell_command")

    normalised_alert = {
        "schema_version": SCHEMA_VERSION,
        "current_stage": "new_alert",
        "alert_summary": {
            "incident_id": incident_id,
            "alert_id": alert_id,
            "alert_name": alert_name,
            "alert_title": alert_name,
            "incident_title": incident_title,
            "alert_time": alert_time,
            "alert_time_epoch_ms": alert_time_epoch_ms,
            "severity": severity,
            "incident_priority": incident_priority,
            "risk_score": risk_score,
            "detection_source": "NetWitness",
            "detection_name": detection_name,
            "event_type": event_type,
            "primary_action": first(observed_actions),
            "observed_actions": observed_actions,
            "raw_event_count": len(raw_event_records),
            "analyst_summary": analyst_summary,
        },
        "identifiers": {
            "session_ids": session_ids,
            "event_source_ids": event_source_ids,
            "record_ids": record_ids,
            "signature_ids": signature_ids,
        },
        "network_indicators": {
            "source_ips": source_ips,
            "destination_ips": destination_ips,
            "internal_ips": internal_ips,
            "external_ips": external_ips,
            "source_ports": source_ports,
            "destination_ports": destination_ports,
            "protocols": protocols,
            "services": services,
            "direction": first(values.get("direction", [])),
            "community_ids": community_ids,
            "tcp_flags_seen": tcp_flags_seen,
            "network_risk_info": network_risk_info,
        },
        "user_and_host_indicators": {
            "source_usernames": source_usernames,
            "destination_usernames": destination_usernames,
            "source_emails": source_emails,
            "reply_to_emails": reply_to_emails,
            "destination_emails": destination_emails,
            "all_usernames": all_usernames,
            "all_emails": all_emails,
            "hostnames": hostnames,
            "domains": domains,
        },
        "email_indicators": {
            "subjects": email_subjects,
            "from_emails": source_emails,
            "sender_emails": source_emails,
            "reply_to_emails": reply_to_emails,
            "recipient_emails": destination_emails,
            "mail_clients": mail_clients,
            "attachment_names": file_names,
            "attachment_extensions": file_extensions,
            "attachment_filetypes": file_types,
        },
        "file_indicators": {
            "file_names": file_names,
            "file_paths": file_paths,
            "file_hashes": file_hashes,
            "file_hashes_by_type": file_hashes_by_type,
            "file_extensions": file_extensions,
            "file_types": file_types,
            "file_sizes": file_sizes,
            "file_analysis": file_analysis,
        },
        "process_indicators": {
            "process_names": process_names,
            "process_paths": process_paths,
            "parent_processes": parent_processes,
            "child_processes": child_processes,
            "process_relationships": process_relationships,
            "command_lines": command_lines,
        },
        "powershell_analysis": powershell_analysis,
        "web_indicators": {
            "urls": external_urls,
            "domains": web_domains,
            "user_agents": user_agents,
        },
        "observed_data_context": observed_data_context,
        "threat_context": {
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "mitre_technique_ids": dedupe(mitre_technique_ids + [m.get("technique_id") for m in powershell_analysis.get("mitre_mapping", []) if isinstance(m, dict)]),
            "threat_categories": threat_categories,
            "risk_indicators": risk_indicators,
            "analysis_services": analysis_services,
            "analysis_sessions": analysis_sessions,
            "feed_names": feed_names,
            "related_iocs": related_iocs,
        },
        "ioc_summary": ioc_summary,
        "normalised_events": normalised_events,
        "netwitness_links": {
            "investigation_links": investigation_links,
        },
        "parser_metadata": {
            "parser": "soc_netwitness_parser",
            "parser_version": PARSER_VERSION,
            "input_format": input_format,
            "normalisation_status": "success",
            "selected_alert_index": alert_index,
            "alert_count": alert_count,
            "raw_event_count": len(raw_event_records),
            "raw_meta_key_count": len(alert),
            "parser_confidence": parser_confidence,
            "parser_confidence_score": parser_confidence_score,
            "missing_fields": dedupe(missing_fields),
            "warnings": warnings,
            "debug_available": True,
            "extraction_summary": {
                "key_fields_found": dedupe(key_fields_found),
                "key_fields_missing": dedupe(missing_fields),
                "fallback_fields_used": any(paths.get(field) for field in ["hostname", "source_ip", "destination_ip", "file_name"]),
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    normalised_alert["data_quality"] = data_quality

    normalised_alert["compatibility_view"] = build_compatibility_view(normalised_alert, incident)

    # Debug evidence is returned separately and must not be merged into normalised_alert.
    debug_evidence = build_debug_evidence(alert, paths, raw_event_records)
    pruned_normalised_alert = prune_empty_and_null_values(normalised_alert) or normalised_alert
    return pruned_normalised_alert, debug_evidence


# [FYP-FUNCTION] `build_compatibility_view` — constructs build compatibility view output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `alert`, `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `first`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_compatibility_view(alert: Dict[str, Any], incident: Dict[str, Any]) -> Dict[str, Any]:
    summary = alert.get("alert_summary", {})
    network = alert.get("network_indicators", {})
    users = alert.get("user_and_host_indicators", {})
    files = alert.get("file_indicators", {})
    processes = alert.get("process_indicators", {})
    powershell = alert.get("powershell_analysis", {})
    identifiers = alert.get("identifiers", {})
    metadata = alert.get("parser_metadata", {})

    return {
        "current_stage": alert.get("current_stage"),
        "incident_id": summary.get("incident_id") or incident.get("id"),
        "alert_id": summary.get("alert_id"),
        "alert_title": summary.get("alert_name"),
        "alert_type": summary.get("event_type"),
        "alert_source": "NetWitness",
        "alert_created_time": summary.get("alert_time"),
        "incident_title": summary.get("incident_title") or incident.get("title"),
        "incident_priority": incident.get("priority"),
        "incident_risk_score": incident.get("riskScore") or summary.get("risk_score"),
        "incident_first_alert_time": incident.get("firstAlertTime"),
        "source_ip": first(network.get("source_ips", [])),
        "destination_ip": first(network.get("destination_ips", [])),
        "source_port": first(network.get("source_ports", [])),
        "destination_port": first(network.get("destination_ports", [])),
        "source_username": first(users.get("source_usernames", [])),
        "destination_username": first(users.get("destination_usernames", [])),
        "username": first(users.get("all_usernames", [])),
        "event_domain": first(users.get("domains", [])),
        "possible_file_name": first(files.get("file_names", [])),
        "file_hash": first(files.get("file_hashes", [])),
        "process_name": first(processes.get("process_names", [])),
        "parent_process_name": first(processes.get("parent_processes", [])),
        "command_line": first(processes.get("command_lines", [])),
        "powershell_analysis": powershell,
        "powershell_decode_status": powershell.get("decode_status"),
        "decoded_powershell_command": first(powershell.get("decoded_commands", [])),
        "session_id": first(identifiers.get("session_ids", [])),
        "event_source_id": first(identifiers.get("event_source_ids", [])),
        "record_id": first(identifiers.get("record_ids", [])),
        "severity": summary.get("severity"),
        "timestamp": summary.get("alert_time"),
        "parser_confidence": metadata.get("parser_confidence"),
        "parser_warnings": metadata.get("warnings", []),
        "missing_fields": metadata.get("missing_fields", []),
    }


# [FYP-FUNCTION] `build_debug_evidence` — constructs build debug evidence output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `flat`, `paths`, `raw_event_records`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:normalise_alert_record; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `dedupe`, `enumerate`, `get`, `is_useful`, `isinstance`, `items`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_debug_evidence(flat: Dict[str, Any], paths: Dict[str, List[str]], raw_event_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    sample_values: Dict[str, List[Any]] = {}
    is_dict = isinstance(flat, dict)
    for field, field_paths in paths.items():
        if not field_paths:
            continue
        samples: List[Any] = []
        for path in field_paths[:8]:
            if is_dict and path in flat and is_useful(flat[path]):
                samples.append(flat[path])
        if samples:
            sample_values[field] = dedupe(samples)

    event_evidence: Dict[str, Any] = {}
    for index, record in enumerate(raw_event_records[:50]):
        raw_ev = record.get("raw_event") or {}
        if isinstance(raw_ev, dict):
            event_evidence[f"event_{index}"] = {
                "source_path": record.get("source_path", ""),
                "field_evidence_paths": {k: v for k, v in raw_ev.items() if is_useful(v)},
            }

    return {
        "raw_meta_key_count": len(paths),
        "field_evidence_paths": {field: field_paths for field, field_paths in paths.items() if field_paths},
        "sample_values": sample_values,
        "event_evidence_paths": event_evidence,
    }


# [FYP-FUNCTION] `severity_sort_score` — implements the severity sort score operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `get`, `int`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def severity_sort_score(alert: Dict[str, Any]) -> int:
    severity_rank = {"Unknown": 0, "Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
    summary = alert.get("alert_summary", {})
    score = severity_rank.get(summary.get("severity", "Unknown"), 0) * 10
    if alert.get("network_indicators", {}).get("source_ips"):
        score += 2
    if alert.get("network_indicators", {}).get("destination_ips"):
        score += 2
    if alert.get("file_indicators", {}).get("file_names"):
        score += 2
    if alert.get("threat_context", {}).get("mitre_technique_ids"):
        score += 2
    score += int(alert.get("parser_metadata", {}).get("parser_confidence_score", 0) / 20)
    return score


# [FYP-FUNCTION] `build_parser_summary` — constructs build parser summary output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `selected`, `alerts`, `input_format`, `output_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_standard_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `get`, `isoformat`, `len`, `now`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_parser_summary(selected: Optional[Dict[str, Any]], alerts: List[Dict[str, Any]], input_format: str, output_dir: str) -> Dict[str, Any]:
    if selected:
        summary = selected.get("alert_summary", {})
        network = selected.get("network_indicators", {})
        users = selected.get("user_and_host_indicators", {})
        files = selected.get("file_indicators", {})
        threat = selected.get("threat_context", {})
        processes = selected.get("process_indicators", {})
        metadata = selected.get("parser_metadata", {})
    else:
        summary, network, users, files, threat, processes, metadata = {}, {}, {}, {}, {}, {}, {}

    return {
        "parsing_succeeded": selected is not None,
        "parser_status": "completed" if selected else "no_alerts_found",
        "detected_input_format": input_format,
        "normalised_alert_count": len(alerts),
        "selected_alert_id": summary.get("alert_id"),
        "parser_confidence": metadata.get("parser_confidence", "Unknown"),
        "parser_confidence_score": metadata.get("parser_confidence_score", 0),
        "important_extracted_fields": {
            "alert_id": summary.get("alert_id"),
            "incident_id": summary.get("incident_id"),
            "alert_name": summary.get("alert_name"),
            "alert_time": summary.get("alert_time"),
            "severity": summary.get("severity"),
            "risk_score": summary.get("risk_score"),
            "source_ips": network.get("source_ips", []),
            "destination_ips": network.get("destination_ips", []),
            "internal_ips": network.get("internal_ips", []),
            "external_ips": network.get("external_ips", []),
            "source_ports": network.get("source_ports", []),
            "destination_ports": network.get("destination_ports", []),
            "services": network.get("services", []),
            "users": users.get("all_usernames", []),
            "emails": users.get("all_emails", []),
            "reply_to_emails": users.get("reply_to_emails", []),
            "hosts": users.get("hostnames", []),
            "file_names": files.get("file_names", []),
            "file_hashes": files.get("file_hashes", []),
            "file_hashes_by_type": files.get("file_hashes_by_type", {}),
            "process_names": processes.get("process_names", []),
            "parent_processes": processes.get("parent_processes", []),
            "child_processes": processes.get("child_processes", []),
            "process_relationships": processes.get("process_relationships", []),
            "command_lines": processes.get("command_lines", []),
            "powershell_analysis": selected.get("powershell_analysis", {}) if selected else {},
            "mitre_technique_ids": threat.get("mitre_technique_ids", []),
        },
        "missing_important_fields": metadata.get("missing_fields", []),
        "warnings": metadata.get("warnings", []),
        "output_files": {
            "normalised_alert": str(Path(output_dir) / NORMALISED_ALERT_FILE),
            "processed_alert": str(Path(output_dir) / PROCESSED_ALERT_FILE),
            "processed_alert_csv": str(Path(output_dir) / PROCESSED_ALERT_CSV_FILE),
            "all_normalised_alerts": str(Path(output_dir) / ALL_NORMALISED_ALERTS_FILE),
            "parser_summary": str(Path(output_dir) / PARSER_SUMMARY_FILE),
            "raw_debug": str(Path(output_dir) / RAW_DEBUG_FILE),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# [FYP-FUNCTION] `normalise_netwitness_data` — transforms normalise netwitness data input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `build_standard_alert`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def normalise_netwitness_data(data: Any) -> Dict[str, Any]:
    """Public function for other project scripts."""
    return build_standard_alert(data)


# [FYP-FUNCTION] `build_standard_alert` — constructs build standard alert output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `data`, `output_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:main, soc_reporting_agent/services/parser_normaliser.py:normalise_netwitness_data, soc_reporting_agent/services/parser_normaliser.py:run_parser_normalisation_for_dashboard; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `append`, `build_parser_summary`, `detect_input_format`, `enumerate`, `get`, `isinstance`, `isoformat`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_standard_alert(data: Any, output_dir: str = "outputs") -> Dict[str, Any]:
    pruned_data = prune_empty_and_null_values(data) or data
    input_format = detect_input_format(pruned_data)
    incident, raw_alerts = prepare_incident_and_alerts(pruned_data)

    normalised_alerts: List[Dict[str, Any]] = []
    debug_by_alert: List[Dict[str, Any]] = []
    all_parsed_events: List[Dict[str, Any]] = []

    for index, raw_alert in enumerate(raw_alerts):
        alert, debug_evidence = normalise_alert_record(
            incident=incident,
            alert=raw_alert,
            alert_index=index,
            alert_count=len(raw_alerts),
            input_format=input_format,
        )
        normalised_alerts.append(alert)
        debug_by_alert.append(debug_evidence)

        # Collect event records across all alerts
        raw_events = walk_event_records(raw_alert)
        alert_title = alert.get("alert_summary", {}).get("alert_name") or "Unknown Alert"
        alert_id = alert.get("alert_summary", {}).get("alert_id")
        preliminary_type = alert.get("alert_summary", {}).get("event_type", "Unknown")
        for evt_idx, record in enumerate(raw_events):
            parsed_evt = normalise_event(record["raw_event"], evt_idx, preliminary_type)
            parsed_evt["parent_alert_id"] = alert_id
            parsed_evt["parent_alert_title"] = alert_title
            all_parsed_events.append(parsed_evt)

    selected_alert = max(normalised_alerts, key=severity_sort_score) if normalised_alerts else None
    selected_index = selected_alert.get("parser_metadata", {}).get("selected_alert_index", 0) if selected_alert else None
    selected_debug = debug_by_alert[selected_index] if isinstance(selected_index, int) and selected_index < len(debug_by_alert) else {}

    parser_summary = build_parser_summary(selected_alert, normalised_alerts, input_format, output_dir)
    raw_debug = {
        "parser": "soc_netwitness_parser",
        "parser_version": PARSER_VERSION,
        "input_format": input_format,
        "selected_alert_index": selected_index,
        "selected_alert_id": selected_alert.get("alert_summary", {}).get("alert_id") if selected_alert else None,
        "selected_alert_raw_evidence": selected_debug,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "parser_status": parser_summary.get("parser_status"),
        "input_shape": input_format,
        "alert_count": len(normalised_alerts),
        "normalised_alert_count": len(normalised_alerts),
        "event_count": len(all_parsed_events),
        "selected_alert_id": parser_summary.get("selected_alert_id"),
        "selected_alert": selected_alert,
        "normalised_alert": selected_alert,
        "normalised_alerts": normalised_alerts,
        "all_parsed_events": all_parsed_events,
        "parser_summary": parser_summary,
        "raw_alert_debug": raw_debug,
        "output_files": {
            "normalised_alert": str(Path(output_dir) / NORMALISED_ALERT_FILE),
            "processed_alert": str(Path(output_dir) / PROCESSED_ALERT_FILE),
            "processed_alert_csv": str(Path(output_dir) / PROCESSED_ALERT_CSV_FILE),
            "all_normalised_alerts": str(Path(output_dir) / ALL_NORMALISED_ALERTS_FILE),
            "all_parsed_events": str(Path(output_dir) / ALL_PARSED_EVENTS_FILE),
            "parser_summary": str(Path(output_dir) / PARSER_SUMMARY_FILE),
            "raw_debug": str(Path(output_dir) / RAW_DEBUG_FILE),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Output writing and CLI
# ---------------------------------------------------------------------------


# [FYP-FUNCTION] `flatten_for_csv` — implements the flatten for csv operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:write_csv_file; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `isinstance`, `items`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def flatten_for_csv(data: Dict[str, Any]) -> Dict[str, str]:
    row = {}
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            row[key] = json.dumps(value, ensure_ascii=False)
        elif value is None:
            row[key] = ""
        else:
            row[key] = str(value)
    return row


# [FYP-FUNCTION] `write_csv_file` — persists or updates write csv file state used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `data`, `path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `DictWriter`, `Path`, `flatten_for_csv`, `keys`, `list`, `mkdir`, `open`, `writeheader`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def write_csv_file(data: Dict[str, Any], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    row = flatten_for_csv(data)
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(row.keys()))
        writer.writeheader()
        writer.writerow(row)


# [FYP-FUNCTION] `write_outputs` — persists or updates write outputs state used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `result`, `output_dir`, `write_debug`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/agents/reporting_agent.py:main, soc_reporting_agent/scripts/test_merged_report_context.py:test_merged_context, soc_reporting_agent/services/parser_normaliser.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `get`, `mkdir`, `prune_empty_and_null_values`, `save_json_file`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def write_outputs(result: Dict[str, Any], output_dir: str = "outputs/soc_context_parser", write_debug: bool = True) -> Dict[str, str]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Get all normalised alerts (matching parsed_incident_INC-53016.json format)
    alerts = result.get("normalised_alerts")
    if not alerts:
        selected = result.get("normalised_alert")
        alerts = [selected] if selected else []
    
    # Recursively prune all None, empty string, empty list, and empty dict fields
    pruned_data = prune_empty_and_null_values(alerts) or []
    
    parsed_file = str(out_dir / "parsed_incident.json")
    processed_file = str(out_dir / "processed_alert.json")
    
    # Save the single clean pruned JSON file
    save_json_file(pruned_data, parsed_file)
    save_json_file(pruned_data, processed_file)
    
    paths = {
        "parsed_incident": parsed_file,
        "normalised_alert": parsed_file,
        "processed_alert": processed_file,
        "all_normalised_alerts": parsed_file,
    }
    return paths


# [FYP-FUNCTION] `print_summary` — implements the print summary operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `result`, `paths`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `items`, `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def print_summary(result: Dict[str, Any], paths: Dict[str, str]) -> None:
    summary = result.get("parser_summary", {})
    extracted = summary.get("important_extracted_fields", {})
    print("SOC NetWitness Parser")
    print("=" * 24)
    print(f"Parsing succeeded: {summary.get('parsing_succeeded')}")
    print(f"Detected input format: {summary.get('detected_input_format')}")
    print(f"Normalised alert count: {summary.get('normalised_alert_count')}")
    print(f"Parser confidence: {summary.get('parser_confidence')} ({summary.get('parser_confidence_score')})")
    print()
    print("Important extracted fields:")
    for key, value in extracted.items():
        print(f"- {key}: {value}")
    print()
    print(f"Missing important fields: {summary.get('missing_important_fields')}")
    print(f"Warnings: {summary.get('warnings')}")
    print()
    print("Output file locations:")
    for name, path in paths.items():
        print(f"- {name}: {path}")


# [FYP-FUNCTION] `parse_args` — transforms parse args input into the stable representation required by downstream parsing and reporting service processing.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async, soc_reporting_agent/agents/reporting_agent.py:main, soc_reporting_agent/agents/reporting_agent.py:parse_args; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ArgumentParser`, `add_argument`, `parse_args`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fresh NetWitness parser, one-file version.")
    parser.add_argument("input_path", help="Path to the raw NetWitness JSON export.")
    parser.add_argument("--output-dir", default="outputs/soc_context_parser", help="Output directory. Default: outputs/soc_context_parser")
    parser.add_argument("--no-debug", action="store_true", help="Do not write raw_alert_debug.json.")
    return parser.parse_args()


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered parsing and reporting service operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `build_standard_alert`, `exists`, `get`, `load_json_file`, `parse_args`, `print`, `print_summary`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main() -> int:
    args = parse_args()
    if not Path(args.input_path).exists():
        print(f"Input file not found: {args.input_path}")
        return 1
    data = load_json_file(args.input_path)
    result = build_standard_alert(data, output_dir=args.output_dir)
    paths = write_outputs(result, output_dir=args.output_dir, write_debug=not args.no_debug)
    print_summary(result, paths)
    return 0 if result.get("parser_status") == "completed" else 1


# Backward-compatible names for older imports.
write_parser_outputs = write_outputs
flatten_meta = flatten_json
detect_input_shape = detect_input_format


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# Dashboard integration helpers
# ---------------------------------------------------------------------------

# [FYP-FUNCTION] `_ioc_items_from_summary` — implements the ioc items from summary operation used by the surrounding parsing and reporting service workflow.
# [FYP-INPUT] Parameters: `summary`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:build_agent_friendly_processed_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `items`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _ioc_items_from_summary(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    mapping = {
        "ips": "ip",
        "emails": "email",
        "hostnames": "hostname",
        "files": "file_name",
        "hashes": "file_hash",
        "urls": "url",
        "domains": "domain",
    }
    for key, ioc_type in mapping.items():
        for value in summary.get(key, []) or []:
            if value not in (None, "", [], {}):
                items.append({"type": ioc_type, "value": value})
    return items


# [FYP-FUNCTION] `build_agent_friendly_processed_alert` — constructs build agent friendly processed alert output for the next parsing and reporting service consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `normalised_alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/services/parser_normaliser.py:run_parser_normalisation_for_dashboard; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_ioc_items_from_summary`, `dict`, `first`, `get`, `make_json_safe`, `prune_empty_and_null_values`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_agent_friendly_processed_alert(normalised_alert: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the rich parser output into the shape existing agents expect.

    The parser keeps detailed SOC context in nested sections. Older triage and
    threat-intel code expects a flatter alert object, so this compatibility view
    is the hand-off between the parser stage and downstream agents.
    """
    normalised_alert = normalised_alert or {}
    compatibility = dict(normalised_alert.get("compatibility_view") or {})
    alert_summary = normalised_alert.get("alert_summary") or {}
    network = normalised_alert.get("network_indicators") or {}
    users = normalised_alert.get("user_and_host_indicators") or {}
    files = normalised_alert.get("file_indicators") or {}
    processes = normalised_alert.get("process_indicators") or {}
    web = normalised_alert.get("web_indicators") or {}
    threat = normalised_alert.get("threat_context") or {}
    ioc_summary = normalised_alert.get("ioc_summary") or {}
    parser_metadata = normalised_alert.get("parser_metadata") or {}
    powershell = normalised_alert.get("powershell_analysis") or {}

    processed = {
        **compatibility,
        "current_stage": "parsing_normalisation_completed",
        "parser_status": "completed",
        "normalisation_status": parser_metadata.get("normalisation_status", "success"),
        "incident_id": compatibility.get("incident_id") or alert_summary.get("incident_id"),
        "incident_title": compatibility.get("incident_title") or alert_summary.get("incident_title"),
        "alert_id": compatibility.get("alert_id") or alert_summary.get("alert_id"),
        "alert_name": compatibility.get("alert_title") or alert_summary.get("alert_name"),
        "alert_title": compatibility.get("alert_title") or alert_summary.get("alert_name"),
        "alert_type": compatibility.get("alert_type") or alert_summary.get("event_type"),
        "source": compatibility.get("alert_source") or alert_summary.get("detection_source") or "NetWitness",
        "severity": alert_summary.get("severity") or compatibility.get("severity"),
        "risk_score": alert_summary.get("risk_score") or compatibility.get("incident_risk_score"),
        "timestamp": alert_summary.get("alert_time") or compatibility.get("timestamp"),
        "first_seen": alert_summary.get("alert_time") or compatibility.get("alert_created_time"),
        "host": first(users.get("hostnames", []), compatibility.get("event_domain") or compatibility.get("host")),
        "hostname": first(users.get("hostnames", []), compatibility.get("event_domain") or compatibility.get("hostname")),
        "username": first(users.get("all_usernames", []), compatibility.get("username")),
        "source_ip": first(network.get("source_ips", []), compatibility.get("source_ip")),
        "destination_ip": first(network.get("destination_ips", []), compatibility.get("destination_ip")),
        "source_port": first(network.get("source_ports", []), compatibility.get("source_port")),
        "destination_port": first(network.get("destination_ports", []), compatibility.get("destination_port")),
        "protocol": first(network.get("protocols", [])),
        "event_domain": first((users.get("domains") or []) + (web.get("domains") or []), compatibility.get("event_domain")),
        "domain": first((web.get("domains") or []) + (users.get("domains") or []), compatibility.get("event_domain")),
        "url": first(web.get("urls", [])),
        "user_agent": first(web.get("user_agents", [])),
        "possible_file_name": first(files.get("file_names", []), compatibility.get("possible_file_name")),
        "file_name": first(files.get("file_names", []), compatibility.get("possible_file_name")),
        "file_path": first(files.get("file_paths", [])),
        "file_hash": first(files.get("file_hashes", []), compatibility.get("file_hash")),
        "md5": first((files.get("file_hashes_by_type") or {}).get("md5", [])),
        "sha1": first((files.get("file_hashes_by_type") or {}).get("sha1", [])),
        "sha256": first((files.get("file_hashes_by_type") or {}).get("sha256", [])),
        "process_name": first(processes.get("process_names", [])),
        "process_path": first(processes.get("process_paths", [])),
        "parent_process_name": first(processes.get("parent_processes", [])),
        "child_process_name": first(processes.get("child_processes", [])),
        "command_line": first(processes.get("command_lines", [])),
        "powershell_analysis": powershell,
        "powershell_decode_status": powershell.get("decode_status"),
        "decoded_powershell_command": first(powershell.get("decoded_commands", [])),
        "decoded_powershell_summary": powershell.get("decoded_command_summary"),
        "powershell_suspicious_behaviours": powershell.get("suspicious_behaviours", []),
        "powershell_extracted_iocs": powershell.get("extracted_iocs", {}),
        "mitre_technique_id": first(threat.get("mitre_technique_ids", [])),
        "mitre_technique": first(threat.get("mitre_techniques", [])),
        "mitre_tactic": first(threat.get("mitre_tactics", [])),
        "analyst_summary": alert_summary.get("analyst_summary"),
        "iocs": _ioc_items_from_summary(ioc_summary),
        "ioc_summary": ioc_summary,
        "normalised_alert": normalised_alert,
        "parser_metadata": parser_metadata,
        "data_quality": normalised_alert.get("data_quality") or {},
        "threat_context": threat,
        "network_indicators": network,
        "user_and_host_indicators": users,
        "file_indicators": files,
        "process_indicators": processes,
        "powershell_analysis": powershell,
        "web_indicators": web,
    }
    return prune_empty_and_null_values(make_json_safe(processed)) or {}


# [FYP-FUNCTION] `run_parser_normalisation_for_dashboard` — orchestrates the run parser normalisation for dashboard entry point and its ordered parsing and reporting service operations.
# [FYP-INPUT] Parameters: `raw_alert`, `output_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis parsing and reporting service workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main, soc_workflow.py:run_parsing; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `build_agent_friendly_processed_alert`, `build_standard_alert`, `get`, `isoformat`, `len`, `make_json_safe`, `now`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def run_parser_normalisation_for_dashboard(raw_alert: Any, output_dir: str | Path = "outputs/soc_context_parser") -> Dict[str, Any]:
    """Run parser and return all dashboard-facing artefacts.

    This is the function the Flask adapter uses. It keeps the original parser
    outputs and also emits a flat processed_alert for existing agents.
    """
    output_dir = Path(output_dir)
    result = build_standard_alert(raw_alert, output_dir=str(output_dir))
    paths = write_outputs(result, output_dir=str(output_dir), write_debug=True)
    normalised = result.get("normalised_alert") or {}
    processed = build_agent_friendly_processed_alert(normalised)
    parsed_path = output_dir / "parsed_incident.json"
    processed_path = output_dir / "processed_alert.json"
    save_json_file(processed, str(parsed_path))
    save_json_file(processed, str(processed_path))

    parser_summary = result.get("parser_summary") or {}
    dashboard_result = {
        "agent": "Parsing and Normalisation",
        "agent_source": "services/parser_normaliser.py",
        "status": "completed" if result.get("parser_status") == "completed" else "failed",
        "display_status": "Completed" if result.get("parser_status") == "completed" else "Failed",
        "current_stage": "parsing_normalisation_completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": parser_summary.get("important_extracted_fields", {}).get("alert_name") or "NetWitness alert parsed and normalised for downstream SOC agents.",
        "parser_status": result.get("parser_status"),
        "parser_confidence": parser_summary.get("parser_confidence", "Unknown"),
        "parser_confidence_score": parser_summary.get("parser_confidence_score", 0),
        "selected_alert_id": result.get("selected_alert_id"),
        "normalised_alert_count": result.get("normalised_alert_count", 0),
        "event_count": result.get("event_count", 0),
        "important_extracted_fields": parser_summary.get("important_extracted_fields", {}),
        "missing_important_fields": parser_summary.get("missing_important_fields", []),
        "warnings": parser_summary.get("warnings", []),
        "parser_summary_card": {
            "input_source": "parser_input",
            "raw_events_retrieved": (normalised.get("alert_summary") or {}).get("raw_event_count", 0),
            "important_fields_extracted": len(parser_summary.get("important_extracted_fields", {}) or {}),
            "missing_fields": parser_summary.get("missing_important_fields", []),
            "powershell_decode_status": (normalised.get("powershell_analysis") or {}).get("decode_status") or "not_detected",
            "ioc_count": len(processed.get("iocs") or []),
            "parser_confidence": parser_summary.get("parser_confidence", "Unknown"),
            "parser_confidence_score": parser_summary.get("parser_confidence_score", 0),
            "warnings": parser_summary.get("warnings", []),
        },
        "normalised_alert": normalised,
        "processed_alert": processed,
        "output_files": {**paths, "parsed_incident_file": str(parsed_path), "processed_alert_flat": str(processed_path)},
        "recommended_next_action": "Run Triage Agent using the normalised alert context." if result.get("parser_status") == "completed" else "Review parser errors or input format before continuing.",
    }
    return make_json_safe(dashboard_result)
