# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: datetime, json, os, re, yaml.
# =============================================================================
# File: soc_investigation_agent_revised/ingest_pipeline.py
# Purpose: [FYP-PROCESS] Raw-log normalization layer — turns a single raw
#   alert JSON file (as handed off by soc_workflow.py's
#   handoff_to_investigation() into triaged_alerts/) into the standard
#   in-memory alert dict shape ({"id", "document", "metadata", ["alerts"]})
#   used everywhere else in this subsystem: ChromaDB ingestion
#   (vector_engine.py), correlation scoring (correlation_engine.py),
#   orchestration seeding/timelines (orchestrator.py).
# Main functionalities:
#   1. extract_mapped_fields(): source-type detection + config-driven field
#      mapping (log_config.yaml) that pulls username/hostname/timestamp out
#      of differently-shaped raw log JSON schemas.
#   2. scan_indicators(): regex-based forensic marker extraction (IPs,
#      SHA256/MD5 hashes, emails, domains) over a flattened JSON string —
#      this IS the indicator-discovery step orchestrator.py's seeding and
#      pivoting logic (prepare_seeds/broaden_indicators) builds on.
#   3. serialize_json_to_narrative(): deterministic (non-LLM) conversion of
#      the raw nested JSON into a flat natural-language narrative string —
#      this becomes the ChromaDB embedding document AND the per-alert line
#      orchestrator.build_timeline_text() assembles into the incident
#      timeline the LLMs reason over.
#   4. [FYP-EVALUATOR] process_log_file(): the public entry point that
#      chains all of the above — parse -> map fields -> scan indicators ->
#      serialize narrative -> pack ChromaDB-ready metadata dict.
# Inputs: a raw alert JSON file path.
# Outputs: dict {"id": incident_id, "document": narrative_str, "metadata":
#   {...flat scalar fields for ChromaDB filtering...}, optionally "alerts":
#   [...] if the raw JSON carries a sub-alerts list}.
# Workflow position: Investigation stage, the FIRST step applied to every
#   raw alert — both the bulk-ingestion pass (main.py's main_async()) and
#   ad-hoc single-alert pivoting (orchestrator.orchestrate_incident()) call
#   this before anything else touches the alert.
# Called by [FYP-USED-BY]: main.py (main_async, generate_local_standalone_
#   report), correlation_engine.py, orchestrator.py — verify exact call
#   sites via grep before demoing.
# Calls [FYP-CALLS]: nothing else in this subsystem (pure stdlib + PyYAML);
#   reads soc_investigation_agent_revised/log_config.yaml for source-type
#   field mappings.
# Key evaluator search terms: process_log_file, scan_indicators,
#   extract_mapped_fields, [FYP-EVALUATOR]
# =============================================================================

import os
import re
import yaml
import json
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "log_config.yaml")

# Load configuration registry
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        log_config = yaml.safe_load(f)
else:
    # Fallback default configuration if not found
    log_config = {
        "source_detection": [],
        "mappings": {
            "Default": {
                "username": ["log_indicators.target_user", "authentication_details.attempted_target_user"],
                "hostname": ["log_indicators.computer_name"],
                "timestamp": ["incident_details.timestamp"]
            }
        }
    }

# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def get_nested_value(data, path_str):
    """
    [FYP-FUNCTION] Safely walks a dotted path (e.g.
    "log_indicators.target_user") through a nested dict, returning None as
    soon as any intermediate key is missing or not a dict, instead of
    raising KeyError/TypeError. Used by extract_mapped_fields() to probe a
    ranked list of candidate field paths per source-type schema.
    """
    parts = path_str.split('.')
    cur = data
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur

def extract_mapped_fields(data: dict) -> dict:
    """
    [FYP-FUNCTION] Config-driven field extraction: uses log_config.yaml's
    "source_detection" rules (a list of {key, source_type} probes, first
    match wins) to classify which SIEM/log schema `data` came from, then
    looks up that source_type's field-mapping rules in log_config.yaml's
    "mappings" section (falling back to the "Default" mapping if the
    detected source_type has none) to pull out username, hostname, and a
    raw timestamp string via get_nested_value(), trying each candidate path
    in order until one resolves to a value.

    Returns a dict with source_type, username, hostname, timestamp_str —
    each defaulting to "Unknown" if no candidate path matched. This
    normalization is what lets correlation_engine.py and orchestrator.py
    reason about "the username"/"the hostname" of an alert without caring
    which raw log schema it originated from.
    """
    source_type = "Default"
    for det in log_config.get("source_detection", []):
        if det["key"] in data:
            source_type = det["source_type"]
            break
            
    mappings = log_config.get("mappings", {}).get(source_type, log_config["mappings"]["Default"])
    
    username = None
    for field in mappings.get("username", []):
        username = get_nested_value(data, field)
        if username:
            break
            
    hostname = None
    for field in mappings.get("hostname", []):
        hostname = get_nested_value(data, field)
        if hostname:
            break
            
    timestamp_str = None
    for field in mappings.get("timestamp", []):
        timestamp_str = get_nested_value(data, field)
        if timestamp_str:
            break
            
    return {
        "source_type": source_type,
        "username": str(username) if username else "Unknown",
        "hostname": str(hostname) if hostname else "Unknown",
        "timestamp_str": str(timestamp_str) if timestamp_str else "Unknown"
    }

def parse_timestamp_to_epoch(timestamp_str: str) -> int:
    """
    [FYP-FUNCTION] Converts an ISO 8601-ish timestamp string (as extracted
    by extract_mapped_fields()) into a Unix epoch integer, trying
    datetime.fromisoformat() first (handles a trailing 'Z' by rewriting to
    '+00:00') and falling back to a stripped-format strptime() for
    non-standard variants (extra millisecond precision, different
    timezone suffixes). Returns 0 on any parse failure or missing input.

    The resulting epoch is what powers every time-window operation
    downstream: correlation_engine.py's temporal scoring,
    vector_engine.py's timestamp_epoch metadata filtering, and
    orchestrator.py's 24-hour RRF pivot window.
    """
    if not timestamp_str or timestamp_str == "Unknown":
        return 0
    try:
        t_str = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(t_str)
        return int(dt.timestamp())
    except Exception:
        try:
            # Fallback for alternative millisecond or timezone formats
            t_str = timestamp_str.split(".")[0].replace("Z", "")
            dt = datetime.strptime(t_str, "%Y-%m-%dT%H:%M:%S")
            return int(dt.timestamp())
        except Exception:
            return 0

# Compile global regex objects for scanning tokens
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b')
DOMAIN_REGEX = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b')

EXCLUDED_EXTENSIONS = {
    '.exe', '.dll', '.txt', '.php', '.yaml', '.json', '.sys', 
    '.lnk', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.zip', '.rar'
}

def scan_indicators(flat_string: str) -> dict:
    """
    [FYP-FUNCTION] Regex-scans a flat string representation of JSON (usually
    json.dumps(data) or json.dumps(metadata)) for forensic markers: IPv4
    addresses, SHA256/MD5 hashes, email addresses, and domains. Domain
    matches are filtered to drop anything that's actually an IP, a numeric-
    only token, or ends in a known non-domain file extension (.exe, .json,
    .pdf, etc. — see EXCLUDED_EXTENSIONS) to reduce false-positive "domain"
    hits on filenames.

    Returns {"ips": [...], "sha256s": [...], "md5s": [...], "emails": [...],
    "domains": [...]}, each deduplicated. This is the sole indicator-
    discovery mechanism feeding orchestrator.py's seed extraction
    (orchestrate_incident()) and pivot-following (each newly-correlated
    alert's metadata is re-scanned here to discover further pivot
    candidates).

    [FYP-USED-BY]: process_log_file(); orchestrator.orchestrate_incident()
    (re-scans each newly-correlated alert's metadata for further pivots).
    """
    ips = list(set(IPV4_REGEX.findall(flat_string)))
    sha256s = list(set(SHA256_REGEX.findall(flat_string)))
    md5s = list(set(MD5_REGEX.findall(flat_string)))
    emails = list(set(EMAIL_REGEX.findall(flat_string)))
    
    # Filter domains to exclude pure IPs, numeric values, and file names
    all_domains = DOMAIN_REGEX.findall(flat_string)
    filtered_domains = []
    for d in all_domains:
        if IPV4_REGEX.match(d):
            continue
        ext = os.path.splitext(d.lower())[1]
        if ext in EXCLUDED_EXTENSIONS:
            continue
        if d.replace('.', '').isdigit():
            continue
        filtered_domains.append(d)
        
    domains = list(set(filtered_domains))
    
    return {
        "ips": ips,
        "sha256s": sha256s,
        "md5s": md5s,
        "emails": emails,
        "domains": domains
    }

# [FYP-FUNCTION] `serialize_json_to_narrative` — implements the serialize json to narrative operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/ingest_pipeline.py:process_log_file; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `enumerate`, `get`, `isinstance`, `join`, `len`, `recurse`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def serialize_json_to_narrative(data: dict) -> str:
    """Recursively serializes JSON fields into structural narrative sentences."""
    lines = []
    incident_id = data.get("incident_id", "Unknown")
    lines.append(f"Incident {incident_id} details are as follows:")
    
    alerts_list = data.get("alerts") or data.get("raw_alerts")
    if isinstance(alerts_list, list) and alerts_list:
        lines.append(f"Incident {incident_id} contains {len(alerts_list)} correlated alert(s):")
        for idx, alt in enumerate(alerts_list, 1):
            if isinstance(alt, dict):
                aid = alt.get("alert_id") or alt.get("id") or f"A-{idx}"
                atitle = alt.get("title") or alt.get("name") or "Security Event"
                ats = alt.get("timestamp") or alt.get("created") or "Unknown Time"
                asev = alt.get("severity") or "Medium"
                auser = alt.get("user") or alt.get("userName") or "Unknown"
                ahost = alt.get("hostname") or alt.get("hostSummary") or "Unknown"
                asrc = alt.get("source_ip") or alt.get("sourceIp") or "Unknown"
                adst = alt.get("destination_ip") or alt.get("destinationIp") or "Unknown"
                adesc = alt.get("description") or alt.get("detail") or ""
                lines.append(
                    f"Alert #{idx} ({aid}) - '{atitle}' at [{ats}], Severity: {asev}, User: {auser}, Host: {ahost}, SrcIP: {asrc}, DstIP: {adst}. Detail: {adesc}".strip()
                )
    
    # [FYP-FUNCTION] `recurse` — implements the recurse operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `d`, `parent_key`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/ingest_pipeline.py:recurse, soc_investigation_agent_revised/ingest_pipeline.py:serialize_json_to_narrative; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `isinstance`, `items`, `join`, `recurse`, `replace`, `sorted`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def recurse(d, parent_key=""):
        for k, v in sorted(d.items()):
            if k in ("alerts", "raw_alerts"):
                continue  # Explicitly handled as sub-alerts above
            full_key = f"{parent_key} {k}".strip().replace("_", " ")
            if isinstance(v, dict):
                recurse(v, full_key)
            elif isinstance(v, list):
                items_str = ", ".join(str(i) for i in v)
                lines.append(f"The {full_key} lists: {items_str}.")
            elif v is not None:
                lines.append(f"The {full_key} is {v}.")
                
    recurse(data)
    return " ".join(lines)

# [FYP-FUNCTION] `process_log_file` — implements the process log file operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `filepath`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async, soc_investigation_agent_revised/orchestrator.py:orchestrate_incident; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `basename`, `dumps`, `extract_mapped_fields`, `get`, `join`, `len`, `load`, `open`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def process_log_file(filepath: str) -> dict:
    """Parses, scans, normalizes, and serializes a raw log JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    incident_id = data.get("incident_id", os.path.basename(filepath).split("_")[0])
    
    # Map variables and parse timestamp
    mapped = extract_mapped_fields(data)
    epoch = parse_timestamp_to_epoch(mapped["timestamp_str"])
    
    # Extract indicators via flat JSON string
    flat_str = json.dumps(data)
    indicators = scan_indicators(flat_str)
    
    # Serialize to narrative
    document = serialize_json_to_narrative(data)
    if len(document) > 12000:
        document = document[:12000] + " [TRUNCATED]"
    
    # Extract mitre tactic and technique
    mitre_data = data.get("incident_details", {}).get("mitre_att&ck", {})
    tactic = mitre_data.get("tactic", "Unknown") if mitre_data else "Unknown"
    technique = mitre_data.get("technique", "Unknown") if mitre_data else "Unknown"

    # Pack flat metadata fields for ChromaDB
    metadata = {
        "incident_id": incident_id,
        "source_type": mapped["source_type"],
        "username": mapped["username"],
        "hostname": mapped["hostname"],
        "timestamp_str": mapped["timestamp_str"],
        "timestamp_epoch": epoch,
        "tactic": tactic,
        "technique": technique,
        "ips": ",".join(indicators["ips"]),
        "sha256s": ",".join(indicators["sha256s"]),
        "md5s": ",".join(indicators["md5s"]),
        "emails": ",".join(indicators["emails"]),
        "domains": ",".join(indicators["domains"])
    }

    # Forward the raw alert's pre-investigation "classification.severity"
    # signal (workflow/engine.py::build_investigation_alert() writes
    # ticket.classification there for a Triage-sourced alert) into metadata
    # so main.py::generate_local_standalone_report() -- which reads
    # metadata["severity"] -- actually has an input to read. Only set when
    # the raw alert genuinely carries one: this key was never populated at
    # all before, so main.py's own `.get("severity", "High")` default must
    # keep applying unchanged whenever there is no such signal (e.g. a raw,
    # non-Triage log). This does NOT change Investigation's own final
    # severity, which stays computed independently later (main.py:783-800).
    classification_severity = (data.get("classification") or {}).get("severity")
    if classification_severity:
        metadata["severity"] = classification_severity

    res = {
        "id": incident_id,
        "document": document,
        "metadata": metadata
    }
    if "alerts" in data:
        res["alerts"] = data["alerts"]
    return res
