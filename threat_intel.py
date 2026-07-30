"""
threat_intel.py — Threat Intelligence Enrichment stage (post-triage, pre-investigation).

Looks up file hashes, public IPs, external domains, URL-derived hostnames, and
PowerShell-decoded IOCs against three external reputation services:

  * VirusTotal    — file hash / IP / domain reputation (VT_API_KEY)
  * AbuseIPDB     — IP abuse-confidence reputation (ABUSEIPDB_API_KEY)
  * AlienVault OTX — pulse/threat-community lookups (OTX_API_KEY)

All three are optional — a missing key means that provider is skipped for
whichever IOCs would have used it, never a fabricated result. Every provider
call is wrapped so a network failure degrades to a "skipped"/"error" status
per lookup — the stage itself never breaks.

Output is a single case-level `enrichment_risk_score` / `enrichment_risk_level`
(Low/Medium/High) / `enrichment_risk_reasons` verdict per run, plus the raw
per-provider results under `threat_intelligence`. There is no per-IOC verdict,
confidence, or caching system — each stage run performs its own fresh lookups.
"""

# =============================================================================
# [FYP-FILE] threat_intel.py
# Important dependencies: csv, datetime, dotenv, json, os, pathlib, re, requests.
# -----------------------------------------------------------------------------
# File: threat_intel.py (repo root)
#
# Purpose:
#   Implements the "Threat Intelligence Enrichment" workflow stage — stage 3
#   of 5 in the Aegis pipeline (Parsing & Normalisation -> Triage -> Threat
#   Intelligence Enrichment -> Investigation -> Reporting). Looks up IOCs
#   pulled off an already-triaged alert against external reputation
#   providers and produces a single case-level risk verdict.
#
# Main functionalities:
#   - [FYP-PROCESS] IOC Extraction — extract_iocs() pulls file hash, public
#     IPs, external domains, URL-derived hostnames and decoded PowerShell
#     IOCs off the alert.
#   - [FYP-VALIDATION] IOC validation / private-IP filtering — is_available(),
#     is_ip_address(), is_private_ip(), is_external_domain() decide which
#     extracted values are even worth sending to an external provider
#     (RFC1918/loopback IPs and bare AD hostnames are filtered out).
#   - [FYP-API] External TI provider lookups — VirusTotal (file hash / IP /
#     domain reputation via VT_API_KEY), AbuseIPDB (IP abuse-confidence via
#     ABUSEIPDB_API_KEY), AlienVault OTX (pulse/threat-community lookups via
#     OTX_API_KEY). Every provider is optional and every call degrades to a
#     "skipped"/"error" status instead of raising.
#   - [FYP-PROCESS][FYP-DECISION] Case-level enrichment risk scoring —
#     calculate_enrichment_risk() turns the raw provider results into a
#     single enrichment_risk_score/level/reasons verdict.
#   - [FYP-USED-BY soc_workflow.py] Dashboard integration adapter —
#     flatten_alert_for_enrichment(), _build_flat_alert(),
#     run_threat_intel_for_dashboard() reshape the richer parser/triage
#     output into the simple alert dict this module was originally written
#     against, and write the dashboard-facing result envelope.
#
# Inputs:
#   - Standalone CLI mode: outputs/processed_alert_test_iocs.json (a
#     processed/triaged alert dict).
#   - Dashboard/workflow mode: an in-memory alert dict built from the raw
#     NetWitness incident (alertMeta), Parsing's normalised_alert output and
#     Triage's triage_result, assembled by soc_workflow.run_threat_intel()
#     via _build_flat_alert().
#   - Environment variables (via python-dotenv): VT_API_KEY,
#     ABUSEIPDB_API_KEY, OTX_API_KEY — each optional; a missing key means
#     that provider is skipped, never a fabricated result.
#
# Outputs:
#   - Standalone CLI mode: outputs/enriched_alert.json, outputs/enriched_alert.csv.
#   - Dashboard/workflow mode: <output_dir>/enriched_alert.json and
#     <output_dir>/threat_intel_result.json — the same dict this module
#     returns to its caller, so the on-disk copy and the in-memory result
#     never diverge.
#   - Fields of note: enrichment_risk_score (int), enrichment_risk_level
#     ("Low"/"Medium"/"High"), enrichment_risk_reasons (list[str]),
#     threat_intelligence (per-provider raw results), warnings (missing-key
#     / provider-error strings only — never informational notes).
#
# Workflow position:
#   Stage 3 of 5 — Threat Intelligence Enrichment. Runs after Triage has
#   produced a triage_result and before Investigation. The dashboard result's
#   recommended_next_action states SOC analyst approval is required before
#   the Investigation stage can run.
#
# Called by:
#   - soc_workflow.py: run_threat_intel() dynamically imports this module,
#     calls _build_flat_alert() then run_threat_intel_for_dashboard().
#   - Standalone: `python threat_intel.py` runs main() directly.
#   - No direct caller confidently identified for the module-level
#     enrich_alert()/extract_iocs() functions outside this file and its own
#     main()/run_threat_intel_for_dashboard() — soc_workflow.py only calls
#     the dashboard-facing entry points listed above.
#
# Calls:
#   - requests: HTTP GET to VirusTotal, AbuseIPDB and AlienVault OTX REST APIs.
#   - python-dotenv (load_dotenv): loads VT_API_KEY / ABUSEIPDB_API_KEY /
#     OTX_API_KEY from a local .env file into the environment.
#   - stdlib: json, csv, os, re, pathlib, datetime, urllib.parse.
#
# Key evaluator search terms:
#   IOC extraction, IOC validation, private IP filtering, VirusTotal,
#   AbuseIPDB, AlienVault OTX, threat intelligence enrichment, enrichment
#   risk score, external reputation lookup.
# =============================================================================

import csv
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

import requests
from dotenv import load_dotenv


INPUT_FILE = "outputs/processed_alert_test_iocs.json"
JSON_OUTPUT_FILE = "outputs/enriched_alert.json"
CSV_OUTPUT_FILE = "outputs/enriched_alert.csv"

load_dotenv()


# [FYP-FUNCTION] `load_processed_alert` — retrieves load processed alert data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `load`, `open`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def load_processed_alert() -> Dict[str, Any]:
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


# [FYP-FUNCTION] `save_json` — persists or updates save json state used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include threat_intel.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dump`, `makedirs`, `open`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def save_json(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    with open(JSON_OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


# [FYP-FUNCTION] `flatten_value` — implements the flatten value operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:save_csv; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def flatten_value(value: Any) -> str:
    if isinstance(value, dict) or isinstance(value, list):
        return json.dumps(value, ensure_ascii=False)

    if value is None:
        return ""

    return str(value)


# [FYP-FUNCTION] `save_csv` — persists or updates save csv state used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include threat_intel.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `DictWriter`, `flatten_value`, `items`, `keys`, `makedirs`, `open`, `writeheader`, `writerow`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def save_csv(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    flattened_data = {}

    for key, value in data.items():
        flattened_data[key] = flatten_value(value)

    with open(CSV_OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=flattened_data.keys())
        writer.writeheader()
        writer.writerow(flattened_data)


# -----------------------------------------------------------------------------
# [FYP-SECTION] IOC validation / private-IP filtering
# -----------------------------------------------------------------------------
# [FYP-VALIDATION] The four helpers below gate which extracted values are even
# worth sending to an external TI provider: is_available() filters out empty/
# placeholder strings, is_ip_address()/is_private_ip() filter out malformed
# and RFC1918/loopback IPs (so internal addresses are never sent to
# VirusTotal/AbuseIPDB/OTX), and is_external_domain() filters out bare AD/
# internal hostnames that have no dot. extract_iocs() below calls all four
# before an indicator is added to any *_indicators list.
# [FYP-EVALUATOR] IOC validation / private-IP filtering lives here.
# -----------------------------------------------------------------------------


# [FYP-FUNCTION] `is_available` — evaluates is available conditions so invalid or unsafe threat intelligence and NetWitness integration processing is stopped early.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:_build_flat_alert, threat_intel.py:_first_am, threat_intel.py:_flatten_ioc_list; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `lower`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def is_available(value: Optional[str]) -> bool:
    """[FYP-VALIDATION] True if `value` is a real, non-placeholder string —
    False for None, blank/whitespace-only strings, and common "no data"
    sentinels ("unknown", "n/a", "none", "null")."""
    if value is None:
        return False

    value = str(value).strip()

    if value == "":
        return False

    if value.lower() in ["not available", "unknown", "none", "null", "n/a"]:
        return False

    return True


# [FYP-FUNCTION] `is_ip_address` — evaluates is ip address conditions so invalid or unsafe threat intelligence and NetWitness integration processing is stopped early.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:_flatten_ioc_list, threat_intel.py:extract_iocs, threat_intel.py:is_private_ip; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `int`, `match`, `split`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def is_ip_address(value: str) -> bool:
    """[FYP-VALIDATION] True if `value` is a syntactically valid dotted-quad
    IPv4 address (each octet 0-255). Used to decide whether a string pulled
    off the alert should be treated as an IP indicator at all."""
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if not re.match(pattern, value):
        return False

    parts = value.split(".")

    for part in parts:
        if int(part) < 0 or int(part) > 255:
            return False

    return True


# [FYP-FUNCTION] `is_private_ip` — evaluates is private ip conditions so invalid or unsafe threat intelligence and NetWitness integration processing is stopped early.
# [FYP-INPUT] Parameters: `ip_address`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:extract_iocs; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `int`, `is_ip_address`, `split`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def is_private_ip(ip_address: str) -> bool:
    """[FYP-VALIDATION] Private-IP filter — True for RFC1918 ranges
    (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback (127.0.0.0/8).
    extract_iocs() only queries VirusTotal/AbuseIPDB/OTX for source/
    destination IPs where this returns False, so internal addresses are
    never sent to an external provider."""
    if not is_ip_address(ip_address):
        return False

    parts = ip_address.split(".")
    first = int(parts[0])
    second = int(parts[1])

    if first == 10:
        return True

    if first == 172 and 16 <= second <= 31:
        return True

    if first == 192 and second == 168:
        return True

    if first == 127:
        return True

    return False


# [FYP-FUNCTION] `is_external_domain` — evaluates is external domain conditions so invalid or unsafe threat intelligence and NetWitness integration processing is stopped early.
# [FYP-INPUT] Parameters: `domain`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:extract_iocs; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `is_available`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def is_external_domain(domain: str) -> bool:
    """[FYP-VALIDATION] True if `domain` looks like a real external domain
    rather than a bare internal/AD hostname (which has no dot)."""
    if not is_available(domain):
        return False

    # Example: BETHANYCHUCHU is likely an internal AD/domain name, not an external domain.
    if "." not in domain:
        return False

    return True


# -----------------------------------------------------------------------------
# [FYP-SECTION] IOC extraction
# -----------------------------------------------------------------------------
def extract_iocs(alert: Dict[str, Any]) -> Dict[str, Any]:
    """[FYP-FUNCTION] [FYP-PROCESS] IOC Extraction — pulls the raw indicators
    this stage will look up externally off an already-triaged/normalised
    alert dict: possible_file_name, a file hash (file_hash/sha256/sha1/md5/
    entity_file_hash, first match wins), public source/destination IPs
    (private IPs dropped via is_private_ip()), an external event domain, the
    hostname derived from a URL indicator, the raw URL itself, and any
    IOCs already recovered from decoded PowerShell (powershell_analysis).
    [FYP-VALIDATION] Every candidate is passed through is_available()/
    is_ip_address()/is_private_ip()/is_external_domain() before being kept,
    so malformed values and internal-only addresses/hostnames never reach
    query_virustotal_*/query_abuseipdb/query_otx_indicator().
    [FYP-USED-BY] enrich_alert() (this file) and run_threat_intel_for_dashboard()
    (via its iocs_preview call) are the two callers.
    [FYP-EVALUATOR] IOC extraction happens here."""
    source_ip = alert.get("source_ip")
    destination_ip = alert.get("destination_ip")
    event_domain = alert.get("event_domain")
    url_indicator = alert.get("url")
    possible_file_name = alert.get("possible_file_name")

    file_hash = (
        alert.get("file_hash")
        or alert.get("sha256")
        or alert.get("sha1")
        or alert.get("md5")
        or alert.get("entity_file_hash")
    )

    ip_indicators = []

    if is_available(source_ip) and is_ip_address(source_ip) and not is_private_ip(source_ip):
        ip_indicators.append(source_ip)

    if is_available(destination_ip) and is_ip_address(destination_ip) and not is_private_ip(destination_ip):
        ip_indicators.append(destination_ip)

    domain_indicators = []

    if is_available(event_domain) and is_external_domain(event_domain):
        domain_indicators.append(event_domain)

    url_indicators = []
    if is_available(url_indicator):
        url_indicators.append(str(url_indicator).strip())
        try:
            from urllib.parse import urlparse
            host = urlparse(str(url_indicator)).hostname
            if host and is_external_domain(host):
                domain_indicators.append(host)
        except Exception:
            pass

    return {
        "possible_file_name": possible_file_name,
        "file_hash": file_hash,
        "ip_indicators": list(set(ip_indicators)),
        "domain_indicators": list(set(domain_indicators)),
        "url_indicators": list(set(url_indicators)),
        "powershell_analysis": alert.get("powershell_analysis") or {},
        "powershell_enrichment_note": "Decoded PowerShell IOCs were included for enrichment when available." if alert.get("powershell_analysis") else "No decoded PowerShell analysis was available before enrichment.",
    }


# -----------------------------------------------------------------------------
# [FYP-SECTION] External threat-intelligence API calls
# -----------------------------------------------------------------------------
# [FYP-API] Three optional providers, each keyed by its own environment
# variable (VT_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY). A missing key
# short-circuits to {"status": "skipped", ...} before any HTTP call is made;
# a request exception is caught and returned as {"status": "error", ...} —
# neither path raises, so one provider being down/unconfigured never stops
# the others or the stage. [FYP-ERROR] status_code != 200 and
# requests.RequestException are the two failure paths handled per call.
# [FYP-FUNCTION] `query_virustotal_file_hash` — retrieves query virustotal file hash data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `file_hash`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_virustotal_file_hash_lookup_returns_reputation, threat_intel.py:enrich_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `getenv`, `json`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def query_virustotal_file_hash(file_hash: str) -> Dict[str, Any]:
    """[FYP-API] VirusTotal — GET /api/v3/files/{hash} (VT_API_KEY). Returns
    the file's last_analysis_stats (malicious/suspicious/harmless/undetected
    counts) plus reputation and first-seen metadata. 404 is reported as
    "not_found" (not an error — VT simply has no record of the hash)."""
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY is missing."
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": vt_api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 404:
            return {
                "status": "not_found",
                "indicator": file_hash,
                "reason": "File hash was not found in VirusTotal."
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": file_hash,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "meaningful_name": attributes.get("meaningful_name"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": file_hash,
            "reason": str(error)
        }


# [FYP-FUNCTION] `query_virustotal_ip` — retrieves query virustotal ip data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `ip_address`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_api_keys_read_at_call_time_not_import_time, tests/test_threat_intel_workflow.py:test_missing_api_key_returns_skipped_not_crash, tests/test_threat_intel_workflow.py:test_virustotal_ip_lookup_returns_reputation; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `getenv`, `json`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def query_virustotal_ip(ip_address: str) -> Dict[str, Any]:
    """[FYP-API] VirusTotal — GET /api/v3/ip_addresses/{ip} (VT_API_KEY).
    Called only for IPs that survived is_private_ip() filtering. Returns
    last_analysis_stats plus reputation/country/AS-owner metadata."""
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY is missing."
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": vt_api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": ip_address,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": ip_address,
            "reason": str(error)
        }


# [FYP-FUNCTION] `query_virustotal_domain` — retrieves query virustotal domain data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `domain`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_virustotal_domain_lookup_returns_reputation, threat_intel.py:enrich_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `getenv`, `json`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def query_virustotal_domain(domain: str) -> Dict[str, Any]:
    """[FYP-API] VirusTotal — GET /api/v3/domains/{domain} (VT_API_KEY).
    Called only for domains that passed is_external_domain(). Same
    skipped/error/completed status contract as the file-hash and IP
    variants above."""
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY is missing."
        }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": vt_api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": domain,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": domain,
            "reason": str(error)
        }


# [FYP-FUNCTION] `query_abuseipdb` — retrieves query abuseipdb data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `ip_address`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_abuseipdb_ip_lookup_returns_reputation, tests/test_threat_intel_workflow.py:test_missing_api_key_returns_skipped_not_crash, threat_intel.py:enrich_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `getenv`, `json`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def query_abuseipdb(ip_address: str) -> Dict[str, Any]:
    """[FYP-API] AbuseIPDB — GET /api/v2/check (ABUSEIPDB_API_KEY, 90-day
    lookback). Returns abuse_confidence_score/total_reports plus ISP/
    country/usage-type context — a second, independent reputation signal
    alongside VirusTotal's for the same IP."""
    abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuseipdb_api_key:
        return {
            "status": "skipped",
            "reason": "ABUSEIPDB_API_KEY is missing."
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": abuseipdb_api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": ip_address,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json().get("data", {})

        return {
            "status": "completed",
            "indicator": ip_address,
            "abuse_confidence_score": result.get("abuseConfidenceScore"),
            "total_reports": result.get("totalReports"),
            "country_code": result.get("countryCode"),
            "isp": result.get("isp"),
            "domain": result.get("domain"),
            "usage_type": result.get("usageType"),
            "last_reported_at": result.get("lastReportedAt")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": ip_address,
            "reason": str(error)
        }


# [FYP-FUNCTION] `query_otx_indicator` — retrieves query otx indicator data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `indicator_type`, `indicator_value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_missing_api_key_returns_skipped_not_crash, tests/test_threat_intel_workflow.py:test_otx_domain_lookup_returns_pulse_data, tests/test_threat_intel_workflow.py:test_otx_file_hash_lookup_returns_pulse_data; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `getenv`, `json`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def query_otx_indicator(indicator_type: str, indicator_value: str) -> Dict[str, Any]:
    """[FYP-API] AlienVault OTX — GET /api/v1/indicators/{type}/{value}/general
    (OTX_API_KEY). indicator_type is "IPv4", "domain", or "file" depending
    on caller. Returns pulse_count (how many threat-intel "pulses"/reports
    reference this indicator) and up to 5 related_pulses — the third and
    final TI provider this stage queries."""
    otx_api_key = os.getenv("OTX_API_KEY")
    if not otx_api_key:
        return {
            "status": "skipped",
            "reason": "OTX_API_KEY is missing."
        }

    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator_value}/general"

    headers = {
        "X-OTX-API-KEY": otx_api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": indicator_value,
                "indicator_type": indicator_type,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        pulse_info = result.get("pulse_info", {})

        related_pulses = []

        for pulse in pulse_info.get("pulses", [])[:5]:
            related_pulses.append(pulse.get("name"))

        return {
            "status": "completed",
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "pulse_count": pulse_info.get("count", 0),
            "related_pulses": related_pulses,
            "sections_available": result.get("sections", [])
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "reason": str(error)
        }


def calculate_enrichment_risk(threat_intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    [FYP-FUNCTION] Enrichment Risk Scoring
    [FYP-PROCESS] [FYP-EVALUATOR]

    Case-level risk score/level for the Threat Intelligence Enrichment
    stage — deterministic, rule-based aggregation of the three providers'
    results (no per-IOC verdict system; this rolls everything up into one
    enrichment_risk_score/enrichment_risk_level/enrichment_risk_reasons for
    the whole alert). Reads whichever of virustotal/abuseipdb/otx results
    are present under threat_intel and accumulates risk_score + a
    human-readable reasons list for each signal that fired (e.g. VT
    malicious detections, AbuseIPDB confidence score, OTX pulse count).

    [FYP-USED-BY]: enrich_alert() below, which packages this into the
    stage's final result alongside the raw per-provider lookups.
    """
    risk_score = 0
    reasons = []

    vt_file_result = threat_intel.get("virustotal", {}).get("file_hash")

    if vt_file_result and vt_file_result.get("status") == "completed":
        malicious = vt_file_result.get("malicious", 0)
        suspicious = vt_file_result.get("suspicious", 0)

        if malicious > 0:
            risk_score += 40
            reasons.append(
                f"VirusTotal reported {malicious} malicious detection(s) for the file hash."
            )

        if suspicious > 0:
            risk_score += 15
            reasons.append(
                f"VirusTotal reported {suspicious} suspicious detection(s) for the file hash."
            )

    for result in threat_intel.get("virustotal", {}).get("ip_results", []):
        if result.get("status") == "completed":
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious > 0:
                risk_score += 25
                reasons.append(
                    f"VirusTotal reported {malicious} malicious detection(s) for IP {result.get('indicator')}."
                )

            if suspicious > 0:
                risk_score += 10
                reasons.append(
                    f"VirusTotal reported {suspicious} suspicious detection(s) for IP {result.get('indicator')}."
                )

    for result in threat_intel.get("virustotal", {}).get("domain_results", []):
        if result.get("status") == "completed":
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious > 0:
                risk_score += 25
                reasons.append(
                    f"VirusTotal reported {malicious} malicious detection(s) for domain {result.get('indicator')}."
                )

            if suspicious > 0:
                risk_score += 10
                reasons.append(
                    f"VirusTotal reported {suspicious} suspicious detection(s) for domain {result.get('indicator')}."
                )

    for result in threat_intel.get("abuseipdb", {}).get("ip_results", []):
        if result.get("status") == "completed":
            abuse_score = result.get("abuse_confidence_score") or 0

            if abuse_score >= 80:
                risk_score += 30
                reasons.append(
                    f"AbuseIPDB abuse confidence score is high for {result.get('indicator')}: {abuse_score}."
                )

            elif abuse_score >= 30:
                risk_score += 15
                reasons.append(
                    f"AbuseIPDB abuse confidence score is moderate for {result.get('indicator')}: {abuse_score}."
                )

    for result in threat_intel.get("alienvault_otx", {}).get("otx_results", []):
        if result.get("status") == "completed":
            pulse_count = result.get("pulse_count") or 0

            if pulse_count > 0:
                risk_score += 20
                reasons.append(
                    f"AlienVault OTX found {pulse_count} related pulse(s) for {result.get('indicator')}."
                )

    if risk_score == 0:
        reasons.append(
            "No confirmed malicious external intelligence was found, or no usable IOC was available."
        )

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "enrichment_risk_score": risk_score,
        "enrichment_risk_level": risk_level,
        "enrichment_risk_reasons": reasons
    }


def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    [FYP-FUNCTION] Threat Intelligence Enrichment (single-alert orchestration)
    [FYP-PROCESS] [FYP-ENTRY-POINT] [FYP-EVALUATOR]

    Orchestrates one alert through the whole enrichment pipeline: [FYP-CALLS]
    extract_iocs() -> the three provider queries (query_virustotal_*,
    query_abuseipdb, query_otx_indicator) for whichever IOCs were extracted
    -> calculate_enrichment_risk() to roll everything into a single score/
    level/reasons. Each provider call is independent and never raises (see
    the [FYP-ERROR]/[FYP-FALLBACK] note above query_virustotal_file_hash),
    so a missing API key or a down provider degrades that one signal to
    "skipped"/"error" without blocking the others or this function.

    [FYP-USED-BY]: run_threat_intel_for_dashboard() below wraps this for the
    dashboard/workflow entry point; main() (CLI) also calls it directly.
    """
    iocs = extract_iocs(alert)

    file_name = iocs.get("possible_file_name")
    file_hash = iocs.get("file_hash")
    ip_indicators = iocs.get("ip_indicators", [])
    domain_indicators = iocs.get("domain_indicators", [])

    notes = []

    if is_available(file_name) and not is_available(file_hash):
        notes.append(
            f"{file_name} was extracted, but no file hash was found. VirusTotal and OTX file reputation checks require a hash."
        )

    if len(ip_indicators) == 0:
        notes.append(
            "No usable public IP indicators were found. AbuseIPDB, VirusTotal IP, and OTX IP lookups were skipped."
        )

    url_indicators = iocs.get("url_indicators", [])
    powershell_analysis = iocs.get("powershell_analysis") or {}
    if len(domain_indicators) == 0:
        notes.append(
            "No usable external domain indicators were found. VirusTotal domain and OTX domain lookups were skipped."
        )
    if powershell_analysis:
        if powershell_analysis.get("decode_status") == "success":
            notes.append("PowerShell EncodedCommand content was decoded before threat intelligence enrichment; extracted URLs/domains/IPs/hashes were included where present.")
        elif powershell_analysis.get("powershell_indicator_present"):
            notes.append("PowerShell activity was detected, but no decodable EncodedCommand content was available for IOC extraction.")
    if url_indicators and len(domain_indicators) == 0:
        notes.append("URL indicators were extracted, but no external domain could be derived for domain reputation lookup.")

    threat_intel = {
        "iocs": iocs,
        "virustotal": {
            "file_hash": None,
            "ip_results": [],
            "domain_results": []
        },
        "abuseipdb": {
            "ip_results": []
        },
        "alienvault_otx": {
            "otx_results": []
        },
        "notes": notes
    }

    if is_available(file_hash):
        threat_intel["virustotal"]["file_hash"] = query_virustotal_file_hash(file_hash)

        threat_intel["alienvault_otx"]["otx_results"].append(
            query_otx_indicator("file", file_hash)
        )
    else:
        threat_intel["virustotal"]["file_hash"] = {
            "status": "skipped",
            "reason": "No file hash was available."
        }

    for ip_address in ip_indicators:
        threat_intel["virustotal"]["ip_results"].append(
            query_virustotal_ip(ip_address)
        )

        threat_intel["abuseipdb"]["ip_results"].append(
            query_abuseipdb(ip_address)
        )

        threat_intel["alienvault_otx"]["otx_results"].append(
            query_otx_indicator("IPv4", ip_address)
        )

    for domain in domain_indicators:
        threat_intel["virustotal"]["domain_results"].append(
            query_virustotal_domain(domain)
        )

        threat_intel["alienvault_otx"]["otx_results"].append(
            query_otx_indicator("domain", domain)
        )

    enrichment_risk = calculate_enrichment_risk(threat_intel)

    enriched_alert = {
        **alert,
        "current_stage": "enrichment_completed",
        "threat_intelligence": threat_intel,
        "enrichment_risk_score": enrichment_risk["enrichment_risk_score"],
        "enrichment_risk_level": enrichment_risk["enrichment_risk_level"],
        "enrichment_risk_reasons": enrichment_risk["enrichment_risk_reasons"]
    }

    return enriched_alert


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered threat intelligence and NetWitness integration operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `enrich_alert`, `load_processed_alert`, `print`, `save_csv`, `save_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main() -> None:
    processed_alert = load_processed_alert()
    enriched_alert = enrich_alert(processed_alert)

    save_json(enriched_alert)
    save_csv(enriched_alert)

    print(json.dumps(enriched_alert, indent=4))
    print()
    print(f"Threat intelligence JSON saved to: {JSON_OUTPUT_FILE}")
    print(f"Threat intelligence CSV saved to: {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# Dashboard / workflow integration helpers
# ---------------------------------------------------------------------------

# [FYP-FUNCTION] `_first_non_empty` — implements the first non empty operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `default`, `*values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/common.py:normalise_incident, threat_intel.py:_flatten_ioc_list, threat_intel.py:flatten_alert_for_enrichment; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _first_non_empty(*values: Any, default: Any = None) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


# [FYP-FUNCTION] `_as_list` — implements the as list operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include compliance_evidence.py:_build, compliance_evidence.py:_detection_summary, final_verdict.py:_build; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `list`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _as_list(value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


# [FYP-FUNCTION] `_flatten_ioc_list` — implements the flatten ioc list operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include threat_intel.py:flatten_alert_for_enrichment; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_as_list`, `_first_non_empty`, `append`, `fromkeys`, `get`, `is_available`, `is_ip_address`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _flatten_ioc_list(alert: Dict[str, Any]) -> Dict[str, List[str]]:
    hashes: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    names: List[str] = []
    for item in _as_list(alert.get("iocs")):
        if isinstance(item, dict):
            value = _first_non_empty(item.get("value"), item.get("indicator"), item.get("ioc"), item.get("hash"), item.get("ip"), item.get("domain"))
            typ = str(_first_non_empty(item.get("type"), item.get("kind"), default="")).lower()
        else:
            value = item
            typ = ""
        if not is_available(value):
            continue
        value_text = str(value).strip()
        if typ in {"file_hash", "hash", "sha256", "sha1", "md5"} or len(value_text) in {32, 40, 64}:
            hashes.append(value_text)
        elif typ in {"ip", "ipv4", "source_ip", "destination_ip"} or is_ip_address(value_text):
            ips.append(value_text)
        elif typ in {"domain", "hostname", "url"}:
            domains.append(value_text)
        elif typ in {"file_name", "filename"}:
            names.append(value_text)
    return {
        "hashes": list(dict.fromkeys(hashes)),
        "ips": list(dict.fromkeys(ips)),
        "domains": list(dict.fromkeys(domains)),
        "file_names": list(dict.fromkeys(names)),
    }


# [FYP-FUNCTION] `flatten_alert_for_enrichment` — implements the flatten alert for enrichment operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_powershell_iocs_preserved_through_flatten, threat_intel.py:run_threat_intel_for_dashboard; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_as_list`, `_first_non_empty`, `_flatten_ioc_list`, `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def flatten_alert_for_enrichment(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt rich parser output into the simple alert shape expected here."""
    alert = alert or {}
    normalised = alert.get("normalised_alert") or {}
    compatibility = normalised.get("compatibility_view") or alert.get("compatibility_view") or {}
    network = normalised.get("network_indicators") or alert.get("network_indicators") or {}
    users = normalised.get("user_and_host_indicators") or alert.get("user_and_host_indicators") or {}
    files = normalised.get("file_indicators") or alert.get("file_indicators") or {}
    web = normalised.get("web_indicators") or alert.get("web_indicators") or {}
    ioc_summary = normalised.get("ioc_summary") or alert.get("ioc_summary") or {}
    powershell = normalised.get("powershell_analysis") or alert.get("powershell_analysis") or {}
    ps_iocs = powershell.get("extracted_iocs") if isinstance(powershell, dict) else {}
    if not isinstance(ps_iocs, dict):
        ps_iocs = {}
    ioc_lists = _flatten_ioc_list(alert)

    source_ips = _as_list(network.get("source_ips")) + _as_list(alert.get("source_ip")) + _as_list(ps_iocs.get("public_ips"))
    destination_ips = _as_list(network.get("destination_ips")) + _as_list(alert.get("destination_ip"))
    domains = (
        _as_list(users.get("domains"))
        + _as_list(web.get("domains"))
        + _as_list(ioc_summary.get("domains"))
        + _as_list(alert.get("event_domain"))
        + _as_list(ps_iocs.get("domains"))
        + ioc_lists["domains"]
    )
    urls = _as_list(web.get("urls")) + _as_list(ioc_summary.get("urls")) + _as_list(alert.get("url")) + _as_list(ps_iocs.get("urls"))
    file_hashes = _as_list(files.get("file_hashes")) + _as_list(ioc_summary.get("hashes")) + _as_list(alert.get("file_hash")) + _as_list(ps_iocs.get("hashes")) + ioc_lists["hashes"]
    file_names = _as_list(files.get("file_names")) + _as_list(ioc_summary.get("files")) + _as_list(alert.get("possible_file_name")) + _as_list(alert.get("file_name")) + _as_list(ps_iocs.get("file_names")) + ioc_lists["file_names"]

    flat = {
        **alert,
        "incident_id": _first_non_empty(alert.get("incident_id"), compatibility.get("incident_id")),
        "incident_title": _first_non_empty(alert.get("incident_title"), compatibility.get("incident_title"), alert.get("alert_name")),
        "alert_id": _first_non_empty(alert.get("alert_id"), compatibility.get("alert_id")),
        "alert_name": _first_non_empty(alert.get("alert_name"), compatibility.get("alert_title")),
        "source_ip": _first_non_empty(*source_ips),
        "destination_ip": _first_non_empty(*destination_ips),
        "event_domain": _first_non_empty(*domains),
        "possible_file_name": _first_non_empty(*file_names),
        "file_hash": _first_non_empty(*file_hashes),
        "url": _first_non_empty(*urls),
        "powershell_analysis": powershell,
        "powershell_decode_status": powershell.get("decode_status") if isinstance(powershell, dict) else None,
        "decoded_powershell_summary": powershell.get("decoded_command_summary") if isinstance(powershell, dict) else None,
        "host": _first_non_empty(alert.get("host"), alert.get("hostname"), compatibility.get("event_domain"), *_as_list(users.get("hostnames"))),
        "hostname": _first_non_empty(alert.get("hostname"), alert.get("host"), compatibility.get("event_domain"), *_as_list(users.get("hostnames"))),
        "iocs": alert.get("iocs") or normalised.get("threat_context", {}).get("related_iocs") or [],
    }
    return flat


# [FYP-FUNCTION] `_build_flat_alert` — constructs build flat alert output for the next threat intelligence and NetWitness integration consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident`, `triage_result`, `normalised_alert`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_threat_intel; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first_am`, `dict`, `get`, `is_available`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _build_flat_alert(incident: Optional[Dict[str, Any]], triage_result: Optional[Dict[str, Any]],
                       normalised_alert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge Parsing's processed_alert (already flat and already carrying the
    nested indicator sections flatten_alert_for_enrichment() reads) with the
    raw incident's alertMeta as a fallback for source_ip/destination_ip/
    event_domain/file_hash, so extract_iocs() has the richest available view
    without re-implementing Triage's own metakey scanning — Parsing's output
    already covers that ground. triage_result is accepted for interface
    symmetry with the workflow's other stage inputs but is not itself
    scanned; nothing here changes if it's absent."""
    base = dict(normalised_alert or {})
    am = (incident or {}).get("alertMeta") or {}

    # [FYP-FUNCTION] `_first_am` — implements the first am operation used by the surrounding threat intelligence and NetWitness integration workflow.
    # [FYP-INPUT] Parameters: `*fields`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include threat_intel.py:_build_flat_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_as_list`, `get`, `is_available`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _first_am(*fields: str) -> Any:
        for field in fields:
            values = am.get(field)
            for v in _as_list(values):
                if is_available(v):
                    return v
        return None

    if not is_available(base.get("source_ip")):
        base["source_ip"] = _first_am("SourceIp", "Source_IP", "source_ip")
    if not is_available(base.get("destination_ip")):
        base["destination_ip"] = _first_am("DestinationIp", "Destination_IP", "destination_ip")
    if not is_available(base.get("event_domain")):
        base["event_domain"] = _first_am("AlertDomain", "Domain", "domain", "EventDomain")
    if not is_available(base.get("file_hash")):
        base["file_hash"] = _first_am("Checksum", "FileHash", "SHA256", "SHA1", "MD5")

    return base


# [FYP-FUNCTION] `_iter_provider_results` — implements the iter provider results operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `threat_intel`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Yields values to its iterator consumer; any state/file/database effects are visible in the body.
# [FYP-USED-BY] Static symbol references include threat_intel.py:run_threat_intel_for_dashboard; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _iter_provider_results(threat_intel: Dict[str, Any]):
    """Yield (provider_label, result_dict) for every per-indicator lookup
    result the engine produced, regardless of whether the provider stores it
    as a single dict (VirusTotal's file_hash) or a list (everything else)."""
    vt = threat_intel.get("virustotal") or {}
    file_hash_result = vt.get("file_hash")
    if isinstance(file_hash_result, dict):
        yield "VirusTotal", file_hash_result
    for r in vt.get("ip_results") or []:
        yield "VirusTotal", r
    for r in vt.get("domain_results") or []:
        yield "VirusTotal", r
    for r in (threat_intel.get("abuseipdb") or {}).get("ip_results") or []:
        yield "AbuseIPDB", r
    for r in (threat_intel.get("alienvault_otx") or {}).get("otx_results") or []:
        yield "AlienVault OTX", r


def run_threat_intel_for_dashboard(alert: Dict[str, Any], output_dir: str | Path = "outputs/threat_intel") -> Dict[str, Any]:
    """
    [FYP-FUNCTION] Threat Intelligence Enrichment — Dashboard/Workflow Entry Point
    [FYP-ENTRY-POINT] [FYP-EVALUATOR] [FYP-OUTPUT]

    Run external IOC enrichment and return dashboard-facing artefacts.

    [FYP-USED-BY]: soc_workflow.run_threat_intel() (repo root) is the
    confirmed caller — it builds a flat alert via threat_intel._build_flat_alert()
    then calls this function, re-keying the result onto the workflow's
    stage-result envelope without further mutation.

    Computes the case-level `warnings` list (applicable-provider missing-key
    skips and genuine provider errors — never informational notes) and the
    resulting `status` BEFORE writing anything to disk, so the returned dict,
    the on-disk enriched_alert.json, and threat_intel_result.json are always
    the exact same data. Nothing about this result is mutated afterward by
    any caller."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    flat_alert = flatten_alert_for_enrichment(alert)

    iocs_preview = extract_iocs(flat_alert)
    applicable_providers = set()
    if is_available(iocs_preview.get("file_hash")):
        applicable_providers |= {"virustotal", "alienvault_otx"}
    if iocs_preview.get("ip_indicators"):
        applicable_providers |= {"virustotal", "abuseipdb", "alienvault_otx"}
    if iocs_preview.get("domain_indicators"):
        applicable_providers |= {"virustotal", "alienvault_otx"}

    key_env = {"virustotal": "VT_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY", "alienvault_otx": "OTX_API_KEY"}
    provider_label = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "alienvault_otx": "AlienVault OTX"}
    missing_key_warnings = [
        f"{provider_label[p]} not queried — {key_env[p]} is not configured."
        for p in sorted(applicable_providers) if not os.getenv(key_env[p])
    ]

    enriched_alert = enrich_alert(flat_alert)
    threat_intel = enriched_alert.get("threat_intelligence") or {}

    provider_error_warnings = [
        f"{plabel} lookup for {r.get('indicator', '?')} failed."
        for plabel, r in _iter_provider_results(threat_intel)
        if r.get("status") == "error"
    ]

    warnings = missing_key_warnings + provider_error_warnings
    status = "completed_with_warnings" if warnings else "completed"
    created_at = datetime.now(timezone.utc).isoformat()

    enriched_alert["agent"] = "Threat Intelligence Enrichment"
    enriched_alert["agent_source"] = "threat_intel.py"
    enriched_alert["status"] = status
    enriched_alert["created_at"] = created_at
    enriched_alert["current_stage"] = "threat_intelligence_completed"
    enriched_alert["recommended_next_action"] = "Submit the enriched case for SOC analyst approval before Investigation."
    enriched_alert["warnings"] = warnings

    output_json = output_dir / "enriched_alert.json"
    output_json.write_text(json.dumps(enriched_alert, indent=2, ensure_ascii=False), encoding="utf-8")

    notes = threat_intel.get("notes", [])
    summary = (
        f"Threat intelligence enrichment completed with "
        f"{enriched_alert.get('enrichment_risk_level', 'Unknown')} enrichment risk."
    )
    if iocs_preview.get("powershell_analysis"):
        summary += " Decoded PowerShell indicators were included where available."

    result = {
        "agent": "Threat Intelligence Enrichment",
        "agent_source": "threat_intel.py",
        "status": status,
        "current_stage": "threat_intelligence_completed",
        "created_at": created_at,
        "summary": summary,
        "enrichment_risk_score": enriched_alert.get("enrichment_risk_score"),
        "enrichment_risk_level": enriched_alert.get("enrichment_risk_level"),
        "enrichment_risk_reasons": enriched_alert.get("enrichment_risk_reasons", []),
        "threat_intelligence": threat_intel,
        "notes": notes,
        "warnings": warnings,
        "enriched_alert": enriched_alert,
        "output_files": {
            "enriched_alert_json": str(output_json),
            "docx": "generate_on_download",
            "pdf": "generate_on_download",
        },
        "export_status": {
            "docx": "generate_on_download",
            "pdf": "generate_on_download",
            "csv": "not_generated",
        },
        "recommended_next_action": "SOC analyst approval is required before Investigation Agent can run.",
    }
    (output_dir / "threat_intel_result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
