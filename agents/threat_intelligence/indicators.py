"""
indicators.py — IOC-centric bookkeeping for the Threat Intelligence
Enrichment stage.

threat_intel.py owns the provider calls and the (unchanged) case-level risk
calculation. This module owns everything about *which* indicators exist and
what happened to each one, so the analyst can see:

  * every indicator extracted from the incident (value, type, source /
    destination role, where it came from),
  * which were eligible for external lookup and which were EXCLUDED (and why
    — private, multicast, broadcast, internal hostname, unsupported type...),
  * which eligible indicators were SKIPPED (per-type enrichment limit, or no
    provider configured) rather than silently dropped,
  * a per-indicator view of what each provider returned, the infrastructure
    context the providers reported, and the intelligence gaps of the run.

Nothing here scores, weights or interprets provider evidence: the stage's
risk score/level stay exclusively in threat_intel.calculate_enrichment_risk().
Provider values are copied (and timestamps made readable), never judged.

Pure functions only — no HTTP, no file I/O — so the whole module is cheap to
test and safe to call more than once per run.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

# -----------------------------------------------------------------------------
# Enrichment limit
# -----------------------------------------------------------------------------
# Provider lookups run sequentially inside the stage worker: one file hash
# costs 2 requests (VirusTotal + OTX), one IP 3 (VirusTotal + AbuseIPDB + OTX),
# one domain 2 (VirusTotal + OTX), each with a 20 s timeout. A cap of 10 per
# indicator type therefore bounds a run at 70 requests, while still covering
# every external indicator seen in the largest real incident in this
# deployment's case database (8 global destination IPs). The VirusTotal
# public API allows 4 requests/minute, so on a free key the later lookups of a
# large run come back as HTTP 429 — they are recorded as failed lookups and
# surfaced as warnings, never hidden. Deployments with premium keys can raise
# the limit; deployments on free keys can lower it.
MAX_INDICATORS_ENV = "TI_MAX_INDICATORS_PER_TYPE"
DEFAULT_MAX_INDICATORS_PER_TYPE = 10

# Indicator types a configured provider can actually look up, and which
# providers apply to each (mirrors enrich_alert()'s dispatch).
ENRICHABLE_TYPES = ("hash", "ip", "domain")
PROVIDERS_BY_TYPE = {
    "hash": ("virustotal", "otx"),
    "ip": ("virustotal", "abuseipdb", "otx"),
    "domain": ("virustotal", "otx"),
}
PROVIDER_LABELS = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "otx": "AlienVault OTX"}
PROVIDER_ENV = {"virustotal": "VT_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY", "otx": "OTX_API_KEY"}
TYPE_LABELS = {"hash": "file hash", "ip": "IP address", "domain": "domain", "url": "URL", "file_name": "file name"}

# RFC 5737 / RFC 3849 documentation ranges are not globally routable, but
# they are also never seen in real traffic: the project's own fixtures and
# demo data use them as stand-ins for public addresses. They stay eligible
# (exactly as before this module existed) so those fixtures keep exercising
# the public-IP path. Remove an entry here to exclude it.
_DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")
_LIMITED_BROADCAST = ipaddress.ip_address("255.255.255.255")

# Suffixes that only resolve inside an organisation (RFC 6762 .local,
# RFC 8375 home.arpa, ICANN-reserved .internal, common LAN conventions) or
# are DNS infrastructure names (.arpa reverse zones). External reputation
# services hold nothing useful for them.
_INTERNAL_DOMAIN_SUFFIXES = (".local", ".localhost", ".localdomain", ".internal", ".lan", ".arpa")

_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)+$")
_PLACEHOLDERS = {"", "not available", "unknown", "none", "null", "n/a", "-"}

# Where an indicator was found. Shown verbatim to the analyst.
ORIGIN_ALERT = "Alert field"
ORIGIN_ALERT_META = "NetWitness alert metadata"
ORIGIN_NETWORK = "Parsed network indicators"
ORIGIN_WEB = "Parsed web indicators"
ORIGIN_FILES = "Parsed file indicators"
ORIGIN_USERS = "Parsed user/host indicators"
ORIGIN_IOC_SUMMARY = "Parsed IOC summary"
ORIGIN_RELATED = "Related IOCs"
ORIGIN_POWERSHELL = "Decoded PowerShell"
ORIGIN_URL = "Derived from URL"

# AbuseIPDB's published category table (https://www.abuseipdb.com/categories).
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def max_indicators_per_type() -> int:
    """The configured per-type lookup limit (read at call time so a test or
    operator can change it without a restart). Invalid / non-positive values
    fall back to the default rather than disabling enrichment."""
    raw = os.getenv(MAX_INDICATORS_ENV)
    try:
        value = int(str(raw).strip()) if raw not in (None, "") else DEFAULT_MAX_INDICATORS_PER_TYPE
    except ValueError:
        return DEFAULT_MAX_INDICATORS_PER_TYPE
    return value if value > 0 else DEFAULT_MAX_INDICATORS_PER_TYPE


# -----------------------------------------------------------------------------
# Eligibility
# -----------------------------------------------------------------------------

def _present(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in _PLACEHOLDERS


def parse_ip(value: Any) -> Optional[ipaddress._BaseAddress]:
    """IPv4/IPv6 address object for `value`, or None. IPv4-mapped IPv6
    addresses (::ffff:a.b.c.d) are reduced to their IPv4 form."""
    text = str(value or "").strip().strip("[]")
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def classify_ip(value: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(canonical value, exclusion category, exclusion reason). A None
    category means the address is eligible for external lookup.

    `ipaddress.is_global` alone is not sufficient: it is True for multicast
    (224.0.0.251, ff02::1), so multicast is checked explicitly first."""
    address = parse_ip(value)
    if address is None:
        return str(value or "").strip(), "invalid", "Not a valid IP address"
    canonical = str(address)
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return canonical, None, None
    if address.is_unspecified:
        return canonical, "non_global", "Unspecified address — not a routable host"
    if address.is_loopback:
        return canonical, "loopback", "Loopback address"
    if address == _LIMITED_BROADCAST:
        return canonical, "broadcast", "Broadcast address — not a routable host"
    if address.is_multicast:
        return canonical, "multicast", "Multicast address — group/local traffic, not a public host"
    if address.is_link_local:
        return canonical, "link_local", "Link-local address"
    if address.version == 4 and address in _SHARED_ADDRESS_SPACE:
        return canonical, "private", "Carrier-grade NAT shared address space (RFC 6598)"
    if address.is_reserved:
        return canonical, "reserved", "Reserved address range — not routable"
    if address.is_private:
        return canonical, "private", "Private/internal address"
    if not address.is_global:
        return canonical, "non_global", "Non-global address — not routable on the public internet"
    return canonical, None, None


def classify_domain(value: Any) -> Tuple[str, Optional[str], Optional[str]]:
    text = str(value or "").strip().rstrip(".").lower()
    if "." not in text:
        return text, "internal_hostname", "Internal hostname — no public domain suffix"
    if text.endswith(_INTERNAL_DOMAIN_SUFFIXES):
        return text, "internal_domain", "Internal/non-public domain suffix"
    if not _DOMAIN_RE.match(text):
        return text, "invalid", "Not a valid domain name"
    return text, None, None


def classify_hash(value: Any) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """(canonical, category, reason, hash type)."""
    text = str(value or "").strip()
    hash_type = _HASH_TYPES.get(len(text)) if _HEX_RE.match(text) else None
    if not hash_type:
        return text, "invalid", "Not a valid MD5, SHA-1 or SHA-256 value", None
    return text.lower(), None, None, hash_type


_UNSUPPORTED_REASONS = {
    "url": "Not enriched — URL reputation lookups are not implemented for the configured providers",
    "file_name": "Not enriched — file reputation lookups require a file hash",
}


# -----------------------------------------------------------------------------
# Candidate collection
# -----------------------------------------------------------------------------

class _Inventory:
    """Ordered, de-duplicated indicator candidates keyed by (type, canonical
    value). A value seen in several places keeps every role and origin."""

    def __init__(self) -> None:
        self._records: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(self, value: Any, kind: str, origin: Optional[str], role: Optional[str] = None) -> None:
        if not _present(value) or kind not in TYPE_LABELS:
            return
        text = str(value).strip()
        category = reason = hash_type = None
        if kind == "domain" and "://" in text:
            kind = "url"
        if kind in ("ip", "domain") and parse_ip(text) is not None:
            kind = "ip"
        if kind == "ip":
            canonical, category, reason = classify_ip(text)
        elif kind == "domain":
            canonical, category, reason = classify_domain(text)
        elif kind == "hash":
            canonical, category, reason, hash_type = classify_hash(text)
        elif kind == "url":
            canonical, category, reason = text, "unsupported_type", _UNSUPPORTED_REASONS["url"]
        else:
            canonical, category, reason = text, "unsupported_type", _UNSUPPORTED_REASONS["file_name"]
        key = (kind, canonical.lower() if kind in ("domain", "url") else canonical)
        record = self._records.get(key)
        if record is None:
            record = {"value": canonical, "type": kind, "roles": [], "origins": [],
                      "exclusion_category": category, "exclusion_reason": reason}
            if hash_type:
                record["hash_type"] = hash_type
            self._records[key] = record
        if role and role not in record["roles"]:
            record["roles"].append(role)
        if origin and origin not in record["origins"]:
            record["origins"].append(origin)
        if kind == "url":
            host = _url_host(text)
            if host:
                self.add(host, "domain", ORIGIN_URL)

    def records(self) -> List[Dict[str, Any]]:
        return list(self._records.values())


def _url_host(url: str) -> Optional[str]:
    try:
        return urlparse(url if "://" in url else f"http://{url}").hostname
    except ValueError:
        return None


def _values(value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def collect_candidates(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every indicator the enrichment input carries, in priority order:

      1. the scalar alert fields extract_iocs() has always read
         (source_ip, destination_ip, event_domain, file hash, url,
         possible_file_name) — so whatever was enriched before this module
         existed is still enriched first when the per-type limit applies;
      2. the full per-source lists flatten_alert_for_enrichment() records
         under `ti_indicator_sources` (Parsing's network/web/file/IOC-summary
         lists, NetWitness alert metadata, decoded PowerShell IOCs);
      3. decoded PowerShell IOCs on the alert itself (direct callers that did
         not go through flatten_alert_for_enrichment()).
    """
    alert = alert or {}
    inventory = _Inventory()
    # On a flattened alert the scalars are copies of the first entry of the
    # per-source lists, which carry the real roles/origins — so the scalars
    # only fix the priority order there. On a plain alert dict they are the
    # indicators themselves.
    flattened = "ti_indicator_sources" in alert
    origin = None if flattened else ORIGIN_ALERT

    def role(name: str) -> Optional[str]:
        return None if flattened else name

    inventory.add(alert.get("source_ip"), "ip", origin, role("source"))
    inventory.add(alert.get("destination_ip"), "ip", origin, role("destination"))
    inventory.add(alert.get("event_domain"), "domain", origin)
    for field in ("file_hash", "sha256", "sha1", "md5", "entity_file_hash"):
        inventory.add(alert.get(field), "hash", origin)
    inventory.add(alert.get("url"), "url", origin)
    inventory.add(alert.get("possible_file_name"), "file_name", origin)

    for source in _values(alert.get("ti_indicator_sources")):
        if isinstance(source, dict):
            inventory.add(source.get("value"), str(source.get("type") or ""), str(source.get("origin") or ""),
                          source.get("role"))

    powershell = alert.get("powershell_analysis")
    extracted = powershell.get("extracted_iocs") if isinstance(powershell, dict) else None
    if isinstance(extracted, dict):
        for field, kind in (("public_ips", "ip"), ("domains", "domain"), ("urls", "url"),
                            ("hashes", "hash"), ("file_names", "file_name")):
            for value in _values(extracted.get(field)):
                inventory.add(value, kind, ORIGIN_POWERSHELL)
    return inventory.records()


def select_indicators(alert: Dict[str, Any], limit: Optional[int] = None) -> Dict[str, Any]:
    """Collect and classify every candidate, then apply the per-type
    enrichment limit to the eligible ones.

    Returns {"limit", "candidates", "selected": {"ip"|"domain"|"hash": [...]}}.
    Each candidate carries `selection`: "selected" (will be looked up),
    "excluded" (not eligible — see exclusion_reason) or "skipped" (eligible
    but over the limit — see skip_reason)."""
    limit = limit or max_indicators_per_type()
    candidates = collect_candidates(alert)
    selected: Dict[str, List[str]] = {kind: [] for kind in ENRICHABLE_TYPES}
    for record in candidates:
        if record["exclusion_category"]:
            record["selection"] = "excluded"
        elif len(selected[record["type"]]) < limit:
            record["selection"] = "selected"
            selected[record["type"]].append(record["value"])
        else:
            record["selection"] = "skipped"
            record["skip_category"] = "limit"
            record["skip_reason"] = (f"Enrichment limit reached — at most {limit} "
                                     f"{TYPE_LABELS[record['type']]} indicators are looked up per run "
                                     f"({MAX_INDICATORS_ENV})")
    return {"limit": limit, "candidates": candidates, "selected": selected}


# -----------------------------------------------------------------------------
# Provider-response helpers (used by threat_intel.py's query_* functions)
# -----------------------------------------------------------------------------

def epoch_to_iso(value: Any) -> Optional[str]:
    """Readable UTC timestamp for a provider epoch-seconds value."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _unique(values: Iterable[Any], limit: int) -> List[str]:
    out: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def virustotal_extras(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """Analyst-useful fields every VirusTotal object response carries."""
    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    detections = []
    if isinstance(results, dict):
        for category in ("malicious", "suspicious"):
            for engine, verdict in results.items():
                if isinstance(verdict, dict) and verdict.get("category") == category:
                    detections.append({"engine": verdict.get("engine_name") or engine,
                                       "category": category, "result": verdict.get("result")})
    categories = attributes.get("categories")
    votes = attributes.get("total_votes") or {}
    return {
        "timeout": stats.get("timeout", 0),
        "tags": _unique(attributes.get("tags") or [], 10),
        "categories": _unique(categories.values() if isinstance(categories, dict) else [], 5),
        "community_votes": {"harmless": votes.get("harmless", 0), "malicious": votes.get("malicious", 0)}
        if isinstance(votes, dict) and votes else None,
        "top_detections": detections[:8],
        "detecting_engine_count": len(detections),
    }


def virustotal_file_extras(attributes: Dict[str, Any]) -> Dict[str, Any]:
    classification = attributes.get("popular_threat_classification") or {}

    def _names(key: str) -> List[str]:
        return _unique((item.get("value") for item in classification.get(key) or [] if isinstance(item, dict)), 5)

    return {
        "type_description": attributes.get("type_description"),
        "size": attributes.get("size"),
        "popular_threat_label": classification.get("suggested_threat_label"),
        "popular_threat_categories": _names("popular_threat_category"),
        "popular_threat_names": _names("popular_threat_name"),
    }


def abuseipdb_extras(data: Dict[str, Any]) -> Dict[str, Any]:
    """Flags and a category summary of the reports the existing verbose
    /check response already includes. Reporter identities and comments are
    deliberately not retained."""
    counts: Counter = Counter()
    reports = data.get("reports") if isinstance(data.get("reports"), list) else []
    for report in reports:
        for category in (report or {}).get("categories") or []:
            counts[category] += 1
    return {
        "is_tor": data.get("isTor"),
        "is_whitelisted": data.get("isWhitelisted"),
        "hostnames": _unique(data.get("hostnames") or [], 5),
        "num_distinct_users": data.get("numDistinctUsers"),
        "reports_considered": len(reports),
        "report_categories": [
            {"id": category, "name": ABUSEIPDB_CATEGORIES.get(category, f"Category {category}"), "count": count}
            for category, count in counts.most_common(6)
        ],
    }


def _names_of(items: Any, *keys: str) -> List[str]:
    out = []
    for item in items or []:
        if isinstance(item, dict):
            out.append(next((item.get(k) for k in keys if item.get(k)), None))
        else:
            out.append(item)
    return [str(v) for v in out if v]


def otx_extras(result: Dict[str, Any]) -> Dict[str, Any]:
    """Concise subset of the existing OTX /general response: per-pulse
    name/dates/tags/families/adversary/ATT&CK IDs (first 5 pulses), the same
    values aggregated across every pulse returned, and OTX's own
    country/ASN for IP indicators."""
    pulse_info = result.get("pulse_info") or {}
    pulses = [p for p in pulse_info.get("pulses") or [] if isinstance(p, dict)]
    related = pulse_info.get("related") or {}
    tag_counts: Counter = Counter()
    families: List[str] = []
    adversaries: List[str] = []
    attack_ids: List[str] = []
    summaries = []
    for pulse in pulses:
        tags = [str(t) for t in pulse.get("tags") or [] if t]
        tag_counts.update(tags)
        pulse_families = _names_of(pulse.get("malware_families"), "display_name", "id")
        pulse_attack = _names_of(pulse.get("attack_ids"), "id", "display_name")
        families += pulse_families
        attack_ids += pulse_attack
        if pulse.get("adversary"):
            adversaries.append(str(pulse["adversary"]))
        if len(summaries) < 5:
            summaries.append({
                "name": pulse.get("name"), "created": pulse.get("created"), "modified": pulse.get("modified"),
                "tags": tags[:5], "malware_families": _unique(pulse_families, 5),
                "adversary": pulse.get("adversary") or None, "attack_ids": _unique(pulse_attack, 8),
                "tlp": pulse.get("TLP") or pulse.get("tlp"),
            })
    for group in related.values() if isinstance(related, dict) else []:
        if isinstance(group, dict):
            families += _names_of(group.get("malware_families"), "display_name", "id")
            adversaries += _names_of(group.get("adversary"), "display_name", "name")
    modified = [str(p.get("modified")) for p in pulses if p.get("modified")]
    return {
        "pulses": summaries,
        "pulse_tags": [tag for tag, _ in tag_counts.most_common(10)],
        "malware_families": _unique(families, 10),
        "adversaries": _unique(adversaries, 5),
        "attack_ids": _unique(attack_ids, 15),
        "latest_pulse_modified": max(modified) if modified else None,
        "country_name": result.get("country_name"),
        "asn": result.get("asn"),
    }


# -----------------------------------------------------------------------------
# Per-indicator view, coverage and gaps (built after the lookups)
# -----------------------------------------------------------------------------

_ANSWERED = ("completed", "not_found")
_ATTEMPTED = ("completed", "not_found", "error")


def _provider_evidence(provider: str, kind: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Concise, analyst-facing copy of one provider's lookup for one
    indicator. Values are the provider's own; only epoch timestamps are made
    readable and VirusTotal's analysed-vendor total is summed from its own
    last_analysis_stats."""
    if kind not in PROVIDERS_BY_TYPE or provider not in PROVIDERS_BY_TYPE[kind]:
        return {"status": "not_applicable"}
    if not isinstance(raw, dict):
        return {"status": "not_queried"}
    status = str(raw.get("status") or "unknown")
    out: Dict[str, Any] = {"status": status}
    if status == "skipped":
        out["status"] = "not_configured"
        out["reason"] = f"{PROVIDER_LABELS[provider]} not queried — {PROVIDER_ENV[provider]} is not configured"
        return out
    if status != "completed":
        if raw.get("status_code"):
            out["http_status"] = raw.get("status_code")
        out["reason"] = raw.get("reason") or (f"HTTP {raw.get('status_code')}" if raw.get("status_code") else None)
        return out
    if provider == "virustotal":
        verdicts = [raw.get(k) for k in ("malicious", "suspicious", "harmless", "undetected")]
        out.update({k: raw.get(k) for k in ("malicious", "suspicious", "harmless", "undetected", "reputation",
                                            "tags", "categories", "community_votes", "top_detections",
                                            "detecting_engine_count")})
        out["analysed_vendors"] = sum(v for v in verdicts if isinstance(v, int)) if all(
            isinstance(v, int) for v in verdicts) else None
        out["last_analysed_at"] = epoch_to_iso(raw.get("last_analysis_date"))
        if kind == "hash":
            out.update({k: raw.get(k) for k in ("meaningful_name", "type_description", "popular_threat_label",
                                                "popular_threat_categories", "popular_threat_names")})
            out["first_submitted_at"] = epoch_to_iso(raw.get("first_submission_date"))
        if kind == "domain":
            out["registrar"] = raw.get("registrar")
            out["domain_created_at"] = epoch_to_iso(raw.get("creation_date"))
    elif provider == "abuseipdb":
        out.update({k: raw.get(k) for k in ("abuse_confidence_score", "total_reports", "num_distinct_users",
                                            "last_reported_at", "is_tor", "is_whitelisted",
                                            "report_categories", "reports_considered")})
    else:
        out.update({k: raw.get(k) for k in ("pulse_count", "related_pulses", "pulses", "pulse_tags",
                                            "malware_families", "adversaries", "attack_ids",
                                            "latest_pulse_modified")})
    return {k: v for k, v in out.items() if v not in (None, "", [], {})} | {"status": out["status"]}


def _context_rows(kind: str, raw: Dict[str, Optional[Dict[str, Any]]], enriched_at: datetime) -> List[Dict[str, Any]]:
    """Infrastructure / ownership facts the providers reported, one row per
    distinct value with every provider that reported it. Absent values are
    omitted — never shown as N/A."""
    rows: List[Dict[str, Any]] = []

    def add(field: str, label: str, value: Any, source: str) -> None:
        if value in (None, "", []):
            return
        if isinstance(value, bool):
            value = "Yes" if value else "No"
        elif isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        text = str(value)
        for row in rows:
            if row["field"] == field and row["value"].lower() == text.lower():
                if source not in row["sources"]:
                    row["sources"].append(source)
                return
        rows.append({"field": field, "label": label, "value": text, "sources": [source]})

    def done(provider: str) -> Dict[str, Any]:
        result = raw.get(provider)
        return result if isinstance(result, dict) and result.get("status") == "completed" else {}

    vt, abuse, otx = done("virustotal"), done("abuseipdb"), done("otx")
    if kind == "ip":
        add("country", "Country", vt.get("country"), "VirusTotal")
        add("country", "Country", abuse.get("country_code"), "AbuseIPDB")
        asn = vt.get("asn")
        add("asn", "ASN", f"AS{asn}" if isinstance(asn, int) else asn, "VirusTotal")
        # OTX words these differently ("Germany", "AS24940 Hetzner"); used
        # only when no other provider reported the field, to avoid
        # duplicate-looking rows for the same fact.
        if not any(r["field"] == "country" for r in rows):
            add("country", "Country", otx.get("country_name"), "AlienVault OTX")
        if not any(r["field"] == "asn" for r in rows):
            add("asn", "ASN", otx.get("asn"), "AlienVault OTX")
        add("as_owner", "AS owner", vt.get("as_owner"), "VirusTotal")
        add("network", "Network", vt.get("network"), "VirusTotal")
        add("isp", "ISP", abuse.get("isp"), "AbuseIPDB")
        add("usage_type", "Usage type", abuse.get("usage_type"), "AbuseIPDB")
        add("domain", "Associated domain", abuse.get("domain"), "AbuseIPDB")
        add("hostnames", "Hostnames", abuse.get("hostnames"), "AbuseIPDB")
        add("is_tor", "Tor exit node", abuse.get("is_tor"), "AbuseIPDB")
        add("is_whitelisted", "AbuseIPDB allow-listed", abuse.get("is_whitelisted"), "AbuseIPDB")
    elif kind == "domain":
        add("registrar", "Registrar", vt.get("registrar"), "VirusTotal")
        created = vt.get("creation_date")
        add("domain_created_at", "Domain registered", epoch_to_iso(created), "VirusTotal")
        if isinstance(created, (int, float)) and created > 0:
            age = (enriched_at - datetime.fromtimestamp(created, tz=timezone.utc)).days
            if age >= 0:
                add("domain_age", "Domain age (at enrichment)", f"{age} day{'s' if age != 1 else ''}", "VirusTotal")
        add("categories", "Categories", vt.get("categories"), "VirusTotal")
    elif kind == "hash":
        add("meaningful_name", "File name (VirusTotal)", vt.get("meaningful_name"), "VirusTotal")
        add("type_description", "File type", vt.get("type_description"), "VirusTotal")
        add("popular_threat_label", "Threat label", vt.get("popular_threat_label"), "VirusTotal")
        add("popular_threat_names", "Malware family names", vt.get("popular_threat_names"), "VirusTotal")
    return rows


def _freshness_rows(kind: str, raw: Dict[str, Optional[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Provider timestamps with the provider's own meaning in the label —
    e.g. 'First submitted to VirusTotal', never a generic 'first seen'."""
    rows = []

    def done(provider: str) -> Dict[str, Any]:
        result = raw.get(provider)
        return result if isinstance(result, dict) and result.get("status") == "completed" else {}

    vt, abuse, otx = done("virustotal"), done("abuseipdb"), done("otx")
    candidates = [
        ("First submitted to VirusTotal", epoch_to_iso(vt.get("first_submission_date")) if kind == "hash" else None,
         "VirusTotal"),
        ("Last VirusTotal analysis", epoch_to_iso(vt.get("last_analysis_date")), "VirusTotal"),
        ("Domain registered", epoch_to_iso(vt.get("creation_date")) if kind == "domain" else None, "VirusTotal"),
        ("Last AbuseIPDB report", abuse.get("last_reported_at"), "AbuseIPDB"),
        ("Most recent OTX pulse update", otx.get("latest_pulse_modified"), "AlienVault OTX"),
    ]
    for label, value, source in candidates:
        if value:
            rows.append({"label": label, "value": value, "source": source})
    return rows


def build_indicator_view(selection: Dict[str, Any],
                         lookups: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]],
                         *, configured: Optional[Dict[str, bool]] = None,
                         enriched_at: Optional[datetime] = None) -> Dict[str, Any]:
    """The IOC-centric part of the stage result.

    `lookups` maps (type, value) -> {provider: raw lookup result} exactly as
    enrich_alert() issued them. `configured` is whether each provider's
    credential was present for this run (used only to word gaps for
    providers that had nothing to look up).

    Returns {"indicators", "coverage", "provider_coverage",
    "intelligence_gaps"}."""
    enriched_at = enriched_at or datetime.now(timezone.utc)
    configured = configured if configured is not None else {p: bool(os.getenv(e)) for p, e in PROVIDER_ENV.items()}
    indicators: List[Dict[str, Any]] = []
    for candidate in selection.get("candidates") or []:
        kind = candidate["type"]
        record: Dict[str, Any] = {
            "value": candidate["value"], "type": kind,
            "roles": list(candidate.get("roles") or []), "origins": list(candidate.get("origins") or []),
            "eligible": candidate.get("selection") in ("selected", "skipped"),
            "status": None, "status_category": None, "status_reason": None,
            "providers_queried": 0, "providers_answered": 0,
            "providers": {}, "context": [], "freshness": [],
        }
        if candidate.get("hash_type"):
            record["hash_type"] = candidate["hash_type"]
        if candidate.get("selection") == "excluded":
            record.update(status="excluded", status_category=candidate.get("exclusion_category"),
                          status_reason=candidate.get("exclusion_reason"))
        elif candidate.get("selection") == "skipped":
            record.update(status="skipped", status_category=candidate.get("skip_category"),
                          status_reason=candidate.get("skip_reason"))
        else:
            raw = lookups.get((kind, candidate["value"])) or {}
            record["providers"] = {p: _provider_evidence(p, kind, raw.get(p)) for p in PROVIDER_LABELS}
            statuses = [str((raw.get(p) or {}).get("status") or "") for p in PROVIDERS_BY_TYPE[kind]]
            record["providers_queried"] = sum(s in _ATTEMPTED for s in statuses)
            record["providers_answered"] = sum(s in _ANSWERED for s in statuses)
            if record["providers_queried"]:
                record["status"] = "enriched"
            else:
                record.update(status="skipped", status_category="no_provider",
                              status_reason="No provider request was sent — no applicable provider is configured")
            record["context"] = _context_rows(kind, raw, enriched_at)
            record["freshness"] = _freshness_rows(kind, raw)
        indicators.append(record)

    order = {"enriched": 0, "skipped": 1, "excluded": 2}
    indicators.sort(key=lambda r: order.get(r["status"], 3))
    coverage = _coverage(indicators, selection.get("limit"))
    provider_coverage = _provider_coverage(indicators, configured)
    return {
        "indicators": indicators,
        "coverage": coverage,
        "provider_coverage": provider_coverage,
        "intelligence_gaps": _gaps(indicators, provider_coverage, coverage),
    }


def _coverage(indicators: List[Dict[str, Any]], limit: Optional[int]) -> Dict[str, Any]:
    by_type: Dict[str, Dict[str, int]] = {}
    for record in indicators:
        bucket = by_type.setdefault(record["type"], {"extracted": 0, "enriched": 0, "excluded": 0, "skipped": 0})
        bucket["extracted"] += 1
        bucket[record["status"]] += 1
    count = Counter(r["status"] for r in indicators)
    return {
        "extracted": len(indicators),
        "eligible": sum(1 for r in indicators if r["eligible"]),
        "enriched": count["enriched"],
        "excluded": count["excluded"],
        "skipped": count["skipped"],
        "skipped_by_limit": sum(1 for r in indicators if r["status_category"] == "limit"),
        "provider_requests": sum(r["providers_queried"] for r in indicators),
        "limit_per_type": limit,
        "by_type": by_type,
    }


def _provider_coverage(indicators: List[Dict[str, Any]], configured: Dict[str, bool]) -> Dict[str, Any]:
    """Per provider, counted from the lookups actually issued: how many
    selected indicators it applied to, how many requests were sent, and how
    each ended. `state` is a display summary of those counts only."""
    out: Dict[str, Any] = {}
    for provider, label in PROVIDER_LABELS.items():
        counts = Counter()
        for record in indicators:
            evidence = record["providers"].get(provider)
            if not evidence or evidence.get("status") == "not_applicable":
                continue
            counts["applicable"] += 1
            counts[evidence.get("status")] += 1
        queried = counts["completed"] + counts["not_found"] + counts["error"]
        if not counts["applicable"]:
            state = "not_applicable"
        elif counts["not_configured"] == counts["applicable"]:
            state = "not_configured"
        elif counts["error"] == counts["applicable"]:
            state = "failed"
        elif counts["error"] or counts["not_configured"]:
            state = "partial"
        else:
            state = "available"
        out[provider] = {
            "label": label, "configured": bool(configured.get(provider)), "state": state,
            "applicable": counts["applicable"], "queried": queried,
            "returned_data": counts["completed"], "not_found": counts["not_found"],
            "failed": counts["error"], "not_configured": counts["not_configured"],
        }
    return out


def _gaps(indicators: List[Dict[str, Any]], providers: Dict[str, Any], coverage: Dict[str, Any]) -> List[str]:
    """Limitations of this run, each stated only when it actually occurred.
    Missing-credential and failed-lookup *warnings* are already reported by
    the stage's `warnings` list; the entries here add the per-indicator
    scope of those problems and every other limitation."""
    gaps: List[str] = []
    for provider, info in providers.items():
        label = info["label"]
        if info["not_configured"]:
            gaps.append(f"{label} was not queried for {info['not_configured']} applicable indicator(s) — "
                        f"{PROVIDER_ENV[provider]} is not configured.")
        if info["failed"]:
            reasons = Counter()
            for record in indicators:
                evidence = record["providers"].get(provider) or {}
                if evidence.get("status") == "error":
                    reasons[str(evidence.get("reason") or "provider error")] += 1
            detail = "; ".join(f"{reason} ×{n}" if n > 1 else reason for reason, n in reasons.most_common(3))
            gaps.append(f"{label} lookup failed for {info['failed']} indicator(s) ({detail}).")
        if info["not_found"]:
            gaps.append(f"{label} had no record for {info['not_found']} indicator(s).")
    urls = [r for r in indicators if r["type"] == "url"]
    if urls:
        gaps.append(f"{len(urls)} URL(s) extracted but not enriched — URL reputation lookups are not "
                    "implemented for the configured providers.")
    if coverage["skipped_by_limit"]:
        gaps.append(f"{coverage['skipped_by_limit']} eligible indicator(s) skipped — the enrichment limit of "
                    f"{coverage['limit_per_type']} per indicator type was reached ({MAX_INDICATORS_ENV}).")
    hashes_enriched = any(r["type"] == "hash" and r["status"] == "enriched" for r in indicators)
    if any(r["type"] == "file_name" for r in indicators) and not hashes_enriched:
        gaps.append("File name(s) were extracted without an enrichable file hash — file reputation requires a hash.")
    if not coverage["eligible"]:
        gaps.append("No eligible external indicators were available — no provider requests were made.")
    return gaps
