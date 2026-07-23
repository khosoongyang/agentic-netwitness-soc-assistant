"""
threat_intel.py — IOC enrichment stage (post-triage, pre-investigation).

Adapted from Anthropic's "Threat Intel Enrichment Agent" cookbook
(platform.claude.com/cookbook/tool-use-threat-intel-enrichment-agent) to fit
this platform's no-new-agent architecture: the cookbook's four tools become
real code-driven lookups, verdict aggregation is deterministic scoring, and
the SYNTHESIS is left to the existing investigation LLM — the enrichment
block is embedded in the investigation alert (same marker contract as the
entity map and triage deep-dive), so Pass1/Pass2 narrate over real intel.

Lookup sources (all optional, all guarded, all short-timeout):
  * ip-api.com          — geolocation / ASN / hosting+proxy flags (free, no key)
  * reverse DNS          — socket.gethostbyaddr
  * Feodo Tracker        — abuse.ch botnet-C2 IP blocklist (free JSON download,
                           cached to soc_db/ti_feodo_cache.json, refreshed daily)
  * RDAP (rdap.org)      — domain registration date/registrar (free, no key)
  * AbuseIPDB            — only when ABUSEIPDB_API_KEY is set
  * VirusTotal           — only when VT_API_KEY is set (IPs, domains, hashes)

Verdict rubric (code, cookbook-inspired):
  MALICIOUS   — Feodo C2 hit, AbuseIPDB confidence ≥ 85, or VT ≥ 5 detections
  SUSPICIOUS  — AbuseIPDB 50-84, VT 1-4, young domain (< 90 days),
                or hosting/proxy-flagged IP with other weak signals
  NO_FINDINGS — sources answered, nothing adverse (NOT proof of clean)
  UNKNOWN     — lookups unavailable/offline

Results are cached in soc_db/ti_cache.json (TTL 24 h) so repeat runs are
cheap and deterministic within the cache window. Everything is wrapped so a
total network failure degrades to honest UNKNOWN verdicts — the workflow
never breaks on enrichment.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any

import requests

_DB_DIR = Path(__file__).resolve().parent / "soc_db"
_CACHE_FILE = _DB_DIR / "ti_cache.json"
_FEODO_FILE = _DB_DIR / "ti_feodo_cache.json"
_CACHE_TTL = 24 * 3600
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_HTTP_TIMEOUT = float(os.environ.get("TI_HTTP_TIMEOUT", "6"))

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ── cache ────────────────────────────────────────────────────────────────────

def _cache_load() -> dict:
    try:
        return json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _cache_save(cache: dict) -> None:
    try:
        _DB_DIR.mkdir(exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(cache), encoding="utf-8")
    except Exception:
        pass


# ── source lookups (each returns evidence strings + raw fields) ──────────────

def _feodo_c2_set() -> set[str]:
    """abuse.ch Feodo Tracker botnet-C2 IPs, cached to disk, refreshed daily."""
    try:
        d = json.loads(_FEODO_FILE.read_text(encoding="utf-8"))
        if time.time() - d.get("fetched", 0) < _CACHE_TTL:
            return set(d.get("ips", []))
    except Exception:
        pass
    try:
        rows = requests.get(_FEODO_URL, timeout=_HTTP_TIMEOUT).json()
        ips = {r.get("ip_address") for r in rows if r.get("ip_address")}
        _DB_DIR.mkdir(exist_ok=True)
        _FEODO_FILE.write_text(
            json.dumps({"fetched": time.time(), "ips": sorted(ips)}),
            encoding="utf-8")
        return ips
    except Exception:
        try:  # stale cache beats nothing
            return set(json.loads(_FEODO_FILE.read_text(encoding="utf-8")).get("ips", []))
        except Exception:
            return set()


def _lookup_ip(ip: str, feodo: set[str]) -> tuple[int, list[str], list[str]]:
    """→ (score_delta, evidence, sources_answered)"""
    score, ev, srcs = 0, [], []

    if ip in feodo:
        score += 90
        ev.append("LISTED on abuse.ch Feodo Tracker botnet-C2 blocklist")
        srcs.append("feodo")
    elif feodo:
        ev.append("not on Feodo C2 blocklist")
        srcs.append("feodo")

    try:  # geolocation / ASN / hosting flags
        r = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,as,isp,reverse,proxy,hosting",
            timeout=_HTTP_TIMEOUT).json()
        if r.get("status") == "success":
            srcs.append("ip-api")
            ev.append(f"geo: {r.get('country')}, {r.get('as')} ({r.get('isp')})")
            if r.get("proxy"):
                score += 20
                ev.append("flagged as proxy/VPN exit")
            if r.get("hosting"):
                score += 10
                ev.append("datacenter/hosting-provider IP (not residential)")
    except Exception:
        pass

    try:  # reverse DNS
        socket.setdefaulttimeout(3)
        ev.append(f"rDNS: {socket.gethostbyaddr(ip)[0]}")
    except Exception:
        pass

    key = os.environ.get("ABUSEIPDB_API_KEY")
    if key:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
                timeout=_HTTP_TIMEOUT).json().get("data", {})
            conf = int(r.get("abuseConfidenceScore") or 0)
            srcs.append("abuseipdb")
            ev.append(f"AbuseIPDB confidence {conf}/100 "
                      f"({r.get('totalReports', 0)} reports)")
            score += 90 if conf >= 85 else (40 if conf >= 50 else 0)
        except Exception:
            pass

    vt = os.environ.get("VT_API_KEY")
    if vt:
        score2, ev2, ok = _vt_lookup(f"ip_addresses/{ip}", vt)
        score += score2
        ev += ev2
        if ok:
            srcs.append("virustotal")
    return score, ev, srcs


def _lookup_domain(domain: str) -> tuple[int, list[str], list[str]]:
    score, ev, srcs = 0, [], []
    try:  # resolution
        socket.setdefaulttimeout(3)
        ips = sorted({a[4][0] for a in socket.getaddrinfo(domain, None)})
        ev.append(f"resolves to {', '.join(ips[:4])}")
    except Exception:
        ev.append("does not currently resolve")
        score += 5

    try:  # RDAP registration age
        r = requests.get(f"https://rdap.org/domain/{domain}",
                         timeout=_HTTP_TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            srcs.append("rdap")
            reg = next((e["eventDate"] for e in d.get("events", [])
                        if e.get("eventAction") == "registration"), None)
            if reg:
                age_days = (time.time() - time.mktime(
                    time.strptime(reg[:10], "%Y-%m-%d"))) / 86400
                ev.append(f"registered {reg[:10]} ({age_days:.0f} days ago)")
                if age_days < 90:
                    score += 25
                    ev.append("YOUNG domain (< 90 days) — common phishing trait")
    except Exception:
        pass

    vt = os.environ.get("VT_API_KEY")
    if vt:
        score2, ev2, ok = _vt_lookup(f"domains/{domain}", vt)
        score += score2
        ev += ev2
        if ok:
            srcs.append("virustotal")
    return score, ev, srcs


def _lookup_hash(h: str) -> tuple[int, list[str], list[str]]:
    vt = os.environ.get("VT_API_KEY")
    if not vt:
        return 0, ["hash reputation requires VT_API_KEY (not configured)"], []
    score, ev, ok = _vt_lookup(f"files/{h}", vt)
    return score, ev, (["virustotal"] if ok else [])


def _vt_lookup(path: str, key: str) -> tuple[int, list[str], bool]:
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}",
                         headers={"x-apikey": key}, timeout=_HTTP_TIMEOUT)
        if r.status_code == 404:
            return 0, ["VirusTotal: not found"], True
        stats = (r.json().get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        mal = int(stats.get("malicious") or 0)
        ev = [f"VirusTotal: {mal} malicious / "
              f"{sum(v for v in stats.values() if isinstance(v, int))} engines"]
        return (90 if mal >= 5 else 40 if mal >= 1 else 0), ev, True
    except Exception:
        return 0, [], False


# ── IOC extraction + verdicts ────────────────────────────────────────────────

def _is_public_ip(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def extract_iocs(incident: dict, triage_result: dict | None = None,
                 max_iocs: int = 8) -> dict:
    """Deterministic IOC pull: hashes and domains from triage metakeys,
    public IPs from alertMeta (destinations before sources)."""
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    am = incident.get("alertMeta") or {}

    hashes, domains, ips = [], [], []
    for key, vals in mkv.items():
        for v in (vals if isinstance(vals, list) else [vals]):
            v = str(v or "").strip()
            if _HASH_RE.match(v):
                hashes.append(v)
            elif ("domain" in key.lower() or "fqdn" in key.lower()) and "." in v:
                domains.append(v)
    for field in ("DestinationIp", "SourceIp"):
        for v in am.get(field) or []:
            if isinstance(v, str) and _IP_RE.match(v) and _is_public_ip(v):
                ips.append(v)

    def dedup(seq):
        return list(dict.fromkeys(seq))

    hashes, domains, ips = dedup(hashes), dedup(domains), dedup(ips)
    n_private = sum(1 for f in ("DestinationIp", "SourceIp")
                    for v in am.get(f) or []
                    if isinstance(v, str) and _IP_RE.match(v) and not _is_public_ip(v))
    picked: list[tuple[str, str]] = (
        [("hash", h) for h in hashes] + [("domain", d) for d in domains]
        + [("ip", i) for i in ips])[:max_iocs]
    return {"iocs": picked, "skipped_private_ips": n_private,
            "truncated": len(hashes) + len(domains) + len(ips) > max_iocs}


def _verdict(score: int, sources: list[str]) -> str:
    if score >= 85:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "NO_FINDINGS" if sources else "UNKNOWN (lookups unavailable)"


def _confidence(score: int, sources: list[str]) -> str:
    """Cookbook-style multi-source corroboration: more independent sources
    answering = higher confidence in the verdict, whatever it is."""
    n = len(sources)
    if n == 0:
        return "NONE (no sources reachable)"
    pts = 40 + 20 * n + (15 if score >= 85 else 0)
    band = "HIGH" if pts >= 80 else ("MEDIUM" if pts >= 60 else "LOW")
    return f"{band} ({n} source{'s' if n != 1 else ''} answered)"


# evidence-pattern → MITRE ATT&CK techniques (deterministic; applied only to
# SUSPICIOUS/MALICIOUS verdicts so weak signals don't spray technique noise)
_MITRE_RULES: list[tuple[str, list[tuple[str, str, str]]]] = [
    ("Feodo Tracker botnet-C2",
     [("T1071", "Application Layer Protocol", "Command and Control"),
      ("T1571", "Non-Standard Port", "Command and Control")]),
    ("proxy/VPN exit",
     [("T1090", "Proxy", "Command and Control")]),
    ("YOUNG domain",
     [("T1583.001", "Acquire Infrastructure: Domains", "Resource Development"),
      ("T1566", "Phishing", "Initial Access")]),
    ("VirusTotal:",  # only reaches here on suspicious/malicious scores
     [("T1204.002", "User Execution: Malicious File", "Execution")]),
]


def _map_mitre(record: dict) -> list[dict]:
    if not record["verdict"].startswith(("MALICIOUS", "SUSPICIOUS")):
        return []
    seen, out = set(), []
    for needle, techniques in _MITRE_RULES:
        if any(needle in e for e in record["evidence"]):
            for tid, name, tactic in techniques:
                if tid not in seen:
                    seen.add(tid)
                    out.append({"technique_id": tid, "technique_name": name,
                                "tactic": tactic})
    return out


def _vt_related(h: str, key: str, limit: int = 4) -> list[tuple[str, str]]:
    """Cookbook cross-referencing hook: contacted IPs/domains of a file hash
    (VirusTotal relationships). Returns [(ioc_type, value), ...]."""
    related: list[tuple[str, str]] = []
    for rel, ioc_type in (("contacted_ips", "ip"), ("contacted_domains", "domain")):
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{h}/{rel}",
                params={"limit": limit},
                headers={"x-apikey": key}, timeout=_HTTP_TIMEOUT)
            for item in r.json().get("data", []):
                v = item.get("id")
                if v and (ioc_type != "ip" or _is_public_ip(v)):
                    related.append((ioc_type, v))
        except Exception:
            pass
    return related


def enrich_iocs(incident: dict, triage_result: dict | None = None,
                max_iocs: int = 8, deadline_seconds: float = 25.0) -> dict:
    """Enrich the incident's IOCs. Returns {"results": [...], "stats": {...}}.
    Cached per-IOC for 24 h; wall-clock-bounded; never raises."""
    t0 = time.time()
    ext = extract_iocs(incident, triage_result, max_iocs=max_iocs)
    cache = _cache_load()
    feodo = _feodo_c2_set() if any(t == "ip" for t, _ in ext["iocs"]) else set()

    results = []
    looked_up = cache_hits = 0
    queue: list[tuple[str, str, str | None]] = [
        (t, v, None) for t, v in ext["iocs"]]        # (type, value, discovered_via)
    processed: set[str] = set()
    vt_key = os.environ.get("VT_API_KEY")

    while queue:
        ioc_type, value, via = queue.pop(0)
        ck = f"{ioc_type}:{value}"
        if ck in processed:
            continue
        processed.add(ck)
        hit = cache.get(ck)
        if hit and time.time() - hit.get("ts", 0) < _CACHE_TTL:
            results.append(hit["r"])
            cache_hits += 1
            continue
        if time.time() - t0 > deadline_seconds:
            results.append({"value": value, "type": ioc_type, "score": 0,
                            "verdict": "UNKNOWN (enrichment deadline reached)",
                            "confidence": "NONE (no sources reachable)",
                            "evidence": [], "sources": [], "mitre_techniques": []})
            continue
        try:
            if ioc_type == "ip":
                score, ev, srcs = _lookup_ip(value, feodo)
            elif ioc_type == "domain":
                score, ev, srcs = _lookup_domain(value)
            else:
                score, ev, srcs = _lookup_hash(value)
                # cookbook cross-referencing: follow the hash's contacted
                # infrastructure (VT-gated; bounded by the shared deadline
                # and the processed-set dedup)
                if vt_key and len(processed) < max_iocs * 2:
                    for rt, rv in _vt_related(value, vt_key):
                        queue.append((rt, rv, value))
        except Exception as exc:
            score, ev, srcs = 0, [f"lookup failed: {exc}"], []
        if via:
            ev = [f"discovered via VT relations of hash {via[:16]}…"] + ev
        looked_up += 1
        r = {"value": value, "type": ioc_type, "score": min(score, 100),
             "verdict": _verdict(score, srcs),
             "confidence": _confidence(score, srcs),
             "evidence": ev, "sources": srcs}
        r["mitre_techniques"] = _map_mitre(r)
        results.append(r)
        cache[ck] = {"ts": time.time(), "r": r}

    if looked_up:
        _cache_save(cache)
    keyed = [s for s, k in (("VirusTotal", "VT_API_KEY"),
                            ("AbuseIPDB", "ABUSEIPDB_API_KEY"))
             if os.environ.get(k)]
    return {
        "results": results,
        "stats": {
            "iocs_enriched": len(results),
            "cache_hits": cache_hits,
            "skipped_private_ips": ext["skipped_private_ips"],
            "truncated": ext["truncated"],
            "keyed_sources": keyed,
            "seconds": round(time.time() - t0, 2),
        },
    }


def format_enrichment(enr: dict) -> str:
    """Plain-text block for the investigation alert / LLM prompt."""
    s = enr["stats"]
    counts: dict[str, int] = {}
    for r in enr["results"]:
        base = r["verdict"].split(" ")[0]
        counts[base] = counts.get(base, 0) + 1
    lines = [
        "THREAT INTELLIGENCE ENRICHMENT (deterministic lookups; "
        "sources: Feodo C2 list, ip-api, rDNS, RDAP"
        + (", " + ", ".join(s["keyed_sources"]) if s["keyed_sources"] else "")
        + ")",
        "  verdict summary: " + (", ".join(
            f"{v} {k}" for k, v in sorted(counts.items())) or "no external IOCs"),
    ]
    for r in enr["results"]:
        lines.append(f"  {r['value']} [{r['type']}] — {r['verdict']}"
                     f" (score {r['score']}, confidence {r.get('confidence', '?')})")
        for e in r["evidence"][:5]:
            lines.append(f"      · {e}")
        for t in r.get("mitre_techniques", []):
            lines.append(f"      · MITRE {t['technique_id']} "
                         f"{t['technique_name']} ({t['tactic']})")
    if s["skipped_private_ips"]:
        lines.append(f"  {s['skipped_private_ips']} private/internal IPs skipped "
                     "(no external reputation applicable)")
    if s["truncated"]:
        lines.append("  note: IOC list truncated to budget")
    mal = [r["value"] for r in enr["results"] if r["verdict"] == "MALICIOUS"]
    if mal:
        lines.append("  RECOMMENDED PERIMETER BLOCKS: " + ", ".join(mal))
    return "\n".join(lines)
