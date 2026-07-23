"""
endpoint_profile.py — deep endpoint entity analysis over the incident corpus.

Part of the incident-mapping upgrade (sits between Stage 2 expansion and
Stage 3 narration). For the incident's focus entity (the "for KELLYWANG" /
"for DESKTOP-HU4A549" endpoint NetWitness names in titles), this module
computes a deterministic behavioural profile from the local corpus:

  * activity timeline — first/last seen, active days, burst days, recency
    relative to the newest data in the corpus (never wall-clock "now")
  * severity mix — priority histogram + risk score stats
  * network footprint — top co-occurring source/destination IPs, with
    infrastructure noise (broadcast, loopback, link-local, well-known DNS)
    tagged rather than hidden
  * lateral-movement candidates — OTHER endpoint entities whose incidents
    share this entity's source IPs (computed, not inferred)

Everything is code — no LLM. The formatted profile block is embedded in the
entity map text, so the analysis LLM narrates over real numbers.

Corpus reality this is built against (scanned 2026-07-17): 1,034 NetWitness
Endpoint incidents across just 9 entities; hostname-pattern names
(DESKTOP-*, WIN-*, FILESERV*) vs. probable account names (KELLYWANG,
BETHANYCHUCHU); activity 2024-07 → 2026-01 with clear burst days.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from typing import Any

_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")

# name-shape heuristics for Windows estates — honest labels, never certainty
_HOSTNAME_PATTERNS = (
    re.compile(r"^(DESKTOP|WIN|LAPTOP|SRV|SERVER|DC|PC)[-_]", re.I),
    re.compile(r"(SERV|SRV)\d*$", re.I),
)

_NOISE_IPS = {"127.0.0.1", "8.8.8.8", "8.8.4.4", "1.1.1.1"}


def _classify_entity_name(name: str) -> str:
    if any(p.search(name) for p in _HOSTNAME_PATTERNS):
        return "likely Windows hostname"
    if _looks_ipv6(name) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):
        return "IP address"
    return "user-or-host entity (name pattern inconclusive)"


def _looks_ipv6(v: str) -> bool:
    return ":" in v and all(c in "0123456789abcdefABCDEF:" for c in v)


def _ip_tag(ip: str) -> str:
    """Short noise/infrastructure tag for an IP, empty when it's interesting."""
    if ip in _NOISE_IPS:
        return " (well-known/loopback — noise)"
    if ip.endswith(".255"):
        return " (broadcast — noise)"
    if _looks_ipv6(ip) and ip.lower().startswith("fe80"):
        return " (IPv6 link-local — noise)"
    return ""


def profile_entity(db_path: str, entity: str, exclude_id: str = "",
                   max_rows: int = 3000, lateral_ips: int = 2) -> dict | None:
    """Behavioural profile of `entity` across the incident corpus.

    Returns None when the entity has no boundary-verified corpus presence.
    Read-only (SQLite mode=ro); deterministic for a fixed corpus.
    """
    boundary = re.compile(
        r"(?<![0-9A-Za-z.])" + re.escape(entity) + r"(?![0-9A-Za-z.])")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    try:
        rows = con.execute(
            "SELECT id, raw_json FROM incidents WHERE instr(raw_json, ?) > 0 "
            "ORDER BY LENGTH(id), id LIMIT ?", (entity, max_rows)).fetchall()

        dates: list[str] = []
        prio: Counter = Counter()
        risks: list[float] = []
        src_ips: Counter = Counter()
        dst_ips: Counter = Counter()
        n = 0
        for rid, raw in rows:
            if rid == exclude_id or not boundary.search(raw):
                continue
            try:
                d = json.loads(raw)
            except Exception:
                continue
            n += 1
            if d.get("created"):
                dates.append(str(d["created"])[:10])
            prio[str(d.get("priority") or "?")] += 1
            if isinstance(d.get("riskScore"), (int, float)):
                risks.append(d["riskScore"])
            am = d.get("alertMeta") or {}
            for ip in am.get("SourceIp") or []:
                if ip:
                    src_ips[ip] += 1
            for ip in am.get("DestinationIp") or []:
                if ip:
                    dst_ips[ip] += 1
        if n == 0:
            return None

        # recency is judged against the newest incident in the CORPUS —
        # wall-clock "now" would make every profile look stale on old data
        corpus_max = (con.execute(
            "SELECT MAX(substr(created, 1, 10)) FROM incidents").fetchone()[0]
            or (max(dates) if dates else ""))

        # lateral-movement candidates: other endpoint entities whose
        # incidents share this entity's top (non-noise) source IPs
        lateral: dict[str, list[str]] = {}
        top_srcs = [ip for ip, _ in src_ips.most_common(6)
                    if not _ip_tag(ip)][:lateral_ips]
        for ip in top_srcs:
            others: Counter = Counter()
            for (raw,) in con.execute(
                    "SELECT raw_json FROM incidents WHERE instr(raw_json, ?) > 0 "
                    "LIMIT 800", (ip,)):
                m = _TITLE_ENTITY_RE.search(
                    str(json.loads(raw).get("title") or "")) if raw else None
                if m:
                    other = m.group(1).strip()
                    # skip self and the shared IP's own ESA-titled incidents
                    # ("High Risk Alerts: ESA for <ip>" — same machine, not a
                    # lateral hop)
                    if other and other != entity and other != ip:
                        others[other] += 1
            if others:
                lateral[ip] = [f"{e} ({c})" for e, c in others.most_common(4)]

        day_counts = Counter(dates)
        return {
            "entity": entity,
            "entity_kind": _classify_entity_name(entity),
            "total_incidents": n,
            "first_seen": min(dates) if dates else None,
            "last_seen": max(dates) if dates else None,
            "active_days": len(day_counts),
            "burst_days": day_counts.most_common(3),
            "corpus_newest": corpus_max,
            "priority_mix": dict(prio),
            "risk_max": max(risks) if risks else None,
            "risk_mean": round(sum(risks) / len(risks), 1) if risks else None,
            "top_source_ips": [(ip, c, _ip_tag(ip)) for ip, c in src_ips.most_common(5)],
            "top_dest_ips": [(ip, c, _ip_tag(ip)) for ip, c in dst_ips.most_common(5)],
            "lateral_candidates": lateral,
        }
    finally:
        con.close()


def format_profile(p: dict) -> str:
    """Plain-text profile block for the entity map / LLM prompt."""
    lines = [
        f"ENDPOINT PROFILE — {p['entity']} [{p['entity_kind']}]",
        f"  corpus history: {p['total_incidents']} incidents, "
        f"{p['first_seen']} → {p['last_seen']} ({p['active_days']} active days; "
        f"newest data in corpus: {p['corpus_newest']})",
    ]
    if p["last_seen"] and p["corpus_newest"]:
        status = ("ACTIVE at the newest corpus data"
                  if p["last_seen"] >= p["corpus_newest"]
                  else f"last activity {p['last_seen']} (before newest corpus data "
                       f"{p['corpus_newest']})")
        lines.append(f"  recency: {status}")
    if p["burst_days"]:
        lines.append("  burst days: " + ", ".join(
            f"{d} ({c} incidents)" for d, c in p["burst_days"]))
    lines.append(
        f"  severity: priorities {p['priority_mix']}, "
        f"risk mean {p['risk_mean']} / max {p['risk_max']}")
    if p["top_source_ips"]:
        lines.append("  source IPs: " + ", ".join(
            f"{ip} ×{c}{tag}" for ip, c, tag in p["top_source_ips"]))
    if p["top_dest_ips"]:
        lines.append("  destination IPs: " + ", ".join(
            f"{ip} ×{c}{tag}" for ip, c, tag in p["top_dest_ips"]))
    if p["lateral_candidates"]:
        for ip, ents in p["lateral_candidates"].items():
            lines.append(
                f"  lateral-movement candidates via shared source IP {ip}: "
                + ", ".join(ents))
    else:
        lines.append("  lateral-movement candidates: none found via shared source IPs")
    return "\n".join(lines)
