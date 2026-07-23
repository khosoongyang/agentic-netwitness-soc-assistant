"""
ioc_correlation.py — internal IOC correlation (triage-agent skill, standalone).

Adapted from dandye's "Security IOC Correlation" SecOps skill
(mcpmarket.com/tools/skills/security-ioc-correlation → the correlate-ioc /
get_ioc_matches pattern in github.com/dandye/mcp-security + the secops-triage
"find related cases" protocol). The upstream skill is Google SecOps / Chronicle
specific (udm_search over SIEM alerts + list_cases over SOAR). A literal port is
impossible here — we have no Chronicle — so this adapts the *logic* to our own
internal data:

  * "SIEM alert history"  -> the local incident corpus (soc_db/soc_incidents.db,
                             ~53k fetched incidents), opened read-only.
  * "SOAR cases"          -> the SOC case pipeline (soc_db/soc_pipeline.db) and
                             analyst tickets (soc_db/soc_tickets.db), read-only.

For each IOC on the incident (IPs from alertMeta, domains/hashes from triage
metakeys) it derives a malicious-confidence band — HIGH / MEDIUM / LOW / NONE —
from three axes, exactly as the upstream skill does:

  frequency  — how many prior corpus alerts reference the IOC
  severity   — how many of those alerts are HIGH/CRITICAL
  status     — whether the IOC is currently being worked in an ACTIVE case
               (an open pipeline stage / analyst ticket) vs. a closed/finalized
               one. NB: the fetched corpus itself is a point-in-time snapshot in
               which every incident is status="New", so the open-vs-closed axis
               is derived from the *pipeline*, not the corpus — surfaced honestly.

What makes this distinct from the neighbouring skills (kept deliberately narrow):
  * incident_expansion.py finds *related incidents* by IOC pivot (frequency) but
    derives no confidence and never checks cases.
  * threat_intel.py scores *external* reputation (Feodo / VT / AbuseIPDB).
  * this scores *internal* corroboration — "have WE seen it, how bad, is it in an
    open case" — and nothing else.

Safety properties (deliberate, mirror incident_expansion.py):
  - never writes anywhere (every SQLite handle opened mode=ro)
  - ubiquity guard: an IOC in a huge slice of the corpus (a gateway/internal IP
    in >1500 incidents) is shared infrastructure, NOT a discriminating indicator
    — it is capped at LOW confidence, never allowed to read as HIGH on volume.
  - boundary-verified matches: sampled rows are re-checked in Python so
    "192.168.0.34" cannot match inside "192.168.0.341".
  - deterministic (fixed SQL ordering + fixed rubric) and bounded (per-IOC
    sample cap + wall-clock deadline); never raises — degrades to a reason.
  - kill switch: set NW_DISABLE_IOC_CORRELATION=1 to disable entirely.

Usage:
    corr = correlate_iocs(incident, triage_result)   # DBs self-located
    print(format_correlation(corr))
"""

from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

_DB_DIR = Path(__file__).resolve().parent / "soc_db"
_INCIDENTS_DB = _DB_DIR / "soc_incidents.db"
_PIPELINE_DB = _DB_DIR / "soc_pipeline.db"
_TICKETS_DB = _DB_DIR / "soc_tickets.db"

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# corpus-mention thresholds (shared with incident_expansion.py for consistency)
_WEAK_SIGNAL_AT = 200      # above this: common across corpus (frequency diluted)
_UBIQUITOUS_AT = 1500      # above this: ubiquity guard — cap at LOW, never HIGH
_RECURRING_AT = 5          # at/above this: notably recurring (not a one-off)

# pipeline stages that represent an OPEN / actively-worked case vs a finished one
_ACTIVE_PIPELINE = ("alerts_to_triage", "post_triage_investigate",
                    "initial_ticket", "pending_ticket_report")
_CLOSED_PIPELINE = ("post_triage_no_investigate", "finalized_report",
                    "post_investigation", "workflow_runs")


def _is_public_ip(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def _boundary(value: str) -> re.Pattern:
    """Match `value` only on token boundaries (digits/letters/dot are 'inside'),
    so partial IP/hash substrings don't produce phantom correlations."""
    return re.compile(r"(?<![0-9A-Za-z.])" + re.escape(value) + r"(?![0-9A-Za-z.])")


def _extract_iocs(incident: dict, triage_result: dict | None,
                  max_iocs: int) -> tuple[list[tuple[str, str, str]], bool]:
    """Deterministic IOC pull for internal correlation. Unlike the external
    enrichment path we KEEP private IPs — an internal host IP that recurs across
    high-severity alerts is exactly the internal signal this skill exists to
    surface. Returns ([(type, value, scope)], truncated)."""
    mkv = ((triage_result or {}).get("metakeys_payload") or {}).get("metakey_values") or {}
    am = incident.get("alertMeta") or {}

    hashes, domains, pub_ips, priv_ips = [], [], [], []
    for key, vals in mkv.items():
        klow = key.lower()
        for v in (vals if isinstance(vals, list) else [vals]):
            v = str(v or "").strip()
            if _HASH_RE.match(v):
                hashes.append(v)
            elif (("domain" in klow or "fqdn" in klow or "host" in klow)
                  and "." in v and not _IP_RE.match(v)):
                domains.append(v)
    for field in ("DestinationIp", "SourceIp"):
        for v in am.get(field) or []:
            if isinstance(v, str) and _IP_RE.match(v):
                (pub_ips if _is_public_ip(v) else priv_ips).append(v)

    def dedup(seq: list) -> list:
        return list(dict.fromkeys(seq))

    hashes, domains, pub_ips, priv_ips = map(dedup, (hashes, domains, pub_ips, priv_ips))
    # order: specific indicators first (hashes/domains), then external then
    # internal IPs — most-discriminating IOCs get budget before shared infra.
    picked = ([("hash", h, "") for h in hashes]
              + [("domain", d, "") for d in domains]
              + [("ip", i, "public") for i in pub_ips]
              + [("ip", i, "private") for i in priv_ips])
    return picked[:max_iocs], len(picked) > max_iocs


def _seed_ids(incident: dict) -> set[str]:
    """Best-effort identifiers of the CURRENT incident so its own case rows are
    excluded from 'related' correlation. Corpus ids (INC-53033) and pipeline/
    ticket ids (incident 53000-….json) differ, so we collect both plus the bare
    numeric core."""
    ids: set[str] = set()
    for k in ("id", "incident_id"):
        v = incident.get(k)
        if v:
            ids.add(str(v))
            m = re.search(r"(\d{4,})", str(v))
            if m:
                ids.add(m.group(1))
    return ids


def _corpus_correlate(con: sqlite3.Connection, value: str,
                      sample_cap: int) -> dict:
    """Frequency + severity + recency of `value` across the incident corpus.
    raw_mentions is the fast substring count (same honest convention as
    incident_expansion); severity/status/recency are computed over the newest
    boundary-verified sample."""
    raw = con.execute(
        "SELECT COUNT(*) FROM incidents WHERE instr(raw_json, ?) > 0", (value,)
    ).fetchone()[0]
    out = {"raw_mentions": raw, "verified_in_sample": 0, "sample_size": 0,
           "sev_dist": {}, "hi_sev": 0, "first_seen": "", "last_seen": "",
           "related": []}
    if raw == 0:
        return out

    rows = con.execute(
        "SELECT id, severity, status, created FROM incidents "
        "WHERE instr(raw_json, ?) > 0 ORDER BY LENGTH(id) DESC, id DESC LIMIT ?",
        (value, sample_cap),
    ).fetchall()
    # boundary-verify against raw_json for exactly the sampled rows (one small
    # extra fetch keeps the big COUNT fast while killing partial-match noise).
    bnd = _boundary(value)
    createds: list[str] = []
    for rid, sev, status, created in rows:
        raw_json = con.execute(
            "SELECT raw_json FROM incidents WHERE id = ?", (rid,)).fetchone()
        if not raw_json or not bnd.search(raw_json[0] or ""):
            continue
        sev_u = (sev or "UNKNOWN").upper()
        out["sev_dist"][sev_u] = out["sev_dist"].get(sev_u, 0) + 1
        out["verified_in_sample"] += 1
        if created:
            createds.append(str(created))
        if len(out["related"]) < 5:
            out["related"].append({"id": rid, "severity": sev,
                                   "status": status, "created": str(created or "")[:19]})
    out["sample_size"] = len(rows)
    out["hi_sev"] = out["sev_dist"].get("HIGH", 0) + out["sev_dist"].get("CRITICAL", 0)
    if createds:
        out["first_seen"] = min(createds)[:19]
        out["last_seen"] = max(createds)[:19]
    return out


_SUBNET_CAP = 3          # max /24 neighbourhoods analysed per incident
_SUBNET_SAMPLE = 40      # newest rows sampled per subnet for neighbour extraction


def _subnet_prefix(ip: str) -> str | None:
    """'a.b.c.' prefix for a private IPv4 — its /24 neighbourhood. Public IPs
    return None: a /24 around external infrastructure is not lateral movement."""
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 4 and a.is_private and not (a.is_loopback or a.is_link_local):
            return ip.rsplit(".", 1)[0] + "."
    except ValueError:
        pass
    return None


def _subnet_correlate(con: sqlite3.Connection, prefix: str,
                      own_ips: set[str], sample_cap: int = _SUBNET_SAMPLE) -> dict:
    """/24 neighbourhood scan: exact-match correlation misses lateral movement
    when the neighbour host's IP differs from the incident's own IOCs. Fast
    substring count on the prefix, then boundary-verified neighbour-IP
    extraction over the newest sample (the incident's own IPs excluded)."""
    raw = con.execute(
        "SELECT COUNT(*) FROM incidents WHERE instr(raw_json, ?) > 0", (prefix,)
    ).fetchone()[0]
    out = {"subnet": f"{prefix}0/24", "mentions": raw, "sample_size": 0,
           "distinct_neighbours": 0, "neighbours": [], "hi_sev_sample": 0}
    if raw == 0:
        return out
    rows = con.execute(
        "SELECT id, severity, raw_json FROM incidents "
        "WHERE instr(raw_json, ?) > 0 ORDER BY LENGTH(id) DESC, id DESC LIMIT ?",
        (prefix, sample_cap),
    ).fetchall()
    # same token-boundary convention as _boundary(): a full IP in this /24,
    # not a longer dotted string containing it.
    ip_re = re.compile(r"(?<![0-9A-Za-z.])" + re.escape(prefix)
                       + r"\d{1,3}(?![0-9A-Za-z.])")
    counts: dict[str, int] = {}
    for _rid, sev, raw_json in rows:
        found = {m.group(0) for m in ip_re.finditer(raw_json or "")} - own_ips
        if not found:
            continue
        if str(sev or "").upper() in ("HIGH", "CRITICAL"):
            out["hi_sev_sample"] += 1
        for ip in found:
            counts[ip] = counts.get(ip, 0) + 1
    out["sample_size"] = len(rows)
    out["distinct_neighbours"] = len(counts)
    out["neighbours"] = [{"ip": ip, "in_sample": n} for ip, n in
                         sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]]
    return out


def _case_correlate(pcon: sqlite3.Connection | None,
                    tcon: sqlite3.Connection | None,
                    value: str, seed_ids: set[str]) -> tuple[list, list]:
    """Which SOC cases reference `value`: (open_cases, closed_cases). Open =
    active pipeline stage or an analyst ticket; closed = a finalized/archived
    pipeline stage. The current incident's own rows are excluded."""
    bnd = _boundary(value)
    open_cases: list[dict] = []
    closed_cases: list[dict] = []

    if pcon is not None:
        for tbl, bucket in ([(t, open_cases) for t in _ACTIVE_PIPELINE]
                            + [(t, closed_cases) for t in _CLOSED_PIPELINE]):
            try:
                rows = pcon.execute(
                    f"SELECT id, incident_id, severity, raw_json FROM {tbl} "
                    "WHERE instr(raw_json, ?) > 0", (value,)).fetchall()
            except sqlite3.Error:
                continue
            for rid, incident_id, sev, raw in rows:
                if incident_id and str(incident_id) in seed_ids:
                    continue
                if not bnd.search(raw or ""):
                    continue
                bucket.append({"ref": rid or incident_id, "incident_id": incident_id,
                              "severity": sev, "stage": tbl})

    if tcon is not None:
        try:
            rows = tcon.execute(
                "SELECT unc, incident_id, severity, payload FROM tickets "
                "WHERE instr(payload, ?) > 0", (value,)).fetchall()
        except sqlite3.Error:
            rows = []
        for unc, incident_id, sev, payload in rows:
            if incident_id and str(incident_id) in seed_ids:
                continue
            if not bnd.search(payload or ""):
                continue
            open_cases.append({"ref": unc, "incident_id": incident_id,
                              "severity": sev, "stage": "ticket"})
    return open_cases, closed_cases


def _confidence(raw_mentions: int, hi_sev: int,
                open_cases: list, closed_cases: list) -> tuple[str, list[str]]:
    """Deterministic HIGH/MEDIUM/LOW/NONE band from frequency + severity +
    case status, with the ubiquity guard. Returns (band, rationale). The bands
    are defensible (frequency/severity/status, same spirit as the neighbouring
    confidence models) — not a byte-for-byte port of Chronicle's internal
    thresholds, which are not public."""
    rationale: list[str] = []
    if raw_mentions == 0 and not open_cases and not closed_cases:
        return "none", ["not seen in prior alerts or cases — first internal sighting"]

    ubiquitous = raw_mentions > _UBIQUITOUS_AT
    weak = _WEAK_SIGNAL_AT < raw_mentions <= _UBIQUITOUS_AT

    if open_cases:
        rationale.append(f"in {len(open_cases)} active case(s): "
                         + ", ".join(str(c["ref"]) for c in open_cases[:4]))
    if closed_cases and not open_cases:
        rationale.append(f"referenced in {len(closed_cases)} closed/finalized case(s)")

    # ubiquity guard first — shared infrastructure never reads as HIGH on volume.
    if ubiquitous:
        rationale.append(f"{raw_mentions} corpus mentions — ubiquitous "
                         "(shared/internal infrastructure), not a discriminating indicator")
        return ("medium" if open_cases else "low"), rationale

    if hi_sev:
        rationale.append(f"{hi_sev} of the related alerts are HIGH/CRITICAL severity")
    if raw_mentions:
        rationale.append(f"{raw_mentions} corpus mention(s)"
                         + (" — common across corpus (weak indicator)" if weak else ""))

    # HIGH: actively worked in an open case, or recurring AND concentrated in
    # serious alerts — provided frequency isn't diluted into the 'weak' band.
    if not weak and (open_cases or (raw_mentions >= _RECURRING_AT and hi_sev)):
        return "high", rationale
    # MEDIUM: any case link, or recurring, or a few sightings with high severity.
    if open_cases or closed_cases or raw_mentions >= _RECURRING_AT \
            or (raw_mentions >= 3 and hi_sev):
        return "medium", rationale
    return "low", rationale


def correlate_iocs(incident: dict, triage_result: dict | None = None,
                   incidents_db: str | None = None,
                   pipeline_db: str | None = None,
                   tickets_db: str | None = None,
                   max_iocs: int = 10, sample_cap: int = 60,
                   deadline_seconds: float = 8.0) -> dict:
    """Correlate the incident's IOCs against internal alert history + SOC cases.
    Read-only, deterministic, wall-clock bounded; never raises. Returns
    {"available": bool, "results": [...], "stats": {...}}."""
    if os.environ.get("NW_DISABLE_IOC_CORRELATION"):
        return {"available": False, "reason": "disabled via NW_DISABLE_IOC_CORRELATION",
                "results": [], "stats": {}}

    t0 = time.time()
    iocs, truncated = _extract_iocs(incident, triage_result, max_iocs)
    seed_ids = _seed_ids(incident)

    inc_path = incidents_db or str(_INCIDENTS_DB)
    pipe_path = pipeline_db or str(_PIPELINE_DB)
    tick_path = tickets_db or str(_TICKETS_DB)

    def _ro(path: str) -> sqlite3.Connection | None:
        try:
            return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10.0)
        except sqlite3.Error:
            return None

    icon = _ro(inc_path)
    if icon is None:
        return {"available": False, "reason": f"incident corpus not readable ({inc_path})",
                "results": [], "stats": {}}
    pcon = _ro(pipe_path) if Path(pipe_path).exists() else None
    tcon = _ro(tick_path) if Path(tick_path).exists() else None

    results = []
    deadline_hit = False
    try:
        for ioc_type, value, scope in iocs:
            if time.time() - t0 > deadline_seconds:
                deadline_hit = True
                break
            corp = _corpus_correlate(icon, value, sample_cap)
            open_cases, closed_cases = _case_correlate(pcon, tcon, value, seed_ids)
            band, rationale = _confidence(
                corp["raw_mentions"], corp["hi_sev"], open_cases, closed_cases)
            results.append({
                "value": value, "type": ioc_type, "scope": scope,
                "confidence": band, "rationale": rationale,
                "raw_mentions": corp["raw_mentions"],
                "verified_in_sample": corp["verified_in_sample"],
                "sample_size": corp["sample_size"],
                "hi_sev": corp["hi_sev"], "sev_dist": corp["sev_dist"],
                "first_seen": corp["first_seen"], "last_seen": corp["last_seen"],
                "related": corp["related"],
                "open_cases": open_cases, "closed_cases": closed_cases,
            })

        # ── /24 subnet neighbourhoods (lateral-movement pivots) ─────────────
        # Reported SEPARATELY from the per-IOC results so subnet volume can
        # never inflate an IOC's confidence band (the ubiquity guard stays
        # authoritative). Informational: names the neighbour IPs that recur
        # alongside this incident's subnet. NW_DISABLE_SUBNET_PIVOT=1 skips.
        subnets: list[dict] = []
        if not os.environ.get("NW_DISABLE_SUBNET_PIVOT"):
            own_ips = {v for t, v, _s in iocs if t == "ip"}
            prefixes = list(dict.fromkeys(
                p for _t, v, s in iocs if s == "private"
                for p in [_subnet_prefix(v)] if p))[:_SUBNET_CAP]
            for pfx in prefixes:
                if time.time() - t0 > deadline_seconds:
                    deadline_hit = True
                    break
                try:
                    subnets.append(_subnet_correlate(icon, pfx, own_ips))
                except sqlite3.Error:
                    continue
    finally:
        for c in (icon, pcon, tcon):
            try:
                if c is not None:
                    c.close()
            except sqlite3.Error:
                pass

    # rank most-corroborated first for display: confidence band, then case
    # presence, then frequency — deterministic tie-break on value.
    _band_rank = {"high": 0, "medium": 1, "low": 2, "none": 3}
    results.sort(key=lambda r: (_band_rank.get(r["confidence"], 4),
                                -len(r["open_cases"]), -r["raw_mentions"], r["value"]))

    return {
        "available": True,
        "results": results,
        "subnets": subnets,
        "stats": {
            "iocs_correlated": len(results),
            "subnets_analysed": len(subnets),
            "truncated": truncated,
            "deadline_hit": deadline_hit,
            "cases_source": bool(pcon) or bool(tcon),
            "seconds": round(time.time() - t0, 2),
            "corpus_note": ("corpus is a point-in-time snapshot (all incidents "
                            "status=New); open-vs-closed status is taken from the "
                            "SOC case pipeline, not the corpus"),
        },
    }


def format_correlation(corr: dict) -> str:
    """Plain-text block for the Map panel (and any LLM prompt reuse)."""
    if not corr.get("available"):
        return "INTERNAL IOC CORRELATION unavailable: " + corr.get("reason", "unknown")
    if not corr["results"]:
        return ("INTERNAL IOC CORRELATION: no IPs, domains or hashes on this "
                "incident to correlate.")

    st = corr["stats"]
    bands: dict[str, int] = {}
    for r in corr["results"]:
        bands[r["confidence"]] = bands.get(r["confidence"], 0) + 1
    order = ["high", "medium", "low", "none"]

    lines = [
        "INTERNAL IOC CORRELATION (deterministic; sources: local alert corpus "
        "+ SOC case pipeline/tickets)",
        "  confidence summary: " + (", ".join(
            f"{bands[b]} {b}" for b in order if b in bands) or "no IOCs"),
    ]
    for r in corr["results"]:
        scope = f", {r['scope']}" if r.get("scope") else ""
        lines.append(f"  {r['value']} [{r['type']}{scope}] — "
                     f"{r['confidence'].upper()} confidence")
        for rr in r["rationale"]:
            lines.append(f"      · {rr}")
        if r["raw_mentions"]:
            lines.append(
                f"      · corpus window {r['first_seen'] or '?'} → "
                f"{r['last_seen'] or '?'} "
                f"({r['verified_in_sample']}/{r['sample_size']} sampled "
                "mentions boundary-verified)")
        for c in (r.get("open_cases") or [])[:4]:
            lines.append(f"      · ACTIVE case {c['ref']} "
                         f"[{c['stage']}] sev={c.get('severity')}")
    hi = [r["value"] for r in corr["results"] if r["confidence"] == "high"]
    if hi:
        lines.append("  HIGH-confidence internal IOCs: " + ", ".join(hi))
    for sn in corr.get("subnets") or []:
        if not sn.get("distinct_neighbours"):
            continue
        lines.append(
            f"  SUBNET {sn['subnet']} — {sn['distinct_neighbours']} neighbour "
            f"IP(s) recur alongside this incident's hosts "
            f"({sn['hi_sev_sample']}/{sn['sample_size']} sampled rows "
            "HIGH/CRITICAL) — possible lateral-movement neighbourhood; "
            "informational, does not raise IOC confidence:")
        for nb in sn["neighbours"][:5]:
            lines.append(f"      · {nb['ip']} (in {nb['in_sample']} of the "
                         "sampled incidents)")
    if st.get("truncated"):
        lines.append("  note: IOC list truncated to budget")
    if st.get("deadline_hit"):
        lines.append("  note: correlation deadline reached; remaining IOCs skipped")
    lines.append("  · " + st["corpus_note"])
    return "\n".join(lines)
