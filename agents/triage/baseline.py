# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, ipaddress, pathlib, re, sqlite3.
# =============================================================================
# File: agents/triage/baseline.py
# Purpose: Deterministic, read-only HISTORICAL BASELINE for one incident --
#   "how often has this detection fired on this entity before?" -- measured
#   from the real incident history in soc_db/soc_incidents.db instead of
#   asking the LLM to guess an occurrence frequency.
# Main functionality: compute_baseline(), extract_entity(), classify_entity(),
#   detection_source(), incident_created_time().
# Inputs: an incident dict (NetWitness shape) and an optional SQLite path.
# Outputs: a plain dict of occurrence counts (7/30/90 days + all-time),
#   first/last seen, first-occurrence and known-noisy flags, DB coverage, and
#   an explicit status ("measured" | "unknown") with a reason.
# Workflow position: Triage stage, before the three LLM phases -- feeds the
#   evidence packet (agents/triage/evidence_packet.py).
# Called by: agents/triage/evidence_packet.py, agents/triage/soc_triage_agent.py
#   (TriageAgent.triage), workflow/engine.py (mock_triage_result).
# Important side effects: NONE. The database is opened with SQLite URI
#   mode=ro; no schema change, no index, no write.
# Error and fallback behaviour: never raises for data problems -- a missing
#   DB, unreadable table, unresolved entity or out-of-coverage incident time
#   returns status="unknown" with a reason ("missing = unknown, not safe").
# Key evaluator search terms: compute_baseline, KNOWN_NOISY_THRESHOLD_30D,
#   [FYP-TRIAGE-BASELINE], [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================
"""
Historical baseline for Triage  --  baseline.py
===============================================
[FYP-TRIAGE-BASELINE] An alert is a likelihood ratio, not a verdict: before
weighing evidence the analyst reconstructs the PRIOR -- how often this
detection normally fires on this entity. This module measures that prior.

Rules enforced here (each is a design decision, not an accident):
  * Windows are measured RELATIVE TO THE INCIDENT'S OWN ``created`` time,
    never "now" (the demo data ends 2026-07-27).
  * Only incidents created strictly BEFORE this one count, and the incident's
    own id is excluded -- no future data can leak into the prior.
  * Baseline = occurrence COUNTS only. Past triage verdicts stored in the DB
    are unvalidated LLM output and are never read.
  * Detection source = raw_json.createdBy + raw_json.ruleId (ruleId alone
    has only two distinct values and would lump every ESA rule together).
  * Missing DB / unresolved entity / incident time outside the DB's coverage
    -> status "unknown". An absence of rows is only "measured" when the DB
    actually covers the period being measured.

This module imports nothing from ``workflow/`` or Flask (agents/ architecture
rule); the workflow layer passes its own DB path in explicitly.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ── Named constants ──────────────────────────────────────────────────────────

# Default DB: <project>/soc_db/soc_incidents.db (same layout as
# soc_triage_agent._SOC_DB_DIR). NOT created if absent -- absence = "unknown".
# [AUDIT T-24] the live incident DB (AEGIS_DATA_DIR, seeded from soc_db/).
from aegis_paths import ensure_live as _ensure_live, live_db as _live_db
DEFAULT_BASELINE_DB = _live_db("soc_incidents.db")

# Look-back windows, in days, measured back from the incident's created time.
BASELINE_WINDOWS_DAYS: tuple[int, ...] = (7, 30, 90)

# [FYP-EVALUATOR] "Known noisy": this detection has fired on this entity at
# least this many times in the 30 days before the incident.
KNOWN_NOISY_THRESHOLD_30D = 30

# How far past the DB's newest row an incident may be and still be
# considered covered (sync lag). Beyond this, the days right before the
# incident are simply not in the DB, so zero counts would be a false
# "first occurrence" -> status "unknown".
COVERAGE_GAP_TOLERANCE = timedelta(days=1)

# Entity kinds. "file" is an additive kind for the handful of NetWitness
# Endpoint titles of the form "... for FILE powershell.exe".
ENTITY_KINDS = ("ip_internal", "ip_external", "hostname", "user", "file", "unresolved")

# Title shape: "<rule name> for <group-by entity>". Same idea as
# agents/investigation/tools/asset_criticality.py::_TITLE_ENTITY_RE, but
# anchored on the LAST " for " so a rule name containing "for" can't win.
_TITLE_ENTITY_RE = re.compile(r"^.*\bfor\s+(.+?)\s*$", re.IGNORECASE)
_ENTITY_PREFIX_RE = re.compile(r"^(HOST|USER|FILE|IP)\s+(.+)$", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")

_CREATED_FIELDS = ("created", "createdDate", "createdAt", "created_at")
_ISO_SECONDS = "%Y-%m-%dT%H:%M:%S"


# =============================================================================
# [FYP-SECTION] ENTITY + DETECTION-SOURCE RESOLUTION
# =============================================================================

def _first_str(value: Any) -> str | None:
    """First non-empty string of a scalar-or-list value."""
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
        return None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _entity_key(raw: str) -> tuple[str, str | None]:
    """Strip a NetWitness 'HOST '/'USER '/'FILE '/'IP ' prefix.

    Returns (key, prefix_kind) where key is the entity used for matching."""
    m = _ENTITY_PREFIX_RE.match(raw.strip())
    if m:
        return m.group(2).strip(), m.group(1).upper()
    return raw.strip(), None


def classify_entity(value: str | None, prefix: str | None = None) -> str:
    """[FYP-FUNCTION] Classify an entity string as ip_internal / ip_external /
    hostname / user / file / unresolved.

    IPs use the stdlib ``ipaddress`` module: RFC1918 plus loopback,
    link-local and IPv6 ULA (``is_private``) count as internal -- a
    127.0.0.1 or fe80:: entity is certainly not an external party."""
    if not value or not str(value).strip():
        return "unresolved"
    v = str(value).strip()
    if prefix == "FILE":
        return "file"
    if prefix == "USER":
        return "user"
    try:
        ip = ipaddress.ip_address(v.split("%")[0])
    except ValueError:
        ip = None
    if ip is not None:
        internal = ip.is_private or ip.is_loopback or ip.is_link_local
        return "ip_internal" if internal else "ip_external"
    if "@" in v or "\\" in v:
        return "user"
    if prefix == "HOST" or _HOSTNAME_RE.match(v):
        return "hostname"
    return "unresolved"


def extract_entity(incident: dict) -> dict:
    """[FYP-FUNCTION] Resolve the incident's primary entity.

    Order: the NetWitness group-by entity after the last " for " in the
    title (``name`` for Respond-API exports), then alertMeta.SourceIp, then
    alertMeta.DestinationIp. Returns {value, kind, source, raw}; value is
    None and kind "unresolved" when nothing usable exists."""
    title = str(incident.get("title") or incident.get("name") or "")
    m = _TITLE_ENTITY_RE.match(title)
    if m and m.group(1).strip():
        raw = m.group(1).strip()
        key, prefix = _entity_key(raw)
        kind = classify_entity(key, prefix)
        if kind != "unresolved":
            return {"value": key, "kind": kind, "source": "incident.title", "raw": raw}
    meta = incident.get("alertMeta")
    if isinstance(meta, dict):
        for field_name in ("SourceIp", "DestinationIp"):
            candidate = _first_str(meta.get(field_name))
            if candidate:
                kind = classify_entity(candidate)
                if kind != "unresolved":
                    return {"value": candidate, "kind": kind,
                            "source": f"incident.alertMeta.{field_name}[0]", "raw": candidate}
    return {"value": None, "kind": "unresolved", "source": "none", "raw": None}


def detection_source(incident: dict) -> dict:
    """[FYP-FUNCTION] Detection source = createdBy + ruleId (both raw_json
    fields). ``key`` is None when createdBy is absent."""
    created_by = _first_str(incident.get("createdBy"))
    rule_id = _first_str(incident.get("ruleId"))
    key = f"{created_by}|{rule_id or ''}" if created_by else None
    return {"created_by": created_by, "rule_id": rule_id, "key": key}


def _parse_time(value: Any) -> datetime | None:
    """Parse ISO-8601 (with or without offset / 'Z') or epoch s/ms to naive UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:19], _ISO_SECONDS)
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def incident_created_time(incident: dict) -> tuple[str | None, str | None]:
    """[FYP-FUNCTION] The incident's own creation time as naive-UTC ISO
    seconds ("YYYY-MM-DDTHH:MM:SS", the same format as incidents.created),
    plus the field it came from."""
    for field_name in _CREATED_FIELDS:
        dt = _parse_time(incident.get(field_name))
        if dt is not None:
            return dt.strftime(_ISO_SECONDS), f"incident.{field_name}"
    return None, None


# =============================================================================
# [FYP-SECTION] BASELINE COMPUTATION (read-only SQLite)
# =============================================================================

def _connect_read_only(db_path: Path) -> sqlite3.Connection:
    """Open SQLite strictly read-only (URI mode=ro). Path.as_uri() percent-
    encodes spaces/'&'/'#' in the Windows project path."""
    return sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=15)


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _empty_counts() -> dict[str, int | None]:
    return {**{f"{d}d": None for d in BASELINE_WINDOWS_DAYS}, "all_time": None}


def _unknown(reason: str, base: dict) -> dict:
    base.update(status="unknown", reason=reason)
    return base


def compute_baseline(incident: dict, db_path: Path | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Measured historical prior for one incident.

    Counts prior incidents (created strictly before this incident, own id
    excluded) for (same detection source + same entity) and (same entity,
    any source) over 7/30/90 days and all-time (= within DB coverage).

    Returns a flat dict (every key is always present, None when not
    measurable -- see the ``result`` literal below). ``status`` is
    "measured" only when the DB was readable, the entity resolved and the
    incident time falls inside the DB's coverage window."""
    db = _ensure_live(Path(db_path) if db_path is not None else DEFAULT_BASELINE_DB)
    entity = extract_entity(incident)
    source = detection_source(incident)
    as_of, as_of_field = incident_created_time(incident)
    inc_id = str(incident.get("id") or incident.get("incidentId") or "")

    result: dict[str, Any] = {
        "status": "unknown",
        "reason": "",
        "db_source": f"{db.name}:incidents",
        "as_of": as_of,
        "as_of_field": as_of_field,
        "incident_id": inc_id or None,
        "entity": entity["value"],
        "entity_kind": entity["kind"],
        "entity_source": entity["source"],
        "created_by": source["created_by"],
        "rule_id": source["rule_id"],
        "same_source_entity": _empty_counts(),
        "same_entity_any_source": _empty_counts(),
        "window_complete": {f"{d}d": None for d in BASELINE_WINDOWS_DAYS},
        "first_seen": None,
        "last_seen": None,
        "is_first_occurrence": None,
        "is_known_noisy": None,
        "known_noisy_threshold_30d": KNOWN_NOISY_THRESHOLD_30D,
        "coverage_start": None,
        "coverage_end": None,
    }

    if not db.is_file():
        return _unknown(f"baseline database not found ({db.name})", result)

    try:
        con = _connect_read_only(db)
    except sqlite3.Error as exc:
        return _unknown(f"baseline database could not be opened read-only: {exc}", result)
    try:
        try:
            cov = con.execute(
                "SELECT MIN(created), MAX(created) FROM incidents "
                "WHERE created IS NOT NULL AND created != ''").fetchone()
        except sqlite3.Error as exc:
            return _unknown(f"incidents table unreadable: {exc}", result)
        coverage_start = str(cov[0])[:19] if cov and cov[0] else None
        coverage_end = str(cov[1])[:19] if cov and cov[1] else None
        result["coverage_start"] = coverage_start
        result["coverage_end"] = coverage_end

        if entity["value"] is None:
            return _unknown("entity unresolved (no ' for <entity>' title suffix and "
                            "no alertMeta.SourceIp/DestinationIp)", result)
        if as_of is None:
            return _unknown("incident has no parseable created time to anchor the "
                            "look-back windows", result)
        if coverage_start is None or coverage_end is None:
            return _unknown("incidents table is empty", result)
        t = datetime.strptime(as_of, _ISO_SECONDS)
        cov_start_dt = _parse_time(coverage_start)
        cov_end_dt = _parse_time(coverage_end)
        if cov_start_dt is None or cov_end_dt is None:
            return _unknown("incidents.created coverage bounds unparseable", result)
        if t < cov_start_dt:
            return _unknown(f"incident time {as_of} predates baseline coverage "
                            f"(starts {coverage_start})", result)
        if t > cov_end_dt + COVERAGE_GAP_TOLERANCE:
            return _unknown(f"incident time {as_of} is after baseline coverage ends "
                            f"({coverage_end}); the days before the incident are not "
                            "in the database", result)

        key_cf = entity["value"].casefold()
        try:
            rows = con.execute(
                "SELECT id, title, created, "
                "json_extract(raw_json, '$.createdBy'), json_extract(raw_json, '$.ruleId') "
                "FROM incidents "
                "WHERE created < ? AND id != ? AND title LIKE ? ESCAPE '\\'",
                (as_of, inc_id, "%" + _like_escape(entity["value"])),
            ).fetchall()
        except sqlite3.Error as exc:
            return _unknown(f"baseline query failed: {exc}", result)
    finally:
        con.close()

    same_entity: list[tuple[str, bool]] = []   # (created, same_source?)
    for _rid, title, created, created_by, rule_id in rows:
        m = _TITLE_ENTITY_RE.match(str(title or ""))
        if not m:
            continue
        other_key, _prefix = _entity_key(m.group(1))
        if other_key.casefold() != key_cf:
            continue
        created_s = str(created or "")[:19]
        if not created_s:
            continue
        same_src = (source["key"] is not None
                    and created_by == source["created_by"]
                    and (rule_id or None) == (source["rule_id"] or None))
        same_entity.append((created_s, same_src))

    window_complete: dict[str, bool] = {}
    ent_counts: dict[str, int | None] = {}
    src_counts: dict[str, int | None] = {}
    for days in BASELINE_WINDOWS_DAYS:
        lo_dt = t - timedelta(days=days)
        lo = lo_dt.strftime(_ISO_SECONDS)
        label = f"{days}d"
        window_complete[label] = lo_dt >= cov_start_dt
        ent_counts[label] = sum(1 for c, _s in same_entity if c >= lo)
        src_counts[label] = (sum(1 for c, s in same_entity if s and c >= lo)
                             if source["key"] is not None else None)
    ent_counts["all_time"] = len(same_entity)
    src_counts["all_time"] = (sum(1 for _c, s in same_entity if s)
                              if source["key"] is not None else None)

    result["same_entity_any_source"] = ent_counts
    result["same_source_entity"] = src_counts
    result["window_complete"] = window_complete

    reasons = [f"measured from {len(same_entity)} prior incident(s) on this entity "
               f"before {as_of}"]
    if source["key"] is not None:
        src_times = sorted(c for c, s in same_entity if s)
        result["first_seen"] = src_times[0] if src_times else None
        result["last_seen"] = src_times[-1] if src_times else None
        result["is_first_occurrence"] = not src_times
        n30 = src_counts["30d"] or 0
        if window_complete["30d"] or n30 >= KNOWN_NOISY_THRESHOLD_30D:
            result["is_known_noisy"] = n30 >= KNOWN_NOISY_THRESHOLD_30D
    else:
        reasons.append("detection source (createdBy) missing: same-source counts "
                       "not measurable")
    partial = [w for w, ok in window_complete.items() if not ok]
    if partial:
        reasons.append(f"windows {', '.join(partial)} start before coverage_start "
                       "(counts are lower bounds)")
    result["status"] = "measured"
    result["reason"] = "; ".join(reasons)
    return result


NOISY_PAIRS_DEFAULT_LIMIT = 20


def noisy_pairs(db_path: Path | None = None, *, limit: int = NOISY_PAIRS_DEFAULT_LIMIT,
                as_of: str | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-TRIAGE-STEP3] Noisy-rules report: the top
    (detection source, entity) pairs by 30-day and 90-day incident counts.

    READ-ONLY (same mode=ro connection and the same entity / detection-source
    keys as compute_baseline(); never writes). Windows are measured back from
    ``as_of`` or, by default, the DB's newest created time (the data may be
    an offline snapshot, so "now" would make every window empty).
    detection_source = "createdBy" or "createdBy / ruleId" (the same label
    agents/triage/suppression.scope_from_packet() produces)."""
    db = _ensure_live(Path(db_path) if db_path is not None else DEFAULT_BASELINE_DB)
    out: dict[str, Any] = {"status": "unknown", "reason": "", "db_source": f"{db.name}:incidents",
                           "as_of": None, "pairs": []}
    if not db.is_file():
        out["reason"] = f"baseline database not found ({db.name})"
        return out
    try:
        con = _connect_read_only(db)
    except sqlite3.Error as exc:
        out["reason"] = f"baseline database could not be opened read-only: {exc}"
        return out
    try:
        try:
            end = as_of or (con.execute("SELECT MAX(created) FROM incidents WHERE created IS NOT NULL "
                                        "AND created != ''").fetchone() or [None])[0]
            if not end:
                out["reason"] = "incidents table is empty"
                return out
            end_dt = _parse_time(end)
            if end_dt is None:
                out["reason"] = "incidents.created unparseable"
                return out
            lo90 = (end_dt - timedelta(days=90)).strftime(_ISO_SECONDS)
            rows = con.execute(
                "SELECT title, created, json_extract(raw_json, '$.createdBy'), "
                "json_extract(raw_json, '$.ruleId') FROM incidents WHERE created >= ? AND created <= ?",
                (lo90, end_dt.strftime(_ISO_SECONDS) + "~")).fetchall()
        except sqlite3.Error as exc:
            out["reason"] = f"noisy-pairs query failed: {exc}"
            return out
    finally:
        con.close()
    lo30 = (end_dt - timedelta(days=30)).strftime(_ISO_SECONDS)
    counts: dict[tuple[str, str], dict] = {}
    for title, created, created_by, rule_id in rows:
        m = _TITLE_ENTITY_RE.match(str(title or ""))
        if not m:
            continue
        ent, _prefix = _entity_key(m.group(1))
        cb = _first_str(created_by)
        if not ent or not cb:
            continue
        rid = _first_str(rule_id)
        source = f"{cb} / {rid}" if rid else cb
        key = (source, ent)
        c = counts.setdefault(key, {"detection_source": source, "entity": ent,
                                    "count_30d": 0, "count_90d": 0, "last_seen": None})
        created_s = str(created or "")[:19]
        c["count_90d"] += 1
        if created_s >= lo30:
            c["count_30d"] += 1
        if created_s and (c["last_seen"] is None or created_s > c["last_seen"]):
            c["last_seen"] = created_s
    pairs = sorted(counts.values(), key=lambda c: (-c["count_30d"], -c["count_90d"], c["entity"]))
    for p in pairs:
        p["known_noisy"] = p["count_30d"] >= KNOWN_NOISY_THRESHOLD_30D
    out.update({"status": "measured", "as_of": end_dt.strftime(_ISO_SECONDS),
                "pairs": pairs[:max(1, int(limit))],
                "reason": f"{len(rows)} incident(s) in the 90 days before {end_dt:%Y-%m-%d}"})
    return out


__all__ = [
    "DEFAULT_BASELINE_DB",
    "BASELINE_WINDOWS_DAYS",
    "KNOWN_NOISY_THRESHOLD_30D",
    "COVERAGE_GAP_TOLERANCE",
    "ENTITY_KINDS",
    "classify_entity",
    "extract_entity",
    "detection_source",
    "incident_created_time",
    "compute_baseline",
    "noisy_pairs",
]
