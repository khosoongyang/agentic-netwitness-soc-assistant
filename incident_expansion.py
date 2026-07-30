# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, json, re, sqlite3, time, typing.
# =============================================================================
# File: incident_expansion.py
# Purpose: This module expands a seed incident with related alert and entity evidence.
# Main functionality: LocalCorpusSource, NetWitnessEventsSource, _frontier, expand_incident_map.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis SOC analysis support component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, json, re, sqlite3, time, typing.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: LocalCorpusSource, NetWitnessEventsSource, _frontier, expand_incident_map, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
incident_expansion.py — Stage 2 of the autonomous incident-mapping upgrade.

Takes the Stage 1 entity graph (incident_map.build_incident_map) and expands
it autonomously: frontier entities (IPs, users, hosts, domains, hashes) are
pivoted against an evidence source to discover related incidents, which are
added to the graph as evidence-tagged `also_seen_in` edges. Deterministic,
budget-bounded, read-only.

Evidence sources:
  * LocalCorpusSource — the 53k-incident SQLite cache (soc_db/soc_incidents.db,
    opened read-only). Works offline today; ~150ms per pivot on the slimmed DB.
  * NetWitnessEventsSource — documented stub for the live NetWitness query API
    (Stage 2b, blocked until the per-incident alerts fetch / VPN access is
    sorted). Same pivot() contract, so it drops in without touching the loop.

Safety properties (deliberate):
  - never writes anywhere (SQLite opened with mode=ro)
  - hard budgets: max_pivots, per-pivot sample cap, wall-clock deadline
  - ubiquity guard: entities matching huge swathes of the corpus (e.g. a
    gateway IP in 2,486 incidents) are annotated but NOT edge-expanded,
    so common infrastructure can't flood the map
  - deterministic: fixed frontier ordering + fixed SQL ordering → identical
    maps on identical data

Usage:
    imap = build_incident_map(incident)
    with LocalCorpusSource(db_path) as src:
        expand_incident_map(imap, src)          # mutates + returns imap
    # imap["expansion_log"] is the human-readable pivot trace
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from typing import Any

# entity types worth pivoting on (never pivot the incident itself or MITRE tags)
_PIVOTABLE_TYPES = ("user", "host", "entity", "domain", "hash", "ip", "process", "file")

# pivot values that can only produce noise
_MIN_VALUE_LEN = 4

# corpus-mention thresholds
_WEAK_SIGNAL_AT = 200     # above this: flag as weak indicator, still sample edges
_UBIQUITOUS_AT = 1500     # above this: annotate only, add NO edges (gateway-class noise)


# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-CLASS] `LocalCorpusSource` — owns LocalCorpusSource state or behaviour for the SOC analysis support component.
# [FYP-PROCESS] Important methods: __init__, __enter__, __exit__, close, pivot.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class LocalCorpusSource:
    """Read-only pivot source over the cached incident corpus in SQLite."""

    name = "local incident corpus"

    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `db_path`, `timeout`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `connect`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __init__(self, db_path: str, timeout: float = 10.0) -> None:
        self.db_path = db_path
        self._con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=timeout)

    # [FYP-FUNCTION] `__enter__` — implements the enter operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: no nested function/service calls.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __enter__(self) -> "LocalCorpusSource":
        return self

    # [FYP-FUNCTION] `__exit__` — implements the exit operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `*exc`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `close`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # [FYP-FUNCTION] `close` — implements the close operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include app.py:gp_is_reachable, chroma_viewer.py:sqlite_count, chroma_viewer.py:sqlite_load; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `close`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def close(self) -> None:
        try:
            self._con.close()
        except Exception:
            pass

    # [FYP-FUNCTION] `pivot` — implements the pivot operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `value`, `exclude_ids`, `limit`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include incident_expansion.py:expand_incident_map; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `compile`, `escape`, `execute`, `fetchall`, `fetchone`, `get`, `len`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def pivot(self, value: str, exclude_ids: set[str], limit: int = 6) -> dict:
        """All incidents whose stored JSON mentions `value`.

        Returns {"count": int, "related": [{id,title,created,priority}]}.
        count comes from a raw substring scan (fast); the sampled rows are
        boundary-verified in Python so "192.168.10.20" can't match inside
        "192.168.10.204". Sample is newest-first, deterministic.
        """
        count = self._con.execute(
            "SELECT COUNT(*) FROM incidents WHERE instr(raw_json, ?) > 0", (value,)
        ).fetchone()[0]
        if count == 0:
            return {"count": 0, "related": []}

        # newest-first for INC-<n> ids: longer id string = bigger number
        rows = self._con.execute(
            "SELECT id, raw_json FROM incidents WHERE instr(raw_json, ?) > 0 "
            "ORDER BY LENGTH(id) DESC, id DESC LIMIT ?",
            (value, limit * 3 + len(exclude_ids)),
        ).fetchall()

        boundary = re.compile(
            r"(?<![0-9A-Za-z.])" + re.escape(value) + r"(?![0-9A-Za-z.])")
        related = []
        for rid, raw in rows:
            if rid in exclude_ids or len(related) >= limit:
                continue
            if not boundary.search(raw):
                continue  # substring hit only (e.g. partial IP) — drop
            try:
                d = json.loads(raw)
            except Exception:
                continue
            related.append({
                "id": rid,
                "title": str(d.get("title") or "")[:90],
                "created": str(d.get("created") or "")[:19],
                "priority": d.get("priority"),
            })
        return {"count": count, "related": related}


# [FYP-CLASS] `NetWitnessEventsSource` — owns NetWitnessEventsSource state or behaviour for the SOC analysis support component.
# [FYP-PROCESS] Important methods: pivot.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class NetWitnessEventsSource:
    """Stage 2b stub: pivot against the LIVE NetWitness API instead of the
    local cache. Same contract as LocalCorpusSource.pivot(). Implementation
    is blocked on working per-incident alert/event queries (needs VPN + the
    alerts-endpoint HTTP code the user will capture on the next live run);
    when built it should route requests through app.py's _bounded_get so a
    dribbling NetWitness server can't hang the map."""

    name = "NetWitness live query"

    # [FYP-FUNCTION] `pivot` — implements the pivot operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `value`, `exclude_ids`, `limit`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include incident_expansion.py:expand_incident_map; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `NotImplementedError`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

    def pivot(self, value: str, exclude_ids: set[str], limit: int = 6) -> dict:
        raise NotImplementedError(
            "Live NetWitness pivoting lands in Stage 2b once the alerts "
            "endpoint is fixed; use LocalCorpusSource meanwhile."
        )


# [FYP-FUNCTION] `_frontier` — implements the frontier operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `imap`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include incident_expansion.py:expand_incident_map; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `len`, `sorted`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _frontier(imap: dict) -> list[dict]:
    """Pivotable entity nodes, deterministic priority order: the incident's
    focus entity first, then hosts/users, then everything else."""
    # [FYP-FUNCTION] `rank` — implements the rank operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `n`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `any`, `get`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def rank(n: dict) -> tuple:
        focus = 0 if any(
            e["src"] == n["id"] and e["relation"] == "focus_of"
            for e in imap["edges"]) else 1
        type_rank = {"user": 0, "host": 0, "entity": 1, "hash": 2,
                     "process": 2, "file": 2, "domain": 3, "ip": 4}
        return (focus, type_rank.get(n["type"], 5), n["id"])

    cands = [
        n for n in imap["nodes"]
        if n["type"] in _PIVOTABLE_TYPES
        and len(n["label"]) >= _MIN_VALUE_LEN
        and not n["props"].get("expanded")
    ]
    return sorted(cands, key=rank)


# [FYP-FUNCTION] `expand_incident_map` — implements the expand incident map operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `imap`, `source`, `max_pivots`, `max_related`, `deadline_seconds`, `profile_focus`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_frontier`, `add`, `add_edge`, `append`, `format_profile`, `get`, `hasattr`, `len`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def expand_incident_map(imap: dict, source: Any, max_pivots: int = 10,
                        max_related: int = 6,
                        deadline_seconds: float = 8.0,
                        profile_focus: bool = True) -> dict:
    """Autonomous expansion loop (mutates and returns `imap`).

    For each frontier entity, asks `source` which other incidents mention it
    and grafts the results onto the map with evidence tags. Bounded by
    max_pivots and a wall-clock deadline; ubiquitous entities are annotated
    but not expanded.
    """
    t0 = time.time()
    log: list[str] = imap.setdefault("expansion_log", [])
    seed_id = imap["incident_id"]
    known_incidents = {n["label"] for n in imap["nodes"] if n["type"] == "incident"}
    nodes_by_id = {n["id"]: n for n in imap["nodes"]}
    pivots = related_added = 0

    # [FYP-FUNCTION] `add_edge` — implements the add edge operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `src`, `dst`, `relation`, `evidence`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include incident_expansion.py:expand_incident_map; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def add_edge(src: str, dst: str, relation: str, evidence: str) -> None:
        for e in imap["edges"]:
            if e["src"] == src and e["dst"] == dst and e["relation"] == relation:
                if evidence not in e["evidence"]:
                    e["evidence"].append(evidence)
                e["count"] += 1
                return
        imap["edges"].append({"src": src, "dst": dst, "relation": relation,
                              "evidence": [evidence], "count": 1})

    for node in _frontier(imap):
        if pivots >= max_pivots:
            log.append(f"pivot budget ({max_pivots}) reached")
            break
        if time.time() - t0 > deadline_seconds:
            log.append(f"expansion deadline ({deadline_seconds:.0f}s) reached")
            break
        pivots += 1
        value = node["label"]
        try:
            res = source.pivot(value, exclude_ids={seed_id} | known_incidents,
                               limit=max_related)
        except Exception as exc:
            log.append(f"pivot failed for {value}: {exc}")
            continue
        node["props"]["expanded"] = True
        node["props"]["corpus_mentions"] = res["count"]

        if res["count"] == 0:
            log.append(f"· {value}: no other incidents reference it")
            continue
        if res["count"] > _UBIQUITOUS_AT:
            log.append(
                f"{value}: in {res['count']} incidents — ubiquitous "
                f"(gateway/scanner-class), not expanded")
            node["props"]["ubiquitous"] = True
            continue

        weak = res["count"] > _WEAK_SIGNAL_AT
        tag = " common across corpus (weak indicator)" if weak else ""
        log.append(
            f"{value}: seen in {res['count']} other incidents — "
            f"linked newest {len(res['related'])}{tag}")
        for rel in res["related"]:
            rid = rel["id"]
            nid = f"incident:{rid}"
            if nid not in nodes_by_id:
                new_node = {"id": nid, "type": "incident", "label": rid,
                            "props": {"title": rel["title"],
                                      "created": rel["created"],
                                      "priority": rel["priority"],
                                      "related": True}}
                imap["nodes"].append(new_node)
                nodes_by_id[nid] = new_node
                known_incidents.add(rid)
                related_added += 1
            add_edge(node["id"], nid, "also_seen_in", f"{source.name} pivot")

    # Endpoint entity profile — deep behavioural analysis of the incident's
    # focus entity (timeline, bursts, severity mix, co-IPs, lateral-movement
    # candidates). Only for local-corpus sources; guarded + deadline-aware.
    if profile_focus and hasattr(source, "db_path"):
        focus = next((nodes_by_id.get(e["src"]) for e in imap["edges"]
                      if e["relation"] == "focus_of"), None)
        if focus and focus["type"] in ("user", "host", "entity") and \
                time.time() - t0 < deadline_seconds:
            try:
                from endpoint_profile import profile_entity, format_profile
                prof = profile_entity(source.db_path, focus["label"],
                                      exclude_id=seed_id)
                if prof:
                    imap["endpoint_profile"] = prof
                    imap["endpoint_profile_text"] = format_profile(prof)
                    focus["props"]["profiled"] = True
                    log.append(
                        f"endpoint profile: {focus['label']} — "
                        f"{prof['total_incidents']} incidents "
                        f"{prof['first_seen']} → {prof['last_seen']}, "
                        f"{len(prof['lateral_candidates'])} shared-IP lateral trail(s)")
            except Exception as exc:
                log.append(f"endpoint profile unavailable: {exc}")

    # refresh counts so map_caption reflects the expanded graph
    type_counts: dict[str, int] = {}
    for n in imap["nodes"]:
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1
    imap["stats"]["node_counts"] = type_counts
    imap["stats"]["edge_count"] = len(imap["edges"])
    imap["stats"]["pivots"] = pivots
    imap["stats"]["related_incidents"] = related_added
    imap["stats"]["expansion_seconds"] = round(time.time() - t0, 2)
    if pivots:
        imap["stats"]["evidence_basis"] += (
            f" + autonomous expansion ({pivots} pivots via {source.name})")
    return imap
