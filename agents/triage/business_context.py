"""agents/triage/business_context.py -- improvement #2: real business context.

The evidence packet's three business-context leaves used to be permanent
placeholders, so `benign_expected` was only reachable through an analyst
note. Each leaf is now built from a real, attributable source. workflow/
reads the sources and passes the finished leaves in (agents/ never reads
the workflow DB), so this module is pure and stdlib-only:

* context.confirmed_benign_history -- prior APPROVED analyst reviews for the
  same detection source + entity: "measured", value = counts by analyst
  disposition. No prior approved review -> "missing" (unknown, not safe).
* context.change_context -- the analyst-maintained change-window list
  (JSON file, AEGIS_CHANGE_WINDOWS, default runtime/context/change_windows.json):
  "measured" only when a window names this entity and covers the incident
  time. Malformed windows never match.
* context.asset_context -- the asset inventory (JSON file,
  AEGIS_ASSET_INVENTORY, default runtime/context/asset_inventory.json):
  "measured" when the entity is listed; otherwise, for a hostname, the
  naming-pattern tier from agents/investigation/tools/asset_criticality.py
  as "inferred"; an IP with no inventory entry stays "missing".

The guards are unchanged: context must be measured or inferred and CITED to
count, a strong rule signal still needs cited context, and context is not
part of the uncertainty score (audit T-18 decision).
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_ROOT = Path(__file__).resolve().parents[2]
CHANGE_WINDOWS_ENV = "AEGIS_CHANGE_WINDOWS"
ASSET_INVENTORY_ENV = "AEGIS_ASSET_INVENTORY"
DEFAULT_CHANGE_WINDOWS = _ROOT / "runtime" / "context" / "change_windows.json"
DEFAULT_ASSET_INVENTORY = _ROOT / "runtime" / "context" / "asset_inventory.json"

NO_HISTORY_SOURCE = "no prior approved analyst review for this detection source + entity"
NO_WINDOW_SOURCE = "no approved change window covers this entity at the incident time"
NO_ASSET_SOURCE = "entity not in the asset inventory and its role cannot be inferred"
_MAX_EXAMPLES = 5


def _leaf(value: Any, status: str, source: str) -> dict:
    return {"value": value, "status": status, "source": source}


def _missing(source: str) -> dict:
    return _leaf(None, "missing", source)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _same(a: Any, b: Any) -> bool:
    return (a not in (None, "") and b not in (None, "")
            and str(a).strip().casefold() == str(b).strip().casefold())


# ── confirmed_benign_history ────────────────────────────────────────────────

def benign_history_leaf(prior_reviews: Iterable[dict] | None) -> dict:
    """Counts of APPROVED prior analyst dispositions for this scope. Caller
    passes reviews already filtered to the same detection source + entity
    and excluding the current run."""
    approved = [r for r in (prior_reviews or [])
                if isinstance(r, dict) and str(r.get("decision") or "").lower() in ("approved", "approve")
                and r.get("analyst_disposition")]
    if not approved:
        return _missing(NO_HISTORY_SOURCE)
    counts = Counter(str(r["analyst_disposition"]) for r in approved)
    latest = sorted(approved, key=lambda r: str(r.get("decided_at") or ""))[-_MAX_EXAMPLES:]
    value = {
        "prior_reviews": len(approved),
        "true_positive": counts.get("true_positive", 0),
        "false_positive": counts.get("false_positive", 0),
        "benign_expected": counts.get("benign_expected", 0),
        "needs_info": counts.get("needs_info", 0),
        "latest": [{"incident_id": r.get("incident_id"), "disposition": r.get("analyst_disposition"),
                    "analyst": r.get("analyst"), "decided_at": r.get("decided_at")} for r in reversed(latest)],
    }
    return _leaf(value, "measured",
                 f"{len(approved)} prior analyst-reviewed decision(s) for this detection source + entity")


# ── change_context ──────────────────────────────────────────────────────────

def load_change_windows(path: str | Path | None = None) -> list[dict]:
    """Analyst-maintained change windows. Missing / unreadable -> []."""
    p = Path(path or os.environ.get(CHANGE_WINDOWS_ENV, "").strip() or DEFAULT_CHANGE_WINDOWS)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = data.get("windows") if isinstance(data, dict) else data
    return [w for w in (items or []) if isinstance(w, dict)]


def change_context_leaf(windows: Iterable[dict] | None, *, entity: Any, when: Any) -> dict:
    """The first window naming `entity` whose [start, end] covers `when`."""
    t = _parse_time(when)
    if t is None or entity in (None, ""):
        return _missing(NO_WINDOW_SOURCE)
    for w in windows or []:
        entities = w.get("entities") if isinstance(w.get("entities"), list) else [w.get("entity")]
        if not any(_same(e, entity) for e in entities):
            continue
        start, end = _parse_time(w.get("start")), _parse_time(w.get("end"))
        if start is None or end is None or not (start <= t <= end):
            continue
        change_id = str(w.get("id") or "unnamed change")
        value = {"change_id": change_id, "description": w.get("description"),
                 "start": w.get("start"), "end": w.get("end"), "approved_by": w.get("approved_by")}
        who = f", approved by {w['approved_by']}" if w.get("approved_by") else ""
        return _leaf(value, "measured", f"change window {change_id} ({w.get('start')} - {w.get('end')}{who})")
    return _missing(NO_WINDOW_SOURCE)


# ── asset_context ───────────────────────────────────────────────────────────

def load_asset_inventory(path: str | Path | None = None) -> dict:
    """{entity: {role, tier, owner, ...}}. Missing / unreadable -> {}."""
    p = Path(path or os.environ.get(ASSET_INVENTORY_ENV, "").strip() or DEFAULT_ASSET_INVENTORY)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if isinstance(data, list):
        data = {str(a.get("entity") or a.get("name")): a for a in data if isinstance(a, dict)}
    return {str(k).casefold(): v for k, v in (data or {}).items() if isinstance(v, dict)}


def asset_context_leaf(inventory: dict | None, *, entity: Any, entity_kind: Any) -> dict:
    if entity in (None, ""):
        return _missing(NO_ASSET_SOURCE)
    entry = (inventory or {}).get(str(entity).strip().casefold())
    if isinstance(entry, dict):
        value = {k: entry.get(k) for k in ("role", "tier", "owner", "business_function", "notes")
                 if entry.get(k) not in (None, "")}
        return _leaf(value, "measured", f"asset inventory entry for {entity}")
    if str(entity_kind or "").startswith("host"):
        try:
            from agents.investigation.tools.asset_criticality import classify_asset
        except Exception:
            return _missing(NO_ASSET_SOURCE)
        c = classify_asset(str(entity))
        if c.get("tier") and c["tier"] != "unclassified":
            return _leaf({"tier": c["tier"], "reason": c.get("reason")}, "inferred",
                         f"hostname naming pattern ({c.get('reason')}); not verified against an inventory")
    return _missing(NO_ASSET_SOURCE)


__all__ = ["benign_history_leaf", "change_context_leaf", "asset_context_leaf",
           "load_change_windows", "load_asset_inventory",
           "CHANGE_WINDOWS_ENV", "ASSET_INVENTORY_ENV"]
