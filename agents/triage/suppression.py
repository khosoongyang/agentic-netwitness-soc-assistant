# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, typing,
#   agents.triage.baseline (detection_source / extract_entity semantics).
# =============================================================================
# File: agents/triage/suppression.py
# Purpose: [FYP-TRIAGE-STEP3] X3 -- pure rules for SCOPED, EXPIRING
#   suppression proposals: expiry bounds, the scope text an approver must
#   type, scope extraction from an evidence packet, and matching an
#   APPROVED, UNEXPIRED proposal to an incident's packet so it can appear as
#   the `context.suppression_match` evidence leaf.
# Main functionality: DEFAULT_SUPPRESSION_EXPIRY_DAYS,
#   MAX_SUPPRESSION_EXPIRY_DAYS, clamp_expiry_days(), scope_text(),
#   scope_from_packet(), signature_label(), match_suppressions(),
#   suppression_match_leaf().
# Inputs: proposal dicts (rows of the suppression_proposals table, read by
#   workflow/review_store.py) and an evidence packet.
# Outputs: plain dicts / evidence leaves.
# Workflow position: Triage Phase 0 (evidence packet) + feedback routing.
# Called by: agents/triage/evidence_packet.py, agents/triage/guards.py,
#   workflow/review_store.py, backend/services/triage_feedback_service.py.
# Important side effects: none (pure; no I/O, no Flask, no workflow/).
# Error and fallback behaviour: malformed proposals are skipped (no match),
#   never guessed into a match; an unparseable expiry is treated as EXPIRED.
# Key evaluator search terms: suppression_match, adversarial mimicry,
#   never auto-suppress, [FYP-TRIAGE-STEP3].
# =============================================================================
"""
Scoped suppression proposals  --  suppression.py
================================================
[FYP-TRIAGE-STEP3] Method principles:

* FP != Benign-Expected. Benign-Expected is a CONTEXT fact (who/when/why),
  so the remedy is a narrowly SCOPED, EXPIRING suppression proposal -- not
  a rule change (that is the false_positive -> tuning backlog route).
* Tier 2 hard rule: never auto-close, never auto-suppress. A proposal only
  takes effect after a second human approves it by typing its scope, and
  even then it only ADDS an evidence leaf (context.suppression_match); the
  analyst still reviews every incident.
* Adversarial mimicry: an attacker can make malicious activity look like
  the expected maintenance job. A suppression therefore can NEVER satisfy
  the Step-1/2 strong-signal floor: if the packet has strong rule signals or
  strong LOLBAS hits / path_mismatch, the match is marked
  ignored_for_guards and agents/triage/guards.py disregards it.
* Missing = unknown, not safe: an expired or unparseable proposal is no
  match.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

DEFAULT_SUPPRESSION_EXPIRY_DAYS = 30
MAX_SUPPRESSION_EXPIRY_DAYS = 90
SUPPRESSION_STATUSES: tuple[str, ...] = ("proposed", "approved", "rejected", "expired", "revoked")

MISSING_SOURCE = "no approved, unexpired suppression proposal matches this incident's scope"


def clamp_expiry_days(days: Any) -> int:
    """Default 30, hard max 90 (both named constants). Values above the max
    raise rather than being silently shortened, so the proposer sees why."""
    if days in (None, ""):
        return DEFAULT_SUPPRESSION_EXPIRY_DAYS
    try:
        n = int(days)
    except (TypeError, ValueError) as exc:
        raise ValueError("expiry_days must be an integer") from exc
    if n < 1 or n > MAX_SUPPRESSION_EXPIRY_DAYS:
        raise ValueError(f"expiry_days must be between 1 and {MAX_SUPPRESSION_EXPIRY_DAYS}")
    return n


def expiry_from(created_at: datetime, days: int) -> str:
    return (created_at + timedelta(days=days)).isoformat()


def scope_text(detection_source: str, entity: str, alert_signature: str | None = None) -> str:
    """Canonical human-readable scope; an approver must type it EXACTLY to
    confirm (same pattern as the admin pipeline's "DELETE <stage>/<id>")."""
    parts = [f"source={str(detection_source).strip()}", f"entity={str(entity).strip()}"]
    if alert_signature and str(alert_signature).strip():
        parts.append(f"signature={str(alert_signature).strip()}")
    return "; ".join(parts)


def signature_label(sig: dict) -> str | None:
    """"<alert name> :: <process>" -- the raw-alert signature label used for
    the tuning backlog and suppression scopes (command lines are excluded:
    they are long, attacker-controlled and vary per run)."""
    if not isinstance(sig, dict):
        return None
    name = str(sig.get("alert_name") or "").strip()
    proc = str(sig.get("process") or "").strip()
    if not name and not proc:
        return None
    return f"{name or '?'} :: {proc}" if proc else name


def _leaf_value(packet: dict, *path: str) -> Any:
    node: Any = packet or {}
    for p in path:
        if not isinstance(node, dict):
            return None
        node = node.get(p)
    if isinstance(node, dict) and set(node) == {"value", "status", "source"}:
        return None if node.get("status") == "missing" else node.get("value")
    return None


def scope_from_packet(packet: dict | None) -> dict:
    """{detection_source, entity, signatures[]} of an incident, from its
    evidence packet. detection_source = "createdBy" or "createdBy / ruleId"
    (the same pair agents/triage/baseline.detection_source keys on)."""
    created_by = _leaf_value(packet or {}, "detection", "createdBy")
    rule_id = _leaf_value(packet or {}, "detection", "ruleId")
    source = None
    if created_by not in (None, ""):
        source = str(created_by).strip()
        if rule_id not in (None, ""):
            source = f"{source} / {str(rule_id).strip()}"
    entity = _leaf_value(packet or {}, "entity", "value")
    sigs_val = _leaf_value(packet or {}, "raw_alerts", "signatures")
    items = sigs_val.get("items") if isinstance(sigs_val, dict) else None
    labels: list[str] = []
    for sig in items or []:
        lab = signature_label(sig)
        if lab and lab not in labels:
            labels.append(lab)
    return {"detection_source": source,
            "entity": str(entity).strip() if entity not in (None, "") else None,
            "signatures": labels}


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_active(proposal: dict, now: datetime | None = None) -> bool:
    """Approved AND unexpired. Unparseable expiry = expired (fail closed)."""
    if not isinstance(proposal, dict) or proposal.get("status") != "approved":
        return False
    exp = _parse_iso(proposal.get("expires_at"))
    now = now or datetime.now(timezone.utc)
    return exp is not None and exp > now


def _same(a: Any, b: Any) -> bool:
    return (a not in (None, "") and b not in (None, "")
            and str(a).strip().casefold() == str(b).strip().casefold())


def match_suppressions(packet: dict | None, proposals: Iterable[dict] | None,
                       now: datetime | None = None) -> list[dict]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Active proposals whose scope matches
    the packet: same detection source AND same entity, and -- when the
    proposal names one -- the signature is among the incident's raw-alert
    signatures. Returns compact match dicts (newest approval first)."""
    scope = scope_from_packet(packet)
    out = []
    for p in proposals or []:
        if not is_active(p, now):
            continue
        if not (_same(p.get("detection_source"), scope["detection_source"])
                and _same(p.get("entity"), scope["entity"])):
            continue
        sig = p.get("alert_signature")
        if sig not in (None, "") and not any(_same(sig, s) for s in scope["signatures"]):
            continue
        out.append({
            "suppression_id": p.get("id"),
            "scope": scope_text(p.get("detection_source"), p.get("entity"), sig),
            "approved_by": p.get("decided_by"),
            "approved_at": p.get("decided_at"),
            "expires_at": p.get("expires_at"),
            "benign_context": p.get("benign_context"),
        })
    out.sort(key=lambda m: str(m.get("approved_at") or ""), reverse=True)
    return out


def suppression_match_leaf(matches: list[dict], strong_signals: list[str]) -> dict:
    """The `context.suppression_match` leaf. Status "measured" (an approved
    human decision is an observed fact), source names the suppression, its
    approver and expiry. When strong signals are present the value carries
    ignored_for_guards=True plus the reason the UI shows (adversarial
    mimicry) -- guards.py ignores the match in that case."""
    if not matches:
        return {"value": None, "status": "missing", "source": MISSING_SOURCE}
    first = matches[0]
    value: dict[str, Any] = {"matches": matches, "ignored_for_guards": bool(strong_signals)}
    if strong_signals:
        value["ignored_reason"] = (
            "strong rule signal(s) present (" + ", ".join(strong_signals) + "): a suppression "
            "can never satisfy the strong-signal floor -- attackers can mimic expected "
            "activity (adversarial mimicry), so the analyst must review the evidence")
    source = (f"suppression #{first.get('suppression_id')} approved by "
              f"{first.get('approved_by') or 'unknown'}, expires {first.get('expires_at')}")
    if len(matches) > 1:
        source += f" (+{len(matches) - 1} more)"
    return {"value": value, "status": "measured", "source": source}


__all__ = [
    "DEFAULT_SUPPRESSION_EXPIRY_DAYS",
    "MAX_SUPPRESSION_EXPIRY_DAYS",
    "SUPPRESSION_STATUSES",
    "clamp_expiry_days",
    "expiry_from",
    "scope_text",
    "signature_label",
    "scope_from_packet",
    "is_active",
    "match_suppressions",
    "suppression_match_leaf",
]
