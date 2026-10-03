# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, hashlib, json, pydantic, typing,
#   agents.triage.triage_result.
# =============================================================================
# File: agents/triage/review.py
# Purpose: [FYP-TRIAGE-STEP3] The analyst's STRUCTURED triage review: the
#   human verdict that becomes canonical downstream (X1), the routing key for
#   feedback (X3: false_positive -> rule tuning, benign_expected -> scoped
#   suppression proposal) and one row of the labelled-verdict store (X6).
# Main functionality: TriageReview / BenignContext / SuppressionProposalInput
#   (Pydantic, extra="forbid"), validate_review(), ai_side(),
#   build_triage_review_block(), packet_sha256(), checklist_sections(),
#   ai_to_analyst_line().
# Inputs: the JSON `review` object posted with a Triage approval/rejection,
#   plus the persisted triage result (evidence_packet + assessment).
# Outputs: validated dicts; a stable sha256 of the evidence snapshot; the
#   additive `triage_review` block the investigation/reporting handoffs and
#   the ticket export carry.
# Workflow position: Triage approval gate (workflow/commands.py::approve_stage
#   / reject_stage) and every downstream consumer of the Triage verdict.
# Called by: workflow/commands.py, workflow/engine.py,
#   agents/reporting/triage_ticket_editing.py, backend/services/triage_feedback_service.py.
# Important side effects: none (pure; no Flask, no workflow/, no I/O).
# Error and fallback behaviour: pydantic.ValidationError on an invalid review;
#   callers turn it into the canonical {"error": {code, message}} shape.
# Key evaluator search terms: TriageReview, triage_review, analyst verdict,
#   [FYP-TRIAGE-STEP3], [FYP-EVALUATOR].
# =============================================================================
"""
Structured triage review  --  review.py
=======================================
[FYP-TRIAGE-STEP3] Method principles enforced here (cited in docs/triage-review.md):

* Step 9 "Document the verdict AND the evidence trail" -- a review must name
  at least one piece of evidence the analyst actually checked; the evidence
  packet AS SEEN AT DECISION TIME is snapshotted and hashed with it.
  Confirmed-benign vs assumed-benign: the difference is recording WHAT was
  checked.
* Step 10 "FP from a broken rule -> flag it for tuning". FP != Benign-Expected:
  false_positive REQUIRES a rule_tuning_note (a rule problem), benign_expected
  REQUIRES benign_context {who, when, why} (a context problem).
* Automation bias: the analyst must state a disagreement_reason whenever the
  analyst disposition differs from the AI final disposition, and in
  blind_first mode the initial (pre-reveal) disposition is kept separately.
* Tier 3 / Tier 2: the verdict stays human; nothing here closes or suppresses
  anything -- a suppression is only a PROPOSAL that a second human approves.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .triage_result import DISPOSITIONS, Disposition

ReviewMode = Literal["assisted", "blind_first"]
REVIEW_MODES: tuple[str, ...] = ("assisted", "blind_first")

# Free-text bounds: long enough for a real note, short enough that a review
# row cannot be used to smuggle a whole log into the labelled store.
_SHORT = 300
_LONG = 2000
_MAX_EVIDENCE_ITEMS = 60

DISPOSITION_LABELS: dict[str, str] = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "benign_expected": "Benign-expected",
    "needs_info": "Needs-info",
}


def _clean(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


class BenignContext(BaseModel):
    """Benign-Expected is a CONTEXT fact, so it records who did it, when, and
    why it is expected (e.g. "IT ops / patch window 02:00-04:00 / WSUS
    rollout CHG-1234"). All three are required."""

    model_config = ConfigDict(extra="forbid")

    who: str = Field(min_length=1, max_length=_SHORT)
    when: str = Field(min_length=1, max_length=_SHORT)
    why: str = Field(min_length=1, max_length=_LONG)

    @field_validator("who", "when", "why", mode="before")
    @classmethod
    def _strip(cls, v: Any) -> Any:
        return _clean(v)


class SuppressionScope(BaseModel):
    """What a suppression would match. detection_source and entity are
    required (a suppression is always scoped to ONE rule on ONE entity);
    alert_signature narrows it further when given."""

    model_config = ConfigDict(extra="forbid")

    detection_source: str = Field(min_length=1, max_length=_SHORT)
    entity: str = Field(min_length=1, max_length=_SHORT)
    alert_signature: Optional[str] = Field(default=None, max_length=_SHORT)

    @field_validator("detection_source", "entity", "alert_signature", mode="before")
    @classmethod
    def _strip(cls, v: Any) -> Any:
        v = _clean(v)
        return None if v == "" else v


class SuppressionProposalInput(BaseModel):
    """Optional suppression proposal attached to a benign_expected review.
    expiry_days is bounded by agents/triage/suppression.py's named constants
    (default 30, max 90); the bound is re-checked there."""

    model_config = ConfigDict(extra="forbid")

    scope: SuppressionScope
    expiry_days: Optional[int] = Field(default=None, ge=1, le=365)


class TriageReview(BaseModel):
    """[FYP-EVALUATOR] The analyst's structured review of one Triage result.

    Disposition-dependent required fields (validated below, all strings
    stripped first so whitespace never satisfies a requirement):
      * evidence_checked: >= 1 item, ALWAYS (packet dot-paths or free text);
      * justification: ALWAYS (one sentence);
      * lookalike_considered: unless analyst_disposition == true_positive;
      * rule_tuning_note: iff false_positive (required);
      * benign_context {who, when, why}: iff benign_expected (required);
      * suppression_proposal: only allowed with benign_expected;
      * disagreement_reason: required when analyst_disposition differs
        from ai_final_disposition (the AI value is filled in by the server
        from the persisted result, never trusted from the client);
      * blind_first: analyst_initial_disposition required; a revision after
        the AI reveal (initial != final) requires revision_reason.
    """

    model_config = ConfigDict(extra="forbid")

    analyst_disposition: Disposition
    evidence_checked: list[str] = Field(min_length=1, max_length=_MAX_EVIDENCE_ITEMS)
    justification: str = Field(min_length=1, max_length=_LONG)
    lookalike_considered: Optional[str] = Field(default=None, max_length=_LONG)
    rule_tuning_note: Optional[str] = Field(default=None, max_length=_LONG)
    benign_context: Optional[BenignContext] = None
    suppression_proposal: Optional[SuppressionProposalInput] = None
    disagreement_reason: Optional[str] = Field(default=None, max_length=_LONG)
    review_mode: ReviewMode = "assisted"
    analyst_initial_disposition: Optional[Disposition] = None
    revision_reason: Optional[str] = Field(default=None, max_length=_LONG)
    # Server-filled from the persisted triage result before validation (the
    # client value, if any, is overwritten) -- see validate_review().
    ai_final_disposition: Optional[Disposition] = None

    @field_validator("justification", "lookalike_considered", "rule_tuning_note",
                     "disagreement_reason", "revision_reason", mode="before")
    @classmethod
    def _strip_text(cls, v: Any) -> Any:
        v = _clean(v)
        return None if v == "" else v

    @field_validator("evidence_checked", mode="before")
    @classmethod
    def _strip_items(cls, v: Any) -> Any:
        if isinstance(v, list):
            out: list[Any] = []
            for item in v:
                item = _clean(item)
                if isinstance(item, str) and item and item not in out:
                    out.append(item[:_SHORT])
                elif not isinstance(item, str):
                    out.append(item)   # let pydantic reject the wrong type
            return out
        return v

    @model_validator(mode="after")
    def _disposition_rules(self) -> "TriageReview":
        d = self.analyst_disposition
        errors: list[str] = []
        if d != "true_positive" and not self.lookalike_considered:
            errors.append("lookalike_considered is required unless the disposition is "
                          "true_positive (name the most plausible malicious lookalike)")
        if d == "false_positive" and not self.rule_tuning_note:
            errors.append("rule_tuning_note is required for false_positive "
                          "(FP = rule problem -> tuning)")
        if d != "false_positive" and self.rule_tuning_note:
            errors.append("rule_tuning_note is only allowed with false_positive")
        if d == "benign_expected" and self.benign_context is None:
            errors.append("benign_context {who, when, why} is required for benign_expected "
                          "(Benign-Expected = context problem -> record who/when/why)")
        if d != "benign_expected" and self.benign_context is not None:
            errors.append("benign_context is only allowed with benign_expected")
        if self.suppression_proposal is not None and d != "benign_expected":
            errors.append("a suppression proposal is only allowed with benign_expected")
        if (self.ai_final_disposition and d != self.ai_final_disposition
                and not self.disagreement_reason):
            errors.append("disagreement_reason is required when the analyst disposition "
                          f"differs from the AI final disposition ({self.ai_final_disposition})")
        if self.review_mode == "blind_first":
            if self.analyst_initial_disposition is None:
                errors.append("analyst_initial_disposition is required in blind_first mode")
            elif self.analyst_initial_disposition != d and not self.revision_reason:
                errors.append("revision_reason is required when the disposition is revised "
                              "after the AI verdict is revealed")
        elif self.analyst_initial_disposition is not None and self.analyst_initial_disposition != d:
            errors.append("analyst_initial_disposition differs from analyst_disposition but "
                          "review_mode is assisted (only blind_first records a revision)")
        if errors:
            raise ValueError("; ".join(errors))
        return self

    @property
    def agrees_with_ai(self) -> Optional[bool]:
        if not self.ai_final_disposition:
            return None
        return self.analyst_disposition == self.ai_final_disposition

    @property
    def revised_after_ai_reveal(self) -> bool:
        return (self.review_mode == "blind_first"
                and self.analyst_initial_disposition is not None
                and self.analyst_initial_disposition != self.analyst_disposition)


def validate_review(raw: Any, *, ai_final_disposition: str | None) -> TriageReview:
    """[FYP-FUNCTION] Validate a posted review against the persisted AI
    verdict. The AI disposition is taken from the server's own triage
    result, never from the request body (an analyst cannot "agree" with a
    verdict the AI never gave)."""
    if not isinstance(raw, dict):
        raise ValueError("review must be a JSON object")
    data = dict(raw)
    ai = ai_final_disposition if ai_final_disposition in DISPOSITIONS else None
    data["ai_final_disposition"] = ai
    return TriageReview.model_validate(data)


def packet_sha256(packet: Any) -> str | None:
    """Stable sha256 of an evidence-packet snapshot (sorted keys, compact)."""
    if not packet:
        return None
    blob = json.dumps(packet, sort_keys=True, separators=(",", ":"), default=str,
                      ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def ai_side(triage_result: dict | None) -> dict:
    """AI side of a review row, read from the persisted triage result."""
    tr = triage_result if isinstance(triage_result, dict) else {}
    a = tr.get("assessment") if isinstance(tr.get("assessment"), dict) else {}
    return {
        "ai_proposed_disposition": a.get("proposed_disposition"),
        "ai_final_disposition": a.get("disposition"),
        "uncertainty": a.get("uncertainty"),
    }


def checklist_sections(packet: dict | None) -> list[str]:
    """Packet sections that contain >= 1 measured leaf -- the "Evidence I
    checked" checklist the review form offers (mirrored in
    frontend/js/components/triageReview.js)."""
    out = []
    for section, node in (packet or {}).items():
        if isinstance(node, dict) and _has_measured(node):
            out.append(section)
    return out


def _has_measured(node: dict) -> bool:
    if set(node) == {"value", "status", "source"}:
        return node.get("status") == "measured"
    return any(isinstance(v, dict) and _has_measured(v) for v in node.values())


def build_triage_review_block(review_row: dict | None) -> dict | None:
    """[FYP-FUNCTION] [FYP-EVALUATOR] The additive `triage_review` block the
    investigation / reporting handoffs and the ticket export carry. The
    ANALYST'S disposition is `final_disposition` (canonical); the AI's is
    kept alongside for traceability. ticket.classification (severity) is
    untouched -- severity != disposition."""
    if not isinstance(review_row, dict) or not review_row.get("analyst_disposition"):
        return None
    ev = review_row.get("evidence_checked")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except (TypeError, ValueError):
            ev = [ev]
    agrees = review_row.get("agrees_with_ai")
    return {
        "final_disposition": review_row.get("analyst_disposition"),
        "final_disposition_source": "analyst",
        "ai_disposition": review_row.get("ai_final_disposition"),
        "ai_proposed_disposition": review_row.get("ai_proposed_disposition"),
        "agrees_with_ai": None if agrees is None else bool(agrees),
        "justification": review_row.get("justification"),
        "evidence_checked": ev or [],
        "analyst": review_row.get("analyst"),
        "decided_at": review_row.get("decided_at"),
        "decision": review_row.get("decision"),
        "review_id": review_row.get("id"),
        "label_provenance": review_row.get("label_provenance") or "analyst",
    }


def disposition_label(value: str | None) -> str:
    return DISPOSITION_LABELS.get(str(value or ""), str(value or "unknown"))


def ai_to_analyst_line(block: dict | None) -> str | None:
    """"AI: X -> Analyst: Y" (plain ASCII arrow so DOCX/PDF fonts never
    need a glyph fallback)."""
    if not block:
        return None
    return (f"AI: {disposition_label(block.get('ai_disposition'))} -> "
            f"Analyst: {disposition_label(block.get('final_disposition'))}")


__all__ = [
    "REVIEW_MODES",
    "DISPOSITION_LABELS",
    "BenignContext",
    "SuppressionScope",
    "SuppressionProposalInput",
    "TriageReview",
    "validate_review",
    "packet_sha256",
    "ai_side",
    "checklist_sections",
    "build_triage_review_block",
    "disposition_label",
    "ai_to_analyst_line",
]
