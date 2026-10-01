# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, copy, typing, agents.triage.evidence_packet,
#   agents.triage.triage_result.
# =============================================================================
# File: agents/triage/guards.py
# Purpose: Code-enforced safety net around the LLM's disposition. Verifies
#   that every citation points at real, non-missing evidence, then applies
#   hard disposition guards (rules a-e) and computes uncertainty
#   deterministically from evidence completeness.
# Main functionality: normalize_assessment(), verify_citations(),
#   apply_guards(), compute_uncertainty(), build_assessment(),
#   MANDATORY_EVIDENCE, CORE_EVIDENCE.
# Inputs: the raw `_run_cls` JSON (or any dict with the assessment keys) and
#   the evidence packet built by agents/triage/evidence_packet.py.
# Outputs: an assessment dict validated by triage_result.TriageAssessment:
#   {disposition, proposed_disposition, uncertainty, hypotheses,
#    lookalike_ruled_out, fn_cost_if_wrong, evidence_checked,
#    citation_errors, guard_actions}.
# Workflow position: Triage stage, AFTER the SOC Classification LLM call.
# Called by: agents/triage/soc_triage_agent.py (TriageAgent.triage),
#   workflow/engine.py (mock_triage_result).
# Important side effects: none (pure functions; inputs are never mutated).
# Error and fallback behaviour: malformed model output degrades to
#   proposed_disposition="needs_info" with a guard action -- never a crash,
#   never a silent "benign".
# Key evaluator search terms: verify_citations, apply_guards,
#   compute_uncertainty, MANDATORY_EVIDENCE, [FYP-TRIAGE-GUARDS].
# =============================================================================
"""
Triage guards  --  guards.py
============================
[FYP-TRIAGE-GUARDS] The prompt ASKS the model to reason from cited evidence;
this module ENFORCES it in Python, because a prompt is a request and code is
a rule. Order of operations (build_assessment):

  1. normalize_assessment()  -- coerce the model's JSON into the schema
  2. verify_citations()      -- drop cites that don't exist or are "missing";
                                drop claims left with no valid cite
  3. apply_guards()          -- rules a..e below, in order; each override is
                                recorded as {rule, from, to, reason}
  4. compute_uncertainty()   -- from evidence completeness + override count,
                                NEVER from a model-reported confidence

Guard rules (a disposition can only be moved TO "needs_info"):
  a) missing mandatory evidence    -> no false_positive / benign_expected
  b) strong rule signal present    -> no false_positive / benign_expected
                                      unless a non-missing context.* is cited
  c) benign_expected               -> needs >= 1 valid context.* cite
  d) false_positive                -> needs >= 1 valid data_quality.* or
                                      detection.* cite
  e) supporting hypothesis uncited -> needs_info

Rule (c) makes benign_expected unreachable while context.* is a placeholder.
That is intended: "confirmed-benign" requires evidence; "assumed-benign" is
not acceptable.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

from .evidence_packet import STRONG_SIGNAL_LABELS, get_leaf
# [FYP-TRIAGE-STEP2] abused-tool (LOLBAS) + masquerade floor labels.
from .lolbas import floor_labels as abused_tool_floor_labels
from .triage_result import DISPOSITIONS, TriageAssessment

NEEDS_INFO = "needs_info"
_BENIGN_SIDE = ("false_positive", "benign_expected")

# [FYP-EVALUATOR] Mandatory evidence: without ALL of these, the alert cannot
# be closed as false_positive or benign_expected (guard a). Each entry is
# (name, dot-path, predicate on the leaf, human description).
MANDATORY_EVIDENCE: tuple[tuple[str, str, Callable[[dict], bool], str], ...] = (
    ("detection_source", "detection.createdBy",
     lambda leaf: leaf["status"] != "missing",
     "detection source (raw_json.createdBy) is known"),
    ("resolved_entity", "entity.value",
     lambda leaf: leaf["status"] != "missing",
     "the incident's entity is resolved"),
    ("incident_time", "detection.created",
     lambda leaf: leaf["status"] != "missing",
     "the incident's own created time is known"),
    ("baseline_measured", "baseline.status",
     lambda leaf: leaf["status"] == "measured" and leaf["value"] == "measured",
     "the historical baseline status is 'measured'"),
    ("parser_completed", "data_quality.parser_status",
     lambda leaf: leaf["status"] != "missing" and str(leaf["value"]).lower() == "completed",
     "the Parsing stage completed"),
    # [FYP-TRIAGE-STEP2] SOC triage Step 2: "pull the raw log, never trust
    # the alert summary alone". The raw alerts must actually have been
    # fetched (and be non-empty) before the alert can be closed as benign.
    # Consequence (intended): an incident triaged from the slim SQLite copy
    # (alerts stripped) or with an unknown fetch outcome can only end as
    # needs_info or true_positive.
    ("raw_alerts_available", "raw_alerts.available",
     lambda leaf: leaf["status"] != "missing" and leaf["value"] is True,
     "the raw alerts were fetched (alerts_fetch_succeeded) and alerts_count > 0"),
)

# Core (non-mandatory) evidence that completes the picture. Uncertainty is
# the share of MANDATORY paths + these that have status "measured".
CORE_EVIDENCE: tuple[str, ...] = (
    "detection.ruleId",
    "detection.riskScore",
    "entity.kind",
    "baseline.same_source_entity_30d",
    "baseline.is_known_noisy",
    "data_quality.parser_confidence",
    "context.asset_context",
    "context.change_context",
    "context.confirmed_benign_history",
)

# Completeness bands. With context.* always missing the maximum completeness
# is 12/15 = 0.80 (Step 1: 11/14 = 0.79), so "low" uncertainty is not
# reachable until business context is integrated -- deliberately.
# [FYP-TRIAGE-STEP2] The low threshold moved 0.80 -> 0.85 ONLY to preserve
# that Step-1 invariant after raw_alerts.available joined the mandatory list
# (12/15 would otherwise have hit 0.80 exactly). This is not a calibration:
# the bands still mean the same thing (calibration is out of scope).
UNCERTAINTY_LOW_MIN_COMPLETENESS = 0.85
UNCERTAINTY_MEDIUM_MIN_COMPLETENESS = 0.55

_CLAIM_SLOTS: tuple[tuple[str, str], ...] = (
    ("malicious", "evidence_for"), ("malicious", "evidence_against"),
    ("benign", "evidence_for"), ("benign", "evidence_against"),
)


# =============================================================================
# [FYP-SECTION] NORMALISATION OF THE MODEL'S JSON
# =============================================================================

def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
    return []


def _as_claims(value: Any) -> list[dict]:
    claims: list[dict] = []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return claims
    for item in value:
        if isinstance(item, dict):
            text = str(item.get("claim") or item.get("text") or "").strip()
            cites = _as_str_list(item.get("cites") or item.get("citations"))
        elif isinstance(item, str):
            text, cites = item.strip(), []
        else:
            continue
        if text:
            claims.append({"claim": text, "cites": cites})
    return claims


def _as_disposition(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower().replace("-", "_").replace(" ", "_")
    return v if v in DISPOSITIONS else None


def normalize_assessment(raw: dict | None) -> dict:
    """[FYP-FUNCTION] Coerce the model's JSON into the assessment shape.

    An absent or invalid proposed_disposition becomes "needs_info" and is
    reported via ``_proposal_error`` (turned into a guard action later)."""
    raw = raw if isinstance(raw, dict) else {}
    hyp_raw = raw.get("hypotheses") if isinstance(raw.get("hypotheses"), dict) else {}
    hypotheses = {}
    for side in ("malicious", "benign"):
        h = hyp_raw.get(side) if isinstance(hyp_raw.get(side), dict) else {}
        hypotheses[side] = {"evidence_for": _as_claims(h.get("evidence_for")),
                            "evidence_against": _as_claims(h.get("evidence_against"))}

    lookalike = None
    la = raw.get("lookalike_ruled_out")
    if isinstance(la, dict):
        name = str(la.get("lookalike") or la.get("explanation") or la.get("claim") or "").strip()
        if name:
            lookalike = {"lookalike": name,
                         "ruled_out": la.get("ruled_out") is True,
                         "reason": str(la.get("reason") or la.get("why") or "").strip(),
                         "cites": _as_str_list(la.get("cites"))}
    elif isinstance(la, str) and la.strip():
        lookalike = {"lookalike": la.strip(), "ruled_out": False, "reason": "", "cites": []}

    raw_proposal = raw.get("proposed_disposition", raw.get("disposition"))
    proposal = _as_disposition(raw_proposal)
    out = {
        "proposed_disposition": proposal or NEEDS_INFO,
        "hypotheses": hypotheses,
        "lookalike_ruled_out": lookalike,
        "fn_cost_if_wrong": str(raw.get("fn_cost_if_wrong") or "").strip()
                            or "not stated by the model",
        "evidence_checked": _as_str_list(raw.get("evidence_checked")),
        "citation_errors": [],
        "guard_actions": [],
    }
    if proposal is None:
        out["_proposal_error"] = ("absent" if raw_proposal in (None, "")
                                  else f"invalid value {str(raw_proposal)[:60]!r}")
    return out


# =============================================================================
# [FYP-SECTION] CITATION VERIFICATION (T3)
# =============================================================================

def _cite_error(packet: dict, path: str) -> str | None:
    leaf = get_leaf(packet, path)
    if leaf is None:
        return "unknown_path"
    if leaf["status"] == "missing":
        return "missing_status"
    return None


def is_valid_cite(packet: dict, path: str) -> bool:
    """A cite is valid iff the dot-path names a packet leaf whose status is
    not "missing"."""
    return _cite_error(packet, path) is None


def verify_citations(assessment: dict, packet: dict) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Remove invalid citations.

    Every cited dot-path must exist in the packet AND must not have status
    "missing". Invalid cites are removed and listed in ``citation_errors``;
    a claim left with zero valid cites is dropped (also listed).
    ``evidence_checked`` may name missing leaves (checking and finding
    nothing is a legitimate record) but unknown paths are removed.
    Returns a new dict; the input is not mutated."""
    out = copy.deepcopy(assessment)
    errors: list[dict] = list(out.get("citation_errors") or [])

    hyps = out.setdefault("hypotheses", {})
    for side, slot in _CLAIM_SLOTS:
        claims = (hyps.setdefault(side, {}).get(slot)) or []
        kept = []
        for i, claim in enumerate(claims):
            loc = f"hypotheses.{side}.{slot}[{i}]"
            valid = []
            for path in claim.get("cites") or []:
                err = _cite_error(packet, path)
                if err:
                    errors.append({"location": loc, "path": path, "error": err})
                elif path not in valid:
                    valid.append(path)
            if valid:
                kept.append({"claim": claim["claim"], "cites": valid})
            else:
                errors.append({"location": loc, "path": "",
                               "error": f"uncited_claim_dropped: {claim['claim'][:120]}"})
        hyps[side][slot] = kept

    la = out.get("lookalike_ruled_out")
    if isinstance(la, dict):
        valid = []
        for path in la.get("cites") or []:
            err = _cite_error(packet, path)
            if err:
                errors.append({"location": "lookalike_ruled_out", "path": path, "error": err})
            elif path not in valid:
                valid.append(path)
        la["cites"] = valid
        if not valid and la.get("ruled_out"):
            # A lookalike cannot be "ruled out" on no evidence.
            la["ruled_out"] = False
            la["reason"] = ("[not ruled out: no valid citation] " + (la.get("reason") or "")).strip()
            errors.append({"location": "lookalike_ruled_out", "path": "",
                           "error": "uncited_claim_dropped: ruled_out reset to false"})

    checked = []
    for path in out.get("evidence_checked") or []:
        if get_leaf(packet, path) is None:
            errors.append({"location": "evidence_checked", "path": path, "error": "unknown_path"})
        elif path not in checked:
            checked.append(path)
    out["evidence_checked"] = checked
    out["citation_errors"] = errors
    return out


# =============================================================================
# [FYP-SECTION] HARD GUARDS (T4)
# =============================================================================

def missing_mandatory_evidence(packet: dict) -> list[str]:
    """Names of MANDATORY_EVIDENCE entries that are not satisfied."""
    missing = []
    for name, path, ok, _desc in MANDATORY_EVIDENCE:
        leaf = get_leaf(packet, path)
        if leaf is None or not ok(leaf):
            missing.append(name)
    return missing


def strong_rule_signals(packet: dict) -> list[str]:
    """Strong deterministic indicator labels present in the packet
    (suspicious_ip, weight 1, is excluded by STRONG_SIGNAL_LABELS).

    [FYP-TRIAGE-STEP2] Plus abused-tool floor labels from
    rule_signals.lolbas / rule_signals.masquerade: STRONG LOLBAS hits in
    categories Download / Execute / AWL Bypass / UAC Bypass / Credentials and
    every path_mismatch (masquerade). Weak (name-only) hits never count, and
    a valid signature never removes a hit (adversarial mimicry)."""
    signals = (packet or {}).get("rule_signals") or {}
    labels = [label for label, leaf in signals.items()
              if label in STRONG_SIGNAL_LABELS and isinstance(leaf, dict)
              and leaf.get("status") != "missing"]
    return sorted(set(labels) | set(abused_tool_floor_labels(packet)))


def _valid_cites(packet: dict, claims: list[dict]) -> list[str]:
    return [p for c in claims for p in (c.get("cites") or []) if is_valid_cite(packet, p)]


def _supporting_cites(assessment: dict, packet: dict, disposition: str) -> list[str]:
    """Cites that argue FOR the given disposition.

    true_positive -> malicious.evidence_for + benign.evidence_against
    false_positive / benign_expected -> benign.evidence_for +
        malicious.evidence_against + the lookalike's cites if ruled out."""
    h = assessment.get("hypotheses") or {}
    mal, ben = h.get("malicious") or {}, h.get("benign") or {}
    if disposition == "true_positive":
        return _valid_cites(packet, (mal.get("evidence_for") or []) + (ben.get("evidence_against") or []))
    if disposition in _BENIGN_SIDE:
        cites = _valid_cites(packet, (ben.get("evidence_for") or []) + (mal.get("evidence_against") or []))
        la = assessment.get("lookalike_ruled_out")
        if isinstance(la, dict) and la.get("ruled_out"):
            cites += [p for p in la.get("cites") or [] if is_valid_cite(packet, p)]
        return cites
    return []


def _primary_support(assessment: dict, packet: dict, disposition: str) -> list[str]:
    """Cites on the proposed disposition's OWN hypothesis (rule e):
    malicious.evidence_for for true_positive, benign.evidence_for for
    false_positive / benign_expected."""
    side = "malicious" if disposition == "true_positive" else "benign"
    claims = ((assessment.get("hypotheses") or {}).get(side) or {}).get("evidence_for") or []
    return _valid_cites(packet, claims)


def apply_guards(assessment: dict, packet: dict) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Apply guard rules a..e in order.

    Starts from ``proposed_disposition``; any rule may move the disposition
    to "needs_info" (never the other way). Every override is appended to
    ``guard_actions`` as {rule, from, to, reason}. Returns a new dict."""
    out = copy.deepcopy(assessment)
    actions: list[dict] = list(out.get("guard_actions") or [])
    proposal_error = out.pop("_proposal_error", None)
    disposition = out.get("proposed_disposition") or NEEDS_INFO
    if proposal_error:
        actions.append({"rule": "schema_proposed_disposition", "from": proposal_error,
                        "to": NEEDS_INFO,
                        "reason": "model did not propose a valid disposition"})

    def override(rule: str, reason: str) -> None:
        nonlocal disposition
        actions.append({"rule": rule, "from": disposition, "to": NEEDS_INFO, "reason": reason})
        disposition = NEEDS_INFO

    # a) missing mandatory evidence
    if disposition in _BENIGN_SIDE:
        missing = missing_mandatory_evidence(packet)
        if missing:
            override("a_missing_mandatory_evidence",
                     f"mandatory evidence missing ({', '.join(missing)}): missing = "
                     "unknown, not safe, so the alert cannot be closed as benign")

    # b) abused-tool / strong-signal floor
    if disposition in _BENIGN_SIDE:
        strong = strong_rule_signals(packet)
        support = _supporting_cites(out, packet, disposition)
        if strong and not any(p.startswith("context.") for p in support):
            override("b_strong_signal_floor",
                     f"strong rule signal(s) {', '.join(strong)} present and no "
                     "non-missing context.* evidence was cited to explain them")

    # c) benign_expected requires context evidence
    if disposition == "benign_expected":
        support = _supporting_cites(out, packet, disposition)
        if not any(p.startswith("context.") for p in support):
            override("c_benign_expected_requires_context",
                     "benign_expected needs >= 1 valid context.* citation "
                     "(confirmed-benign requires evidence; assumed-benign is not allowed)")

    # d) false_positive requires a data/detection-quality cite
    if disposition == "false_positive":
        support = _supporting_cites(out, packet, disposition)
        if not any(p.startswith(("data_quality.", "detection.")) for p in support):
            override("d_false_positive_requires_rule_or_data_evidence",
                     "false_positive means the rule or data is wrong; that needs >= 1 "
                     "valid data_quality.* or detection.* citation")

    # e) the proposed disposition's own hypothesis must be cited
    if disposition != NEEDS_INFO and not _primary_support(out, packet, disposition):
        side = "malicious" if disposition == "true_positive" else "benign"
        override("e_uncited_supporting_hypothesis",
                 f"hypotheses.{side}.evidence_for has no claim with a valid citation")

    out["disposition"] = disposition
    out["guard_actions"] = actions
    return out


# =============================================================================
# [FYP-SECTION] DETERMINISTIC UNCERTAINTY
# =============================================================================

def evidence_completeness(packet: dict) -> float:
    """Share of MANDATORY + CORE evidence paths whose status is "measured"."""
    paths = [p for _n, p, _ok, _d in MANDATORY_EVIDENCE] + list(CORE_EVIDENCE)
    measured = sum(1 for p in paths if (get_leaf(packet, p) or {}).get("status") == "measured")
    return measured / len(paths)


def compute_uncertainty(packet: dict, guard_actions: list[dict] | None = None) -> str:
    """[FYP-FUNCTION] [FYP-EVALUATOR] "low" | "medium" | "high", from evidence
    completeness and the number of guard overrides only.

      completeness >= 0.80 -> low, >= 0.55 -> medium, else high;
      any missing mandatory evidence -> high;
      each guard override raises the level by one step (capped at high).

    No model-reported confidence is ever read: raw, uncalibrated model
    confidence has been shown to make analysts worse."""
    levels = ("low", "medium", "high")
    c = evidence_completeness(packet)
    if missing_mandatory_evidence(packet):
        idx = 2
    elif c >= UNCERTAINTY_LOW_MIN_COMPLETENESS:
        idx = 0
    elif c >= UNCERTAINTY_MEDIUM_MIN_COMPLETENESS:
        idx = 1
    else:
        idx = 2
    idx = min(2, idx + len(guard_actions or []))
    return levels[idx]


# =============================================================================
# [FYP-SECTION] PIPELINE
# =============================================================================

def build_assessment(raw: dict | None, packet: dict) -> dict:
    """[FYP-FUNCTION] normalize -> verify_citations -> apply_guards ->
    compute_uncertainty -> validate. Returns a JSON-safe dict matching
    triage_result.TriageAssessment (guard_actions use the key "from")."""
    assessment = normalize_assessment(raw)
    assessment = verify_citations(assessment, packet)
    assessment = apply_guards(assessment, packet)
    assessment["uncertainty"] = compute_uncertainty(packet, assessment["guard_actions"])
    return TriageAssessment.model_validate(assessment).model_dump(mode="json", by_alias=True)


__all__ = [
    "MANDATORY_EVIDENCE",
    "CORE_EVIDENCE",
    "UNCERTAINTY_LOW_MIN_COMPLETENESS",
    "UNCERTAINTY_MEDIUM_MIN_COMPLETENESS",
    "normalize_assessment",
    "is_valid_cite",
    "verify_citations",
    "missing_mandatory_evidence",
    "strong_rule_signals",
    "apply_guards",
    "evidence_completeness",
    "compute_uncertainty",
    "build_assessment",
]
