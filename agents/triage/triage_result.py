"""Canonical, dependency-light Pydantic contract for the Triage Agent's
real return-boundary output.

This module intentionally imports nothing from `soc_triage_agent.py` (or the
heavier machinery it pulls in transitively at import time -- `langchain_core`,
`langchain_openai`, the OpenAI client) so that a future consumer of this
contract (workflow orchestration, Reporting, tests) can parse and validate a
persisted Triage result without loading the Triage Agent's LLM machinery.
Only `pydantic` and `typing` are required.

Phase 1 scope (Canonical Triage Result contract migration): this module
models ONLY the real, current return value of
`agents.triage.soc_triage_agent.TriageAgent.triage()` -- the Triage
stage-of-record result. It deliberately does NOT model:
  - `deep_triage_supplement()`'s output (a wholly different shape used only
    by the Investigation feedback loop's gap-filling deep-dive, never merged
    back into the persisted triage_result);
  - `alert_triage.py::analyze_alert()`/`normalize_to_incident()`'s output
    (a separate, rule-based, pre-ingest verdict embedded under
    `incident["_analyze_alert"]`/`["_extracted_iocs"]` for non-NetWitness
    alert normalisation -- computed but never read by this pipeline's
    Triage/Investigation/Reporting stages);
  - `workflow/engine.py::handoff_to_reporting()`'s hand-flattened
    `triage_doc` (a downstream RESHAPING of this contract's fields --
    `classification` renamed to `severity`, etc. -- for Reporting's
    filesystem handoff; a later-phase concern, not this stage's own output).

Field-for-field, this module mirrors exactly what `TriageAgent.triage()`
already produces -- nothing added, nothing renamed, nothing invented. In
particular, Triage does NOT produce `severity`, `confidence`,
`likely_scenario`, a structured `iocs`/`evidence`/`timeline` list,
`missing_evidence`/`missing_fields`, `containment_action`, or a structured
`mitre_mappings` list (only scalar `mitre_tactic`/`mitre_technique`) -- so
none of those appear here. `classification` IS a real, Triage-owned field.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class TriageRiskRating(BaseModel):
    """Mirrors TriageAgent.triage()'s `ticket["risk_rating"]` dict exactly
    (soc_triage_agent.py:1434-1440). All five sub-fields are always strings
    -- each is populated via `risk_data.get(...) or "—"` (or, for
    `rationale`, `or ""`), so none of them are ever absent or non-string on
    a successful triage run."""

    likelihood_initiation: str
    likelihood_occurrence: str
    likelihood_adverse_impact: str
    overall_risk: str
    rationale: str


class TriageMetakeysPayload(BaseModel):
    """Mirrors TriageAgent.triage()'s `metakeys_payload` dict exactly
    (soc_triage_agent.py:1412-1423)."""

    incident_id: str
    incident_title: str
    timestamp: str
    matched_metakeys: list[str]
    metakey_values: dict[str, Any]
    ioc_summary: str
    risk_level: str
    classification: str
    mitre_tactic: str
    mitre_technique: str


class TriageTicket(BaseModel):
    """Mirrors TriageAgent.triage()'s `ticket` dict exactly
    (soc_triage_agent.py:1427-1452).

    Note `classification` here is `classification.upper()` (e.g. "HIGH"),
    a different casing from `TriageMetakeysPayload.classification` (the
    lowercase `risk_level`-derived value, e.g. "high") -- both are real,
    independently-set values in the live producer, not a bug this contract
    should paper over."""

    unc: str
    incident_id: str
    title: str
    incident_time: str
    created_at: str
    classification: str
    risk_rating: TriageRiskRating
    incident_category: str
    mitre_tactic: str
    mitre_technique: str
    initial_response_time: str
    summary: str
    recommended_actions: list[str]
    matched_ioc_count: int
    metakeys: list[str]


class TriageAgentSuccessOutput(BaseModel):
    """Canonical shape of a successful (non-error) `TriageAgent.triage()`
    return value -- covers both a freshly-computed run (`result`,
    soc_triage_agent.py:1456-1462) and a cache-served run (`cached`,
    soc_triage_agent.py:1343-1348), which share the identical field set
    plus one additive marker (see `cached` below).
    """

    metakeys_payload: TriageMetakeysPayload
    ticket: TriageTicket
    trace: list[dict[str, Any]]
    used_parsed_context: bool
    error: None = None
    # Added by triage() itself -- `cached["cached"] = True` -- only on the
    # cache-hit return path, immediately before return
    # (soc_triage_agent.py:1347-1348). This is provenance/serving metadata
    # about HOW the result was produced (fresh vs. memoized), not itself
    # Triage-domain content, but it originates at the exact same return
    # boundary this model validates, so it is modelled as an additive,
    # optional field here rather than stripped before validation -- a
    # previously-valid cache hit must keep validating. Absent (defaults to
    # False) on a freshly-computed run.
    cached: bool = False


class TriageAgentErrorOutput(BaseModel):
    """Canonical shape of `TriageAgent.triage()`'s exception-branch return
    (soc_triage_agent.py:1403-1407).

    Deliberately NOT the same shape as `TriageAgentSuccessOutput` with
    fields loosened to Optional: the real error branch returns genuinely
    empty `{}` dicts for `metakeys_payload`/`ticket` (no classification/
    ticket was ever produced), and -- unlike the success path -- never sets
    `used_parsed_context` at all, so that field has no place on this model.
    `trace` may be non-empty here: an exception raised partway through
    Phase 2 or 3 still returns whatever steps Phase 1/2 already appended."""

    error: str
    metakeys_payload: dict[str, Any] = Field(default_factory=dict)
    ticket: dict[str, Any] = Field(default_factory=dict)
    trace: list[dict[str, Any]] = Field(default_factory=list)


def validate_triage_agent_output(
    raw: dict[str, Any],
) -> TriageAgentSuccessOutput | TriageAgentErrorOutput:
    """Validate a raw `TriageAgent.triage()` return dict against whichever
    of the two real output shapes it actually matches.

    Uses the field that already exists on both real shapes -- `error`
    (`None` on success, a non-empty string on failure) -- as the
    discriminator, rather than inventing a new status/type tag that the
    live producer doesn't itself set."""
    if isinstance(raw, dict) and raw.get("error") is not None:
        return TriageAgentErrorOutput.model_validate(raw)
    return TriageAgentSuccessOutput.model_validate(raw)


__all__ = [
    "TriageRiskRating",
    "TriageMetakeysPayload",
    "TriageTicket",
    "TriageAgentSuccessOutput",
    "TriageAgentErrorOutput",
    "validate_triage_agent_output",
]
