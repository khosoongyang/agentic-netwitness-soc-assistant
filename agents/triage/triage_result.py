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

[FYP-TRIAGE-STEP1] Deliberate, additive extension (Triage upgrade Step 1):
  - `evidence_packet` (top level): the code-built, citable evidence record
    (agents/triage/evidence_packet.py). Every leaf is
    {value, status: measured|inferred|missing, source}.
  - `assessment` (top level): the disposition -- true_positive /
    false_positive / benign_expected / needs_info -- which is ORTHOGONAL to
    the unchanged `classification` severity, plus the competing hypotheses,
    lookalike, citation errors and Python guard overrides behind it.
  - `ticket.disposition` / `ticket.uncertainty`: copies for the UI/exports.
Nothing existing was renamed or removed; `extra="forbid"` is kept on every
model, including the new ones. `uncertainty` is computed deterministically
from evidence completeness (agents/triage/guards.py), never a model-reported
number -- so the long-standing "no invented confidence" rule still holds.

[FYP-TRIAGE-STEP2] Additive extension (Triage upgrade Step 2):
  - `evidence_packet.raw_alerts` (EvidenceRawAlerts): fetch status + a
    deterministic digest of ALL raw alerts/events (agents/triage/raw_alerts.py).
  - `evidence_packet.rule_signals.lolbas`: abused-tool (LOLBAS) enrichment
    (agents/triage/lolbas.py) -- an ordinary EvidenceLeaf under the existing
    keyed rule_signals map, so no new model was needed for it.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# [FYP-SECTION] Step 1 additions: evidence packet + assessment models
# =============================================================================

Disposition = Literal["true_positive", "false_positive", "benign_expected", "needs_info"]
Uncertainty = Literal["low", "medium", "high"]
EvidenceStatus = Literal["measured", "inferred", "missing"]

DISPOSITIONS: tuple[str, ...] = ("true_positive", "false_positive", "benign_expected", "needs_info")
UNCERTAINTY_LEVELS: tuple[str, ...] = ("low", "medium", "high")


class EvidenceLeaf(BaseModel):
    """One citable fact in the evidence packet. `status` says how it is
    known: measured (observed), inferred (derived by code) or missing
    (unknown -- never to be read as "safe")."""

    model_config = ConfigDict(extra="forbid")

    value: Any = None
    status: EvidenceStatus
    source: str


class EvidenceDetection(BaseModel):
    """What fired: NetWitness incident-level detection facts."""

    model_config = ConfigDict(extra="forbid")

    createdBy: EvidenceLeaf
    ruleId: EvidenceLeaf
    created: EvidenceLeaf
    sources: EvidenceLeaf
    riskScore: EvidenceLeaf
    priority: EvidenceLeaf
    alertCount: EvidenceLeaf
    eventCount: EvidenceLeaf
    tactics: EvidenceLeaf
    techniques: EvidenceLeaf


class EvidenceEntity(BaseModel):
    """The resolved primary entity and its kind (ip_internal/ip_external/
    hostname/user/file/unresolved)."""

    model_config = ConfigDict(extra="forbid")

    value: EvidenceLeaf
    kind: EvidenceLeaf


class EvidenceDataQuality(BaseModel):
    """Parsing-stage data quality, copied from parsed_context."""

    model_config = ConfigDict(extra="forbid")

    parser_status: EvidenceLeaf
    parser_confidence: EvidenceLeaf
    missing_fields: EvidenceLeaf
    data_quality: EvidenceLeaf


class EvidenceBaseline(BaseModel):
    """The measured historical prior (agents/triage/baseline.py)."""

    model_config = ConfigDict(extra="forbid")

    status: EvidenceLeaf
    reason: EvidenceLeaf
    same_source_entity_7d: EvidenceLeaf
    same_source_entity_30d: EvidenceLeaf
    same_source_entity_90d: EvidenceLeaf
    same_source_entity_all_time: EvidenceLeaf
    same_source_entity_annualized: EvidenceLeaf
    same_entity_7d: EvidenceLeaf
    same_entity_30d: EvidenceLeaf
    same_entity_90d: EvidenceLeaf
    same_entity_all_time: EvidenceLeaf
    first_seen: EvidenceLeaf
    last_seen: EvidenceLeaf
    is_first_occurrence: EvidenceLeaf
    is_known_noisy: EvidenceLeaf
    coverage_start: EvidenceLeaf
    coverage_end: EvidenceLeaf


class EvidenceContext(BaseModel):
    """Business context. Always status "missing" in Step 1 (placeholders
    filled by later steps) -- so benign_expected is unreachable by design.

    [FYP-TRIAGE-STEP3] analyst_note (a note attached to a Triage re-run,
    "measured", source "analyst <name> @ <iso time>") and suppression_match
    (an approved, unexpired, scope-matching suppression proposal) are the
    two human-attested context leaves; both are "missing" unless present.
    Required, like raw_alerts in Step 2: a packet without them cannot be
    told apart from one where they were never looked up."""

    model_config = ConfigDict(extra="forbid")

    asset_context: EvidenceLeaf
    change_context: EvidenceLeaf
    confirmed_benign_history: EvidenceLeaf
    analyst_note: EvidenceLeaf
    suppression_match: EvidenceLeaf


class EvidenceRawAlerts(BaseModel):
    """[FYP-TRIAGE-STEP2] Raw-alert evidence (agents/triage/raw_alerts.py):
    "pull the raw log, never trust the alert summary alone". Fetch status
    (from ingestion's data_availability) plus a deterministic digest over
    ALL alerts/events, every list capped with an explicit truncation note.
    `available` is status "missing" unless the fetch succeeded with > 0
    alerts -- missing raw evidence is unknown, not safe."""

    model_config = ConfigDict(extra="forbid")

    incident_source: EvidenceLeaf
    fetch_succeeded: EvidenceLeaf
    alerts_count: EvidenceLeaf
    declared_alert_count: EvidenceLeaf
    coverage_ratio: EvidenceLeaf
    available: EvidenceLeaf
    events_digested: EvidenceLeaf
    alert_names: EvidenceLeaf
    signatures: EvidenceLeaf
    processes: EvidenceLeaf
    command_lines: EvidenceLeaf
    hashes: EvidenceLeaf
    signers: EvidenceLeaf
    users: EvidenceLeaf
    hosts: EvidenceLeaf
    ips: EvidenceLeaf
    mitre: EvidenceLeaf
    threat_desc: EvidenceLeaf
    context_tags: EvidenceLeaf
    file_context_tags: EvidenceLeaf
    behaviors: EvidenceLeaf


class EvidencePacket(BaseModel):
    """[FYP-EVALUATOR] The whole evidence packet. `rule_signals` is keyed by
    indicator label (plus `scan_summary`, and from Step 2 `lolbas`) because
    the set of deterministic hits varies per incident; every other section
    has a fixed field set."""

    model_config = ConfigDict(extra="forbid")

    detection: EvidenceDetection
    entity: EvidenceEntity
    data_quality: EvidenceDataQuality
    baseline: EvidenceBaseline
    # [FYP-TRIAGE-STEP2] required: a packet without raw-alert status cannot
    # be told apart from one whose alerts were simply never looked at.
    raw_alerts: EvidenceRawAlerts
    rule_signals: dict[str, EvidenceLeaf] = Field(default_factory=dict)
    context: EvidenceContext


class TriageClaim(BaseModel):
    """One piece of reasoning with the evidence-packet dot-paths it rests
    on. After agents/triage/guards.verify_citations() every surviving claim
    has >= 1 valid cite (existing path, status != missing)."""

    model_config = ConfigDict(extra="forbid")

    claim: str
    cites: list[str]


class TriageHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_for: list[TriageClaim] = Field(default_factory=list)
    evidence_against: list[TriageClaim] = Field(default_factory=list)


class TriageHypotheses(BaseModel):
    """The two competing explanations: malicious activity vs normal
    operations."""

    model_config = ConfigDict(extra="forbid")

    malicious: TriageHypothesis = Field(default_factory=TriageHypothesis)
    benign: TriageHypothesis = Field(default_factory=TriageHypothesis)


class TriageLookalike(BaseModel):
    """The most plausible malicious explanation and whether the cited
    evidence rules it out."""

    model_config = ConfigDict(extra="forbid")

    lookalike: str
    ruled_out: bool
    reason: str
    cites: list[str]


class TriageCitationError(BaseModel):
    """A citation removed by verify_citations(): `error` is
    "unknown_path" or "missing_status" (or "uncited_claim_dropped")."""

    model_config = ConfigDict(extra="forbid")

    location: str
    path: str
    error: str


class TriageGuardAction(BaseModel):
    """One Python-guard override of the model's disposition. Serialized
    with the key "from" (a Python keyword, hence the `from_` alias)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    rule: str
    from_: str = Field(alias="from")
    to: str
    reason: str


class TriageAssessment(BaseModel):
    """[FYP-EVALUATOR] Disposition + the reasoning trail behind it.

    `proposed_disposition` is what the model proposed; `disposition` is what
    survived citation verification and the guards in agents/triage/guards.py
    (every change is listed in `guard_actions`)."""

    model_config = ConfigDict(extra="forbid")

    disposition: Disposition
    proposed_disposition: Disposition
    uncertainty: Uncertainty
    hypotheses: TriageHypotheses
    lookalike_ruled_out: Optional[TriageLookalike] = None
    fn_cost_if_wrong: str
    evidence_checked: list[str]
    citation_errors: list[TriageCitationError]
    guard_actions: list[TriageGuardAction]


class TriageRiskRating(BaseModel):
    """Mirrors TriageAgent.triage()'s `ticket["risk_rating"]` dict exactly
    (soc_triage_agent.py:1434-1440). All five sub-fields are always strings
    -- each is populated via `risk_data.get(...) or "—"` (or, for
    `rationale`, `or ""`), so none of them are ever absent or non-string on
    a successful triage run.

    `extra="forbid"`: an unrecognised key here (e.g. a `confidence` score
    the LLM prompt starts emitting) must fail loudly rather than be
    silently dropped on re-serialization -- silent dropping would hide
    producer/schema drift from whoever reads the validated result."""

    model_config = ConfigDict(extra="forbid")

    likelihood_initiation: str
    likelihood_occurrence: str
    likelihood_adverse_impact: str
    overall_risk: str
    rationale: str


class TriageMetakeysPayload(BaseModel):
    """Mirrors TriageAgent.triage()'s `metakeys_payload` dict exactly
    (soc_triage_agent.py:1412-1423). `extra="forbid"` -- see
    `TriageRiskRating` for rationale."""

    model_config = ConfigDict(extra="forbid")

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
    should paper over.

    `extra="forbid"` -- see `TriageRiskRating` for rationale."""

    model_config = ConfigDict(extra="forbid")

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
    # [FYP-TRIAGE-STEP1] Copies of assessment.disposition/.uncertainty for
    # the UI and exports. Orthogonal to `classification` (severity).
    disposition: Disposition
    uncertainty: Uncertainty


class TriageAgentSuccessOutput(BaseModel):
    """Canonical shape of a successful (non-error) `TriageAgent.triage()`
    return value -- covers both a freshly-computed run (`result`,
    soc_triage_agent.py:1456-1462) and a cache-served run (`cached`,
    soc_triage_agent.py:1343-1348), which share the identical field set
    plus one additive marker (see `cached` below).

    `extra="forbid"` at the top level too -- see `TriageRiskRating` for
    rationale. Note this does NOT cover `mock_triage_result()`
    (workflow/engine.py) -- that offline substitute is a *different*,
    deliberately-mocked producer outside this contract's stated scope (see
    module docstring), and its own `"mock": True` marker key is stripped
    before validation at its one call site rather than modelled here."""

    model_config = ConfigDict(extra="forbid")

    metakeys_payload: TriageMetakeysPayload
    ticket: TriageTicket
    trace: list[dict[str, Any]]
    used_parsed_context: bool
    # [FYP-TRIAGE-STEP1] Required on every new result. A cache row written
    # before Step 1 lacks both, fails validation, and is therefore treated
    # as an ordinary cache miss by TriageAgent.triage() (it is also keyed by
    # a new fingerprint -- see TRIAGE_PROMPT_VERSION).
    evidence_packet: EvidencePacket
    assessment: TriageAssessment
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
    #
    # IMPORTANT: pre-Phase-1, a freshly-computed run's returned dict never
    # contained this key at all (only `cached["cached"] = True` on the
    # cache-hit path ever set it) -- so `model_dump()` must NOT be called
    # directly on this model when re-serializing at the external return
    # boundary, since that always emits `"cached": false` for a fresh run
    # and would silently change the previously-byte-for-byte-identical
    # external shape. Use `dump_triage_agent_output()` below instead, which
    # omits this key exactly when it is `False`.
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
    Phase 2 or 3 still returns whatever steps Phase 1/2 already appended.

    `extra="forbid"`: the real error branch (soc_triage_agent.py:1406-1409)
    always constructs exactly these four keys -- no other call site feeds a
    dict with diagnostic extras into `validate_triage_agent_output()` --
    so there is no historical/error-path compatibility evidence requiring
    a looser policy here. Should a genuine need for extra diagnostic
    fields on the error path emerge later, loosen this deliberately then,
    with that evidence recorded here."""

    model_config = ConfigDict(extra="forbid")

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


def dump_triage_agent_output(
    output: TriageAgentSuccessOutput | TriageAgentErrorOutput,
) -> dict[str, Any]:
    """Serialize a validated Triage output back to the exact plain-dict
    shape `TriageAgent.triage()` returned before this contract existed.

    `model_dump(mode="json")` alone is NOT byte-for-byte safe here: it
    always emits every field on the model, including `cached: false` for
    `TriageAgentSuccessOutput`, but pre-Phase-1 a freshly-computed run's
    dict never had a `"cached"` key at all -- only a cache-hit ever set it
    (to `True`). This helper omits `"cached"` exactly when it is `False`,
    so a fresh result's external shape is unchanged and a cache-hit's
    `"cached": true` is preserved exactly as before.

    `by_alias=True` only affects TriageGuardAction.from_ (serialized as
    "from"); no other model declares an alias."""
    dumped = output.model_dump(mode="json", by_alias=True)
    if isinstance(output, TriageAgentSuccessOutput) and not output.cached:
        dumped.pop("cached", None)
    return dumped


__all__ = [
    "Disposition",
    "Uncertainty",
    "EvidenceStatus",
    "DISPOSITIONS",
    "UNCERTAINTY_LEVELS",
    "EvidenceLeaf",
    "EvidenceDetection",
    "EvidenceEntity",
    "EvidenceDataQuality",
    "EvidenceBaseline",
    "EvidenceContext",
    "EvidenceRawAlerts",
    "EvidencePacket",
    "TriageClaim",
    "TriageHypothesis",
    "TriageHypotheses",
    "TriageLookalike",
    "TriageCitationError",
    "TriageGuardAction",
    "TriageAssessment",
    "TriageRiskRating",
    "TriageMetakeysPayload",
    "TriageTicket",
    "TriageAgentSuccessOutput",
    "TriageAgentErrorOutput",
    "validate_triage_agent_output",
    "dump_triage_agent_output",
]
