"""Canonical, dependency-light Pydantic contract for the Threat Intelligence
Enrichment stage's real return-boundary output.

This module intentionally imports nothing from `threat_intel.py` (or the
heavier machinery it pulls in transitively at import time -- `requests`,
`python-dotenv`) so that a future consumer of this contract (workflow
orchestration, Reporting, tests) can parse and validate a persisted Threat
Intelligence result without loading the provider-lookup machinery. Only
`pydantic` and `typing` are required.

Phase 2 scope (canonical Threat Intelligence Result contract migration):
this module models ONLY the real, current return value of
`agents.threat_intelligence.threat_intel.run_threat_intel_for_dashboard()`
-- the Threat Intelligence stage-of-record result -- field-for-field,
nothing added, nothing renamed, nothing invented. In particular:

  - `incident_id`, `run_id`, `stage`, and `generated_at` are NOT modelled
    here. Those are added by `workflow/engine.py::run_threat_intel()` when
    it re-keys this function's return value onto the workflow's own
    stage-result envelope for SQLite/Reporting/Investigation handoff (the
    same way `ai_summary`/`ai_summary_model`/`ai_summary_generated_at` are
    added later still, by `workflow/stage_summaries.py`) -- workflow-owned
    wrapping applied AFTER this stage's own producer returns, not this
    stage's own output.
  - There is exactly one real result shape. Unlike Triage's `triage()`,
    `run_threat_intel_for_dashboard()` never raises and has no separate
    exception-branch return shape -- every provider failure/missing-key/
    no-IOC case degrades in place into this same shape (`status` becomes
    `"completed_with_warnings"`, individual provider records carry their
    own `"skipped"`/`"error"`/`"not_found"` status, and `warnings` is
    populated) rather than the stage returning something else entirely.
    So there is no discriminated success/error union to model here, and no
    `"failed"`/`"error"` value of the stage-level `status` field exists in
    real executable behaviour -- workflow-level stage failure (e.g. an
    identity mismatch via `ThreatIntelValidationError`, or a lease/worker
    fault) is represented in workflow state (`threat_intel_status`), a
    wholly separate concept from this payload's own `status` field.
  - `enrichment_risk_score`/`enrichment_risk_level`/`enrichment_risk_reasons`
    are Threat-Intelligence-owned and intentionally distinct from Parsing's
    raw/source `risk_score`, Triage's `risk_rating`, and Investigation's
    `severity` -- this module does not model those other stages' fields.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class ThreatIntelIOCs(BaseModel):
    """Mirrors `extract_iocs()`'s return dict exactly (threat_intel.py:319-
    380). All seven keys are unconditionally present on every call --
    `possible_file_name`/`file_hash` may individually be `None` (sourced
    from `alert.get(...)`, which may find nothing), but the keys themselves
    are never absent, and none of the other five fields are ever `None`
    (`ip_indicators`/`domain_indicators`/`url_indicators` default to `[]`,
    `powershell_analysis` to `{}`, `powershell_enrichment_note` is always a
    non-empty string from one of two fixed sentinels).

    `extra="forbid"`: this exact key set is constructed by one literal
    `return {...}` with no conditional key addition/omission -- there is no
    historical/compatibility evidence requiring a looser policy."""

    model_config = ConfigDict(extra="forbid")

    possible_file_name: str | None
    file_hash: str | None
    ip_indicators: list[str]
    domain_indicators: list[str]
    url_indicators: list[str]
    powershell_analysis: dict[str, Any]
    powershell_enrichment_note: str


class VirusTotalResults(BaseModel):
    """Mirrors `enrich_alert()`'s `threat_intel["virustotal"]` dict exactly
    (threat_intel.py:883-887, 897-925). `file_hash` is initialised to
    `None` in the dict literal but is unconditionally overwritten by either
    branch of the `is_available(file_hash)` check immediately after (a real
    lookup result if a hash was available, else an explicit
    `{"status": "skipped", ...}` dict) before `enrich_alert()` ever
    returns -- so by the real return boundary it is always a dict, never
    `None`. `ip_results`/`domain_results` start as `[]` and are appended to
    once per queried IP/domain -- each entry is a per-provider lookup
    result whose own field set intentionally varies by `status`
    (`completed`/`skipped`/`error`), so those entries are modelled as
    `dict[str, Any]` rather than a further nested strict model (see module
    docstring and `ThreatIntelProviderBundle` below for the stable-
    container / flexible-payload split this follows).

    `extra="forbid"`: this container's own key set (`file_hash`/
    `ip_results`/`domain_results`) is fixed by one literal, never
    conditionally extended."""

    model_config = ConfigDict(extra="forbid")

    file_hash: dict[str, Any]
    ip_results: list[dict[str, Any]]
    domain_results: list[dict[str, Any]]


class AbuseIPDBResults(BaseModel):
    """Mirrors `enrich_alert()`'s `threat_intel["abuseipdb"]` dict exactly
    (threat_intel.py:888-890, 914-916). AbuseIPDB is only ever queried per
    IP indicator, so `ip_results` is its one real field."""

    model_config = ConfigDict(extra="forbid")

    ip_results: list[dict[str, Any]]


class AlienVaultOTXResults(BaseModel):
    """Mirrors `enrich_alert()`'s `threat_intel["alienvault_otx"]` dict
    exactly (threat_intel.py:891-893, 900-902, 918-920, 927-929).
    `otx_results` mixes file/IP/domain lookups in one list (each entry
    carries its own `indicator_type`), matching the real producer -- there
    is no separate per-indicator-type container to model."""

    model_config = ConfigDict(extra="forbid")

    otx_results: list[dict[str, Any]]


class ThreatIntelProviderBundle(BaseModel):
    """Mirrors `enrich_alert()`'s `threat_intel` dict exactly
    (threat_intel.py:881-895). Strictly models the known top-level provider
    keys (`iocs`/`virustotal`/`abuseipdb`/`alienvault_otx`/`notes`) --
    always present, never conditionally added or removed -- while each
    provider's own per-lookup result bodies remain `dict[str, Any]`, since
    VirusTotal/AbuseIPDB/AlienVault OTX intentionally return different
    field sets from each other (and across `status` values). This is the
    "stable container, flexible payload" split called for by the Threat
    Intelligence contract audit: strict enough to catch a future producer
    dropping/renaming one of these five keys, loose enough not to force
    three brittle provider-specific Pydantic classes onto data that
    genuinely varies by provider and by call outcome.

    `extra="forbid"`: matches `enrich_alert()`'s one literal `threat_intel
    = {...}` dict -- exactly these five keys, always."""

    model_config = ConfigDict(extra="forbid")

    iocs: ThreatIntelIOCs
    virustotal: VirusTotalResults
    abuseipdb: AbuseIPDBResults
    alienvault_otx: AlienVaultOTXResults
    notes: list[str]


class ThreatIntelResult(BaseModel):
    """Canonical shape of `run_threat_intel_for_dashboard()`'s return value
    (threat_intel.py:1250-1277) -- the Threat Intelligence stage's one real
    result shape. Every field below is unconditionally set on every call
    (success, `completed_with_warnings`, no-IOC, every provider
    skipped/missing-key, or any individual provider error) -- none of them
    are ever absent, so none are `Optional` here.

    `extra="forbid"`: an unrecognised key here (e.g. a future producer
    change adding a new top-level field) must fail loudly at the point
    `validate_threat_intel_result()` is called rather than be silently
    dropped on re-serialization -- silent dropping would hide producer
    schema drift from whoever reads the validated result, which is exactly
    the class of bug the Threat Intelligence contract audit was run to
    find.

    Deliberately NOT modelled here (see module docstring):
    `incident_id`/`run_id`/`stage`/`generated_at` (added by
    `workflow/engine.py::run_threat_intel()`'s re-keying, not by this
    function), and `ai_summary`/`ai_summary_model`/
    `ai_summary_generated_at` (added later still by
    `workflow/stage_summaries.py`) -- both are workflow-owned augmentation
    applied after this stage's own producer returns."""

    model_config = ConfigDict(extra="forbid")

    agent: str
    agent_source: str
    status: Literal["completed", "completed_with_warnings"]
    current_stage: str
    created_at: str
    summary: str
    enrichment_risk_score: int
    enrichment_risk_level: Literal["Low", "Medium", "High"]
    enrichment_risk_reasons: list[str]
    threat_intelligence: ThreatIntelProviderBundle
    notes: list[str]
    warnings: list[str]
    enriched_alert: dict[str, Any]
    output_files: dict[str, str]
    export_status: dict[str, str]
    recommended_next_action: str


def validate_threat_intel_result(raw: dict[str, Any]) -> ThreatIntelResult:
    """Validate a raw `run_threat_intel_for_dashboard()` return dict against
    the one real Threat Intelligence result shape.

    There is no discriminated success/error union to pick between here --
    unlike Triage's `triage()`, this producer never raises and has no
    separate exception-branch return shape (see module docstring)."""
    return ThreatIntelResult.model_validate(raw)


def dump_threat_intel_result(result: ThreatIntelResult) -> dict[str, Any]:
    """Serialize a validated Threat Intelligence result back to the exact
    plain-dict shape `run_threat_intel_for_dashboard()` returned before
    this contract existed.

    Every field on `ThreatIntelResult` is required (no defaults), so --
    unlike Triage's `cached` field -- `model_dump(mode="json")` alone is
    already byte-for-byte safe here: it emits exactly the keys that were
    present on the validated input, nothing more."""
    return result.model_dump(mode="json")


__all__ = [
    "ThreatIntelIOCs",
    "VirusTotalResults",
    "AbuseIPDBResults",
    "AlienVaultOTXResults",
    "ThreatIntelProviderBundle",
    "ThreatIntelResult",
    "validate_threat_intel_result",
    "dump_threat_intel_result",
]
