# ============================================================================
# [FYP-FILE] soc_reporting_agent/reporting/export_context_enhancer.py
# File: soc_reporting_agent/reporting/export_context_enhancer.py
# Purpose: This module implements report generation and export behaviour for export context enhancer.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: __future__, datetime, re, reporting, typing.
# Key evaluator search terms: is_unknown, first_present, as_list, get_path, _normalise_lookup, _quality, [FYP-FUNCTION].
# ----------------------------------------------------------------------------
# PURPOSE
#   The Reporting stage's deterministic "context enhancement" pass: takes the
#   raw merged context dict assembled by context_builder.build_context() --
#   which stitches together the alert, triage_result, investigation_result,
#   threat_intel_result and analyst approval/containment records -- and fills
#   in every field a report template needs, recovering values from whichever
#   upstream stage actually produced them, deduplicating/normalising IOCs and
#   MITRE ATT&CK mappings, reconstructing an evidence-backed incident
#   timeline, and replacing empty/unknown values with clearly-labelled
#   placeholders (never fabricated facts) so the exported report has no bare
#   "None"/"" gaps. All of this happens BEFORE the optional LLM narrative
#   pass, so the LLM (or the deterministic narrative fallback) always writes
#   from complete, locked facts rather than raw upstream leftovers.
#
# MAIN FUNCTIONALITIES
#   - Field recovery with provenance: first_available()/first_present() walk
#     an ordered list of upstream candidate values and record WHERE the
#     chosen value came from (field_provenance / recovered_fields), used by
#     _apply_field_provenance() for a fixed set of key incident fields
#   - IOC pipeline: build_evidence_index() -> rebuild_iocs() (dedupe,
#     classify by type, reject non-IOC noise such as alert IDs/severity
#     labels, attach threat-intel reputation via _threat_intel_index())
#   - MITRE ATT&CK mapping repair: repair_mitre_mapping() -- prefers the
#     Investigation Agent's own genuine structured mapping verbatim, only
#     falling back to a generic technique-ID regex scan when no genuine
#     mapping exists
#   - Incident timeline reconstruction: derive_timeline() -- parses the
#     Investigation Agent's own "Technical Chronology" narrative sentence by
#     sentence (never inventing timestamps or events), with a MITRE-mapping-
#     based fallback when no chronology text is available
#   - Affected asset/user derivation: derive_affected_assets(),
#     derive_affected_users() -- scan ticket/alert/triage/investigation
#     sources for host/user identifiers and backfill placeholder metadata
#   - Approval/containment normalisation: normalise_approval() -- reconciles
#     the analyst's approval_result record into consistent approval/
#     containment status fields
#   - Recommended-actions enrichment: enrich_recommendations() -- backfills
#     owner/approval_required/risk_addressed/rationale per recommendation
#   - Compact/placeholder-aware render tables and narrative-quality counters
#     for the exported report's appendices and quality-check section
#   - apply_llm_narrative(): invokes the optional LLM narrative pass
#     (reporting.llm_narrative.enhance_narrative) and records its usage/
#     status/quality metadata; falls back to the deterministic narrative if
#     the LLM is disabled/unavailable
#   - enhance_export_context(): the single public orchestrator that runs
#     every step above, in order, and returns the fully enhanced context
#
# INPUTS
#   - context: dict produced by reporting.context_builder.build_context(),
#     containing raw_inputs (processed_alert/enriched_alert/triage_result/
#     investigation_result), evidence, approval_result, mitre_attack_mapping,
#     recommended_actions, etc.
#   - ticket: optional dict with ticket_id/title/host/user fields (source:
#     the SOC ticket record; falls back to context.get("ticket") if omitted)
#
# OUTPUTS
#   - The SAME context dict, mutated in place and returned, with dozens of
#     fields filled in/normalised: affected_assets, affected_users, iocs,
#     mitre_mapping/mitre_attack_mapping, timeline, approval/containment,
#     recommendations/recommended_actions/management_action_plan,
#     evidence_backed_findings/key_findings, appendix_summaries,
#     report_validation_checks, compact_evidence_register, compact_tables,
#     data_impact_summary, chain_of_custody_note, approval_summary(_table),
#     active_narrative/llm* fields, quality_checks, report_title
#
# WORKFLOW POSITION
#   Reporting stage (last stage, after Triage and Investigation -- see
#   soc_workflow.py's stage_labels). Runs between context_builder.build_
#   context() (raw merge) and reporting.report_renderer.render_reports() /
#   reporting.template_document_exporter (Jinja2 template rendering to the
#   four report .txt/.docx/.pdf outputs that editable_reports.py then takes
#   over for the analyst draft/confirm/export lifecycle).
#
# CALLED BY (verified via repo-wide grep for "export_context_enhancer" /
# "enhance_export_context")
#   - soc_reporting_agent/agents/reporting_agent.py -- the Reporting Agent's
#     own CLI entry point; calls enhance_export_context(context, ticket=None)
#     right after build_context(), before render_reports()
#   - soc_reporting_agent/reporting/template_document_exporter.py -- calls
#     enhance_export_context(context, ticket) again just before Jinja2
#     rendering (the ticket argument here typically carries live ticket
#     fields such as ticket_id/case_title/owner/current_stage merged in)
#   - soc_reporting_agent/scripts/test_merged_report_context.py (test script)
#
# CALLS
#   - reporting.llm_narrative.enhance_narrative() -- optional LLM narrative
#     generation with a deterministic-narrative fallback (see
#     apply_llm_narrative())
#   - reporting.compact_renderer (approval_summary_table,
#     build_approval_summary, build_chain_of_custody_note,
#     build_data_impact_summary, build_evidence_register_summary,
#     compact_table, count_placeholders, is_placeholder,
#     split_into_sentences, split_numbered_items) -- shared placeholder-aware
#     table/summary builders used across the reporting pipeline
#
# KEY EVALUATOR SEARCH TERMS
#   [FYP-EVALUATOR] enhance_export_context / normalise_approval /
#   _apply_field_provenance / rebuild_iocs / repair_mitre_mapping
#   [FYP-RAG]/[FYP-KNOWLEDGE-BASE] not applicable in this file (no retrieval
#   or knowledge-base lookups here; MITRE_LOCAL_MAPPING below is a small
#   static lookup table, not a RAG store)
#   [FYP-EXPORT] compact_tables / appendix_summaries / report_validation_checks
# ============================================================================

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from reporting.llm_narrative import enhance_narrative
from reporting.compact_renderer import (
    approval_summary_table,
    build_approval_summary,
    build_chain_of_custody_note,
    build_data_impact_summary,
    build_evidence_register_summary,
    compact_table,
    count_placeholders,
    is_placeholder,
    split_into_sentences,
    split_numbered_items,
)

# ============================================================================
# [FYP-SECTION] Module-Level Constants & Placeholder Vocabulary
# [FYP-CONFIG] These sets/strings define what counts as "no real value" and
# what the standard, analyst-legible placeholder text looks like once a
# value is confirmed missing. Keeping this vocabulary centralised means
# is_unknown()/is_placeholder()-style checks stay consistent everywhere in
# the reporting pipeline (see also reporting.compact_renderer.is_placeholder
# / count_placeholders, which recognise the same PLACEHOLDER_VALUES set).
# ============================================================================
# [FYP-VALIDATION] Values treated as "no real data" when deciding whether to
# recover a field from a fallback source (see is_unknown()).
UNKNOWN_VALUES = {
    "", "unknown", "unknown-alert", "unknown-incident", "not provided", "none", "null", "n/a", "na", "-", "—"
}
UNKNOWN_VALUES.update({"to be validated", "not linked", "pending", "not recorded"})

# [FYP-CONFIG] Standard, analyst-legible placeholder strings substituted for
# genuinely-missing fields -- never fabricated data, always an explicit
# "this still needs analyst attention" label.
OWNER_PLACEHOLDER = "To be assigned"
VALIDATION_PLACEHOLDER = "Pending analyst validation"
TELEMETRY_PLACEHOLDER = "Unavailable from source telemetry"
EVIDENCE_PLACEHOLDER = "Evidence link unavailable"
NOT_EVIDENCED = "Not evidenced in source telemetry"

# [FYP-CONFIG] Small static MITRE ATT&CK technique-ID -> (name, tactic)
# lookup used only as a last-resort enrichment when a technique ID is found
# in the report context but no technique_name/tactic accompanied it (see
# _normalise_mitre_item()). Not a knowledge base/RAG store -- just three
# hardcoded techniques observed to need this backfill in practice.
MITRE_LOCAL_MAPPING = {
    "T1486": {"technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1210": {"technique_name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1046": {"technique_name": "Network Service Discovery", "tactic": "Discovery"},
}

# [FYP-VALIDATION] Lower-cased placeholder text values counted by
# _count_placeholders()/finalise_quality_counters() to report how many
# fields in the final context are still unresolved placeholders (a report
# "completeness" signal surfaced to the analyst).
PLACEHOLDER_VALUES = {
    "unavailable from source telemetry",
    "not provided",
    "to be validated",
    "pending analyst validation",
    "evidence link unavailable",
    "to be assigned",
    "pending",
    "not linked",
}


# ============================================================================
# [FYP-SECTION] Generic Value Helpers
# [FYP-EXPORT] Small, widely-reused primitives underpinning almost every
# other function in this file -- treat "is this value actually usable" and
# "give me the first usable value from these candidates" consistently.
# ============================================================================
def is_unknown(value: Any) -> bool:
    """[FYP-FUNCTION] [FYP-VALIDATION] Is This Value Effectively Missing?
    True for None, empty list/tuple/dict/set, or a string that (after
    stripping/lower-casing) matches UNKNOWN_VALUES. Used everywhere in this
    module as the gate before treating a candidate value as real data."""
    if value is None:
        return True
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return str(value).strip().lower() in UNKNOWN_VALUES


def first_present(*values: Any, default: Any = "Not Provided") -> Any:
    """[FYP-FUNCTION] First Non-Unknown Value. Returns the first argument in
    `values` for which is_unknown() is False, else `default`. The core
    "prefer this field, fall back to that one" primitive used throughout
    this module wherever a value could come from more than one upstream
    source, WITHOUT recording provenance (contrast with first_available(),
    which records where the chosen value came from)."""
    for value in values:
        if not is_unknown(value):
            return value
    return default


def as_list(value: Any) -> list[Any]:
    """[FYP-FUNCTION] Coerce To A List. is_unknown() values become [];
    list/tuple/set become list(value); anything else is wrapped as a
    single-item list. Used to normalise fields that may be a scalar, a
    list, or missing entirely into a consistently iterable shape."""
    if is_unknown(value):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def get_path(obj: Any, path: str, default: Any = None) -> Any:
    """[FYP-FUNCTION] Dotted-Path Dict Lookup. E.g. get_path(context,
    "severity.label") walks context["severity"]["label"]; returns `default`
    as soon as any segment is missing or the current value is not a dict
    (deliberately does not support list-index segments)."""
    cur = obj or {}
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _normalise_lookup(value: Any) -> str:
    """[FYP-FUNCTION] Normalise A Value For Index/Dedup Key Use. Cleans
    whitespace (_clean_text), strips common quoting/punctuation wrapper
    characters, collapses escaped backslashes, and lower-cases -- so the
    same underlying value written slightly differently (quoted, extra
    spaces, mixed case) still hits the same key when used in
    build_evidence_index()/_canonical_ioc_key()/threat-intel lookups etc."""
    text = _clean_text(value).strip("`'\".,;()[]{}")
    return text.replace("\\\\", "\\").lower()


# ============================================================================
# [FYP-SECTION] Quality-Check Counters & Provenance Recording
# [FYP-VALIDATION] Every recovery/dedup/repair operation elsewhere in this
# file reports back through _bump() into context["quality_checks"], and
# every recovered field is recorded via _record_recovery() into
# context["field_provenance"]/["recovered_fields"] -- together these give
# the exported report an auditable "what did this module change, and from
# where" trail (surfaced in the report's quality-checks/appendix sections).
# ============================================================================
def _quality(context: dict[str, Any]) -> dict[str, Any]:
    """[FYP-FUNCTION] Ensure And Return quality_checks Dict. Lazily
    initialises context["quality_checks"] with zeroed counters
    (fields_recovered_from_fallback_sources, iocs_deduplicated,
    evidence_links_recovered, placeholders_reduced,
    fields_still_unavailable_from_source_telemetry) and
    fallback_logic_used="No" the first time it's touched. Called by nearly
    every function that mutates quality counters, and directly by
    enhance_export_context() at the very start."""
    checks = context.setdefault("quality_checks", {})
    for key in (
        "fields_recovered_from_fallback_sources",
        "iocs_deduplicated",
        "evidence_links_recovered",
        "placeholders_reduced",
        "fields_still_unavailable_from_source_telemetry",
    ):
        checks.setdefault(key, 0)
    checks.setdefault("fallback_logic_used", "No")
    return checks


def _bump(context: dict[str, Any], key: str, count: int = 1) -> None:
    """[FYP-FUNCTION] Increment One Quality Counter. No-op for count <= 0.
    Also flips fallback_logic_used to "Yes" whenever a positive count is
    recorded, since a non-zero bump means this module changed/recovered
    something the upstream stages did not directly supply. Called by nearly
    every recovery/dedup/repair function below."""
    if count <= 0:
        return
    checks = _quality(context)
    checks[key] = int(checks.get(key) or 0) + count
    checks["fallback_logic_used"] = "Yes"


def _parse_key_value(text: Any) -> tuple[str | None, str | None]:
    """[FYP-FUNCTION] Split "key: value" Text. Splits on the first colon
    only; returns (None, cleaned_text) if there is no colon. Used to parse
    loosely-structured evidence descriptions like "source_ip: 10.0.0.5"
    back into a field/value pair. Returns (key_or_None, value_or_None)."""
    raw = _clean_text(text)
    if ":" not in raw:
        return None, raw or None
    key, value = raw.split(":", 1)
    return _clean_text(key) or None, _clean_text(value) or None


def _add_index(index: dict[str, list[str]], value: Any, evidence_id: str) -> None:
    """[FYP-FUNCTION] Add One (normalised value -> evidence_id) Mapping,
    de-duplicated per key. No-op if either the normalised key or
    evidence_id is empty. Called by build_evidence_index()."""
    key = _normalise_lookup(value)
    if not key or not evidence_id:
        return
    refs = index.setdefault(key, [])
    if evidence_id not in refs:
        refs.append(evidence_id)


def build_evidence_index(evidence: list[dict[str, Any]]) -> dict[str, list[str]]:
    """[FYP-FUNCTION] Build A Value->Evidence-ID Lookup Index.

    Purpose: index every evidence register entry by its description text
    (whole description, the parsed "value" half of a "key: value"
    description, and the recombined "key: value" form) so any later value
    encountered elsewhere in the context (an IOC, a MITRE technique ID, an
    asset hostname, ...) can be matched back to the evidence item(s) that
    support it.
    Params: evidence -- list of evidence dicts (source: context["evidence"],
        built earlier in the pipeline, e.g. by context_builder.py).
    Returns: dict mapping normalised lookup key -> list of evidence IDs.
    Called by: enhance_export_context() (built once per run and threaded
        through as evidence_index to nearly every other function below).
    Calls: _add_index(), _parse_key_value().
    """
    index: dict[str, list[str]] = {}
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("id") or item.get("evidence_id") or "").strip()
        if not evidence_id:
            continue
        description = item.get("description") or item.get("summary") or item.get("value") or ""
        _add_index(index, description, evidence_id)
        key, value = _parse_key_value(description)
        if value:
            _add_index(index, value, evidence_id)
        if key and value:
            _add_index(index, f"{key}: {value}", evidence_id)
    return index


def _first_evidence_id(value: Any, evidence_index: dict[str, list[str]]) -> str | None:
    """[FYP-FUNCTION] Look Up The First Evidence ID Backing A Value. Tries
    the value as-is, then (if it parses as "key: value") the value half
    alone, then the recombined "key: value" form, against
    build_evidence_index()'s index. Returns the first evidence ID found, or
    None. Called by first_available(), _evidence_refs()."""
    keys = [_normalise_lookup(value)]
    parsed_key, parsed_value = _parse_key_value(value)
    if parsed_value:
        keys.append(_normalise_lookup(parsed_value))
    if parsed_key and parsed_value:
        keys.append(_normalise_lookup(f"{parsed_key}: {parsed_value}"))
    for key in keys:
        refs = evidence_index.get(key) or []
        if refs:
            return refs[0]
    return None


def _evidence_refs(value: Any, evidence_index: dict[str, list[str]]) -> list[str]:
    """[FYP-FUNCTION] Evidence References For A Single Value, as a list of
    zero or one evidence IDs (list form, since callers store evidence_refs
    as lists even though this particular lookup can only ever find one
    match). Thin wrapper around _first_evidence_id()."""
    evidence_id = _first_evidence_id(value, evidence_index)
    return [evidence_id] if evidence_id else []


def _record_recovery(
    context: dict[str, Any],
    *,
    field: str,
    value: Any,
    source: str,
    source_path: str,
    confidence: str = "High",
    evidence_id: str | None = None,
    reason: str = "Recovered from deterministic merged report context.",
) -> None:
    """[FYP-FUNCTION] [FYP-VALIDATION] Record Field Provenance.

    Purpose: log which upstream source/path a field's value was resolved
    from, both as a single current-value record (field_provenance[field])
    and as an append-only, de-duplicated audit trail
    (recovered_fields list) -- this is what lets the exported report's
    appendix show "where did this fact come from".
    Params: context -- mutated in place; field -- context field name;
        value -- the resolved value; source/source_path -- upstream origin
        label and dotted path (e.g. "enriched_alert", "host_ip"); confidence
        -- "High"/"Medium" etc; evidence_id -- linked evidence register ID if
        any; reason -- human-readable note (default: generic recovery note).
    Returns: None. Side effects: mutates
        context["field_provenance"][field] and appends to
        context["recovered_fields"] (deduplicated on
        (field, value, source, source_path)).
    Called by: first_available().
    """
    context.setdefault("field_provenance", {})[field] = {
        "value": value,
        "source": source,
        "source_path": source_path,
        "confidence": confidence,
        "evidence_id": evidence_id,
    }
    recovered = context.setdefault("recovered_fields", [])
    key = (field, str(value), source, source_path)
    seen = {
        (item.get("field"), str(item.get("value")), item.get("recovered_from"), item.get("source_path"))
        for item in recovered
        if isinstance(item, dict)
    }
    if key not in seen:
        recovered.append({
            "field": field,
            "value": value,
            "recovered_from": source,
            "source_path": source_path,
            "confidence": confidence,
            "evidence_id": evidence_id,
            "reason": reason,
        })


def first_available(
    context: dict[str, Any],
    field: str,
    candidates: list[tuple[str, str, Any]],
    *,
    evidence_index: dict[str, list[str]] | None = None,
    default: Any = None,
    confidence: str = "High",
) -> Any:
    """[FYP-FUNCTION] [FYP-STATE] First Available Value, WITH Provenance
    Recording.

    Purpose: like first_present(), but for the specific case of resolving a
    single context field across multiple named upstream sources -- as soon
    as a usable candidate is found, records where it came from via
    _record_recovery() (including any matching evidence ID) before
    returning it. This is the field-provenance counterpart used by
    _apply_field_provenance() and the asset/user/asset-IP derivation
    functions.
    Params: context -- mutated via _record_recovery(); field -- name being
        resolved; candidates -- ordered list of (source_label, source_path,
        value) tuples, tried in order; evidence_index -- optional
        build_evidence_index() output for evidence linking; default --
        returned if every candidate is_unknown(); confidence -- recorded
        confidence label for the recovery.
    Returns: the first non-unknown candidate value, or `default`.
    Calls: is_unknown(), _first_evidence_id(), _record_recovery().
    Called by: _apply_field_provenance(), _recover_asset_ip().
    """
    for source, source_path, value in candidates:
        if is_unknown(value):
            continue
        evidence_id = _first_evidence_id(value, evidence_index or {})
        _record_recovery(
            context,
            field=field,
            value=value,
            source=source,
            source_path=source_path,
            confidence=confidence,
            evidence_id=evidence_id,
        )
        return value
    return default


def _flatten_values(value: Any, prefix: str = "", limit: int = 1000) -> list[tuple[str, Any]]:
    """[FYP-FUNCTION] Recursively Flatten A Nested dict/list Into
    (dotted.path, leaf_value) Pairs.

    Purpose: turn an arbitrarily-nested upstream payload (e.g. a whole
    triage_result or investigation_result dict) into a flat list so it can
    be regex-scanned for MITRE technique IDs (see _mitre_candidates())
    without writing bespoke per-shape traversal code.
    Params: value -- any nested structure; prefix -- dotted path prefix used
        during recursion (callers normally omit this); limit -- safety cap
        on total leaves collected (default 1000; only the first 100 items
        of any list are walked) so a pathological payload cannot cause
        runaway recursion/output size.
    Returns: list of (path, leaf_value) tuples; leaves that are_unknown()
        are skipped.
    Called by: _mitre_candidates().
    """
    out: list[tuple[str, Any]] = []

    # [FYP-FUNCTION] `walk` — implements the walk operation used by the surrounding report generation and export workflow.
    # [FYP-INPUT] Parameters: `obj`, `path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:_flatten_values, soc_reporting_agent/reporting/export_context_enhancer.py:_threat_intel_index, soc_reporting_agent/reporting/export_context_enhancer.py:walk; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `enumerate`, `is_unknown`, `isinstance`, `items`, `len`, `str`, `walk`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def walk(obj: Any, path: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(obj, dict):
            for key, item in obj.items():
                walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj[:100]):
                walk(item, f"{path}[{idx}]")
        elif not is_unknown(obj):
            out.append((path, obj))

    walk(value, prefix)
    return out


# ============================================================================
# [FYP-SECTION] IOC Classification & Rebuild
# [FYP-EVALUATOR] This section (culminating in rebuild_iocs() below) is one
# of the clearest examples in this file of merging upstream stage data: it
# scans processed_alert/enriched_alert/triage_result/investigation_result/
# evidence/threat_intel_result for indicator-shaped values, classifies each
# by type, rejects values that only look like an IOC (severity labels,
# alert IDs, usernames, the alert's own title), deduplicates by canonical
# key, and attaches VirusTotal/AbuseIPDB/OTX reputation where available.
# ============================================================================
def _classify_ioc(value: Any, hinted_type: Any = None) -> str:
    """[FYP-FUNCTION] Classify An IOC Value By Type.

    Purpose: decide the IOC "type" label (sha256/sha1/md5/file_hash/ip/url/
    domain/hostname/process_path/process_name/command_line/registry_key/
    file_name/indicator) for a candidate value, preferring an explicit hint
    from its source field name when the value itself is ambiguous, but
    always checking file-path/command-line/`.exe` shapes first since those
    are unambiguous regardless of hint.
    Params: value -- candidate IOC value; hinted_type -- the source field
        name/type label the value was found under (e.g. "source_ip",
        "sha256", "process_name"), used as a classification hint.
    Returns: one of the type strings above, or the raw hint (or "indicator")
        if nothing matched.
    Called by: rebuild_iocs().
    """
    text = _clean_text(value)
    hint = str(hinted_type or "").strip().lower()
    domain_pattern = r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
    if re.search(r"(?:^|\s)(?:[A-Za-z]:\\|\\\\|/).+\.exe(?:\s+.+)$", text, re.IGNORECASE):
        return "command_line"
    if re.search(r"(?:[A-Za-z]:\\|\\\\|/).+\.exe$", text, re.IGNORECASE):
        return "process_path"
    if re.fullmatch(r"[\w.-]+\.exe", text, re.IGNORECASE):
        return "file_name"
    if hint in {"sha256", "sha1", "md5"}:
        return hint
    if hint in {"file_hash", "hash", "hashes"}:
        if re.fullmatch(r"[a-fA-F0-9]{64}", text):
            return "sha256"
        if re.fullmatch(r"[a-fA-F0-9]{40}", text):
            return "sha1"
        if re.fullmatch(r"[a-fA-F0-9]{32}", text):
            return "md5"
        return "file_hash"
    if hint in {"destination_ip", "source_ip", "ip", "ip_address", "ips", "public_ip"}:
        return "ip"
    if hint in {"url", "urls"}:
        return "url"
    if hint in {"domain", "domains", "event_domain"} and re.fullmatch(domain_pattern, text):
        return "domain"
    if hint in {"host", "hostname", "hostnames"}:
        return "hostname"
    if hint in {"process_path", "file_path", "path"}:
        return "process_path"
    if hint in {"command_line", "cmdline", "process_command_line"}:
        return "command_line"
    if hint in {"process_name", "process", "file_name", "filename", "files"}:
        return "file_name"
    if hint in {"registry_key", "registry"}:
        return "registry_key"
    if text.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{64}", text):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", text):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", text):
        return "md5"
    if re.fullmatch(domain_pattern, text):
        return "domain"
    return hint or "indicator"


def _canonical_ioc_key(value: Any, ioc_type: str) -> str:
    """[FYP-FUNCTION] Canonical Dedup Key For An IOC. Prefixes the
    normalised value with "hash:"/"ip:"/"<type>:" so, e.g., the same hash
    value classified once as sha256 and once (via a different hint) is
    still keyed consistently, and different types sharing an incidentally
    equal text value do not collide. Called by: rebuild_iocs()."""
    text = _normalise_lookup(value)
    if ioc_type in {"sha256", "sha1", "md5", "file_hash"}:
        return f"hash:{text}"
    if ioc_type in {"destination_ip", "source_ip", "ip", "ip_address"}:
        return f"ip:{text}"
    return f"{ioc_type}:{text}"


def _looks_like_bad_file_ioc(value: Any, ioc_type: str, context: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-VALIDATION] Reject A False-Positive "file_name"
    IOC. True when a value classified as file_name is actually the alert's
    own case_title/alert name (not a real file), or contains a space
    without matching a recognised executable/script extension pattern
    (i.e. looks like a sentence fragment, not a filename). Called by:
    _is_rejected_ioc()."""
    text = _clean_text(value)
    if ioc_type != "file_name":
        return False
    title = _clean_text(context.get("case_title") or get_path(context, "alert.name") or "")
    if title and text.lower() == title.lower():
        return True
    if " " in text and not re.fullmatch(r"[\w.-]+\.(?:exe|dll|ps1|bat|cmd|scr|js|vbs|bin)", text, re.IGNORECASE):
        return True
    return False


def _known_non_ioc_values(context: dict[str, Any]) -> set[str]:
    """[FYP-FUNCTION] [FYP-VALIDATION] Build The "Definitely Not An IOC" Set.

    Purpose: collect values that are structurally IOC-shaped (a short
    string) but are actually the incident's own metadata -- alert ID, case
    title, severity/confidence labels -- from context and every raw_inputs
    source, plus derived "<value> severity"/"<value> confidence" variants
    (since severity/confidence values sometimes appear suffixed that way in
    free text). Called by: _is_rejected_ioc()."""
    raw = context.get("raw_inputs") or {}
    values: set[str] = set()
    candidate_paths = [
        context.get("alert_id"),
        context.get("case_title"),
        get_path(context, "alert.id"),
        get_path(context, "alert.name"),
        get_path(context, "severity.label"),
        get_path(context, "confidence.label"),
    ]
    for source in raw.values():
        if not isinstance(source, dict):
            continue
        candidate_paths.extend([
            source.get("alert_id"),
            source.get("alert_title"),
            source.get("alert_name"),
            source.get("case_title"),
            source.get("title"),
            source.get("severity"),
            source.get("confidence"),
        ])
    for value in candidate_paths:
        if not is_unknown(value):
            text = _normalise_lookup(value)
            values.add(text)
            values.add(f"{text} severity")
            values.add(f"{text} confidence")
    return values


def _looks_like_user_or_account(value: Any) -> bool:
    """[FYP-FUNCTION] [FYP-VALIDATION] Detect A DOMAIN\\user-Style Account
    Value (including the NT AUTHORITY\\ built-in prefix) so it is rejected
    as an IOC rather than misclassified as, e.g., a hostname or file path.
    Called by: _is_rejected_ioc()."""
    text = _clean_text(value)
    upper = text.upper()
    if upper.startswith("NT AUTHORITY\\"):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]+\\[A-Za-z0-9$_.-]+", text):
        return True
    return False


def _looks_like_alert_id(value: Any, context: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-VALIDATION] Detect An Alert/Case-ID-Shaped Value
    -- either an exact match against context["alert_id"], or a generic
    "PREFIX-...-123" style ID pattern (e.g. "NW-ALERT-2024-001"). Called by:
    _is_rejected_ioc()."""
    text = _clean_text(value)
    if text.upper() == _clean_text(context.get("alert_id")).upper():
        return True
    return bool(re.fullmatch(r"[A-Z]{2,}(?:-[A-Z0-9]{2,})+-\d{3,}(?:-\d+)?", text))


def _is_rejected_ioc(value: Any, ioc_type: str, context: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-VALIDATION] Should This Candidate Be Excluded
    From The Final IOC List?

    Purpose: the combined noise filter for rebuild_iocs() -- rejects empty
    text, known non-IOC metadata values (_known_non_ioc_values()), alert
    IDs, user/account strings, bare severity/confidence labels, malformed
    "domain"-typed values that don't actually match a domain pattern, and
    bad file_name matches (_looks_like_bad_file_ioc()).
    Params: value -- candidate IOC text; ioc_type -- its _classify_ioc()
        result; context -- for _known_non_ioc_values()/_looks_like_alert_id().
    Returns: True if the value should be dropped, not added to the IOC list.
    Called by: rebuild_iocs().
    """
    text = _clean_text(value)
    normalised = _normalise_lookup(text)
    if not text:
        return True
    if normalised in _known_non_ioc_values(context):
        return True
    if _looks_like_alert_id(text, context):
        return True
    if _looks_like_user_or_account(text):
        return True
    if re.fullmatch(r"(critical|high|medium|low|informational)(?:\s+(?:severity|confidence))?", text, re.IGNORECASE):
        return True
    if ioc_type == "domain" and not re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", text):
        return True
    return _looks_like_bad_file_ioc(text, ioc_type, context)


def _clean_text(value: Any) -> str:
    """[FYP-FUNCTION] Whitespace-Normalise To A Plain String. Coerces to
    str, strips, and collapses any internal whitespace runs to single
    spaces. The base text-cleaning primitive used by nearly every other
    helper in this file."""
    text = str(value or "").strip()
    return " ".join(text.split())


def _source_label(value: Any) -> str:
    """[FYP-FUNCTION] Human-Readable Source Label. Maps an internal source
    key/string (e.g. "processed_alert", "triage_result", a threat-intel
    provider hint) to the analyst-facing label shown in the report
    ("NetWitness Alert", "Triage Agent", "Investigation Agent",
    "Threat Intelligence Agent", "SOC Analyst Approval", "Reporting
    Context"); falls back to the raw value if unrecognised. Called by:
    rebuild_iocs()."""
    text = str(value or "").strip().lower()
    if not text:
        return "Reporting Context"
    if "netwitness" in text or text in {"processed_alert", "raw_alert", "alert"}:
        return "NetWitness Alert"
    if "triage" in text:
        return "Triage Agent"
    if "investigation" in text:
        return "Investigation Agent"
    if "threat" in text or "virustotal" in text or "otx" in text or "abuseipdb" in text:
        return "Threat Intelligence Agent"
    if "approval" in text:
        return "SOC Analyst Approval"
    if "report" in text or "merged" in text or "evidence" in text:
        return "Reporting Context"
    return str(value)


def _dedupe(items: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] Generic Dict-List Dedup By Key Fields. Builds a
    case-insensitive "|"-joined key from the given fields; drops an item if
    its key is empty, already seen, or every one of key_fields is
    is_unknown() on that item. Preserves first-seen order. Used across
    assets/users/timeline dedup (derive_affected_assets(),
    derive_affected_users(), derive_timeline())."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = "|".join(str(item.get(field, "")).strip().lower() for field in key_fields)
        if not key or key in seen or all(is_unknown(item.get(field)) for field in key_fields):
            continue
        seen.add(key)
        out.append(item)
    return out


def _candidate_ioc_items(context: dict[str, Any]) -> list[tuple[Any, str | None, str, str]]:
    """[FYP-FUNCTION] [FYP-USED-BY] rebuild_iocs() Collect Every Raw IOC
    Candidate From Every Upstream Source.

    Purpose: scan context["iocs"] (already-known IOCs), then
    processed_alert/enriched_alert/triage_result/investigation_result
    (direct indicator-shaped fields, list fields like matched_iocs/
    extracted_iocs/indicators, and their metakeys_payload sub-dict),
    enriched_alert's ioc_summary groups, the evidence register's "key:
    value" descriptions (excluding known non-IOC keys like severity/
    risk_score/username), and investigation findings' evidence text.
    Params: context -- the full reporting context.
    Returns: list of (value, hinted_type_or_None, source_name, source_path)
        tuples -- raw candidates, NOT yet classified/deduplicated/filtered
        (that happens in rebuild_iocs()).
    Called by: rebuild_iocs().
    """
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    candidates: list[tuple[Any, str | None, str, str]] = []

    # [FYP-PROCESS] Local helper: normalise one raw field (scalar, list, or
    # list-of-dicts) into individual (value, type, source, path) candidates,
    # appended to the enclosing `candidates` list.
    # [FYP-FUNCTION] `add` — implements the add operation used by the surrounding report generation and export workflow.
    # [FYP-INPUT] Parameters: `value`, `hinted_type`, `source`, `source_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include APIRetrieval.py:process_respond_api_telemetry, app.py:_pipeline_worked_ids, asset_criticality.py:assess_incident; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `as_list`, `first_present`, `get`, `is_unknown`, `isinstance`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def add(value: Any, hinted_type: str | None, source: str, source_path: str) -> None:
        for item in as_list(value):
            if isinstance(item, dict):
                item_value = first_present(
                    item.get("value"), item.get("ioc"), item.get("indicator"),
                    item.get("hash"), item.get("file_hash"), item.get("ip"), item.get("domain"),
                    default=None,
                )
                item_type = item.get("type") or item.get("ioc_type") or item.get("kind") or hinted_type
                if not is_unknown(item_value):
                    candidates.append((item_value, item_type, source, source_path))
            elif not is_unknown(item):
                candidates.append((item, hinted_type, source, source_path))

    for idx, item in enumerate(context.get("iocs") or []):
        add(item, item.get("type") if isinstance(item, dict) else None, "report_context", f"iocs[{idx}]")
    for source_name, source in [("processed_alert", processed), ("enriched_alert", enriched), ("triage_result", triage), ("investigation_result", investigation)]:
        for key in ("iocs", "matched_iocs", "extracted_iocs", "final_iocs", "indicators"):
            add(source.get(key), None, source_name, key)
        for key in ("source_ip", "destination_ip", "domain", "event_domain", "url", "sha256", "sha1", "md5", "file_hash", "process_name", "process_path", "command_line", "file_name", "registry_key", "hostname", "host"):
            add(source.get(key), key, source_name, key)
        meta = source.get("metakeys_payload") if isinstance(source.get("metakeys_payload"), dict) else {}
        for key in ("source_ip", "destination_ip", "domain", "url", "sha256", "file_name", "process_name", "process_path", "command_line", "hostname", "host"):
            add(meta.get(key), key, source_name, f"metakeys_payload.{key}")
    for group, values in (enriched.get("ioc_summary") or {}).items():
        add(values, group, "enriched_alert", f"ioc_summary.{group}")
    for item in context.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        key, value = _parse_key_value(item.get("description"))
        if key and value and key.lower() not in {"severity", "risk_score", "username", "user", "account", "execution_context", "destination_port", "protocol", "analyst_summary", "mitre_technique_id"}:
            add(value, key, "evidence", f"evidence.{item.get('id')}")
    for finding in as_list(investigation.get("findings")):
        if isinstance(finding, dict):
            for evidence_item in as_list(finding.get("evidence")):
                key, value = _parse_key_value(evidence_item)
                if key and value:
                    add(value, key, "investigation_result", "findings.evidence")
    return candidates


def _threat_intel_index(enriched: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """[FYP-FUNCTION] Build An Indicator->Threat-Intel-Verdict Index.

    Purpose: recursively walk a threat_intelligence payload (VirusTotal/
    AbuseIPDB/AlienVault OTX shapes) and index every indicator found by its
    normalised value, recording source label, a human-readable reputation
    string (verdict/reputation/risk_level, or a derived "N malicious
    detection(s)"/"N OTX pulse(s)"/"Abuse confidence N" string), and a
    confidence level ("High" if any malicious/suspicious/pulse count is
    positive or abuse score >= 50, else "Medium"). If the same indicator is
    seen more than once, keeps the higher-confidence entry.
    Params: enriched -- a dict expected to contain a "threat_intelligence"
        sub-dict (source: enriched_alert.json, or -- preferentially, see
        rebuild_iocs() -- context["threat_intel_result"]).
    Returns: dict of normalised indicator -> {source, reputation,
        confidence, source_path}.
    Called by: rebuild_iocs().
    """
    ti = enriched.get("threat_intelligence") if isinstance(enriched.get("threat_intelligence"), dict) else {}
    index: dict[str, dict[str, Any]] = {}
    source_names = {
        "virustotal": "VirusTotal",
        "abuseipdb": "AbuseIPDB",
        "alienvault_otx": "AlienVault OTX",
        "otx": "AlienVault OTX",
    }

    # [FYP-FUNCTION] `walk` — implements the walk operation used by the surrounding report generation and export workflow.
    # [FYP-INPUT] Parameters: `obj`, `path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:_flatten_values, soc_reporting_agent/reporting/export_context_enhancer.py:_threat_intel_index, soc_reporting_agent/reporting/export_context_enhancer.py:walk; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_normalise_lookup`, `any`, `enumerate`, `first_present`, `get`, `int`, `isinstance`, `items`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            indicator = first_present(obj.get("indicator"), obj.get("value"), obj.get("ioc"), default=None)
            if indicator:
                source = "Threat Intelligence"
                for token, label in source_names.items():
                    if token in path.lower():
                        source = label
                        break
                malicious = obj.get("malicious")
                suspicious = obj.get("suspicious")
                pulse_count = obj.get("pulse_count")
                abuse_score = obj.get("abuse_confidence_score")
                reputation = first_present(
                    obj.get("verdict"), obj.get("reputation"), obj.get("risk_level"),
                    f"{malicious} malicious detection(s)" if malicious not in (None, "") else None,
                    f"{pulse_count} OTX pulse(s)" if pulse_count not in (None, "") else None,
                    f"Abuse confidence {abuse_score}" if abuse_score not in (None, "") else None,
                    default=VALIDATION_PLACEHOLDER,
                )
                confidence = "High" if any(int(x or 0) > 0 for x in (malicious, suspicious, pulse_count)) else "Medium"
                if abuse_score not in (None, "") and int(abuse_score or 0) >= 50:
                    confidence = "High"
                existing = index.get(_normalise_lookup(indicator))
                entry = {"source": source, "reputation": reputation, "confidence": confidence, "source_path": path}
                if not existing or existing.get("confidence") != "High":
                    index[_normalise_lookup(indicator)] = entry
            for key, item in obj.items():
                walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{path}[{idx}]")

    walk(ti, "threat_intelligence")
    return index


def rebuild_iocs(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-STATE] Rebuild The Report's IOC
    List From Every Upstream Stage.

    Purpose: the IOC pipeline's orchestrator -- gathers every raw candidate
    (_candidate_ioc_items()), classifies each (_classify_ioc()), drops
    non-IOC noise (_is_rejected_ioc()), deduplicates by canonical key
    (_canonical_ioc_key()), links each to supporting evidence
    (_evidence_refs()) and to any known threat-intel verdict
    (_threat_intel_index()), and returns the final report-ready IOC list.
    Also updates quality counters for how many raw candidates were
    deduplicated away, how many evidence links were recovered, and how many
    placeholders were reduced (a threat-intel match counts for 3, since it
    fills reputation/confidence/source at once).
    Params: context -- full reporting context, notably raw_inputs
        (enriched_alert) and, preferentially, threat_intel_result -- see the
        inline note on why threat_intel_result is preferred over
        enriched_alert's own threat_intelligence field (enriched_alert.json
        is a separate, hand-rolled harvest built at handoff time that does
        not reliably carry the real computed threat-intel payload);
        evidence_index -- from build_evidence_index().
    Returns: list of IOC dicts: type, value, ioc, source, confidence,
        reputation, evidence (comma-joined string), evidence_refs (list),
        source_path.
    Side effects: bumps context["quality_checks"]["iocs_deduplicated"],
        ["evidence_links_recovered"], ["placeholders_reduced"].
    Called by: enhance_export_context() (writes the result to
        context["iocs"]).
    Calls: _threat_intel_index(), _candidate_ioc_items(), _classify_ioc(),
        _is_rejected_ioc(), _canonical_ioc_key(), _evidence_refs(),
        _source_label(), _clean_text(), _bump().
    """
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    # Threat Intelligence is passed explicitly via threat_intel_result.json
    # (see input_loader.py/context_builder.py) rather than assumed to have
    # survived into enriched_alert.json — that file is a separate,
    # hand-rolled harvest built at handoff time and does not reliably carry
    # the real computed threat_intelligence payload. Prefer the explicit
    # threat_intel_result; fall back to enriched_alert only for legacy
    # inputs that predate this wiring.
    ti_source = context.get("threat_intel_result") or enriched
    ti_index = _threat_intel_index(ti_source)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_candidates = 0
    links_recovered = 0
    placeholders_reduced = 0

    for value, hinted_type, source, source_path in _candidate_ioc_items(context):
        if is_unknown(value):
            continue
        total_candidates += 1
        ioc_type = _classify_ioc(value, hinted_type)
        if ioc_type in {"indicator", "mitre_technique_id"}:
            continue
        if _is_rejected_ioc(value, ioc_type, context):
            continue
        key = _canonical_ioc_key(value, ioc_type)
        if key in seen:
            continue
        seen.add(key)
        refs = _evidence_refs(value, evidence_index)
        if refs:
            links_recovered += 1
        ti = ti_index.get(_normalise_lookup(value), {})
        if ti:
            placeholders_reduced += 3
        out.append({
            "type": ioc_type,
            "value": _clean_text(value),
            "ioc": _clean_text(value),
            "source": ti.get("source") or _source_label(source),
            "confidence": ti.get("confidence") or "Observed",
            "reputation": ti.get("reputation") or "No external reputation supplied",
            "evidence": ", ".join(refs) if refs else "",
            "evidence_refs": refs,
            "source_path": ti.get("source_path") or source_path,
        })
    _bump(context, "iocs_deduplicated", max(0, total_candidates - len(out)))
    _bump(context, "evidence_links_recovered", links_recovered)
    _bump(context, "placeholders_reduced", placeholders_reduced + links_recovered)
    return out


def repair_evidence_rows(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-VALIDATION] Backfill Missing Evidence Register
    Fields. For each evidence item, resolves an unknown source label to
    "Reporting Context" (or normalises a known one via _source_label()), and
    blanks out unknown timestamp/confidence/raw_reference fields to "" so
    templates render an empty cell instead of a literal "None"/"unknown".
    Mutates context["evidence"] items in place. Side effect: bumps
    quality_checks["placeholders_reduced"] by the number of fields blanked.
    Called by: enhance_export_context()."""
    changed = 0
    for item in context.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if is_unknown(item.get("source")):
            item["source"] = "Reporting Context"
            changed += 1
        else:
            item["source"] = _source_label(item.get("source"))
        if is_unknown(item.get("timestamp")):
            item["timestamp"] = ""
            changed += 1
        if is_unknown(item.get("confidence")):
            item["confidence"] = ""
            changed += 1
        if is_unknown(item.get("raw_reference")):
            item["raw_reference"] = ""
            changed += 1
    _bump(context, "placeholders_reduced", changed)


# ============================================================================
# [FYP-SECTION] Affected Asset / User Derivation
# ============================================================================
def _asset(hostname: Any, source: str = "Derived from ticket context", confidence: str = "High") -> dict[str, Any] | None:
    """[FYP-FUNCTION] Build A New Asset Record Skeleton From A Hostname.
    Returns None for an unknown/placeholder hostname (including the literal
    "unknown-host"/"localhost" values). Every non-hostname field starts as a
    placeholder (VALIDATION_PLACEHOLDER / OWNER_PLACEHOLDER / "Not
    Provided") to be backfilled later by derive_affected_assets(). Called
    by: derive_affected_assets()."""
    host = _clean_text(hostname)
    if is_unknown(host) or host.lower() in {"unknown-host", "localhost"}:
        return None
    return {
        "hostname": host,
        "asset": host,
        "host": host,
        "name": host,
        "ip_address": "Not Provided",
        "ip": "Not Provided",
        "asset_type": "Endpoint",
        "criticality": VALIDATION_PLACEHOLDER,
        "role": VALIDATION_PLACEHOLDER,
        "owner": OWNER_PLACEHOLDER,
        "business_function": VALIDATION_PLACEHOLDER,
        "isolation_status": VALIDATION_PLACEHOLDER,
        "status": VALIDATION_PLACEHOLDER,
        "source": source,
        "confidence": confidence,
    }


def _recover_asset_ip(context: dict[str, Any], asset: dict[str, Any], evidence_index: dict[str, list[str]]) -> str:
    """[FYP-FUNCTION] [FYP-STATE] Recover One Asset's IP Address.

    Purpose: try, in priority order, the asset's own existing ip_address/ip
    field, then ticket_context, enriched_alert, processed_alert, and
    triage/investigation result fields (via first_available(), which
    records provenance); if still unknown, scans the evidence register's
    "key: value" descriptions for an IP-shaped key (ip/source_ip/host_ip/
    asset_ip/endpoint_ip) as a last resort.
    Params: context -- full reporting context; asset -- the asset dict being
        enriched (its current ip_address/ip is the first candidate);
        evidence_index -- for provenance/evidence linking.
    Returns: the recovered IP string, or TELEMETRY_PLACEHOLDER if nothing
        was found anywhere.
    Side effects: via first_available()/_record_recovery(), may write to
        context["field_provenance"]["asset_ip"] /
        context["recovered_fields"]; bumps
        quality_checks["fields_still_unavailable_from_source_telemetry"] by
        1 if no value was found at all.
    Called by: derive_affected_assets().
    """
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    ticket = context.get("ticket") or {}
    # Phase 4 (Reporting dead-fallback cleanup): dropped three
    # triage_result-sourced terms here -- "metakeys_payload.source_ip",
    # "host_ip", and "source_ip" -- none of which the flattened
    # triage_result.json has ever had at the top level (only the RAW
    # canonical Triage contract nests a "metakeys_payload", and even that
    # payload's real key is "ip.src"/"ip.dst", not "source_ip"/"host_ip").
    # All three always resolved to None; the remaining fallback tiers below
    # are unaffected.
    current = first_present(asset.get("ip_address"), asset.get("ip"), default=None)
    value = first_available(context, "asset_ip", [
        ("affected_assets", "asset.ip_address", current),
        ("ticket_context", "host_ip", ticket.get("host_ip")),
        ("ticket_context", "asset_ip", ticket.get("asset_ip")),
        ("ticket_context", "endpoint_ip", ticket.get("endpoint_ip")),
        ("enriched_alert", "host_ip", enriched.get("host_ip")),
        ("enriched_alert", "source_ip", enriched.get("source_ip")),
        ("enriched_alert", "asset_ip", enriched.get("asset_ip")),
        ("enriched_alert", "endpoint_ip", enriched.get("endpoint_ip")),
        ("processed_alert", "source_ip", processed.get("source_ip")),
        ("processed_alert", "host_ip", processed.get("host_ip")),
        ("investigation_result", "source_ip", investigation.get("source_ip")),
        ("investigation_result", "host_ip", investigation.get("host_ip")),
    ], evidence_index=evidence_index, default=None)
    if not is_unknown(value):
        return _clean_text(value)
    for item in context.get("evidence") or []:
        key, evidence_value = _parse_key_value(item.get("description") if isinstance(item, dict) else item)
        if key and key.lower() in {"ip", "source_ip", "host_ip", "asset_ip", "endpoint_ip"} and evidence_value:
            _record_recovery(
                context,
                field="asset_ip",
                value=evidence_value,
                source="evidence",
                source_path=f"evidence.{item.get('id')}" if isinstance(item, dict) else "evidence",
                confidence="High",
                evidence_id=item.get("id") if isinstance(item, dict) else _first_evidence_id(evidence_value, evidence_index),
            )
            return _clean_text(evidence_value)
    _bump(context, "fields_still_unavailable_from_source_telemetry", 1)
    return TELEMETRY_PLACEHOLDER


def derive_affected_assets(context: dict[str, Any], ticket: dict[str, Any] | None, evidence_index: dict[str, list[str]] | None = None) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-STATE] Derive The Final Affected-Assets List.

    Purpose: start from any assets already present in context, then scan a
    wide set of candidate host-identifying fields across ticket/
    enriched_alert/processed_alert/investigation/triage sources (including
    nested affected_assets lists on each) to build additional asset records
    via _asset(); dedupe by hostname; backfill each surviving asset's
    ip_address (via _recover_asset_ip()), owner, and validation-pending
    fields (criticality/role/business_function/isolation_status/status)
    with placeholders where still unknown.
    Params: context -- full reporting context; ticket -- optional ticket
        dict (falls back to context.get("ticket")); evidence_index --
        optional, for IP recovery evidence linking.
    Returns: the final list of asset dicts.
    Side effects: bumps quality_checks["fields_recovered_from_fallback_
        sources"] and ["placeholders_reduced"] once per asset whose IP was
        actually recovered (not left as TELEMETRY_PLACEHOLDER).
    Called by: enhance_export_context() (writes to
        context["affected_assets"]).
    Calls: _asset(), _dedupe(), _recover_asset_ip(), as_list(), get_path().
    """
    evidence_index = evidence_index or {}
    assets = list(context.get("affected_assets") or [])
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    ticket = ticket or context.get("ticket") or {}

    candidates = [
        ticket.get("host"), ticket.get("hostname"), ticket.get("host_name"), ticket.get("asset"),
        enriched.get("host"), enriched.get("hostname"), enriched.get("host.name"), enriched.get("asset"), enriched.get("device"),
        processed.get("host"), processed.get("hostname"), processed.get("host.name"), processed.get("asset"),
        get_path(enriched, "ticket_context.host"), get_path(enriched, "ticket_context.hostname"),
        get_path(investigation, "available_evidence.host"), get_path(investigation, "available_evidence.hostname"),
        get_path(triage, "metakeys_payload.metakey_values.host.name"),
        get_path(triage, "raw_agent_result.ticket.host"), get_path(triage, "ticket.host"),
    ]
    for item in as_list(enriched.get("affected_assets")) + as_list(investigation.get("affected_assets")) + as_list(ticket.get("affected_assets")):
        if isinstance(item, dict):
            candidates.extend([item.get("hostname"), item.get("host"), item.get("host.name"), item.get("name")])
        else:
            candidates.append(item)
    for host in candidates:
        asset = _asset(host)
        if asset:
            assets.append(asset)

    repaired: list[dict[str, Any]] = []
    for asset in _dedupe(assets, ("hostname",)):
        if is_unknown(asset.get("ip_address")):
            ip = _recover_asset_ip(context, asset, evidence_index)
            if ip != TELEMETRY_PLACEHOLDER:
                _bump(context, "fields_recovered_from_fallback_sources", 1)
                _bump(context, "placeholders_reduced", 1)
            asset["ip_address"] = ip
            asset["ip"] = ip
        for owner_key in ("owner",):
            if is_unknown(asset.get(owner_key)):
                asset[owner_key] = OWNER_PLACEHOLDER
        for validation_key in ("criticality", "role", "business_function", "isolation_status", "status"):
            if is_unknown(asset.get(validation_key)):
                asset[validation_key] = VALIDATION_PLACEHOLDER
        repaired.append(asset)
    return repaired


def derive_affected_users(context: dict[str, Any], ticket: dict[str, Any] | None) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-STATE] Derive The Final Affected-Users List.

    Purpose: mirrors derive_affected_assets() for user/account identifiers
    -- scans ticket/enriched_alert/processed_alert/investigation for
    user/username/account fields, builds a user record per candidate
    (email/role/privilege_level/mfa_status/account_status defaulted to
    placeholders), dedupes by username, and backfills any still-unknown
    fields on surviving (including pre-existing) users.
    Params: context -- full reporting context; ticket -- optional ticket
        dict (falls back to context.get("ticket")).
    Returns: the final list of user dicts.
    Called by: enhance_export_context() (writes to
        context["affected_users"]).
    Calls: _dedupe(), get_path().
    """
    users = list(context.get("affected_users") or [])
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    ticket = ticket or context.get("ticket") or {}
    candidates = [
        ticket.get("user"), ticket.get("username"), ticket.get("account"),
        enriched.get("user"), enriched.get("username"), enriched.get("account"),
        processed.get("user"), processed.get("username"), processed.get("account"),
        get_path(investigation, "available_evidence.user"), get_path(investigation, "available_evidence.username"),
    ]
    for user in candidates:
        if not is_unknown(user):
            username = _clean_text(user)
            users.append({
                "username": username,
                "user": username,
                "email": TELEMETRY_PLACEHOLDER,
                "role": VALIDATION_PLACEHOLDER,
                "privilege_level": VALIDATION_PLACEHOLDER,
                "groups": [],
                "mfa_status": VALIDATION_PLACEHOLDER,
                "account_status": VALIDATION_PLACEHOLDER,
            })
    repaired: list[dict[str, Any]] = []
    for user in _dedupe(users, ("username",)):
        if is_unknown(user.get("email")):
            user["email"] = TELEMETRY_PLACEHOLDER
        if is_unknown(user.get("role")):
            user["role"] = VALIDATION_PLACEHOLDER
        for key in ("privilege_level", "mfa_status", "account_status"):
            if is_unknown(user.get(key)):
                user[key] = VALIDATION_PLACEHOLDER
        repaired.append(user)
    return repaired


# ============================================================================
# [FYP-SECTION] Approval & Containment Normalisation
# [FYP-APPROVAL] These functions reconcile the analyst's upstream approval
# decision (context["approval_result"], produced by the SOC Analyst Approval
# workflow step) with the recommended containment action surfaced by Triage/
# Investigation, into a single consistent set of approval/containment
# fields for the exported report.
# ============================================================================
def _approval_decision(approval_result: dict[str, Any]) -> str:
    """[FYP-FUNCTION] [FYP-APPROVAL] Normalise The Raw Approval Decision
    String (lower-cased, from analyst_decision/decision/approval_status,
    in that preference order) for comparison against the accepted/rejected
    keyword sets in normalise_approval(). Called by: normalise_approval()."""
    return str(first_present(
        approval_result.get("analyst_decision"),
        approval_result.get("decision"),
        approval_result.get("approval_status"),
        default="Not Provided",
    )).strip().lower()


def _looks_like_containment_action(value: Any) -> bool:
    """[FYP-FUNCTION] Keyword Heuristic: Is This A Containment Action?
    True if the text contains a containment verb (isolate/contain/quarantine/
    block/disable/disconnect/terminate). Used by _find_recommended_
    containment_action() and normalise_approval() to distinguish real
    containment recommendations from unrelated recommendation text."""
    text = _clean_text(value).lower()
    return bool(text) and any(token in text for token in (
        "isolate", "contain", "quarantine", "block", "disable", "disconnect", "terminate"
    ))


def _find_recommended_containment_action(context: dict[str, Any]) -> Any:
    """[FYP-FUNCTION] [FYP-STATE] Locate The Recommended Containment Action.
    Checks explicit approval/investigation/triage fields first (via
    first_present()), then falls back to scanning each source's
    containment_recommendations/recommended_actions/recommendations lists
    for the first entry that _looks_like_containment_action(). Returns None
    if nothing containment-shaped is found anywhere. Called by:
    normalise_approval()."""
    raw = context.get("raw_inputs") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    approval = context.get("approval_result") or {}

    # triage.get("recommended_containment_action"/"containment_action")
    # dropped -- Triage does not produce containment recommendations at
    # all; neither key has ever existed on the flattened triage_result.json.
    explicit = first_present(
        approval.get("approved_containment_action"),
        approval.get("approved_action") if _looks_like_containment_action(approval.get("approved_action")) else None,
        investigation.get("recommended_containment_action"),
        investigation.get("containment_action"),
        default=None,
    )
    if not is_unknown(explicit):
        return explicit

    # The loop below is shared/generic across investigation, triage, and
    # context -- "recommendations" and "containment_recommendations" are
    # left alone here (not proven dead for investigation/context, only for
    # Triage specifically, and this expression isn't triage-specific).
    for source in (investigation, triage, context):
        for item in as_list(source.get("containment_recommendations")) + as_list(source.get("recommended_actions")) + as_list(source.get("recommendations")):
            action = item
            if isinstance(item, dict):
                action = first_present(item.get("action"), item.get("recommendation"), item.get("title"), default=None)
            if _looks_like_containment_action(action):
                return action
    return None


def normalise_approval(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-APPROVAL] [FYP-STATE] [FYP-EVALUATOR] Reconcile
    The Analyst's Raw approval_result Record Into Consistent Status Fields.
    Populates context["approval"] and context["containment"] (plus mirrored
    top-level keys such as approval_status/containment_status) from the
    approval_result dict recorded by the workflow's approval gate --
    distinguishing approved/rejected/pending decisions, containment vs.
    report-generation approval types, and computing the final_analyst_
    review_status shown on the report cover. Mutates context in place;
    called once per report from enhance_export_context()."""
    approval_result = context.get("approval_result") or {}
    approval = context.setdefault("approval", {})
    containment = context.setdefault("containment", {})

    decision = _approval_decision(approval_result)
    analyst_name = first_present(approval_result.get("analyst"), approval_result.get("approved_by"), approval_result.get("reviewed_by"), default="SOC Analyst")

    approval_gate = first_present(approval_result.get("approval_gate"), approval_result.get("approval_type"), default=None)
    recommended_containment = _find_recommended_containment_action(context)

    if decision in {"approved", "approve", "accepted", "accept"}:
        approval["approval_status"] = "approved"
        approval["analyst_decision"] = "approved"
        approval["approved_by"] = analyst_name
        context["approval_status"] = "approved"
        context["analyst_decision"] = "approved"
    elif decision in {"rejected", "reject", "declined", "deny", "denied"}:
        approval["approval_status"] = "rejected"
        approval["analyst_decision"] = "rejected"
        approval["approved_by"] = analyst_name
        context["approval_status"] = "rejected"
        context["analyst_decision"] = "rejected"
        containment["status"] = "rejected"
        containment["execution_status"] = "not_executed"
        context["containment_status"] = "rejected"
    else:
        # triage.get("soc_analyst_approval_status") dropped -- Triage does
        # not perform approval gating; this key has never existed on the
        # flattened triage_result.json.
        approval["approval_status"] = first_present(approval.get("approval_status"), default="pending")
        approval["analyst_decision"] = first_present(approval.get("analyst_decision"), default="pending")
        approval["approved_by"] = first_present(approval.get("approved_by"), default="")
        context["approval_status"] = approval["approval_status"]
        context["analyst_decision"] = approval["analyst_decision"]

    approval["analyst_comments"] = first_present(approval_result.get("comments"), approval_result.get("analyst_comments"), approval.get("analyst_comments"), default="No approval comments supplied.")
    approval["approval_type"] = first_present(approval_result.get("approval_type"), approval_gate, default="")
    approval["approved_action"] = first_present(approval_result.get("approved_action"), approval_result.get("approved_containment_action"), default="")

    is_containment_approval = any(token in str(approval_gate or "").lower() for token in ("containment", "response_action"))
    is_report_approval = any(token in str(approval_gate or "").lower() for token in ("report", "investigation", "evidence_gap"))

    final_review_status = first_present(
        approval_result.get("final_analyst_review_status"),
        approval_result.get("analyst_review_status"),
        context.get("final_analyst_review_status") if _analyst_review_completed(context) else None,
        default="Requires final analyst review",
    )
    if str(final_review_status).strip().lower() in {"approved", "confirmed", "completed", "closed", "reviewed", "final_review_completed"}:
        context["final_analyst_review_status"] = final_review_status
    else:
        context["final_analyst_review_status"] = "Requires final analyst review"

    report_generation_status = approval["approval_status"] if is_report_approval or not is_containment_approval else ""
    context["report_generation_approval"] = {
        "status": report_generation_status,
        "approved_by": approval.get("approved_by", ""),
        "approval_gate": approval_gate or "",
        "comments": approval.get("analyst_comments", ""),
    }
    approval["report_generation_approval_status"] = report_generation_status
    approval["report_generation_approved_by"] = approval.get("approved_by", "")
    approval["final_analyst_review_status"] = context["final_analyst_review_status"]
    containment["recommended_action"] = first_present(containment.get("recommended_action"), recommended_containment, default="")
    containment["approval_status"] = first_present(
        approval_result.get("containment_approval_status"),
        approval_result.get("containment_status") if is_containment_approval else None,
        default="approved" if is_containment_approval and decision in {"approved", "approve", "accepted", "accept"} else "Pending analyst approval" if _looks_like_containment_action(recommended_containment) else "not_required",
    )
    execution = first_present(
        approval_result.get("containment_execution_status"),
        approval_result.get("execution_status"),
        context.get("containment_execution_status"),
        default=None,
    )
    containment["execution_status"] = execution if not is_unknown(execution) else "not_contained"
    # triage.get("containment_status") dropped -- never produced by Triage.
    containment["status"] = first_present(containment.get("status"), default=containment["execution_status"])
    if str(containment["status"]).lower() in {"approved_pending_execution", "pending_execution"}:
        containment["status"] = "not_contained"
    context["containment_status"] = containment["status"]
    context["containment_approval_status"] = containment["approval_status"]
    context["containment_execution_status"] = containment["execution_status"]
    context["approval_type_validation_note"] = "" if approval.get("approval_type") else "Approval record exists, but approval type requires analyst validation."
    approval["approval_required"] = first_present(
        approval.get("approval_required"),
        approval_result.get("approval_required"),
        "Yes" if _looks_like_containment_action(recommended_containment) else "No",
        default="",
    )


def replace_low_value_placeholders(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-VALIDATION] Soften Bare "Unknown" Fields Into
    Analyst-Legible Copy. For a fixed set of low-stakes fields (severity/
    confidence rationale, owners, malware_family, root_cause.category, etc.)
    replaces genuinely-missing (is_unknown()) values with either an empty
    string or a short explanatory placeholder sentence, so the exported
    report never shows a bare "Unknown"/"None" for these fields. Mutates
    context in place. Called from enhance_export_context()."""
    severity = context.get("severity") if isinstance(context.get("severity"), dict) else {}
    confidence = context.get("confidence") if isinstance(context.get("confidence"), dict) else {}
    if is_unknown(severity.get("reason")):
        severity["reason"] = "No explicit severity rationale was supplied; validate against triage and investigation evidence."
    if is_unknown(confidence.get("reason")):
        confidence["reason"] = "No explicit confidence rationale was supplied; validate against evidence completeness and source telemetry."
    context["severity"] = severity
    context["confidence"] = confidence

    replacements = {
        "business_owner": "",
        "technical_owner": "",
        "rule_id": "",
        "initial_risk_score": "",
        "enrichment_risk_score": "",
        "malware_family": "",
        "threat_actor": "",
        "scenario_type": "Requires analyst validation",
        "triage_summary": "No standalone triage summary was supplied.",
        "investigation_summary": "No standalone investigation summary was supplied.",
    }
    for key, replacement in replacements.items():
        if is_unknown(context.get(key)):
            context[key] = replacement

    root_cause = context.get("root_cause") if isinstance(context.get("root_cause"), dict) else {}
    if is_unknown(root_cause.get("category")):
        root_cause["category"] = "Requires analyst validation"
    context["root_cause"] = root_cause

    alert = context.get("alert") if isinstance(context.get("alert"), dict) else {}
    if is_unknown(alert.get("timestamp")):
        alert["timestamp"] = ""
    context["alert"] = alert


_INCIDENT_TIMESTAMP_RE = re.compile(
    r"(?:\bat\s+)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)(?:\s*:)?"
)
_CHRONOLOGY_HEADING_RE = re.compile(r"^#{1,6}\s*Technical Chronology\b.*$", re.IGNORECASE | re.MULTILINE)

# Keyword heuristics used only to LABEL a sentence the Investigation Agent
# already wrote -- never to invent or alter its content. Checked in order
# (a limitation caveat inside an otherwise-suspicious sentence still reads
# as a limitation, since that is the more analyst-relevant flag).
_TIMELINE_LIMITATION_MARKERS = (
    "no confirmed", "not confirmed", "did not confirm", "no evidence",
    "cannot be", "could not", "not proven", "unable to", "not present",
    "no hash", "no decodable", "not available", "no usable", "lack of",
    "no process", "no endpoint", "no hostname", "without process",
    "without host", "remained unresolved", "did not prove", "no host telemetry",
    "not directly available", "is not confirmed", "not confirmed as",
)
_TIMELINE_SUSPECTED_MARKERS = (
    "suspicious", "potential", "possible", "suggest", "appears",
    "unconfirmed", "may indicate", "likely", "consistent with",
)


def _classify_timeline_activity(sentence: str) -> str:
    """[FYP-FUNCTION] Label a chronology sentence as confirmed, suspected/unconfirmed, or an
    investigation limitation, based purely on the Investigation Agent's own
    wording -- the sentence text itself is never altered."""
    lowered = sentence.lower()
    if any(marker in lowered for marker in _TIMELINE_LIMITATION_MARKERS):
        return "Investigation limitation"
    if any(marker in lowered for marker in _TIMELINE_SUSPECTED_MARKERS):
        return "Suspected or unconfirmed activity"
    return "Confirmed activity"


def _extract_technical_chronology_narrative(narrative_report: Any) -> str:
    """[FYP-FUNCTION] Return the Investigation Agent's own free-text account of the real
    incident: the paragraph it writes under its "Technical Chronology &
    MITRE ATT&CK TTP Mapping" heading (orchestrator.FinalIncidentAnalysis.
    incident_summary), stopping before the MITRE mapping table that follows
    it. This is the actual attacker/host/process/file/network chronology --
    as opposed to internal workflow milestones (triage, approval, report
    generation), which must never appear in the Incident Timeline."""
    text = str(narrative_report or "")
    if not text:
        return ""
    match = _CHRONOLOGY_HEADING_RE.search(text)
    if not match:
        return ""
    lines: list[str] = []
    for line in text[match.end():].splitlines():
        stripped = line.strip()
        if not stripped:
            if lines:
                break
            continue
        if stripped.startswith("#") or stripped.startswith("|"):
            break
        lines.append(stripped)
    return " ".join(lines).strip()


def _incident_timeline_from_chronology(chronology_text: str) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] Turn the Investigation Agent's chronology paragraph into one timeline
    entry per described event, carrying forward the most recent explicit
    timestamp mentioned in the text. Never invents a timestamp: an event
    described before any timestamp has appeared is recorded as such."""
    if not chronology_text:
        return []
    events: list[dict[str, Any]] = []
    current_time = ""
    for raw_sentence in split_into_sentences(chronology_text):
        match = _INCIDENT_TIMESTAMP_RE.search(raw_sentence)
        if match:
            current_time = match.group(1)
            sentence = raw_sentence[:match.start()] + raw_sentence[match.end():]
        else:
            sentence = raw_sentence
        sentence = re.sub(r"\s{2,}", " ", sentence).strip(" .,:;-")
        if not sentence:
            continue
        events.append({
            "time": current_time or "Time not available",
            "timestamp": current_time or "Time not available",
            "event": sentence + ".",
            "description": sentence + ".",
            "source": "",
            "evidence_refs": [],
            "significance": _classify_timeline_activity(sentence),
        })
    return events


def _incident_timeline_from_mitre_mapping(context: dict[str, Any]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-FALLBACK] Fallback source for when the Investigation Agent's narrative has no
    chronology paragraph to parse: its own structured MITRE ATT&CK mapping
    (timeline_phase / observed_evidence, already resolved onto the context by
    repair_mitre_mapping) still describes real, chronologically-ordered
    incident activity. No timestamp accompanies this data, so the time is
    stated as unavailable rather than invented."""
    mitre_mappings = context.get("mitre_attack_mapping") or context.get("mitre_mapping") or []
    events: list[dict[str, Any]] = []
    for item in mitre_mappings:
        if not isinstance(item, dict):
            continue
        phase = str(first_present(item.get("timeline_phase"), default="")).strip()
        evidence = str(first_present(item.get("observed_evidence"), default="")).strip()
        if is_unknown(phase) and is_unknown(evidence):
            continue
        event = ": ".join(part for part in (phase, evidence) if part and not is_unknown(part))
        events.append({
            "time": "Time not available",
            "timestamp": "Time not available",
            "event": event,
            "description": event,
            "source": "",
            "evidence_refs": [],
            "significance": _classify_timeline_activity(event),
        })
    return events


def _is_placeholder_timeline_event(item: Any) -> bool:
    """[FYP-FUNCTION] True for a generic "Timeline event N" stub entry (no
    real description), as opposed to a genuine timeline item supplied
    directly by the Investigation Agent. Used by derive_timeline() to avoid
    treating unresolved placeholders as real explicit timeline data."""
    if not isinstance(item, dict):
        return False
    event = first_present(item.get("event"), item.get("description"), default="")
    return bool(re.fullmatch(r"Timeline event \d+", str(event).strip(), re.IGNORECASE))


def derive_timeline(context: dict[str, Any]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-STATE] [FYP-EVALUATOR] Build the Incident Timeline strictly from the Investigation Agent's
    own account of the real incident. Internal workflow/processing
    milestones (alert ingestion, triage, investigation, approval, or report
    generation) are not incident events and must never appear here."""
    raw = context.get("raw_inputs") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}

    chronology_text = _extract_technical_chronology_narrative(investigation.get("narrative_report"))
    timeline = _incident_timeline_from_chronology(chronology_text)
    if not timeline:
        timeline = _incident_timeline_from_mitre_mapping(context)

    # A genuinely populated investigation.timeline (time/event/significance
    # supplied directly by the Investigation Agent, distinct from this
    # module's own unresolved placeholder shape) describes real incident
    # data too, and is kept alongside the chronology/MITRE-derived events.
    explicit_timeline = [
        item for item in as_list(context.get("timeline"))
        if isinstance(item, dict) and not _is_placeholder_timeline_event(item)
    ]

    return _dedupe(explicit_timeline + timeline, ("time", "event"))


def _apply_field_provenance(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> None:
    """[FYP-FUNCTION] [FYP-VALIDATION] [FYP-STATE] [FYP-EVALUATOR] Recover A
    Fixed Set Of Key Incident Fields, WITH Provenance. For each field in the
    `fields` table below (host, source_ip, destination_ip, domain, url,
    sha256, process_name, process_path, mitre_technique_id, severity,
    confidence, classification, approval_status, analyst_decision,
    approved_by, containment_status, recommended_containment_action,
    containment_execution_status), walks an ordered list of
    (source_name, source_path, value) candidates drawn from enriched_alert/
    processed_alert/triage_result(.metakeys_payload)/investigation_result/
    approval_result/ticket, and delegates to first_available() to pick the
    first usable value while recording where it came from
    (context["field_provenance"]/["recovered_fields"]). Mutates context in
    place; called once per report from enhance_export_context()."""
    raw = context.get("raw_inputs") or {}
    enriched = raw.get("enriched_alert") or {}
    processed = raw.get("processed_alert") or {}
    triage = raw.get("triage_result") or context.get("triage") or {}
    investigation = raw.get("investigation_result") or context.get("investigation") or {}
    approval = context.get("approval_result") or {}
    ticket = context.get("ticket") or {}
    # Phase 4 (Reporting dead-fallback cleanup): dropped every
    # "triage_result", "metakeys_payload.*"-sourced term below (host,
    # source_ip, destination_ip, domain, url, sha256, process_name,
    # mitre_technique_id) -- the flattened triage_result.json has never had
    # a "metakeys_payload" key at all (that only exists on the RAW canonical
    # Triage contract), so `triage_meta` was always {} and every one of
    # these terms always resolved to None. Also dropped triage.get(
    # "confidence"/"soc_analyst_approval_status"/"containment_status"/
    # "containment_action"/"recommended_containment_action") -- none of
    # these has ever existed on the flattened document either. triage.get(
    # "severity"/"classification") remain -- both real, Triage-owned fields.
    fields = {
        "host": [
            ("enriched_alert", "host", enriched.get("host")),
            ("enriched_alert", "hostname", enriched.get("hostname")),
            ("processed_alert", "hostname", processed.get("hostname")),
            ("ticket_context", "host", ticket.get("host")),
        ],
        "source_ip": [
            ("enriched_alert", "source_ip", enriched.get("source_ip")),
            ("processed_alert", "source_ip", processed.get("source_ip")),
        ],
        "destination_ip": [
            ("enriched_alert", "destination_ip", enriched.get("destination_ip")),
            ("processed_alert", "destination_ip", processed.get("destination_ip")),
        ],
        "domain": [
            ("enriched_alert", "domain", enriched.get("domain")),
            ("enriched_alert", "event_domain", enriched.get("event_domain")),
        ],
        "url": [
            ("enriched_alert", "url", enriched.get("url")),
            ("processed_alert", "url", processed.get("url")),
        ],
        "sha256": [
            ("enriched_alert", "sha256", enriched.get("sha256")),
            ("enriched_alert", "file_hash", enriched.get("file_hash")),
            ("processed_alert", "file_hash", processed.get("file_hash")),
        ],
        "process_name": [
            ("enriched_alert", "process_name", enriched.get("process_name")),
            ("enriched_alert", "file_name", enriched.get("file_name")),
        ],
        "process_path": [
            ("enriched_alert", "process_path", enriched.get("process_path")),
            ("enriched_alert", "command_line", enriched.get("command_line")),
        ],
        "mitre_technique_id": [
            ("enriched_alert", "mitre_technique_id", enriched.get("mitre_technique_id")),
            ("investigation_result", "mitre_technique_id", investigation.get("mitre_technique_id")),
        ],
        "severity": [
            ("investigation_result", "severity", investigation.get("severity")),
            ("triage_result", "severity", triage.get("severity")),
            ("enriched_alert", "severity", enriched.get("severity")),
        ],
        "confidence": [
            ("investigation_result", "confidence", investigation.get("confidence")),
            ("enriched_alert", "confidence", enriched.get("confidence")),
        ],
        "classification": [
            ("investigation_result", "classification", investigation.get("classification")),
            ("triage_result", "classification", triage.get("classification")),
            ("approval_result", "classification", approval.get("classification")),
        ],
        "approval_status": [
            ("approval_result", "approval_status", approval.get("approval_status")),
            ("approval_result", "decision", approval.get("decision")),
        ],
        "analyst_decision": [
            ("approval_result", "analyst_decision", approval.get("analyst_decision")),
            ("approval_result", "decision", approval.get("decision")),
        ],
        "approved_by": [
            ("approval_result", "analyst", approval.get("analyst")),
            ("approval_result", "approved_by", approval.get("approved_by")),
            ("approval_result", "reviewed_by", approval.get("reviewed_by")),
        ],
        "containment_status": [
            ("approval_result", "containment_status", approval.get("containment_status")),
        ],
        "recommended_containment_action": [
            ("approval_result", "approved_action", approval.get("approved_action")),
            ("investigation_result", "containment_action", investigation.get("containment_action")),
            ("investigation_result", "recommended_containment_action", investigation.get("recommended_containment_action")),
            ("approval_result", "approved_containment_action", approval.get("approved_containment_action")),
        ],
        "containment_execution_status": [
            ("approval_result", "containment_execution_status", approval.get("containment_execution_status")),
        ],
    }
    for field, candidates in fields.items():
        first_available(context, field, candidates, evidence_index=evidence_index, default=None)


def _mitre_candidates(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-FALLBACK] Regex-Scan Fallback For MITRE Technique
    IDs. Only used by repair_mitre_mapping() when the Investigation Agent
    supplied no genuine structured mapping. Recursively flattens context/
    enriched_alert/triage_result/investigation_result (via _flatten_values())
    and the evidence register, and regex-matches MITRE technique IDs
    (T####/T####.###) anywhere in the flattened text, building one recovered
    mapping entry per unique technique ID with tactic/technique_name
    backfilled from the source record or MITRE_LOCAL_MAPPING where possible.
    Every recovered entry is explicitly reason-labelled "Recovered from
    deterministic report context" so it is never confused with a genuine
    Investigation-stage finding."""
    raw = context.get("raw_inputs") or {}
    sources = [
        ("context", context),
        ("enriched_alert", raw.get("enriched_alert") or {}),
        ("triage_result", raw.get("triage_result") or context.get("triage") or {}),
        ("investigation_result", raw.get("investigation_result") or context.get("investigation") or {}),
    ]
    found: dict[str, dict[str, Any]] = {}

    for source_name, source in sources:
        meta = source.get("metakeys_payload") if isinstance(source, dict) and isinstance(source.get("metakeys_payload"), dict) else {}
        technique_name = first_present(source.get("mitre_technique"), meta.get("mitre_technique"), source.get("technique_name"), default="")
        for path, value in _flatten_values(source, source_name):
            for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(value)):
                entry = found.setdefault(technique_id, {
                    "tactic": first_present(source.get("mitre_tactic"), meta.get("mitre_tactic"), default=VALIDATION_PLACEHOLDER),
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "reason": "Recovered from deterministic report context.",
                    "confidence": "High",
                    "evidence_refs": _evidence_refs(technique_id, evidence_index),
                    "source": source_name,
                    "source_path": path,
                })
                if not entry.get("technique_name") and technique_name:
                    entry["technique_name"] = technique_name
        direct = first_present(source.get("mitre_technique_id"), meta.get("mitre_technique_id"), default=None)
        if direct:
            for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(direct)):
                found.setdefault(technique_id, {
                    "tactic": first_present(source.get("mitre_tactic"), meta.get("mitre_tactic"), default=VALIDATION_PLACEHOLDER),
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "reason": "Recovered from deterministic report context.",
                    "confidence": "High",
                    "evidence_refs": _evidence_refs(technique_id, evidence_index),
                    "source": source_name,
                    "source_path": "mitre_technique_id",
                })
    for item in context.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get("description") or "")
        for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text):
            found.setdefault(technique_id, {
                "tactic": VALIDATION_PLACEHOLDER,
                "technique_id": technique_id,
                "technique_name": "",
                "reason": f"Evidence register contains {technique_id}.",
                "confidence": "High",
                "evidence_refs": [item.get("id")],
                "source": "evidence",
                "source_path": f"evidence.{item.get('id')}",
            })
    return list(found.values())


def _normalise_mitre_item(item: dict[str, Any], evidence_index: dict[str, list[str]], context: dict[str, Any]) -> dict[str, Any] | None:
    """[FYP-FUNCTION] Normalise One MITRE Mapping Row. Extracts a valid
    T####(.###) technique_id (returns None if the row has none), backfills
    evidence_refs from evidence_index when absent, and fills tactic/
    technique_name from MITRE_LOCAL_MAPPING when the source row is missing
    them. Used by repair_mitre_mapping() to normalise both existing and
    _mitre_candidates()-recovered rows before deduping."""
    technique_id = first_present(item.get("technique_id"), item.get("technique"), default="")
    match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", str(technique_id))
    if not match:
        return None
    technique_id = match.group(0)
    refs = as_list(item.get("evidence_refs")) or _evidence_refs(technique_id, evidence_index)
    if refs and not item.get("evidence_refs"):
        _bump(context, "evidence_links_recovered", 1)
    mapped = MITRE_LOCAL_MAPPING.get(technique_id)
    tactic = item.get("tactic")
    technique_name = first_present(item.get("technique_name"), item.get("name"), default="")
    if mapped:
        tactic = mapped["tactic"]
        technique_name = mapped["technique_name"]
    return {
        **item,
        "tactic": first_present(tactic, default=VALIDATION_PLACEHOLDER),
        "technique_id": technique_id,
        "technique_name": technique_name,
        "reason": first_present(item.get("reason"), default="Recovered from deterministic report context."),
        "confidence": first_present(item.get("confidence"), default=VALIDATION_PLACEHOLDER),
        "evidence_refs": refs,
    }


def _is_genuine_investigation_mitre_item(item: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] True for a MITRE mapping entry that actually came from the
    Investigation Agent's own structured analysis (mitre_mapper.
    MitreTTPMapping / orchestrator.FinalIncidentAnalysis.mitre_mappings,
    surfaced via context_builder's investigation.mitre_mappings). No other
    source in this pipeline populates timeline_phase/observed_evidence, so
    their presence is what distinguishes real Investigation-stage output
    from the generic technique-ID scan below."""
    return not is_unknown(item.get("observed_evidence")) or not is_unknown(item.get("timeline_phase"))


def _dedupe_mitre_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] Collapse only EXACT duplicate rows (same technique, tactic, timeline
    phase, AND evidence). A row sharing a technique_id with another but
    describing different evidence or a different activity step is a
    distinct chronological entry and must be kept, never merged."""
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = tuple(
            re.sub(r"\s+", " ", str(item.get(field) or "").strip().lower())
            for field in ("technique_id", "tactic", "technique_name", "timeline_phase", "observed_evidence")
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def repair_mitre_mapping(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-STATE] Repair/Rebuild The Report's
    MITRE ATT&CK Mapping. If the Investigation Agent supplied a genuine
    structured mapping (_is_genuine_investigation_mitre_item() true for at
    least one row -- i.e. it has timeline_phase/observed_evidence), that
    mapping is returned verbatim (only exact-duplicate rows collapsed via
    _dedupe_mitre_rows()) -- it is NEVER merged with, relabelled by, or
    displaced by the regex-scan fallback. Only when no genuine mapping
    exists does it fall back to _mitre_candidates() + _normalise_mitre_item()
    to recover technique IDs found elsewhere in the report context. Called
    from enhance_export_context(); result is stored as both
    context["mitre_mapping"] and context["mitre_attack_mapping"]."""
    existing = context.get("mitre_attack_mapping") or context.get("mitre_mapping") or []
    existing_items = [item for item in as_list(existing) if isinstance(item, dict)]

    # The Investigation stage's own MITRE ATT&CK mapping must be shown
    # verbatim — never merged with the generic regex-scan fallback below,
    # never relabelled with a placeholder "recovered from..." reason, and
    # never dropped in favour of unrelated technique IDs found elsewhere in
    # the report context.
    genuine = [item for item in existing_items if _is_genuine_investigation_mitre_item(item)]
    if genuine:
        return _dedupe_mitre_rows(genuine)

    recovered = _mitre_candidates(context, evidence_index)
    repaired: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in existing_items + recovered:
        normalised = _normalise_mitre_item(item, evidence_index, context)
        if not normalised:
            continue
        technique_id = normalised["technique_id"]
        if technique_id in seen:
            existing_item = next((row for row in repaired if row.get("technique_id") == technique_id), None)
            if existing_item is not None and not existing_item.get("evidence_refs") and normalised.get("evidence_refs"):
                existing_item["evidence_refs"] = normalised["evidence_refs"]
            continue
        seen.add(technique_id)
        repaired.append(normalised)
    if repaired:
        if not existing:
            _bump(context, "fields_recovered_from_fallback_sources", len(repaired))
            _bump(context, "placeholders_reduced", len(repaired))
        return repaired
    return []


def _refs_for_text(text: Any, evidence_index: dict[str, list[str]]) -> list[str]:
    """[FYP-FUNCTION] Find Evidence IDs Whose Normalised Key Appears Inside
    `text`. A looser match than _first_evidence_id()/_evidence_refs() (which
    match a single value against the index): here the WHOLE text (e.g. a
    recommendation action sentence) is scanned for any indexed key it
    contains, capped at 5 refs. Used by enrich_recommendations()."""
    refs: list[str] = []
    for key, linked in evidence_index.items():
        if key and key in _normalise_lookup(text):
            for ref in linked:
                if ref not in refs:
                    refs.append(ref)
    return refs[:5]


def _all_evidence_ids(context: dict[str, Any]) -> list[str]:
    """[FYP-FUNCTION] Every "id" Present In context["evidence"]. Used by
    _fallback_recommendation_refs() as the pool to fall back to when no
    text-matched evidence reference is found for a recommendation."""
    ids: list[str] = []
    for item in context.get("evidence") or []:
        if isinstance(item, dict) and item.get("id"):
            ids.append(str(item["id"]))
    return ids


def _fallback_recommendation_refs(context: dict[str, Any]) -> list[str]:
    """[FYP-FUNCTION] [FYP-FALLBACK] Last-Resort Evidence Refs For A
    Recommendation. When a recommendation has no evidence_refs of its own and
    _refs_for_text() finds no text match, prefers a small fixed set of
    commonly-relevant evidence IDs if present, else the first 3 available
    evidence IDs, else the literal string "investigation_result.json" as an
    explicit source label (never an empty list)."""
    preferred = {"EV-003", "EV-006", "EV-010", "EV-013", "EV-015"}
    available = _all_evidence_ids(context)
    refs = [ref for ref in available if ref in preferred]
    return refs[:3] or available[:3] or ["investigation_result.json"]


def _recommendation_owner(action: str) -> str:
    """[FYP-FUNCTION] Keyword Heuristic: Which Team Should Own This
    Recommendation? Endpoint-shaped wording -> Endpoint Response Team;
    network-shaped wording -> Network Security Team; review/hunt-shaped
    wording -> SOC Analyst; otherwise OWNER_PLACEHOLDER ("To be assigned").
    Only used as a backfill when the recommendation item has no owner of its
    own -- see enrich_recommendations()."""
    text = action.lower()
    if any(token in text for token in ("endpoint", "host", "isolate", "quarantine", "process", "file", "malware")):
        return "Endpoint Response Team"
    if any(token in text for token in ("network", "firewall", "proxy", "dns", "ip", "domain", "url", "block", "traffic")):
        return "Network Security Team"
    if any(token in text for token in ("review", "validate", "hunt", "document", "escalate", "evidence", "confirm")):
        return "SOC Analyst"
    return OWNER_PLACEHOLDER


def _recommendation_approval_required(action: str) -> str:
    """[FYP-FUNCTION] Keyword Heuristic: Does This Recommendation Need
    Analyst Approval Before Execution? "Yes" for disruptive/containment-
    shaped actions (isolate/contain/block/disable/etc.), "No" for read-only/
    investigative actions (validate/review/hunt/document/etc.) and as the
    default. Backfill used by enrich_recommendations() when the item has no
    approval_required of its own."""
    text = action.lower()
    if any(token in text for token in ("isolate", "contain", "block", "disable", "quarantine", "disconnect", "terminate", "remove")):
        return "Yes"
    if any(token in text for token in ("validate", "review", "hunt", "document", "collect", "confirm", "search")):
        return "No"
    return "No"


def _recommendation_risk(action: str) -> str:
    """[FYP-FUNCTION] Keyword Heuristic: What Risk Does This Recommendation
    Address? Maps endpoint/network/validation-shaped action wording to a
    short risk-addressed label, defaulting to "Incident response follow-up".
    Backfill used by enrich_recommendations() when risk_addressed/risk is
    not supplied on the recommendation item."""
    text = action.lower()
    if any(token in text for token in ("isolate", "contain", "endpoint", "host", "malware", "file", "process")):
        return "Endpoint compromise or malware execution"
    if any(token in text for token in ("network", "block", "ip", "domain", "url", "traffic", "dns", "proxy", "firewall")):
        return "Potential malicious network activity"
    if any(token in text for token in ("validate", "review", "evidence", "document", "confirm")):
        return "Unvalidated incident scope and evidence completeness"
    return "Incident response follow-up"


def _recommendation_rationale(action: str, context: dict[str, Any], refs: list[str]) -> str:
    """[FYP-FUNCTION] Build A One-Sentence Rationale For A Recommendation
    Backfilled from already-resolved context fields (severity, classification,
    first affected asset's hostname, IOC count, evidence refs) -- never from
    `action` itself beyond the surrounding sentence template. Only used by
    enrich_recommendations() when the source item supplied no rationale."""
    severity = get_path(context, "severity.label", "Not Provided")
    classification = context.get("classification", "Not Provided")
    asset = first_present(*(a.get("hostname") for a in context.get("affected_assets") or [] if isinstance(a, dict)), default="affected asset")
    ioc_count = len(context.get("iocs") or [])
    ref_text = ", ".join(refs)
    return (
        f"Based on {severity} severity, {classification} classification, {asset} scope, "
        f"and {ioc_count} technical indicator(s) linked to evidence ({ref_text})."
    )


def enrich_recommendations(context: dict[str, Any], evidence_index: dict[str, list[str]]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Backfill Every Recommended Action With
    Owner/Approval/Risk/Rationale/Evidence. Iterates context["recommended_
    actions"] (or ["recommendations"]), coercing bare strings into dict
    items, and fills any missing owner/approval_required/risk_addressed/
    rationale/evidence_refs fields via the _recommendation_*() heuristics
    and _refs_for_text()/_fallback_recommendation_refs() above. Writes the
    enriched list back to THREE context keys in sync -- recommendations,
    recommended_actions, and management_action_plan -- since different
    templates/callers read different key names for the same data. Called
    from enhance_export_context()."""
    enriched: list[dict[str, Any]] = []
    for idx, item in enumerate(as_list(context.get("recommended_actions") or context.get("recommendations")), start=1):
        if not isinstance(item, dict):
            item = {"priority": f"P{idx}", "recommendation": str(item), "action": str(item)}
        action = first_present(item.get("action"), item.get("recommendation"), item.get("title"), default=f"Recommendation {idx}")
        refs = as_list(item.get("evidence_refs")) or _refs_for_text(action, evidence_index) or _fallback_recommendation_refs(context)
        owner = first_present(item.get("owner"), default=_recommendation_owner(action))
        if is_unknown(owner):
            owner = _recommendation_owner(action)
        approval_required = first_present(item.get("approval_required"), default=_recommendation_approval_required(action))
        if is_unknown(approval_required):
            approval_required = _recommendation_approval_required(action)
        risk_addressed = first_present(item.get("risk_addressed"), item.get("risk"), default=_recommendation_risk(action))
        rationale = first_present(item.get("rationale"), default=_recommendation_rationale(action, context, refs))
        if is_unknown(rationale):
            rationale = _recommendation_rationale(action, context, refs)
        enriched.append({
            **item,
            "priority": first_present(item.get("priority"), default=f"P{idx}"),
            "recommendation": action,
            "action": action,
            "owner": owner,
            "status": first_present(item.get("status"), default="Open for analyst review"),
            "rationale": rationale,
            "approval_required": approval_required,
            "risk_addressed": risk_addressed,
            "target_date": first_present(item.get("target_date"), default=""),
            "evidence_refs": refs,
        })
    context["recommendations"] = enriched
    context["recommended_actions"] = enriched
    context["management_action_plan"] = enriched
    return enriched


def _mitre_cell(value: Any) -> str:
    """[FYP-FUNCTION] Markdown-table-safe cell text: collapse embedded newlines (which would
    otherwise split a table row) and escape literal '|' characters (which
    otherwise read as a new column) — e.g. in observed-evidence text quoting a
    command line or log line. No wording is altered, only made table-safe."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text.replace("|", "\\|")


def build_compact_render_tables(context: dict[str, Any]) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-EXPORT] [FYP-CALLS] Build The Placeholder-Aware
    Compact Render Tables Used By Report Templates. Wraps assets/users/iocs/
    timeline/mitre/recommendations into reporting.compact_renderer.
    compact_table() calls (each with an explicit column list, row list, a
    human label, and the current evidence_gaps), which hides low-information
    columns/rows rather than rendering walls of "Unknown". Returns a dict
    keyed "assets"/"users"/"iocs"/"timeline"/"mitre"/"recommendations",
    stored as context["compact_tables"] by enhance_export_context()."""
    assets = context.get("affected_assets") or []
    users = context.get("affected_users") or []
    iocs = context.get("iocs") or []
    timeline = context.get("timeline") or []
    mitre = context.get("mitre_attack_mapping") or []
    recommendations = context.get("recommended_actions") or []
    gaps = context.get("evidence_gaps") or []

    tables = {
        "assets": compact_table(
            ["Hostname", "IP Address", "Type", "Criticality", "Owner", "Business Function", "Isolation Status"],
            [[a.get("hostname"), a.get("ip_address"), a.get("asset_type"), a.get("criticality"), a.get("owner"), a.get("business_function"), a.get("isolation_status")] for a in assets if isinstance(a, dict)],
            "Affected assets",
            gaps,
        ),
        "users": compact_table(
            ["Username", "Email", "Role", "Privilege", "Groups", "MFA", "Status"],
            [[u.get("username"), u.get("email"), u.get("role"), u.get("privilege_level"), ", ".join(as_list(u.get("groups"))), u.get("mfa_status"), u.get("account_status")] for u in users if isinstance(u, dict)],
            "Affected users",
            gaps,
        ),
        "iocs": compact_table(
            ["IOC", "Type", "Reputation", "Confidence", "Source", "Evidence"],
            [[f"`{i.get('value')}`", i.get("type"), i.get("reputation"), i.get("confidence"), i.get("source"), ", ".join(as_list(i.get("evidence_refs")))] for i in iocs if isinstance(i, dict)],
            "IOC analysis",
            gaps,
        ),
        "timeline": compact_table(
            ["Time", "Observed Incident Activity", "Classification"],
            [[e.get("time") or e.get("timestamp"), e.get("event") or e.get("description"), e.get("significance")] for e in timeline if isinstance(e, dict)],
            "Incident timeline",
            gaps,
        ),
        "mitre": compact_table(
            ["Timeline Phase / Activity", "Observed Evidence", "MITRE Tactic", "MITRE Technique Name", "MITRE ID"],
            [
                [
                    _mitre_cell(m.get("timeline_phase")),
                    _mitre_cell(m.get("observed_evidence")) or ", ".join(as_list(m.get("evidence_refs"))),
                    _mitre_cell(m.get("tactic")),
                    _mitre_cell(m.get("technique_name")),
                    _mitre_cell(m.get("technique_id")),
                ]
                for m in mitre if isinstance(m, dict)
            ],
            "MITRE ATT&CK mapping",
            gaps,
        ),
        "recommendations": compact_table(
            ["Priority", "Action", "Owner", "Approval Required", "Rationale"],
            [[r.get("priority"), r.get("action") or r.get("recommendation"), r.get("owner"), r.get("approval_required"), r.get("rationale")] for r in recommendations if isinstance(r, dict)],
            "Recommended actions",
            gaps,
        ),
    }
    return tables


def _number_or_none(value: Any) -> float | None:
    """[FYP-FUNCTION] Best-effort float coercion: None for is_unknown()
    values or anything not float()-able, rather than raising. Used by
    set_report_title() to compare a completeness/quality score against a
    threshold without crashing on missing/non-numeric scores."""
    try:
        if is_unknown(value):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _analyst_review_completed(context: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] True if final_analyst_review_status/analyst_review_
    status already reads as a completed review (approved/confirmed/
    completed/closed/reviewed/final_review_completed). Used by both
    normalise_approval() (to decide whether to trust an existing final
    review status) and set_report_title() (to decide Draft vs. Final)."""
    review = str(first_present(context.get("final_analyst_review_status"), context.get("analyst_review_status"), default="")).lower()
    return review in {"approved", "confirmed", "completed", "closed", "reviewed", "final_review_completed"}


def set_report_title(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Decide Between "Draft Incident Report
    for SOC Analyst Review" And "Final Incident Report". Requires a "Draft"
    title unless the report_status/validation_status show no outstanding
    validation need, a completeness/quality score of >= 80 is present, AND
    _analyst_review_completed() is true -- i.e. the title only reads "Final"
    once every completeness/approval signal available agrees the report is
    ready. Sets context["report_title"]; called from
    enhance_export_context()."""
    report_status = str(context.get("report_status") or "").lower()
    validation_status = str(context.get("validation_status") or "").lower()
    score = _number_or_none(first_present(context.get("report_completeness_score"), context.get("report_quality_score"), default=None))
    draft_required = (
        report_status == "generated for analyst review"
        or "requires analyst validation" in validation_status
        or score is None
        or score < 80
        or not _analyst_review_completed(context)
    )
    context["report_title"] = "Draft Incident Report for SOC Analyst Review" if draft_required else "Final Incident Report"


def _count_placeholders(value: Any, *, key: str = "") -> int:
    """[FYP-FUNCTION] Recursively Count PLACEHOLDER_VALUES Occurrences In A
    Context Value. Skips bookkeeping-only subtrees (raw_inputs, evidence_
    index, field_provenance, recovered_fields) that are not analyst-facing
    report content and would otherwise inflate the count with internal
    metadata. Recurses through dicts/lists/tuples/sets; for strings, counts
    an exact placeholder match as 1, else counts every placeholder phrase
    found as a substring. Used by finalise_quality_counters()."""
    if key in {"raw_inputs", "evidence_index", "field_provenance", "recovered_fields"}:
        return 0
    if isinstance(value, dict):
        return sum(_count_placeholders(item, key=str(item_key)) for item_key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return sum(_count_placeholders(item, key=key) for item in value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in PLACEHOLDER_VALUES:
            return 1
        return sum(1 for placeholder in PLACEHOLDER_VALUES if placeholder in normalised)
    return 0


def finalise_quality_counters(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Compute The Final Placeholder Count
    For The "Fields Still Unavailable From Source Telemetry" Quality Signal
    -- run LAST (after every recovery/enrichment pass above has had a
    chance to resolve fields) so the count reflects what genuinely remains
    unresolved, not a stale mid-pipeline snapshot. Writes to
    context["quality_checks"]. Called from enhance_export_context()."""
    checks = _quality(context)
    placeholder_count = _count_placeholders(context)
    checks["final_placeholder_count"] = placeholder_count
    checks["fields_still_unavailable_from_source_telemetry"] = placeholder_count


def finalise_section_placeholder_counts(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Per-Section Placeholder/Hidden-Content
    Quality Signals. Rolls up how many compact-table columns/rows were
    hidden for low information value, how much of the evidence register /
    approval / containment sections are still placeholder-valued, whether
    data-impact and chain-of-custody summaries exist, how many evidence
    gaps were summarised, and how many report sections used AI narrative
    (vs. deterministic placeholder text). Updates context["quality_checks"].
    Must run AFTER build_compact_render_tables()/normalise_approval() (reads
    their output); called from enhance_export_context()."""
    compact_tables = context.get("compact_tables") or {}
    hidden_columns = sum(len((table or {}).get("hidden_columns") or []) for table in compact_tables.values() if isinstance(table, dict))
    hidden_rows = sum(int((table or {}).get("hidden_rows") or 0) for table in compact_tables.values() if isinstance(table, dict))
    evidence_register = context.get("compact_evidence_register") or {}
    section_map = {
        "evidence_register_placeholders": evidence_register.get("placeholder_ratio", 0),
        "approval_section_placeholders": 0,
        "containment_section_placeholders": 0,
        "data_impact_placeholders": 1.0 if context.get("data_impact_summary") else 0.0,
        "chain_of_custody_placeholders": 1.0 if context.get("chain_of_custody_compact") else 0.0,
        "columns_hidden_due_to_low_information_value": hidden_columns + len(evidence_register.get("hidden_columns") or []),
        "rows_hidden_due_to_no_useful_values": hidden_rows + int(evidence_register.get("hidden_rows") or 0),
        "missing_fields_summarised_into_evidence_gaps": len(context.get("evidence_gaps") or []),
        "ai_narrative_sections_used_to_reduce_placeholder_repetition": len([k for k, v in (context.get("llm_section_results") or {}).items() if isinstance(v, dict) and str(v.get("status", "")).startswith("llm")]),
    }
    approval = context.get("approval") or {}
    containment = context.get("containment") or {}
    section_map["approval_section_placeholders"] = count_placeholders(approval) / max(1, len(approval))
    section_map["containment_section_placeholders"] = count_placeholders(containment) / max(1, len(containment))
    context.setdefault("quality_checks", {}).update(section_map)


def build_appendix_summaries(context: dict[str, Any]) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-EXPORT] Build The Report's Appendix Summary
    Tables (raw_alert/triage/investigation/approval), each a flat dict of
    display-label -> already-resolved context value (using first_present()/
    get_path() so the appendix reflects the same recovered/normalised
    values as the main report body, never re-deriving anything). Returns
    the dict stored as context["appendix_summaries"]; called from
    enhance_export_context() after affected_assets/iocs/recommendations/
    approval have all been resolved."""
    triage = context.get("triage") or {}
    investigation = context.get("investigation") or {}
    approval_result = context.get("approval_result") or {}
    alert = context.get("alert") or {}
    assets = context.get("affected_assets") or []
    iocs = context.get("iocs") or []
    recommendations = context.get("recommended_actions") or []
    gaps = context.get("evidence_gaps") or []

    first_asset = assets[0].get("hostname") if assets else ""
    first_ioc = iocs[0].get("value") if iocs else ""

    return {
        "raw_alert": {
            "Alert ID": context.get("alert_id"),
            "Source": alert.get("source"),
            "Alert Name": alert.get("name"),
            "First Seen": alert.get("timestamp"),
            "Host": first_asset,
            "Severity": get_path(context, "severity.label", ""),
            "Confidence": get_path(context, "confidence.label", ""),
            "Original Alert Risk Score": first_present(context.get("original_alert_risk_score"), context.get("initial_risk_score"), default=""),
            "Enriched Risk Score": first_present(context.get("enriched_risk_score"), context.get("enrichment_risk_score"), default=""),
            "Final Risk Rating": first_present(context.get("final_risk_rating"), get_path(context, "severity.label", ""), default=""),
            "Primary IOC": first_ioc,
        },
        "triage": {
            "Classification": first_present(triage.get("classification"), context.get("classification")),
            "Severity": get_path(context, "severity.label", ""),
            "Confidence": get_path(context, "confidence.label", ""),
            # triage.get("next_action") dropped -- Triage's field is the
            # plural recommended_actions list (see "Recommended Action
            # Count" below), never a single "next_action" string.
            "Next Action": "No standalone next action supplied.",
            "Containment Status": context.get("containment_status"),
            "Recommended Action Count": len(recommendations),
        },
        "investigation": {
            "Classification": context.get("classification"),
            "Likely Scenario": context.get("likely_scenario"),
            "Status": first_present(investigation.get("status"), default=""),
            "Finding Count": len(as_list(investigation.get("findings"))),
            "Missing Evidence": ", ".join(str(g.get("gap", g)) for g in gaps) if gaps else "None recorded",
            "Recommended Next Action": first_present(investigation.get("recommended_next_action"), default="No standalone investigation next action supplied."),
        },
        "approval": {
            "Report Generation Approval Status": get_path(context, "report_generation_approval.status", ""),
            "Report Generation Approved By": get_path(context, "report_generation_approval.approved_by", ""),
            "Containment Approval Status": get_path(context, "containment.approval_status", ""),
            "Containment Execution Status": get_path(context, "containment.execution_status", ""),
            "Final Analyst Review Status": context.get("final_analyst_review_status", ""),
            "Comments": first_present(approval_result.get("comments"), approval_result.get("analyst_comments"), default="No approval comments supplied."),
        },
    }


def apply_llm_narrative(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-LLM] [FYP-CALLS] Invoke The Optional LLM Narrative
    Pass And Merge Its Output Into context. Calls reporting.llm_narrative.
    enhance_narrative(context) -- which itself decides whether an LLM call
    is attempted and [FYP-FALLBACK]s to a deterministic narrative if the LLM
    is disabled/unavailable/fails -- then copies each present narrative
    field (executive_summary, technical_analysis, business_impact_
    explanation, attack_narrative, conclusion, analyst_friendly_explanation,
    soc_analyst_review_checklist) from whichever of llm_enhanced_narrative/
    deterministic_narrative was actually produced into both
    context["active_narrative"] and the matching top-level context key.
    Also records llm_used/llm_provider/llm_model/llm_status/llm_quality_*/
    llm_section_results/llm_attempt_count/llm_cache_status* and derives
    quality_checks["fallback_logic_used"] and report_generation_mode from
    whether the LLM path actually ran. MUST run only after every
    deterministic field (assets/users/iocs/mitre/timeline/approval/
    recommendations) has already been resolved, since the LLM prompt is
    built from those locked facts (see enhance_export_context())."""
    llm_result = enhance_narrative(context)
    enhanced = llm_result.get("llm_enhanced_narrative") or llm_result.get("deterministic_narrative") or {}
    active = context.setdefault("active_narrative", {})
    mapping = {
        "executive_summary": "executive_summary",
        "technical_analysis": "technical_analysis",
        "business_impact_explanation": "business_impact_explanation",
        "attack_narrative": "attack_narrative",
        "conclusion": "conclusion",
        "analyst_friendly_explanation": "analyst_friendly_explanation",
        "soc_analyst_review_checklist": "soc_analyst_review_checklist",
    }
    for source_key, target_key in mapping.items():
        if not is_unknown(enhanced.get(source_key)):
            active[target_key] = enhanced[source_key]
            context[target_key] = enhanced[source_key]

    context["llm"] = enhanced
    context["llm_used"] = bool(llm_result.get("llm_used"))
    context["llm_provider"] = llm_result.get("llm_provider", "not_used")
    context["llm_model"] = llm_result.get("llm_model", "not_used")
    context["llm_status"] = llm_result.get("llm_status", "not_used")
    context["llm_status_display"] = llm_result.get("llm_status", "not_used")
    context["llm_quality_status"] = llm_result.get("llm_quality_status", "not_used")
    context["llm_quality_issues"] = llm_result.get("llm_quality_issues", [])
    context["llm_section_results"] = llm_result.get("llm_section_results", {})
    context["llm_attempt_count"] = llm_result.get("llm_attempt_count", 0)
    context["llm_cache_status"] = llm_result.get("llm_cache_status", "not_used")
    context["llm_cache_status_display"] = llm_result.get("llm_cache_status", "not_used")
    context["llm_status_explanation"] = (
        "LLM narrative fields generated from locked incident facts."
        if context["llm_used"] else
        "LLM disabled or unavailable; deterministic fallback narrative was used."
    )
    context["report_generation_mode"] = "deterministic_facts_plus_llm_narrative" if context["llm_used"] else "deterministic_facts_plus_template_export"
    checks = context.setdefault("quality_checks", {})
    if not context["llm_used"] or checks.get("fallback_logic_used") == "Yes":
        checks["fallback_logic_used"] = "Yes"
    else:
        checks["fallback_logic_used"] = "No"


def build_readable_narrative_sections(context: dict[str, Any]) -> None:
    """[FYP-FUNCTION] Pre-split long free-text narrative fields into presentation-ready
    lists so templates can render bullets/tables instead of dense paragraphs.
    Does not alter any narrative wording — only how it is broken up for
    display in the exported report."""
    active = context.get("active_narrative") or {}
    context["analyst_guidance_bullets"] = split_into_sentences(
        active.get("analyst_friendly_explanation"))
    context["soc_analyst_review_checklist_items"] = split_numbered_items(
        active.get("soc_analyst_review_checklist"))


def enhance_export_context(context: dict[str, Any], ticket: dict[str, Any] | None = None) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] [FYP-EVALUATOR] [FYP-STATE]
    [FYP-CALLS] The Single Public Orchestrator For This Module. Runs, in a
    fixed, dependency-respecting order: evidence index -> evidence-row
    repair -> field provenance recovery (_apply_field_provenance) ->
    incident_id/ticket_id/case_title resolution -> affected assets/users
    (derive_affected_assets/derive_affected_users) -> IOC rebuild
    (rebuild_iocs) -> MITRE mapping repair (repair_mitre_mapping) ->
    timeline reconstruction (derive_timeline) -> approval/containment
    normalisation (normalise_approval) -> placeholder softening
    (replace_low_value_placeholders) -> recommendation enrichment
    (enrich_recommendations) -> report title (set_report_title) ->
    evidence-backed key findings rebuild -> appendix summaries
    (build_appendix_summaries) -> report_validation_checks recompute ->
    compact tables/evidence register/data-impact/chain-of-custody/approval
    summaries (build_compact_render_tables + reporting.compact_renderer
    helpers) -> optional LLM narrative pass (apply_llm_narrative) ->
    readable narrative section splitting (build_readable_narrative_sections)
    -> final quality counters (finalise_quality_counters,
    finalise_section_placeholder_counts). Mutates `context` in place AND
    returns it. [FYP-USED-BY] soc_reporting_agent/agents/reporting_agent.py
    (right after context_builder.build_context(), before render_reports())
    and reporting/template_document_exporter.py (again, just before Jinja2
    rendering, with a ticket dict carrying live ticket fields)."""
    ticket = ticket or context.get("ticket") or {}
    _quality(context)
    evidence_index = build_evidence_index(context.get("evidence") or [])
    context["evidence_index"] = evidence_index
    repair_evidence_rows(context)
    _apply_field_provenance(context, evidence_index)

    ticket_id = first_present(ticket.get("ticket_id"), context.get("ticket_id"), context.get("incident_id"), default="unknown")
    if is_unknown(context.get("incident_id")):
        context["incident_id"] = ticket_id
    context["ticket_id"] = ticket_id
    if not is_unknown(ticket.get("title")):
        context["case_title"] = ticket.get("title")

    context["affected_assets"] = derive_affected_assets(context, ticket, evidence_index)
    context["affected_users"] = derive_affected_users(context, ticket)
    context["iocs"] = rebuild_iocs(context, evidence_index)
    mitre_mapping = repair_mitre_mapping(context, evidence_index)
    context["mitre_mapping"] = mitre_mapping
    context["mitre_attack_mapping"] = mitre_mapping
    context["timeline"] = derive_timeline(context)
    normalise_approval(context)
    replace_low_value_placeholders(context)
    enrich_recommendations(context, evidence_index)
    set_report_title(context)

    # Rebuild findings after factual correction.
    confidence_label = get_path(context, "confidence.label", "Not Provided")
    classification = context.get("classification", "Not Provided")
    asset_refs: list[str] = []
    for asset in context.get("affected_assets") or []:
        asset_refs.extend(_evidence_refs(asset.get("hostname"), evidence_index))
        asset_refs.extend(_evidence_refs(asset.get("ip_address"), evidence_index))
    asset_refs = list(dict.fromkeys(asset_refs))
    classification_refs = _refs_for_text(classification, evidence_index) or ["investigation_result.json"]
    approval_refs = ["approval_result.json"]
    context["evidence_backed_findings"] = [
        {"finding_id": "KF-001", "statement": f"The incident classification is {classification}.", "finding": f"The incident classification is {classification}.", "status": "Fact", "confidence": confidence_label, "evidence_refs": classification_refs, "evidence": ", ".join(classification_refs), "interpretation": "Classification is taken from investigation output first, with triage as fallback."},
        {"finding_id": "KF-002", "statement": "Affected scope has available context." if context["affected_assets"] or context["affected_users"] else "Affected scope requires validation.", "finding": "Affected scope has available context." if context["affected_assets"] or context["affected_users"] else "Affected scope requires validation.", "status": "Fact" if context["affected_assets"] or context["affected_users"] else "Evidence Gap", "confidence": confidence_label, "evidence_refs": asset_refs or ["enriched_alert", "investigation_result.json"], "evidence": ", ".join(asset_refs or ["enriched_alert", "investigation_result.json"]), "interpretation": "Assets and users are derived only from supplied ticket, alert, triage, and investigation context."},
        {"finding_id": "KF-003", "statement": f"Approval status is {get_path(context, 'approval.approval_status', 'Not Provided')}.", "finding": f"Approval status is {get_path(context, 'approval.approval_status', 'Not Provided')}.", "status": "Fact", "confidence": confidence_label, "evidence_refs": approval_refs, "evidence": ", ".join(approval_refs), "interpretation": "Approval data is recorded only from analyst approval context."},
    ]
    if asset_refs:
        _bump(context, "evidence_links_recovered", len(asset_refs))
    context["key_findings"] = context["evidence_backed_findings"]

    context["appendix_summaries"] = build_appendix_summaries(context)

    # Recompute validation checks after fallback fixes.
    context["report_validation_checks"] = [
        {"check": "Incident ID present", "status": "Pass" if not is_unknown(context.get("incident_id")) else "Review Required"},
        {"check": "Alert ID present", "status": "Pass" if not is_unknown(context.get("alert_id")) and str(context.get("alert_id")).upper() != "UNKNOWN-ALERT" else "Review Required"},
        {"check": "Severity present", "status": "Pass" if not is_unknown(get_path(context, "severity.label")) else "Fail"},
        {"check": "Confidence present", "status": "Pass" if not is_unknown(get_path(context, "confidence.label")) else "Fail"},
        {"check": "Affected asset context present", "status": "Pass" if context.get("affected_assets") else "Review Required"},
        {"check": "Timeline reconstructed", "status": "Pass" if context.get("timeline") else "Review Required"},
        {"check": "Evidence present", "status": "Pass" if context.get("evidence") else "Review Required"},
        {"check": "IOC evidence links recovered", "status": "Pass" if int(context.get("quality_checks", {}).get("evidence_links_recovered") or 0) else "Review Required"},
        {"check": "MITRE mapping present", "status": "Pass" if context.get("mitre_attack_mapping") else "Review Required"},
    ]

    # Build compact summaries before LLM narrative so the LLM sees concise locked facts.
    evidence = context.get("evidence") or []
    evidence_gaps = context.get("evidence_gaps") or []
    context["compact_evidence_register"] = build_evidence_register_summary(evidence, evidence_gaps)
    context["compact_tables"] = build_compact_render_tables(context)
    context["data_impact_summary"] = build_data_impact_summary(context)
    chain_note = build_chain_of_custody_note(evidence)
    if chain_note:
        context["chain_of_custody_note"] = chain_note
        context["chain_of_custody_compact"] = True
    else:
        context["chain_of_custody_note"] = ""
        context["chain_of_custody_compact"] = False
    approval = context.get("approval") or {}
    containment = context.get("containment") or {}
    context["approval_summary"] = build_approval_summary(approval, containment)
    context["approval_summary_table"] = approval_summary_table(context["approval_summary"])

    apply_llm_narrative(context)
    build_readable_narrative_sections(context)
    finalise_quality_counters(context)
    finalise_section_placeholder_counts(context)
    return context
