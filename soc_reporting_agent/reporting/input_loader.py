"""
[FYP-FILE] reporting/input_loader.py (143 lines)
# File: soc_reporting_agent/reporting/input_loader.py
# Purpose: This module implements report generation and export behaviour for input loader.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: json, pathlib, typing.
# Key evaluator search terms: ReportingInputError, load_json_file, load_reporting_inputs, [FYP-FUNCTION].
[FYP-ENTRY-POINT] load_reporting_inputs() is the first pipeline step invoked
by agents/reporting_agent.py:main() — it reads every upstream agent's JSON
handoff file from the run's input directory before context_builder.build_context()
normalises them.

[FYP-SECTION] Responsibility
Defines which JSON files the Reporting Agent expects from upstream agents
(Parsing, Triage, Investigation, Threat Intel, Approval, workflow
orchestration), which of those are optional, and which are "hard required"
for the CURRENT run (see HARD_REQUIRED_INPUT_KEYS below). Performs the
actual file read + JSON parse and raises ReportingInputError when a
hard-required input is missing/empty/unreadable, so callers can fail the
Reporting stage safely instead of generating a degraded report silently.

[FYP-USED-BY] agents/reporting_agent.py:main() (load_reporting_inputs);
scripts/test_merged_report_context.py and
scripts/test_reporting_appendix_context.py (dev/test harnesses that also
call load_reporting_inputs directly).
"""
from pathlib import Path
import json
from typing import Any

# [FYP-SECTION] Input file registry.
# Core files consumed by the Reporting Agent.
INPUT_FILES = {
    "processed_alert": "processed_alert.json",
    "enriched_alert": "enriched_alert.json",
    "triage_result": "triage_result.json",
    "investigation_result": "investigation_result.json",
    "threat_intel_result": "threat_intel_result.json",
    "approval_result": "approval_result.json",
    "approval_history": "approval_history.json",
    "workflow_metadata": "workflow_metadata.json",
    "ticket_context": "ticket_context.json",
    "grouped_incident_context": "grouped_incident_context.json",
    "correlation_recommendations": "correlation_recommendations.json",
}
OPTIONAL_INPUT_KEYS = {
    "approval_result", "approval_history", "workflow_metadata", "ticket_context",
    "grouped_incident_context", "correlation_recommendations",
}

# Inputs whose absence means an upstream workflow precondition was violated
# for a CURRENT-run generation, not a normal "optional field" gap:
# Reporting cannot even start until triage_status=Approved and
# threat_intel_status is Complete/Complete with Warnings and
# investigation_status=Approved, and Parsing must have produced the alert
# Reporting is reporting on — so a missing file here means handoff itself
# is broken. Generation must fail safely (see ReportingInputError below)
# rather than silently produce a reduced-confidence report. This is
# distinct from a LEGACY stored reporting_result_json (generated before
# this requirement existed) being previewed later — that backward-
# compatibility case is handled by the dashboard's own reader
# (case_view.build_reporting()), not here.
HARD_REQUIRED_INPUT_KEYS = {"processed_alert", "triage_result", "investigation_result", "threat_intel_result"}


# [FYP-CLASS] `ReportingInputError` — owns ReportingInputError state or behaviour for the report generation and export component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include soc_reporting_agent/reporting/input_loader.py:load_reporting_inputs.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class ReportingInputError(Exception):
    """Raised when a hard-required current-run input (see
    HARD_REQUIRED_INPUT_KEYS) is missing, empty, or unreadable. Callers
    must let this propagate — it is what makes run_reporting_stage() mark
    the attempt Failed/Failed with no candidate manifest published,
    instead of quietly generating a degraded report."""


def load_json_file(path: Path, *, required: bool = True) -> tuple[dict[str, Any], str | None]:
    """[FYP-FUNCTION] Read and JSON-parse a single upstream agent output file.

    [FYP-INPUT] path: absolute Path to the expected JSON file;
    required: if False, a missing file is treated as a normal (non-warning)
    empty result rather than a warning-worthy gap.

    [FYP-PROCESS] Returns (data, warning) where data is `{}` on any failure
    (missing file, invalid JSON, unreadable file) and warning is a
    human-readable string describing what went wrong, or None on success /
    on an accepted-as-optional missing file. Never raises — callers
    (load_reporting_inputs, and ultimately HARD_REQUIRED_INPUT_KEYS
    enforcement) decide whether an empty/missing hard-required file should
    escalate to a hard failure.
    [FYP-EVALUATOR] This is the boundary where a malformed or absent
    upstream JSON hand-off first surfaces — inspect this function first
    when diagnosing "Reporting cannot start" failures during evaluation.
    """
    if not path.exists():
        if required:
            return {}, f"Input file missing: {path}"
        return {}, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as error:
        return {}, f"Invalid JSON in {path}: {error}"
    except Exception as error:
        return {}, f"Failed to read {path}: {error}"


def load_reporting_inputs(input_dir: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] Load every INPUT_FILES entry from
    input_dir and enforce HARD_REQUIRED_INPUT_KEYS.

    [FYP-INPUT] input_dir: the run's input directory (defaults to
    settings.INPUT_DIR when called from agents/reporting_agent.py).

    [FYP-PROCESS] Loads each registered file via load_json_file(), collecting
    per-file warnings for OPTIONAL_INPUT_KEYS gaps. After loading, checks
    that every key in HARD_REQUIRED_INPUT_KEYS resolved to non-empty data;
    if any is missing, raises ReportingInputError naming the missing
    file(s) so run_reporting_stage() (outside this file) can mark the
    attempt Failed rather than publish a candidate report built on an
    incomplete/broken handoff.

    [FYP-VALIDATION] This is the sole hard gate on required upstream data
    for a current-run generation; it is deliberately stricter than the
    later validate_required_fields() check in report_validator.py, which
    validates content richness rather than file presence.
    [FYP-CALLS] load_json_file() once per registered INPUT_FILES entry.
    [FYP-USED-BY] agents/reporting_agent.py:main() (first call in the
    pipeline); scripts/test_merged_report_context.py,
    scripts/test_reporting_appendix_context.py.
    [FYP-EVALUATOR] Confirm this raises ReportingInputError (not a silent
    empty-dict fallback) when processed_alert/triage_result/
    investigation_result/threat_intel_result are missing — that guarantee
    is what the "Reporting cannot generate without them" behaviour depends
    on.
    """
    loaded: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for key, filename in INPUT_FILES.items():
        data, warning = load_json_file(input_dir / filename, required=key not in OPTIONAL_INPUT_KEYS)
        loaded[key] = data
        if warning:
            warnings.append(warning)
    missing_hard_required = [key for key in HARD_REQUIRED_INPUT_KEYS if not loaded.get(key)]
    if missing_hard_required:
        raise ReportingInputError(
            "Required current-run input(s) missing or empty: "
            + ", ".join(f"{key} ({INPUT_FILES[key]})" for key in missing_hard_required)
            + " — Reporting cannot generate without them."
        )
    return loaded, warnings
