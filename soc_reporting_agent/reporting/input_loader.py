from pathlib import Path
import json
from typing import Any

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


class ReportingInputError(Exception):
    """Raised when a hard-required current-run input (see
    HARD_REQUIRED_INPUT_KEYS) is missing, empty, or unreadable. Callers
    must let this propagate — it is what makes run_reporting_stage() mark
    the attempt Failed/Failed with no candidate manifest published,
    instead of quietly generating a degraded report."""


def load_json_file(path: Path, *, required: bool = True) -> tuple[dict[str, Any], str | None]:
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
