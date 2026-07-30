# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, adapters, json, os, pathlib, services, shutil, sys.
# =============================================================================
# File: soc_reporting_agent/adapters/run_parser_normalisation.py
# Purpose: This module provides the command-line adapter for the parsing and normalisation stage.
# Main functionality: progress, selected_ticket_id, load_raw_alert_context, mirror_ticket_parser_outputs, main.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis stage adapter component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, adapters, json, os, pathlib, services, shutil, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: progress, selected_ticket_id, load_raw_alert_context, mirror_ticket_parser_outputs, main, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adapters.common import INPUTS_DIR, OUTPUTS_DIR, RUNTIME_DIR, now_iso, read_json, write_json
from services.parser_context_guard import extract_alert_identity, validate_parser_identity
from services.parser_normaliser import run_parser_normalisation_for_dashboard


# =============================================================================
# [FYP-SECTION] STAGE ADAPTER EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `progress` — implements the progress operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `percent`, `message`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `print`, `sleep`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def progress(percent: int, message: str) -> None:
    print(f"[PROGRESS {percent}] {message}", flush=True)
    time.sleep(0.05)


# [FYP-FUNCTION] `selected_ticket_id` — implements the selected ticket id operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `getenv`, `read_json`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def selected_ticket_id() -> str | None:
    env_ticket = os.getenv("SOC_TICKET_ID")
    if env_ticket:
        return str(env_ticket).strip()
    selected = read_json(RUNTIME_DIR / "selected_ticket.json", {}) or {}
    ticket_id = selected.get("ticket_id")
    return str(ticket_id).strip() if ticket_id else None

# [FYP-FUNCTION] `load_raw_alert_context` — retrieves load raw alert context data for the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isinstance`, `now_iso`, `read_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def load_raw_alert_context(ticket_id: str | None = None) -> tuple[dict[str, Any], Path | None]:
    if ticket_id:
        ticket_input = OUTPUTS_DIR / ticket_id / "parsing" / "raw_input_alert.json"
        data = read_json(ticket_input, None)
        if isinstance(data, dict) and data:
            return data, ticket_input

    raw_candidates = [
        INPUTS_DIR / "raw_alert.json",
        INPUTS_DIR / "netwitness_alert.json",
        INPUTS_DIR / "alert.json",
        OUTPUTS_DIR / "raw_alert.json",
    ]
    for path in raw_candidates:
        data = read_json(path, None)
        if isinstance(data, dict) and data:
            return data, path

    enriched = read_json(INPUTS_DIR / "enriched_alert.json", {}) or read_json(OUTPUTS_DIR / "enriched_alert.json", {}) or {}
    if isinstance(enriched, dict) and enriched:
        raw = enriched.get("raw") if isinstance(enriched.get("raw"), dict) and enriched.get("raw") else enriched
        return raw, INPUTS_DIR / "enriched_alert.json"

    return {
        "alert_id": "ALERT-UNKNOWN",
        "alert_name": "Selected NetWitness Alert",
        "incident_id": ticket_id or "unknown",
        "severity": "Medium",
        "source": "NetWitness",
        "timestamp": now_iso(),
    }, None


# [FYP-FUNCTION] `mirror_ticket_parser_outputs` — implements the mirror ticket parser outputs operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`, `ticket_parser_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `copytree`, `exists`, `resolve`, `rmtree`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def mirror_ticket_parser_outputs(ticket_id: str | None, ticket_parser_dir: Path) -> None:
    """Write compatibility files for existing downstream adapters.

    Ticket-specific output is the source of truth. These compatibility files are
    refreshed after every run so downstream code that still reads global paths
    cannot consume stale parser context.
    """
    if not ticket_parser_dir.exists():
        return
    legacy_dir = OUTPUTS_DIR / "soc_context_parser"
    if ticket_parser_dir.resolve() == legacy_dir.resolve():
        return
    if legacy_dir.exists():
        shutil.rmtree(legacy_dir)
    shutil.copytree(ticket_parser_dir, legacy_dir)


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered stage adapter operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `bool`, `dumps`, `extract_alert_identity`, `fromkeys`, `get`, `int`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main() -> int:
    started_at = now_iso()
    start_monotonic = time.monotonic()
    ticket_id = selected_ticket_id()
    progress(5, "Loading selected ticket raw NetWitness alert context")
    raw_alert, input_path = load_raw_alert_context(ticket_id)
    input_identity = extract_alert_identity(raw_alert)
    if ticket_id:
        input_identity["ticket_id"] = ticket_id

    progress(10, f"Input alert ID: {input_identity.get('alert_id') or 'unknown'}")
    progress(12, f"Input title: {input_identity.get('alert_title') or 'unknown'}")
    progress(18, "Detecting input format and extracting NetWitness metakeys")

    parser_dir = OUTPUTS_DIR / ticket_id / "parsing" if ticket_id else OUTPUTS_DIR / "soc_context_parser"
    parser_dir.mkdir(parents=True, exist_ok=True)
    write_json(parser_dir / "raw_input_alert.json", raw_alert)
    write_json(parser_dir / "input_identity.json", input_identity)

    progress(28, "Building normalised alert and parser summary")
    result = run_parser_normalisation_for_dashboard(raw_alert, parser_dir)
    processed = result.get("processed_alert") or {}

    progress(55, "Writing parser output for downstream agents")
    validation = validate_parser_identity(input_identity, result)
    result["input_source_path"] = str(input_path) if input_path else None
    result["input_source"] = "selected_ticket_parser_input" if ticket_id and input_path and "outputs" in str(input_path) else ("local_file" if input_path else "synthetic_fallback")
    result["input_identity"] = input_identity
    result["identity_validation"] = validation

    progress(62, f"Parsed alert ID: {validation.get('parsed_identity', {}).get('alert_id') or 'unknown'}")
    if not validation.get("passed"):
        result["status"] = "failed"
        result["parser_status"] = "failed"
        result["current_stage"] = "parser_input_mismatch"
        result["summary"] = validation.get("message")
        result["recommended_next_action"] = "Reload the selected ticket and rerun Parsing & Normalisation. Do not continue with stale parser output."
        result.setdefault("warnings", []).append(validation.get("message"))
        write_json(parser_dir / "parser_result.json", result)
        write_json(OUTPUTS_DIR / "parser_result.json", result)
        write_json(INPUTS_DIR / "parser_result.json", result)
        progress(100, "Parser identity check failed")
        print(json.dumps({"status": "failed", "reason": validation.get("message"), "identity_validation": validation}, indent=2), flush=True)
        return 1

    progress(70, "Parser identity check passed")
    processed_meta = processed.get("parser_metadata") or {}
    powershell_analysis = processed.get("powershell_analysis") or {}
    missing_fields = result.get("missing_important_fields") or processed_meta.get("missing_fields") or []
    warnings = list(result.get("warnings") or [])
    raw_event_count = int(processed_meta.get("raw_event_count") or (processed.get("normalised_alert") or {}).get("alert_summary", {}).get("raw_event_count") or 0)
    if raw_event_count == 0:
        warnings.append("No raw NetWitness event records were available. Parsing continued using ticket alert metadata.")
    if missing_fields:
        warnings.append("Missing parser fields: " + ", ".join(str(x) for x in missing_fields))
    warning_status = bool(warnings)
    result["warnings"] = list(dict.fromkeys(str(w) for w in warnings if w))
    result["status"] = "completed_with_warnings" if result.get("status") == "completed" and warning_status else result.get("status")
    result["parser_status"] = result.get("status")
    result["display_status"] = "Completed with warnings" if warning_status else "Completed"
    result["parser_run_metadata"] = {
        "started_at": started_at,
        "completed_at": now_iso(),
        "duration_seconds": round(time.monotonic() - start_monotonic, 3),
        "input_source": result.get("input_source"),
        "input_source_path": result.get("input_source_path"),
        "netwitness_raw_event_fetch": {
            "attempted": False,
            "status": "not_attempted_by_parser",
            "note": "Parser used the selected ticket raw alert context. Live NetWitness retrieval is handled before parser input preparation."
        },
        "raw_event_count": raw_event_count,
        "missing_fields": missing_fields,
        "warning_count": len(result["warnings"]),
        "powershell_decode_status": powershell_analysis.get("decode_status") or "not_detected",
        "ioc_count": len(processed.get("iocs") or []),
        "parser_confidence": result.get("parser_confidence"),
        "parser_confidence_score": result.get("parser_confidence_score"),
    }
    result["parser_summary_card"] = {
        "input_source": result["parser_run_metadata"]["input_source"],
        "raw_events_retrieved": raw_event_count,
        "important_fields_extracted": len(result.get("important_extracted_fields") or {}),
        "missing_fields": missing_fields,
        "powershell_decode_status": result["parser_run_metadata"]["powershell_decode_status"],
        "ioc_count": result["parser_run_metadata"]["ioc_count"],
        "parser_confidence": result.get("parser_confidence"),
        "parser_confidence_score": result.get("parser_confidence_score"),
        "warnings": result.get("warnings") or [],
    }
    result["export_status"] = {
        "docx": "generate_on_download",
        "pdf": "generate_on_download",
        "note": "Parsing Word/PDF reports are generated on demand and do not block Triage.",
    }

    # Ticket-specific outputs.
    write_json(parser_dir / "parser_result.json", result)
    write_json(parser_dir / "processed_alert.json", processed)
    write_json(parser_dir / "processed_alert_ticket_context.json", processed)

    # Compatibility outputs for older adapters and existing dashboard routes.
    mirror_ticket_parser_outputs(ticket_id, parser_dir)
    write_json(OUTPUTS_DIR / "parser_result.json", result)
    write_json(INPUTS_DIR / "parser_result.json", result)
    write_json(OUTPUTS_DIR / "processed_alert.json", processed)
    write_json(INPUTS_DIR / "processed_alert.json", processed)
    write_json(OUTPUTS_DIR / "enriched_alert.json", processed)
    write_json(INPUTS_DIR / "enriched_alert.json", processed)

    progress(85, "Parser output ready for Triage Agent")
    progress(100, "Parsing and normalisation completed")
    print(json.dumps({
        "status": result.get("status"),
        "selected_alert_id": result.get("selected_alert_id"),
        "parser_confidence": result.get("parser_confidence"),
        "identity_validation": validation.get("status"),
    }, indent=2), flush=True)
    return 0 if str(result.get("status") or "").lower() in {"completed", "completed_with_warnings"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
