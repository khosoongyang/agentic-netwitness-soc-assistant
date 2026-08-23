"""
[FYP-FILE] reporting/output_writer.py (174 lines)
# File: soc_reporting_agent/reporting/output_writer.py
# Purpose: This module implements report generation and export behaviour for output writer.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: config, json, pathlib, reporting, typing.
# Key evaluator search terms: write_json, _display_fields, build_reporting_result, write_outputs, try_store_postgres, [FYP-FUNCTION].
[FYP-SECTION] Responsibility
Final pipeline stage: assembles the persisted reporting_result.json record
(build_reporting_result), writes it plus the full enriched context to disk
(write_outputs), and optionally mirrors a summary row into PostgreSQL
(try_store_postgres). Also owns the generic write_json() helper used by
the CLI entry point for a second write-back after Postgres status is
known.

[FYP-USED-BY] agents/reporting_agent.py:main() (write_outputs,
try_store_postgres, write_json); scripts/test_merged_report_context.py
(write_outputs).
[FYP-CALLS] reporting/status_display.py (get_status_metadata,
calculate_llm_enhancement_score) to translate every technical status code
in the context into analyst-facing display/explanation/workflow_impact
text.
"""
from pathlib import Path
import json
from typing import Any
from config import settings
from reporting.status_display import get_status_metadata, calculate_llm_enhancement_score


def write_json(path: Path, data: dict[str, Any]) -> None:
    """[FYP-FUNCTION] Write `data` as indented JSON to `path`, creating
    parent directories as needed. Generic helper used both internally
    (write_outputs) and by the CLI entry point to overwrite
    reporting_result.json a second time once the Postgres store outcome is
    known."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def _display_fields(prefix: str, category: str, technical_status: Any) -> dict[str, str]:
    """[FYP-FUNCTION] Look up `category`/`technical_status` in
    status_display.STATUS_DISPLAY_MAP and return it as three
    `{prefix}_display` / `{prefix}_explanation` / `{prefix}_workflow_impact`
    keys, ready to be merged into the result dict via dict.update()."""
    meta = get_status_metadata(category, technical_status)
    return {
        f"{prefix}_display": meta["display"],
        f"{prefix}_explanation": meta["explanation"],
        f"{prefix}_workflow_impact": meta["workflow_impact"],
    }


def build_reporting_result(context: dict[str, Any], generated_reports: dict[str, str]) -> dict[str, Any]:
    """[FYP-FUNCTION] Assemble the persisted `reporting_result.json` schema
    ("reporting-result-v1") from the full build_context() output plus the
    rendered report file paths.

    [FYP-INPUT] context: the dict returned by context_builder.build_context()
    (as further enhanced by export_context_enhancer.enhance_export_context(),
    called between build_context and render_reports in
    agents/reporting_agent.py:main()); generated_reports: the dict of
    output-file paths returned by report_renderer.render_reports().

    [FYP-PROCESS] Pulls report/validation/rag/llm/cache/completeness status
    codes out of context, computes the LLM enhancement score via
    calculate_llm_enhancement_score(), and merges in human-facing
    display/explanation/workflow_impact fields for each status category
    via _display_fields(). Also carries forward several backwards-
    compatible key aliases (report_quality_score/status/dict) kept for
    older tests/scripts that read the pre-rename field names.
    [FYP-VALIDATION] This is the summary record analysts/downstream code
    read to decide whether a report is ready for review — every
    *_status_display/_explanation/_workflow_impact triple originates here.
    [FYP-USED-BY] write_outputs() (below).
    """
    report_status = context["report_status"]
    validation_status = context["validation_status"]
    rag_status = context["rag_status"]
    llm_status = context["llm_status"]
    cache_status = context.get("llm_cache_status", "not_recorded")
    completeness_status = context.get("report_quality_status", "not_recorded")
    llm_enhancement = calculate_llm_enhancement_score(context.get("llm_section_results", {}), llm_status)

    result = {
        "schema_version": "reporting-result-v1",
        "incident_id": context["incident_id"],
        "alert_id": context["alert_id"],
        "report_status": report_status,
        "report_generation_mode": context["report_generation_mode"],
        "validation_status": validation_status,
        "missing_required_fields": context["missing_required_fields"],
        "recovered_fields": context["recovered_fields"],
        "report_completeness_score": context.get("report_quality_score"),
        "report_completeness_status": completeness_status,
        "report_completeness": context.get("report_quality", {}),
        "quality_checks": context.get("quality_checks", {}),
        "field_provenance": context.get("field_provenance", {}),
        "evidence_index": context.get("evidence_index", {}),
        # Backwards-compatible aliases kept for existing tests and scripts.
        "report_quality_score": context.get("report_quality_score"),
        "report_quality_status": completeness_status,
        "report_quality": context.get("report_quality", {}),
        "generated_reports": generated_reports,
        "warnings": context["warnings"],
        "data_consistency_status": context.get("data_consistency_status", context.get("data_consistency", {}).get("status", "passed")),
        "data_consistency": context.get("data_consistency", {}),
        "input_context_hash": context.get("input_context_hash"),
        "rag_used": context["rag_used"],
        "rag_status": rag_status,
        "llm_used": context["llm_used"],
        "llm_provider": context.get("llm_provider", "not_recorded"),
        "llm_model": context.get("llm_model", "not_recorded"),
        "llm_status": llm_status,
        "llm_quality_status": context.get("llm_quality_status", "not_recorded"),
        "llm_quality_issues": context.get("llm_quality_issues", []),
        "llm_section_results": context.get("llm_section_results", {}),
        "llm_enhancement_score": llm_enhancement["score"],
        "llm_enhancement_score_detail": llm_enhancement,
        "llm_attempt_count": context.get("llm_attempt_count", 0),
        "llm_cache_status": cache_status,
        "created_at": context["created_at"],
    }
    result.update(_display_fields("report_status", "report", report_status))
    result.update(_display_fields("validation_status", "validation", validation_status))
    result.update(_display_fields("rag_status", "rag", rag_status))
    result.update(_display_fields("llm_status", "llm", llm_status))
    result.update(_display_fields("llm_cache_status", "cache", cache_status))
    result.update(_display_fields("report_completeness_status", "quality", completeness_status))
    result.update(_display_fields("data_consistency_status", "data_consistency", result.get("data_consistency_status")))
    return result


def write_outputs(context: dict[str, Any], generated_reports: dict[str, str], output_dir: Path | None = None) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] Persist the two disk artefacts of a
    reporting run: `reporting_result.json` (the summary record built by
    build_reporting_result()) and `enriched_reporting_context.json` (the
    full, unabridged `context` dict) under
    `{output_dir or settings.OUTPUT_DIR}/{incident_id}/`.

    [FYP-INPUT] context: build_context() output as enhanced by
    export_context_enhancer.enhance_export_context(); generated_reports:
    output-file-path dict from report_renderer.render_reports();
    output_dir: overrides settings.OUTPUT_DIR (used by the dev/test
    harnesses to write into a scratch directory).

    [FYP-PROCESS] Creates the incident output directory, builds the
    reporting_result via build_reporting_result(), writes both JSON files
    via write_json(), and returns the reporting_result dict so the caller
    can mutate it further (e.g. agents/reporting_agent.py:main() adds
    postgres_used/postgres display fields and re-writes
    reporting_result.json a second time after try_store_postgres()).
    [FYP-CALLS] build_reporting_result(), write_json() (both in this file).
    [FYP-USED-BY] agents/reporting_agent.py:main() (second-to-last pipeline
    step, right after report_renderer.render_reports()); dev/test harness
    scripts/test_merged_report_context.py.
    """
    root_output_dir = output_dir or settings.OUTPUT_DIR
    incident_output_dir = root_output_dir / context["incident_id"]
    incident_output_dir.mkdir(parents=True, exist_ok=True)

    reporting_result = build_reporting_result(context, generated_reports)
    write_json(incident_output_dir / "reporting_result.json", reporting_result)
    write_json(incident_output_dir / "enriched_reporting_context.json", context)
    return reporting_result


def try_store_postgres(reporting_result: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str]:
    """[FYP-FUNCTION] Best-effort mirror of a reporting_result summary row
    into the `report_results` PostgreSQL table, gated by
    settings.USE_POSTGRES.

    [FYP-INPUT] reporting_result: the dict returned by write_outputs()/
    build_reporting_result(); context: the full build_context() output
    (accepted for signature symmetry with the caller but not read here —
    only the already-flattened reporting_result fields are inserted).

    [FYP-PROCESS] Returns (False, "postgres_disabled") immediately when
    Postgres storage is disabled in settings. Otherwise lazily imports
    psycopg2, opens a connection to settings.POSTGRES_DSN, inserts a single
    row (incident_id, alert_id, report_status, validation_status,
    report_generation_mode, llm_used, rag_used, and the full
    reporting_result as a JSON blob), commits, and returns
    (True, "postgres_store_success"). Any exception (missing driver,
    connection failure, bad DSN, insert error) is caught and reported as
    (False, f"postgres_store_failed: {error}") rather than raised — a
    Postgres outage must never fail report generation, since the JSON
    files written by write_outputs() are the source of truth.
    [FYP-USED-BY] agents/reporting_agent.py:main(), immediately after
    write_outputs(); its (postgres_used, postgres_status) result is folded
    back into reporting_result and re-persisted via write_json().
    [FYP-EVALUATOR] If Postgres mirroring appears to silently "not work"
    during evaluation, check settings.USE_POSTGRES first — this function
    treats disabled Postgres as a normal, non-error outcome rather than a
    failure worth surfacing.
    """
    if not settings.USE_POSTGRES:
        return False, "postgres_disabled"

    try:
        import psycopg2

        conn = psycopg2.connect(settings.POSTGRES_DSN)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO report_results (
                incident_id, alert_id, report_status, validation_status,
                report_generation_mode, llm_used, rag_used, result_json
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                reporting_result["incident_id"],
                reporting_result["alert_id"],
                reporting_result["report_status"],
                reporting_result["validation_status"],
                reporting_result["report_generation_mode"],
                reporting_result["llm_used"],
                reporting_result["rag_used"],
                json.dumps(reporting_result),
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
        return True, "postgres_store_success"
    except Exception as error:
        return False, f"postgres_store_failed: {error}"
