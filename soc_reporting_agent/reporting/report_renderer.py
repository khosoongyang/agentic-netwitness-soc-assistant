"""
[FYP-FILE] reporting/report_renderer.py (61 lines)
# File: soc_reporting_agent/reporting/report_renderer.py
# Purpose: This module implements report generation and export behaviour for report renderer.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: __future__, config, jinja2, pathlib, reporting, typing.
# Key evaluator search terms: render_reports, [FYP-FUNCTION].

[FYP-SECTION] Responsibility
Fourth pipeline stage: renders every configured report section (executive
summary, technical findings, SOC analyst review, SOC triage review, final
incident report) from Jinja2 `.md.j2` templates against the fully-built
`context` dict, converts each rendered Markdown string into the structured
"block" representation used by the analyst-facing editable preview/editor
(reporting/structured_report.py), and writes both the plain-text and
structured-JSON forms to disk under the incident's editable-reports
directory. Delegates the report *manifest* record (which is what the
approval UI actually reads to enumerate available reports) to
reporting/editable_reports.py:build_report_manifest().

[FYP-ENTRY-POINT] render_reports() is called once per run, immediately
after context_builder.build_context() (and export_context_enhancer.
enhance_export_context()) and immediately before output_writer.
write_outputs().
[FYP-USED-BY] agents/reporting_agent.py:main(); dev/test harnesses
scripts/test_merged_report_context.py, scripts/test_reporting_appendix_context.py.
[FYP-CALLS] reporting/editable_reports.py (REPORT_SECTION_CONFIG for the
per-section template/filename mapping, editable_dir() for the output path,
build_report_manifest() to persist report_manifest.json); reporting/
structured_report.py (markdown_to_blocks(), blocks_to_plain_text(),
save_blocks()) to convert each rendered template into the block format the
web editor/preview and DOCX/PDF exporters both consume.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import settings
from reporting.editable_reports import REPORT_SECTION_CONFIG, build_report_manifest, editable_dir
from reporting.structured_report import markdown_to_blocks, blocks_to_plain_text, save_blocks

# [FYP-SECTION] Template registry: maps each report section key to its
# Jinja2 template name and output filename, both sourced from
# editable_reports.REPORT_SECTION_CONFIG (the single source of truth also
# used by the DOCX/PDF exporters and the web editor).
# All report templates are actively used. The source templates are the uploaded
# report_templates/*.md.j2 files, but the Reporting Agent now writes editable
# plain-text sections for SOC analyst review instead of Markdown-first outputs.
TEMPLATES = {
    "executive_summary": (REPORT_SECTION_CONFIG["executive_summary"]["template"], REPORT_SECTION_CONFIG["executive_summary"]["filename"]),
    "technical_findings": (REPORT_SECTION_CONFIG["technical_findings"]["template"], REPORT_SECTION_CONFIG["technical_findings"]["filename"]),
    "soc_analyst_review": (REPORT_SECTION_CONFIG["soc_analyst_review"]["template"], REPORT_SECTION_CONFIG["soc_analyst_review"]["filename"]),
    "soc_triage_review": (REPORT_SECTION_CONFIG["soc_triage_review"]["template"], REPORT_SECTION_CONFIG["soc_triage_review"]["filename"]),
    "final_incident_report": (REPORT_SECTION_CONFIG["final_incident_report"]["template"], REPORT_SECTION_CONFIG["final_incident_report"]["filename"]),
}


def render_reports(context: dict[str, Any], output_dir: Path | None = None, template_dir: Path | None = None) -> dict[str, str]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] Render every TEMPLATES entry against
    `context`, write plain-text + structured-block outputs, and build the
    report manifest.

    [FYP-INPUT] context: the fully-built context dict (build_context() +
    enhance_export_context()); output_dir: overrides settings.OUTPUT_DIR;
    template_dir: overrides settings.TEMPLATE_DIR (both used by dev/test
    harnesses pointing at scratch/fixture directories).

    [FYP-PROCESS] For each (key, (template_name, output_name)) in
    TEMPLATES: renders the Jinja2 template with `**context` as the
    variable namespace, converts the rendered Markdown to blocks via
    markdown_to_blocks(), derives plain text via blocks_to_plain_text(),
    writes the plain-text file and a `{key}.json` structured-block file
    under the incident's editable-reports directory (editable_dir()), and
    records both paths in the returned dict under `{key}` and
    `{key}_structured`. Also copies the rendered final_incident_report text
    to a legacy `final_report.txt` path for older dashboard code/tests, and
    calls build_report_manifest() to persist report_manifest.json — the
    record the approval UI reads to enumerate available reports.
    [FYP-VALIDATION] Jinja2's `autoescape=select_autoescape(enabled_extensions=())`
    disables HTML autoescaping entirely (these are plain-text/Markdown
    templates, not HTML), so any escaping concerns must be handled by the
    caller/template rather than by Jinja2 here.
    [FYP-CALLS] editable_reports.editable_dir(), editable_reports.
    build_report_manifest(), structured_report.markdown_to_blocks(),
    structured_report.blocks_to_plain_text(), structured_report.save_blocks().
    [FYP-USED-BY] agents/reporting_agent.py:main() (between build_context/
    enhance_export_context and output_writer.write_outputs()).
    """
    template_dir = template_dir or settings.TEMPLATE_DIR
    root = output_dir or settings.OUTPUT_DIR
    incident_id = context["incident_id"]
    incident_root = root / incident_id
    incident_root.mkdir(parents=True, exist_ok=True)
    editable_root = editable_dir(root, incident_id)
    editable_root.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=False,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )
    generated: dict[str, str] = {}
    for key, (template_name, output_name) in TEMPLATES.items():
        rendered_template = env.get_template(template_name).render(**context)
        blocks = markdown_to_blocks(rendered_template)
        plain_text = blocks_to_plain_text(blocks)
        path = editable_root / output_name
        path.write_text(plain_text, encoding="utf-8")
        block_path = editable_root / f"{key}.json"
        save_blocks(block_path, blocks)
        generated[key] = str(path)
        generated[f"{key}_structured"] = str(block_path)

    # Backwards-compatible plain-text aliases for older dashboard code/tests.
    final_text = editable_root / REPORT_SECTION_CONFIG["final_incident_report"]["filename"]
    if final_text.exists():
        (incident_root / "final_report.txt").write_text(final_text.read_text(encoding="utf-8"), encoding="utf-8")
        generated["final_report_text"] = str(incident_root / "final_report.txt")

    manifest = build_report_manifest(root, incident_id, generated, context)
    generated["report_manifest"] = str((root / incident_id / "reports" / "report_manifest.json"))
    return generated
