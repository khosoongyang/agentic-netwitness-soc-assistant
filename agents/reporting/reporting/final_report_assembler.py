"""final_report_assembler.py — Phase 5 of the Reporting redesign.

Deterministically builds the Final Incident Report block list from the
LATEST REVIEWED versions of Executive Summary, Technical Findings, and SOC
Analyst Review — never an independent LLM pass, never a re-run of
Investigation, never a rewrite of the source sections' own content.

Trigger: agents/reporting/report_editing.py::mark_reviewed() calls
_maybe_assemble_final_incident_report() every time a component report is
reviewed. That helper checks whether all three components are now reviewed
on their current latest version and, if the exact set of source version ids
differs from what the last assembled Final Incident Report was built from,
calls assemble_final_incident_report() here and persists the result as a
new, immutable report_versions row (origin='assembled'). This module itself
never touches the database — it is a pure content-shaping function.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

COMPONENT_REPORT_TYPES = ("executive_summary", "technical_findings", "soc_analyst_review")

SECTION_TITLES = {
    "executive_summary": "Executive Summary",
    "technical_findings": "Technical Findings",
    "soc_analyst_review": "SOC Analyst Review",
}


def assemble_final_incident_report(incident_id: str, *,
                                   reviewed_sections: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """`reviewed_sections` must map each of COMPONENT_REPORT_TYPES to its
    latest REVIEWED block list, taken verbatim from report_versions —
    this function only assembles and labels them, it never invents or
    rewrites section content. Returns the assembled Final Incident Report
    block list (the same heading/paragraph/bullet_list/table/page_break
    schema every other report already uses, so it renders/exports/edits
    through the existing pipeline unchanged)."""
    blocks: list[dict[str, Any]] = [
        {"type": "heading", "level": 1, "text": "Final Incident Report"},
        {"type": "table", "columns": ["Field", "Value"], "rows": [
            ["Incident ID", incident_id],
            ["Assembled", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
            ["Source", "Assembled from the latest reviewed component reports"],
        ]},
        {"type": "page_break"},
    ]
    for report_type in COMPONENT_REPORT_TYPES:
        section_blocks = reviewed_sections.get(report_type) or []
        blocks.append({"type": "heading", "level": 1, "text": SECTION_TITLES[report_type]})
        blocks.extend(section_blocks)
        blocks.append({"type": "page_break"})
    if blocks and blocks[-1].get("type") == "page_break":
        blocks.pop()
    return blocks
