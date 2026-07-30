# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, json, pytest, reporting, zipfile.
# =============================================================================
# File: soc_reporting_agent/tests/test_structured_report_tables.py
# Purpose: This module implements test and validation behaviour for test structured report tables.
# Main functionality: test_plain_correlated_alerts_with_blank_lines_becomes_one_table, test_markdown_table_spacing_separator_and_long_cell, test_multiple_tables_and_non_table_paragraph_are_not_merged, test_template_exporter_uses_shared_plain_table_parser, test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation, test_collapsed_header_separator_merges_with_following_table.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, json, pytest, reporting, zipfile.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: test_plain_correlated_alerts_with_blank_lines_becomes_one_table, test_markdown_table_spacing_separator_and_long_cell, test_multiple_tables_and_non_table_paragraph_are_not_merged, test_template_exporter_uses_shared_plain_table_parser, test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation, test_collapsed_header_separator_merges_with_following_table, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
from zipfile import ZipFile

import pytest

import reporting.editable_reports as editable_reports
from reporting.editable_reports import (
    _confirmed_blocks_or_text,
    _docx_write_blocks,
    _pdf_write_blocks,
    _validate_no_raw_markdown_tables,
)
from reporting.structured_report import (
    blocks_from_text,
    convert_key_value_lines_to_tables,
    markdown_to_blocks,
    paragraph_contains_raw_pipe_table,
    parse_pipe_table,
    repair_pipe_tables_in_blocks,
)
from reporting.template_document_exporter import _load_cached_json_blocks, markdown_to_report_blocks


CORRELATED_ALERTS = """Alert ID | Alert Name | Source | Severity | Relationship | Linked By | Link Reason

ALERT-2025-77864 | High Risk Endpoint Alert | NetWitness Endpoint | Critical | Primary alert | System | Primary alert that created the ticket.

ALERT-2025-77865 | Malicious File Detected | NetWitness Endpoint | Critical | Same endpoint malware chain | SOC Analyst | Same endpoint malware chain

ALERT-2025-77866 | Suspicious Process Execution | NetWitness Endpoint | High | Same endpoint malware chain | SOC Analyst | Same endpoint malware chain
"""


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `test_plain_correlated_alerts_with_blank_lines_becomes_one_table` — verifies plain correlated alerts with blank lines becomes one table behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `blocks_from_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_plain_correlated_alerts_with_blank_lines_becomes_one_table():
    blocks = blocks_from_text(CORRELATED_ALERTS)
    assert blocks == [{
        "type": "table",
        "columns": ["Alert ID", "Alert Name", "Source", "Severity", "Relationship", "Linked By", "Link Reason"],
        "rows": [
            ["ALERT-2025-77864", "High Risk Endpoint Alert", "NetWitness Endpoint", "Critical", "Primary alert", "System", "Primary alert that created the ticket."],
            ["ALERT-2025-77865", "Malicious File Detected", "NetWitness Endpoint", "Critical", "Same endpoint malware chain", "SOC Analyst", "Same endpoint malware chain"],
            ["ALERT-2025-77866", "Suspicious Process Execution", "NetWitness Endpoint", "High", "Same endpoint malware chain", "SOC Analyst", "Same endpoint malware chain"],
        ],
    }]


# [FYP-FUNCTION] `test_markdown_table_spacing_separator_and_long_cell` — verifies markdown table spacing separator and long cell behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `markdown_to_blocks`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_markdown_table_spacing_separator_and_long_cell():
    long_text = "A long analyst explanation " * 20
    blocks = markdown_to_blocks(
        f"| Field| Assessment |\n\n| :--- | ---: |\n\n| Evidence | {long_text} |\n"
    )
    assert blocks[0]["type"] == "table"
    assert blocks[0]["columns"] == ["Field", "Assessment"]
    assert blocks[0]["rows"][0][1] == long_text.strip()


# [FYP-FUNCTION] `test_multiple_tables_and_non_table_paragraph_are_not_merged` — verifies multiple tables and non table paragraph are not merged behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `blocks_from_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_multiple_tables_and_non_table_paragraph_are_not_merged():
    text = (
        "A | B\n1 | 2\n\n\n"
        "Narrative with a casual A | B reference.\n\n"
        "| C | D |\n|---|---|\n| 3 | 4 |\n"
    )
    blocks = blocks_from_text(text)
    assert [block["type"] for block in blocks] == ["table", "paragraph", "table"]
    assert blocks[1]["text"] == "Narrative with a casual A | B reference."


# [FYP-FUNCTION] `test_template_exporter_uses_shared_plain_table_parser` — verifies template exporter uses shared plain table parser behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `len`, `markdown_to_report_blocks`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_template_exporter_uses_shared_plain_table_parser():
    blocks = markdown_to_report_blocks(CORRELATED_ALERTS)
    assert blocks[0]["type"] == "table"
    assert len(blocks[0]["rows"]) == 3


# [FYP-FUNCTION] `test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation` — verifies legacy paragraph blocks are repaired for editable confirmation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `len`, `repair_pipe_tables_in_blocks`, `splitlines`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation():
    legacy = [{"type": "paragraph", "text": line} for line in CORRELATED_ALERTS.splitlines() if line]
    repaired = repair_pipe_tables_in_blocks(legacy)
    assert len(repaired) == 1
    assert repaired[0]["type"] == "table"
    assert len(repaired[0]["rows"]) == 3


# [FYP-FUNCTION] `test_collapsed_header_separator_merges_with_following_table` — verifies collapsed header separator merges with following table behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `repair_pipe_tables_in_blocks`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_collapsed_header_separator_merges_with_following_table():
    blocks = [
        {"type": "heading", "level": 3, "text": "Appendix A"},
        {"type": "paragraph", "text": "| Field | Value | |---|---|"},
        {
            "type": "table",
            "columns": ["Alert ID", "ALERT-1"],
            "rows": [["Source", "NetWitness"], ["Severity", "Critical"]],
        },
    ]
    repaired = repair_pipe_tables_in_blocks(blocks)
    assert repaired[1] == {
        "type": "table",
        "columns": ["Field", "Value"],
        "rows": [
            ["Alert ID", "ALERT-1"],
            ["Source", "NetWitness"],
            ["Severity", "Critical"],
        ],
    }


# [FYP-FUNCTION] `test_complete_collapsed_priority_table_is_recovered` — verifies complete collapsed priority table is recovered behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `len`, `repair_pipe_tables_in_blocks`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_complete_collapsed_priority_table_is_recovered():
    raw = (
        "Priority | Action | Owner | Approval Required | Rationale |  "
        "| --- | --- | --- | --- | --- |  "
        "| P1 | Isolate host | SOC | True | Critical incident |  "
        "| P2 | Preserve evidence | IR | False | Investigation support |"
    )
    repaired = repair_pipe_tables_in_blocks([{"type": "paragraph", "text": raw}])
    assert repaired[0]["type"] == "table"
    assert repaired[0]["columns"] == ["Priority", "Action", "Owner", "Approval Required", "Rationale"]
    assert len(repaired[0]["rows"]) == 2


# [FYP-FUNCTION] `test_editable_confirmed_blocks_are_repaired_and_persisted` — verifies editable confirmed blocks are repaired and persisted behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_confirmed_blocks_or_text`, `dumps`, `loads`, `read_text`, `str`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_editable_confirmed_blocks_are_repaired_and_persisted(tmp_path):
    structured = tmp_path / "confirmed.json"
    confirmed_text = tmp_path / "confirmed.txt"
    legacy = [
        {"type": "heading", "level": 2, "text": "Correlated Alerts"},
        {"type": "paragraph", "text": "| Username | | --- |"},
        {"type": "paragraph", "text": "| ACME\\analyst |"},
        {"type": "paragraph", "text": "| SYSTEM |"},
    ]
    structured.write_text(json.dumps(legacy), encoding="utf-8")
    confirmed_text.write_text("confirmed report", encoding="utf-8")
    blocks, _ = _confirmed_blocks_or_text({
        "title": "Technical Findings",
        "structured_confirmed_path": str(structured),
        "confirmed_path": str(confirmed_text),
    })
    assert blocks[1]["type"] == "table"
    assert blocks[1]["rows"] == [["ACME\\analyst"], ["SYSTEM"]]
    assert json.loads(structured.read_text(encoding="utf-8")) == blocks


# [FYP-FUNCTION] `test_cached_blocks_are_repaired_before_reuse` — verifies cached blocks are repaired before reuse behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_load_cached_json_blocks`, `dumps`, `loads`, `read_text`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_cached_blocks_are_repaired_before_reuse(tmp_path):
    cache_path = tmp_path / "export.json"
    payload = {
        "source_hash": "hash-1",
        "structured_blocks": [
            {"type": "paragraph", "text": "| Field | Value | |---|---|"},
            {"type": "table", "columns": ["Alert ID", "ALERT-1"], "rows": [["Source", "NetWitness"]]},
        ],
    }
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    _, blocks = _load_cached_json_blocks(cache_path, "hash-1")
    assert blocks == [{
        "type": "table",
        "columns": ["Field", "Value"],
        "rows": [["Alert ID", "ALERT-1"], ["Source", "NetWitness"]],
    }]
    assert json.loads(cache_path.read_text(encoding="utf-8"))["structured_blocks"] == blocks


# [FYP-FUNCTION] `test_raw_table_validation_and_single_pipe_prose` — verifies raw table validation and single pipe prose behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_validate_no_raw_markdown_tables`, `paragraph_contains_raw_pipe_table`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_raw_table_validation_and_single_pipe_prose():
    assert paragraph_contains_raw_pipe_table("|---|---|")
    assert paragraph_contains_raw_pipe_table("Alert ID | Alert Name | Source")
    assert not paragraph_contains_raw_pipe_table("Use option A | option B when documenting the decision.")
    _validate_no_raw_markdown_tables([
        {"type": "paragraph", "text": "Use option A | option B when documenting the decision."}
    ])
    with pytest.raises(ValueError, match='section "Correlated Alerts".*block index 1.*Alert ID'):
        _validate_no_raw_markdown_tables([
            {"type": "heading", "level": 2, "text": "Correlated Alerts"},
            {"type": "paragraph", "text": "Alert ID | Alert Name | Source"}
        ])


# [FYP-FUNCTION] `test_docx_contains_native_table_and_no_pipe_paragraphs` — verifies docx contains native table and no pipe paragraphs behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `ZipFile`, `_docx_write_blocks`, `blocks_from_text`, `decode`, `importorskip`, `read`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_docx_contains_native_table_and_no_pipe_paragraphs(tmp_path):
    pytest.importorskip("docx")
    path = tmp_path / "correlated-alerts.docx"
    blocks = blocks_from_text(CORRELATED_ALERTS)
    _docx_write_blocks(path, "Incident Report", blocks, "INC-1", {})
    with ZipFile(path) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
    assert "<w:tbl>" in document_xml
    assert "ALERT-2025-77864" in document_xml
    assert "|---|---|" not in document_xml


# [FYP-FUNCTION] `test_pdf_recovers_raw_blocks_before_rendering` — verifies pdf recovers raw blocks before rendering behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_pdf_write_blocks`, `exists`, `skip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_pdf_recovers_raw_blocks_before_rendering(tmp_path):
    if editable_reports.SimpleDocTemplate is None:
        pytest.skip("reportlab is not installed")
    path = tmp_path / "recovered.pdf"
    raw_blocks = [
        {"type": "paragraph", "text": "| Field | Value | |---|---|"},
        {"type": "table", "columns": ["Alert ID", "ALERT-1"], "rows": [["Source", "NetWitness"]]},
    ]
    _pdf_write_blocks(path, "Incident Report", raw_blocks, "INC-1", {})
    assert path.exists()


# ══════════════════════════════════════════════════════════════════════
# Escaped-pipe scanner — state-machine tokenizer, not a naive .split("|")
# or a single-character regex lookbehind (which can't tell odd vs. even
# runs of backslashes apart).
# ══════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_escaped_pipe_stays_inside_one_cell` — verifies escaped pipe stays inside one cell behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `parse_pipe_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_escaped_pipe_stays_inside_one_cell():
    lines = ["| Evidence | Description |",
            "| IOC-1 | Command used A \\| B syntax |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert consumed == 2
    assert table["columns"] == ["Evidence", "Description"]
    assert table["rows"] == [["IOC-1", "Command used A | B syntax"]]


# [FYP-FUNCTION] `test_double_backslash_before_pipe_is_one_literal_backslash_then_separator` — verifies double backslash before pipe is one literal backslash then separator behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `parse_pipe_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_double_backslash_before_pipe_is_one_literal_backslash_then_separator():
    lines = ["| A | B |", "| A \\\\| B |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert consumed == 2
    # One escaped backslash (\\ -> \), then a REAL column separator.
    assert table["rows"] == [["A \\", "B"]]


# [FYP-FUNCTION] `test_windows_path_in_cell_is_left_untouched` — verifies windows path in cell is left untouched behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `parse_pipe_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_windows_path_in_cell_is_left_untouched():
    lines = ["| Field | Value |", "| Path | C:\\Users\\x\\file.txt |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert consumed == 2
    assert table["rows"] == [["Path", "C:\\Users\\x\\file.txt"]]


# [FYP-FUNCTION] `test_malformed_row_produces_warning_not_silent_column_change` — verifies malformed row produces warning not silent column change behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `any`, `get`, `parse_pipe_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_malformed_row_produces_warning_not_silent_column_change():
    lines = ["| A | B | C |", "| 1 | 2 |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert table is not None
    assert table["rows"] == [["1", "2", ""]]
    assert any("padded" in w for w in table.get("row_warnings", []))


# ══════════════════════════════════════════════════════════════════════
# Key/value-line table heuristic — "P1: Priority investigation | Owner:
# Tier 1 | Approval Required: No" shaped lines, deliberately strict.
# ══════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_priority_line_pair_converts_to_table` — verifies priority line pair converts to table behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `convert_key_value_lines_to_tables`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_priority_line_pair_converts_to_table():
    blocks = [
        {"type": "paragraph", "text": "P1: Priority investigation | Owner: Tier 1 | Approval Required: No"},
        {"type": "paragraph", "text": "P2: Monitor for recurrence | Owner: Tier 2 | Approval Required: Yes"},
    ]
    result = convert_key_value_lines_to_tables(blocks)
    assert len(result) == 1
    assert result[0]["type"] == "table"
    assert result[0]["columns"] == ["Priority", "Action", "Owner", "Approval Required"]
    assert result[0]["rows"] == [
        ["P1", "Priority investigation", "Tier 1", "No"],
        ["P2", "Monitor for recurrence", "Tier 2", "Yes"],
    ]


# [FYP-FUNCTION] `test_single_matching_line_is_not_converted_alone` — verifies single matching line is not converted alone behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `convert_key_value_lines_to_tables`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_single_matching_line_is_not_converted_alone():
    blocks = [{"type": "paragraph",
              "text": "P1: Priority investigation | Owner: Tier 1 | Approval Required: No"}]
    result = convert_key_value_lines_to_tables(blocks)
    assert len(result) == 1
    assert result[0]["type"] == "paragraph"
    assert "row_warnings" in result[0]


# [FYP-FUNCTION] `test_ordinary_prose_with_colon_and_pipe_is_not_converted` — verifies ordinary prose with colon and pipe is not converted behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `convert_key_value_lines_to_tables`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_ordinary_prose_with_colon_and_pipe_is_not_converted():
    blocks = [{"type": "paragraph",
              "text": "The analyst noted: suspicious activity | further review needed"}]
    result = convert_key_value_lines_to_tables(blocks)
    assert result == blocks
