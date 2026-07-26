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


def test_markdown_table_spacing_separator_and_long_cell():
    long_text = "A long analyst explanation " * 20
    blocks = markdown_to_blocks(
        f"| Field| Assessment |\n\n| :--- | ---: |\n\n| Evidence | {long_text} |\n"
    )
    assert blocks[0]["type"] == "table"
    assert blocks[0]["columns"] == ["Field", "Assessment"]
    assert blocks[0]["rows"][0][1] == long_text.strip()


def test_multiple_tables_and_non_table_paragraph_are_not_merged():
    text = (
        "A | B\n1 | 2\n\n\n"
        "Narrative with a casual A | B reference.\n\n"
        "| C | D |\n|---|---|\n| 3 | 4 |\n"
    )
    blocks = blocks_from_text(text)
    assert [block["type"] for block in blocks] == ["table", "paragraph", "table"]
    assert blocks[1]["text"] == "Narrative with a casual A | B reference."


def test_template_exporter_uses_shared_plain_table_parser():
    blocks = markdown_to_report_blocks(CORRELATED_ALERTS)
    assert blocks[0]["type"] == "table"
    assert len(blocks[0]["rows"]) == 3


def test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation():
    legacy = [{"type": "paragraph", "text": line} for line in CORRELATED_ALERTS.splitlines() if line]
    repaired = repair_pipe_tables_in_blocks(legacy)
    assert len(repaired) == 1
    assert repaired[0]["type"] == "table"
    assert len(repaired[0]["rows"]) == 3


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

def test_escaped_pipe_stays_inside_one_cell():
    lines = ["| Evidence | Description |",
            "| IOC-1 | Command used A \\| B syntax |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert consumed == 2
    assert table["columns"] == ["Evidence", "Description"]
    assert table["rows"] == [["IOC-1", "Command used A | B syntax"]]


def test_double_backslash_before_pipe_is_one_literal_backslash_then_separator():
    lines = ["| A | B |", "| A \\\\| B |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert consumed == 2
    # One escaped backslash (\\ -> \), then a REAL column separator.
    assert table["rows"] == [["A \\", "B"]]


def test_windows_path_in_cell_is_left_untouched():
    lines = ["| Field | Value |", "| Path | C:\\Users\\x\\file.txt |"]
    table, consumed = parse_pipe_table(lines, 0)
    assert consumed == 2
    assert table["rows"] == [["Path", "C:\\Users\\x\\file.txt"]]


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


def test_single_matching_line_is_not_converted_alone():
    blocks = [{"type": "paragraph",
              "text": "P1: Priority investigation | Owner: Tier 1 | Approval Required: No"}]
    result = convert_key_value_lines_to_tables(blocks)
    assert len(result) == 1
    assert result[0]["type"] == "paragraph"
    assert "row_warnings" in result[0]


def test_ordinary_prose_with_colon_and_pipe_is_not_converted():
    blocks = [{"type": "paragraph",
              "text": "The analyst noted: suspicious activity | further review needed"}]
    result = convert_key_value_lines_to_tables(blocks)
    assert result == blocks
