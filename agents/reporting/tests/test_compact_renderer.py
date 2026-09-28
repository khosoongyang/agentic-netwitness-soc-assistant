"""
[FYP-FILE]
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis test and validation.
# Important dependencies: __future__, pytest, reporting.
# Key evaluator search terms: TestIsPlaceholder, TestCountPlaceholders, TestFilterEmptyColumns, TestFilterEmptyRows, TestTablePlaceholderRatio, TestBuildEvidenceRegisterSummary, [FYP-FUNCTION].
File: soc_reporting_agent/tests/test_compact_renderer.py
Purpose: Unit tests for the report "compaction" helpers in
    reporting/compact_renderer.py (placeholder detection/counting, table
    column/row filtering, evidence/data-impact/chain-of-custody/approval
    summary builders) plus the plain-text/markdown table parsing entry
    points in reporting/structured_report.py that feed those summaries.
Main functionalities: Exercises each pure helper function with small
    literal inputs and asserts the exact return value/shape, covering both
    the "mostly placeholders -> compact summary" and "mostly real data ->
    full table" branches used when rendering incident reports.
Called by: Executed by pytest, or by running
    `python -m pytest soc_reporting_agent/tests/test_compact_renderer.py`.
[FYP-CALLS] reporting.compact_renderer -- is_placeholder, count_placeholders,
    filter_empty_columns, filter_empty_rows, table_placeholder_ratio,
    build_evidence_register_summary, build_data_impact_summary,
    build_chain_of_custody_note, build_approval_summary;
    reporting.structured_report -- blocks_from_text, markdown_to_blocks.
[/FYP-FILE]
"""
from __future__ import annotations

import pytest

from reporting.compact_renderer import (
    build_approval_summary,
    build_chain_of_custody_note,
    build_data_impact_summary,
    build_evidence_register_summary,
    count_placeholders,
    filter_empty_columns,
    filter_empty_rows,
    is_placeholder,
    table_placeholder_ratio,
)
from reporting.structured_report import blocks_from_text, markdown_to_blocks


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] is_placeholder() -- single-value placeholder classification
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestIsPlaceholder` — owns TestIsPlaceholder state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_none_is_placeholder, test_empty_string_is_placeholder, test_known_placeholder_strings, test_real_value_is_not_placeholder, test_empty_list_is_placeholder, test_non_empty_list_is_not_placeholder.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestIsPlaceholder:
    def test_none_is_placeholder(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.is_placeholder(): None counts as a placeholder value."""
        assert is_placeholder(None) is True

    def test_empty_string_is_placeholder(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.is_placeholder(): an empty string counts as a placeholder value."""
        assert is_placeholder("") is True

    def test_known_placeholder_strings(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.is_placeholder(): every string in the known PLACEHOLDER_VALUES set (e.g. "Not Provided", "Pending") is classified as a placeholder."""
        for value in ["Not Provided", "To Be Validated", "Pending", "Not linked", "To Be Assigned"]:
            assert is_placeholder(value) is True

    def test_real_value_is_not_placeholder(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.is_placeholder(): genuine analyst/report values (hostname, name, decision) are NOT classified as placeholders."""
        assert is_placeholder("FINANCE-WKS-017") is False
        assert is_placeholder("Soong Yang") is False
        assert is_placeholder("approved") is False

    def test_empty_list_is_placeholder(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.is_placeholder(): an empty list counts as a placeholder value."""
        assert is_placeholder([]) is True

    def test_non_empty_list_is_not_placeholder(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.is_placeholder(): a list containing a real item is NOT a placeholder."""
        assert is_placeholder(["EV-001"]) is False


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] count_placeholders() -- recursive placeholder counting
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestCountPlaceholders` — owns TestCountPlaceholders state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_empty_dict, test_nested_placeholders, test_list_placeholders, test_deep_nesting.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestCountPlaceholders:
    def test_empty_dict(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.count_placeholders(): an empty dict yields a count of zero."""
        assert count_placeholders({}) == 0

    def test_nested_placeholders(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.count_placeholders(): counts exactly the placeholder-valued keys within a flat dict, ignoring real values."""
        assert count_placeholders({"a": "Not Provided", "b": "real"}) == 1

    def test_list_placeholders(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.count_placeholders(): counts placeholder entries within a list, ignoring real entries."""
        assert count_placeholders(["Not Provided", "real"]) == 1

    def test_deep_nesting(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.count_placeholders(): recurses into nested dicts to find a placeholder value at any depth."""
        assert count_placeholders({"outer": {"inner": "To Be Validated"}}) == 1


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] filter_empty_columns() / filter_empty_rows() -- table pruning
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestFilterEmptyColumns` — owns TestFilterEmptyColumns state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_hides_all_placeholder_column, test_keeps_real_column, test_empty_inputs.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestFilterEmptyColumns:
    def test_hides_all_placeholder_column(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.filter_empty_columns(): a column whose cells are all placeholder values is dropped and reported as hidden."""
        columns = ["A", "B"]
        rows = [["x", "Not Provided"], ["y", "Pending"]]
        kept, kept_rows, hidden = filter_empty_columns(columns, rows)
        assert kept == ["A"]
        assert hidden == [1]

    def test_keeps_real_column(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.filter_empty_columns(): a column with at least one real value is kept and nothing is reported as hidden."""
        columns = ["A", "B"]
        rows = [["x", "real"]]
        kept, kept_rows, hidden = filter_empty_columns(columns, rows)
        assert kept == ["A", "B"]
        assert hidden == []

    def test_empty_inputs(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.filter_empty_columns(): empty columns/rows input degrades gracefully to empty output rather than raising."""
        kept, kept_rows, hidden = filter_empty_columns([], [])
        assert kept == []
        assert hidden == []


# [FYP-CLASS] `TestFilterEmptyRows` — owns TestFilterEmptyRows state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_removes_all_placeholder_row, test_keeps_partial_row.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestFilterEmptyRows:
    def test_removes_all_placeholder_row(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.filter_empty_rows(): a row whose cells are all placeholder values is dropped, leaving only the real row."""
        columns = ["A", "B"]
        rows = [["Not Provided", "Pending"], ["real", "value"]]
        kept_cols, kept_rows = filter_empty_rows(columns, rows)
        assert len(kept_rows) == 1
        assert kept_rows[0] == ["real", "value"]

    def test_keeps_partial_row(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.filter_empty_rows(): a row with at least one real value is kept even if other cells are placeholders."""
        columns = ["A", "B"]
        rows = [["real", "Pending"]]
        kept_cols, kept_rows = filter_empty_rows(columns, rows)
        assert len(kept_rows) == 1


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] table_placeholder_ratio() -- compaction trigger metric
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestTablePlaceholderRatio` — owns TestTablePlaceholderRatio state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_no_placeholders, test_all_placeholders, test_mixed.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestTablePlaceholderRatio:
    def test_no_placeholders(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.table_placeholder_ratio(): an all-real table yields a ratio of 0.0."""
        columns = ["A", "B"]
        rows = [["x", "y"]]
        ratio = table_placeholder_ratio(rows, columns)
        assert ratio == 0.0

    def test_all_placeholders(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.table_placeholder_ratio(): an all-placeholder table yields a ratio of 1.0."""
        columns = ["A", "B"]
        rows = [["Not Provided", "Pending"]]
        ratio = table_placeholder_ratio(rows, columns)
        assert ratio == 1.0

    def test_mixed(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.table_placeholder_ratio(): a half-real, half-placeholder table yields a ratio of 0.5."""
        columns = ["A", "B"]
        rows = [["real", "Not Provided"]]
        ratio = table_placeholder_ratio(rows, columns)
        assert ratio == 0.5


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] build_evidence_register_summary() -- evidence table/summary
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestBuildEvidenceRegisterSummary` — owns TestBuildEvidenceRegisterSummary state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_compact_when_many_placeholders, test_full_when_few_placeholders, test_notes_when_timestamp_missing, test_notes_when_raw_reference_missing.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestBuildEvidenceRegisterSummary:
    def test_compact_when_many_placeholders(self):
        """[FYP-FUNCTION] [FYP-VALIDATION] Validates reporting.compact_renderer.build_evidence_register_summary(): evidence entries that are mostly placeholder fields collapse into a compact prose summary with hidden_columns reported, instead of a full table."""
        evidence = [
            {"id": "EV-001", "source": None, "type": "Evidence", "description": "alert", "timestamp": None, "confidence": None, "raw_reference": None},
            {"id": "EV-002", "source": None, "type": "Evidence", "description": "log", "timestamp": None, "confidence": None, "raw_reference": None},
        ]
        result = build_evidence_register_summary(evidence)
        assert result["compact"] is True
        assert result["summary"] is not None
        assert "Evidence register summary:" in result["summary"]
        assert len(result["hidden_columns"]) >= 1

    def test_full_when_few_placeholders(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_evidence_register_summary(): a fully-populated evidence entry is rendered as the full table (compact=False, no summary text)."""
        evidence = [
            {"id": "EV-001", "source": "NetWitness", "type": "SIEM", "description": "alert", "timestamp": "2025-01-01T00:00:00Z", "confidence": "High", "raw_reference": "NW-123"},
        ]
        result = build_evidence_register_summary(evidence)
        assert result["compact"] is False
        assert result["summary"] is None
        assert "Timestamp" in result["columns"]

    def test_notes_when_timestamp_missing(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_evidence_register_summary(): a missing timestamp field on every evidence entry produces an explanatory note and a hidden_rows key."""
        evidence = [
            {"id": "EV-001", "source": None, "type": None, "description": None, "timestamp": None, "confidence": None, "raw_reference": None},
        ]
        result = build_evidence_register_summary(evidence)
        assert any("Timestamps were not supplied" in n for n in result["notes"])
        assert "hidden_rows" in result

    def test_notes_when_raw_reference_missing(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_evidence_register_summary(): a missing raw_reference field on every evidence entry produces its own explanatory note."""
        evidence = [
            {"id": "EV-001", "source": None, "type": None, "description": None, "timestamp": None, "confidence": None, "raw_reference": None},
        ]
        result = build_evidence_register_summary(evidence)
        assert any("Raw event references were not supplied" in n for n in result["notes"])


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] build_data_impact_summary() -- data-impact narrative
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestBuildDataImpactSummary` — owns TestBuildDataImpactSummary state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_returns_compact_summary, test_includes_impact_context.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestBuildDataImpactSummary:
    def test_returns_compact_summary(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_data_impact_summary(): an empty context still yields a well-formed summary with sensible defaults for data access and personal-data involvement."""
        summary = build_data_impact_summary({})
        assert "Data impact assessment:" in summary
        assert "No evidence of data access" in summary
        assert "Personal data involvement: Cannot determine from current evidence" in summary

    def test_includes_impact_context(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_data_impact_summary(): business/security impact_assessment text from the report context is folded into the generated summary verbatim."""
        context = {
            "impact_assessment": {
                "business": "Limited to FINANCE-WKS-017.",
                "security": "Potential malware execution.",
            }
        }
        summary = build_data_impact_summary(context)
        assert "Limited to FINANCE-WKS-017." in summary
        assert "Potential malware execution." in summary


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] build_chain_of_custody_note() -- custody gap disclosure
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestBuildChainOfCustodyNote` — owns TestBuildChainOfCustodyNote state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_note_when_no_real_custody, test_empty_note_when_real_custody_exists, test_empty_note_when_no_evidence.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestBuildChainOfCustodyNote:
    def test_note_when_no_real_custody(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_chain_of_custody_note(): evidence lacking formal custody metadata produces a disclosure note."""
        evidence = [
            {"id": "EV-001", "timestamp": None, "source": None},
        ]
        note = build_chain_of_custody_note(evidence)
        assert "Formal chain-of-custody metadata was not supplied" in note

    def test_empty_note_when_real_custody_exists(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_chain_of_custody_note(): evidence with a full set of custody fields (collector, hash, integrity, etc.) produces no note at all."""
        evidence = [
            {"id": "EV-001", "collection_time": "2025-01-01T00:00:00Z", "collector": "SOC Analyst", "storage_location": "case-folder", "hash": "abc123", "integrity": "verified"},
        ]
        note = build_chain_of_custody_note(evidence)
        assert note == ""

    def test_empty_note_when_no_evidence(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_chain_of_custody_note(): an empty evidence list still yields the custody-gap disclosure note rather than erroring."""
        note = build_chain_of_custody_note([])
        assert "Formal chain-of-custody metadata was not supplied" in note


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] build_approval_summary() -- report/containment approval text
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestBuildApprovalSummary` — owns TestBuildApprovalSummary state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_approved_report_summary, test_containment_summary, test_unknown_note_when_both_unknown.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestBuildApprovalSummary:
    def test_approved_report_summary(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_approval_summary(): an approved report-generation decision renders the analyst's name into the "report" summary line."""
        approval = {"approval_status": "approved", "analyst_decision": "approved", "approved_by": "Soong Yang"}
        containment = {}
        summary = build_approval_summary(approval, containment)
        assert summary["report"].startswith("Report generation approval status: Approved by Soong Yang.")

    def test_containment_summary(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_approval_summary(): a pending-execution containment decision renders both the status and the recommended containment action into their summary lines."""
        approval = {}
        containment = {"status": "approved_pending_execution", "recommended_action": "Isolate FINANCE-WKS-017"}
        summary = build_approval_summary(approval, containment)
        assert "Containment approval status: Approved Pending Execution." in summary["containment"]
        assert "Recommended containment action: Isolate FINANCE-WKS-017." in summary["recommended"]

    def test_unknown_note_when_both_unknown(self):
        """[FYP-FUNCTION] Validates reporting.compact_renderer.build_approval_summary(): empty report and containment approval dicts fall back to the generic "requires analyst validation" note."""
        summary = build_approval_summary({}, {})
        assert "Approval record exists, but approval type requires analyst validation." in summary["note"]


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] markdown_to_blocks() / blocks_from_text() -- table parsing
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestMarkdownTableParsing` — owns TestMarkdownTableParsing state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_compact_markdown_separator_becomes_table_block, test_plain_text_pipe_table_fallback_becomes_table_block.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestMarkdownTableParsing:
    def test_compact_markdown_separator_becomes_table_block(self):
        """[FYP-FUNCTION] Validates reporting.structured_report.markdown_to_blocks(): a standard "| header |\\n|---|---|\\n| row |" markdown table is parsed into a single table block with the expected columns/rows."""
        blocks = markdown_to_blocks("| Field | Value |\n|---|---|\n| A | B |\n")
        assert blocks[0]["type"] == "table"
        assert blocks[0]["columns"] == ["Field", "Value"]
        assert blocks[0]["rows"] == [["A", "B"]]

    def test_plain_text_pipe_table_fallback_becomes_table_block(self):
        """[FYP-FUNCTION] Validates reporting.structured_report.blocks_from_text(): a plain pipe-delimited block without a markdown separator row (LLM output without proper markdown formatting) still parses into a table block via the plain-table fallback."""
        blocks = blocks_from_text("Field | Value\nA | B\nC | D\n")
        assert blocks[0]["type"] == "table"
        assert blocks[0]["columns"] == ["Field", "Value"]
        assert blocks[0]["rows"] == [["A", "B"], ["C", "D"]]
