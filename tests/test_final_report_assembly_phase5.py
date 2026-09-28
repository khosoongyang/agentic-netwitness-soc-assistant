"""Phase 5 of the Reporting redesign: automatic Final Incident Report
assembly from the latest REVIEWED versions of the three component reports —
no LLM call, no Investigation re-run, content taken verbatim.

Covers: agents/reporting/reporting/final_report_assembler.py (pure function)
and the trigger wired into agents/reporting/report_editing.py::mark_reviewed().
"""

from __future__ import annotations

import json

import pytest

from workflow import state_store as wss
from agents.reporting import report_editing as re
from agents.reporting.reporting.final_report_assembler import assemble_final_incident_report


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "phase5.db")
    wss.db_init()


INCIDENT_ID = "INC-P5-TEST"
RUN_ID = "INC-P5-TEST@run1"
COMPONENTS = ("executive_summary", "technical_findings", "soc_analyst_review")


def _blocks(text):
    return [{"type": "paragraph", "text": text}]


def _review_component(report_type, text, analyst="Analyst A"):
    version = re.save_report_edit(INCIDENT_ID, RUN_ID, report_type, _blocks(text), analyst,
                                  source_report_set_id="set-1")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, report_type, analyst, expected_report_version_id=version["id"])
    return version


# =============================================================================
# assemble_final_incident_report(): pure function
# =============================================================================

def test_assemble_final_incident_report_combines_sections_verbatim_in_order():
    sections = {
        "executive_summary": _blocks("exec summary content"),
        "technical_findings": _blocks("technical findings content"),
        "soc_analyst_review": _blocks("soc analyst review content"),
    }
    blocks = assemble_final_incident_report("INC-1", reviewed_sections=sections)

    texts_in_order = [b.get("text") for b in blocks if b.get("type") in ("heading", "paragraph")]
    assert texts_in_order.index("Executive Summary") < texts_in_order.index("exec summary content")
    assert texts_in_order.index("exec summary content") < texts_in_order.index("Technical Findings")
    assert texts_in_order.index("technical findings content") < texts_in_order.index("SOC Analyst Review")
    assert "soc analyst review content" in texts_in_order
    # verbatim — not rewritten, not summarised
    assert sections["executive_summary"][0]["text"] in texts_in_order


# =============================================================================
# Trigger: mark_reviewed() -> _maybe_assemble_final_incident_report()
# =============================================================================

def test_no_assembly_until_all_three_components_are_reviewed():
    _review_component("executive_summary", "exec v1")
    assert wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report") is None

    _review_component("technical_findings", "tech v1")
    assert wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report") is None


def test_assembly_triggers_automatically_once_all_three_are_reviewed():
    _review_component("executive_summary", "exec v1")
    _review_component("technical_findings", "tech v1")
    exec_v = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "executive_summary")
    tech_v = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "technical_findings")
    soc_v = _review_component("soc_analyst_review", "soc v1")

    final_version = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report")
    assert final_version is not None
    assert final_version["origin"] == "assembled"
    assert final_version["edited_by"] == "Aegis"

    source_ids = json.loads(final_version["source_version_ids_json"])
    assert source_ids == {
        "executive_summary": exec_v["id"],
        "technical_findings": tech_v["id"],
        "soc_analyst_review": soc_v["id"],
    }

    content = json.loads(final_version["content_json"])
    texts = [b.get("text") for b in content]
    assert "exec v1" in texts
    assert "tech v1" in texts
    assert "soc v1" in texts

    # Not yet reviewed itself -> resolves to "Ready for Review", not "Reviewed"
    review = wss.get_report_review(final_version["id"])
    assert re.resolve_report_status(final_version, review) == "Ready for Review"


def test_assembly_is_idempotent_when_nothing_changed():
    _review_component("executive_summary", "exec v1")
    _review_component("technical_findings", "tech v1")
    _review_component("soc_analyst_review", "soc v1")
    first_final = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report")

    # Re-marking an already-reviewed component reviewed again (e.g. a
    # double-click) must NOT create a second, redundant assembled version.
    exec_latest = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "executive_summary")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "executive_summary", "Analyst B",
                     expected_report_version_id=exec_latest["id"])

    all_final_versions = wss.list_report_versions(INCIDENT_ID, RUN_ID, "final_incident_report")
    assert len(all_final_versions) == 1
    assert all_final_versions[0]["id"] == first_final["id"]


def test_component_changed_and_reviewed_again_creates_new_final_version_and_preserves_the_old_one():
    _review_component("executive_summary", "exec v1")
    _review_component("technical_findings", "tech v1")
    _review_component("soc_analyst_review", "soc v1")
    first_final = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report")

    # An analyst reviews the assembled Final Incident Report itself.
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "final_incident_report", "Analyst C",
                     expected_report_version_id=first_final["id"])
    assert wss.get_report_review(first_final["id"]) is not None

    # Now a component changes and is reviewed again.
    _review_component("executive_summary", "exec v2 — materially different")

    second_final = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report")
    assert second_final["id"] != first_final["id"]
    assert second_final["origin"] == "assembled"
    content = json.loads(second_final["content_json"])
    assert any(b.get("text") == "exec v2 — materially different" for b in content)

    # The OLD assembled version, and its review, remain exactly as they were.
    reloaded_first = [v for v in wss.list_report_versions(INCIDENT_ID, RUN_ID, "final_incident_report")
                      if v["id"] == first_final["id"]][0]
    assert reloaded_first["content_json"] == first_final["content_json"]
    assert wss.get_report_review(first_final["id"]) is not None

    # The NEW version has no review of its own yet — reviewing the old one
    # never carries over to content that changed underneath it.
    assert wss.get_report_review(second_final["id"]) is None
    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, "final_incident_report",
        current_attempt={"report_set_id": "set-1", "reports": []},
        reporting_status="Pending", reporting_updated_at=None)
    assert row["status"] == "Ready for Review"


# =============================================================================
# final_incident_report must never be seeded from the AI pipeline's own
# independently-rendered draft — only assembly may create its first version.
# =============================================================================

def test_final_incident_report_is_never_seeded_from_ai_pipeline_original():
    current_attempt = {
        "report_set_id": "set-1",
        "reports": [{"report_type": "final_incident_report",
                     "structured_content": _blocks("independent AI draft — should be ignored"),
                     "generated_at": "2026-01-01T00:00:00+00:00"}],
    }
    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, "final_incident_report",
        current_attempt=current_attempt, reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    assert row["status"] == "Not generated"
    assert row["exists"] is False
    assert wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report") is None
