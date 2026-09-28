"""Phase 7 of the Reporting redesign: precise current-vs-approved status
resolution (Correction 4) — "Approved"/"Finalised" must be shown only when
the CURRENT latest report_versions row is exactly the one baked into the
most recently approved report_sets row, never merely because the whole
workflow's reporting_status flag says "Approved". Also covers the legacy
fallback for approvals that predate per-report version tracking.

Pure DB-level tests — no filesystem/candidate-manifest machinery needed
(see tests/test_reporting_stage.py for the full materialise+approve
integration test, which reuses that file's existing real-docx/pdf fixtures).
"""

from __future__ import annotations

import pytest

from workflow import state_store as wss
from agents.reporting import report_editing as re


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "phase7.db")
    wss.db_init()


INCIDENT_ID = "INC-P7-TEST"
RUN_ID = "INC-P7-TEST@run1"
ALL_FOUR = ("executive_summary", "technical_findings", "soc_analyst_review", "final_incident_report")


def _blocks(text):
    return [{"type": "paragraph", "text": text}]


def _current_attempt(report_set_id="set-1"):
    return {"report_set_id": report_set_id, "reports": []}


def test_approved_status_shown_when_current_version_matches_the_approved_set():
    saved = re.save_report_edit(INCIDENT_ID, RUN_ID, "executive_summary", _blocks("reviewed"), "Analyst A",
                                source_report_set_id="set-1")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "executive_summary", "Analyst A", expected_report_version_id=saved["id"])

    wss.create_report_set(
        INCIDENT_ID, RUN_ID, report_set_id="approved-set-1", based_on_report_set_id=None,
        manifest_path="/fake/path.json", manifest_sha256="deadbeef",
        report_version_ids={rt: (saved["id"] if rt == "executive_summary" else 0) for rt in ALL_FOUR},
        status="approved", created_by="Analyst A")

    row = re.report_row_state(INCIDENT_ID, RUN_ID, "executive_summary",
                              current_attempt=_current_attempt(), reporting_status="Approved",
                              reporting_updated_at=None)
    assert row["status"] == "Approved"


def test_final_incident_report_shows_finalised_not_approved():
    saved = re.save_report_edit(INCIDENT_ID, RUN_ID, "final_incident_report", _blocks("assembled"), "Aegis",
                                source_report_set_id="set-1")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "final_incident_report", "Analyst A",
                     expected_report_version_id=saved["id"])
    wss.create_report_set(
        INCIDENT_ID, RUN_ID, report_set_id="approved-set-1", based_on_report_set_id=None,
        manifest_path="/fake/path.json", manifest_sha256="deadbeef",
        report_version_ids={rt: (saved["id"] if rt == "final_incident_report" else 0) for rt in ALL_FOUR},
        status="approved", created_by="Analyst A")

    row = re.report_row_state(INCIDENT_ID, RUN_ID, "final_incident_report",
                              current_attempt=_current_attempt(), reporting_status="Approved",
                              reporting_updated_at=None)
    assert row["status"] == "Finalised"


def test_edit_after_approval_shows_edited_not_approved():
    """The Correction 4 scenario: v4 approved, then edited -> v5. The table
    must show "Edited", never "Finalised"/"Approved", just because
    reporting_status still says Approved."""
    v4 = re.save_report_edit(INCIDENT_ID, RUN_ID, "executive_summary", _blocks("v4 reviewed"), "Analyst A",
                             source_report_set_id="set-1")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "executive_summary", "Analyst A", expected_report_version_id=v4["id"])
    wss.create_report_set(
        INCIDENT_ID, RUN_ID, report_set_id="approved-set-1", based_on_report_set_id=None,
        manifest_path="/fake/path.json", manifest_sha256="deadbeef",
        report_version_ids={rt: (v4["id"] if rt == "executive_summary" else 0) for rt in ALL_FOUR},
        status="approved", created_by="Analyst A")

    row_before = re.report_row_state(INCIDENT_ID, RUN_ID, "executive_summary",
                                     current_attempt=_current_attempt(), reporting_status="Approved",
                                     reporting_updated_at=None)
    assert row_before["status"] == "Approved"

    re.save_report_edit(INCIDENT_ID, RUN_ID, "executive_summary", _blocks("v5 edited after approval"),
                        "Analyst B", source_report_set_id="set-1")

    row_after = re.report_row_state(INCIDENT_ID, RUN_ID, "executive_summary",
                                    current_attempt=_current_attempt(), reporting_status="Approved",
                                    reporting_updated_at=None)
    assert row_after["status"] == "Edited"

    # The approved report_sets row itself is completely untouched.
    still_approved = wss.get_latest_report_set(INCIDENT_ID, RUN_ID, status="approved")
    assert still_approved["report_set_id"] == "approved-set-1"


def test_reassembled_final_incident_report_after_approval_also_loses_approved_status():
    """Same scenario, but via re-assembly (origin='assembled') rather than
    a direct analyst edit — has_edits alone can't catch this, only the
    version-id comparison can."""
    v1 = re.save_report_edit(INCIDENT_ID, RUN_ID, "final_incident_report", _blocks("assembled v1"), "Aegis",
                             source_report_set_id="set-1")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "final_incident_report", "Analyst A", expected_report_version_id=v1["id"])
    wss.create_report_set(
        INCIDENT_ID, RUN_ID, report_set_id="approved-set-1", based_on_report_set_id=None,
        manifest_path="/fake/path.json", manifest_sha256="deadbeef",
        report_version_ids={rt: (v1["id"] if rt == "final_incident_report" else 0) for rt in ALL_FOUR},
        status="approved", created_by="Analyst A")

    # A component changed and Final Incident Report was re-assembled
    # (origin='assembled', not 'analyst_edit' -> has_edits stays False).
    wss.create_report_version(
        INCIDENT_ID, RUN_ID, "final_incident_report",
        content=_blocks("assembled v2 — different content"), origin="assembled", edited_by="Aegis",
        source_version_ids={"executive_summary": 99})

    row = re.report_row_state(INCIDENT_ID, RUN_ID, "final_incident_report",
                              current_attempt=_current_attempt(), reporting_status="Approved",
                              reporting_updated_at=None)
    assert row["status"] != "Finalised"
    assert row["status"] == "Ready for Review"


def test_legacy_approval_without_version_tracking_still_shows_approved():
    """Backward compatibility: an approval whose report_sets row has an
    EMPTY report_version_ids_json (a direct v1 approval predating the
    reviewed-candidate flow) must fall back to the old whole-workflow
    check, so existing approved incidents don't lose their displayed
    status just because Phase 7 shipped."""
    saved = re.save_report_edit(INCIDENT_ID, RUN_ID, "executive_summary", _blocks("legacy content"), "Analyst A",
                                source_report_set_id="set-1")
    wss.create_report_set(
        INCIDENT_ID, RUN_ID, report_set_id="legacy-approved-set", based_on_report_set_id=None,
        manifest_path="/fake/path.json", manifest_sha256="deadbeef",
        report_version_ids={}, status="approved", created_by="Aegis")

    row = re.report_row_state(INCIDENT_ID, RUN_ID, "executive_summary",
                              current_attempt=_current_attempt(), reporting_status="Approved",
                              reporting_updated_at=None)
    assert row["status"] == "Approved"


def test_no_approved_report_set_and_not_approved_workflow_status_shows_normal_status():
    saved = re.save_report_edit(INCIDENT_ID, RUN_ID, "executive_summary", _blocks("draft"), "Analyst A",
                                source_report_set_id="set-1")
    row = re.report_row_state(INCIDENT_ID, RUN_ID, "executive_summary",
                              current_attempt=_current_attempt(), reporting_status="Awaiting Approval",
                              reporting_updated_at=None)
    assert row["status"] == "Edited"
