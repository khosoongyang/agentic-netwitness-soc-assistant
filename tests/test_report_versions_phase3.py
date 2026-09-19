"""Phase 3 of the Reporting redesign: persisted, immutable per-report version
history (report_versions) separated from review facts (report_reviews), plus
the real "Mark as Reviewed" action and the compatibility backfill from the
pre-Phase-3 report_edits table.

Covers: workflow/state_store.py's new CRUD functions directly, and
agents/reporting/report_editing.py's status-resolution/save/discard/
mark_reviewed logic built on top of them.
"""

from __future__ import annotations

import json

import pytest

from workflow import state_store as wss
from agents.reporting import report_editing as re


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "reporting_phase3.db")
    wss.db_init()


INCIDENT_ID = "INC-P3-TEST"
RUN_ID = "INC-P3-TEST@run1"
REPORT_TYPE = "executive_summary"


def _blocks(text):
    return [{"type": "paragraph", "text": text}]


# =============================================================================
# report_versions: immutability
# =============================================================================

def test_create_report_version_appends_never_updates():
    v1 = wss.create_report_version(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        content=_blocks("first"), origin="ai_generated", edited_by="Aegis")
    v2 = wss.create_report_version(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        content=_blocks("second"), origin="analyst_edit", edited_by="Analyst A")

    assert v1["version"] == 1
    assert v2["version"] == 2
    # v1's row, re-read from the DB, must be byte-identical to what was
    # written — nothing about creating v2 may have touched it.
    reloaded_v1 = [row for row in wss.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)
                   if row["version"] == 1][0]
    assert json.loads(reloaded_v1["content_json"]) == _blocks("first")
    assert reloaded_v1["origin"] == "ai_generated"


def test_list_report_versions_orders_newest_first_and_joins_review_facts():
    v1 = wss.create_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE, content=_blocks("a"),
                                   origin="ai_generated", edited_by="Aegis")
    wss.create_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE, content=_blocks("b"),
                              origin="analyst_edit", edited_by="Analyst A")
    wss.create_report_review(v1["id"], reviewed_by="Analyst B")

    rows = wss.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    assert [r["version"] for r in rows] == [2, 1]
    assert rows[1]["review_status"] == "Reviewed"
    assert rows[1]["reviewed_by"] == "Analyst B"
    assert rows[0]["review_status"] is None  # v2 was never reviewed


# =============================================================================
# report_reviews: independence from report_versions, idempotency
# =============================================================================

def test_create_report_review_is_idempotent_per_version():
    v1 = wss.create_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE, content=_blocks("a"),
                                   origin="ai_generated", edited_by="Aegis")
    first = wss.create_report_review(v1["id"], reviewed_by="Analyst A")
    second = wss.create_report_review(v1["id"], reviewed_by="Analyst B")  # re-click
    assert first["id"] == second["id"]
    assert second["reviewed_by"] == "Analyst A"  # first review wins, not silently overwritten


def test_review_never_mutates_the_versioned_content():
    v1 = wss.create_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE, content=_blocks("original"),
                                   origin="ai_generated", edited_by="Aegis")
    wss.create_report_review(v1["id"], reviewed_by="Analyst A")
    reloaded = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    assert reloaded["content_json"] == v1["content_json"]
    assert reloaded["version"] == v1["version"]


# =============================================================================
# resolve_report_status(): the four base states, origin-driven not
# version-number-driven (Correction 1 of the approved design)
# =============================================================================

def test_resolve_report_status_not_generated():
    assert re.resolve_report_status(None, None) == "Not generated"


def test_resolve_report_status_ready_for_review_for_ai_generated_and_assembled_origins():
    ai_version = {"origin": "ai_generated", "version": 1}
    assembled_version = {"origin": "assembled", "version": 3}  # NOT version 1 — origin decides, not version number
    assert re.resolve_report_status(ai_version, None) == "Ready for Review"
    assert re.resolve_report_status(assembled_version, None) == "Ready for Review"


def test_resolve_report_status_edited_for_analyst_edit_origin():
    edited_version = {"origin": "analyst_edit", "version": 2}
    assert re.resolve_report_status(edited_version, None) == "Edited"


def test_resolve_report_status_reviewed_when_review_exists_regardless_of_origin():
    for origin in ("ai_generated", "analyst_edit", "assembled"):
        version = {"origin": origin, "version": 5}
        assert re.resolve_report_status(version, {"reviewed_by": "x"}) == "Reviewed"


# =============================================================================
# report_editing.py: save/discard/mark_reviewed against the live tables
# =============================================================================

def test_save_report_edit_creates_analyst_edit_version():
    row = re.save_report_edit(
        INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("analyst text"), "Analyst A",
        source_report_set_id="set-1")
    assert row["origin"] == "analyst_edit"
    assert row["edited_by"] == "Analyst A"
    assert row["version"] == 1


def test_mark_reviewed_persists_review_and_edit_after_reverts_to_edited():
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("v1"), "Analyst A",
                        source_report_set_id="set-1")
    latest = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    re.mark_reviewed(INCIDENT_ID, RUN_ID, REPORT_TYPE, "Analyst B",
                     expected_report_version_id=latest["id"])

    review = wss.get_report_review(latest["id"])
    assert review is not None
    assert review["reviewed_by"] == "Analyst B"

    status_after_review = re.resolve_report_status(latest, review)
    assert status_after_review == "Reviewed"

    # A further edit must NOT touch the old version or its review row — it
    # appends a new one, and the report reverts to "Edited" for that new
    # version (which has no review row of its own).
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("v2"), "Analyst A",
                        source_report_set_id="set-1")
    new_latest = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    new_review = wss.get_report_review(new_latest["id"])
    assert new_latest["id"] != latest["id"]
    assert new_review is None
    assert re.resolve_report_status(new_latest, new_review) == "Edited"

    # The OLD version's review fact must still be exactly as it was.
    assert wss.get_report_review(latest["id"]) == review


def test_mark_reviewed_rejects_when_report_changed_since_it_was_loaded():
    v1 = re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("v1"), "Analyst A",
                             source_report_set_id="set-1")
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("v2"), "Analyst A",
                        source_report_set_id="set-1")
    with pytest.raises(re.ReportEditingError):
        re.mark_reviewed(INCIDENT_ID, RUN_ID, REPORT_TYPE, "Analyst B",
                         expected_report_version_id=v1["id"])


def test_mark_reviewed_raises_when_nothing_to_review():
    with pytest.raises(re.ReportEditingError):
        re.mark_reviewed(INCIDENT_ID, RUN_ID, REPORT_TYPE, "Analyst A")


def test_discard_report_edit_appends_new_version_and_preserves_the_discarded_one():
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("analyst text"), "Analyst A",
                        source_report_set_id="set-1")
    discarded_version_id = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE)["id"]

    reverted = re.discard_report_edit(
        INCIDENT_ID, RUN_ID, REPORT_TYPE, "Analyst A",
        ai_blocks=_blocks("ai original"), ai_report_set_id="set-1")

    assert reverted["origin"] == "ai_generated"
    assert reverted["edited_by"] == "Aegis"
    assert reverted["version"] == 2

    all_versions = wss.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    assert len(all_versions) == 2  # the discarded edit is NOT deleted
    discarded = [v for v in all_versions if v["id"] == discarded_version_id][0]
    assert json.loads(discarded["content_json"]) == _blocks("analyst text")


# =============================================================================
# report_row_state(): full integration, including compatibility seeding
# =============================================================================

def _current_attempt(blocks, report_set_id="set-live"):
    return {
        "report_set_id": report_set_id,
        "reports": [{"report_type": REPORT_TYPE, "structured_content": blocks,
                     "generated_at": "2026-01-01T00:00:00+00:00"}],
    }


def test_report_row_state_not_generated_when_no_ai_content_and_no_legacy_edit():
    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt([]), reporting_status="Pending",
        reporting_updated_at=None)
    assert row["status"] == "Not generated"
    assert row["exists"] is False


def test_report_row_state_seeds_and_shows_ready_for_review_for_fresh_ai_content():
    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("ai content")), reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    assert row["status"] == "Ready for Review"
    assert row["edited_by"] is None  # not yet "edited" by anyone
    assert row["blocks"] == _blocks("ai content")

    # Calling it again must NOT reseed / duplicate versions.
    re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("ai content")), reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    assert len(wss.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)) == 1


def test_report_row_state_reflects_review_after_mark_reviewed():
    re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("ai content")), reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    latest = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    re.mark_reviewed(INCIDENT_ID, RUN_ID, REPORT_TYPE, "Analyst A",
                     expected_report_version_id=latest["id"])

    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("ai content")), reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    assert row["status"] == "Reviewed"
    assert row["review_status"] == "Reviewed"
    assert row["reviewed_by"] == "Analyst A"


def test_report_row_state_backfills_legacy_report_edits_without_losing_the_analyst_edit():
    # Simulate a pre-Phase-3 analyst edit exactly as upsert_report_edit used
    # to write it, with NO report_versions rows yet.
    wss.upsert_report_edit(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        edited_blocks=_blocks("legacy analyst edit"),
        original_blocks=_blocks("legacy ai original"),
        source_report_set_id="legacy-set", analyst="Legacy Analyst")

    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("legacy ai original"), report_set_id="legacy-set"),
        reporting_status="Awaiting Approval", reporting_updated_at=None)

    # The analyst's edit must still be what's shown — not silently replaced
    # by the AI original.
    assert row["status"] == "Edited"
    assert row["blocks"] == _blocks("legacy analyst edit")
    assert row["edited_by"] == "Legacy Analyst"

    versions = wss.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    assert len(versions) == 2
    by_version = {v["version"]: v for v in versions}
    assert by_version[1]["origin"] == "ai_generated"
    assert json.loads(by_version[1]["content_json"]) == _blocks("legacy ai original")
    assert by_version[2]["origin"] == "analyst_edit"
    assert json.loads(by_version[2]["content_json"]) == _blocks("legacy analyst edit")

    # The legacy report_edits row itself must be untouched, not deleted.
    legacy_row = wss.get_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    assert legacy_row is not None
    assert legacy_row["last_edited_by"] == "Legacy Analyst"


def test_report_row_state_shows_edited_when_analyst_edit_is_the_very_first_version():
    # Regression test: a report that has never been generated by the AI
    # pipeline (empty current_attempt, so ensure_report_version_seeded()
    # never runs) can still receive a manual analyst save — that save lands
    # as version 1, not version 2+. Status/has_edits must be driven by
    # origin ("analyst_edit"), never by version number (Correction 1 of the
    # approved design) — a naive `version > 1` check would misclassify this
    # exact case as "Ready for Review"/"Not generated" instead of "Edited".
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("manual edit, no AI seed"),
                        "Analyst A", source_report_set_id=None)
    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt([]), reporting_status="Pending",
        reporting_updated_at=None)
    assert row["status"] == "Edited"
    assert row["has_edits"] is True
    assert row["edited_by"] == "Analyst A"
    assert row["blocks"] == _blocks("manual edit, no AI seed")


def test_list_report_versions_shapes_newest_first_with_review_facts():
    v1 = re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("v1"), "Analyst A",
                             source_report_set_id="set-1")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, REPORT_TYPE, "Analyst B",
                     expected_report_version_id=v1["id"])
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("v2"), "Analyst A",
                        source_report_set_id="set-1")

    versions = re.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)
    assert [v["version"] for v in versions] == [2, 1]
    assert versions[0]["origin"] == "analyst_edit"
    assert versions[0]["review_status"] is None
    assert versions[0]["blocks"] == _blocks("v2")
    assert versions[1]["review_status"] == "Reviewed"
    assert versions[1]["reviewed_by"] == "Analyst B"
    assert versions[1]["blocks"] == _blocks("v1")


def test_report_row_state_does_not_reseed_once_analyst_edit_exists_via_new_path():
    re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("ai content")), reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    re.save_report_edit(INCIDENT_ID, RUN_ID, REPORT_TYPE, _blocks("real edit"), "Analyst A",
                        source_report_set_id="set-live")
    row = re.report_row_state(
        INCIDENT_ID, RUN_ID, REPORT_TYPE,
        current_attempt=_current_attempt(_blocks("ai content")), reporting_status="Awaiting Approval",
        reporting_updated_at=None)
    assert row["blocks"] == _blocks("real edit")
    assert len(wss.list_report_versions(INCIDENT_ID, RUN_ID, REPORT_TYPE)) == 2
