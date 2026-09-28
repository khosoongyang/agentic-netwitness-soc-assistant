"""Phase 6 of the Reporting redesign: materialising a NEW, immutable
reviewed candidate set from the four core reports' latest REVIEWED
versions. Never mutates or overwrites the original AI-generated
candidate_manifest.json (v1), and is built in exactly the shape
reporting_approval._verify_candidate_manifest() already knows how to
validate — that function is completely unmodified for this phase.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from workflow import state_store as wss
from workflow import engine as sw
from agents.reporting import report_editing as re
from agents.reporting import reporting_approval as ra
from agents.reporting.reporting.candidate_materialiser import (
    CandidateMaterialisationError, materialise_reviewed_candidate)


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "phase6.db")
    wss.db_init()


@pytest.fixture(autouse=True)
def _isolated_artifact_root(monkeypatch):
    # A materialised candidate's own on-disk paths nest many levels deep
    # (…/reporting/attempt_N/outputs/<incident_id>/reports/
    # reviewed_candidates/<token>/<report>.docx). Real production's
    # _TRUSTED_OUTPUT_ROOT is a short, fixed path under the repo, but
    # pytest's default tmp_path (pytest-of-<user>/pytest-NNN/<full test
    # function name>0/…) is verbose enough to hit Windows' ~260-char
    # MAX_PATH at this depth — a test-harness artifact, not a real
    # production constraint. Use a short, manually-managed temp root
    # instead of tmp_path here so this test exercises real path depth.
    base = Path(tempfile.mkdtemp(prefix="p6-"))
    trusted_root = base / "trusted_outputs"
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", trusted_root)
    monkeypatch.setattr(ra, "_TRUSTED_OUTPUT_ROOT", trusted_root)
    yield
    shutil.rmtree(base, ignore_errors=True)


INCIDENT_ID = "INC-P6-TEST"
RUN_ID = "INC-P6-TEST@run1"
ATTEMPT = 1
ALL_FOUR = ("executive_summary", "technical_findings", "soc_analyst_review", "final_incident_report")


def _blocks(text):
    return [{"type": "paragraph", "text": text}]


def _review_component(incident_id, run_id, report_type, text, analyst="Analyst A"):
    version = re.save_report_edit(incident_id, run_id, report_type, _blocks(text), analyst,
                                  source_report_set_id="set-1")
    re.mark_reviewed(incident_id, run_id, report_type, analyst, expected_report_version_id=version["id"])
    return version


def _review_all_four(incident_id=INCIDENT_ID, run_id=RUN_ID):
    _review_component(incident_id, run_id, "executive_summary", "exec content")
    _review_component(incident_id, run_id, "technical_findings", "tech content")
    _review_component(incident_id, run_id, "soc_analyst_review", "soc content")  # triggers assembly
    final_latest = wss.get_latest_report_version(incident_id, run_id, "final_incident_report")
    re.mark_reviewed(incident_id, run_id, "final_incident_report", "Analyst A",
                     expected_report_version_id=final_latest["id"])


# =============================================================================
# Gate: no submission without all four reviewed (Correction 10)
# =============================================================================

def test_submit_for_approval_refuses_unless_all_four_are_reviewed():
    _review_component(INCIDENT_ID, RUN_ID, "executive_summary", "exec content")
    _review_component(INCIDENT_ID, RUN_ID, "technical_findings", "tech content")
    # soc_analyst_review and final_incident_report not reviewed yet.
    with pytest.raises(re.ReportEditingError):
        re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst A")


def test_materialise_reviewed_candidate_rejects_incomplete_input_directly():
    with pytest.raises(CandidateMaterialisationError):
        materialise_reviewed_candidate(
            sw.reporting_attempt_dir(INCIDENT_ID, RUN_ID, ATTEMPT),
            INCIDENT_ID, RUN_ID, ATTEMPT,
            reviewed_reports={"executive_summary": {"version_id": 1, "blocks": _blocks("x")}},
            based_on_report_set_id=None, analyst="Analyst A")


# =============================================================================
# The materialised candidate itself
# =============================================================================

def test_submit_for_approval_materialises_a_new_immutable_candidate_set():
    _review_all_four()
    manifest = re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst A")

    assert manifest["incident_id"] == INCIDENT_ID
    assert manifest["run_id"] == RUN_ID
    assert manifest["reporting_stage_attempt"] == ATTEMPT
    assert len(manifest["reports"]) == 4
    assert {r["report_type"] for r in manifest["reports"]} == set(ALL_FOUR)
    for r in manifest["reports"]:
        assert r["validation"]["status"] in ("valid", "warning")
        assert r["structured_content"]["sha256"]
        assert r["docx"]["sha256"]
        assert r["pdf"]["sha256"]

    report_set = wss.get_latest_report_set(INCIDENT_ID, RUN_ID)
    assert report_set["report_set_id"] == manifest["report_set_id"]
    assert report_set["status"] == "materialised"
    assert report_set["created_by"] == "Analyst A"
    version_ids = json.loads(report_set["report_version_ids_json"])
    assert set(version_ids) == set(ALL_FOUR)


def test_materialised_manifest_passes_the_existing_unchanged_verification_function():
    _review_all_four()
    manifest = re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst A")
    report_set = wss.get_latest_report_set(INCIDENT_ID, RUN_ID)

    # The critical correctness property for this phase: reporting_approval.
    # _verify_candidate_manifest() — completely unmodified — must accept
    # what this module produces, with no special-casing.
    verified = ra._verify_candidate_manifest(
        report_set["manifest_path"], incident_id=INCIDENT_ID, run_id=RUN_ID,
        expected_reporting_attempt=ATTEMPT)
    assert verified["report_set_id"] == manifest["report_set_id"]
    assert verified["candidate_manifest_sha256"] == manifest["candidate_manifest_sha256"]


def test_tampering_with_a_materialised_file_is_detected_by_the_unchanged_verifier():
    _review_all_four()
    re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst A")
    report_set = wss.get_latest_report_set(INCIDENT_ID, RUN_ID)
    manifest = json.loads(Path(report_set["manifest_path"]).read_text(encoding="utf-8"))
    docx_rel_path = manifest["reports"][0]["docx"]["path"]
    attempt_dir = sw.reporting_attempt_dir(INCIDENT_ID, RUN_ID, ATTEMPT)
    docx_abs_path = attempt_dir / docx_rel_path
    docx_abs_path.write_bytes(b"tampered bytes")

    with pytest.raises(ra.ReportValidationError):
        ra._verify_candidate_manifest(
            report_set["manifest_path"], incident_id=INCIDENT_ID, run_id=RUN_ID,
            expected_reporting_attempt=ATTEMPT)


# =============================================================================
# Lineage: based_on_report_set_id resolution, immutability across submissions
# =============================================================================

def test_based_on_report_set_id_falls_back_to_the_registered_generated_row():
    # Simulate the export_documents.py registration hook having already
    # registered the original AI-generated candidate as report_sets row #1.
    wss.create_report_set(
        INCIDENT_ID, RUN_ID, report_set_id="v1-report-set-id", based_on_report_set_id=None,
        manifest_path="/fake/v1/candidate_manifest.json", manifest_sha256="deadbeef",
        report_version_ids={}, status="generated", created_by="Aegis")

    _review_all_four()
    manifest = re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst A")
    assert manifest["based_on_report_set_id"] == "v1-report-set-id"


def test_second_submission_creates_a_new_set_and_never_touches_the_first():
    _review_all_four()
    first_manifest = re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst A")
    first_report_set = wss.get_latest_report_set(INCIDENT_ID, RUN_ID)
    first_manifest_path = first_report_set["manifest_path"]
    first_manifest_bytes_before = open(first_manifest_path, "rb").read()

    # A component changes and is reviewed again -> Final Incident Report
    # re-assembles -> needs re-review -> full set reviewed again.
    _review_component(INCIDENT_ID, RUN_ID, "executive_summary", "exec content v2")
    final_latest = wss.get_latest_report_version(INCIDENT_ID, RUN_ID, "final_incident_report")
    re.mark_reviewed(INCIDENT_ID, RUN_ID, "final_incident_report", "Analyst A",
                     expected_report_version_id=final_latest["id"])

    second_manifest = re.submit_for_approval(INCIDENT_ID, RUN_ID, ATTEMPT, analyst="Analyst B")

    assert second_manifest["report_set_id"] != first_manifest["report_set_id"]
    all_sets = wss.list_report_sets(INCIDENT_ID, RUN_ID)
    assert len(all_sets) == 2
    assert {s["status"] for s in all_sets} == {"materialised"}

    # The FIRST manifest file on disk is byte-for-byte unchanged.
    assert open(first_manifest_path, "rb").read() == first_manifest_bytes_before
