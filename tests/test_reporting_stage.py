from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import workflow_state_store as wss
import soc_workflow as sw
import reporting_approval as ra
import case_view as cv


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "reporting.db")
    wss.db_init()


@pytest.fixture(autouse=True)
def _isolated_artifact_root(tmp_path, monkeypatch):
    """Every run-scoped path (reporting_attempt_dir / _artifact_dir) is
    computed from soc_workflow._TRUSTED_OUTPUT_ROOT — isolate it to a tmp
    dir so tests never touch the real soc_reporting_agent/outputs tree."""
    trusted_root = tmp_path / "trusted_outputs"
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", trusted_root)
    monkeypatch.setattr(ra, "_TRUSTED_OUTPUT_ROOT", trusted_root)
    return trusted_root


def _run_awaiting_reporting_approval(incident_id: str = "INC-1") -> str:
    run_id = wss.start_run(incident_id)
    wss._guarded_update(incident_id, run_id, {
        "triage_status": "Approved",
        "threat_intel_status": "Complete",
        "investigation_status": "Approved",
        "reporting_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "reporting",
    })
    return run_id


def _write_minimal_docx(path: Path) -> None:
    from docx import Document
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = Document()
    doc.add_paragraph("Test report content.")
    doc.save(str(path))


def _write_minimal_pdf(path: Path) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    SimpleDocTemplate(str(path), pagesize=A4).build(
        [Paragraph("Test report content.", styles["BodyText"])])


_ALL_CORE_REPORT_TYPES = ("executive_summary", "technical_findings",
                         "soc_analyst_review", "final_incident_report")


def _build_candidate_set(incident_id: str, run_id: str, attempt: int, trusted_root: Path,
                         *, report_types=_ALL_CORE_REPORT_TYPES) -> tuple[Path, dict]:
    """Builds a real, on-disk candidate set (structured content + real
    DOCX + real PDF for each report type) and finalizes it via
    editable_reports.finalize_candidate_manifest()'s own hashing/atomic-
    write logic reused here directly for test setup speed — instead we
    hand-construct a report_manifest.json shaped exactly like
    editable_reports.build_report_manifest() would produce, then call the
    real finalize_candidate_manifest()."""
    import sys
    rep_dir = str(Path(__file__).resolve().parent.parent / "soc_reporting_agent")
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from reporting import editable_reports as er

    attempt_dir = sw.reporting_attempt_dir(incident_id, run_id, attempt)
    output_dir = attempt_dir / "outputs"
    incident_report_dir = er.incident_report_dir(output_dir, incident_id)
    confirmed_dir = er.confirmed_dir(output_dir, incident_id)
    exports_dir = er.exports_dir(output_dir, incident_id)
    confirmed_dir.mkdir(parents=True, exist_ok=True)
    exports_dir.mkdir(parents=True, exist_ok=True)

    sections = {}
    for key in report_types:
        structured_path = confirmed_dir / f"{key}.json"
        structured_path.write_text(json.dumps(
            [{"type": "heading", "level": 1, "text": key},
             {"type": "paragraph", "text": "Body text."}]), encoding="utf-8")
        docx_path = exports_dir / f"{key}.docx"
        pdf_path = exports_dir / f"{key}.pdf"
        _write_minimal_docx(docx_path)
        _write_minimal_pdf(pdf_path)
        sections[key] = {
            "key": key, "title": key.replace("_", " ").title(), "template": f"{key}.md.j2",
            "structured_confirmed_path": str(structured_path),
            "exports": {"docx": {"path": str(docx_path)}, "pdf": {"path": str(pdf_path)}},
        }
    manifest = {"schema_version": "editable-report-manifest-v2", "incident_id": incident_id,
               "sections": sections, "section_order": list(report_types)}
    (incident_report_dir / "report_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")

    candidate = er.finalize_candidate_manifest(output_dir, incident_id, run_id, attempt)
    return er.candidate_manifest_path(output_dir, incident_id), candidate


def _approve_via_state(incident_id: str, run_id: str, attempt: int,
                       candidate_manifest_path: Path) -> None:
    """Stamps reporting_result_json the way run_reporting_stage() would,
    then transitions to Awaiting Approval so approve_reporting_candidate()
    has something real to validate."""
    result = {"status": "completed",
             "document_exports": {"candidate_manifest_path": str(candidate_manifest_path)}}
    wss._guarded_update(incident_id, run_id, {
        "reporting_attempt": attempt,
        "reporting_result_json": json.dumps(result),
        "reporting_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "reporting",
    })


def test_run_scoped_handoff_includes_threat_intel_in_reporting_inputs(
        tmp_path, monkeypatch, _isolated_artifact_root):
    incident_id = "INC-HANDOFF-1"
    run_id = "run-handoff-1"
    attempt = 2
    monkeypatch.setattr(sw, "REP_DIR", tmp_path)

    parsing_dir = tmp_path / "outputs" / incident_id / run_id / "parsing"
    parsing_dir.mkdir(parents=True)
    (parsing_dir / "processed_alert.json").write_text(json.dumps({
        "incident_id": incident_id,
        "alert_id": "ALERT-HANDOFF-1",
    }), encoding="utf-8")

    threat_intel = {
        "incident_id": incident_id,
        "run_id": run_id,
        "stage": "threat_intelligence",
        "status": "completed",
        "threat_intelligence": {"iocs": {}},
    }
    sw.handoff_to_reporting(
        {
            "metakeys_payload": {"incident_id": incident_id},
            "ticket": {"incident_id": incident_id, "unc": "#HANDOFF-1"},
        },
        {"id": incident_id, "title": "Handoff regression test"},
        {"incident_id": incident_id, "status": "completed", "summary": "Done"},
        threat_intel_result=threat_intel,
        incident_id=incident_id,
        run_id=run_id,
        reporting_stage_attempt=attempt,
    )

    attempt_dir = sw.reporting_attempt_dir(incident_id, run_id, attempt)
    input_path = attempt_dir / "inputs" / "threat_intel_result.json"
    output_path = attempt_dir / "outputs" / "threat_intel_result.json"
    assert json.loads(input_path.read_text(encoding="utf-8")) == threat_intel
    assert json.loads(output_path.read_text(encoding="utf-8")) == threat_intel

    manifest = json.loads(
        (attempt_dir / "inputs" / "handoff_manifest.json").read_text(encoding="utf-8"))
    assert str(Path("inputs") / "threat_intel_result.json") in manifest["files"]
    assert str(Path("outputs") / "threat_intel_result.json") in manifest["files"]


# ══════════════════════════════════════════════════════════════════════
# workflow_state_store.py — durable approval binding
# ══════════════════════════════════════════════════════════════════════

def test_commit_reporting_approval_is_only_approve_reporting_workflow_status_setter():
    run_id = _run_awaiting_reporting_approval()
    state = wss.get_state("INC-1")
    result = wss.commit_reporting_approval(
        "INC-1", run_id, expected_reporting_attempt=state["reporting_attempt"],
        expected_reporting_result_json=state["reporting_result_json"],
        metadata={"report_set_id": "rs-1"}, approved_by="analyst")
    assert result["incident_id"] == "INC-1"
    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Approved"
    assert state["workflow_status"] == "Complete"


def test_commit_reporting_approval_fails_when_reporting_result_json_changed():
    run_id = _run_awaiting_reporting_approval()
    state = wss.get_state("INC-1")
    captured_json = state["reporting_result_json"]
    # Simulate a concurrent rerun changing reporting_result_json between
    # the caller's validation pass and this call.
    wss._guarded_update("INC-1", run_id, {"reporting_result_json": json.dumps({"x": 1})})
    with pytest.raises(wss.ApprovalConflictError):
        wss.commit_reporting_approval(
            "INC-1", run_id, expected_reporting_attempt=state["reporting_attempt"],
            expected_reporting_result_json=captured_json,
            metadata={}, approved_by="analyst")


def test_commit_reporting_approval_fails_when_attempt_changed():
    run_id = _run_awaiting_reporting_approval()
    state = wss.get_state("INC-1")
    with pytest.raises(wss.ApprovalConflictError):
        wss.commit_reporting_approval(
            "INC-1", run_id, expected_reporting_attempt=state["reporting_attempt"] + 1,
            expected_reporting_result_json=state["reporting_result_json"],
            metadata={}, approved_by="analyst")


def test_get_approved_reporting_sets_reads_durable_metadata_survives_rerun_clear():
    run_id = _run_awaiting_reporting_approval()
    state = wss.get_state("INC-1")
    wss.commit_reporting_approval(
        "INC-1", run_id, expected_reporting_attempt=state["reporting_attempt"],
        expected_reporting_result_json=state["reporting_result_json"],
        metadata={"report_set_id": "rs-durable", "candidate_manifest_path": "x",
                 "candidate_manifest_sha256": "abc", "reporting_stage_attempt": 1,
                 "validation_status": "valid", "warning_count": 0},
        approved_by="analyst")

    # rerun clears the working reporting_result_json — the durable
    # approval record must not be affected.
    wss.rerun_stage("INC-1", run_id, "reporting")
    state = wss.get_state("INC-1")
    assert state["reporting_result_json"] is None

    latest = wss.get_latest_approved_reporting_set("INC-1", run_id)
    assert latest is not None
    assert latest["report_set_id"] == "rs-durable"
    assert latest["candidate_manifest_sha256"] == "abc"


def test_rejected_reporting_attempt_can_be_rerun():
    run_id = _run_awaiting_reporting_approval()
    wss.reject_reporting("INC-1", run_id, rejected_by="analyst", reason="needs fixes")
    assert wss.get_state("INC-1")["reporting_status"] == "Rejected"
    wss.rerun_stage("INC-1", run_id, "reporting")
    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Processing"
    assert state["reporting_attempt"] == 2


def test_complete_stage_expected_stage_attempt_rejects_stale_worker():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {"reporting_status": "Processing"})
    worker_id, attempt = wss.claim_stage(
        "INC-1", run_id, stage="reporting", status_column="reporting_status",
        expect_status="Processing")
    # Simulate the attempt having moved on before this (late) worker saves.
    wss._guarded_update("INC-1", run_id, {"reporting_attempt": attempt + 1})
    ok = wss.complete_stage(
        "INC-1", run_id, worker_id, stage="reporting", result_column="reporting_result_json",
        result={"status": "completed"},
        status_updates={"reporting_status": "Awaiting Approval"},
        expected_stage_attempt=attempt)
    assert ok is False


# ══════════════════════════════════════════════════════════════════════
# reporting_approval.py — layering + validation
# ══════════════════════════════════════════════════════════════════════

def test_workflow_state_store_has_no_report_specific_validation_imports():
    import inspect
    src = inspect.getsource(wss)
    for banned in ("import docx", "import pypdf", "from docx", "hashlib.sha256(Path"):
        assert banned not in src, f"workflow_state_store.py must not import/do report validation: {banned}"


def test_approve_reporting_candidate_end_to_end(tmp_path, _isolated_artifact_root):
    run_id = _run_awaiting_reporting_approval()
    manifest_path, candidate = _build_candidate_set(
        "INC-1", run_id, 1, _isolated_artifact_root)
    _approve_via_state("INC-1", run_id, 1, manifest_path)

    result = ra.approve_reporting_candidate("INC-1", run_id, analyst="analyst")
    assert result["incident_id"] == "INC-1"
    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Approved"
    assert state["workflow_status"] == "Complete"

    latest = wss.get_latest_approved_reporting_set("INC-1", run_id)
    assert latest["report_set_id"] == candidate["report_set_id"]


def test_approve_reporting_candidate_fails_when_docx_tampered_after_generation(
        tmp_path, _isolated_artifact_root):
    run_id = _run_awaiting_reporting_approval()
    manifest_path, candidate = _build_candidate_set(
        "INC-1", run_id, 1, _isolated_artifact_root)
    _approve_via_state("INC-1", run_id, 1, manifest_path)

    attempt_dir = sw.reporting_attempt_dir("INC-1", run_id, 1)
    docx_path = attempt_dir / candidate["reports"][0]["docx"]["path"]
    docx_path.write_bytes(docx_path.read_bytes() + b"tampered")

    with pytest.raises(ra.ReportValidationError):
        ra.approve_reporting_candidate("INC-1", run_id, analyst="analyst")
    assert wss.get_state("INC-1")["reporting_status"] == "Awaiting Approval"


def test_approve_reporting_candidate_fails_on_identity_mismatch(tmp_path, _isolated_artifact_root):
    run_id = _run_awaiting_reporting_approval()
    manifest_path, _ = _build_candidate_set("INC-1", run_id, 1, _isolated_artifact_root)
    _approve_via_state("INC-1", run_id, 1, manifest_path)
    # Reporting attempt moved on without the manifest being re-finalized.
    wss._guarded_update("INC-1", run_id, {"reporting_attempt": 2})
    with pytest.raises(ra.ReportValidationError):
        ra.approve_reporting_candidate("INC-1", run_id, analyst="analyst")


# ══════════════════════════════════════════════════════════════════════
# editable_reports.finalize_candidate_manifest — immutability
# ══════════════════════════════════════════════════════════════════════

def test_finalize_candidate_manifest_refuses_to_overwrite_differing_content(
        _isolated_artifact_root):
    manifest_path, candidate = _build_candidate_set("INC-2", "run-a", 1, _isolated_artifact_root)

    import sys
    rep_dir = str(Path(__file__).resolve().parent.parent / "soc_reporting_agent")
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from reporting import editable_reports as er

    attempt_dir = sw.reporting_attempt_dir("INC-2", "run-a", 1)
    output_dir = attempt_dir / "outputs"
    # Mutate one exported DOCX so a re-finalize would produce different hashes.
    docx_path = attempt_dir / candidate["reports"][0]["docx"]["path"]
    docx_path.write_bytes(docx_path.read_bytes() + b"changed")

    with pytest.raises(er.CandidateManifestConflictError):
        er.finalize_candidate_manifest(output_dir, "INC-2", "run-a", 1)


def test_finalize_candidate_manifest_idempotent_on_identical_repeat_call(_isolated_artifact_root):
    manifest_path, candidate = _build_candidate_set("INC-3", "run-a", 1, _isolated_artifact_root)

    import sys
    rep_dir = str(Path(__file__).resolve().parent.parent / "soc_reporting_agent")
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from reporting import editable_reports as er

    attempt_dir = sw.reporting_attempt_dir("INC-3", "run-a", 1)
    output_dir = attempt_dir / "outputs"
    repeat = er.finalize_candidate_manifest(output_dir, "INC-3", "run-a", 1)
    assert repeat["report_set_id"] == candidate["report_set_id"]


def test_final_incident_report_export_populates_section_exports(_isolated_artifact_root):
    """Final Incident Report's DOCX/PDF export must be mirrored into
    sections.final_incident_report.exports (previously left {}), and use
    the renamed final_incident_report.* filename."""
    import sys
    rep_dir = str(Path(__file__).resolve().parent.parent / "soc_reporting_agent")
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from reporting import editable_reports as er

    output_dir = _isolated_artifact_root / "final_report_test"
    incident_id = "INC-4"
    for key in er.CORE_REPORT_KEYS:
        cfg = er.REPORT_SECTION_CONFIG[key]
        er._write(er.drafts_dir(output_dir, incident_id) / cfg["filename"], f"{key} content")
        er.save_blocks(er.drafts_dir(output_dir, incident_id) / f"{key}.json",
                       [{"type": "paragraph", "text": f"{key} body"}])
    er.build_report_manifest(output_dir, incident_id, {
        key: str(er.drafts_dir(output_dir, incident_id) / er.REPORT_SECTION_CONFIG[key]["filename"])
        for key in er.CORE_REPORT_KEYS
    })
    er.confirm_report(output_dir, analyst="tester", incident_id=incident_id)
    result = er.export_docx(output_dir, incident_id=incident_id)
    assert Path(result["path"]).name == "final_incident_report.docx"
    manifest = er.load_manifest(output_dir, incident_id)
    assert manifest["sections"]["final_incident_report"]["exports"]["docx"]["path"] == result["path"]
