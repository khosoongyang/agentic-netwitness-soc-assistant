"""Reporting and triage review operations backed by existing domain modules."""

from __future__ import annotations

import json
from typing import Any

from . import case_view_service as case_view
from agents.reporting import report_editing
from agents.reporting import reporting_approval
from agents.reporting import triage_ticket_editing
from workflow import state_store as wss

from ..errors import CaseNotFoundError


class ReportServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code, self.message, self.status_code = code, message, status_code
        super().__init__(message)


def _json(raw: Any) -> dict:
    try:
        value = json.loads(raw or "{}") if not isinstance(raw, dict) else raw
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


class ReportService:
    def _state(self, case_id: str) -> dict:
        state = wss.get_state(case_id)
        if not state:
            raise CaseNotFoundError()
        if not state.get("run_id"):
            raise ReportServiceError("REPORT_NOT_FOUND", "The case has no active workflow run.", 404)
        return state

    def _report_model(self, case_id: str, state: dict) -> dict:
        return case_view.build_reporting(state, case_id, state["run_id"])

    def list_reports(self, case_id: str) -> dict[str, Any]:
        state = self._state(case_id)
        model = self._report_model(case_id, state)
        attempt = model["current_attempt"]
        reports = [
            report_editing.report_row_state(
                case_id, state["run_id"], report_type,
                current_attempt=attempt,
                reporting_status=state.get("reporting_status") or "Pending",
                reporting_updated_at=state.get("reporting_updated_at"),
            )
            for report_type in report_editing.CORE_REPORT_TYPES
        ]
        triage = _json(state.get("triage_result_json"))
        ticket = triage_ticket_editing.ticket_row_state(
            case_id, state["run_id"],
            ticket=triage.get("ticket") or {},
            threat_intel=_json(state.get("threat_intel_result_json")),
            triage_status=state.get("triage_status"),
            triage_updated_at=state.get("workflow_updated_at"),
        )
        confirmations = self._confirmations(case_id, state["run_id"])
        for row in [*reports, ticket]:
            row["confirmed"] = row["report_type"] in confirmations
        # Phase 7: lets the frontend show "Approve reviewed report set" only
        # once a Submit-for-Approval materialisation is actually pending —
        # not merely because the whole-workflow reporting_status says
        # Awaiting Approval, which doesn't by itself mean a reviewed
        # candidate exists yet.
        pending_set = wss.get_latest_report_set(case_id, state["run_id"], status="materialised")
        return {
            "case_id": case_id,
            "run_id": state["run_id"],
            "reporting_status": state.get("reporting_status") or "Pending",
            "reporting_attempt": int(state.get("reporting_attempt") or 1),
            "report_set_id": attempt.get("report_set_id"),
            "pending_report_set_id": pending_set["report_set_id"] if pending_set else None,
            "reports": reports,
            "triage_ticket": ticket,
            "export_all_available": model.get("export_all_available", False),
            "warnings": model.get("warnings", []),
        }

    @staticmethod
    def _confirmations(case_id: str, run_id: str) -> set[str]:
        output = set()
        for item in wss.get_activity(case_id, run_id):
            if item.get("action") == "report_section_confirmed":
                metadata = _json(item.get("metadata_json"))
                if metadata.get("report_type"):
                    output.add(metadata["report_type"])
        return output

    def get_report(self, case_id: str, report_type: str) -> dict:
        listing = self.list_reports(case_id)
        rows = [*listing["reports"], listing["triage_ticket"]]
        row = next((item for item in rows if item["report_type"] == report_type), None)
        if not row:
            raise ReportServiceError("REPORT_NOT_FOUND", "Report section was not found.", 404)
        return {"case_id": case_id, "run_id": listing["run_id"], **row}

    @staticmethod
    def _validate_blocks(blocks: Any) -> list[dict]:
        if not isinstance(blocks, list) or not blocks or len(blocks) > 500:
            raise ReportServiceError("REPORT_INVALID", "Report blocks must be a non-empty list.")
        allowed = {"heading", "paragraph", "bullet_list", "table", "page_break", "markdown"}
        for block in blocks:
            if not isinstance(block, dict) or block.get("type") not in allowed:
                raise ReportServiceError("REPORT_INVALID", "A report block is invalid.")
            if len(json.dumps(block, default=str)) > 200000:
                raise ReportServiceError("REPORT_INVALID", "A report block is too large.")
        return blocks

    def save_report(self, case_id: str, report_type: str, values: dict) -> dict:
        current = self.get_report(case_id, report_type)
        if values.get("run_id") and values["run_id"] != current["run_id"]:
            raise ReportServiceError("REPORT_INVALID", "The report belongs to a different workflow run.", 409)
        if values.get("report_set_id") and values["report_set_id"] != current.get("current_report_set_id"):
            raise ReportServiceError("REPORT_INVALID", "The report candidate changed; reload before saving.", 409)
        blocks = self._validate_blocks(values.get("blocks"))
        analyst = str(values.get("analyst") or "").strip()
        if not analyst:
            raise ReportServiceError("REPORT_INVALID", "Analyst identity is required.")
        editor = triage_ticket_editing if report_type == triage_ticket_editing.TICKET_REPORT_TYPE else report_editing
        editor.save_report_edit(
            case_id, current["run_id"], report_type, blocks, analyst,
            original_blocks=current["original_blocks"],
            source_report_set_id=current.get("current_report_set_id"),
        )
        return self.get_report(case_id, report_type)

    def discard_report(self, case_id: str, report_type: str, analyst: str) -> dict:
        current = self.get_report(case_id, report_type)
        if report_type == triage_ticket_editing.TICKET_REPORT_TYPE:
            triage_ticket_editing.discard_report_edit(case_id, current["run_id"], report_type, analyst)
        else:
            # report_editing's Phase 3 immutable-version model appends a new
            # "reverted to AI" version rather than deleting anything, so it
            # needs the current AI-original content/candidate id supplied —
            # both already loaded on `current` from get_report() above.
            report_editing.discard_report_edit(
                case_id, current["run_id"], report_type, analyst,
                ai_blocks=current["original_blocks"],
                ai_report_set_id=current.get("current_report_set_id"))
        return self.get_report(case_id, report_type)

    def list_versions(self, case_id: str, report_type: str) -> dict:
        state = self._state(case_id)
        if report_type == triage_ticket_editing.TICKET_REPORT_TYPE:
            raise ReportServiceError("REPORT_INVALID", "The triage ticket does not support version history.", 400)
        if report_type not in report_editing.CORE_REPORT_TYPES:
            raise ReportServiceError("REPORT_NOT_FOUND", "Unknown report type.", 404)
        return {
            "report_type": report_type,
            "versions": report_editing.list_report_versions(case_id, state["run_id"], report_type),
        }

    def mark_reviewed(self, case_id: str, report_type: str, values: dict) -> dict:
        current = self.get_report(case_id, report_type)
        if report_type == triage_ticket_editing.TICKET_REPORT_TYPE:
            raise ReportServiceError("REPORT_INVALID", "The triage ticket does not support review state.", 400)
        analyst = str(values.get("analyst") or "").strip()
        if not analyst:
            raise ReportServiceError("REPORT_REVIEW_FAILED", "Analyst identity is required.")
        try:
            report_editing.mark_reviewed(
                case_id, current["run_id"], report_type, analyst,
                expected_report_version_id=values.get("report_version_id"))
        except report_editing.ReportEditingError as exc:
            raise ReportServiceError("REPORT_REVIEW_FAILED", str(exc), 409) from exc
        return self.get_report(case_id, report_type)

    def submit_for_approval(self, case_id: str, values: dict) -> dict:
        state = self._state(case_id)
        analyst = str(values.get("analyst") or "").strip()
        if not analyst:
            raise ReportServiceError("REPORT_SUBMIT_FAILED", "Analyst identity is required.")
        reporting_stage_attempt = int(state.get("reporting_attempt") or 1)
        try:
            manifest = report_editing.submit_for_approval(
                case_id, state["run_id"], reporting_stage_attempt, analyst=analyst)
        except report_editing.ReportEditingError as exc:
            raise ReportServiceError("REPORT_SUBMIT_FAILED", str(exc), 409) from exc
        return {
            "report_set_id": manifest["report_set_id"],
            "based_on_report_set_id": manifest.get("based_on_report_set_id"),
            "status": "materialised",
        }

    def confirm_section(self, case_id: str, report_type: str, values: dict) -> dict:
        current = self.get_report(case_id, report_type)
        expected = values.get("report_set_id")
        if expected and expected != current.get("current_report_set_id"):
            raise ReportServiceError("REPORT_CONFIRMATION_FAILED", "The report candidate changed; reload before confirming.", 409)
        analyst = str(values.get("analyst") or "").strip()
        if not analyst or not current.get("exists"):
            raise ReportServiceError("REPORT_CONFIRMATION_FAILED", "A valid report and analyst identity are required.")
        wss.record_activity(
            case_id, current["run_id"], "reporting", "report_section_confirmed",
            actor=analyst,
            metadata={"report_type": report_type, "report_set_id": current.get("current_report_set_id")},
        )
        return self.get_report(case_id, report_type)

    def confirm_final(self, case_id: str, values: dict) -> dict:
        state = self._state(case_id)
        if values.get("run_id") and values["run_id"] != state["run_id"]:
            raise ReportServiceError("REPORT_CONFIRMATION_FAILED", "The report belongs to a different workflow run.", 409)
        analyst = str(values.get("analyst") or "").strip()
        if not analyst:
            raise ReportServiceError("REPORT_CONFIRMATION_FAILED", "Analyst identity is required.")
        try:
            return reporting_approval.approve_reporting_candidate(
                case_id, state["run_id"],
                analyst=analyst,
                comments=str(values.get("comments") or ""),
            )
        except reporting_approval.ReportValidationError as exc:
            raise ReportServiceError("REPORT_CONFIRMATION_FAILED", str(exc), 409) from exc
        except Exception as exc:
            raise ReportServiceError("REPORT_CONFIRMATION_FAILED", "The final report decision could not be committed.", 409) from exc

    def export(self, case_id: str, report_type: str, file_type: str, analyst: str, *, approved=False):
        current = self.get_report(case_id, report_type)
        if file_type not in {"docx", "pdf"}:
            raise ReportServiceError("REPORT_EXPORT_FAILED", "Export format must be docx or pdf.")
        if approved and report_type != triage_ticket_editing.TICKET_REPORT_TYPE:
            resolved = reporting_approval.resolve_approved_report_file(case_id, current["run_id"], report_type, file_type)
            if not resolved:
                raise ReportServiceError("REPORT_EXPORT_FAILED", "The approved report artifact is unavailable.", 404)
            data, _ = resolved
            return data, f"{report_type}_{case_id}.{file_type}"
        editor = triage_ticket_editing if report_type == triage_ticket_editing.TICKET_REPORT_TYPE else report_editing
        try:
            return editor.export_report(
                case_id, current["run_id"], report_type, file_type,
                row_state=current,
                reporting_stage_attempt=int(self._state(case_id).get("reporting_attempt") or 1),
                analyst=analyst,
            )
        except Exception as exc:
            raise ReportServiceError("REPORT_EXPORT_FAILED", "The report could not be exported.", 500) from exc

    def export_all(self, case_id: str):
        state = self._state(case_id)
        try:
            result = reporting_approval.build_export_all_zip(case_id, state["run_id"])
            return result["bytes"], result["filename"]
        except Exception as exc:
            raise ReportServiceError("REPORT_EXPORT_FAILED", "The approved report package could not be exported.", 409) from exc

    def reporting_json(self, case_id: str):
        state = self._state(case_id)
        return report_editing.reporting_data_json(state, case_id)
