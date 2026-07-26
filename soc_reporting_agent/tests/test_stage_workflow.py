from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import stage_workflow, ticket_workflow  # noqa: E402


def finish(ticket: dict, agent: str) -> None:
    stage = stage_workflow.stage_definition(agent)
    assert stage
    ticket[stage["result_key"]] = stage_workflow.completed_result(
        stage,
        {"status": "completed", "summary": f"{stage['label']} output"},
        success=True,
    )


def approve(ticket: dict, agent: str) -> None:
    stage = stage_workflow.stage_definition(agent)
    assert stage
    allowed, reason, _ = stage_workflow.can_approve(ticket, stage)
    assert allowed, reason
    payload = {
        "decision": "approved",
        "status": "completed",
        "approval_gate": stage["approval_gate"],
    }
    ticket.update(stage_workflow.approval_fields(ticket, stage, payload))


class StageWorkflowTests(unittest.TestCase):
    def test_initial_state_and_buttons(self) -> None:
        ticket: dict = {}
        expected = {
            "parsing": "ready",
            "triage": "locked",
            "threat_intel": "locked",
            "investigation": "locked",
            "reporting": "locked",
        }
        self.assertEqual(
            {stage["agent"]: stage_workflow.status(ticket, stage) for stage in stage_workflow.STAGES},
            expected,
        )
        panel = {item["key"]: item for item in ticket_workflow.agent_panel(ticket)}
        self.assertEqual(panel["parsing"]["actions"][0]["label"], "Start Process")
        self.assertTrue(panel["parsing"]["actions"][0]["enabled"])
        self.assertEqual(panel["triage"]["actions"][0]["label"], "Start Process")
        self.assertFalse(panel["triage"]["actions"][0]["enabled"])
        self.assertEqual(panel["triage"]["status_message"], "Complete the Parsing stage to continue.")
        decorated = ticket_workflow.decorate_ticket(ticket)
        self.assertEqual([step["label"] for step in decorated["workflow_steps"]], [
            "Parsing",
            "Triage",
            "Threat Intelligence Enrichment",
            "Investigation",
            "Reporting",
        ])
        self.assertEqual(decorated["next_step"]["agent"], "parsing")

    def test_only_immediate_next_stage_unlocks_after_required_approval(self) -> None:
        ticket: dict = {}
        finish(ticket, "parsing")
        self.assertEqual(stage_workflow.status(ticket, "triage"), "ready")
        self.assertEqual(stage_workflow.status(ticket, "threat_intel"), "locked")

        finish(ticket, "triage")
        self.assertEqual(stage_workflow.status(ticket, "triage"), "pending_approval")
        self.assertEqual(stage_workflow.status(ticket, "threat_intel"), "locked")
        approve(ticket, "triage")
        self.assertEqual(stage_workflow.status(ticket, "triage"), "approved")
        self.assertEqual(stage_workflow.status(ticket, "threat_intel"), "ready")
        self.assertEqual(stage_workflow.status(ticket, "investigation"), "locked")

        finish(ticket, "threat_intel")
        self.assertEqual(stage_workflow.status(ticket, "threat_intel"), "pending_approval")
        approve(ticket, "threat_intel")
        self.assertEqual(stage_workflow.status(ticket, "investigation"), "ready")
        self.assertEqual(stage_workflow.status(ticket, "reporting"), "locked")

    def test_reporting_approval_completes_workflow(self) -> None:
        ticket: dict = {}
        finish(ticket, "parsing")
        for agent in ("triage", "threat_intel", "investigation", "reporting"):
            finish(ticket, agent)
            approve(ticket, agent)
        self.assertTrue(stage_workflow.workflow_complete(ticket))
        self.assertEqual(ticket["status"], "Workflow Completed")
        self.assertEqual(stage_workflow.status(ticket, "reporting"), "approved")

    def test_rerun_invalidates_approval_and_all_existing_downstream_outputs(self) -> None:
        ticket: dict = {}
        finish(ticket, "parsing")
        for agent in ("triage", "threat_intel", "investigation", "reporting"):
            finish(ticket, agent)
            approve(ticket, agent)

        fields = stage_workflow.begin_run_fields(ticket, "triage", rerun=True)
        ticket.update(fields)
        self.assertEqual(stage_workflow.status(ticket, "triage"), "running")
        self.assertEqual(ticket["approval_result"], {})
        for agent in ("threat_intel", "investigation", "reporting"):
            self.assertEqual(stage_workflow.status(ticket, agent), "rerun_required")
            self.assertEqual(
                stage_workflow.status_message(ticket, agent),
                "Re-run required, as Triage was re-run.",
            )
            self.assertFalse(stage_workflow.output_valid(ticket, agent))

        finish(ticket, "triage")
        self.assertEqual(stage_workflow.status(ticket, "triage"), "pending_approval")
        self.assertFalse(stage_workflow.can_run(ticket, "threat_intel")[0])
        approve(ticket, "triage")
        self.assertEqual(stage_workflow.status(ticket, "threat_intel"), "rerun_required")
        self.assertTrue(stage_workflow.can_run(ticket, "threat_intel")[0])
        panel = {item["key"]: item for item in ticket_workflow.agent_panel(ticket)}
        self.assertEqual(panel["threat_intel"]["actions"][0]["label"], "Re-run")
        self.assertTrue(panel["threat_intel"]["actions"][0]["enabled"])
        self.assertFalse(panel["investigation"]["actions"][0]["enabled"])

    def test_latest_rerun_reason_replaces_earlier_reason(self) -> None:
        ticket: dict = {}
        finish(ticket, "parsing")
        for agent in ("triage", "threat_intel", "investigation", "reporting"):
            finish(ticket, agent)
            approve(ticket, agent)
        ticket.update(stage_workflow.begin_run_fields(ticket, "triage", rerun=True))
        finish(ticket, "triage")
        approve(ticket, "triage")
        ticket.update(stage_workflow.begin_run_fields(ticket, "threat_intel", rerun=True))
        self.assertEqual(
            stage_workflow.status_message(ticket, "investigation"),
            "Re-run required, as Threat Intelligence Enrichment was re-run.",
        )

    def test_backend_start_and_approval_guards(self) -> None:
        ticket: dict = {}
        self.assertFalse(stage_workflow.can_start(ticket, "triage", rerun=False)[0])
        self.assertFalse(stage_workflow.can_approve(ticket, "triage")[0])
        finish(ticket, "parsing")
        self.assertFalse(stage_workflow.can_start(ticket, "triage", rerun=True)[0])
        finish(ticket, "triage")
        self.assertFalse(stage_workflow.can_start(ticket, "triage", rerun=False)[0])
        approve(ticket, "triage")
        self.assertFalse(stage_workflow.can_approve(ticket, "triage")[0])


if __name__ == "__main__":
    unittest.main()
