"""
[FYP-FILE]
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis test and validation.
# Important dependencies: __future__, backend, pathlib, sys, unittest.
# Key evaluator search terms: finish, approve, StageWorkflowTests, [FYP-FUNCTION].
File: soc_reporting_agent/tests/test_stage_workflow.py
Purpose: Unit tests for the five-stage pipeline state machine in
    backend/stage_workflow.py (Parsing -> Triage -> Threat Intelligence ->
    Investigation -> Reporting) and its dashboard presentation layer in
    backend/ticket_workflow.py, covering initial lock state, sequential
    unlocking on approval, workflow completion, and the re-run
    invalidation cascade.
Main functionalities: Drives a plain in-memory ticket dict through
    stage_workflow.completed_result()/approval_fields()/begin_run_fields()
    via the local finish()/approve() helpers below, then asserts
    stage_workflow.status()/can_run()/can_start()/can_approve() and
    ticket_workflow.agent_panel()/decorate_ticket() report the expected
    per-stage state (locked/ready/pending_approval/approved/rerun_required)
    and UI button labels at each step.
Called by: Executed by pytest, or by running
    `python -m pytest soc_reporting_agent/tests/test_stage_workflow.py`
    (also runnable directly via `python
    soc_reporting_agent/tests/test_stage_workflow.py`, which invokes
    unittest.main()).
[FYP-CALLS] backend.stage_workflow -- STAGES, stage_definition(),
    completed_result(), approval_fields(), begin_run_fields(), status(),
    status_message(), can_run(), can_start(), can_approve(),
    output_valid(), workflow_complete(); backend.ticket_workflow --
    agent_panel(), decorate_ticket().
[FYP-STAGE-LOCK]
[/FYP-FILE]
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.reporting.backend import stage_workflow, ticket_workflow  # noqa: E402


def finish(ticket: dict, agent: str) -> None:
    """[FYP-FUNCTION] Test helper -- simulate a stage completing successfully.

    Writes a synthetic "completed" result (via
    backend.stage_workflow.completed_result()) onto ticket[stage["result_key"]]
    for the given agent, mimicking what an actual stage run would persist.
    """
    stage = stage_workflow.stage_definition(agent)
    assert stage
    ticket[stage["result_key"]] = stage_workflow.completed_result(
        stage,
        {"status": "completed", "summary": f"{stage['label']} output"},
        success=True,
    )


def approve(ticket: dict, agent: str) -> None:
    """[FYP-FUNCTION] Test helper -- simulate an analyst approving a completed stage.

    Asserts backend.stage_workflow.can_approve() allows the approval, then
    applies backend.stage_workflow.approval_fields() onto the ticket, mimicking
    the analyst approval-gate action in the dashboard.
    """
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


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Stage state machine tests
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `StageWorkflowTests` — owns StageWorkflowTests state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_initial_state_and_buttons, test_only_immediate_next_stage_unlocks_after_required_approval, test_reporting_approval_completes_workflow, test_rerun_invalidates_approval_and_all_existing_downstream_outputs, test_latest_rerun_reason_replaces_earlier_reason, test_backend_start_and_approval_guards.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class StageWorkflowTests(unittest.TestCase):
    def test_initial_state_and_buttons(self) -> None:
        """[FYP-FUNCTION] Validates backend.stage_workflow.status()/STAGES and backend.ticket_workflow.agent_panel()/decorate_ticket(): a brand-new (empty) ticket has only Parsing "ready" and every other stage "locked", the dashboard panel shows an enabled "Start Process" button only for Parsing, and next_step points at Parsing."""
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
        """[FYP-FUNCTION] Validates backend.stage_workflow.status(): completing and approving a stage unlocks exactly the next stage in sequence (never two stages ahead) -- walked through Parsing -> Triage -> Threat Intelligence."""
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
        """[FYP-FUNCTION] Validates backend.stage_workflow.workflow_complete(): finishing and approving all five stages in order marks the ticket status "Workflow Completed" and leaves Reporting in the "approved" state."""
        ticket: dict = {}
        finish(ticket, "parsing")
        for agent in ("triage", "threat_intel", "investigation", "reporting"):
            finish(ticket, agent)
            approve(ticket, agent)
        self.assertTrue(stage_workflow.workflow_complete(ticket))
        self.assertEqual(ticket["status"], "Workflow Completed")
        self.assertEqual(stage_workflow.status(ticket, "reporting"), "approved")

    def test_rerun_invalidates_approval_and_all_existing_downstream_outputs(self) -> None:
        """[FYP-FUNCTION] [FYP-RERUN] Validates backend.stage_workflow.begin_run_fields()/status()/status_message()/output_valid()/can_run(): re-running an already-approved Triage stage clears its approval, flips every downstream stage (Threat Intel/Investigation/Reporting) to "rerun_required" with an explanatory message, and invalidates their prior outputs -- until Triage is re-approved, at which point only the immediate next stage becomes runnable again."""
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
        """[FYP-FUNCTION] Validates backend.stage_workflow.status_message(): when two upstream stages are re-run in sequence (Triage, then Threat Intel), the downstream Investigation stage's status message reflects the MOST RECENT re-run trigger, not the earlier one."""
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
        """[FYP-FUNCTION] [FYP-VALIDATION] Validates backend.stage_workflow.can_start()/can_approve(): a stage cannot be started before its prerequisite is complete, cannot be started fresh (rerun=False) once it already has output, and cannot be approved again once already approved -- the core guard checks behind the dashboard's action buttons."""
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
