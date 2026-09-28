// Stage action labels and "Continue to <next stage>" controls for the case
// workspace (frontend/js/pages/workspace.js). No imports, no fetch, no
// workflow requests — so it can be exercised directly under Node
// (tests/test_stage_continue_controls.py).
//
// Workflow model — three separate analyst actions, never combined:
//   APPROVE  -> unlocks the next stage (backend leaves it "Pending")
//   CONTINUE -> navigation only: selects the next stage in the workspace,
//               which stays "Pending" and shows its own Run <Stage> button
//   RUN      -> execution: that stage's own backend `start` action
//               (POST /stages/<key>/runs -> commands.start_stage ->
//               wss.begin_stage, Pending -> Processing)
// Continue therefore never calls the next stage's start action. The start
// action is only READ here, to tell whether the backend has unlocked the
// next stage (workflow/commands.py::available_actions()).

// Reporting is the final agent stage, so it has no entry.
export const NEXT_STAGE = {
  parsing: "triage",
  triage: "threat_intel",
  threat_intel: "investigation",
  investigation: "reporting",
};

export const CONTINUE_LABELS = {
  parsing: "Continue to Triage",
  triage: "Continue to Threat Intelligence Enrichment",
  threat_intel: "Continue to Investigation",
  investigation: "Continue to Reporting",
};

// Presentation labels only — each keeps its backend action type, enabled
// state and handler. Unlisted types (e.g. "resume") keep the backend label.
export const STAGE_ACTION_LABELS = {
  parsing: { start: "Run Parsing", rerun: "Re-run Parsing" },
  triage: { start: "Run Triage", rerun: "Re-run Triage", approve: "Approve Triage", reject: "Reject Triage" },
  threat_intel: { start: "Run Threat Intelligence Enrichment", rerun: "Re-run Threat Intelligence" },
  investigation: { start: "Run Investigation", rerun: "Re-run Investigation", approve: "Approve Investigation", reject: "Reject Investigation" },
  reporting: { start: "Run Reporting", rerun: "Re-run Reporting", approve: "Approve Reporting", reject: "Reject Reporting" },
};

export function stageActionLabel(stageKey, action) {
  return STAGE_ACTION_LABELS[stageKey]?.[action.type] || action.label;
}

// Returns null unless the current stage is completed (the backend's own
// `completed` flag — Triage/Investigation only once Approved, so never while
// awaiting approval) AND the next stage exposes a `start` action (i.e. the
// backend has unlocked it and it has not been started yet). `enabled`
// mirrors that start action so Continue is only active when the next stage
// is genuinely available — but Continue itself only navigates to it.
export function continueControl(workflow, stage) {
  const nextKey = NEXT_STAGE[stage?.key];
  if (!nextKey || !stage.completed) return null;
  const nextStage = (workflow?.stages || []).find((candidate) => candidate.key === nextKey);
  const start = (nextStage?.actions || []).find((action) => action.type === "start");
  if (!start) return null;
  return {
    label: CONTINUE_LABELS[stage.key],
    nextStage,
    enabled: Boolean(start.enabled),
    reason: start.reason || null,
  };
}

// The action bar for one stage: Run/Re-run/Resume plus Continue in the
// primary group; Reject/Approve (only present while a gate is awaiting a
// decision) in the separate decision group.
export function stageActionModel(stage, workflow) {
  const actions = stage?.actions || [];
  const decisionTypes = ["reject", "approve"];
  const toButton = (action) => ({
    type: action.type,
    label: stageActionLabel(stage.key, action),
    enabled: Boolean(action.enabled),
    reason: action.reason || null,
    danger: action.type === "reject",
  });
  return {
    primary: actions.filter((action) => !decisionTypes.includes(action.type)).map(toButton),
    decision: decisionTypes
      .map((type) => actions.find((action) => action.type === type))
      .filter(Boolean)
      .map(toButton),
    continueTo: continueControl(workflow, stage),
  };
}

// Wires the stage's Continue button (rendered with data-continue-stage) to
// onNavigate(nextStageKey) — the workspace's stage-selection callback, the
// same thing clicking that stage's card does. It is given no action/request
// callback at all, so a Continue click cannot start a stage.
export function bindContinueButton(root, workflow, stage, onNavigate) {
  const cont = continueControl(workflow, stage);
  root.querySelectorAll("[data-continue-stage]").forEach((button) => {
    if (!cont || button.dataset.continueStage !== cont.nextStage.key) return;
    button.addEventListener("click", () => onNavigate(cont.nextStage.key));
  });
}
