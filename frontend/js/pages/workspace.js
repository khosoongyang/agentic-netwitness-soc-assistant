import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, formatDate, jsonPreview, loadingState, provenanceValue, severityBadge, stateBadge } from "../ui.js";
import { installChat } from "./chatbot.js";

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 60;

function caseContext(detail) {
  const context = detail.case.context || {};
  const overviewContext = detail.workspace?.overview?.case_context || {};
  const rows = [
    ["NetWitness severity", provenanceValue(overviewContext.netwitness_severity) || detail.case.severity],
    ["Triage classification", provenanceValue(overviewContext.triage_classification) || "—"],
    ["Unified verdict", provenanceValue(overviewContext.unified_verdict) || "—"],
    ["Host", provenanceValue(overviewContext.host) || context.hosts?.[0] || "—"],
    ["User", provenanceValue(overviewContext.user) || context.users?.[0] || "—"],
    ["Alert count", detail.case.alert_count],
    ["Created", formatDate(detail.case.created)],
    ["Last seen", formatDate(detail.case.last_seen)],
  ];
  return `<div class="case-context-grid">${rows.map(([label, value]) => `<article class="metric-card"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value ?? "—")}</strong></article>`).join("")}</div>`;
}

function stageCards(stages) {
  return stages.map((stage) => `<button class="stage-card ${stage.locked ? "locked" : ""}" data-stage="${escapeHTML(stage.key)}"><strong>${escapeHTML(stage.name)}</strong><small>${escapeHTML(stage.status)}</small>${stateBadge(stage)}</button>`).join("");
}

function findings(workspace) {
  const items = workspace?.overview?.key_findings || [];
  if (!items.length) return emptyState("No findings have been distilled for this case yet.");
  return `<ul class="data-list">${items.slice(0, 12).map((item) => `<li><div><strong>${escapeHTML(item.title || "Finding")}</strong><p>${escapeHTML(item.desc || "")}</p></div>${item.confidence ? `<span>${escapeHTML(item.confidence)}</span>` : ""}</li>`).join("")}</ul>`;
}

function actionControls(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  return `<div class="stage-actions" aria-label="${escapeHTML(stage.name)} actions">${actions.map((action) => `<button class="action-button ${action.type === "reject" ? "danger" : ""}" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(action.label)}</button>`).join("")}</div>`;
}

function renderSelectedStage(root, stage, onAction) {
  root.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>Persisted output · ${escapeHTML(stage.status_text)}${stage.attempt ? ` · attempt ${stage.attempt}` : ""}</p></div>${stateBadge(stage)}</div>${stage.updated_at ? `<p class="notice">Last updated ${formatDate(stage.updated_at)}</p>` : ""}${actionControls(stage)}<div id="action-status" aria-live="polite"></div>${jsonPreview(stage.result)}`;
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
}

async function analystIdentity() {
  const settings = await fetchJSON("/api/settings");
  const analyst = settings.analyst_name || window.prompt("Analyst name", "")?.trim() || "";
  if (analyst && !settings.analyst_name) {
    await fetchJSON("/api/settings", { method: "PUT", body: { analyst_name: analyst, openai_model: settings.openai_model } });
  }
  return analyst;
}

async function actionRequest(caseId, action, stage) {
  const base = `/api/cases/${encodeURIComponent(caseId)}`;
  if (action === "start") return [`${base}/stages/${stage.key}/runs`, {}];
  if (action === "rerun") return [`${base}/stages/${stage.key}/reruns`, {}];
  if (action === "resume") return [`${base}/workflow/resume`, {}];
  const analyst = await analystIdentity();
  if (!analyst) throw new Error("An analyst name is required.");
  if (action === "approve") {
    const comments = window.prompt("Approval comments (optional)", "") ?? "";
    return [`${base}/approvals/${stage.key}`, { decision: "approve", analyst, comments }];
  }
  const comments = window.prompt("Rejection reason (required)", "")?.trim() || "";
  if (!comments) throw new Error("A rejection reason is required.");
  return [`${base}/approvals/${stage.key}`, { decision: "reject", analyst, comments }];
}

function requiresConfirmation(action, stage) {
  if (action === "rerun") {
    return window.confirm(`Re-run ${stage.name}? Canonical downstream invalidation rules will apply.`);
  }
  if (action === "reject") {
    return window.confirm(`Reject ${stage.name}? Downstream stages may remain blocked.`);
  }
  return true;
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function pollRun(runId, onProgress) {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt += 1) {
    const run = await fetchJSON(`/api/runs/${encodeURIComponent(runId)}`);
    onProgress(run);
    if (!run.poll) return run;
    await delay(POLL_INTERVAL_MS);
  }
  return null;
}

export async function renderWorkspace(root, { navigate, route }) {
  const caseId = route.caseId;
  if (!caseId) {
    root.innerHTML = errorState({ message: "No case was selected.", code: "CASE_NOT_SELECTED" });
    return;
  }
  root.innerHTML = loadingState(`Loading case ${caseId}…`);
  try {
    const detail = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}`);
    let workflow = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/workflow`);
    let selectedStageKey = workflow.stages.find((stage) => stage.name === workflow.current_stage)?.key || workflow.stages[0]?.key;
    root.innerHTML = `
      <button class="text-button" id="back-to-cases">← Back to cases</button>
      <section class="page-header"><div><p class="mono">${escapeHTML(detail.case.id)}</p><h1>${escapeHTML(detail.case.title)}</h1><p>${escapeHTML(detail.case.status)} · ${escapeHTML(detail.case.assignee)}</p></div>${severityBadge(detail.case.severity)}</section>
      <div class="stage-actions"><button class="action-button" id="open-reports">Review reports &amp; triage ticket</button><button class="action-button" id="load-raw">View raw incident JSON</button></div><div id="raw-incident"></div>
      <section class="panel"><h2>Case context</h2>${caseContext(detail)}</section>
      <section class="panel" id="workflow-panel" style="margin-top:1rem"></section>
      <section class="workspace-grid"><article class="panel"><h2>Key findings</h2>${findings(detail.workspace)}</article><article class="panel" id="stage-output"></article></section>
      <section class="panel" style="margin-top:1rem"><h2>Case evidence views</h2><div class="evidence-view-grid">${[
        ["Timeline", detail.workspace?.timeline], ["MITRE ATT&CK", detail.workspace?.mitre],
        ["Entity graph", detail.workspace?.entity_graph], ["Evidence", detail.workspace?.evidence],
        ["Activity", detail.workspace?.activity], ["Investigation output", detail.workspace?.output],
      ].map(([label, value]) => `<details><summary>${escapeHTML(label)}</summary>${jsonPreview(value)}</details>`).join("")}</div></section>
      <section class="panel" style="margin-top:1rem"><h2>Ask Aegis about this case</h2><div id="case-chat"></div></section>`;
    root.querySelector("#back-to-cases").addEventListener("click", () => navigate("cases"));
    root.querySelector("#open-reports").addEventListener("click", () => navigate("reports", { case: caseId }));
    root.querySelector("#load-raw").addEventListener("click", async () => { const output = root.querySelector("#raw-incident"); output.innerHTML = loadingState("Loading raw incident…"); try { const raw = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/raw`); output.innerHTML = jsonPreview(raw.incident); } catch (error) { output.innerHTML = errorState(error); } });
    installChat(root.querySelector("#case-chat"), { caseId });
    const workflowRoot = root.querySelector("#workflow-panel");
    const outputRoot = root.querySelector("#stage-output");

    const renderWorkflow = () => {
      workflowRoot.innerHTML = `<div class="page-header"><div><h2>Workflow</h2><p>${escapeHTML(workflow.workflow_status)} · run ${escapeHTML(workflow.run_id || "not started")}</p></div></div>${workflow.progress_note ? `<p class="notice">${escapeHTML(workflow.progress_note)}</p>` : ""}<div class="stage-grid">${stageCards(workflow.stages)}</div><p class="notice">${escapeHTML(workflow.evidence_gap?.message || "")}</p>`;
      const selected = workflow.stages.find((stage) => stage.key === selectedStageKey) || workflow.stages[0];
      selectedStageKey = selected.key;
      renderSelectedStage(outputRoot, selected, handleAction);
      workflowRoot.querySelectorAll("[data-stage]").forEach((button) => {
        button.classList.toggle("active", button.dataset.stage === selectedStageKey);
        button.addEventListener("click", () => {
          selectedStageKey = button.dataset.stage;
          renderWorkflow();
        });
      });
    };

    const refreshWorkflow = async () => {
      workflow = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/workflow`);
      renderWorkflow();
    };

    async function handleAction(action, stage) {
      if (!requiresConfirmation(action, stage)) return;
      const actionStatus = outputRoot.querySelector("#action-status");
      outputRoot.querySelectorAll("[data-workflow-action]").forEach((button) => { button.disabled = true; });
      try {
        const [path, body] = await actionRequest(caseId, action, stage);
        if (actionStatus) actionStatus.innerHTML = `<p class="notice"><span class="spinner"></span>Submitting ${escapeHTML(action)}…</p>`;
        const result = await fetchJSON(path, { method: "POST", body });
        await refreshWorkflow();
        if (result.run_id) {
          await pollRun(result.run_id, (run) => {
            const statusRoot = outputRoot.querySelector("#action-status");
            if (statusRoot) statusRoot.innerHTML = `<p class="notice">${escapeHTML(run.stage || stage.name)} · ${escapeHTML(run.stage_status || run.status)}${run.progress?.note ? ` · ${escapeHTML(run.progress.note)}` : ""}</p>`;
          });
          await refreshWorkflow();
        }
      } catch (error) {
        const statusRoot = outputRoot.querySelector("#action-status");
        if (statusRoot) statusRoot.innerHTML = errorState(error);
      }
    }

    renderWorkflow();
  } catch (error) {
    root.innerHTML = errorState(error);
  }
}
