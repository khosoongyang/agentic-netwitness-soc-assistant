import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, formatCount, formatDate, loadingState, severityBadge } from "../ui.js";

const pipelineLabels = {
  alerts_to_triage: "Alerts to Triage",
  post_triage_investigate: "Needs Investigation",
  post_triage_no_investigate: "No Investigation Needed",
  post_investigation: "Investigation Findings",
  initial_ticket: "Initial Tickets",
  pending_ticket_report: "Pending Reports",
  finalized_report: "Finalized Reports",
  workflow_runs: "Workflow Runs",
};

function recentCases(items) {
  if (!items.length) return emptyState("No cases have been recorded yet.");
  return `<div class="table-wrap"><table><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Stage</th><th>Last seen</th></tr></thead><tbody>${items.map((item) => `
    <tr>
      <td><button class="case-link mono" data-case-id="${escapeHTML(item.id)}">${escapeHTML(item.id)}</button><br>${escapeHTML(item.title)}</td>
      <td>${severityBadge(item.severity)}</td>
      <td>${escapeHTML(item.status)}</td>
      <td>${escapeHTML(item.current_stage)}</td>
      <td>${formatDate(item.last_seen || item.updated)}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

export async function renderOverview(root, { navigate }) {
  root.innerHTML = loadingState("Loading the operations overview…");
  try {
    const data = await fetchJSON("/api/dashboard");
    const summary = data.summary;
    root.innerHTML = `
      <section class="page-header"><div><h1>Operations overview</h1><p>${formatCount(summary.active_cases)} active cases · last fetch ${formatDate(summary.last_fetch)}</p></div></section>
      <section class="metrics-grid">
        <article class="metric-card"><span>Total cases</span><strong>${formatCount(summary.total_cases)}</strong></article>
        <article class="metric-card"><span>Critical active</span><strong>${formatCount(summary.critical_active)}</strong></article>
        <article class="metric-card"><span>Unassigned active</span><strong>${formatCount(summary.unassigned_active)}</strong></article>
        <article class="metric-card"><span>Awaiting approval</span><strong>${formatCount(summary.awaiting_approval)}</strong></article>
        <article class="metric-card"><span>NetWitness fetches</span><strong>${formatCount(summary.fetch_count)}</strong></article>
      </section>
      <section class="overview-grid">
        <article class="panel"><h2>Pipeline archive</h2><ul class="data-list">${Object.entries(data.pipeline_counts).map(([key, value]) => `<li><span>${escapeHTML(pipelineLabels[key] || key)}</span><strong>${formatCount(value)}</strong></li>`).join("")}</ul></article>
        <article class="panel"><h2>Recent cases</h2>${recentCases(data.recent_cases)}</article>
      </section>`;
    root.querySelectorAll("[data-case-id]").forEach((button) => {
      button.addEventListener("click", () => navigate("case", { case: button.dataset.caseId }));
    });
  } catch (error) {
    root.innerHTML = errorState(error);
  }
}
