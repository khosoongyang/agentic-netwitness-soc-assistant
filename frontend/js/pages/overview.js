import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, formatCount, formatDate, loadingState, severityBadge } from "../ui.js";

const summaryIcons = {
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
  alert: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12.5"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
};

function summaryCard(icon, variant, label, value) {
  return `<article class="summary-card">
    <span class="summary-card-icon summary-card-icon-${variant}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${summaryIcons[icon]}</svg></span>
    <span class="summary-card-body"><span class="summary-card-label">${escapeHTML(label)}</span><strong class="summary-card-value">${formatCount(value)}</strong></span>
  </article>`;
}

function recentCases(items) {
  if (!items.length) return emptyState("No cases have been recorded yet.");
  return `<div class="table-wrap"><table><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Stage</th><th>Last seen</th></tr></thead><tbody>${items.map((item) => `
    <tr class="case-row" data-case-id="${escapeHTML(item.id)}" tabindex="0" role="button" aria-label="Open incident ${escapeHTML(item.id)}: ${escapeHTML(item.title)}">
      <td><span class="case-link mono">${escapeHTML(item.id)}</span><br>${escapeHTML(item.title)}</td>
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
      <section class="summary-cards">
        ${summaryCard("bell", "total", "Total Alerts", summary.total_cases)}
        ${summaryCard("alert", "critical", "Critical", summary.critical_active)}
        ${summaryCard("search", "investigation", "Under Investigation", summary.under_investigation)}
        ${summaryCard("user", "analyst", "Awaiting Analyst", summary.awaiting_analyst)}
      </section>
      <section class="overview-grid">
        <article class="panel"><h2>Recent cases</h2>${recentCases(data.recent_cases)}</article>
      </section>`;
    root.querySelectorAll(".case-row[data-case-id]").forEach((row) => {
      const open = () => navigate("case", { case: row.dataset.caseId });
      row.addEventListener("click", open);
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          open();
        }
      });
    });
  } catch (error) {
    root.innerHTML = errorState(error);
  }
}
