import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, formatCount, formatDate, loadingState, severityBadge } from "../ui.js";

function option(value, selected) {
  return `<option value="${escapeHTML(value)}" ${value === selected ? "selected" : ""}>${escapeHTML(value)}</option>`;
}

function caseTable(items) {
  if (!items.length) return emptyState("No cases match the current filters.");
  return `<div class="table-wrap"><table><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Owner</th><th>Current stage</th><th>Updated</th></tr></thead><tbody>${items.map((item) => `
    <tr><td><button class="case-link mono" data-case-id="${escapeHTML(item.id)}">${escapeHTML(item.id)}</button><br>${escapeHTML(item.title)}</td><td>${severityBadge(item.severity)}</td><td>${escapeHTML(item.status)}</td><td>${escapeHTML(item.assignee)}</td><td>${escapeHTML(item.current_stage)}</td><td>${formatDate(item.updated || item.last_seen)}</td></tr>`).join("")}</tbody></table></div>`;
}

export async function renderCases(root, { navigate, route }) {
  root.innerHTML = loadingState("Loading cases…");
  const params = route.params;
  const query = new URLSearchParams({
    search: params.get("search") || "",
    severity: params.get("severity") || "ALL",
    status: params.get("status") || "ALL",
    page: params.get("page") || "1",
    limit: params.get("limit") || "50",
    sort: params.get("sort") || "updated",
    direction: params.get("direction") || "desc",
  });
  try {
    const data = await fetchJSON(`/api/cases?${query.toString()}`);
    const filters = data.filters;
    const pagination = data.pagination;
    root.innerHTML = `
      <section class="page-header"><div><h1>Cases</h1><p>${formatCount(pagination.total)} cases match the current view.</p></div><a class="action-button" href="/api/cases/export">Export all as CSV</a></section>
      <form class="filters" id="case-filters">
        <input name="search" type="search" value="${escapeHTML(filters.search)}" placeholder="Search title, ID, or assignee" aria-label="Search cases">
        <select name="severity" aria-label="Filter by severity">${option("ALL", filters.severity)}${data.facets.severities.map((value) => option(value, filters.severity)).join("")}</select>
        <select name="status" aria-label="Filter by status">${option("ALL", filters.status)}${data.facets.statuses.map((value) => option(value, filters.status)).join("")}</select>
        <select name="sort" aria-label="Sort cases">${[["updated", "Recently updated"], ["created", "Created"], ["severity", "Severity"], ["status", "Status"], ["title", "Title"], ["id", "Case ID"]].map(([value, label]) => `<option value="${value}" ${filters.sort === value ? "selected" : ""}>${label}</option>`).join("")}</select>
        <button type="submit">Apply</button>
      </form>
      <section class="panel">${caseTable(data.items)}<div class="pagination"><span>Page ${pagination.page} of ${pagination.pages || 1}</span><button type="button" data-page="${pagination.page - 1}" ${pagination.page <= 1 ? "disabled" : ""}>Previous</button><button type="button" data-page="${pagination.page + 1}" ${pagination.page >= pagination.pages ? "disabled" : ""}>Next</button></div></section>`;

    root.querySelector("#case-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      navigate("cases", { search: form.get("search"), severity: form.get("severity"), status: form.get("status"), sort: form.get("sort"), direction: filters.direction, page: 1, limit: pagination.limit });
    });
    root.querySelectorAll("[data-page]").forEach((button) => {
      button.addEventListener("click", () => navigate("cases", { ...Object.fromEntries(query), page: button.dataset.page }));
    });
    root.querySelectorAll("[data-case-id]").forEach((button) => {
      button.addEventListener("click", () => navigate("case", { case: button.dataset.caseId }));
    });
  } catch (error) {
    root.innerHTML = errorState(error);
  }
}
