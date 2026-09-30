import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, formatCount, formatDate, loadingState, severityBadge } from "../ui.js";
import {
  activeFilterCount, apiParams, chipsRowHTML, clearFilters, headerSortDirection, mountOverviewControls,
  nextHeaderSort, overviewURL, removeChip, stateFromParams,
} from "../components/caseFilters.js";

// Recent Cases shows at most this many rows; the count line says when more match.
const RECENT_LIMIT = 200;

const summaryIcons = {
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
  alert: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12.5"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
};

const SORT_INDICATORS = { ascending: "↑", descending: "↓", none: "↕" };

function summaryCard(icon, variant, label, value) {
  return `<article class="summary-card">
    <span class="summary-card-icon summary-card-icon-${variant}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${summaryIcons[icon]}</svg></span>
    <span class="summary-card-body"><span class="summary-card-label">${escapeHTML(label)}</span><strong class="summary-card-value">${formatCount(value)}</strong></span>
  </article>`;
}

// CASE / SEVERITY / LAST SEEN headers drive the same single sort state as
// the topbar "Sort by" menu; STATUS and STAGE are deliberately not sortable.
function sortableHeader(column, label, sort) {
  const direction = headerSortDirection(column, sort);
  const ariaSort = direction === "none" ? "" : ` aria-sort="${direction}"`;
  return `<th${ariaSort}><button type="button" class="th-sort${direction === "none" ? "" : " is-active"}" data-sort-column="${column}">${escapeHTML(label)}<span class="th-sort-indicator" aria-hidden="true">${SORT_INDICATORS[direction]}</span></button></th>`;
}

function recentCases(items, sort, filtered) {
  if (!items.length) {
    return emptyState(filtered ? "No cases match the current search and filters." : "No cases have been recorded yet.");
  }
  return `<div class="table-wrap recent-cases-wrap"><table class="recent-cases-table"><thead><tr>${sortableHeader("case", "Case", sort)}${sortableHeader("severity", "Severity", sort)}<th>Status</th><th>Stage</th>${sortableHeader("last_seen", "Last seen", sort)}</tr></thead><tbody>${items.map((item) => `
    <tr class="case-row" data-case-id="${escapeHTML(item.id)}" tabindex="0" role="button" aria-label="Open incident ${escapeHTML(item.id)}: ${escapeHTML(item.title)}">
      <td><span class="case-link mono">${escapeHTML(item.id)}</span><br>${escapeHTML(item.title)}</td>
      <td>${severityBadge(item.severity)}</td>
      <td>${escapeHTML(item.status)}</td>
      <td>${escapeHTML(item.current_stage)}</td>
      <td>${formatDate(item.last_seen || item.updated)}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

function resultCountText(shown, total, filtered) {
  const noun = filtered ? "matching cases" : "cases";
  if (shown < total) return `Showing ${formatCount(shown)} of ${formatCount(total)} ${noun}`;
  if (!total) return "";
  return `${formatCount(total)} ${total === 1 ? noun.replace("cases", "case") : noun}`;
}

export async function renderOverview(root, { navigate, route }) {
  let state = stateFromParams(route.params);
  let requestId = 0;
  let active = true;
  // Header whose click triggered the pending reload; focus returns to it
  // once the table (and so the button itself) has been re-rendered.
  let focusHeader = null;

  const isFiltered = () => Boolean(state.q) || activeFilterCount(state.filters) > 0;

  const controls = mountOverviewControls({
    getState: () => state,
    onChange: (next) => setState(next),
  });

  function setState(next) {
    state = next;
    // Same page, new query: replace (not push) so Back still leaves the
    // Overview, and returning to it restores exactly this state.
    window.history.replaceState(window.history.state, "", overviewURL(state));
    controls?.sync();
    renderChips();
    loadCases();
  }

  function renderChips() {
    const container = root.querySelector("#overview-active-filters");
    if (container) container.innerHTML = chipsRowHTML(state.filters);
  }

  async function loadCases() {
    const body = root.querySelector("#recent-cases-body");
    const count = root.querySelector("#recent-cases-count");
    if (!body) return;
    const current = ++requestId;
    body.setAttribute("aria-busy", "true");
    body.classList.add("is-loading");
    if (!body.children.length) body.innerHTML = loadingState("Loading cases…");
    try {
      const data = await fetchJSON(`/api/cases?${apiParams(state, { limit: RECENT_LIMIT }).toString()}`);
      if (!active || current !== requestId) return;
      body.innerHTML = recentCases(data.items, state.sort, isFiltered());
      count.textContent = resultCountText(data.items.length, data.pagination.total, isFiltered());
      if (focusHeader) body.querySelector(`[data-sort-column="${focusHeader}"]`)?.focus();
      focusHeader = null;
    } catch (error) {
      if (!active || current !== requestId) return;
      body.innerHTML = errorState(error);
      count.textContent = "";
    } finally {
      if (active && current === requestId) {
        body.removeAttribute("aria-busy");
        body.classList.remove("is-loading");
      }
    }
  }

  root.innerHTML = loadingState("Loading the operations overview…");
  try {
    const data = await fetchJSON("/api/dashboard");
    const summary = data.summary;
    root.innerHTML = `
      <div id="overview-active-filters"></div>
      <section class="page-header"><div><h1>Operations overview</h1><p>${formatCount(summary.active_cases)} active cases · last fetch ${formatDate(summary.last_fetch)}</p></div></section>
      <section class="summary-cards">
        ${summaryCard("bell", "total", "Total Alerts", summary.total_cases)}
        ${summaryCard("alert", "critical", "Critical", summary.critical_active)}
        ${summaryCard("search", "investigation", "Under Investigation", summary.under_investigation)}
        ${summaryCard("user", "analyst", "Awaiting Analyst", summary.awaiting_analyst)}
      </section>
      <section class="overview-grid">
        <article class="panel">
          <div class="recent-cases-header"><h2>Recent cases</h2><p class="recent-cases-count" id="recent-cases-count" aria-live="polite"></p></div>
          <div id="recent-cases-body"></div>
        </article>
      </section>`;
  } catch (error) {
    root.innerHTML = errorState(error);
    return;
  }

  // Delegated once on the (persistent) page root; the table and chip row
  // inside it are re-rendered on every state change.
  const page = root.querySelector(".overview-grid");
  const chipRow = root.querySelector("#overview-active-filters");

  chipRow.addEventListener("click", (event) => {
    const chip = event.target.closest("[data-chip-group]");
    if (chip) {
      setState({ ...state, filters: removeChip(state.filters, chip.dataset.chipGroup, chip.dataset.chipValue) });
      (chipRow.querySelector("[data-chip-group]") || document.querySelector("#case-filters-toggle"))?.focus();
    } else if (event.target.closest("[data-chip-clear]")) {
      setState(clearFilters(state));
      document.querySelector("#case-filters-toggle")?.focus();
    }
  });

  page.addEventListener("click", (event) => {
    const header = event.target.closest("[data-sort-column]");
    if (header) {
      focusHeader = header.dataset.sortColumn;
      setState({ ...state, sort: nextHeaderSort(focusHeader, state.sort) });
      return;
    }
    const row = event.target.closest(".case-row[data-case-id]");
    if (row) navigate("case", { case: row.dataset.caseId });
  });

  page.addEventListener("keydown", (event) => {
    const row = event.target.closest(".case-row[data-case-id]");
    if (row && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      navigate("case", { case: row.dataset.caseId });
    }
  });

  // Stop writing into the shared root once another view has rendered.
  window.addEventListener("aegis:navigate", () => { active = false; }, { once: true });
  window.addEventListener("popstate", () => { active = false; }, { once: true });

  renderChips();
  await loadCases();
}
