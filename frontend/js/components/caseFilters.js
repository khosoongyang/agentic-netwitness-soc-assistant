// Operations Overview search / filter / sort controls.
//
// One state object drives the Recent Cases table:
//   { q, filters: { severity, workflow_status, stage, verdict, time, from, to }, sort }
// It lives in the URL (?view=overview&q=…&severity=high,critical&sort=oldest),
// is applied server-side by GET /api/cases, and every control -- the topbar
// search, the Filters panel, the active-filter chips, the Sort menu and the
// sortable table headers -- reads and writes that same object.
//
// `q` is plain text or an Aegis query (severity:HIGH AND stage:investigation);
// the backend parses it and ANDs it with the filters (see queryAssist.js).
// All times are UTC, in the query language and the Custom range alike.
//
// The pure helpers below touch no DOM so they can be unit-tested in Node.

import { escapeHTML } from "../ui.js";
import { createQueryAssist } from "./queryAssist.js";

export const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

// Keys map to incidents.workflow_status server-side (case_service.py).
export const WORKFLOW_STATUS_OPTIONS = [
  { value: "not_started", label: "Not Started" },
  { value: "in_progress", label: "In Progress" },
  { value: "awaiting_action", label: "Awaiting Action" },
  { value: "awaiting_approval", label: "Awaiting Approval" },
  { value: "rejected", label: "Rejected" },
  { value: "failed", label: "Failed" },
  { value: "complete", label: "Complete" },
];

// Real workflow stage keys; the current stage is derived server-side.
export const STAGE_OPTIONS = [
  { value: "parsing", label: "Parsing & Normalisation" },
  { value: "triage", label: "Triage" },
  { value: "threat_intel", label: "Threat Intelligence Enrichment" },
  { value: "investigation", label: "Investigation" },
  { value: "reporting", label: "Reporting" },
];

export const VERDICT_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "unrated", label: "Unrated" },
];

// Time Range = the NetWitness incident's `updated` (last update) time,
// not Aegis's last_seen sync time. Custom bounds are entered and sent as UTC,
// the same instant `updated:>=2026-09-01T10:00` means in the query language.
export const TIME_RANGE_OPTIONS = [
  { value: "", label: "Any time" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "custom", label: "Custom" },
];

// `group` separates the menu into the visual sections of the mock-up.
export const SORT_OPTIONS = [
  { value: "newest", label: "Newest", sort: "created", direction: "desc", group: "created" },
  { value: "oldest", label: "Oldest", sort: "created", direction: "asc", group: "created" },
  { value: "severity-desc", label: "Severity: High → Low", sort: "severity", direction: "desc", group: "severity" },
  { value: "severity-asc", label: "Severity: Low → High", sort: "severity", direction: "asc", group: "severity" },
  { value: "id-asc", label: "Incident ID: Ascending", sort: "id", direction: "asc", group: "id" },
  { value: "id-desc", label: "Incident ID: Descending", sort: "id", direction: "desc", group: "id" },
  { value: "last-seen-desc", label: "Last Seen: Newest", sort: "last_seen", direction: "desc", group: "last_seen" },
  { value: "last-seen-asc", label: "Last Seen: Oldest", sort: "last_seen", direction: "asc", group: "last_seen" },
];
export const DEFAULT_SORT = "newest";

// Sortable Recent Cases columns -> [first click, second click] sort values.
export const HEADER_SORTS = {
  case: ["id-desc", "id-asc"],
  severity: ["severity-desc", "severity-asc"],
  last_seen: ["last-seen-desc", "last-seen-asc"],
};

const LIST_GROUPS = [
  { key: "severity", title: "Severity", options: SEVERITY_OPTIONS },
  { key: "workflow_status", title: "Workflow Status", options: WORKFLOW_STATUS_OPTIONS },
  { key: "stage", title: "Workflow Stage", options: STAGE_OPTIONS },
  { key: "verdict", title: "Unified Verdict", options: VERDICT_OPTIONS },
];
const CUSTOM_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;

export function emptyFilters() {
  return { severity: [], workflow_status: [], stage: [], verdict: [], time: "", from: "", to: "" };
}

function cloneFilters(filters) {
  const base = emptyFilters();
  LIST_GROUPS.forEach(({ key }) => { base[key] = [...(filters?.[key] || [])]; });
  base.time = filters?.time || "";
  base.from = filters?.from || "";
  base.to = filters?.to || "";
  return base;
}

function sortOption(value) {
  return SORT_OPTIONS.find((option) => option.value === value) || SORT_OPTIONS[0];
}

function optionLabel(options, value) {
  return options.find((option) => option.value === value)?.label || value;
}

function customTimeActive(filters) {
  return filters.time === "custom" && Boolean(filters.from || filters.to);
}

// ── URL state ──────────────────────────────────────────────────────────────

export function stateFromParams(params) {
  const filters = emptyFilters();
  LIST_GROUPS.forEach(({ key, options }) => {
    const allowed = new Set(options.map((option) => option.value));
    const values = String(params.get(key) || "").split(",").map((value) => value.trim().toLowerCase());
    filters[key] = options.map((option) => option.value).filter((value) => values.includes(value) && allowed.has(value));
  });
  const time = String(params.get("time") || "").toLowerCase();
  if (TIME_RANGE_OPTIONS.some((option) => option.value === time)) filters.time = time;
  if (filters.time === "custom") {
    const from = String(params.get("from") || "");
    const to = String(params.get("to") || "");
    filters.from = CUSTOM_TIME_PATTERN.test(from) ? from : "";
    filters.to = CUSTOM_TIME_PATTERN.test(to) ? to : "";
    if (!filters.from && !filters.to) filters.time = "";
  }
  const sort = String(params.get("sort") || "");
  return {
    q: String(params.get("q") || "").trim(),
    filters,
    sort: SORT_OPTIONS.some((option) => option.value === sort) ? sort : DEFAULT_SORT,
  };
}

// Ordered [key, value] pairs for the address bar; defaults are omitted.
export function stateToEntries(state) {
  const entries = [];
  if (state.q) entries.push(["q", state.q]);
  LIST_GROUPS.forEach(({ key }) => {
    if (state.filters[key].length) entries.push([key, state.filters[key].join(",")]);
  });
  if (state.filters.time && (state.filters.time !== "custom" || customTimeActive(state.filters))) {
    entries.push(["time", state.filters.time]);
    if (state.filters.time === "custom") {
      if (state.filters.from) entries.push(["from", state.filters.from]);
      if (state.filters.to) entries.push(["to", state.filters.to]);
    }
  }
  if (state.sort && state.sort !== DEFAULT_SORT) entries.push(["sort", state.sort]);
  return entries;
}

// Readable query string: commas and colons stay literal (severity=high,critical).
function encodeValue(value) {
  return encodeURIComponent(value).replace(/%2C/gi, ",").replace(/%3A/gi, ":");
}

export function overviewURL(state) {
  const query = stateToEntries(state).map(([key, value]) => `${key}=${encodeValue(value)}`).join("&");
  return `/?view=overview${query ? `&${query}` : ""}`;
}

// ── API query ──────────────────────────────────────────────────────────────

// Custom range inputs hold UTC wall-clock time ("2026-07-01T09:00").
function utcBound(value) {
  if (!CUSTOM_TIME_PATTERN.test(value)) return "";
  return `${value.length === 16 ? `${value}:00` : value}Z`;
}

export function apiParams(state, { limit = 200, page = 1 } = {}) {
  const option = sortOption(state.sort);
  const params = new URLSearchParams({ page: String(page), limit: String(limit), sort: option.sort, direction: option.direction });
  if (state.q) params.set("query", state.q);
  const { filters } = state;
  if (filters.severity.length) params.set("severity", filters.severity.map((value) => value.toUpperCase()).join(","));
  if (filters.workflow_status.length) params.set("workflow_status", filters.workflow_status.join(","));
  if (filters.stage.length) params.set("stage", filters.stage.join(","));
  if (filters.verdict.length) params.set("verdict", filters.verdict.join(","));
  if (filters.time && filters.time !== "custom") {
    params.set("time_range", filters.time);
  } else if (customTimeActive(filters)) {
    params.set("time_range", "custom");
    if (filters.from) params.set("updated_from", utcBound(filters.from));
    if (filters.to) params.set("updated_to", utcBound(filters.to));
  }
  return params;
}

// ── Counting, chips, clearing ──────────────────────────────────────────────

// One per filter group with any selection: High + Critical is one "Severity".
export function activeFilterCount(filters) {
  const groups = LIST_GROUPS.filter(({ key }) => filters[key].length).length;
  const time = filters.time && (filters.time !== "custom" || customTimeActive(filters)) ? 1 : 0;
  return groups + time;
}

function formatUTC(value) {
  return `${value.replace("T", " ")} UTC`;
}

function timeLabel(filters) {
  if (filters.time !== "custom") return optionLabel(TIME_RANGE_OPTIONS, filters.time);
  if (filters.from && filters.to) return `Updated ${formatUTC(filters.from)} – ${formatUTC(filters.to)}`;
  if (filters.from) return `Updated after ${formatUTC(filters.from)}`;
  return `Updated before ${formatUTC(filters.to)}`;
}

// One chip per selected value. Verdict chips say "Verdict:" so they are not
// confused with the identically named severity values.
export function activeChips(filters) {
  const chips = [];
  LIST_GROUPS.forEach(({ key, title, options }) => {
    filters[key].forEach((value) => {
      const label = optionLabel(options, value);
      chips.push({ group: key, value, label: key === "verdict" ? `Verdict: ${label}` : label, groupTitle: title });
    });
  });
  if (filters.time && (filters.time !== "custom" || customTimeActive(filters))) {
    chips.push({ group: "time", value: filters.time, label: timeLabel(filters), groupTitle: "Time Range" });
  }
  return chips;
}

export function removeChip(filters, group, value) {
  const next = cloneFilters(filters);
  if (group === "time") {
    next.time = "";
    next.from = "";
    next.to = "";
  } else if (next[group]) {
    next[group] = next[group].filter((item) => item !== value);
  }
  return next;
}

// Query-language fields the Filters panel is constraining, to explain an
// empty result when the query constrains the same field (they are ANDed).
export function filterQueryFields(filters) {
  const fields = LIST_GROUPS.filter(({ key }) => filters[key].length).map(({ key }) => key);
  if (filters.time && (filters.time !== "custom" || customTimeActive(filters))) fields.push("updated");
  return fields;
}

// Clears filters only: the search text and sort order are left untouched.
export function clearFilters(state) {
  return { ...state, filters: emptyFilters() };
}

// ── Sorting ────────────────────────────────────────────────────────────────

export function sortLabel(value) {
  return sortOption(value).label;
}

export function nextHeaderSort(column, current) {
  const [first, second] = HEADER_SORTS[column];
  return current === first ? second : first;
}

export function headerSortDirection(column, current) {
  const [first, second] = HEADER_SORTS[column];
  if (current === first) return "descending";
  if (current === second) return "ascending";
  return "none";
}

export function validateCustomRange(filters) {
  if (filters.time !== "custom") return "";
  if (!filters.from && !filters.to) return "Choose a start and/or end time for the custom range.";
  if (filters.from && filters.to && filters.from > filters.to) {
    return "The start time must be before the end time.";
  }
  return "";
}

// ── Markup ─────────────────────────────────────────────────────────────────

const ICON_ATTRS = 'viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"';
export const ICONS = {
  filter: `<svg width="16" height="16" ${ICON_ATTRS}><path d="M3 4h14l-5.5 6.4V16l-3 1.5v-7.1L3 4z"></path></svg>`,
  sort: `<svg width="16" height="16" ${ICON_ATTRS}><path d="M6.5 16V4M3.5 7l3-3 3 3M13.5 4v12M10.5 13l3 3 3-3"></path></svg>`,
  chevronDown: `<svg width="14" height="14" ${ICON_ATTRS}><polyline points="5.5 8 10 12.5 14.5 8"></polyline></svg>`,
  chevronRight: `<svg width="14" height="14" ${ICON_ATTRS}><polyline points="8 5.5 12.5 10 8 14.5"></polyline></svg>`,
  check: `<svg width="15" height="15" ${ICON_ATTRS}><polyline points="4 10.5 8 14.5 16 6"></polyline></svg>`,
  close: `<svg width="12" height="12" ${ICON_ATTRS}><path d="M5 5l10 10M15 5L5 15"></path></svg>`,
  calendar: `<svg width="16" height="16" ${ICON_ATTRS}><rect x="3" y="4.5" width="14" height="12.5" rx="1.5"></rect><path d="M3 8.5h14M7 2.5v4M13 2.5v4"></path></svg>`,
};

export function chipsRowHTML(filters) {
  const chips = activeChips(filters);
  if (!chips.length) return "";
  return `<div class="active-filter-row" role="group" aria-label="Active filters">
    ${chips.map((chip) => `<button type="button" class="active-filter-chip" data-chip-group="${escapeHTML(chip.group)}" data-chip-value="${escapeHTML(chip.value)}" aria-label="Remove ${escapeHTML(chip.groupTitle)} filter: ${escapeHTML(chip.label)}"><span>${escapeHTML(chip.label)}</span>${ICONS.close}</button>`).join("")}
    <button type="button" class="link-button" data-chip-clear>Clear all</button>
  </div>`;
}

function pillGroupHTML({ key, title, options }, filters) {
  const tone = key === "severity" || key === "verdict";
  return `<fieldset class="case-filter-group">
    <legend>${escapeHTML(title)}</legend>
    <div class="case-filter-options">${options.map((option) => {
      const selected = filters[key].includes(option.value);
      const toneClass = tone ? ` tone-${option.value}` : "";
      return `<button type="button" class="filter-pill${toneClass}" data-group="${key}" data-value="${escapeHTML(option.value)}" aria-pressed="${selected}">${escapeHTML(option.label)}</button>`;
    }).join("")}</div>
  </fieldset>`;
}

function filterPanelBodyHTML(filters) {
  const [severity, workflowStatus, stage, verdict] = LIST_GROUPS;
  return `
    ${pillGroupHTML(severity, filters)}
    ${pillGroupHTML(workflowStatus, filters)}
    ${pillGroupHTML(stage, filters)}
    <div class="case-filter-group">
      <label class="case-filter-legend" for="case-filter-time">Time Range</label>
      <div class="case-filter-select">
        ${ICONS.calendar}
        <select id="case-filter-time" aria-describedby="case-filter-time-hint">${TIME_RANGE_OPTIONS.map((option) => `<option value="${option.value}" ${option.value === filters.time ? "selected" : ""}>${escapeHTML(option.label)}</option>`).join("")}</select>
        ${ICONS.chevronDown}
      </div>
      <p class="case-filter-hint" id="case-filter-time-hint">Based on the NetWitness incident's last update time. Times are UTC.</p>
      <div class="case-filter-custom" ${filters.time === "custom" ? "" : "hidden"}>
        <label>From (UTC)<input type="datetime-local" data-time-bound="from" value="${escapeHTML(filters.from)}"></label>
        <label>To (UTC)<input type="datetime-local" data-time-bound="to" value="${escapeHTML(filters.to)}"></label>
      </div>
      <p class="case-filter-error" role="alert" hidden></p>
    </div>
    ${pillGroupHTML(verdict, filters)}
    <button type="button" class="case-filters-more" disabled aria-disabled="true" title="Additional filters are not available yet">
      <span>More filters</span><span class="case-filters-soon">Coming soon</span>${ICONS.chevronRight}
    </button>`;
}

function sortMenuItemsHTML(current) {
  let previousGroup = null;
  return SORT_OPTIONS.map((option) => {
    const separator = previousGroup && previousGroup !== option.group ? '<div class="case-sort-separator" role="separator"></div>' : "";
    previousGroup = option.group;
    const checked = option.value === current;
    return `${separator}<button type="button" class="case-sort-item" role="menuitemradio" aria-checked="${checked}" data-sort="${option.value}" tabindex="-1"><span>${escapeHTML(option.label)}</span>${checked ? ICONS.check : ""}</button>`;
  }).join("");
}

// ── Topbar controls (DOM) ──────────────────────────────────────────────────

let activeControls = null;

export function unmountOverviewControls() {
  activeControls?.destroy();
  activeControls = null;
}

// Keeps a popover inside the viewport (and clear of the sidebar) by
// nudging it horizontally after it opens.
function clampPopover(popover) {
  popover.style.transform = "";
  const rect = popover.getBoundingClientRect();
  const minLeft = (document.querySelector(".app-body")?.getBoundingClientRect().left || 0) + 8;
  const maxRight = document.documentElement.clientWidth - 8;
  let shift = 0;
  if (rect.right > maxRight) shift = maxRight - rect.right;
  if (rect.left + shift < minLeft) shift = minLeft - rect.left;
  if (shift) popover.style.transform = `translateX(${Math.round(shift)}px)`;
}

export function mountOverviewControls({ getState, onChange }) {
  unmountOverviewControls();
  const slot = document.querySelector("#topbar-tools");
  const searchInput = document.querySelector("#topbar-search-input");
  if (!slot || !searchInput) return null;

  slot.innerHTML = `
    <div class="case-tool">
      <button type="button" class="case-tool-button" id="case-filters-toggle" aria-haspopup="dialog" aria-expanded="false" aria-controls="case-filters-panel">
        ${ICONS.filter}<span class="case-tool-label">Filters</span><span class="case-tool-count" hidden></span>
      </button>
      <div class="case-popover case-filters-panel" id="case-filters-panel" role="dialog" aria-labelledby="case-filters-title" hidden>
        <div class="case-filters-header">
          <h2 id="case-filters-title">${ICONS.filter}Filter cases</h2>
          <button type="button" class="link-button" data-panel-action="clear">Clear all</button>
        </div>
        <div class="case-filters-body"></div>
        <div class="case-filters-footer">
          <button type="button" class="case-button-secondary" data-panel-action="cancel">Cancel</button>
          <button type="button" class="case-button-primary" data-panel-action="apply">Apply filters</button>
        </div>
      </div>
    </div>
    <div class="case-tool">
      <button type="button" class="case-tool-button" id="case-sort-toggle" aria-haspopup="menu" aria-expanded="false" aria-controls="case-sort-menu">
        ${ICONS.sort}<span class="case-tool-label">Sort by: <span class="case-sort-current"></span></span>${ICONS.chevronDown}
      </button>
      <div class="case-popover case-sort-menu" id="case-sort-menu" hidden>
        <p class="case-sort-title" id="case-sort-title">${ICONS.sort}Sort by</p>
        <div class="case-sort-items" role="menu" aria-labelledby="case-sort-title"></div>
      </div>
    </div>`;

  const filterToggle = slot.querySelector("#case-filters-toggle");
  const filterPanel = slot.querySelector("#case-filters-panel");
  const filterBody = filterPanel.querySelector(".case-filters-body");
  const countBadge = filterToggle.querySelector(".case-tool-count");
  const sortToggle = slot.querySelector("#case-sort-toggle");
  const sortMenu = slot.querySelector("#case-sort-menu");
  const sortItems = sortMenu.querySelector(".case-sort-items");
  let draft = null;
  let searchTimer = null;

  function sync() {
    const state = getState();
    const count = activeFilterCount(state.filters);
    countBadge.hidden = count === 0;
    countBadge.textContent = String(count);
    filterToggle.classList.toggle("has-active", count > 0);
    filterToggle.setAttribute("aria-label", count ? `Filters, ${count} active` : "Filters");
    const label = sortLabel(state.sort);
    sortToggle.querySelector(".case-sort-current").textContent = label;
    sortToggle.setAttribute("aria-label", `Sort by: ${label}`);
    if (!sortMenu.hidden) sortItems.innerHTML = sortMenuItemsHTML(state.sort);
    if (document.activeElement !== searchInput) searchInput.value = state.q;
  }

  // Filters panel: edits a draft; only Apply (or Clear all) changes state.
  function renderDraft() {
    filterBody.innerHTML = filterPanelBodyHTML(draft);
  }

  function showPanelError(message) {
    const error = filterBody.querySelector(".case-filter-error");
    error.textContent = message;
    error.hidden = !message;
  }

  function openFilters() {
    closeSort(false);
    draft = cloneFilters(getState().filters);
    renderDraft();
    filterPanel.hidden = false;
    filterToggle.setAttribute("aria-expanded", "true");
    clampPopover(filterPanel);
    filterBody.querySelector("button, select, input")?.focus();
  }

  function closeFilters(returnFocus = true) {
    if (filterPanel.hidden) return;
    filterPanel.hidden = true;
    filterToggle.setAttribute("aria-expanded", "false");
    draft = null;
    if (returnFocus) filterToggle.focus();
  }

  function openSort() {
    closeFilters(false);
    sortItems.innerHTML = sortMenuItemsHTML(getState().sort);
    sortMenu.hidden = false;
    sortToggle.setAttribute("aria-expanded", "true");
    clampPopover(sortMenu);
    (sortItems.querySelector('[aria-checked="true"]') || sortItems.querySelector(".case-sort-item"))?.focus();
  }

  function closeSort(returnFocus = true) {
    if (sortMenu.hidden) return;
    sortMenu.hidden = true;
    sortToggle.setAttribute("aria-expanded", "false");
    if (returnFocus) sortToggle.focus();
  }

  filterToggle.addEventListener("click", () => (filterPanel.hidden ? openFilters() : closeFilters()));
  sortToggle.addEventListener("click", () => (sortMenu.hidden ? openSort() : closeSort()));

  filterPanel.addEventListener("click", (event) => {
    const pill = event.target.closest(".filter-pill");
    if (pill && draft) {
      const { group, value } = pill.dataset;
      draft[group] = draft[group].includes(value)
        ? draft[group].filter((item) => item !== value)
        : [...draft[group], value];
      pill.setAttribute("aria-pressed", String(draft[group].includes(value)));
      return;
    }
    const action = event.target.closest("[data-panel-action]")?.dataset.panelAction;
    if (action === "cancel") {
      closeFilters();
    } else if (action === "clear") {
      draft = emptyFilters();
      renderDraft();
      onChange(clearFilters(getState()));
      filterPanel.querySelector('[data-panel-action="clear"]').focus();
    } else if (action === "apply" && draft) {
      const message = validateCustomRange(draft);
      if (message) {
        showPanelError(message);
        return;
      }
      const filters = draft.time === "custom" ? draft : { ...draft, from: "", to: "" };
      closeFilters();
      onChange({ ...getState(), filters });
    }
  });

  filterPanel.addEventListener("change", (event) => {
    if (!draft) return;
    if (event.target.id === "case-filter-time") {
      draft.time = event.target.value;
      filterBody.querySelector(".case-filter-custom").hidden = draft.time !== "custom";
      showPanelError("");
    } else if (event.target.dataset.timeBound) {
      draft[event.target.dataset.timeBound] = event.target.value;
      showPanelError("");
    }
  });

  sortMenu.addEventListener("click", (event) => {
    const item = event.target.closest("[data-sort]");
    if (!item) return;
    closeSort();
    onChange({ ...getState(), sort: item.dataset.sort });
  });

  sortMenu.addEventListener("keydown", (event) => {
    const items = [...sortItems.querySelectorAll(".case-sort-item")];
    const index = items.indexOf(document.activeElement);
    let next = null;
    if (event.key === "ArrowDown") next = items[(index + 1) % items.length];
    else if (event.key === "ArrowUp") next = items[(index - 1 + items.length) % items.length];
    else if (event.key === "Home") next = items[0];
    else if (event.key === "End") next = items[items.length - 1];
    else if (event.key === "Tab") closeSort(false);
    if (next) {
      event.preventDefault();
      next.focus();
    }
  });

  function onDocumentKeydown(event) {
    if (event.key !== "Escape") return;
    if (!filterPanel.hidden) {
      event.preventDefault();
      closeFilters();
    } else if (!sortMenu.hidden) {
      event.preventDefault();
      closeSort();
    }
  }

  function onDocumentPointerDown(event) {
    if (!filterPanel.hidden && !event.target.closest("#case-filters-panel, #case-filters-toggle")) closeFilters(false);
    if (!sortMenu.hidden && !event.target.closest("#case-sort-menu, #case-sort-toggle")) closeSort(false);
  }

  function onResize() {
    if (!filterPanel.hidden) clampPopover(filterPanel);
    if (!sortMenu.hidden) clampPopover(sortMenu);
  }

  // Topbar search: free text runs server-side after a short debounce; a
  // structured query (any field:value) runs on Enter, so a half-typed
  // `severity:` never produces an error while the analyst is typing.
  const assist = createQueryAssist({ input: searchInput, onRun: () => applySearch() });

  function applySearch() {
    clearTimeout(searchTimer);
    assist?.setPending(false);
    const q = searchInput.value.trim();
    if (q !== getState().q) onChange({ ...getState(), q });
  }

  function onSearchInput() {
    clearTimeout(searchTimer);
    assist?.onInput();
    if (assist?.isStructured(searchInput.value)) {
      assist.setPending(searchInput.value.trim() !== getState().q);
    } else {
      assist?.setPending(false);
      searchTimer = setTimeout(applySearch, 300);
    }
  }

  function onSearchKeydown(event) {
    if (assist?.handleKeydown(event)) return;
    if (event.key === "Enter") {
      event.preventDefault();
      applySearch();
    } else if (event.key === "Escape" && searchInput.value) {
      searchInput.value = "";
      assist?.onInput();
      applySearch();
    }
  }

  document.addEventListener("keydown", onDocumentKeydown);
  document.addEventListener("pointerdown", onDocumentPointerDown);
  window.addEventListener("resize", onResize);
  searchInput.addEventListener("input", onSearchInput);
  searchInput.addEventListener("keydown", onSearchKeydown);
  searchInput.value = getState().q;
  sync();

  activeControls = {
    sync,
    showQueryError(error, query) {
      assist?.showError(error, query);
    },
    clearQueryError() {
      assist?.clearError();
    },
    destroy() {
      clearTimeout(searchTimer);
      assist?.destroy();
      document.removeEventListener("keydown", onDocumentKeydown);
      document.removeEventListener("pointerdown", onDocumentPointerDown);
      window.removeEventListener("resize", onResize);
      searchInput.removeEventListener("input", onSearchInput);
      searchInput.removeEventListener("keydown", onSearchKeydown);
      searchInput.value = "";
      slot.innerHTML = "";
    },
  };
  return activeControls;
}
