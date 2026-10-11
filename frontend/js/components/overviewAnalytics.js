// Operations Overview analytics: six charts over GET /api/dashboard/analytics.
//
// One time-range control scopes every chart. Ranges are measured back from
// now on the NetWitness `created` time, and every time shown is UTC.
//
// Drill-downs only use filters that reproduce the clicked count exactly:
//   severity slice  -> Severity filter
//   stage column    -> Workflow Stage filter + `NOT workflow_status:not_started`
//                      (the chart only counts incidents that entered the workflow)
//   trend period    -> `created:>=… AND created:<…`
//   7d / 30d range  -> `created:>=… AND created:<…` added to the above
// Detection rules, MITRE tactics, source IPs and heatmap cells have no exact
// case filter, so they show tooltips but do not filter.

import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, formatCount, loadingState } from "../ui.js";
import {
  areaTrendChart, donutChart, formatPercent, formatUTC, heatmapChart, hideTooltip, rankedBars,
  stackedColumnChart,
} from "./charts.js";

const RANGES = [
  { value: "7d", label: "7 days", phrase: "in the last 7 days" },
  { value: "30d", label: "30 days", phrase: "in the last 30 days" },
  { value: "all", label: "All time", phrase: "" },
];
const DEFAULT_RANGE = "all";

// Hex (not CSS variables) because SVG presentation attributes cannot read
// var(). Severity/state hues were checked with the dataviz palette
// validator against --surface; every mark also carries a text label.
const SEVERITY_COLORS = {
  critical: "#e8505f",
  high: "#e0a030",
  medium: "#3a80dc",
  low: "#27a874",
};
const NEUTRAL_COLOR = "#5d6b80";
const STATE_COLORS = {
  completed: "#27a874",
  in_progress: "#3a80dc",
  awaiting_approval: "#e0a030",
  not_started: "#52637d",
  failed: "#e8505f",
  rejected: "#c95c96",
  locked: "#8792a3",
};
const STATE_ORDER = ["completed", "awaiting_approval", "in_progress", "failed", "rejected", "locked", "not_started"];
const STAGE_LABELS = {
  parsing: ["Parsing", "Parse"],
  triage: ["Triage", "Triage"],
  threat_intel: ["Threat Intel", "TI"],
  investigation: ["Investigation", "Invest."],
  reporting: ["Reporting", "Report"],
};
const TREND_COLOR = "#76b7ff";
const RULE_COLOR = "#5b9cf0";
const TACTIC_COLOR = "#9b7be8";
const IP_COLOR = "#2fb3a8";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DRILL_HINT = "Click to show these incidents in Recent cases";

const CARDS = [
  { id: "severity", title: "Incidents by severity" },
  { id: "stage", title: "Incidents by workflow stage" },
  { id: "trend", title: "Newly created incidents" },
  { id: "types", title: "Top incident types" },
  { id: "ips", title: "Top source IP addresses" },
  { id: "heatmap", title: "Incident activity (day × hour)" },
];

export function analyticsSectionHTML() {
  return `<section class="analytics" aria-labelledby="analytics-title">
    <div class="analytics-toolbar">
      <div class="analytics-heading">
        <h2 id="analytics-title">Threat analytics</h2>
        <p class="analytics-meta" id="analytics-meta">All times UTC</p>
      </div>
      <div class="range-toggle" role="group" aria-label="Analytics time range">
        ${RANGES.map((range) => `<button type="button" class="range-toggle-button" data-range="${range.value}" aria-pressed="${range.value === DEFAULT_RANGE}">${range.label}</button>`).join("")}
      </div>
    </div>
    <div class="analytics-grid">
      ${CARDS.map((card) => `<article class="panel chart-card chart-card-${card.id}" aria-labelledby="chart-${card.id}-title">
        <header class="chart-card-header">
          <div class="chart-card-heading">
            <h3 id="chart-${card.id}-title">${escapeHTML(card.title)}</h3>
            <p class="chart-card-subtitle" id="chart-${card.id}-subtitle"></p>
          </div>
          <div class="chart-card-tools" id="chart-${card.id}-tools"></div>
        </header>
        <div class="chart-card-body" id="chart-${card.id}-body" aria-live="polite">${loadingState("Loading…")}</div>
        <p class="chart-card-footnote" id="chart-${card.id}-footnote"></p>
      </article>`).join("")}
    </div>
  </section>`;
}

// "2026-10-04T10:31:00" -> "2026-10-04T10:31", or "2026-10-04" at midnight.
function queryStamp(stamp) {
  const value = String(stamp).slice(0, 19);
  return value.endsWith("T00:00:00") ? value.slice(0, 10) : value.slice(0, 16);
}

function createdBetween(start, end) {
  return [`created:>=${queryStamp(start)}`, `created:<${queryStamp(end)}`];
}

function bucketLabels(bucket, granularity) {
  const [year, month, day] = bucket.key.split("-");
  if (granularity === "month") {
    return { label: `${MONTHS[Number(month) - 1]} ${year.slice(2)}`, longLabel: `${MONTHS[Number(month) - 1]} ${year} (UTC)` };
  }
  const span = bucket.partial ? ` · ${bucket.start.slice(11, 16)}–${bucket.end.endsWith("T00:00:00") ? "24:00" : bucket.end.slice(11, 16)}` : "";
  return { label: `${Number(day)} ${MONTHS[Number(month) - 1]}`, longLabel: `${Number(day)} ${MONTHS[Number(month) - 1]} ${year}${span} UTC` };
}

/**
 * Mount the analytics behaviour onto the markup from analyticsSectionHTML().
 * onDrilldown({ filters, terms }) applies a Recent Cases filter.
 */
export function mountAnalytics(root, { onDrilldown, isActive }) {
  const section = root.querySelector(".analytics");
  if (!section) return;
  let range = DEFAULT_RANGE;
  let typeView = "rules";
  let requestId = 0;
  let data = null;

  const part = (id, name) => section.querySelector(`#chart-${id}-${name}`);
  const set = (id, name, html) => { part(id, name).innerHTML = html; };

  function rangeTerms() {
    return data?.window?.start ? createdBetween(data.window.start, data.window.end) : [];
  }

  function drill(filters, terms = rangeTerms()) {
    hideTooltip();
    onDrilldown({ filters, terms });
  }

  function noIncidentsMessage() {
    const latest = data.data_bounds?.latest_created;
    if (!latest) return "No incidents have been recorded yet.";
    const phrase = RANGES.find((option) => option.value === range)?.phrase;
    return `No incidents were created ${phrase}. The most recent incident was created ${formatUTC(latest)}.`;
  }

  // Each chart renders in isolation: one failure never blanks the others.
  function renderCard(id, render) {
    set(id, "footnote", "");
    set(id, "tools", "");
    try {
      render();
    } catch (error) {
      console.error(`Analytics chart "${id}" failed to render`, error);
      set(id, "body", errorState({ message: "This chart could not be drawn from the returned data." }));
    }
  }

  function renderSeverity() {
    const { items, total } = data.severity;
    set("severity", "subtitle", "Share of incidents by NetWitness severity");
    if (!total) return set("severity", "body", emptyState(noIncidentsMessage()));
    const unknown = items.filter((item) => !item.filterable && item.count);
    if (unknown.length) {
      set("severity", "footnote", `${unknown.map((item) => `${formatCount(item.count)} ${item.label.toLowerCase()}`).join(", ")}: no severity recorded, shown separately.`);
    }
    donutChart(part("severity", "body"), {
      items: items.map((item) => ({ ...item, color: SEVERITY_COLORS[item.key] || NEUTRAL_COLOR })),
      total,
      centerLabel: total === 1 ? "incident" : "incidents",
      caption: "Incidents by severity",
      hint: DRILL_HINT,
      onSelect: (item) => drill({ severity: [item.key] }),
    });
  }

  function renderStages() {
    const { entered, unprocessed, items, state_labels: stateLabels } = data.stages;
    set("stage", "subtitle", `Current stage of incidents in the agent workflow`);
    set("stage", "tools", `<span class="chart-stat" title="Incidents that have not entered the agent workflow"><strong>${formatCount(unprocessed)}</strong> not yet processed</span>`);
    if (!data.total) return set("stage", "body", emptyState(noIncidentsMessage()));
    if (!entered) {
      return set("stage", "body", emptyState(`None of the ${formatCount(data.total)} incidents in this range has entered the agent workflow yet.`));
    }
    // Fixed bottom-to-top order (JSON object key order is not preserved);
    // any state the backend adds later is appended rather than dropped.
    const order = [...STATE_ORDER, ...Object.keys(stateLabels).filter((state) => !STATE_ORDER.includes(state))];
    const presentStates = order.filter((state) => items.some((item) => item.states[state]));
    stackedColumnChart(part("stage", "body"), {
      items: items.map((item) => ({
        key: item.key,
        label: item.label,
        shortLabel: STAGE_LABELS[item.key]?.[0] || item.label,
        tinyLabel: STAGE_LABELS[item.key]?.[1],
        count: item.count,
        segments: presentStates.map((state) => ({ key: state, label: stateLabels[state], count: item.states[state], color: STATE_COLORS[state] || NEUTRAL_COLOR })),
      })),
      caption: `Incidents by current workflow stage (${formatCount(entered)} in the workflow)`,
      hint: DRILL_HINT,
      onSelect: (item) => drill({ stage: [item.key] }, [...rangeTerms(), "NOT workflow_status:not_started"]),
    });
    part("stage", "body").insertAdjacentHTML("beforeend", `<ul class="chart-legend">${presentStates.map((state) => `<li><span class="legend-swatch" style="background:${STATE_COLORS[state] || NEUTRAL_COLOR}"></span>${escapeHTML(stateLabels[state])}</li>`).join("")}</ul>`);
    set("stage", "footnote", `${formatCount(entered)} of ${formatCount(data.total)} incidents (${formatPercent(entered, data.total)}) have entered the workflow.`);
  }

  function renderTrend() {
    const { buckets, granularity, total, excluded } = data.trend;
    set("trend", "subtitle", `Incidents by NetWitness created time, per ${granularity === "month" ? "month" : "day"} (UTC)`);
    if (!total) return set("trend", "body", emptyState(noIncidentsMessage()));
    if (excluded) set("trend", "footnote", `${formatCount(excluded)} incident${excluded === 1 ? "" : "s"} without a created time not shown.`);
    areaTrendChart(part("trend", "body"), {
      buckets: buckets.map((bucket) => ({ ...bucket, ...bucketLabels(bucket, granularity) })),
      caption: `Newly created incidents per ${granularity} (UTC)`,
      valueLabel: "incidents created",
      color: TREND_COLOR,
      hint: DRILL_HINT,
      onSelect: (bucket) => drill({}, createdBetween(bucket.start, bucket.end)),
    });
  }

  function renderTypes() {
    const rules = data.detection_rules;
    const tactics = data.mitre_tactics;
    set("types", "tools", `<div class="chart-switch" role="group" aria-label="Incident type grouping">
      <button type="button" data-type-view="rules" aria-pressed="${typeView === "rules"}">Detection rules</button>
      <button type="button" data-type-view="tactics" aria-pressed="${typeView === "tactics"}">MITRE ATT&amp;CK</button>
    </div>`);
    if (typeView === "rules") {
      set("types", "subtitle", `<span class="coverage-badge coverage-full">All incidents</span> NetWitness rule that raised the incident`);
      if (!rules.total) return set("types", "body", emptyState(noIncidentsMessage()));
      rankedBars(part("types", "body"), {
        items: rules.items, other: rules.other, otherLabel: "Other rules", total: rules.total,
        color: RULE_COLOR, caption: "Incidents by detection rule", labelHeader: "Detection rule",
      });
      set("types", "footnote", `${formatCount(rules.distinct)} distinct rule${rules.distinct === 1 ? "" : "s"} across ${formatCount(rules.total)} incidents. NetWitness incident categories are empty in this data set.`);
      return;
    }
    set("types", "subtitle", `<span class="coverage-badge coverage-partial">Triaged incidents only</span> Tactic recorded by the Triage agent`);
    if (!data.total) return set("types", "body", emptyState(noIncidentsMessage()));
    if (!tactics.triaged) {
      return set("types", "body", emptyState("No incident in this range has a Triage result yet, so no MITRE ATT&CK tactic is available."));
    }
    rankedBars(part("types", "body"), {
      items: tactics.items, other: tactics.other, otherLabel: "Other tactics", total: tactics.triaged,
      color: TACTIC_COLOR, caption: "Triaged incidents by MITRE ATT&CK tactic", labelHeader: "MITRE ATT&CK tactic",
    });
    set("types", "footnote", `Covers ${formatCount(tactics.triaged)} of ${formatCount(data.total)} incidents (${formatPercent(tactics.triaged, data.total)}). Shares are of triaged incidents.`);
  }

  function renderIPs() {
    const ips = data.source_ips;
    set("ips", "subtitle", "Incidents per alert source IP (alertMeta.SourceIp)");
    if (!data.total) return set("ips", "body", emptyState(noIncidentsMessage()));
    if (!ips.with_ip) return set("ips", "body", emptyState("No source IP is recorded for the incidents in this range."));
    rankedBars(part("ips", "body"), {
      items: ips.items, other: ips.other, otherLabel: `Other (${formatCount(ips.distinct - ips.items.length)} IPs)`,
      total: ips.with_ip, color: IP_COLOR, caption: "Incidents by source IP", labelHeader: "Source IP", mono: true,
    });
    const notes = [`Shares are of ${formatCount(ips.with_ip)} incidents with a source IP; an incident with several IPs counts once for each.`];
    if (ips.without_ip) notes.push(`${formatCount(ips.without_ip)} incident${ips.without_ip === 1 ? "" : "s"} with no source IP not shown.`);
    set("ips", "footnote", notes.join(" "));
  }

  function renderHeatmap() {
    const heat = data.heatmap;
    set("heatmap", "subtitle", "Incidents by created day and hour (UTC)");
    if (!heat.total) return set("heatmap", "body", emptyState(noIncidentsMessage()));
    heatmapChart(part("heatmap", "body"), {
      days: heat.days, cells: heat.cells, max: heat.max,
      caption: "Incidents created by day of week and hour of day, UTC",
    });
    if (heat.excluded) set("heatmap", "footnote", `${formatCount(heat.excluded)} incident${heat.excluded === 1 ? "" : "s"} without a created time not shown.`);
  }

  function renderMeta() {
    const meta = section.querySelector("#analytics-meta");
    const bounds = data.data_bounds || {};
    const parts = ["All times UTC"];
    if (data.window?.start) parts.push(`${formatUTC(data.window.start)} to now`);
    if (bounds.earliest_created) {
      parts.push(`Incident data spans ${formatUTC(bounds.earliest_created, { time: false })} – ${formatUTC(bounds.latest_created, { time: false })}`);
    }
    parts.push(`${formatCount(data.total)} incident${data.total === 1 ? "" : "s"} in range`);
    meta.textContent = parts.join(" · ");
  }

  function renderAll() {
    renderMeta();
    renderCard("severity", renderSeverity);
    renderCard("stage", renderStages);
    renderCard("trend", renderTrend);
    renderCard("types", renderTypes);
    renderCard("ips", renderIPs);
    renderCard("heatmap", renderHeatmap);
  }

  async function load() {
    const current = ++requestId;
    section.classList.add("is-refreshing");
    section.setAttribute("aria-busy", "true");
    try {
      const response = await fetchJSON(`/api/dashboard/analytics?range=${encodeURIComponent(range)}`);
      if (!isActive() || current !== requestId) return;
      data = response;
      renderAll();
    } catch (error) {
      if (!isActive() || current !== requestId) return;
      // Never leave the previous range's charts under the new range's label.
      data = null;
      section.querySelector("#analytics-meta").textContent = "All times UTC";
      CARDS.forEach(({ id }) => {
        set(id, "subtitle", "");
        set(id, "tools", "");
        set(id, "footnote", "");
        set(id, "body", `${errorState(error)}<div class="chart-retry"><button type="button" class="case-tool-button" data-analytics-retry>Retry</button></div>`);
      });
    } finally {
      if (isActive() && current === requestId) {
        section.classList.remove("is-refreshing");
        section.removeAttribute("aria-busy");
      }
    }
  }

  section.addEventListener("click", (event) => {
    const rangeButton = event.target.closest("[data-range]");
    if (rangeButton && rangeButton.dataset.range !== range) {
      range = rangeButton.dataset.range;
      section.querySelectorAll("[data-range]").forEach((button) => button.setAttribute("aria-pressed", String(button === rangeButton)));
      load();
      return;
    }
    const typeButton = event.target.closest("[data-type-view]");
    if (typeButton && data && typeButton.dataset.typeView !== typeView) {
      typeView = typeButton.dataset.typeView;
      renderCard("types", renderTypes);
      part("types", "tools").querySelector(`[data-type-view="${typeView}"]`)?.focus();
      return;
    }
    if (event.target.closest("[data-analytics-retry]")) load();
  });

  load();
}
