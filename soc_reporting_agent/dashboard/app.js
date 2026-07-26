const state = {
  route: "dashboard",
  params: {},
  summary: {},
  tickets: [],
  alerts: [],
  history: [],
  selectedTicket: null,
  selectedAlert: null,
  subroute: null,
  runs: [],
  integrations: {},
  exportStatus: {},
  ticketTab: "overview",
  timelineSort: "oldest",
  timelineExpandedIndex: null,
  timelineFilters: { kind: "all", source: "all", severity: "all", entity: "all", tactic: "all" },
  expandedAgentKey: null,
  selectedAgentKey: "parsing",
  collapsedPanels: {},
  rightPanelCollapsed: false,
  agentWorkspacePreviewCollapsed: true,
  liveLogPollingInterval: null,
  loading: false,
  renderError: "",
  askAgentAnswers: {},
  agentRunGuards: {},
  agentRunGuardSequence: 0,
  approvalRequests: {},
  netwitnessAutoConnectAttempted: false,
  lastNetWitnessSync: null,
  currentUser: document.querySelector(".profile-menu strong")?.textContent?.trim() || "SOC Analyst",
};

const navGroups = [
  { label: "Dashboard", items: [{ id: "dashboard", icon: "ti-layout-dashboard", text: "Dashboard" }] },
  { label: "Tickets", items: [
    { id: "all-tickets", icon: "ti-ticket", text: "All Tickets" },
    { id: "my-tickets", icon: "ti-users", text: "My Tickets", params: { view: "my" } },
    { id: "pending-approval", icon: "ti-clock-up", text: "Pending Approval", params: { view: "pending_approval" } },
    { id: "closed-cases", icon: "ti-circle-check", text: "Closed Cases", params: { view: "closed" } },
  ] },
  { label: "NetWitness", items: [
    { id: "netwitness-alerts", icon: "ti-bell", text: "Alerts" },
    { id: "search-alerts", icon: "ti-search", text: "Search Alerts" },
    { id: "alert-history", icon: "ti-history", text: "Alert History" },
  ] },
  { label: "Reports", items: [
    { id: "reports", icon: "ti-file-description", text: "Reports" },
    { id: "templates", icon: "ti-template", text: "Templates" },
  ] },
  { label: "System", items: [
    { id: "integrations", icon: "ti-link", text: "Integrations" },
    { id: "settings", icon: "ti-settings", text: "Settings" },
    { id: "audit-log", icon: "ti-clipboard-list", text: "Audit Log" },
  ] },
];

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
const norm = (s) => String(s || "").toLowerCase().replace(/[\s-]+/g, "_");
const arrayOf = (value) => Array.isArray(value) ? value : [];
const stripReportUiMarkup = (value) => String(value ?? "")
  .replace(/<\/?(?:td|tr|th|table|tbody|thead|p|div|span|br|strong|em|b|i|ul|ol|li|h[1-6])[^>]*>/gi, " ")
  .replace(/&lt;\/?(?:td|tr|th|table|tbody|thead|p|div|span|br|strong|em|b|i|ul|ol|li|h[1-6])[^&]*&gt;/gi, " ")
  .replace(/```/g, "")
  .replace(/`([^`]+)`/g, "$1")
  .replace(/\*\*([^*]+)\*\*/g, "$1")
  .replace(/__([^_]+)__/g, "$1")
  .replace(/\[([^\]]+)\]\([^\)]+\)/g, "$1")
  .replace(/\s+/g, " ")
  .trim();
const ticketRoutes = ["all-tickets", "my-tickets", "pending-approval", "closed-cases"];
const legacyRoutes = { tickets: "all-tickets", alerts: "netwitness-alerts" };

function normalizeRoute(route) {
  return legacyRoutes[route] || route || "dashboard";
}

function isTicketRoute(route = state.route) {
  return ticketRoutes.includes(route);
}

function isAgentWorkspaceRoute() {
  return state.route === "my-tickets" && state.subroute === "agents";
}

function isTicketPreviewCollapsed() {
  return isAgentWorkspaceRoute() ? state.agentWorkspacePreviewCollapsed : state.rightPanelCollapsed;
}

function dashboardGridClass() {
  return `dashboard-grid ${isTicketPreviewCollapsed() ? "side-collapsed" : ""}`.trim();
}

function toggleTicketPreview() {
  if (isAgentWorkspaceRoute()) {
    state.agentWorkspacePreviewCollapsed = !state.agentWorkspacePreviewCollapsed;
  } else {
    state.rightPanelCollapsed = !state.rightPanelCollapsed;
  }
  render();
}

function setApiError(message) {
  state.renderError = message || "";
}

function dashboardLoadError(res, fallback = "Unable to load dashboard data.") {
  const text = errorText(res, fallback);
  if (res?.error_code === "POSTGRES_UNAVAILABLE" || /postgresql is required|postgres/i.test(text)) {
    return `${text} Start PostgreSQL or fix POSTGRES_DSN, then refresh.`;
  }
  return text;
}

function errorPanel(message, detail = "") {
  return `<section class="panel error-panel">
    <div class="panel-head"><h2>Dashboard data unavailable</h2></div>
    <div class="empty-state">${esc(message || "The dashboard could not load the requested data.")}${detail ? `<br><small>${esc(detail)}</small>` : ""}</div>
  </section>`;
}

function routeTitle() {
  if (state.route === "my-tickets") {
    const subLabels = {
      overview: "Selected Ticket",
      agents: "Agent Workspace",
      alerts: "Related Alerts",
      timeline: "Timeline",
      reports: "Reports",
    };
    const label = state.subroute ? subLabels[state.subroute] || "My Tickets" : "Selected Ticket";
    return `My Tickets / ${label}`;
  }
  const found = navGroups.flatMap(g => g.items).find(i => i.id === state.route);
  return found ? found.text : "Dashboard";
}

function defaultExpandedAgentKey(ticket) {
  if (!ticket || !Array.isArray(ticket.agent_panel)) return null;
  const readyOrRunning = ticket.agent_panel.find(agent => ["Running", "Ready"].includes(agent.status));
  return readyOrRunning?.key || null;
}

function expandedAgentKey(ticket) {
  if (state.expandedAgentKey === "__NONE__") return null;
  return state.expandedAgentKey || defaultExpandedAgentKey(ticket);
}

function toggleAgentCard(agentKey) {
  if (!agentKey) return;
  const current = expandedAgentKey(state.selectedTicket);
  state.expandedAgentKey = current === agentKey ? "__NONE__" : agentKey;
  render();
}

function selectAgent(agentKey) {
  if (!agentKey) return;
  state.selectedAgentKey = agentKey;
  state.collapsedPanels = {};
  render();
}

function togglePanel(panelName) {
  if (!panelName) return;
  state.collapsedPanels[panelName] = !state.collapsedPanels[panelName];
  render();
}

function startLiveActivityLogPolling() {
  if (state.liveLogPollingInterval) clearInterval(state.liveLogPollingInterval);
  state.liveLogPollingInterval = setInterval(() => {
    const agents = arrayOf(state.selectedTicket?.agent_panel);
    const agent = agents.find(a => a.key === state.selectedAgentKey);
    const run = agent ? currentAgentRun(agent) : null;
    if (!run || !agent) {
      stopLiveActivityLogPolling();
      return;
    }
    refresh().then(() => {
      const updated = currentAgentRun(agent);
      if (!runIsActive(updated)) {
        stopLiveActivityLogPolling();
      }
      render();
    });
  }, 1500);
}

function stopLiveActivityLogPolling() {
  if (state.liveLogPollingInterval) {
    clearInterval(state.liveLogPollingInterval);
    state.liveLogPollingInterval = null;
  }
}

function setRoute(route, params = {}) {
  const wasAgentWorkspace = isAgentWorkspaceRoute();
  // support subroutes like "my-tickets/overview"
  let top = route || "dashboard";
  let sub = null;
  if (top.includes("/")) {
    [top, sub] = top.split("/", 2);
  }
  state.route = normalizeRoute(top);
  state.subroute = sub || null;
  if (state.route === "my-tickets" && state.subroute === "agents" && !wasAgentWorkspace) {
    state.agentWorkspacePreviewCollapsed = true;
  }
  state.params = params || {};
  const query = new URLSearchParams(params).toString();
  const hash = `#/${state.route}${state.subroute ? `/${state.subroute}` : ""}${query ? `?${query}` : ""}`;
  if (location.hash !== hash) location.hash = hash;
  else render();
  refresh().then(() => {
    if (state.route === "my-tickets" && state.subroute === "agents") {
      const agents = arrayOf(state.selectedTicket?.agent_panel);
      const runningAgent = agents.find(a => a.status === "Running");
      if (runningAgent) {
        state.selectedAgentKey = runningAgent.key;
        startLiveActivityLogPolling();
        render();
      }
    }
  });
}

function readRoute() {
  const raw = (location.hash || "#/dashboard").replace(/^#\/?/, "");
  const [path, query] = raw.split("?");
  const parts = (path || "dashboard").split("/");
  const top = parts[0] || "dashboard";
  const sub = parts[1] || null;
  state.route = normalizeRoute(top);
  state.subroute = sub;
  state.params = Object.fromEntries(new URLSearchParams(query || ""));
}

async function api(path, opts = {}) {
  const res = await fetch(path, { cache: "no-store", ...opts });
  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) data.success = false;
  data.http_status = res.status;
  if (data.success === false && !data.status && data.message) data.status = data.message;
  if (data.success === false && data.error_code) {
    data.display_error = `${data.title || data.error_code}: ${data.message || data.status || "Request failed"}`;
  }
  return data;
}

function errorText(res, fallback = "Action failed") {
  if (!res) return fallback;
  if (res.display_error) return res.display_error;
  if (res.message && res.analyst_action) return `${res.message} ${res.analyst_action}`;
  return res.status || res.message || fallback;
}

function toast(message, type = "blue") {
  const el = $("#toast");
  if (!el) return console.warn(message);
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.remove("show"), 3600);
}

function openModal(title, sub, body) {
  $("#modal-title").textContent = title;
  $("#modal-sub").textContent = sub || "";
  $("#modal-body").innerHTML = body;
  $("#modal-backdrop").style.display = "flex";
}

function closeModal() {
  $("#modal-backdrop").style.display = "none";
  window.__modalSubmitHandler = null;
}

function optionListForTickets(currentId = "") {
  const ids = new Set();
  arrayOf(state.tickets).forEach(t => t?.ticket_id && ids.add(t.ticket_id));
  if (state.selectedTicket?.ticket_id) ids.add(state.selectedTicket.ticket_id);
  if (currentId) ids.add(currentId);
  return Array.from(ids).map(id => `<option value="${esc(id)}" ${id === currentId ? "selected" : ""}>${esc(id)}</option>`).join("");
}

function openActionModal({ title, sub = "", summary = "", fields = [], confirmText = "Confirm", danger = false, onSubmit }) {
  const fieldHtml = fields.map(field => {
    const value = field.value ?? "";
    if (field.type === "select") {
      return `<label class="modal-field"><span>${esc(field.label)}</span><select name="${esc(field.name)}" ${field.required ? "required" : ""}>${field.options || ""}</select></label>`;
    }
    if (field.type === "textarea") {
      return `<label class="modal-field"><span>${esc(field.label)}</span><textarea name="${esc(field.name)}" rows="${field.rows || 4}" ${field.required ? "required" : ""}>${esc(value)}</textarea></label>`;
    }
    if (field.type === "checkbox") {
      return `<label class="modal-check"><input type="checkbox" name="${esc(field.name)}" ${field.checked ? "checked" : ""}> <span>${esc(field.label)}</span></label>`;
    }
    return `<label class="modal-field"><span>${esc(field.label)}</span><input name="${esc(field.name)}" value="${esc(value)}" placeholder="${esc(field.placeholder || "")}" ${field.required ? "required" : ""}></label>`;
  }).join("");
  const body = `<form id="action-modal-form" class="modal-form">
    ${summary ? `<div class="modal-summary">${summary}</div>` : ""}
    <div class="modal-fields">${fieldHtml}</div>
    <div class="modal-actions">
      <button type="button" class="soc-btn ghost" data-close-modal>Cancel</button>
      <button type="submit" class="soc-btn ${danger ? "danger" : "primary"}">${esc(confirmText)}</button>
    </div>
  </form>`;
  window.__modalSubmitHandler = onSubmit;
  openModal(title, sub, body);
}

function formPayload(form) {
  const data = {};
  Array.from(new FormData(form).entries()).forEach(([key, value]) => { data[key] = value; });
  Array.from(form.querySelectorAll('input[type="checkbox"]')).forEach(input => { data[input.name] = input.checked; });
  return data;
}

function badge(value, type, attrs = "") {
  const n = norm(value);
  const cls = type || (n.includes("critical") || n.includes("reject") || n.includes("failed") ? "red" :
    n.includes("high") || n.includes("pending") || n.includes("approval") ? "yellow" :
    n.includes("complete") || n.includes("closed") || n.includes("approved") ? "green" : "blue");
  return `<span class="soc-badge ${cls}" ${attrs}>${esc(value || "Unknown")}</span>`;
}

function severityBadge(sev) {
  const n = norm(sev);
  return badge(sev || "Unknown", n === "critical" ? "red" : n === "high" ? "orange" : n === "medium" ? "yellow" : "blue");
}

function ticketStatusBadge(status) {
  const fullStatus = status || "Unknown";
  const label = norm(fullStatus) === "awaiting_soc_review" ? "Awaiting Review" : fullStatus;
  return badge(label, undefined, `title="${esc(fullStatus)}"`);
}

function iconButton(icon, label, action, attrs = "") {
  return `<button class="soc-btn ghost" data-action="${esc(action)}" ${attrs} title="${esc(label)}"><i class="ti ${icon}"></i><span>${esc(label)}</span></button>`;
}

function renderNav() {
  $("#nav").innerHTML = navGroups.map(group => {
    const itemsHtml = group.items.map(item => {
      const active = state.route === item.id;
      // Render nested children for My Tickets when a ticket is selected and user is in My Tickets
      if (item.id === "my-tickets") {
        const parentBtn = `<button class="nav-item ${active ? "active" : ""}" data-route="${esc(item.id)}" data-params='${esc(JSON.stringify(item.params || {}))}'>
          <i class="ti ${item.icon}"></i><span>${esc(item.text)}</span>
        </button>`;
        if (state.selectedTicket && state.route === "my-tickets") {
          const activeCaseId = state.selectedTicket.ticket_id || "Selected ticket";
          const children = [
            ["overview", "Selected Ticket"],
            ["agents", "Agent Workspace"],
            ["alerts", "Related Alerts"],
            ["timeline", "Timeline"],
            ["reports", "Reports"],
          ].map(([key, label]) => {
            const childActive = state.route === "my-tickets" && (state.subroute === key || (key === "overview" && !state.subroute));
            return `<button class="nav-item nav-child active-case-child ${childActive ? "active" : ""}" data-route="my-tickets/${key}"><i class="ti"></i><span>${esc(label)}</span></button>`;
          }).join("");
          return parentBtn + `<div class="nav-children"><div class="active-case-block"><div class="active-case-label">Active case</div><div class="active-case-id mono" title="${esc(activeCaseId)}">${esc(activeCaseId)}</div><div class="active-case-subroutes">${children}</div></div></div>`;
        }
        return parentBtn;
      }
      return `<button class="nav-item ${active ? "active" : ""}" data-route="${esc(item.id)}" data-params='${esc(JSON.stringify(item.params || {}))}'>
          <i class="ti ${item.icon}"></i><span>${esc(item.text)}</span>
        </button>`;
    }).join("");
    return `<div class="nav-section"><div class="nav-label">${esc(group.label)}</div>${itemsHtml}</div>`;
  }).join("");
}

function header() {
  if (isAgentWorkspaceRoute()) {
    $("#header-left").innerHTML = `<div class="page-kicker breadcrumb">My Tickets <i class="ti ti-chevron-right"></i> Agent Workspace</div><div class="page-heading">Agent Workspace</div>`;
  } else {
    $("#header-left").innerHTML = `<div class="page-kicker">Agentic SOC Assistant</div><div class="page-heading">${esc(routeTitle())}</div>`;
  }
  const profile = $(".profile-menu");
  if (profile) {
    profile.title = "Soong Yang - SOC Analyst";
    profile.setAttribute("aria-label", "Soong Yang, SOC Analyst profile menu");
  }
  const statusItems = $$(".status-strip span");
  const netwitness = statusItems[0];
  const lastSync = $("#last-sync");
  const sync = state.lastNetWitnessSync;
  if (netwitness) {
    const configured = state.integrations?.netwitness?.configured;
    let label = configured ? "NetWitness Configured" : "NetWitness Not Configured";
    let ok = configured;
    if (sync) {
      ok = !!sync.success;
      label = sync.success ? "NetWitness Connected" : "NetWitness Sync Failed";
    }
    netwitness.innerHTML = `<span class="dot ${ok ? "ok" : "bad"}"></span>${esc(label)}`;
    netwitness.title = sync?.status || sync?.error || sync?.response_preview || "";
  }
  if (lastSync) {
    lastSync.textContent = sync?.completed_at
      ? new Date(sync.completed_at).toLocaleTimeString()
      : "--";
  }
}

async function refresh() {
  try {
    const selected = state.selectedTicket?.ticket_id || "";
    const ticketRoute = isTicketRoute();
    const dashboardParams = new URLSearchParams({ analyst: state.currentUser });
    if (selected) dashboardParams.set("ticket_id", selected);
    const dash = await api(`/api/dashboard?${dashboardParams.toString()}`);
    if (dash.success) {
      setApiError("");
      state.summary = dash.summary || {};
      if (!ticketRoute) state.tickets = dash.tickets || [];
      state.selectedTicket = dash.selected_ticket || state.selectedTicket;
      state.runs = dash.runs || [];
      reconcileAgentRunGuards();
      state.integrations = dash.integrations || {};
      if (state.selectedTicket?.ticket_id) {
        const exp = await api(`/api/tickets/${encodeURIComponent(state.selectedTicket.ticket_id)}/exports/status`);
        state.exportStatus = exp.success ? (exp.exports || {}) : {};
      } else {
        state.exportStatus = {};
      }
    } else {
      setApiError(dashboardLoadError(dash));
    }
    if (ticketRoute) {
      const routeDefaults = navGroups.flatMap(g => g.items).find(i => i.id === state.route)?.params || {};
      state.params = { ...routeDefaults, ...state.params };
      const params = new URLSearchParams(state.params).toString();
      const res = await api(`/api/tickets${params ? `?${params}` : ""}`);
      if (res.success) {
        setApiError("");
        state.tickets = res.tickets || [];
      } else {
        setApiError(dashboardLoadError(res, "Unable to load tickets."));
      }
    }
    if (["netwitness-alerts", "search-alerts"].includes(state.route)) {
      const q = state.params.q ? `?q=${encodeURIComponent(state.params.q)}` : "";
      const res = await api(`/api/netwitness/alerts${q}`);
      if (res.success === false) setApiError(res.status || "Unable to load NetWitness alerts.");
      else state.alerts = res.items || [];
    }
    if (state.route === "alert-history") {
      await loadHistory(false);
    }
    render();
  } catch (err) {
    setApiError(`Refresh failed: ${err.message || err}`);
    render();
    toast(state.renderError, "red");
  }
}

function metricCard(key, label, value, trend, route, params, tone = "blue") {
  return `<button class="metric-card ${tone}" data-route="${route}" data-params='${esc(JSON.stringify(params || {}))}'>
    <div><span>${esc(label)}</span><strong>${esc(value ?? 0)}</strong><small>${esc(trend)}</small></div>
    <i class="ti ti-chart-line"></i>
  </button>`;
}

function workflowCard(label, key, count) {
  return `<div class="workflow-card">
    <i class="ti ti-progress-check"></i>
    <div><strong>${esc(label)}</strong><span>${esc(count || 0)}</span></div>
    <button class="soc-btn compact" data-route="all-tickets" data-params='${esc(JSON.stringify({ stage: key }))}'>Select</button>
  </div>`;
}

function operationalSummaryCards() {
  const summary = state.summary || {};
  const cards = [
    {
      label: "Critical cases",
      value: summary.critical_cases,
      detail: "Requires immediate attention",
      tone: "critical",
      route: "all-tickets",
      params: { severity: "Critical" },
    },
    {
      label: "Approval required",
      value: summary.pending_approval,
      detail: "Awaiting SOC analyst approval",
      tone: "approval",
      route: "pending-approval",
      params: { view: "pending_approval" },
    },
    {
      label: "Unassigned cases",
      value: summary.unassigned_cases,
      detail: "Waiting for an owner",
      tone: "unassigned",
      route: "all-tickets",
      params: { owner: "Unassigned" },
    },
  ];
  return `<section class="operational-summary" aria-label="Case attention summary">
    ${cards.map(card => `<button class="operational-summary-card ${card.tone}" data-route="${card.route}" data-params='${esc(JSON.stringify(card.params))}'>
      <span>${esc(card.label)}</span>
      <strong>${esc(card.value ?? 0)}</strong>
      <small>${esc(card.detail)}</small>
    </button>`).join("")}
  </section>`;
}

function ticketRows(tickets = state.tickets, emptyMessage = "No tickets match this view.") {
  if (!tickets.length) return `<tr><td colspan="8" class="empty-cell">${esc(emptyMessage)}</td></tr>`;
  return tickets.map(t => `
    <tr class="${state.selectedTicket?.ticket_id === t.ticket_id ? "selected" : ""}" data-ticket-id="${esc(t.ticket_id)}">
      <td class="mono ticket-id-cell">${esc(t.ticket_id)}</td>
      <td class="ticket-title-cell" title="${esc(t.title)}">${esc(t.title)}</td>
      <td class="severity-cell">${severityBadge(t.severity)}</td>
      <td class="alerts-cell">${esc(t.alert_count || 0)}</td>
      <td class="status-cell" title="${esc(t.status || "Unknown")}">${ticketStatusBadge(t.status)}</td>
      <td class="owner-cell" title="${esc(t.owner)}">${esc(t.owner)}</td>
      <td class="mono updated-cell">${esc(shortTime(t.updated_at))}</td>
      <td class="actions-cell">
        <div class="row-actions ticket-row-actions">
          ${iconButton("ti-eye", "View", "view-ticket", `data-ticket-id="${esc(t.ticket_id)}"`)}
          ${iconButton("ti-player-play", "Run Next", "run-next", `data-ticket-id="${esc(t.ticket_id)}"`)}
          ${iconButton("ti-user-plus", "Assign", "assign-ticket", `data-ticket-id="${esc(t.ticket_id)}"`)}
          ${iconButton("ti-cloud-download", "Pull Latest", "sync-netwitness", `data-ticket-id="${esc(t.ticket_id)}"`)}
        </div>
      </td>
    </tr>`).join("");
}

function ticketTable(title, tickets = state.tickets, emptyMessage = "No tickets match this view.") {
  return `<section class="panel table-panel">
    <div class="panel-head">
      <h2>${esc(title)}</h2>
      <div class="searchbar"><i class="ti ti-search"></i><input id="ticket-search" placeholder="Search tickets..." value="${esc(state.params.q || "")}"></div>
      <button class="soc-btn ghost" data-action="filter-search"><i class="ti ti-filter"></i> Filters</button>
    </div>
    <table class="soc-table compact-ticket-table">
      <thead><tr><th class="ticket-id-cell">Ticket ID</th><th class="ticket-title-cell">Title</th><th class="severity-cell">Severity</th><th class="alerts-cell">Alerts</th><th class="status-cell">Status</th><th class="owner-cell">Owner</th><th class="updated-cell">Last Updated</th><th class="actions-cell">Actions</th></tr></thead>
      <tbody>${ticketRows(tickets, emptyMessage)}</tbody>
    </table>
  </section>`;
}

function dashboard() {
  const s = state.summary || {};
  return `<div class="${dashboardGridClass()}">
    <section class="main-column">
      <div class="metrics-row">
        ${metricCard("new", "New Alerts", s.new_alerts, "from latest sync", "netwitness-alerts", {}, "red")}
        ${metricCard("open", "Open Tickets", s.open_tickets, "active cases", "all-tickets", {}, "blue")}
        ${metricCard("approval", "Pending Approval", s.pending_approval, "requires analyst", "pending-approval", { view: "pending_approval" }, "yellow")}
        ${metricCard("multi", "Cases with Multiple Alerts", s.multi_alert_cases, "correlated cases", "all-tickets", { multi: "1" }, "green")}
        ${metricCard("closed", "Closed Cases", s.closed_cases, "completed cases", "closed-cases", { view: "closed" }, "purple")}
      </div>
      ${socPipelineCycle(s)}
      <div class="workflow-row">
        ${workflowCard("To Parse", "parsing_normalisation", s.stage_counts?.parsing_normalisation)}
        ${workflowCard("To Triage", "triage", s.stage_counts?.triage)}
        ${workflowCard("Threat Intel", "threat_intelligence", s.stage_counts?.threat_intelligence)}
        ${workflowCard("Awaiting Approval", "triage_approval", (s.stage_counts?.triage_approval || 0) + (s.stage_counts?.investigation_approval || 0))}
        ${workflowCard("Ready for Report", "reporting", s.stage_counts?.reporting)}
        ${workflowCard("Closed", "case_closure", s.stage_counts?.case_closure)}
      </div>
      ${ticketTable("Open Tickets", state.tickets, "No tickets exist yet. Sync NetWitness alerts or run the Postgres seed script to create the demo ticket.")}
      ${relatedAlertsBlock()}
    </section>
    ${ticketPanel()}
  </div>`;
}

function ticketsPage() {
  const title = state.route === "pending-approval" ? "Pending Approval" :
    state.route === "closed-cases" ? "Closed Cases" :
    state.route === "my-tickets" ? "My Tickets" : "All Tickets";
  // Render content differently when in my-tickets subsections
  let subContent = "";
  if (state.route === "my-tickets") {
    const sub = state.subroute;
    if (!sub) {
      subContent = `${selectedTicketCompactSummary()}`;
    } else if (sub === "overview") {
      subContent = `${selectedTicketOverview()}`;
    } else if (sub === "agents") {
      subContent = renderAgentWorkspace(state.selectedTicket);
    } else if (sub === "alerts") {
      subContent = `${relatedAlertsSection(state.selectedTicket)}`;
    } else if (sub === "timeline") {
      subContent = `${timelineSection(state.selectedTicket)}`;
    } else if (sub === "reports") {
      subContent = `${reportsSection(state.selectedTicket)}`;
    } else {
      subContent = `${selectedTicketCompactSummary()}`;
    }
  } else if (state.route === "all-tickets" && state.selectedTicket) {
    subContent = `<section class="panel all-ticket-agent-workspace"><div class="panel-head"><h2><i class="ti ti-route"></i> Selected Ticket Agent Workflow</h2><span class="panel-sub">Available from All Tickets</span></div>${renderAgentWorkspace(state.selectedTicket)}</section>`;
  }
  return `<div class="${dashboardGridClass()}"><section class="main-column">${ticketTable(title)}${subContent}</section>${ticketPanel()}</div>`;
}

function workflowSteps(ticket) {
  const steps = ticket?.workflow_steps || [];
  return `<div class="workflow-list">${steps.map((s, i) => {
    const status = effectiveWorkflowStatus(s, ticket);
    return `<div class="workflow-step ${status}">
    <span>${i + 1}</span><div><strong>${esc(s.label)}</strong><small>${esc(workflowDisplayLabel(s, ticket))}</small></div>
  </div>`;
  }).join("")}</div>`;
}

function workflowStatus(step = {}) {
  const raw = step.status || step.state || "pending";
  const status = norm(raw);
  if (status === "requires_approval") return "awaiting_approval";
  if (status === "awaiting_review") return "awaiting_review";
  if (status === "running") return "in_progress";
  return status || "pending";
}

function workflowStatusLabel(step = {}) {
  return String(step.state || step.status || "Pending").replaceAll("_", " ");
}

function canonicalAgentKey(value = "") {
  const v = norm(value);
  if (!v) return "";
  if (v.includes("correlation") || v.includes("grouping")) return "correlation";
  if (v.includes("parsing") || v.includes("normalisation") || v.includes("normalization") || v.includes("parser")) return "parsing";
  if (v.includes("threat_intel") || v.includes("threat_intelligence") || v.includes("threat") || v.includes("enrichment")) return "threat_intel";
  if (v.includes("investigation_approval")) return "investigation_approval";
  if (v.includes("triage_approval") || v.includes("analyst_approval")) return "triage_approval";
  if (v.includes("soc_review") || v.includes("soc_analyst_review") || v.includes("final_review")) return "soc_review";
  if (v.includes("triage")) return "triage";
  if (v.includes("investigation")) return "investigation";
  if (v.includes("reporting") || v.includes("report")) return "reporting";
  if (v.includes("approval") || v.includes("analyst")) return "triage_approval";
  return v;
}


function workflowAgentKey(step = {}) {
  return canonicalAgentKey(step.agent || step.agent_key || step.key || step.label || "");
}

function runProgressValue(run = {}) {
  const raw = run.progress_percent ?? run.progress ?? run.percent_complete ?? run.completion_percent ?? run.percent;
  if (raw === null || raw === undefined || raw === "") return null;
  const value = Number(String(raw).replace("%", "").trim());
  return Number.isFinite(value) ? Math.max(0, Math.min(100, Math.round(value))) : null;
}

function runHasCompletionTimestamp(run = {}) {
  return Boolean(run.completed_at || run.finished_at || run.ended_at || run.end_time || run.completedAt || run.finishedAt);
}

function runIsActive(run) {
  if (!run || typeof run !== "object") return false;
  if (runIsFailed(run) || runIsCompleted(run)) return false;
  return ["running", "in_progress", "queued", "starting", "started"].includes(norm(run.status));
}

function runIsFailed(run) {
  if (!run || typeof run !== "object") return false;
  return ["failed", "error", "rejected", "execution_error", "timed_out", "timeout", "paused", "cancelled", "canceled"].includes(norm(run.status)) || run.success === false;
}

function runIsCompleted(run) {
  if (!run || typeof run !== "object") return false;
  const progress = runProgressValue(run);
  if (progress !== null && progress >= 100 && !runIsFailed(run)) return true;
  if (runHasCompletionTimestamp(run) && !runIsFailed(run)) return true;
  return ["completed", "complete", "success", "succeeded", "done", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps"].includes(norm(run.status));
}

function runIdentifier(run = {}) {
  return run.run_id || run.id || run.uuid || run.runId || run.execution_id || run.executionId || "";
}

function runTimeValue(run = {}) {
  const value = run.updated_at || run.completed_at || run.finished_at || run.ended_at || run.end_time || run.started_at || run.created_at || run.timestamp;
  const parsed = new Date(value || 0).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
}

function agentRunGuardKey(ticketId, agentKey) {
  return `${ticketId || state.selectedTicket?.ticket_id || "global"}::${canonicalAgentKey(agentKey || "")}`;
}

function agentRunGuard(ticketId, agentKey) {
  return state.agentRunGuards[agentRunGuardKey(ticketId, agentKey)] || null;
}

function latestActualRunForAgent(agentKey, ticketId = state.selectedTicket?.ticket_id) {
  const targetKey = canonicalAgentKey(agentKey || "");
  const runs = arrayOf(state.runs).filter(r => {
    const runAgent = canonicalAgentKey(r.agent || r.agent_key || r.agent_name || r.name || "");
    if (runAgent !== targetKey) return false;
    if (!ticketId) return true;
    return !r.ticket_id || r.ticket_id === ticketId;
  });
  return [...runs].sort((a, b) => runTimeValue(b) - runTimeValue(a))[0] || null;
}

function syntheticRunFromGuard(guard = {}) {
  const status = guard.status || "running";
  return {
    ...guard,
    run_id: guard.run_id || guard.client_token || "",
    agent: guard.agent,
    ticket_id: guard.ticket_id,
    status,
    running: ["starting", "running", "queued", "in_progress"].includes(norm(status)),
    progress_percent: guard.progress_percent ?? 3,
    current_step: guard.error_message || guard.current_step || "Agent is thinking...",
    started_at: guard.started_at,
    logs: arrayOf(guard.logs),
    local_guard: true,
  };
}

function guardedRunForAgent(agent = {}, ticket = state.selectedTicket) {
  const agentKey = canonicalAgentKey(agent.key || agent.label || "");
  const ticketId = ticket?.ticket_id || state.selectedTicket?.ticket_id || "";
  const guard = agentRunGuard(ticketId, agentKey);
  if (!guard) return null;
  const actual = latestActualRunForAgent(agentKey, ticketId);
  if (guard.run_id && actual && runIdentifier(actual) === guard.run_id) return { ...actual, client_token: guard.client_token };
  return syntheticRunFromGuard(guard);
}

function shouldMaskAgentOutput(ticket = state.selectedTicket, agentKey = state.selectedAgentKey) {
  const guard = agentRunGuard(ticket?.ticket_id, agentKey);
  return Boolean(guard && !["completed", "success", "succeeded", "done"].includes(norm(guard.status)));
}

function markAgentRunStarting(agentKey, ticketId, runType = "run") {
  const key = agentRunGuardKey(ticketId, agentKey);
  const clientToken = `${Date.now()}-${++state.agentRunGuardSequence}`;
  const label = agentLabel(agentKey);
  state.agentRunGuards[key] = {
    client_token: clientToken,
    run_id: "",
    agent: canonicalAgentKey(agentKey),
    ticket_id: ticketId || state.selectedTicket?.ticket_id || "",
    status: "starting",
    run_type: runType,
    started_at: new Date().toISOString(),
    progress_percent: 3,
    current_step: "Agent is thinking...",
    logs: [`[UI] ${runType === "rerun" ? "Re-run" : "Run"} requested for ${label}. Waiting for backend run id.`],
  };
  return state.agentRunGuards[key];
}

function updateAgentRunGuardFromResponse(agentKey, ticketId, clientToken, res = {}) {
  const key = agentRunGuardKey(ticketId, agentKey);
  const guard = state.agentRunGuards[key];
  if (!guard || guard.client_token !== clientToken) return null;
  const responseRunId = res.run_id || res.run?.run_id || res.latest_run?.run_id || "";
  const existingActiveRun = res.success === false && responseRunId && res.http_status === 409 && /already running/i.test(String(res.status || res.message || ""));
  const failedToStart = res.success === false && !existingActiveRun;
  state.agentRunGuards[key] = {
    ...guard,
    run_id: responseRunId || guard.run_id,
    started_at: res.started_at || res.run?.started_at || res.latest_run?.started_at || guard.started_at,
    status: failedToStart ? "failed" : norm(res.status) === "started" || existingActiveRun ? "running" : (res.status || "running"),
    current_step: failedToStart ? errorText(res, "Agent run failed to start.") : "Agent is thinking...",
    error_message: failedToStart ? errorText(res, "Agent run failed to start.") : "",
    progress_percent: failedToStart ? 100 : (res.progress_percent ?? res.run?.progress_percent ?? res.latest_run?.progress_percent ?? 3),
    logs: [...arrayOf(guard.logs), responseRunId ? `[UI] Tracking run ${responseRunId}.` : `[UI] Backend response received for ${agentLabel(agentKey)}.`],
  };
  return state.agentRunGuards[key];
}

function responseIsExistingActiveRun(res = {}) {
  return res.success === false && Boolean(res.run_id) && res.http_status === 409 && /already running/i.test(String(res.status || res.message || ""));
}

function markAgentRunGuardFailed(agentKey, ticketId, clientToken, message) {
  const key = agentRunGuardKey(ticketId, agentKey);
  const guard = state.agentRunGuards[key];
  if (!guard || guard.client_token !== clientToken) return null;
  state.agentRunGuards[key] = {
    ...guard,
    status: "failed",
    running: false,
    progress_percent: 100,
    current_step: message || "Agent run failed.",
    error_message: message || "Agent run failed.",
    logs: [...arrayOf(guard.logs), `[UI] ${message || "Agent run failed."}`],
  };
  return state.agentRunGuards[key];
}

function reconcileAgentRunGuards() {
  Object.entries({ ...state.agentRunGuards }).forEach(([key, guard]) => {
    const actual = latestActualRunForAgent(guard.agent, guard.ticket_id);
    if (!actual) return;
    const actualRunId = runIdentifier(actual);
    const guardRunId = guard.run_id || "";
    if (!guardRunId && runIsActive(actual)) {
      state.agentRunGuards[key] = { ...guard, run_id: actualRunId, status: "running", started_at: actual.started_at || guard.started_at };
      return;
    }
    if (guardRunId && actualRunId !== guardRunId) return;
    if (runIsActive(actual)) {
      state.agentRunGuards[key] = {
        ...guard,
        status: "running",
        progress_percent: runProgressValue(actual) ?? guard.progress_percent ?? 3,
        current_step: actual.current_step || guard.current_step || "Agent is thinking...",
      };
      return;
    }
    if (runIsFailed(actual)) {
      state.agentRunGuards[key] = {
        ...guard,
        status: "failed",
        progress_percent: runProgressValue(actual) ?? 100,
        current_step: actual.current_step || actual.error_message || "Agent run failed.",
        error_message: actual.error_message || actual.current_step || "Agent run failed.",
      };
      return;
    }
    if (runIsCompleted(actual)) delete state.agentRunGuards[key];
  });
}

function activeAgentForSelectedTicket() {
  const agents = arrayOf(state.selectedTicket?.agent_panel);
  return agents.find(agent => runIsActive(currentAgentRun(agent))) || null;
}

function effectiveWorkflowStatus(step = {}, ticket = state.selectedTicket) {
  const agentKey = workflowAgentKey(step);
  if (agentKey) {
    const agent = arrayOf(ticket?.agent_panel).find(a => canonicalAgentKey(a.key || a.label) === agentKey) || { key: agentKey, status: step.status || step.state };
    const run = currentAgentRun(agent);
    if (runIsActive(run)) return "in_progress";
    const persisted = norm(agent.workflow_status || step.status || agent.status);
    if (["ready", "running", "completed", "pending_approval", "approved", "locked", "failed", "rerun_required"].includes(persisted)) {
      return persisted === "running" ? "in_progress" : persisted;
    }
    if (runIsFailed(run)) return "failed";
    if (runIsCompleted(run)) return "completed";
  }
  return workflowStatus(step);
}

function workflowDisplayLabel(step = {}, ticket = state.selectedTicket) {
  const agentKey = workflowAgentKey(step);
  if (agentKey) {
    const agent = arrayOf(ticket?.agent_panel).find(a => canonicalAgentKey(a.key || a.label) === agentKey) || { key: agentKey, status: step.status || step.state };
    const run = currentAgentRun(agent);
    const progress = agentProgressPercent(agent, run);
    if (runIsActive(run)) return `In Progress ${progress}%`;
    const persisted = norm(agent.workflow_status || step.status || agent.status);
    if (["ready", "running", "completed", "pending_approval", "approved", "locked", "failed", "rerun_required"].includes(persisted)) {
      return {
        ready: "Ready",
        running: "Processing...",
        completed: "Completed",
        pending_approval: "Pending Approval",
        approved: "Approved",
        locked: "Locked",
        failed: "Failed",
        rerun_required: "Re-run Required",
      }[persisted];
    }
    if (runIsFailed(run)) return "Failed";
    if (runIsCompleted(run)) return "Completed";
  }
  const status = effectiveWorkflowStatus(step, ticket);
  return {
    completed: "Completed",
    in_progress: "In Progress",
    awaiting_approval: "Awaiting Approval",
    awaiting_review: "Awaiting Review",
    pending_approval: "Pending Approval",
    approved: "Approved",
    rerun_required: "Re-run Required",
    evidence_gap_decision: "Evidence Gap Decision",
    locked: "Locked",
    failed: "Failed",
    pending: "Pending",
    ready: "Ready",
  }[status] || workflowStatusLabel(step);
}

function workflowIcon(status) {
  return {
    completed: "ti-check",
    in_progress: "ti-player-play",
    awaiting_approval: "ti-hourglass",
    awaiting_review: "ti-clipboard-check",
    pending_approval: "ti-hourglass",
    approved: "ti-shield-check",
    rerun_required: "ti-refresh-alert",
    evidence_gap_decision: "ti-alert-triangle",
    locked: "ti-lock",
    failed: "ti-alert-triangle",
    pending: "ti-circle",
  }[status] || "ti-circle";
}

function connectorState(left, right) {
  if (left === "approved") left = "completed";
  if (right === "approved") right = "completed";
  if (left === "failed" || right === "failed") return "failed";
  if (left === "completed" && right === "completed") return "completed";
  if (right === "in_progress" || (left === "in_progress" && right !== "awaiting_approval")) return "current";
  if (["awaiting_approval", "awaiting_review"].includes(left) || ["awaiting_approval", "awaiting_review"].includes(right)) return "approval";
  return "pending";
}

function investigationWorkflow(ticket) {
  if (!ticket) {
    return `<section class="panel investigation-workflow"><div class="panel-head"><h2><i class="ti ti-git-branch"></i> SOC Case Workflow</h2></div><div class="empty-state">Select one of your assigned tickets to view workflow progress.</div></section>`;
  }
  const steps = arrayOf(ticket.workflow_steps);
  if (!steps.length) {
    return `<section class="panel investigation-workflow"><div class="panel-head"><h2><i class="ti ti-git-branch"></i> SOC Case Workflow</h2></div><div class="empty-state">Workflow state is not available for this ticket yet.</div></section>`;
  }
  return `<section class="panel investigation-workflow">
    <div class="panel-head"><h2><i class="ti ti-git-branch"></i> SOC Case Workflow</h2><span class="panel-sub">Ticket <strong class="mono">${esc(ticket.ticket_id)}</strong></span></div>
    <div class="workflow-timeline">
      ${steps.map((step, index) => {
        const status = effectiveWorkflowStatus(step, ticket);
        const next = steps[index + 1] ? effectiveWorkflowStatus(steps[index + 1], ticket) : "";
        const connector = index < steps.length - 1 ? connectorState(status, next) : "none";
        const isLast = index === steps.length - 1 ? "is-last" : "";
        return `<div class="workflow-node ${status} connector-${connector} ${isLast}" title="${esc(step.description || workflowDisplayLabel(step, ticket))}">
          <div class="workflow-circle"><i class="ti ${workflowIcon(status)}"></i></div>
          <strong>${esc(step.label)}</strong>
          <small>${esc(workflowDisplayLabel(step, ticket))}</small>
          ${step.message ? `<span class="workflow-stage-message">${esc(step.message)}</span>` : ""}
        </div>`;
      }).join("")}
    </div>
  </section>`;
}

function orchestrationDecisionPanel(ticket = state.selectedTicket, compact = false) {
  if (!ticket) return "";
  const saved = ticket.orchestration_decision_result || {};
  const next = ticket.next_step || {};
  const decision = Object.keys(saved || {}).length ? saved : (next.orchestration_decision || next);
  const workflowDecision = decision.workflow_decision || "not_evaluated";
  const label = decision.next_label || decision.label || next.label || "Not evaluated yet";
  const nextAgent = decision.orchestrated_next_agent || decision.next_agent || next.agent || "None";
  const reason = decision.reason || next.reason || "Run Next Step to generate an orchestration decision.";
  const blocked = decision.allowed === false || next.allowed === false;
  const badgeType = blocked ? "yellow" : "green";
  const missing = arrayOf(decision.missing_inputs);
  const required = arrayOf(decision.required_inputs);
  const riskNotes = arrayOf(decision.risk_notes);
  return `<section class="panel orchestration-decision-panel ${compact ? "compact" : ""}">
    <div class="panel-head">
      <h2><i class="ti ti-route-square"></i> Orchestration Decision</h2>
      <span class="panel-sub">${badge(blocked ? "Gate Active" : "Ready", badgeType)}</span>
    </div>
    <div class="orchestration-grid">
      ${field("Decision", String(workflowDecision).replaceAll("_", " "))}
      ${field("Next Step", label)}
      ${field("Next Agent", String(nextAgent).replaceAll("_", " "))}
      ${field("Approval Gate", decision.approval_gate || (decision.requires_human_approval ? "Required" : "None"))}
    </div>
    <div class="field orchestration-reason"><span>Reason</span><strong>${esc(reason)}</strong></div>
    ${missing.length ? `<div class="orchestration-list missing"><span>Missing Inputs</span><ul>${missing.map(item => `<li>${esc(item)}</li>`).join("")}</ul></div>` : ""}
    ${!compact && required.length ? `<div class="orchestration-list"><span>Required Inputs</span><ul>${required.map(item => `<li>${esc(item)}</li>`).join("")}</ul></div>` : ""}
    ${!compact && riskNotes.length ? `<div class="orchestration-list"><span>Risk Notes</span><ul>${riskNotes.map(item => `<li>${esc(item)}</li>`).join("")}</ul></div>` : ""}
  </section>`;
}

function hasInvestigationEvidenceGapDecision(ticket = state.selectedTicket) {
  const inv = ticket?.investigation_result || {};
  const invApproval = ticket?.investigation_approval_result || {};
  const status = norm(inv.status || inv.report_status || inv.workflow_decision || "");
  const stage = norm(ticket?.current_stage || "");
  const decision = norm(invApproval.evidence_gap_decision || invApproval.decision || "");
  const hasGaps = ["completed_with_evidence_gaps", "completed_limited", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "partial_success"].includes(status) || arrayOf(inv.missing_evidence || inv.missing_fields).length > 0 || !!inv.triage_requery_request;
  const decisionPending = !["continue_to_reporting", "approved", "approve", "completed", "return_to_triage"].includes(decision);
  return hasGaps && decisionPending && ["investigation_evidence_decision", "investigation_approval"].includes(stage);
}

function evidenceGapDecisionButtons(ticket = state.selectedTicket, compact = false) {
  if (!ticket) return "";
  const cls = compact ? "compact" : "";
  return `<button class="soc-btn primary ${cls}" data-action="continue-to-reporting" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-arrow-forward-up"></i> Continue to Reporting Agent</button>
    <button class="soc-btn warning ${cls}" data-action="return-to-triage" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-arrow-back-up"></i> Go back to Triage</button>`;
}

function evidenceGapDecisionCard(ticket = state.selectedTicket) {
  if (!hasInvestigationEvidenceGapDecision(ticket)) return "";
  const inv = ticket?.investigation_result || {};
  const gaps = arrayOf(inv.missing_evidence || inv.missing_fields).slice(0, 6);
  const gapText = gaps.length ? `<ul class="evidence-gap-list">${gaps.map(g => `<li>${esc(typeof g === "string" ? g : (g.gap || g.reason || JSON.stringify(g)))}</li>`).join("")}</ul>` : `<p>No structured missing evidence list was provided, but the Investigation Agent marked the result as limited.</p>`;
  return `<div class="evidence-gap-decision-card">
    <div class="evidence-gap-title"><i class="ti ti-alert-triangle"></i><strong>Investigation completed with evidence gaps</strong></div>
    <p>The analyst must choose the next workflow path. Continue with limitations, or send the case back to Triage Agent for more NetWitness evidence.</p>
    ${gapText}
    <div class="panel-actions evidence-gap-actions">${evidenceGapDecisionButtons(ticket)}</div>
  </div>`;
}

function ticketPanel() {
  const t = state.selectedTicket;
  if (isTicketPreviewCollapsed()) {
    return `<aside class="side-panel side-panel-collapsed" aria-label="Collapsed ticket preview">
      <button class="side-panel-reopen" data-action="toggle-ticket-preview" title="Expand ticket preview">
        <i class="ti ti-layout-sidebar-right-expand"></i>
        <span class="vertical-ticket-label">${esc(t?.ticket_id || "Ticket")}</span>
      </button>
    </aside>`;
  }
  if (!t) return `<aside class="side-panel"><button class="ticket-panel-collapse" data-action="toggle-ticket-preview" title="Collapse ticket preview"><i class="ti ti-layout-sidebar-right-collapse"></i></button><div class="empty-state">Select a ticket to inspect workflow, alerts, approvals, and reports.</div></aside>`;
  const next = t.next_step || {};
  return `<aside class="side-panel">
    <button class="ticket-panel-collapse" data-action="toggle-ticket-preview" title="Collapse ticket preview"><i class="ti ti-layout-sidebar-right-collapse"></i></button>
    <div class="ticket-head">
      <div><small>Ticket ${esc(t.ticket_id)}</small><h2>${esc(t.title)}</h2></div>
      ${severityBadge(t.severity)}
    </div>
    <div class="kv"><span>Status</span>${badge(t.status)}</div>
    <div class="kv"><span>Owner</span><strong>${esc(t.owner)}</strong></div>
    <div class="kv"><span>Created</span><strong>${esc(shortDate(t.created_at))}</strong></div>
    <div class="kv"><span>Updated</span><strong>${esc(shortDate(t.updated_at))}</strong></div>
    ${orchestrationDecisionPanel(t, true)}
    ${evidenceGapDecisionCard(t)}
    <div class="panel-actions">
      ${hasInvestigationEvidenceGapDecision(t) ? "" : (isReadyForClosure(next, t) && shouldUseMainClosureActions() ? "" : nextStepAction(t, next))}
      ${hasInvestigationEvidenceGapDecision(t) ? "" : `<button class="soc-btn green" data-action="approve-ticket" data-ticket-id="${esc(t.ticket_id)}"><i class="ti ti-shield-check"></i> Approve</button>`}
      ${hasInvestigationEvidenceGapDecision(t) ? "" : `<button class="soc-btn danger" data-action="reject-ticket" data-ticket-id="${esc(t.ticket_id)}"><i class="ti ti-x"></i> Reject</button>`}
      ${hasInvestigationEvidenceGapDecision(t) ? "" : `<button class="soc-btn ghost" data-action="more-evidence" data-ticket-id="${esc(t.ticket_id)}"><i class="ti ti-search"></i> More Evidence</button>`}
    </div>
    <h3>Ticket Workflow</h3>
    ${workflowSteps(t)}
  </aside>`;
}

function isReadyForClosure(next = {}, ticket = state.selectedTicket) {
  const label = norm(next?.label || ticket?.next_step?.label || "");
  const agent = canonicalAgentKey(next?.agent || next?.agent_key || ticket?.next_step?.agent || ticket?.next_step?.agent_key || "");
  const stage = norm(ticket?.current_stage || ticket?.stage || ticket?.status || "");
  return !agent && (label.includes("ready_for_closure") || label.includes("case_closure") || stage.includes("case_closure") || stage.includes("ready_for_closure"));
}

function isReadyForClosureResponse(res = {}) {
  return isReadyForClosure(res.next_step || res.ticket?.next_step || {}, res.ticket || state.selectedTicket);
}

function shouldUseMainClosureActions() {
  return state.route === "my-tickets" && (!state.subroute || state.subroute === "overview");
}

function closureRetryButtons(ticket = state.selectedTicket) {
  const retryableKeys = ["parsing", "triage", "threat_intel", "investigation", "reporting"];
  const agents = arrayOf(ticket?.agent_panel);
  const labels = { parsing: "Parsing", triage: "Triage", threat_intel: "Threat Intel", investigation: "Investigation", reporting: "Reporting" };
  const buttons = retryableKeys.map(key => {
    const agent = agents.find(a => canonicalAgentKey(a.key || a.label) === key) || { key, label: agentLabel(key), status: "Completed" };
    const run = currentAgentRun(agent);
    const status = effectiveAgentStatus(agent, run);
    const disabled = ["running", "in_progress", "locked"].includes(status);
    const reason = status === "locked" ? (agent.lock_reason || "This agent is locked by the workflow gate.") : "This agent is already running.";
    return `<button class="soc-btn warning compact" data-action="retry-agent" data-agent="${esc(key)}" data-ticket-id="${esc(ticket?.ticket_id || "")}" ${disabled ? `disabled title="${esc(reason)}"` : ""}><i class="ti ti-refresh"></i> Retry ${esc(labels[key])}</button>`;
  }).join("");
  return `<div class="closure-retry-actions"><span>Rerun before closure</span><div>${buttons}</div></div>`;
}

function closureReadyActions(ticket = state.selectedTicket, compact = false) {
  const next = ticket?.next_step || {};
  const reason = next.reason || "All agent stages have produced ticket context.";
  return `<div class="closure-ready-box ${compact ? "compact" : ""}">
    <div class="closure-ready-head">
      ${badge("Ready for Closure", "green")}
      <small>${esc(reason)}</small>
    </div>
    <div class="closure-primary-actions">
      <button class="soc-btn ghost compact" data-route="my-tickets/reports"><i class="ti ti-file-description"></i> View Reports</button>
      <button class="soc-btn ghost compact" data-route="my-tickets/timeline"><i class="ti ti-history"></i> View Timeline</button>
      <button class="soc-btn green compact" disabled title="Closure route not implemented yet"><i class="ti ti-circle-check"></i> Close Case</button>
    </div>
    ${closureRetryButtons(ticket)}
  </div>`;
}

function ticketPrimaryActions(ticket = state.selectedTicket) {
  if (isReadyForClosure(ticket?.next_step || {}, ticket)) {
    return closureReadyActions(ticket);
  }
  return `<button class="soc-btn primary" data-action="run-next" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-player-play"></i> Run Next Step</button>
      <button class="soc-btn ghost" data-action="assign-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-user-plus"></i> Assign</button>
      <button class="soc-btn ghost" data-action="sync-netwitness" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-cloud-download"></i> Pull Latest</button>`;
}

function nextStepAction(ticket, next = {}) {
  const label = next.label || "Run Next Step";
  const reason = next.reason || "Workflow gate is not ready.";
  if (isReadyForClosure(next, ticket)) {
    return closureReadyActions(ticket, true);
  }
  if (next.allowed === false && norm(label) === "awaiting_approval") {
    return `<div class="next-step-status" title="${esc(reason)}">${badge(label, "yellow")}<small>${esc(reason)}</small></div>`;
  }
  return `<button class="soc-btn primary" data-action="run-next" data-ticket-id="${esc(ticket.ticket_id)}" ${next.allowed === false ? `disabled title="${esc(reason)}"` : ""}><i class="ti ti-player-play"></i> ${esc(label)}</button>`;
}

function nextRequiredActionBanner(ticket = state.selectedTicket) {
  if (!ticket) return "";
  const next = ticket.next_step || {};
  const pending = Number(ticket.pending_correlation_count || 0);
  const decision = ticket.orchestration_decision_result || {};
  const blocked = next.allowed === false || pending > 0 || norm(decision.workflow_decision || "").includes("block");
  const label = pending > 0 ? "Review Incident Grouping / Archive Recommendation" : (next.label || decision.next_label || "Review Workflow State");
  const reason = pending > 0
    ? `${pending} pending alert grouping or archive recommendation requires analyst review before the workflow continues.`
    : (next.reason || decision.reason || "Review agent output and continue the permitted workflow action.");
  const actions = pending > 0
    ? `<button class="soc-btn warning compact" data-route="my-tickets/alerts"><i class="ti ti-git-merge"></i> Go to Recommendations</button>`
    : (blocked ? `<button class="soc-btn ghost compact" data-route="my-tickets/timeline"><i class="ti ti-history"></i> View Timeline</button>` : `<button class="soc-btn primary compact" data-action="run-next" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-player-play"></i> ${esc(label)}</button>`);
  return `<section class="next-required-banner ${blocked ? "blocked" : "ready"}">
    <div><strong>Next Required Action: ${esc(label)}</strong><p>${esc(reason)}</p></div>
    <div class="panel-actions">${actions}</div>
  </section>`;
}

function selectedTicketCompactSummary() {
  const t = state.selectedTicket;
  if (!t) return `<section class="panel"><div class="empty-state">Select one of your assigned tickets to open its summary and Agent Panel.</div></section>`;
  const alertCount = Number(t.alert_count || arrayOf(t.related_alerts).length || 0);
  const assetCount = arrayOf(t.affected_assets).length;
  const iocCount = arrayOf(t.iocs).length;
  return `${nextRequiredActionBanner(t)}<section class="panel selected-ticket-summary">
    <div class="panel-head"><h2>Selected Ticket Summary</h2><span class="panel-sub">Current work cue</span></div>
    <div class="summary-strip">
      ${field("Workflow Stage", String(t.current_stage || "Unknown").replaceAll("_", " "))}
      ${field("Next Step", t.next_step?.label || "Review")}
      ${field("Evidence", `${alertCount} alerts, ${assetCount} assets, ${iocCount} IOCs`)}
      ${field("Decision Gate", t.next_step?.allowed === false ? "Blocked" : "Ready")}
    </div>
    <div class="field"><span>Recommendation</span><strong>${esc(t.next_step?.reason || "Review workflow state and agent outputs.")}</strong></div>
    <div class="panel-actions selected-ticket-primary-actions" style="margin-top:10px">
      ${ticketPrimaryActions(t)}
    </div>
  </section>`;
}

function selectedTicketOverview() {
  const t = state.selectedTicket;
  if (!t) return `<section class="panel"><div class="empty-state">Select a ticket to view the full selected ticket summary.</div></section>`;
  const alertCount = Number(t.alert_count || arrayOf(t.related_alerts).length || 0);
  return `${nextRequiredActionBanner(t)}<section class="panel selected-ticket-overview">
    <div class="panel-head"><h2>Selected Ticket</h2><span class="panel-sub">Full ticket details</span></div>
    <div class="overview-grid">
      ${field("Ticket ID", t.ticket_id)}
      ${field("Title", t.title)}
      ${field("Severity", t.severity)}
      ${field("Confidence", t.confidence || "Unknown")}
      ${field("Status", t.status)}
      ${field("Owner", t.owner || "Unassigned")}
      ${field("Workflow Stage", String(t.current_stage || "Unknown").replaceAll("_", " "))}
      ${field("Recommendation", t.next_step?.reason || "Review workflow state and agent outputs.")}
      ${field("Affected Assets", arrayOf(t.affected_assets).join(", ") || "None recorded")}
      ${field("Affected Users", arrayOf(t.affected_users).join(", ") || "None recorded")}
      ${field("IOCs", compactIocs(t.iocs))}
      ${field("Current Decision Gate", t.next_step?.allowed === false ? "Blocked" : "Ready")}
    </div>
    <div class="panel-actions selected-ticket-primary-actions" style="margin-top:10px">
      ${ticketPrimaryActions(t)}
    </div>
  </section>
  ${orchestrationDecisionPanel(t)}`;
}

function agentPanel(ticket, mode = "wide") {
  if (!ticket) {
    return `<section class="panel agent-panel ${mode}"><div class="panel-head"><h2>Agent Panel</h2></div><div class="empty-state">Select a ticket to work with ticket-scoped agents.</div></section>`;
  }
  const agents = arrayOf(ticket.agent_panel);
  const activeKey = expandedAgentKey(ticket);
  return `<section class="panel agent-panel ${mode}">
    <div class="panel-head"><h2>Agent Panel</h2><span class="panel-sub">Selected ticket context: <strong class="mono">${esc(ticket.ticket_id)}</strong></span></div>
    ${agents.length ? `<div class="agent-accordion">${agents.map(agent => agentAccordionCard(agent, activeKey === agent.key)).join("")}</div>` : `<div class="empty-state">Agent Panel data is missing for this ticket. Refresh or rerun the ticket workflow to rebuild agent context.</div>`}
  </section>`;
}

function agentAccordionCard(agent = {}, expanded = false) {
  const statusType = agent.status === "Locked" ? "yellow" : agent.status === "Failed" ? "red" : agent.status === "Completed" ? "green" : agent.status === "Running" ? "blue" : "blue";
  const actions = prioritisedAgentActions(agent);
  const summary = agent.lock_reason ? `Locked: ${agent.lock_reason}` : (agent.last_output_summary || agent.required_input_status || "No summary available.");
  return `<article class="agent-accordion-card ${norm(agent.status)} ${expanded ? "is-expanded" : "is-collapsed"}">
    <div class="agent-accordion-header" data-action="toggle-agent-card" data-agent="${esc(agent.key)}">
      <div class="agent-accordion-title">
        <strong>${esc(agent.label)}</strong>
        ${badge(agent.status, statusType)}
      </div>
      <div class="agent-accordion-meta-row">
        <span class="agent-accordion-summary">${esc(summary)}</span>
        <span class="agent-accordion-run-time">${esc(agent.last_run_time ? `Last run ${shortDate(agent.last_run_time)}` : "Never run")}</span>
      </div>
      <button class="agent-toggle-button" type="button" aria-expanded="${expanded}" data-action="toggle-agent-card" data-agent="${esc(agent.key)}">
        <i class="ti ${expanded ? "ti-chevron-down" : "ti-chevron-right"}"></i>
      </button>
    </div>
    ${expanded ? `<div class="agent-accordion-body">
      <div class="agent-card-meta">
        <div><span>Status</span><strong>${esc(agent.status)}</strong></div>
        <div><span>Last run</span><strong>${esc(agent.last_run_time ? shortDate(agent.last_run_time) : "Never")}</strong></div>
        <div><span>Required input</span><strong>${esc(agent.required_input_status || "Unknown")}</strong></div>
      </div>
      ${agent.lock_reason ? `<div class="lock-note prominent"><i class="ti ti-lock"></i>${esc(agent.lock_reason)}</div>` : ""}
      <p class="agent-card-detail">${esc(agent.last_output_summary || "No output has been written to this ticket yet.")}</p>
      ${agentRunHistoryMini(agent.key)}
      <div class="agent-card-actions">${actions.map(action => actionButtonForAgent(action, agent)).join("")}</div>
    </div>` : ""}
  </article>`;
}

function prioritisedAgentActions(agent) {
  const actions = arrayOf(agent.actions).map(action => ({ ...action, disabled_reason: action.disabled_reason || agent.lock_reason || "Required ticket context is not ready." }));
  const status = norm(agent.status);
  const isCompleted = status === "completed";
  const isLocked = status === "locked";
  if (["awaiting_approval", "awaiting_review"].includes(status)) {
    const gate = actions.filter(action => ["approve-ticket", "reject-ticket", "more-evidence", "continue-to-reporting", "return-to-triage", "confirm-soc-review"].includes(action.id));
    const view = actions.filter(action => action.id === "view-agent-output");
    const retry = actions.filter(action => (["Retry", "Re-run"].includes(action.label)));
    return [...gate, ...view, ...retry];
  }
  if (isCompleted) {
    const view = actions.filter(action => action.id === "view-agent-output");
    const retry = actions.filter(action => (["Retry", "Re-run"].includes(action.label)));
    const rest = actions.filter(action => action.id !== "view-agent-output" && (!["Retry", "Re-run"].includes(action.label)) && action.enabled);
    return [...view, ...retry, ...rest];
  }
  if (isLocked) {
    const view = actions.filter(action => action.id === "view-agent-output" && action.enabled);
    const blocked = actions.filter(action => action.id !== "view-agent-output").map(action => ({ ...action, enabled: false }));
    return [...view, ...blocked];
  }
  return actions;
}

function actionButtonForAgent(action, agent = {}) {
  const reason = action.disabled_reason || agent.lock_reason || "Required ticket context is not ready.";
  const executionPending = ["run-agent", "rerun-agent"].includes(action.id) && runIsActive(currentAgentRun(agent));
  const approvalPending = action.id === "approve-ticket"
    && Boolean(state.approvalRequests[`${state.selectedTicket?.ticket_id || ""}:${action.gate || "approve"}`]);
  const disabled = action.enabled && !approvalPending && !executionPending ? "" : `disabled title="${esc(approvalPending ? "Approval is being recorded." : executionPending ? "Stage is processing." : reason)}"`;
  const status = norm(agent.status);
  const cls = action.id === "approve-ticket" || action.id === "confirm-soc-review" ? "green" : action.id === "continue-to-reporting" ? "primary" : action.id === "return-to-triage" ? "warning" : action.id === "reject-ticket" ? "danger" : action.id === "view-agent-output" && status === "completed" ? "primary" : (["Retry", "Re-run"].includes(action.label)) && status === "failed" ? "primary" : (["Retry", "Re-run"].includes(action.label)) ? "ghost" : action.enabled ? "primary" : "ghost";
  const icon = action.id === "view-agent-output" ? "ti-eye" : action.id === "approve-ticket" ? "ti-shield-check" : action.id === "continue-to-reporting" ? "ti-arrow-forward-up" : action.id === "return-to-triage" ? "ti-arrow-back-up" : action.id === "confirm-soc-review" ? "ti-clipboard-check" : action.id === "reject-ticket" ? "ti-x" : action.id === "more-evidence" ? "ti-search" : (["Retry", "Re-run"].includes(action.label)) ? "ti-refresh" : "ti-player-play";
  const agentAttr = action.agent ? `data-agent="${esc(action.agent)}"` : "";
  const gateAttr = action.gate ? `data-gate="${esc(action.gate)}"` : "";
  return `<button class="soc-btn ${cls} compact" data-action="${esc(action.id)}" ${agentAttr} ${gateAttr} data-ticket-id="${esc(state.selectedTicket?.ticket_id || "")}" ${disabled}><i class="ti ${executionPending ? "ti-loader-2" : icon}"></i><span>${esc(executionPending ? "Processing..." : action.label)}</span></button>`;
}

// ==================== AGENT WORKSPACE REDESIGN ====================

function renderAgentWorkspace(ticket) {
  if (!ticket) {
    return `<section class="panel agent-workspace"><div class="empty-state">Select a ticket to access the Agent Workspace.</div></section>`;
  }
  const agents = arrayOf(ticket.agent_panel);
  if (!agents.length) {
    return `<section class="panel agent-workspace"><div class="empty-state">Agent Panel data is missing for this ticket. Refresh or rerun the ticket workflow.</div></section>`;
  }

  ensureSelectedAgentKey(ticket);
  const selectedAgent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!selectedAgent && agents.length > 0) state.selectedAgentKey = agents[0].key;
  const selectedAgentKey = canonicalAgentKey((selectedAgent || {}).key || state.selectedAgentKey);
  const isReporting = selectedAgentKey === "reporting";

  if (isReporting) {
    return `<div class="agent-workspace-container reporting-agent-workspace-mode">
      <div class="incident-workspace-layout reporting-selected-grid">
        <main class="incident-workspace-main">
          ${renderAgentWorkspaceHeader(ticket)}
          ${operationalSummaryCards()}
          ${investigationWorkflow(ticket)}
          ${orchestrationDecisionPanel(ticket)}
          ${renderAgentStatusCards(ticket)}
          ${renderSelectedAgentExecutionPanel(ticket)}
          ${renderSelectedAgentOutputPanel(ticket)}
          ${renderSocReportReviewWorkspace(ticket, { fullWidth: true })}
          ${renderAgentLiveActivityLog(ticket)}
        </main>
        <aside class="incident-aegis-rail">
          ${renderAskAgentPanel(ticket)}
        </aside>
      </div>
    </div>`;
  }

  return `<div class="agent-workspace-container">
    <div class="incident-workspace-layout">
      <main class="incident-workspace-main">
        ${renderAgentWorkspaceHeader(ticket)}
        ${operationalSummaryCards()}
        ${investigationWorkflow(ticket)}
        ${orchestrationDecisionPanel(ticket)}
        ${renderAgentStatusCards(ticket)}
        ${renderSelectedAgentExecutionPanel(ticket)}
        ${renderSelectedAgentOutputPanel(ticket)}
        ${renderAgentLiveActivityLog(ticket)}
      </main>
      <aside class="incident-aegis-rail">
        ${renderAskAgentPanel(ticket)}
      </aside>
    </div>
  </div>`;
}

function socPipelineCycle(summary = {}) {
  const counts = summary.stage_counts || {};
  const stages = [
    { label: "Triage", value: (counts.parsing_normalisation || 0) + (counts.triage || 0) + (counts.incident_grouping_review || 0), color: "#3d7184" },
    { label: "Investigation", value: (counts.threat_intelligence || 0) + (counts.triage_approval || 0) + (counts.investigation || 0), color: "#66549b" },
    { label: "Findings", value: counts.investigation_approval || 0, color: "#9a7a3f" },
    { label: "Ticketing", value: counts.soc_analyst_review || 0, color: "#4d56a5" },
    { label: "Reporting", value: counts.reporting || 0, color: "#9a5124" },
    { label: "Finalized", value: counts.case_closure || 0, color: "#47765c", complete: true },
  ];
  const total = stages.reduce((sum, stage) => sum + Number(stage.value || 0), 0);
  const positions = [[50, 8], [86, 29], [86, 71], [50, 92], [14, 71], [14, 29]];
  const nodes = stages.map((stage, index) => {
    const [x, y] = positions[index];
    return `<div class="pipeline-cycle-node" style="--x:${x}%;--y:${y}%;--stage-color:${stage.color}">
      <strong>${esc(stage.complete ? `✓ ${stage.value}` : stage.value)}</strong>
      <span>${esc(stage.label)}</span>
      <small>${esc(stage.complete ? `${stage.value} completed` : `${stage.value} in stage`)}</small>
    </div>`;
  }).join("");
  return `<section class="panel pipeline-cycle-panel" aria-label="${esc(state.currentUser)} SOC pipeline">
    <div class="panel-head">
      <div><h2>SOC Pipeline</h2><span class="panel-sub">${esc(state.currentUser)} · account-specific workload</span></div>
    </div>
    <div class="pipeline-cycle">
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <defs><marker id="cycle-arrow" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto"><path d="M0,0 L5,2.5 L0,5 Z" fill="context-stroke"/></marker></defs>
        <path d="M50 14 C72 14 86 29 86 50" stroke="#3d7184"/>
        <path d="M86 50 C86 72 72 86 50 86" stroke="#66549b"/>
        <path d="M50 86 C28 86 14 72 14 50" stroke="#4d56a5"/>
        <path d="M14 50 C14 28 28 14 50 14" stroke="#47765c"/>
      </svg>
      <div class="pipeline-cycle-center"><span>SOC PIPELINE</span><strong>${esc(total)} Total</strong><small>${esc(stages.filter(stage => stage.value > 0).length)} Stages Active</small></div>
      ${nodes}
    </div>
  </section>`;
}

function ensureSelectedAgentKey(ticket) {
  const agents = arrayOf(ticket.agent_panel);
  if (!agents.find(a => a.key === state.selectedAgentKey)) {
    state.selectedAgentKey = agents[0]?.key || "triage";
  }
}

function renderAgentWorkspaceHeader(ticket) {
  const workflowSteps = arrayOf(ticket.workflow_steps);
  const currentStep = workflowSteps.find(s => !["completed", "approved"].includes(workflowStatus(s)));
  const nextStep = ticket.next_step || {};
  const currentStage = currentStep ? currentStep.label : "Ready";
  const nextStageText = nextStep.label || "Pending";
  const ticketTitle = ticket.title || ticket.ticket_title || "Untitled Ticket";
  
  return `<div class="agent-workspace-header">
    <div class="header-top">
      <div>
        <h2>Agent Workspace</h2>
        <p>Monitor live agent activity, handoffs, outputs, and analyst decisions.</p>
      </div>
    </div>
    <div class="header-context">
      <div class="context-item">
        <span class="label">Selected Ticket</span>
        <div class="context-value">
          <span class="mono ticket-id">${esc(ticket.ticket_id)}</span>
          <span class="separator">|</span>
          <span class="ticket-title">${esc(ticketTitle)}</span>
        </div>
      </div>
      <div class="context-item">
        <span class="label">Severity</span>
        <div class="context-value">${severityBadge(ticket.severity)}</div>
      </div>
      <div class="context-item">
        <span class="label">Workflow Stage</span>
        <div class="context-value"><strong>${esc(currentStage)}</strong></div>
      </div>
      <div class="context-item">
        <span class="label">Next Step</span>
        <div class="context-value"><strong>${esc(nextStageText)}</strong></div>
      </div>
    </div>
  </div>`;
}

function renderAgentStatusCards(ticket) {
  const agents = arrayOf(ticket.agent_panel);
  return `<div class="agent-status-cards-row">
    ${agents.map(agent => renderAgentStatusCard(agent)).join("")}
  </div>`;
}

function renderAgentStatusCard(agent = {}) {
  const isSelected = state.selectedAgentKey === agent.key;
  const run = currentAgentRun(agent);
  const status = effectiveAgentStatus(agent, run);
  const statusLabel = displayAgentStatus(agent, run);
  const statusBadgeType = agentStatusTone(status);
  const counts = getAgentCounts(agent);
  const stateLine = agentCardStateLine(agent, run);
  
  return `<div class="agent-status-card ${esc(status)} ${isSelected ? "active" : ""}" data-action="select-agent" data-agent-key="${esc(agent.key)}">
    <div class="card-header">
      <strong title="${esc(agent.label)}">${esc(agent.label)}</strong>
      ${badge(statusLabel, statusBadgeType, `title="${esc(statusLabel)}"`)}
    </div>
    <div class="card-body">
      <p class="card-description">${esc(stateLine)}</p>
      <div class="card-stats">
        ${counts.map(c => `<span class="stat"><strong>${c.value}</strong> ${c.label}</span>`).join("")}
      </div>
    </div>
    <div class="card-footer">
      <small>${esc(agent.last_run_time ? `Updated ${shortDate(agent.last_run_time)}` : "Never run")}</small>
      ${isSelected ? `<span class="selected-label">Selected</span>` : ""}
    </div>
  </div>`;
}

function agentCardStateLine(agent = {}, run = null) {
  const status = effectiveAgentStatus(agent, run);
  if (agent.status_message) return agent.status_message;
  if (status === "completed") return "Output written to ticket";
  if (status === "approved") return "Latest valid output approved";
  if (status === "running" || status === "in_progress") return "Running with ticket context";
  if (status === "failed") return "Needs retry or review";
  if (status === "pending_approval") return "Waiting for SOC analyst approval";
  if (status === "rerun_required") return "Previous output is outdated";
  if (status === "awaiting_approval") return "Waiting for SOC analyst approval";
  if (status === "awaiting_review") return "Waiting for SOC analyst review";
  if (status === "locked") return "Waiting for workflow gate";
  if (status === "ready") return "Ready to run";
  return agent.status || "Pending";
}

function getAgentCounts(agent = {}) {
  if (agent.key === "parsing") {
    return [{ label: "fields", value: agent.fields_extracted || 0 }];
  }
  if (agent.key === "triage") {
    return [{ label: "alerts", value: agent.alerts_reviewed || 0 }];
  }
  if (agent.key === "threat_intel") {
    return [{ label: "iocs", value: agent.ioc_count || 0 }];
  }
  if (agent.key === "investigation") {
    return [{ label: "artifacts", value: agent.evidence_items || 0 }];
  }
  if (agent.key === "reporting") {
    return [{ label: "reports", value: agent.reports_generated || 0 }];
  }
  if (agent.key === "approval") {
    return [{ label: "decisions", value: agent.approvals_made || 0 }];
  }
  return [];
}

function currentAgentRun(agent = {}) {
  const targetKey = canonicalAgentKey(agent.key || agent.label || "");
  const guarded = guardedRunForAgent(agent);
  if (guarded) return guarded;
  const run = latestActualRunForAgent(targetKey);
  // Always render the latest run state. This prevents an old stale "running" run
  // from making a completed agent look like it is still working.
  return run || null;
}

function effectiveAgentStatus(agent = {}, run = null) {
  if (runIsActive(run)) return "running";
  const persisted = norm(agent.workflow_status || agent.status);
  if (["ready", "running", "completed", "pending_approval", "approved", "locked", "failed", "rerun_required"].includes(persisted)) {
    return persisted;
  }
  if (runIsFailed(run)) return "failed";
  if (runIsCompleted(run)) {
    const runStatus = norm(run?.status);
    if (["completed_limited", "completed_with_warnings", "completed_with_evidence_gaps"].includes(runStatus)) return "completed_with_warnings";
    return "completed";
  }
  const agentStatus = norm(agent.status);
  if (["completed_limited", "completed_with_warnings", "completed_with_evidence_gaps"].includes(agentStatus)) return "completed_with_warnings";
  return agentStatus;
}

function displayAgentStatus(agent = {}, run = null) {
  const status = effectiveAgentStatus(agent, run);
  return {
    completed: "Completed",
    completed_with_warnings: "Completed with Warnings",
    running: "Running",
    in_progress: "In Progress",
    ready: "Ready",
    pending_approval: "Pending Approval",
    approved: "Approved",
    rerun_required: "Re-run Required",
    awaiting_approval: "Awaiting SOC Approval",
    awaiting_review: "Awaiting SOC Analyst Review",
    locked: "Locked",
    failed: "Failed",
    pending: "Pending",
  }[status] || agent.status || "Pending";
}

function agentProgressPercent(agent = {}, run = null) {
  const status = effectiveAgentStatus(agent, run);
  if (["completed", "completed_with_warnings", "pending_approval", "approved", "awaiting_approval", "awaiting_review"].includes(status)) return 100;
  if (status === "failed") return 100;
  const runProgress = run ? runProgressValue(run) : null;
  if (runProgress !== null) return runProgress;
  if (status === "running" || status === "in_progress") return 35;
  if (status === "ready") return 0;
  return 0;
}

function agentStatusTone(status = "") {
  const normalized = norm(status);
  if (normalized === "completed") return "green";
  if (normalized === "approved") return "green";
  if (normalized === "pending_approval") return "yellow";
  if (normalized === "rerun_required") return "purple";
  if (normalized === "completed_with_warnings") return "yellow";
  if (normalized === "awaiting_approval" || normalized === "awaiting_review") return "yellow";
  if (normalized === "locked") return "yellow";
  if (normalized === "failed") return "red";
  if (normalized === "running" || normalized === "in_progress") return "blue";
  return "blue";
}

function agentCurrentTask(agent = {}, run = null) {
  const status = effectiveAgentStatus(agent, run);
  if (run?.current_step) return run.current_step;
  if (agent.status_message) return agent.status_message;
  if (status === "completed") return "Agent completed and wrote output to the selected ticket.";
  if (status === "approved") return "The latest valid output is approved.";
  if (status === "pending_approval") return "Waiting for SOC analyst approval.";
  if (status === "rerun_required") return "This output is outdated and must be re-run in sequence.";
  if (status === "locked") return agent.lock_reason || "Waiting for prerequisite workflow stage.";
  if (status === "ready") return `${agent.label} is ready to run with the selected ticket context.`;
  if (status === "failed") return agent.last_output_summary || "Agent execution failed. Review logs before retrying.";
  return agent.required_input_status || "Waiting for ticket context.";
}

function defaultAgentStepLabels(agent = {}) {
  return {
    parsing: ["Loading raw alert", "Extracting metakeys", "Normalising SOC context", "Writing parser outputs", "Generating PDF"],
    triage: ["Loading normalised alert context", "Reviewing severity and confidence indicators", "Mapping alert behaviour to SOC playbook", "Updating triage_result.json and ticket activity"],
    threat_intel: ["Loading IOCs", "Checking external reputation services", "Calculating enrichment risk", "Writing enriched alert", "Ready for export on demand"],
    investigation: ["Loading selected ticket context", "Confirming approval status", "Reviewing related evidence", "Writing investigation_result.json"],
    reporting: ["Loading ticket investigation context", "Validating required report fields", "Generating report sections", "Saving report output to ticket", "Preparing export actions"],
    triage_approval: ["Reviewing triage and threat intelligence", "Checking decision gate status", "Recording analyst decision", "Unlocking Investigation"],
    investigation_approval: ["Reviewing investigation findings", "Checking evidence limitations", "Recording analyst decision", "Unlocking Reporting"],
    soc_review: ["Reviewing generated report", "Confirming analyst acceptance", "Recording review decision", "Preparing case closure"],
    approval: ["Reviewing recommended action", "Checking decision gate status", "Recording analyst decision", "Updating ticket workflow", "Unlocking next valid stage"],
  }[agent.key] || ["Loading ticket context", "Checking prerequisites", "Running task", "Saving output", "Updating ticket activity"];
}


function normalizeOperationalStep(step) {
  if (typeof step === "string") return { label: step };
  if (!step || typeof step !== "object") return { label: "Operational step" };
  return {
    label: step.label || step.name || step.title || step.current_step || "Operational step",
    state: step.state || step.status || null,
  };
}

function activeStepIndexForProgress(progress = 0, total = 5) {
  const pct = Math.max(0, Math.min(100, Number(progress) || 0));
  if (pct >= 100) return total;
  if (pct <= 15) return 0;
  if (pct <= 35) return Math.min(1, total - 1);
  if (pct <= 55) return Math.min(2, total - 1);
  if (pct <= 75) return Math.min(3, total - 1);
  return Math.max(0, total - 1);
}

function stateForProgressStep(index, activeIndex, progress, status) {
  const pct = Math.max(0, Math.min(100, Number(progress) || 0));
  if (status === "completed" || pct >= 100) return "done";
  if (status === "locked") return index === 0 ? "blocked" : "pending";
  if (status === "failed") {
    if (index < activeIndex) return "done";
    if (index === activeIndex) return "failed";
    return "pending";
  }
  if (index < activeIndex) return "done";
  if (index === activeIndex) return "active";
  return "pending";
}

function agentOperationalSteps(agent = {}, run = null) {
  const progress = agentProgressPercent(agent, run);
  const status = effectiveAgentStatus(agent, run);
  const runSteps = arrayOf(run?.steps).map(normalizeOperationalStep);
  const labels = runSteps.length ? runSteps.map(step => step.label) : defaultAgentStepLabels(agent);
  const activeIndex = activeStepIndexForProgress(progress, labels.length);
  return labels.map((label, index) => {
    const explicitState = runSteps[index]?.state ? norm(runSteps[index].state) : null;
    const derivedState = stateForProgressStep(index, activeIndex, progress, status);
    const state = explicitState && progress >= 100 ? (explicitState === "completed" ? "done" : explicitState) : derivedState;
    return { label, state: state === "completed" ? "done" : state };
  });
}

function renderProgressDial(agent = {}, progress = 0, compact = false, statusLabel = null) {
  const label = statusLabel || agent.status || "Pending";
  const status = effectiveAgentStatus(agent, currentAgentRun(agent));
  return `<div class="agent-progress-linear ${esc(status)} ${compact ? "compact" : ""}" style="--progress:${progress}%" aria-label="${esc(label)} ${esc(progress)}%" title="${esc(label)}">
    <div class="agent-progress-linear-meta"><span>Completion</span><strong>${progress}%</strong></div>
    <div class="agent-progress-linear-track"><span></span></div>
  </div>`;
}

function renderOperationalStepGrid(steps = [], compact = false) {
  return `<div class="agent-step-grid ${compact ? "compact" : ""}">
    ${steps.map(step => `<div class="agent-step ${esc(step.state)}"><i class="ti ${step.state === "done" ? "ti-check" : step.state === "active" ? "ti-player-play" : step.state === "blocked" ? "ti-lock" : step.state === "failed" ? "ti-alert-triangle" : "ti-circle"}"></i><span>${esc(step.label)}</span></div>`).join("")}
  </div>`;
}


function agentThinkingDots(agent = {}, run = null, progress = null) {
  const status = effectiveAgentStatus(agent, run);
  const label = displayAgentStatus(agent, run);
  const pct = progress == null ? null : Number(progress);
  const isCompleted = ["completed", "approved"].includes(status)
    || (Number.isFinite(pct) && pct >= 100 && !["failed", "completed_with_warnings", "pending_approval", "awaiting_approval", "awaiting_review", "rerun_required", "locked"].includes(status));
  const isFailed = ["failed", "error", "rejected"].includes(status);
  const isLocked = status === "locked";
  const isGateWait = ["pending_approval", "awaiting_approval", "awaiting_review"].includes(status);
  const isActive = ["running", "ready", "in_progress"].includes(status);

  if (status === "completed_with_warnings") {
    return `<span class="agent-status-mark warning" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-alert-triangle"></i></span>`;
  }
  if (isCompleted || status === "approved") {
    return `<span class="agent-status-mark completed" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-check"></i></span>`;
  }
  if (isFailed) {
    return `<span class="agent-status-mark failed" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-x"></i></span>`;
  }
  if (isLocked) {
    return `<span class="agent-status-mark locked" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-lock"></i></span>`;
  }
  if (status === "rerun_required") {
    return `<span class="agent-status-mark rerun-required" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-refresh-alert"></i></span>`;
  }
  if (isGateWait) {
    return `<span class="agent-status-mark locked" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-hourglass"></i></span>`;
  }

  if (isActive) {
    return `<span class="thinking-dots is-active" aria-label="${esc(label)}" title="${esc(label)}"><span></span><span></span><span></span></span>`;
  }
  return `<span class="agent-status-mark pending" aria-label="${esc(label)}" title="${esc(label)}"><i class="ti ti-circle"></i></span>`;
}

function renderParserSummaryCard(ticket = {}) {
  const parser = ticket.parsing_result || ticket.parser_result || {};
  if (!parser || typeof parser !== "object" || !Object.keys(parser).length) return "";
  const card = parser.parser_summary_card || {};
  const meta = parser.parser_run_metadata || {};
  const missing = arrayOf(card.missing_fields || meta.missing_fields || parser.missing_important_fields);
  const warnings = arrayOf(card.warnings || parser.warnings);
  const rawEvents = card.raw_events_retrieved ?? meta.raw_event_count ?? (parser.normalised_alert?.alert_summary?.raw_event_count ?? 0);
  const iocCount = card.ioc_count ?? meta.ioc_count ?? arrayOf(parser.processed_alert?.iocs).length;
  const powershellStatus = card.powershell_decode_status || meta.powershell_decode_status || parser.processed_alert?.powershell_decode_status || "not_detected";
  const confidence = card.parser_confidence || meta.parser_confidence || parser.parser_confidence || "Unknown";
  const confidenceScore = card.parser_confidence_score ?? meta.parser_confidence_score ?? parser.parser_confidence_score ?? "";
  const inputSource = card.input_source || meta.input_source || parser.input_source || "unknown";
  return `<div class="parser-summary-card">
    <div class="parser-summary-header"><i class="ti ti-adjustments-code"></i><strong>Parser Summary</strong>${badge(parser.display_status || parser.status || "Completed", warnings.length ? "yellow" : "green")}</div>
    <div class="parser-summary-grid">
      <div><span>Input source</span><strong>${esc(String(inputSource).replaceAll("_", " "))}</strong></div>
      <div><span>Raw events retrieved</span><strong>${esc(rawEvents)}</strong></div>
      <div><span>IOCs extracted</span><strong>${esc(iocCount)}</strong></div>
      <div><span>PowerShell decode</span><strong>${esc(String(powershellStatus).replaceAll("_", " "))}</strong></div>
      <div><span>Parser confidence</span><strong>${esc(confidence)}${confidenceScore !== "" ? ` (${esc(confidenceScore)})` : ""}</strong></div>
      <div><span>Missing fields</span><strong>${missing.length ? esc(missing.join(", ")) : "None"}</strong></div>
    </div>
    ${warnings.length ? `<div class="parser-warning-list"><strong>Warnings</strong>${warnings.slice(0, 4).map(w => `<p><i class="ti ti-alert-triangle"></i>${esc(w)}</p>`).join("")}</div>` : ""}
  </div>`;
}

function renderSelectedAgentExecutionPanel(ticket) {
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";
  const isCollapsed = state.collapsedPanels["execution-panel"];
  const run = currentAgentRun(agent);
  const progress = agentProgressPercent(agent, run);
  const steps = agentOperationalSteps(agent, run);
  const status = effectiveAgentStatus(agent, run);
  const statusLabel = displayAgentStatus(agent, run);
  const title = agent.key === "approval" ? "Approval Review, Decision Gate" : "Selected Agent Execution";
  const isDoneStatus = ["completed", "completed_with_warnings"].includes(status);
  const panelState = isDoneStatus ? "completed" : status === "failed" ? "failed" : status === "locked" ? "locked" : "active";
  const actionCandidates = prioritisedAgentActions(agent);
  const isRunningStatus = status === "running" || status === "in_progress";
  const panelActions = isRunningStatus
    ? actionCandidates.filter(action => action.id === "run-agent").slice(0, 1)
    : isDoneStatus
    ? actionCandidates.filter(action => action.id === "view-agent-output" || (["Retry", "Re-run"].includes(action.label))).slice(0, 2)
    : status === "failed"
      ? actionCandidates.filter(action => (["Retry", "Re-run"].includes(action.label)) || action.id === "run-agent").slice(0, 1)
      : actionCandidates.slice(0, 3);
  const pauseButton = runIsActive(run) ? `<button class="soc-btn warning" data-action="pause-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}" data-run-id="${esc(runIdentifier(run))}"><i class="ti ti-player-pause"></i> Pause Agent</button>` : "";
  const actions = `${pauseButton}${panelActions.map(action => actionButtonForAgent(action, agent)).join("")}`;
  const timestamp = run?.started_at ? `Started ${shortDate(run.started_at)}` : agent.last_run_time ? `Last run ${shortDate(agent.last_run_time)}` : "No run timestamp recorded";
  const successSummary = "Agent completed and wrote output to the selected ticket.";

  return `<div class="agent-execution-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="execution-panel">
      <div>
        <h3>${esc(title)}</h3>
        <small>Agent Execution Progress</small>
      </div>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body agent-execution-body ${panelState}">
      <div class="agent-execution-hero">
        <div class="agent-progress-stack">
          ${renderProgressDial(agent, progress, isDoneStatus, statusLabel)}
          <span class="agent-progress-status-label ${esc(status)}" title="${esc(statusLabel)}">${esc(statusLabel)}</span>
        </div>
        <div class="agent-execution-copy">
          <div class="agent-execution-title-row">
            <h4 class="agent-title-with-dots">${esc(agent.label)}${agentThinkingDots(agent, run, progress)}</h4>
            ${badge(statusLabel, agentStatusTone(statusLabel))}
          </div>
          ${isDoneStatus ? `<p class="completion-summary"><i class="ti ti-circle-check"></i>${esc(status === "completed_with_warnings" ? "Agent completed with warnings and wrote output to the selected ticket." : successSummary)}</p>` : status === "failed" ? `<p class="failure-summary"><i class="ti ti-circle-x"></i><strong>Failed step:</strong> ${esc(agentCurrentTask(agent, run))}</p>` : `<p class="current-task"><strong>Current task:</strong> ${esc(agentCurrentTask(agent, run))}</p>`}
          ${!isDoneStatus ? `<div class="progress-bar-container"><div class="progress-bar" style="width:${progress}%"></div></div>` : ""}
          <small>${esc(timestamp)}</small>
        </div>
      </div>
      ${agent.lock_reason ? `<div class="lock-note prominent"><i class="ti ti-lock"></i>${esc(agent.lock_reason)}</div>` : ""}
      ${agent.key === "parsing" && !shouldMaskAgentOutput(ticket, agent.key) ? renderParserSummaryCard(ticket) : ""}
      ${runIsActive(run) && agent.key === "parsing" && progress >= 25 ? `<div class="parser-wait-card"><i class="ti ti-alert-circle"></i><span>Parsing is taking longer than expected. If NetWitness detail retrieval is unavailable, continue with the selected ticket data.</span><button class="soc-btn warning compact" data-action="continue-parser-available-data" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-player-skip-forward"></i> Continue with Available Data</button></div>` : ""}
      ${renderOperationalStepGrid(steps, isDoneStatus)}
      <div class="execution-actions">${actions}</div>
    </div>` : ""}
  </div>`;
}

function renderAgentHandoffRouting(ticket) {
  const isCollapsed = state.collapsedPanels["routing-panel"];
  const steps = arrayOf(ticket.workflow_steps);
  const pipeline = [
    { label: "Parse", match: "Parsing & Normalisation" },
    { label: "Triage", match: "Triage Agent" },
    { label: "Threat Intel", match: "Threat Intel Enrichment" },
    { label: "Investigation", match: "Investigation Agent" },
    { label: "Reporting", match: "Reporting Agent" },
    { label: "Closure", match: "Case Closure" },
  ];
  const findStep = (item) => steps.find(s => s.label === item.match || s.key === norm(item.match) || s.label === item.label);
  const pipelineHtml = pipeline.map((stage, i) => {
    const step = findStep(stage);
    const status = step ? workflowStatus(step) : "pending";
    return `<div class="pipeline-stage ${status}">
        <div class="stage-badge"><i class="ti ${getPipelineIcon(status)}"></i></div>
        <small>${esc(stage.label)}</small>
      </div>${i < pipeline.length - 1 ? `<div class="pipeline-arrow"></div>` : ""}`;
  }).join("");
  const approvalStep = steps.find(s => ["threat_intelligence", "investigation"].includes(s.key) && workflowStatus(s) === "awaiting_approval");
  const reviewStep = steps.find(s => s.key === "reporting" && workflowStatus(s) === "awaiting_review");
  const warning = approvalStep
    ? `<div class="approval-warning"><i class="ti ti-alert-circle"></i><span>Human approval is waiting inside the ${esc(approvalStep.label)} stage.</span></div>`
    : reviewStep
      ? `<div class="approval-warning"><i class="ti ti-clipboard-check"></i><span>SOC analyst review is waiting inside the Reporting Agent stage.</span></div>`
      : "";

  return `<div class="agent-routing-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="routing-panel">
      <h3>Workflow Routing</h3>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body"><div class="pipeline-visualization">${pipelineHtml}</div>${warning}</div>` : ""}
  </div>`;
}

function getPipelineIcon(status) {
  if (status === "completed") return "ti-circle-check";
  if (status === "in_progress") return "ti-player-play";
  if (status === "awaiting_approval" || status === "requires_approval") return "ti-lock";
  if (status === "awaiting_review") return "ti-clipboard-check";
  if (status === "failed") return "ti-circle-x";
  return "ti-circle";
}


function renderEmbeddedHumanGate(agent = {}) {
  const gate = agent.embedded_gate || {};
  if (!gate || !Object.keys(gate).length) return "";
  const status = norm(gate.status || "pending");
  const tone = ["approved", "confirmed", "completed"].includes(status) ? "green" : ["awaiting_approval", "awaiting_review"].includes(status) ? "yellow" : "blue";
  return `<div class="embedded-human-gate ${esc(status)}">
    <div><span>${esc(gate.label || "Human Decision Gate")}</span><strong>${esc(String(gate.status || "Pending").replaceAll("_", " "))}</strong></div>
    ${badge(String(gate.status || "Pending").replaceAll("_", " "), tone)}
    <p>${esc(gate.summary || "Human validation is tracked inside this stage.")}</p>
  </div>`;
}
function renderSelectedAgentOutputPanel(ticket) {
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";
  
  const isCollapsed = state.collapsedPanels["output-panel"];
  const outputKey = { parsing: "parsing_result", triage: "triage_result", threat_intel: "threat_intel_result", investigation: "investigation_result", reporting: "reporting_result", triage_approval: "approval_result", investigation_approval: "investigation_approval_result", soc_review: "soc_review_result", approval: "approval_result" }[agent.key] || "triage_result";
  const output = ticket[outputKey] || {};
  const hasOutput = Object.keys(output).length > 0;
  const run = currentAgentRun(agent);
  const status = effectiveAgentStatus(agent, run);
  const statusLabel = displayAgentStatus(agent, run);
  
  let actionButtons = "";
  if (["completed", "completed_with_warnings"].includes(status) && hasOutput) {
    actionButtons = `
      <button class="soc-btn primary" data-action="view-agent-output" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
        <i class="ti ti-eye"></i> View Output
      </button>
      <button class="soc-btn ghost" data-action="retry-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
        <i class="ti ti-refresh"></i> Retry
      </button>
    `;
  } else if (status === "ready") {
    if (["triage_approval", "investigation_approval", "approval"].includes(agent.key)) {
      actionButtons = `
        <button class="soc-btn green" data-action="approve-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-shield-check"></i> Approve</button>
        <button class="soc-btn danger" data-action="reject-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-x"></i> Reject</button>
      `;
    } else if (agent.key === "soc_review") {
      actionButtons = `<button class="soc-btn green" data-action="confirm-soc-review" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-clipboard-check"></i> Confirm Review</button>`;
    } else {
      const runLabel = { parsing: "Run Parsing", triage: "Run Triage", threat_intel: "Run Threat Intel", investigation: "Run Investigation", reporting: "Generate Report", triage_approval: "Review", investigation_approval: "Review", soc_review: "Confirm Review", approval: "Review" }[agent.key] || "Run Agent";
      actionButtons = `
        <button class="soc-btn primary" data-action="run-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
          <i class="ti ti-player-play"></i> ${esc(runLabel)}
        </button>
      `;
    }
  } else if (status === "awaiting_approval") {
    actionButtons = `
      <button class="soc-btn green" data-action="approve-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-shield-check"></i> Approve</button>
      <button class="soc-btn danger" data-action="reject-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-x"></i> Reject</button>
      <button class="soc-btn ghost" data-action="more-evidence" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-search"></i> More Evidence</button>
    `;
  } else if (status === "awaiting_review") {
    actionButtons = `<button class="soc-btn green" data-action="confirm-soc-review" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-clipboard-check"></i> Confirm Review</button>`;
  } else if (status === "locked") {
    actionButtons = `<p class="lock-reason"><i class="ti ti-lock"></i> ${esc(agent.lock_reason || "Agent is locked")}</p>`;
  } else if (status === "running" || status === "in_progress") {
    actionButtons = `<p class="running-text"><i class="ti ti-loader-2"></i> Agent is running...</p>
      <button class="soc-btn warning" data-action="pause-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}" data-run-id="${esc(runIdentifier(run))}"><i class="ti ti-player-pause"></i> Pause Agent</button>`;
  } else if (status === "failed") {
    actionButtons = `
      <button class="soc-btn primary" data-action="retry-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
        <i class="ti ti-refresh"></i> Retry
      </button>
    `;
  }
  
  return `<div class="agent-output-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="output-panel">
      <h3>Selected Agent Output</h3>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body">
      <div class="output-status">
        <p class="status-text">Status: <strong>${esc(statusLabel)}</strong></p>
        ${hasOutput ? `<p class="summary-text">${esc(output.summary || output.recommendation || "Output available")}</p>` : `<p class="no-output">No output yet</p>`}
      </div>
      ${renderEmbeddedHumanGate(agent)}
      <div class="output-actions">
        ${actionButtons}
      </div>
    </div>` : ""}
  </div>`;
}


function askAnswerKey(ticketId, agentKey) {
  return `${ticketId || state.selectedTicket?.ticket_id || "ticket"}::${agentKey || state.selectedAgentKey || "agent"}`;
}

function askAgentResponseText(res = {}) {
  if (!res || typeof res !== "object") return "No answer returned.";
  return res.answer || res.response || res.message || res.result || res.output || res.status || res.error || "No answer returned.";
}

function renderAskAgentAnswer(entry = null) {
  if (!entry) {
    return `<div class="ask-answer-empty">Ask a question about this ticket or selected agent output.</div>`;
  }
  const status = entry.status || "answered";
  const label = status === "thinking" ? "Thinking" : status === "error" ? "Error" : "Answer";
  const icon = status === "thinking" ? "ti-loader-2" : status === "error" ? "ti-alert-triangle" : "ti-message-circle";
  const time = entry.updated_at ? shortTime(entry.updated_at) : "";
  return `<div class="ask-answer-card ${esc(status)}">
    <div class="ask-answer-head">
      <span><i class="ti ${icon}"></i>${esc(label)}</span>
      ${time ? `<small>${esc(time)}</small>` : ""}
    </div>
    ${entry.question ? `<div class="ask-question"><strong>Question</strong><span>${esc(entry.question)}</span></div>` : ""}
    <div class="ask-response">${esc(entry.answer || "No answer returned.")}</div>
  </div>`;
}

function renderAskAgentPanel(ticket) {
  const isCollapsed = state.collapsedPanels["ask-panel"];
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";
  const askKey = askAnswerKey(ticket.ticket_id, agent.key);
  const savedAnswer = state.askAgentAnswers[askKey] || null;
  
  const questions = [
    "Explain Decision",
    "Next Action",
    "Summarise Output",
    "View Raw JSON",
    "What evidence?",
    "What should I do?"
  ];
  
  return `<div class="agent-ask-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="ask-panel">
      <h3><i class="ti ti-sparkles"></i> Ask Aegis</h3>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body">
      <div class="ask-quick-actions">
        ${questions.map(q => `<button class="ask-quick-btn" type="button" data-question="${esc(q)}">${esc(q)}</button>`).join("")}
      </div>
      <div class="ask-input-row">
        <input class="ask-agent-input" id="ask-input-workspace" placeholder="Ask ${esc(agent.label)} about this ticket..." data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
        <button class="soc-btn primary" type="button" data-action="ask-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
          <i class="ti ti-send"></i>
        </button>
      </div>
      <div id="ask-answer-workspace" data-ask-key="${esc(askKey)}">${renderAskAgentAnswer(savedAnswer)}</div>
    </div>` : ""}
  </div>`;
}

function liveLogStateFromText(text = "", fallback = "info") {
  const value = String(text || "").toLowerCase();
  if (value.includes("fail") || value.includes("error") || value.includes("exception") || value.includes("rejected")) return "failed";
  if (value.includes("complete") || value.includes("completed") || value.includes("success") || value.includes("written") || value.includes("saved")) return "done";
  if (value.includes("running") || value.includes("started") || value.includes("loading") || value.includes("checking") || value.includes("querying") || value.includes("reviewing") || value.includes("generating") || value.includes("mapping") || value.includes("validating")) return "active";
  if (value.includes("lock") || value.includes("blocked") || value.includes("waiting")) return "blocked";
  return fallback;
}

function liveLogIconForState(state = "info") {
  return {
    done: "ti-check",
    active: "ti-player-play",
    failed: "ti-alert-triangle",
    blocked: "ti-lock",
    pending: "ti-circle",
    info: "ti-activity",
  }[state] || "ti-activity";
}

function liveLogStageLabel(agent = {}, index = 0) {
  const label = String(agent.label || agentLabel(agent.key) || "Agent").replace(" / Analyst Review", "");
  return `${label} Step ${index + 1}`;
}

function normalizeLiveLogEntry(entry, index, agent = {}, defaultState = "info") {
  if (entry && typeof entry === "object") {
    const rawMessage = String(entry.message || entry.detail || entry.description || entry.current_step || entry.step || entry.label || entry.name || "Agent activity recorded.").trim();
    const timestamp = entry.timestamp || entry.created_at || entry.updated_at || entry.time || entry.started_at || entry.completed_at || "";
    const state = norm(entry.state || entry.status || "") || liveLogStateFromText(rawMessage, defaultState);
    return {
      title: entry.title || entry.label || liveLogStageLabel(agent, index),
      message: rawMessage,
      timestamp,
      state,
      source: entry.source || entry.actor || agent.label || "Selected Agent",
      sequence: index + 1,
    };
  }

  const raw = String(entry || "").trim();
  const timeMatch = raw.match(/^\[([^\]]+)\]\s*(.*)$/);
  const timestamp = timeMatch ? timeMatch[1] : "";
  const message = timeMatch ? timeMatch[2].trim() : raw;
  const state = liveLogStateFromText(message, defaultState);
  return {
    title: liveLogStageLabel(agent, index),
    message: message || "Agent activity recorded.",
    timestamp,
    state,
    source: agent.label || "Selected Agent",
    sequence: index + 1,
  };
}

function liveLogEntriesFromRun(agent = {}, run = null) {
  if (!run) return [];
  const rawLogs = [
    ...arrayOf(run.logs),
    ...arrayOf(run.log_lines),
    ...arrayOf(run.activity_log),
    ...arrayOf(run.events),
  ];
  if (rawLogs.length) {
    return rawLogs.slice(-60).map((entry, index) => normalizeLiveLogEntry(entry, index, agent, runIsActive(run) ? "active" : runIsCompleted(run) ? "done" : runIsFailed(run) ? "failed" : "info"));
  }
  return [];
}

function liveLogEntriesFromTicketActivity(ticket = {}, agent = {}) {
  const agentKey = canonicalAgentKey(agent.key || agent.label || "");
  return arrayOf(ticket.activity_log)
    .filter(item => {
      const searchable = `${item.actor || ""} ${item.action || ""} ${item.message || ""}`.toLowerCase();
      return searchable.includes(agentKey) || searchable.includes(String(agent.label || "").toLowerCase()) || searchable.includes(agentKey.replace("_", " "));
    })
    .slice(-20)
    .map((item, index) => normalizeLiveLogEntry({
      title: titleCase(String(item.action || "agent update").replaceAll("_", " ")),
      message: item.message || item.action || "Agent activity recorded.",
      timestamp: item.timestamp || item.created_at || item.updated_at,
      status: liveLogStateFromText(`${item.action || ""} ${item.message || ""}`),
      actor: item.actor || agent.label,
    }, index, agent));
}

function liveLogEntriesFromOperationalSteps(agent = {}, run = null) {
  return agentOperationalSteps(agent, run).map((step, index) => ({
    title: liveLogStageLabel(agent, index),
    message: step.label,
    timestamp: "",
    state: step.state === "done" ? "done" : step.state === "active" ? "active" : step.state === "failed" ? "failed" : step.state === "blocked" ? "blocked" : "pending",
    source: agent.label || "Selected Agent",
    sequence: index + 1,
  }));
}

function buildLiveLogEntries(ticket = {}, agent = {}, run = null) {
  const fromRun = liveLogEntriesFromRun(agent, run);
  if (fromRun.length) return fromRun;
  const fromActivity = liveLogEntriesFromTicketActivity(ticket, agent);
  if (fromActivity.length) return fromActivity;
  return liveLogEntriesFromOperationalSteps(agent, run);
}

function liveLogStateLabel(state = "info") {
  return {
    done: "Done",
    active: "Active",
    failed: "Failed",
    blocked: "Blocked",
    pending: "Pending",
    info: "Info",
  }[state] || "Info";
}

function liveLogTimestampLabel(value) {
  if (!value) return "Current trace";
  const str = String(value);
  if (/^\d{1,2}:\d{2}/.test(str)) return str;
  const d = new Date(str);
  if (Number.isNaN(d.getTime())) return str;
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function renderLiveLogTrace(entries = [], agent = {}, run = null) {
  if (!entries.length) return `<div class="empty-state">No live activity recorded for this agent yet.</div>`;
  const runStatus = runIsActive(run) ? "active" : runIsCompleted(run) ? "done" : runIsFailed(run) ? "failed" : "info";
  return `<div class="live-log-trace ${esc(runStatus)}">
    ${entries.map(entry => {
      const state = entry.state || "info";
      return `<article class="live-log-item ${esc(state)}">
        <div class="live-log-marker"><i class="ti ${esc(liveLogIconForState(state))}"></i></div>
        <div class="live-log-card">
          <div class="live-log-card-top">
            <div class="live-log-title-row">
              <strong>${esc(entry.title || liveLogStageLabel(agent, (entry.sequence || 1) - 1))}</strong>
              <span class="live-log-state-pill ${esc(state)}">${esc(liveLogStateLabel(state))}</span>
            </div>
            <time>${esc(liveLogTimestampLabel(entry.timestamp))}</time>
          </div>
          <p>${esc(entry.message || "Agent activity recorded.")}</p>
          <div class="live-log-meta">
            <span><i class="ti ti-cpu"></i>${esc(entry.source || agent.label || "Selected Agent")}</span>
            <span><i class="ti ti-list-numbers"></i>Step ${esc(entry.sequence || "-")}</span>
          </div>
        </div>
      </article>`;
    }).join("")}
  </div>`;
}

function normaliseThinkingEntriesForRunState(entries = [], agent = {}, run = null) {
  const status = effectiveAgentStatus(agent, run);
  const progress = agentProgressPercent(agent, run);

  if (status === "completed" || progress >= 100) {
    return entries.map(entry => ({
      ...entry,
      state: entry.state === "failed" ? "failed" : "done",
      timestamp: entry.timestamp || "Completed",
    }));
  }

  if (status === "failed") {
    let failureSeen = false;
    return entries.map(entry => {
      if (failureSeen) return { ...entry, state: "pending" };
      if (entry.state === "failed" || entry.state === "active") {
        failureSeen = true;
        return { ...entry, state: "failed" };
      }
      return entry;
    });
  }

  return entries;
}

function renderAgentLiveActivityLog(ticket) {
  const isCollapsed = state.collapsedPanels["log-panel"];
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";

  const run = currentAgentRun(agent);
  const progress = agentProgressPercent(agent, run);
  const status = effectiveAgentStatus(agent, run);
  const entries = buildLiveLogEntries(ticket, agent, run);
  const doneCount = entries.filter(entry => entry.state === "done").length;
  const activeCount = entries.filter(entry => entry.state === "active").length;
  const failedCount = entries.filter(entry => entry.state === "failed").length;
  const traceSubtitle = runIsActive(run)
    ? "Live execution trace for the selected agent"
    : "Latest execution trace for the selected agent";

  return `<div class="agent-live-log-panel enhanced-live-log-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="log-panel">
      <div>
        <h3><i class="ti ti-activity"></i> Live Activity Log</h3>
        <small>${esc(traceSubtitle)}</small>
      </div>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body live-log-body">
      <div class="live-log-summary-row">
        <div class="live-log-summary-card"><span>Selected Agent</span><strong>${esc(agent.label || agentLabel(agent.key))}</strong></div>
        <div class="live-log-summary-card"><span>Run Status</span><strong>${esc(displayAgentStatus(agent, run))}</strong></div>
        <div class="live-log-summary-card"><span>Progress</span><strong>${esc(progress)}%</strong></div>
        <div class="live-log-summary-card"><span>Trace Events</span><strong>${esc(entries.length)}</strong></div>
      </div>
      <div class="live-log-health-row">
        <span class="live-health-pill done"><i class="ti ti-check"></i>${esc(doneCount)} done</span>
        <span class="live-health-pill active"><i class="ti ti-player-play"></i>${esc(activeCount)} active</span>
        <span class="live-health-pill failed"><i class="ti ti-alert-triangle"></i>${esc(failedCount)} failed</span>
        <span class="live-health-pill info"><i class="ti ti-clock"></i>${esc(run?.started_at ? `Started ${shortDate(run.started_at)}` : agent.last_run_time ? `Last run ${shortDate(agent.last_run_time)}` : "No run timestamp")}</span>
      </div>
      ${renderLiveLogTrace(entries, agent, run)}
    </div>` : ""}
  </div>`;
}
function ticketTabs(t) {
  const tabs = [
    ["overview", "Ticket Overview"],
    ["alerts", "Related Alerts"],
    ["updates", "Agent Updates"],
    ["approval", "Approval Log"],
    ["timeline", "Timeline"],
    ["reports", "Reports"],
  ];
  return `<div class="tabs">${tabs.map(([id, label]) => `<button class="${state.ticketTab === id ? "active" : ""}" data-tab="${id}">${esc(label)}</button>`).join("")}</div>
  <div class="tab-body">${tabBody(t)}</div>`;
}

function tabBody(t) {
  if (state.ticketTab === "alerts") return relatedAlertsTable(t, true);
  if (state.ticketTab === "updates") return activityList(arrayOf(t.activity_log).filter(a => String(a.action || "").includes("updated") || String(a.actor || "").includes("Agent")));
  if (state.ticketTab === "approval") return approvalLog(t);
  if (state.ticketTab === "timeline") return activityList(arrayOf(t.activity_log));
  if (state.ticketTab === "reports") return reportsForTicket(t);
  return `<div class="overview-grid">
    ${field("Severity", t.severity)}${field("Confidence", t.confidence)}${field("Affected Assets", arrayOf(t.affected_assets).join(", ") || "None recorded")}
    ${field("Affected Users", arrayOf(t.affected_users).join(", ") || "None recorded")}${field("IOCs", compactIocs(t.iocs))}${field("Recommendation", t.next_step?.reason || "Review workflow state.")}
  </div>`;
}

function field(k, v) {
  const key = norm(k);
  const technical = /(ioc|hash|url|domain|path|registry|command|asset|host|user|id)/.test(key);
  return `<div class="field card-content ${technical ? "technical-value" : ""}" data-field-key="${esc(key)}"><span>${esc(k)}</span><strong class="summary-value ${technical ? "mono-wrap" : "safe-wrap"}">${esc(v || "Unknown")}</strong></div>`;
}

function correlationRecommendationsPanel(ticket = state.selectedTicket, sourceStages = []) {
  if (!ticket) return "";
  const stageSet = new Set(arrayOf(sourceStages).map(s => norm(s)).filter(Boolean));
  const recs = arrayOf(ticket.correlation_recommendations).filter(rec => {
    if (!stageSet.size) return true;
    const stage = norm(rec.source_stage || "triage");
    if (stageSet.has("triage")) return ["triage", "correlation", ""].includes(stage);
    return stageSet.has(stage);
  });
  const pending = recs.filter(r => norm(r.status) === "pending");
  const history = recs.filter(r => norm(r.status) !== "pending").slice(0, 6);
  if (!pending.length && !history.length) return "";

  const title = stageSet.has("investigation") ? "Investigation Incident Grouping Review" : stageSet.has("triage") ? "Triage Incident Grouping Review" : "Incident Grouping Recommendations";
  const header = `<div class="panel-head"><h2><i class="ti ti-git-merge"></i> ${esc(title)}</h2><span class="panel-sub">Review only when the system finds related alerts or duplicate tickets.</span></div>`;
  const card = (rec, pendingMode = true) => {
    const matched = arrayOf(rec.matched_fields).slice(0, 4).map(m => `<li><strong>${esc(String(m.field || "field").replaceAll("_", " "))}</strong>: ${esc(Array.isArray(m.value) ? m.value.join(", ") : (m.value || m.reason || "matched"))}</li>`).join("");
    const archiveRequired = Boolean(rec.requires_archive_approval || rec.archive_after_approval || norm(rec.recommendation_type).includes("archive"));
    const action = rec.archive_action || {};
    const sourceTicket = rec.source_ticket_id || action.source_ticket_id || "None";
    const actionLabel = archiveRequired ? "Approve Grouping & Archive" : "Approve Grouping";
    const archiveNote = archiveRequired ? `<div class="correlation-archive-note"><strong>Archive impact:</strong> ${esc(sourceTicket)} will be merged into ${esc(rec.target_ticket_id || ticket.ticket_id)} and marked as an archived duplicate only after analyst approval. No evidence is deleted.</div>` : "";
    return `<div class="correlation-card ${pendingMode ? "pending" : "history"} ${archiveRequired ? "archive-review" : ""}">
      <div class="correlation-card-head"><strong>${esc(rec.recommendation_type || "add alert to ticket").replaceAll("_", " ")}</strong>${badge(rec.status || "pending", pendingMode ? "yellow" : "green")}${archiveRequired ? badge("Archive approval", "red") : ""}</div>
      <div class="overview-grid mini">
        ${field("Alert", rec.source_alert_id || "Ticket-level merge")}
        ${field("Source Ticket", sourceTicket)}
        ${field("Target Ticket", rec.target_ticket_id || ticket.ticket_id)}
        ${field("Score", `${rec.score || 0}% (${rec.confidence || "Unknown"})`)}
      </div>
      <p class="correlation-reason">${esc(rec.reason || "No reason provided.")}</p>
      ${archiveNote}
      ${matched ? `<ul class="correlation-match-list">${matched}</ul>` : ""}
      ${pendingMode ? `<div class="panel-actions">
        <button class="soc-btn green compact" data-action="confirm-correlation" data-recommendation-id="${esc(rec.recommendation_id)}" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-check"></i> ${actionLabel}</button>
        <button class="soc-btn ghost compact" data-action="edit-correlation" data-recommendation-id="${esc(rec.recommendation_id)}" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-edit"></i> Edit Grouping</button>
        <button class="soc-btn danger compact" data-action="reject-correlation" data-recommendation-id="${esc(rec.recommendation_id)}" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-x"></i> Reject Grouping</button>
      </div>` : `<small class="muted">Reviewed by ${esc(rec.reviewed_by || "analyst")} ${rec.reviewed_at ? `on ${esc(shortDate(rec.reviewed_at))}` : ""}${archiveRequired ? " · archive action audited" : ""}</small>`}
    </div>`;
  };
  return `<section class="panel correlation-panel embedded-grouping-panel">${header}
    ${pending.length ? `<div class="correlation-list">${pending.map(r => card(r, true)).join("")}</div>` : `<div class="empty-state small">No pending recommendations.</div>`}
    ${history.length ? `<h3 class="section-subtitle">Recent grouping decisions</h3><div class="correlation-list history-list">${history.map(r => card(r, false)).join("")}</div>` : ""}
  </section>`;
}

function relatedAlertsBlock() {
  return `<section class="panel">${relatedAlertsSection(state.selectedTicket)}</section>`;
}

function relatedAlertsSection(ticket) {
  const alerts = arrayOf(ticket?.related_alerts);
  const mergeBtn = ticket?.ticket_id ? `<button class="soc-btn warning" data-action="merge-tickets" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-git-merge"></i> Merge Another Ticket</button>` : "";
  if (!alerts.length) return `<section class="panel"><div class="panel-head"><h2>Related Alerts</h2><div class="panel-actions">${mergeBtn}<button class="soc-btn ghost" data-route="search-alerts"><i class="ti ti-search"></i> Search Alerts</button></div></div><div class="empty-state">No related alerts are linked to the selected ticket.</div></section>`;
  return `<section class="panel">
    <div class="panel-head"><h2>Related Alerts (${alerts.length})</h2><div class="panel-actions">${mergeBtn}<button class="soc-btn ghost" data-route="search-alerts"><i class="ti ti-search"></i> Search Related Alerts</button><button class="soc-btn ghost" data-route="search-alerts"><i class="ti ti-link"></i> Link Another Alert</button></div></div>
    <table class="soc-table compact related-alerts-table"><thead><tr><th>Alert ID</th><th>Alert Name</th><th>Severity</th><th>Relationship</th><th>Linked By</th><th>Score</th><th>Confirmed</th><th>Actions</th></tr></thead>
    <tbody>${alerts.map(a => `<tr>
      <td class="mono">${esc(a.alert_id)}</td>
      <td><strong>${esc(a.alert_name)}</strong><small>${esc(a.hostname || a.username || a.source || "")}</small></td>
      <td>${severityBadge(a.severity)}</td>
      <td><span>${esc(a.relationship || "Related")}</span><small>${esc(a.link_reason || "")}</small></td>
      <td>${esc(a.linked_by || a.link_source || "System")}</td>
      <td>${a.correlation_score ? badge(String(a.correlation_score), Number(a.correlation_score) >= 80 ? "green" : "yellow") : badge("Manual", "blue")}</td>
      <td>${esc(a.confirmed_by || "Pending/Manual")}<small>${esc(a.confirmed_at ? shortDate(a.confirmed_at) : "")}</small></td>
      <td class="row-actions"><button class="soc-btn ghost compact" data-action="view-alert" data-alert-id="${esc(a.alert_id)}">View</button>${a.netwitness_url ? `<a class="soc-btn ghost compact" href="${esc(a.netwitness_url)}" target="_blank">NetWitness</a>` : ""}<button class="soc-btn ghost compact" data-action="move-alert" data-alert-id="${esc(a.alert_id)}">Move</button><button class="soc-btn ghost compact" data-action="split-alert" data-alert-id="${esc(a.alert_id)}">Split</button><button class="soc-btn danger compact" data-action="remove-alert" data-alert-id="${esc(a.alert_id)}">Remove</button></td>
    </tr>`).join("")}</tbody></table>
  </section>`;
}

function timelineSection(ticket) {
  const rawEvents = arrayOf(ticket?.activity_log);
  const events = compressTimelineEvents(rawEvents.map(normalizeTimelineEvent).filter(Boolean));
  const filter = state.timelineFilters;
  const filtered = events.filter(event =>
    (filter.kind === "all" || event.kind === filter.kind) &&
    (filter.source === "all" || event.actor === filter.source) &&
    (filter.severity === "all" || event.severity === filter.severity)
  ).sort((a, b) => state.timelineSort === "oldest" ? a.timeMs - b.timeMs : b.timeMs - a.timeMs);
  const sources = [...new Set(events.map(event => event.actor).filter(Boolean))];
  const severities = [...new Set(events.map(event => event.severity).filter(Boolean))];
  const options = (values, selected, allLabel) => `<option value="all">${allLabel}</option>${values.map(value => `<option value="${esc(value)}" ${value === selected ? "selected" : ""}>${esc(titleCase(value))}</option>`).join("")}`;

  return `<section class="panel timeline-panel enhanced-timeline-panel">
    <div class="panel-head timeline-panel-head">
      <div>
        <h2>Incident Timeline</h2>
        <span class="timeline-subtitle">Significant security events in chronological order.</span>
      </div>
      <div class="timeline-sort-controls">
        <button class="soc-btn compact ${state.timelineSort === "oldest" ? "active" : "ghost"}" data-action="timeline-sort" data-sort="oldest">Oldest first</button>
        <button class="soc-btn compact ${state.timelineSort === "newest" ? "active" : "ghost"}" data-action="timeline-sort" data-sort="newest">Newest first</button>
      </div>
    </div>
    <div class="timeline-filter-bar">
      <select data-timeline-filter="kind">${options([...new Set(events.map(event => event.kind))], filter.kind, "All Events")}</select>
      <select data-timeline-filter="source">${options(sources, filter.source, "All Sources")}</select>
      <select data-timeline-filter="severity">${options(severities, filter.severity, "All Severities")}</select>
      <select data-timeline-filter="entity"><option value="all">All Entity Types</option></select>
      <select data-timeline-filter="tactic"><option value="all">All Tactics</option></select>
      <button class="soc-btn ghost compact" data-action="reset-timeline-filters">Reset Filters</button>
    </div>
    ${renderTimelineAuditTrail(filtered)}
  </section>`;
}

function normalizeTimelineEvent(event = {}) {
  if (!event || typeof event !== "object") return null;
  const createdAt = event.created_at || event.timestamp || event.time || event.updated_at || new Date().toISOString();
  const parsedTime = new Date(createdAt).getTime();
  const action = String(event.action || event.event || event.type || "updated").replaceAll("_", " ").trim();
  const message = String(event.message || event.description || event.detail || "").trim();
  const actor = String(event.actor || event.user || event.source || "System").trim();
  const searchable = `${actor} ${action} ${message}`.toLowerCase();
  const kind = timelineEventKind(searchable);

  return {
    actor,
    action,
    message,
    createdAt,
    timeMs: Number.isNaN(parsedTime) ? 0 : parsedTime,
    kind,
    title: timelineEventTitle(action, message, kind),
    badge: timelineEventBadge(kind),
    icon: timelineEventIcon(kind),
    severity: timelineEventSeverity(searchable, kind),
    source: actor,
    mitre: event.mitre_id || event.mitre || event.technique_id || "T1082",
    entities: Number(event.related_entities || event.entity_count || 1),
    evidence: Number(event.evidence_count || 1),
    normalized: event.normalized_event || `${norm(action).replaceAll("_", ".")} actor=${actor.replaceAll(" ", "_")}`,
    count: 1,
  };
}

function timelineEventSeverity(text = "", kind = "system") {
  if (text.includes("critical") || text.includes("malicious") || text.includes("ransomware")) return "critical";
  if (text.includes("high") || ["investigation", "threat_intel", "approval"].includes(kind)) return "high";
  if (text.includes("medium") || ["triage", "alert", "retry"].includes(kind)) return "medium";
  return "low";
}

function timelineEventKind(text = "") {
  if (text.includes("retry") || text.includes("rerun")) return "retry";
  if (text.includes("clos")) return "closure";
  if (text.includes("soc analyst review") || text.includes("soc_review")) return "soc_review";
  if (text.includes("approval") || text.includes("approved") || text.includes("reject") || text.includes("more evidence")) return "approval";
  if (text.includes("threat") || text.includes("enrichment")) return "threat_intel";
  if (text.includes("report")) return "reporting";
  if (text.includes("investigation")) return "investigation";
  if (text.includes("parsing") || text.includes("normalisation") || text.includes("normalization") || text.includes("parser")) return "parsing";
  if (text.includes("triage")) return "triage";
  if (text.includes("alert") || text.includes("linked")) return "alert";
  if (text.includes("assign")) return "assignment";
  return "system";
}

function timelineEventTitle(action = "", message = "", kind = "system") {
  const text = `${action} ${message}`.toLowerCase();
  if (kind === "parsing" && text.includes("started")) return "Parsing and Normalisation started";
  if (kind === "parsing" && (text.includes("completed") || text.includes("updated") || text.includes("appended"))) return "Parser output updated";
  if (kind === "triage" && text.includes("started")) return "Triage Agent started";
  if (kind === "triage" && (text.includes("completed") || text.includes("updated") || text.includes("appended"))) return "Triage output updated";
  if (kind === "threat_intel" && text.includes("started")) return "Threat Intelligence started";
  if (kind === "threat_intel" && (text.includes("completed") || text.includes("updated") || text.includes("appended"))) return "Threat intelligence output updated";
  if (kind === "investigation" && text.includes("started")) return "Investigation Agent started";
  if (kind === "investigation" && (text.includes("completed") || text.includes("updated") || text.includes("appended"))) return "Investigation output updated";
  if (kind === "reporting" && text.includes("started")) return "Reporting Agent started";
  if (kind === "reporting" && (text.includes("completed") || text.includes("updated") || text.includes("appended") || text.includes("generated"))) return "Report output updated";
  if (kind === "approval" && text.includes("approved")) return "Approval decision recorded";
  if (kind === "approval" && text.includes("reject")) return "Rejection decision recorded";
  if (kind === "approval") return "Approval activity recorded";
  if (kind === "soc_review") return "SOC analyst review recorded";
  if (kind === "retry") return "Agent retry requested";
  if (kind === "closure") return "Case closure activity";
  if (kind === "alert") return "Alert linked to ticket";
  if (kind === "assignment") return "Ticket assignment updated";
  return titleCase(action || message || "Ticket activity recorded");
}

function timelineEventBadge(kind = "system") {
  return {
    parsing: "Parsing",
    triage: "Triage",
    threat_intel: "Threat Intel",
    investigation: "Investigation",
    reporting: "Reporting",
    triage_approval: "SOC Approval",
    investigation_approval: "SOC Approval",
    soc_review: "SOC Review",
    approval: "Approval",
    retry: "Retry",
    closure: "Closure",
    alert: "Alert",
    assignment: "Assignment",
    system: "System",
  }[kind] || "System";
}

function timelineEventIcon(kind = "system") {
  return {
    parsing: "ti-adjustments-code",
    triage: "ti-stethoscope",
    threat_intel: "ti-radar-2",
    investigation: "ti-search",
    reporting: "ti-file-report",
    triage_approval: "ti-shield-check",
    investigation_approval: "ti-shield-check",
    soc_review: "ti-clipboard-check",
    approval: "ti-shield-check",
    retry: "ti-refresh",
    closure: "ti-circle-check",
    alert: "ti-bell",
    assignment: "ti-user-check",
    system: "ti-settings",
  }[kind] || "ti-circle";
}

function titleCase(value = "") {
  return String(value || "")
    .replaceAll("_", " ")
    .split(" ")
    .filter(Boolean)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function compressTimelineEvents(events = []) {
  const sorted = [...events].sort((a, b) => b.timeMs - a.timeMs);
  const compressed = [];
  sorted.forEach(event => {
    const previous = compressed[compressed.length - 1];
    const sameEvent = previous
      && previous.actor === event.actor
      && previous.action === event.action
      && previous.message === event.message
      && Math.abs(previous.timeMs - event.timeMs) <= 10000;
    if (sameEvent) {
      previous.count = (previous.count || 1) + 1;
      return;
    }
    compressed.push({ ...event });
  });
  return compressed;
}

function renderTimelineAuditTrail(events = []) {
  if (!events.length) return `<div class="empty-state">No timeline activity recorded yet.</div>`;
  return `<div class="timeline-audit-trail">${events.map((event, index) => renderTimelineItem(event, index)).join("")}</div>`;
}

function renderTimelineItem(event = {}, index = 0) {
  const message = event.message || "Ticket activity recorded.";
  const expanded = state.timelineExpandedIndex === index;
  return `<article class="timeline-audit-item ${esc(event.kind)} ${expanded ? "expanded" : ""}">
    <button class="timeline-event-summary" data-action="toggle-timeline-event" data-index="${index}" aria-expanded="${expanded}">
      <span class="timeline-marker"><i class="ti ${esc(event.icon)}"></i></span>
      <time>${esc(timelineDateLabel(event.createdAt).replace(",", ""))}, ${esc(timelineTimeLabel(event.createdAt).toLowerCase())}</time>
      <span class="timeline-event-copy"><strong>${esc(event.title)}</strong><small>${esc(message)}</small></span>
      <span class="timeline-severity ${esc(event.severity)}">${esc(titleCase(event.severity))}</span>
      <span class="timeline-expand-symbol">${expanded ? "−" : "+"}</span>
    </button>
    ${expanded ? `<div class="timeline-event-details">
      <p>${esc(message)} This event was recorded by ${esc(event.actor || "System")} and is included in the incident investigation trail.</p>
      <div class="timeline-detail-grid">
        <div><span>Source</span><strong>${esc(event.actor || "System")}</strong></div>
        <div><span>Related Entities</span><strong>${esc(event.entities)}</strong></div>
        <div><span>Significance</span><strong>${esc(titleCase(event.severity))} security event</strong></div>
        <div><span>MITRE ATT&CK</span><strong>${esc(event.mitre)}</strong></div>
        <div><span>Evidence</span><strong>${esc(event.evidence)} item${event.evidence === 1 ? "" : "s"}</strong></div>
      </div>
      <div class="timeline-normalized"><span>Normalised Event</span><code>${esc(event.normalized)}</code></div>
      <div class="timeline-detail-actions">
        <button class="soc-btn ghost">View Supporting Evidence</button>
        <button class="soc-btn ghost">View in Entity Graph</button>
        <button class="soc-btn ghost">View MITRE Mapping</button>
      </div>
    </div>` : ""}
  </article>`;
}

function timelineDateLabel(value) {
  if (!value) return "Unknown date";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" });
}

function timelineTimeLabel(value) {
  if (!value) return "--:--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function approvalLog(t) {
  const approval = t.approval_result || {};
  return `<div class="activity-list">
    <div class="activity-item"><strong>${esc(approval.analyst || "SOC Analyst")}</strong><span>${esc(approval.decision || "No decision recorded")}</span><small>${esc(approval.comments || "No analyst comment yet.")}</small></div>
  </div>`;
}

function activityList(items) {
  items = arrayOf(items);
  if (!items.length) return `<div class="empty-state">No activity recorded yet.</div>`;
  return `<div class="activity-list">${items.map(a => `<div class="activity-item">
    <strong>${esc(a.actor || "System")} ${esc(String(a.action || "updated").replaceAll("_", " "))}</strong>
    <span>${esc(a.message)}</span><small>${esc(shortDate(a.created_at))}</small>
  </div>`).join("")}</div>`;
}

function reportsSection(t) {
  if (!t) return `<section class="panel"><div class="empty-state">Select a ticket to view generated reports.</div></section>`;
  return renderSocReportReviewWorkspace(t);
}

function askPanel(t) {
  const qs = ["Why is this case Critical?", "What evidence supports this case?", "What IOCs should I look for?", "Has this file been seen in other incidents?", "Summarise this case for a SOC manager.", "What should the analyst do next?"];
  return `<section class="ask-panel"><h3>Ask Agent</h3><div class="ask-chips">${qs.map(q => `<button data-question="${esc(q)}">${esc(q)}</button>`).join("")}</div><div class="ask-row"><input id="ask-input" placeholder="Ask about the selected ticket or alert..."><button class="soc-btn primary" data-action="ask-agent" data-ticket-id="${esc(t.ticket_id)}"><i class="ti ti-send"></i> Ask</button></div><div id="ask-answer"></div></section>`;
}

function alertsPage(historyMode = false) {
  const alerts = historyMode ? state.history : state.alerts;
  return `<section class="panel">
    <div class="panel-head">
      <h2>${historyMode ? "NetWitness Alert History" : "NetWitness Alerts"}</h2>
      <div class="panel-actions">
        <button class="soc-btn primary" data-action="${historyMode ? "search-history" : "sync-netwitness"}"><i class="ti ti-cloud-download"></i> ${historyMode ? "Search History" : "Pull Latest"}</button>
      </div>
    </div>
    ${historyMode ? historyFilters() : `<div class="searchbar wide"><i class="ti ti-search"></i><input id="alert-search" placeholder="Search alerts..." value="${esc(state.params.q || "")}"></div>`}
    <table class="soc-table"><thead><tr><th>Alert ID</th><th>Alert Name</th><th>First Seen</th><th>Last Seen</th><th>Severity</th><th>Status</th><th>Linked Ticket</th><th>Actions</th></tr></thead>
    <tbody>${alerts.length ? alerts.map(alertRow).join("") : `<tr><td colspan="8" class="empty-cell">No alerts loaded yet.</td></tr>`}</tbody></table>
  </section>`;
}

function alertRow(a) {
  const linked = a.linked_ticket;
  return `<tr><td class="mono">${esc(a.alert_id)}</td><td>${esc(a.alert_name)}</td><td class="mono">${esc(shortTime(a.first_seen))}</td><td class="mono">${esc(shortTime(a.last_seen))}</td><td>${severityBadge(a.severity)}</td><td>${badge(a.status)}</td><td>${linked ? esc(linked) : "Unlinked"}</td><td class="row-actions">
    <button class="soc-btn ghost compact" data-action="view-alert" data-alert-id="${esc(a.alert_id)}">View Alert</button>
    ${linked ? `<button class="soc-btn ghost compact" data-action="link-alert" data-alert-id="${esc(a.alert_id)}">Link to Existing</button>` : `<button class="soc-btn primary compact" data-action="create-ticket" data-alert-id="${esc(a.alert_id)}">Create New Ticket</button>`}
    ${a.netwitness_url ? `<a class="soc-btn ghost compact" href="${esc(a.netwitness_url)}" target="_blank">View in NetWitness</a>` : ""}
  </td></tr>`;
}

function historyFilters() {
  const fields = ["incident_id", "ticket_id", "hostname", "source_ip", "destination_ip", "file_hash", "username", "severity"];
  return `<div class="history-filters">${fields.map(f => `<label>${esc(f.replaceAll("_", " "))}<input id="hist-${f}" value="${esc(state.params[f] || "")}"></label>`).join("")}
    <label>Date range<select id="hist-range"><option value="24h">Last 24 hours</option><option value="7d">Past 7 days</option><option value="30d">Past 30 days</option></select></label>
  </div>`;
}

function integrationsPage() {
  const nw = state.integrations.netwitness || {};
  return `<section class="panel"><div class="panel-head"><h2>Integrations</h2><button class="soc-btn primary" data-action="sync-netwitness"><i class="ti ti-plug-connected"></i> Test by Sync</button></div>
    <div class="cards-4">${integrationCard("NetWitness", nw.configured, nw.base_url || "Not configured")}${integrationCard("Threat Intel", true, "VT / OTX / AbuseIPDB environment driven")}${integrationCard("LLM", true, "Ask Agent and reporting provider")}${integrationCard("Reports", true, "DOCX/PDF export backend")}</div>
  </section>`;
}

function integrationCard(name, ok, detail) {
  return `<div class="mini-card"><i class="ti ${ok ? "ti-circle-check" : "ti-alert-triangle"}"></i><strong>${esc(name)}</strong><span>${esc(detail)}</span>${badge(ok ? "Available" : "Missing", ok ? "green" : "red")}</div>`;
}

function simplePage(title, text) {
  return `<section class="panel"><h2>${esc(title)}</h2><div class="empty-state">${esc(text)}</div></section>`;
}

function render() {
  try {
    renderNav();
    header();
    const content = $("#content");
    if (!content) throw new Error("Missing #content render container.");
    const pages = {
      dashboard,
      "all-tickets": ticketsPage,
      "my-tickets": ticketsPage,
      "pending-approval": ticketsPage,
      "closed-cases": ticketsPage,
      "netwitness-alerts": () => alertsPage(false),
      "search-alerts": () => alertsPage(false),
      "alert-history": () => alertsPage(true),
      reports: () => state.selectedTicket ? `<div class="${dashboardGridClass()}"><section class="main-column">${reportsForTicket(state.selectedTicket)}</section>${ticketPanel()}</div>` : simplePage("Reports", "Select a ticket to generate and export reports."),
      templates: () => simplePage("Templates", "Report templates are connected through the existing reporting backend."),
      integrations: integrationsPage,
      settings: () => simplePage("Settings", "Workflow guardrails are enabled: sequential agents, ticket context, approval blocking, and explicit NetWitness fallback."),
      "audit-log": () => simplePage("Audit Log", "Ticket activity and agent updates are captured in each selected ticket timeline."),
      profile: () => simplePage("Profile", "Soong Yang, SOC Analyst."),
    };
    content.innerHTML = `${state.renderError ? errorPanel(state.renderError) : ""}${(pages[state.route] || dashboard)()}`;
  } catch (err) {
    const content = $("#content");
    if (content) content.innerHTML = errorPanel("The dashboard hit a rendering error.", err.message || String(err));
    console.error(err);
  }
}

async function loadTicket(ticketId) {
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}`);
  if (res.success) {
    state.selectedTicket = res.ticket;
    reconcileAgentRunGuards();
    // if user is in My Tickets, move to the selected ticket overview subsection
    if (state.route === "my-tickets") {
      setRoute("my-tickets/overview");
    } else {
      render();
    }
  } else toast(res.status || "Ticket not found", "red");
}

async function refreshSelectedTicket(ticketId, { renderAfter = true } = {}) {
  const id = ticketId || state.selectedTicket?.ticket_id;
  if (!id) return null;
  const res = await api(`/api/tickets/${encodeURIComponent(id)}`);
  if (res.success) {
    state.selectedTicket = res.ticket;
    reconcileAgentRunGuards();
    if (renderAfter) render();
    return res.ticket;
  }
  toast(res.status || "Ticket refresh failed", "red");
  if (renderAfter) render();
  return null;
}

async function loadTicketsWithParams() {
  const params = new URLSearchParams(state.params).toString();
  const res = await api(`/api/tickets${params ? `?${params}` : ""}`);
  if (res.success) {
    setApiError("");
    state.tickets = res.tickets || [];
    state.summary = res.summary || state.summary;
    const selectedInView = state.selectedTicket && state.tickets.some(t => t.ticket_id === state.selectedTicket.ticket_id);
    if (state.tickets.length && !selectedInView) await loadTicket(state.tickets[0].ticket_id);
    else render();
  } else {
    setApiError(res.status || "Unable to load tickets.");
    render();
  }
}

async function loadHistory(renderAfter = true) {
  const params = new URLSearchParams(state.params).toString();
  const res = await api(`/api/netwitness/history${params ? `?${params}` : ""}`);
  if (res.success === false) setApiError(res.status || "Unable to load NetWitness history.");
  else state.history = res.results || res.items || [];
  if (renderAfter) render();
}

async function continueParserWithAvailableData(ticketId) {
  if (!ticketId) return toast("Select a ticket first.", "yellow");
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/parsing/continue-available-data`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason: "Continue Parsing and Normalisation with available local ticket data." }),
  });
  if (res.success) {
    toast(res.message || "Parser continue-with-available-data request recorded.", "green");
    await refreshSelectedTicket(ticketId, { renderAfter: true });
  } else {
    toast(errorText(res, "Unable to continue parser with available data."), "red");
  }
}

async function action(name, el) {
  const ticketId = el.dataset.ticketId || state.selectedTicket?.ticket_id;
  const alertId = el.dataset.alertId;
  if (name === "view-ticket") return loadTicket(ticketId);
  if (name === "run-next") return runNext(ticketId);
  if (name === "run-correlation") return runAgent("correlation", ticketId, { routeToWorkspace: false });
  if (name === "confirm-correlation") return confirmCorrelation(el.dataset.recommendationId, ticketId);
  if (name === "reject-correlation") return rejectCorrelation(el.dataset.recommendationId, ticketId);
  if (name === "edit-correlation") return editCorrelation(el.dataset.recommendationId, ticketId);
  if (name === "move-alert") return moveAlert(alertId);
  if (name === "split-alert") return splitAlert(alertId);
  if (name === "merge-tickets") return mergeTickets(ticketId);
  if (name === "run-agent") return runAgent(el.dataset.agent, ticketId);
  if (name === "rerun-agent") return retryAgent(el.dataset.agent, ticketId);
  if (name === "continue-parser-available-data") return continueParserWithAvailableData(ticketId);
  if (name === "retry-agent") return retryAgent(el.dataset.agent, ticketId);
  if (name === "pause-agent") return pauseAgent(el.dataset.agent, ticketId, el.dataset.runId);
  if (name === "toggle-agent-card") return toggleAgentCard(el.dataset.agent);
  if (name === "select-agent") return selectAgent(el.dataset.agentKey);
  if (name === "toggle-panel") return togglePanel(el.dataset.panel);
  if (name === "toggle-timeline-event") {
    const index = Number(el.dataset.index);
    state.timelineExpandedIndex = state.timelineExpandedIndex === index ? null : index;
    return render();
  }
  if (name === "timeline-sort") {
    state.timelineSort = el.dataset.sort === "newest" ? "newest" : "oldest";
    state.timelineExpandedIndex = null;
    return render();
  }
  if (name === "reset-timeline-filters") {
    state.timelineFilters = { kind: "all", source: "all", severity: "all", entity: "all", tactic: "all" };
    state.timelineExpandedIndex = null;
    return render();
  }
  if (name === "toggle-ticket-preview") return toggleTicketPreview();
  if (name === "view-agent-output") return viewAgentOutput(el.dataset.agent, ticketId);
  if (name === "view-summary-json" || name === "download-agent-summary-json") return downloadAgentSummaryJson(el.dataset.agent || state.selectedAgentKey, ticketId);
  if (name === "download-reporting-data") return downloadReportingDataJson(ticketId);
  if (name === "export-agent-summary-word" || name === "download-agent-summary-word") return downloadAgentSummaryWord(el.dataset.agent || state.selectedAgentKey, ticketId);
  if (name === "export-agent-summary-pdf" || name === "download-agent-summary-pdf") return downloadAgentSummaryPdf(el.dataset.agent || state.selectedAgentKey, ticketId);
  if (name === "download-report-json") return downloadReportingReport(el.dataset.reportKey, ticketId, "json");
  if (name === "download-report-word") return downloadReportingReport(el.dataset.reportKey, ticketId, "word");
  if (name === "download-report-pdf") return downloadReportingReport(el.dataset.reportKey, ticketId, "pdf");
  if (name === "open-report-editor") return openStructuredReportEditor(ticketId, el.dataset.reportKey);
  if (name === "save-report-draft") return saveStructuredReportDraft(ticketId, el.dataset.reportKey);
  if (name === "confirm-report-section") return confirmStructuredReportSection(ticketId, el.dataset.reportKey);
  if (name === "assign-ticket") return assignTicket(ticketId);
  if (name === "sync-netwitness") return syncNetWitness();
  if (name === "continue-to-reporting") return evidenceGapDecision(ticketId, "continue_to_reporting");
  if (name === "return-to-triage") return evidenceGapDecision(ticketId, "return_to_triage");
  if (name === "approve-ticket") return decision(ticketId, "approve", el.dataset.gate || "");
  if (name === "reject-ticket") return decision(ticketId, "reject");
  if (name === "more-evidence") return decision(ticketId, "more");
  if (name === "confirm-soc-review") return confirmSocReview(ticketId);
  if (name === "create-ticket") return createTicket(alertId);
  if (name === "link-alert") return linkAlert(alertId);
  if (name === "remove-alert") return removeAlert(alertId);
  if (name === "view-alert") return viewAlert(alertId);
  if (name === "ask-agent") return askAgent(ticketId, el.dataset.agent || state.selectedAgentKey);
  if (name === "search-history") return searchHistoryFromInputs();
  if (name === "filter-search") return ticketSearch();
}

async function runNext(ticketId) {
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/run-next-step`, { method: "POST" });
  if (res.success) {
    toast("Agent run started for ticket.", "blue");
  } else if (isReadyForClosureResponse(res)) {
    openModal("Ticket ready for closure", "Workflow complete", `<div class="closure-modal-content"><p>All agent stages have produced ticket context. Review the reports or timeline, then close the case when your backend closure route is ready.</p><div class="panel-actions"><button class="soc-btn ghost" data-route="my-tickets/reports"><i class="ti ti-file-description"></i> Go to Reports</button><button class="soc-btn ghost" data-route="my-tickets/timeline"><i class="ti ti-history"></i> Go to Timeline</button></div></div>`);
  } else {
    openModal("Run Next Step blocked", "Workflow gate", `<pre>${esc(JSON.stringify(res, null, 2))}</pre>`);
  }
  await refresh();
  if (res.success && state.route === "my-tickets") {
    const activeAgent = activeAgentForSelectedTicket();
    const responseAgent = canonicalAgentKey(res.agent || res.agent_key || res.next_agent || res.run?.agent || res.run?.agent_key || "");
    if (activeAgent?.key) state.selectedAgentKey = activeAgent.key;
    else if (responseAgent) state.selectedAgentKey = responseAgent;
    state.agentWorkspacePreviewCollapsed = true;
    setRoute("my-tickets/agents");
    startLiveActivityLogPolling();
  }
}

async function runAgent(agent, ticketId, options = {}) {
  const agentKey = canonicalAgentKey(agent || "");
  if (!agentKey) return toast("Select an agent to run first.", "yellow");
  if (runIsActive(agentRunGuard(ticketId, agentKey))) return toast(`${agentLabel(agentKey)} is already processing.`, "yellow");
  state.selectedAgentKey = agentKey;
  const guard = markAgentRunStarting(agentKey, ticketId, "run");
  render();
  const endpoint = ticketId
    ? `/api/tickets/${encodeURIComponent(ticketId)}/agents/${encodeURIComponent(agentKey || agent)}/run`
    : `/api/run/${encodeURIComponent(agentKey || agent)}`;
  const res = await api(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ticket_id: ticketId, run_type: "run" }) });
  const currentGuard = updateAgentRunGuardFromResponse(agentKey, ticketId, guard.client_token, res);
  const trackingRun = res.success || responseIsExistingActiveRun(res);
  if (res.success) toast(`${agentLabel(agentKey || agent)} started.`, "blue");
  else if (trackingRun) toast(`${agentLabel(agentKey || agent)} is already running. Tracking latest run.`, "blue");
  else {
    markAgentRunGuardFailed(agentKey, ticketId, guard.client_token, errorText(res, "Agent run failed to start."));
    openModal("Agent run blocked", agentLabel(agentKey || agent), `<pre>${esc(JSON.stringify(res, null, 2))}</pre>`);
  }
  if (!currentGuard && trackingRun) return res;
  await refresh();
  if (trackingRun && agentKey) state.selectedAgentKey = agentKey;
  if (trackingRun && options.routeToWorkspace && state.route === "my-tickets") {
    state.agentWorkspacePreviewCollapsed = true;
    setRoute("my-tickets/agents");
    startLiveActivityLogPolling();
    return res;
  }
  if (trackingRun && state.route === "my-tickets" && state.subroute === "agents") {
    startLiveActivityLogPolling();
  }
  return res;
}

async function retryAgent(agent, ticketId) {
  const agentKey = canonicalAgentKey(agent || "");
  if (!agentKey) return toast("Select an agent to retry first.", "yellow");
  if (runIsActive(agentRunGuard(ticketId, agentKey))) return toast(`${agentLabel(agentKey)} is already processing.`, "yellow");
  if (isReadyForClosure(state.selectedTicket?.next_step || {}, state.selectedTicket)) {
    const downstream = {
      triage: "Approval, Investigation, and Reporting may need review after this retry.",
      investigation: "Reporting may need to be regenerated after this retry.",
      reporting: "The report output will be regenerated for the selected ticket.",
      approval: "Approval decisions should usually be changed through the approval controls.",
    }[agentKey] || "Downstream outputs may need review after this retry.";
    const ok = window.confirm(`Retry ${agentLabel(agentKey)}?

${downstream}

Continue?`);
    if (!ok) return;
  }
  state.selectedAgentKey = agentKey;
  const guard = markAgentRunStarting(agentKey, ticketId, "rerun");
  render();
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/agents/${encodeURIComponent(agentKey)}/rerun`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason: "SOC analyst requested agent re-run." }),
  });
  const currentGuard = updateAgentRunGuardFromResponse(agentKey, ticketId, guard.client_token, res);
  const trackingRun = res.success || responseIsExistingActiveRun(res);
  if (res.success) toast(`${agentLabel(agentKey)} re-run started.`, "blue");
  else if (trackingRun) toast(`${agentLabel(agentKey)} is already running. Tracking latest run.`, "blue");
  else {
    markAgentRunGuardFailed(agentKey, ticketId, guard.client_token, errorText(res, "Agent re-run failed to start."));
    openModal("Agent re-run blocked", agentLabel(agentKey), `<pre>${esc(JSON.stringify(res, null, 2))}</pre>`);
  }
  if (!currentGuard && trackingRun) return res;
  await refresh();
  if (trackingRun) {
    state.selectedAgentKey = agentKey;
    if (state.route === "my-tickets") {
      state.agentWorkspacePreviewCollapsed = true;
      setRoute("my-tickets/agents");
      startLiveActivityLogPolling();
    }
  }
}


async function pauseAgent(agent, ticketId, runId = "") {
  if (!ticketId || !agent) return toast("Select a running agent first.", "yellow");
  const payload = { ticket_id: ticketId, agent, run_id: runId || null };
  const headers = { "Content-Type": "application/json" };
  const attempts = [];
  if (runId) attempts.push(`/api/runs/${encodeURIComponent(runId)}/pause`);
  attempts.push(`/api/run/${encodeURIComponent(agent)}/pause`);
  attempts.push(`/api/tickets/${encodeURIComponent(ticketId)}/pause-agent`);

  let lastRes = null;
  for (const path of attempts) {
    const res = await api(path, { method: "POST", headers, body: JSON.stringify(payload) });
    lastRes = res;
    if (res.success) {
      stopLiveActivityLogPolling();
      toast(`${agentLabel(agent)} paused.`, "yellow");
      await refresh();
      return;
    }
    if (![404, 405].includes(res.http_status)) break;
  }

  openModal(
    "Pause Agent unavailable",
    agentLabel(agent),
    `<p class="empty-state">The pause button is wired in the dashboard, but the backend pause route is not available yet. Add a pause endpoint for active runs, then this button will pause the running agent process.</p><pre>${esc(JSON.stringify(lastRes || {}, null, 2))}</pre>`
  );
}

function viewAgentOutput(agent, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const agentKey = canonicalAgentKey(agent || "");
  if (shouldMaskAgentOutput(t, agentKey)) return toast("The latest run is still in progress or failed. Active output is not available yet.", "yellow");
  const key = summaryOutputKeyForAgent(agentKey);
  const payload = t[key] || {};
  if (!Object.keys(payload).length) return toast("No output has been written to this ticket yet.", "yellow");
  openModal(`${agentLabel(agent)} Output`, `Ticket ${t.ticket_id}`, `<pre>${esc(JSON.stringify(payload, null, 2))}</pre>`);
}

function agentLabel(agent) {
  const key = canonicalAgentKey(agent || "");
  return {
    correlation: "Incident Grouping",
    parsing: "Parsing & Normalisation",
    triage: "Triage Agent",
    threat_intel: "Threat Intelligence Enrichment",
    triage_approval: "SOC Analyst Approval",
    investigation: "Investigation Agent",
    investigation_approval: "SOC Analyst Approval",
    reporting: "Reporting Agent",
    soc_review: "SOC Analyst Review",
    approval: "Approval / Analyst Review",
  }[key] || "Agent";
}

async function assignTicket(ticketId) {
  const owner = "Soong Yang";
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/assign`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ owner, analyst: "Soong Yang" }) });
  if (res.success) { state.selectedTicket = res.ticket; toast(`Assigned to ${owner}.`, "green"); }
  await loadTicketsWithParams();
}

async function syncNetWitness() {
  const res = await api("/api/netwitness/sync", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(state.params) });
  state.lastNetWitnessSync = { ...res, completed_at: new Date().toISOString() };
  const failure = res.status || res.error || res.response_preview || "NetWitness sync failed.";
  toast(res.success ? (res.fallback ? "NetWitness unavailable; fallback alerts loaded explicitly." : `Synced ${res.synced || 0} alerts from NetWitness.`) : failure, res.success ? "green" : "red");
  await refresh();
}

async function autoConnectNetWitnessOnStartup() {
  if (state.netwitnessAutoConnectAttempted) return;
  state.netwitnessAutoConnectAttempted = true;
  const res = await api("/api/netwitness/sync", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ auto_connect: true })
  });
  state.lastNetWitnessSync = { ...res, completed_at: new Date().toISOString() };
  if (res.success) {
    if (Array.isArray(res.alerts)) state.alerts = res.alerts;
    await refresh();
  } else if (state.route === "netwitness-alerts" || state.route === "integrations") {
    toast(res.status || res.error || "NetWitness auto-connect failed.", "yellow");
  }
}

async function evidenceGapDecision(ticketId, decision) {
  if (!ticketId) return toast("Select a ticket first.", "yellow");
  const isReturn = decision === "return_to_triage";
  const comments = isReturn ? "Return to Triage Agent for more NetWitness evidence." : "Continue to Reporting Agent with investigation limitations documented.";
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/investigation/evidence-gap-decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision, analyst: "Soong Yang", comments })
  });
  if (res.success) {
    state.selectedTicket = res.ticket;
    toast(isReturn ? "Returned to Triage Agent for more evidence." : "Reporting Agent is ready with limitations.", "green");
  } else {
    toast(res.status || "Evidence-gap decision failed", "red");
  }
  await refresh();
}

async function decision(ticketId, kind, gate = "") {
  const requestKey = `${ticketId}:${gate || kind}`;
  if (state.approvalRequests[requestKey]) return toast("This approval request is already being recorded.", "yellow");
  state.approvalRequests[requestKey] = true;
  render();
  const endpoints = { approve: "approve", reject: "reject", more: "request-more-evidence" };
  try {
    const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/${endpoints[kind]}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ analyst: "Soong Yang", gate: gate || undefined, comments: kind === "more" ? "Requesting more evidence before continuing." : "" }) });
    if (res.success) { state.selectedTicket = res.ticket; toast("Analyst decision recorded. Staying on the current Agent Workspace.", "green"); }
    else toast(res.error || res.status || "Decision failed", "red");
    await refresh();
  } finally {
    delete state.approvalRequests[requestKey];
  }
}

async function confirmSocReview(ticketId) {
  if (!ticketId) return toast("Select a ticket first.", "yellow");
  openActionModal({
    title: "Confirm SOC Review",
    sub: `Ticket ${ticketId}`,
    summary: `<div class="impact-box"><strong>What happens after approval</strong><ul><li>The report review is recorded in the activity log.</li><li>The ticket can proceed towards case closure.</li><li>Generated report sections remain auditable.</li></ul></div>`,
    fields: [{ type: "textarea", name: "comments", label: "SOC analyst comments", value: "Report reviewed and accepted for case closure.", required: true }],
    confirmText: "Confirm SOC Review",
    onSubmit: async ({ comments }) => {
      const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/confirm-soc-review`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: "confirmed", comments, analyst: "Soong Yang" })
      });
      if (res.success) { toast("SOC analyst review confirmed.", "green"); state.selectedTicket = res.ticket; closeModal(); }
      else toast(errorText(res, "Unable to confirm SOC review"), "red");
      await refresh();
    }
  });
}

async function confirmCorrelation(recommendationId, ticketId) {
  if (!recommendationId) return toast("Missing recommendation id.", "yellow");
  const rec = arrayOf(state.selectedTicket?.correlation_recommendations).find(r => r.recommendation_id === recommendationId) || {};
  const archiveRequired = rec.requires_archive_approval || rec.archive_after_approval || norm(rec.recommendation_type).includes("archive") || norm(rec.recommendation_type).includes("merge");
  openActionModal({
    title: archiveRequired ? "Approve Grouping & Archive" : "Confirm Alert Grouping",
    sub: `Recommendation ${recommendationId}`,
    summary: `<div class="impact-box ${archiveRequired ? "danger" : ""}"><strong>Recommended action</strong><p>${esc(rec.reason || "Confirm the agent's grouping recommendation.")}</p><ul><li>Target ticket: ${esc(rec.target_ticket_id || ticketId || "selected ticket")}</li><li>Source alert/ticket: ${esc(rec.source_alert_id || rec.source_ticket_id || "not specified")}</li>${archiveRequired ? `<li>Duplicate tickets will be archived, not deleted.</li><li>Evidence remains auditable in the original ticket history.</li>` : `<li>The alert will be added to the selected incident ticket.</li>`}<li>Downstream context will be marked for review or re-run if required.</li></ul></div>`,
    fields: [{ type: "textarea", name: "comments", label: "Analyst approval comments", value: "Confirmed grouping/archive recommendation after analyst review.", required: true }],
    confirmText: archiveRequired ? "Approve Grouping & Archive" : "Confirm Grouping",
    danger: archiveRequired,
    onSubmit: async ({ comments }) => {
      const res = await api(`/api/correlation/recommendations/${encodeURIComponent(recommendationId)}/confirm`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analyst: "Soong Yang", comments })
      });
      if (res.success) { state.selectedTicket = res.ticket; toast("Grouping confirmed. Duplicate archive actions were applied only after approval.", "green"); closeModal(); }
      else toast(errorText(res, "Incident grouping approval failed"), "red");
      await refresh();
    }
  });
}

async function rejectCorrelation(recommendationId, ticketId) {
  if (!recommendationId) return toast("Missing recommendation id.", "yellow");
  const rec = arrayOf(state.selectedTicket?.correlation_recommendations).find(r => r.recommendation_id === recommendationId) || {};
  openActionModal({
    title: "Reject Incident Grouping Recommendation",
    sub: `Recommendation ${recommendationId}`,
    summary: `<div class="impact-box"><strong>Impact</strong><p>The suggested link will not become part of the official incident grouping. Rejected alerts will not be used as confirmed evidence in the final report.</p><p class="muted">Reason: ${esc(rec.reason || "No agent reason provided.")}</p></div>`,
    fields: [{ type: "textarea", name: "comments", label: "Reason for rejection", value: "Not related to this incident.", required: true }],
    confirmText: "Reject Recommendation",
    danger: true,
    onSubmit: async ({ comments }) => {
      const res = await api(`/api/correlation/recommendations/${encodeURIComponent(recommendationId)}/reject`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analyst: "Soong Yang", comments })
      });
      if (res.success) { if (res.ticket) state.selectedTicket = res.ticket; toast("Incident grouping recommendation rejected.", "green"); closeModal(); }
      else toast(errorText(res, "Incident grouping rejection failed"), "red");
      await refresh();
    }
  });
}

async function editCorrelation(recommendationId, ticketId) {
  if (!recommendationId) return toast("Missing recommendation id.", "yellow");
  openActionModal({
    title: "Edit Incident Grouping Target",
    sub: `Recommendation ${recommendationId}`,
    summary: `<div class="impact-box"><strong>Analyst override</strong><p>Choose the ticket this recommended alert or duplicate should belong to. The override is recorded in the activity log.</p></div>`,
    fields: [
      { type: "select", name: "target_ticket_id", label: "Target ticket", options: optionListForTickets(ticketId || state.selectedTicket?.ticket_id || ""), required: true },
      { type: "textarea", name: "comments", label: "Analyst reason", value: "Related, but belongs to a different incident ticket.", required: true }
    ],
    confirmText: "Apply Edited Grouping",
    onSubmit: async ({ target_ticket_id, comments }) => {
      const res = await api(`/api/correlation/recommendations/${encodeURIComponent(recommendationId)}/edit`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analyst: "Soong Yang", target_ticket_id, comments })
      });
      if (res.success) { state.selectedTicket = res.ticket; toast("Incident grouping edited and applied.", "green"); closeModal(); }
      else toast(errorText(res, "Incident grouping edit failed"), "red");
      await refresh();
    }
  });
}

async function moveAlert(alertId) {
  if (!state.selectedTicket || !alertId) return toast("Select a ticket and alert first.", "yellow");
  openActionModal({
    title: "Move Alert to Another Ticket",
    sub: alertId,
    summary: `<div class="impact-box"><strong>What happens after approval</strong><ul><li>The alert is removed from the current ticket.</li><li>The alert is added to the selected target ticket.</li><li>The move is recorded as an analyst override.</li><li>Downstream triage/investigation/reporting context is marked for refresh.</li></ul></div>`,
    fields: [
      { type: "select", name: "target_ticket_id", label: "Target ticket", options: optionListForTickets(state.selectedTicket.ticket_id), required: true },
      { type: "textarea", name: "reason", label: "Reason for moving this alert", value: "Analyst manually reassigned alert grouping.", required: true }
    ],
    confirmText: "Move Alert",
    onSubmit: async ({ target_ticket_id, reason }) => {
      const res = await api(`/api/tickets/${encodeURIComponent(state.selectedTicket.ticket_id)}/move-alert`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: alertId, target_ticket_id, analyst: "Soong Yang", reason })
      });
      if (res.success) { state.selectedTicket = res.ticket; toast("Alert moved.", "green"); closeModal(); }
      else toast(errorText(res, "Move failed"), "red");
      await refresh();
    }
  });
}

async function splitAlert(alertId) {
  if (!state.selectedTicket || !alertId) return toast("Select a ticket and alert first.", "yellow");
  openActionModal({
    title: "Split Alert into New Ticket",
    sub: alertId,
    summary: `<div class="impact-box"><strong>What happens after approval</strong><ul><li>The alert is removed from ${esc(state.selectedTicket.ticket_id)}.</li><li>A new incident ticket is created for this alert.</li><li>The original ticket remains auditable.</li></ul></div>`,
    fields: [{ type: "textarea", name: "reason", label: "Reason for split", value: "Analyst split alert into a separate incident.", required: true }],
    confirmText: "Split into New Ticket",
    danger: true,
    onSubmit: async ({ reason }) => {
      const res = await api(`/api/tickets/${encodeURIComponent(state.selectedTicket.ticket_id)}/split-alert`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: alertId, analyst: "Soong Yang", reason })
      });
      if (res.success) { state.selectedTicket = res.ticket; toast("Alert split into a new ticket.", "green"); closeModal(); setRoute("all-tickets"); }
      else toast(errorText(res, "Split failed"), "red");
      await refresh();
    }
  });
}

async function mergeTickets(ticketId = state.selectedTicket?.ticket_id) {
  if (!ticketId) return toast("Select a target ticket first.", "yellow");
  openActionModal({
    title: "Merge Another Ticket Into This Incident",
    sub: `Target ticket ${ticketId}`,
    summary: `<div class="impact-box danger"><strong>Archive impact</strong><ul><li>Alerts from the source ticket will be moved into ${esc(ticketId)}.</li><li>The source ticket will be marked as Archived Duplicate by default.</li><li>No evidence is deleted. The archived ticket remains auditable.</li><li>Investigation/reporting context will be marked for refresh.</li></ul></div>`,
    fields: [
      { type: "select", name: "source_ticket_id", label: "Source ticket to merge", options: optionListForTickets(""), required: true },
      { type: "textarea", name: "reason", label: "Reason for merge", value: "Analyst confirmed these tickets belong to the same incident.", required: true },
      { type: "checkbox", name: "archive_duplicate", label: "Archive source ticket as duplicate after merge", checked: true }
    ],
    confirmText: "Merge & Archive Duplicate",
    danger: true,
    onSubmit: async ({ source_ticket_id, reason, archive_duplicate }) => {
      if (source_ticket_id === ticketId) return toast("Source and target ticket cannot be the same.", "yellow");
      const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/merge`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_ticket_id, target_ticket_id: ticketId, analyst: "Soong Yang", reason, archive_duplicate })
      });
      if (res.success) { state.selectedTicket = res.ticket; toast("Tickets merged. Source ticket archive status updated.", "green"); closeModal(); }
      else toast(errorText(res, "Ticket merge failed"), "red");
      await refresh();
    }
  });
}

async function createTicket(alertId) {
  const res = await api(`/api/tickets/from-alert/${encodeURIComponent(alertId)}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ owner: "Unassigned" }) });
  if (res.success) { state.selectedTicket = res.ticket; toast("Ticket created from alert.", "green"); setRoute("all-tickets"); }
  else toast(errorText(res, "Could not create ticket"), "red");
}

async function linkAlert(alertId) {
  if (!state.selectedTicket) return toast("Select a ticket first.", "yellow");
  const res = await api(`/api/tickets/${encodeURIComponent(state.selectedTicket.ticket_id)}/link-alert`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alert_id: alertId, relationship: "Related NetWitness alert", analyst: "Soong Yang" }) });
  if (res.success) { state.selectedTicket = res.ticket; toast("Alert linked to ticket.", "green"); }
  else toast(errorText(res, "Link failed"), "red");
  render();
}

async function removeAlert(alertId) {
  if (!state.selectedTicket || !alertId) return;
  openActionModal({
    title: "Remove Alert from Ticket",
    sub: alertId,
    summary: `<div class="impact-box danger"><strong>What happens after approval</strong><ul><li>The alert will be removed from this ticket grouping.</li><li>The alert record is not deleted.</li><li>The removal is recorded in the activity log.</li></ul></div>`,
    fields: [{ type: "textarea", name: "reason", label: "Reason for removal", value: "Analyst confirmed this alert is not related to this incident.", required: true }],
    confirmText: "Remove Alert",
    danger: true,
    onSubmit: async ({ reason }) => {
      const res = await api(`/api/tickets/${encodeURIComponent(state.selectedTicket.ticket_id)}/unlink-alert`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: alertId, analyst: "Soong Yang", reason })
      });
      if (res.success) { state.selectedTicket = res.ticket; toast("Alert removed from ticket.", "green"); closeModal(); render(); }
      else toast(errorText(res, "Remove failed"), "red");
    }
  });
}


async function viewAlert(alertId) {
  const res = await api(`/api/netwitness/alerts/${encodeURIComponent(alertId)}`);
  openModal("Alert Detail", alertId, `<pre>${esc(JSON.stringify(res.alert || res, null, 2))}</pre>`);
}

async function askAgent(ticketId, agentKey = state.selectedAgentKey) {
  const input = $("#ask-input-workspace") || $("#ask-input");
  const question = input?.value?.trim();
  if (!question) return toast("Enter a question first.", "yellow");
  const key = askAnswerKey(ticketId, agentKey);
  state.askAgentAnswers[key] = {
    status: "thinking",
    question,
    answer: `Thinking with selected ticket and ${agentLabel(agentKey)} context...`,
    ticket_id: ticketId,
    agent: agentKey,
    updated_at: new Date().toISOString(),
  };
  render();
  try {
    const res = await api("/api/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question, agent: agentKey || "SOC Assistant", ticket_id: ticketId }) });
    const failed = res.success === false || res.http_status >= 400;
    state.askAgentAnswers[key] = {
      status: failed ? "error" : "answered",
      question,
      answer: askAgentResponseText(res),
      ticket_id: ticketId,
      agent: agentKey,
      updated_at: new Date().toISOString(),
    };
  } catch (err) {
    state.askAgentAnswers[key] = {
      status: "error",
      question,
      answer: `Ask Agent failed: ${err.message || err}`,
      ticket_id: ticketId,
      agent: agentKey,
      updated_at: new Date().toISOString(),
    };
  }
  render();
}

function searchHistoryFromInputs() {
  const fields = ["incident_id", "ticket_id", "hostname", "source_ip", "destination_ip", "file_hash", "username", "severity"];
  const params = {};
  fields.forEach(f => { const v = $(`#hist-${f}`)?.value?.trim(); if (v) params[f] = v; });
  params.range = $("#hist-range")?.value || "24h";
  setRoute("alert-history", params);
}

function ticketSearch() {
  const q = $("#ticket-search")?.value?.trim();
  setRoute(isTicketRoute() ? state.route : "all-tickets", q ? { q } : {});
}

async function confirmReport() {
  const res = await api("/api/reports/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ analyst: "Soong Yang" }) });
  toast(res.success ? "Report confirmed." : (res.status || "Report confirmation failed."), res.success ? "green" : "red");
}

async function exportReport(type) {
  const res = await api(`/api/reports/export/${encodeURIComponent(type)}`, { method: "POST" });
  toast(res.success ? `${type.toUpperCase()} export ready.` : (res.status || "Export failed."), res.success ? "green" : "red");
  if (res.download_url) window.open(res.download_url, "_blank");
}

function compactIocs(iocs) {
  if (!Array.isArray(iocs) || !iocs.length) return "None recorded";
  return iocs.slice(0, 4).map(i => typeof i === "string" ? i : (i.value || i.indicator || JSON.stringify(i))).join(", ");
}

function shortDate(value) {
  if (!value) return "Unknown";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

function shortTime(value) {
  if (!value) return "--";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleTimeString();
}

document.addEventListener("submit", (event) => {
  const form = event.target.closest("#action-modal-form");
  if (!form) return;
  event.preventDefault();
  if (typeof window.__modalSubmitHandler === "function") {
    window.__modalSubmitHandler(formPayload(form));
  }
});

document.addEventListener("click", (event) => {
  const routeEl = event.target.closest("[data-route]");
  if (routeEl) {
    event.preventDefault();
    const params = routeEl.dataset.params ? JSON.parse(routeEl.dataset.params) : {};
    setRoute(routeEl.dataset.route, params);
    return;
  }
  const actionEl = event.target.closest("[data-action]");
  if (actionEl) {
    event.preventDefault();
    if (actionEl.disabled) return toast(actionEl.title || "Action is currently disabled.", "yellow");
    action(actionEl.dataset.action, actionEl);
    return;
  }
  const row = event.target.closest("tr[data-ticket-id]");
  if (row && !event.target.closest("button,a")) loadTicket(row.dataset.ticketId);
  const tab = event.target.closest("[data-tab]");
  if (tab) { state.ticketTab = tab.dataset.tab; render(); }
  const q = event.target.closest("[data-question]");
  if (q) { 
    const input = $("#ask-input-workspace") || $("#ask-input");
    if (input) input.value = q.dataset.question;
  }
  if (event.target.closest("[data-close-modal]") || event.target.id === "modal-backdrop") closeModal();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && event.target.id === "ticket-search") ticketSearch();
  if (event.key === "Enter" && event.target.id === "alert-search") {
    const q = event.target.value.trim();
    setRoute("netwitness-alerts", q ? { q } : {});
  }
  if (event.key === "Escape") closeModal();
});

document.addEventListener("change", (event) => {
  const filter = event.target.closest("[data-timeline-filter]");
  if (!filter) return;
  state.timelineFilters[filter.dataset.timelineFilter] = filter.value;
  state.timelineExpandedIndex = null;
  render();
});

window.addEventListener("hashchange", () => {
  readRoute();
  if (isTicketRoute()) {
    const params = { ...state.params };
    const routeDefaults = navGroups.flatMap(g => g.items).find(i => i.id === state.route)?.params || {};
    state.params = { ...routeDefaults, ...params };
    loadTicketsWithParams();
  } else {
    refresh();
  }
});

$("#collapse-btn")?.addEventListener("click", () => document.body.classList.toggle("collapsed"));

readRoute();
render();
const startupLoad = isTicketRoute() ? (() => {
  const routeDefaults = navGroups.flatMap(g => g.items).find(i => i.id === state.route)?.params || {};
  state.params = { ...routeDefaults, ...state.params };
  return loadTicketsWithParams();
})() : refresh();
startupLoad.then(() => autoConnectNetWitnessOnStartup()).catch(() => autoConnectNetWitnessOnStartup());
// Do not poll the entire dashboard. refresh() replaces #content, which interrupts
// searches, editable reports, focus, and scroll position. Active agent runs use
// startLiveActivityLogPolling(); user actions refresh their own affected data.

// ==================== AGENT-CENTRIC LIVE ACTIVITY LOG OVERRIDE ====================
// Purpose: keep Timeline as the ticket audit trail, while Live Activity Log shows the selected agent's working progress.
function agentWorkingObjective(agent = {}) {
  const key = canonicalAgentKey(agent.key || agent.label || "");
  return {
    triage: "Assess alert severity, confidence, evidence quality, and recommended next action.",
    investigation: "Validate triage context, examine related evidence, and confirm affected assets or IOCs.",
    reporting: "Turn validated investigation context into analyst-ready report sections.",
    approval: "Review the decision gate and record the analyst approval outcome.",
  }[key] || "Work through the selected ticket context and update the case.";
}

function liveThinkingTitleFromMessage(message = "", agent = {}, index = 0) {
  const text = String(message || "").toLowerCase();
  const key = canonicalAgentKey(agent.key || agent.label || "");
  if (text.includes("load") || text.includes("read") || text.includes("context")) return "Reading case context";
  if (text.includes("extract") || text.includes("entity") || text.includes("ioc")) return "Extracting useful signals";
  if (text.includes("threat") || text.includes("intel") || text.includes("virus") || text.includes("otx")) return "Checking threat intelligence";
  if (text.includes("severity") || text.includes("confidence") || text.includes("risk")) return "Scoring risk and confidence";
  if (text.includes("approval") || text.includes("decision") || text.includes("gate")) return "Checking analyst decision gate";
  if (text.includes("netwitness") || text.includes("telemetry") || text.includes("alert")) return "Reviewing telemetry and linked alerts";
  if (text.includes("investigation") || text.includes("asset") || text.includes("evidence")) return "Investigating evidence";
  if (text.includes("report") || text.includes("template") || text.includes("section")) return "Preparing report content";
  if (text.includes("map") || text.includes("playbook") || text.includes("sop") || text.includes("policy")) return "Applying SOC playbook";
  if (text.includes("write") || text.includes("save") || text.includes("append") || text.includes("output")) return "Writing result back to ticket";
  if (text.includes("fail") || text.includes("error") || text.includes("exception")) return "Handling execution issue";
  if (runIsActive(currentAgentRun(agent))) return "Working on current step";
  return {
    triage: ["Reading alert context", "Checking evidence", "Applying triage policy", "Preparing triage decision", "Updating ticket"],
    investigation: ["Reading ticket context", "Checking prerequisites", "Reviewing evidence", "Building findings", "Updating investigation output"],
    reporting: ["Reading investigation context", "Validating report fields", "Drafting report sections", "Checking report completeness", "Saving report output"],
    approval: ["Reading recommendation", "Checking approval gate", "Recording decision", "Updating workflow", "Unlocking next stage"],
  }[key]?.[index] || `Working step ${index + 1}`;
}

function liveThinkingStateFromText(text = "", fallback = "pending") {
  const value = String(text || "").toLowerCase();
  if (value.includes("fail") || value.includes("error") || value.includes("exception") || value.includes("rejected")) return "failed";
  if (value.includes("blocked") || value.includes("locked") || value.includes("waiting")) return "blocked";
  if (value.includes("complete") || value.includes("success") || value.includes("written") || value.includes("saved") || value.includes("appended")) return "done";
  if (value.includes("start") || value.includes("running") || value.includes("load") || value.includes("read") || value.includes("check") || value.includes("review") || value.includes("query") || value.includes("map") || value.includes("generat") || value.includes("validat") || value.includes("extract")) return "active";
  return fallback;
}

function liveThinkingIconForState(state = "pending") {
  return {
    done: "ti-check",
    active: "ti-loader-2",
    failed: "ti-alert-triangle",
    blocked: "ti-lock",
    pending: "ti-circle-dot",
    info: "ti-sparkles",
  }[state] || "ti-sparkles";
}

function liveThinkingStateLabel(state = "pending") {
  return {
    done: "Done",
    active: "Working",
    failed: "Issue",
    blocked: "Blocked",
    pending: "Queued",
    info: "Note",
  }[state] || "Note";
}

function liveThinkingTimestamp(value) {
  if (!value) return "Now";
  const str = String(value);
  if (/^\d{1,2}:\d{2}/.test(str)) return str;
  const d = new Date(str);
  if (Number.isNaN(d.getTime())) return str;
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function normalizeThinkingLogEntry(entry, index, agent = {}, defaultState = "pending") {
  if (entry && typeof entry === "object") {
    const rawMessage = String(entry.message || entry.detail || entry.description || entry.current_step || entry.step || entry.label || entry.name || "Agent is processing ticket context.").trim();
    const timestamp = entry.timestamp || entry.created_at || entry.updated_at || entry.time || entry.started_at || entry.completed_at || "";
    const explicit = norm(entry.state || entry.status || "");
    const state = explicit ? (explicit === "completed" ? "done" : explicit === "running" || explicit === "in_progress" ? "active" : explicit) : liveThinkingStateFromText(rawMessage, defaultState);
    return {
      title: entry.title || liveThinkingTitleFromMessage(rawMessage, agent, index),
      message: rawMessage,
      timestamp,
      state,
      sequence: index + 1,
      focus: entry.focus || entry.source || agent.label || "Selected Agent",
    };
  }

  const raw = String(entry || "").trim();
  const timeMatch = raw.match(/^\[([^\]]+)\]\s*(.*)$/);
  const timestamp = timeMatch ? timeMatch[1] : "";
  const message = timeMatch ? timeMatch[2].trim() : raw;
  return {
    title: liveThinkingTitleFromMessage(message, agent, index),
    message: message || "Agent is processing ticket context.",
    timestamp,
    state: liveThinkingStateFromText(message, defaultState),
    sequence: index + 1,
    focus: agent.label || "Selected Agent",
  };
}

function liveThinkingEntriesFromRun(agent = {}, run = null) {
  if (!run) return [];
  const rawLogs = [
    ...arrayOf(run.logs),
    ...arrayOf(run.log_lines),
    ...arrayOf(run.steps),
    ...arrayOf(run.events),
  ];
  const defaultState = runIsActive(run) ? "active" : runIsCompleted(run) ? "done" : runIsFailed(run) ? "failed" : "pending";
  return rawLogs.slice(-30).map((entry, index) => normalizeThinkingLogEntry(entry, index, agent, defaultState));
}

function liveThinkingEntriesFromOperationalSteps(agent = {}, run = null) {
  return agentOperationalSteps(agent, run).map((step, index) => ({
    title: liveThinkingTitleFromMessage(step.label, agent, index),
    message: step.label,
    timestamp: step.state === "active" ? "Now" : "",
    state: step.state === "done" ? "done" : step.state === "active" ? "active" : step.state === "failed" ? "failed" : step.state === "blocked" ? "blocked" : "pending",
    sequence: index + 1,
    focus: agent.label || "Selected Agent",
  }));
}

function buildLiveLogEntries(ticket = {}, agent = {}, run = null) {
  const fromRun = liveThinkingEntriesFromRun(agent, run);
  if (fromRun.length) return fromRun;
  // Do not fall back to ticket.activity_log here. That belongs to the Timeline, not the Live Activity Log.
  return liveThinkingEntriesFromOperationalSteps(agent, run);
}

function currentThinkingFocus(entries = [], agent = {}) {
  const active = entries.find(entry => entry.state === "active");
  const failed = entries.find(entry => entry.state === "failed");
  const latestDone = [...entries].reverse().find(entry => entry.state === "done");
  if (failed) return failed.title || "Execution issue";
  if (active) return active.title || "Working";
  if (latestDone) return latestDone.title || "Completed";
  return agentWorkingObjective(agent);
}

function renderLiveLogTrace(entries = [], agent = {}, run = null) {
  if (!entries.length) return `<div class="empty-state">No working progress is available for this agent yet.</div>`;
  const runStatus = runIsActive(run) ? "active" : runIsCompleted(run) ? "done" : runIsFailed(run) ? "failed" : "info";
  return `<div class="agent-thinking-flow ${esc(runStatus)}">
    ${entries.map((entry, index) => {
      const state = entry.state || "pending";
      return `<article class="agent-thinking-step ${esc(state)}">
        <div class="thinking-step-index">
          <span>${esc(index + 1)}</span>
          <i class="ti ${esc(liveThinkingIconForState(state))}"></i>
        </div>
        <div class="thinking-step-card">
          <div class="thinking-step-head">
            <strong>${esc(entry.title || liveThinkingTitleFromMessage(entry.message, agent, index))}</strong>
            <span class="thinking-state-pill ${esc(state)}">${esc(liveThinkingStateLabel(state))}</span>
          </div>
          <p>${esc(entry.message || "Agent is processing ticket context.")}</p>
          <div class="thinking-step-meta">
            <span><i class="ti ti-target-arrow"></i>${esc(entry.focus || agent.label || "Selected Agent")}</span>
            <span><i class="ti ti-clock"></i>${esc(liveThinkingTimestamp(entry.timestamp))}</span>
          </div>
        </div>
      </article>`;
    }).join("")}
  </div>`;
}

function renderAgentLiveActivityLog(ticket) {
  const isCollapsed = state.collapsedPanels["log-panel"];
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";

  const run = currentAgentRun(agent);
  const progress = agentProgressPercent(agent, run);
  const status = effectiveAgentStatus(agent, run);
  const entries = buildLiveLogEntries(ticket, agent, run);
  const doneCount = entries.filter(entry => entry.state === "done").length;
  const activeCount = entries.filter(entry => entry.state === "active").length;
  const pendingCount = entries.filter(entry => entry.state === "pending").length;
  const failedCount = entries.filter(entry => entry.state === "failed").length;
  const focus = currentThinkingFocus(entries, agent);
  const subtitle = runIsActive(run)
    ? "Live view of what the selected agent is doing now"
    : "Latest working progress for the selected agent";

  return `<div class="agent-live-log-panel agent-thinking-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="log-panel">
      <div>
        <h3><i class="ti ti-brain"></i> Agent Working Progress</h3>
        <small>${esc(subtitle)}</small>
      </div>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body agent-thinking-body">
      <div class="thinking-focus-card ${esc(status)}">
        <div>
          <span>Current focus</span>
          <strong>${esc(focus)}</strong>
          <p>${esc(agentWorkingObjective(agent))}</p>
        </div>
        <div class="thinking-progress-chip"><strong>${esc(progress)}%</strong><span>${esc(displayAgentStatus(agent, run))}</span></div>
      </div>
      <div class="thinking-metrics-row">
        <div class="thinking-metric"><span>Done</span><strong>${esc(doneCount)}</strong></div>
        <div class="thinking-metric active"><span>Working</span><strong>${esc(activeCount)}</strong></div>
        <div class="thinking-metric"><span>Queued</span><strong>${esc(pendingCount)}</strong></div>
        <div class="thinking-metric failed"><span>Issues</span><strong>${esc(failedCount)}</strong></div>
      </div>
      ${renderLiveLogTrace(entries, agent, run)}
    </div>` : ""}
  </div>`;
}


// ==================== DEEP AGENT WORKING PROGRESS OVERRIDE ====================
// This section renders a structured, explainable agent progress view.
// It intentionally shows a reasoning summary and evidence trace, not hidden model chain-of-thought.
function reasoningOutputKeyForAgent(agent = {}) {
  const key = canonicalAgentKey(agent.key || agent.label || "");
  return summaryOutputKeyForAgent(key);
}


function selectedAgentOutput(ticket = {}, agent = {}) {
  if (shouldMaskAgentOutput(ticket, agent.key || agent.label)) return {};
  const key = reasoningOutputKeyForAgent(agent);
  const output = ticket?.[key];
  return output && typeof output === "object" ? output : {};
}

function firstMeaningfulValue(...values) {
  for (const value of values) {
    if (value == null) continue;
    if (Array.isArray(value) && value.length) return value;
    if (typeof value === "object" && Object.keys(value).length) return value;
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" || typeof value === "boolean") return String(value);
  }
  return "";
}

function listifyReasoningValue(value, fallback = []) {
  if (Array.isArray(value)) return value.filter(Boolean).map(item => typeof item === "string" ? item : firstMeaningfulValue(item.value, item.indicator, item.label, item.name, item.message, item.summary, JSON.stringify(item)));
  if (value && typeof value === "object") {
    return Object.entries(value).slice(0, 6).map(([key, val]) => `${key.replaceAll("_", " ")}: ${typeof val === "object" ? JSON.stringify(val) : val}`);
  }
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return fallback;
}

function limitReasoningList(items = [], max = 5) {
  const cleaned = arrayOf(items).map(item => String(item || "").trim()).filter(Boolean);
  const unique = [];
  cleaned.forEach(item => {
    if (!unique.some(existing => existing.toLowerCase() === item.toLowerCase())) unique.push(item);
  });
  return unique.slice(0, max);
}

function reasoningContextLoaded(ticket = {}, agent = {}) {
  const key = canonicalAgentKey(agent.key || agent.label || "");
  const relatedAlerts = arrayOf(ticket.related_alerts).length;
  const assets = arrayOf(ticket.affected_assets).length;
  const iocs = arrayOf(ticket.iocs).length;
  const base = [
    ticket.ticket_id ? `Selected ticket: ${ticket.ticket_id}` : "Selected ticket context",
    ticket.severity ? `Severity: ${ticket.severity}` : "Severity not confirmed yet",
    ticket.confidence ? `Confidence: ${ticket.confidence}` : "Confidence not confirmed yet",
    `${relatedAlerts} related alert${relatedAlerts === 1 ? "" : "s"} linked`,
    `${assets} affected asset${assets === 1 ? "" : "s"} recorded`,
    `${iocs} IOC${iocs === 1 ? "" : "s"} available`,
  ];
  const agentSpecific = {
    parsing: ["Raw NetWitness alert", "Parser aliases", "SOC normalisation rules"],
    correlation: ["Confirmed linked alerts", "Open NetWitness alerts", "Host/user/IOC/time-window matching"],
    triage: ["Normalised alert context", "SOC triage policy"],
    threat_intel: ["Extracted IOCs", "VirusTotal", "AbuseIPDB", "AlienVault OTX"],
    investigation: ["Triage result", "Threat intelligence result", "Approval decision state", "Related NetWitness alert evidence"],
    reporting: ["Investigation result", "Second approval decision", "Report templates", "Required reporting fields"],
    approval: ["Triage recommendation", "Containment approval policy", "Analyst decision gate"],
  }[key] || ["Ticket context", "Workflow state"];
  return limitReasoningList([...base, ...agentSpecific], 8);
}

function reasoningEvidenceConsidered(ticket = {}, agent = {}, output = {}) {
  const relatedAlerts = arrayOf(ticket.related_alerts).slice(0, 3).map(alert => firstMeaningfulValue(alert.alert_name, alert.name, alert.alert_id, "Related alert"));
  const assets = arrayOf(ticket.affected_assets).slice(0, 3).map(asset => typeof asset === "string" ? `Affected asset: ${asset}` : `Affected asset: ${firstMeaningfulValue(asset.hostname, asset.host, asset.asset_id, asset.ip, JSON.stringify(asset))}`);
  const iocs = arrayOf(ticket.iocs).slice(0, 4).map(ioc => typeof ioc === "string" ? `IOC: ${ioc}` : `IOC: ${firstMeaningfulValue(ioc.value, ioc.indicator, ioc.hash, ioc.ip, JSON.stringify(ioc))}`);
  const outputEvidence = listifyReasoningValue(firstMeaningfulValue(output.evidence, output.evidence_summary, output.key_evidence, output.indicators, output.iocs), []);
  const threatIntel = listifyReasoningValue(firstMeaningfulValue(ticket.threat_intel_summary, ticket.enrichment_summary, ticket.enriched_alert?.threat_intel, output.threat_intel), []);
  const fallback = ["Ticket workflow state", "Agent prerequisite checks", "Available case context"];
  return limitReasoningList([...outputEvidence, ...threatIntel, ...relatedAlerts, ...assets, ...iocs, ...fallback], 8);
}

function reasoningHypothesis(ticket = {}, agent = {}, output = {}, run = null) {
  const key = canonicalAgentKey(agent.key || agent.label || "");
  const direct = firstMeaningfulValue(output.working_hypothesis, output.hypothesis, output.likely_scenario, output.classification, output.investigation_summary, output.summary, agent.last_output_summary);
  if (direct) return direct;
  if (runIsActive(run)) {
    return {
      correlation: "The agent is checking whether newly discovered evidence links this alert to existing alerts, incidents, or tickets.",
      triage: "The agent is assessing whether the alert behaviour and enrichment evidence justify escalation.",
      investigation: "The agent is validating whether the triage finding is supported by related alert and endpoint evidence.",
      reporting: "The agent is checking whether the validated ticket context is complete enough to generate analyst-ready reports.",
      approval: "The agent is checking whether the analyst decision gate has been satisfied.",
    }[key] || "The agent is forming a working view from the selected ticket context.";
  }
  return "No final hypothesis has been written yet. Review the agent output once execution completes.";
}

function reasoningDecisionRationale(ticket = {}, agent = {}, output = {}) {
  const key = canonicalAgentKey(agent.key || agent.label || "");
  const direct = firstMeaningfulValue(output.decision_rationale, output.rationale, output.reasoning_summary, output.recommendation_reason, output.recommendation, output.conclusion, agent.last_output_summary);
  if (direct) return direct;
  return {
    triage: "The triage decision is based on severity indicators, confidence, threat intelligence evidence, and SOC policy alignment.",
    investigation: "The investigation result is based on whether the triage conclusion is supported by related alerts, affected assets, IOCs, and available evidence.",
    reporting: "The report output is based on validated fields from enrichment, triage, approval, and investigation context.",
    approval: "The approval outcome is based on the analyst decision gate and containment approval policy.",
  }[key] || "The agent will explain its decision after writing output to the selected ticket.";
}

function reasoningNextAction(ticket = {}, agent = {}, output = {}, run = null) {
  const direct = firstMeaningfulValue(output.next_action, output.recommended_action, output.action_required, output.follow_up, ticket.next_step?.label);
  if (runIsActive(run)) return "Wait for the current run to finish, then review the updated output.";
  if (direct) return direct;
  if (norm(agent.status) === "completed") return "Review output, retry if context changed, or continue to the next valid workflow stage.";
  if (norm(agent.status) === "locked") return agent.lock_reason || "Resolve the workflow gate before running this agent.";
  return "Run the agent when the ticket context is ready.";
}

function reasoningChecksPerformed(agent = {}, run = null) {
  const steps = agentOperationalSteps(agent, run);
  if (steps.length) {
    return steps.map(step => `${liveThinkingStateLabel(step.state === "done" ? "done" : step.state === "active" ? "active" : step.state === "failed" ? "failed" : step.state === "blocked" ? "blocked" : "pending")}: ${step.label}`);
  }
  const key = canonicalAgentKey(agent.key || agent.label || "");
  return {
    parsing: ["Load raw alert", "Extract fields", "Normalise schema", "Write parser result", "Generate PDF"],
    triage: ["Load normalised alert", "Assess severity", "Assess confidence", "Apply triage playbook", "Write triage result"],
    threat_intel: ["Load IOCs", "Query reputation services", "Calculate enrichment risk", "Write enriched alert", "Ready for export on demand"],
    investigation: ["Load ticket context", "Validate approval state", "Review related alerts", "Confirm evidence", "Write investigation result"],
    reporting: ["Load investigation context", "Validate report fields", "Generate sections", "Check completeness", "Save report output"],
    approval: ["Read recommendation", "Check decision gate", "Record analyst decision", "Update workflow"],
  }[key] || ["Load context", "Check prerequisites", "Run task", "Save output"];
}

function buildReasoningSnapshot(ticket = {}, agent = {}, run = null, entries = []) {
  const output = selectedAgentOutput(ticket, agent);
  return {
    objective: agentWorkingObjective(agent),
    contextLoaded: reasoningContextLoaded(ticket, agent),
    evidenceConsidered: reasoningEvidenceConsidered(ticket, agent, output),
    hypothesis: reasoningHypothesis(ticket, agent, output, run),
    checksPerformed: limitReasoningList(reasoningChecksPerformed(agent, run), 7),
    rationale: reasoningDecisionRationale(ticket, agent, output),
    nextAction: reasoningNextAction(ticket, agent, output, run),
    confidence: firstMeaningfulValue(output.confidence?.label, output.confidence, ticket.confidence, "Not confirmed yet"),
    currentFocus: currentThinkingFocus(entries, agent),
  };
}

function renderReasoningList(items = [], emptyText = "No details available yet.") {
  const safe = limitReasoningList(items, 8);
  if (!safe.length) return `<p class="reasoning-empty">${esc(emptyText)}</p>`;
  return `<ul>${safe.map(item => `<li>${esc(item)}</li>`).join("")}</ul>`;
}

function renderReasoningCard(title, icon, body, tone = "blue") {
  return `<article class="reasoning-card ${esc(tone)}">
    <div class="reasoning-card-title"><i class="ti ${esc(icon)}"></i><span>${esc(title)}</span></div>
    ${body}
  </article>`;
}

function renderAgentReasoningSummary(snapshot = {}, agent = {}, run = null) {
  const active = runIsActive(run);
  return `<div class="agent-reasoning-summary ${active ? "is-live" : "is-static"}">
    <div class="reasoning-summary-head">
      <div>
        <span class="reasoning-eyebrow">Explainable working trace</span>
        <h4>${esc(agent.label || "Selected Agent")} reasoning summary</h4>
        <p>Structured summary of what the agent is checking, considering, and preparing to do.</p>
      </div>
      <span class="reasoning-live-pill ${active ? "active" : "idle"}"><i class="ti ${active ? "ti-loader-2" : "ti-circle-check"}"></i>${active ? "Live" : "Latest"}</span>
    </div>
    <div class="reasoning-grid">
      ${renderReasoningCard("Current Objective", "ti-target-arrow", `<p>${esc(snapshot.objective)}</p>`, "blue")}
      ${renderReasoningCard("Context Loaded", "ti-database", renderReasoningList(snapshot.contextLoaded), "cyan")}
      ${renderReasoningCard("Evidence Considered", "ti-search", renderReasoningList(snapshot.evidenceConsidered), "purple")}
      ${renderReasoningCard("Working Hypothesis", "ti-bulb", `<p>${esc(snapshot.hypothesis)}</p>`, "yellow")}
      ${renderReasoningCard("Checks Performed", "ti-list-check", renderReasoningList(snapshot.checksPerformed), "green")}
      ${renderReasoningCard("Decision Rationale", "ti-message-2-check", `<p>${esc(snapshot.rationale)}</p><small>Confidence: ${esc(snapshot.confidence)}</small>`, "orange")}
      ${renderReasoningCard("Next Action", "ti-player-track-next", `<p>${esc(snapshot.nextAction)}</p>`, "red")}
    </div>
    <div class="reasoning-boundary-note"><i class="ti ti-shield-lock"></i> Shows an explainable working summary, not hidden chain-of-thought.</div>
  </div>`;
}

function enrichThinkingEntriesWithReasoning(entries = [], snapshot = {}, agent = {}, run = null) {
  const hasActive = entries.some(entry => entry.state === "active");
  const activeState = runIsActive(run) && !hasActive;
  const starter = {
    title: "Understanding the case objective",
    message: snapshot.objective,
    timestamp: activeState ? "Now" : "",
    state: entries.length ? "done" : (activeState ? "active" : "pending"),
    sequence: 1,
    focus: agent.label || "Selected Agent",
  };
  const hypothesis = {
    title: "Building a working hypothesis",
    message: snapshot.hypothesis,
    timestamp: activeState ? "Now" : "",
    state: activeState ? "active" : "info",
    sequence: 2,
    focus: "Reasoning Summary",
  };
  const next = {
    title: "Preparing next action",
    message: snapshot.nextAction,
    timestamp: "",
    state: runIsActive(run) ? "pending" : "done",
    sequence: 3,
    focus: "Workflow Decision",
  };
  return [starter, ...entries.slice(0, 12), hypothesis, next].map((entry, index) => ({ ...entry, sequence: index + 1 }));
}

function renderAgentLiveActivityLog(ticket) {
  const isCollapsed = state.collapsedPanels["log-panel"];
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";

  const run = currentAgentRun(agent);
  const progress = agentProgressPercent(agent, run);
  const status = effectiveAgentStatus(agent, run);
  const baseEntries = buildLiveLogEntries(ticket, agent, run);
  const snapshot = buildReasoningSnapshot(ticket, agent, run, baseEntries);
  const entries = normaliseThinkingEntriesForRunState(enrichThinkingEntriesWithReasoning(baseEntries, snapshot, agent, run), agent, run);
  const doneCount = entries.filter(entry => entry.state === "done").length;
  const activeCount = entries.filter(entry => entry.state === "active").length;
  const pendingCount = entries.filter(entry => entry.state === "pending").length;
  const failedCount = entries.filter(entry => entry.state === "failed").length;
  const subtitle = runIsActive(run)
    ? "Live view of what the selected agent is checking and doing now"
    : "Latest explainable working trace for the selected agent";

  return `<div class="agent-live-log-panel agent-thinking-panel deep-reasoning-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="log-panel">
      <div>
        <h3><i class="ti ti-brain"></i> Agent Working Progress</h3>
        <small>${esc(subtitle)}</small>
      </div>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body agent-thinking-body deep-reasoning-body">
      <div class="thinking-focus-card ${esc(status)}">
        <div>
          <span>Current focus</span>
          <strong>${esc(snapshot.currentFocus)}</strong>
          <p>${esc(snapshot.objective)}</p>
        </div>
        <div class="thinking-progress-chip"><strong>${esc(progress)}%</strong><span>${esc(displayAgentStatus(agent, run))}</span></div>
      </div>
      ${renderAgentReasoningSummary(snapshot, agent, run)}
      <div class="thinking-metrics-row">
        <div class="thinking-metric"><span>Done</span><strong>${esc(doneCount)}</strong></div>
        <div class="thinking-metric active"><span>Working</span><strong>${esc(activeCount)}</strong></div>
        <div class="thinking-metric"><span>Queued</span><strong>${esc(pendingCount)}</strong></div>
        <div class="thinking-metric failed"><span>Issues</span><strong>${esc(failedCount)}</strong></div>
      </div>
      <div class="reasoning-section-label"><i class="ti ti-route"></i><span>Step-by-step working progress</span></div>
      ${renderLiveLogTrace(entries, agent, run)}
    </div>` : ""}
  </div>`;
}


// ==================== SUMMARY PANEL + EXPORT OVERRIDE ====================
// Keeps the old agent output data intact, but presents it as a readable summary.
function summaryOutputKeyForAgent(agentKey = "") {
  const key = canonicalAgentKey(agentKey || "");
  return {
    correlation: "correlation_result",
    parsing: "parsing_result",
    triage: "triage_result",
    threat_intel: "threat_intel_result",
    triage_approval: "approval_result",
    approval: "approval_result",
    investigation: "investigation_result",
    investigation_approval: "investigation_approval_result",
    reporting: "reporting_result",
    soc_review: "soc_review_result",
  }[key] || "triage_result";
}


function objectValueByPath(obj = {}, path = "") {
  try {
    return path.split(".").reduce((acc, key) => acc && acc[key] != null ? acc[key] : undefined, obj);
  } catch {
    return undefined;
  }
}

function summaryFirstValue(...values) {
  for (const value of values) {
    if (value == null) continue;
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    if (Array.isArray(value) && value.length) return value.map(v => typeof v === "string" ? v : summaryFirstValue(v.value, v.label, v.name, v.summary, v.message, JSON.stringify(v))).filter(Boolean).join(", ");
    if (typeof value === "object" && Object.keys(value).length) {
      const known = summaryFirstValue(value.label, value.value, value.summary, value.message, value.recommendation, value.status);
      if (known) return known;
    }
  }
  return "";
}

function summaryList(value, fallback = []) {
  let items = [];
  if (Array.isArray(value)) {
    items = value.map(item => typeof item === "string" ? item : summaryFirstValue(item.value, item.indicator, item.label, item.name, item.message, item.summary, item.title, JSON.stringify(item)));
  } else if (value && typeof value === "object") {
    items = Object.entries(value).map(([key, val]) => `${key.replaceAll("_", " ")}: ${typeof val === "object" ? JSON.stringify(val) : val}`);
  } else if (typeof value === "string" && value.trim()) {
    items = value.split(/\n|;|\u2022/g).map(x => x.trim()).filter(Boolean);
  }
  const cleaned = [...items, ...fallback].map(item => String(item || "").trim()).filter(Boolean);
  const unique = [];
  cleaned.forEach(item => {
    if (!unique.some(existing => existing.toLowerCase() === item.toLowerCase())) unique.push(item);
  });
  return unique.slice(0, 6);
}

function buildAgentSummaryPayload(ticket = state.selectedTicket, agentKey = state.selectedAgentKey) {
  const agents = arrayOf(ticket?.agent_panel);
  const agent = agents.find(a => canonicalAgentKey(a.key || a.label) === canonicalAgentKey(agentKey)) || agents[0] || { key: agentKey, label: agentLabel(agentKey) };
  const key = summaryOutputKeyForAgent(agent.key || agentKey);
  const rawOutput = !shouldMaskAgentOutput(ticket, agent.key || agentKey) && ticket?.[key] && typeof ticket[key] === "object" ? ticket[key] : {};
  const run = currentAgentRun(agent);
  const statusLabel = displayAgentStatus(agent, run);
  const hasOutput = Object.keys(rawOutput).length > 0;
  const headline = hasOutput
    ? summaryFirstValue(
        rawOutput.summary,
        rawOutput.executive_summary,
        rawOutput.investigation_summary,
        rawOutput.soc_analyst_review,
        rawOutput.recommendation,
        rawOutput.conclusion,
        rawOutput.final_incident_report?.summary,
        rawOutput.report_summary,
        agent.last_output_summary,
        "Output is available for this agent."
      )
    : "No output has been written to this ticket yet.";
  const severity = summaryFirstValue(rawOutput.severity?.label, rawOutput.severity, ticket?.severity, "Unknown");
  const confidence = summaryFirstValue(rawOutput.confidence?.label, rawOutput.confidence, ticket?.confidence, "Unknown");
  const classification = summaryFirstValue(rawOutput.classification, rawOutput.likely_scenario, rawOutput.decision, rawOutput.approval_status, rawOutput.report_status, "Not recorded");
  const nextAction = summaryFirstValue(rawOutput.next_action, rawOutput.recommended_action, rawOutput.action_required, rawOutput.follow_up, ticket?.next_step?.label, "Review workflow state");
  const findings = summaryList(summaryFirstValue(rawOutput.key_findings, rawOutput.findings, rawOutput.evidence_summary, rawOutput.evidence, rawOutput.indicators, rawOutput.iocs, rawOutput.missing_report_fields), [
    rawOutput.recommendation ? `Recommendation: ${rawOutput.recommendation}` : "",
    rawOutput.report_status ? `Report status: ${rawOutput.report_status}` : "",
    rawOutput.validation_status ? `Validation status: ${rawOutput.validation_status}` : "",
  ]);
  const files = summaryList(rawOutput.generated_reports || rawOutput.report_paths || rawOutput.output_files || rawOutput.exports, []);
  const ps = rawOutput.powershell_analysis || rawOutput.powershell_command_analysis || rawOutput.raw_agent_result?.powershell_analysis || {};
  return {
    ticket_id: ticket?.ticket_id || "Unknown ticket",
    ticket_title: ticket?.title || ticket?.ticket_title || "Untitled Ticket",
    agent_key: agent.key || agentKey || "agent",
    agent_label: agent.label || agentLabel(agentKey),
    status: statusLabel,
    severity,
    confidence,
    classification,
    next_action: nextAction,
    headline,
    findings,
    files,
    generated_at: new Date().toLocaleString(),
    powershell_analysis: ps && typeof ps === "object" ? ps : {},
    raw_output: rawOutput,
  };
}

function renderPowerShellAnalysisCard(ps = {}) {
  if (!ps || typeof ps !== "object" || !Object.keys(ps).length) return "";
  const behaviours = arrayOf(ps.suspicious_behaviours);
  const mitre = arrayOf(ps.mitre_mapping);
  const iocs = ps.extracted_iocs && typeof ps.extracted_iocs === "object" ? ps.extracted_iocs : {};
  const iocSummary = Object.entries(iocs).filter(([, v]) => arrayOf(v).length).map(([k, v]) => `${k.replaceAll("_", " ")}: ${arrayOf(v).slice(0, 4).join(", ")}`);
  return `<div class="powershell-analysis-card">
    <div class="powershell-analysis-head"><i class="ti ti-terminal-2"></i><div><span>PowerShell Command Analysis</span><strong>${esc(ps.decode_status || "Not provided")}</strong></div></div>
    <p>${esc(ps.decoded_command_summary || "No decoded PowerShell command summary was available.")}</p>
    ${behaviours.length ? `<div><span>Suspicious Behaviours</span><ul>${behaviours.slice(0, 5).map(b => `<li>${esc(summaryFirstValue(b.behaviour, b.name, b.summary))} <small>${esc(summaryFirstValue(b.risk, b.severity, ""))}</small></li>`).join("")}</ul></div>` : ""}
    ${iocSummary.length ? `<div><span>Extracted Indicators</span><ul>${iocSummary.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>` : ""}
    ${mitre.length ? `<div><span>MITRE Mapping</span><ul>${mitre.slice(0, 6).map(m => `<li>${esc(summaryFirstValue(m.technique_id, m.id))}: ${esc(summaryFirstValue(m.technique, m.name))}</li>`).join("")}</ul></div>` : ""}
  </div>`;
}

function renderAgentSummary(payload = {}) {
  const findings = arrayOf(payload.findings);
  const files = arrayOf(payload.files);
  return `<div class="agent-summary-view">
    <div class="agent-summary-headline">
      <span class="summary-eyebrow">Summary</span>
      <strong>${esc(payload.headline)}</strong>
    </div>
    <div class="agent-summary-grid">
      <div><span>Status</span><strong>${esc(payload.status)}</strong></div>
      <div><span>Severity</span><strong>${esc(payload.severity)}</strong></div>
      <div><span>Confidence</span><strong>${esc(payload.confidence)}</strong></div>
      <div><span>Decision / Classification</span><strong>${esc(payload.classification)}</strong></div>
    </div>
    <div class="summary-next-action"><span>Next Action</span><strong>${esc(payload.next_action)}</strong></div>
    <div class="summary-findings">
      <span>Key Points</span>
      ${findings.length ? `<ul>${findings.map(item => `<li>${esc(item)}</li>`).join("")}</ul>` : `<p>No key points were found in the saved output yet.</p>`}
    </div>
    ${renderPowerShellAnalysisCard(payload.powershell_analysis)}
    ${files.filter(item => !looksLikeLocalFilesystemPath(item)).length ? `<div class="summary-files summary-outputs"><span>Outputs</span>${files.filter(item => !looksLikeLocalFilesystemPath(item)).map(item => `<p>${esc(item)}</p>`).join("")}</div>` : ""}
  </div>`;
}

function renderAgentRunPendingSummary(agent = {}, run = null) {
  const failed = runIsFailed(run);
  const headline = failed
    ? (run?.error_message || run?.current_step || "The latest agent run failed.")
    : "Agent is thinking...";
  const detail = failed
    ? "The previous output is not shown as the active result. Check run history for older results."
    : "Waiting for the latest run to finish before showing active output or enabling downloads.";
  return `<div class="agent-summary-view agent-rerun-placeholder">
    <div class="agent-summary-headline">
      <span class="summary-eyebrow">${failed ? "Latest run failed" : "Latest run in progress"}</span>
      <strong>${esc(headline)}</strong>
    </div>
    <div class="summary-next-action"><span>${esc(agent.label || "Selected Agent")}</span><strong>${esc(detail)}</strong></div>
  </div>`;
}

function backendAgentExportHref(ticketId, agentKey, format) {
  return `/api/tickets/${encodeURIComponent(ticketId || "")}/exports/${encodeURIComponent(agentKey || "triage")}/${encodeURIComponent(format || "json")}`;
}

function backendReportExportHref(ticketId, reportKey, format) {
  return `/api/tickets/${encodeURIComponent(ticketId || "")}/exports/reporting/${encodeURIComponent(reportKey || "final_incident_report")}/${encodeURIComponent(format || "json")}`;
}

function downloadAnchor(label, href, icon = "ti-download", extraClass = "") {
  return `<a class="soc-btn ghost compact download-link ${extraClass}" href="${esc(href)}" download target="_self"><i class="ti ${icon}"></i> ${esc(label)}</a>`;
}

function disabledDownloadButton(label, icon = "ti-download") {
  return `<button class="soc-btn ghost compact download-link" type="button" disabled><i class="ti ${icon}"></i> ${esc(label)}</button>`;
}

function normaliseExportStatusText(status = "not_generated") {
  const value = norm(status || "not_generated");
  if (value === "ready") return "Ready";
  if (value === "preparing") return "Preparing";
  if (value === "failed") return "Failed";
  return "Generate on download";
}

function exportStatusTone(status = "not_generated") {
  const value = norm(status || "not_generated");
  if (value === "ready") return "green";
  if (value === "preparing") return "yellow";
  if (value === "failed") return "red";
  return "blue";
}

function exportStatusBadge(status = "not_generated") {
  const tone = exportStatusTone(status);
  return `<span class="export-status-pill ${tone}">${esc(normaliseExportStatusText(status))}</span>`;
}

function exportStatusForAgent(agentKey, format) {
  const key = canonicalAgentKey(agentKey || "");
  const aliases = [key];
  if (key === "parsing") aliases.push("parsing_normalisation");
  if (key === "threat_intel") aliases.push("threat_intelligence");
  const agents = state.exportStatus?.agents || {};
  for (const alias of aliases) {
    if (agents[alias]?.[format]) return agents[alias][format];
  }
  return { status: "not_generated" };
}

function exportStatusForReport(reportKey, format) {
  const reporting = state.exportStatus?.reporting || {};
  return reporting[reportKey]?.[format] || { status: "not_generated" };
}

function renderExportStatusLine(agentKey) {
  const docx = exportStatusForAgent(agentKey, "docx");
  const pdf = exportStatusForAgent(agentKey, "pdf");
  return `<div class="export-status-line"><span>Word ${exportStatusBadge(docx.status)}</span><span>PDF ${exportStatusBadge(pdf.status)}</span></div>`;
}

function renderReportExportStatusLine(reportKey) {
  const docx = exportStatusForReport(reportKey, "docx");
  const pdf = exportStatusForReport(reportKey, "pdf");
  return `<div class="export-status-line"><span>Word ${exportStatusBadge(docx.status)}</span><span>PDF ${exportStatusBadge(pdf.status)}</span></div>`;
}

function renderSummaryFormatActions(ticket = {}, agent = {}, hasOutput = false) {
  const agentKey = agent.key || state.selectedAgentKey || "triage";
  const ticketId = ticket.ticket_id || state.selectedTicket?.ticket_id || "";
  const key = canonicalAgentKey(agentKey);
  const includeJson = !["parsing", "threat_intel"].includes(key);
  const label = ["parsing", "threat_intel"].includes(key) ? "Export report" : "Download summary";
  if (!hasOutput) {
    return `<div class="summary-format-actions download-format-actions">
      <span>${esc(label)}</span>
      ${renderExportStatusLine(agentKey)}
      ${includeJson ? disabledDownloadButton("Download JSON", "ti-braces") : ""}
      ${disabledDownloadButton("Download Word", "ti-file-type-docx")}
      ${disabledDownloadButton("Download PDF", "ti-file-type-pdf")}
    </div>`;
  }
  return `<div class="summary-format-actions download-format-actions">
    <span>${esc(label)}</span>
    ${renderExportStatusLine(agentKey)}
    ${includeJson ? downloadAnchor("Download JSON", backendAgentExportHref(ticketId, agentKey, "json"), "ti-braces") : ""}
    ${downloadAnchor("Download Word", backendAgentExportHref(ticketId, agentKey, "docx"), "ti-file-type-docx")}
    ${downloadAnchor("Download PDF", backendAgentExportHref(ticketId, agentKey, "pdf"), "ti-file-type-pdf")}
  </div>`;
}
function renderSelectedAgentOutputPanel(ticket) {
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";

  const isCollapsed = state.collapsedPanels["output-panel"];
  const agentKey = canonicalAgentKey(agent.key || agent.label || state.selectedAgentKey);
  const outputKey = summaryOutputKeyForAgent(agent.key);
  const maskOutput = shouldMaskAgentOutput(ticket, agentKey);
  const output = maskOutput ? {} : (ticket[outputKey] || {});
  const hasOutput = output && typeof output === "object" && Object.keys(output).length > 0;
  const run = currentAgentRun(agent);
  const status = effectiveAgentStatus(agent, run);
  const payload = buildAgentSummaryPayload(ticket, agent.key);

  let actionButtons = "";
  if (["completed", "completed_with_warnings"].includes(status) && hasOutput) {
    actionButtons = `
      <button class="soc-btn ghost" data-action="retry-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
        <i class="ti ti-refresh"></i> Retry
      </button>
    `;
  } else if (status === "ready") {
    if (["triage_approval", "investigation_approval", "approval"].includes(agent.key)) {
      actionButtons = `
        <button class="soc-btn green" data-action="approve-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-shield-check"></i> Approve</button>
        <button class="soc-btn danger" data-action="reject-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-x"></i> Reject</button>
      `;
    } else if (agent.key === "soc_review") {
      actionButtons = `<button class="soc-btn green" data-action="confirm-soc-review" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-clipboard-check"></i> Confirm Review</button>`;
    } else {
      const runLabel = { parsing: "Run Parsing", triage: "Run Triage", threat_intel: "Run Threat Intel", investigation: "Run Investigation", reporting: "Generate Report", triage_approval: "Review", investigation_approval: "Review", soc_review: "Confirm Review", approval: "Review" }[agent.key] || "Run Agent";
      actionButtons = `
        <button class="soc-btn primary" data-action="run-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
          <i class="ti ti-player-play"></i> ${esc(runLabel)}
        </button>
      `;
    }
  } else if (status === "awaiting_approval") {
    actionButtons = `
      <button class="soc-btn green" data-action="approve-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-shield-check"></i> Approve</button>
      <button class="soc-btn danger" data-action="reject-ticket" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-x"></i> Reject</button>
      <button class="soc-btn ghost" data-action="more-evidence" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-search"></i> More Evidence</button>
    `;
  } else if (status === "awaiting_review") {
    actionButtons = `<button class="soc-btn green" data-action="confirm-soc-review" data-ticket-id="${esc(ticket.ticket_id)}"><i class="ti ti-clipboard-check"></i> Confirm Review</button>`;
  } else if (status === "locked") {
    actionButtons = `<p class="lock-reason"><i class="ti ti-lock"></i> ${esc(agent.lock_reason || "Agent is locked")}</p>`;
  } else if (status === "running" || status === "in_progress") {
    actionButtons = `<p class="running-text"><i class="ti ti-loader-2"></i> Agent is running...</p>
      <button class="soc-btn warning" data-action="pause-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}" data-run-id="${esc(runIdentifier(run))}"><i class="ti ti-player-pause"></i> Pause Agent</button>`;
  } else if (status === "failed") {
    actionButtons = `
      <button class="soc-btn primary" data-action="retry-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}">
        <i class="ti ti-refresh"></i> Retry
      </button>
    `;
  }
  if (agent.workflow_status) {
    const workflowButtons = prioritisedAgentActions(agent).map(action => actionButtonForAgent(action, agent)).join("");
    const pause = status === "running" && runIsActive(run)
      ? `<button class="soc-btn warning" data-action="pause-agent" data-agent="${esc(agent.key)}" data-ticket-id="${esc(ticket.ticket_id)}" data-run-id="${esc(runIdentifier(run))}"><i class="ti ti-player-pause"></i> Pause Agent</button>`
      : "";
    actionButtons = `${workflowButtons}${pause}`;
  }

  const summaryContent = maskOutput
    ? `${renderAgentRunPendingSummary(agent, run)}${renderSummaryFormatActions(ticket, agent, false)}`
    : agentKey === "reporting" && hasOutput && agent.output_valid !== false
    ? renderReportingSummaryDownloads(ticket, agent, payload)
    : `${agent.status_message ? `<div class="workflow-progress-message ${esc(status)}">${status === "locked" || agent.locked ? `<i class="ti ti-lock"></i>` : status === "rerun_required" ? `<i class="ti ti-refresh-alert"></i>` : ""}<span>${esc(agent.status_message)}</span></div>` : ""}${renderAgentSummary(payload)}${renderSummaryFormatActions(ticket, agent, hasOutput && agent.output_valid !== false)}`;
  const groupingReviewHtml = agentKey === "triage"
    ? correlationRecommendationsPanel(ticket, ["triage"])
    : agentKey === "investigation"
      ? correlationRecommendationsPanel(ticket, ["investigation"])
      : "";

  return `<div class="agent-output-panel summary-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="output-panel">
      <div>
        <h3>Outputs</h3>
        <small>${esc(agent.label || "Selected Agent")} results in text</small>
      </div>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body">
      ${summaryContent}
      ${groupingReviewHtml}
      ${renderEmbeddedHumanGate(agent)}
      <div class="output-actions summary-actions">
        ${actionButtons}
      </div>
    </div>` : ""}
  </div>`;
}
function safeFilename(value = "agent-summary") {
  return String(value || "agent-summary").replace(/[^a-z0-9_\-]+/gi, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "agent-summary";
}

function summaryDocumentHtml(payload = {}) {
  const findings = arrayOf(payload.findings);
  const files = arrayOf(payload.files);
  const raw = JSON.stringify(payload.raw_output || {}, null, 2);
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(payload.agent_label)} Summary</title>
  <style>
    body{font-family:Arial,sans-serif;line-height:1.5;color:#111827;margin:32px}h1{font-size:24px;margin-bottom:4px}h2{font-size:16px;margin-top:24px;border-bottom:1px solid #d1d5db;padding-bottom:6px}.muted{color:#6b7280}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:16px 0}.card{border:1px solid #d1d5db;border-radius:8px;padding:10px}.card span{display:block;color:#6b7280;font-size:12px}.card strong{display:block;margin-top:4px}pre{white-space:pre-wrap;word-break:break-word;background:#f3f4f6;border:1px solid #d1d5db;padding:12px;border-radius:8px;font-size:12px}
  </style></head><body>
    <h1>${esc(payload.agent_label)} Summary</h1>
    <p class="muted">Ticket ${esc(payload.ticket_id)} | ${esc(payload.ticket_title)}</p>
    <p class="muted">Generated ${esc(payload.generated_at)}</p>
    <h2>Summary</h2><p>${esc(payload.headline)}</p>
    <div class="grid">
      <div class="card"><span>Status</span><strong>${esc(payload.status)}</strong></div>
      <div class="card"><span>Severity</span><strong>${esc(payload.severity)}</strong></div>
      <div class="card"><span>Confidence</span><strong>${esc(payload.confidence)}</strong></div>
      <div class="card"><span>Decision / Classification</span><strong>${esc(payload.classification)}</strong></div>
    </div>
    <h2>Next Action</h2><p>${esc(payload.next_action)}</p>
    <h2>Key Points</h2>${findings.length ? `<ul>${findings.map(item => `<li>${esc(item)}</li>`).join("")}</ul>` : `<p>No key points found.</p>`}
    ${files.length ? `<h2>Generated Files</h2><ul>${files.map(item => `<li>${esc(item)}</li>`).join("")}</ul>` : ""}
    <h2>Raw JSON Output</h2><pre>${esc(raw)}</pre>
  </body></html>`;
}

function downloadableAgentPayload(payload = {}) {
  return {
    ticket_id: payload.ticket_id,
    ticket_title: payload.ticket_title,
    agent_key: payload.agent_key,
    agent_label: payload.agent_label,
    generated_at: payload.generated_at,
    summary: {
      headline: payload.headline,
      status: payload.status,
      severity: payload.severity,
      confidence: payload.confidence,
      classification: payload.classification,
      next_action: payload.next_action,
      key_points: arrayOf(payload.findings),
      generated_files: arrayOf(payload.files),
    },
    raw_output: payload.raw_output || {},
  };
}

function viewAgentSummaryJson(agentKey, ticketId) {
  return downloadAgentSummaryJson(agentKey, ticketId);
}

function downloadBlob(filename, content, mimeType) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1200);
}

function downloadAgentSummaryJson(agentKey, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const payload = buildAgentSummaryPayload(t, agentKey);
  if (!Object.keys(payload.raw_output || {}).length) return toast("No saved output is available for this agent yet.", "yellow");
  const filename = `${safeFilename(payload.ticket_id)}_${safeFilename(payload.agent_key)}_summary.json`;
  downloadBlob(filename, JSON.stringify(downloadableAgentPayload(payload), null, 2), "application/json;charset=utf-8");
  toast("JSON summary downloaded.", "green");
}

function downloadReportingDataJson(ticketId) {
  const ticket = state.selectedTicket;
  if (!ticket || ticket.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const reportingData = ticket.reporting_result;
  if (!reportingData || !Object.keys(reportingData).length) return toast("Reporting data has not been generated yet.", "yellow");
  const payload = {
    ticket_id: ticket.ticket_id,
    incident_id: ticket.incident_id || ticket.ticket_id,
    generated_at: reportingData.created_at || reportingData.generated_at || ticket.updated_at || null,
    reporting_data: reportingData,
  };
  downloadBlob(
    `${safeFilename(ticket.ticket_id)}_reporting_data.json`,
    JSON.stringify(payload, null, 2),
    "application/json;charset=utf-8"
  );
  toast("Reporting data downloaded.", "green");
}

function exportAgentSummaryWord(agentKey, ticketId) {
  return downloadAgentSummaryWord(agentKey, ticketId);
}

function downloadAgentSummaryWord(agentKey, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const payload = buildAgentSummaryPayload(t, agentKey);
  if (!Object.keys(payload.raw_output || {}).length) return toast("No saved output is available for this agent yet.", "yellow");
  const html = summaryDocumentHtml(payload);
  const filename = `${safeFilename(payload.ticket_id)}_${safeFilename(payload.agent_key)}_summary.doc`;
  downloadBlob(filename, html, "application/msword;charset=utf-8");
  toast("Word summary downloaded.", "green");
}

function exportAgentSummaryPdf(agentKey, ticketId) {
  return downloadAgentSummaryPdf(agentKey, ticketId);
}

function downloadAgentSummaryPdf(agentKey, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const payload = buildAgentSummaryPayload(t, agentKey);
  if (!Object.keys(payload.raw_output || {}).length) return toast("No saved output is available for this agent yet.", "yellow");
  const lines = agentSummaryPdfLines(payload);
  const pdfBlob = buildSimplePdfBlob(`${payload.agent_label} Summary`, lines);
  const filename = `${safeFilename(payload.ticket_id)}_${safeFilename(payload.agent_key)}_summary.pdf`;
  downloadBlob(filename, pdfBlob, "application/pdf");
  toast("PDF summary downloaded.", "green");
}

function reportDefinitions() {
  return [
    { key: "executive_summary", title: "Executive Summary", aliases: ["executive_summary", "executiveSummary", "executive", "summary"] },
    { key: "technical_findings", title: "Technical Findings", aliases: ["technical_findings", "technicalFindings", "technical", "findings"] },
    { key: "soc_analyst_review", title: "SOC Analyst Review", aliases: ["soc_analyst_review", "socAnalystReview", "analyst_review", "review"] },
    { key: "final_incident_report", title: "Final Incident Report", aliases: ["final_incident_report", "finalIncidentReport", "final_report", "incident_report"] },
  ];
}

function getNestedValue(obj = {}, path = "") {
  return path.split(".").reduce((acc, key) => acc && acc[key] != null ? acc[key] : undefined, obj);
}

function extractReportingSection(rawOutput = {}, reportKey = "") {
  const def = reportDefinitions().find(r => r.key === reportKey) || reportDefinitions()[0];
  const candidates = [];
  def.aliases.forEach(alias => {
    candidates.push(rawOutput[alias]);
    candidates.push(getNestedValue(rawOutput, `reports.${alias}`));
    candidates.push(getNestedValue(rawOutput, `generated_reports.${alias}`));
    candidates.push(getNestedValue(rawOutput, `report_sections.${alias}`));
    candidates.push(getNestedValue(rawOutput, `sections.${alias}`));
  });
  candidates.push(getNestedValue(rawOutput, `outputs.${def.key}`));
  candidates.push(getNestedValue(rawOutput, `documents.${def.key}`));
  const section = candidates.find(value => {
    if (value == null) return false;
    if (typeof value === "string") return value.trim().length > 0;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === "object") return Object.keys(value).length > 0;
    return true;
  });
  return section == null ? null : section;
}

function reportSectionToText(section) {
  if (section == null) return "";
  if (typeof section === "string") return section.trim();
  if (Array.isArray(section)) return section.map(item => reportSectionToText(item)).filter(Boolean).join("\n");
  if (typeof section === "object") {
    const preferred = summaryFirstValue(section.content, section.text, section.body, section.report, section.summary, section.findings, section.details, section.narrative);
    if (preferred) return preferred;
    return Object.entries(section).map(([key, value]) => `${key.replaceAll("_", " ")}: ${typeof value === "object" ? JSON.stringify(value, null, 2) : value}`).join("\n");
  }
  return String(section);
}


function looksLikeLocalFilesystemPath(value = "") {
  const s = String(value || "").trim();
  return /(^\/Users\/|^\/home\/|^\/mnt\/|^[A-Z]:\\|\\outputs\\|\/outputs\/)/i.test(s);
}

function removeLocalPathNoise(value = "") {
  return String(value || "")
    .split(/\r?\n/)
    .filter(line => {
      const trimmed = line.trim();
      if (!trimmed) return true;
      if (looksLikeLocalFilesystemPath(trimmed)) return false;
      if (/^template basis:/i.test(trimmed)) return false;
      if (/^expected template sections:/i.test(trimmed)) return false;
      if (/^source:/i.test(trimmed) && /report_templates|jinja2|local/i.test(trimmed)) return false;
      return true;
    })
    .join("\n")
    .trim();
}

function cleanReportContentForDocument(value = "") {
  const cleaned = removeLocalPathNoise(value);
  return cleaned || "No report content was returned by the Reporting Agent.";
}

function safeReportJson(report = {}) {
  return {
    ticket_id: report.ticket_id,
    ticket_title: report.ticket_title,
    report_key: report.report_key,
    report_title: report.report_title,
    generated_at: report.generated_at,
    content: cleanReportContentForDocument(report.content || ""),
    raw_section: report.raw_section || {},
  };
}

function realReportExportRouteCandidates(ticketId, reportKey, format) {
  const encodedTicket = encodeURIComponent(ticketId || "");
  const encodedReport = encodeURIComponent(reportKey || "");
  const encodedFormat = encodeURIComponent(format || "docx");
  return [
    `/api/tickets/${encodedTicket}/reports/${encodedReport}/download?format=${encodedFormat}`,
    `/api/tickets/${encodedTicket}/reports/${encodedReport}/export?format=${encodedFormat}`,
    `/api/reports/${encodedTicket}/${encodedReport}/download?format=${encodedFormat}`,
    `/api/reports/${encodedTicket}/${encodedReport}/export?format=${encodedFormat}`,
    `/api/reports/download?ticket_id=${encodedTicket}&report_key=${encodedReport}&format=${encodedFormat}`,
    `/api/reports/export/${encodedFormat}?ticket_id=${encodedTicket}&report_key=${encodedReport}`,
  ];
}

async function tryDownloadBackendReportArtifact(report, format) {
  const routeFormat = format === "word" ? "docx" : format;
  const extension = format === "word" ? "docx" : format;
  const base = `${safeFilename(report.ticket_id)}_${safeFilename(report.report_key)}`;
  const routes = realReportExportRouteCandidates(report.ticket_id, report.report_key, routeFormat);
  for (const url of routes) {
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) continue;
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const payload = await res.clone().json().catch(() => null);
        const downloadUrl = payload?.download_url || payload?.url || payload?.file_url;
        if (downloadUrl) {
          window.open(downloadUrl, "_blank");
          return true;
        }
        continue;
      }
      const blob = await res.blob();
      if (!blob || blob.size === 0) continue;
      downloadBlob(`${base}.${extension}`, blob, contentType || (format === "pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
      return true;
    } catch (err) {
      // Try the next possible backend route without breaking the dashboard.
    }
  }
  return false;
}

function buildReportingReportPayload(ticket = state.selectedTicket, reportKey = "executive_summary") {
  const rawOutput = !shouldMaskAgentOutput(ticket, "reporting") && ticket?.reporting_result && typeof ticket.reporting_result === "object" ? ticket.reporting_result : {};
  const def = reportDefinitions().find(r => r.key === reportKey) || reportDefinitions()[0];
  const section = extractReportingSection(rawOutput, def.key);
  const content = cleanReportContentForDocument(reportSectionToText(section));
  const ps = rawOutput.powershell_analysis || rawOutput.powershell_command_analysis || rawOutput.raw_agent_result?.powershell_analysis || {};
  return {
    ticket_id: ticket?.ticket_id || "Unknown ticket",
    ticket_title: ticket?.title || ticket?.ticket_title || "Untitled Ticket",
    agent_key: "reporting",
    agent_label: "Reporting Agent",
    report_key: def.key,
    report_title: def.title,
    generated_at: new Date().toLocaleString(),
    has_content: Boolean(content.trim()),
    content: content || "This report section has not been generated yet.",
    raw_section: section || {},
    raw_output: rawOutput,
  };
}

function renderReportingSummaryDownloads(ticket = {}, agent = {}, payload = {}) {
  const ticketId = ticket.ticket_id || state.selectedTicket?.ticket_id || "";
  const reportCards = reportDefinitions().map(def => {
    const report = buildReportingReportPayload(ticket, def.key);
    return `<article class="report-download-card available">
      <div class="report-download-card-head">
        <div>
          <strong>${esc(def.title)}</strong>
          <small>Template-based export ready</small>
        </div>
        ${badge("Ready", "green")}
      </div>
      <p>Downloads are generated by the backend from the Jinja2 template, then Word is converted to PDF. Repeated downloads use the export cache.</p>
      ${renderReportExportStatusLine(def.key)}
      <div class="report-download-actions">
        ${downloadAnchor("Download JSON", backendReportExportHref(ticketId, def.key, "json"), "ti-braces")}
        ${downloadAnchor("Download Word", backendReportExportHref(ticketId, def.key, "docx"), "ti-file-type-docx")}
        ${downloadAnchor("Download PDF", backendReportExportHref(ticketId, def.key, "pdf"), "ti-file-type-pdf")}
      </div>
    </article>`;
  }).join("");
  return `<div class="reporting-summary-downloads">
    <div class="agent-summary-headline">
      <span class="summary-eyebrow">Reporting Summary</span>
      <strong>${esc(payload.headline || "Template-based reporting exports are available.")}</strong>
    </div>
    <div class="reporting-report-grid">${reportCards}</div>
  </div>`;
}
function reportDocumentHtml(report = {}) {
  const raw = JSON.stringify(report.raw_section || {}, null, 2);
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(report.report_title)}</title>
  <style>
    body{font-family:Arial,sans-serif;line-height:1.55;color:#111827;margin:36px}h1{font-size:24px;margin-bottom:4px}h2{font-size:16px;margin-top:24px;border-bottom:1px solid #d1d5db;padding-bottom:6px}.muted{color:#6b7280}.content{white-space:pre-wrap;border:1px solid #d1d5db;border-radius:8px;padding:14px;background:#fff}pre{white-space:pre-wrap;word-break:break-word;background:#f3f4f6;border:1px solid #d1d5db;padding:12px;border-radius:8px;font-size:12px}
  </style></head><body>
    <h1>${esc(report.report_title)}</h1>
    <p class="muted">Ticket ${esc(report.ticket_id)} | ${esc(report.ticket_title)}</p>
    <p class="muted">Generated ${esc(report.generated_at)}</p>
    <h2>Report Content</h2><div class="content">${esc(report.content)}</div>
    <h2>Raw Report Section JSON</h2><pre>${esc(raw)}</pre>
  </body></html>`;
}

function downloadReportingReport(reportKey, ticketId, format) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const report = buildReportingReportPayload(t, reportKey);
  if (!report.has_content) return toast(`${report.report_title} has not been generated yet.`, "yellow");
  const base = `${safeFilename(report.ticket_id)}_${safeFilename(report.report_key)}`;
  if (format === "json") {
    downloadBlob(`${base}.json`, JSON.stringify(report, null, 2), "application/json;charset=utf-8");
    return toast(`${report.report_title} JSON downloaded.`, "green");
  }
  if (format === "word") {
    downloadBlob(`${base}.doc`, reportDocumentHtml(report), "application/msword;charset=utf-8");
    return toast(`${report.report_title} Word document downloaded.`, "green");
  }
  if (format === "pdf") {
    const lines = reportPdfLines(report);
    downloadBlob(`${base}.pdf`, buildSimplePdfBlob(report.report_title, lines), "application/pdf");
    return toast(`${report.report_title} PDF downloaded.`, "green");
  }
}

function plainTextLines(value = "") {
  return String(value || "").replace(/\r/g, "").split("\n").flatMap(line => wrapText(line.trim(), 92));
}

function agentSummaryPdfLines(payload = {}) {
  const lines = [
    `${payload.agent_label} Summary`,
    `Ticket: ${payload.ticket_id} | ${payload.ticket_title}`,
    `Generated: ${payload.generated_at}`,
    "",
    "Summary",
    payload.headline,
    "",
    `Status: ${payload.status}`,
    `Severity: ${payload.severity}`,
    `Confidence: ${payload.confidence}`,
    `Decision / Classification: ${payload.classification}`,
    `Next Action: ${payload.next_action}`,
    "",
    "Key Points",
    ...arrayOf(payload.findings).map(item => `- ${item}`),
    "",
    "Raw JSON Output",
    JSON.stringify(payload.raw_output || {}, null, 2),
  ];
  return lines.flatMap(plainTextLines);
}

function reportPdfLines(report = {}) {
  const lines = [
    report.report_title,
    `Ticket: ${report.ticket_id} | ${report.ticket_title}`,
    `Generated: ${report.generated_at}`,
    "",
    "Report Content",
    report.content,
    "",
    "Raw Report Section JSON",
    JSON.stringify(report.raw_section || {}, null, 2),
  ];
  return lines.flatMap(plainTextLines);
}

function wrapText(text = "", maxChars = 92) {
  const safe = String(text || "");
  if (!safe) return [""];
  const words = safe.split(/\s+/);
  const lines = [];
  let current = "";
  words.forEach(word => {
    if ((current + " " + word).trim().length > maxChars) {
      if (current) lines.push(current);
      current = word;
    } else {
      current = (current + " " + word).trim();
    }
  });
  if (current) lines.push(current);
  return lines.length ? lines : [safe.slice(0, maxChars)];
}

function pdfSafeText(value = "") {
  return String(value || "")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "?")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function buildSimplePdfBlob(title = "Summary", lines = []) {
  const pageLines = [];
  const allLines = [title, "", ...arrayOf(lines)];
  const perPage = 48;
  for (let i = 0; i < allLines.length; i += perPage) pageLines.push(allLines.slice(i, i + perPage));
  const objects = [];
  const addObject = (body) => {
    objects.push(body);
    return objects.length;
  };
  const catalogId = addObject("<< /Type /Catalog /Pages 2 0 R >>");
  const pagesPlaceholderId = addObject("PAGES_PLACEHOLDER");
  const fontId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const kids = [];
  pageLines.forEach(page => {
    const contentLines = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"];
    page.forEach((line, index) => {
      if (index > 0) contentLines.push("T*");
      contentLines.push(`(${pdfSafeText(line)}) Tj`);
    });
    contentLines.push("ET");
    const stream = contentLines.join("\n");
    const contentId = addObject(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    const pageId = addObject(`<< /Type /Page /Parent ${pagesPlaceholderId} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId} 0 R >>`);
    kids.push(`${pageId} 0 R`);
  });
  objects[pagesPlaceholderId - 1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${kids.length} >>`;

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((body, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([pdf], { type: "application/pdf" });
}
// Stronger completion-state normalisation for Agent Working Progress.
// If the selected agent or latest run is completed, no step should remain Working/Blocked/Pending.
function normaliseThinkingEntriesForRunState(entries = [], agent = {}, run = null) {
  const status = effectiveAgentStatus(agent, run);
  const progress = agentProgressPercent(agent, run);
  const agentCompleted = norm(agent.status) === "completed";
  const runCompleted = runIsCompleted(run);
  const total = Math.max(1, entries.length);

  if (status === "completed" || progress >= 100 || agentCompleted || runCompleted || ["awaiting_approval", "awaiting_review"].includes(status)) {
    return entries.map(entry => ({
      ...entry,
      state: entry.state === "failed" ? "failed" : "done",
      timestamp: entry.timestamp || (status === "awaiting_approval" ? "Awaiting approval" : status === "awaiting_review" ? "Awaiting review" : "Completed"),
    }));
  }

  const activeIndex = activeStepIndexForProgress(progress, total);

  if (status === "failed") {
    return entries.map((entry, index) => {
      if (index < activeIndex) return { ...entry, state: "done" };
      if (index === activeIndex) return { ...entry, state: "failed" };
      return { ...entry, state: "pending" };
    });
  }

  if (status === "running" || status === "in_progress") {
    return entries.map((entry, index) => {
      if (index < activeIndex) return { ...entry, state: "done" };
      if (index === activeIndex) return { ...entry, state: "active", timestamp: entry.timestamp || "Now" };
      return { ...entry, state: "pending" };
    });
  }

  return entries;
}

function renderAgentLiveActivityLog(ticket) {
  const isCollapsed = state.collapsedPanels["log-panel"];
  const agents = arrayOf(ticket.agent_panel);
  const agent = agents.find(a => a.key === state.selectedAgentKey) || agents[0];
  if (!agent) return "";

  const run = currentAgentRun(agent);
  const progress = agentProgressPercent(agent, run);
  const status = effectiveAgentStatus(agent, run);
  const rawEntries = buildLiveLogEntries(ticket, agent, run);
  const baseEntries = normaliseThinkingEntriesForRunState(rawEntries, agent, run);
  const snapshot = buildReasoningSnapshot(ticket, agent, run, baseEntries);
  const entries = normaliseThinkingEntriesForRunState(enrichThinkingEntriesWithReasoning(baseEntries, snapshot, agent, run), agent, run);
  const doneCount = entries.filter(entry => entry.state === "done").length;
  const activeCount = entries.filter(entry => entry.state === "active").length;
  const pendingCount = entries.filter(entry => entry.state === "pending").length;
  const failedCount = entries.filter(entry => entry.state === "failed").length;
  const focus = currentThinkingFocus(entries, agent);
  const subtitle = runIsActive(run)
    ? "Live view of what the selected agent is checking and doing now"
    : "Latest explainable working trace for the selected agent";

  return `<div class="agent-live-log-panel agent-thinking-panel deep-reasoning-panel ${isCollapsed ? "is-collapsed" : "is-expanded"}">
    <div class="panel-collapsible-header" data-action="toggle-panel" data-panel="log-panel">
      <div>
        <h3><i class="ti ti-brain"></i> Agent Working Progress</h3>
        <small>${esc(subtitle)}</small>
      </div>
      <button class="collapse-btn"><i class="ti ${isCollapsed ? "ti-chevron-right" : "ti-chevron-down"}"></i></button>
    </div>
    ${!isCollapsed ? `<div class="panel-body agent-thinking-body deep-reasoning-body">
      <div class="thinking-focus-card ${esc(status)}">
        <div>
          <span>Current focus</span>
          <strong>${esc(focus)}</strong>
          <p>${esc(snapshot.objective)}</p>
        </div>
        <div class="thinking-progress-chip"><strong>${esc(progress)}%</strong><span>${esc(displayAgentStatus(agent, run))}</span></div>
      </div>
      ${renderAgentReasoningSummary(snapshot, agent, run)}
      <div class="thinking-metrics-row">
        <div class="thinking-metric"><span>Done</span><strong>${esc(doneCount)}</strong></div>
        <div class="thinking-metric active"><span>Working</span><strong>${esc(activeCount)}</strong></div>
        <div class="thinking-metric"><span>Queued</span><strong>${esc(pendingCount)}</strong></div>
        <div class="thinking-metric failed"><span>Issues</span><strong>${esc(failedCount)}</strong></div>
      </div>
      <div class="reasoning-section-label"><i class="ti ti-route"></i><span>Step-by-step working progress</span></div>
      ${renderLiveLogTrace(entries, agent, run)}
    </div>` : ""}
  </div>`;
}

/* ==================== RICH WORD/PDF DOCUMENT FORMATTING OVERRIDES ==================== */
/*
  These overrides keep the existing download button behaviour, but make the Word/PDF
  outputs human-readable for SOC analysts. Reporting downloads render the generated
  reporting sections with template-like structure, markdown cleanup, headings, bold
  labels, readable sizing, and tables where possible.
*/

function stripMarkdownDecorators(value = "") {
  return String(value || "")
    .replace(/```[\s\S]*?```/g, match => match.replace(/```[a-zA-Z]*\n?|```/g, ""))
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/__([^_]+)__/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2013\u2014]/g, "-");
}

function inlineMarkdownHtml(value = "") {
  let text = esc(value);
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/\b(Critical|High|Medium|Low|Malicious|Suspicious|Approved|Rejected|Failed|Completed|Ready for Closure|Containment|Immediate|Risk|Confidence|Severity)\b/g, "<strong>$1</strong>");
  return text;
}

function lineLooksLikeMarkdownTable(line = "") {
  const value = String(line || "").trim();
  return value.includes("|") && value.split("|").filter(Boolean).length >= 2;
}

function lineLooksLikeTableSeparator(line = "") {
  return /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(String(line || ""));
}

function splitMarkdownTableRow(line = "") {
  return String(line || "").trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(cell => cell.trim());
}

function parseMarkdownReportBlocks(text = "") {
  const cleaned = String(text || "").replace(/\r/g, "");
  const lines = cleaned.split("\n");
  const blocks = [];
  let i = 0;

  const isBlockStarter = (line, nextLine = "") => {
    const value = String(line || "").trim();
    return !value || /^#{1,6}\s+/.test(value) || /^[-*•]\s+/.test(value) || /^\d+[.)]\s+/.test(value) || (lineLooksLikeMarkdownTable(value) && lineLooksLikeTableSeparator(nextLine));
  };

  while (i < lines.length) {
    const raw = lines[i] || "";
    const line = raw.trim();
    const next = lines[i + 1] || "";
    if (!line) { i += 1; continue; }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      blocks.push({ type: "heading", level: Math.min(4, heading[1].length), text: heading[2].trim() });
      i += 1;
      continue;
    }

    const firstTableCells = line.includes("|") ? splitMarkdownTableRow(line) : [];
    let tableLookahead = i + 1;
    while (tableLookahead < lines.length && !String(lines[tableLookahead] || "").trim()) tableLookahead += 1;
    const lookaheadLine = lines[tableLookahead] || "";
    const lookaheadCells = lookaheadLine.includes("|") ? splitMarkdownTableRow(lookaheadLine) : [];
    if (firstTableCells.length >= 2 && (
      lineLooksLikeTableSeparator(lookaheadLine) ||
      (lookaheadCells.length === firstTableCells.length && lookaheadLine.includes("|"))
    )) {
      const headers = splitMarkdownTableRow(line);
      i += 1;
      const rows = [];
      while (i < lines.length) {
        let blanks = 0;
        while (i < lines.length && !String(lines[i] || "").trim()) { blanks += 1; i += 1; }
        if (blanks >= 2 || i >= lines.length) break;
        if (lineLooksLikeTableSeparator(lines[i])) { i += 1; continue; }
        if (!String(lines[i] || "").includes("|")) break;
        const cells = splitMarkdownTableRow(lines[i]);
        if (cells.length > headers.length || cells.length < 2) break;
        rows.push(cells.concat(Array(Math.max(0, headers.length - cells.length)).fill("")));
        i += 1;
      }
      if (rows.length) blocks.push({ type: "table", headers, columns: headers, rows });
      else blocks.push({ type: "paragraph", text: line });
      continue;
    }

    if (/^[-*•]\s+/.test(line) || /^\d+[.)]\s+/.test(line)) {
      const ordered = /^\d+[.)]\s+/.test(line);
      const items = [];
      while (i < lines.length) {
        const itemLine = String(lines[i] || "").trim();
        if (ordered && /^\d+[.)]\s+/.test(itemLine)) {
          items.push(itemLine.replace(/^\d+[.)]\s+/, ""));
          i += 1;
          continue;
        }
        if (!ordered && /^[-*•]\s+/.test(itemLine)) {
          items.push(itemLine.replace(/^[-*•]\s+/, ""));
          i += 1;
          continue;
        }
        break;
      }
      blocks.push({ type: ordered ? "ordered_list" : "bullet_list", items });
      continue;
    }

    const keyValue = line.match(/^\*{0,2}([A-Za-z][A-Za-z0-9 /&()_\-]{2,70})\*{0,2}:\s*(.+)$/);
    if (keyValue && keyValue[2].trim().length) {
      blocks.push({ type: "key_value", key: keyValue[1].replaceAll("_", " ").trim(), value: keyValue[2].trim() });
      i += 1;
      continue;
    }

    const paragraphLines = [line];
    i += 1;
    while (i < lines.length && !isBlockStarter(lines[i], lines[i + 1])) {
      paragraphLines.push(String(lines[i] || "").trim());
      i += 1;
    }
    blocks.push({ type: "paragraph", text: paragraphLines.join(" ").replace(/\s+/g, " ").trim() });
  }

  return blocks.length ? blocks : [{ type: "paragraph", text: String(text || "No content available.") }];
}

function renderMarkdownBlocksForDocument(blocks = []) {
  const keyValueRows = [];
  const html = [];
  const flushKeyValues = () => {
    if (!keyValueRows.length) return;
    html.push(`<table class="kv-doc-table"><tbody>${keyValueRows.map(row => `<tr><th>${inlineMarkdownHtml(row.key)}</th><td>${inlineMarkdownHtml(row.value)}</td></tr>`).join("")}</tbody></table>`);
    keyValueRows.length = 0;
  };

  arrayOf(blocks).forEach(block => {
    if (block.type !== "key_value") flushKeyValues();
    if (block.type === "heading") {
      const tag = block.level <= 1 ? "h2" : block.level === 2 ? "h2" : "h3";
      html.push(`<${tag}>${inlineMarkdownHtml(block.text)}</${tag}>`);
    } else if (block.type === "paragraph") {
      html.push(`<p>${inlineMarkdownHtml(block.text)}</p>`);
    } else if (block.type === "bullet_list") {
      html.push(`<ul>${arrayOf(block.items).map(item => `<li>${inlineMarkdownHtml(item)}</li>`).join("")}</ul>`);
    } else if (block.type === "ordered_list") {
      html.push(`<ol>${arrayOf(block.items).map(item => `<li>${inlineMarkdownHtml(item)}</li>`).join("")}</ol>`);
    } else if (block.type === "table") {
      html.push(`<table class="report-doc-table"><thead><tr>${arrayOf(block.headers).map(h => `<th>${inlineMarkdownHtml(h)}</th>`).join("")}</tr></thead><tbody>${arrayOf(block.rows).map(row => `<tr>${arrayOf(row).map(cell => `<td>${inlineMarkdownHtml(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
    } else if (block.type === "key_value") {
      keyValueRows.push(block);
    }
  });
  flushKeyValues();
  return html.join("\n");
}

function reportTemplateDescriptor(reportKey = "") {
  const map = {
    executive_summary: {
      subtitle: "Executive-level incident summary for SOC manager review",
      sections: ["Business Impact", "Severity and Confidence", "Recommended Response"],
    },
    technical_findings: {
      subtitle: "Technical evidence, affected assets, indicators, and investigation notes",
      sections: ["Evidence Summary", "Indicators of Compromise", "Affected Assets", "Technical Analysis"],
    },
    soc_analyst_review: {
      subtitle: "Analyst-facing review notes, decision gates, limitations, and next actions",
      sections: ["Analyst Decision", "Limitations", "Approval Notes", "Recommended Next Steps"],
    },
    final_incident_report: {
      subtitle: "Complete incident record for handover, closure, and post-incident review",
      sections: ["Incident Overview", "Timeline", "Evidence", "Impact", "Actions Taken", "Recommendations"],
    },
  };
  return map[reportKey] || { subtitle: "SOC report generated from reporting templates", sections: [] };
}

function documentHtmlShell({ title = "SOC Document", subtitle = "", meta = [], body = "", accent = "#2563eb" } = {}) {
  const metaRows = arrayOf(meta).map(item => `<tr><th>${esc(item.label)}</th><td>${inlineMarkdownHtml(item.value)}</td></tr>`).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title>
  <style>
    @page{margin:28mm 22mm 26mm 22mm}
    body{font-family:Arial,Calibri,sans-serif;color:#111827;line-height:1.55;margin:32px;font-size:11.5pt}
    .doc-cover{border-bottom:4px solid ${accent};padding-bottom:14px;margin-bottom:22px}
    .doc-eyebrow{font-size:9pt;text-transform:uppercase;letter-spacing:.12em;font-weight:700;color:${accent};margin:0 0 6px}
    h1{font-size:24pt;line-height:1.1;margin:0 0 6px;color:#0f172a;font-weight:800}
    .subtitle{font-size:11pt;color:#475569;margin:0 0 10px}
    h2{font-size:15.5pt;margin:22px 0 8px;color:#0f172a;border-bottom:1px solid #cbd5e1;padding-bottom:5px;font-weight:800}
    h3{font-size:12.5pt;margin:17px 0 6px;color:#1e293b;font-weight:800}
    p{margin:0 0 10px}.important{font-weight:700;color:#0f172a}
    strong{font-weight:800;color:#0f172a}code{font-family:Consolas,monospace;background:#eef2ff;padding:1px 3px;border-radius:3px;color:#1e3a8a}
    ul,ol{margin:6px 0 12px 22px;padding:0}li{margin:4px 0}
    .meta-table,.kv-doc-table,.report-doc-table{width:100%;border-collapse:collapse;margin:12px 0 16px;page-break-inside:avoid}
    .meta-table th,.meta-table td,.kv-doc-table th,.kv-doc-table td,.report-doc-table th,.report-doc-table td{border:1px solid #cbd5e1;padding:7px 9px;vertical-align:top}
    .meta-table th,.kv-doc-table th{width:28%;background:#f1f5f9;color:#334155;text-align:left;font-weight:800}
    .report-doc-table th{background:#eaf2ff;color:#1e3a8a;text-align:left;font-weight:800}
    .summary-callout{border-left:5px solid ${accent};background:#f8fafc;border-top:1px solid #dbeafe;border-right:1px solid #dbeafe;border-bottom:1px solid #dbeafe;padding:12px 14px;margin:14px 0 18px;page-break-inside:avoid}
    .template-note{font-size:9.5pt;color:#64748b;margin-top:6px}.footer-note{border-top:1px solid #cbd5e1;margin-top:28px;padding-top:8px;font-size:9pt;color:#64748b}
  </style></head><body>
    <div class="doc-cover"><p class="doc-eyebrow">Agentic SOC Assistant</p><h1>${esc(title)}</h1>${subtitle ? `<p class="subtitle">${esc(subtitle)}</p>` : ""}</div>
    ${metaRows ? `<table class="meta-table"><tbody>${metaRows}</tbody></table>` : ""}
    ${body}
    <p class="footer-note">Generated by Agentic SOC Assistant. JSON download is available separately for raw machine-readable output.</p>
  </body></html>`;
}

function summaryDocumentHtml(payload = {}) {
  const findings = arrayOf(payload.findings);
  const files = arrayOf(payload.files);
  const body = `
    <div class="summary-callout"><strong>Summary:</strong> ${inlineMarkdownHtml(payload.headline || "No summary available.")}</div>
    <h2>Decision Overview</h2>
    <table class="kv-doc-table"><tbody>
      <tr><th>Status</th><td>${inlineMarkdownHtml(payload.status || "Unknown")}</td></tr>
      <tr><th>Severity</th><td>${inlineMarkdownHtml(payload.severity || "Unknown")}</td></tr>
      <tr><th>Confidence</th><td>${inlineMarkdownHtml(payload.confidence || "Unknown")}</td></tr>
      <tr><th>Decision / Classification</th><td>${inlineMarkdownHtml(payload.classification || "Not recorded")}</td></tr>
      <tr><th>Next Action</th><td>${inlineMarkdownHtml(payload.next_action || "Review output")}</td></tr>
    </tbody></table>
    <h2>Key Points</h2>
    ${findings.length ? `<ul>${findings.map(item => `<li>${inlineMarkdownHtml(item)}</li>`).join("")}</ul>` : `<p>No key points found in the saved output.</p>`}
    ${files.filter(item => !looksLikeLocalFilesystemPath(item)).length ? `<h2>Generated Files</h2><ul>${files.filter(item => !looksLikeLocalFilesystemPath(item)).map(item => `<li>${inlineMarkdownHtml(item)}</li>`).join("")}</ul>` : ""}
  `;
  return documentHtmlShell({
    title: `${payload.agent_label || "Agent"} Summary`,
    subtitle: "Readable analyst summary generated from the selected agent output",
    meta: [
      { label: "Ticket", value: `${payload.ticket_id || "Unknown"} | ${payload.ticket_title || "Untitled Ticket"}` },
      { label: "Agent", value: payload.agent_label || payload.agent_key || "Unknown Agent" },
      { label: "Generated", value: payload.generated_at || new Date().toLocaleString() },
    ],
    body,
    accent: "#2563eb",
  });
}

function reportDocumentHtml(report = {}) {
  const descriptor = reportTemplateDescriptor(report.report_key);
  const cleanedContent = cleanReportContentForDocument(report.content || "");
  const blocks = parseMarkdownReportBlocks(cleanedContent);
  const body = `
    ${renderMarkdownBlocksForDocument(blocks)}
  `;
  return documentHtmlShell({
    title: report.report_title || "SOC Report",
    subtitle: descriptor.subtitle,
    meta: [
      { label: "Ticket", value: `${report.ticket_id || "Unknown"} | ${report.ticket_title || "Untitled Ticket"}` },
      { label: "Report Type", value: report.report_title || "SOC Report" },
      { label: "Generated", value: report.generated_at || new Date().toLocaleString() },
    ],
    body,
    accent: "#059669",
  });
}

function plainPdfText(value = "") {
  return stripMarkdownDecorators(value).replace(/\s+/g, " ").trim();
}

function modelFromAgentSummary(payload = {}) {
  return {
    title: `${payload.agent_label || "Agent"} Summary`,
    subtitle: `Ticket ${payload.ticket_id || "Unknown"} | ${payload.ticket_title || "Untitled Ticket"}`,
    meta: [
      ["Agent", payload.agent_label || payload.agent_key || "Unknown"],
      ["Generated", payload.generated_at || new Date().toLocaleString()],
      ["Status", payload.status || "Unknown"],
      ["Severity", payload.severity || "Unknown"],
      ["Confidence", payload.confidence || "Unknown"],
      ["Decision", payload.classification || "Not recorded"],
      ["Next Action", payload.next_action || "Review output"],
    ],
    blocks: [
      { type: "heading", text: "Summary", level: 2 },
      { type: "paragraph", text: payload.headline || "No summary available." },
      { type: "heading", text: "Key Points", level: 2 },
      { type: "bullet_list", items: arrayOf(payload.findings).length ? arrayOf(payload.findings) : ["No key points found in the saved output."] },
    ],
  };
}

function modelFromReport(report = {}) {
  const descriptor = reportTemplateDescriptor(report.report_key);
  return {
    title: report.report_title || "SOC Report",
    subtitle: descriptor.subtitle || `Ticket ${report.ticket_id || "Unknown"}`,
    meta: [
      ["Ticket", `${report.ticket_id || "Unknown"} | ${report.ticket_title || "Untitled Ticket"}`],
      ["Report Type", report.report_title || "SOC Report"],
      ["Generated", report.generated_at || new Date().toLocaleString()],
    ],
    blocks: parseMarkdownReportBlocks(cleanReportContentForDocument(report.content || "No report content available.")),
  };
}

function wrapPdfText(text = "", maxWidth = 500, fontSize = 10) {
  const approxCharWidth = fontSize * 0.52;
  const maxChars = Math.max(24, Math.floor(maxWidth / approxCharWidth));
  return wrapText(plainPdfText(text), maxChars);
}

function buildStyledPdfBlob(doc = {}) {
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 48;
  const bottom = 52;
  const usableWidth = pageWidth - margin * 2;
  const pages = [];
  let commands = [];
  let y = pageHeight - margin;

  const newPage = () => {
    if (commands.length) pages.push(commands.join("\n"));
    commands = [];
    y = pageHeight - margin;
  };
  const ensureSpace = (needed = 40) => {
    if (y - needed < bottom) newPage();
  };
  const textCmd = (text, x, yy, font = "F1", size = 10) => `BT /${font} ${size} Tf ${x} ${yy.toFixed(2)} Td (${pdfSafeText(text)}) Tj ET`;
  const drawText = (text, { x = margin, size = 10, font = "F1", leading = 1.35, maxWidth = usableWidth, spaceAfter = 4 } = {}) => {
    const lines = wrapPdfText(text, maxWidth, size);
    lines.forEach(line => {
      ensureSpace(size * leading + 2);
      commands.push(textCmd(line, x, y, font, size));
      y -= size * leading;
    });
    y -= spaceAfter;
  };
  const drawRule = () => { ensureSpace(12); commands.push(`0.80 0.84 0.90 RG ${margin} ${y.toFixed(2)} m ${pageWidth - margin} ${y.toFixed(2)} l S`); y -= 14; };
  const drawHeading = (text, level = 2) => {
    const size = level <= 1 ? 20 : level === 2 ? 14 : 12;
    ensureSpace(size * 2.2);
    y -= level <= 1 ? 0 : 4;
    drawText(text, { size, font: "F2", leading: 1.15, spaceAfter: 6 });
    if (level <= 2) drawRule();
  };
  const drawMetaTable = (rows = []) => {
    if (!arrayOf(rows).length) return;
    ensureSpace(24);
    rows.forEach(([label, value]) => {
      ensureSpace(26);
      commands.push(`0.94 0.97 1.00 rg ${margin} ${(y - 18).toFixed(2)} ${usableWidth} 22 re f`);
      commands.push(`0.78 0.83 0.90 RG ${margin} ${(y - 18).toFixed(2)} ${usableWidth} 22 re S`);
      commands.push(textCmd(String(label || ""), margin + 8, y - 13, "F2", 9));
      const valueLines = wrapPdfText(value || "", usableWidth - 170, 9);
      commands.push(textCmd(valueLines[0] || "", margin + 150, y - 13, "F1", 9));
      y -= 22;
    });
    y -= 8;
  };
  const drawBullets = (items = []) => {
    arrayOf(items).forEach(item => {
      wrapPdfText(item, usableWidth - 18, 10).forEach((line, idx) => {
        ensureSpace(16);
        commands.push(textCmd(idx === 0 ? "-" : " ", margin, y, "F2", 10));
        commands.push(textCmd(line, margin + 18, y, "F1", 10));
        y -= 13.5;
      });
    });
    y -= 4;
  };
  const drawSimpleTable = (headers = [], rows = []) => {
    const cells = [arrayOf(headers), ...arrayOf(rows)].filter(row => row.length);
    cells.slice(0, 24).forEach((row, rowIndex) => {
      const text = row.map(cell => stripMarkdownDecorators(cell)).join(" | ");
      drawText(text, { size: 9, font: rowIndex === 0 ? "F2" : "F1", maxWidth: usableWidth, spaceAfter: 2 });
    });
    y -= 4;
  };

  drawHeading(doc.title || "SOC Document", 1);
  if (doc.subtitle) drawText(doc.subtitle, { size: 10, font: "F1", spaceAfter: 10 });
  drawMetaTable(doc.meta || []);

  arrayOf(doc.blocks).forEach(block => {
    if (block.type === "heading") drawHeading(block.text, block.level || 2);
    else if (block.type === "paragraph") drawText(block.text, { size: 10, font: /critical|high|approved|containment|severity|confidence/i.test(block.text || "") ? "F2" : "F1" });
    else if (block.type === "bullet_list" || block.type === "ordered_list") drawBullets(block.items || []);
    else if (block.type === "key_value") drawMetaTable([[block.key, block.value]]);
    else if (block.type === "table") drawSimpleTable(block.headers || [], block.rows || []);
  });
  if (commands.length) pages.push(commands.join("\n"));

  const objects = [];
  const addObject = (body) => { objects.push(body); return objects.length; };
  const catalogId = addObject("<< /Type /Catalog /Pages 2 0 R >>");
  const pagesPlaceholderId = addObject("PAGES_PLACEHOLDER");
  const fontRegularId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const fontBoldId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  const kids = [];
  pages.forEach(stream => {
    const contentId = addObject(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    const pageId = addObject(`<< /Type /Page /Parent ${pagesPlaceholderId} 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R >> >> /Contents ${contentId} 0 R >>`);
    kids.push(`${pageId} 0 R`);
  });
  objects[pagesPlaceholderId - 1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${kids.length} >>`;

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((body, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => { pdf += `${String(offset).padStart(10, "0")} 00000 n \n`; });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([pdf], { type: "application/pdf" });
}

function downloadAgentSummaryPdf(agentKey, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const payload = buildAgentSummaryPayload(t, agentKey);
  if (!Object.keys(payload.raw_output || {}).length) return toast("No saved output is available for this agent yet.", "yellow");
  const filename = `${safeFilename(payload.ticket_id)}_${safeFilename(payload.agent_key)}_summary.pdf`;
  downloadBlob(filename, buildStyledPdfBlob(modelFromAgentSummary(payload)), "application/pdf");
  toast("PDF summary downloaded.", "green");
}

async function downloadReportingReport(reportKey, ticketId, format) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const report = buildReportingReportPayload(t, reportKey);
  if (!report.has_content) return toast(`${report.report_title} has not been generated yet.`, "yellow");
  const base = `${safeFilename(report.ticket_id)}_${safeFilename(report.report_key)}`;
  if (format === "json") {
    downloadBlob(`${base}.json`, JSON.stringify(safeReportJson(report), null, 2), "application/json;charset=utf-8");
    return toast(`${report.report_title} JSON downloaded.`, "green");
  }

  // Reporting Word/PDF should come from the backend report_templates/*.md.j2 flow when available.
  // The frontend only falls back to cleaned readable content so it never injects local paths or template notes.
  if (format === "word" || format === "pdf") {
    const backendDownloaded = await tryDownloadBackendReportArtifact(report, format);
    if (backendDownloaded) {
      return toast(`${report.report_title} ${format === "pdf" ? "PDF" : "Word document"} downloaded.`, "green");
    }
  }

  if (format === "word") {
    downloadBlob(`${base}.doc`, reportDocumentHtml(report), "application/msword;charset=utf-8");
    return toast(`${report.report_title} Word document downloaded using cleaned report content.`, "green");
  }
  if (format === "pdf") {
    downloadBlob(`${base}.pdf`, buildStyledPdfBlob(modelFromReport(report)), "application/pdf");
    return toast(`${report.report_title} PDF downloaded using cleaned report content.`, "green");
  }
}

/* ==================== RELIABLE DOCX/PDF DOWNLOAD FIX ====================
   This final override fixes unreadable Word/PDF downloads by producing real
   .docx OOXML packages and byte-correct PDF files in the browser fallback.
   Backend-generated artifacts are still preferred, but HTML/error responses
   are ignored so the dashboard never downloads an unreadable error page.
==================== */

function utf8Bytes(value = "") {
  return new TextEncoder().encode(String(value || ""));
}

function concatBytes(parts = []) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  parts.forEach(part => { out.set(part, offset); offset += part.length; });
  return out;
}

function le16(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value & 0xffff, true);
  return out;
}

function le32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
}

const __crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = __crc32Table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZipBlob(files = {}) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const now = new Date();
  const dosTime = ((now.getHours() & 31) << 11) | ((now.getMinutes() & 63) << 5) | ((Math.floor(now.getSeconds() / 2)) & 31);
  const dosDate = (((now.getFullYear() - 1980) & 127) << 9) | (((now.getMonth() + 1) & 15) << 5) | (now.getDate() & 31);

  Object.entries(files).forEach(([name, content]) => {
    const nameBytes = utf8Bytes(name);
    const data = content instanceof Uint8Array ? content : utf8Bytes(content);
    const crc = crc32(data);
    const localHeader = concatBytes([
      le32(0x04034b50), le16(20), le16(0), le16(0), le16(dosTime), le16(dosDate),
      le32(crc), le32(data.length), le32(data.length), le16(nameBytes.length), le16(0), nameBytes,
    ]);
    localParts.push(localHeader, data);

    const centralHeader = concatBytes([
      le32(0x02014b50), le16(20), le16(20), le16(0), le16(0), le16(dosTime), le16(dosDate),
      le32(crc), le32(data.length), le32(data.length), le16(nameBytes.length), le16(0), le16(0),
      le16(0), le16(0), le32(0), le32(offset), nameBytes,
    ]);
    centralParts.push(centralHeader);
    offset += localHeader.length + data.length;
  });

  const centralStart = offset;
  const centralDir = concatBytes(centralParts);
  const fileCount = Object.keys(files).length;
  const endRecord = concatBytes([
    le32(0x06054b50), le16(0), le16(0), le16(fileCount), le16(fileCount),
    le32(centralDir.length), le32(centralStart), le16(0),
  ]);
  return new Blob([concatBytes([...localParts, centralDir, endRecord])], {
    type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  });
}

function xmlEsc(value = "") {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cleanDocText(value = "") {
  return stripMarkdownDecorators(String(value || ""))
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function docxRun(text = "", opts = {}) {
  const props = [];
  if (opts.bold) props.push("<w:b/>");
  if (opts.italic) props.push("<w:i/>");
  if (opts.size) props.push(`<w:sz w:val="${opts.size}"/>`);
  if (opts.color) props.push(`<w:color w:val="${opts.color.replace(/^#/, "")}"/>`);
  const rPr = props.length ? `<w:rPr>${props.join("")}</w:rPr>` : "";
  return `<w:r>${rPr}<w:t xml:space="preserve">${xmlEsc(text)}</w:t></w:r>`;
}

function docxInlineRuns(value = "", opts = {}) {
  const text = String(value || "");
  const parts = text.split(/(\*\*[^*]+\*\*|__[^_]+__|`[^`]+`)/g).filter(Boolean);
  if (!parts.length) return docxRun("", opts);
  return parts.map(part => {
    if (/^\*\*[^*]+\*\*$/.test(part)) return docxRun(part.slice(2, -2), { ...opts, bold: true });
    if (/^__[^_]+__$/.test(part)) return docxRun(part.slice(2, -2), { ...opts, bold: true });
    if (/^`[^`]+`$/.test(part)) return docxRun(part.slice(1, -1), { ...opts, color: "1E3A8A" });
    return docxRun(part, opts);
  }).join("");
}

function docxParagraph(value = "", opts = {}) {
  const pPr = [];
  if (opts.heading) pPr.push(`<w:keepNext/><w:spacing w:before="${opts.before || 180}" w:after="${opts.after || 100}"/>`);
  else pPr.push(`<w:spacing w:after="${opts.after || 120}"/>`);
  if (opts.align) pPr.push(`<w:jc w:val="${opts.align}"/>`);
  const runOpts = {
    bold: Boolean(opts.bold),
    size: opts.size || 22,
    color: opts.color || "111827",
  };
  return `<w:p><w:pPr>${pPr.join("")}</w:pPr>${docxInlineRuns(value, runOpts)}</w:p>`;
}

function docxBullet(value = "") {
  return `<w:p><w:pPr><w:spacing w:after="80"/><w:ind w:left="360" w:hanging="260"/></w:pPr>${docxRun("• ", { bold: true, size: 22, color: "2563EB" })}${docxInlineRuns(value, { size: 22, color: "111827" })}</w:p>`;
}

function docxTable(rows = []) {
  const validRows = arrayOf(rows).filter(row => arrayOf(row).length);
  if (!validRows.length) return "";
  const border = `<w:tblBorders><w:top w:val="single" w:sz="6" w:color="CBD5E1"/><w:left w:val="single" w:sz="6" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="6" w:color="CBD5E1"/><w:right w:val="single" w:sz="6" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="6" w:color="CBD5E1"/><w:insideV w:val="single" w:sz="6" w:color="CBD5E1"/></w:tblBorders>`;
  return `<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>${border}</w:tblPr>` + validRows.map((row, rowIndex) =>
    `<w:tr>${arrayOf(row).map(cell => `<w:tc><w:tcPr><w:tcW w:w="2400" w:type="dxa"/><w:shd w:fill="${rowIndex === 0 ? "EAF2FF" : "FFFFFF"}"/></w:tcPr>${docxParagraph(cell, { bold: rowIndex === 0, size: 20, color: rowIndex === 0 ? "1E3A8A" : "111827", after: 40 })}</w:tc>`).join("")}</w:tr>`
  ).join("") + `</w:tbl>${docxParagraph("", { after: 80 })}`;
}

function docxBlocksXml(blocks = []) {
  let xml = "";
  const keyValueRows = [];
  const flushKeyValues = () => {
    if (!keyValueRows.length) return;
    xml += docxTable([["Field", "Value"], ...keyValueRows.splice(0)]);
  };
  arrayOf(blocks).forEach(block => {
    if (block.type !== "key_value") flushKeyValues();
    if (block.type === "heading") xml += docxParagraph(block.text, { heading: true, bold: true, size: block.level <= 1 ? 32 : block.level === 2 ? 28 : 24, color: "0F172A", before: 220, after: 100 });
    else if (block.type === "paragraph") xml += docxParagraph(block.text, { size: 22 });
    else if (block.type === "bullet_list" || block.type === "ordered_list") arrayOf(block.items).forEach(item => { xml += docxBullet(item); });
    else if (block.type === "table") xml += docxTable([arrayOf(block.headers), ...arrayOf(block.rows)]);
    else if (block.type === "key_value") keyValueRows.push([block.key, block.value]);
  });
  flushKeyValues();
  return xml;
}

function buildDocxBlob(doc = {}) {
  const blocks = arrayOf(doc.blocks);
  const metaRows = arrayOf(doc.meta).map(row => Array.isArray(row) ? row : [row.label, row.value]);
  const body = [
    docxParagraph(doc.title || "SOC Document", { heading: true, bold: true, size: 40, color: "0F172A", after: 80 }),
    doc.subtitle ? docxParagraph(doc.subtitle, { size: 22, color: "475569", after: 180 }) : "",
    metaRows.length ? docxTable([["Field", "Details"], ...metaRows]) : "",
    docxBlocksXml(blocks),
    `<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1200" w:bottom="1440" w:left="1200" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>`,
  ].join("");

  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}</w:body></w:document>`;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;

  return makeZipBlob({
    "[Content_Types].xml": contentTypes,
    "_rels/.rels": rels,
    "word/document.xml": documentXml,
  });
}

function pdfByteLength(value = "") {
  return utf8Bytes(value).length;
}

function reliablePdfFromDoc(doc = {}) {
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 48;
  const bottom = 52;
  const maxWidth = pageWidth - margin * 2;
  const pages = [];
  let stream = "";
  let y = pageHeight - margin;
  const add = (cmd) => { stream += cmd + "\n"; };
  const newPage = () => { if (stream.trim()) pages.push(stream); stream = ""; y = pageHeight - margin; };
  const ensure = (height = 18) => { if (y - height < bottom) newPage(); };
  const pdfText = (text) => pdfSafeText(stripMarkdownDecorators(text));
  const line = (text, x, font, size) => { add(`BT /${font} ${size} Tf ${x} ${y.toFixed(2)} Td (${pdfText(text)}) Tj ET`); y -= size * 1.35; };
  const draw = (text, opts = {}) => {
    const size = opts.size || 10;
    const font = opts.bold ? "F2" : "F1";
    const x = opts.x || margin;
    const width = opts.width || maxWidth;
    const approxCharWidth = size * 0.52;
    const maxChars = Math.max(24, Math.floor(width / approxCharWidth));
    wrapText(stripMarkdownDecorators(String(text || "")), maxChars).forEach(part => { ensure(size * 1.5); line(part, x, font, size); });
    y -= opts.after == null ? 4 : opts.after;
  };
  const heading = (text, level = 2) => {
    const size = level <= 1 ? 20 : level === 2 ? 14 : 12;
    ensure(size * 2.4);
    draw(text, { size, bold: true, after: 6 });
    if (level <= 2) { add(`0.78 0.83 0.90 RG ${margin} ${y.toFixed(2)} m ${pageWidth - margin} ${y.toFixed(2)} l S`); y -= 12; }
  };
  const table = (rows = []) => {
    arrayOf(rows).forEach((row, idx) => {
      const text = arrayOf(row).map(cell => cleanDocText(cell)).join(" | ");
      draw(text, { size: 9, bold: idx === 0, after: 1 });
    });
    y -= 6;
  };

  heading(doc.title || "SOC Document", 1);
  if (doc.subtitle) draw(doc.subtitle, { size: 10, after: 10 });
  if (arrayOf(doc.meta).length) table([["Field", "Details"], ...arrayOf(doc.meta).map(row => Array.isArray(row) ? row : [row.label, row.value])]);
  arrayOf(doc.blocks).forEach(block => {
    if (block.type === "heading") heading(block.text, block.level || 2);
    else if (block.type === "paragraph") draw(block.text, { size: 10, bold: /critical|high|approved|containment|severity|confidence|malicious|risk/i.test(block.text || "") });
    else if (block.type === "bullet_list" || block.type === "ordered_list") arrayOf(block.items).forEach(item => draw(`- ${item}`, { size: 10, x: margin + 8, width: maxWidth - 8 }));
    else if (block.type === "key_value") table([[block.key, block.value]]);
    else if (block.type === "table") table([arrayOf(block.headers), ...arrayOf(block.rows)]);
  });
  newPage();

  const objects = [];
  const addObject = (body) => { objects.push(body); return objects.length; };
  const catalogId = addObject("<< /Type /Catalog /Pages 2 0 R >>");
  const pagesId = addObject("PAGES_PLACEHOLDER");
  const f1 = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const f2 = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  const kids = [];
  pages.forEach(pageStream => {
    const contentId = addObject(`<< /Length ${pdfByteLength(pageStream)} >>\nstream\n${pageStream}\nendstream`);
    const pageId = addObject(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${contentId} 0 R >>`);
    kids.push(`${pageId} 0 R`);
  });
  objects[pagesId - 1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${kids.length} >>`;

  const chunks = [];
  let offset = 0;
  const push = (s) => { const b = utf8Bytes(s); chunks.push(b); offset += b.length; };
  const offsets = [0];
  push("%PDF-1.4\n");
  objects.forEach((body, i) => { offsets.push(offset); push(`${i + 1} 0 obj\n${body}\nendobj\n`); });
  const xref = offset;
  push(`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`);
  offsets.slice(1).forEach(o => push(`${String(o).padStart(10, "0")} 00000 n \n`));
  push(`trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xref}\n%%EOF`);
  return new Blob([concatBytes(chunks)], { type: "application/pdf" });
}

function buildStyledPdfBlob(doc = {}) {
  return reliablePdfFromDoc(doc);
}

async function blobLooksLikeArtifact(blob, format) {
  if (!blob || blob.size < 20) return false;
  const head = await blob.slice(0, 8).arrayBuffer();
  const bytes = new Uint8Array(head);
  const sig = Array.from(bytes).map(b => String.fromCharCode(b)).join("");
  if (format === "pdf") return sig.startsWith("%PDF");
  if (format === "word" || format === "docx") return sig.startsWith("PK\u0003\u0004");
  return true;
}

async function tryDownloadBackendReportArtifact(report, format) {
  const routeFormat = format === "word" ? "docx" : format;
  const extension = format === "word" ? "docx" : format;
  const base = `${safeFilename(report.ticket_id)}_${safeFilename(report.report_key)}`;
  const routes = realReportExportRouteCandidates(report.ticket_id, report.report_key, routeFormat);
  for (const url of routes) {
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) continue;
      const contentType = (res.headers.get("content-type") || "").toLowerCase();
      if (contentType.includes("application/json")) {
        const payload = await res.clone().json().catch(() => null);
        const downloadUrl = payload?.download_url || payload?.url || payload?.file_url;
        if (downloadUrl && !looksLikeLocalFilesystemPath(downloadUrl)) {
          window.open(downloadUrl, "_blank");
          return true;
        }
        continue;
      }
      if (contentType.includes("text/html") || contentType.includes("text/plain")) continue;
      const blob = await res.blob();
      if (!(await blobLooksLikeArtifact(blob, format))) continue;
      downloadBlob(`${base}.${extension}`, blob, contentType || (format === "pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
      return true;
    } catch (err) {
      // Fall back to the next candidate route, then to browser-generated DOCX/PDF.
    }
  }
  return false;
}

function downloadAgentSummaryWord(agentKey, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const payload = buildAgentSummaryPayload(t, agentKey);
  if (!Object.keys(payload.raw_output || {}).length) return toast("No saved output is available for this agent yet.", "yellow");
  const filename = `${safeFilename(payload.ticket_id)}_${safeFilename(payload.agent_key)}_summary.docx`;
  downloadBlob(filename, buildDocxBlob(modelFromAgentSummary(payload)), "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
  toast("Word summary downloaded.", "green");
}

function downloadAgentSummaryPdf(agentKey, ticketId) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const payload = buildAgentSummaryPayload(t, agentKey);
  if (!Object.keys(payload.raw_output || {}).length) return toast("No saved output is available for this agent yet.", "yellow");
  const filename = `${safeFilename(payload.ticket_id)}_${safeFilename(payload.agent_key)}_summary.pdf`;
  downloadBlob(filename, buildStyledPdfBlob(modelFromAgentSummary(payload)), "application/pdf");
  toast("PDF summary downloaded.", "green");
}

async function downloadReportingReport(reportKey, ticketId, format) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const report = buildReportingReportPayload(t, reportKey);
  if (!report.has_content) return toast(`${report.report_title} has not been generated yet.`, "yellow");
  const base = `${safeFilename(report.ticket_id)}_${safeFilename(report.report_key)}`;
  if (format === "json") {
    downloadBlob(`${base}.json`, JSON.stringify(safeReportJson(report), null, 2), "application/json;charset=utf-8");
    return toast(`${report.report_title} JSON downloaded.`, "green");
  }
  if (format === "word" || format === "pdf") {
    const backendDownloaded = await tryDownloadBackendReportArtifact(report, format);
    if (backendDownloaded) return toast(`${report.report_title} ${format === "pdf" ? "PDF" : "Word document"} downloaded.`, "green");
  }
  if (format === "word") {
    downloadBlob(`${base}.docx`, buildDocxBlob(modelFromReport(report)), "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    return toast(`${report.report_title} Word document downloaded.`, "green");
  }
  if (format === "pdf") {
    downloadBlob(`${base}.pdf`, buildStyledPdfBlob(modelFromReport(report)), "application/pdf");
    return toast(`${report.report_title} PDF downloaded.`, "green");
  }
}
/* ==================== BACKEND TEMPLATE EXPORT OVERRIDES ====================
   Reporting/Triage/Investigation downloads must come from the Flask backend.
   The backend renders report_templates/*.md.j2 with ticket/agent context,
   creates real DOCX files, then converts those DOCX files to PDF.
   The browser no longer invents Word/PDF report content.
==================== */

function filenameFromContentDisposition(header, fallback) {
  const text = String(header || "");
  const utf = text.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf) return decodeURIComponent(utf[1].replace(/"/g, ""));
  const normal = text.match(/filename="?([^";]+)"?/i);
  if (normal) return normal[1];
  return fallback;
}

async function downloadBackendTemplateArtifact(url, fallbackFilename, label) {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) {
      const err = await res.json().catch(async () => ({ status: await res.text().catch(() => "Export failed") }));
      toast(err.status || err.error || `${label} export failed.`, "red");
      return false;
    }
    const contentType = res.headers.get("content-type") || "application/octet-stream";
    const blob = await res.blob();
    if (!blob || blob.size === 0) {
      toast(`${label} export returned an empty file.`, "red");
      return false;
    }
    const filename = filenameFromContentDisposition(res.headers.get("content-disposition"), fallbackFilename);
    downloadBlob(filename, blob, contentType);
    toast(`${label} downloaded.`, "green");
    return true;
  } catch (err) {
    toast(`${label} export failed: ${err.message || err}`, "red");
    return false;
  }
}

function backendExportFormat(format) {
  const value = String(format || "").toLowerCase();
  if (value === "word" || value === "doc" || value === "docx") return "docx";
  if (value === "pdf") return "pdf";
  return "json";
}

function backendExtension(format) {
  const value = backendExportFormat(format);
  return value === "docx" ? "docx" : value;
}

function backendAgentExportUrl(ticketId, agentKey, format) {
  return `/api/tickets/${encodeURIComponent(ticketId)}/exports/${encodeURIComponent(agentKey)}/${encodeURIComponent(backendExportFormat(format))}`;
}

function backendReportingExportUrl(ticketId, reportKey, format) {
  return `/api/tickets/${encodeURIComponent(ticketId)}/exports/reporting/${encodeURIComponent(reportKey)}/${encodeURIComponent(backendExportFormat(format))}`;
}

async function downloadAgentSummaryJson(agentKey, ticketId) {
  const base = `${safeFilename(ticketId)}_${safeFilename(agentKey)}_template_export.json`;
  return downloadBackendTemplateArtifact(backendAgentExportUrl(ticketId, agentKey, "json"), base, `${agentLabel(agentKey)} JSON`);
}

async function downloadAgentSummaryWord(agentKey, ticketId) {
  const base = `${safeFilename(ticketId)}_${safeFilename(agentKey)}_template_export.docx`;
  return downloadBackendTemplateArtifact(backendAgentExportUrl(ticketId, agentKey, "docx"), base, `${agentLabel(agentKey)} Word document`);
}

async function downloadAgentSummaryPdf(agentKey, ticketId) {
  const base = `${safeFilename(ticketId)}_${safeFilename(agentKey)}_template_export.pdf`;
  return downloadBackendTemplateArtifact(backendAgentExportUrl(ticketId, agentKey, "pdf"), base, `${agentLabel(agentKey)} PDF`);
}

async function downloadReportingReport(reportKey, ticketId, format) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const report = buildReportingReportPayload(t, reportKey);
  const reportTitle = report?.report_title || String(reportKey || "Report").replaceAll("_", " ");
  const ext = backendExtension(format);
  const base = `${safeFilename(ticketId)}_${safeFilename(reportKey)}.${ext}`;
  return downloadBackendTemplateArtifact(
    backendReportingExportUrl(ticketId, reportKey, format),
    base,
    `${reportTitle} ${ext.toUpperCase()}`
  );
}

/* -------------------------------------------------------------------------
   SOC structured report review workspace
   ------------------------------------------------------------------------- */

function socReportDefinitions() {
  return [
    { key: "executive_summary", title: "Executive Summary", description: "High-level overview of the incident and key findings.", icon: "ti-file-text", tone: "blue" },
    { key: "technical_findings", title: "Technical Findings", description: "Detailed technical analysis, evidence, and indicators.", icon: "ti-list-details", tone: "green" },
    { key: "soc_analyst_review", title: "SOC Analyst Review", description: "Analyst assessment, decisions, and recommendations.", icon: "ti-user", tone: "purple" },
    { key: "final_incident_report", title: "Final Incident Report", description: "Comprehensive report combining all approved sections.", icon: "ti-clipboard-text", tone: "amber" },
  ];
}

function reportManifestFromTicket(ticket = state.selectedTicket) {
  if (shouldMaskAgentOutput(ticket, "reporting")) return {};
  const rr = ticket?.reporting_result || {};
  return rr.report_manifest && typeof rr.report_manifest === "object" ? rr.report_manifest : {};
}

function reportSectionMeta(ticket = state.selectedTicket, reportKey = "") {
  const manifest = reportManifestFromTicket(ticket);
  return (manifest.sections || {})[reportKey] || {};
}

function reportReviewStatus(section = {}, ticket = state.selectedTicket) {
  const status = norm(section.status || "");
  if (status === "confirmed" || status === "exported" || section.confirmed_path) return { label: "Confirmed", tone: "green", exportReady: true };
  if (status.includes("draft")) return { label: "Draft saved", tone: "yellow", exportReady: false };
  if (ticket?.reporting_result) return { label: "Generated for review", tone: "blue", exportReady: false };
  return { label: "Not generated", tone: "red", exportReady: false };
}

function reportsForTicket(ticket) {
  return renderSocReportReviewWorkspace(ticket);
}

function renderReportingSummaryDownloads(ticket = {}, agent = {}, payload = {}) {
  const manifest = reportManifestFromTicket(ticket);
  const definitions = socReportDefinitions();
  const sections = manifest.sections || {};
  const confirmed = definitions.filter(def => reportReviewStatus(sections[def.key], ticket).exportReady).length;
  const generated = ticket.reporting_result ? definitions.length : 0;
  const mode = ticket.reporting_result?.reporting_mode || manifest.reporting_mode || "standard";
  const limitations = arrayOf(ticket.reporting_result?.investigation_limitations || ticket.reporting_result?.limitations || []);
  return `<div class="reporting-output-mini-summary">
    <div class="agent-summary-headline">
      <span class="summary-eyebrow">Reporting Agent Output</span>
      <strong>${esc(payload?.headline || ticket.reporting_result?.summary || "Generated reports are ready for SOC analyst review.")}</strong>
    </div>
    <div class="reporting-mini-grid">
      <span><strong>${esc(generated)}</strong> generated reports</span>
      <span><strong>${esc(confirmed)}/${esc(definitions.length)}</strong> confirmed</span>
      <span><strong>${esc(mode.replaceAll("_", " "))}</strong> reporting mode</span>
    </div>
    ${limitations.length ? `<div class="mini-warning"><i class="ti ti-alert-triangle"></i> Investigation limitations must remain documented in the report editor.</div>` : ""}
    <p class="mini-help-text">Use the full-width SOC Report Review Workspace in the centre panel to edit tables, save drafts, confirm review, and unlock Word/PDF export.</p>
  </div>`;
}

function renderSocReportReviewWorkspace(ticket = {}, options = {}) {
  const reportingAgent = arrayOf(ticket.agent_panel).find(a => canonicalAgentKey(a.key || a.label) === "reporting") || { key: "reporting", label: "Reporting" };
  if (reportingAgent.output_valid === false && ["rerun_required", "failed"].includes(reportingAgent.workflow_status)) {
    const actions = prioritisedAgentActions(reportingAgent).map(action => actionButtonForAgent(action, reportingAgent)).join("");
    return `<section class="soc-report-review-workspace reporting-rerun-placeholder">
      <div class="workflow-progress-message ${esc(reportingAgent.workflow_status)}"><i class="ti ${reportingAgent.workflow_status === "failed" ? "ti-alert-triangle" : "ti-refresh-alert"}"></i><span>${esc(reportingAgent.status_message || "The previous report is outdated and must be re-run before it can be used.")}</span></div>
      <div class="panel-actions">${actions}</div>
    </section>`;
  }
  if (shouldMaskAgentOutput(ticket, "reporting")) {
    const agent = reportingAgent;
    const run = currentAgentRun(agent);
    return `<section class="soc-report-review-workspace reporting-rerun-placeholder">
      ${renderAgentRunPendingSummary(agent, run)}
    </section>`;
  }
  const ticketId = ticket.ticket_id || state.selectedTicket?.ticket_id || "";
  const manifest = reportManifestFromTicket(ticket);
  const definitions = socReportDefinitions();
  const sections = manifest.sections || {};
  const allConfirmed = definitions.every(def => reportReviewStatus(sections[def.key], ticket).exportReady);
  const reportingMode = ticket.reporting_result?.reporting_mode || manifest.reporting_mode || "standard";
  const limitations = arrayOf(ticket.reporting_result?.investigation_limitations || ticket.reporting_result?.limitations || []);
  const generatedAt = ticket.reporting_result?.created_at || ticket.reporting_result?.generated_at || ticket.updated_at;
  const workflowActions = !ticket.reporting_result
    ? prioritisedAgentActions(reportingAgent).map(action => actionButtonForAgent(action, reportingAgent)).join("")
    : "";

  const rows = definitions.map(def => {
    const section = sections[def.key] || {};
    const status = reportReviewStatus(section, ticket);
    const available = Boolean(
      section.path
      || section.draft_path
      || section.confirmed_path
      || section.structured_draft_path
      || section.structured_confirmed_path
      || ticket.reporting_result?.[def.key]
    );
    const saved = available ? section.confirmed_at || section.last_saved_at || generatedAt : null;
    const openTitle = available ? `Open and edit ${def.title}` : `${def.title} has not been generated yet`;
    const exportTitle = status.exportReady ? `Export the reviewed ${def.title}` : "Open and edit the report, then choose Save & Enable Export.";
    const displayStatus = !available ? "Not generated" : status.exportReady ? "Export ready" : status.label === "Generated for review" ? "Draft ready" : status.label;
    const displayTone = available ? status.tone : "red";
    return `<div class="generated-file-row report-file-row" role="row">
      <div class="generated-file-document" role="cell">
        <span class="generated-file-icon ${esc(def.tone)}"><i class="ti ${esc(def.icon)}"></i></span>
        <div class="generated-file-copy">
          <div class="generated-file-title-line">
            <strong>${esc(def.title)}</strong>
            ${badge(displayStatus, displayTone)}
          </div>
          <p>${esc(def.description)}</p>
        </div>
      </div>
      <div class="generated-file-saved" role="cell">
        <span>${esc(saved ? shortDate(saved) : "Not generated")}</span>
        <small>${esc(section.confirmed_by ? `Reviewed by ${section.confirmed_by}` : section.last_saved_by ? `Edited by ${section.last_saved_by}` : "Generated draft")}</small>
      </div>
      <div class="generated-file-actions" role="cell">
        <button class="soc-btn primary report-open-action" ${available ? "" : "disabled"} title="${esc(openTitle)}" data-action="open-report-editor" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(def.key)}"><i class="ti ti-edit"></i> Open &amp; Edit</button>
        <button class="soc-btn ghost report-word-action ${status.exportReady ? "" : "disabled"}" ${status.exportReady ? "" : "disabled"} title="${esc(exportTitle)}" data-action="download-report-word" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(def.key)}"><i class="ti ti-file-type-docx"></i> Export Word</button>
        <button class="soc-btn ghost report-pdf-action ${status.exportReady ? "" : "disabled"}" ${status.exportReady ? "" : "disabled"} title="${esc(exportTitle)}" data-action="download-report-pdf" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(def.key)}"><i class="ti ti-file-type-pdf"></i> Export PDF</button>
      </div>
    </div>`;
  }).join("");

  return `<section class="panel soc-report-review-workspace report-files-workspace">
    <div class="panel-head generated-files-head">
      <div>
        <h2>Generated Files</h2>
        <span class="panel-sub">Open a generated report to review and edit it. Word and PDF export use the analyst-reviewed version.</span>
      </div>
      <div class="generated-files-status">
        ${workflowActions}
        ${badge(allConfirmed ? "All exports ready" : "Analyst review required", allConfirmed ? "green" : "yellow")}
      </div>
    </div>
    ${reportingMode === "with_limitations" || limitations.length ? `<div class="report-review-warning"><i class="ti ti-alert-triangle"></i><div><strong>Reporting with limitations</strong><p>Investigation evidence gaps must remain documented in the reviewed reports.</p>${limitations.length ? `<ul>${limitations.map(item => `<li>${esc(typeof item === "string" ? item : item.gap || item.reason || JSON.stringify(item))}</li>`).join("")}</ul>` : ""}</div></div>` : ""}
    <div class="report-review-rule"><i class="ti ti-pencil-check"></i> Open and edit a draft, then select <strong>Save &amp; Enable Export</strong>. The Word and PDF actions will export those saved edits.</div>
    <div class="generated-files-table" role="table" aria-label="Generated reporting files">
      <div class="generated-files-columns" role="row">
        <span role="columnheader">Document</span>
        <span role="columnheader">Last saved</span>
        <span role="columnheader">Actions</span>
      </div>
      <div class="generated-file-row reporting-data-row" role="row">
        <div class="generated-file-document" role="cell">
          <span class="generated-file-icon slate"><i class="ti ti-code"></i></span>
          <div class="generated-file-copy">
            <div class="generated-file-title-line"><strong>Reporting Data</strong></div>
            <p>Structured stage data used to generate the reporting documents.</p>
          </div>
        </div>
        <div class="generated-file-saved" role="cell">
          <span>${esc(generatedAt ? shortDate(generatedAt) : "Not generated")}</span>
          <small>Source data</small>
        </div>
        <div class="generated-file-actions" role="cell">
          <button class="soc-btn ghost report-json-action" ${ticket.reporting_result ? "" : "disabled"} data-action="download-reporting-data" data-ticket-id="${esc(ticketId)}" title="${ticket.reporting_result ? "Download structured reporting data" : "Reporting data has not been generated yet"}"><i class="ti ti-download"></i> Download JSON</button>
        </div>
      </div>
      ${rows}
    </div>
  </section>`;
}

function normaliseEditorBlocks(blocks = []) {
  if (!Array.isArray(blocks) || !blocks.length) {
    return [{ type: "paragraph", text: "No structured report content was returned. Add analyst-reviewed report text here." }];
  }
  return blocks.map(block => {
    const b = block && typeof block === "object" ? { ...block } : { type: "paragraph", text: String(block || "") };
    if (b.type === "table") {
      const columns = (Array.isArray(b.columns) ? b.columns : Array.isArray(b.headers) ? b.headers : []).map(stripReportUiMarkup);
      const rawRows = Array.isArray(b.rows) ? b.rows : [];
      const rows = rawRows.map(row => {
        if (Array.isArray(row)) return row.map(stripReportUiMarkup);
        if (row && typeof row === "object") return columns.map(col => stripReportUiMarkup(row[col] ?? row[col.toLowerCase?.()] ?? ""));
        return [stripReportUiMarkup(row)];
      });
      return { type: "table", title: stripReportUiMarkup(b.title || ""), columns, rows };
    }
    if (b.type === "heading") return { ...b, text: stripReportUiMarkup(b.text || "") };
    if (b.type === "bullet_list") return { ...b, items: arrayOf(b.items).map(stripReportUiMarkup).filter(Boolean) };
    return { ...b, text: stripReportUiMarkup(b.text || b.content || "") };
  });
}

function renderEditableReportBlock(block = {}, index = 0) {
  const type = block.type || "paragraph";
  if (type === "heading") {
    return `<div class="report-editor-block" data-block-index="${esc(index)}" data-block-type="heading" data-level="${esc(block.level || 2)}">
      <div class="editable-report-heading level-${esc(block.level || 2)}" contenteditable="true" data-field="text">${esc(block.text || "Section Heading")}</div>
    </div>`;
  }
  if (type === "bullet_list") {
    const items = arrayOf(block.items).length ? arrayOf(block.items) : [""];
    return `<div class="report-editor-block" data-block-index="${esc(index)}" data-block-type="bullet_list">
      <ul class="editable-report-list">${items.map(item => `<li contenteditable="true" data-list-item="true">${esc(item)}</li>`).join("")}</ul>
      <button class="mini-inline-btn" type="button" onclick="addEditableReportListItem(this)">+ Add bullet</button>
    </div>`;
  }
  if (type === "table") {
    const columns = arrayOf(block.columns).length ? arrayOf(block.columns) : ["Field", "Value"];
    const rows = arrayOf(block.rows).length ? arrayOf(block.rows) : [["", ""]];
    return `<div class="report-editor-block table-block" data-block-index="${esc(index)}" data-block-type="table">
      ${block.title ? `<h4 contenteditable="true" data-table-title="true">${esc(block.title)}</h4>` : ""}
      <table class="editable-report-table" data-report-table="true">
        <thead><tr>${columns.map(col => `<th contenteditable="true" data-cell-kind="header">${esc(col)}</th>`).join("")}</tr></thead>
        <tbody>${rows.map(row => `<tr>${columns.map((_, cidx) => `<td contenteditable="true" data-cell-kind="body">${esc((row || [])[cidx] || "")}</td>`).join("")}</tr>`).join("")}</tbody>
      </table>
      <div class="table-edit-actions"><button class="mini-inline-btn" type="button" onclick="addEditableReportTableRow(this)">+ Add row</button></div>
    </div>`;
  }
  return `<div class="report-editor-block" data-block-index="${esc(index)}" data-block-type="paragraph">
    <p class="editable-report-paragraph" contenteditable="true" data-field="text">${esc(block.text || "")}</p>
  </div>`;
}

function isDuplicateReportTitleBlock(block = {}, reportTitle = "") {
  if ((block.type || "") !== "heading") return false;
  const text = String(block.text || "").trim().toLowerCase();
  const title = String(reportTitle || "").trim().toLowerCase();
  const duplicateTitles = new Set([
    title,
    "cybersecurity incident post-incident review report",
    "post-incident review report",
    "incident report",
  ].filter(Boolean));
  return duplicateTitles.has(text);
}

function reportEditorIncidentId(payload = {}) {
  return payload.incident_id || state.selectedTicket?.incident_id || state.selectedTicket?.ticket_id || "Not recorded";
}

function renderReportEditorMetaTable(payload = {}, section = {}) {
  const incidentId = reportEditorIncidentId(payload);
  const reviewedBy = section.confirmed_by || section.last_saved_by || "SOC Analyst, pending";
  const generatedAt = section.confirmed_at || section.last_saved_at || state.selectedTicket?.reporting_result?.created_at || "Not recorded";
  return `<table class="editable-report-meta-table">
    <thead><tr><th>Field</th><th>Value</th></tr></thead>
    <tbody>
      <tr><td>Incident ID</td><td>${esc(incidentId)}</td></tr>
      <tr><td>Confirmed by</td><td>${esc(reviewedBy)}</td></tr>
      <tr><td>Generated at</td><td>${esc(generatedAt)}</td></tr>
    </tbody>
  </table>`;
}

function renderStructuredReportEditor(ticketId, reportKey, payload = {}) {
  const def = socReportDefinitions().find(item => item.key === reportKey) || { title: reportKey };
  const blocks = normaliseEditorBlocks(payload.blocks || []).filter((block, index) => index !== 0 || !isDuplicateReportTitleBlock(block, def.title));
  const section = payload.section || {};
  const exportReady = reportReviewStatus(section, state.selectedTicket).exportReady;
  const exportTitle = exportReady ? `Export ${def.title}` : "Save and enable export first";
  return `<div class="structured-report-editor-shell" id="report-editor-root" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(reportKey)}">
    <div class="structured-report-toolbar">
      <div><strong>${esc(def.title)}</strong><span id="report-editor-status">${esc(reportReviewStatus(section, state.selectedTicket).label)}</span></div>
      <div class="panel-actions report-editor-actions">
        <button class="soc-btn ghost" data-action="save-report-draft" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(reportKey)}"><i class="ti ti-device-floppy"></i> Save Draft</button>
        <button class="soc-btn primary" data-action="confirm-report-section" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(reportKey)}"><i class="ti ti-pencil-check"></i> Save &amp; Enable Export</button>
        <button class="soc-btn ghost editor-export-action ${exportReady ? "" : "disabled"}" ${exportReady ? "" : "disabled"} title="${esc(exportTitle)}" data-action="download-report-word" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(reportKey)}"><i class="ti ti-file-type-docx"></i> Word</button>
        <button class="soc-btn ghost editor-export-action report-pdf-action ${exportReady ? "" : "disabled"}" ${exportReady ? "" : "disabled"} title="${esc(exportTitle)}" data-action="download-report-pdf" data-ticket-id="${esc(ticketId)}" data-report-key="${esc(reportKey)}"><i class="ti ti-file-type-pdf"></i> PDF</button>
      </div>
    </div>
    <div class="editable-report-page">
      <div class="editable-report-logo-wrap"><img src="assets/aegis-logo.png" alt="Aegis" class="editable-report-logo"></div>
      <h1 class="editable-report-title">${esc(def.title)}</h1>
      ${renderReportEditorMetaTable(payload, section)}
      ${blocks.map(renderEditableReportBlock).join("")}
    </div>
  </div>`;
}

async function openStructuredReportEditor(ticketId, reportKey) {
  if (!ticketId || !reportKey) return toast("Select a ticket and report first.", "yellow");
  try {
    const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/reports/${encodeURIComponent(reportKey)}`);
    if (!res.success) return toast(res.status || "Report section is not available yet.", "red");
    const title = (socReportDefinitions().find(r => r.key === reportKey) || {}).title || reportKey.replaceAll("_", " ");
    openModal(title, `Ticket ${ticketId}`, renderStructuredReportEditor(ticketId, reportKey, res));
  } catch (err) {
    toast(`Could not open report editor: ${err.message || err}`, "red");
  }
}

function addEditableReportTableRow(button) {
  const table = button.closest(".report-editor-block")?.querySelector("table");
  if (!table) return;
  const columnCount = table.querySelectorAll("thead th").length || 2;
  const row = document.createElement("tr");
  row.innerHTML = Array.from({ length: columnCount }).map(() => `<td contenteditable="true" data-cell-kind="body"></td>`).join("");
  table.querySelector("tbody").appendChild(row);
}

function addEditableReportListItem(button) {
  const list = button.closest(".report-editor-block")?.querySelector("ul");
  if (!list) return;
  const item = document.createElement("li");
  item.setAttribute("contenteditable", "true");
  item.setAttribute("data-list-item", "true");
  item.textContent = "";
  list.appendChild(item);
  item.focus();
}

function collectStructuredReportBlocks() {
  const root = document.querySelector("#report-editor-root");
  if (!root) return [];
  return Array.from(root.querySelectorAll(".report-editor-block")).map(block => {
    const type = block.dataset.blockType || "paragraph";
    if (type === "heading") {
      return { type: "heading", level: Number(block.dataset.level || 2), text: block.querySelector("[data-field='text']")?.innerText?.trim() || "" };
    }
    if (type === "bullet_list") {
      return { type: "bullet_list", items: Array.from(block.querySelectorAll("[data-list-item]")).map(item => item.innerText.trim()).filter(Boolean) };
    }
    if (type === "table") {
      const columns = Array.from(block.querySelectorAll("thead th")).map(cell => cell.innerText.trim());
      const rows = Array.from(block.querySelectorAll("tbody tr")).map(row => Array.from(row.querySelectorAll("td")).map(cell => cell.innerText.trim()));
      const title = block.querySelector("[data-table-title]")?.innerText?.trim() || "";
      return { type: "table", title, columns, rows };
    }
    return { type: "paragraph", text: block.querySelector("[data-field='text']")?.innerText?.trim() || "" };
  });
}

function structuredBlocksToPlainText(blocks = []) {
  const out = [];
  blocks.forEach(block => {
    if (!block || typeof block !== "object") return;
    if (block.type === "heading") out.push(`\n${block.text || ""}`.trim());
    else if (block.type === "paragraph") out.push(block.text || "");
    else if (block.type === "bullet_list") arrayOf(block.items).forEach(item => out.push(`- ${item}`));
    else if (block.type === "table") {
      out.push(arrayOf(block.columns).join(" | "));
      arrayOf(block.rows).forEach(row => out.push(arrayOf(row).join(" | ")));
    }
  });
  return out.filter(Boolean).join("\n");
}

async function saveStructuredReportDraft(ticketId, reportKey) {
  const blocks = collectStructuredReportBlocks();
  if (!blocks.length) return toast("Open the report editor first.", "yellow");
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/reports/${encodeURIComponent(reportKey)}/draft`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analyst: "Soong Yang", blocks, text: structuredBlocksToPlainText(blocks) }),
  });
  if (res.success) {
    toast("Draft saved. You are still in the report editor.", "green");
    const status = document.querySelector("#report-editor-status");
    if (status) status.textContent = "Draft saved";
    await refreshSelectedTicket(ticketId, { renderAfter: false });
  } else toast(res.status || "Draft save failed.", "red");
}

async function confirmStructuredReportSection(ticketId, reportKey) {
  const root = document.querySelector("#report-editor-root");
  const body = { analyst: "Soong Yang" };
  if (root && root.dataset.reportKey === reportKey) {
    const blocks = collectStructuredReportBlocks();
    body.blocks = blocks;
    body.text = structuredBlocksToPlainText(blocks);
  }
  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/reports/${encodeURIComponent(reportKey)}/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.success) {
    toast("Edits saved. Word and PDF export are now ready.", "green");
    const status = document.querySelector("#report-editor-status");
    if (status) status.textContent = "Saved · Export ready";
    document.querySelectorAll("#report-editor-root .editor-export-action").forEach(button => {
      button.disabled = false;
      button.classList.remove("disabled");
      button.title = "Export the saved analyst-reviewed report";
    });
    document.querySelectorAll(`.generated-files-table [data-report-key="${reportKey}"][data-action="download-report-word"], .generated-files-table [data-report-key="${reportKey}"][data-action="download-report-pdf"]`).forEach(button => {
      button.disabled = false;
      button.classList.remove("disabled");
      button.title = "Export the saved analyst-reviewed report";
      const rowBadge = button.closest(".generated-file-row")?.querySelector(".soc-badge");
      if (rowBadge) {
        rowBadge.textContent = "Export ready";
        rowBadge.classList.remove("blue", "yellow", "red");
        rowBadge.classList.add("green");
      }
    });
    await refreshSelectedTicket(ticketId, { renderAfter: false });
  } else toast(res.status || "Report confirmation failed.", "red");
}

async function downloadReportingReport(reportKey, ticketId, format) {
  const t = state.selectedTicket;
  if (!t || t.ticket_id !== ticketId) return toast("Select the ticket first.", "yellow");
  const reportTitle = (socReportDefinitions().find(r => r.key === reportKey) || {}).title || String(reportKey || "Report").replaceAll("_", " ");
  const ext = backendExtension(format);
  if (ext === "json") return toast("JSON export is not part of the approved report package. Confirm the report, then download Word/PDF.", "yellow");
  const base = `${safeFilename(ticketId)}_${safeFilename(reportKey)}.${ext}`;
  return downloadBackendTemplateArtifact(
    `/api/tickets/${encodeURIComponent(ticketId)}/reports/${encodeURIComponent(reportKey)}/export/${encodeURIComponent(ext)}`,
    base,
    `${reportTitle} ${ext.toUpperCase()}`
  );
}
