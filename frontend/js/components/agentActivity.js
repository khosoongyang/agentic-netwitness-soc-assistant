// Agent Activity timeline — a pure renderer of backend events.
//
// It has no knowledge of what any stage "should" do: every row is one event
// recorded by the backend observability layer (observability/) from real
// execution, loaded from GET /api/cases/<id>/activity and then streamed live
// over SSE (GET /api/cases/<id>/activity/stream). Static here: badge names,
// status icons and layout. Dynamic: everything shown inside them.
//
// Event grouping uses the backend's own span ids: events sharing a span_id
// are the same operation (a "running" row is shown as resolved once a later
// event for that span arrives); events with a parent_span_id (e.g. the model
// calls LangChain reported inside an AI phase) are folded into the parent's
// expandable details instead of becoming rows of their own.

import { fetchJSON } from "../api.js";
import { escapeHTML } from "../ui.js";

const SOURCE_LABELS = {
  system: "SYSTEM",
  rule: "RULE ENGINE",
  tool: "TOOL",
  decision: "DECISION",
  orchestration: "ORCHESTRATION",
  human: "HUMAN",
};

// Only the labels the backend may emit under the current model
// configuration — deliberately no reasoning label, because the providers
// Aegis uses return no reasoning content.
const AI_LABELS = {
  assessment: "AI ASSESSMENT",
  explanation: "AI EXPLANATION",
  summary: "AI SUMMARY",
};

const STATUS_ICONS = {
  completed: "✓",
  warning: "!",
  failed: "✕",
  info: "•",
  waiting: "◷",
};

function sourceLabel(event) {
  if (event.source === "ai") return AI_LABELS[event.ai_content_kind] || "AI";
  return SOURCE_LABELS[event.source] || String(event.source || "").toUpperCase();
}

function badgeClass(event) {
  return event.source === "ai" ? `ai-${event.ai_content_kind || "assessment"}` : event.source;
}

function clockTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function elapsedSince(iso) {
  const started = new Date(iso).getTime();
  if (Number.isNaN(started)) return "";
  const seconds = Math.max(0, Math.round((Date.now() - started) / 1000));
  return seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
}

function renderBlock(block) {
  if (!block || typeof block !== "object") return "";
  const label = block.label ? `<h5>${escapeHTML(block.label)}</h5>` : "";
  if (block.type === "fields") {
    const rows = (block.fields || []).map((field) => `<dt>${escapeHTML(field.label)}</dt><dd>${escapeHTML(field.value)}</dd>`).join("");
    return `<div class="activity-block">${label}<dl class="activity-fields">${rows}</dl></div>`;
  }
  if (block.type === "text") {
    return `<div class="activity-block">${label}<p>${escapeHTML(block.text)}</p></div>`;
  }
  if (block.type === "list") {
    return `<div class="activity-block">${label}<ul>${(block.items || []).map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul></div>`;
  }
  if (block.type === "note") {
    return `<p class="activity-note">${escapeHTML(block.text)}</p>`;
  }
  if (block.type === "log") {
    // Unclassified agent output, already sanitised server-side; collapsed by default.
    return `<details class="activity-log"><summary>${escapeHTML(block.label || "Raw log")}</summary><pre>${escapeHTML((block.lines || []).join("\n"))}</pre></details>`;
  }
  return "";
}

function renderBlocks(blocks) {
  return (Array.isArray(blocks) ? blocks : []).map(renderBlock).join("");
}

export function mountAgentActivity(container, {
  caseId,
  runId,
  stage,
  live = false,
  collapsed = false,
  onSettled = null,
} = {}) {
  const events = new Map();        // sequence -> event
  const expanded = new Set();      // event_id of rows whose details are open
  let source = null;
  let ticker = null;
  let destroyed = false;
  let settledNotified = false;
  let loaded = false;
  let connection = live ? "connecting" : "history";

  container.classList.add("agent-activity");
  container.innerHTML = `
    <div class="agent-activity-header">
      <button type="button" class="agent-activity-toggle" aria-expanded="${collapsed ? "false" : "true"}">
        <span class="agent-activity-caret" aria-hidden="true">▾</span>
        <h3>Agent Activity</h3>
      </button>
      <span class="agent-activity-connection" aria-live="polite"></span>
    </div>
    <div class="agent-activity-body" role="log" aria-live="polite" ${collapsed ? "hidden" : ""}>
      <ol class="agent-activity-list"></ol>
    </div>`;
  const toggle = container.querySelector(".agent-activity-toggle");
  const body = container.querySelector(".agent-activity-body");
  const list = container.querySelector(".agent-activity-list");
  const connectionEl = container.querySelector(".agent-activity-connection");

  toggle.addEventListener("click", () => {
    const open = toggle.getAttribute("aria-expanded") !== "true";
    toggle.setAttribute("aria-expanded", String(open));
    body.hidden = !open;
  });

  list.addEventListener("click", (event) => {
    const button = event.target.closest("[data-activity-toggle]");
    if (!button) return;
    const key = button.dataset.activityToggle;
    if (expanded.has(key)) expanded.delete(key);
    else expanded.add(key);
    render();
  });

  function renderConnection() {
    const labels = { live: "Live", connecting: "Connecting…", reconnecting: "Reconnecting…", history: "" };
    connectionEl.textContent = labels[connection] || "";
    connectionEl.className = `agent-activity-connection connection-${connection}`;
  }

  function render() {
    const ordered = [...events.values()].sort((a, b) => a.sequence - b.sequence);
    const latestBySpan = new Map();
    const children = new Map();
    for (const event of ordered) {
      if (event.span_id) latestBySpan.set(event.span_id, event);
      if (event.parent_span_id) {
        if (!children.has(event.parent_span_id)) children.set(event.parent_span_id, []);
        children.get(event.parent_span_id).push(event);
      }
    }
    const rows = ordered.filter((event) => !event.parent_span_id);
    if (!rows.length) {
      list.innerHTML = loaded
        ? `<li class="agent-activity-empty">${escapeHTML(live
          ? "Waiting for the first recorded activity for this run…"
          : "No agent activity was recorded for this run. Activity is captured only for runs executed while Agent Activity is enabled.")}</li>`
        : `<li class="agent-activity-empty"><span class="spinner" aria-hidden="true"></span>Loading activity…</li>`;
      return;
    }

    const attempts = new Set(rows.map((event) => event.stage_attempt).filter((value) => value != null));
    let lastAttempt = null;
    let lastGroup = null;
    let hasUnresolved = false;
    const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 32;

    list.innerHTML = rows.map((event) => {
      let prefix = "";
      if (attempts.size > 1 && event.stage_attempt != null && event.stage_attempt !== lastAttempt) {
        lastAttempt = event.stage_attempt;
        prefix = `<li class="agent-activity-attempt">Attempt ${escapeHTML(event.stage_attempt)}</li>`;
        lastGroup = null;
      }
      // Backend-declared grouping (e.g. separate agent runs within one
      // attempt). Purely a heading; event order is unchanged.
      const group = event.metadata?.group || null;
      if (group && group !== lastGroup) {
        prefix += `<li class="agent-activity-attempt agent-activity-group">${escapeHTML(group)}</li>`;
      }
      if (group) lastGroup = group;
      const latest = event.span_id ? latestBySpan.get(event.span_id) : event;
      const resolved = latest !== event;
      const pending = (event.status === "running" || event.status === "waiting") && !resolved;
      if (pending && event.status === "running") hasUnresolved = true;

      let icon;
      if (event.status === "running") icon = resolved ? "·" : `<span class="spinner" aria-hidden="true"></span>`;
      else if (event.status === "waiting" && resolved) icon = "·";
      else icon = STATUS_ICONS[event.status] || "•";

      const spanChildren = (event.span_id ? (children.get(event.span_id) || []) : [])
        .filter((child) => !child.span_id || latestBySpan.get(child.span_id) === child);
      // While an operation is in flight: with one child operation, a one-liner
      // of the newest thing it reported (e.g. "Model: gpt-5.4-mini"); with
      // several (e.g. sequential provider lookups), each child's latest state
      // in the order the backend recorded them.
      const inflight = pending && spanChildren.length === 1 ? spanChildren[0] : null;
      const inflightList = pending && spanChildren.length > 1
        ? `<ul class="activity-inflight-list">${spanChildren.map((child) => {
          const childIcon = child.status === "running" ? `<span class="spinner" aria-hidden="true"></span>` : escapeHTML(STATUS_ICONS[child.status] || "•");
          return `<li class="status-${escapeHTML(child.status)}"><span class="activity-inflight-icon">${childIcon}</span>${escapeHTML(child.title)}${child.detail ? ` <span class="activity-inflight-detail">· ${escapeHTML(child.detail)}</span>` : ""}</li>`;
        }).join("")}</ul>`
        : "";
      // Full child detail is attached to the operation's final row.
      const childBlocks = !pending && event === latest
        ? spanChildren.map((child) => `<div class="activity-child status-${escapeHTML(child.status)}"><div class="activity-child-title">${escapeHTML(STATUS_ICONS[child.status] || "•")} ${escapeHTML(child.title)}</div>${child.metadata?.details ? renderBlocks(child.metadata.details) : (child.detail ? `<p>${escapeHTML(child.detail)}</p>` : "")}</div>`).join("")
        : "";
      const ownBlocks = renderBlocks(event.metadata?.details);
      const detailsHTML = ownBlocks + childBlocks;
      const isOpen = expanded.has(event.event_id);
      const toggleLabel = event.source === "ai" ? "View AI output" : "View details";
      const postStage = (event.metadata?.post_stage ? `<span class="activity-pill">Post-stage</span>` : "")
        + (event.metadata?.fallback ? `<span class="activity-pill activity-pill-fallback">Fallback</span>` : "");

      return `${prefix}<li class="agent-activity-row status-${escapeHTML(event.status)}${resolved ? " resolved" : ""}">
        <time datetime="${escapeHTML(event.timestamp)}">${escapeHTML(clockTime(event.timestamp))}</time>
        <span class="activity-icon icon-${escapeHTML(event.status)}" aria-label="${escapeHTML(event.status)}">${icon}</span>
        <div class="activity-main">
          <div class="activity-head">
            <span class="activity-badge badge-${escapeHTML(badgeClass(event))}">${escapeHTML(sourceLabel(event))}</span>${postStage}
            <span class="activity-title">${escapeHTML(event.title)}</span>
            ${pending && event.status === "running" ? `<span class="activity-elapsed" data-since="${escapeHTML(event.timestamp)}">${escapeHTML(elapsedSince(event.timestamp))}</span>` : ""}
          </div>
          ${event.detail ? `<div class="activity-detail">${escapeHTML(event.detail)}</div>` : ""}
          ${inflight ? `<div class="activity-inflight">${escapeHTML(inflight.detail || inflight.title)}</div>` : ""}
          ${inflightList}
          ${detailsHTML ? `<button type="button" class="activity-details-toggle" data-activity-toggle="${escapeHTML(event.event_id)}" aria-expanded="${isOpen}">${escapeHTML(toggleLabel)} ${isOpen ? "▴" : "▾"}</button>
          <div class="activity-details" ${isOpen ? "" : "hidden"}>${detailsHTML}</div>` : ""}
        </div>
      </li>`;
    }).join("");

    if (atBottom || !loaded) body.scrollTop = body.scrollHeight;
    if (hasUnresolved && !ticker) {
      ticker = window.setInterval(() => {
        if (detached()) return;
        container.querySelectorAll(".activity-elapsed[data-since]").forEach((el) => {
          el.textContent = elapsedSince(el.dataset.since);
        });
      }, 1000);
    } else if (!hasUnresolved && ticker) {
      window.clearInterval(ticker);
      ticker = null;
    }
  }

  function add(event, { fromStream = false } = {}) {
    if (!event || typeof event.sequence !== "number" || events.has(event.sequence)) return;
    events.set(event.sequence, event);
    if (fromStream && event.event_type === "stage_settled" && !settledNotified && typeof onSettled === "function") {
      settledNotified = true;
      window.setTimeout(() => { if (!destroyed) onSettled(event); }, 0);
    }
  }

  function lastSequence() {
    let last = 0;
    for (const sequence of events.keys()) last = Math.max(last, sequence);
    return last;
  }

  function query(extra = {}) {
    const params = new URLSearchParams();
    if (runId) params.set("run_id", runId);
    if (stage) params.set("stage", stage);
    Object.entries(extra).forEach(([key, value]) => params.set(key, value));
    return params.toString();
  }

  // The router can replace the page without telling this component; the
  // stream closes itself the next time it hears anything (an event, a
  // heartbeat-driven reconnect) once its container has left the document.
  function detached() {
    if (container.isConnected) return false;
    api.destroy();
    return true;
  }

  function openStream() {
    if (destroyed || typeof window.EventSource !== "function") return;
    source = new window.EventSource(`/api/cases/${encodeURIComponent(caseId)}/activity/stream?${query({ after: lastSequence() })}`);
    source.addEventListener("open", () => {
      if (detached()) return;
      connection = "live";
      renderConnection();
    });
    source.addEventListener("activity", (message) => {
      if (detached()) return;
      try {
        add(JSON.parse(message.data), { fromStream: true });
        render();
      } catch (error) {
        // A malformed frame is skipped; the next frame/reconnect continues.
      }
    });
    source.addEventListener("error", () => {
      if (detached()) return;
      // EventSource reconnects by itself (sending Last-Event-ID), so already
      // rendered events are never duplicated.
      connection = source && source.readyState === window.EventSource.CLOSED ? "history" : "reconnecting";
      renderConnection();
    });
  }

  async function load() {
    try {
      const history = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/activity?${query()}`);
      if (destroyed) return;
      (history.events || []).forEach((event) => add(event));
    } catch (error) {
      if (destroyed) return;
      list.innerHTML = `<li class="agent-activity-empty">${escapeHTML(error?.message || "Agent Activity could not be loaded.")}</li>`;
      return;
    } finally {
      loaded = true;
    }
    render();
    if (live) openStream();
  }

  const api = {
    destroy() {
      destroyed = true;
      if (source) source.close();
      source = null;
      if (ticker) window.clearInterval(ticker);
      ticker = null;
    },
  };

  renderConnection();
  render();
  load();
  return api;
}
