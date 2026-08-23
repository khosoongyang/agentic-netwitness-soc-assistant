export function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function loadingState(message = "Loading…") {
  return `<div class="state-panel"><span><span class="spinner" aria-hidden="true"></span>${escapeHTML(message)}</span></div>`;
}

export function emptyState(message) {
  return `<div class="state-panel">${escapeHTML(message)}</div>`;
}

export function errorState(error) {
  const message = error?.message || "The request could not be completed.";
  const code = error?.code ? `<div class="mono">${escapeHTML(error.code)}</div>` : "";
  return `<div class="state-panel error"><div><strong>Unable to load this view</strong><p>${escapeHTML(message)}</p>${code}</div></div>`;
}

export function formatCount(value) {
  return Number(value || 0).toLocaleString();
}

export function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? escapeHTML(value) : date.toLocaleString();
}

export function badge(value, className = "") {
  return `<span class="badge ${escapeHTML(className)}">${escapeHTML(value || "Unknown")}</span>`;
}

export function severityBadge(value) {
  return badge(value, `severity-${String(value || "").toLowerCase()}`);
}

export function stateBadge(stage) {
  return badge(stage.status_text || stage.status, `state-${stage.state}`);
}

export function jsonPreview(value) {
  if (!value) return emptyState("No persisted output is available for this stage.");
  return `<pre class="json-preview">${escapeHTML(JSON.stringify(value, null, 2))}</pre>`;
}

export function provenanceValue(value) {
  return value && typeof value === "object" && "value" in value ? value.value : value;
}
