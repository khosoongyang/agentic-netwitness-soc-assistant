import { badge, escapeHTML, severityBadge } from "./ui.js";

// Shared "headline assessment -> details on demand" presentation used by the
// Parsing, Triage, Threat Intelligence and Investigation stages and by the
// Unified Verdict (see pages/workspace.js). Every helper here only formats
// values the caller already read from a persisted stage result or from
// case_context.unified_verdict — nothing is scored, ranked or derived.
//
// The disclosure reuses the existing <details class="parsing-field-list">
// pattern (native open/close, no modal, no JS state); the View/Hide wording
// swaps purely in CSS via details[open].

const _BANDS = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

export function confidenceBadge(level, justification) {
  const tone = String(level || "").toLowerCase() === "high" ? "confidence-high"
    : String(level || "").toLowerCase() === "medium" ? "confidence-medium" : "confidence-low";
  return badge(level, tone, justification || "");
}

export function pendingValue(text) {
  return `<span class="value-pending">${escapeHTML(text)}</span>`;
}

export function hasValue(value) {
  if (value === null || value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

// Severity/risk band as a badge (upper-cased for display only); anything that
// is not a band (e.g. "unclassified asset") is shown as plain text.
export function bandValue(value) {
  const upper = String(value ?? "").trim().toUpperCase();
  if (_BANDS.has(upper)) return severityBadge(upper);
  return escapeHTML(String(value ?? ""));
}

// One headline row: scope-specific label on the left, value on the right.
export function assessmentHeadline(label, valueHTML) {
  return `<div class="assessment-headline"><span class="assessment-headline-label">${escapeHTML(label)}</span><span class="assessment-headline-value">${valueHTML}</span></div>`;
}

// Small stroked icons for section headings, in the same inline-SVG style
// the rest of Aegis already uses (overview.js summaryIcons, reports.js) —
// decorative only (aria-hidden), no icon library.
const _ICON_PATHS = {
  document: '<path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h6M9 9h2"/>',
  clipboard: '<rect x="6" y="4" width="12" height="17" rx="1.5"/><path d="M9 4V3h6v1"/><path d="M9 10h6M9 14h6M9 18h3"/>',
  bars: '<path d="M4 20h16"/><path d="M7 16v-5M12 16V6M17 16v-8"/>',
  bulb: '<path d="M9 18h6M10 21h4"/><path d="M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0 0 12 3Z"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  target: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="0.6" fill="currentColor"/>',
  shield: '<path d="M12 3 5 6v5c0 4.4 3 8.3 7 10 4-1.7 7-5.6 7-10V6l-7-3Z"/>',
  arrows: '<path d="M4 8h14l-3-3M20 16H6l3 3"/>',
  database: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
};

function _icon(name) {
  const paths = _ICON_PATHS[name];
  if (!paths) return "";
  return `<span class="assessment-section-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${paths}</svg></span>`;
}

// [label, valueHTML, noteHTML?] rows -> the shared label/value list (a <dl>
// in a rounded inner card). The optional third column is static UI text
// (e.g. what a risk dimension means), never incident evidence. Callers drop
// rows whose source value is absent before calling, so nothing is backfilled.
export function assessmentTable(rows) {
  if (!rows.length) return "";
  const withNotes = rows.some((row) => row[2]);
  return `<dl class="assessment-rows${withNotes ? " has-notes" : ""}">${rows.map(([label, value, note]) => `<div class="assessment-row"><dt class="assessment-row-label">${escapeHTML(label)}</dt><dd class="assessment-row-value">${value}</dd>${note ? `<dd class="assessment-row-note">${note}</dd>` : ""}</div>`).join("")}</dl>`;
}

// One titled block inside a details view: optional icon beside the
// heading, optional `aside` (e.g. a badge) on the heading's right. Spacing
// and the divider between consecutive sections come from CSS, so callers
// never add their own margins. Renders nothing without a body or aside.
export function assessmentSection(title, bodyHTML, { className = "", icon = "", aside = "" } = {}) {
  if (!bodyHTML && !aside) return "";
  const heading = title || aside
    ? `<div class="assessment-section-head">${title ? `<h4 class="assessment-section-title">${escapeHTML(title)}</h4>` : ""}${aside ? `<span class="assessment-section-aside">${aside}</span>` : ""}</div>`
    : "";
  const classes = ["assessment-section", icon ? "has-icon" : "", className].filter(Boolean).map(escapeHTML).join(" ");
  return `<section class="${classes}">${_icon(icon)}<div class="assessment-section-body">${heading}${bodyHTML || ""}</div></section>`;
}

// Stored prose (a rationale/justification string, or a list of finished
// sentences) as paragraphs. Blank-line breaks in the stored text become
// paragraph breaks; the wording itself is never changed.
export function assessmentProse(text) {
  const items = (Array.isArray(text) ? text : [text])
    .flatMap((item) => String(item ?? "").split(/\n\s*\n/))
    .map((item) => item.trim())
    .filter(Boolean);
  if (!items.length) return "";
  return `<div class="assessment-rationale">${items.map((item) => `<p>${escapeHTML(item)}</p>`).join("")}</div>`;
}

// The "Assessment Rationale" section every stage uses for its own stored
// explanation; `fallback` (an already-built note) is shown when it is absent.
export function assessmentRationale(text, { fallback = "", icon = "document" } = {}) {
  return assessmentSection("Assessment Rationale", assessmentProse(text) || fallback, { icon });
}

// `noun` is the thing being disclosed: "assessment details", "parsing
// details" or "verdict calculation" -> "View …" / "Hide …".
export function assessmentDisclosure(noun, bodyHTML) {
  if (!bodyHTML) return "";
  return `<details class="parsing-field-list assessment-details"><summary><span class="assessment-when-closed">View ${escapeHTML(noun)}</span><span class="assessment-when-open">Hide ${escapeHTML(noun)}</span></summary><div class="assessment-details-body">${bodyHTML}</div></details>`;
}

// Headline row(s) + optional supporting content + the disclosure.
export function assessmentCard({ headlines, noun = "assessment details", details = "", extra = "", className = "" }) {
  return `<section class="panel assessment-card${className ? ` ${escapeHTML(className)}` : ""}">${headlines.join("")}${extra}${assessmentDisclosure(noun, details)}</section>`;
}

// ── Unified Verdict ────────────────────────────────────────────────────────
// Rendered from case_context.unified_verdict.signals, which the backend
// (case_view_service.py::_unified_verdict_signals) builds from the signals
// aggregate_verdict() actually evaluated — display name (base severity is
// already named after its real source), value, status and source all arrive
// ready to show, so this never infers which source a value came from.

const _SIGNAL_STATUS_LABELS = {
  absent: "Not yet available",
  unavailable: "Unavailable",
  error: "Error",
  not_evaluated: "Not evaluated",
};

function _signalValueCell(signal) {
  const parts = [];
  if (signal.status === "scored") {
    parts.push(hasValue(signal.value) ? bandValue(signal.value) : pendingValue("—"));
  } else {
    parts.push(badge(_SIGNAL_STATUS_LABELS[signal.status] || signal.status, "state-locked"));
    if (signal.reason) parts.push(`<small class="assessment-note">${escapeHTML(signal.reason)}</small>`);
  }
  if (signal.detail) parts.push(`<small class="assessment-note">${escapeHTML(signal.detail)}</small>`);
  if (signal.source) parts.push(`<small class="assessment-note assessment-source">Source: ${escapeHTML(signal.source)}</small>`);
  return parts.join("");
}

// `signals` is always present for an available verdict from the current
// backend (it is recomputed per request from persisted stage results); the
// fallback message only covers a response without it — e.g. a server
// process still running pre-`signals` code — and never fabricates rows.
export function unifiedVerdictCard(verdict) {
  if (!verdict || !verdict.value || verdict.value === "—") return "";
  const signals = Array.isArray(verdict.signals) ? verdict.signals : [];
  const rows = signals.map((signal) => [signal.display_name, _signalValueCell(signal)]);
  const details = rows.length
    ? [
      assessmentSection("Contributing Signals", assessmentTable(rows), { icon: "bars" }),
      assessmentSection("", `<p class="assessment-footnote">The Unified Verdict is the incident-level assessment across these signals. It is separate from Investigation Severity, which is the Investigation stage's own conclusion.</p>`),
    ].join("")
    : `<p class="value-pending">The verdict signal breakdown is not available for this case.</p>`;
  return assessmentCard({
    className: "verdict-card",
    headlines: [assessmentHeadline("Unified Verdict", bandValue(verdict.value))],
    noun: "verdict calculation",
    details,
  });
}
