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

// [label, html] rows -> the standard label/value table. Callers drop rows
// whose source value is absent before calling, so nothing is backfilled.
export function assessmentTable(rows) {
  if (!rows.length) return "";
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
}

// One titled block inside a details view. Consecutive sections are spaced
// and divided by CSS (.assessment-section + .assessment-section), so callers
// never add their own margins. Empty bodies render nothing.
export function assessmentSection(title, bodyHTML, { className = "" } = {}) {
  if (!bodyHTML) return "";
  const heading = title ? `<h4 class="triage-subheading assessment-section-title">${escapeHTML(title)}</h4>` : "";
  return `<section class="assessment-section${className ? ` ${escapeHTML(className)}` : ""}">${heading}${bodyHTML}</section>`;
}

// "Why <value>?" section around a rationale string the backend already stored.
export function assessmentWhy(heading, text) {
  return assessmentSection(heading, `<p class="assessment-rationale">${escapeHTML(text)}</p>`);
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
      assessmentSection("Contributing Signals", assessmentTable(rows)),
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
