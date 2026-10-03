import { fetchJSON } from "../api.js";
import { badge, emptyState, errorState, escapeHTML, formatDate, jsonPreview, loadingState, openModal, provenanceValue, severityBadge, stateBadge } from "../ui.js";
import { TICKET_REPORT_TYPE, mountReportsPanel, openReportInto } from "./reports.js";
import { bindContinueButton, stageActionModel } from "../stageContinue.js";
import { mountAgentActivity } from "../components/agentActivity.js";
import {
  assessmentCard, assessmentHeadline, assessmentProse, assessmentRationale, assessmentSection,
  assessmentTable, bandValue, confidenceBadge, hasValue, pendingValue, unifiedVerdictCard,
} from "../assessment.js";

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 60;

// Aegis workflow phases: Parsing & Normalisation -> Triage -> Threat
// Intelligence Enrichment -> Investigation -> Reporting. `current_stage` is
// already resolved to one of these human-readable names server-side (see
// case_service.py::_STAGE_DEFINITIONS) so it is reused as-is here rather
// than re-deriving it from a raw stage key.
function stageBadge(stageName) {
  return badge(stageName, "state-in_progress");
}

function statusBadge(status) {
  const normalised = String(status || "").toLowerCase();
  let tone = "state-in_progress";
  if (/closed|resolved|approved|complete/.test(normalised)) tone = "state-completed";
  else if (/reject|fail|block/.test(normalised)) tone = "state-failed";
  return badge(status, tone);
}

export function caseContext(detail) {
  const context = detail.case.context || {};
  const overviewContext = detail.workspace?.overview?.case_context || {};
  const investigation = detail.workspace?.output?.investigation_result || null;
  const investigationHasResult = !!(investigation && Object.keys(investigation).length);
  const investigationStatus = detail.workspace?.output?.status || "Pending";
  // A result can exist (investigationHasResult) without every field populated
  // — e.g. an older persisted run captured before a field like `confidence`
  // was added to the Investigation Agent's contract — so that case reads as
  // "Not Identified" (the data genuinely isn't there), not "still pending"
  // (which would wrongly imply the stage hasn't run yet).
  const investigationFieldFallback = investigationHasResult
    ? "Not Identified"
    : investigationStatus === "Processing" ? "Investigation in progress" : "Pending Investigation";

  const netwitnessSeverity = provenanceValue(overviewContext.netwitness_severity) || detail.case.severity;

  // NOTE: a provenance field must be checked for existence *before* being
  // defaulted to `{}` — `{}` itself passes straight through provenanceValue()
  // unchanged (it fails that helper's own "value" in value check), which
  // would otherwise leak the placeholder object into the rendered cell.
  const triage = overviewContext.triage_classification;
  const triageClassification = triage && triage.evidence_status !== "unavailable" ? provenanceValue(triage) : null;

  const verdict = overviewContext.unified_verdict || {};
  const unifiedVerdict = verdict.value && verdict.value !== "—" ? verdict.value : null;

  const host = overviewContext.host;
  const hostValue = (host && host.evidence_status !== "unavailable" ? provenanceValue(host) : null) || context.hosts?.[0] || null;

  const user = overviewContext.user;
  const userValue = (user && user.evidence_status !== "unavailable" ? provenanceValue(user) : null) || context.users?.[0] || null;

  // Case ID/Status/NetWitness Severity/Current Stage are the fields an
  // analyst needs at a glance, so they lead the (scrollable) table; every
  // other field is unchanged, just reordered to sit below the fold.
  const rows = [
    ["Case ID", escapeHTML(detail.case.id)],
    ["Status", statusBadge(detail.case.status)],
    ["NetWitness Severity", netwitnessSeverity ? severityBadge(netwitnessSeverity) : pendingValue("Not Identified")],
    ["Current Stage", stageBadge(detail.case.current_stage)],
    // investigation_result.severity — the Investigation stage's own
    // conclusion, deliberately not the incident-level Unified Verdict.
    ["Investigation Severity", investigation?.severity
      ? severityBadge(investigation.severity, investigation.severity_justification)
      : pendingValue(investigationFieldFallback)],
    ["Triage Classification", triageClassification ? severityBadge(triageClassification) : pendingValue("Pending Triage")],
    ["Unified Verdict", unifiedVerdict ? severityBadge(unifiedVerdict) : pendingValue("Not Identified")],
    ["Investigation Confidence", investigation?.confidence
      ? confidenceBadge(investigation.confidence, investigation.confidence_justification)
      : pendingValue(investigationFieldFallback)],
    ["Host", escapeHTML(hostValue || "Not Identified")],
    ["User", escapeHTML(userValue || "Not Identified")],
    ["Alert Count", escapeHTML(String(detail.case.alert_count ?? 0))],
    ["Assigned To", escapeHTML(detail.case.assignee || "Unassigned")],
    ["Created", escapeHTML(formatDate(detail.case.created))],
    ["Last Seen", escapeHTML(formatDate(detail.case.last_seen))],
  ];

  return `<div class="case-context-card"><div class="case-context-scroll table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div><div class="case-context-fade" aria-hidden="true"></div></div>`;
}

function stageCards(stages) {
  return stages.map((stage) => `<button class="stage-card ${stage.locked ? "locked" : ""}" data-stage="${escapeHTML(stage.key)}"><strong>${escapeHTML(stage.name)}</strong><small>${escapeHTML(stage.status)}</small>${stateBadge(stage)}</button>`).join("");
}

// The "Key findings" card only makes sense for stages that actually
// produce a verdict/evidence to distil — Parsing is pure normalisation and
// Reporting consumes prior findings rather than discovering new ones, so
// neither gets a card at all (see renderWorkflow()'s hideKeyFindings check).
// Triage and Investigation present their findings within their Overview tabs,
// while Threat Intelligence is itself a per-indicator findings view. All three
// therefore take the full width (.workspace-grid.stage-only) without a
// duplicate sidebar.
const KEY_FINDINGS_STAGES = new Set();

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Pattern-based fallback for evidence embedded in free-text narrative
// (Investigation's execution_trace/mitre observed_evidence sentences carry
// no separate structured field per value) — applied only where a backend
// `evidence` value hasn't already claimed the span. Every pattern here
// detects a general SHAPE (IP, hash, path, port, …), never a specific
// hardcoded example value.
const EVIDENCE_PATTERNS = [
  // Full URLs
  /https?:\/\/[^\s"'<>)]+/g,
  
  // Full ISO timestamps with timezone offset (+/-HH:MM or Z)
  /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/gi,

  // Full command invocations with arguments/flags/quoted paths:
  // e.g., cmd.exe /c "C:\...", powershell.exe -ExecutionPolicy Bypass, sc.exe start wuauserv,
  //       Upfc.exe /launchtype periodic /cv ..., sihclient.exe /cv ...
  /\b[\w-]+\.(?:exe|bat|ps1|cmd|sh)\b(?:\s+(?:(?:"[^"\\]*(?:\\.[^"\\]*)*")|(?:'[^'\\]*(?:\\.[^'\\]*)*')|(?:[-/][\w.:/-]+(?:\s+(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[A-Za-z]:\\[^\s,;"]+|HK[A-Z0-9_\\]+|(?!on\b|in\b|with\b|by\b|and\b|to\b|for\b|at\b|from\b|of\b|the\b|a\b|an\b|was\b|is\b|were\b|activity\b)[\w.-]+))?)|(?:ADD|DELETE|QUERY|CREATE|STOP|START|CONFIG|install-manifest|uninstall-manifest|runasservice|periodic)\b(?:\s+(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|HK[A-Z0-9_\\]+|[A-Za-z]:\\[^\s,;"]+|(?!on\b|in\b|with\b|by\b|and\b|to\b|for\b|at\b|from\b|of\b|the\b|a\b|an\b|was\b|is\b|were\b|activity\b)[\w.-]+))*))+/gi,

  // Standalone command arguments / switches with values (e.g. -ExecutionPolicy Bypass, /v EnableLUA, /t REG_DWORD, /d 0, /f, /c "...")
  /(?:^|(?<=\s))(?:[-/][a-zA-Z0-9_:-]+(?:\s+(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[A-Za-z]:\\[^\s,;"]+|HK[A-Z0-9_\\]+|(?!on\b|in\b|with\b|by\b|and\b|to\b|for\b|at\b|from\b|of\b|the\b|a\b|an\b|was\b|is\b|were\b|activity\b)[\w.-]+))?)(?=\s|[.,;:]|$)/g,

  // Windows absolute paths (quoted or unquoted)
  /(?:"[A-Za-z]:\\[^"]*"|'[A-Za-z]:\\[^']*'|[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+)/g,
  
  // Registry keys
  /\bHK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|LM|CU|CR|U|CC)\\[^\s,;"]+/gi,
  
  // Hashes (SHA-256, SHA-1, MD5)
  /\b[a-fA-F0-9]{64}\b/g,
  /\b[a-fA-F0-9]{40}\b/g,
  /\b[a-fA-F0-9]{32}\b/g,
  
  // IPv6
  /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g,
  
  // IPv4 with optional CIDR subnet or port
  /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2}|:\d{1,5})?\b/g,

  // Standalone Executables / scripts / binaries
  /\b[\w-]+\.(?:exe|dll|ps1|psm1|bat|cmd|sh|py|js|vbs|hta|scr|msi|jar)\b/gi,
  
  // Domains
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|dev|co|uk|de|fr|gov|edu|int|mil|app|cloud)\b(?!\.?[\w-])/gi,
  
  // Unix paths
  /(?:\/[\w.-]+){2,}/g,
  
  // Event IDs / Process IDs
  /\b(?:Event ID|EventID|Process ID|Parent Process ID|PID|PPID)\s*[:#]?\s*\d+\b/gi,
  
  // Explicit port
  /\bport\s+\d{1,5}\b/gi,
];

// Highlights evidence values inside `text` as compact chips so an analyst
// can tell observed-evidence apart from explanatory prose at a glance.
// Backend-supplied `evidence` (exact values drawn from the stage's own
// structured result) always wins over pattern detection for the same span.
function highlightEvidence(text, evidenceMap) {
  if (!text) return "";
  const ranges = [];
  const claim = (start, end) => {
    if (start >= end) return;
    for (const r of ranges) { if (start < r.end && end > r.start) return; }
    ranges.push({ start, end });
  };

  const evidenceValues = Object.values(evidenceMap || {})
    .filter((v) => v !== null && v !== undefined && String(v).trim().length > 1)
    .map(String)
    .sort((a, b) => b.length - a.length);
  for (const value of evidenceValues) {
    const re = new RegExp(escapeRegExp(value), "g");
    let match;
    while ((match = re.exec(text))) {
      claim(match.index, match.index + match[0].length);
    }
  }

  for (const pattern of EVIDENCE_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text))) {
      claim(match.index, match.index + match[0].length);
      if (match[0].length === 0) pattern.lastIndex += 1;
    }
  }

  if (!ranges.length) return escapeHTML(text);
  ranges.sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const { start, end } of ranges) {
    if (start < cursor) continue;
    out += escapeHTML(text.slice(cursor, start));
    out += `<span class="evidence-chip">${escapeHTML(text.slice(start, end))}</span>`;
    cursor = end;
  }
  out += escapeHTML(text.slice(cursor));
  return out;
}

const FINDING_CATEGORY_LABELS = {
  observed: "Observed",
  correlation: "Correlation",
  agent_inference: "Agent inference",
  assessment: "Assessment",
};

// Evidence values the backend extracted from the finding's full source text
// (evidence_values) that the short summary doesn't already show inline.
function findingEvidenceChips(item) {
  const desc = item.desc || "";
  const values = (item.evidence_values || []).filter((v) => v && !desc.includes(v));
  if (!values.length) return "";
  return `<div class="finding-evidence"><span class="finding-evidence-label">Evidence</span>${values.map((v) => `<span class="evidence-chip">${escapeHTML(v)}</span>`).join("")}</div>`;
}

// MITRE IDs + where the finding came from (playbook step / MITRE mapping);
// the hover text carries the original playbook question or tactic/phase.
function findingMeta(item) {
  const parts = [];
  if (item.mitre_ids?.length) parts.push(`<span class="finding-mitre">MITRE ${item.mitre_ids.map((id) => escapeHTML(id)).join(" · ")}</span>`);
  const source = item.source || {};
  if (source.label) {
    const suffix = item.truncated && source.full_text ? ` · full text in ${source.full_text}` : "";
    parts.push(`<span class="finding-source" title="${escapeHTML(source.detail || "")}">${escapeHTML(source.label + suffix)}</span>`);
  }
  return parts.length ? `<div class="finding-meta">${parts.join("")}</div>` : "";
}

function findingsList(items) {
  if (!items || !items.length) return "";
  return `<ul class="data-list findings-list">${items.map((item) => {
    const categoryLabel = FINDING_CATEGORY_LABELS[item.category] || "";
    return `<li class="finding-item">
      <div>
        <div class="finding-heading"><strong>${escapeHTML(item.title || "Finding")}</strong>${categoryLabel ? `<span class="finding-category cat-${escapeHTML(item.category)}">${escapeHTML(categoryLabel)}</span>` : ""}</div>
        <p>${highlightEvidence(item.desc || "", item.evidence)}</p>
        ${findingEvidenceChips(item)}
        ${findingMeta(item)}
      </div>
      ${item.confidence ? `<span>${escapeHTML(item.confidence)}</span>` : ""}
    </li>`;
  }).join("")}</ul>`;
}

function findings(workspace, stage) {
  if (!stage) return "";
  // While the stage is running, key_findings_by_stage can still hold the
  // previous run's findings (a re-run leaves the old result persisted until
  // the new one lands), so it is ignored until the stage leaves Processing.
  const items = stage.state === "in_progress" ? [] : (workspace?.overview?.key_findings_by_stage?.[stage.key] || []);
  if (!items.length) return emptyState("No key findings have been distilled for this stage yet.");
  return findingsList(items.slice(0, 5));
}

// One action bar for every stage (see ../stageContinue.js for the labels and
// the Continue rule): [Run/Re-run <stage>] [Continue to <next stage>] on the
// left, [Reject <stage>] [Approve <stage>] on the right while a gate is
// awaiting a decision. Every button keeps its backend action's enabled state
// and reason; Continue is enabled only while the NEXT stage's `start` action
// is (i.e. the backend has unlocked it). `footer` renders the bar as the
// stage's bottom action area (divider above it) — Parsing, Triage, Threat
// Intelligence and Investigation place it after all of their stage output.
function stageActionButtons(stage, workflow, { footer = false } = {}) {
  const model = stageActionModel(stage, workflow);
  if (!model.primary.length && !model.decision.length && !model.continueTo) return "";
  const button = (action) => `<button class="action-button ${action.danger ? "danger" : ""}" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(action.label)}</button>`;
  const cont = model.continueTo;
  const continueButton = cont
    ? `<button class="action-button" data-continue-stage="${escapeHTML(cont.nextStage.key)}" ${cont.enabled ? "" : "disabled"} title="${escapeHTML(cont.reason || `Start ${cont.nextStage.name}`)}">${escapeHTML(cont.label)}</button>`
    : "";
  return `<div class="stage-actions triage-workflow-actions${footer ? " stage-actions-footer" : ""}" aria-label="${escapeHTML(stage.name)} actions"><div class="triage-action-group">${model.primary.map(button).join("")}${continueButton}</div><div class="triage-action-group">${model.decision.map(button).join("")}</div></div>`;
}

// Continue = navigation, Run = execution. The stage's own buttons (Run/
// Re-run/Approve/Reject/Resume) go to onAction(type, stage); Continue only
// calls onNavigate(nextStageKey), which selects the next stage so the analyst
// sees it still Pending with its own Run <Stage> button. Continue never
// reaches onAction, so it can never start a stage.
function bindStageActions(root, stage, workflow, onAction, onNavigate) {
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
  bindContinueButton(root, workflow, stage, onNavigate);
}

// The parser run's own summary sentence — ai_summary (added by workflow/
// stage_summaries.py) falling back to the parser's `summary` — read from
// the persisted parsing_result_json wrapper, not from normalised_alert.
// Shown inside the Overview's Parser Summary section; omitted when absent.
function parserSummaryText(result) {
  const summaryText = result?.ai_summary || result?.summary;
  if (!summaryText) return "";
  const caption = result.ai_summary_model
    ? `Generated by ${result.ai_summary_model}${result.ai_summary_generated_at ? ` · ${formatDate(result.ai_summary_generated_at)}` : ""}`
    : "";
  return `<p class="notice" style="margin-top:0.75rem">${escapeHTML(summaryText)}${caption ? `<br><small style="opacity:0.75">${escapeHTML(caption)}</small>` : ""}</p>`;
}

// ── Parsing Overview ─────────────────────────────────────────────────────
// A read-only, human-readable projection of stage.result.normalised_alert
// (agents/parsing/parser_normaliser.py::normalise_alert_record()'s output,
// pruned of empty/null keys before it is persisted). Every row below reads
// a field that already exists on that object; rows whose value is absent
// are omitted and sections with no rows are omitted, so nothing is
// backfilled or re-derived. Formatting (Yes/No, dates, list joins) is
// presentation-only — normalised_alert itself is never mutated, and the
// JSON view/Download JSON continue to expose it unchanged.

function _poHas(value) {
  if (value === null || value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function _poHumanise(value) {
  return String(value).replaceAll("_", " ");
}

// Arrays of objects (process_relationships, decoded_commands, …) are not
// flattened into rows — the count is shown and the detail stays in JSON.
function _poValue(value, { mono = false, code = false } = {}) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    if (value.some((item) => item && typeof item === "object")) {
      return `${escapeHTML(String(value.length))} ${value.length === 1 ? "entry" : "entries"} <span class="value-pending">· see JSON</span>`;
    }
    if (code) return value.map((item) => `<code class="parsing-overview-code">${escapeHTML(item)}</code>`).join("");
    const joined = value.map((item) => escapeHTML(item)).join(", ");
    return mono ? `<span class="mono">${joined}</span>` : joined;
  }
  if (value && typeof value === "object") {
    return Object.entries(value)
      .filter(([, v]) => _poHas(v))
      .map(([k, v]) => `<div><span class="value-pending">${escapeHTML(_poHumanise(k))}:</span> ${_poValue(v, { mono })}</div>`)
      .join("");
  }
  if (code) return `<code class="parsing-overview-code">${escapeHTML(value)}</code>`;
  return mono ? `<span class="mono">${escapeHTML(value)}</span>` : escapeHTML(value);
}

// [label, rawValue, render?] -> [label, html]; drops rows with no value.
function _poRows(specs) {
  return specs
    .filter(([, value]) => _poHas(value))
    .map(([label, value, render]) => [label, render ? render(value) : _poValue(value)]);
}

function _poTable(rows) {
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
}

// Renders a section only when it has rows/extra content. When empty,
// `notObservedNote` (driven by the parser's own observed_data_context
// flags, never guessed) explains why instead of silently dropping it.
function _poSection(title, rows, { extra = "", notObservedNote = "" } = {}) {
  if (!rows.length && !extra) {
    return notObservedNote ? `<article class="panel"><h3>${escapeHTML(title)}</h3><p class="value-pending">${escapeHTML(notObservedNote)}</p></article>` : "";
  }
  return `<article class="panel"><h3>${escapeHTML(title)}</h3>${rows.length ? _poTable(rows) : ""}${extra}</article>`;
}

function _poFieldList(label, fields) {
  if (!Array.isArray(fields) || !fields.length) return "";
  return `<details class="parsing-field-list"><summary>${escapeHTML(label)} (${fields.length})</summary><div class="parsing-field-chips">${fields.map((f) => `<span class="evidence-chip">${escapeHTML(f)}</span>`).join("")}</div></details>`;
}

// True only when the parser explicitly recorded every listed data type as
// not observed — an absent flag is treated as "unknown", not "absent".
function _poNotObserved(context, flags) {
  return flags.every((flag) => context[flag] === false);
}

// `summaryTextHTML` is parserSummaryText(stage.result) — the run-level
// summary sentence — placed directly after the alert fields. The alert's
// NetWitness severity/risk score are not repeated here: they are the
// stage's headline assessment (parsingAssessment()).
function _poParserSummary(na, summaryTextHTML) {
  const summary = na.alert_summary || {};
  const ids = na.identifiers || {};
  const alertName = summary.alert_name || summary.alert_title;
  const rows = _poRows([
    ["Alert Name", alertName],
    ["Incident Title", summary.incident_title !== alertName ? summary.incident_title : null],
    ["Alert ID", summary.alert_id, (v) => _poValue(v, { mono: true })],
    ["Incident ID", summary.incident_id, (v) => _poValue(v, { mono: true })],
    ["Incident Priority", summary.incident_priority],
    ["Alert Time", summary.alert_time, (v) => escapeHTML(formatDate(v))],
    ["Detection Source", summary.detection_source],
    ["Detection Name", summary.detection_name !== alertName ? summary.detection_name : null],
    ["Event Type", summary.event_type],
    ["Primary Action", summary.primary_action],
    ["Observed Actions", summary.observed_actions],
    ["Raw Event Count", summary.raw_event_count],
    ["Session IDs", ids.session_ids, (v) => _poValue(v, { mono: true })],
    ["Event Source IDs", ids.event_source_ids, (v) => _poValue(v, { mono: true })],
    ["Record IDs", ids.record_ids, (v) => _poValue(v, { mono: true })],
    ["Signature IDs", ids.signature_ids, (v) => _poValue(v, { mono: true })],
  ]);
  return _poSection("Parser Summary", rows, { extra: summaryTextHTML });
}

function _poNetwork(na, context) {
  const net = na.network_indicators || {};
  const web = na.web_indicators || {};
  const mono = (v) => _poValue(v, { mono: true });
  const rows = _poRows([
    ["Source IP", net.source_ips, mono],
    ["Source Port", net.source_ports, mono],
    ["Destination IP", net.destination_ips, mono],
    ["Destination Port", net.destination_ports, mono],
    ["Protocol", net.protocols],
    ["Service", net.services],
    ["Direction", net.direction],
    ["Internal IPs", net.internal_ips, mono],
    ["External IPs", net.external_ips, mono],
    ["Community IDs", net.community_ids, mono],
    ["TCP Flags Seen", net.tcp_flags_seen],
    ["Network Risk Info", net.network_risk_info],
    ["Domain", web.domains, mono],
    ["URL", web.urls, mono],
    ["User Agent", web.user_agents],
  ]);
  return _poSection("Network Details", rows, {
    notObservedNote: _poNotObserved(context, ["has_network_data", "has_web_data"]) ? "No network or web telemetry was observed for this alert." : "",
  });
}

function _poEndpoint(na, context) {
  const uh = na.user_and_host_indicators || {};
  const email = na.email_indicators || {};
  const hasDirectionalUsers = _poHas(uh.source_usernames) || _poHas(uh.destination_usernames);
  const rows = _poRows([
    ["Hostname", uh.hostnames, (v) => _poValue(v, { mono: true })],
    ["Source User", uh.source_usernames],
    ["Destination User", uh.destination_usernames],
    ["Usernames", hasDirectionalUsers ? null : uh.all_usernames],
    ["Associated Domains", uh.domains, (v) => _poValue(v, { mono: true })],
    ["Sender Email", uh.source_emails],
    ["Recipient Email", uh.destination_emails],
    ["Reply-To Email", uh.reply_to_emails],
    ["Email Subject", email.subjects],
    ["Mail Client", email.mail_clients],
    ["Attachment Names", email.attachment_names],
  ]);
  return _poSection("Endpoint / User Details", rows, {
    notObservedNote: _poNotObserved(context, ["has_endpoint_data", "has_email_data"]) ? "No endpoint, user, or email telemetry was observed for this alert." : "",
  });
}

function _poProcessFile(na, context) {
  const proc = na.process_indicators || {};
  const file = na.file_indicators || {};
  const psa = na.powershell_analysis || {};
  const mono = (v) => _poValue(v, { mono: true });
  const decodedCommands = (Array.isArray(psa.decoded_commands) ? psa.decoded_commands : [])
    .map((entry) => (entry && typeof entry === "object" ? entry.decoded_command : null))
    .filter((cmd) => _poHas(cmd));
  const rows = _poRows([
    ["Process Name", proc.process_names],
    ["Process Path", proc.process_paths, mono],
    ["Parent Process", proc.parent_processes],
    ["Child Process", proc.child_processes],
    ["Command Line", proc.command_lines, (v) => _poValue(v, { code: true })],
    ["Process Relationships", proc.process_relationships],
    ["Decoded PowerShell Command", decodedCommands, (v) => _poValue(v, { code: true })],
    ["File Name", file.file_names],
    ["File Path", file.file_paths, mono],
    ["File Hash", file.file_hashes, mono],
    ["File Hashes by Type", file.file_hashes_by_type, mono],
    ["File Extension", file.file_extensions],
    ["File Type", file.file_types],
    ["File Size", file.file_sizes],
    ["File Analysis", file.file_analysis],
  ]);
  return _poSection("Process / File Details", rows, {
    notObservedNote: _poNotObserved(context, ["has_process_data", "has_file_data"]) ? "No process or file telemetry was observed for this alert." : "",
  });
}

// PowerShell Risk (risk_assessment) lives in the parsing details view, not
// here, so the main view carries no competing risk value.
function _poDetection(na) {
  const psa = na.powershell_analysis || {};
  const threat = na.threat_context || {};
  const mono = (v) => _poValue(v, { mono: true });
  const rows = _poRows([
    ["PowerShell Indicator Present", psa.powershell_indicator_present],
    ["Encoded Command Present", psa.encoded_command_present],
    ["PowerShell Decode Status", psa.decode_status, (v) => escapeHTML(_poHumanise(v))],
    ["Encoded Command Count", psa.encoded_command_count],
    ["Decoded Command Count", psa.decoded_command_count],
    ["Suspicious Behaviours", psa.suspicious_behaviours],
    ["PowerShell Extracted IOCs", psa.extracted_iocs, mono],
    ["MITRE Tactics", threat.mitre_tactics],
    ["MITRE Techniques", threat.mitre_techniques],
    ["MITRE Technique IDs", threat.mitre_technique_ids, mono],
    ["Threat Categories", threat.threat_categories],
    ["Risk Indicators", threat.risk_indicators],
    ["Feed Names", threat.feed_names],
    ["Analysis Services", threat.analysis_services],
    ["Related IOCs", threat.related_iocs, mono],
  ]);
  const summary = psa.decoded_command_summary ? `<p class="notice" style="margin-top:0.75rem">${escapeHTML(psa.decoded_command_summary)}</p>` : "";
  return _poSection("Detection / Risk Indicators", rows, { extra: summary });
}

// A field list's count: the list's length, or the number itself when the
// parser stored a count rather than the list.
function _poCount(value) {
  if (Array.isArray(value)) return value.length;
  return typeof value === "number" ? value : null;
}

// Parsing is a normalisation stage, so its headline is the two values it
// actually carries — the NetWitness alert's own severity (as extracted by
// the parser; Parsing does not produce a severity) and the parser's
// confidence. No overall "Parsing risk" is invented. Everything else —
// PowerShell Risk (scoped to PowerShell only), data quality and
// normalisation metadata — sits in the parsing details view.
export function parsingAssessment(na, context = na?.observed_data_context || {}) {
  const summary = na.alert_summary || {};
  const risk = na.powershell_analysis?.risk_assessment || {};
  const dq = na.data_quality || {};
  const meta = na.parser_metadata || {};
  const confidence = dq.parser_confidence || meta.parser_confidence;
  const score = dq.parser_confidence_score ?? meta.parser_confidence_score;

  const headlines = [
    assessmentHeadline("NetWitness Severity", hasValue(summary.severity) ? bandValue(summary.severity) : pendingValue("Not provided in the alert")),
    assessmentHeadline("Parser Confidence", hasValue(confidence) ? confidenceBadge(confidence) : pendingValue("Not recorded")),
  ];

  const rows = _poRows([
    ["NetWitness Severity", summary.severity, bandValue],
    ["NetWitness Risk Score", summary.risk_score],
    ["PowerShell Risk", risk.risk_level, bandValue],
    ["PowerShell Risk Score", risk.risk_score],
    ["Parser Confidence", confidence, (v) => confidenceBadge(v)],
    ["Parser Confidence Score", score, (v) => `<span class="mono">${escapeHTML(String(v))}/100</span>`],
    ["Confidence Explanation", dq.confidence_explanation],
    ["Normalisation Status", meta.normalisation_status, (v) => escapeHTML(_poHumanise(v))],
    ["Missing Optional Fields", _poCount(dq.missing_optional_fields)],
    ["Not Applicable Fields", _poCount(dq.not_applicable_fields)],
    ["Normalised Event Count", dq.normalised_event_count],
  ]);
  const warnings = Array.isArray(dq.warnings) ? dq.warnings.filter((w) => _poHas(w)) : [];
  const metadataRows = _poRows([
    ["Missing Required Fields", dq.missing_required_fields, (v) => _poValue(v, { mono: true })],
    ["Missing Context Fields", dq.missing_context_fields, (v) => _poValue(v, { mono: true })],
    ["Primary Data Source", context.primary_data_source],
    ["Observed Data Types", context.observed_data_types],
    ["Input Format", meta.input_format],
    ["Alert Count", meta.alert_count],
    ["Parser", meta.parser && meta.parser_version ? `${meta.parser} · ${meta.parser_version}` : meta.parser || meta.parser_version],
  ]);
  const details = [
    assessmentSection("Assessment Details", assessmentTable(rows)),
    assessmentSection("Warnings", warnings.length ? `<ul class="data-list">${warnings.map((w) => `<li><div>${escapeHTML(w)}</div></li>`).join("")}</ul>` : ""),
    assessmentSection("Normalisation Metadata", assessmentTable(metadataRows)),
    assessmentSection("", [
      _poFieldList("Missing Optional Fields", dq.missing_optional_fields),
      _poFieldList("Not Applicable Fields", dq.not_applicable_fields),
    ].join(""), { className: "assessment-field-lists" }),
  ].join("");
  return assessmentCard({ headlines, noun: "parsing details", details });
}

function parsingOverview(result) {
  const normalisedAlert = result?.normalised_alert;
  const summaryTextHTML = parserSummaryText(result);
  if (!normalisedAlert || typeof normalisedAlert !== "object" || !Object.keys(normalisedAlert).length) {
    // Legacy run: no structured fields to show, but the run's own summary
    // sentence (if persisted) is real data and stays visible.
    const unavailable = emptyState("Structured normalised data is unavailable for this parsing run. Re-run Parsing to generate the latest structured output, or view the available result in JSON.");
    return summaryTextHTML
      ? `<div class="parsing-overview">${unavailable}<article class="panel"><h3>Parser Summary</h3>${summaryTextHTML}</article></div>`
      : unavailable;
  }
  const context = normalisedAlert.observed_data_context || {};
  const detailCards = [
    _poNetwork(normalisedAlert, context),
    _poEndpoint(normalisedAlert, context),
    _poProcessFile(normalisedAlert, context),
    _poDetection(normalisedAlert),
  ].filter(Boolean).join("");
  return `<div class="parsing-overview">
    ${parsingAssessment(normalisedAlert, context)}
    ${_poParserSummary(normalisedAlert, summaryTextHTML)}
    ${detailCards ? `<div class="integration-grid">${detailCards}</div>` : ""}
  </div>`;
}

// Parsing never has an approval gate and is never locked (it is always the
// first stage), so build_workflow_stages() can only ever report one of
// four states for it — "awaiting_approval" is unreachable here and
// intentionally not handled. "Continue to Triage" only navigates to the
// Triage stage (still Pending); Triage runs from its own Run Triage button.
function renderParsingStage(root, stage, caseId, lastError, onAction, onNavigate, workflow) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>Transform raw NetWitness incident data into structured, analyst-ready context.</p></div>${stateBadge(stage)}</div>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      <section id="parsing-agent-activity"></section>
      <div id="action-status" aria-live="polite"></div>
    `;
    mountStageActivity(root.querySelector("#parsing-agent-activity"), caseId, stage, workflow, { live: true });
  } else if (stage.state === "failed") {
    root.innerHTML = `
      ${header}
      <section id="parsing-agent-activity"></section>
      <div class="state-panel error"><div>${escapeHTML(lastError || "Parsing failed for this run.")}</div></div>
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    mountStageActivity(root.querySelector("#parsing-agent-activity"), caseId, stage, workflow);
  } else if (stage.state === "completed") {
    const downloadButton = `<a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/stages/parsing/download">Download JSON</a>`;
    // Overview/JSON are two views of the same already-loaded stage.result:
    // both are rendered once here and switching only toggles `hidden`, so
    // it never re-runs Parsing, mutates the result, or issues a request.
    let overviewHTML;
    try {
      overviewHTML = parsingOverview(stage.result);
    } catch (error) {
      overviewHTML = errorState(error);
    }
    root.innerHTML = `
      ${header}
      <section id="parsing-agent-activity"></section>
      <div class="subtab-bar" role="tablist" aria-label="Parsing output view">
        <button type="button" class="subtab-button active" role="tab" id="parsing-tab-overview" data-parsing-view="overview" aria-selected="true" aria-controls="parsing-view-overview">Overview</button>
        <button type="button" class="subtab-button" role="tab" id="parsing-tab-json" data-parsing-view="json" aria-selected="false" aria-controls="parsing-view-json">JSON</button>
      </div>
      <div id="parsing-view-overview" role="tabpanel" aria-labelledby="parsing-tab-overview">${overviewHTML}</div>
      <section class="panel" id="parsing-view-json" role="tabpanel" aria-labelledby="parsing-tab-json" hidden>
        <div class="panel-header-row"><h3>Normalised Alert</h3>${downloadButton}</div>
        ${jsonPreview(stage.result?.normalised_alert || stage.result)}
      </section>
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    // Full trace stays available above the unchanged Parsing output.
    mountStageActivity(root.querySelector("#parsing-agent-activity"), caseId, stage, workflow, { collapsed: true });
  } else {
    // not_started
    root.innerHTML = `
      ${header}
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
  }
  bindStageActions(root, stage, workflow, onAction, onNavigate);
  const viewButtons = [...root.querySelectorAll("[data-parsing-view]")];
  viewButtons.forEach((button) => button.addEventListener("click", () => {
    viewButtons.forEach((b) => {
      const active = b === button;
      b.classList.toggle("active", active);
      b.setAttribute("aria-selected", String(active));
      const panel = root.querySelector(`#${b.getAttribute("aria-controls")}`);
      if (panel) panel.hidden = !active;
    });
  }));
}

// Triage's canonical persisted shape (agents/triage/triage_result.py's
// TriageAgentSuccessOutput, served verbatim by GET /api/cases/<id>/workflow's
// stages[].result — see backend/services/case_service.py::_safe_stage_result,
// which only redacts/truncates, never renames or drops a field): { ticket,
// metakeys_payload, trace, used_parsed_context, cached, ai_summary,
// ai_thinking, ai_summary_model, ai_summary_generated_at }. `ticket` and its
// nested `risk_rating` are TriageTicket/TriageRiskRating's real fields — this
// renderer draws ONLY on those (plus the trace's own "IOC Checklist" step and
// metakeys_payload.metakey_values for the IOC evidence), no value is invented
// or hard-coded. Triage never produces a "severity" or "confidence" field,
// unlike Investigation, so neither is shown here. Presentation reuses the
// Parsing Overview helpers (_poRows/_poTable/_poValue) so both stages read
// the same way. Its action bar is the shared stageActionButtons(): Approve
// Triage only unlocks Threat Intelligence (it stays "Pending"); "Continue to
// Threat Intelligence Enrichment" only navigates there, and Threat
// Intelligence runs from its own Run Threat Intelligence Enrichment button.

// Display names for the closed set of NetWitness metakeys the Triage Agent
// can extract (soc_triage_agent.py::_METAKEY_MAP). This is the metakey's own
// meaning, not a semantic role — the raw key is always shown alongside, and
// any key not listed here is displayed as-is.
const _TRIAGE_METAKEY_LABELS = {
  "ip.src": "Source IP",
  "ip.dst": "Destination IP",
  "host.name": "Host Name",
  "user.name": "User Name",
  "domain": "Domain",
  "event.type": "Event Type",
  "bytes.out": "Bytes Out",
  "protocol": "Protocol",
  "geo.country": "Country",
  "file.name": "File Name",
  "file.hash": "File Hash",
  "process.name": "Process Name",
  "os.version": "OS Version",
};

const _TRIAGE_IOC_CATEGORY_ORDER = ["confidentiality", "integrity", "availability"];

function triageTraceStep(result, stepName) {
  return (result?.trace || []).find((step) => step && step.step === stepName) || null;
}

function _triageNormText(value) {
  return String(value || "").replace(/\s+/g, " ").trim().toLowerCase();
}

// ticket.summary (the classification phase's own summary) leads; the
// stage-level ai_summary keeps its "AI-generated summary · model" label and
// is only dropped when it repeats ticket.summary word-for-word.
function triageExplanation(ticket, result) {
  const parts = [];
  if (ticket.summary) parts.push(`<p class="notice triage-explanation">${escapeHTML(ticket.summary)}</p>`);
  if (result.ai_summary && _triageNormText(result.ai_summary) !== _triageNormText(ticket.summary)) {
    parts.push(`<p class="notice triage-explanation">${escapeHTML(result.ai_summary)}<small class="triage-attribution">AI-generated summary${result.ai_summary_model ? ` · ${escapeHTML(result.ai_summary_model)}` : ""}</small></p>`);
  }
  return parts.join("");
}

// Classification/category/risk are the Triage assessment (triageAssessment());
// the summary keeps only what is not repeated there.
function triageSummarySection(ticket, result) {
  const rows = _poRows([
    ["Initial Response", ticket.initial_response_time],
  ]);
  const explanation = triageExplanation(ticket, result);
  if (!rows.length && !explanation) return "";
  return `<section class="panel"><h3>Triage Summary</h3>${rows.length ? _poTable(rows) : ""}${explanation}</section>`;
}

function triageIOCEvidence(iocStep, ticket, result) {
  const count = ticket.matched_ioc_count ?? iocStep?.total_ioc_count ?? 0;
  const mono = (v) => _poValue(v, { mono: true });

  // Array.isArray / typeof guards: a persisted result the backend sanitizer
  // has redacted-to-string (or any other unexpected shape) must degrade to
  // "no rows" here rather than throw and blank the whole stage.
  const rawValues = result.metakeys_payload?.metakey_values;
  const metakeyValues = rawValues && typeof rawValues === "object" && !Array.isArray(rawValues) ? rawValues : {};
  const observedRows = Object.entries(metakeyValues)
    .filter(([, value]) => _poHas(value))
    .map(([key, value]) => [
      `${escapeHTML(_TRIAGE_METAKEY_LABELS[key] || key)}${_TRIAGE_METAKEY_LABELS[key] ? `<small class="mono triage-metakey">${escapeHTML(key)}</small>` : ""}`,
      mono(value),
    ]);

  const rawCategories = iocStep?.per_category;
  const categories = rawCategories && typeof rawCategories === "object" ? rawCategories : {};
  const categoryKeys = [
    ..._TRIAGE_IOC_CATEGORY_ORDER.filter((key) => key in categories),
    ...Object.keys(categories).filter((key) => !_TRIAGE_IOC_CATEGORY_ORDER.includes(key)),
  ];
  const categoryLabel = (key) => key.charAt(0).toUpperCase() + key.slice(1);
  const categoryRows = [];
  const reasoningItems = [];
  categoryKeys.forEach((key) => {
    const data = categories[key] || {};
    const names = Array.isArray(data.matched_ioc_names) ? data.matched_ioc_names : [];
    if (!names.length) return;
    categoryRows.push([escapeHTML(categoryLabel(key)), escapeHTML(names.join(", "))]);
    if (data.reasoning) reasoningItems.push(`<li><div><strong>${escapeHTML(categoryLabel(key))}:</strong> ${escapeHTML(data.reasoning)}</div></li>`);
  });

  const ticketKeys = Array.isArray(ticket.metakeys) ? ticket.metakeys : [];
  const traceKeys = Array.isArray(iocStep?.matched_metakeys) ? iocStep.matched_metakeys : [];
  const mkeys = ticketKeys.length ? ticketKeys : traceKeys;
  const iocSummary = iocStep?.ioc_summary || "";

  const technical = [
    reasoningItems.length ? `<h4 class="triage-subheading">Category Reasoning</h4><ul class="data-list">${reasoningItems.join("")}</ul>` : "",
    iocSummary ? `<h4 class="triage-subheading">IOC Summary</h4><code class="parsing-overview-code">${escapeHTML(iocSummary)}</code>` : "",
    mkeys.length ? `<h4 class="triage-subheading">Matched Metakeys</h4><div class="parsing-field-chips">${mkeys.map((key) => `<span class="evidence-chip">${escapeHTML(key)}</span>`).join("")}</div>` : "",
  ].join("");

  return `<article class="panel">
    <h3>IOC Evidence</h3>
    ${_triageTable([["IOCs Matched", escapeHTML(String(count))]])}
    ${observedRows.length ? `<h4 class="triage-subheading">Observed IOC Values</h4>${_triageTable(observedRows)}` : ""}
    ${categoryRows.length ? `<h4 class="triage-subheading">Matched Categories</h4>${_triageTable(categoryRows)}` : ""}
    ${technical ? `<details class="parsing-field-list"><summary>Technical Details</summary>${technical}</details>` : ""}
  </article>`;
}

// Like _poTable, but the label cell is pre-built HTML (used for the
// metakey label + raw key pair); callers escape their own label text.
function _triageTable(rows) {
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows.map(([labelHTML, value]) => `<tr><th scope="row">${labelHTML}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
}

// Static definitions of the three risk dimensions, worded after the Triage
// Agent's own rubric (agents/triage/soc_triage_agent.py::
// RISK_RATING_GUIDANCE). They describe what each field means — they are not
// findings about the incident.
const _TRIAGE_RISK_DEFINITIONS = {
  initiation: "Likelihood that an adversary initiates the threat event.",
  occurrence: "Likelihood that the threat event occurs.",
  adverse: "Likelihood that the threat event results in adverse impact.",
};

function _definition(text) {
  return `<span class="assessment-definition">${escapeHTML(text)}</span>`;
}

// Headline = ticket.risk_rating.overall_risk (the Triage Agent's own overall
// rating) — shown once, as the headline, not repeated in the Risk table.
// Triage produces no severity or confidence field, so neither is shown.
// ticket.classification and ticket.incident_category are separate fields
// and stay separate rows.
export function triageAssessment(ticket) {
  const rr = ticket.risk_rating || {};
  const overall = rr.overall_risk;
  const classificationRows = _poRows([
    ["Triage Classification", ticket.classification, bandValue],
    ["Incident Category", ticket.incident_category],
  ]);
  const riskRows = [
    ["Initiation Risk", rr.likelihood_initiation, _TRIAGE_RISK_DEFINITIONS.initiation],
    ["Occurrence Risk", rr.likelihood_occurrence, _TRIAGE_RISK_DEFINITIONS.occurrence],
    ["Adverse Impact", rr.likelihood_adverse_impact, _TRIAGE_RISK_DEFINITIONS.adverse],
  ].filter(([, value]) => _poHas(value))
    .map(([label, value, definition]) => [label, bandValue(value), _definition(definition)]);
  const details = [
    assessmentSection("Triage Assessment", assessmentTable(classificationRows), { icon: "clipboard" }),
    assessmentSection("Risk Assessment", assessmentTable(riskRows), { icon: "bars" }),
    assessmentRationale(rr.rationale, { icon: "bulb" }),
  ].join("");
  return assessmentCard({
    headlines: [assessmentHeadline("Overall Triage Risk", hasValue(overall) ? bandValue(overall) : pendingValue("Not recorded"))],
    details,
  });
}

// Presentation-only split of a leading ATT&CK ID ("T1046 Network Service
// Scanning" -> T1046 / Network Service Scanning). Anything that doesn't
// start with a T#### ID is shown intact as a single Technique row.
const _MITRE_TECHNIQUE_RE = /^(T\d{4}(?:\.\d{3})?)(?:\s*[-–—:]\s*|\s+)(.+)$/i;

function triageMitreSection(ticket) {
  if (!ticket.mitre_tactic && !ticket.mitre_technique) return "";
  const known = (value) => value && String(value).toLowerCase() !== "unknown";
  const technique = String(ticket.mitre_technique || "").trim();
  const match = technique.match(_MITRE_TECHNIQUE_RE);
  const idOnly = /^T\d{4}(?:\.\d{3})?$/i.test(technique);
  const rows = [["Tactic", known(ticket.mitre_tactic) ? escapeHTML(ticket.mitre_tactic) : pendingValue(ticket.mitre_tactic || "Unknown")]];
  if (match) {
    rows.push(["Technique ID", `<span class="mono">${escapeHTML(match[1])}</span>`], ["Technique Name", escapeHTML(match[2])]);
  } else if (idOnly) {
    rows.push(["Technique ID", `<span class="mono">${escapeHTML(technique)}</span>`]);
  } else {
    rows.push(["Technique", known(technique) ? escapeHTML(technique) : pendingValue(technique || "Unknown")]);
  }
  return `<section class="panel"><h3>MITRE ATT&amp;CK</h3>${_poTable(rows)}</section>`;
}

function triageRecommendedActions(ticket) {
  const actions = Array.isArray(ticket.recommended_actions) ? ticket.recommended_actions : [];
  if (!actions.length) return "";
  return `<section class="panel"><h3>Recommended Actions</h3><ol class="triage-action-list">${actions.map((action) => `<li>${escapeHTML(action)}</li>`).join("")}</ol></section>`;
}

// The Triage Ticket tab's report viewer (edit/export/versions all live
// inside it — reports.js::openReportInto) is fetched once, on first open,
// and its DOM node is kept here so re-renders of this stage (tab switches,
// stage re-selection, workflow refreshes) re-attach it instead of refetching.
// Keyed on the ticket's own identity so a re-run's new ticket loads fresh.
const _triageTicketViews = new Map();
const _triageSelectedView = new Map();

function _triageTicketKey(caseId, ticket) {
  return [caseId, ticket.unc || "", ticket.incident_id || "", ticket.created_at || ""].join("::");
}

function mountTriageTicket(panel, caseId, key) {
  let view = _triageTicketViews.get(key);
  // A failed load (errorState rendered at the top level) is retried rather
  // than cached forever.
  const failed = view && view.querySelector(":scope > .state-panel.error");
  if (!view || failed) {
    view = document.createElement("div");
    view.id = "triage-ticket-detail";
    _triageTicketViews.set(key, view);
    panel.replaceChildren(view);
    openReportInto(view, { caseId, reportType: TICKET_REPORT_TYPE, mode: "view" });
    return;
  }
  if (view.parentElement !== panel) panel.replaceChildren(view);
}

// Agent Activity panel (frontend/js/components/agentActivity.js): renders the
// backend-recorded events for this run/stage. Only one panel (and so at most
// one SSE connection) exists at a time; renderSelectedStage() tears it down
// before any stage re-render. While the stage is in progress the panel
// streams live and, when the backend reports the stage settled, asks the
// workspace to refresh so the normal stage output appears.
let _stageActivity = null;
let _onStageActivitySettled = null;
// A panel the analyst watched live stays expanded on every later render of
// that same case/run/stage in this page session (several refreshes follow a
// settled stage), instead of collapsing under them.
const _watchedLive = new Set();

function destroyStageActivity() {
  if (_stageActivity) _stageActivity.destroy();
  _stageActivity = null;
}

function mountStageActivity(container, caseId, stage, workflow, { live = false, collapsed = false } = {}) {
  destroyStageActivity();
  if (!container || !workflow?.run_id) return;
  const watchKey = `${caseId}|${workflow.run_id}|${stage.key}`;
  if (live) _watchedLive.add(watchKey);
  _stageActivity = mountAgentActivity(container, {
    caseId,
    runId: workflow.run_id,
    stage: stage.key,
    live,
    collapsed: collapsed && !_watchedLive.has(watchKey),
    onSettled: live ? () => _onStageActivitySettled?.() : null,
  });
}

function renderTriageStage(root, stage, caseId, lastError, onAction, onNavigate, workflow) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>IOC assessment, risk evaluation and SOC classification.</p></div>${stateBadge(stage)}</div>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      <section id="triage-agent-activity"></section>
      <div id="action-status" aria-live="polite"></div>
    `;
    mountStageActivity(root.querySelector("#triage-agent-activity"), caseId, stage, workflow, { live: true });
    bindStageActions(root, stage, workflow, onAction, onNavigate);
    return;
  }

  // A ticket persists once Triage has completed at least once, independent
  // of the current state label — a Rejected run still has its ticket (the
  // analyst needs to see what they rejected), and a Failed run never wrote
  // one (workflow/engine.py::run_until_triage_approval returns before
  // wss.save_triage_result() on the error branch). Keying off the actual
  // data rather than an exhaustive state switch means every real status
  // (not_started/locked/failed/awaiting_approval/completed/rejected)
  // degrades correctly without a matching branch for each.
  const result = stage.result || {};
  const ticket = result.ticket || {};
  const hasTicket = Boolean(ticket.incident_id || ticket.classification);

  if (!hasTicket) {
    root.innerHTML = `
      ${header}
      ${stage.state === "failed" ? `<section id="triage-agent-activity"></section>` : ""}
      ${stage.state === "failed"
        ? `<div class="state-panel error"><div>${escapeHTML(lastError || "Triage failed for this run.")}</div></div>`
        : emptyState("No persisted Triage output is available for this run yet.")}
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    if (stage.state === "failed") {
      mountStageActivity(root.querySelector("#triage-agent-activity"), caseId, stage, workflow);
    }
  } else {
    // Overview and Triage Ticket are two views of the same already-loaded
    // Triage run: Overview is built from stage.result, the Ticket tab is
    // the existing ticket viewer (lazy-loaded once, see mountTriageTicket).
    // Switching only toggles `hidden` — it never re-runs Triage.
    const ticketKey = _triageTicketKey(caseId, ticket);
    let overviewHTML;
    try {
      const iocStep = triageTraceStep(result, "IOC Checklist");
      overviewHTML = `<div class="triage-overview">
        ${triageAssessment(ticket)}
        ${triageSummarySection(ticket, result)}
        ${triageIOCEvidence(iocStep, ticket, result)}
        ${triageMitreSection(ticket)}
        ${triageRecommendedActions(ticket)}
      </div>`;
    } catch (error) {
      overviewHTML = errorState(error);
    }
    root.innerHTML = `
      ${header}
      <section id="triage-agent-activity"></section>
      <div class="subtab-bar" role="tablist" aria-label="Triage output view">
        <button type="button" class="subtab-button active" role="tab" id="triage-tab-overview" data-triage-view="overview" aria-selected="true" aria-controls="triage-view-overview">Overview</button>
        <button type="button" class="subtab-button" role="tab" id="triage-tab-ticket" data-triage-view="ticket" aria-selected="false" aria-controls="triage-view-ticket">Triage Ticket</button>
      </div>
      <div id="triage-view-overview" role="tabpanel" aria-labelledby="triage-tab-overview">${overviewHTML}</div>
      <div id="triage-view-ticket" role="tabpanel" aria-labelledby="triage-tab-ticket" hidden></div>
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    // Full trace stays available after completion; expanded while the
    // result is awaiting the analyst's decision, collapsed afterwards.
    mountStageActivity(root.querySelector("#triage-agent-activity"), caseId, stage, workflow,
      { collapsed: stage.state !== "awaiting_approval" });
    const viewButtons = [...root.querySelectorAll("[data-triage-view]")];
    const selectView = (view) => {
      _triageSelectedView.set(ticketKey, view);
      viewButtons.forEach((b) => {
        const active = b.dataset.triageView === view;
        b.classList.toggle("active", active);
        b.setAttribute("aria-selected", String(active));
        const panel = root.querySelector(`#${b.getAttribute("aria-controls")}`);
        if (panel) panel.hidden = !active;
      });
      if (view === "ticket") mountTriageTicket(root.querySelector("#triage-view-ticket"), caseId, ticketKey);
    };
    viewButtons.forEach((button) => button.addEventListener("click", () => selectView(button.dataset.triageView)));
    if (_triageSelectedView.get(ticketKey) === "ticket") selectView("ticket");
  }
  bindStageActions(root, stage, workflow, onAction, onNavigate);
}

// -----------------------------------------------------------------------------
// Threat Intelligence Enrichment stage renderer
// -----------------------------------------------------------------------------
// Canonical source: agents/threat_intelligence/threat_intel.py's
// run_threat_intel_for_dashboard(), validated against the ThreatIntelResult
// contract (agents/threat_intelligence/threat_intel_result.py) before it is
// ever persisted. workflow/engine.py::run_threat_intel() re-keys it onto the
// workflow's own stage envelope (adds incident_id/run_id/stage/generated_at,
// then workflow/stage_summaries.py adds ai_summary/-model/-generated_at) and
// stores the result verbatim in incidents.threat_intel_result_json.
// backend/services/case_service.py::_safe_stage_result() only redacts
// secret-looking keys / truncates long strings before it reaches
// GET /api/cases/<id>/workflow as stage.result.
//
// The page is IOC-centric. Its layout, top to bottom:
//   1. Aegis Assessment   — the engine's own risk level/score/reasons,
//                           indicator counts, provider coverage and
//                           recommended_next_action (tiAssessment)
//   2. Indicator Overview — one row per enriched indicator, expandable into
//                           its provider evidence (tiIndicatorOverview)
//   3. Skipped / Excluded — eligible-but-not-looked-up and never-eligible
//                           indicators, each with its recorded reason
//   4. Intelligence Gaps  — warnings and gaps of this run
//   5. Raw provider details (collapsed) — the full per-provider tables
// Everything per-indicator comes from threat_intelligence.indicators /
// coverage / provider_coverage / intelligence_gaps
// (agents/threat_intelligence/indicators.py). This section formats, labels
// and selects fields only: it never scores, ranks or re-derives provider
// status, eligibility or risk, and provider values are shown as the
// provider's own statements, never as Aegis conclusions.
// "Continue to Investigation" (shared stageActionButtons()) is shown on the
// completed Threat Intelligence card while the Investigation stage's OWN
// backend `start` action (workflow/commands.py::available_actions()) is
// available. Clicking it only navigates to the Investigation stage, which
// stays "Pending"; Investigation runs only from its own Run Investigation
// button (handleAction("start") -> POST /stages/investigation/runs ->
// begin_stage()).

function tiDash() {
  return `<span class="value-pending">—</span>`;
}

function tiText(value) {
  return value === 0 || value ? escapeHTML(String(value)) : tiDash();
}

function tiJoined(list) {
  return Array.isArray(list) && list.length ? escapeHTML(list.join(", ")) : tiDash();
}

function tiTable(columns, rows) {
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr>${columns.map((c) => `<th>${escapeHTML(c)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function _tiNum(value) {
  return Number(value).toLocaleString();
}

function _tiPlural(count, word) {
  return `${_tiNum(count)} ${word}${Number(count) === 1 ? "" : "s"}`;
}

// Presentation-only status -> badge tone, reusing the same state-* tones the
// stage cards already render. This labels whatever status string the
// provider call already returned (completed/skipped/not_found/error) — it
// never re-derives whether a lookup "worked".
function providerStatusBadge(status, label = status || "unknown") {
  const s = String(status || "").toLowerCase();
  const tone = s === "completed" ? "state-completed"
    : s === "error" ? "state-failed"
    : s === "not_found" ? "state-awaiting_approval"
    : s === "skipped" ? "state-locked"
    : "state-not_started";
  return badge(label, tone);
}

// Skipped/error results carry their own explanatory "reason" (or an HTTP
// status_code) straight from threat_intel.py's provider functions — shown
// visibly under the badge, so a failed/skipped lookup is never mistaken for
// "no results".
function providerStatusCell(result) {
  const detail = result?.reason || (result?.status_code ? `HTTP ${result.status_code}` : "");
  const badgeHTML = providerStatusBadge(result?.status);
  return detail ? `${badgeHTML}<br><small class="ti-muted">${escapeHTML(detail)}</small>` : badgeHTML;
}

const _TI_PROVIDERS = [["virustotal", "VirusTotal"], ["abuseipdb", "AbuseIPDB"], ["otx", "AlienVault OTX"]];
const _TI_TYPE_LABELS = { ip: "IP address", domain: "Domain", hash: "File hash", url: "URL", file_name: "File name" };
const _TI_ROLE_LABELS = { source: "Source", destination: "Destination" };
const _TI_COVERAGE_STATES = {
  available: ["Available", "state-completed"],
  partial: ["Partial", "state-awaiting_approval"],
  failed: ["Failed", "state-failed"],
  not_configured: ["Not configured", "state-awaiting_approval"],
  not_applicable: ["Not applicable", "state-locked"],
};

function _tiIndicators(block) {
  return Array.isArray(block?.indicators) ? block.indicators.filter((r) => r && typeof r === "object") : null;
}

function _tiTypeLabel(record) {
  const base = _TI_TYPE_LABELS[record.type] || record.type || "Indicator";
  return record.hash_type ? `${base} (${String(record.hash_type).toUpperCase().replace("SHA", "SHA-")})` : base;
}

function _tiRoles(record) {
  const roles = (record.roles || []).map((r) => _TI_ROLE_LABELS[r] || r);
  return roles.length ? roles.join(" / ") : "";
}

function _tiIndicatorValue(value) {
  return `<span class="mono ti-ioc-value" title="${escapeHTML(value)}">${escapeHTML(value)}</span>`;
}

// ── 1. Aegis Assessment ───────────────────────────────────────────────────
// Only values the engine stored: the additive, uncapped score (shown raw,
// never "/ 100") with enrichment_risk_level beside it, indicator coverage
// counts and provider coverage counts.

function _tiCoverageLine(info) {
  if (info.state === "not_applicable") return "No applicable indicators in this run";
  if (info.state === "not_configured") return `Not queried — not configured (${_tiPlural(info.applicable, "applicable indicator")})`;
  const parts = [`${_tiNum(info.queried)} / ${_tiNum(info.applicable)} queried`];
  if (info.returned_data) parts.push(`${_tiNum(info.returned_data)} returned data`);
  if (info.not_found) parts.push(`${_tiNum(info.not_found)} no record`);
  if (info.failed) parts.push(`${_tiNum(info.failed)} failed`);
  if (info.not_configured) parts.push(`${_tiNum(info.not_configured)} not configured`);
  return parts.join(" · ");
}

function _tiProviderCoverage(block) {
  const coverage = block.provider_coverage;
  if (!coverage || typeof coverage !== "object") return "";
  const rows = _TI_PROVIDERS.filter(([key]) => coverage[key]).map(([key, name]) => {
    const info = coverage[key];
    const [label, tone] = _TI_COVERAGE_STATES[info.state] || [info.state, "state-not_started"];
    return `<div class="ti-coverage-row"><span class="ti-coverage-name">${escapeHTML(name)}</span>${badge(label, tone)}<span class="ti-coverage-detail">${escapeHTML(_tiCoverageLine(info))}</span></div>`;
  });
  return rows.length ? `<div class="ti-coverage">${rows.join("")}</div>` : "";
}

function _tiCounts(coverage) {
  if (!coverage || typeof coverage !== "object") return "";
  const cells = [
    ["Extracted", coverage.extracted, "Every indicator found in the incident"],
    ["Enriched", coverage.enriched, "Looked up with at least one provider"],
    ["Excluded", coverage.excluded, "Not eligible for external lookup (internal, non-global or unsupported)"],
    ["Skipped", coverage.skipped, coverage.skipped_by_limit
      ? `Eligible but not looked up — ${_tiNum(coverage.skipped_by_limit)} over the enrichment limit`
      : "Eligible but not looked up"],
  ];
  return `<dl class="ti-counts">${cells.map(([label, value, hint]) => `<div class="ti-count" title="${escapeHTML(hint)}"><dt>${escapeHTML(label)}</dt><dd>${tiText(value)}</dd></div>`).join("")}</dl>`;
}

// No-indicator / no-request runs keep the engine's own Low/0 contract, but
// the page must not read as "Threat Intelligence found this incident safe".
function _tiNoEnrichmentNotice(coverage) {
  if (!coverage || coverage.enriched) return "";
  const text = coverage.eligible
    ? "No provider requests were sent for the eligible indicators (see Intelligence Gaps). The risk level reflects the absence of external evidence — it is not a determination that the incident is safe."
    : "No eligible external indicators were available for enrichment, so no provider requests were made. The risk level reflects the absence of external evidence — it is not a determination that the incident is safe.";
  return `<p class="notice ti-no-enrichment">${escapeHTML(text)}</p>`;
}

export function tiAssessment(result, block = result.threat_intelligence || {}) {
  const level = result.enrichment_risk_level;
  const score = result.enrichment_risk_score;
  const enrichedAt = result.generated_at || result.created_at;
  // The engine's own level, shown beside its score: "170 (HIGH)".
  const levelText = hasValue(level) ? String(level).trim().toUpperCase() : "";
  const levelHTML = levelText
    ? ` <span class="ti-risk-level ti-risk-${escapeHTML(levelText.toLowerCase())}">(${escapeHTML(levelText)})</span>`
    : "";
  const scoreHTML = hasValue(score) || levelText
    ? `<p class="assessment-score">${hasValue(score) ? escapeHTML(String(score)) : pendingValue("—")}${levelHTML}</p><p class="assessment-footnote">Rule-based score calculated by Aegis from the provider results (additive, not a percentage).</p>`
    : "";
  const extra = [
    `<h3>Summary</h3>`,
    _tiNoEnrichmentNotice(block.coverage),
    `<div class="ti-assessment-grid">`,
    scoreHTML ? `<div class="ti-assessment-cell"><h4>Risk Score</h4>${scoreHTML}${enrichedAt ? `<p class="assessment-footnote">Last enriched ${escapeHTML(formatDate(enrichedAt))}</p>` : ""}</div>` : "",
    block.coverage ? `<div class="ti-assessment-cell"><h4>Indicators</h4>${_tiCounts(block.coverage)}</div>` : "",
    block.provider_coverage ? `<div class="ti-assessment-cell ti-assessment-wide"><h4>Provider Coverage</h4>${_tiProviderCoverage(block)}</div>` : "",
    `</div>`,
    _tiAiSummary(result),
  ].join("");
  return assessmentCard({ headlines: [], extra, className: "ti-assessment" });
}

// Whole-enrichment AI summary (workflow/stage_summaries.py, generated after
// the stage from its indicator-attributed fact packet). Shown as written,
// labelled as AI output; it plays no part in scoring or enrichment.
function _tiAiSummary(result) {
  const text = String(result.ai_summary || "").trim();
  if (!text) return "";
  const unavailable = /^ai summary unavailable/i.test(text);
  const model = result.ai_summary_model ? ` by ${escapeHTML(result.ai_summary_model)}` : "";
  return `<div class="ti-assessment-cell ti-ai-summary"><h4>AI Summary</h4><p class="${unavailable ? "ti-muted" : ""}">${escapeHTML(text)}</p><p class="assessment-footnote">AI-generated after enrichment${model}. Not used in risk scoring.</p></div>`;
}

// ── 2. Indicator Overview + per-indicator detail ───────────────────────────
// Compact cells use the provider's own numbers; "—"/Not applicable/Not
// configured/Failed are distinct, so a missing value is never shown as 0.

function _tiEvidence(record, provider) {
  return (record.providers || {})[provider] || { status: "not_queried" };
}

function _tiNonResultCell(evidence) {
  const status = evidence.status;
  if (status === "not_applicable") return `<span class="ti-muted" title="This provider does not look up this indicator type">Not applicable</span>`;
  if (status === "not_configured") return `<span class="ti-muted" title="${escapeHTML(evidence.reason || "Provider not configured")}">Not configured</span>`;
  if (status === "error") return badge("Failed", "state-failed", evidence.reason || "");
  if (status === "not_found") return `<span class="ti-muted" title="The provider has no record of this indicator">No record</span>`;
  if (status !== "completed") return tiDash();
  return null;
}

function _tiVtCell(evidence) {
  const other = _tiNonResultCell(evidence);
  if (other !== null) return other;
  const malicious = evidence.malicious ?? 0;
  const ratio = hasValue(evidence.analysed_vendors)
    ? `${_tiNum(malicious)} / ${_tiNum(evidence.analysed_vendors)} malicious`
    : `${_tiNum(malicious)} malicious`;
  const suspicious = evidence.suspicious ? `<small class="ti-muted">${_tiNum(evidence.suspicious)} suspicious</small>` : "";
  return `<span class="${malicious > 0 ? "ti-flagged" : ""}" title="Security vendors in VirusTotal's last analysis that returned a verdict">${escapeHTML(ratio)}</span>${suspicious}`;
}

function _tiAbuseCell(evidence) {
  const other = _tiNonResultCell(evidence);
  if (other !== null) return other;
  const score = evidence.abuse_confidence_score;
  const text = `${hasValue(score) ? `${score}%` : "—"} · ${_tiPlural(evidence.total_reports ?? 0, "report")}`;
  const tor = evidence.is_tor ? `<small class="ti-flagged">Tor exit node</small>` : "";
  return `<span class="${score > 0 ? "ti-flagged" : ""}" title="AbuseIPDB abuse confidence score · reports in the last 90 days">${escapeHTML(text)}</span>${tor}`;
}

function _tiOtxCell(evidence) {
  const other = _tiNonResultCell(evidence);
  if (other !== null) return other;
  const count = evidence.pulse_count ?? 0;
  const families = (evidence.malware_families || []).slice(0, 2).join(", ");
  return `<span class="${count > 0 ? "ti-flagged" : ""}" title="AlienVault OTX community threat reports (pulses) referencing this indicator">${escapeHTML(_tiPlural(count, "pulse"))}</span>${families ? `<small class="ti-muted">${escapeHTML(families)}</small>` : ""}`;
}

function _tiContextValue(record, ...fields) {
  for (const field of fields) {
    const row = (record.context || []).find((r) => r.field === field);
    if (row) return row.value;
  }
  return "";
}

function _tiOwnerCell(record) {
  let parts = [];
  if (record.type === "ip") {
    parts = [_tiContextValue(record, "as_owner", "isp"), _tiContextValue(record, "asn"), _tiContextValue(record, "country")];
  } else if (record.type === "domain") {
    const created = _tiContextValue(record, "domain_created_at");
    parts = [_tiContextValue(record, "registrar"), created ? `registered ${formatDate(created)}` : ""];
  } else if (record.type === "hash") {
    parts = [_tiContextValue(record, "popular_threat_label", "meaningful_name"), _tiContextValue(record, "type_description")];
  }
  const text = parts.filter(Boolean).join(" · ");
  return text ? `<span class="ti-owner" title="${escapeHTML(text)}">${escapeHTML(text)}</span>` : tiDash();
}

function _tiAnswered(record) {
  const applicable = _TI_PROVIDERS.filter(([key]) => _tiEvidence(record, key).status !== "not_applicable").length;
  const failed = _TI_PROVIDERS.filter(([key]) => _tiEvidence(record, key).status === "error").length;
  const notConfigured = _TI_PROVIDERS.filter(([key]) => _tiEvidence(record, key).status === "not_configured").length;
  const parts = [`${record.providers_answered ?? 0} of ${applicable} providers answered`];
  if (failed) parts.push(`${failed} failed`);
  if (notConfigured) parts.push(`${notConfigured} not configured`);
  return parts.join(" · ");
}

function _tiRows(rows) {
  const shown = rows.filter(([, value]) => hasValue(value) && value !== tiDash());
  if (!shown.length) return "";
  return `<dl class="ti-kv">${shown.map(([label, value, note]) => `<div class="ti-kv-row"><dt>${escapeHTML(label)}</dt><dd>${value}${note ? `<small class="ti-muted">${escapeHTML(note)}</small>` : ""}</dd></div>`).join("")}</dl>`;
}

function _tiChips(values) {
  const list = (values || []).filter(Boolean);
  return list.length ? `<span class="ti-chips">${list.map((v) => `<span class="evidence-chip">${escapeHTML(String(v))}</span>`).join("")}</span>` : "";
}

function _tiDate(value) {
  return value ? escapeHTML(formatDate(value)) : "";
}

function _tiYesNo(value) {
  return value === true ? "Yes" : value === false ? "No" : "";
}

function _tiProviderCard(name, evidence, body) {
  const status = evidence.status;
  if (status === "not_applicable") return "";
  let content = body;
  if (status === "not_configured" || status === "not_queried") content = `<p class="ti-muted">${escapeHTML(evidence.reason || "Not queried.")}</p>`;
  else if (status === "error") content = `<p class="ti-muted">Lookup failed${evidence.reason ? ` — ${escapeHTML(evidence.reason)}` : ""}.</p>`;
  else if (status === "not_found") content = `<p class="ti-muted">${escapeHTML(name)} has no record of this indicator.</p>`;
  const statusBadge = status === "completed" ? "" : status === "error" ? badge("Failed", "state-failed")
    : status === "not_found" ? badge("No record", "state-awaiting_approval") : badge("Not queried", "state-locked");
  return `<section class="ti-evidence-card"><h5>${escapeHTML(name)}${statusBadge}</h5>${content || `<p class="ti-muted">No further details returned.</p>`}</section>`;
}

function _tiVtEvidence(e) {
  const detections = Array.isArray(e.top_detections) ? e.top_detections : [];
  const vendorTable = detections.length
    ? `<details class="ti-subdetails"><summary>Top detecting vendors (${detections.length}${e.detecting_engine_count > detections.length ? ` of ${e.detecting_engine_count}` : ""})</summary><table class="ti-vendor-table"><tbody>${detections.map((d) => `<tr><td>${escapeHTML(d.engine || "—")}</td><td>${escapeHTML(d.category || "")}</td><td class="mono">${escapeHTML(d.result || "")}</td></tr>`).join("")}</tbody></table></details>`
    : "";
  const votes = e.community_votes ? `${_tiNum(e.community_votes.harmless ?? 0)} harmless · ${_tiNum(e.community_votes.malicious ?? 0)} malicious` : "";
  return _tiRows([
    ["Detections", hasValue(e.analysed_vendors) ? escapeHTML(`${_tiNum(e.malicious ?? 0)} / ${_tiNum(e.analysed_vendors)} vendors flagged malicious`) : tiText(e.malicious), hasValue(e.analysed_vendors) ? `${_tiNum(e.harmless ?? 0)} harmless · ${_tiNum(e.undetected ?? 0)} undetected` : ""],
    ["Suspicious", e.suspicious ? tiText(e.suspicious) : ""],
    ["Reputation", hasValue(e.reputation) ? tiText(e.reputation) : "", "VirusTotal community reputation score"],
    ["Community votes", votes ? escapeHTML(votes) : ""],
    ["Threat label", e.popular_threat_label ? escapeHTML(e.popular_threat_label) : ""],
    ["Malware family names", _tiChips(e.popular_threat_names)],
    ["Threat categories", _tiChips(e.popular_threat_categories)],
    ["Categories", _tiChips(e.categories)],
    ["Tags", _tiChips(e.tags)],
  ]) + vendorTable;
}

function _tiAbuseEvidence(e) {
  const categories = (e.report_categories || []).map((c) => `${c.name}${c.count > 1 ? ` ×${c.count}` : ""}`);
  return _tiRows([
    ["Abuse confidence", hasValue(e.abuse_confidence_score) ? escapeHTML(`${e.abuse_confidence_score}%`) : ""],
    ["Total reports", hasValue(e.total_reports) ? tiText(e.total_reports) : "", "Last 90 days"],
    ["Distinct reporters", e.num_distinct_users ? tiText(e.num_distinct_users) : ""],
    ["Last reported", _tiDate(e.last_reported_at)],
    ["Tor exit node", escapeHTML(_tiYesNo(e.is_tor))],
    ["AbuseIPDB allow-listed", escapeHTML(_tiYesNo(e.is_whitelisted))],
    ["Recent report categories", _tiChips(categories), e.reports_considered ? `From ${_tiPlural(e.reports_considered, "report")} returned by AbuseIPDB` : ""],
  ]);
}

function _tiOtxEvidence(e) {
  const pulses = Array.isArray(e.pulses) ? e.pulses : [];
  const pulseList = pulses.length
    ? `<details class="ti-subdetails"><summary>Pulses (${pulses.length}${e.pulse_count > pulses.length ? ` of ${_tiNum(e.pulse_count)}` : ""})</summary><ul class="ti-pulse-list">${pulses.map((p) => `<li><strong>${escapeHTML(p.name || "Unnamed pulse")}</strong>${p.modified ? `<small class="ti-muted">updated ${escapeHTML(formatDate(p.modified))}</small>` : ""}${_tiChips([...(p.malware_families || []), ...(p.attack_ids || []), ...(p.tags || [])])}</li>`).join("")}</ul></details>`
    : "";
  return _tiRows([
    ["Pulses", tiText(e.pulse_count ?? 0), "Community threat reports referencing this indicator"],
    ["Malware families", _tiChips(e.malware_families)],
    ["Adversaries", _tiChips(e.adversaries)],
    ["ATT&CK techniques", _tiChips(e.attack_ids)],
    ["Pulse tags", _tiChips(e.pulse_tags)],
    ["Most recent pulse update", _tiDate(e.latest_pulse_modified)],
  ]) + pulseList;
}

function _tiIndicatorDetail(record) {
  const contextRows = (record.context || []).map((row) => [row.label, escapeHTML(row.value), (row.sources || []).join(", ")]);
  const freshnessRows = (record.freshness || []).map((row) => [row.label, _tiDate(row.value), row.source]);
  const meta = [
    _tiTypeLabel(record),
    _tiRoles(record),
    `Enriched — ${_tiAnswered(record)}`,
  ].filter(Boolean).map((m) => `<span>${escapeHTML(m)}</span>`).join("");
  const origins = (record.origins || []).length ? `<p class="ti-muted">Found in: ${escapeHTML(record.origins.join(", "))}</p>` : "";
  const context = _tiRows(contextRows);
  const freshness = _tiRows(freshnessRows);
  const evidence = [
    _tiProviderCard("VirusTotal", _tiEvidence(record, "virustotal"), _tiVtEvidence(_tiEvidence(record, "virustotal"))),
    _tiProviderCard("AbuseIPDB", _tiEvidence(record, "abuseipdb"), _tiAbuseEvidence(_tiEvidence(record, "abuseipdb"))),
    _tiProviderCard("AlienVault OTX", _tiEvidence(record, "otx"), _tiOtxEvidence(_tiEvidence(record, "otx"))),
  ].join("");
  return `<div class="ti-ioc-detail">
    <div class="ti-ioc-detail-head">${_tiIndicatorValue(record.value)}<div class="ti-ioc-detail-meta">${meta}</div>${origins}</div>
    ${context || freshness ? `<div class="ti-ioc-detail-grid">
      ${context ? `<section><h5>Indicator Context</h5>${context}</section>` : ""}
      ${freshness ? `<section><h5>Freshness</h5>${freshness}</section>` : ""}
    </div>` : ""}
    <h5 class="ti-evidence-title">Provider Evidence <small class="ti-muted">— statements returned by each provider, not Aegis conclusions</small></h5>
    <div class="ti-evidence-grid">${evidence}</div>
  </div>`;
}

export function tiIndicatorOverview(block) {
  const all = _tiIndicators(block);
  if (all === null) return "";
  const enriched = all.filter((r) => r.status === "enriched");
  if (!enriched.length) return emptyState("No indicators were enriched in this run — see Skipped and Excluded Indicators and Intelligence Gaps below.");
  const rows = enriched.map((record, index) => {
    const id = `ti-ioc-detail-${index}`;
    return `<tr class="ti-ioc-row">
      <td data-label="Indicator">${_tiIndicatorValue(record.value)}<small class="ti-muted">${escapeHTML(_tiTypeLabel(record))} · ${escapeHTML(_tiAnswered(record))}</small></td>
      <td data-label="Role">${_tiRoles(record) ? escapeHTML(_tiRoles(record)) : `<span class="ti-muted" title="No source/destination role recorded for this indicator">—</span>`}</td>
      <td data-label="VirusTotal">${_tiVtCell(_tiEvidence(record, "virustotal"))}</td>
      <td data-label="AbuseIPDB">${_tiAbuseCell(_tiEvidence(record, "abuseipdb"))}</td>
      <td data-label="AlienVault OTX">${_tiOtxCell(_tiEvidence(record, "otx"))}</td>
      <td data-label="Owner / Context">${_tiOwnerCell(record)}</td>
      <td class="ti-ioc-action"><button type="button" class="ti-ioc-toggle" aria-expanded="false" aria-controls="${id}"><span class="ti-when-closed">Details</span><span class="ti-when-open">Hide</span></button></td>
    </tr>
    <tr class="ti-ioc-detail-row" id="${id}" hidden><td colspan="7">${_tiIndicatorDetail(record)}</td></tr>`;
  }).join("");
  return `<div class="ti-ioc-table-wrap"><table class="ti-ioc-table" aria-label="Enriched indicators">
    <thead><tr><th scope="col">Indicator</th><th scope="col">Role</th><th scope="col">VirusTotal</th><th scope="col">AbuseIPDB</th><th scope="col">AlienVault OTX</th><th scope="col">Owner / Context</th><th scope="col"><span class="provider-summary-sr">Details</span></th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

// ── 3. Skipped / Excluded indicators ───────────────────────────────────────

function _tiReasonTable(records) {
  const rows = records.map((r) => {
    const where = [_tiRoles(r), (r.origins || []).join(", ")].filter(Boolean).join(" · ");
    return `<tr><td data-label="Indicator">${_tiIndicatorValue(r.value)}</td><td data-label="Type">${escapeHTML(_tiTypeLabel(r))}</td><td data-label="Role / found in">${where ? escapeHTML(where) : tiDash()}</td><td data-label="Reason">${escapeHTML(r.status_reason || "—")}</td></tr>`;
  }).join("");
  return `<div class="ti-reason-wrap"><table class="ti-reason-table"><thead><tr><th scope="col">Indicator</th><th scope="col">Type</th><th scope="col">Role / found in</th><th scope="col">Reason</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

export function tiSkippedExcluded(block) {
  const all = _tiIndicators(block);
  if (all === null) return "";
  const skipped = all.filter((r) => r.status === "skipped");
  const excluded = all.filter((r) => r.status === "excluded");
  return [
    skipped.length ? `<section class="panel ti-skipped"><h3>Skipped Indicators (${skipped.length})</h3><p class="assessment-footnote">Eligible for enrichment but not looked up.</p>${_tiReasonTable(skipped)}</section>` : "",
    excluded.length ? `<section class="panel ti-excluded"><h3>Excluded Indicators (${excluded.length})</h3><p class="assessment-footnote">Not sent to external providers — internal, non-global or an indicator type the configured providers do not look up.</p>${_tiReasonTable(excluded)}</section>` : "",
  ].join("");
}

// ── 4. Intelligence Gaps / limitations ─────────────────────────────────────
// warnings (missing credential / provider error) and intelligence_gaps
// (scope of those problems plus every other limitation) — both recorded by
// the backend for this run; nothing generic is added here.

export function tiIntelligenceGaps(result, block) {
  const clean = (list) => (Array.isArray(list) ? list : []).filter((item) => String(item || "").trim());
  const warnings = clean(result.warnings);
  const gaps = clean(block.intelligence_gaps);
  const list = (items) => `<ul class="data-list">${items.map((item) => `<li><div>${escapeHTML(item)}</div></li>`).join("")}</ul>`;
  const body = [
    warnings.length ? `<div class="notice notice-error ti-provider-note"><strong>Warnings</strong>${list(warnings)}</div>` : "",
    gaps.length ? list(gaps) : "",
  ].join("");
  return `<section class="panel ti-gaps"><h3>Intelligence Gaps &amp; Limitations</h3>${body || emptyState("No intelligence gaps or provider warnings were recorded for this run.")}</section>`;
}

// ── 5. Raw provider details (collapsed) ────────────────────────────────────

function tiVirusTotalCard(vt, iocs) {
  const rows = [];
  const hashResults = Array.isArray(vt?.file_hash_results) ? vt.file_hash_results
    : (vt?.file_hash && typeof vt.file_hash === "object" ? [vt.file_hash] : []);
  for (const r of hashResults) rows.push(["File hash", r.indicator || iocs?.file_hash, r]);
  for (const r of vt?.ip_results || []) rows.push(["IP", r.indicator, r]);
  for (const r of vt?.domain_results || []) rows.push(["Domain", r.indicator, r]);
  if (!rows.length) return emptyState("No VirusTotal lookups were performed for this run.");
  const body = rows.map(([type, indicator, r]) => `<tr><td>${tiText(type)}</td><td class="mono">${tiText(indicator)}</td><td>${providerStatusCell(r)}</td><td>${tiText(r.malicious)}</td><td>${tiText(r.suspicious)}</td><td>${tiText(r.harmless)}</td><td>${tiText(r.undetected)}</td><td>${tiText(r.reputation)}</td></tr>`).join("");
  return tiTable(["Type", "Indicator", "Status", "Malicious", "Suspicious", "Harmless", "Undetected", "Reputation"], [body]);
}

function tiAbuseIPDBCard(abuse) {
  const rows = abuse?.ip_results || [];
  if (!rows.length) return emptyState("No AbuseIPDB lookups were performed for this run.");
  const body = rows.map((r) => `<tr><td class="mono">${tiText(r.indicator)}</td><td>${providerStatusCell(r)}</td><td>${tiText(r.abuse_confidence_score)}</td><td>${tiText(r.total_reports)}</td><td>${tiText(r.country_code)}</td><td>${tiText(r.isp)}</td><td>${tiText(r.usage_type)}</td><td>${r.last_reported_at ? escapeHTML(formatDate(r.last_reported_at)) : tiDash()}</td></tr>`).join("");
  return tiTable(["IP", "Status", "Abuse confidence", "Total reports", "Country", "ISP", "Usage type", "Last reported"], [body]);
}

function tiOTXCard(otx) {
  const rows = otx?.otx_results || [];
  if (!rows.length) return emptyState("No AlienVault OTX lookups were performed for this run.");
  const body = rows.map((r) => `<tr><td class="mono">${tiText(r.indicator)}</td><td>${tiText(r.indicator_type)}</td><td>${providerStatusCell(r)}</td><td>${tiText(r.pulse_count)}</td><td>${tiJoined(r.related_pulses)}</td></tr>`).join("");
  return tiTable(["Indicator", "Type", "Status", "Pulse count", "Related pulses"], [body]);
}

// Results persisted before per-indicator recording existed: the extraction
// table those results always carried, unchanged.
function tiLegacyIOCsCard(iocs) {
  if (!iocs || !Object.keys(iocs).length) return emptyState("No IOC extraction data is available for this run.");
  const rows = [
    ["Possible file name", iocs.possible_file_name ? escapeHTML(iocs.possible_file_name) : tiDash()],
    ["File hash", iocs.file_hash ? `<span class="mono">${escapeHTML(iocs.file_hash)}</span>` : tiDash()],
    ["Public IP indicators", tiJoined(iocs.ip_indicators)],
    ["Domain indicators", tiJoined(iocs.domain_indicators)],
    ["URL indicators", tiJoined(iocs.url_indicators)],
  ];
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
}

export function tiProviderResults(block, { open = false } = {}) {
  const iocs = block.iocs || {};
  const section = (title, body) => `<section class="ti-provider-section"><h4>${escapeHTML(title)}</h4>${body}</section>`;
  return `<details class="parsing-field-list ti-raw-details"${open ? " open" : ""}>
    <summary>Raw provider details</summary>
    <div class="ti-provider-results">
      ${section("VirusTotal", tiVirusTotalCard(block.virustotal, iocs))}
      ${section("AbuseIPDB", tiAbuseIPDBCard(block.abuseipdb))}
      ${section("AlienVault OTX", tiOTXCard(block.alienvault_otx))}
    </div>
  </details>`;
}

function bindIndicatorToggles(root) {
  root.querySelectorAll(".ti-ioc-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const detail = root.querySelector(`#${button.getAttribute("aria-controls")}`);
      if (!detail) return;
      const open = button.getAttribute("aria-expanded") !== "true";
      button.setAttribute("aria-expanded", String(open));
      detail.hidden = !open;
      button.closest("tr")?.classList.toggle("is-open", open);
    });
  });
}

function renderThreatIntelStage(root, stage, caseId, lastError, onAction, onNavigate, workflow) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>VirusTotal, AbuseIPDB and AlienVault OTX evidence for every extracted indicator, with Aegis's case-level risk assessment.</p></div>${stateBadge(stage)}</div>`;
  if (stage.state === "in_progress") {
    // Backend-driven: only the provider lookups that actually run appear.
    root.innerHTML = `
      ${header}
      <section id="threat-intel-agent-activity"></section>
      <div id="action-status" aria-live="polite"></div>
    `;
    mountStageActivity(root.querySelector("#threat-intel-agent-activity"), caseId, stage, workflow, { live: true });
    bindStageActions(root, stage, workflow, onAction, onNavigate);
    return;
  }

  const result = stage.result || {};
  const block = result.threat_intelligence || {};
  const hasResult = Boolean(result.threat_intelligence);

  if (!hasResult) {
    root.innerHTML = `
      ${header}
      ${stage.state === "failed" ? `<section id="threat-intel-agent-activity"></section>` : ""}
      ${stage.state === "failed"
        ? `<div class="state-panel error"><div>${escapeHTML(lastError || "Threat Intelligence enrichment failed for this run.")}</div></div>`
        : emptyState("No persisted Threat Intelligence output is available for this run yet.")}
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    if (stage.state === "failed") {
      mountStageActivity(root.querySelector("#threat-intel-agent-activity"), caseId, stage, workflow);
    }
  } else {
    const legacy = _tiIndicators(block) === null;
    const overview = legacy
      ? `<section class="panel"><h3>Extracted IOCs</h3><p class="notice">Indicator-level detail is not available for this result — it was produced before per-indicator recording was added. Re-run Threat Intelligence Enrichment to see the indicator overview, exclusions and provider coverage.</p>${tiLegacyIOCsCard(block.iocs)}</section>`
      : `<section class="panel ti-overview"><h3>Indicator Overview</h3><p class="assessment-footnote">Provider evidence for each enriched indicator. Select Details for context, freshness and the full provider statements.</p>${tiIndicatorOverview(block)}</section>`;
    root.innerHTML = `
      ${header}
      <section id="threat-intel-agent-activity"></section>
      <div class="stage-sections ti-stage">
        ${tiAssessment(result, block)}
        ${overview}
        ${tiSkippedExcluded(block)}
        ${tiIntelligenceGaps(result, block)}
        ${tiProviderResults(block, { open: legacy })}
      </div>
      ${stageActionButtons(stage, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    bindIndicatorToggles(root);
    // Full trace stays available above the Threat Intelligence result.
    mountStageActivity(root.querySelector("#threat-intel-agent-activity"), caseId, stage, workflow, { collapsed: true });
  }
  bindStageActions(root, stage, workflow, onAction, onNavigate);
}

// ══════════════════════════════════════════════════════════════════════════
// Investigation stage — Overview/Output/Timeline/MITRE ATT&CK/Entity Graph/
// Evidence/Activity sub-tabs. All seven are already computed server-side by
// backend/services/case_view_service.py::build_case_view() (see its own
// docstring: "app.py must render Overview/Output/Timeline/MITRE ATT&CK/
// Entity Graph/Evidence/Activity from ONE call") and returned as `workspace`
// on GET /api/cases/<id> — this only renders that payload; it never derives
// evidence, MITRE mappings, or containment recommendations of its own, and
// every sub-tab shows an explicit "not available" message instead of
// fabricating content when its source field is empty/absent.
// ══════════════════════════════════════════════════════════════════════════

function _provEntry(entry) {
  return entry && typeof entry === "object" && "value" in entry ? entry : { value: entry };
}

function provenanceRow(label, entry) {
  const e = _provEntry(entry);
  const title = e.source_stage ? `Source: ${e.source_stage}${e.source_field ? ` · ${e.source_field}` : ""}` : "";
  return `<tr><th scope="row">${escapeHTML(label)}</th><td title="${escapeHTML(title)}">${escapeHTML(e.value ?? "—")}</td></tr>`;
}

// Display order follows the reference layout; any key the checklist adds
// later is still shown, after these.
const _BUSINESS_IMPACT_LABELS = {
  critical_system: "Critical System",
  data_sensitivity: "Data Sensitivity",
  essential_service: "Essential Service",
  operational_impact: "Operational Impact",
};

// The checklist answers are yes/no/unknown strings (orchestrator.py::
// BusinessImpactChecklist). "No" (assessed, not applicable) and "Unknown"
// (not enough information) mean different things, so they get different
// badges — Unknown is a muted neutral, and is never shown as No. Any other
// string is shown as stored.
const _IMPACT_TONES = { yes: "impact-yes", no: "impact-no", unknown: "impact-unknown" };

function _impactValue(value) {
  const key = String(value).trim().toLowerCase();
  if (!_IMPACT_TONES[key]) return escapeHTML(String(value));
  return badge(key.charAt(0).toUpperCase() + key.slice(1), _IMPACT_TONES[key]);
}

// Presentation of severity_divergence.direction only — the stored value is
// never changed; anything unrecognised is shown humanised, without an arrow.
const _DIRECTION_DISPLAY = {
  upgraded: ["↑", "Upgraded"],
  downgraded: ["↓", "Downgraded"],
  unchanged: ["→", "Unchanged"],
};

function _directionValue(value) {
  const key = String(value).trim().toLowerCase();
  const known = _DIRECTION_DISPLAY[key];
  if (!known) return escapeHTML(_poHumanise(value));
  return `<span class="assessment-change assessment-change-${key}"><span class="assessment-change-arrow" aria-hidden="true">${known[0]}</span>${known[1]}</span>`;
}

// Headline = investigation_result.severity: the Investigation stage's own
// conclusion from its own evidence. It is deliberately a separate card from
// the Unified Verdict (the incident-level aggregation across stages). The
// details show only what the Investigation result actually stored —
// severity/confidence justifications, severity_divergence (written by
// workflow/engine.py only when Triage and Investigation disagree) and the
// business_impact_checklist — and say so when an older run lacks them.
export function investigationAssessment(result) {
  if (!result || !Object.keys(result).length) return "";
  const severity = _pickAnalysisField(result, "severity");
  const severityWhy = _pickAnalysisField(result, "severity_justification");
  const confidence = _pickAnalysisField(result, "confidence");
  const confidenceWhy = _pickAnalysisField(result, "confidence_justification");
  const divergence = result.severity_divergence;
  const impact = _pickAnalysisField(result, "business_impact_checklist");

  const parts = [
    assessmentRationale(severityWhy, {
      fallback: `<p class="value-pending">Severity justification was not recorded for this Investigation run.</p>`,
    }),
  ];
  if (hasValue(confidence)) {
    parts.push(assessmentSection("Investigation Confidence", assessmentProse(confidenceWhy), {
      icon: "shield", aside: confidenceBadge(confidence),
    }));
  }
  if (divergence && typeof divergence === "object") {
    parts.push(assessmentSection("Assessment Change", assessmentTable(_poRows([
      ["Previous Triage Assessment", divergence.triage, bandValue],
      ["Investigation Assessment", divergence.investigation, bandValue],
      ["Change", divergence.direction, _directionValue],
    ])), { icon: "arrows" }));
  }
  if (impact && typeof impact === "object") {
    const keys = [
      ...Object.keys(_BUSINESS_IMPACT_LABELS).filter((k) => k in impact),
      ...Object.keys(impact).filter((k) => !(k in _BUSINESS_IMPACT_LABELS)),
    ];
    const rows = keys
      .filter((k) => _poHas(impact[k]))
      .map((k) => [_BUSINESS_IMPACT_LABELS[k] || _poHumanise(k), _impactValue(impact[k])]);
    parts.push(assessmentSection("Business Impact", assessmentTable(rows), { icon: "database" }));
  }
  return assessmentCard({
    headlines: [assessmentHeadline("Investigation Severity", hasValue(severity) ? bandValue(severity) : pendingValue("Not recorded"))],
    details: parts.join(""),
  });
}

export function investigationOverviewTab(workspace) {
  const ctx = workspace?.overview?.case_context || {};
  const stageFindings = workspace?.overview?.key_findings_by_stage?.investigation || [];
  const assessment = investigationAssessment(workspace?.output?.investigation_result);

  const findingsSection = stageFindings.length ? `
    <section class="panel" style="margin-top:.75rem">
      <h3>Key Findings</h3>
      ${findingsList(stageFindings)}
    </section>
  ` : "";

  if (!Object.keys(ctx).length && !findingsSection) return assessment || emptyState("No case overview is available yet.");
  const rows = [
    provenanceRow("NetWitness Severity", ctx.netwitness_severity),
    provenanceRow("Triage Classification", ctx.triage_classification),
    provenanceRow("Host", ctx.host),
    provenanceRow("User", ctx.user),
    provenanceRow("NetWitness Status", ctx.netwitness_status),
    provenanceRow("Workflow Status", ctx.workflow_status),
    provenanceRow("IOC IP Count", ctx.ioc_ip_count),
  ].join("");
  // Investigation Severity (stage conclusion) and the Unified Verdict
  // (case-level aggregation) are deliberately separate groups: the verdict
  // sits in its own divided .verdict-section, never inside the Investigation
  // assessment.
  const verdict = unifiedVerdictCard(ctx.unified_verdict);
  return `<div class="stage-sections">
    ${assessment}
    ${verdict ? `<div class="verdict-section" aria-label="Case-level assessment">${verdict}</div>` : ""}
    ${findingsSection}
    <div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows}</tbody></table></div>
  </div>`;
}

function _pickAnalysisField(result, key) {
  const analysis = result?.investigation_analysis;
  if (analysis && analysis[key] !== undefined && analysis[key] !== null) return analysis[key];
  return result?.[key];
}

function markdownBlock(text) {
  if (!text) return "";
  if (window.marked && window.DOMPurify) {
    return `<div class="markdown-body">${window.DOMPurify.sanitize(window.marked.parse(text, { breaks: true, gfm: true }))}</div>`;
  }
  return `<pre class="json-preview">${escapeHTML(text)}</pre>`;
}

function playbookTraceTable(steps) {
  if (!Array.isArray(steps) || !steps.length) {
    return emptyState("No structured playbook execution trace was persisted for this run — see the narrative report above.");
  }
  const statusTone = (status) => (status === "MET" ? "state-completed" : status === "SKIPPED" ? "state-locked" : "state-failed");
  const rows = steps.map((s) => `<tr><td class="mono">${escapeHTML(s.step_id)}</td><td>${escapeHTML(s.instruction)}</td><td>${badge(s.status, statusTone(s.status))}</td><td>${escapeHTML(s.findings)}</td></tr>`).join("");
  return `<div class="table-wrap"><table class="case-context-table"><thead><tr><th>Step ID</th><th>Instruction</th><th>Status</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function policyAuditTable(records) {
  if (!Array.isArray(records) || !records.length) {
    return emptyState("No policy compliance audit log was persisted for this run.");
  }
  const rows = records.map((r) => `<tr><td class="mono">${escapeHTML(r.audit_id)}</td><td>${escapeHTML(r.decision_point)}</td><td>${escapeHTML(r.policy_reference)}</td><td>${escapeHTML(r.input_summary)}</td><td>${escapeHTML(r.result)}</td><td class="mono">${escapeHTML(r.decision_made)}</td><td>${r.human_review_required ? "Yes" : "No"}</td><td>${escapeHTML(formatDate(typeof r.timestamp === "number" ? r.timestamp * 1000 : r.timestamp))}</td></tr>`).join("");
  return `<div class="table-wrap"><table class="case-context-table"><thead><tr><th>Audit ID</th><th>Decision Point</th><th>Policy Reference</th><th>Input Summary</th><th>Result</th><th>Decision Made</th><th>Human Review?</th><th>Timestamp</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function investigationOutputTab(workspace) {
  const output = workspace?.output || {};
  const result = output.investigation_result || {};
  if (!Object.keys(result).length) {
    return emptyState(output.status === "Processing"
      ? "Investigation is currently running."
      : "No Investigation output has been persisted yet.");
  }
  const parts = [];
  parts.push(`<p>${result.severity ? severityBadge(result.severity, result.severity_justification) : ""} ${result.confidence ? confidenceBadge(result.confidence, result.confidence_justification) : ""} ${statusBadge(result.status)}</p>`);
  if (output.errors?.length) parts.push(`<p class="notice">${output.errors.map((e) => escapeHTML(e)).join("<br>")}</p>`);
  if (output.last_error) parts.push(`<p class="notice">${escapeHTML(output.last_error)}</p>`);
  if (output.worker_progress_note) parts.push(`<p class="notice">${escapeHTML(output.worker_progress_note)}</p>`);
  if (output.warnings?.length) {
    parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Evidence Gaps</h3><ul class="data-list">${output.warnings.map((w) => `<li>${escapeHTML(w)}</li>`).join("")}</ul></section>`);
  }
  if (result.summary) {
    parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Summary</h3><p>${escapeHTML(result.summary)}</p></section>`);
  }
  if (result.narrative_report) {
    parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Investigation Narrative Report</h3>${markdownBlock(result.narrative_report)}</section>`);
  }
  const containment = _pickAnalysisField(result, "recommended_containment");
  if (Array.isArray(containment) && containment.length) {
    parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Recommended Containment Actions</h3><ul class="data-list">${containment.map((c) => `<li>${escapeHTML(c)}</li>`).join("")}</ul></section>`);
  }
  const trace = _pickAnalysisField(result, "execution_trace");
  parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Playbook Execution Trace</h3>${playbookTraceTable(trace)}</section>`);
  const audits = result.investigation_analysis?.policy_audit_logs;
  parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Policy-Based Compliance Audit Log</h3>${policyAuditTable(audits)}</section>`);
  if (Array.isArray(result.missing_evidence) && result.missing_evidence.length) {
    parts.push(`<section class="panel" style="margin-top:.75rem"><h3>Missing Evidence</h3><ul class="data-list">${result.missing_evidence.map((m) => `<li>${escapeHTML(m)}</li>`).join("")}</ul></section>`);
  }
  return parts.join("");
}

function investigationTimelineTab(workspace) {
  const items = workspace?.timeline || [];
  if (!items.length) return emptyState("No timeline events have been recorded for this case yet.");
  const typeTone = {
    security: "state-in_progress",
    telemetry: "state-in_progress",
    attack_chain: "state-in_progress",
    Execution: "state-in_progress",
    Persistence: "state-in_progress",
    "Privilege Escalation": "state-failed",
    "Defense Evasion": "state-failed",
    "Credential Access": "state-failed",
    Discovery: "state-locked",
    "Lateral Movement": "state-failed",
    "Command and Control": "state-failed",
    Exfiltration: "state-failed",
    Impact: "state-failed",
    warning: "state-failed",
    workflow: "state-completed",
    info: "state-locked",
  };
  const rows = items.map((it) => {
    const time = it.timestamp ? formatDate(it.timestamp) : "—";
    const originId = it.event_origin || it.incident_id || "—";
    const headline = it.event || it.phase || "Security Event";
    const narrative = it.description || it.observed_evidence || "";
    const showNarrative = narrative && narrative.trim() !== headline.trim();

    const eventContent = `
      <div class="timeline-event-body">
        <strong class="timeline-event-title">${escapeHTML(headline)}</strong>
        ${showNarrative ? `<p class="timeline-event-narrative">${highlightEvidence(narrative, it.evidence ? { ev: it.evidence } : {})}</p>` : ""}
      </div>
    `;
    const typeLabel = it.tactic || it.event_type || "security";
    const mitreLabel = it.technique_id
      ? `<span class="mono">${escapeHTML(it.technique_id)}</span>${it.technique_name ? `<br><small class="muted">${escapeHTML(it.technique_name)}</small>` : ""}`
      : "—";

    return `<tr>
      <td class="mono" style="white-space:nowrap">${escapeHTML(time)}</td>
      <td>${eventContent}</td>
      <td>${badge(typeLabel, typeTone[typeLabel] || "state-in_progress")}</td>
      <td>${mitreLabel}</td>
      <td><span class="origin-tag mono">${escapeHTML(originId)}</span></td>
    </tr>`;
  }).join("");
  return `<div class="table-wrap"><table class="case-context-table timeline-table"><thead><tr><th style="min-width:140px">Timestamp</th><th>Event</th><th style="min-width:120px">Type</th><th style="min-width:160px">MITRE ID</th><th style="min-width:110px">Event Origin</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function investigationMitreTab(workspace) {
  const mappings = workspace?.mitre || [];
  const warnings = workspace?.mitre_warnings || [];
  if (!mappings.length) return emptyState("No MITRE ATT&CK mappings are available for this case yet.");
  const rows = mappings.map((m) => `<tr><td>${escapeHTML(m.timeline_phase || "")}</td><td>${escapeHTML((m.evidence || []).join("; "))}</td><td>${escapeHTML(m.tactic)}</td><td>${escapeHTML(m.technique_name)}</td><td class="mono">${escapeHTML(m.technique_id)}</td><td><span class="origin-tag">${escapeHTML((m.origin || "").replaceAll("_", " "))}</span></td></tr>`).join("");
  const warn = warnings.length ? `<p class="notice">${warnings.map((w) => escapeHTML(w)).join("<br>")}</p>` : "";
  return `${warn}<div class="table-wrap"><table class="case-context-table"><thead><tr><th>Timeline Phase / Activity</th><th>Observed Evidence</th><th>MITRE Tactic</th><th>MITRE Technique Name</th><th>MITRE ID</th><th>Origin</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// Entity Graph — a real interactive node-link diagram over the exact
// nodes/edges backend/services/case_view_service.py::build_entity_graph()
// derives (deterministically, no LLM) from agents/investigation/tools/
// incident_map.py. No node, edge, or property here is invented client-side:
// this module only lays out and renders what the server already computed.
// Layout is a small Fruchterman-Reingold force simulation run once per
// mount (deterministic circular starting positions keyed by node order, so
// Entity Graph — an interactive multi-incident node-link diagram over the
// nodes/edges derived from backend/services/case_view_service.py::build_entity_graph()
// and agents/investigation/tools/incident_map.py.
// Supports:
//   - Multi-incident color-coded clusters (Primary in Electric Cyan, Correlated in distinct colors)
//   - Dual layout modes: Force-Directed Nodal Web and Hierarchical Process Tree
//   - Forensic Inspector Panel with process arguments, threat intel scores, and linked cases
//   - Bottom entity count summary pills with instant type highlighting

const _ENTITY_TYPE_META = {
  incident: { color: "#38bdf8", name: "Incident", icon: "IN" },
  host: { color: "#ff7382", name: "Host", icon: "HO" },
  user: { color: "#5ec8ff", name: "User", icon: "US" },
  ip: { color: "#b9a3ff", name: "IP Address", icon: "IP" },
  domain: { color: "#efba5a", name: "Domain / URL", icon: "DM" },
  process: { color: "#45d49a", name: "Process", icon: "PR" },
  file: { color: "#f2c879", name: "File", icon: "FL" },
  hash: { color: "#9b8dff", name: "Hash", icon: "HS" },
  registry: { color: "#fb923c", name: "Registry", icon: "RG" },
  email: { color: "#38bdf8", name: "Email", icon: "EM" },
  mitre: { color: "#ff8fc7", name: "MITRE ATT&CK", icon: "M8" },
  entity: { color: "#92a3ba", name: "Entity", icon: "ET" },
};
function _entityMeta(type) { return _ENTITY_TYPE_META[type] || _ENTITY_TYPE_META.entity; }
function _entityMonogram(type) { return String(_ENTITY_TYPE_META[type]?.icon || (type || "??")).slice(0, 2).toUpperCase(); }




const _GRAPH_W = 1800;
const _GRAPH_H = 1100;
const SVG_NS = "http://www.w3.org/2000/svg";

function _svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") el.setAttribute(k, v); });
  return el;
}

function _calcEdgePath(pv, pu, isCrossIncident = false, edgeIdx = 0) {
  const dx = pu.x - pv.x;
  const dy = pu.y - pv.y;
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
  const midX = (pv.x + pu.x) / 2;
  const midY = (pv.y + pu.y) / 2;
  
  // Perpendicular normal vector (-dy, dx)
  const nx = -dy / dist;
  const ny = dx / dist;

  // Gentle, organic curvature matching design vision
  const curveAmp = isCrossIncident ? 40 : ((edgeIdx % 2 === 0 ? 1 : -1) * Math.min(28, dist * 0.14));
  const ctrlX = midX + nx * curveAmp;
  const ctrlY = midY + ny * curveAmp;

  // Stagger label position along Bézier curve to prevent label collisions on parallel edges
  const t = (edgeIdx % 2 === 0) ? 0.42 : 0.58;
  const oneMinusT = 1 - t;
  const labelX = oneMinusT * oneMinusT * pv.x + 2 * oneMinusT * t * ctrlX + t * t * pu.x;
  const labelY = oneMinusT * oneMinusT * pv.y + 2 * oneMinusT * t * ctrlY + t * t * pu.y;

  return {
    d: `M ${pv.x.toFixed(1)},${pv.y.toFixed(1)} Q ${ctrlX.toFixed(1)},${ctrlY.toFixed(1)} ${pu.x.toFixed(1)},${pu.y.toFixed(1)}`,
    labelX,
    labelY,
  };
}

function _formatRelationshipDesc(edge, dir, currentNode, otherNode) {
  const rel = edge.relation || "";
  const out = dir === "out";

  let action = "";
  if (rel === "focus_of") {
    action = out ? "Target / primary focus entity of incident" : "Designates primary investigation focus";
  } else if (rel === "spawned" || rel === "spawns") {
    action = out ? "Spawned child execution process" : "Spawned by parent execution process";
  } else if (rel === "executed" || rel === "executed_on") {
    action = out ? "Executed on host system" : "Execution environment / Host system";
  } else if (rel === "communicated_with" || rel === "connected_to") {
    action = out ? "Established outbound network connection to" : "Received inbound connection from";
  } else if (rel === "accessed_file" || rel === "has_file" || rel === "has_artifact") {
    action = out ? "Created or accessed filesystem artifact" : "Filesystem artifact accessed by process";
  } else if (rel === "modified_registry") {
    action = out ? "Modified persistence registry key" : "Registry persistence key modified by process";
  } else if (rel === "associated_with") {
    action = "Forensically correlated in security telemetry";
  } else if (rel === "queried_dns" || rel === "queried") {
    action = out ? "Resolved external domain name via DNS" : "Domain resolved by endpoint";
  } else if (rel === "logged_in" || rel === "active_on") {
    action = out ? "User account authenticated session on" : "Active logged in user account";
  } else if (rel === "matches_hash" || rel === "has_hash") {
    action = out ? "Cryptographic binary signature" : "Binary matching file hash";
  } else if (rel === "attributed_to" || rel === "mapped_to" || rel === "exhibits_technique") {
    action = "Exhibits MITRE ATT&CK technique";
  } else if (rel === "correlated_indicator") {
    action = "Correlated pivot indicator across cases";
  } else {
    action = rel.replaceAll("_", " ");
  }

  let evidence = "";
  const status = edge.evidence_status;
  if (status === "observed") {
    evidence = "Directly observed in alert & network/host telemetry";
  } else if (status === "inferred") {
    evidence = "Inferred from parent-child behavioral chain";
  } else if (status === "co_occurrence_only") {
    evidence = "Correlated via shared temporal & incident context";
  } else if (status) {
    evidence = status.replaceAll("_", " ");
  }

  return { action, evidence };
}

function _computeForceLayout(nodes, edges, primaryId) {
  const pos = new Map();
  const n = nodes.length;
  if (!n) return pos;
  const cx = _GRAPH_W / 2, cy = _GRAPH_H / 2;

  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  // Identify child processes vs root processes
  const childProcessIds = new Set();
  edges.forEach((e) => {
    if ((e.relation === "spawned" || e.relation === "spawns") && nodeById.get(e.src)?.type === "process") {
      childProcessIds.add(e.dst);
    }
  });

  // 1. Separate primary vs correlated incident nodes
  const incidentNodes = nodes.filter((node) => node.type === "incident");
  const incClusterCenters = new Map();

  const primaryIncNode = incidentNodes.find((inc) => inc.id === primaryId) || incidentNodes[0];
  const correlatedIncNodes = incidentNodes.filter((inc) => inc !== primaryIncNode);

  if (primaryIncNode) {
    incClusterCenters.set(primaryIncNode.id, { x: 720, y: 420 });
  }
  if (primaryId && !incClusterCenters.has(primaryId)) {
    incClusterCenters.set(primaryId, { x: 720, y: 420 });
  }

  // Correlated historical incidents arrayed on the western perimeter
  correlatedIncNodes.forEach((incNode, idx) => {
    const yStep = (_GRAPH_H - 300) / Math.max(correlatedIncNodes.length, 1);
    const targetX = 180 + ((idx % 2) * 50);
    const targetY = 280 + (idx + 0.5) * yStep;
    incClusterCenters.set(incNode.id, { x: targetX, y: targetY });
  });

  // Count nodes by category for uniform fan-out
  const mitreNodes = nodes.filter((node) => node.type === "mitre");
  const hostNodes = nodes.filter((node) => node.type === "host");
  const userNodes = nodes.filter((node) => node.type === "user");
  const rootProcNodes = nodes.filter((node) => node.type === "process" && !childProcessIds.has(node.id));
  const childProcNodes = nodes.filter((node) => node.type === "process" && childProcessIds.has(node.id));
  const fileHashRegNodes = nodes.filter((node) => ["file", "hash", "registry"].includes(node.type));
  const netNodes = nodes.filter((node) => ["ip", "domain"].includes(node.type));

  const targetZones = new Map();

  // Zone 1: MITRE ATT&CK sky ribbon (y ~ 130) across the top
  mitreNodes.forEach((node, i) => {
    const xStep = (_GRAPH_W - 550) / Math.max(mitreNodes.length, 1);
    const targetX = 320 + (i + 0.5) * xStep;
    const targetY = 130 + ((i % 2) * 35);
    targetZones.set(node.id, { x: targetX, y: targetY, tier: "mitre", weightY: 0.38, weightX: 0.1 });
    pos.set(node.id, { x: targetX, y: targetY });
  });

  // Zone 2: Incident Hubs (Correlated on West, Primary in Mid-Center)
  incidentNodes.forEach((node) => {
    const center = incClusterCenters.get(node.id) || { x: 720, y: 420 };
    targetZones.set(node.id, { x: center.x, y: center.y, tier: "incident", weightY: 0.45, weightX: 0.45 });
    pos.set(node.id, { x: center.x, y: center.y });
  });

  // Zone 3: Shared Pivot IPs (Bridge corridor between correlated incidents and primary incident)
  netNodes.forEach((node, i) => {
    const isShared = node.props?.is_shared_pivot || (node.incidents && node.incidents.length > 1);
    if (isShared) {
      const targetX = 430 + (i * 40);
      const targetY = 530 + ((i % 2) * 60);
      targetZones.set(node.id, { x: targetX, y: targetY, tier: "pivot_ip", weightY: 0.35, weightX: 0.35 });
      pos.set(node.id, { x: targetX, y: targetY });
    } else {
      // External C2 / Uncorrelated IPs in Eastern Corridor
      const targetX = 1520 + ((i % 2) * 110);
      const targetY = 420 + i * 150;
      targetZones.set(node.id, { x: targetX, y: targetY, tier: "network", weightY: 0.25, weightX: 0.25 });
      pos.set(node.id, { x: targetX, y: targetY });
    }
  });

  // Zone 4: Hosts & Users (Adjacent to Primary Incident)
  hostNodes.forEach((node, i) => {
    const targetX = 890 + i * 140;
    const targetY = 320 + (i % 2) * 40;
    targetZones.set(node.id, { x: targetX, y: targetY, tier: "host", weightY: 0.3, weightX: 0.25 });
    pos.set(node.id, { x: targetX, y: targetY });
  });
  userNodes.forEach((node, i) => {
    const targetX = 890 + i * 120;
    const targetY = 190 + (i % 2) * 35;
    targetZones.set(node.id, { x: targetX, y: targetY, tier: "user", weightY: 0.3, weightX: 0.25 });
    pos.set(node.id, { x: targetX, y: targetY });
  });

  // Zone 5: Directed Process Tree in East Sector
  rootProcNodes.forEach((node, i) => {
    const xStep = 220;
    const targetX = 1080 + i * xStep;
    const targetY = 460 + (i % 2) * 40;
    targetZones.set(node.id, { x: targetX, y: targetY, tier: "root_proc", weightY: 0.25, weightX: 0.15 });
    pos.set(node.id, { x: targetX, y: targetY });
  });

  childProcNodes.forEach((node, i) => {
    const xStep = (_GRAPH_W - 1050) / Math.max(childProcNodes.length, 1);
    const targetX = 1040 + (i + 0.5) * xStep;
    const targetY = 740 + ((i % 2) * 45);
    targetZones.set(node.id, { x: targetX, y: targetY, tier: "child_proc", weightY: 0.22, weightX: 0.1 });
    pos.set(node.id, { x: targetX, y: targetY });
  });

  // Files, Hashes & Registry tightly clustered underneath their parent processes
  fileHashRegNodes.forEach((node, i) => {
    const xStep = (_GRAPH_W - 1080) / Math.max(fileHashRegNodes.length, 1);
    const targetX = 1060 + (i + 0.5) * xStep;
    const targetY = 910 + ((i % 2) * 40);
    targetZones.set(node.id, { x: targetX, y: targetY, tier: "artifact", weightY: 0.25, weightX: 0.1 });
    pos.set(node.id, { x: targetX, y: targetY });
  });

  // Any remaining nodes
  nodes.forEach((node, i) => {
    if (!pos.has(node.id)) {
      const angle = (2 * Math.PI * i) / n;
      const targetX = cx + Math.cos(angle) * 350;
      const targetY = cy + Math.sin(angle) * 250;
      targetZones.set(node.id, { x: targetX, y: targetY, tier: "misc", weightY: 0.1, weightX: 0.1 });
      pos.set(node.id, { x: targetX, y: targetY });
    }
  });

  if (n < 2) return pos;

  // Constrained Relaxation with strict collision clearance & tier gravity
  const k = Math.sqrt((_GRAPH_W * _GRAPH_H) / n) * 1.35;
  const iterations = 180;
  let temp = _GRAPH_W / 9;
  const cooling = temp / iterations;
  const disp = new Map();

  for (let iter = 0; iter < iterations; iter += 1) {
    nodes.forEach((v) => disp.set(v.id, { x: 0, y: 0 }));

    // Zonal Gravity
    nodes.forEach((v) => {
      const p = pos.get(v.id);
      const zone = targetZones.get(v.id) || { x: cx, y: cy, weightX: 0.08, weightY: 0.08 };
      const dv = disp.get(v.id);
      dv.x += (zone.x - p.x) * (zone.weightX || 0.1);
      dv.y += (zone.y - p.y) * (zone.weightY || 0.1);
    });

    // Pairwise Repulsion & Strong Collision Clearance (150px min gap)
    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        const idA = nodes[i].id, idB = nodes[j].id;
        const pv = pos.get(idA), pu = pos.get(idB);
        const dx = pv.x - pu.x, dy = pv.y - pu.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;

        if (dist < 360) {
          const isInc = nodes[i].type === "incident" || nodes[j].type === "incident";
          const isHost = nodes[i].type === "host" || nodes[j].type === "host";
          const minDist = (isInc || isHost) ? 220 : 150;
          let force = (k * k) / (dist * dist + 180);

          if (dist < minDist) {
            const overlap = minDist - dist;
            force += (overlap * overlap) * 0.48;
          }

          const ux = dx / dist, uy = dy / dist;
          const dv = disp.get(idA), du = disp.get(idB);
          dv.x += ux * force * 14; dv.y += uy * force * 14;
          du.x -= ux * force * 14; du.y -= uy * force * 14;
        }
      }
    }

    // Spring forces along connecting edges (with vertical damping to preserve tier levels)
    edges.forEach((e) => {
      const pv = pos.get(e.src), pu = pos.get(e.dst);
      if (!pv || !pu || e.src === e.dst) return;
      const dx = pv.x - pu.x, dy = pv.y - pu.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = (dist * dist) / (k * 2.8);
      const ux = dx / dist, uy = dy / dist;
      const dv = disp.get(e.src), du = disp.get(e.dst);

      dv.x -= ux * force;
      dv.y -= uy * force * 0.35;
      du.x += ux * force;
      du.y += uy * force * 0.35;
    });

    // Apply displacement
    nodes.forEach((v) => {
      const d = disp.get(v.id);
      const dist = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01;
      const p = pos.get(v.id);
      p.x += (d.x / dist) * Math.min(dist, temp);
      p.y += (d.y / dist) * Math.min(dist, temp);

      // Boundary soft damping
      const margin = 85;
      p.x = Math.min(_GRAPH_W - margin, Math.max(margin, p.x));
      p.y = Math.min(_GRAPH_H - margin, Math.max(margin, p.y));
    });
    temp = Math.max(temp - cooling, 0.4);
  }
  return pos;
}

function _neighborsOf(nodeId, edges) {
  const out = [];
  edges.forEach((e) => {
    if (e.src === nodeId) out.push({ id: e.dst, dir: "out", edge: e });
    else if (e.dst === nodeId) out.push({ id: e.src, dir: "in", edge: e });
  });
  return out;
}

function investigationEntityGraphTab(workspace) {
  const graph = workspace?.entity_graph || {};
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (!nodes.length) return emptyState("No entity graph could be derived for this case yet.");

  const primaryIncId = String(workspace?.incident_id || "");
  const primaryColor = graph.primary_incident_color || "#38bdf8";
  const correlatedList = graph.correlated_incidents || [];
  const stats = graph.stats || {};
  const nodeCounts = stats.node_counts || {};

  const hostCount = nodeCounts.host || 0;
  const procCount = nodeCounts.process || 0;
  const fileCount = nodeCounts.file || 0;
  const hashCount = nodeCounts.hash || 0;
  const ipCount = (nodeCounts.ip || 0) + (nodeCounts.domain || 0);
  const totalIncidents = 1 + correlatedList.length;

  const warning = graph.data_availability_warning ? `<p class="notice">${escapeHTML(graph.data_availability_warning)}</p>` : "";

  // Filter chips for incidents
  const incidentChips = [
    `<button type="button" class="entity-graph-filter-chip is-active" data-incident="all">All Incidents (${totalIncidents})</button>`,
    `<button type="button" class="entity-graph-filter-chip" data-incident="${escapeHTML(primaryIncId)}"><span class="entity-graph-filter-dot" style="background:${primaryColor}"></span>${escapeHTML(primaryIncId)} (Primary)</button>`,
    ...correlatedList.map((rel) => `<button type="button" class="entity-graph-filter-chip" data-incident="${escapeHTML(rel.id)}"><span class="entity-graph-filter-dot" style="background:${rel.color}"></span>${escapeHTML(rel.id)}</button>`)
  ].join("");

  return `<div class="entity-graph-wrap" id="entity-graph-wrap">
    <div class="entity-graph-toolbar">
      <input type="search" id="entity-graph-search" class="entity-graph-search-input" placeholder="Search entities (host, process, IP, hash, CVE)…" aria-label="Search entities">
      
      <div class="entity-graph-toolbar-actions">
        <button type="button" class="action-button" id="entity-graph-fit">Reset View</button>
        <button type="button" class="action-button" id="entity-graph-fullscreen" title="Fullscreen">⤢</button>
      </div>
    </div>

    <div class="entity-graph-filter-bar" id="entity-graph-filter-bar">
      ${incidentChips}
    </div>

    ${warning}

    <div class="entity-graph-body" id="entity-graph-body">
      <div class="entity-graph-canvas-wrap"><div class="entity-graph-canvas" id="entity-graph-canvas"></div></div>
      <aside class="entity-graph-details panel" id="entity-graph-details"></aside>
    </div>

    <div class="entity-graph-metrics-bar" id="entity-graph-metrics-bar">
      ${hostCount ? `<span class="entity-graph-metric-pill" data-type="host">💻 <strong>${hostCount}</strong> Host(s)</span>` : ""}
      <span class="entity-graph-metric-pill" data-type="incident">🛡️ <strong>${totalIncidents}</strong> Incident(s)</span>
      ${procCount ? `<span class="entity-graph-metric-pill" data-type="process">⚙️ <strong>${procCount}</strong> Process(es)</span>` : ""}
      ${fileCount ? `<span class="entity-graph-metric-pill" data-type="file">📄 <strong>${fileCount}</strong> File(s)</span>` : ""}
      ${hashCount ? `<span class="entity-graph-metric-pill" data-type="hash">🔑 <strong>${hashCount}</strong> Hash(es)</span>` : ""}
      ${ipCount ? `<span class="entity-graph-metric-pill" data-type="ip">🌐 <strong>${ipCount}</strong> C2 / IP / Domain(s)</span>` : ""}
      <span class="entity-graph-metric-pill" data-type="all">↔️ <strong>${edges.length}</strong> Relationships</span>
    </div>

    <div class="entity-graph-legend" id="entity-graph-legend"></div>
  </div>`;
}

function mountEntityGraph(container, workspace) {
  const graph = workspace?.entity_graph || {};
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const primaryIncId = String(workspace?.incident_id || "");
  const wrap = container.querySelector("#entity-graph-wrap");
  const graphBody = container.querySelector("#entity-graph-body");
  const canvasHost = container.querySelector("#entity-graph-canvas");
  const detailsHost = container.querySelector("#entity-graph-details");
  const legendHost = container.querySelector("#entity-graph-legend");
  const searchInput = container.querySelector("#entity-graph-search");
  const fitButton = container.querySelector("#entity-graph-fit");
  const fullscreenButton = container.querySelector("#entity-graph-fullscreen");
  const filterBar = container.querySelector("#entity-graph-filter-bar");
  const metricsBar = container.querySelector("#entity-graph-metrics-bar");

  if (!canvasHost || !nodes.length) return;

  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  let activeIncidentFilter = "all";
  let activeTypeFilter = "all";
  let selectedId = null;

  let pos = _computeForceLayout(nodes, edges, primaryIncId);

  const svg = _svgEl("svg", { viewBox: `0 0 ${_GRAPH_W} ${_GRAPH_H}`, class: "entity-graph-svg", role: "img", "aria-label": "Multi-incident relationship graph" });
  const defs = _svgEl("defs");

  // Arrow markers for standard and cross-incident connections
  const markerStd = _svgEl("marker", { id: "arrow-std", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" });
  markerStd.appendChild(_svgEl("path", { d: "M0,0 L10,5 L0,10 z", fill: "#5b7a8f" }));
  defs.appendChild(markerStd);

  const markerCross = _svgEl("marker", { id: "arrow-cross", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" });
  markerCross.appendChild(_svgEl("path", { d: "M0,0 L10,5 L0,10 z", fill: "#f59e0b" }));
  defs.appendChild(markerCross);

  svg.appendChild(defs);

  const viewport = _svgEl("g", { class: "entity-graph-viewport" });
  const edgeLayer = _svgEl("g", { class: "entity-graph-edges" });
  const nodeLayer = _svgEl("g", { class: "entity-graph-nodes" });
  viewport.appendChild(edgeLayer);
  viewport.appendChild(nodeLayer);
  svg.appendChild(viewport);

  const edgeGroups = [];
  const nodeGroups = new Map();

  function updateConnectedEdges(nodeId) {
    edgeGroups.forEach((eg, idx) => {
      const srcId = eg.dataset.src;
      const dstId = eg.dataset.dst;
      if (srcId !== nodeId && dstId !== nodeId) return;

      const pv = pos.get(srcId), pu = pos.get(dstId);
      if (!pv || !pu) return;

      const isCross = eg.classList.contains("is-cross-incident");
      const pathData = _calcEdgePath(pv, pu, isCross, idx);

      const path = eg.querySelector("path");
      if (path) {
        path.setAttribute("d", pathData.d);
      }

      const label = eg.querySelector("text.entity-graph-edge-label");
      if (label) {
        label.setAttribute("x", pathData.labelX);
        label.setAttribute("y", pathData.labelY);
      }
      const bg = eg.querySelector("rect.entity-graph-edge-label-bg");
      if (bg && label) {
        try {
          const bbox = label.getBBox();
          bg.setAttribute("x", bbox.x - 4);
          bg.setAttribute("y", bbox.y - 2);
        } catch {}
      }
    });
  }

  // Relations that should display visible on-canvas text labels (structural hierarchy only)
  const VISIBLE_LABEL_RELATIONS = new Set([
    "spawned", "spawns", "injected_into", "modified_registry", "communicates_with"
  ]);

  function renderGraphElements() {
    edgeLayer.innerHTML = "";
    nodeLayer.innerHTML = "";
    edgeGroups.length = 0;
    nodeGroups.clear();

    edges.forEach((e, idx) => {
      const pv = pos.get(e.src), pu = pos.get(e.dst);
      if (!pv || !pu) return;
      const g = _svgEl("g", { class: `entity-graph-edge ${e.is_cross_incident ? "is-cross-incident" : ""}`, "data-src": e.src, "data-dst": e.dst });
      
      const strokeColor = e.color || (e.is_cross_incident ? "#f59e0b" : e.relation?.includes("spawn") || e.relation?.includes("inject") ? "#ff7382" : e.evidence_status === "co_occurrence_only" ? "#475569" : "#5b7a8f");
      const pathData = _calcEdgePath(pv, pu, Boolean(e.is_cross_incident), idx);

      g.appendChild(_svgEl("path", {
        d: pathData.d,
        stroke: strokeColor,
        "stroke-width": e.is_cross_incident ? 1.8 : 1.4,
        "stroke-dasharray": e.is_cross_incident ? "5 3" : e.evidence_status === "co_occurrence_only" ? "4 3" : "",
        "marker-end": e.is_cross_incident ? "url(#arrow-cross)" : "url(#arrow-std)",
        fill: "none",
      }));

      // Only print text labels on-canvas for high-value structural relationships to eliminate overlapping text clutter
      const shouldShowLabel = VISIBLE_LABEL_RELATIONS.has(e.relation);
      if (shouldShowLabel) {
        const label = (e.relation || "").replaceAll("_", " ");
        const text = _svgEl("text", { x: pathData.labelX, y: pathData.labelY, class: "entity-graph-edge-label", "text-anchor": "middle" });
        text.textContent = label;
        g.appendChild(text);
      }

      const title = _svgEl("title");
      title.textContent = `${e.relation}${(e.evidence || []).length ? ` — evidence: ${e.evidence.join(", ")}` : ""}`;
      g.appendChild(title);

      edgeLayer.appendChild(g);
      edgeGroups.push(g);
    });

    nodes.forEach((n) => {
      const p = pos.get(n.id);
      if (!p) return;
      const meta = _entityMeta(n.type);
      const isIncident = n.type === "incident";
      const isMalicious = n.disposition === "malicious";
      const isSuspicious = n.disposition === "suspicious";
      const isShared = n.props?.is_shared_pivot || (n.incidents && n.incidents.length > 1);
      const nodeColor = n.color || meta.color;
      const radius = isIncident ? 26 : isShared ? 23 : 19;

      const classes = [
        "entity-graph-node",
        isIncident ? "is-incident" : "",
        isMalicious ? "is-malicious" : "",
        isSuspicious ? "is-suspicious" : "",
        isShared ? "is-shared-pivot" : "",
      ].filter(Boolean).join(" ");

      const g = _svgEl("g", { class: classes, "data-id": n.id, transform: `translate(${p.x},${p.y})`, tabindex: "0", role: "button" });

      // Outer circle / glowing halo
      g.appendChild(_svgEl("circle", {
        r: radius,
        fill: isIncident ? "#0a192f" : "#080f1a",
        stroke: isMalicious ? "#ef4444" : isSuspicious ? "#f97316" : nodeColor,
        "stroke-width": isIncident ? 3.5 : isMalicious ? 3.5 : 2.2,
      }));

      // Monogram icon inside circle
      const mono = _svgEl("text", { class: "entity-graph-node-icon", fill: isMalicious ? "#ef4444" : isSuspicious ? "#f97316" : nodeColor, "text-anchor": "middle", dy: "0.35em" });
      mono.textContent = _entityMonogram(n.type);
      g.appendChild(mono);

      // Label under node
      const label = _svgEl("text", { class: "entity-graph-node-label", y: radius + 14, "text-anchor": "middle" });
      const displayLabel = n.label && n.label.length > 24 ? `${n.label.slice(0, 23)}…` : (n.label || "");
      label.textContent = displayLabel;
      g.appendChild(label);

      // Tooltip
      const title = _svgEl("title");
      const dispTag = (n.disposition && n.disposition !== "unknown") ? ` — [${String(n.disposition).toUpperCase()}]` : "";
      title.textContent = `${n.label || n.id} (${meta.name})${dispTag} — Click to inspect, drag to reposition`;
      g.appendChild(title);

      // Interactive Draggable Node Handling
      let isDraggingNode = false;
      let startPointerX = 0, startPointerY = 0;
      let nodeStartX = 0, nodeStartY = 0;
      let moved = false;

      g.addEventListener("pointerdown", (e) => {
        if (e.button !== 0) return;
        e.stopPropagation();
        isDraggingNode = true;
        moved = false;
        startPointerX = e.clientX;
        startPointerY = e.clientY;
        const currentPos = pos.get(n.id) || { x: 0, y: 0 };
        nodeStartX = currentPos.x;
        nodeStartY = currentPos.y;
        g.setPointerCapture(e.pointerId);
        g.classList.add("is-dragging");
      });

      g.addEventListener("pointermove", (e) => {
        if (!isDraggingNode) return;
        const dx = (e.clientX - startPointerX) / scale;
        const dy = (e.clientY - startPointerY) / scale;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
          moved = true;
        }
        const newX = Math.max(35, Math.min(_GRAPH_W - 35, nodeStartX + dx));
        const newY = Math.max(35, Math.min(_GRAPH_H - 35, nodeStartY + dy));
        pos.set(n.id, { x: newX, y: newY });
        g.setAttribute("transform", `translate(${newX},${newY})`);
        updateConnectedEdges(n.id);
      });

      const handleEnd = (e) => {
        if (!isDraggingNode) return;
        isDraggingNode = false;
        g.classList.remove("is-dragging");
        try { g.releasePointerCapture(e.pointerId); } catch {}
        if (!moved) {
          selectNode(selectedId === n.id ? null : n.id);
        }
      };

      g.addEventListener("pointerup", handleEnd);
      g.addEventListener("pointercancel", handleEnd);

      g.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(selectedId === n.id ? null : n.id); }
      });

      nodeLayer.appendChild(g);
      nodeGroups.set(n.id, g);
    });

    // Label backing rects
    edgeLayer.querySelectorAll("text.entity-graph-edge-label").forEach((text) => {
      try {
        const bbox = text.getBBox();
        const rect = _svgEl("rect", { x: bbox.x - 4, y: bbox.y - 2, width: bbox.width + 8, height: bbox.height + 4, class: "entity-graph-edge-label-bg" });
        text.parentNode.insertBefore(rect, text);
      } catch { /* hidden tab fallback */ }
    });

    applyFilters();
  }

  canvasHost.innerHTML = "";
  canvasHost.appendChild(svg);
  renderGraphElements();

  // Pan and Zoom
  let scale = 1, tx = 0, ty = 0, dragging = false, dragStartX = 0, dragStartY = 0, startTx = 0, startTy = 0;
  const applyTransform = () => viewport.setAttribute("transform", `translate(${tx},${ty}) scale(${scale})`);

  svg.addEventListener("pointerdown", (event) => {
    if (event.target.closest(".entity-graph-node")) return;
    dragging = true; dragStartX = event.clientX; dragStartY = event.clientY; startTx = tx; startTy = ty;
    svg.setPointerCapture(event.pointerId);
  });
  svg.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    tx = startTx + (event.clientX - dragStartX);
    ty = startTy + (event.clientY - dragStartY);
    applyTransform();
  });
  svg.addEventListener("pointerup", () => { dragging = false; });
  svg.addEventListener("pointercancel", () => { dragging = false; });
  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    scale = Math.min(2.8, Math.max(0.35, scale * (event.deltaY > 0 ? 0.9 : 1.1)));
    applyTransform();
  }, { passive: false });

  // Deselect on clicking canvas backdrop
  svg.addEventListener("click", (event) => {
    if (!event.target.closest(".entity-graph-node")) {
      selectNode(null);
    }
  });

  function renderDetails(node) {
    if (!node) {
      if (graphBody) graphBody.classList.remove("has-inspector");
      detailsHost.innerHTML = "";
      return;
    }

    if (graphBody) graphBody.classList.add("has-inspector");
    const meta = _entityMeta(node.type);
    const props = node.props || {};
    const incidents = node.incidents || [];
    const neighbors = _neighborsOf(node.id, edges);

    // Disposition Badge
    let dispBadge = "";
    if (node.disposition === "malicious") dispBadge = `<span class="entity-graph-disposition-badge is-malicious">🔴 Malicious</span>`;
    else if (node.disposition === "suspicious") dispBadge = `<span class="entity-graph-disposition-badge is-suspicious">🟠 Suspicious</span>`;
    else if (node.disposition === "clean") dispBadge = `<span class="entity-graph-disposition-badge is-clean">🟢 Clean</span>`;

    // Linked Incidents Pills
    const incPills = incidents.map((incId) => {
      const isPrimary = incId === primaryIncId;
      const incMeta = (graph.correlated_incidents || []).find((c) => c.id === incId);
      const color = isPrimary ? (graph.primary_incident_color || "#38bdf8") : (incMeta?.color || "#f59e0b");
      return `<button type="button" class="entity-graph-filter-chip is-active" style="padding:0.18rem 0.55rem;font-size:0.72rem;" data-jump-incident="${escapeHTML(incId)}"><span class="entity-graph-filter-dot" style="background:${color}"></span>${escapeHTML(incId)}${isPrimary ? " (Focus Case)" : ""}</button>`;
    }).join(" ");

    // Attribute Rows
    const propRows = Object.entries(props)
      .filter(([k]) => !["is_focus_entity", "is_shared_pivot"].includes(k))
      .map(([k, v]) => `<tr><th scope="row">${escapeHTML(k.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase()))}</th><td class="${k.includes('cmd') || k.includes('hash') || k.includes('id') || k.includes('ip') ? 'mono' : ''}">${escapeHTML(String(v))}</td></tr>`).join("");

    const related = neighbors.map(({ id, dir, edge }) => {
      const other = nodeById.get(id);
      if (!other) return "";
      const otherMeta = _entityMeta(other.type);
      const arrow = dir === "out" ? "→" : "←";
      const { action, evidence } = _formatRelationshipDesc(edge, dir, node, other);

      return `<li class="entity-graph-related-item">
        <div class="entity-graph-related-header">
          <button type="button" class="entity-graph-related-link" data-id="${escapeHTML(id)}">
            <span class="entity-graph-mini-icon" style="color:${other.color || otherMeta.color}">${_entityMonogram(other.type)}</span>
            <span class="entity-label-text" title="${escapeHTML(other.label)}">${escapeHTML(other.label)}</span>
          </button>
          <span class="mono" style="font-size:0.7rem;color:var(--muted);background:var(--surface);padding:0.1rem 0.4rem;border-radius:0.25rem;border:1px solid var(--border-soft);flex-shrink:0;">${escapeHTML(otherMeta.name)}</span>
        </div>
        <div class="entity-graph-rel-desc">
          <div style="color:var(--accent);font-weight:600;display:flex;align-items:center;gap:0.35rem;">
            <span>${arrow}</span> <span>${escapeHTML(action)}</span>
          </div>
          ${evidence ? `<div style="font-size:0.72rem;color:var(--muted);margin-top:0.2rem;font-style:italic;">Evidence: ${escapeHTML(evidence)}</div>` : ""}
        </div>
      </li>`;
    }).join("");

    detailsHost.innerHTML = `
      <div class="entity-graph-details-header">
        <div style="display:flex;align-items:center;gap:0.75rem;min-width:0;">
          <span class="entity-graph-mini-icon" style="color:${node.color || meta.color};width:2.2rem;height:2.2rem;font-size:0.8rem;">${_entityMonogram(node.type)}</span>
          <div style="min-width:0;">
            <h3 style="margin:0;font-size:1.05rem;word-break:break-all;">${escapeHTML(node.label)}</h3>
            <div style="display:flex;align-items:center;gap:0.4rem;margin-top:0.25rem;">
              <span class="mono" style="color:var(--muted);font-size:0.75rem;">${escapeHTML(meta.name)}</span>
              ${dispBadge}
            </div>
          </div>
        </div>
        <button type="button" class="entity-graph-close-btn" id="entity-graph-close-inspector" title="Close Inspector" aria-label="Close Inspector">✕</button>
      </div>

      ${incidents.length ? `<div style="margin-bottom:0.9rem;"><strong style="font-size:0.78rem;color:var(--muted);display:block;margin-bottom:0.35rem;">Correlated Incident Scope (${incidents.length})</strong><div style="display:flex;flex-wrap:wrap;gap:0.35rem;">${incPills}</div></div>` : ""}

      <div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>
        <tr><th scope="row">Entity Type</th><td>${escapeHTML(meta.name)}</td></tr>
        <tr><th scope="row">Direct Connections</th><td>${neighbors.length}</td></tr>
        ${propRows}
      </tbody></table></div>

      <h3 style="margin-top:1.1rem;margin-bottom:0.6rem;">Forensic Relationships (${neighbors.length})</h3>
      <ul class="data-list entity-graph-related-list" style="margin:0;padding:0;list-style:none;">${related || `<li>${emptyState("No related entities.")}</li>`}</ul>`;

    const closeBtn = detailsHost.querySelector("#entity-graph-close-inspector");
    if (closeBtn) closeBtn.addEventListener("click", () => selectNode(null));

    detailsHost.querySelectorAll(".entity-graph-related-link").forEach((btn) => {
      btn.addEventListener("click", () => selectNode(btn.dataset.id));
    });
    detailsHost.querySelectorAll("[data-jump-incident]").forEach((btn) => {
      btn.addEventListener("click", () => {
        setIncidentFilter(btn.dataset.jumpIncident);
      });
    });
  }

  function selectNode(id) {
    selectedId = id;
    const isConnected = (nid) => nid === id || edges.some((e) => (e.src === id && e.dst === nid) || (e.dst === id && e.src === nid));
    
    nodeGroups.forEach((g, nid) => {
      g.classList.toggle("is-selected", nid === id);
      g.classList.toggle("is-dimmed", Boolean(id) && !isConnected(nid));
    });
    edgeGroups.forEach((g) => {
      const connected = g.dataset.src === id || g.dataset.dst === id;
      g.classList.toggle("is-highlighted", Boolean(id) && connected);
      g.classList.toggle("is-dimmed", Boolean(id) && !connected);
    });
    renderDetails(id ? nodeById.get(id) : null);
  }

  function applyFilters() {
    const q = (searchInput?.value || "").trim().toLowerCase();

    nodeGroups.forEach((g, id) => {
      const n = nodeById.get(id);
      const matchesSearch = !q || (n.label || "").toLowerCase().includes(q) || (n.type || "").toLowerCase().includes(q);
      
      let matchesIncident = false;
      if (activeIncidentFilter === "all") {
        matchesIncident = true;
      } else {
        const incs = n.incidents || [];
        matchesIncident = incs.includes(activeIncidentFilter) || n.id === activeIncidentFilter || n.label === activeIncidentFilter;
      }
      const matchesType = activeTypeFilter === "all" || n.type === activeTypeFilter;
      
      const isVisible = matchesSearch && matchesIncident && matchesType;
      g.classList.toggle("is-filter-hidden", !matchesIncident);
      g.classList.toggle("is-search-dimmed", !isVisible && matchesIncident);
      g.classList.remove("is-dimmed");
    });

    edgeGroups.forEach((eg) => {
      const srcId = eg.dataset.src;
      const dstId = eg.dataset.dst;
      const srcNode = nodeById.get(srcId);
      const dstNode = nodeById.get(dstId);

      if (activeIncidentFilter === "all") {
        eg.classList.remove("is-filter-hidden");
      } else {
        const srcInInc = srcNode?.incidents?.includes(activeIncidentFilter) || srcNode?.id === activeIncidentFilter;
        const dstInInc = dstNode?.incidents?.includes(activeIncidentFilter) || dstNode?.id === activeIncidentFilter;
        eg.classList.toggle("is-filter-hidden", !(srcInInc || dstInInc));
      }
      eg.classList.remove("is-dimmed");
    });
  }

  function updateFilterChipUI() {
    filterBar.querySelectorAll(".entity-graph-filter-chip").forEach((chip) => {
      chip.classList.toggle("is-active", chip.dataset.incident === activeIncidentFilter);
      chip.classList.toggle("is-inactive", chip.dataset.incident !== activeIncidentFilter && activeIncidentFilter !== "all");
    });
  }

  function setIncidentFilter(incId) {
    activeIncidentFilter = incId;
    selectedId = null;
    updateFilterChipUI();
    applyFilters();
    renderDetails(null);
  }

  // Filter chips interaction
  filterBar.addEventListener("click", (event) => {
    const chip = event.target.closest(".entity-graph-filter-chip");
    if (!chip) return;
    setIncidentFilter(chip.dataset.incident);
  });

  // Metrics bar pill interaction
  metricsBar.addEventListener("click", (event) => {
    const pill = event.target.closest(".entity-graph-metric-pill");
    if (!pill) return;
    const type = pill.dataset.type;
    activeTypeFilter = activeTypeFilter === type ? "all" : type;
    metricsBar.querySelectorAll(".entity-graph-metric-pill").forEach((p) => {
      p.classList.toggle("is-active", p.dataset.type === activeTypeFilter && activeTypeFilter !== "all");
    });
    applyFilters();
  });

  if (searchInput) {
    searchInput.addEventListener("input", applyFilters);
  }

  if (fitButton) {
    fitButton.addEventListener("click", () => {
      scale = 1; tx = 0; ty = 0; applyTransform();
      if (searchInput) searchInput.value = "";
      setIncidentFilter("all");
      activeTypeFilter = "all";
      metricsBar.querySelectorAll(".entity-graph-metric-pill").forEach((p) => p.classList.remove("is-active"));
      applyFilters();
      selectNode(null);
    });
  }

  if (fullscreenButton && wrap) {
    fullscreenButton.addEventListener("click", () => {
      const isFull = wrap.classList.toggle("is-fullscreen");
      fullscreenButton.textContent = isFull ? "⤡" : "⤢";
      fullscreenButton.title = isFull ? "Exit fullscreen" : "Fullscreen";
    });
  }

  // Legend
  const presentTypes = [...new Set(nodes.map((n) => n.type))];
  legendHost.innerHTML = "<strong>Legend</strong>" + presentTypes.map((t) => `<span class="entity-graph-legend-item"><span class="entity-graph-mini-icon" style="color:${_entityMeta(t).color}">${_entityMonogram(t)}</span>${escapeHTML(_entityMeta(t).name)}</span>`).join("");
}


function investigationEvidenceTab(workspace) {
  const items = workspace?.evidence || [];
  if (!items.length) return emptyState("No evidence items have been recorded for this case yet.");
  const rows = items.map((it) => `<li><div><strong>${escapeHTML(it.summary || it.evidence_type)}</strong><p>${escapeHTML(it.evidence_type)} · ${escapeHTML(it.source)} · ${escapeHTML(formatDate(it.timestamp))}</p>${(it.related_entities || []).length ? `<p class="mono">${escapeHTML(it.related_entities.join(", "))}</p>` : ""}${(it.supported_findings || []).length ? `<p>${it.supported_findings.map((f) => escapeHTML(f)).join("; ")}</p>` : ""}</div><span class="evidence-status-tag">${escapeHTML(it.evidence_status || "")}</span></li>`).join("");
  return `<ul class="data-list">${rows}</ul>`;
}

function investigationActivityTab(workspace) {
  const items = workspace?.activity || [];
  if (!items.length) return emptyState("No activity has been recorded for this case yet.");
  const rows = items.map((it) => `<tr><td class="mono">${escapeHTML(formatDate(it.timestamp))}</td><td>${escapeHTML(it.actor)}</td><td>${escapeHTML(it.action)}</td><td class="mono">${escapeHTML(it.stage || "")}</td><td>${escapeHTML(it.comments || "")}</td></tr>`).join("");
  return `<div class="table-wrap"><table class="case-context-table"><thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Stage</th><th>Comments</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

const _INVESTIGATION_SUBTABS = [
  ["overview", "Overview", investigationOverviewTab],
  ["output", "Output", investigationOutputTab],
  ["timeline", "Timeline", investigationTimelineTab],
  ["entity_graph", "Entity Graph", investigationEntityGraphTab, mountEntityGraph],
];

// Approve Investigation only unlocks Reporting (it stays "Pending"); "Continue
// to Reporting" only navigates there, and Reporting runs from its own Run
// Reporting button (stageActionButtons()). The action bar sits after the
// sub-tab body, so switching tabs never moves or re-renders it.
//
// While Processing, only the live Agent Activity panel is shown (as in
// renderThreatIntelStage())— no sub-tabs, since `workspace` may still carry
// a previous run's result during a re-run. The backend attaches a `resume`
// action to every Processing stage but enables it only when the worker lease
// has lapsed (workflow/commands.py::available_actions()), so Resume is shown
// only in that genuinely interrupted case.
function renderInvestigationStage(root, stage, caseId, lastError, onAction, onNavigate, workflow, workspace) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>Playbook-driven investigation of the enriched case — evidence collection, timeline reconstruction, MITRE ATT&amp;CK mapping, and entity correlation.</p></div>${stateBadge(stage)}</div>`;
  if (stage.state === "in_progress") {
    const resumable = { ...stage, actions: (stage.actions || []).filter((action) => action.type === "resume" && action.enabled) };
    root.innerHTML = `
      ${header}
      <section id="investigation-agent-activity"></section>
      ${stageActionButtons(resumable, workflow, { footer: true })}
      <div id="action-status" aria-live="polite"></div>
    `;
    mountStageActivity(root.querySelector("#investigation-agent-activity"), caseId, stage, workflow, { live: true });
    bindStageActions(root, stage, workflow, onAction, onNavigate);
    return;
  }
  const nav = `<div class="subtab-bar" role="tablist">${_INVESTIGATION_SUBTABS.map(([key, label]) => `<button type="button" class="subtab-button" data-subtab="${key}" role="tab">${escapeHTML(label)}</button>`).join("")}</div>`;
  const actions = `${stageActionButtons(stage, workflow, { footer: true })}<div id="action-status" aria-live="polite"></div>`;
  root.innerHTML = `${header}<section id="investigation-agent-activity"></section>${nav}<div id="investigation-subtab-body"></div>${actions}`;
  // Full trace stays available above the unchanged Investigation tabs;
  // expanded while the result awaits the analyst's decision.
  if (stage.state !== "not_started" && stage.state !== "locked") {
    mountStageActivity(root.querySelector("#investigation-agent-activity"), caseId, stage, workflow,
      { collapsed: stage.state !== "awaiting_approval" });
  }
  bindStageActions(root, stage, workflow, onAction, onNavigate);
  const body = root.querySelector("#investigation-subtab-body");
  const buttons = [...root.querySelectorAll("[data-subtab]")];
  const activate = (key) => {
    const entry = _INVESTIGATION_SUBTABS.find(([k]) => k === key) || _INVESTIGATION_SUBTABS[0];
    buttons.forEach((b) => b.classList.toggle("active", b.dataset.subtab === entry[0]));
    try {
      body.innerHTML = entry[2](workspace);
      if (typeof entry[3] === "function") entry[3](body, workspace);
    } catch (error) {
      body.innerHTML = errorState(error);
    }
  };
  buttons.forEach((button) => button.addEventListener("click", () => activate(button.dataset.subtab)));
  activate("overview");
}

function renderSelectedStage(root, stage, caseId, lastError, onAction, onNavigate, workflow, workspace) {
  destroyStageActivity();
  if (stage.key === "parsing") {
    renderParsingStage(root, stage, caseId, lastError, onAction, onNavigate, workflow);
    return;
  }
  if (stage.key === "triage") {
    renderTriageStage(root, stage, caseId, lastError, onAction, onNavigate, workflow);
    return;
  }
  if (stage.key === "threat_intel") {
    renderThreatIntelStage(root, stage, caseId, lastError, onAction, onNavigate, workflow);
    return;
  }
  if (stage.key === "investigation") {
    renderInvestigationStage(root, stage, caseId, lastError, onAction, onNavigate, workflow, workspace);
    return;
  }
  if (stage.key === "reporting") {
    renderReportingStage(root, stage, caseId, lastError, onAction, onNavigate, workflow);
    return;
  }
  root.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2></div>${stateBadge(stage)}</div>${stageActionButtons(stage, workflow)}<div id="action-status" aria-live="polite"></div>${jsonPreview(stage.result)}`;
  bindStageActions(root, stage, workflow, onAction, onNavigate);
}

// Reporting stage card: same header/action-bar shape every other stage uses
// (name, stateBadge, Re-run/Reject/Approve Reporting — the final stage, so
// never a Continue control), but with the four-report
// table (frontend/js/pages/reports.js —
// the SAME implementation the standalone Reporting page uses, embedded
// directly here) in place of a raw JSON dump. Raw Reporting JSON is still
// available, just as a secondary "Raw JSON" link inside that panel rather
// than the primary view. Approve is only enabled once a reviewed candidate
// has actually been materialised (Submit for Approval, inside the reports
// panel) — see workflow/commands.py::available_actions() — so this single
// Approve control is the one approval path; there is no second "confirm"
// button competing with it.
function renderReportingStage(root, stage, caseId, lastError, onAction, onNavigate, workflow) {
  root.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2></div>${stateBadge(stage)}</div>${stageActionButtons(stage, workflow)}<div id="action-status" aria-live="polite"></div><section id="reporting-agent-activity"></section><div id="reporting-panel"></div>`;
  bindStageActions(root, stage, workflow, onAction, onNavigate);
  // Live trace while Reporting runs; afterwards the full trace stays above
  // the unchanged reports UI, expanded while it awaits the analyst's
  // decision or after a failure.
  if (stage.state === "in_progress") {
    mountStageActivity(root.querySelector("#reporting-agent-activity"), caseId, stage, workflow, { live: true });
  } else if (stage.state !== "not_started" && stage.state !== "locked") {
    mountStageActivity(root.querySelector("#reporting-agent-activity"), caseId, stage, workflow,
      { collapsed: stage.state !== "awaiting_approval" && stage.state !== "failed" });
  }
  const panel = root.querySelector("#reporting-panel");
  mountReportsPanel(panel, { caseId, navigate: null, embedded: true });
}

async function analystIdentity() {
  const settings = await fetchJSON("/api/settings");
  const analyst = settings.analyst_name || window.prompt("Analyst name", "")?.trim() || "";
  if (analyst && !settings.analyst_name) {
    await fetchJSON("/api/settings", { method: "PUT", body: { analyst_name: analyst, openai_model: settings.openai_model } });
  }
  return analyst;
}

async function actionRequest(caseId, action, stage) {
  const base = `/api/cases/${encodeURIComponent(caseId)}`;
  if (action === "start") return [`${base}/stages/${stage.key}/runs`, {}];
  if (action === "rerun") return [`${base}/stages/${stage.key}/reruns`, {}];
  if (action === "resume") return [`${base}/workflow/resume`, {}];
  const analyst = await analystIdentity();
  if (!analyst) throw new Error("An analyst name is required.");
  if (action === "approve") {
    const comments = window.prompt("Approval comments (optional)", "") ?? "";
    return [`${base}/approvals/${stage.key}`, { decision: "approve", analyst, comments }];
  }
  const comments = window.prompt("Rejection reason (required)", "")?.trim() || "";
  if (!comments) throw new Error("A rejection reason is required.");
  return [`${base}/approvals/${stage.key}`, { decision: "reject", analyst, comments }];
}

function requiresConfirmation(action, stage) {
  if (action === "rerun") {
    return window.confirm(`Re-run ${stage.name}? Canonical downstream invalidation rules will apply.`);
  }
  if (action === "reject") {
    return window.confirm(`Reject ${stage.name}? Downstream stages may remain blocked.`);
  }
  return true;
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function pollRun(runId, onProgress) {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt += 1) {
    const run = await fetchJSON(`/api/runs/${encodeURIComponent(runId)}`);
    onProgress(run);
    if (!run.poll) return run;
    await delay(POLL_INTERVAL_MS);
  }
  return null;
}

export async function renderWorkspace(root, { navigate, route }) {
  const caseId = route.caseId;
  if (!caseId) {
    root.innerHTML = errorState({ message: "No case was selected.", code: "CASE_NOT_SELECTED" });
    return;
  }
  root.innerHTML = loadingState(`Loading case ${caseId}…`);
  try {
    let detail = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}`);
    let workflow = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/workflow`);
    let selectedStageKey = workflow.stages.find((stage) => stage.name === workflow.current_stage)?.key || workflow.stages[0]?.key;
    root.innerHTML = `
      <section class="page-header"><div><p class="mono">${escapeHTML(detail.case.id)}</p><h1>${escapeHTML(detail.case.title)}</h1><p>${escapeHTML(detail.case.status)} · ${escapeHTML(detail.case.assignee)}</p></div><div class="stage-actions" style="margin:0"><button class="action-button" id="load-raw">View Raw Incident JSON</button></div></section>
      <section class="panel" id="case-context-panel"><h2>Case context</h2>${caseContext(detail)}</section>
      <section class="panel" id="workflow-panel" style="margin-top:1rem"></section>
      <section class="workspace-grid${KEY_FINDINGS_STAGES.has(selectedStageKey) ? "" : " stage-only"}" id="stage-workspace-grid"><article class="panel" id="key-findings-panel" ${KEY_FINDINGS_STAGES.has(selectedStageKey) ? "" : "hidden"}><h2>Key findings</h2>${findings(detail.workspace, workflow.stages.find((stage) => stage.key === selectedStageKey))}</article><article class="panel" id="stage-output"></article></section>`;
    root.querySelector("#load-raw").addEventListener("click", async () => {
      const modal = openModal("Raw Incident JSON");
      modal.setBody(loadingState("Loading raw incident…"));
      try {
        const raw = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/raw`);
        modal.setBody(jsonPreview(raw.incident));
      } catch (error) {
        modal.setBody(errorState(error));
      }
    });
    const workflowRoot = root.querySelector("#workflow-panel");
    const stageWorkspaceGrid = root.querySelector("#stage-workspace-grid");
    const keyFindingsPanel = root.querySelector("#key-findings-panel");
    const caseContextPanel = root.querySelector("#case-context-panel");
    const outputRoot = root.querySelector("#stage-output");

    const renderWorkflow = () => {
      workflowRoot.innerHTML = `<div class="page-header"><div><h2>Workflow</h2></div></div><div class="stage-grid">${stageCards(workflow.stages)}</div>`;
      const selected = workflow.stages.find((stage) => stage.key === selectedStageKey) || workflow.stages[0];
      selectedStageKey = selected.key;
      const showKeyFindings = KEY_FINDINGS_STAGES.has(selected.key);
      keyFindingsPanel.hidden = !showKeyFindings;
      stageWorkspaceGrid.classList.toggle("stage-only", !showKeyFindings);
      if (showKeyFindings) {
        keyFindingsPanel.innerHTML = `<h2>Key findings</h2>${findings(detail.workspace, selected)}`;
      }
      renderSelectedStage(outputRoot, selected, caseId, workflow.last_error, handleAction, selectStage, workflow, detail.workspace);
      workflowRoot.querySelectorAll("[data-stage]").forEach((button) => {
        button.classList.toggle("active", button.dataset.stage === selectedStageKey);
        button.addEventListener("click", () => selectStage(button.dataset.stage));
      });
    };

    // Stage navigation only (stage cards and Continue buttons): re-renders
    // from the already-loaded workflow — no request, no state change.
    function selectStage(stageKey) {
      selectedStageKey = stageKey;
      renderWorkflow();
    }

    // Refetches BOTH the workflow (per-stage status/actions) and the full
    // case detail (`detail.workspace` — the Investigation tabs' data source)
    // together, so an approve/rerun/reject action can never leave the
    // Investigation tabs, the Key findings panel, or the Case context
    // severity/confidence badges showing a stale run's data after the
    // action completes.
    const refreshWorkflow = async () => {
      [detail, workflow] = await Promise.all([
        fetchJSON(`/api/cases/${encodeURIComponent(caseId)}`),
        fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/workflow`),
      ]);
      caseContextPanel.innerHTML = `<h2>Case context</h2>${caseContext(detail)}`;
      renderWorkflow();
    };
    // The live Agent Activity stream reports when the running stage has
    // settled; refresh once so the stage's normal output replaces it.
    _onStageActivitySettled = () => { refreshWorkflow().catch(() => {}); };

    async function handleAction(action, stage) {
      if (!requiresConfirmation(action, stage)) return;
      const actionStatus = outputRoot.querySelector("#action-status");
      outputRoot.querySelectorAll("[data-workflow-action], [data-continue-stage]").forEach((button) => { button.disabled = true; });
      try {
        const [path, body] = await actionRequest(caseId, action, stage);
        if (actionStatus) actionStatus.innerHTML = `<p class="notice"><span class="spinner"></span>Submitting ${escapeHTML(action)}…</p>`;
        const result = await fetchJSON(path, { method: "POST", body });
        // Presentation only: once the backend has accepted a stage's Run
        // (start) action, keep that stage focused so its progress is visible.
        if (action === "start") selectedStageKey = stage.key;
        // The analyst launched this run here: keep its Agent Activity panel
        // expanded even if the run finishes before it is first shown running.
        if ((action === "start" || action === "rerun") && result.run_id) {
          _watchedLive.add(`${caseId}|${result.run_id}|${stage.key}`);
        }
        await refreshWorkflow();
        if (result.run_id) {
          await pollRun(result.run_id, (run) => {
            const statusRoot = outputRoot.querySelector("#action-status");
            if (statusRoot) statusRoot.innerHTML = run.progress?.note ? `<p class="notice">${escapeHTML(run.progress.note)}</p>` : "";
          });
          await refreshWorkflow();
        }
      } catch (error) {
        const statusRoot = outputRoot.querySelector("#action-status");
        if (statusRoot) statusRoot.innerHTML = errorState(error);
      }
    }

    renderWorkflow();
  } catch (error) {
    root.innerHTML = errorState(error);
  }
}
