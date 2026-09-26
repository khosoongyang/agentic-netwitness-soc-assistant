import { fetchJSON } from "../api.js";
import { badge, emptyState, errorState, escapeHTML, formatDate, jsonPreview, loadingState, openModal, provenanceValue, severityBadge, stateBadge } from "../ui.js";
import { TICKET_REPORT_TYPE, mountReportsPanel, openReportInto } from "./reports.js";

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

function confidenceBadge(level, justification) {
  const tone = String(level || "").toLowerCase() === "high" ? "confidence-high"
    : String(level || "").toLowerCase() === "medium" ? "confidence-medium" : "confidence-low";
  return badge(level, tone, justification || "");
}

function pendingValue(text) {
  return `<span class="value-pending">${escapeHTML(text)}</span>`;
}

function caseContext(detail) {
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
    ["Aegis Severity", investigation?.severity
      ? severityBadge(investigation.severity, investigation.severity_justification)
      : pendingValue(investigationFieldFallback)],
    ["Triage Classification", triageClassification ? severityBadge(triageClassification) : pendingValue("Pending Triage")],
    ["Unified Verdict", unifiedVerdict ? severityBadge(unifiedVerdict) : pendingValue("Not Identified")],
    ["Confidence", investigation?.confidence
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
// Triage is excluded too: its Overview tab already presents the same
// classification/IOC/risk evidence, so the sidebar only duplicated it and
// the stage now takes the full width (.workspace-grid.stage-only).
const KEY_FINDINGS_STAGES = new Set(["threat_intel", "investigation"]);

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
  /https?:\/\/[^\s"'<>)]+/g,
  /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+/g,
  /\b[a-fA-F0-9]{64}\b/g,
  /\b[a-fA-F0-9]{40}\b/g,
  /\b[a-fA-F0-9]{32}\b/g,
  /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  /(?<=:)\d{2,5}\b/g,
  /\bport\s+\d{1,5}\b/gi,
  /\b[\w-]+\.(?:exe|dll|ps1|psm1|bat|cmd|sh|py|js|vbs|scr|msi|jar)\b/gi,
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|dev|co|uk|de|fr|gov|edu|int|mil|app|cloud)\b/gi,
  /(?:\/[\w.-]+){2,}/g,
  /\b(?:Event ID|EventID|Process ID|Parent Process ID|PID|PPID)\s*[:#]?\s*\d+\b/gi,
  /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/g,
  /\bHK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|LM|CU|CR|U|CC)\\[^\s,;]+/gi,
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

const FINDING_CATEGORY_LABELS = { observed: "Observed", correlation: "Correlation", assessment: "Assessment" };

function findings(workspace, stageKey) {
  if (!KEY_FINDINGS_STAGES.has(stageKey)) return "";
  const items = workspace?.overview?.key_findings_by_stage?.[stageKey] || [];
  if (!items.length) return emptyState("No key findings have been distilled for this stage yet.");
  return `<ul class="data-list findings-list">${items.slice(0, 5).map((item) => {
    const categoryLabel = FINDING_CATEGORY_LABELS[item.category] || "";
    return `<li class="finding-item">
      <div>
        <div class="finding-heading"><strong>${escapeHTML(item.title || "Finding")}</strong>${categoryLabel ? `<span class="finding-category cat-${escapeHTML(item.category)}">${escapeHTML(categoryLabel)}</span>` : ""}</div>
        <p>${highlightEvidence(item.desc || "", item.evidence)}</p>
      </div>
      ${item.confidence ? `<span>${escapeHTML(item.confidence)}</span>` : ""}
    </li>`;
  }).join("")}</ul>`;
}

function actionControls(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  return `<div class="stage-actions" aria-label="${escapeHTML(stage.name)} actions">${actions.map((action) => `<button class="action-button ${action.type === "reject" ? "danger" : ""}" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(action.label)}</button>`).join("")}</div>`;
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

// Parsing never has an approval gate and is never locked (it is always the
// first stage), so build_workflow_stages() can only ever report one of
// these four states for it — the fifth generic state ("awaiting_approval")
// is unreachable here and intentionally not handled.
const _PARSING_ACTION_LABELS = { start: "Run Parsing", rerun: "Re-run Parsing" };

function parsingActionControls(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  return `<div class="stage-actions" aria-label="${escapeHTML(stage.name)} actions">${actions.map((action) => `<button class="action-button" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(_PARSING_ACTION_LABELS[action.type] || action.label)}</button>`).join("")}</div>`;
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
// summary sentence — placed directly after the alert fields.
function _poParserSummary(na, summaryTextHTML) {
  const summary = na.alert_summary || {};
  const ids = na.identifiers || {};
  const alertName = summary.alert_name || summary.alert_title;
  const rows = _poRows([
    ["Alert Name", alertName],
    ["Incident Title", summary.incident_title !== alertName ? summary.incident_title : null],
    ["Alert ID", summary.alert_id, (v) => _poValue(v, { mono: true })],
    ["Incident ID", summary.incident_id, (v) => _poValue(v, { mono: true })],
    ["Severity", summary.severity, (v) => severityBadge(v)],
    ["Incident Priority", summary.incident_priority],
    ["Risk Score", summary.risk_score],
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

function _poDetection(na) {
  const psa = na.powershell_analysis || {};
  const risk = psa.risk_assessment || {};
  const threat = na.threat_context || {};
  const mono = (v) => _poValue(v, { mono: true });
  const rows = _poRows([
    ["PowerShell Indicator Present", psa.powershell_indicator_present],
    ["Encoded Command Present", psa.encoded_command_present],
    ["PowerShell Decode Status", psa.decode_status, (v) => escapeHTML(_poHumanise(v))],
    ["Encoded Command Count", psa.encoded_command_count],
    ["Decoded Command Count", psa.decoded_command_count],
    ["PowerShell Risk Level", risk.risk_level, (v) => severityBadge(v)],
    ["PowerShell Risk Score", risk.risk_score],
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

function _poDataQuality(na, context) {
  const dq = na.data_quality || {};
  const meta = na.parser_metadata || {};
  const confidence = dq.parser_confidence || meta.parser_confidence;
  const score = dq.parser_confidence_score ?? meta.parser_confidence_score;
  const rows = _poRows([
    ["Parser Confidence", confidence, (v) => `${confidenceBadge(v)}${score !== undefined && score !== null ? ` <span class="mono">${escapeHTML(String(score))}/100</span>` : ""}`],
    ["Confidence Explanation", dq.confidence_explanation],
    ["Missing Required Fields", dq.missing_required_fields, (v) => _poValue(v, { mono: true })],
    ["Missing Context Fields", dq.missing_context_fields, (v) => _poValue(v, { mono: true })],
    ["Normalised Event Count", dq.normalised_event_count],
    ["Primary Data Source", context.primary_data_source],
    ["Observed Data Types", context.observed_data_types],
    ["Normalisation Status", meta.normalisation_status],
    ["Input Format", meta.input_format],
    ["Alert Count", meta.alert_count],
    ["Parser", meta.parser && meta.parser_version ? `${meta.parser} · ${meta.parser_version}` : meta.parser || meta.parser_version],
  ]);
  const warnings = Array.isArray(dq.warnings) ? dq.warnings.filter((w) => _poHas(w)) : [];
  const extra = [
    warnings.length ? `<div class="notice" style="margin-top:0.75rem"><strong>Warnings</strong><ul class="data-list">${warnings.map((w) => `<li><div>${escapeHTML(w)}</div></li>`).join("")}</ul></div>` : "",
    _poFieldList("Missing Optional Fields", dq.missing_optional_fields),
    _poFieldList("Not Applicable Fields", dq.not_applicable_fields),
  ].join("");
  return _poSection("Normalisation / Data Quality", rows, { extra });
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
    ${_poParserSummary(normalisedAlert, summaryTextHTML)}
    ${detailCards ? `<div class="integration-grid">${detailCards}</div>` : ""}
    ${_poDataQuality(normalisedAlert, context)}
  </div>`;
}

function renderParsingStage(root, stage, caseId, lastError, onAction, onContinue) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>Transform raw NetWitness incident data into structured, analyst-ready context.</p></div>${stateBadge(stage)}</div>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      ${loadingState("Parsing incident…")}
      <div id="action-status" aria-live="polite"></div>
    `;
  } else if (stage.state === "failed") {
    root.innerHTML = `
      ${header}
      <div class="state-panel error"><div>${escapeHTML(lastError || "Parsing failed for this run.")}</div></div>
      ${parsingActionControls(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
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
      <div id="action-status" aria-live="polite"></div>
      <div class="subtab-bar" role="tablist" aria-label="Parsing output view">
        <button type="button" class="subtab-button active" role="tab" id="parsing-tab-overview" data-parsing-view="overview" aria-selected="true" aria-controls="parsing-view-overview">Overview</button>
        <button type="button" class="subtab-button" role="tab" id="parsing-tab-json" data-parsing-view="json" aria-selected="false" aria-controls="parsing-view-json">JSON</button>
      </div>
      <div id="parsing-view-overview" role="tabpanel" aria-labelledby="parsing-tab-overview">${overviewHTML}</div>
      <section class="panel" id="parsing-view-json" role="tabpanel" aria-labelledby="parsing-tab-json" hidden>
        <div class="panel-header-row"><h3>Normalised Alert</h3>${downloadButton}</div>
        ${jsonPreview(stage.result?.normalised_alert || stage.result)}
      </section>
      <div class="stage-actions" style="margin-top:1rem">${(stage.actions || []).map((action) => `<button class="action-button" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(_PARSING_ACTION_LABELS[action.type] || action.label)}</button>`).join("")}<button class="action-button" id="continue-to-triage">Continue to Triage</button></div>
    `;
  } else {
    // not_started
    root.innerHTML = `
      ${header}
      ${parsingActionControls(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
  }
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
  const continueButton = root.querySelector("#continue-to-triage");
  if (continueButton) continueButton.addEventListener("click", () => onContinue("triage"));
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
// the same way.
const _TRIAGE_ACTION_LABELS = { start: "Run Triage", rerun: "Re-run Triage", approve: "Approve & Continue", reject: "Reject Triage" };

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

// Approve/Reject sit on the right, everything else (Run/Re-run) on the left;
// each button keeps its original action type, enabled state and handler.
function triageActionButtons(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  const button = (action) => `<button class="action-button ${action.type === "reject" ? "danger" : ""}" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(_TRIAGE_ACTION_LABELS[action.type] || action.label)}</button>`;
  const decision = ["reject", "approve"].map((type) => actions.find((action) => action.type === type)).filter(Boolean);
  const other = actions.filter((action) => !decision.includes(action));
  return `<div class="stage-actions triage-workflow-actions" aria-label="${escapeHTML(stage.name)} actions"><div class="triage-action-group">${other.map(button).join("")}</div><div class="triage-action-group">${decision.map(button).join("")}</div></div>`;
}

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

function triageSummarySection(ticket, result) {
  const rows = _poRows([
    ["Classification", ticket.classification, (v) => severityBadge(v)],
    ["Category", ticket.incident_category],
    ["Overall Risk", ticket.risk_rating?.overall_risk, (v) => severityBadge(v)],
    ["Initial Response", ticket.initial_response_time],
  ]);
  return `<section class="panel"><h3>Triage Summary</h3>${rows.length ? _poTable(rows) : ""}${triageExplanation(ticket, result)}</section>`;
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

function triageRiskAssessment(ticket) {
  const rr = ticket.risk_rating || {};
  const rows = [
    ["Initiation", rr.likelihood_initiation],
    ["Occurrence", rr.likelihood_occurrence],
    ["Adverse Impact", rr.likelihood_adverse_impact],
    ["Overall", rr.overall_risk],
  ];
  return `<article class="panel">
    <h3>Risk Assessment</h3>
    <div class="table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr><th>Dimension</th><th>Rating</th></tr></thead><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value ? severityBadge(value) : pendingValue("—")}</td></tr>`).join("")}</tbody></table></div>
    ${rr.rationale ? `<div class="notice triage-why"><h4 class="triage-subheading">Why ${escapeHTML(rr.overall_risk || "this rating")}?</h4><p>${escapeHTML(rr.rationale)}</p></div>` : ""}
  </article>`;
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

function renderTriageStage(root, stage, caseId, lastError, onAction) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>IOC assessment, risk evaluation and SOC classification.</p></div>${stateBadge(stage)}</div>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      ${loadingState("Analysing IOCs · assessing risk · classifying the incident…")}
      <div id="action-status" aria-live="polite"></div>
    `;
    root.querySelectorAll("[data-workflow-action]").forEach((button) => {
      button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
    });
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
      ${stage.state === "failed"
        ? `<div class="state-panel error"><div>${escapeHTML(lastError || "Triage failed for this run.")}</div></div>`
        : emptyState("No persisted Triage output is available for this run yet.")}
      ${triageActionButtons(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
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
        ${triageSummarySection(ticket, result)}
        <div class="integration-grid">${triageIOCEvidence(iocStep, ticket, result)}${triageRiskAssessment(ticket)}</div>
        ${triageMitreSection(ticket)}
        ${triageRecommendedActions(ticket)}
      </div>`;
    } catch (error) {
      overviewHTML = errorState(error);
    }
    root.innerHTML = `
      ${header}
      <div id="action-status" aria-live="polite"></div>
      <div class="subtab-bar" role="tablist" aria-label="Triage output view">
        <button type="button" class="subtab-button active" role="tab" id="triage-tab-overview" data-triage-view="overview" aria-selected="true" aria-controls="triage-view-overview">Overview</button>
        <button type="button" class="subtab-button" role="tab" id="triage-tab-ticket" data-triage-view="ticket" aria-selected="false" aria-controls="triage-view-ticket">Triage Ticket</button>
      </div>
      <div id="triage-view-overview" role="tabpanel" aria-labelledby="triage-tab-overview">${overviewHTML}</div>
      <div id="triage-view-ticket" role="tabpanel" aria-labelledby="triage-tab-ticket" hidden></div>
      ${triageActionButtons(stage)}
    `;
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
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
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
// GET /api/cases/<id>/workflow as stage.result — every field rendered below
// (iocs, virustotal, abuseipdb, alienvault_otx, enrichment_risk_*, notes,
// warnings, recommended_next_action) is that same backend-computed value.
// This section formats/labels/selects fields only; it never recomputes risk,
// provider status, or IOC validity — see the ownership note on
// tiWorkflowStatusLine() below for why the live "what happens next" line is
// derived from the Investigation stage's own reported state rather than from
// Threat Intelligence's recommended_next_action.
const _TI_ACTION_LABELS = { start: "Run Threat Intelligence", rerun: "Re-run Threat Intelligence" };

function tiActionButtons(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  return `<div class="stage-actions" style="margin-top:1rem" aria-label="${escapeHTML(stage.name)} actions">${actions.map((action) => `<button class="action-button" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(_TI_ACTION_LABELS[action.type] || action.label)}</button>`).join("")}</div>`;
}

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

// Presentation-only status -> badge tone, reusing the same state-* tones the
// stage cards already render (state-completed/failed/locked/
// awaiting_approval/not_started) rather than inventing new CSS. This labels
// whatever status string the provider call already returned
// (completed/skipped/not_found/error/unknown) — it never re-derives whether
// a lookup "worked".
function providerStatusBadge(status) {
  const s = String(status || "").toLowerCase();
  const tone = s === "completed" ? "state-completed"
    : s === "error" ? "state-failed"
    : s === "not_found" ? "state-awaiting_approval"
    : s === "skipped" ? "state-locked"
    : "state-not_started";
  return badge(status || "unknown", tone);
}

// Skipped/error results carry their own explanatory "reason" (or an HTTP
// status_code) straight from threat_intel.py's provider functions — shown
// visibly under the badge, not only as a hover title, so a failed/skipped
// lookup is never mistaken for "no results".
function providerStatusCell(result) {
  const detail = result?.reason || (result?.status_code ? `HTTP ${result.status_code}` : "");
  const badgeHTML = providerStatusBadge(result?.status);
  return detail ? `${badgeHTML}<br><small style="opacity:0.7">${escapeHTML(detail)}</small>` : badgeHTML;
}

const _INVESTIGATION_STATE_LINES = {
  not_started: "Investigation has not started yet.",
  in_progress: "Investigation is currently running.",
  awaiting_approval: "Investigation is complete and awaiting SOC analyst approval.",
  completed: "Investigation has been approved.",
  failed: "Investigation failed.",
  rejected: "Investigation was rejected.",
  locked: "Investigation is locked pending an earlier stage.",
};

// [OWNERSHIP] Threat Intelligence has no analyst-approval gate of its own —
// workflow/engine.py::resume_after_triage_approval() flips
// investigation_status straight to "Processing" the moment this stage
// completes (confirmed via workflow/commands.py's APPROVAL_STAGES, which
// does not include "threat_intel"). So "what happens next" is an
// orchestration fact, not a Threat-Intelligence one: it is read here from
// the Investigation stage's OWN already-computed `state` (the same enum
// stateBadge() renders on every stage card), never inferred or recomputed
// client-side. This is deliberately kept separate from — and never
// substituted for — result.recommended_next_action below, which is
// threat_intel.py's own risk-derived recommendation and must not be read as
// a workflow-state claim (including for older persisted results that still
// contain the pre-fix orchestration-claiming sentence).
function tiWorkflowStatusLine(workflow) {
  const investigation = workflow?.stages?.find((stage) => stage.key === "investigation");
  if (!investigation) return "";
  return _INVESTIGATION_STATE_LINES[investigation.state] || "";
}

function tiSummaryCard(result, workflow) {
  const rows = [
    ["Risk level", result.enrichment_risk_level ? severityBadge(result.enrichment_risk_level) : tiDash()],
    ["Risk score", tiText(result.enrichment_risk_score)],
    ["Last enriched", (result.generated_at || result.created_at) ? escapeHTML(formatDate(result.generated_at || result.created_at)) : tiDash()],
  ];
  const table = `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
  const summaryPara = result.summary ? `<p class="notice">${escapeHTML(result.summary)}</p>` : "";
  const aiPara = result.ai_summary
    ? `<p class="notice">${escapeHTML(result.ai_summary)}<br><small style="opacity:0.75">AI-generated summary${result.ai_summary_model ? ` · ${escapeHTML(result.ai_summary_model)}` : ""}</small></p>`
    : "";
  // Labelled explicitly as a Threat Intelligence recommendation (not "Next
  // step"/"Workflow") so it can never be misread as an orchestration
  // decision — see tiWorkflowStatusLine() above for the actual live
  // workflow-state line, sourced independently from the Investigation
  // stage's own state.
  const recommendation = result.recommended_next_action
    ? `<p class="notice"><strong>Threat Intelligence recommendation:</strong> ${escapeHTML(result.recommended_next_action)}</p>`
    : "";
  const workflowLine = tiWorkflowStatusLine(workflow);
  const workflowPara = workflowLine ? `<p class="notice"><strong>Workflow:</strong> ${escapeHTML(workflowLine)}</p>` : "";
  return table + summaryPara + aiPara + recommendation + workflowPara;
}

// Mirrors agents/reporting/triage_ticket_editing.py::_threat_intel_blocks()'s
// Extracted IOCs table field-for-field (same source: threat_intelligence.iocs)
// so the live workspace view and the generated ticket/report document never
// disagree on what was extracted. possible_file_name is a single string on
// the current contract (ThreatIntelIOCs.possible_file_name: str | None) —
// rendered as plain text, not as a reconstructed list.
function tiIOCsCard(iocs) {
  if (!iocs || !Object.keys(iocs).length) return emptyState("No IOC extraction data is available for this run.");
  const rows = [
    ["Possible file name", iocs.possible_file_name ? escapeHTML(iocs.possible_file_name) : tiDash()],
    ["File hash", iocs.file_hash ? `<span class="mono">${escapeHTML(iocs.file_hash)}</span>` : tiDash()],
    ["Public IP indicators", tiJoined(iocs.ip_indicators)],
    ["Domain indicators", tiJoined(iocs.domain_indicators)],
    ["URL indicators", tiJoined(iocs.url_indicators)],
    ["PowerShell enrichment", iocs.powershell_enrichment_note ? escapeHTML(iocs.powershell_enrichment_note) : tiDash()],
  ];
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
}

// powershell_analysis (agents/parsing/powershell_decoder.py's real output,
// passed through threat_intel.py's extract_iocs() unchanged) — rendered as
// a compact field table, never as a raw nested JSON dump. When the decoder
// found no encoded command at all, this degrades to a one-line empty state
// instead of a table of all-empty fields.
function tiPowerShellCard(psa) {
  if (!psa || typeof psa !== "object" || !Object.keys(psa).length) return "";
  const hasActivity = Boolean(psa.encoded_command_present || psa.powershell_indicator_present)
    || Boolean(psa.decode_status && !["not_present", "not_found"].includes(psa.decode_status));
  if (!hasActivity) {
    return `<article class="panel"><h3>PowerShell Analysis</h3>${emptyState(psa.decoded_command_summary || "No PowerShell activity was detected for this alert.")}</article>`;
  }
  const risk = psa.risk_assessment || {};
  const extracted = psa.extracted_iocs || {};
  const rows = [
    ["Decode status", psa.decode_status ? escapeHTML(psa.decode_status) : tiDash()],
    ["Encoded command detected", psa.encoded_command_present ? "Yes" : "No"],
    ["Encoded command count", tiText(psa.encoded_command_count)],
    ["Decoded command count", tiText(psa.decoded_command_count)],
    ["PowerShell risk level", risk.risk_level ? severityBadge(risk.risk_level) : tiDash()],
    ["PowerShell risk score", tiText(risk.risk_score)],
    ["Extracted URLs", tiJoined(extracted.urls)],
    ["Extracted domains", tiJoined(extracted.domains)],
    ["Extracted public IPs", tiJoined(extracted.public_ips)],
    ["Extracted hashes", tiJoined(extracted.hashes)],
    ["Extracted file paths", tiJoined(extracted.file_paths)],
    ["Extracted file names", tiJoined(extracted.file_names)],
  ];
  const table = `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`;
  const summary = psa.decoded_command_summary ? `<p class="notice">${escapeHTML(psa.decoded_command_summary)}</p>` : "";
  return `<article class="panel"><h3>PowerShell Analysis</h3>${table}${summary}</article>`;
}

// Columns mirror _threat_intel_blocks()'s VirusTotal table (Type/Indicator/
// Status/Malicious/Suspicious/Reputation) plus a visible status detail —
// file_hash is always present as a dict (real result or an explicit
// {"status":"skipped",...}), so a "skipped" row is expected, not a bug.
function tiVirusTotalCard(vt, iocs) {
  const rows = [];
  const fileHash = vt?.file_hash;
  if (fileHash && typeof fileHash === "object") {
    rows.push([tiText("File hash"), tiText(fileHash.indicator || iocs?.file_hash), providerStatusCell(fileHash), tiText(fileHash.malicious), tiText(fileHash.suspicious), tiText(fileHash.reputation)]);
  }
  for (const r of vt?.ip_results || []) rows.push([tiText("IP"), tiText(r.indicator), providerStatusCell(r), tiText(r.malicious), tiText(r.suspicious), tiText(r.reputation)]);
  for (const r of vt?.domain_results || []) rows.push([tiText("Domain"), tiText(r.indicator), providerStatusCell(r), tiText(r.malicious), tiText(r.suspicious), tiText(r.reputation)]);
  if (!rows.length) return emptyState("No VirusTotal lookups were performed for this run.");
  const body = rows.map(([type, indicator, status, malicious, suspicious, reputation]) => `<tr><td>${type}</td><td class="mono">${indicator}</td><td>${status}</td><td>${malicious}</td><td>${suspicious}</td><td>${reputation}</td></tr>`).join("");
  return tiTable(["Type", "Indicator", "Status", "Malicious", "Suspicious", "Reputation"], [body]);
}

function tiAbuseIPDBCard(abuse, iocs) {
  const rows = abuse?.ip_results || [];
  if (!rows.length) {
    return emptyState((iocs?.ip_indicators || []).length
      ? "AbuseIPDB did not return a result for the extracted IP indicator(s)."
      : "No AbuseIPDB results for this run — no usable public IP indicator was extracted.");
  }
  const body = rows.map((r) => `<tr><td class="mono">${tiText(r.indicator)}</td><td>${providerStatusCell(r)}</td><td>${tiText(r.abuse_confidence_score)}</td><td>${tiText(r.total_reports)}</td><td>${tiText(r.country_code)}</td><td>${tiText(r.isp)}</td><td>${tiText(r.usage_type)}</td><td>${r.last_reported_at ? escapeHTML(formatDate(r.last_reported_at)) : tiDash()}</td></tr>`).join("");
  return tiTable(["IP", "Status", "Abuse confidence", "Total reports", "Country", "ISP", "Usage type", "Last reported"], [body]);
}

function tiOTXCard(otx, iocs) {
  const rows = otx?.otx_results || [];
  if (!rows.length) {
    const hasIndicator = Boolean(iocs?.file_hash) || (iocs?.ip_indicators || []).length || (iocs?.domain_indicators || []).length;
    return emptyState(hasIndicator
      ? "AlienVault OTX did not return a result for the extracted indicator(s)."
      : "No AlienVault OTX results for this run — no usable indicator was extracted.");
  }
  const body = rows.map((r) => `<tr><td class="mono">${tiText(r.indicator)}</td><td>${tiText(r.indicator_type)}</td><td>${providerStatusCell(r)}</td><td>${tiText(r.pulse_count)}</td><td>${tiJoined(r.related_pulses)}</td><td>${tiJoined(r.sections_available)}</td></tr>`).join("");
  return tiTable(["Indicator", "Type", "Status", "Pulse count", "Related pulses", "Available sections"], [body]);
}

// enrichment_risk_reasons is already a list of finished, human-readable
// sentences produced by threat_intel.py::calculate_enrichment_risk() — this
// only renders them as bullets, it never re-derives a score from provider
// fields.
function tiRiskAssessmentCard(result) {
  const level = result.enrichment_risk_level;
  const score = result.enrichment_risk_score;
  const reasons = (Array.isArray(result.enrichment_risk_reasons) ? result.enrichment_risk_reasons : []).filter((r) => String(r || "").trim());
  const heading = level ? `${escapeHTML(level)} risk (score ${score != null ? escapeHTML(String(score)) : "—"})` : "Risk not assessed";
  const list = reasons.length
    ? `<ul class="data-list">${reasons.map((r) => `<li><div>${escapeHTML(r)}</div></li>`).join("")}</ul>`
    : emptyState("No risk reasons were recorded for this run.");
  return `<article class="panel"><h3>Risk Assessment</h3><p><strong>${heading}</strong></p>${list}</article>`;
}

// notes (informational — why a lookup was skipped, PowerShell handling,
// etc.) and warnings (missing API key / provider error only) are two
// distinct lists on the real result and are kept visually distinct here —
// warnings get their own notice-error treatment rather than being merged
// into the informational list.
function tiNotesCard(result) {
  const notes = (Array.isArray(result.notes) ? result.notes : []).filter((n) => String(n || "").trim());
  const warnings = (Array.isArray(result.warnings) ? result.warnings : []).filter((w) => String(w || "").trim());
  const notesBlock = notes.length
    ? `<ul class="data-list">${notes.map((n) => `<li><div>${escapeHTML(n)}</div></li>`).join("")}</ul>`
    : emptyState("No enrichment notes were recorded for this run.");
  const warningsBlock = warnings.length
    ? `<div class="notice notice-error" style="margin-top:0.75rem"><strong>Warnings</strong><ul class="data-list">${warnings.map((w) => `<li><div>${escapeHTML(w)}</div></li>`).join("")}</ul></div>`
    : "";
  return `<article class="panel"><h3>Notes</h3>${notesBlock}${warningsBlock}</article>`;
}

function renderThreatIntelStage(root, stage, caseId, lastError, onAction, workflow) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>VirusTotal, AbuseIPDB, and AlienVault OTX enrichment for the extracted IOCs, with the resulting case-level risk verdict.</p></div>${stateBadge(stage)}</div>`;
  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      ${loadingState("Querying VirusTotal · AbuseIPDB · AlienVault OTX…")}
      <div id="action-status" aria-live="polite"></div>
    `;
    root.querySelectorAll("[data-workflow-action]").forEach((button) => {
      button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
    });
    return;
  }

  const result = stage.result || {};
  const block = result.threat_intelligence || {};
  const hasResult = Boolean(result.threat_intelligence);

  if (!hasResult) {
    root.innerHTML = `
      ${header}
      ${stage.state === "failed"
        ? `<div class="state-panel error"><div>${escapeHTML(lastError || "Threat Intelligence enrichment failed for this run.")}</div></div>`
        : emptyState("No persisted Threat Intelligence output is available for this run yet.")}
      ${tiActionButtons(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
  } else {
    const iocs = block.iocs || {};
    const psaHTML = tiPowerShellCard(iocs.powershell_analysis);
    root.innerHTML = `
      ${header}
      <div id="action-status" aria-live="polite"></div>
      <section class="panel"><h3>Summary</h3>${tiSummaryCard(result, workflow)}</section>
      <section class="panel" style="margin-top:1rem"><h3>Extracted IOCs</h3>${tiIOCsCard(iocs)}</section>
      ${psaHTML ? `<div style="margin-top:1rem">${psaHTML}</div>` : ""}
      <section class="panel" style="margin-top:1rem"><h3>VirusTotal</h3>${tiVirusTotalCard(block.virustotal, iocs)}</section>
      <section class="panel" style="margin-top:1rem"><h3>AbuseIPDB</h3>${tiAbuseIPDBCard(block.abuseipdb, iocs)}</section>
      <section class="panel" style="margin-top:1rem"><h3>AlienVault OTX</h3>${tiOTXCard(block.alienvault_otx, iocs)}</section>
      <div style="margin-top:1rem">${tiRiskAssessmentCard(result)}</div>
      <div style="margin-top:1rem">${tiNotesCard(result)}</div>
      ${tiActionButtons(stage)}
    `;
  }
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
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

function investigationOverviewTab(workspace) {
  const ctx = workspace?.overview?.case_context || {};
  if (!Object.keys(ctx).length) return emptyState("No case overview is available yet.");
  const verdict = ctx.unified_verdict || {};
  const rows = [
    provenanceRow("NetWitness Severity", ctx.netwitness_severity),
    provenanceRow("Triage Classification", ctx.triage_classification),
    provenanceRow("Host", ctx.host),
    provenanceRow("User", ctx.user),
    provenanceRow("NetWitness Status", ctx.netwitness_status),
    provenanceRow("Workflow Status", ctx.workflow_status),
    provenanceRow("IOC IP Count", ctx.ioc_ip_count),
  ].join("");
  const verdictBlock = verdict.value
    ? `<div class="table-wrap case-context-table-wrap" style="margin-top:1rem"><h3>Unified Verdict</h3><p>${severityBadge(verdict.value)} <span class="mono">${escapeHTML((verdict.source_stages || []).join(", "))}</span></p>${(verdict.reasons || []).length ? `<ul class="data-list">${verdict.reasons.map((r) => `<li>${escapeHTML(r)}</li>`).join("")}</ul>` : ""}</div>`
    : "";
  return `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows}</tbody></table></div>${verdictBlock}`;
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
  const typeTone = { security: "state-in_progress", warning: "state-failed", workflow: "state-completed", info: "state-locked" };
  const rows = items.map((it) => `<tr><td class="mono">${escapeHTML(it.timestamp || "—")}</td><td>${escapeHTML(it.event)}</td><td>${badge(it.event_type, typeTone[it.event_type] || "")}</td><td class="mono">${escapeHTML(it.source_stage || "")}</td></tr>`).join("");
  return `<div class="table-wrap"><table class="case-context-table"><thead><tr><th>Timestamp</th><th>Event</th><th>Type</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table></div>`;
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
// re-mounting the same graph reproduces the same layout).

const _ENTITY_TYPE_META = {
  incident: { color: "#76b7ff", name: "Incident" },
  host: { color: "#ff7382", name: "Host" },
  user: { color: "#5ec8ff", name: "User" },
  ip: { color: "#b9a3ff", name: "IP Address" },
  domain: { color: "#efba5a", name: "Domain / URL" },
  process: { color: "#45d49a", name: "Process" },
  file: { color: "#f2c879", name: "File" },
  hash: { color: "#9b8dff", name: "Hash" },
  mitre: { color: "#ff8fc7", name: "MITRE ATT&CK" },
  entity: { color: "#92a3ba", name: "Entity" },
};
function _entityMeta(type) { return _ENTITY_TYPE_META[type] || _ENTITY_TYPE_META.entity; }
function _entityMonogram(type) { return (type || "??").slice(0, 2).toUpperCase(); }

const _GRAPH_W = 960;
const _GRAPH_H = 560;
const SVG_NS = "http://www.w3.org/2000/svg";

function _svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") el.setAttribute(k, v); });
  return el;
}

function _computeGraphLayout(nodes, edges) {
  const pos = new Map();
  const n = nodes.length;
  if (!n) return pos;
  const cx = _GRAPH_W / 2, cy = _GRAPH_H / 2;
  const r0 = Math.min(_GRAPH_W, _GRAPH_H) / 2 - 70;
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n;
    pos.set(node.id, { x: cx + r0 * Math.cos(angle), y: cy + r0 * Math.sin(angle) });
  });
  if (n < 2) return pos;
  const k = Math.sqrt((_GRAPH_W * _GRAPH_H) / n) * 0.85;
  const iterations = n > 260 ? 40 : n > 100 ? 90 : 220;
  let temp = _GRAPH_W / 10;
  const cooling = temp / iterations;
  const disp = new Map();
  for (let iter = 0; iter < iterations; iter += 1) {
    nodes.forEach((v) => disp.set(v.id, { x: 0, y: 0 }));
    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        const pv = pos.get(nodes[i].id), pu = pos.get(nodes[j].id);
        const dx = pv.x - pu.x, dy = pv.y - pu.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const force = (k * k) / dist;
        const ux = dx / dist, uy = dy / dist;
        const dv = disp.get(nodes[i].id), du = disp.get(nodes[j].id);
        dv.x += ux * force; dv.y += uy * force;
        du.x -= ux * force; du.y -= uy * force;
      }
    }
    edges.forEach((e) => {
      const pv = pos.get(e.src), pu = pos.get(e.dst);
      if (!pv || !pu || e.src === e.dst) return;
      const dx = pv.x - pu.x, dy = pv.y - pu.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = (dist * dist) / k;
      const ux = dx / dist, uy = dy / dist;
      const dv = disp.get(e.src), du = disp.get(e.dst);
      dv.x -= ux * force; dv.y -= uy * force;
      du.x += ux * force; du.y += uy * force;
    });
    nodes.forEach((v) => {
      const d = disp.get(v.id);
      const dist = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01;
      const p = pos.get(v.id);
      p.x += (d.x / dist) * Math.min(dist, temp);
      p.y += (d.y / dist) * Math.min(dist, temp);
      p.x += (cx - p.x) * 0.006;
      p.y += (cy - p.y) * 0.006;
      const margin = 50;
      p.x = Math.min(_GRAPH_W - margin, Math.max(margin, p.x));
      p.y = Math.min(_GRAPH_H - margin, Math.max(margin, p.y));
    });
    temp = Math.max(temp - cooling, 0.5);
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
  const stats = graph.stats || {};
  const typeCounts = Object.entries(stats.node_counts || {})
    .filter(([t]) => t !== "incident")
    .map(([t, c]) => `${escapeHTML(_entityMeta(t).name)}: ${c}`).join(" · ");
  const caption = `<p class="mono entity-graph-caption">${edges.length} relationships${typeCounts ? ` · ${typeCounts}` : ""}${stats.evidence_basis ? ` · basis: ${escapeHTML(stats.evidence_basis)}` : ""}</p>`;
  const warning = graph.data_availability_warning ? `<p class="notice">${escapeHTML(graph.data_availability_warning)}</p>` : "";
  return `<div class="entity-graph-wrap" id="entity-graph-wrap">
    <div class="entity-graph-toolbar">
      <input type="search" id="entity-graph-search" class="entity-graph-search-input" placeholder="Search entities…" aria-label="Search entities">
      <div class="entity-graph-toolbar-actions">
        <button type="button" class="action-button" id="entity-graph-fit">Reset View</button>
        <button type="button" class="action-button" id="entity-graph-fullscreen" title="Fullscreen">⤢</button>
      </div>
    </div>
    ${warning}${caption}
    <div class="entity-graph-body">
      <div class="entity-graph-canvas-wrap"><div class="entity-graph-canvas" id="entity-graph-canvas"></div></div>
      <aside class="entity-graph-details panel" id="entity-graph-details"><h3>Entity Details</h3><p class="notice">Select a node to view its details.</p></aside>
    </div>
    <div class="entity-graph-legend" id="entity-graph-legend"></div>
  </div>`;
}

function mountEntityGraph(container, workspace) {
  const graph = workspace?.entity_graph || {};
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const wrap = container.querySelector("#entity-graph-wrap");
  const canvasHost = container.querySelector("#entity-graph-canvas");
  const detailsHost = container.querySelector("#entity-graph-details");
  const legendHost = container.querySelector("#entity-graph-legend");
  const searchInput = container.querySelector("#entity-graph-search");
  const fitButton = container.querySelector("#entity-graph-fit");
  const fullscreenButton = container.querySelector("#entity-graph-fullscreen");
  if (!canvasHost || !nodes.length) return;

  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const pos = _computeGraphLayout(nodes, edges);

  const svg = _svgEl("svg", { viewBox: `0 0 ${_GRAPH_W} ${_GRAPH_H}`, class: "entity-graph-svg", role: "img", "aria-label": "Entity relationship graph" });
  const defs = _svgEl("defs");
  const marker = _svgEl("marker", { id: "entity-graph-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
  marker.appendChild(_svgEl("path", { d: "M0,0 L10,5 L0,10 z", fill: "#5b7a8f" }));
  defs.appendChild(marker);
  svg.appendChild(defs);
  const viewport = _svgEl("g", { class: "entity-graph-viewport" });
  const edgeLayer = _svgEl("g", { class: "entity-graph-edges" });
  const nodeLayer = _svgEl("g", { class: "entity-graph-nodes" });
  viewport.appendChild(edgeLayer);
  viewport.appendChild(nodeLayer);
  svg.appendChild(viewport);

  const edgeGroups = [];
  edges.forEach((e) => {
    const pv = pos.get(e.src), pu = pos.get(e.dst);
    if (!pv || !pu) return;
    const g = _svgEl("g", { class: "entity-graph-edge", "data-src": e.src, "data-dst": e.dst });
    g.appendChild(_svgEl("line", {
      x1: pv.x, y1: pv.y, x2: pu.x, y2: pu.y,
      stroke: e.evidence_status === "co_occurrence_only" ? "#5b6b7a" : "#5b7a8f",
      "stroke-width": 1.4,
      "stroke-dasharray": e.evidence_status === "co_occurrence_only" ? "4 3" : "",
      "marker-end": "url(#entity-graph-arrow)",
    }));
    const label = (e.relation || "").replaceAll("_", " ");
    if (label) {
      const text = _svgEl("text", { x: (pv.x + pu.x) / 2, y: (pv.y + pu.y) / 2, class: "entity-graph-edge-label", "text-anchor": "middle" });
      text.textContent = label;
      g.appendChild(text);
    }
    const title = _svgEl("title");
    title.textContent = `${e.relation}${(e.evidence || []).length ? ` — evidence: ${e.evidence.join(", ")}` : ""}`;
    g.appendChild(title);
    edgeLayer.appendChild(g);
    edgeGroups.push(g);
  });

  const nodeGroups = new Map();
  nodes.forEach((n) => {
    const p = pos.get(n.id);
    if (!p) return;
    const meta = _entityMeta(n.type);
    const radius = n.type === "incident" ? 26 : 22;
    const g = _svgEl("g", { class: "entity-graph-node", "data-id": n.id, transform: `translate(${p.x},${p.y})`, tabindex: "0", role: "button" });
    g.appendChild(_svgEl("circle", { r: radius, fill: "#0b1422", stroke: meta.color, "stroke-width": 2.5 }));
    const mono = _svgEl("text", { class: "entity-graph-node-icon", fill: meta.color, "text-anchor": "middle", dy: "0.32em" });
    mono.textContent = _entityMonogram(n.type);
    g.appendChild(mono);
    const label = _svgEl("text", { class: "entity-graph-node-label", y: radius + 14, "text-anchor": "middle" });
    label.textContent = n.label && n.label.length > 22 ? `${n.label.slice(0, 21)}…` : (n.label || "");
    g.appendChild(label);
    const title = _svgEl("title");
    title.textContent = `${n.label} (${n.type})`;
    g.appendChild(title);
    nodeLayer.appendChild(g);
    nodeGroups.set(n.id, g);
  });

  canvasHost.innerHTML = "";
  canvasHost.appendChild(svg);

  // Edge label backgrounds need real layout metrics (getBBox), so they're
  // added only once the <svg> is attached to the document.
  edgeLayer.querySelectorAll("text.entity-graph-edge-label").forEach((text) => {
    try {
      const bbox = text.getBBox();
      const rect = _svgEl("rect", { x: bbox.x - 3, y: bbox.y - 1, width: bbox.width + 6, height: bbox.height + 2, class: "entity-graph-edge-label-bg" });
      text.parentNode.insertBefore(rect, text);
    } catch { /* getBBox can throw on a hidden tab in some browsers; label just renders without a backing rect */ }
  });

  // Pan (drag background) and zoom (wheel), scoped to this <svg> via
  // pointer capture so listeners are discarded with the element on remount
  // instead of accumulating on `window`.
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
    scale = Math.min(2.5, Math.max(0.4, scale * (event.deltaY > 0 ? 0.9 : 1.1)));
    applyTransform();
  }, { passive: false });

  function renderDetails(node) {
    if (!node) {
      detailsHost.innerHTML = `<h3>Entity Details</h3><p class="notice">Select a node to view its details.</p>`;
      return;
    }
    const props = node.props || {};
    const propRows = Object.entries(props).map(([k, v]) => `<tr><th scope="row">${escapeHTML(k.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase()))}</th><td>${escapeHTML(String(v))}</td></tr>`).join("");
    const neighbors = _neighborsOf(node.id, edges);
    const related = neighbors.map(({ id, dir, edge }) => {
      const other = nodeById.get(id);
      if (!other) return "";
      const arrow = dir === "out" ? "→" : "←";
      return `<li><button type="button" class="entity-graph-related-link" data-id="${escapeHTML(id)}"><span class="entity-graph-mini-icon" style="color:${_entityMeta(other.type).color}">${_entityMonogram(other.type)}</span><span>${escapeHTML(other.label)}</span></button><p class="mono">${arrow} ${escapeHTML((edge.relation || "").replaceAll("_", " "))}${edge.evidence_status ? ` · ${escapeHTML(edge.evidence_status)}` : ""}</p></li>`;
    }).join("");
    detailsHost.innerHTML = `
      <div class="entity-graph-details-header">
        <span class="entity-graph-mini-icon" style="color:${_entityMeta(node.type).color}">${_entityMonogram(node.type)}</span>
        <div><strong>${escapeHTML(node.label)}</strong><p class="mono">${escapeHTML(node.type)}</p></div>
      </div>
      <div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>
        <tr><th scope="row">Entity Type</th><td>${escapeHTML(_entityMeta(node.type).name)}</td></tr>
        <tr><th scope="row">Connections</th><td>${neighbors.length}</td></tr>
        ${propRows}
      </tbody></table></div>
      <h3 style="margin-top:1rem">Related Entities (${neighbors.length})</h3>
      <ul class="data-list entity-graph-related-list">${related || `<li>${emptyState("No related entities.")}</li>`}</ul>`;
    detailsHost.querySelectorAll(".entity-graph-related-link").forEach((btn) => {
      btn.addEventListener("click", () => selectNode(btn.dataset.id));
    });
  }

  let selectedId = null;
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
  nodeGroups.forEach((g, id) => {
    g.addEventListener("click", () => selectNode(selectedId === id ? null : id));
    g.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(selectedId === id ? null : id); }
    });
  });

  // Default selection: the most-connected node (real degree, not a guess).
  const degree = new Map(nodes.map((n) => [n.id, 0]));
  edges.forEach((e) => {
    degree.set(e.src, (degree.get(e.src) || 0) + 1);
    degree.set(e.dst, (degree.get(e.dst) || 0) + 1);
  });
  const defaultNode = [...nodes].sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))[0] || null;
  selectNode(defaultNode ? defaultNode.id : null);

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      const q = searchInput.value.trim().toLowerCase();
      nodeGroups.forEach((g, id) => {
        const n = nodeById.get(id);
        g.classList.toggle("is-search-dimmed", Boolean(q) && !(n.label || "").toLowerCase().includes(q));
      });
    });
  }
  if (fitButton) {
    fitButton.addEventListener("click", () => {
      scale = 1; tx = 0; ty = 0; applyTransform();
      if (searchInput) searchInput.value = "";
      nodeGroups.forEach((g) => g.classList.remove("is-search-dimmed"));
      selectNode(defaultNode ? defaultNode.id : null);
    });
  }
  if (fullscreenButton && wrap) {
    fullscreenButton.addEventListener("click", () => {
      const isFull = wrap.classList.toggle("is-fullscreen");
      fullscreenButton.textContent = isFull ? "⤡" : "⤢";
      fullscreenButton.title = isFull ? "Exit fullscreen" : "Fullscreen";
    });
  }

  // Legend lists only the entity types actually present in this graph —
  // never the full type catalogue, so it never implies evidence that
  // wasn't derived for this case.
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
  ["mitre", "MITRE ATT&CK", investigationMitreTab],
  ["entity_graph", "Entity Graph", investigationEntityGraphTab, mountEntityGraph],
  ["evidence", "Evidence", investigationEvidenceTab],
  ["activity", "Activity", investigationActivityTab],
];

function renderInvestigationStage(root, stage, caseId, lastError, onAction, workspace) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2></div>${stateBadge(stage)}</div>${actionControls(stage)}<div id="action-status" aria-live="polite"></div>`;
  const nav = `<div class="subtab-bar" role="tablist">${_INVESTIGATION_SUBTABS.map(([key, label]) => `<button type="button" class="subtab-button" data-subtab="${key}" role="tab">${escapeHTML(label)}</button>`).join("")}</div>`;
  root.innerHTML = `${header}${nav}<div id="investigation-subtab-body"></div>`;
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
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

function renderSelectedStage(root, stage, caseId, lastError, onAction, onContinue, workflow, workspace) {
  if (stage.key === "parsing") {
    renderParsingStage(root, stage, caseId, lastError, onAction, onContinue);
    return;
  }
  if (stage.key === "triage") {
    renderTriageStage(root, stage, caseId, lastError, onAction);
    return;
  }
  if (stage.key === "threat_intel") {
    renderThreatIntelStage(root, stage, caseId, lastError, onAction, workflow);
    return;
  }
  if (stage.key === "investigation") {
    renderInvestigationStage(root, stage, caseId, lastError, onAction, workspace);
    return;
  }
  if (stage.key === "reporting") {
    renderReportingStage(root, stage, caseId, lastError, onAction);
    return;
  }
  root.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2></div>${stateBadge(stage)}</div>${actionControls(stage)}<div id="action-status" aria-live="polite"></div>${jsonPreview(stage.result)}`;
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
}

// Reporting stage card: same header/action-controls shape every other stage
// uses (name, stateBadge, Re-run/Approve/Reject), but with the four-report
// table (frontend/js/pages/reports.js —
// the SAME implementation the standalone Reporting page uses, embedded
// directly here) in place of a raw JSON dump. Raw Reporting JSON is still
// available, just as a secondary "Raw JSON" link inside that panel rather
// than the primary view. Approve is only enabled once a reviewed candidate
// has actually been materialised (Submit for Approval, inside the reports
// panel) — see workflow/commands.py::available_actions() — so this single
// Approve control is the one approval path; there is no second "confirm"
// button competing with it.
function renderReportingStage(root, stage, caseId, lastError, onAction) {
  root.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2></div>${stateBadge(stage)}</div>${actionControls(stage)}<div id="action-status" aria-live="polite"></div><div id="reporting-panel"></div>`;
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
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
      <section class="workspace-grid${KEY_FINDINGS_STAGES.has(selectedStageKey) ? "" : " stage-only"}" id="stage-workspace-grid"><article class="panel" id="key-findings-panel" ${KEY_FINDINGS_STAGES.has(selectedStageKey) ? "" : "hidden"}><h2>Key findings</h2>${findings(detail.workspace, selectedStageKey)}</article><article class="panel" id="stage-output"></article></section>`;
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
      workflowRoot.innerHTML = `<div class="page-header"><div><h2>Workflow</h2></div></div>${workflow.progress_note ? `<p class="notice">${escapeHTML(workflow.progress_note)}</p>` : ""}<div class="stage-grid">${stageCards(workflow.stages)}</div>`;
      const selected = workflow.stages.find((stage) => stage.key === selectedStageKey) || workflow.stages[0];
      selectedStageKey = selected.key;
      const showKeyFindings = KEY_FINDINGS_STAGES.has(selected.key);
      keyFindingsPanel.hidden = !showKeyFindings;
      stageWorkspaceGrid.classList.toggle("stage-only", !showKeyFindings);
      if (showKeyFindings) {
        keyFindingsPanel.innerHTML = `<h2>Key findings</h2>${findings(detail.workspace, selected.key)}`;
      }
      renderSelectedStage(outputRoot, selected, caseId, workflow.last_error, handleAction, (key) => {
        selectedStageKey = key;
        renderWorkflow();
      }, workflow, detail.workspace);
      workflowRoot.querySelectorAll("[data-stage]").forEach((button) => {
        button.classList.toggle("active", button.dataset.stage === selectedStageKey);
        button.addEventListener("click", () => {
          selectedStageKey = button.dataset.stage;
          renderWorkflow();
        });
      });
    };

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

    async function handleAction(action, stage) {
      if (!requiresConfirmation(action, stage)) return;
      const actionStatus = outputRoot.querySelector("#action-status");
      outputRoot.querySelectorAll("[data-workflow-action]").forEach((button) => { button.disabled = true; });
      try {
        const [path, body] = await actionRequest(caseId, action, stage);
        if (actionStatus) actionStatus.innerHTML = `<p class="notice"><span class="spinner"></span>Submitting ${escapeHTML(action)}…</p>`;
        const result = await fetchJSON(path, { method: "POST", body });
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
