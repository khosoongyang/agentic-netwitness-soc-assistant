import { fetchJSON } from "../api.js";
import { badge, emptyState, errorState, escapeHTML, formatDate, jsonPreview, loadingState, openModal, provenanceValue, severityBadge, stateBadge } from "../ui.js";

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

function findings(workspace) {
  const items = workspace?.overview?.key_findings || [];
  if (!items.length) return emptyState("No findings have been distilled for this case yet.");
  return `<ul class="data-list">${items.slice(0, 12).map((item) => `<li><div><strong>${escapeHTML(item.title || "Finding")}</strong><p>${escapeHTML(item.desc || "")}</p></div>${item.confidence ? `<span>${escapeHTML(item.confidence)}</span>` : ""}</li>`).join("")}</ul>`;
}

function actionControls(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  return `<div class="stage-actions" aria-label="${escapeHTML(stage.name)} actions">${actions.map((action) => `<button class="action-button ${action.type === "reject" ? "danger" : ""}" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(action.label)}</button>`).join("")}</div>`;
}

// Only fields that actually exist in the persisted parsing result are
// shown here — the live workflow (workflow/engine.py::run_until_triage_
// approval) persists status/parser_confidence/recommended_next_action/
// run_id/generated_at plus the ai_summary/-model/-generated_at trio into
// parsing_result_json. The rich structured normalised_alert is persisted
// alongside it but shown separately, in full, via the Normalised Alert
// JSON viewer below. Anything missing here is simply omitted rather than
// backfilled with a placeholder.
function parserSummaryRows(result) {
  const generatedAt = result.generated_at || result.ai_summary_generated_at;
  return [
    ["Status", result.status ? statusBadge(result.status) : null],
    ["Parser Confidence", result.parser_confidence ? confidenceBadge(result.parser_confidence) : null],
    ["Recommended Next Action", result.recommended_next_action ? escapeHTML(result.recommended_next_action) : null],
    ["Run ID", result.run_id ? `<span class="mono">${escapeHTML(result.run_id)}</span>` : null],
    ["Generated At", generatedAt ? escapeHTML(formatDate(generatedAt)) : null],
  ].filter(([, value]) => value);
}

function parserSummaryCard(result) {
  if (!result) return emptyState("No persisted output is available for this stage yet.");
  const rows = parserSummaryRows(result);
  const table = rows.length
    ? `<div class="table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div>`
    : emptyState("No parser summary fields are available for this stage yet.");
  const summaryText = result.ai_summary || result.summary;
  const caption = result.ai_summary_model
    ? `Generated by ${result.ai_summary_model}${result.ai_summary_generated_at ? ` · ${formatDate(result.ai_summary_generated_at)}` : ""}`
    : "";
  const summaryBlock = summaryText
    ? `<p class="notice" style="margin-top:0.9rem">${escapeHTML(summaryText)}${caption ? `<br><small style="opacity:0.75">${escapeHTML(caption)}</small>` : ""}</p>`
    : "";
  return table + summaryBlock;
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

function renderParsingStage(root, stage, caseId, lastError, onAction, onContinue) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>Transform raw NetWitness incident data into structured, analyst-ready context.</p></div>${stateBadge(stage)}</div>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      <p class="notice">Status: Running</p>
      ${loadingState("Parsing incident…")}
      <div id="action-status" aria-live="polite"></div>
    `;
  } else if (stage.state === "failed") {
    root.innerHTML = `
      ${header}
      <p class="notice">Status: Failed</p>
      <div class="state-panel error"><div>${escapeHTML(lastError || "Parsing failed for this run.")}</div></div>
      ${parsingActionControls(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
  } else if (stage.state === "completed") {
    const downloadButton = `<a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/stages/parsing/download">Download JSON</a>`;
    root.innerHTML = `
      ${header}
      <p class="notice">Status: Completed${stage.updated_at ? ` · Last updated ${formatDate(stage.updated_at)}` : ""}</p>
      <div id="action-status" aria-live="polite"></div>
      <section class="panel" style="margin-top:1rem"><h3>Parser Summary</h3>${parserSummaryCard(stage.result)}</section>
      <section class="panel" style="margin-top:1rem">
        <div class="panel-header-row"><h3>Normalised Alert</h3>${downloadButton}</div>
        ${jsonPreview(stage.result?.normalised_alert || stage.result)}
      </section>
      <div class="stage-actions" style="margin-top:1rem">${(stage.actions || []).map((action) => `<button class="action-button" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(_PARSING_ACTION_LABELS[action.type] || action.label)}</button>`).join("")}<button class="action-button" id="continue-to-triage">Continue to Triage</button></div>
    `;
  } else {
    // not_started
    root.innerHTML = `
      ${header}
      <p class="notice">Status: Not started</p>
      ${parsingActionControls(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
  }
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
  const continueButton = root.querySelector("#continue-to-triage");
  if (continueButton) continueButton.addEventListener("click", () => onContinue("triage"));
}

// Triage's canonical persisted shape (agents/triage/triage_result.py's
// TriageAgentSuccessOutput, served verbatim by GET /api/cases/<id>/workflow's
// stages[].result — see backend/services/case_service.py::_safe_stage_result,
// which only redacts/truncates, never renames or drops a field): { ticket,
// metakeys_payload, trace, used_parsed_context, cached, ai_summary,
// ai_thinking, ai_summary_model, ai_summary_generated_at }. `ticket` and its
// nested `risk_rating` are TriageTicket/TriageRiskRating's real fields — this
// renderer draws ONLY on those (plus the trace's own "IOC Checklist" step for
// the per-category confidentiality/integrity/availability breakdown), no
// value is invented or hard-coded. Triage never produces a "confidence"
// field, unlike Investigation, so none is shown here.
const _TRIAGE_ACTION_LABELS = { start: "Run Triage", rerun: "Re-run Triage", approve: "Approve & Continue", reject: "Reject Triage" };

function triageActionButtons(stage) {
  const actions = stage.actions || [];
  if (!actions.length) return "";
  return `<div class="stage-actions" style="margin-top:1rem" aria-label="${escapeHTML(stage.name)} actions">${actions.map((action) => `<button class="action-button ${action.type === "reject" ? "danger" : ""}" data-workflow-action="${escapeHTML(action.type)}" ${action.enabled ? "" : "disabled"} title="${escapeHTML(action.reason || action.label)}">${escapeHTML(_TRIAGE_ACTION_LABELS[action.type] || action.label)}</button>`).join("")}</div>`;
}

function triageTraceStep(result, stepName) {
  return (result?.trace || []).find((step) => step && step.step === stepName) || null;
}

function triageClassificationCard(ticket) {
  const rows = [
    ["Classification", ticket.classification ? severityBadge(ticket.classification) : pendingValue("Not classified")],
    ["Category", escapeHTML(ticket.incident_category || "—")],
    ["MITRE Tactic", escapeHTML(ticket.mitre_tactic || "Unknown")],
    ["MITRE Technique", escapeHTML(ticket.mitre_technique || "Unknown")],
    ["Initial Response Time", escapeHTML(ticket.initial_response_time || "—")],
  ];
  return `<section class="panel"><h3>SOC Classification</h3><div class="table-wrap case-context-table-wrap"><table class="case-context-table"><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value}</td></tr>`).join("")}</tbody></table></div></section>`;
}

function triageIOCCard(iocStep, ticket) {
  const count = ticket.matched_ioc_count ?? iocStep?.total_ioc_count ?? 0;
  const summary = iocStep?.ioc_summary || "";
  // Array.isArray guards, not just a truthy/length check: a persisted
  // result the backend sanitizer has redacted-to-string (or any other
  // unexpected shape) must degrade to an empty list here rather than throw
  // on .map() below and blank the whole stage.
  const ticketKeys = Array.isArray(ticket.metakeys) ? ticket.metakeys : [];
  const traceKeys = Array.isArray(iocStep?.matched_metakeys) ? iocStep.matched_metakeys : [];
  const mkeys = ticketKeys.length ? ticketKeys : traceKeys;
  const categories = iocStep?.per_category && typeof iocStep.per_category === "object" ? iocStep.per_category : {};
  const catItems = Object.entries(categories)
    .map(([name, data]) => {
      const names = Array.isArray(data?.matched_ioc_names) ? data.matched_ioc_names : [];
      if (!names.length) return "";
      const label = name.charAt(0).toUpperCase() + name.slice(1);
      const reasoning = data.reasoning ? ` — ${escapeHTML(data.reasoning)}` : "";
      return `<li><div><strong>${escapeHTML(label)}:</strong> ${escapeHTML(names.join(", "))}${reasoning}</div></li>`;
    })
    .filter(Boolean)
    .join("");
  return `<article class="panel">
    <h3>IOC Checklist</h3>
    <p><strong>IOCs matched:</strong> ${escapeHTML(String(count))}</p>
    ${summary ? `<p>${escapeHTML(summary)}</p>` : ""}
    ${catItems ? `<ul class="data-list">${catItems}</ul>` : emptyState("No category-level IOC findings were recorded for this run.")}
    ${mkeys.length ? `<p class="mono" style="margin-top:0.6rem;opacity:0.75">${mkeys.map((key) => escapeHTML(key)).join(" · ")}</p>` : ""}
  </article>`;
}

function triageRiskCard(ticket) {
  const rr = ticket.risk_rating || {};
  const rows = [
    ["Initiation", rr.likelihood_initiation],
    ["Occurrence", rr.likelihood_occurrence],
    ["Adverse Impact", rr.likelihood_adverse_impact],
    ["Overall", rr.overall_risk],
  ];
  return `<article class="panel">
    <h3>Risk Rating</h3>
    <div class="table-wrap case-context-table-wrap"><table class="case-context-table"><thead><tr><th>Dimension</th><th>Rating</th></tr></thead><tbody>${rows.map(([label, value]) => `<tr><th scope="row">${escapeHTML(label)}</th><td>${value ? severityBadge(value) : pendingValue("—")}</td></tr>`).join("")}</tbody></table></div>
    ${rr.rationale ? `<p class="notice" style="margin-top:0.6rem">${escapeHTML(rr.rationale)}</p>` : ""}
  </article>`;
}

function triageSummaryCard(ticket, result) {
  const parts = [];
  if (ticket.summary) parts.push(`<p>${escapeHTML(ticket.summary)}</p>`);
  if (result.ai_summary) parts.push(`<p class="notice">${escapeHTML(result.ai_summary)}<br><small style="opacity:0.75">AI-generated summary${result.ai_summary_model ? ` · ${escapeHTML(result.ai_summary_model)}` : ""}</small></p>`);
  if (!parts.length) return "";
  return `<section class="panel" style="margin-top:1rem"><h3>Triage Summary</h3>${parts.join("")}</section>`;
}

function triageMitreCard(ticket) {
  if (!ticket.mitre_tactic && !ticket.mitre_technique) return "";
  return `<section class="panel" style="margin-top:1rem"><h3>MITRE ATT&amp;CK</h3><p>${escapeHTML(ticket.mitre_tactic || "Unknown")} · ${escapeHTML(ticket.mitre_technique || "Unknown")}</p></section>`;
}

function triageActionsListCard(ticket) {
  const actions = Array.isArray(ticket.recommended_actions) ? ticket.recommended_actions : [];
  if (!actions.length) return "";
  return `<section class="panel" style="margin-top:1rem"><h3>Recommended Actions</h3><ul class="data-list">${actions.map((action) => `<li><div>${escapeHTML(action)}</div></li>`).join("")}</ul></section>`;
}

function renderTriageStage(root, stage, caseId, lastError, onAction) {
  const header = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>IOC checklist, risk rating, and SOC classification for this incident.</p></div>${stateBadge(stage)}</div>`;
  const statusLine = `<p class="notice">Status: ${escapeHTML(stage.status_text || stage.status)}${stage.updated_at ? ` · Last updated ${formatDate(stage.updated_at)}` : ""}</p>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      ${statusLine}
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
      ${statusLine}
      ${stage.state === "failed"
        ? `<div class="state-panel error"><div>${escapeHTML(lastError || "Triage failed for this run.")}</div></div>`
        : emptyState("No persisted Triage output is available for this run yet.")}
      ${triageActionButtons(stage)}
      <div id="action-status" aria-live="polite"></div>
    `;
  } else {
    const iocStep = triageTraceStep(result, "IOC Checklist");
    root.innerHTML = `
      ${header}
      ${statusLine}
      <div id="action-status" aria-live="polite"></div>
      ${triageClassificationCard(ticket)}
      <div class="integration-grid">${triageIOCCard(iocStep, ticket)}${triageRiskCard(ticket)}</div>
      ${triageSummaryCard(ticket, result)}
      ${triageMitreCard(ticket)}
      ${triageActionsListCard(ticket)}
      ${triageActionButtons(stage)}
    `;
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
  const statusLine = `<p class="notice">Status: ${escapeHTML(stage.status_text || stage.status)}${stage.updated_at ? ` · Last updated ${formatDate(stage.updated_at)}` : ""}</p>`;

  if (stage.state === "in_progress") {
    root.innerHTML = `
      ${header}
      ${statusLine}
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
      ${statusLine}
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
      ${statusLine}
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

function renderSelectedStage(root, stage, caseId, lastError, onAction, onContinue, workflow) {
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
  root.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(stage.name)}</h2><p>Persisted output · ${escapeHTML(stage.status_text)}${stage.attempt ? ` · attempt ${stage.attempt}` : ""}</p></div>${stateBadge(stage)}</div>${stage.updated_at ? `<p class="notice">Last updated ${formatDate(stage.updated_at)}</p>` : ""}${actionControls(stage)}<div id="action-status" aria-live="polite"></div>${jsonPreview(stage.result)}`;
  root.querySelectorAll("[data-workflow-action]").forEach((button) => {
    button.addEventListener("click", () => onAction(button.dataset.workflowAction, stage));
  });
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
    const detail = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}`);
    let workflow = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/workflow`);
    let selectedStageKey = workflow.stages.find((stage) => stage.name === workflow.current_stage)?.key || workflow.stages[0]?.key;
    root.innerHTML = `
      <section class="page-header"><div><p class="mono">${escapeHTML(detail.case.id)}</p><h1>${escapeHTML(detail.case.title)}</h1><p>${escapeHTML(detail.case.status)} · ${escapeHTML(detail.case.assignee)}</p></div><div class="stage-actions" style="margin:0"><button class="action-button" id="open-reports">Review reports &amp; triage ticket</button><button class="action-button" id="load-raw">View Raw Incident JSON</button></div></section>
      <section class="panel"><h2>Case context</h2>${caseContext(detail)}</section>
      <section class="panel" id="workflow-panel" style="margin-top:1rem"></section>
      <section class="workspace-grid${selectedStageKey === "parsing" ? " stage-only" : ""}" id="stage-workspace-grid"><article class="panel" id="key-findings-panel" ${selectedStageKey === "parsing" ? "hidden" : ""}><h2>Key findings</h2>${findings(detail.workspace)}</article><article class="panel" id="stage-output"></article></section>`;
    root.querySelector("#open-reports").addEventListener("click", () => navigate("reports", { case: caseId }));
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
    const outputRoot = root.querySelector("#stage-output");

    const renderWorkflow = () => {
      workflowRoot.innerHTML = `<div class="page-header"><div><h2>Workflow</h2><p>${escapeHTML(workflow.workflow_status)} · run ${escapeHTML(workflow.run_id || "not started")}</p></div></div>${workflow.progress_note ? `<p class="notice">${escapeHTML(workflow.progress_note)}</p>` : ""}<div class="stage-grid">${stageCards(workflow.stages)}</div>`;
      const selected = workflow.stages.find((stage) => stage.key === selectedStageKey) || workflow.stages[0];
      selectedStageKey = selected.key;
      const isParsingStage = selected.key === "parsing";
      keyFindingsPanel.hidden = isParsingStage;
      stageWorkspaceGrid.classList.toggle("stage-only", isParsingStage);
      renderSelectedStage(outputRoot, selected, caseId, workflow.last_error, handleAction, (key) => {
        selectedStageKey = key;
        renderWorkflow();
      }, workflow);
      workflowRoot.querySelectorAll("[data-stage]").forEach((button) => {
        button.classList.toggle("active", button.dataset.stage === selectedStageKey);
        button.addEventListener("click", () => {
          selectedStageKey = button.dataset.stage;
          renderWorkflow();
        });
      });
    };

    const refreshWorkflow = async () => {
      workflow = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/workflow`);
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
            if (statusRoot) statusRoot.innerHTML = `<p class="notice">${escapeHTML(run.stage || stage.name)} · ${escapeHTML(run.stage_status || run.status)}${run.progress?.note ? ` · ${escapeHTML(run.progress.note)}` : ""}</p>`;
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
