// =============================================================================
// [FYP-FILE] frontend/js/components/triageReview.js
// [FYP-TRIAGE-STEP3] X1 triage review screen + structured review form, and
// the X6 blind_first flow. Rendered by workspace.js::renderTriageStage()
// ABOVE the existing ticket view; workspace.js only wires it in.
//
// Method principles (docs/triage-review.md):
//   * Step 9 "document the verdict AND the evidence trail": the analyst must
//     tick >= 1 evidence item actually checked; the packet snapshot is stored
//     with the review server-side.
//   * FP != Benign-Expected: false_positive asks for a rule-tuning note,
//     benign_expected asks for who/when/why (+ optional scoped suppression).
//   * Automation bias: the disposition dropdown starts EMPTY (never the AI's
//     value); blind_first hides the AI verdict + hypotheses until the analyst
//     commits an initial disposition.
//   * Missing = unknown, not safe: the "Unknown != safe" banner.
//
// SECURITY: evidence values are attacker-controlled (command lines, file
// names, alert text). EVERY dynamic value goes through escapeHTML(); no
// markdown rendering; innerHTML is only ever given escaped template output.
// =============================================================================
import { escapeHTML } from "../ui.js";

export const DISPOSITIONS = ["true_positive", "false_positive", "benign_expected", "needs_info"];
export const DISPOSITION_LABELS = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign_expected: "Benign-expected",
  needs_info: "Needs-info",
};
const UNCERTAINTY_WORDS = { low: "Low", medium: "Medium", high: "High" };
const SECTION_LABELS = {
  detection: "Detection", entity: "Entity", data_quality: "Data quality", baseline: "Baseline",
  raw_alerts: "Raw alerts", rule_signals: "Rule signals", context: "Business context",
};
// Plain-language reasons for each guard rule (agents/triage/guards.py).
const GUARD_REASONS = {
  a_missing_mandatory_evidence: "mandatory evidence was missing",
  b_strong_signal_floor: "a strong malicious signal was present and not explained by context",
  c_benign_expected_requires_context: "benign-expected needs cited business context",
  d_false_positive_requires_rule_or_data_evidence: "a false positive needs cited detection or data-quality evidence",
  e_uncited_supporting_hypothesis: "the supporting hypothesis had no valid citation",
  schema_proposed_disposition: "the model did not propose a valid disposition",
};
const MAX_VALUE_CHARS = 400;

export function dispositionLabel(value) {
  return DISPOSITION_LABELS[value] || String(value || "Unknown");
}

function isLeaf(node) {
  return node && typeof node === "object" && "value" in node && "status" in node && "source" in node
    && Object.keys(node).length === 3;
}

export function iterLeaves(node, prefix = "") {
  const out = [];
  Object.entries(node || {}).forEach(([key, child]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (isLeaf(child)) out.push([path, child]);
    else if (child && typeof child === "object" && !Array.isArray(child)) out.push(...iterLeaves(child, path));
  });
  return out;
}

export function checklistSections(packet) {
  return Object.keys(packet || {}).filter((section) => iterLeaves(packet[section]).some(([, l]) => l.status === "measured"));
}

// Suppression scope defaults (mirrors agents/triage/suppression.scope_from_packet).
export function scopeFromPacket(packet) {
  const createdBy = val(packet, "detection.createdBy");
  const ruleId = val(packet, "detection.ruleId");
  let source = createdBy ? String(createdBy).trim() : "";
  if (source && ruleId) source = `${source} / ${String(ruleId).trim()}`;
  const entity = val(packet, "entity.value");
  return { detection_source: source, entity: entity ? String(entity).trim() : "" };
}

// Recorded reviews for this case (GET /api/cases/<id>/triage/reviews).
export function reviewHistoryHTML(reviews) {
  if (!reviews || !reviews.length) return "";
  const rows = reviews.map((r) => `<tr><td>${escapeHTML(r.decided_at || "")}</td><td>${escapeHTML(r.analyst || "")}</td><td>${escapeHTML(r.decision || "")}</td><td>AI: ${escapeHTML(dispositionLabel(r.ai_final_disposition))} → Analyst: <strong>${escapeHTML(dispositionLabel(r.analyst_disposition))}</strong></td><td>${escapeHTML(r.justification || "")}</td><td>${escapeHTML(r.review_mode || "")}${r.revised_after_ai_reveal ? " (revised after reveal)" : ""}</td><td>${escapeHTML(r.label_provenance || "analyst")}</td></tr>`).join("");
  return `<section class="panel triage-review-history"><h3>Recorded analyst reviews</h3><table class="data-table"><thead><tr><th>Decided</th><th>Analyst</th><th>Decision</th><th>Verdict</th><th>Justification</th><th>Mode</th><th>Label</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

function short(value) {
  let text = typeof value === "string" ? value : JSON.stringify(value);
  if (text === undefined) text = String(value);
  return text.length > MAX_VALUE_CHARS ? `${text.slice(0, MAX_VALUE_CHARS)}… [truncated]` : text;
}

function leafId(path) {
  return `ev-${path.replace(/[^A-Za-z0-9_-]/g, "-")}`;
}

function statusChip(status) {
  const cls = { measured: "confidence-high", inferred: "confidence-medium", missing: "state-locked" }[status] || "";
  return `<span class="badge ${cls}">${escapeHTML(status)}</span>`;
}

// ── Highlights (plain words) ────────────────────────────────────────────────

function val(packet, path) {
  const leaf = iterLeaves(packet).find(([p]) => p === path)?.[1];
  return leaf && leaf.status !== "missing" ? leaf.value : null;
}

function baselineWords(packet) {
  const n30 = val(packet, "baseline.same_source_entity_30d");
  const all = val(packet, "baseline.same_source_entity_all_time") ?? val(packet, "baseline.same_entity_all_time");
  const noisy = val(packet, "baseline.is_known_noisy");
  const first = val(packet, "baseline.is_first_occurrence");
  if (n30 === null && all === null) return "Historical baseline not measured (unknown, not safe).";
  const parts = [];
  if (all !== null) parts.push(`seen ${Number(all).toLocaleString()} times before on this entity`);
  if (n30 !== null) parts.push(`${Number(n30).toLocaleString()} in the last 30 days`);
  if (noisy === true) parts.push("known-noisy");
  if (first === true) parts.push("first occurrence");
  return `${parts.join("; ")}.`;
}

function signatureRows(packet) {
  const sig = val(packet, "raw_alerts.signatures");
  const items = (sig && sig.items) || [];
  if (!items.length) return "";
  return `<table class="data-table"><thead><tr><th>Alert signature</th><th>Process</th><th>Count</th><th>threat_desc</th></tr></thead><tbody>${items.slice(0, 8).map((s) => `<tr><td>${escapeHTML(short(s.alert_name || ""))}</td><td><code>${escapeHTML(short(s.process || "—"))}</code></td><td>${escapeHTML(s.count ?? "")}</td><td>${escapeHTML(short((s.threat_desc || []).join("; ") || "—"))}</td></tr>`).join("")}</tbody></table>${sig.note ? `<p class="form-help">${escapeHTML(sig.note)}</p>` : ""}`;
}

function lolbasHighlights(packet) {
  const lol = val(packet, "rule_signals.lolbas");
  const mas = val(packet, "rule_signals.masquerade");
  const rows = [];
  ((lol && lol.strong_hits) || []).slice(0, 6).forEach((h) => rows.push(`<li><span class="badge severity-high">strong</span> <code>${escapeHTML(short(h.binary))}</code> ${escapeHTML(short(h.category || ""))} ${h.path_mismatch ? '<span class="badge severity-critical">path_mismatch</span>' : ""}</li>`));
  if (lol && lol.weak_hit_count) rows.push(`<li><span class="badge severity-low">weak</span> ${escapeHTML(lol.weak_hit_count)} name-only hit(s)</li>`);
  ((mas && mas.path_mismatches) || []).slice(0, 4).forEach((h) => rows.push(`<li><span class="badge severity-critical">masquerade</span> <code>${escapeHTML(short(h.binary))}</code> in <code>${escapeHTML(short(h.observed_directory || ""))}</code></li>`));
  return rows.length ? `<ul class="data-list">${rows.join("")}</ul>` : `<p class="form-help">No abused-tool (LOLBAS) hits.</p>`;
}

function threatDesc(packet) {
  const td = val(packet, "raw_alerts.threat_desc");
  const items = (td && td.items) || [];
  return items.length ? `<ul class="data-list">${items.slice(0, 6).map((t) => `<li><span>${escapeHTML(short(t.value ?? t))}</span>${t.count ? `<strong>${escapeHTML(t.count)}</strong>` : ""}</li>`).join("")}</ul>` : "";
}

// ── Left: evidence packet ───────────────────────────────────────────────────

function evidencePane(packet) {
  const sections = Object.keys(packet || {}).map((section) => {
    const leaves = iterLeaves(packet[section], section);
    const rows = leaves.map(([path, leaf]) => `<tr id="${escapeHTML(leafId(path))}" data-leaf-path="${escapeHTML(path)}"><td><code>${escapeHTML(path)}</code></td><td>${statusChip(leaf.status)}</td><td><code class="triage-review-value">${leaf.status === "missing" ? "—" : escapeHTML(short(leaf.value))}</code></td><td class="form-help">${escapeHTML(short(leaf.source))}</td></tr>`).join("");
    return `<details class="triage-review-section"${["raw_alerts", "rule_signals", "baseline", "context"].includes(section) ? " open" : ""}><summary>${escapeHTML(SECTION_LABELS[section] || section)} <span class="form-help">(${leaves.filter(([, l]) => l.status === "measured").length} measured / ${leaves.length})</span></summary><table class="data-table"><tbody>${rows}</tbody></table></details>`;
  }).join("");
  const supp = val(packet, "context.suppression_match");
  const suppNote = supp ? `<p class="notice${supp.ignored_for_guards ? " notice-error" : ""}">Approved suppression matches this incident${supp.ignored_for_guards ? `, but it is <strong>ignored</strong>: ${escapeHTML(supp.ignored_reason || "strong signals present")}` : " (the analyst still reviews it)"}.</p>` : "";
  return `<div class="triage-review-evidence"><h3>Evidence packet</h3>
    <div class="triage-review-highlights">
      <p><strong>Baseline:</strong> ${escapeHTML(baselineWords(packet))}</p>
      ${signatureRows(packet)}
      <h4>Abused tools (LOLBAS)</h4>${lolbasHighlights(packet)}
      ${threatDesc(packet) ? `<h4>threat_desc</h4>${threatDesc(packet)}` : ""}
      ${suppNote}
    </div>${sections}</div>`;
}

// ── Right: hypotheses ───────────────────────────────────────────────────────

function citeChips(cites, packet) {
  const known = new Set(iterLeaves(packet).map(([p]) => p));
  return (cites || []).map((c) => known.has(c)
    ? `<button type="button" class="evidence-chip" data-cite="${escapeHTML(c)}">${escapeHTML(c)}</button>`
    : `<span class="evidence-chip" title="Unknown path">${escapeHTML(c)}</span>`).join(" ");
}

function claims(list, packet) {
  if (!list || !list.length) return `<p class="form-help">None cited.</p>`;
  return `<ul class="triage-review-claims">${list.map((c) => `<li>${escapeHTML(c.claim)}<div>${citeChips(c.cites, packet)}</div></li>`).join("")}</ul>`;
}

function hypothesesPane(a, packet) {
  const h = a.hypotheses || {};
  const errs = (a.citation_errors || []).filter((e) => e.path);
  const la = a.lookalike_ruled_out;
  return `<div class="triage-review-hypotheses"><h3>Competing hypotheses</h3>
    <h4>Malicious</h4><p class="form-help">For</p>${claims(h.malicious?.evidence_for, packet)}<p class="form-help">Against</p>${claims(h.malicious?.evidence_against, packet)}
    <h4>Benign</h4><p class="form-help">For</p>${claims(h.benign?.evidence_for, packet)}<p class="form-help">Against</p>${claims(h.benign?.evidence_against, packet)}
    ${errs.length ? `<h4>Invalid citations (removed by code)</h4><ul class="triage-review-claims">${errs.map((e) => `<li><s><code>${escapeHTML(e.path)}</code></s> <span class="form-help">${escapeHTML(e.error)} · ${escapeHTML(e.location)}</span></li>`).join("")}</ul>` : ""}
    <h4>Most plausible malicious lookalike</h4>${la ? `<p>${escapeHTML(la.lookalike)} — <strong>${la.ruled_out ? "ruled out" : "NOT ruled out"}</strong>${la.reason ? `: ${escapeHTML(la.reason)}` : ""}</p><div>${citeChips(la.cites, packet)}</div>` : `<p class="form-help">Not stated.</p>`}
    <h4>Cost if this is malicious and we close it</h4><p>${escapeHTML(a.fn_cost_if_wrong || "—")}</p>
    <h4>Guard actions</h4>${(a.guard_actions || []).length ? `<ul class="triage-review-claims">${a.guard_actions.map((g) => `<li><code>${escapeHTML(g.rule)}</code>: ${escapeHTML(dispositionLabel(g.from))} → ${escapeHTML(dispositionLabel(g.to))}<div class="form-help">${escapeHTML(g.reason)}</div></li>`).join("")}</ul>` : `<p class="form-help">No overrides.</p>`}
  </div>`;
}

// ── Verdict header ──────────────────────────────────────────────────────────

function guardSentence(a) {
  const actions = a.guard_actions || [];
  if (!actions.length || a.proposed_disposition === a.disposition) return "";
  const why = actions.map((g) => GUARD_REASONS[g.rule] || g.reason).join("; ");
  return `Changed to ${dispositionLabel(a.disposition)}: ${why}.`;
}

function missingMandatory(packet) {
  const out = [];
  const raw = iterLeaves(packet).find(([p]) => p === "raw_alerts.available")?.[1];
  if (raw && (raw.status === "missing" || raw.value !== true)) out.push("raw alerts were not available");
  const base = val(packet, "baseline.status");
  if (base !== "measured") out.push("historical baseline not measured");
  if (val(packet, "detection.createdBy") === null) out.push("detection source unknown");
  if (val(packet, "entity.value") === null) out.push("entity unresolved");
  const parser = val(packet, "data_quality.parser_status");
  if (String(parser || "").toLowerCase() !== "completed") out.push("parsing did not complete");
  return out;
}

function verdictHeader(a, packet, { hidden }) {
  const missing = missingMandatory(packet);
  const banner = missing.length ? `<div class="notice notice-error triage-review-banner"><strong>Unknown ≠ safe.</strong> Missing mandatory evidence: ${escapeHTML(missing.join("; "))}. The alert cannot be closed as benign on this evidence.</div>` : "";
  if (hidden) {
    return `<div class="triage-review-verdict"><p><strong>Blind-first review:</strong> the AI verdict and hypotheses are hidden until you record your own disposition.</p>${banner}</div>`;
  }
  const sentence = guardSentence(a);
  return `<div class="triage-review-verdict">
    <div class="triage-review-verdict-row">
      <span>AI final disposition</span> <span class="badge state-awaiting_approval" id="ai-final-disposition">${escapeHTML(dispositionLabel(a.disposition))}</span>
      <span>Proposed</span> <span class="badge">${escapeHTML(dispositionLabel(a.proposed_disposition))}</span>
      <span>Uncertainty</span> <span class="badge">${escapeHTML(UNCERTAINTY_WORDS[a.uncertainty] || "Unknown")}</span>
    </div>
    ${sentence ? `<p class="notice">${escapeHTML(sentence)}</p>` : ""}${banner}</div>`;
}

// ── Review form ─────────────────────────────────────────────────────────────

function options(selected = "") {
  return `<option value="">— choose —</option>${DISPOSITIONS.map((d) => `<option value="${d}"${d === selected ? " selected" : ""}>${escapeHTML(DISPOSITION_LABELS[d])}</option>`).join("")}`;
}

function reviewForm(packet, { blind }) {
  const sections = checklistSections(packet);
  return `<form class="settings-form triage-review-form" id="triage-review-form" novalidate>
    <h3>Analyst review</h3>
    <label>${blind ? "Your initial disposition (before seeing the AI)" : "Analyst disposition"}
      <select name="analyst_disposition" required>${options()}</select></label>
    <fieldset><legend>Evidence I checked (at least one)</legend>
      ${sections.map((s) => `<label class="check-field"><input type="checkbox" name="evidence_checked" value="${escapeHTML(s)}"> ${escapeHTML(SECTION_LABELS[s] || s)}</label>`).join("")}
      <label>Other evidence checked (free text)<input name="evidence_other" maxlength="300"></label>
    </fieldset>
    <label>One-sentence justification<input name="justification" maxlength="2000" required></label>
    <label data-show-if="not-tp">Most plausible malicious lookalike considered<input name="lookalike_considered" maxlength="2000"></label>
    <label data-show-if="false_positive">Rule tuning note (what is wrong with the rule)<input name="rule_tuning_note" maxlength="2000"></label>
    <fieldset data-show-if="benign_expected"><legend>Benign context (all required)</legend>
      <label>Who<input name="bc_who" maxlength="300"></label>
      <label>When<input name="bc_when" maxlength="300"></label>
      <label>Why it is expected<input name="bc_why" maxlength="2000"></label>
      <label class="check-field"><input type="checkbox" name="propose_suppression"> Propose a scoped suppression (a second analyst must approve)</label>
      <div data-show-if="suppression"><label>Detection source<input name="sp_source" maxlength="300"></label><label>Entity<input name="sp_entity" maxlength="300"></label><label>Alert signature (optional)<input name="sp_signature" maxlength="300"></label><label>Expiry (days, max 90)<input name="sp_days" type="number" min="1" max="90" value="30"></label></div>
    </fieldset>
    <label data-show-if="disagree">Why you disagree with the AI<input name="disagreement_reason" maxlength="2000"></label>
    <label data-show-if="revised">Why you revised your initial disposition<input name="revision_reason" maxlength="2000"></label>
    <label>Comments / rejection reason<input name="comments" maxlength="2000"></label>
    <div id="triage-review-errors" aria-live="polite"></div>
    <div class="stage-actions">
      ${blind ? `<button class="action-button" type="button" data-review-step="reveal">Record initial verdict &amp; reveal AI</button>` : ""}
      <button class="action-button" type="submit" data-review-submit="approve"${blind ? " hidden" : ""}>Approve (continue to Threat Intel)</button>
      <button class="action-button danger" type="button" data-review-submit="reject"${blind ? " hidden" : ""}>Reject (return)</button>
      <button class="action-button danger" type="button" data-review-submit="reject-retriage"${blind ? " hidden" : ""}>Reject and re-triage with this note</button>
    </div>
  </form>`;
}

// Pure: build + validate the review payload from form values. Mirrors
// agents/triage/review.TriageReview (the server re-validates everything).
export function buildReview(values, { aiFinal, reviewMode, initialDisposition }) {
  const errors = [];
  const d = values.analyst_disposition || "";
  if (!DISPOSITIONS.includes(d)) errors.push("Choose an analyst disposition.");
  const evidence = [...(values.evidence_checked || [])];
  if ((values.evidence_other || "").trim()) evidence.push(values.evidence_other.trim());
  if (!evidence.length) errors.push("Tick at least one piece of evidence you checked.");
  const just = (values.justification || "").trim();
  if (!just) errors.push("A one-sentence justification is required.");
  const review = { analyst_disposition: d, evidence_checked: evidence, justification: just, review_mode: reviewMode };
  if (d && d !== "true_positive") {
    if (!(values.lookalike_considered || "").trim()) errors.push("Name the most plausible malicious lookalike you considered.");
    else review.lookalike_considered = values.lookalike_considered.trim();
  }
  if (d === "false_positive") {
    if (!(values.rule_tuning_note || "").trim()) errors.push("A false positive needs a rule tuning note.");
    else review.rule_tuning_note = values.rule_tuning_note.trim();
  }
  if (d === "benign_expected") {
    const bc = { who: (values.bc_who || "").trim(), when: (values.bc_when || "").trim(), why: (values.bc_why || "").trim() };
    if (!bc.who || !bc.when || !bc.why) errors.push("Benign-expected needs who, when and why.");
    review.benign_context = bc;
    if (values.propose_suppression) {
      const scope = { detection_source: (values.sp_source || "").trim(), entity: (values.sp_entity || "").trim() };
      if ((values.sp_signature || "").trim()) scope.alert_signature = values.sp_signature.trim();
      const days = Number(values.sp_days || 30);
      if (!scope.detection_source || !scope.entity) errors.push("A suppression needs a detection source and an entity.");
      if (!Number.isInteger(days) || days < 1 || days > 90) errors.push("Suppression expiry must be 1-90 days.");
      review.suppression_proposal = { scope, expiry_days: days };
    }
  }
  if (aiFinal && d && d !== aiFinal) {
    if (!(values.disagreement_reason || "").trim()) errors.push(`You disagree with the AI (${dispositionLabel(aiFinal)}): say why.`);
    else review.disagreement_reason = values.disagreement_reason.trim();
  }
  if (reviewMode === "blind_first") {
    review.analyst_initial_disposition = initialDisposition || d;
    if (initialDisposition && d && initialDisposition !== d) {
      if (!(values.revision_reason || "").trim()) errors.push("Say why you revised your initial disposition after seeing the AI.");
      else review.revision_reason = values.revision_reason.trim();
    }
  }
  return { review, errors };
}

function formValues(form) {
  const fd = new FormData(form);
  const out = {};
  for (const [k, v] of fd.entries()) {
    if (k === "evidence_checked") (out.evidence_checked ||= []).push(String(v));
    else out[k] = String(v);
  }
  out.propose_suppression = fd.get("propose_suppression") === "on";
  return out;
}

// Pure: the whole review screen as an (escaped) HTML string. Exported so the
// escaping and the blind_first hiding can be tested under Node without a DOM.
export function reviewScreenHTML(result, { revealed = true, awaitingApproval = false } = {}) {
  const a = result.assessment;
  const packet = result.evidence_packet;
  return `<section class="panel triage-review" id="triage-review">
      ${verdictHeader(a, packet, { hidden: !revealed })}
      <div class="triage-review-split">
        ${evidencePane(packet)}
        ${revealed ? hypothesesPane(a, packet) : `<div class="triage-review-hypotheses"><p class="form-help">Hidden until you record your initial disposition.</p></div>`}
      </div>
      ${awaitingApproval ? reviewForm(packet, { blind: !revealed }) : ""}
    </section>`;
}

// ── Mount ───────────────────────────────────────────────────────────────────

/**
 * Renders the review screen into `container`.
 * opts: { result, awaitingApproval, reviewMode, defaultScope, onDecision(kind, review, comments) }
 *   kind: "approve" | "reject" | "reject-retriage"
 */
export function mountTriageReview(container, opts) {
  const result = opts.result || {};
  const a = result.assessment;
  const packet = result.evidence_packet;
  if (!a || !packet) {
    container.innerHTML = `<p class="form-help">This Triage result predates the evidence packet; no structured review is available.</p>`;
    return;
  }
  const blind = opts.awaitingApproval && opts.reviewMode === "blind_first";
  let revealed = !blind;
  let initialDisposition = null;

  const render = () => {
    container.innerHTML = reviewScreenHTML(result, { revealed, awaitingApproval: opts.awaitingApproval });
    bind();
  };

  const bind = () => {
    container.querySelectorAll("[data-cite]").forEach((chip) => chip.addEventListener("click", () => {
      const row = container.querySelector(`#${CSS.escape(leafId(chip.dataset.cite))}`);
      if (!row) return;
      const details = row.closest("details");
      if (details) details.open = true;
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.classList.add("triage-review-highlight");
      window.setTimeout(() => row.classList.remove("triage-review-highlight"), 2500);
    }));
    const form = container.querySelector("#triage-review-form");
    if (!form) return;
    const scope = opts.defaultScope || {};
    if (form.elements.sp_source) form.elements.sp_source.value = scope.detection_source || "";
    if (form.elements.sp_entity) form.elements.sp_entity.value = scope.entity || "";
    const sync = () => {
      const v = formValues(form);
      const d = v.analyst_disposition;
      const show = {
        "not-tp": d && d !== "true_positive",
        false_positive: d === "false_positive",
        benign_expected: d === "benign_expected",
        suppression: d === "benign_expected" && v.propose_suppression,
        disagree: revealed && d && a.disposition && d !== a.disposition,
        revised: revealed && initialDisposition && d && d !== initialDisposition,
      };
      form.querySelectorAll("[data-show-if]").forEach((el) => { el.hidden = !show[el.dataset.showIf]; });
    };
    form.addEventListener("change", sync);
    form.addEventListener("input", sync);
    sync();
    const errorsBox = form.querySelector("#triage-review-errors");
    const showErrors = (errs) => {
      errorsBox.innerHTML = errs.length ? `<div class="notice notice-error"><ul>${errs.map((e) => `<li>${escapeHTML(e)}</li>`).join("")}</ul></div>` : "";
    };
    const reveal = form.querySelector('[data-review-step="reveal"]');
    if (reveal) reveal.addEventListener("click", () => {
      const v = formValues(form);
      const { errors } = buildReview(v, { aiFinal: null, reviewMode: "blind_first", initialDisposition: null });
      if (errors.length) { showErrors(errors); return; }
      initialDisposition = v.analyst_disposition;
      revealed = true;
      render();
      const f2 = container.querySelector("#triage-review-form");
      // Restore what the analyst already entered; disposition is preselected
      // with THEIR OWN initial choice (never the AI's).
      Object.entries(v).forEach(([k, value]) => {
        if (k === "evidence_checked") {
          f2.querySelectorAll('input[name="evidence_checked"]').forEach((cb) => { cb.checked = value.includes(cb.value); });
        } else if (f2.elements[k] && f2.elements[k].type !== "checkbox") f2.elements[k].value = value;
        else if (f2.elements[k]) f2.elements[k].checked = Boolean(value);
      });
      f2.dispatchEvent(new Event("change"));
    });
    const submit = (kind) => {
      const v = formValues(form);
      const { review, errors } = buildReview(v, {
        aiFinal: a.disposition, reviewMode: opts.reviewMode === "blind_first" ? "blind_first" : "assisted", initialDisposition,
      });
      const comments = (v.comments || "").trim();
      if (kind !== "approve" && !comments) errors.push("A rejection reason (comments) is required to reject.");
      if (kind === "reject-retriage" && !comments) errors.push("The comments are the note the re-triage will use.");
      showErrors(errors);
      if (errors.length) return;
      opts.onDecision(kind, review, comments);
    };
    form.addEventListener("submit", (event) => { event.preventDefault(); submit("approve"); });
    form.querySelectorAll('[data-review-submit="reject"], [data-review-submit="reject-retriage"]').forEach((b) => b.addEventListener("click", () => submit(b.dataset.reviewSubmit)));
  };

  render();
}
