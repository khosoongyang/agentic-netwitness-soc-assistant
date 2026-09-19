import { fetchJSON } from "../api.js";
import { badge, emptyState, errorState, escapeHTML, formatDate, loadingState, openModal } from "../ui.js";
import { createBlockEditor } from "../components/blockEditor.js";

// Reused from the app's existing icon-badge component (components.css
// .summary-card-icon) rather than introducing a new icon system.
const DOCUMENT_ICON_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h6M9 9h2"/></svg>`;

// The Reporting table always shows exactly these four rows, in this order —
// matches backend/services/report_service.py::list_reports(), which already
// iterates agents.reporting.report_editing.CORE_REPORT_TYPES in this order.
// The Triage Ticket (a 5th row the backend still returns alongside these
// four) is a Triage-stage concern, not Reporting — it's never shown in this
// table. Its own entry point lives on the Triage stage card (workspace.js
// calls openReportInto() below with TICKET_REPORT_TYPE), reusing the same
// view/edit/export machinery without being mixed into the Reporting UI.
export const TICKET_REPORT_TYPE = "triage_ticket";
const PREVIEW_REPORT_TYPES = new Set(["final_incident_report"]);
// Mirrors agents/reporting/reporting/final_report_assembler.COMPONENT_REPORT_TYPES —
// reviewing any of these three can trigger automatic Final Incident Report assembly.
const COMPONENT_REPORT_TYPES = new Set(["executive_summary", "technical_findings", "soc_analyst_review"]);

// Closed over the currently-rendered panel's document click listener so a
// re-render never accumulates a second document-level listener on the
// shared #app-content root (or, when embedded, the workspace stage panel).
let activeDocumentClickHandler = null;

function renderBlock(block) {
  if (block.type === "heading") return `<h${Math.min(Math.max(block.level || 2, 2), 4)}>${escapeHTML(block.text)}</h${Math.min(Math.max(block.level || 2, 2), 4)}>`;
  if (block.type === "bullet_list") return `<ul>${(block.items || []).map(item => `<li>${escapeHTML(item.text ?? item)}</li>`).join("")}</ul>`;
  if (block.type === "table") return `<div class="table-wrap"><table><thead><tr>${(block.columns || []).map(value => `<th>${escapeHTML(value)}</th>`).join("")}</tr></thead><tbody>${(block.rows || []).map(row => `<tr>${row.map(value => `<td>${escapeHTML(value)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  if (block.type === "page_break") return `<hr>`;
  return `<p>${escapeHTML(block.text || "")}</p>`;
}

// "Updated By" is dynamic: the backend only returns an editor identity when
// an analyst edit exists (report_row_state()'s edited_by); when a report is
// still exactly as generated, we label it "Aegis" rather than leaving it
// blank. No name is ever hardcoded — has_edits/edited_by both come from the
// API response for this specific case.
function updatedByLabel(row) {
  return row.has_edits && row.edited_by ? row.edited_by : "Aegis";
}

function exportMenu(caseId, reportType) {
  const base = `/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/download`;
  return `
    <div class="export-dropdown">
      <button type="button" class="action-button" data-export-toggle>Export ▾</button>
      <div class="export-menu" data-export-menu hidden>
        <a href="${base}?format=docx">Export as Word (.docx)</a>
        <a href="${base}?format=pdf">Export as PDF</a>
      </div>
    </div>`;
}

function reportsTableRows(caseId, reports) {
  return reports.map(row => {
    const viewLabel = PREVIEW_REPORT_TYPES.has(row.report_type) ? "Preview" : "View";
    return `
      <tr data-report-type="${escapeHTML(row.report_type)}">
        <td><strong>${escapeHTML(row.title)}</strong></td>
        <td class="reports-table-description">${escapeHTML(row.description)}</td>
        <td data-cell="status">${badge(row.status, `report-status-${escapeHTML(row.tone || "info")}`)}</td>
        <td data-cell="last-updated">${formatDate(row.last_saved_iso)}</td>
        <td data-cell="updated-by">${escapeHTML(updatedByLabel(row))}</td>
        <td class="report-actions-cell">
          <button type="button" class="action-button" data-view="${escapeHTML(row.report_type)}">${viewLabel}</button>
          <button type="button" class="action-button" data-edit="${escapeHTML(row.report_type)}">Edit</button>
          ${exportMenu(caseId, row.report_type)}
        </td>
      </tr>`;
  }).join("");
}

// Patches one row's Status/Last Updated/Updated By cells in place after a
// save/confirm/discard succeeds in the detail panel below, so the table
// above never shows stale values without requiring a full page reload.
function syncTableRow(tableRoot, row) {
  if (!tableRoot) return; // no table to sync (e.g. the standalone Triage Ticket viewer)
  const tr = tableRoot.querySelector(`tr[data-report-type="${CSS.escape(row.report_type)}"]`);
  if (!tr) return;
  tr.querySelector('[data-cell="status"]').innerHTML = badge(row.status, `report-status-${escapeHTML(row.tone || "info")}`);
  tr.querySelector('[data-cell="last-updated"]').textContent = formatDate(row.last_saved_iso);
  tr.querySelector('[data-cell="updated-by"]').textContent = updatedByLabel(row);
}

async function analystName() {
  const settings = await fetchJSON("/api/settings");
  return settings.analyst_name || window.prompt("Analyst name", "")?.trim() || "";
}

function closeAllExportMenus() {
  document.querySelectorAll(".export-menu:not([hidden])").forEach(menu => { menu.hidden = true; });
}

const VERSION_ORIGIN_LABELS = {
  ai_generated: "AI generated",
  analyst_edit: "Analyst edit",
  assembled: "Assembled",
};

// Read-only version browser (Phase 4) — GET /<report_type>/versions returns
// every immutable report_versions row newest-first, each already carrying
// its own report_reviews fact (see report_editing.list_report_versions()).
// A version reviewed in the past stays marked "Reviewed" here even once a
// later edit has moved the report's current status back to "Edited".
async function openVersionHistory(caseId, reportType, title) {
  const modal = openModal(`Version history — ${title}`);
  modal.setBody(loadingState("Loading version history…"));
  try {
    const data = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/versions`);
    const versions = data.versions || [];
    const showList = () => {
      modal.setBody(versions.length ? `
        <ul class="version-history-list">
          ${versions.map(v => `
            <li class="version-history-item">
              <div class="version-history-item-header">
                <strong>Version ${v.version}</strong>
                <span class="muted">${escapeHTML(VERSION_ORIGIN_LABELS[v.origin] || v.origin)}</span>
                ${v.review_status ? badge("Reviewed", "report-status-low") : ""}
              </div>
              <p class="muted">${escapeHTML(v.edited_by)} · ${formatDate(v.created_at)}${v.reviewed_by ? ` · reviewed by ${escapeHTML(v.reviewed_by)} on ${formatDate(v.reviewed_at)}` : ""}</p>
              <button type="button" class="text-button" data-view-version="${v.report_version_id}">View content</button>
            </li>`).join("")}
        </ul>` : emptyState("No saved versions yet."));
      document.querySelectorAll("[data-view-version]").forEach(button => {
        button.addEventListener("click", () => {
          const entry = versions.find(v => String(v.report_version_id) === button.dataset.viewVersion);
          modal.setBody(`
            <button type="button" class="text-button" id="version-history-back">← Back to versions</button>
            <article class="report-preview">${(entry.blocks || []).map(renderBlock).join("") || emptyState("This version has no content.")}</article>`);
          document.querySelector("#version-history-back")?.addEventListener("click", showList);
        });
      });
    };
    showList();
  } catch (error) {
    modal.setBody(errorState(error));
  }
}

// Shared view/edit/save/review/discard logic for a single report or ticket,
// rendered into `detail`. `tableRoot` is the ancestor containing a reports
// table whose row should be kept in sync after a mutation — pass null when
// there is no table (e.g. the standalone Triage Ticket viewer opened from
// the Triage stage card).
function createReportOpener({ caseId, detail, tableRoot }) {
  async function open(reportType, mode = "view") {
    closeAllExportMenus();
    detail.innerHTML = loadingState("Loading report…");
    detail.scrollIntoView({ behavior: "smooth", block: "start" });
    try {
      let report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}`);
      const show = () => {
        detail.innerHTML = `
          <div class="page-header"><div><h2>${escapeHTML(report.title)}</h2><p>${escapeHTML(report.status)}${report.is_stale ? " · based on an older candidate" : ""}</p></div></div>
          <div class="stage-actions"><button type="button" class="action-button" id="edit-report">Edit</button><button type="button" class="action-button" id="confirm-report">Confirm section</button>${report.has_edits ? `<button type="button" class="action-button danger" id="discard-report">Replace with AI version</button>` : ""}</div>
          <div id="report-action"></div><article class="report-preview">${(report.blocks || []).map(renderBlock).join("") || emptyState("This report has not been generated.")}</article>`;
        detail.querySelector("#edit-report").addEventListener("click", edit);
        detail.querySelector("#confirm-report").addEventListener("click", confirm);
        detail.querySelector("#discard-report")?.addEventListener("click", discard);
      };
      function edit() {
        const editor = createBlockEditor(report.blocks);
        detail.innerHTML = `
          <div class="report-editor-header">
            <span class="summary-card-icon summary-card-icon-investigation" aria-hidden="true">${DOCUMENT_ICON_SVG}</span>
            <div><h2>Edit Report</h2><p class="form-help">Review, refine and finalise report content before approval.</p></div>
          </div>
          <div class="report-editor-meta">
            <div class="report-editor-meta-row"><strong>${escapeHTML(report.title)}</strong>${badge(report.status, `report-status-${escapeHTML(report.tone || "info")}`)}</div>
            <p class="muted">${escapeHTML(report.description)}</p>
          </div>
          <div id="editor-mount"></div>
          <div id="report-action"></div>
          <div class="stage-actions report-editor-footer">
            ${report.exists ? `<button type="button" class="text-button" id="editor-version-history">Version history</button>` : "<span></span>"}
            <div class="report-editor-footer-actions">
              <button type="button" class="action-button" id="editor-cancel">Cancel</button>
              <button type="button" class="action-button" id="editor-save-draft">Save Draft</button>
              <button type="button" class="action-button" id="editor-mark-reviewed">Mark as Reviewed</button>
            </div>
          </div>`;
        detail.querySelector("#editor-mount").appendChild(editor.element);

        editor.onPreview((previewBlocks) => {
          const modal = openModal(`Preview — ${report.title}`);
          modal.setBody(`<article class="report-preview">${previewBlocks.map(renderBlock).join("") || emptyState("Nothing to preview yet.")}</article>`);
        });

        detail.querySelector("#editor-version-history")?.addEventListener("click", () => {
          openVersionHistory(caseId, reportType, report.title);
        });

        detail.querySelector("#editor-cancel").addEventListener("click", () => {
          if (editor.isDirty() && !window.confirm("You have unsaved changes. Discard them?")) return;
          show();
        });
        detail.querySelector("#editor-save-draft").addEventListener("click", async () => {
          try {
            const analyst = await analystName();
            if (!analyst) throw new Error("Analyst identity is required.");
            const blocks = editor.getBlocks();
            report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}`, { method: "PUT", body: { blocks, analyst, run_id: report.run_id, report_set_id: report.current_report_set_id } });
            editor.markSaved();
            syncTableRow(tableRoot, report);
            detail.querySelector("#report-action").innerHTML = `<p class="notice">Draft saved.</p>`;
            detail.querySelector(".report-editor-meta-row").innerHTML = `<strong>${escapeHTML(report.title)}</strong>${badge(report.status, `report-status-${escapeHTML(report.tone || "info")}`)}`;
          } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
        });
        // Phase 3: real persisted per-version review state — records a
        // report_reviews row against this exact report_versions row
        // (backend/routes/reports.py POST /<report_type>/review ->
        // agents/reporting/report_editing.py::mark_reviewed()). A later
        // edit produces a new version with no review row, so this never
        // silently "carries over" onto content the analyst didn't review.
        detail.querySelector("#editor-mark-reviewed").addEventListener("click", async () => {
          if (editor.isDirty()) {
            detail.querySelector("#report-action").innerHTML = errorState({ message: "Save your changes as a draft before marking this report as reviewed." });
            return;
          }
          try {
            const analyst = await analystName();
            report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/review`, { method: "POST", body: { analyst, report_version_id: report.report_version_id } });
            syncTableRow(tableRoot, report);
            // Reviewing a component report can silently (re)assemble the
            // Final Incident Report server-side (see report_editing.py's
            // _maybe_assemble_final_incident_report()) — that row's own
            // status/last-updated wouldn't otherwise refresh until the
            // page reloads, so re-fetch it too whenever it might have
            // changed as a side effect of this action.
            if (tableRoot && COMPONENT_REPORT_TYPES.has(reportType)) {
              fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/final_incident_report`)
                .then(finalReport => syncTableRow(tableRoot, finalReport))
                .catch(() => {});
            }
            show();
          } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
        });
      }
      async function confirm() {
        try {
          const analyst = await analystName();
          report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/confirm`, { method: "POST", body: { analyst, report_set_id: report.current_report_set_id } });
          syncTableRow(tableRoot, report);
          show();
        } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
      }
      async function discard() {
        if (!window.confirm("Discard saved edits and replace them with the current AI version?")) return;
        try {
          report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/draft`, { method: "DELETE", body: { analyst: await analystName() } });
          syncTableRow(tableRoot, report);
          show();
        } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
      }
      if (mode === "edit") { show(); edit(); } else { show(); }
    } catch (error) { detail.innerHTML = errorState(error); }
  }
  return open;
}

// Core reports table + detail panel, mountable either as the full standalone
// page (embedded=false, kept for direct-URL / compatibility access — no
// longer linked from any button) or embedded directly inside the Agents
// workspace's Reporting stage card (embedded=true). Both modes share the
// exact same table-rendering and view/edit logic — there is only one
// implementation of the reports table in this codebase.
export async function mountReportsPanel(container, { caseId, navigate, embedded = false }) {
  if (!caseId) { container.innerHTML = errorState({ code: "CASE_NOT_SELECTED", message: "Select a case before opening reports." }); return; }
  container.innerHTML = loadingState("Loading report workspace…");
  try {
    let listing = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports`);
    const chrome = embedded ? "" : `
      <button class="text-button" id="back-case">← Back to case</button>
      <header class="page-header">
        <div><h1>Reporting</h1><p>${escapeHTML(caseId)} · ${escapeHTML(listing.reporting_status)} · attempt ${listing.reporting_attempt}</p></div>
      </header>`;
    container.innerHTML = `
      ${chrome}
      <div class="stage-actions reports-panel-actions">
        <a class="text-button" href="/api/cases/${encodeURIComponent(caseId)}/reports/data/download">Raw JSON</a>
        <button type="button" class="action-button" id="submit-for-approval">Submit for Approval</button>
        ${listing.export_all_available ? `<a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/reports/export-all">Export all</a>` : ""}
      </div>
      ${listing.pending_report_set_id ? `<p class="notice">A reviewed report set is materialised and awaiting approval (set ${escapeHTML(listing.pending_report_set_id.slice(0, 12))}…). Use the stage's Approve action above once ready.</p>` : ""}
      ${listing.warnings.map(value => `<p class="notice">${escapeHTML(value)}</p>`).join("")}
      <div class="table-wrap reports-table-wrap${embedded ? " reports-table-embedded" : ""}">
        <table class="reports-table">
          <thead><tr><th>Report</th><th>Description</th><th>Status</th><th>Last Updated</th><th>Updated By</th><th>Actions</th></tr></thead>
          <tbody>${reportsTableRows(caseId, listing.reports)}</tbody>
        </table>
      </div>
      <section class="panel" id="report-detail">${emptyState("Choose View, Preview or Edit on a report above.")}</section>`;

    if (!embedded) {
      container.querySelector("#back-case").addEventListener("click", () => navigate("case", { case: caseId }));
    }
    // Phase 6/7: materialises a new immutable candidate from the four core
    // reports' latest REVIEWED versions. Refused server-side (with a clear
    // per-report message) unless all four are currently Reviewed — this
    // button never bypasses that gate, it just surfaces the result. The
    // actual approval decision is made with the stage-level Approve/Reject
    // controls (workflow/commands.py::available_actions(), which only
    // enables Approve once a materialised set like this exists) — kept as
    // the single approval path rather than duplicating it here.
    container.querySelector("#submit-for-approval").addEventListener("click", async () => {
      try {
        const analyst = await analystName();
        if (!analyst) throw new Error("Analyst identity is required.");
        await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/submit-for-approval`, { method: "POST", body: { analyst } });
        await mountReportsPanel(container, { caseId, navigate, embedded });
      } catch (error) { container.insertAdjacentHTML("afterbegin", errorState(error)); }
    });

    // Export dropdowns: one delegated document-level listener closes any
    // open menu on an outside click; replacing (not stacking) the handler
    // on every render keeps this safe across re-renders of the shared root.
    if (activeDocumentClickHandler) document.removeEventListener("click", activeDocumentClickHandler);
    activeDocumentClickHandler = (event) => {
      if (!event.target.closest(".export-dropdown")) closeAllExportMenus();
    };
    document.addEventListener("click", activeDocumentClickHandler);
    container.querySelectorAll("[data-export-toggle]").forEach(button => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        const menu = button.nextElementSibling;
        const wasHidden = menu.hidden;
        closeAllExportMenus();
        menu.hidden = !wasHidden;
      });
    });

    const detail = container.querySelector("#report-detail");
    const open = createReportOpener({ caseId, detail, tableRoot: container });
    container.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => open(button.dataset.view, "view")));
    container.querySelectorAll("[data-edit]").forEach(button => button.addEventListener("click", () => open(button.dataset.edit, "edit")));
  } catch (error) { container.innerHTML = errorState(error); }
}

// Standalone full-page route (?view=reports&case=...) — kept only for
// direct-URL / compatibility access. No button in the normal analyst flow
// navigates here any more; the Reporting stage card in the Agents/case
// workspace (frontend/js/pages/workspace.js) embeds mountReportsPanel()
// directly instead.
export async function renderReports(root, { navigate, route }) {
  return mountReportsPanel(root, { caseId: route.caseId, navigate, embedded: false });
}

// Opens a single report or the Triage Ticket into an arbitrary container,
// with no surrounding table — used by the Triage stage card to show the
// ticket without pulling Reporting's table/page into the Triage workflow.
export async function openReportInto(container, { caseId, reportType, mode = "view" }) {
  container.innerHTML = loadingState("Loading…");
  const open = createReportOpener({ caseId, detail: container, tableRoot: null });
  await open(reportType, mode);
}
