import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, loadingState } from "../ui.js";


function renderBlock(block) {
  if (block.type === "heading") return `<h${Math.min(Math.max(block.level || 2, 2), 4)}>${escapeHTML(block.text)}</h${Math.min(Math.max(block.level || 2, 2), 4)}>`;
  if (block.type === "bullet_list") return `<ul>${(block.items || []).map(item => `<li>${escapeHTML(item.text ?? item)}</li>`).join("")}</ul>`;
  if (block.type === "table") return `<div class="table-wrap"><table><thead><tr>${(block.columns || []).map(value => `<th>${escapeHTML(value)}</th>`).join("")}</tr></thead><tbody>${(block.rows || []).map(row => `<tr>${row.map(value => `<td>${escapeHTML(value)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  if (block.type === "page_break") return `<hr>`;
  return `<p>${escapeHTML(block.text || "")}</p>`;
}

function reportCards(listing) {
  const reports = [...listing.reports, listing.triage_ticket];
  return reports.map(row => `<button class="report-card" data-report="${escapeHTML(row.report_type)}"><strong>${escapeHTML(row.title)}</strong><span>${escapeHTML(row.status)}</span><small>${row.confirmed ? "Confirmed" : escapeHTML(row.description)}</small></button>`).join("");
}

async function analystName() {
  const settings = await fetchJSON("/api/settings");
  return settings.analyst_name || window.prompt("Analyst name", "")?.trim() || "";
}

export async function renderReports(root, { navigate, route }) {
  const caseId = route.caseId;
  if (!caseId) { root.innerHTML = errorState({ code: "CASE_NOT_SELECTED", message: "Select a case before opening reports." }); return; }
  root.innerHTML = loadingState("Loading report workspace…");
  try {
    let listing = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports`);
    root.innerHTML = `
      <button class="text-button" id="back-case">← Back to case</button>
      <header class="page-header"><div><h1>Report workspace</h1><p>${escapeHTML(caseId)} · ${escapeHTML(listing.reporting_status)} · attempt ${listing.reporting_attempt}</p></div><div class="stage-actions"><a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/reports/data/download">Reporting JSON</a>${listing.reporting_status === "Awaiting Approval" ? `<button class="action-button" id="confirm-final">Confirm final report set</button>` : ""}${listing.export_all_available ? `<a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/reports/export-all">Export all</a>` : ""}</div></header>
      ${listing.warnings.map(value => `<p class="notice">${escapeHTML(value)}</p>`).join("")}
      <div class="reports-layout"><aside class="report-list">${reportCards(listing)}</aside><section class="panel" id="report-detail">${emptyState("Choose a report section.")}</section></div>`;
    root.querySelector("#back-case").addEventListener("click", () => navigate("case", { case: caseId }));
    root.querySelector("#confirm-final")?.addEventListener("click", async () => {
      if (!window.confirm("Approve the hash-verified final report candidate for this run?")) return;
      try {
        const analyst = await analystName();
        await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/final/confirm`, { method: "POST", body: { analyst, run_id: listing.run_id } });
        await renderReports(root, { navigate, route });
      } catch (error) { root.insertAdjacentHTML("afterbegin", errorState(error)); }
    });
    const detail = root.querySelector("#report-detail");
    async function open(reportType) {
      detail.innerHTML = loadingState("Loading report…");
      try {
        let report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}`);
        const show = () => {
          detail.innerHTML = `
            <div class="page-header"><div><h2>${escapeHTML(report.title)}</h2><p>${escapeHTML(report.status)}${report.is_stale ? " · based on an older candidate" : ""}</p></div></div>
            <div class="stage-actions"><button class="action-button" id="edit-report">Edit</button><button class="action-button" id="confirm-report">Confirm section</button><a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/download?format=docx">DOCX</a><a class="action-button" href="/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/download?format=pdf">PDF</a>${report.has_edits ? `<button class="action-button danger" id="discard-report">Replace with AI version</button>` : ""}</div>
            <div id="report-action"></div><article class="report-preview">${(report.blocks || []).map(renderBlock).join("") || emptyState("This report has not been generated.")}</article>`;
          detail.querySelector("#edit-report").addEventListener("click", edit);
          detail.querySelector("#confirm-report").addEventListener("click", confirm);
          detail.querySelector("#discard-report")?.addEventListener("click", discard);
        };
        async function edit() {
          detail.innerHTML = `<h2>Edit ${escapeHTML(report.title)}</h2><p class="form-help">Saved blocks remain server-side and retain candidate identity.</p><textarea class="block-editor">${escapeHTML(JSON.stringify(report.blocks, null, 2))}</textarea><div class="stage-actions"><button class="action-button" id="save-edit">Save changes</button><button class="action-button" id="cancel-edit">Cancel</button></div><div id="report-action"></div>`;
          detail.querySelector("#cancel-edit").addEventListener("click", show);
          detail.querySelector("#save-edit").addEventListener("click", async () => {
            try {
              const analyst = await analystName();
              if (!analyst) throw new Error("Analyst identity is required.");
              const blocks = JSON.parse(detail.querySelector("textarea").value);
              report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}`, { method: "PUT", body: { blocks, analyst, run_id: report.run_id, report_set_id: report.current_report_set_id } });
              show();
            } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
          });
        }
        async function confirm() {
          try {
            const analyst = await analystName();
            report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/confirm`, { method: "POST", body: { analyst, report_set_id: report.current_report_set_id } });
            show();
          } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
        }
        async function discard() {
          if (!window.confirm("Discard saved edits and replace them with the current AI version?")) return;
          try {
            report = await fetchJSON(`/api/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportType)}/draft`, { method: "DELETE", body: { analyst: await analystName() } });
            show();
          } catch (error) { detail.querySelector("#report-action").innerHTML = errorState(error); }
        }
        show();
      } catch (error) { detail.innerHTML = errorState(error); }
    }
    root.querySelectorAll("[data-report]").forEach(button => button.addEventListener("click", () => open(button.dataset.report)));
  } catch (error) { root.innerHTML = errorState(error); }
}
