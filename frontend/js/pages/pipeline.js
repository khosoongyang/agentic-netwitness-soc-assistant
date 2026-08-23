import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, loadingState } from "../ui.js";

export async function renderPipeline(root) {
  root.innerHTML = loadingState("Loading pipeline inspection tools…");
  try {
    const summary = await fetchJSON("/api/pipeline");
    root.innerHTML = `<header class="page-header"><div><h1>Data pipeline</h1><p>Read-only stage inspection with separated developer operations.</p></div></header><div class="pipeline-grid">${summary.stages.map(stage => `<button class="pipeline-card" data-stage="${stage.key}"><strong>${escapeHTML(stage.label)}</strong><span>${stage.count} records</span><small>${escapeHTML(stage.last_write || "Never written")}</small></button>`).join("")}</div><section class="panel pipeline-records" id="pipeline-records">${emptyState("Choose a pipeline stage.")}</section>`;
    const output = root.querySelector("#pipeline-records");
    async function load(stage) {
      output.innerHTML = loadingState("Loading records…");
      try {
        const result = await fetchJSON(`/api/pipeline/${encodeURIComponent(stage)}/records?limit=100`);
        output.innerHTML = `<div class="page-header"><div><h2>${escapeHTML(result.label)}</h2><p>${result.total} records</p></div><button class="action-button danger" id="clear-stage">Clear stage</button></div><form class="filters" id="pipeline-search"><input name="query" required placeholder="Semantic search in this stage"><button>Search vectors</button><button type="button" id="browse-vectors">Browse vectors</button></form><div id="pipeline-vectors"></div>${result.items.length ? `<div class="pipeline-list">${result.items.map(item => `<article><div><strong>${escapeHTML(item.id)}</strong><span>${escapeHTML(item.severity || "")}</span></div><p>${escapeHTML(item.title || item.summary || "")}</p><div class="stage-actions"><a class="action-button" href="/api/pipeline/${encodeURIComponent(stage)}/records/${encodeURIComponent(item.id)}/download?format=csv">CSV</a><button class="action-button" data-json="${escapeHTML(item.id)}">Raw JSON</button><button class="action-button danger" data-delete="${escapeHTML(item.id)}">Delete</button></div><pre class="json-preview" data-json-output="${escapeHTML(item.id)}" hidden>${escapeHTML(JSON.stringify(item.raw, null, 2))}</pre></article>`).join("")}</div>` : emptyState("No records in this stage.")}`;
        const vectorOutput = output.querySelector("#pipeline-vectors");
        const renderVectors = items => { vectorOutput.innerHTML = items.length ? `<ul class="search-results">${items.map(item => `<li><button><strong>${escapeHTML(item.id)}</strong>${item.score !== undefined ? `<span>${item.score}%</span>` : ""}<p>${escapeHTML(item.text)}</p></button></li>`).join("")}</ul>` : emptyState("No vectors found."); };
        output.querySelector("#pipeline-search").addEventListener("submit", async event => { event.preventDefault(); vectorOutput.innerHTML = loadingState("Searching vectors…"); try { const data = await fetchJSON("/api/search", { method: "POST", body: { stage, query: new FormData(event.currentTarget).get("query"), limit: 10 } }); renderVectors(data.items); } catch (error) { vectorOutput.innerHTML = errorState(error); } });
        output.querySelector("#browse-vectors").addEventListener("click", async () => { vectorOutput.innerHTML = loadingState("Loading vectors…"); try { const data = await fetchJSON(`/api/search/vectors?stage=${encodeURIComponent(stage)}&limit=100`); renderVectors(data.items); } catch (error) { vectorOutput.innerHTML = errorState(error); } });
        output.querySelectorAll("[data-json]").forEach(button => button.addEventListener("click", () => { const preview = output.querySelector(`[data-json-output="${CSS.escape(button.dataset.json)}"]`); preview.hidden = !preview.hidden; }));
        output.querySelectorAll("[data-delete]").forEach(button => button.addEventListener("click", async () => {
          const id = button.dataset.delete; const confirmation = window.prompt(`Type DELETE ${stage}/${id} to permanently delete this record.`) || "";
          if (!confirmation) return;
          try { await fetchJSON(`/api/admin/pipeline/${encodeURIComponent(stage)}/records/${encodeURIComponent(id)}`, { method: "DELETE", body: { confirmation } }); await load(stage); } catch (error) { window.alert(`${error.code}: ${error.message}`); }
        }));
        output.querySelector("#clear-stage").addEventListener("click", async () => {
          const confirmation = window.prompt(`Type CLEAR ${stage} to permanently clear this stage.`) || "";
          if (!confirmation) return;
          try { await fetchJSON(`/api/admin/pipeline/${encodeURIComponent(stage)}`, { method: "DELETE", body: { confirmation } }); await load(stage); } catch (error) { window.alert(`${error.code}: ${error.message}`); }
        });
      } catch (error) { output.innerHTML = errorState(error); }
    }
    root.querySelectorAll("[data-stage]").forEach(button => button.addEventListener("click", () => load(button.dataset.stage)));
  } catch (error) { root.innerHTML = errorState(error); }
}
