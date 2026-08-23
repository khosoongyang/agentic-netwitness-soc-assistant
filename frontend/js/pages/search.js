import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, loadingState } from "../ui.js";

export async function renderSearch(root, { navigate }) {
  root.innerHTML = `<header class="page-header"><div><h1>Semantic search</h1><p>Search incident context through the server-owned vector store.</p></div></header><section class="panel"><div id="vector-status">${loadingState("Checking vector store…")}</div><form class="filters" id="search-form"><input name="query" required placeholder="e.g. ransomware lateral movement C2"><select name="limit"><option>5</option><option>10</option><option>20</option></select><button>Search</button></form><div id="search-results"></div></section>`;
  const status = root.querySelector("#vector-status");
  try { const value = await fetchJSON("/api/search/status"); status.innerHTML = `<p class="notice">${value.available ? `${value.vectors} vectors available` : escapeHTML(value.message || "Vector store unavailable")}</p>`; } catch (error) { status.innerHTML = errorState(error); }
  root.querySelector("form").addEventListener("submit", async event => {
    event.preventDefault(); const output = root.querySelector("#search-results"); output.innerHTML = loadingState("Searching…");
    try {
      const data = new FormData(event.currentTarget);
      const result = await fetchJSON("/api/search", { method: "POST", body: { query: data.get("query"), limit: Number(data.get("limit")) } });
      output.innerHTML = result.items.length ? `<ul class="search-results">${result.items.map(item => `<li><button data-case="${escapeHTML(item.id)}"><strong>${escapeHTML(item.id)}</strong><span>${item.score}%</span><p>${escapeHTML(item.text)}</p></button></li>`).join("")}</ul>` : emptyState("No semantic matches found.");
      output.querySelectorAll("[data-case]").forEach(button => button.addEventListener("click", () => navigate("case", { case: button.dataset.case })));
    } catch (error) { output.innerHTML = errorState(error); }
  });
}
