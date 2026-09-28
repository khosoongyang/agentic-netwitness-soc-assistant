import { fetchJSON } from "../api.js";
import { errorState, escapeHTML, loadingState } from "../ui.js";

export async function renderSettings(root) {
  root.innerHTML = loadingState("Loading settings…");
  try {
    let settings = await fetchJSON("/api/settings");
    root.innerHTML = `<header class="page-header"><div><h1>Settings</h1><p>Analyst identity and secret-safe OpenAI configuration.</p></div></header><div class="integration-grid"><section class="panel"><h2>Workspace</h2><form class="settings-form" id="settings-form"><label>Analyst display name<input name="analyst_name" maxlength="120" value="${escapeHTML(settings.analyst_name)}"></label><label>OpenAI model<input name="openai_model" value="${escapeHTML(settings.openai_model)}"></label><label>Replace OpenAI API key<input name="openai_api_key" type="password" autocomplete="new-password" placeholder="Leave blank to keep current key"></label><label class="check-field"><input name="developer_mode" type="checkbox"${settings.developer_mode ? " checked" : ""}> Enable developer tools</label><div class="stage-actions"><button class="action-button" type="submit">Save settings</button><button class="action-button danger" id="clear-openai" type="button">Clear OpenAI key</button></div></form><div id="settings-result"></div></section><section class="panel"><h2>Status</h2><ul class="data-list"><li><span>OpenAI</span><strong>${settings.openai_configured ? "Configured" : "Not configured"}</strong></li><li><span>Model</span><strong>${escapeHTML(settings.openai_model)}</strong></li><li><span>Workflow storage</span><strong>Configured</strong></li><li><span>Runtime storage</span><strong>${escapeHTML(settings.storage.runtime_directory)}</strong></li></ul><p class="form-help">Existing secrets are never returned to this page.</p><hr><h3>Developer vector actions</h3><div class="stage-actions"><button class="action-button" id="sync-vectors">Synchronize vectors</button><button class="action-button danger" id="wipe-vectors">Wipe incident vectors</button></div></section></div>`;
    const form = root.querySelector("#settings-form"); const result = root.querySelector("#settings-result");
    async function save(extra = {}) {
      const values = new FormData(form);
      try {
        settings = await fetchJSON("/api/settings", { method: "PUT", body: { analyst_name: values.get("analyst_name"), openai_model: values.get("openai_model"), openai_api_key: values.get("openai_api_key") || undefined, developer_mode: values.get("developer_mode") === "on", ...extra } });
        form.elements.openai_api_key.value = ""; result.innerHTML = `<p class="notice">Settings saved. OpenAI is ${settings.openai_configured ? "configured" : "not configured"}.</p>`;
      } catch (error) { result.innerHTML = errorState(error); }
    }
    form.addEventListener("submit", event => { event.preventDefault(); save(); });
    root.querySelector("#clear-openai").addEventListener("click", () => { if (window.confirm("Clear the server-side OpenAI key for this process?")) save({ clear_openai_api_key: true }); });
    root.querySelector("#sync-vectors").addEventListener("click", async () => { try { const value = await fetchJSON("/api/admin/vector/sync", { method: "POST", body: {} }); result.innerHTML = `<p class="notice">Synchronized ${value.synchronized} vectors.</p>`; } catch (error) { result.innerHTML = errorState(error); } });
    root.querySelector("#wipe-vectors").addEventListener("click", async () => { const confirmation = window.prompt("Type WIPE soc_incidents to clear the collection.") || ""; if (!confirmation) return; try { await fetchJSON("/api/admin/vector/collections/soc_incidents", { method: "DELETE", body: { confirmation } }); result.innerHTML = `<p class="notice">Incident vector collection cleared.</p>`; } catch (error) { result.innerHTML = errorState(error); } });
  } catch (error) { root.innerHTML = errorState(error); }
}
