import { fetchJSON } from "../api.js";
import { escapeHTML, loadingState } from "../ui.js";


function statusMarkup(status) {
  const state = status.verified ? "Connected and verified" : status.authenticated ? "Token configured" : status.configured ? "Configured" : "Not configured";
  return `
    <div class="integration-status">
      <strong>${escapeHTML(state)}</strong>
      <span>${escapeHTML(status.base_url || "No NetWitness host configured")}</span>
      <span>TLS verification: ${status.verify_tls ? "enabled" : "disabled (explicit compatibility mode)"}</span>
    </div>`;
}

function setResult(root, message, error = false) {
  const output = root.querySelector("#integration-result");
  output.className = `notice${error ? " notice-error" : ""}`;
  output.textContent = message;
  output.hidden = false;
}

function connectionValues(form) {
  const data = new FormData(form);
  return {
    base_url: data.get("base_url"),
    username: data.get("username"),
    password: data.get("password"),
    auth_style: data.get("auth_style"),
    verify_tls: data.get("verify_tls") === "on",
    ca_certificate: data.get("ca_certificate"),
  };
}

export async function renderIntegrations(root, { navigate }) {
  root.innerHTML = loadingState("Loading integration status…");
  let status;
  try {
    status = await fetchJSON("/api/integrations/netwitness/status");
  } catch (error) {
    root.innerHTML = `<div class="state-panel error">${escapeHTML(error.message)}</div>`;
    return;
  }
  root.innerHTML = `
    <header class="page-header">
      <div><h1>NetWitness &amp; imports</h1><p>Connect, synchronize incidents, or import a supported incident file.</p></div>
    </header>
    <div class="integration-grid">
      <section class="panel">
        <h2>NetWitness connection</h2>
        <div id="netwitness-status">${statusMarkup(status)}</div>
        <form id="netwitness-form" class="settings-form" autocomplete="off">
          <label>Host URL<input name="base_url" type="url" required value="${escapeHTML(status.base_url)}" placeholder="https://netwitness.example"></label>
          <label>Username<input name="username" autocomplete="off"></label>
          <label>Password<input name="password" type="password" autocomplete="new-password"></label>
          <label>Authentication style<select name="auth_style">
            ${["NetWitness-Token", "Bearer", "Cookie", "Both"].map(value => `<option${status.auth_style === value ? " selected" : ""}>${value}</option>`).join("")}
          </select></label>
          <label>CA certificate path<input name="ca_certificate" autocomplete="off" placeholder="Server-side path (optional)"></label>
          <label class="check-field"><input name="verify_tls" type="checkbox"${status.verify_tls ? " checked" : ""}> Verify TLS certificates</label>
          <p class="form-help">Disabling TLS verification is an explicit compatibility option for existing lab deployments.</p>
          <div class="stage-actions">
            <button class="action-button" type="submit">Sign in</button>
            <button class="action-button" id="test-connection" type="button">Test connection</button>
          </div>
        </form>
        <form id="token-form" class="settings-form compact" autocomplete="off">
          <label>Manual token<input name="token" type="password" required autocomplete="new-password"></label>
          <button class="action-button" type="submit">Verify token</button>
        </form>
      </section>
      <section class="panel">
        <h2>Incident ingestion</h2>
        <p class="form-help">Synchronization is manual in Phase 5 and runs entirely on the server.</p>
        <div class="stage-actions">
          <button class="action-button" id="sync-netwitness" type="button">Synchronize NetWitness</button>
          <button class="action-button" id="view-cases" type="button">View cases</button>
        </div>
        <hr>
        <h3>Import incident file</h3>
        <form id="import-form" class="settings-form">
          <label>JSON, CSV, TXT, or LOG<input name="file" type="file" accept=".json,.csv,.txt,.log" required></label>
          <label>Expected incident ID <span class="optional">optional identity guard</span><input name="incident_id"></label>
          <button class="action-button" type="submit">Import incident</button>
        </form>
      </section>
    </div>
    <div id="integration-result" class="notice" hidden></div>`;

  const connectionForm = root.querySelector("#netwitness-form");
  connectionForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = connectionForm.elements.password;
    try {
      const updated = await fetchJSON("/api/integrations/netwitness/login", { method: "POST", body: connectionValues(connectionForm) });
      root.querySelector("#netwitness-status").innerHTML = statusMarkup(updated);
      setResult(root, "NetWitness authentication and token verification succeeded.");
    } catch (error) {
      setResult(root, error.message, true);
    } finally {
      password.value = "";
    }
  });

  root.querySelector("#token-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const tokenInput = event.currentTarget.elements.token;
    try {
      const values = connectionValues(connectionForm);
      values.token = tokenInput.value;
      const updated = await fetchJSON("/api/integrations/netwitness/token", { method: "POST", body: values });
      root.querySelector("#netwitness-status").innerHTML = statusMarkup(updated);
      setResult(root, "The NetWitness token was verified.");
    } catch (error) {
      setResult(root, error.message, true);
    } finally {
      tokenInput.value = "";
    }
  });

  root.querySelector("#test-connection").addEventListener("click", async () => {
    try {
      await fetchJSON("/api/integrations/netwitness/test", { method: "POST", body: {} });
      setResult(root, "NetWitness connection test passed.");
    } catch (error) {
      setResult(root, error.message, true);
    }
  });

  root.querySelector("#sync-netwitness").addEventListener("click", async (event) => {
    event.currentTarget.disabled = true;
    try {
      const summary = await fetchJSON("/api/integrations/netwitness/sync", { method: "POST", body: {} });
      setResult(root, `Sync complete: ${summary.fetched} fetched, ${summary.added} added, ${summary.updated} updated, ${summary.skipped} skipped.`);
    } catch (error) {
      setResult(root, error.message, true);
    } finally {
      event.currentTarget.disabled = false;
    }
  });

  root.querySelector("#import-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const result = await fetchJSON("/api/imports/incidents", { method: "POST", body: new FormData(form) });
      setResult(root, `Imported incident ${result.incident_id}. It is now available in Cases.`);
      form.reset();
    } catch (error) {
      setResult(root, error.message, true);
    }
  });
  root.querySelector("#view-cases").addEventListener("click", () => navigate("cases"));
}
