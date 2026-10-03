// =============================================================================
// [FYP-FILE] frontend/js/pages/triageFeedback.js  (route ?view=triage-feedback)
// [FYP-TRIAGE-STEP3] X3 + X6 feedback page: Tuning backlog (false positives =
// rule problems), Suppression proposals (benign-expected = context problems;
// approve requires typing the exact scope and a second analyst), Noisy rules
// (read-only baseline counts) and Triage quality (agreement metrics).
// Never auto-closes or auto-suppresses anything. Every dynamic value is
// escaped with escapeHTML(); no markdown rendering.
// =============================================================================
import { fetchJSON } from "../api.js";
import { emptyState, errorState, escapeHTML, loadingState } from "../ui.js";

async function analystName() {
  const settings = await fetchJSON("/api/settings");
  return settings.analyst_name || window.prompt("Analyst name", "")?.trim() || "";
}

const pct = (x) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(1)}%`);
const num = (x) => (x === null || x === undefined ? "n/a" : Number(x).toFixed(3));

function backlogHTML(data) {
  if (!data.items.length) return emptyState("No false-positive reviews yet.");
  return `<p class="form-help">${escapeHTML(data.note)} Export ADS stubs with <code>python scripts/export_tuning_backlog.py</code>.</p>
    <table class="data-table"><thead><tr><th>FP count</th><th>Detection source</th><th>Signature</th><th>Entity</th><th>Latest tuning notes</th><th>Examples</th><th>First / last seen</th></tr></thead><tbody>
    ${data.items.map((i) => `<tr><td><strong>${escapeHTML(i.fp_count)}</strong></td><td>${escapeHTML(i.detection_source)}</td><td><code>${escapeHTML(i.alert_signature)}</code></td><td>${escapeHTML(i.entity)}</td><td><ul>${i.tuning_notes.map((n) => `<li>${escapeHTML(n)}</li>`).join("")}</ul></td><td>${i.example_incident_ids.map((x) => `<a href="/?view=case&case=${encodeURIComponent(x)}">${escapeHTML(x)}</a>`).join(", ")}</td><td>${escapeHTML(i.first_seen || "")}<br>${escapeHTML(i.last_seen || "")}</td></tr>`).join("")}
    </tbody></table>`;
}

function suppressionActions(p) {
  if (p.status === "proposed") {
    return `<button class="action-button" data-supp-action="approve" data-supp-id="${escapeHTML(p.id)}" data-scope="${escapeHTML(p.scope_text)}">Approve</button><button class="action-button danger" data-supp-action="reject" data-supp-id="${escapeHTML(p.id)}">Reject</button>`;
  }
  if (p.status === "approved") return `<button class="action-button danger" data-supp-action="revoke" data-supp-id="${escapeHTML(p.id)}">Revoke</button>`;
  return "";
}

function suppressionsHTML(data) {
  if (!data.items.length) return emptyState("No suppression proposals. Propose one from a benign-expected triage review.");
  return `<p class="form-help">A suppression never closes or hides an incident: an approved, unexpired match only adds <code>context.suppression_match</code> evidence, and it is ignored whenever strong rule signals or abused-tool hits are present.</p>
    <table class="data-table"><thead><tr><th>#</th><th>Status</th><th>Scope</th><th>Who / when / why</th><th>Proposed</th><th>Expires</th><th>Decided</th><th></th></tr></thead><tbody>
    ${data.items.map((p) => `<tr><td>${escapeHTML(p.id)}</td><td><span class="badge">${escapeHTML(p.status)}</span></td><td><code>${escapeHTML(p.scope_text)}</code></td><td>${escapeHTML(p.benign_context?.who || "")} / ${escapeHTML(p.benign_context?.when || "")} / ${escapeHTML(p.benign_context?.why || "")}</td><td>${escapeHTML(p.proposed_by)}<br><small>${escapeHTML(p.created_at)}</small></td><td>${escapeHTML(p.expires_at)}</td><td>${escapeHTML(p.decided_by || "")}<br><small>${escapeHTML(p.decided_at || "")}</small></td><td><div class="stage-actions">${suppressionActions(p)}</div></td></tr>`).join("")}
    </tbody></table>`;
}

function noisyHTML(data) {
  if (data.status !== "measured") return emptyState(`Noisy-rules report unavailable: ${data.reason || "unknown"}`);
  if (!data.pairs.length) return emptyState("No (detection source, entity) pairs in the window.");
  return `<p class="form-help">Read-only counts from the baseline incidents table, as of ${escapeHTML(data.as_of)} (${escapeHTML(data.reason)}).</p>
    <table class="data-table"><thead><tr><th>Detection source</th><th>Entity</th><th>30 days</th><th>90 days</th><th>Known noisy</th><th>FP reviews</th><th>Benign-expected reviews</th></tr></thead><tbody>
    ${data.pairs.map((p) => `<tr><td>${escapeHTML(p.detection_source)}</td><td>${escapeHTML(p.entity)}</td><td>${escapeHTML(p.count_30d)}</td><td>${escapeHTML(p.count_90d)}</td><td>${p.known_noisy ? "yes" : "no"}</td><td>${escapeHTML(p.fp_reviews)}</td><td>${escapeHTML(p.benign_expected_reviews)}</td></tr>`).join("")}
    </tbody></table>`;
}

function metricsHTML(m) {
  const caveats = (m.caveats || []).map((c) => `<p class="notice notice-error">${escapeHTML(c)}</p>`).join("");
  const pairs = Object.entries(m.pairs || {}).map(([name, p]) => `<tr><td>${escapeHTML(name)}</td><td>${escapeHTML(p.n)}</td><td>${pct(p.observed_agreement)}</td><td>${pct(p.expected_agreement)}</td><td>${num(p.kappa)}${p.degenerate ? " (one label only)" : ""}</td></tr>`).join("");
  const disp = Object.entries(m.per_disposition || {}).map(([d, n]) => `<li><span>${escapeHTML(d)}</span><strong>${escapeHTML(n)} (AI: ${escapeHTML((m.ai_final_per_disposition || {})[d] ?? 0)})</strong></li>`).join("");
  return `${caveats}
    <ul class="data-list"><li><span>Reviews</span><strong>${escapeHTML(m.n_reviews)}</strong></li><li><span>Mentor-labelled (blind)</span><strong>${escapeHTML(m.n_mentor_labelled)}${m.mentor ? ` · ${escapeHTML(m.mentor)}` : ""}</strong></li>
    <li><span>Override rate (analyst ≠ AI final)</span><strong>${pct(m.override_rate)}</strong></li><li><span>Guard intervention rate (AI proposed ≠ final)</span><strong>${pct(m.guard_intervention_rate)}</strong></li>
    <li><span>Needs-info rate</span><strong>${pct(m.needs_info_rate)}</strong></li><li><span>Blind-first: revised after AI reveal</span><strong>${escapeHTML(m.blind_first.revised_after_reveal)} / ${escapeHTML(m.blind_first.n)} (${pct(m.blind_first.revision_after_reveal_rate)})</strong></li></ul>
    <table class="data-table"><thead><tr><th>Pair</th><th>n</th><th>Raw agreement</th><th>Chance</th><th>Cohen's kappa</th></tr></thead><tbody>${pairs}</tbody></table>
    <h3>Per-disposition (analyst)</h3><ul class="data-list">${disp}</ul>`;
}

export async function renderTriageFeedback(root) {
  root.innerHTML = `<header class="page-header"><div><h1>Triage feedback</h1><p>False positives go to rule tuning; benign-expected verdicts become scoped, expiring suppression proposals that a second analyst approves. Nothing is closed or suppressed automatically.</p></div></header>
    <section class="panel" id="tf-backlog"><h2>Tuning backlog</h2>${loadingState()}</section>
    <section class="panel" id="tf-supp" style="margin-top:1rem"><h2>Suppression proposals</h2>${loadingState()}</section>
    <section class="panel" id="tf-noisy" style="margin-top:1rem"><h2>Noisy rules</h2>${loadingState()}</section>
    <section class="panel" id="tf-metrics" style="margin-top:1rem"><h2>Triage quality</h2>${loadingState()}</section>`;

  const load = async (id, url, render) => {
    const el = root.querySelector(id);
    const title = el.querySelector("h2").outerHTML;
    try { el.innerHTML = title + render(await fetchJSON(url)); } catch (error) { el.innerHTML = title + errorState(error); }
    return el;
  };

  const loadSuppressions = async () => {
    const el = await load("#tf-supp", "/api/triage/suppressions", suppressionsHTML);
    el.querySelectorAll("[data-supp-action]").forEach((button) => button.addEventListener("click", async () => {
      const action = button.dataset.suppAction;
      const id = button.dataset.suppId;
      try {
        const analyst = await analystName();
        if (!analyst) return;
        const body = { analyst };
        if (action === "approve") {
          // Same typed-confirmation pattern as the admin endpoints.
          const confirmation = window.prompt(`Type the exact scope to approve suppression #${id}:\n${button.dataset.scope}`) || "";
          if (!confirmation) return;
          body.confirmation = confirmation;
        } else {
          const note = window.prompt(`${action === "revoke" ? "Revoke" : "Reject"} suppression #${id}: reason`) || "";
          if (!note.trim()) return;
          body.note = note.trim();
        }
        await fetchJSON(`/api/triage/suppressions/${encodeURIComponent(id)}/${action}`, { method: "POST", body });
        await loadSuppressions();
      } catch (error) {
        window.alert(`${error.code || "ERROR"}: ${error.message}`);
      }
    }));
  };

  await Promise.all([
    load("#tf-backlog", "/api/triage/tuning-backlog", backlogHTML),
    loadSuppressions(),
    load("#tf-noisy", "/api/triage/noisy-rules", noisyHTML),
    load("#tf-metrics", "/api/triage/metrics", metricsHTML),
  ]);
}
