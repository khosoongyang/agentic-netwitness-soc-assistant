import { fetchJSON } from "../api.js";
import { escapeHTML } from "../ui.js";


function messagesMarkup(messages) {
  if (!messages.length) return `<div class="chat-empty">Ask a security question to begin.</div>`;
  return messages.map(item => `<div class="chat-message ${item.role}"><strong>${item.role === "user" ? "You" : "Aegis"}</strong><div>${escapeHTML(item.content)}</div></div>`).join("");
}

export function installChat(container, { caseId = null } = {}) {
  const messages = [];
  const endpoint = caseId ? `/api/cases/${encodeURIComponent(caseId)}/chat` : "/api/chat";
  container.innerHTML = `
    <div class="chat-context">${caseId ? `Trusted context is resolved server-side for case ${escapeHTML(caseId)}.` : "Global SOC question mode."}</div>
    <div class="chat-messages" aria-live="polite">${messagesMarkup(messages)}</div>
    ${caseId ? `<div class="chat-prompts"><button>Summarise the investigation on this case.</button><button>Explain the key findings for this case.</button><button>What requires analyst attention on this case?</button></div>` : ""}
    <form class="chat-composer"><input name="message" maxlength="8000" required placeholder="Ask Aegis…"><button class="action-button" type="submit">Send</button></form>`;
  const output = container.querySelector(".chat-messages");
  const form = container.querySelector("form");
  async function send(message) {
    message = message.trim();
    if (!message) return;
    messages.push({ role: "user", content: message });
    output.innerHTML = `${messagesMarkup(messages)}<div class="chat-message assistant"><span class="spinner"></span>Analysing trusted context…</div>`;
    form.elements.message.value = "";
    form.querySelector("button").disabled = true;
    try {
      const response = await fetchJSON(endpoint, { method: "POST", body: { message } });
      messages.push({ role: "assistant", content: response.message });
    } catch (error) {
      messages.push({ role: "assistant", content: `${error.code || "CHAT_UNAVAILABLE"}: ${error.message}` });
    } finally {
      form.querySelector("button").disabled = false;
      output.innerHTML = messagesMarkup(messages);
      output.scrollTop = output.scrollHeight;
    }
  }
  form.addEventListener("submit", event => { event.preventDefault(); send(form.elements.message.value); });
  container.querySelectorAll(".chat-prompts button").forEach(button => button.addEventListener("click", () => send(button.textContent)));
}

export async function renderChat(root) {
  root.innerHTML = `<header class="page-header"><div><h1>Ask Aegis</h1><p>Security analysis using the existing Aegis chatbot behavior.</p></div></header><section class="panel"><div id="global-chat"></div></section>`;
  installChat(root.querySelector("#global-chat"));
}
