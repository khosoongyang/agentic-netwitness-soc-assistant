import { fetchJSON } from "./api.js";
import { currentRoute } from "./router.js";

const COLLAPSE_STORAGE_KEY = "aegis:ask-aegis-collapsed";

const panel = document.querySelector("#ask-aegis-panel");
const collapseButton = document.querySelector("#ask-aegis-collapse-toggle");
const fab = document.querySelector("#ask-aegis-fab");
const promptsBar = document.querySelector("#ask-aegis-prompts");
const contextBar = document.querySelector("#ask-aegis-context");
const messagesEl = document.querySelector("#ask-aegis-messages");
const form = document.querySelector("#ask-aegis-composer");
const input = document.querySelector("#ask-aegis-input");
const sendButton = form?.querySelector(".ask-aegis-send");

if (panel && collapseButton && fab) {
  function setCollapsed(collapsed) {
    panel.classList.toggle("collapsed", collapsed);
    fab.classList.toggle("visible", collapsed);
    collapseButton.setAttribute("aria-expanded", String(!collapsed));
    fab.setAttribute("aria-expanded", String(!collapsed));
    try {
      localStorage.setItem(COLLAPSE_STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      // Ignore storage failures (e.g. private browsing); collapse still works for this session.
    }
  }

  let storedCollapsed = false;
  try {
    storedCollapsed = localStorage.getItem(COLLAPSE_STORAGE_KEY) === "1";
  } catch {
    storedCollapsed = false;
  }
  setCollapsed(storedCollapsed);

  collapseButton.addEventListener("click", () => setCollapsed(true));
  fab.addEventListener("click", () => setCollapsed(false));
}

const ROBOT_AVATAR_IMG = `<img src="/frontend/assets/aegis-avatar.png" alt="">`;

function avatarMarkup(role) {
  if (role === "user") return `<span class="ask-aegis-msg-avatar user" aria-hidden="true">SK</span>`;
  return `<span class="ask-aegis-msg-avatar assistant" aria-hidden="true">${ROBOT_AVATAR_IMG}</span>`;
}

function renderMarkdown(content) {
  const html = window.marked.parse(content, { breaks: true, gfm: true });
  return window.DOMPurify.sanitize(html);
}

if (messagesEl && form && input) {
  const messages = [
    { role: "assistant", content: "Hi, I'm Aegis. I can help you understand this incident, its findings, and recommended next steps." },
  ];
  let sending = false;

  function activeCase() {
    const route = currentRoute();
    return route.view === "case" && route.caseId ? route.caseId : null;
  }

  function endpointFor(caseId) {
    return caseId ? `/api/cases/${encodeURIComponent(caseId)}/chat` : "/api/chat";
  }

  function renderContext() {
    const caseId = activeCase();
    contextBar.textContent = caseId ? `Context: ${caseId}` : "";
  }

  function renderMessages() {
    messagesEl.innerHTML = messages
      .map((item) => `<div class="ask-aegis-message ${item.role}">${avatarMarkup(item.role)}<div class="ask-aegis-bubble">${renderMarkdown(item.content)}</div></div>`)
      .join("");
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function setSending(state) {
    sending = state;
    sendButton.disabled = state;
    input.disabled = state;
  }

  async function send(message) {
    message = message.trim();
    if (!message || sending) return;
    messages.push({ role: "user", content: message });
    renderMessages();
    input.value = "";
    setSending(true);
    messagesEl.insertAdjacentHTML("beforeend", `<div class="ask-aegis-message assistant">${avatarMarkup("assistant")}<div class="ask-aegis-bubble ask-aegis-typing"><span class="spinner" aria-hidden="true"></span>Analysing trusted context…</div></div>`);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    try {
      const response = await fetchJSON(endpointFor(activeCase()), { method: "POST", body: { message } });
      messages.push({ role: "assistant", content: response.message });
    } catch (error) {
      messages.push({ role: "assistant", content: `${error.code || "CHAT_UNAVAILABLE"}: ${error.message}` });
    } finally {
      setSending(false);
      renderMessages();
    }
  }

  promptsBar?.querySelectorAll("button[data-prompt]").forEach((button) => {
    button.addEventListener("click", () => send(button.dataset.prompt));
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    send(input.value);
  });

  window.addEventListener("popstate", renderContext);
  window.addEventListener("aegis:navigate", renderContext);

  renderContext();
  renderMessages();
}
