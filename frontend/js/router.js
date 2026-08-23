export function currentRoute() {
  const params = new URLSearchParams(window.location.search);
  const view = params.get("view") || "overview";
  return {
    view: ["case", "cases", "chat", "reports", "search", "pipeline", "integrations", "settings"].includes(view) ? view : "overview",
    caseId: params.get("case"),
    params,
  };
}

export function navigate(view, values = {}) {
  const params = new URLSearchParams();
  params.set("view", view);
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  });
  window.history.pushState({}, "", `/?${params.toString()}`);
  window.dispatchEvent(new Event("aegis:navigate"));
}

export function installRouter(render) {
  window.addEventListener("popstate", render);
  window.addEventListener("aegis:navigate", render);
  document.querySelectorAll("[data-nav]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      navigate(link.dataset.nav || "overview");
    });
  });
}

export function markActiveNavigation(view) {
  const activeView = view === "case" ? "cases" : view;
  document.querySelectorAll("[data-nav]").forEach((link) => {
    link.classList.toggle("active", link.dataset.nav === activeView);
  });
}
