import { currentRoute, installRouter, markActiveNavigation, navigate } from "./router.js";
import { renderCases } from "./pages/cases.js";
import { renderOverview } from "./pages/overview.js";
import { renderWorkspace } from "./pages/workspace.js";
import { renderIntegrations } from "./pages/integrations.js";


const root = document.querySelector("#app-content");

async function render() {
  const route = currentRoute();
  markActiveNavigation(route.view);
  const context = { navigate, route };
  if (route.view === "cases") {
    await renderCases(root, context);
  } else if (route.view === "case") {
    await renderWorkspace(root, context);
  } else if (route.view === "integrations") {
    await renderIntegrations(root, context);
  } else {
    await renderOverview(root, context);
  }
}

installRouter(render);
document.documentElement.dataset.aegisShell = "loaded";
render();
