"""
# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, html, math, typing, urllib.
# Key evaluator search terms: _e, sev_class, page_title, pill, hero, stat_row, [FYP-FUNCTION].
# =============================================================================
# File:
#   ui_components.py
#
# Purpose:
#   Shared "Aegis" design-system component library for the Streamlit SOC
#   dashboard — pure Python functions that each return a raw HTML string
#   (plus one shared <style> block) to be rendered via
#   `st.markdown(html, unsafe_allow_html=True)`. Ported from the team's
#   "Aegis" dashboard mockup (agentic-netwitness-soc-assistant-feature-
#   dashboard-ui-mockup) so the Streamlit app's look matches that reference
#   design instead of default Streamlit widgets. Colours reference the app's
#   existing `:root` CSS vars (--blue/--amber/--red/--text/--sub/…) defined
#   in app.py's base theme, so these components inherit whatever theme is
#   active rather than hard-coding a second palette.
#
# Main functionalities [FYP-UI]:
#   1. COMPONENT_CSS: one <style> block (all `.ag-*` classes) injected ONCE
#      per page load — see app.py's `_ui.COMPONENT_CSS` usage.
#   2. Builder functions, one per visual pattern — pills/severity badges
#      (pill/sev_class), page headers (page_title), the circular SOC-pipeline
#      diagram (circular_pipeline/stepper), case header banners
#      (case_header/case_header_left/case_header_right), key-findings rows
#      (key_findings), the Overview context grid (context_grid), generic
#      panel wrappers (panel_open/panel_close), the "My Queue" table
#      (queue_table), the sidebar workspace identity card (workspace_card),
#      SOC attention/stat metric rows (attention_row/stat_row), the AI
#      summary card incl. fallback-text detection (ai_summary/
#      detect_fallback), the MITRE ATT&CK kill-chain strip (mitre_strip) and
#      the evidence-backed MITRE mapping workspace (mitre_mapping_workspace),
#      the agent-completion ring (agent_ring), the Reports-tab file-row head
#      (report_file_head), and a human-friendly timestamp formatter
#      (humanize_timestamp).
#   3. Some builders exist in the module but have NO confirmed caller
#      anywhere in the repo today (verified via grep for `.<name>(` outside
#      this file) — hero, stat_row, stepper, case_workflow,
#      case_header_left, case_header_right, agent_ring, mitre_strip. They
#      are kept as part of the ported component set (mockup parity /
#      available-but-unused) rather than being dead code left over from a
#      removed feature; do not assume any of them render anywhere in the
#      live app today.
#
# Inputs:
#   Plain dicts/tuples/strings/iterables assembled by the calling page
#   (app.py) from case/incident/pipeline data — this module never reads
#   session state, the DB, or any other module's data itself.
#
# Outputs:
#   Escaped (via `_e`/`html.escape`) HTML strings, safe to pass straight to
#   `st.markdown(..., unsafe_allow_html=True)`.
#
# Workflow position:
#   A leaf UI-rendering layer with no Streamlit import and no knowledge of
#   the SOC workflow — pure string builders that unit-test offline. Sits
#   below app.py (and, per in-file comments only — see below, not an actual
#   import — the general `pill()` tone vocabulary is referenced by
#   report_editing.py's STATUS_TONES for visual consistency).
#
# Called by [FYP-USED-BY] (confirmed via grep for `import ui_components`):
#   * app.py — the ONLY module that actually imports this file.
#     - `import ui_components as _ui` (module-level, ~line 3368): 46 call
#       sites across the dashboard using 17 distinct names — queue_table(7),
#       detect_fallback(7), ai_summary(7), pill(6), humanize_timestamp(3),
#       sev_class(2), report_file_head(2), panel_open(2), panel_close(2),
#       page_title(2), mitre_mapping_workspace(1), key_findings(1),
#       context_grid(1), circular_pipeline(1), case_header(1),
#       attention_row(1), COMPONENT_CSS(1).
#     - `import ui_components as _uisb` (guarded, local, Settings-page
#       sidebar block, ~line 8542): renders the sidebar's
#       `workspace_card(...)` identity card before the main `_ui` import has
#       necessarily run for that render pass.
#   * case_view.py and report_editing.py mention "ui_components.py" / its
#     pill() tone vocabulary only in prose comments (e.g. report_editing.py's
#     STATUS_TONES comment) — NEITHER file actually imports this module
#     (confirmed: no `import ui_components` / `from ui_components` statement
#     in either file). Do not describe them as callers.
#
# Calls [FYP-CALLS]:
#   Standard library only (`html`, `math`, `urllib.parse.quote`, `datetime`
#   inside humanize_timestamp) — this module imports nothing else from the
#   repo, by design (keeps it a dependency-free, offline-testable leaf).
#
# Key evaluator search terms [FYP-EVALUATOR]:
#   [FYP-UI], circular_pipeline (the SOC-pipeline ring diagram),
#   mitre_mapping_workspace (origin-tagged MITRE cards — see its own
#   docstring on why it never fabricates a confidence percentage),
#   detect_fallback/ai_summary (the "Fallback logic" amber-tag mechanism),
#   COMPONENT_CSS (the single injected stylesheet).
# =============================================================================

ui_components.py — Aegis design-system components for the Streamlit SOC dashboard.

Reusable HTML component builders + their CSS, ported from the team's "Aegis"
dashboard mockup (agentic-netwitness-soc-assistant-feature-dashboard-ui-mockup).
Each builder returns an HTML string to render with
`st.markdown(html, unsafe_allow_html=True)`; inject COMPONENT_CSS once per page
(app.py does this next to its base theme). Colours reference the app's existing
`:root` CSS vars (--blue/--amber/--red…) so components inherit the theme.

Pure string builders — no Streamlit import, so they unit-test offline.
"""

from __future__ import annotations

import html as _html
import math
from typing import Any, Iterable
from urllib.parse import quote as _url_quote

# ── shared CSS (inject once) ──────────────────────────────────────────────────
COMPONENT_CSS = """
<style>
/* ===== Aegis components ===== */
html, body, .stApp, p, div:not([data-testid*="Icon"]), button, input, select, textarea, label, h1, h2, h3, h4, h5, h6 {
  font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif;
}
[data-testid*="Icon"], [class*="material-symbols"], [class*="material-icons"] {
  font-family: 'Material Symbols Rounded', 'Material Icons', sans-serif !important;
}
.ag-eyebrow{color:var(--sub);font-size:.68rem;font-weight:800;letter-spacing:.14em;
  text-transform:uppercase;margin-bottom:2px;}
.ag-page-title{font-size:1.7rem;font-weight:800;letter-spacing:-.5px;color:var(--text);margin:0 0 2px;}
.ag-page-sub{color:var(--sub);font-size:.85rem;margin:0 0 14px;}

/* pills */
.ag-pill{display:inline-flex;align-items:center;border:1px solid;border-radius:99px;
  padding:2px 9px;font-size:.68rem;font-weight:800;white-space:nowrap;line-height:1.5;}
.ag-critical{color:#ff99a3;border-color:#713744;background:#321b25;}
.ag-high{color:#f3c679;border-color:#684c2a;background:#2b221a;}
.ag-medium{color:#c9a6f7;border-color:#5b3f82;background:#241a34;}
.ag-low{color:#7fe0ac;border-color:#2a6146;background:#122b21;}
.ag-info,.ag-stage-pill{color:#aeb7ff;border-color:#3b4c81;background:#192743;}
.ag-wait{color:#9eacc0;border-color:#35445a;background:#16202e;}
.ag-open{color:#9fa9ff;border-color:#3b4c81;background:#171f3a;}

/* hero next-move */
.ag-hero{border:1px solid #633645;border-radius:14px;padding:16px 18px;
  background:linear-gradient(105deg,#351d2acc,#111b2c 58%);
  display:flex;align-items:center;gap:14px;box-shadow:0 16px 45px #0005;margin:6px 0 4px;}
.ag-hero.blue{border-color:#33407a;background:linear-gradient(105deg,#1a2350cc,#111b2c 58%);}
.ag-hero-icon{width:42px;height:42px;min-width:42px;border:1px solid #6e3542;border-radius:12px;
  background:#351c27;color:#ff8b96;display:grid;place-items:center;font-size:20px;}
.ag-hero.blue .ag-hero-icon{border-color:#3b4c81;background:#192743;color:#aeb7ff;}
.ag-hero-body{flex:1;min-width:0;}
.ag-hero-body .e{color:#ff939d;font-size:.66rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase;}
.ag-hero.blue .ag-hero-body .e{color:#aeb7ff;}
.ag-hero-body h4{margin:3px 0 2px;font-size:.98rem;font-weight:700;color:var(--text);}
.ag-hero-body p{margin:0;color:#a8b5c6;font-size:.75rem;}
.ag-cta{height:34px;border-radius:9px;padding:0 14px;display:grid;place-items:center;
  background:linear-gradient(135deg,#7381f6,#5361d5);color:#fff;font-size:.72rem;font-weight:800;
  box-shadow:0 8px 22px #3a459466;white-space:nowrap;}

/* stat cards */
.ag-stats{display:flex;gap:12px;margin:6px 0;}
.ag-stat{flex:1;border:0;border-radius:14px;padding:15px 16px;
  background:linear-gradient(145deg,#111c2d,#0c1523);position:relative;overflow:hidden;}
.ag-stat .lbl{color:#a6b2c4;font-size:.72rem;font-weight:600;}
.ag-stat .val{display:block;font-size:1.9rem;font-weight:800;letter-spacing:-.5px;margin:6px 0 2px;color:var(--text);}
.ag-stat .sub{font-size:.7rem;color:var(--sub);}
.ag-stat.red .val{color:#ff8c97;}   .ag-stat.amber .val{color:#f3c36f;}
.ag-stat.blue .val{color:#9fa9ff;}  .ag-stat.green .val{color:#7fe0ac;}

/* stage stepper */
.ag-stepper{display:flex;gap:0;margin:14px 0 2px;}
.ag-step{flex:1;text-align:center;position:relative;padding-top:4px;}
.ag-step:not(:first-child)::before{content:"";position:absolute;top:20px;left:-50%;width:100%;
  height:2px;background:#27344a;z-index:0;}
.ag-step.done::before,.ag-step.current::before{background:var(--blue);}
.ag-node{position:relative;z-index:1;width:32px;height:32px;border-radius:50%;margin:0 auto;
  display:grid;place-items:center;font-weight:800;font-size:.75rem;border:2px solid;}
.ag-node.done{background:#1d2948;border-color:var(--blue);color:#fff;}
.ag-node.current{background:#2b221a;border-color:var(--amber);color:var(--amber);
  box-shadow:0 0 0 4px #f4bc5f18;}
.ag-node.queued,.ag-node.idle{background:#0e1929;border-color:#27344a;color:var(--faint);}
.ag-step b{display:block;font-size:.74rem;margin-top:8px;color:var(--text);}
.ag-step small{display:block;font-size:.64rem;color:var(--faint);margin-top:1px;}

.ag-casehdr-left{display:flex;gap:14px;align-items:flex-start;}
.ag-casehdr-left .ico{width:42px;height:42px;min-width:42px;border-radius:12px;display:grid;place-items:center;
  font-size:20px;border:1px solid #713744;background:#321b25;color:#ff8b96;}
.ag-casehdr-left .body{flex:1;min-width:0;}
.ag-casehdr-left .tid{font-family:var(--mono);font-size:.68rem;color:var(--sub);letter-spacing:.05em;}
.ag-casehdr-left h3{margin:5px 0 3px;font-size:1.05rem;color:var(--text);}
.ag-casehdr-left .sub{color:var(--sub);font-size:.75rem;}
.ag-casehdr{display:grid;grid-template-columns:42px minmax(260px,1fr) auto;align-items:center;gap:12px;
  padding:14px 16px;border:1px solid #293b57;border-radius:12px;
  background:#0d1929;box-shadow:0 10px 28px #0002;margin:8px 0 12px;}
.ag-casehdr .ico{width:40px;height:40px;min-width:40px;border-radius:10px;display:grid;place-items:center;
  font-size:17px;border:1px solid #35445a;background:#16202e;color:#9eacc0;}
.ag-casehdr.ag-critical{border-left:3px solid #ff6e7c;}
.ag-casehdr.ag-high{border-left:3px solid #f3b85c;}
.ag-casehdr.ag-medium{border-left:3px solid #b88af2;}
.ag-casehdr.ag-low{border-left:3px solid #56d89a;}
.ag-casehdr.ag-critical .ico{border-color:#713744;background:#321b25;color:#ff99a3;}
.ag-casehdr.ag-high .ico{border-color:#684c2a;background:#2b221a;color:#f3c679;}
.ag-casehdr.ag-medium .ico{border-color:#5b3f82;background:#241a34;color:#c9a6f7;}
.ag-casehdr.ag-low .ico{border-color:#2a6146;background:#122b21;color:#7fe0ac;}
.ag-casehdr .body{min-width:0;}
.ag-casehdr .tid{display:flex;align-items:center;flex-wrap:wrap;gap:5px;
  font-family:var(--mono);font-size:1.05rem!important;font-weight:700;color:#c6d4eb;letter-spacing:.03em;}
.ag-casehdr .tid .ag-pill{font-family:'IBM Plex Sans','Segoe UI',sans-serif;letter-spacing:0;}
.ag-casehdr .tid .ag-pill{padding:3px 9px;font-size:.95rem!important;line-height:1.45;}
.ag-casehdr h3{margin:8px 0 5px;font-size:2rem!important;line-height:1.25;color:#f4f7fb;
  font-weight:800;overflow-wrap:anywhere;}
.ag-casehdr .sub{color:#91a3bd;font-size:1rem!important;}
.ag-metas{display:flex;gap:8px;justify-content:flex-end;margin-bottom:8px;}
.ag-meta{border:1px solid #293b57;border-radius:9px;padding:8px 10px;background:#091422;min-width:92px;}
.ag-meta span{display:block;color:#7185a2;font-size:.58rem;text-transform:uppercase;letter-spacing:.08em;
  white-space:nowrap;margin-bottom:3px;}
.ag-meta b{display:block;font-size:.7rem;line-height:1.25;color:#fff;font-weight:700;white-space:nowrap;}
.ag-casehdr .ag-metas{margin:0;flex-wrap:nowrap;max-width:none;}
@media(max-width:900px){
  .ag-casehdr{grid-template-columns:auto minmax(0,1fr);}
  .ag-casehdr .ag-metas{grid-column:1/-1;flex-direction:row;justify-content:flex-start;width:100%;max-width:none;
    padding-top:12px;border-top:1px solid var(--line);}
  .ag-casehdr .ag-meta{flex:1;min-width:90px;}
}
@media(max-width:520px){
  .ag-casehdr{padding:14px;gap:11px;}
  .ag-casehdr .ico{width:38px;height:38px;min-width:38px;border-radius:10px;}
  .ag-casehdr h3{font-size:1.6rem!important;}
}

/* key findings */
.ag-finding{display:flex;align-items:center;gap:12px;padding:11px 4px;border-top:1px solid var(--line);}
.ag-finding:first-child{border-top:0;}
.ag-finding .fi{width:30px;height:30px;min-width:30px;border-radius:9px;display:grid;place-items:center;font-size:14px;
  border:1px solid #713744;background:#321b25;color:#ff8b96;}
.ag-finding .ft{flex:1;min-width:0;}
.ag-finding .ft b{display:block;font-size:.8rem;color:var(--text);}
.ag-finding .ft small{color:var(--sub);font-size:.7rem;}
.ag-finding .fc{font-size:.8rem;font-weight:800;color:#7fe0ac;}

/* context grid */
.ag-ctx{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
.ag-ctx div{border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:#091320;}
.ag-ctx span{display:block;color:var(--faint);font-size:.6rem;text-transform:uppercase;letter-spacing:.06em;}
.ag-ctx span[title]{text-decoration:underline dotted;text-decoration-color:var(--faint);cursor:help;}
.ag-ctx b{font-size:.82rem;color:var(--text);}
.ag-ctx b.crit{color:#ff99a3;} .ag-ctx b.warn{color:#f3c679;} .ag-ctx b.ok{color:#7fe0ac;}

/* panel wrapper */
.ag-panel{border:1px solid var(--line);border-radius:14px;padding:16px 18px;background:#0d1726;
  box-shadow:0 15px 45px #0003;margin:6px 0;}
.ag-panel > .h{font-size:.95rem;font-weight:700;color:var(--text);margin:0 0 2px;}
.ag-panel > .s{color:var(--sub);font-size:.74rem;margin:0 0 10px;}

/* queue table (My Queue mockup) */
.ag-qwrap{border:1px solid var(--line);border-radius:14px;background:#0d1726;
  overflow:auto;margin:6px 0;box-shadow:0 15px 45px #0003;}
.ag-qtable{width:100%;border-collapse:collapse;}
.ag-qtable th{text-align:left;color:#687993;text-transform:uppercase;letter-spacing:.06em;
  font-size:.64rem;font-weight:800;padding:10px 12px;border-bottom:1px solid var(--line);
  white-space:nowrap;}
.ag-qtable td{padding:9px 12px;border-bottom:1px solid #1d2a3e;color:#c8d2df;
  font-size:.74rem;vertical-align:middle;}
.ag-qtable tbody tr:last-child td{border-bottom:0;}
.ag-qtable tbody tr:hover td{background:#111c2f;}
.ag-qtable .mono{font-family:var(--mono);font-size:.68rem;color:#9fb2c8;}

/* sidebar workspace card (mockup .workspace) */
.ag-workspace{margin:4px 0 10px;padding:11px;border:1px solid var(--line);border-radius:12px;
  background:#0c1625;display:flex;align-items:center;gap:10px;}
.ag-workspace .wi{width:31px;height:31px;min-width:31px;border-radius:8px;background:#182641;
  display:grid;place-items:center;color:#aab4ff;font-size:15px;}
.ag-workspace b{font-size:.74rem;color:var(--text);display:block;}
.ag-workspace small{display:block;color:var(--sub);font-size:.68rem;margin-top:2px;}

/* Aegis grouped-nav look for the sidebar section labels */
.sec-label{color:#61728b !important;text-transform:uppercase;letter-spacing:.15em !important;
  font-size:.64rem !important;font-weight:800 !important;}

/* attention metrics (operations mockup .metric — corner glow) */
.ag-attn{display:flex;gap:12px;margin:6px 0;}
.ag-am{flex:1;border:1px solid var(--line);border-radius:14px;padding:15px 16px;position:relative;
  overflow:hidden;background:linear-gradient(145deg,#111c2d,#0c1523);}
.ag-am::after{content:"";position:absolute;width:75px;height:75px;border-radius:50%;right:-35px;
  bottom:-43px;background:radial-gradient(circle,#6f7cff55,transparent 70%);}
.ag-am.red::after{background:radial-gradient(circle,#ff6e7c55,transparent 70%);}
.ag-am.amber::after{background:radial-gradient(circle,#f4bc5f55,transparent 70%);}
.ag-am.green::after{background:radial-gradient(circle,#43d28c55,transparent 70%);}
.ag-am .l{color:#a6b2c4;font-size:.72rem;font-weight:600;}
.ag-am .v{display:block;font-size:1.65rem;font-weight:800;margin:7px 0 2px;color:var(--text);}
.ag-am.red .v{color:#ff8c97;} .ag-am.amber .v{color:#f3c36f;} .ag-am.green .v{color:#7fe0ac;}
.ag-am .s{font-size:.68rem;color:var(--sub);position:relative;z-index:1;}

/* AI-generated summary card (case-workspace mockup .ai-summary-card) */
.ag-aisum{padding:14px 16px;margin:6px 0;border:1px solid #33406b;border-radius:12px;
  background:linear-gradient(135deg,#161f3a,#0d1726);}
.ag-aisum-h{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
.ag-aisum-h .ic{color:#a67af4;font-size:.9rem;}
.ag-aisum-h b{font-size:.78rem;color:var(--text);}
.ag-aisum-h .tag{margin-left:auto;color:#f3c679;border:1px solid #684c2a;background:#2b221a;
  border-radius:99px;padding:2px 9px;font-size:.62rem;font-weight:800;cursor:help;}
.ag-aisum p{margin:0;color:#c8d2e1;font-size:.76rem;line-height:1.65;white-space:pre-wrap;}

/* MITRE kill-chain tactic strip (case-workspace mockup .mitre-tactics) */
.ag-mitre{display:flex;align-items:center;gap:7px;overflow-x:auto;padding:8px 0 12px;margin:2px 0;}
.ag-mitre .t{display:inline-flex;flex:0 0 auto;align-items:center;gap:6px;border:1px solid #293a54;
  border-radius:10px;padding:7px 11px;background:#0b1625;color:var(--sub);font-size:.7rem;white-space:nowrap;
  cursor:help;}
.ag-mitre .t.active{border-color:#536ab0;background:#101c31;color:var(--text);font-weight:700;
  box-shadow:0 0 0 3px #6f7cff22;}
.ag-mitre .t .n{display:grid;min-width:19px;height:18px;place-items:center;border-radius:999px;
  background:#2a3751;font-size:.64rem;}
.ag-mitre .t.active .n{background:#3b4c81;color:#fff;}
.ag-mitre .arw{color:#53627a;flex:0 0 auto;}

/* Evidence-backed MITRE ATT&CK mapping workspace */
.ag-mitre-workspace{border:1px solid #26334a;border-radius:16px;background:#0d1523;
  padding:22px 24px 24px;color:var(--text);margin:4px 0 16px;}
.ag-mw-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;}
.ag-mw-head h3{font-size:1.12rem;margin:0 0 5px;font-weight:800;color:#f5f7fb;}
.ag-mw-head p{font-size:.78rem;margin:0;color:#91a4c8;}
.ag-mw-count{border:1px solid #3b4861;border-radius:999px;padding:5px 12px;
  color:#c8d5ef;font-size:.75rem;white-space:nowrap;}
.ag-mw-filters{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin:20px 0 20px;}
.ag-mw-filter{display:inline-flex;align-items:center;gap:8px;border:1px solid #35425c;
  border-radius:9px;padding:8px 12px;color:#b8c7e3;background:#111b2b;font-size:.72rem;
  font-weight:750;}
.ag-mw-filter.active{border-color:#6478c3;background:#1b2542;color:#fff;}
.ag-mw-filter .count{display:grid;place-items:center;min-width:22px;height:22px;border-radius:50%;
  background:#34415f;color:#d8e2f5;font-size:.68rem;}
.ag-mw-arrow{color:#64748e;font-size:1rem;}
.ag-map-card{border:1px solid #5c70be;border-radius:12px;background:#141e33;margin-top:12px;
  overflow:hidden;}
.ag-map-card summary{display:grid;grid-template-columns:minmax(130px,.65fr) minmax(240px,2fr) auto auto 18px;
  align-items:center;gap:18px;padding:18px 20px;cursor:pointer;list-style:none;}
.ag-map-card summary::-webkit-details-marker{display:none;}
.ag-map-tactic{color:#93a9ff;font-size:.7rem;font-weight:850;text-transform:uppercase;}
.ag-map-tech b{display:block;color:#fff;font-size:.79rem;margin-bottom:3px;}
.ag-map-tech span{color:#92a8d3;font-size:.72rem;}
.ag-map-confidence{border:1px solid #386b4e;background:#12291f;border-radius:999px;
  padding:5px 10px;color:#75e69b;font-size:.68rem;white-space:nowrap;}
.ag-map-review{border:1px solid #3c4962;border-radius:999px;padding:5px 10px;
  color:#c3d0e9;font-size:.67rem;font-weight:750;white-space:nowrap;}
.ag-map-chevron{color:#d9e3f8;font-size:.85rem;transition:transform .15s;}
.ag-map-card[open] .ag-map-chevron{transform:rotate(180deg);}
.ag-map-body{border-top:1px solid #2e3b55;padding:17px 60px 22px;}
.ag-map-desc{color:#d2dcf1;font-size:.73rem;margin:0 0 16px;line-height:1.55;}
.ag-map-facts{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:14px;}
.ag-map-fact{border:1px solid #303d55;border-radius:9px;background:#0d1626;padding:10px 12px;}
.ag-map-fact span{display:block;color:#7187af;font-size:.64rem;text-transform:uppercase;margin-bottom:4px;}
.ag-map-fact b{display:block;color:#fff;font-size:.71rem;}
.ag-map-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px;}
.ag-map-action{border:1px solid #3a4863;border-radius:8px;background:#111b2c;color:#c8d5ec;
  padding:8px 11px;font-size:.68rem;font-weight:750;}
.ag-map-action.primary{border-color:#5368ac;background:#1a2541;color:#fff;}
@media(max-width:800px){
  .ag-map-card summary{grid-template-columns:1fr auto;gap:9px;}
  .ag-map-tactic,.ag-map-tech{grid-column:1}.ag-map-confidence,.ag-map-review{grid-column:auto}
  .ag-map-chevron{position:absolute;right:22px}.ag-map-body{padding:16px 18px 20px}
  .ag-map-facts{grid-template-columns:1fr}.ag-mw-head{align-items:center}
}

/* agent completion ring (case-workspace mockup .agent-ring — conic gradient) */
.ag-ringwrap{display:flex;align-items:center;gap:12px;margin:6px 0;}
.ag-ring{position:relative;flex:none;width:66px;height:66px;border-radius:50%;display:grid;
  place-items:center;background:conic-gradient(var(--green) calc(var(--pct,0)*3.6deg),#1c2a3d 0);}
.ag-ring.warn{background:conic-gradient(var(--amber) calc(var(--pct,0)*3.6deg),#1c2a3d 0);}
.ag-ring::before{content:"";position:absolute;inset:6px;border-radius:50%;background:#0d1726;}
.ag-ring b{position:relative;z-index:1;font-size:.9rem;color:var(--text);}
.ag-ringwrap .rl b{display:block;font-size:.8rem;color:var(--text);}
.ag-ringwrap .rl small{display:block;font-size:.68rem;color:var(--sub);}

/* Reports tab — Generated Files row head (icon + title + description) */
.ag-rf-head{display:flex;align-items:flex-start;gap:11px;padding:2px 0;}
.ag-rf-icon{width:34px;height:34px;min-width:34px;border-radius:9px;display:grid;
  place-items:center;font-size:16px;color:#fff;}
.ag-rf-icon.blue{background:#2b5cd8;}
.ag-rf-icon.green{background:#1f8a5c;}
.ag-rf-icon.purple{background:#6b46c1;}
.ag-rf-icon.gold{background:#b9860b;}
.ag-rf-icon.slate{background:#3a4863;}
.ag-rf-title{font-size:.85rem;font-weight:800;color:var(--text);margin:0 0 2px;}
.ag-rf-desc{font-size:.72rem;color:var(--sub);margin:0;}
</style>
"""

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "info": "info", "informational": "info"}


# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def _e(s: Any) -> str:
    """[FYP-FUNCTION] HTML-escape a value for safe interpolation into the
    markdown/HTML strings this module returns; every builder below routes
    user/incident-derived text through this (never raw f-string interp)."""
    return _html.escape(str(s if s is not None else ""))


def sev_class(sev: str) -> str:
    """[FYP-FUNCTION] Normalize a free-text severity ("High", "critical", …)
    to one of the `.ag-critical/.ag-high/.ag-medium/.ag-low/.ag-info` CSS
    classes defined in COMPONENT_CSS; unrecognized/empty input falls back to
    the neutral "wait" tone rather than guessing."""
    return _SEV.get(str(sev or "").strip().lower(), "wait")


# ── builders [FYP-UI] ──────────────────────────────────────────────────────
# [FYP-FUNCTION] `page_title` — implements the page title operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `title`, `sub`, `eyebrow`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_render_overview_header; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `append`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def page_title(title: str, sub: str = "", eyebrow: str = "") -> str:
    """[FYP-UI] Page header block: optional small-caps eyebrow label, the
    main title, and an optional subtitle line. Used at the top of most
    dashboard pages (app.py: 2 call sites)."""
    out = []
    if eyebrow:
        out.append(f'<div class="ag-eyebrow">{_e(eyebrow)}</div>')
    out.append(f'<div class="ag-page-title">{_e(title)}</div>')
    if sub:
        out.append(f'<div class="ag-page-sub">{_e(sub)}</div>')
    return "".join(out)


# [FYP-FUNCTION] `pill` — implements the pill operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `text`, `kind`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_render_case_table, app.py:_render_reports_workspace; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def pill(text: str, kind: str = "stage") -> str:
    """[FYP-UI] Small rounded status/severity badge (e.g. "High", "Open").
    `kind` selects the `.ag-<kind>` colour class from COMPONENT_CSS
    (critical/high/medium/low/info/wait/open/stage-pill); see sev_class()
    for mapping a raw severity string to one of these. The most-used single
    builder in this module — app.py calls it 6 times directly, plus every
    queue_table() {"pill": …} cell and case_header()/case_header_left()
    severity/status badge routes through it."""
    k = {"stage": "stage-pill"}.get(kind, kind)
    return f'<span class="ag-pill ag-{_e(k)}">{_e(text)}</span>'


# [FYP-FUNCTION] `hero` — implements the hero operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `eyebrow`, `title`, `why`, `cta`, `tone`, `icon`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def hero(eyebrow: str, title: str, why: str = "", cta: str = "",
         tone: str = "red", icon: str = "") -> str:
    """[FYP-UI] "Next move" hero banner (mockup's headline call-to-action
    card) — icon + eyebrow + title + rationale + optional CTA pill.
    `tone="blue"` swaps the default red/urgent palette for the calmer
    informational one. No confirmed caller in the current app.py (see the
    file header's list of ported-but-unwired builders)."""
    blue = " blue" if tone == "blue" else ""
    cta_html = f'<div class="ag-cta">{_e(cta)}</div>' if cta else ""
    why_html = f'<p>{_e(why)}</p>' if why else ""
    icon_html = f'<div class="ag-hero-icon">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-hero{blue}">{icon_html}'
            f'<div class="ag-hero-body"><div class="e">{_e(eyebrow)}</div>'
            f'<h4>{_e(title)}</h4>{why_html}</div>{cta_html}</div>')


# [FYP-FUNCTION] `stat_row` — implements the stat row operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `cards`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`, `append`, `get`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def stat_row(cards: Iterable[dict]) -> str:
    """[FYP-UI] Row of KPI stat cards (label/value/sub-caption, one of
    red|amber|blue|green tones). `cards`: [{label,value,sub,tone}]. No
    confirmed caller in the current app.py — app.py's analogous cross-page
    metrics use attention_row() instead."""
    cells = []
    for c in cards:
        tone = _e(c.get("tone", "blue"))
        cells.append(
            f'<div class="ag-stat {tone}"><div class="lbl">{_e(c.get("label",""))}</div>'
            f'<span class="val">{_e(c.get("value",""))}</span>'
            f'<div class="sub">{_e(c.get("sub",""))}</div></div>')
    return f'<div class="ag-stats">{"".join(cells)}</div>'


# [FYP-FUNCTION] `circular_pipeline` — implements the circular pipeline operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `stages`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_render_circular_pipeline_section, ui_components.py:stepper; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `any`, `append`, `cos`, `enumerate`, `get`, `int`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def circular_pipeline(stages: Iterable[dict]) -> str:
    """[FYP-UI] Renders a grand, sleek circular workflow progression diagram for the SOC pipeline.
    Stages flow clockwise from top (Triage) to top-left (Finalized).
    Progression segments light up in vibrant stage colors when active/completed,
    and remain unlit dark grey when uncompleted/pending.

    Dual-mode renderer (app.py, 1 direct call site — plus every call routed
    through the stepper() alias below):
      * Cross-case Overview mode: stages carry only a "count" (cases
        currently in that stage); the center badge shows the total case
        count and "N Stages Active".
      * Per-case "My Workspace" mode: any stage carrying an explicit
        "state" ("done"|"current"|"queued") switches the whole renderer
        into single-case-stepper mode — the center badge then shows that
        case's current stage name instead of a count. See _case_stage_states
        in app.py for how that per-stage `state` list is built.
    """
    stage_list = list(stages)
    if not stage_list:
        return ""
    
    colors = ["#36c5d3", "#a67af4", "#f4bc5f", "#6f7cff", "#ff7700", "#43d28c"]
    total_cases = sum(int(s.get("count", 0) or 0) for s in stage_list)
    # Per-case mode (My Workspace): any stage carrying an explicit "state"
    # means this is one case's workflow, not the cross-case aggregate —
    # the center badge shows that case's current stage instead of a count.
    _is_case_mode = any(s.get("state") is not None for s in stage_list)
    _current_stage_name = next(
        (s.get("name", "") for s in stage_list if s.get("state") == "current"),
        "Finalized" if _is_case_mode else "")
    
    # Larger Dimensions for a prominent, spacious circle diagram (shifted slightly downwards)
    cx, cy, r = 360, 248, 175
    angles_deg = [-90, -30, 30, 90, 150, 210]
    
    arcs_svg = []
    arrows_svg = []
    nodes_svg = []
    labels_svg = []
    
    # 1. Generate 6 Arc Segments & Arrow Markers around the circle (Progression Lit/Unlit)
    for i in range(6):
        deg1 = angles_deg[i]
        deg2 = angles_deg[(i + 1) % 6]
        if deg2 <= deg1:
            deg2 += 360
            
        cnt_curr = int(stage_list[i].get("count", 0) or 0)
        _seg_state = stage_list[i].get("state")

        # Segment is lit if current stage has active cases in pipeline —
        # OR, for a single-case stepper, if this stage is done/current
        # (explicit "state" takes priority over the count-derived default,
        # so cross-case Overview and per-case My Workspace share one
        # renderer without either mode fighting the other's assumptions).
        is_lit = (_seg_state in ("done", "current")) if _seg_state is not None else (cnt_curr > 0)
        
        # Arc SVG Path
        rad1 = math.radians(deg1)
        rad2 = math.radians(deg2)
        x1 = cx + r * math.cos(rad1)
        y1 = cy + r * math.sin(rad1)
        x2 = cx + r * math.cos(rad2)
        y2 = cy + r * math.sin(rad2)
        
        arc_stroke = colors[i % len(colors)] if is_lit else "#1e2d42"
        stroke_w = "4" if is_lit else "2"
        opacity = "0.95" if is_lit else "0.45"
        
        arcs_svg.append(
            f'<path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 0 1 {x2:.1f} {y2:.1f}" '
            f'fill="none" stroke="{arc_stroke}" stroke-width="{stroke_w}" opacity="{opacity}" />'
        )
        
        # Directional Arrowhead at midpoint of arc
        mid_deg = (deg1 + deg2) / 2.0
        mid_rad = math.radians(mid_deg)
        ax = cx + r * math.cos(mid_rad)
        ay = cy + r * math.sin(mid_rad)
        tangent_deg = mid_deg + 90
        
        arrow_fill = colors[i % len(colors)] if is_lit else "#2a3e59"
        arrow_op = "1.0" if is_lit else "0.4"
        
        arrows_svg.append(
            f'<g transform="translate({ax:.1f}, {ay:.1f}) rotate({tangent_deg:.1f})">'
            f'<polygon points="-7,-4.5 7,0 -7,4.5" fill="{arrow_fill}" opacity="{arrow_op}" />'
            f'</g>'
        )

    # 2. Nodes & Labels
    for idx, s in enumerate(stage_list):
        name = _e(s.get("name", ""))
        cnt_val = int(s.get("count", 0) or 0)
        is_finalized = (name.lower() == "finalized")
        _state = s.get("state")   # explicit "done"|"current"|"queued", or None
        is_active = (_state in ("done", "current")) if _state is not None else (cnt_val > 0)

        # Color & Styling based on stage status. Explicit per-stage `state`
        # (single-case stepper — see _case_stage_states in app.py) takes
        # priority; falls back to the original count-derived logic for the
        # cross-case Overview pipeline, which never sets `state`.
        if _state == "done":
            color = "#43d28c"
            fill_bg = "#0c261b"
            stroke_w = "4"
            stroke_dash = ""
            display_count = "✓"
            title_color = "#43d28c"
            sub_txt = "Done"
        elif _state == "current":
            color = "#f4bc5f"
            fill_bg = "#2b2210"
            stroke_w = "4"
            stroke_dash = ""
            display_count = "●"
            title_color = "#f4bc5f"
            sub_txt = "In progress"
        elif _state == "queued":
            color = "#24364e"
            fill_bg = "#060b14"
            stroke_w = "2"
            stroke_dash = 'stroke-dasharray="4,4"'
            display_count = ""
            title_color = "#586d88"
            sub_txt = "Queued"
        elif is_finalized and is_active:
            color = "#43d28c"  # Emerald green for completed phase
            fill_bg = "#0c261b"
            stroke_w = "4"
            stroke_dash = ""
            display_count = f"{cnt_val}"
            title_color = "#43d28c"
            sub_txt = f"{cnt_val} completed"
        elif is_active:
            color = colors[idx % len(colors)]
            fill_bg = "#091424"
            stroke_w = "3.5"
            stroke_dash = ""
            display_count = f"{cnt_val}"
            title_color = "#f3f6fb"
            sub_txt = f"{cnt_val} in stage"
        else:
            color = "#24364e"  # Unlit / empty stage
            fill_bg = "#060b14"
            stroke_w = "2"
            stroke_dash = 'stroke-dasharray="4,4"'
            display_count = "0"
            title_color = "#586d88"
            sub_txt = "Pending"
            
        deg = angles_deg[idx % len(angles_deg)]
        rad = math.radians(deg)
        
        nx = cx + r * math.cos(rad)
        ny = cy + r * math.sin(rad)
        
        # Node SVG circle + count text (Larger radius 26px)
        nodes_svg.append(
            f'<g class="ag-circ-node">'
            f'<circle cx="{nx:.1f}" cy="{ny:.1f}" r="26" fill="{fill_bg}" stroke="{color}" stroke-width="{stroke_w}" {stroke_dash} />'
            f'<text x="{nx:.1f}" y="{ny + 6:.1f}" text-anchor="middle" fill="{color if not is_active else "#ffffff"}" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="16" font-weight="700">{_e(display_count)}</text>'
            f'</g>'
        )
        
        # Label positions (Zero overlap with top node!)
        if deg == -90:  # Top (Triage)
            tx, ty = nx, ny - 38
            anchor = "middle"
            t1_y, t2_y = ty - 16, ty
        elif deg == -30:  # Top-Right (Investigation)
            tx, ty = nx + 38, ny - 6
            anchor = "start"
            t1_y, t2_y = ty, ty + 16
        elif deg == 30:  # Bottom-Right (Findings)
            tx, ty = nx + 38, ny + 10
            anchor = "start"
            t1_y, t2_y = ty, ty + 16
        elif deg == 90:  # Bottom (Ticketing)
            tx, ty = nx, ny + 44
            anchor = "middle"
            t1_y, t2_y = ty, ty + 16
        elif deg == 150:  # Bottom-Left (Reporting)
            tx, ty = nx - 38, ny + 10
            anchor = "end"
            t1_y, t2_y = ty, ty + 16
        else:  # Top-Left (Finalized)
            tx, ty = nx - 38, ny - 6
            anchor = "end"
            t1_y, t2_y = ty, ty + 16
            
        labels_svg.append(
            f'<g class="ag-circ-label" text-anchor="{anchor}">'
            f'<text x="{tx:.1f}" y="{t1_y:.1f}" fill="{title_color}" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="14" font-weight="700">{name}</text>'
            f'<text x="{tx:.1f}" y="{t2_y:.1f}" fill="#8b9bb2" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="12" font-weight="400">{_e(sub_txt)}</text>'
            f'</g>'
        )
        
    return (
        f'<div style="display:flex;justify-content:center;align-items:center;padding:4px 0 10px;margin-top:-6px;background:transparent;">'
        f'<svg viewBox="0 0 720 520" style="width:100%;max-width:760px;height:auto;">'
        # Unlit Background Track Ring
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#132032" stroke-width="5" />'
        # Lit Arc Segments
        f'{"".join(arcs_svg)}'
        # Center Badge
        f'<circle cx="{cx}" cy="{cy}" r="64" fill="#091424" stroke="#1e3048" stroke-width="2" />'
        + (
            f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" fill="#8b9bb2" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="11" font-weight="800" letter-spacing="1.8">CASE STATUS</text>'
            f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="#f4bc5f" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="16" font-weight="800">{_e(_current_stage_name)}</text>'
            if _is_case_mode else
            f'<text x="{cx}" y="{cy - 14}" text-anchor="middle" fill="#8b9bb2" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="11" font-weight="800" letter-spacing="1.8">SOC PIPELINE</text>'
            f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" fill="#6f7cff" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="20" font-weight="800">{total_cases} Total</text>'
            f'<text x="{cx}" y="{cy + 30}" text-anchor="middle" fill="#8b9bb2" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="11" font-weight="500">6 Stages Active</text>'
        )
        # Directional Arrows
        + f'{"".join(arrows_svg)}'
        # Nodes
        f'{"".join(nodes_svg)}'
        # Labels
        f'{"".join(labels_svg)}'
        f'</svg>'
        f'</div>'
    )


# [FYP-FUNCTION] `stepper` — implements the stepper operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `stages`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `circular_pipeline`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def stepper(stages: Iterable[dict]) -> str:
    """[FYP-UI] Thin backward-compatible alias for circular_pipeline() — kept
    so older call sites/names referring to a "stepper" still resolve to the
    one dual-mode (cross-case/per-case) renderer rather than a second
    diverging implementation."""
    return circular_pipeline(stages)


# [FYP-FUNCTION] `case_workflow` — implements the case workflow operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `stages`, `selected_stage`, `case_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`, `_url_quote`, `append`, `enumerate`, `get`, `join`, `len`, `list`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_workflow(
    stages: Iterable[dict],
    selected_stage: str = "",
    case_id: str = "",
) -> str:
    """[FYP-UI] Render a compact, linear workflow for a single incident.
    Unlike circular_pipeline()'s per-case mode, this renders each stage as a
    clickable `<a href="?case_stage=...">` step (query-param navigation,
    `target="_self"`) with its own inline <style> block, rather than an SVG
    ring. No confirmed caller in the current app.py (see the file header's
    list of ported-but-unwired builders) — app.py's actual case-detail page
    uses circular_pipeline()'s per-case mode instead."""
    stage_list = list(stages)
    if not stage_list:
        return ""

    cells = []
    for index, stage in enumerate(stage_list):
        raw_name = str(stage.get("name", ""))
        name = _e(raw_name)
        state = str(stage.get("state") or "queued").lower()
        selected = raw_name == selected_stage
        selected_attr = ' aria-current="step"' if selected else ""
        if state == "done":
            marker = "&#10003;"
            status = "Complete"
        elif state == "current":
            marker = str(index + 1)
            status = "Current stage"
        else:
            marker = str(index + 1)
            status = "Queued" if state == "queued" else _e(state.replace("_", " ").title())

        stage_query = f"case_stage={_url_quote(raw_name)}"
        if case_id:
            stage_query = (
                f"case_id={_url_quote(str(case_id))}&amp;{stage_query}"
            )

        cells.append(
            f'<a class="ag-case-path-step {state}'
            f'{" selected" if selected else ""}" '
            f'href="?{stage_query}" target="_self" '
            f'aria-label="Open {name} stage"'
            f'{selected_attr}>'
            f'<span class="ag-case-path-marker">{marker}</span>'
            f'<span class="ag-case-path-name">{name}</span>'
            f'<span class="ag-case-path-status">{status}</span>'
            f'</a>'
        )

    return (
        '<section class="ag-case-path">'
        '<div class="ag-case-path-heading">'
        '<div><h3>Case workflow</h3>'
        '<p>Select a stage to inspect its work, outputs and actions</p></div>'
        '</div>'
        f'<div class="ag-case-path-track">{"".join(cells)}</div>'
        '</section>'
        '<style>'
        '.ag-case-path{background:#0d1626!important;border:0!important;'
        'border-radius:0!important;padding:18px 18px 10px!important;'
        'margin:14px 0 12px!important;box-shadow:none!important}'
        '.ag-case-path-heading{display:flex!important;align-items:center!important;'
        'justify-content:space-between!important;margin-bottom:28px!important}'
        '.ag-case-path-heading h3{margin:0!important;color:#f7f9fd!important;font-size:17px!important;'
        'font-weight:800;letter-spacing:-.01em}'
        '.ag-case-path-heading p{margin:7px 0 0!important;color:#91acd5!important;'
        'font-size:12px!important}'
        '.ag-case-path-track{display:grid!important;grid-template-columns:repeat('
        + str(len(stage_list)) +
        ',minmax(125px,1fr))!important;align-items:start!important;margin-top:0!important;'
        'padding:0 4px!important;overflow-x:auto!important}'
        '.ag-case-path-step{display:flex!important;flex-direction:column!important;'
        'align-items:center!important;position:relative!important;'
        'box-sizing:border-box!important;min-width:125px!important;'
        'min-height:126px!important;text-align:center!important;'
        'margin:0!important;padding:8px 10px 12px!important;'
        'border:1px solid transparent!important;background:transparent!important;'
        'color:#73849d!important;text-decoration:none!important;cursor:pointer;'
        'border-radius:12px!important;transition:background .16s ease,transform .16s ease,'
        'box-shadow .16s ease}'
        '.ag-case-path-step *{box-sizing:border-box!important;'
        'text-decoration:none!important}'
        '.ag-case-path-step:hover{background:#111d30!important;'
        'transform:translateY(-2px);'
        'box-shadow:0 8px 20px rgba(0,0,0,.16)}'
        '.ag-case-path-step:focus-visible{outline:2px solid #7182ff;'
        'outline-offset:3px}'
        '.ag-case-path-step:not(:last-child)::after{content:""!important;position:absolute!important;'
        'z-index:0;top:27px;left:calc(50% + 20px);width:calc(100% - 40px);'
        'height:2px!important;background:#2a354a!important}'
        '.ag-case-path-step.done:not(:last-child)::after{'
        'background:#7778f6!important}'
        '.ag-case-path-step.current:not(:last-child)::after{'
        'left:100%!important;width:calc(50% - 20px)!important;'
        'background:#2a354a!important}'
        '.ag-case-path-step.selected.done:not(:last-child)::after{'
        'left:100%!important;width:calc(50% - 20px)!important;'
        'background:#7778f6!important}'
        '.ag-case-path-marker{display:flex!important;position:relative!important;'
        'z-index:1!important;margin:0 auto!important;padding:0!important;'
        'width:40px!important;min-width:40px!important;max-width:40px!important;'
        'height:40px!important;min-height:40px!important;max-height:40px!important;'
        'border-radius:50%!important;align-items:center!important;'
        'justify-content:center!important;background:#132036!important;'
        'border:1px solid #32445e!important;color:#8293ab!important;'
        'font:700 12px var(--mono)!important;line-height:1!important}'
        '.ag-case-path-step.done .ag-case-path-marker{background:#25396f!important;'
        'border-color:#7182ff!important;color:#fff!important;'
        'box-shadow:0 0 0 5px rgba(111,124,255,.10)}'
        '.ag-case-path-step.current{color:#d5deec}'
        '.ag-case-path-step.selected{margin:0!important;padding:8px 10px 12px!important;'
        'background:#1c263b!important;border:1px solid #485a79!important;'
        'border-radius:12px!important;box-shadow:none!important}'
        '.ag-case-path-step.current .ag-case-path-marker{background:#332812!important;'
        'border-color:#c68c29!important;color:#ffd36b!important;'
        'box-shadow:0 0 0 6px rgba(244,188,95,.10)}'
        '.ag-case-path-name{display:block!important;margin:13px 0 0!important;'
        'padding:0!important;color:#f2f4fa!important;font-size:12px!important;'
        'font-weight:750!important;line-height:1.25!important}'
        '.ag-case-path-status{display:block!important;margin:4px 0 0!important;'
        'padding:0!important;color:#8e99ad!important;font-size:11px!important;'
        'line-height:1.2!important}'
        '.ag-case-path-step.done .ag-case-path-status{color:#a9b4ff!important}'
        '.ag-case-path-step.current .ag-case-path-status{color:#ffd36b!important}'
        '.ag-case-path-step.selected .ag-case-path-name{color:#fff!important}'
        '@media(max-width:900px){.ag-case-path-track{justify-content:start}'
        '.ag-case-path-step{min-width:112px}}'
        '</style>'
    )


# [FYP-FUNCTION] `case_header_left` — implements the case header left operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `ticket`, `title`, `sev`, `status`, `subtitle`, `icon`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`, `pill`, `sev_class`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_header_left(ticket: str, title: str, sev: str = "", status: str = "",
                     subtitle: str = "", icon: str = "") -> str:
    """[FYP-UI] Left-hand half of a two-column case header (icon + ticket ID
    + severity/status pills + title + subtitle) — a split-layout companion
    to the single-block case_header() below. No confirmed caller in the
    current app.py; app.py's case pages use the combined case_header()
    instead."""
    pills = ""
    if sev:
        pills += " " + pill(sev, sev_class(sev))
    if status:
        pills += " " + pill(status, "open")
    icon_html = f'<div class="ico">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-casehdr-left">{icon_html}'
            f'<div class="body"><div class="tid">{_e(ticket)}{pills}</div>'
            f'<h3>{_e(title)}</h3><div class="sub">{_e(subtitle)}</div></div></div>')


# [FYP-FUNCTION] `case_header_right` — implements the case header right operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `metas`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_header_right(metas: Iterable[tuple] = ()) -> str:
    """[FYP-UI] Right-hand half of a two-column case header — a row of small
    label/value meta chips (e.g. Created/Assignee), meant to pair with
    case_header_left(). No confirmed caller in the current app.py."""
    meta_html = "".join(
        f'<div class="ag-meta"><span>{_e(k)}</span><b>{_e(v)}</b></div>' for k, v in metas)
    return f'<div class="ag-metas">{meta_html}</div>' if meta_html else ""


# [FYP-FUNCTION] `case_header` — implements the case header operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `ticket`, `title`, `sev`, `status`, `subtitle`, `metas`, `icon`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `join`, `pill`, `sev_class`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_header(ticket: str, title: str, sev: str = "", status: str = "",
                subtitle: str = "", metas: Iterable[tuple] = (), icon: str = "") -> str:
    """[FYP-UI] Single-block case header banner (icon, ticket ID + severity/
    status pills, title, subtitle, and a right-aligned meta-chip row) — the
    combined equivalent of case_header_left() + case_header_right() in one
    call. The left accent border and icon colour both derive from
    sev_class(sev). app.py's case-detail page's confirmed caller (1 call
    site)."""
    pills = ""
    if sev:
        pills += " " + pill(sev, sev_class(sev))
    if status:
        pills += " " + pill(status, "open")
    meta_html = "".join(
        f'<div class="ag-meta"><span>{_e(k)}</span><b>{_e(v)}</b></div>' for k, v in metas)
    metas_wrap = f'<div class="ag-metas">{meta_html}</div>' if meta_html else ""
    icon_html = f'<div class="ico">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-casehdr ag-{sev_class(sev)}">{icon_html}'
            f'<div class="body"><div class="tid">{_e(ticket)}{pills}</div>'
            f'<h3>{_e(title)}</h3><div class="sub">{_e(subtitle)}</div></div>{metas_wrap}</div>')


# [FYP-FUNCTION] `key_findings` — implements the key findings operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `findings`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `append`, `get`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def key_findings(findings: Iterable[dict]) -> str:
    """[FYP-UI] Stacked list of "key finding" rows (icon + title + short
    description + optional right-aligned confidence figure). `findings`:
    [{icon,title,desc,confidence}]. app.py's confirmed caller (1 call site)."""
    rows = []
    for f in findings:
        conf = f.get("confidence")
        conf_html = f'<div class="fc">{_e(conf)}</div>' if conf not in (None, "") else ""
        rows.append(
            f'<div class="ag-finding"><div class="fi">{_e(f.get("icon") or "!")}</div>'
            f'<div class="ft"><b>{_e(f.get("title",""))}</b>'
            f'<small>{_e(f.get("desc",""))}</small></div>{conf_html}</div>')
    return "".join(rows)


# [FYP-FUNCTION] `context_grid` — implements the context grid operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `items`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `append`, `join`, `len`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def context_grid(items: Iterable[tuple]) -> str:
    """[FYP-UI] 2-column key/value grid (Overview panel's context facts —
    hostnames, IPs, users, verdicts, etc). app.py's confirmed caller (1 call
    site). items: [(label, value)], [(label, value, tone)], or
    [(label, value, tone, help)] tone ∈ crit|warn|ok. `help`, when given,
    renders as a hover title on the label so jargon (e.g. "Unified verdict",
    "IOC IPs") gets a plain-English definition instead of just an acronym."""
    cells = []
    for it in items:
        label, value = it[0], it[1]
        tone = f" {it[2]}" if len(it) > 2 and it[2] else ""
        help_txt = it[3] if len(it) > 3 and it[3] else ""
        title_attr = f' title="{_e(help_txt)}"' if help_txt else ""
        cells.append(f'<div><span{title_attr}>{_e(label)}</span>'
                     f'<b class="{tone.strip()}">{_e(value)}</b></div>')
    return f'<div class="ag-ctx">{"".join(cells)}</div>'


# [FYP-FUNCTION] `panel_open` — implements the panel open operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `heading`, `sub`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def panel_open(heading: str, sub: str = "") -> str:
    """[FYP-UI] Opens a generic bordered panel wrapper div (heading + optional
    subtitle); the caller renders its own body content (often further
    Streamlit widgets, not just markdown) and must close with panel_close().
    Deliberately split open/close rather than one all-in-one builder so
    arbitrary Streamlit content can sit inside the panel. app.py's confirmed
    caller (2 open/close pairs)."""
    s = f'<div class="s">{_e(sub)}</div>' if sub else ""
    return f'<div class="ag-panel"><div class="h">{_e(heading)}</div>{s}'


# [FYP-FUNCTION] `panel_close` — implements the panel close operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def panel_close() -> str:
    """[FYP-UI] Closes the div opened by panel_open() — see its docstring."""
    return "</div>"


# [FYP-FUNCTION] `queue_table` — implements the queue table operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `headers`, `rows`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_render_reporting_ops_readonly; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `append`, `get`, `isinstance`, `join`, `pill`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def queue_table(headers: Iterable[str], rows: Iterable[Iterable]) -> str:
    """[FYP-UI] Aegis 'My Queue' table. Each cell is a plain value (escaped), or a dict:
    {"pill": text, "kind": "high|stage|…"} renders a pill (via pill());
    {"mono": text} renders in the mono id style. app.py's most-used table
    builder (7 confirmed call sites — queues/lists across the dashboard)."""
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = []
    for row in rows:
        tds = []
        for cell in row:
            if isinstance(cell, dict) and "pill" in cell:
                tds.append(f'<td>{pill(cell["pill"], cell.get("kind", "stage"))}</td>')
            elif isinstance(cell, dict) and "mono" in cell:
                tds.append(f'<td><span class="mono">{_e(cell["mono"])}</span></td>')
            else:
                tds.append(f"<td>{_e(cell)}</td>")
        body.append(f'<tr>{"".join(tds)}</tr>')
    return (f'<div class="ag-qwrap"><table class="ag-qtable">'
            f'<thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


# [FYP-FUNCTION] `workspace_card` — implements the workspace card operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `title`, `sub`, `icon`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def workspace_card(title: str, sub: str = "", icon: str = "") -> str:
    """[FYP-UI] Sidebar workspace identity card (mockup .workspace). Rendered
    on the Settings page's sidebar via the guarded, locally-aliased
    `import ui_components as _uisb` (see this file's [FYP-FILE] header) with
    the analyst's display name in `sub` — the confirmed caller."""
    sub_html = f"<small>{_e(sub)}</small>" if sub else ""
    icon_html = f'<div class="wi">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-workspace">{icon_html}'
            f'<div><b>{_e(title)}</b>{sub_html}</div></div>')


# [FYP-FUNCTION] `attention_row` — implements the attention row operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `cards`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `append`, `get`, `join`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def attention_row(cards: Iterable[dict]) -> str:
    """[FYP-UI] SOC 'attention' metrics (mockup operations page). cards: [{label,value,sub,tone}]
    tone ∈ blue|red|amber|green. Visually similar to stat_row() but with a
    decorative radial-glow corner (`.ag-am::after` in COMPONENT_CSS); this
    is the one app.py actually calls (1 confirmed call site), stat_row() is
    not."""
    cells = []
    for c in cards:
        tone = _e(c.get("tone", "blue"))
        cells.append(
            f'<div class="ag-am {tone}"><div class="l">{_e(c.get("label",""))}</div>'
            f'<span class="v">{_e(c.get("value",""))}</span>'
            f'<div class="s">{_e(c.get("sub",""))}</div></div>')
    return f'<div class="ag-attn">{"".join(cells)}</div>'


# markers that mean an AI narrative fell back to error text instead of real output
_FALLBACK_MARKERS = (
    "fallback due to error", "pass 1 error", "pass 2 error", "invalid_request_error",
    "analysis failed due to error", "response_format type is unavailable",
    "missing credentials", "llm call failed",
)


def detect_fallback(text: Any) -> bool:
    """[FYP-UI] [FYP-FUNCTION] True when an agent narrative is actually an
    error/fallback rather than a real AI summary — drives the amber
    'Fallback logic' tag rendered by ai_summary() below. Pure substring
    match against _FALLBACK_MARKERS (case-insensitive); this is a UI-layer
    heuristic over already-produced text, it does not itself know why an
    LLM call failed. app.py's confirmed caller (7 call sites, one per
    AI-narrative surface in the dashboard)."""
    t = str(text or "").lower()
    return any(m in t for m in _FALLBACK_MARKERS)


# [FYP-FUNCTION] `ai_summary` — implements the ai summary operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `body`, `fallback`, `title`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def ai_summary(body: str, fallback: bool = False,
               title: str = "AI-Generated Summary") -> str:
    """[FYP-UI] Case-workspace AI summary card (mockup .ai-summary-card) with an optional
    amber 'Fallback logic' tag when the summary is error-fallback text.
    Callers normally pass `fallback=detect_fallback(body)` so the tag stays
    in sync with the text actually displayed. app.py's confirmed caller (7
    call sites)."""
    tag = ('<span class="tag" title="The AI analysis failed to run, so this '
           'text is an automatic fallback message — not a real summary. '
           'Treat it as unreliable and re-run the analysis.">'
           ' Fallback logic</span>' if fallback else "")
    return (f'<div class="ag-aisum"><div class="ag-aisum-h"><span class="ic">✦</span>'
            f'<b>{_e(title)}</b>{tag}</div><p>{_e(body)}</p></div>')


# ATT&CK enterprise tactics in kill-chain order (strip scrolls horizontally)
_ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# One plain-English line per tactic — shown as a hover title so a non-expert
# reader isn't left guessing what "Lateral Movement" or "Defense Evasion" means.
_ATTACK_TACTIC_DEFS = {
    "Reconnaissance": "The attacker is gathering information to plan the attack.",
    "Resource Development": "The attacker is building or acquiring tools/infrastructure to use later.",
    "Initial Access": "The attacker is trying to get an initial foothold in the network.",
    "Execution": "The attacker is running malicious code on a system.",
    "Persistence": "The attacker is trying to maintain access across restarts/logouts.",
    "Privilege Escalation": "The attacker is trying to gain higher-level permissions.",
    "Defense Evasion": "The attacker is trying to avoid being detected.",
    "Credential Access": "The attacker is trying to steal usernames/passwords.",
    "Discovery": "The attacker is trying to learn about the environment.",
    "Lateral Movement": "The attacker is moving from one system to another.",
    "Collection": "The attacker is gathering data of interest.",
    "Command and Control": "The attacker is communicating with compromised systems.",
    "Exfiltration": "The attacker is trying to steal data out of the network.",
    "Impact": "The attacker is trying to disrupt, damage, or destroy systems/data.",
}


# [FYP-FUNCTION] `mitre_strip` — implements the mitre strip operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `active_tactic`, `technique`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`, `append`, `bool`, `enumerate`, `get`, `join`, `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def mitre_strip(active_tactic: str = "", technique: str = "") -> str:
    """[FYP-UI] Horizontal MITRE ATT&CK kill-chain strip with the incident's tactic
    highlighted (mockup .mitre-tactics). active_tactic matched case-insensitively.
    Each tactic carries a plain-English hover title (see _ATTACK_TACTIC_DEFS).
    No confirmed caller in the current app.py — the case-detail MITRE view
    uses the fuller mitre_mapping_workspace() below instead, which surfaces
    per-mapping evidence/origin rather than just highlighting one tactic in
    the fixed 14-tactic strip."""
    act = str(active_tactic or "").strip().lower()
    parts = []
    for i, tac in enumerate(_ATTACK_TACTICS, start=1):
        is_active = bool(act) and (act in tac.lower() or tac.lower() in act)
        label = _e(tac) + (f" · {_e(technique)}" if is_active and technique else "")
        cls = "t active" if is_active else "t"
        title = _e(_ATTACK_TACTIC_DEFS.get(tac, ""))
        if i > 1:
            parts.append('<span class="arw">›</span>')
        parts.append(f'<span class="{cls}" title="{title}">'
                     f'<span class="n">{i}</span>{label}</span>')
    return f'<div class="ag-mitre">{"".join(parts)}</div>'


# origin -> (display label, tone) — never "confirmed" unless an analyst
# actually confirmed it (no such action exists in this pass, see
# case_view.build_mitre — so "analyst_confirmed" simply never appears
# today; the tag is reserved, not fabricated).
_MITRE_ORIGIN_LABELS = {
    "netwitness_detection_mapping": ("NetWitness detection", "info"),
    "deterministic_keyword_inference": ("Deterministic inference", "wait"),
    "investigation_agent_suggestion": ("Investigation agent suggestion", "high"),
    "analyst_confirmed": ("Analyst confirmed", "low"),
}


# [FYP-FUNCTION] `mitre_mapping_workspace` — implements the mitre mapping workspace operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `mappings`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`, `append`, `enumerate`, `get`, `isinstance`, `items`, `join`, `len`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def mitre_mapping_workspace(mappings: Iterable[dict]) -> str:
    """[FYP-UI] Render MITRE mappings as reviewable technique cards, each tagged with
    its ORIGIN (how it was produced) instead of a fabricated confidence
    percentage — no field in any of the three source tiers (NetWitness
    native data, deterministic keyword inference, or the Investigation
    Agent's own markdown table) carries a real numeric confidence, so none
    is invented here. An LLM/agent suggestion is never displayed
    indistinguishably from a confirmed mapping.

    [FYP-DECISION] The `_MITRE_ORIGIN_LABELS` map above never resolves to
    "Analyst confirmed" today — no action anywhere in this pass lets an
    analyst confirm a mapping, so that entry is a reserved-but-unused label
    (see the comment on `_MITRE_ORIGIN_LABELS`), not a claim about existing
    functionality. `mappings` is the raw list this app assembles (each
    origin string is a key into `_MITRE_ORIGIN_LABELS`; unrecognized origins
    fall back to a title-cased "Unlabeled origin" tone rather than being
    dropped). app.py's confirmed caller (1 call site, the case-detail page's
    MITRE tab)."""
    clean = []
    for raw in mappings or []:
        if not isinstance(raw, dict):
            continue
        tactic = str(raw.get("tactic") or "Unclassified").strip()
        tech_id = str(raw.get("technique_id") or raw.get("id")
                      or raw.get("technique") or "").strip()
        tech_name = str(raw.get("technique_name") or raw.get("name") or "").strip()
        evidence = raw.get("evidence") or raw.get("observed_evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence] if evidence.strip() else []
        origin = str(raw.get("origin") or "").strip()
        origin_label, origin_tone = _MITRE_ORIGIN_LABELS.get(
            origin, (origin.replace("_", " ").title() or "Unlabeled origin", "stage"))
        clean.append({
            "tactic": tactic, "technique_id": tech_id or "—",
            "technique_name": tech_name, "evidence": evidence,
            "origin_label": origin_label, "origin_tone": origin_tone,
            "source": str(raw.get("source") or "").strip() or "—",
        })
    if not clean:
        return ('<div class="ag-mitre-workspace"><div class="ag-mw-head"><div>'
                '<h3>MITRE ATT&amp;CK Mappings</h3>'
                '<p>No mappings are available for this case yet.</p>'
                '</div><span class="ag-mw-count">0 mapped</span></div></div>')

    tactic_counts = {}
    for item in clean:
        tactic_counts[item["tactic"]] = tactic_counts.get(item["tactic"], 0) + 1
    filters = ['<span class="ag-mw-filter active">All Tactics</span>']
    for index, (tactic, count) in enumerate(tactic_counts.items()):
        if index:
            filters.append('<span class="ag-mw-arrow">→</span>')
        filters.append(f'<span class="ag-mw-filter">{_e(tactic)}'
                       f'<span class="count">{count}</span></span>')

    cards = []
    for index, item in enumerate(clean):
        details = " open" if index == 0 else ""
        ev_html = ("".join(f'<li>{_e(e)}</li>' for e in item["evidence"])
                  if item["evidence"] else '<li>No supporting evidence recorded.</li>')
        cards.append(
            f'<details class="ag-map-card"{details}><summary>'
            f'<span class="ag-map-tactic">{_e(item["tactic"])}</span>'
            f'<span class="ag-map-tech"><b>{_e(item["technique_id"])}</b>'
            f'<span>{_e(item["technique_name"])}</span></span>'
            f'{pill(item["origin_label"], item["origin_tone"])}'
            '<span class="ag-map-chevron">⌃</span></summary>'
            f'<div class="ag-map-body">'
            '<div class="ag-map-facts">'
            f'<div class="ag-map-fact"><span>Origin</span><b>{_e(item["origin_label"])}</b></div>'
            f'<div class="ag-map-fact"><span>Source</span><b>{_e(item["source"])}</b></div>'
            '</div>'
            f'<p class="ag-map-desc"><b>Supporting evidence</b></p><ul>{ev_html}</ul>'
            '</div></details>')

    return (
        '<div class="ag-mitre-workspace"><div class="ag-mw-head"><div>'
        '<h3>MITRE ATT&amp;CK Mappings</h3>'
        '<p>Tactics and techniques for this case, tagged by origin</p></div>'
        f'<span class="ag-mw-count">{len(clean)} mapped</span></div>'
        f'<div class="ag-mw-filters">{"".join(filters)}</div>'
        f'{"".join(cards)}</div>')


# [FYP-FUNCTION] `agent_ring` — implements the agent ring operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `pct`, `label`, `sub`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_e`, `float`, `int`, `max`, `min`, `round`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def agent_ring(pct: Any, label: str = "", sub: str = "") -> str:
    """[FYP-UI] Conic-gradient completion ring (mockup .agent-ring). pct 0-100; ring turns
    amber when < 100 (in progress), green at 100 (complete). No confirmed
    caller in the current app.py (see the file header's list of
    ported-but-unwired builders)."""
    try:
        p = max(0, min(100, int(round(float(pct)))))
    except (TypeError, ValueError):
        p = 0
    ring_cls = "ag-ring" if p >= 100 else "ag-ring warn"
    side = ""
    if label or sub:
        side = (f'<div class="rl"><b>{_e(label)}</b>'
                + (f"<small>{_e(sub)}</small>" if sub else "") + "</div>")
    return (f'<div class="ag-ringwrap"><div class="{ring_cls}" style="--pct:{p}">'
            f'<b>{p}%</b></div>{side}</div>')


# [FYP-FUNCTION] `report_file_head` — implements the report file head operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `icon`, `color`, `title`, `description`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_render_reports_workspace; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_e`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def report_file_head(icon: str, color: str, title: str, description: str) -> str:
    """[FYP-UI] Reports tab 'Generated Files' row head — colored icon square + title +
    description, matching the reference design's document rows. `color` is
    one of blue|green|purple|gold|slate (see .ag-rf-icon.* in COMPONENT_CSS).
    app.py's confirmed caller (2 call sites)."""
    return (f'<div class="ag-rf-head"><div class="ag-rf-icon {_e(color)}">{_e(icon)}</div>'
            f'<div><p class="ag-rf-title">{_e(title)}</p>'
            f'<p class="ag-rf-desc">{_e(description)}</p></div></div>')


def humanize_timestamp(iso_str: str | None) -> str:
    """[FYP-UI] [FYP-FUNCTION] "Generated today at 5:52 PM" / "Edited yesterday at 3:20 PM" style
    display string for the Reports tab's Last Saved column. `iso_str` is a
    plain ISO-8601 UTC timestamp (as produced throughout this app);
    falls back to the raw string (or "—") when it can't be parsed. Converts
    to the local ("astimezone()") timezone before formatting, so "today"/
    "yesterday" reflect the viewer's clock, not UTC. app.py's confirmed
    caller (3 call sites)."""
    if not iso_str:
        return "—"
    try:
        from datetime import datetime as _dt, timezone as _tz
        dt = _dt.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_tz.utc)
        local = dt.astimezone()
        now = _dt.now(local.tzinfo)
        time_part = local.strftime("%I:%M %p").lstrip("0")
        day_delta = (now.date() - local.date()).days
        if day_delta == 0:
            return f"today at {time_part}"
        if day_delta == 1:
            return f"yesterday at {time_part}"
        return local.strftime("%b %d, %Y at ") + time_part
    except Exception:
        return str(iso_str)
