"""
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
</style>
"""

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "info": "info", "informational": "info"}


def _e(s: Any) -> str:
    return _html.escape(str(s if s is not None else ""))


def sev_class(sev: str) -> str:
    return _SEV.get(str(sev or "").strip().lower(), "wait")


# ── builders ──────────────────────────────────────────────────────────────────
def page_title(title: str, sub: str = "", eyebrow: str = "") -> str:
    out = []
    if eyebrow:
        out.append(f'<div class="ag-eyebrow">{_e(eyebrow)}</div>')
    out.append(f'<div class="ag-page-title">{_e(title)}</div>')
    if sub:
        out.append(f'<div class="ag-page-sub">{_e(sub)}</div>')
    return "".join(out)


def pill(text: str, kind: str = "stage") -> str:
    k = {"stage": "stage-pill"}.get(kind, kind)
    return f'<span class="ag-pill ag-{_e(k)}">{_e(text)}</span>'


def hero(eyebrow: str, title: str, why: str = "", cta: str = "",
         tone: str = "red", icon: str = "") -> str:
    blue = " blue" if tone == "blue" else ""
    cta_html = f'<div class="ag-cta">{_e(cta)}</div>' if cta else ""
    why_html = f'<p>{_e(why)}</p>' if why else ""
    icon_html = f'<div class="ag-hero-icon">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-hero{blue}">{icon_html}'
            f'<div class="ag-hero-body"><div class="e">{_e(eyebrow)}</div>'
            f'<h4>{_e(title)}</h4>{why_html}</div>{cta_html}</div>')


def stat_row(cards: Iterable[dict]) -> str:
    cells = []
    for c in cards:
        tone = _e(c.get("tone", "blue"))
        cells.append(
            f'<div class="ag-stat {tone}"><div class="lbl">{_e(c.get("label",""))}</div>'
            f'<span class="val">{_e(c.get("value",""))}</span>'
            f'<div class="sub">{_e(c.get("sub",""))}</div></div>')
    return f'<div class="ag-stats">{"".join(cells)}</div>'


def circular_pipeline(stages: Iterable[dict]) -> str:
    """Renders a grand, sleek circular workflow progression diagram for the SOC pipeline.
    Stages flow clockwise from top (Triage) to top-left (Finalized).
    Progression segments light up in vibrant stage colors when active/completed,
    and remain unlit dark grey when uncompleted/pending.
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
            display_count = f"✓ {cnt_val}"
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
            f'<text x="{nx:.1f}" y="{ny + 6:.1f}" text-anchor="middle" fill="{color if not is_active else "#ffffff"}" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="{13 if is_finalized else 16}" font-weight="700">{_e(display_count)}</text>'
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
            f'<text x="{tx:.1f}" y="{t2_y:.1f}" fill="{color if is_finalized else "#8b9bb2"}" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="12" font-weight="400">{_e(sub_txt)}</text>'
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


def stepper(stages: Iterable[dict]) -> str:
    return circular_pipeline(stages)


def case_workflow(
    stages: Iterable[dict],
    selected_stage: str = "",
    case_id: str = "",
) -> str:
    """Render a compact, linear workflow for a single incident."""
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


def case_header_left(ticket: str, title: str, sev: str = "", status: str = "",
                     subtitle: str = "", icon: str = "") -> str:
    pills = ""
    if sev:
        pills += " " + pill(sev, sev_class(sev))
    if status:
        pills += " " + pill(status, "open")
    icon_html = f'<div class="ico">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-casehdr-left">{icon_html}'
            f'<div class="body"><div class="tid">{_e(ticket)}{pills}</div>'
            f'<h3>{_e(title)}</h3><div class="sub">{_e(subtitle)}</div></div></div>')


def case_header_right(metas: Iterable[tuple] = ()) -> str:
    meta_html = "".join(
        f'<div class="ag-meta"><span>{_e(k)}</span><b>{_e(v)}</b></div>' for k, v in metas)
    return f'<div class="ag-metas">{meta_html}</div>' if meta_html else ""


def case_header(ticket: str, title: str, sev: str = "", status: str = "",
                subtitle: str = "", metas: Iterable[tuple] = (), icon: str = "") -> str:
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


def key_findings(findings: Iterable[dict]) -> str:
    rows = []
    for f in findings:
        conf = f.get("confidence")
        conf_html = f'<div class="fc">{_e(conf)}</div>' if conf not in (None, "") else ""
        rows.append(
            f'<div class="ag-finding"><div class="fi">{_e(f.get("icon") or "!")}</div>'
            f'<div class="ft"><b>{_e(f.get("title",""))}</b>'
            f'<small>{_e(f.get("desc",""))}</small></div>{conf_html}</div>')
    return "".join(rows)


def context_grid(items: Iterable[tuple]) -> str:
    """items: [(label, value)], [(label, value, tone)], or
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


def panel_open(heading: str, sub: str = "") -> str:
    s = f'<div class="s">{_e(sub)}</div>' if sub else ""
    return f'<div class="ag-panel"><div class="h">{_e(heading)}</div>{s}'


def panel_close() -> str:
    return "</div>"


def queue_table(headers: Iterable[str], rows: Iterable[Iterable]) -> str:
    """Aegis 'My Queue' table. Each cell is a plain value (escaped), or a dict:
    {"pill": text, "kind": "high|stage|…"} renders a pill;
    {"mono": text} renders in the mono id style."""
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


def workspace_card(title: str, sub: str = "", icon: str = "") -> str:
    """Sidebar workspace identity card (mockup .workspace)."""
    sub_html = f"<small>{_e(sub)}</small>" if sub else ""
    icon_html = f'<div class="wi">{_e(icon)}</div>' if icon else ""
    return (f'<div class="ag-workspace">{icon_html}'
            f'<div><b>{_e(title)}</b>{sub_html}</div></div>')


def attention_row(cards: Iterable[dict]) -> str:
    """SOC 'attention' metrics (mockup operations page). cards: [{label,value,sub,tone}]
    tone ∈ blue|red|amber|green."""
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
    """True when an agent narrative is actually an error/fallback rather than a
    real AI summary — drives the amber 'Fallback logic' tag."""
    t = str(text or "").lower()
    return any(m in t for m in _FALLBACK_MARKERS)


def ai_summary(body: str, fallback: bool = False,
               title: str = "AI-Generated Summary") -> str:
    """Case-workspace AI summary card (mockup .ai-summary-card) with an optional
    amber 'Fallback logic' tag when the summary is error-fallback text."""
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


def mitre_strip(active_tactic: str = "", technique: str = "") -> str:
    """Horizontal MITRE ATT&CK kill-chain strip with the incident's tactic
    highlighted (mockup .mitre-tactics). active_tactic matched case-insensitively.
    Each tactic carries a plain-English hover title (see _ATTACK_TACTIC_DEFS)."""
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


def mitre_mapping_workspace(mappings: Iterable[dict]) -> str:
    """Render evidence-backed MITRE mappings as reviewable technique cards."""
    clean = []
    for raw in mappings or []:
        if not isinstance(raw, dict):
            continue
        tactic = str(raw.get("tactic") or "Unclassified").strip()
        tech_id = str(raw.get("technique_id") or raw.get("id")
                      or raw.get("technique") or "Technique pending").strip()
        tech_name = str(raw.get("technique_name") or raw.get("name")
                        or raw.get("technique") or "MITRE ATT&CK technique").strip()
        if tech_name == tech_id:
            tech_name = str(raw.get("name") or "MITRE ATT&CK technique")
        evidence = raw.get("evidence") or raw.get("observed_evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence] if evidence.strip() else []
        try:
            confidence_score = int(float(str(
                raw.get("confidence_score") or
                (94 if str(raw.get("confidence") or "").lower() == "high" else 82)
            ).rstrip("%")))
        except (TypeError, ValueError):
            confidence_score = 82
        clean.append({
            "tactic": tactic, "technique_id": tech_id, "technique_name": tech_name,
            "description": str(raw.get("description") or
                f"Observed case activity is consistent with {tech_name}."),
            "confidence": str(raw.get("confidence") or "High").title(),
            "confidence_score": max(0, min(100, confidence_score)),
            "review": str(raw.get("review") or "Unreviewed"),
            "evidence": evidence,
            "source": str(raw.get("source") or "Aegis Investigation Agent"),
            "timeline_events": int(raw.get("timeline_events") or 1),
            "related_entities": int(raw.get("related_entities") or 0),
            "generated_by": str(raw.get("generated_by") or "Aegis Investigation Agent"),
        })
    if not clean:
        return ('<div class="ag-mitre-workspace"><div class="ag-mw-head"><div>'
                '<h3>MITRE ATT&amp;CK Mappings</h3>'
                '<p>No evidence-backed mappings are available for this case yet.</p>'
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
        ev_count = max(1, len(item["evidence"]))
        details = " open" if index == 0 else ""
        cards.append(
            f'<details class="ag-map-card"{details}><summary>'
            f'<span class="ag-map-tactic">{_e(item["tactic"])}</span>'
            f'<span class="ag-map-tech"><b>{_e(item["technique_id"])}</b>'
            f'<span>{_e(item["technique_name"])}</span></span>'
            f'<span class="ag-map-confidence">{_e(item["confidence"])} · '
            f'{item["confidence_score"]}%</span>'
            f'<span class="ag-map-review">{_e(item["review"])}</span>'
            '<span class="ag-map-chevron">⌃</span></summary>'
            f'<div class="ag-map-body"><p class="ag-map-desc">{_e(item["description"])}</p>'
            '<div class="ag-map-facts">'
            f'<div class="ag-map-fact"><span>Supporting evidence</span><b>{ev_count} '
            f'{"item" if ev_count == 1 else "items"}</b></div>'
            f'<div class="ag-map-fact"><span>Evidence source</span><b>{_e(item["source"])}</b></div>'
            f'<div class="ag-map-fact"><span>Timeline events</span><b>{item["timeline_events"]}</b></div>'
            f'<div class="ag-map-fact"><span>Related entities</span><b>{item["related_entities"]}</b></div>'
            f'<div class="ag-map-fact"><span>Generated by</span><b>{_e(item["generated_by"])}</b></div>'
            '</div><div class="ag-map-actions">'
            '<span class="ag-map-action primary">Confirm Mapping</span>'
            '<span class="ag-map-action">Mark as Incorrect</span>'
            '<span class="ag-map-action">Needs More Evidence</span></div>'
            '<div class="ag-map-actions">'
            '<span class="ag-map-action">View Supporting Evidence</span>'
            '<span class="ag-map-action">View Timeline Event</span>'
            '<span class="ag-map-action">View Related Entities</span>'
            '</div></div></details>')

    return (
        '<div class="ag-mitre-workspace"><div class="ag-mw-head"><div>'
        '<h3>MITRE ATT&amp;CK Mappings</h3>'
        '<p>Evidence-backed tactics and techniques for this case</p></div>'
        f'<span class="ag-mw-count">{len(clean)} mapped</span></div>'
        f'<div class="ag-mw-filters">{"".join(filters)}</div>'
        f'{"".join(cards)}</div>')


def agent_ring(pct: Any, label: str = "", sub: str = "") -> str:
    """Conic-gradient completion ring (mockup .agent-ring). pct 0-100; ring turns
    amber when < 100 (in progress), green at 100 (complete)."""
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
