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
from typing import Any, Iterable

# ── shared CSS (inject once) ──────────────────────────────────────────────────
COMPONENT_CSS = """
<style>
/* ===== Aegis components ===== */
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
.ag-stat{flex:1;border:1px solid var(--line);border-radius:14px;padding:15px 16px;
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

/* case header */
.ag-casehdr{border:1px solid var(--line);border-radius:14px;padding:16px 18px;
  background:linear-gradient(135deg,#0f1a2b,#0c1523);display:flex;gap:14px;align-items:flex-start;
  box-shadow:0 15px 45px #0003;margin:6px 0;}
.ag-casehdr .ico{width:42px;height:42px;min-width:42px;border-radius:12px;display:grid;place-items:center;
  font-size:20px;border:1px solid #713744;background:#321b25;color:#ff8b96;}
.ag-casehdr .body{flex:1;min-width:0;}
.ag-casehdr .tid{font-family:var(--mono);font-size:.68rem;color:var(--sub);letter-spacing:.05em;}
.ag-casehdr h3{margin:5px 0 3px;font-size:1.05rem;color:var(--text);}
.ag-casehdr .sub{color:var(--sub);font-size:.75rem;}
.ag-metas{display:flex;gap:8px;}
.ag-meta{border:1px solid var(--line);border-radius:10px;padding:8px 12px;background:#091320;min-width:104px;}
.ag-meta span{display:block;color:var(--faint);font-size:.6rem;text-transform:uppercase;letter-spacing:.06em;}
.ag-meta b{font-size:.78rem;color:var(--text);font-weight:600;}

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
  border-radius:99px;padding:2px 9px;font-size:.62rem;font-weight:800;}
.ag-aisum p{margin:0;color:#c8d2e1;font-size:.76rem;line-height:1.65;white-space:pre-wrap;}

/* MITRE kill-chain tactic strip (case-workspace mockup .mitre-tactics) */
.ag-mitre{display:flex;align-items:center;gap:7px;overflow-x:auto;padding:8px 0 12px;margin:2px 0;}
.ag-mitre .t{display:inline-flex;flex:0 0 auto;align-items:center;gap:6px;border:1px solid #293a54;
  border-radius:10px;padding:7px 11px;background:#0b1625;color:var(--sub);font-size:.7rem;white-space:nowrap;}
.ag-mitre .t.active{border-color:#536ab0;background:#101c31;color:var(--text);font-weight:700;
  box-shadow:0 0 0 3px #6f7cff22;}
.ag-mitre .t .n{display:grid;min-width:19px;height:18px;place-items:center;border-radius:999px;
  background:#2a3751;font-size:.64rem;}
.ag-mitre .t.active .n{background:#3b4c81;color:#fff;}
.ag-mitre .arw{color:#53627a;flex:0 0 auto;}

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
         tone: str = "red", icon: str = "⚠") -> str:
    blue = " blue" if tone == "blue" else ""
    cta_html = f'<div class="ag-cta">{_e(cta)}</div>' if cta else ""
    why_html = f'<p>{_e(why)}</p>' if why else ""
    return (f'<div class="ag-hero{blue}"><div class="ag-hero-icon">{_e(icon)}</div>'
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


def stepper(stages: Iterable[dict]) -> str:
    """stages: [{name, count|label, state}]  state ∈ done|current|queued|idle."""
    cells = []
    for s in stages:
        state = _e(s.get("state", "idle"))
        inner = s.get("count")
        if state == "done" and inner in (None, "", 0, "0"):
            inner = "✓"
        cells.append(
            f'<div class="ag-step {state}"><div class="ag-node {state}">{_e(inner)}</div>'
            f'<b>{_e(s.get("name",""))}</b><small>{_e(s.get("label",""))}</small></div>')
    return f'<div class="ag-stepper">{"".join(cells)}</div>'


def case_header(ticket: str, title: str, sev: str = "", status: str = "",
                subtitle: str = "", metas: Iterable[tuple] = (), icon: str = "⚠") -> str:
    pills = ""
    if sev:
        pills += " " + pill(sev, sev_class(sev))
    if status:
        pills += " " + pill(status, "open")
    meta_html = "".join(
        f'<div class="ag-meta"><span>{_e(k)}</span><b>{_e(v)}</b></div>' for k, v in metas)
    metas_wrap = f'<div class="ag-metas">{meta_html}</div>' if meta_html else ""
    return (f'<div class="ag-casehdr"><div class="ico">{_e(icon)}</div>'
            f'<div class="body"><div class="tid">{_e(ticket)}{pills}</div>'
            f'<h3>{_e(title)}</h3><div class="sub">{_e(subtitle)}</div></div>{metas_wrap}</div>')


def key_findings(findings: Iterable[dict]) -> str:
    rows = []
    for f in findings:
        conf = f.get("confidence")
        conf_html = f'<div class="fc">{_e(conf)}</div>' if conf not in (None, "") else ""
        rows.append(
            f'<div class="ag-finding"><div class="fi">{_e(f.get("icon","!"))}</div>'
            f'<div class="ft"><b>{_e(f.get("title",""))}</b>'
            f'<small>{_e(f.get("desc",""))}</small></div>{conf_html}</div>')
    return "".join(rows)


def context_grid(items: Iterable[tuple]) -> str:
    """items: [(label, value)] or [(label, value, tone)] tone ∈ crit|warn|ok."""
    cells = []
    for it in items:
        label, value = it[0], it[1]
        tone = f" {it[2]}" if len(it) > 2 and it[2] else ""
        cells.append(f'<div><span>{_e(label)}</span><b class="{tone.strip()}">{_e(value)}</b></div>')
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


def workspace_card(title: str, sub: str = "", icon: str = "🛡️") -> str:
    """Sidebar workspace identity card (mockup .workspace)."""
    sub_html = f"<small>{_e(sub)}</small>" if sub else ""
    return (f'<div class="ag-workspace"><div class="wi">{_e(icon)}</div>'
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
    tag = ('<span class="tag">⚠ Fallback logic</span>' if fallback else "")
    return (f'<div class="ag-aisum"><div class="ag-aisum-h"><span class="ic">✦</span>'
            f'<b>{_e(title)}</b>{tag}</div><p>{_e(body)}</p></div>')


# ATT&CK enterprise tactics in kill-chain order (strip scrolls horizontally)
_ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def mitre_strip(active_tactic: str = "", technique: str = "") -> str:
    """Horizontal MITRE ATT&CK kill-chain strip with the incident's tactic
    highlighted (mockup .mitre-tactics). active_tactic matched case-insensitively."""
    act = str(active_tactic or "").strip().lower()
    parts = []
    for i, tac in enumerate(_ATTACK_TACTICS, start=1):
        is_active = bool(act) and (act in tac.lower() or tac.lower() in act)
        label = _e(tac) + (f" · {_e(technique)}" if is_active and technique else "")
        cls = "t active" if is_active else "t"
        if i > 1:
            parts.append('<span class="arw">›</span>')
        parts.append(f'<span class="{cls}"><span class="n">{i}</span>{label}</span>')
    return f'<div class="ag-mitre">{"".join(parts)}</div>'


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
