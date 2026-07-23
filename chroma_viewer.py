"""
chroma_viewer.py  —  SOC Pipeline ChromaDB Viewer
══════════════════════════════════════════════════
Standalone Streamlit page that connects to the same ChromaDB
persistent store as the main SOC Platform and lets you browse,
search, and inspect every pipeline collection.

Run alongside the main app on a separate port:
    streamlit run chroma_viewer.py --server.port 8502

The main app links directly to this page with ?collection=pipeline_<stage>
"""

import streamlit as st
import json
import re
from pathlib import Path
from datetime import datetime

# ── ChromaDB ───────────────────────────────────────────────────────────────────
try:
    import chromadb
    CHROMA_OK = True
except ImportError:
    CHROMA_OK = False

# ── SQLite (pipeline db) ───────────────────────────────────────────────────────
import sqlite3

PIPELINE_DB_FILE = Path(__file__).parent / "soc_pipeline.db"

PIPELINE_STAGES = [
    "alerts_to_triage",
    "post_triage_investigate",
    "post_triage_no_investigate",
    "initial_ticket",
    "pending_ticket_report",
    "finalized_report",
]

PIPELINE_LABELS = {
    "alerts_to_triage":            "Alerts to Triage",
    "post_triage_investigate":     "Post-Triage · Needs Investigation",
    "post_triage_no_investigate":  "Post-Triage · No Investigation Needed",
    "initial_ticket":              "Initial Ticket Generation",
    "pending_ticket_report":       "Pending Ticket / Report Generation",
    "finalized_report":            "Finalized Report",
}

PIPELINE_ICONS = {
    "alerts_to_triage":            "🚨",
    "post_triage_investigate":     "🔍",
    "post_triage_no_investigate":  "✅",
    "initial_ticket":              "🎫",
    "pending_ticket_report":       "⏳",
    "finalized_report":            "📄",
}

PIPELINE_COLORS = {
    "alerts_to_triage":            "#FF3B3B",
    "post_triage_investigate":     "#FF7700",
    "post_triage_no_investigate":  "#0AF0A0",
    "initial_ticket":              "#00D4FF",
    "pending_ticket_report":       "#FFB700",
    "finalized_report":            "#A78BFA",
}

CHROMA_PATH = "./chroma_db"

# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SOC Pipeline · ChromaDB Viewer",
    page_icon="🗄️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&display=swap');

:root {
  --bg:      #04080F;
  --bg1:     #080F1A;
  --bg2:     #0C1624;
  --border:  #162840;
  --accent:  #00D4FF;
  --green:   #0AF0A0;
  --warn:    #FFB700;
  --danger:  #FF3B3B;
  --orange:  #FF7700;
  --purple:  #A78BFA;
  --muted:   #3A607A;
  --text:    #B8D4E8;
  --mono:    'Share Tech Mono', monospace;
  --sans:    'Barlow', sans-serif;
}

html, body, [class*="css"] { font-family: var(--sans); background: var(--bg); color: var(--text); }
.main { background: var(--bg); }

section[data-testid="stSidebar"] > div:first-child {
  background: linear-gradient(180deg, #040810 0%, #06101A 100%);
  border-right: 1px solid #0E1E30;
}

h1,h2,h3 { font-family: var(--mono); color: var(--accent); letter-spacing: 2px; }

.stButton > button {
  background: linear-gradient(90deg, #052030, #083050);
  color: var(--accent); border: 1px solid #0E4A6A;
  border-radius: 5px; font-family: var(--mono);
  font-size: 0.72rem; letter-spacing: 1px;
  padding: 6px 14px; transition: all 0.15s;
}
.stButton > button:hover {
  background: linear-gradient(90deg, #083050, #0E4A6A);
  box-shadow: 0 0 14px rgba(0,212,255,0.2);
  color: #fff; border-color: var(--accent);
}

.stTextInput > div > div > input {
  background: #060E1A !important;
  border: 1px solid #0E2030 !important;
  color: var(--text) !important;
  border-radius: 5px; font-family: var(--sans);
}
.stTextInput > div > div > input:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 2px rgba(0,212,255,0.12) !important;
}

.record-card {
  background: #060C16;
  border-radius: 7px;
  padding: 12px 16px;
  margin: 5px 0;
  transition: all 0.15s;
}
.record-card:hover { border-color: #1E4060 !important; transform: translateX(1px); }

.badge {
  padding: 2px 9px; border-radius: 3px;
  font-family: var(--mono); font-size: 0.62rem;
  display: inline-block;
}

hr { border-color: #0E1E2E; margin: 0.8rem 0; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: #0E2030; border-radius: 2px; }

.stage-pill {
  display: inline-block;
  padding: 4px 14px;
  border-radius: 20px;
  font-family: var(--mono);
  font-size: 0.65rem;
  letter-spacing: 1px;
  cursor: pointer;
  transition: all 0.15s;
  margin: 3px;
}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE & HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def get_chroma_client():
    if "cv_chroma_client" not in st.session_state:
        st.session_state.cv_chroma_client = None
    return st.session_state.cv_chroma_client

def connect_chroma(path: str = CHROMA_PATH):
    try:
        client = chromadb.PersistentClient(path=path)
        st.session_state.cv_chroma_client = client
        return client, ""
    except Exception as e:
        return None, str(e)

def get_collection(client, stage: str):
    try:
        return client.get_or_create_collection(
            name=f"pipeline_{stage}",
            metadata={"hnsw:space": "cosine"},
        )
    except Exception:
        return None

def sqlite_load(stage: str, limit: int = 500) -> list[dict]:
    if not PIPELINE_DB_FILE.exists():
        return []
    try:
        con = sqlite3.connect(str(PIPELINE_DB_FILE))
        con.row_factory = sqlite3.Row
        rows = con.execute(
            f"SELECT * FROM {stage} ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def sqlite_count(stage: str) -> int:
    if not PIPELINE_DB_FILE.exists():
        return 0
    try:
        con = sqlite3.connect(str(PIPELINE_DB_FILE))
        n = con.execute(f"SELECT COUNT(*) FROM {stage}").fetchone()[0]
        con.close()
        return n
    except Exception:
        return 0

# ── URL param — pre-select collection ─────────────────────────────────────────
_query_params = st.query_params
_preselect    = _query_params.get("collection", "")
# strip "pipeline_" prefix if present
if _preselect.startswith("pipeline_"):
    _preselect = _preselect[len("pipeline_"):]
if _preselect not in PIPELINE_STAGES:
    _preselect = None


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(
        '<div style="font-family:var(--mono);font-size:1rem;color:var(--accent);'
        'letter-spacing:3px;padding:4px 0">🗄️ CHROMA VIEWER</div>'
        '<div style="font-family:var(--mono);font-size:0.52rem;color:var(--muted);'
        'letter-spacing:2px;margin-bottom:12px">SOC PIPELINE COLLECTIONS</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    chroma_path_in = st.text_input("ChromaDB path", value=CHROMA_PATH)
    if st.button("🗄️ Connect", use_container_width=True):
        client, err = connect_chroma(chroma_path_in)
        if client:
            st.success(f"Connected — {chroma_path_in}")
        else:
            st.error(err or "Failed to connect")
        st.rerun()

    client = get_chroma_client()
    if client is None and CHROMA_OK:
        client, _err = connect_chroma()
        if client:
            st.session_state.cv_chroma_client = client

    if client:
        st.markdown(
            '<div style="background:#041208;border:1px solid #0A3020;border-radius:5px;'
            'padding:8px 11px;font-family:var(--mono);font-size:0.6rem;margin:8px 0">'
            '<span style="color:#0AF0A0">● CONNECTED</span></div>',
            unsafe_allow_html=True,
        )
    elif not CHROMA_OK:
        st.error("chromadb not installed.\nRun: pip install chromadb")
    else:
        st.warning("Not connected. Click Connect above.")

    st.markdown("---")

    # Stage nav
    st.markdown(
        '<div style="font-family:var(--mono);font-size:0.58rem;'
        'color:var(--muted);letter-spacing:2px;margin-bottom:8px">■ STAGES</div>',
        unsafe_allow_html=True,
    )

    if "cv_stage" not in st.session_state:
        st.session_state.cv_stage = _preselect or PIPELINE_STAGES[0]

    for stage in PIPELINE_STAGES:
        icon  = PIPELINE_ICONS[stage]
        label = PIPELINE_LABELS[stage]
        color = PIPELINE_COLORS[stage]
        cnt   = sqlite_count(stage)
        is_sel = st.session_state.cv_stage == stage
        border = f"2px solid {color}" if is_sel else "1px solid #162840"
        bg     = f"{color}18" if is_sel else "#060C16"
        st.markdown(
            f'<div style="background:{bg};border:{border};border-radius:5px;'
            f'padding:7px 10px;margin:3px 0;cursor:pointer;font-family:var(--mono);'
            f'font-size:0.62rem;display:flex;justify-content:space-between">'
            f'<span style="color:{"var(--text)" if is_sel else "var(--muted)"}">'
            f'{icon} {label}</span>'
            f'<span style="color:{color};font-weight:bold">{cnt}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
        if st.button(f"Select", key=f"nav_{stage}", use_container_width=True,
                     help=label):
            st.session_state.cv_stage = stage
            st.rerun()

    st.markdown("---")
    st.markdown(
        f'<div style="font-family:var(--mono);font-size:0.5rem;color:#1A3A52;'
        f'text-align:center">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CONTENT
# ══════════════════════════════════════════════════════════════════════════════
stage = st.session_state.cv_stage
color = PIPELINE_COLORS[stage]
icon  = PIPELINE_ICONS[stage]
label = PIPELINE_LABELS[stage]

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    f'<div style="background:#060C16;border:1px solid {color};'
    f'border-left:6px solid {color};border-radius:8px;'
    f'padding:16px 22px;margin-bottom:16px">'
    f'<div style="font-family:var(--mono);font-size:1.1rem;color:{color};'
    f'letter-spacing:2px">{icon} {label.upper()}</div>'
    f'<div style="font-family:var(--mono);font-size:0.6rem;color:var(--muted);margin-top:4px">'
    f'ChromaDB collection: <code style="color:var(--accent)">pipeline_{stage}</code> &nbsp;·&nbsp; '
    f'SQLite table: <code style="color:var(--accent)">{stage}</code>'
    f'</div></div>',
    unsafe_allow_html=True,
)

# ── Summary metrics ────────────────────────────────────────────────────────────
sql_cnt  = sqlite_count(stage)
vec_cnt  = 0
if client:
    col_obj = get_collection(client, stage)
    if col_obj:
        vec_cnt = col_obj.count()

m1, m2, m3, m4 = st.columns(4)
m1.metric("💾 SQLite Records", sql_cnt)
m2.metric("🧠 ChromaDB Vectors", vec_cnt)
m3.metric("📋 Stage", label[:20])
m4.metric("🗂️ Collection", f"pipeline_{stage}")

st.markdown("---")

# ── Tabs: SQLite view | ChromaDB search ───────────────────────────────────────
vtab_sql, vtab_chroma = st.tabs(["💾  SQLITE RECORDS", "🧠  CHROMADB SEARCH"])


# ── SQLite tab ────────────────────────────────────────────────────────────────
with vtab_sql:
    st.markdown(
        '<div style="font-family:var(--mono);font-size:0.62rem;color:var(--muted);'
        'letter-spacing:2px;margin-bottom:10px">■ ALL RECORDS IN THIS STAGE</div>',
        unsafe_allow_html=True,
    )

    # Filter
    fc1, fc2 = st.columns([4, 1])
    sql_search = fc1.text_input("Filter by title / ID / summary",
                                placeholder="Type to filter…", key="sql_search")
    sql_limit  = fc2.number_input("Limit", 10, 2000, 200, key="sql_limit",
                                   label_visibility="collapsed")

    rows = sqlite_load(stage, limit=sql_limit)
    if sql_search.strip():
        s = sql_search.lower()
        rows = [r for r in rows if (
            s in (r.get("title") or "").lower() or
            s in (r.get("id") or "").lower() or
            s in (r.get("summary") or "").lower()
        )]

    if not rows:
        st.markdown(
            '<div style="text-align:center;padding:50px;font-family:var(--mono);'
            'font-size:0.78rem;color:var(--muted)">● NO RECORDS FOUND</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div style="font-family:var(--mono);font-size:0.6rem;color:var(--muted);'
            f'margin-bottom:8px">{len(rows)} records</div>',
            unsafe_allow_html=True,
        )
        for row in rows:
            r_id    = row.get("id","—")
            r_title = row.get("title","Untitled")
            r_sev   = row.get("severity","—")
            r_inc   = row.get("incident_id","—")
            r_sum   = (row.get("summary") or "")[:200]
            r_ts    = str(row.get("created_at",""))[:16]

            sev_colors = {
                "CRITICAL": "#FF3B3B", "HIGH": "#FF7700",
                "MEDIUM": "#FFB700", "LOW": "#0AF0A0",
            }
            sev_c = sev_colors.get(r_sev.upper(), "#3A607A")

            st.markdown(
                f'<div class="record-card" style="border:1px solid {color}44;'
                f'border-left:3px solid {color}">'
                f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
                f'<code style="font-family:var(--mono);font-size:0.65rem;color:{color}">{r_id}</code>'
                f'<strong style="flex:1;font-size:0.85rem">{r_title}</strong>'
                f'<span class="badge" style="background:{sev_c}22;color:{sev_c};'
                f'border:1px solid {sev_c}44">{r_sev}</span>'
                f'<span style="font-family:var(--mono);font-size:0.56rem;color:var(--muted)">{r_ts}</span>'
                f'</div>'
                f'<div style="font-size:0.7rem;color:var(--muted);margin-top:6px">'
                f'Incident: <code style="color:var(--accent)">{r_inc}</code>'
                f'{"&nbsp;·&nbsp;" + r_sum if r_sum else ""}'
                f'</div></div>',
                unsafe_allow_html=True,
            )

            if st.button("{ } View JSON", key=f"sql_json_{stage}_{r_id}"):
                try:
                    raw_j = json.loads(row.get("raw_json") or "{}")
                except Exception:
                    raw_j = row
                with st.expander(f"JSON — {r_id}", expanded=True):
                    st.json(raw_j)


# ── ChromaDB tab ──────────────────────────────────────────────────────────────
with vtab_chroma:
    st.markdown(
        '<div style="font-family:var(--mono);font-size:0.62rem;color:var(--muted);'
        'letter-spacing:2px;margin-bottom:10px">■ SEMANTIC SEARCH IN CHROMADB COLLECTION</div>',
        unsafe_allow_html=True,
    )

    if not client:
        st.warning("Connect ChromaDB from the sidebar to enable semantic search.")
    else:
        col_obj = get_collection(client, stage)
        if col_obj is None:
            st.error(f"Could not open collection pipeline_{stage}")
        else:
            vec_total = col_obj.count()
            st.markdown(
                f'<div style="font-family:var(--mono);font-size:0.65rem;'
                f'color:var(--muted);margin-bottom:10px">'
                f'{vec_total} vectors in <code>pipeline_{stage}</code></div>',
                unsafe_allow_html=True,
            )

            sq, sn = st.columns([5, 1])
            query  = sq.text_input("Semantic query", key="cv_query",
                                    placeholder="e.g. ransomware lateral movement C2")
            top_n  = sn.number_input("Top N", 1, 20, 5, key="cv_topn",
                                      label_visibility="collapsed")

            if st.button("🔍 Search", key="cv_search_btn") and query.strip():
                if vec_total == 0:
                    st.info("No vectors yet — run triage in the main app first.")
                else:
                    try:
                        res = col_obj.query(
                            query_texts=[query],
                            n_results=min(top_n, vec_total),
                        )
                        results = [
                            {
                                "id":    res["ids"][0][i],
                                "doc":   doc,
                                "score": round((1 - res["distances"][0][i]) * 100, 1),
                                "meta":  res["metadatas"][0][i],
                            }
                            for i, doc in enumerate(res["documents"][0])
                        ]
                        if not results:
                            st.info("No results.")
                        for r in results:
                            m    = r["meta"]
                            scol = PIPELINE_COLORS.get(m.get("stage", stage), color)
                            st.markdown(
                                f'<div class="record-card" style="border:1px solid {scol}55;'
                                f'border-left:3px solid {scol}">'
                                f'<div style="display:flex;align-items:center;gap:10px">'
                                f'<span class="badge" style="background:{scol}22;color:{scol};'
                                f'border:1px solid {scol}44">{r["score"]}%</span>'
                                f'<strong>{r["id"]}</strong>'
                                f'<span style="font-family:var(--mono);font-size:0.58rem;'
                                f'color:var(--muted)">'
                                f'sev:{m.get("severity","?")} · {m.get("created","")[:10]}'
                                f'</span></div>'
                                f'<div style="font-size:0.72rem;color:var(--text);margin-top:6px">'
                                f'{r["doc"][:300]}</div>'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                    except Exception as e:
                        st.error(f"Search error: {e}")

            st.markdown("---")

            # ── Browse all vectors ─────────────────────────────────────────────
            st.markdown(
                '<div style="font-family:var(--mono);font-size:0.6rem;color:var(--muted);'
                'letter-spacing:2px;margin-bottom:8px">■ BROWSE ALL VECTORS</div>',
                unsafe_allow_html=True,
            )
            if st.button("📋 Load All Vectors", key="cv_load_all"):
                if vec_total == 0:
                    st.info("No vectors in this collection.")
                else:
                    try:
                        all_data = col_obj.get(include=["documents","metadatas"])
                        for i, doc_id in enumerate(all_data["ids"]):
                            doc  = all_data["documents"][i] if all_data["documents"] else ""
                            meta = all_data["metadatas"][i] if all_data["metadatas"] else {}
                            scol = PIPELINE_COLORS.get(meta.get("stage", stage), color)
                            st.markdown(
                                f'<div class="record-card" style="border:1px solid {scol}44;'
                                f'border-left:3px solid {scol}">'
                                f'<div style="display:flex;gap:10px;align-items:center">'
                                f'<code style="font-size:0.62rem;color:{scol}">{doc_id}</code>'
                                f'<span style="font-family:var(--mono);font-size:0.56rem;'
                                f'color:var(--muted)">'
                                f'sev:{meta.get("severity","?")} · {meta.get("created","")[:10]}'
                                f'</span></div>'
                                f'<div style="font-size:0.7rem;color:var(--text);margin-top:5px">'
                                f'{str(doc)[:250]}</div>'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                    except Exception as e:
                        st.error(f"Error loading vectors: {e}")

            st.markdown("---")

            # ── Wipe collection ────────────────────────────────────────────────
            st.markdown(
                '<div style="font-family:var(--mono);font-size:0.6rem;color:var(--muted);'
                'letter-spacing:2px;margin-bottom:8px">■ ACTIONS</div>',
                unsafe_allow_html=True,
            )
            if st.button(f"🗑️ Wipe Collection pipeline_{stage}", key="cv_wipe"):
                try:
                    client.delete_collection(f"pipeline_{stage}")
                    get_collection(client, stage)  # recreate empty
                    st.success(f"Collection pipeline_{stage} wiped and recreated.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))