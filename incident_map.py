"""
incident_map.py — Stage 1 of the autonomous incident-mapping upgrade.

Deterministic entity-graph extraction from a NetWitness incident: no LLM,
no network, no database writes. Walks the incident's scalar fields,
alertMeta, MITRE tactics/techniques, and (when present) the raw alerts
array with per-event source/destination detail, and emits a typed graph:

    nodes: host / user / ip / domain / process / file / hash / mitre
    edges: connected_to / focus_of / observed / mapped_to ... with an
           `evidence` tag saying exactly where each edge came from
           (alertMeta, title, alert event, ...) — nothing is invented.

Today's stored incidents only carry SourceIp/DestinationIp in alertMeta
plus the title entity, so maps are modest; the alert/event walker below
lights up automatically once the per-incident alerts fetch is fixed.

Stage 2 (autonomous expansion via NetWitness queries) and Stage 3 (LLM
narration over the graph) build on the dict this module returns.

Usage:
    imap = build_incident_map(incident)            # incident dict from API/DB
    dot  = to_dot(imap)                            # for st.graphviz_chart
    txt  = summarize_map(imap)                     # plain-text for agents
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# ── entity classification ────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
# "High Risk Alerts: NetWitness Endpoint for KELLYWANG" → "KELLYWANG"
_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")

# meta-key substrings → node type (checked in order; suffix conventions match
# the triage agent's metakey extraction)
_KEY_TYPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sourceip", "ip.src", "ip_src", "srcip"), "ip"),
    (("destinationip", "ip.dst", "ip_dst", "dstip"), "ip"),
    (("checksum", "hash"), "hash"),
    (("process",), "process"),
    (("filename", "file."), "file"),
    (("user", "username"), "user"),
    (("host", "alias.host", "device"), "host"),
    (("domain", "fqdn"), "domain"),
]


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _classify_value(value: str, key_hint: str = "") -> str:
    """Best-effort node type for a raw string, using the meta key when known."""
    v = value.strip()
    if _IP_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash"
    hint = key_hint.lower()
    for needles, ntype in _KEY_TYPE_RULES:
        if any(n in hint for n in needles):
            return ntype
    if "." in v and " " not in v and any(c.isalpha() for c in v):
        return "domain"
    return "entity"  # honest: shape alone can't tell user from hostname


# ── graph assembly ────────────────────────────────────────────────────────────


class _Graph:
    """Dedup-on-insert node/edge accumulator."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, ntype: str, value: str, **props: Any) -> str:
        nid = f"{ntype}:{value}"
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": value, "props": {}}
        self.nodes[nid]["props"].update({k: v for k, v in props.items() if v not in (None, "", [])})
        return nid

    def edge(self, src: str, dst: str, relation: str, evidence: str) -> None:
        key = (src, dst, relation)
        if key in self.edges:
            self.edges[key]["count"] += 1
            if evidence not in self.edges[key]["evidence"]:
                self.edges[key]["evidence"].append(evidence)
        else:
            self.edges[key] = {
                "src": src, "dst": dst, "relation": relation,
                "evidence": [evidence], "count": 1,
            }


def _walk_alert(g: _Graph, inc_node: str, alert: dict, timeline: list[dict]) -> None:
    """Extract entities/edges from one raw alert (Respond API shape)."""
    a_id = str(alert.get("id") or "?")
    ev_tag = f"alert {a_id}"
    when = alert.get("created") or alert.get("receivedTime")
    if when:
        timeline.append({"time": str(when),
                         "event": alert.get("title") or alert.get("name") or f"alert {a_id}"})

    # flat convenience fields some alert shapes carry
    flat = {
        "sourceIp": "ip", "destinationIp": "ip", "domain": "domain",
        "userName": "user", "fileName": "file", "fileHash": "hash",
        "processName": "process", "hostSummary": "host",
    }
    for field, ntype in flat.items():
        val = alert.get(field)
        for v in (val if isinstance(val, list) else [val]):
            if v and isinstance(v, str):
                g.edge(inc_node, g.node(ntype, v), "observed", ev_tag)

    for ev in alert.get("events") or []:
        if not isinstance(ev, dict):
            continue
        side_nodes: dict[str, str | None] = {"source": None, "destination": None}
        for side in ("source", "destination"):
            node = ev.get(side) or {}
            if not isinstance(node, dict):
                continue
            dev = node.get("device") or {}
            ip = dev.get("ipAddress") or node.get("ipAddress")
            hostname = dev.get("dnsHostname") or dev.get("dnsDomain")
            username = (node.get("user") or {}).get("username") or node.get("username")
            if ip:
                side_nodes[side] = g.node("ip", str(ip), private=_is_private_ip(str(ip)))
            if hostname:
                h = g.node("host", str(hostname))
                if side_nodes[side]:
                    g.edge(h, side_nodes[side], "resolves_to", ev_tag)
                else:
                    side_nodes[side] = h
            if username:
                u = g.node("user", str(username))
                if side_nodes[side]:
                    g.edge(u, side_nodes[side], "active_on", ev_tag)
        if side_nodes["source"] and side_nodes["destination"]:
            port = ((ev.get("destination") or {}).get("device") or {}).get("port") or ev.get("port")
            proto = ev.get("ip_proto") or ev.get("protocol")
            rel = "connected_to" + (f" :{port}" if port else "") + (f" ({proto})" if proto else "")
            g.edge(side_nodes["source"], side_nodes["destination"], rel, ev_tag)
        dom = ev.get("domain") or ev.get("domain_dst")
        if dom and side_nodes["source"]:
            g.edge(side_nodes["source"], g.node("domain", str(dom)), "queried", ev_tag)


def build_incident_map(incident: dict, alerts: list | None = None,
                       max_alerts: int = 200) -> dict:
    """Build the typed entity graph for one incident.

    `alerts` defaults to incident["alerts"] when present. Returns a plain
    dict (JSON-safe) with nodes, edges, timeline, and honest stats about
    which evidence sources were available.
    """
    g = _Graph()
    timeline: list[dict] = []
    inc_id = str(incident.get("id") or "?")
    title = str(incident.get("title") or incident.get("name") or "")

    inc_node = g.node("incident", inc_id, title=title,
                      priority=incident.get("priority"),
                      risk_score=incident.get("riskScore"),
                      detection_source=incident.get("createdBy"))

    for field, label in (("firstAlertTime", "first alert"),
                         ("created", "incident created"),
                         ("lastUpdated", "last updated")):
        if incident.get(field):
            timeline.append({"time": str(incident[field]), "event": label})

    # 1. title entity — often the only named endpoint/user NetWitness gives us
    m = _TITLE_ENTITY_RE.search(title)
    if m:
        val = m.group(1).strip()
        g.edge(g.node(_classify_value(val), val), inc_node, "focus_of", "incident title")

    # 2. alertMeta — incident-level indicator lists (SourceIp/DestinationIp today)
    meta = incident.get("alertMeta")
    src_ids: list[str] = []
    dst_ids: list[str] = []
    if isinstance(meta, dict):
        for key, values in meta.items():
            k_low = str(key).lower()
            for v in (values if isinstance(values, list) else [values]):
                if not v or not isinstance(v, str):
                    continue
                ntype = _classify_value(v, k_low)
                nid = g.node(ntype, v, private=_is_private_ip(v) if ntype == "ip" else None)
                if "source" in k_low or ".src" in k_low:
                    src_ids.append(nid)
                elif "destination" in k_low or ".dst" in k_low:
                    dst_ids.append(nid)
                else:
                    g.edge(inc_node, nid, "observed", f"alertMeta {key}")
        # network flow edges: every source talked to the destination set
        for s in src_ids:
            for d in dst_ids:
                g.edge(s, d, "connected_to", "alertMeta co-occurrence")
        if src_ids and not dst_ids:
            for s in src_ids:
                g.edge(inc_node, s, "observed", "alertMeta")

    # 3. MITRE tactics / techniques (empty on most stored incidents, kept for live data)
    for field, rel in (("tactics", "tactic"), ("techniques", "technique")):
        for t in incident.get(field) or []:
            if t:
                g.edge(inc_node, g.node("mitre", str(t), kind=rel), "mapped_to", f"incident {field}")

    # 4. raw alerts with per-event detail — the walker that matters once the
    #    per-incident alerts fetch is fixed (today usually absent/empty)
    alerts = alerts if alerts is not None else incident.get("alerts")
    n_alerts_walked = 0
    if isinstance(alerts, list):
        for alert in alerts[:max_alerts]:
            if isinstance(alert, dict):
                _walk_alert(g, inc_node, alert, timeline)
                n_alerts_walked += 1

    timeline.sort(key=lambda t: t["time"])
    type_counts: dict[str, int] = {}
    for n in g.nodes.values():
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1

    return {
        "incident_id": inc_id,
        "title": title,
        "nodes": list(g.nodes.values()),
        "edges": list(g.edges.values()),
        "timeline": timeline,
        "stats": {
            "node_counts": type_counts,
            "edge_count": len(g.edges),
            "alerts_walked": n_alerts_walked,
            "alerts_available": isinstance(alerts, list) and len(alerts) > 0,
            "alerts_stripped": incident.get("_alerts_stripped"),
            "evidence_basis": (
                f"{n_alerts_walked} raw alerts + incident metadata"
                if n_alerts_walked
                else "incident-level metadata only (per-incident alerts not available)"
            ),
        },
    }


# ── rendering ────────────────────────────────────────────────────────────────

_DOT_STYLE = {
    "incident": ('box', '#0E2A3F', '#4FC3F7'),
    "ip":       ('ellipse', '#102437', '#81D4FA'),
    "host":     ('box', '#14324A', '#A5D6A7'),
    "user":     ('ellipse', '#1B2A44', '#FFCC80'),
    "domain":   ('ellipse', '#241B3A', '#CE93D8'),
    "process":  ('box', '#2A2438', '#EF9A9A'),
    "file":     ('note', '#232D3A', '#B0BEC5'),
    "hash":     ('note', '#1C2A2E', '#80CBC4'),
    "mitre":    ('hexagon', '#33222A', '#F48FB1'),
    "entity":   ('ellipse', '#1E2B36', '#E0E0E0'),
}


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(imap: dict, max_fanout: int = 20) -> str:
    """DOT source for st.graphviz_chart. High-fanout node groups (e.g. one
    source IP → 700 destinations) are capped at `max_fanout` with an
    aggregate "+N more" node so the graph stays readable."""
    nodes = {n["id"]: n for n in imap["nodes"]}
    edges = imap["edges"]

    # cap fanout per (src, relation)
    fan: dict[tuple, list[dict]] = {}
    for e in edges:
        fan.setdefault((e["src"], e["relation"]), []).append(e)

    lines = [
        "digraph incident {",
        '  rankdir=LR; bgcolor="transparent";',
        '  node [fontname="Helvetica", fontsize=11, style="filled", fontcolor="#E8F1F8"];',
        '  edge [fontname="Helvetica", fontsize=9, color="#5B7A8F", fontcolor="#9FB8C8"];',
    ]
    used: set[str] = set()
    agg_i = 0

    def emit_node(nid: str, label: str | None = None, ntype: str | None = None) -> None:
        if nid in used:
            return
        used.add(nid)
        n = nodes.get(nid, {})
        t = ntype or n.get("type", "entity")
        shape, fill, border = _DOT_STYLE.get(t, _DOT_STYLE["entity"])
        lbl = _dot_escape(label if label is not None else n.get("label", nid))
        if t == "incident":
            lbl = f"{lbl}\\n{_dot_escape((n.get('props') or {}).get('title', '') or '')[:48]}"
        lines.append(
            f'  "{_dot_escape(nid)}" [label="{lbl}", shape={shape}, '
            f'fillcolor="{fill}", color="{border}"];'
        )

    for (src, relation), group in fan.items():
        emit_node(src)
        shown = group[:max_fanout]
        for e in shown:
            emit_node(e["dst"])
            lines.append(
                f'  "{_dot_escape(e["src"])}" -> "{_dot_escape(e["dst"])}" '
                f'[label="{_dot_escape(relation)}"];'
            )
        hidden = len(group) - len(shown)
        if hidden > 0:
            agg_i += 1
            agg = f"agg:{agg_i}"
            emit_node(agg, label=f"+{hidden} more", ntype=nodes.get(shown[0]["dst"], {}).get("type", "entity"))
            lines.append(
                f'  "{_dot_escape(src)}" -> "{agg}" '
                f'[label="{_dot_escape(relation)}", style=dashed];'
            )
    # nodes with no edges at all still get drawn; fanout-hidden ones don't
    in_edges = {e["src"] for e in edges} | {e["dst"] for e in edges}
    for nid in nodes:
        if nid not in in_edges:
            emit_node(nid)
    lines.append("}")
    return "\n".join(lines)


def map_caption(imap: dict) -> str:
    """One-line honest summary for UI captions."""
    s = imap["stats"]
    parts = [f"{t}: {c}" for t, c in sorted(s["node_counts"].items()) if t != "incident"]
    if s.get("related_incidents"):
        parts.append(f"related incidents: {s['related_incidents']}")
    return (
        f"{s['edge_count']} relationships · " + (", ".join(parts) or "no entities") +
        f" · basis: {s['evidence_basis']}"
    )


def summarize_map(imap: dict, max_lines: int = 40) -> str:
    """Plain-text rendering of the graph for agent prompts (Stage 3 hook)."""
    nodes = {n["id"]: n for n in imap["nodes"]}
    out = [f"ENTITY MAP for {imap['incident_id']} — {imap['title']}",
           f"basis: {imap['stats']['evidence_basis']}"]
    for e in imap["edges"][:max_lines]:
        src = nodes.get(e["src"], {}).get("label", e["src"])
        dst = nodes.get(e["dst"], {}).get("label", e["dst"])
        ev = ", ".join(e["evidence"][:3])
        out.append(f"  {src} -[{e['relation']}]-> {dst}  (evidence: {ev})")
    if len(imap["edges"]) > max_lines:
        out.append(f"  ... and {len(imap['edges']) - max_lines} more relationships")
    if imap["timeline"]:
        out.append("TIMELINE:")
        for t in imap["timeline"][:15]:
            out.append(f"  {t['time']} — {t['event']}")
    # deep endpoint analysis block (set by incident_expansion when the focus
    # entity has corpus history) — pre-formatted, appended verbatim
    if imap.get("endpoint_profile_text"):
        out.append(imap["endpoint_profile_text"])
    return "\n".join(out)
