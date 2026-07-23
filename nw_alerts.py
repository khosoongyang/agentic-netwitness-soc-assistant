"""
nw_alerts.py — NetWitness alert-response parsing & distillation (pure helpers).

Extracted verbatim from app.py to start slimming the Streamlit monolith. These
functions are PURE (stdlib only — no Streamlit, no session state, no globals,
no network), so they unit-test offline and app.py imports them unchanged.

WHAT'S HERE
    _extract_alert_items(payload)   — pull the alert list out of any NW response
                                      shape (bare list / items / results / …/ nested)
    _alerts_has_more(payload, page) — pagination across NW conventions
                                      (hasNext / Spring last / totalPages)
    _alerts_error_hint(code)        — actionable next-step for a failed fetch by
                                      HTTP status
    _distill_alerts(alerts)         — pull endpoint identity + behavioural IOCs out
                                      of the alerts' nested event structure into a
                                      flat alertMeta-shaped digest
    _merge_alert_digest(inc)        — fold the digest into inc['alertMeta']
                                      (additive) + surface a top-level hostname
    _alerts_fetch_warning(inc)      — actionable UI warning string when alerts
                                      didn't attach

Behaviour is identical to the previous in-app definitions; this is a move, not a
rewrite. The per-incident alerts endpoint (/rest/api/incidents/{id}/alerts) has
returned 0 attached alerts even when alertCount>0; these helpers make the fetch
robust to the two failure modes seen: (1) a 200 whose JSON isn't the
{items,hasNext} shape the incidents-list endpoint uses, and (2) an HTTP error
whose bare code alone wasn't enough to diagnose.
"""
from __future__ import annotations


def _extract_alert_items(payload) -> list:
    """Pull the alert list out of a NetWitness alerts response across the shapes
    different NW versions return: a bare list, {items:[…]}, {results/alerts/
    content:[…]}, or one level nested under {data:{…}}."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("items", "results", "alerts", "content", "data"):
            v = payload.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
            if isinstance(v, dict):  # e.g. {"data": {"items": [...]}}
                for k2 in ("items", "results", "alerts", "content"):
                    v2 = v.get(k2)
                    if isinstance(v2, list):
                        return [x for x in v2 if isinstance(x, dict)]
    return []


def _alerts_has_more(payload, page: int) -> bool:
    """Whether more pages remain, across NW pagination conventions: hasNext
    (RSA), last=true (Spring Pageable), or totalPages."""
    if not isinstance(payload, dict):
        return False
    if "hasNext" in payload:
        return bool(payload.get("hasNext"))
    if "last" in payload:
        return not bool(payload.get("last"))
    tp = payload.get("totalPages")
    if isinstance(tp, int):
        return (page + 1) < tp
    return False


def _alerts_error_hint(code: int) -> str:
    """Actionable next-step for a failed alerts fetch, keyed on HTTP status — so a
    live (VPN) run surfaces exactly what to fix instead of a bare code."""
    return {
        401: "token expired/invalid — re-login (Refresh Data alone won't help until you re-auth)",
        403: "account lacks permission on the incident-alerts endpoint — grant "
             "integration-server.api.access / respond-server alert read",
        404: "alerts path not found for this incident — this NW version may expose "
             "alerts elsewhere (e.g. the incident detail returns alertIds to fetch individually)",
        400: "bad request — the alerts endpoint may require query params (e.g. a date range) on this NW version",
    }.get(int(code), "unexpected response — capture the body snippet below to diagnose")


def _distill_alerts(alerts: list) -> dict:
    """Pull the incident-level indicators out of the fetched alerts' nested event
    structure. NetWitness Endpoint (ECAT) alerts carry the endpoint identity and
    behavioural IOCs that the incident object itself lacks — the machine name in
    events[].domain, the alert name in alert.title, and (when populated)
    source/destination device+user fields. Distilling these into alertMeta is
    what lets triage/investigation/skills see a real host/user instead of
    "Unknown". Deterministic, dedup, bounded, null-safe. Pure → unit-testable."""
    def _add(bucket: dict, key: str, val) -> None:
        v = str(val or "").strip()
        if v and v.lower() not in ("none", "null", "n/a"):
            bucket.setdefault(key, [])
            if v not in bucket[key]:
                bucket[key].append(v)

    out: dict = {}
    for a in (alerts or [])[:200]:
        if not isinstance(a, dict):
            continue
        _add(out, "AlertTitles", a.get("title"))
        _add(out, "AlertTypes", a.get("type"))
        for t in (a.get("tactics") or []):
            _add(out, "AlertTactics", t.get("name") if isinstance(t, dict) else t)
        for t in (a.get("techniques") or []):
            _add(out, "AlertTechniques", t.get("id") if isinstance(t, dict) else t)
        for ev in (a.get("events") or [])[:50]:
            if not isinstance(ev, dict):
                continue
            _add(out, "Hostname", ev.get("domain"))  # ECAT machine/agent name
            for side, ipkey in (("source", "SourceIp"), ("destination", "DestinationIp")):
                node = ev.get(side) or {}
                dev = node.get("device") or {}
                usr = node.get("user") or {}
                _add(out, ipkey, dev.get("ipAddress"))
                _add(out, "Hostname", dev.get("dnsHostname"))
                _add(out, "MacAddress", dev.get("macAddress"))
                _add(out, "DnsDomain", dev.get("dnsDomain"))
                _add(out, "User", usr.get("username"))
                _add(out, "AdUser", usr.get("adUsername"))
    # cap list sizes so a huge incident can't bloat alertMeta
    return {k: v[:40] for k, v in out.items()}


def _merge_alert_digest(inc: dict) -> None:
    """Merge distilled alert indicators into inc['alertMeta'] (additive — existing
    keys are unioned, never clobbered) and surface a top-level hostname so
    asset_criticality and the host-based skills pick it up. Persisted via the slim
    raw_json (alertMeta is kept), so the endpoint identity survives into the DB
    and every downstream consumer even though the bulky alerts array is stripped."""
    digest = _distill_alerts(inc.get("alerts") or [])
    if not digest:
        return
    meta = inc.get("alertMeta")
    if not isinstance(meta, dict):
        meta = {}
    for k, vals in digest.items():
        existing = meta.get(k)
        if isinstance(existing, list):
            meta[k] = existing + [v for v in vals if v not in existing]
        else:
            meta[k] = list(vals)
    inc["alertMeta"] = meta
    if not inc.get("hostname") and digest.get("Hostname"):
        inc["hostname"] = digest["Hostname"][0]


def _alerts_fetch_warning(inc: dict) -> str:
    """Actionable UI warning when an incident's alerts didn't attach: the code,
    the status-specific hint, the exact endpoint, and a response snippet."""
    err = inc.get("alerts_fetch_error") or "unknown"
    diag = inc.get("alerts_fetch_diag") or {}
    msg = f"⚠️ Alerts fetch failed: **{err}**."
    if diag.get("hint"):
        msg += f" {diag['hint']}."
    if diag.get("url"):
        msg += f"\n\n• Endpoint tried: `{diag['url']}`"
    if diag.get("body"):
        msg += f"\n\n• Response: `{str(diag['body'])[:160]}`"
    msg += ("\n\nTriage/investigation will have no per-alert event data for this "
            "incident. Click **Refresh Data** to re-fetch.")
    return msg
