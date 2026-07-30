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
# =============================================================================
# [FYP-FILE] nw_alerts.py
# Important dependencies: __future__.
# -----------------------------------------------------------------------------
# File: nw_alerts.py (repo root)
#
# Purpose:
#   Pure, stdlib-only helper functions for parsing NetWitness Respond
#   "/rest/api/incidents/{id}/alerts" API responses and distilling their
#   nested event/endpoint data into the incident's alertMeta structure.
#   Extracted verbatim from app.py to slim the Streamlit monolith and make
#   the logic independently unit-testable — no Streamlit, session state,
#   globals, or network calls in this module.
#
# Main functionalities:
#   1. [FYP-PROCESS] Response-shape normalisation — _extract_alert_items()
#      pulls the alert list out of whichever shape a given NW version's
#      alerts response takes (bare list / items / results / alerts /
#      content, or one level nested under data); _alerts_has_more() checks
#      for another page across NW's differing pagination conventions
#      (hasNext / Spring Pageable last / totalPages).
#   2. [FYP-PROCESS] Endpoint/IOC distillation — _distill_alerts() walks
#      each alert's nested events (incl. NetWitness Endpoint/ECAT
#      source/destination device+user structures) into a flat, deduped,
#      size-capped alertMeta-shaped digest (Hostname, User, SourceIp,
#      DestinationIp, FileHash, FileName, BehavioralIOC, MacAddress,
#      DnsDomain, AdUser, AlertTitles/Types/Tactics/Techniques).
#   3. [FYP-PROCESS] Digest merge — _merge_alert_digest() folds that digest
#      additively into inc['alertMeta'] (existing keys are unioned, never
#      clobbered) and backfills a top-level hostname.
#   4. [FYP-ERROR] Diagnostics — _alerts_error_hint() maps a failed fetch's
#      HTTP status to an actionable next step; _alerts_fetch_warning()
#      renders the full UI-facing warning (code + hint + endpoint +
#      response snippet) when alerts didn't attach to an incident.
#
# Inputs:
#   Raw NetWitness Respond alerts-endpoint JSON (per-page dict/list), an
#   incident dict (for _merge_alert_digest/_alerts_fetch_warning), an HTTP
#   status code (for _alerts_error_hint).
#
# Outputs:
#   Normalised alert-item lists, a "more pages remain" bool, an
#   alertMeta-shaped digest dict, an incident dict with alertMeta merged in
#   place, and plain-text warning strings for the UI.
#
# Workflow position:
#   Runs during alert ingestion (Parsing / pre-Triage), so alertMeta is
#   populated with a real host/user before Triage, Investigation and the
#   skills sidecar run — otherwise those stages see "Unknown".
#
# Called by [FYP-USED-BY]:
#   app.py imports all six functions (see the `from nw_alerts import …`
#   block near line 2159); the per-incident alerts-fetch/pagination loop
#   (~lines 2319-2346) uses _extract_alert_items/_alerts_has_more/
#   _alerts_error_hint/_merge_alert_digest, and _alerts_fetch_warning is
#   used in the incident-detail UI (~line 6924). soc_workflow.py imports
#   _merge_alert_digest directly (`from nw_alerts import _merge_alert_digest`)
#   and calls it from enrich_incident_with_apiretrieval_fetch() after an
#   APIRetrieval FETCH-API enrichment. diamond_model.py and
#   skills_sidecar.py only *mention* _distill_alerts/_merge_alert_digest in
#   comments, not live imports — verified via grep, not treated as callers.
#
# Calls [FYP-CALLS]:
#   None — pure stdlib (isinstance/dict/list/str operations only); no
#   network, DB, Streamlit or session-state access anywhere in this file.
#
# Key evaluator search terms:
#   _distill_alerts, _merge_alert_digest, alertMeta, ECAT, NetWitness
#   Endpoint, pagination, alerts fetch warning.
# =============================================================================

from __future__ import annotations


# =============================================================================
# [FYP-SECTION] THREAT INTELLIGENCE AND NETWITNESS INTEGRATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def _extract_alert_items(payload) -> list:
    """[FYP-FUNCTION] [FYP-PROCESS] Alerts-response shape normaliser.

    Pull the alert list out of a NetWitness alerts response across the shapes
    different NW versions return: a bare list, {items:[…]}, {results/alerts/
    content:[…]}, or one level nested under {data:{…}}. Non-dict entries are
    filtered out defensively at every level.
    [FYP-CALLS] none — pure isinstance/dict-key parsing, no I/O.
    [FYP-USED-BY] app.py's per-incident alerts pagination loop, called once
    per fetched page before _distill_alerts()/_merge_alert_digest()."""
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
    """[FYP-FUNCTION] [FYP-PROCESS] Cross-convention pagination check.

    Whether more pages remain, across NW pagination conventions: hasNext
    (RSA), last=true (Spring Pageable), or totalPages. Checked in that
    order — the first convention present in the payload wins; a payload
    that isn't a dict, or exposes none of the three keys, is treated as
    "no more pages" (returns False) rather than looping forever.
    [FYP-CALLS] none — pure dict-key parsing, no I/O.
    [FYP-USED-BY] app.py's per-incident alerts pagination loop, evaluated
    after each page fetched via _extract_alert_items() to decide whether
    to request page+1."""
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
    """[FYP-FUNCTION] [FYP-ERROR] HTTP-status -> actionable-hint lookup.

    Actionable next-step for a failed alerts fetch, keyed on HTTP status — so a
    live (VPN) run surfaces exactly what to fix instead of a bare code.
    Covers the four statuses actually observed against the per-incident
    alerts endpoint (401 expired/invalid token, 403 missing permission, 404
    endpoint not present on this NW version, 400 bad request/missing query
    params); any other code falls through to a generic "capture the body"
    hint rather than a wrong-sounding specific one.
    [FYP-CALLS] none — a static dict lookup, no I/O.
    [FYP-USED-BY] app.py's alerts-fetch failure path (feeds the diagnostic
    string attached to the incident) and, by extension, whatever
    _alerts_fetch_warning() ends up rendering for the UI."""
    return {
        401: "token expired/invalid — re-login (Refresh Data alone won't help until you re-auth)",
        403: "account lacks permission on the incident-alerts endpoint — grant "
             "integration-server.api.access / respond-server alert read",
        404: "alerts path not found for this incident — this NW version may expose "
             "alerts elsewhere (e.g. the incident detail returns alertIds to fetch individually)",
        400: "bad request — the alerts endpoint may require query params (e.g. a date range) on this NW version",
    }.get(int(code), "unexpected response — capture the body snippet below to diagnose")


def _distill_alerts(alerts: list) -> dict:
    """[FYP-FUNCTION] [FYP-PROCESS] Endpoint identity + behavioural-IOC
    distillation (the core of this module).

    Pull the incident-level indicators out of the fetched alerts' nested event
    structure. NetWitness Endpoint (ECAT) alerts carry the endpoint identity and
    behavioural IOCs that the incident object itself lacks — the machine name in
    events[].domain, the alert name in alert.title, and (when populated)
    source/destination device+user fields. Distilling these into alertMeta is
    what lets triage/investigation/skills see a real host/user instead of
    "Unknown". Deterministic, dedup, bounded, null-safe. Pure → unit-testable.

    Mechanics: the inner _add() helper appends a value into bucket[key] only
    if it's non-empty after stripping and isn't one of a fixed set of
    placeholder strings ("none"/"null"/"n/a"/"unknown"/"[]"/"{}"/…), and
    only if not already present (dedup). Iterates at most 250 alerts and,
    per alert, at most 50 events (`[:250]` / `[:50]` slices) so a huge
    incident can't blow up processing time; every output list is further
    capped to 40 entries in the final `{k: v[:40] ...}` comprehension.
    Reads both the flat per-event fields (domain, user_src, ip_src, ip_dst,
    checksum_src, filename_src, boc, …) AND the nested source/destination
    device+user sub-objects (dnsHostname, ipAddress, macAddress,
    dnsDomain, username, adUsername) — ECAT alerts populate one shape or
    the other depending on version/config, so both are read defensively.
    [FYP-CALLS] none — pure dict/list traversal and string normalisation,
    no I/O.
    [FYP-USED-BY] _merge_alert_digest() (this file), which folds this
    function's return value into an incident's alertMeta."""
    # [FYP-FUNCTION] `_add` — implements the add operation used by the surrounding threat intelligence and NetWitness integration workflow.
    # [FYP-INPUT] Parameters: `bucket`, `key`, `val`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include nw_alerts.py:_add, nw_alerts.py:_distill_alerts, skills_sidecar.py:_assets_from_skills; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_add`, `append`, `isinstance`, `lower`, `setdefault`, `str`, `strip`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _add(bucket: dict, key: str, val) -> None:
        if isinstance(val, list):
            for v_item in val:
                _add(bucket, key, v_item)
            return
        v = str(val or "").strip()
        if v and v.lower() not in ("none", "null", "n/a", "na", "undefined", "not available", "unknown", "[]", "{}"):
            bucket.setdefault(key, [])
            if v not in bucket[key]:
                bucket[key].append(v)

    out: dict = {}
    for a in (alerts or [])[:250]:
        if not isinstance(a, dict):
            continue
        orig = a.get("originalAlert") if isinstance(a.get("originalAlert"), dict) else a
        _add(out, "AlertTitles", a.get("title") or a.get("name") or orig.get("moduleName"))
        _add(out, "AlertTypes", a.get("type"))
        for t in (a.get("tactics") or orig.get("tactics") or []):
            _add(out, "AlertTactics", t.get("name") if isinstance(t, dict) else t)
        for t in (a.get("techniques") or orig.get("techniques") or []):
            _add(out, "AlertTechniques", t.get("id") if isinstance(t, dict) else t)
        
        events = a.get("events") or orig.get("events") or []
        for ev in (events or [])[:50]:
            if not isinstance(ev, dict):
                continue
            _add(out, "Hostname", ev.get("domain"))  # ECAT machine/agent name
            _add(out, "Hostname", ev.get("alias_host"))
            _add(out, "Hostname", ev.get("host_src"))
            _add(out, "User", ev.get("user_src"))
            _add(out, "User", ev.get("owner"))
            _add(out, "SourceIp", ev.get("ip_src"))
            _add(out, "DestinationIp", ev.get("ip_dst"))
            _add(out, "FileHash", ev.get("checksum_src") or ev.get("hash") or ev.get("file_hash"))
            _add(out, "FileName", ev.get("filename_src") or ev.get("filename") or ev.get("process_name"))
            _add(out, "BehavioralIOC", ev.get("boc") or ev.get("context_src"))
            
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
    """[FYP-FUNCTION] [FYP-PROCESS] alertMeta merge (in-place incident mutation).

    Merge distilled alert indicators into inc['alertMeta'] (additive — existing
    keys are unioned, never clobbered) and surface a top-level hostname so
    asset_criticality and the host-based skills pick it up. Persisted via the slim
    raw_json (alertMeta is kept), so the endpoint identity survives into the DB
    and every downstream consumer even though the bulky alerts array is stripped.

    No-op (returns immediately) if inc['alerts'] distils to an empty digest.
    Existing alertMeta values are coerced to a list before unioning (a
    non-list existing value is replaced wholesale by the digest's list) so
    the merge never raises on a malformed pre-existing alertMeta shape.
    inc['hostname'] is only backfilled when currently unset, so it never
    overwrites a hostname already established elsewhere in the pipeline.
    [FYP-CALLS] _distill_alerts() (this file) — no direct I/O of its own.
    [FYP-USED-BY] app.py (imported directly, called after each incident's
    alerts finish paginating) and soc_workflow.py
    (enrich_incident_with_apiretrieval_fetch(), after an APIRetrieval
    FETCH-API enrichment) — see this file's [FYP-FILE] header for exact
    call sites, verified via grep."""
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
    """[FYP-FUNCTION] [FYP-ERROR] UI-facing alerts-fetch failure renderer.

    Actionable UI warning when an incident's alerts didn't attach: the code,
    the status-specific hint, the exact endpoint, and a response snippet.
    Reads inc['alerts_fetch_error'] / inc['alerts_fetch_diag'] (populated
    upstream by app.py's fetch loop using _alerts_error_hint()'s hint text)
    and degrades gracefully — each optional diag field (hint/url/body) only
    adds its line if present, so a partially-populated diag dict still
    renders a usable message rather than raising.
    [FYP-CALLS] none — pure string formatting of fields already present on
    `inc`; no DB or network access.
    [FYP-USED-BY] app.py's incident-detail UI (renders this string as a
    Streamlit warning when an incident's alerts failed to attach)."""
    err = inc.get("alerts_fetch_error") or "unknown"
    diag = inc.get("alerts_fetch_diag") or {}
    msg = f"Alerts fetch failed: **{err}**."
    if diag.get("hint"):
        msg += f" {diag['hint']}."
    if diag.get("url"):
        msg += f"\n\n• Endpoint tried: `{diag['url']}`"
    if diag.get("body"):
        msg += f"\n\n• Response: `{str(diag['body'])[:160]}`"
    msg += ("\n\nTriage/investigation will have no per-alert event data for this "
            "incident. Click **Refresh Data** to re-fetch.")
    return msg
