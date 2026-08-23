"""
# =============================================================================
# [FYP-FILE] APIRetrieval.py
# Important dependencies: __future__, base64, dotenv, json, os, requests, sys.
# -----------------------------------------------------------------------------
# File: APIRetrieval.py (repo root)
#
# Purpose:
#   Retrieves incident + alert telemetry from the NetWitness Respond
#   REST API (a self-hosted SIEM/SOAR product — the org's own NetWitness
#   deployment, not a public/cloud service), with an on-disk export JSON
#   fallback for offline/repeatable runs. This is the module that talks to
#   NetWitness directly; nw_alerts.py (separate file) then parses/distills
#   whatever alerts this module returns.
#
# Main functionalities:
#   1. [FYP-API] Authentication — authenticate_netwitness() POSTs
#      username/password (optionally base64-decoded via
#      _maybe_b64_decode(), see NW_PASSWORD note below) to
#      /rest/api/auth/userpass to obtain a NetWitness accessToken, cached
#      into the NW_TOKEN/NETWITNESS_TOKEN env vars. get_auth_token() /
#      refresh_token() are the orchestrating entry points every fetch_*
#      function goes through rather than calling authenticate_netwitness()
#      directly.
#   2. [FYP-ERROR][FYP-FALLBACK] Expired-token detection + single-retry
#      auto-reauth — _is_expired_token_response() inspects a failed
#      response's status (500/401/403/400) and body text/JSON `errors[]`
#      for NetWitness's "Expired Token" signature. Every fetch_* function
#      that takes `auto_refresh` checks this on failure, calls
#      refresh_token() once, and retries the SAME request with the fresh
#      token — always with auto_refresh=False on the retry, so a second
#      failure is NOT retried again (bounds the reauth loop to one retry).
#   3. [FYP-API] Incident + alert retrieval — four distinct NetWitness
#      Respond endpoints, used for overlapping purposes (summary vs.
#      comprehensive raw export; single-shot vs. paginated):
#        - fetch_incident_details(): GET /rest/api/incidents/{id}
#        - fetch_incident_via_fetch_api(): GET /rest/api/incident/fetch
#        - fetch_alerts_via_fetch_api(): GET /rest/api/alert/fetch
#        - fetch_all_alerts_and_endpoint_events(): paginated GET
#          /rest/api/incidents/{id}/alerts
#      tried in a fallback chain by get_comprehensive_incident_payload().
#   4. [FYP-PROCESS] Telemetry synthesis — process_respond_api_telemetry()
#      is a pure transform (no network/DB) that flattens an incident + its
#      alerts' nested event/originalAlert structures into one structured
#      report: hosts/users/IPs, process-execution telemetry (launch args,
#      directories, filenames, hashes, behavioural IOCs), and MITRE
#      ATT&CK technique strings.
#   5. [FYP-PROCESS][FYP-FALLBACK] Orchestration —
#      get_comprehensive_incident_payload() tries on-disk export JSON
#      files first (offline / repeatable-demo path — no live NW call at
#      all if a matching file exists), then falls back to the live FETCH
#      API chain only if the disk lookup misses AND a host+token are
#      resolvable. main() is the CLI entry point; it additionally accepts
#      an export .json path directly on argv, bypassing the network path
#      entirely for demo/offline use.
#
# Inputs:
#   Environment (via python-dotenv): NW_HOST / NETWITNESS_HOST (default
#   "https://192.168.20.11" — an internal/lab NetWitness appliance
#   address, not a public host), NW_USERNAME / NETWITNESS_USERNAME,
#   NW_PASSWORD / NETWITNESS_PASSWORD (may be saved base64-encoded by
#   app.py to preserve special characters — decoded via
#   _maybe_b64_decode() before use; never logged), NW_TOKEN /
#   NETWITNESS_TOKEN (cached session token). Also: incident_id / host /
#   token function args, and on-disk incident_<id>*.json export files.
#
# Outputs:
#   dict/list payloads mirroring NetWitness's own response shapes
#   (incident dict, alerts list), a structured telemetry dict from
#   process_respond_api_telemetry(), and — from main() only — an on-disk
#   incident_<id>_respond_api_export.json snapshot.
#
# Workflow position:
#   Dual-purpose: (a) a standalone CLI ingestion utility (`python
#   APIRetrieval.py <INC-ID|export.json>`), and (b) a live-fetch
#   enrichment fallback invoked mid-pipeline — soc_workflow.py's
#   enrich_incident_with_apiretrieval_fetch() dynamically imports this
#   module and calls get_comprehensive_incident_payload() to backfill an
#   already-ingested incident with comprehensive raw alerts, which
#   nw_alerts._merge_alert_digest() then folds into alertMeta.
#
# Called by [FYP-USED-BY]:
#   soc_workflow.py — `import APIRetrieval` (dynamic, inside the function)
#   + `APIRetrieval.get_comprehensive_incident_payload(inc_id, host=host,
#   token=token)` in enrich_incident_with_apiretrieval_fetch()
#   (soc_workflow.py, ~line 3483-3489). tests/test_apiretrieval.py
#   exercises every public/underscored function directly with mocked
#   requests calls. Verified via grep — no other in-repo caller found.
#
# Calls [FYP-CALLS]:
#   requests — HTTP GET/POST to the NetWitness Respond REST API. Every
#   call passes verify=False (SSL verification disabled module-wide via
#   requests.packages.urllib3.disable_warnings() below) — consistent with
#   targeting an internal appliance with a self-signed certificate;
#   documented here, not altered by these doc-only edits. python-dotenv
#   (load_dotenv) loads the NW_*/NETWITNESS_* variables from a local .env
#   file. stdlib: os, sys, json, base64.
#
# Key evaluator search terms:
#   authenticate_netwitness, get_auth_token, _is_expired_token_response,
#   fetch_alerts_via_fetch_api, get_comprehensive_incident_payload,
#   NetWitness-Token, [FYP-API].
# =============================================================================
"""
from __future__ import annotations

import os
import sys
import json
import base64
import requests
import urllib3
from dotenv import load_dotenv

# Suppress SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


# =============================================================================
# [FYP-SECTION] THREAT INTELLIGENCE AND NETWITNESS INTEGRATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def _maybe_b64_decode(value: str) -> str:
    """[FYP-FUNCTION] Password decode helper (NOT authentication itself).

    Decode password if it was saved base64-encoded by app.py to preserve special
    characters. Strips surrounding whitespace/quotes first, then attempts a
    strict (validate=True) base64 decode; if that fails OR the decoded bytes
    aren't printable text, the original (already-stripped) value is returned
    unchanged — so a genuinely plain-text password that happens to look
    base64-shaped is never mis-decoded into garbage.
    [FYP-VALIDATION] base64.b64decode(..., validate=True) + str.isprintable()
    is the guard that distinguishes "was base64" from "just looks like it".
    Never logs or echoes the password value itself.
    [FYP-CALLS] base64 (stdlib) only — no I/O.
    [FYP-USED-BY] get_auth_token() (this file), applied to NW_PASSWORD /
    NETWITNESS_PASSWORD before it's handed to authenticate_netwitness()."""
    val = value.strip().strip("'\"").strip()
    if not val:
        return ""
    try:
        decoded = base64.b64decode(val.encode(), validate=True).decode("utf-8")
        return decoded if decoded.isprintable() else val
    except Exception:
        return val


# [FYP-FUNCTION] `authenticate_netwitness` — implements the authenticate netwitness operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`, `username`, `password`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:get_auth_token, tests/test_apiretrieval.py:test_authenticate_netwitness_failure, tests/test_apiretrieval.py:test_authenticate_netwitness_success; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `RuntimeError`, `get`, `json`, `post`, `print`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def authenticate_netwitness(host: str, username: str, password: str) -> str:
    """[FYP-API] NetWitness Respond — POST /rest/api/auth/userpass
    (username/password auth; no API-key env var — credentials come from
    NW_USERNAME/NW_PASSWORD via the caller, see get_auth_token()).

    Authenticate via NetWitness Respond API (/rest/api/auth/userpass) to obtain an accessToken.
    On HTTP 200, extracts accessToken (or access_token) from the JSON body,
    stores it into BOTH the NW_TOKEN and NETWITNESS_TOKEN env vars (the two
    aliases this module and its callers accept interchangeably) and returns
    it. Never echoes username/password in log output — only the login URL
    and username are printed, never the password.
    [FYP-ERROR] Non-200 response, or a 200 with no token field, both raise
    RuntimeError (with up to 200 chars of the response body for
    diagnosis) — this function does NOT swallow auth failures; callers
    (get_auth_token()) are the ones that catch and degrade to None.
    [FYP-CALLS] requests.post (verify=False, timeout=15s) — the one and
    only credential-bearing HTTP call in this module.
    [FYP-USED-BY] get_auth_token() (this file), which wraps this in a
    try/except so a login failure degrades to a logged warning + None
    rather than propagating."""
    login_url = f"{host}/rest/api/auth/userpass"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
        "Accept": "application/json;charset=UTF-8",
    }
    data = {"username": username, "password": password}

    print(f"[NetWitness Respond API] Authenticating at {login_url} (user: {username})...")
    response = requests.post(login_url, data=data, headers=headers, verify=False, timeout=15)

    if response.status_code == 200:
        res_data = response.json()
        session_token = res_data.get("accessToken") or res_data.get("access_token")
        if session_token:
            print("[NetWitness Respond API] Authentication successful! Session token acquired.")
            os.environ["NW_TOKEN"] = session_token
            os.environ["NETWITNESS_TOKEN"] = session_token
            return session_token
        raise RuntimeError(f"Login succeeded but no token returned: {res_data}")
    else:
        raise RuntimeError(f"Authentication failed (HTTP {response.status_code}): {response.text[:200]}")


def _is_expired_token_response(response: requests.Response | None) -> bool:
    """[FYP-FUNCTION] [FYP-ERROR] Expired-token signature detector — the
    trigger condition for every fetch_*() function's single-retry
    auto-reauth path.

    Check if API response indicates an expired or invalid token. A None
    response (e.g. the request itself raised) is treated as "not an
    expired token" (returns False) so callers fall through to their
    generic failure handling rather than looping on reauth for an
    unrelated network error. Only inspects status codes NetWitness
    actually uses for auth failure (500/401/403/400 — note 500 is
    included because this NW deployment has been observed returning a
    generic 500 for an expired token rather than 401); within those,
    checks the raw response text for "expired token"/"token expired"/
    "expired_token" (case-insensitive), then — if the body parses as
    JSON — also checks each entry of an `errors` list for "expired" or
    "token" in its message field. Any JSON-parse failure is swallowed
    (falls through to return False) since a non-JSON body on one of those
    status codes just isn't the expired-token case this function detects.
    [FYP-CALLS] none — pure string/JSON inspection of an already-received
    response object; makes no HTTP calls itself.
    [FYP-USED-BY] fetch_incident_details(), fetch_incident_via_fetch_api(),
    fetch_alerts_via_fetch_api(), fetch_all_alerts_and_endpoint_events()
    (this file) — each calls this on a non-200 response before deciding
    whether to refresh_token() and retry once."""
    if response is None:
        return False
    if response.status_code in (500, 401, 403, 400):
        text_lower = response.text.lower()
        if "expired token" in text_lower or "token expired" in text_lower or "expired_token" in text_lower:
            return True
        try:
            body = response.json()
            if isinstance(body, dict):
                errors = body.get("errors", [])
                if isinstance(errors, list):
                    for err in errors:
                        msg = err.get("message", "") if isinstance(err, dict) else str(err)
                        if "expired" in str(msg).lower() or "token" in str(msg).lower():
                            return True
        except Exception:
            pass
    return False


# [FYP-FUNCTION] `get_auth_token` — retrieves get auth token data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`, `token`, `force_refresh`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:get_comprehensive_incident_payload, APIRetrieval.py:main, APIRetrieval.py:refresh_token; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_maybe_b64_decode`, `authenticate_netwitness`, `getenv`, `load_dotenv`, `print`, `rstrip`, `strip`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def get_auth_token(host: str | None = None, token: str | None = None, force_refresh: bool = False) -> str | None:
    """Get an active NetWitness session token.
    If an explicit token is provided and force_refresh is False, return it.
    Otherwise, if token is not in memory or force_refresh is True,
    dynamically authenticate via NetWitness Respond API using NW_USERNAME & NW_PASSWORD.
    """
    if token and not force_refresh:
        return token.strip().strip("'\"")

    if not force_refresh:
        cached_token = os.getenv("NW_TOKEN", os.getenv("NETWITNESS_TOKEN", "")).strip().strip("'\"")
        if cached_token:
            return cached_token

    load_dotenv(override=True)
    target_host = (host or os.getenv("NW_HOST", os.getenv("NETWITNESS_HOST", "https://192.168.20.11"))).strip().rstrip("/")
    username = os.getenv("NW_USERNAME", os.getenv("NETWITNESS_USERNAME", "")).strip()
    raw_password = os.getenv("NW_PASSWORD", os.getenv("NETWITNESS_PASSWORD", "")).strip()
    password = _maybe_b64_decode(raw_password)

    if not username or not password:
        print("[APIRetrieval] Cannot authenticate: NW_USERNAME or NW_PASSWORD not found in environment.")
        return None

    try:
        print(f"[APIRetrieval] Authenticating user '{username}' at {target_host} to acquire fresh token...")
        session_token = authenticate_netwitness(target_host, username, password)
        return session_token
    except Exception as err:
        print(f"[APIRetrieval] Authentication failed: {err}")
        return None


# [FYP-FUNCTION] `refresh_token` — implements the refresh token operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:fetch_alerts_via_fetch_api, APIRetrieval.py:fetch_all_alerts_and_endpoint_events, APIRetrieval.py:fetch_incident_details; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get_auth_token`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def refresh_token(host: str | None = None) -> str | None:
    """Re-authenticate using NW_USERNAME / NW_PASSWORD from environment to acquire a fresh token."""
    return get_auth_token(host=host, force_refresh=True)


# [FYP-FUNCTION] `fetch_incident_details` — retrieves fetch incident details data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`, `headers`, `incident_id`, `auto_refresh`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:fetch_incident_details, APIRetrieval.py:get_comprehensive_incident_payload, APIRetrieval.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_is_expired_token_response`, `dict`, `fetch_incident_details`, `get`, `json`, `print`, `refresh_token`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def fetch_incident_details(host: str, headers: dict, incident_id: str, auto_refresh: bool = True) -> dict:
    """Fetch Incident details from NetWitness Respond API (/rest/api/incidents/{incident_id})."""
    url = f"{host}/rest/api/incidents/{incident_id}"
    print(f"[NetWitness Respond API] Fetching Incident metadata from {url}...")
    res = requests.get(url, headers=headers, verify=False, timeout=15)
    if res.status_code == 200:
        return res.json()

    if auto_refresh and _is_expired_token_response(res):
        print(f"[APIRetrieval] Expired token detected on Incident metadata call (HTTP {res.status_code}). Attempting token refresh...")
        new_token = refresh_token(host)
        if new_token:
            new_headers = dict(headers)
            new_headers["NetWitness-Token"] = new_token
            return fetch_incident_details(host, new_headers, incident_id, auto_refresh=False)

    print(f"Warning: Incident metadata call returned HTTP {res.status_code}")
    return {}


# [FYP-FUNCTION] `fetch_incident_via_fetch_api` — retrieves fetch incident via fetch api data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`, `token`, `incident_id`, `auto_refresh`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:fetch_incident_via_fetch_api, APIRetrieval.py:get_comprehensive_incident_payload, APIRetrieval.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_is_expired_token_response`, `dumps`, `fetch_incident_via_fetch_api`, `get`, `isinstance`, `json`, `len`, `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def fetch_incident_via_fetch_api(host: str, token: str, incident_id: str, auto_refresh: bool = True) -> dict:
    """Fetch Incident details using NetWitness FETCH API (/rest/api/incident/fetch) as in nw_respond_inc-alert_call-comprehensive.sh."""
    url = f"{host}/rest/api/incident/fetch"
    headers = {
        "Accept": "application/json;charset=UTF-8",
        "NetWitness-Token": token,
        "Content-Type": "text/plain; charset=ISO-8859-1",
    }
    body = json.dumps({"meta_name": "id", "meta_value": incident_id, "numberOfRecords": "1"})
    print(f"[NetWitness FETCH API] Requesting incident details via {url}...")
    res = requests.get(url, headers=headers, data=body, verify=False, timeout=15)
    if res.status_code == 200:
        items = res.json()
        if isinstance(items, list) and len(items) > 0:
            return items[0]
        elif isinstance(items, dict):
            return items

    if auto_refresh and _is_expired_token_response(res):
        print(f"[APIRetrieval] Expired token detected on FETCH incident API (HTTP {res.status_code}). Attempting token refresh...")
        new_token = refresh_token(host)
        if new_token:
            return fetch_incident_via_fetch_api(host, new_token, incident_id, auto_refresh=False)

    print(f"Warning: FETCH incident API returned HTTP {res.status_code}: {res.text[:150]}")
    return {}


# [FYP-FUNCTION] `fetch_alerts_via_fetch_api` — retrieves fetch alerts via fetch api data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`, `token`, `incident_id`, `count`, `auto_refresh`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:fetch_alerts_via_fetch_api, APIRetrieval.py:get_comprehensive_incident_payload, APIRetrieval.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_is_expired_token_response`, `dumps`, `fetch_alerts_via_fetch_api`, `get`, `isinstance`, `json`, `len`, `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def fetch_alerts_via_fetch_api(host: str, token: str, incident_id: str, count: int = 1000, auto_refresh: bool = True) -> list:
    """Fetch full raw originalAlert items using NetWitness FETCH API (/rest/api/alert/fetch) as in nw_respond_inc-alert_call-comprehensive.sh."""
    url = f"{host}/rest/api/alert/fetch"
    headers = {
        "Accept": "application/json;charset=UTF-8",
        "NetWitness-Token": token,
        "Content-Type": "text/plain; charset=ISO-8859-1",
    }
    body = json.dumps({
        "meta_name": "incidentId",
        "meta_value": incident_id,
        "numberOfRecords": str(count),
        "includeFields": "null",
    })
    print(f"[NetWitness FETCH API] Requesting {count} comprehensive raw alerts via {url}...")
    res = requests.get(url, headers=headers, data=body, verify=False, timeout=30)
    if res.status_code == 200:
        items = res.json()
        if isinstance(items, list):
            print(f"  -> Successfully retrieved {len(items)} comprehensive raw alerts from FETCH API.")
            return items

    if auto_refresh and _is_expired_token_response(res):
        print(f"[APIRetrieval] Expired token detected on FETCH alert API (HTTP {res.status_code}). Attempting token refresh...")
        new_token = refresh_token(host)
        if new_token:
            return fetch_alerts_via_fetch_api(host, new_token, incident_id, count=count, auto_refresh=False)

    print(f"Warning: FETCH alert API returned HTTP {res.status_code}: {res.text[:150]}")
    return []


# [FYP-FUNCTION] `fetch_all_alerts_and_endpoint_events` — retrieves fetch all alerts and endpoint events data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `host`, `headers`, `incident_id`, `auto_refresh`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:get_comprehensive_incident_payload, APIRetrieval.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_is_expired_token_response`, `dict`, `extend`, `get`, `json`, `len`, `print`, `refresh_token`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def fetch_all_alerts_and_endpoint_events(host: str, headers: dict, incident_id: str, auto_refresh: bool = True) -> tuple[list, dict]:
    """Paginate through ALL pages of /rest/api/incidents/{incident_id}/alerts to extract 100% of alerts and events."""
    alerts_url = f"{host}/rest/api/incidents/{incident_id}/alerts"
    all_alerts = []
    page = 0
    page_size = 100
    pagination_info = {}
    curr_headers = dict(headers)
    refreshed_already = False

    print(f"[NetWitness Respond API] Fetching ALL Alert & Endpoint Event Data from {alerts_url}...")
    while True:
        res = requests.get(
            alerts_url,
            headers=curr_headers,
            params={"pageSize": page_size, "pageNumber": page},
            verify=False,
            timeout=25,
        )
        if res.status_code != 200:
            if auto_refresh and not refreshed_already and _is_expired_token_response(res):
                print(f"[APIRetrieval] Expired token detected on paginated alerts call (HTTP {res.status_code}). Attempting token refresh...")
                new_token = refresh_token(host)
                if new_token:
                    refreshed_already = True
                    curr_headers["NetWitness-Token"] = new_token
                    continue
            print(f"Failed to fetch alerts page {page}: HTTP {res.status_code}")
            break

        data = res.json()
        items = data.get("items", [])
        all_alerts.extend(items)

        total_items = data.get("totalItems", len(all_alerts))
        total_pages = data.get("totalPages", page + 1)
        has_next = data.get("hasNext", False)

        pagination_info = {
            "totalItems": total_items,
            "totalPages": total_pages,
            "fetchedItems": len(all_alerts),
            "pagesFetched": page + 1,
        }

        print(f"  -> Page {page}: Received {len(items)} alerts (Total fetched so far: {len(all_alerts)} / {total_items})")

        if not has_next or (page + 1) >= total_pages:
            break
        page += 1

    return all_alerts, pagination_info



# [FYP-FUNCTION] `process_respond_api_telemetry` — implements the process respond api telemetry operation used by the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `incident`, `alerts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `add`, `append`, `get`, `isinstance`, `len`, `list`, `set`, `sorted`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def process_respond_api_telemetry(incident: dict, alerts: list) -> dict:
    """Synthesize incident, alert, process events, and endpoint telemetry into a structured Respond report."""
    hosts = set()
    users = set()
    source_ips = set()
    destination_ips = set()
    event_sources = set()
    alert_title_counts = {}
    sample_alerts_by_title = {}

    process_details = []
    launch_args = set()
    process_directories = set()
    process_filenames = set()
    file_hashes = set()
    behavioral_iocs = set()
    mitre_techniques = set()

    if incident.get("hostname"):
        hosts.add(incident["hostname"])

    for alert in alerts:
        # Handle both summary alert shape and full raw originalAlert shape
        orig_alert = alert.get("originalAlert") if isinstance(alert.get("originalAlert"), dict) else alert
        title = alert.get("title") or alert.get("name") or orig_alert.get("moduleName") or "Unknown"
        alert_title_counts[title] = alert_title_counts.get(title, 0) + 1

        if title not in sample_alerts_by_title:
            sample_alerts_by_title[title] = alert

        # Extract events list (from summary shape or originalAlert shape)
        events = alert.get("events") or orig_alert.get("events") or []
        for evt in events:
            if not isinstance(evt, dict):
                continue

            # --- 1. Basic Respond Summary Event Fields ---
            if evt.get("domain"):
                hosts.add(evt["domain"])
            if evt.get("eventSource"):
                event_sources.add(evt["eventSource"])

            src = evt.get("source", {}) if isinstance(evt.get("source"), dict) else {}
            src_dev = src.get("device", {}) if isinstance(src.get("device"), dict) else {}
            if src_dev.get("ipAddress"):
                source_ips.add(src_dev["ipAddress"])
            if src_dev.get("dnsHostname"):
                hosts.add(src_dev["dnsHostname"])

            src_usr = src.get("user", {}) if isinstance(src.get("user"), dict) else {}
            if src_usr.get("username"):
                users.add(src_usr["username"])

            dst = evt.get("destination", {}) if isinstance(evt.get("destination"), dict) else {}
            dst_dev = dst.get("device", {}) if isinstance(dst.get("device"), dict) else {}
            if dst_dev.get("ipAddress"):
                destination_ips.add(dst_dev["ipAddress"])
            if dst_dev.get("dnsHostname"):
                hosts.add(dst_dev["dnsHostname"])

            dst_usr = dst.get("user", {}) if isinstance(dst.get("user"), dict) else {}
            if dst_usr.get("username"):
                users.add(dst_usr["username"])

            # --- 2. Full Endpoint & Process Details (from originalAlert / full export) ---
            # Launch Arguments (param_src)
            p_args = evt.get("param_src") or evt.get("param") or evt.get("cmdline")
            if p_args:
                args_list = p_args if isinstance(p_args, list) else [p_args]
                for arg in args_list:
                    if arg:
                        launch_args.add(str(arg))

            # Directories (directory_src)
            dirs = evt.get("directory_src") or evt.get("directory") or evt.get("process_path")
            if dirs:
                dir_list = dirs if isinstance(dirs, list) else [dirs]
                for d in dir_list:
                    if d:
                        process_directories.add(str(d))

            # Process / Binary Filenames (filename_src)
            fnames = evt.get("filename_src") or evt.get("filename") or evt.get("process_name")
            if fnames:
                fn_list = fnames if isinstance(fnames, list) else [fnames]
                for fn in fn_list:
                    if fn:
                        process_filenames.add(str(fn))

            # Hashes / Checksums (checksum_src)
            hashes = evt.get("checksum_src") or evt.get("hash") or evt.get("file_hash")
            if hashes:
                hash_list = hashes if isinstance(hashes, list) else [hashes]
                for h in hash_list:
                    if h:
                        file_hashes.add(str(h))

            # User (user_src)
            u_src = evt.get("user_src") or evt.get("owner")
            if u_src:
                users.add(str(u_src))

            # Host (alias_host)
            h_src = evt.get("alias_host") or evt.get("host_src")
            if h_src:
                h_list = h_src if isinstance(h_src, list) else [h_src]
                for h in h_list:
                    if h:
                        hosts.add(str(h))

            # Source / Dest IPs
            if evt.get("ip_src"):
                source_ips.add(str(evt["ip_src"]))
            if evt.get("ip_dst"):
                destination_ips.add(str(evt["ip_dst"]))

            # Behavioral IOCs (boc / context_src)
            bocs = evt.get("boc") or evt.get("context_src")
            if bocs:
                boc_list = bocs if isinstance(bocs, list) else [bocs]
                for b in boc_list:
                    if b:
                        behavioral_iocs.add(str(b))

            # MITRE ATT&CK
            t_id = evt.get("attack_tid")
            t_name = evt.get("attack_technique")
            t_tactic = evt.get("attack_tactic")
            if t_id or t_name or t_tactic:
                mitre_techniques.add(f"{t_tactic} | {t_name} ({t_id})")

            # Collect detailed record if process fields present
            if p_args or dirs or fnames:
                process_details.append({
                    "alert_title": title,
                    "process_filename": fnames,
                    "directory": dirs,
                    "launch_arguments": p_args,
                    "checksums": hashes,
                    "user": u_src or (list(users)[0] if users else None),
                    "host": h_src or (list(hosts)[0] if hosts else None),
                    "mitre": f"{t_tactic} | {t_name} ({t_id})" if t_id else None,
                })

    return {
        "incident_summary": {
            "id": incident.get("id"),
            "title": incident.get("title"),
            "priority": incident.get("priority"),
            "riskScore": incident.get("riskScore"),
            "status": incident.get("status"),
            "alertCount": incident.get("alertCount"),
            "eventCount": incident.get("eventCount"),
            "sources": incident.get("sources"),
            "created": incident.get("created"),
            "lastUpdated": incident.get("lastUpdated"),
        },
        "all_unique_alert_titles": alert_title_counts,
        "process_execution_telemetry": {
            "launch_arguments": sorted(list(launch_args)),
            "process_directories": sorted(list(process_directories)),
            "process_filenames": sorted(list(process_filenames)),
            "checksums_hashes": sorted(list(file_hashes)),
            "behavioral_iocs": sorted(list(behavioral_iocs)),
            "mitre_techniques": sorted(list(mitre_techniques)),
            "process_event_records": process_details,
        },
        "endpoint_identity": {
            "hosts": sorted(list(hosts)),
            "users": sorted(list(users)),
            "source_ips": sorted(list(source_ips)),
            "destination_ips": sorted(list(destination_ips)),
            "event_sources": sorted(list(event_sources)),
        },
        "alerts_count": len(alerts),
    }


# [FYP-FUNCTION] `get_comprehensive_incident_payload` — retrieves get comprehensive incident payload data for the surrounding threat intelligence and NetWitness integration workflow.
# [FYP-INPUT] Parameters: `incident_id`, `host`, `token`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:enrich_incident_with_apiretrieval_fetch, tests/test_apiretrieval.py:test_get_comprehensive_incident_payload_disk_file, tests/test_apiretrieval.py:test_get_comprehensive_incident_payload_live_fetch; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exists`, `fetch_alerts_via_fetch_api`, `fetch_all_alerts_and_endpoint_events`, `fetch_incident_details`, `fetch_incident_via_fetch_api`, `get_auth_token`, `getenv`, `isinstance`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def get_comprehensive_incident_payload(incident_id: str, host: str | None = None, token: str | None = None) -> dict:
    """Retrieve comprehensive incident + raw alerts telemetry payload.
    Checks disk for matching JSON exports first (e.g. incident_<id>_respond_api_export.json).
    If not found and live host+token are provided, fetches raw alerts via NetWitness FETCH API.
    """
    inc_clean = str(incident_id or "").strip()
    
    # 1. Disk Export Lookup
    candidate_files = [
        f"incident_{inc_clean}_respond_api_export.json",
        f"incident_{inc_clean}.json",
        f"{inc_clean}.json",
        f"outputs/{inc_clean}/parsing/raw_input_alert.json",
    ]
    for cfile in candidate_files:
        if os.path.exists(cfile):
            try:
                with open(cfile, "r", encoding="utf-8") as f:
                    export_data = json.load(f)
                if isinstance(export_data, dict):
                    print(f"[APIRetrieval] Loaded comprehensive export payload from {cfile}")
                    return export_data
            except Exception as exc:
                print(f"[APIRetrieval] Warning: error reading {cfile}: {exc}")

    # 2. Live NetWitness FETCH API Lookup (Dynamic Auth via Username & Password)
    live_host = (host or os.getenv("NW_HOST", os.getenv("NETWITNESS_HOST", "https://192.168.20.11"))).strip().rstrip("/")
    live_token = get_auth_token(host=live_host, token=token)

    if live_host and live_token and inc_clean:
        try:
            print(f"[APIRetrieval] Fetching live FETCH API telemetry for incident {inc_clean}...")
            inc_details = fetch_incident_via_fetch_api(live_host, live_token, inc_clean)
            active_token = get_auth_token(host=live_host, token=live_token)
            if not active_token:
                raise RuntimeError("Unable to obtain a NetWitness authentication token")
            headers = {"NetWitness-Token": active_token, "Accept": "application/json"}
            if not inc_details:
                inc_details = fetch_incident_details(live_host, headers, inc_clean)
                active_token = get_auth_token(host=live_host, token=active_token)
                if not active_token:
                    raise RuntimeError("Unable to refresh the NetWitness authentication token")
                headers["NetWitness-Token"] = active_token
            
            raw_alerts = fetch_alerts_via_fetch_api(live_host, active_token, inc_clean, count=1000)
            if not raw_alerts:
                active_token = get_auth_token(host=live_host, token=active_token)
                if not active_token:
                    raise RuntimeError("Unable to refresh the NetWitness authentication token")
                headers["NetWitness-Token"] = active_token
                raw_alerts, _ = fetch_all_alerts_and_endpoint_events(live_host, headers, inc_clean)
            
            return {
                "incident": inc_details or {"id": inc_clean},
                "alerts": raw_alerts or [],
            }
        except Exception as exc:
            print(f"[APIRetrieval] Live FETCH API retrieval encountered error: {exc}")

    return {}


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered threat intelligence and NetWitness integration operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis threat intelligence and NetWitness integration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dump`, `dumps`, `endswith`, `exists`, `exit`, `fetch_alerts_via_fetch_api`, `fetch_all_alerts_and_endpoint_events`, `fetch_incident_details`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main():
    target_arg = sys.argv[1].strip() if len(sys.argv) > 1 else "INC-52825"

    # Check if target argument is a JSON file (e.g. INC-6126_export.json)
    if target_arg.endswith(".json") and os.path.exists(target_arg):
        print(f"[Offline Mode] Loading export file from {target_arg}...")
        with open(target_arg, "r", encoding="utf-8") as f:
            export_data = json.load(f)

        incident_data = export_data.get("incident_raw") or export_data.get("incident", {})
        alerts = export_data.get("alerts_full_raw") or export_data.get("alerts_summary_raw", {}).get("items") or export_data.get("alerts", [])
        incident_id = incident_data.get("id") or export_data.get("incident_id") or "INC-FILE"
        pagination_info = export_data.get("counts", {})
    else:
        incident_id = target_arg
        host = os.getenv("NW_HOST", os.getenv("NETWITNESS_HOST", "https://192.168.20.11")).strip().rstrip("/")
        session_token = get_auth_token(host=host)

        if not session_token:
            print("Error: No valid NetWitness authentication token could be acquired.")
            sys.exit(1)

        headers = {"NetWitness-Token": session_token}

        # 2. Fetch Incident Details via FETCH API (fallback to standard endpoint)
        incident_data = fetch_incident_via_fetch_api(host, session_token, incident_id)
        if not incident_data:
            incident_data = fetch_incident_details(host, headers, incident_id)

        # 3. Fetch Comprehensive Raw Alerts via FETCH API (/rest/api/alert/fetch)
        fetch_alerts = fetch_alerts_via_fetch_api(host, session_token, incident_id, count=1000)

        # 4. Also fetch summary items from paginated endpoint if FETCH returns partial list
        summary_alerts, pagination_info = fetch_all_alerts_and_endpoint_events(host, headers, incident_id)

        # Combine or prefer full raw FETCH alerts
        alerts = fetch_alerts if len(fetch_alerts) > 0 else summary_alerts


    # 4. Extract Structured Respond API Telemetry
    result = process_respond_api_telemetry(incident_data, alerts)
    result["pagination"] = pagination_info

    # Output to Console
    print("\n" + "=" * 65)
    print(f" NETWITNESS RESPOND API EXTRACTION REPORT FOR {incident_id}")
    print("=" * 65)

    print("\n--- ALL UNIQUE ALERT TITLES ---")
    print(json.dumps(result["all_unique_alert_titles"], indent=2))

    print("\n--- PROCESS EXECUTION TELEMETRY (LAUNCH ARGS & DIRECTORY) ---")
    print(json.dumps(result["process_execution_telemetry"], indent=2))

    print("\n--- ENDPOINT IDENTITY ---")
    print(json.dumps(result["endpoint_identity"], indent=2))

    # Save complete JSON payload to file
    out_filename = f"incident_{incident_id}_respond_api_export.json"
    with open(out_filename, "w", encoding="utf-8") as f:
        json.dump({"incident": incident_data, "alerts": alerts, "telemetry": result}, f, indent=2)
    print(f"\n[Saved complete Respond API export to {out_filename}]")


if __name__ == "__main__":
    main()
