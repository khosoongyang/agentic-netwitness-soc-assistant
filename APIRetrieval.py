from __future__ import annotations

import os
import sys
import json
import base64
import requests
from dotenv import load_dotenv

# Suppress SSL verification warnings
requests.packages.urllib3.disable_warnings()

load_dotenv()


def _maybe_b64_decode(value: str) -> str:
    """Decode password if it was saved base64-encoded by app.py to preserve special characters."""
    val = value.strip().strip("'\"").strip()
    if not val:
        return ""
    try:
        decoded = base64.b64decode(val.encode(), validate=True).decode("utf-8")
        return decoded if decoded.isprintable() else val
    except Exception:
        return val


def authenticate_netwitness(host: str, username: str, password: str) -> str:
    """Authenticate via NetWitness Respond API (/rest/api/auth/userpass) to obtain an accessToken."""
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
            return session_token
        raise RuntimeError(f"Login succeeded but no token returned: {res_data}")
    else:
        raise RuntimeError(f"Authentication failed (HTTP {response.status_code}): {response.text[:200]}")


def fetch_incident_details(host: str, headers: dict, incident_id: str) -> dict:
    """Fetch Incident details from NetWitness Respond API (/rest/api/incidents/{incident_id})."""
    url = f"{host}/rest/api/incidents/{incident_id}"
    print(f"[NetWitness Respond API] Fetching Incident metadata from {url}...")
    res = requests.get(url, headers=headers, verify=False, timeout=15)
    if res.status_code == 200:
        return res.json()
    print(f"Warning: Incident metadata call returned HTTP {res.status_code}")
    return {}


def fetch_incident_via_fetch_api(host: str, token: str, incident_id: str) -> dict:
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
    print(f"Warning: FETCH incident API returned HTTP {res.status_code}: {res.text[:150]}")
    return {}


def fetch_alerts_via_fetch_api(host: str, token: str, incident_id: str, count: int = 1000) -> list:
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
    print(f"Warning: FETCH alert API returned HTTP {res.status_code}: {res.text[:150]}")
    return []


def fetch_all_alerts_and_endpoint_events(host: str, headers: dict, incident_id: str) -> tuple[list, dict]:
    """Paginate through ALL pages of /rest/api/incidents/{incident_id}/alerts to extract 100% of alerts and events."""
    alerts_url = f"{host}/rest/api/incidents/{incident_id}/alerts"
    all_alerts = []
    page = 0
    page_size = 100
    pagination_info = {}

    print(f"[NetWitness Respond API] Fetching ALL Alert & Endpoint Event Data from {alerts_url}...")
    while True:
        res = requests.get(
            alerts_url,
            headers=headers,
            params={"pageSize": page_size, "pageNumber": page},
            verify=False,
            timeout=25,
        )
        if res.status_code != 200:
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
        host = os.getenv("NW_HOST", "https://192.168.20.11").strip().rstrip("/")
        username = os.getenv("NW_USERNAME", "").strip()
        raw_password = os.getenv("NW_PASSWORD", "").strip()
        password = _maybe_b64_decode(raw_password)
        token = os.getenv("NW_TOKEN", os.getenv("NETWITNESS_TOKEN", "")).strip().strip("'\"")

        # 1. Authenticate & Obtain Token
        if username and password:
            try:
                session_token = authenticate_netwitness(host, username, password)
            except Exception as err:
                print(f"Authentication error: {err}")
                if token:
                    print("Falling back to NW_TOKEN from environment.")
                    session_token = token
                else:
                    sys.exit(1)
        elif token:
            print("Using NW_TOKEN from environment.")
            session_token = token
        else:
            print("Error: No authentication credentials found.")
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
