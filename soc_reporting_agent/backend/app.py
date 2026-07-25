from __future__ import annotations

import json
import os
import re
import subprocess
import shutil
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file, send_from_directory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load .env before importing reporting/config modules so LLM settings such as
# REPORTING_USE_LLM, REPORTING_LLM_PROVIDER, and OPENAI_API_KEY are visible.
load_dotenv(PROJECT_ROOT / ".env", override=False)

from reporting.editable_reports import (
    REPORT_SECTION_CONFIG,
    CORE_REPORT_KEYS,
    confirm_report,
    confirm_section,
    download_path,
    export_docx,
    export_pdf,
    export_section_docx,
    export_section_pdf,
    list_reports,
    list_section_drafts,
    load_manifest,
    read_section,
    save_section,
)

from backend.postgres_casework_store import normalise_alert
from backend.store_factory import PostgresUnavailableError, UnavailableCaseworkStore, get_casework_store
from backend.error_handling import api_error, install_api_guards, safe_load_json_file, safe_write_json_file
from backend.openai_client import invoke_openai_text
from backend.netwitness_client import NetWitnessClient
from backend import ticket_workflow
from backend.reporting_context_resolver import (
    ensure_reporting_inputs,
    resolve_investigation_approval_context,
    resolve_investigation_context,
)
from backend.export_cache import collect_ticket_export_status
from backend.orchestration_service import build_orchestration_decision
from services.parser_context_guard import clear_stale_parser_outputs, extract_alert_identity
from reporting.template_document_exporter import generate_agent_export, generate_reporting_export, REPORT_TEMPLATES

DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
INPUTS_DIR = PROJECT_ROOT / "inputs"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
LOGS_DIR = PROJECT_ROOT / "logs"
RUNTIME_DIR = PROJECT_ROOT / "runtime"

for d in (INPUTS_DIR, OUTPUTS_DIR, LOGS_DIR, RUNTIME_DIR):
    d.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=None)

RUNS: dict[str, dict[str, Any]] = {}
RUN_PROCESSES: dict[str, subprocess.Popen] = {}
RUN_LOCK = threading.Lock()

AGENT_TIMEOUT_SECONDS = {
    "correlation": 120,
    "orchestration": 60,
    "parsing": 30,
    "triage": 120,
    "threat_intel": 180,
    "investigation": 240,
    "reporting": 240,
}
try:
    CASEWORK = get_casework_store()
except PostgresUnavailableError as exc:
    CASEWORK = UnavailableCaseworkStore(exc)
SELECTED_TICKET_FILE = RUNTIME_DIR / "selected_ticket.json"


THINKING_STEPS = {
    "correlation": [
        "Loading ticket and candidate alert context",
        "Extracting hosts, users, IOCs, processes, and timestamps",
        "Scoring alert relationships against open tickets",
        "Creating pending analyst review recommendations",
        "Writing correlation output and updating the ticket",
    ],
    "orchestration": [
        "Loading selected ticket workflow state",
        "Checking completed agent outputs",
        "Validating required context",
        "Checking SOC approval gates",
        "Selecting the next permitted stage",
        "Writing orchestration decision",
    ],
    "parsing": [
        "Loading raw NetWitness alert context",
        "Detecting input format and flattening metakeys",
        "Extracting SOC-relevant alert fields and IOCs",
        "Building normalised alert and parser summary",
        "Writing processed alert context for Triage",
        "Parser output ready for Triage",
    ],
    "threat_intel": [
        "Loading processed alert and triage context",
        "Extracting file hashes, public IPs, and external domains",
        "Checking VirusTotal, AbuseIPDB, and AlienVault OTX where configured",
        "Calculating enrichment risk score and reasons",
        "Writing enriched alert context for Investigation",
        "Enriched alert ready for SOC approval and Investigation",
    ],
    "triage": [
        "Loading enriched alert context and extracted entities",
        "Checking whether Investigation requested more telemetry",
        "Querying NetWitness if evidence enrichment was thrown back to Triage",
        "Reviewing severity, confidence, and risk score indicators",
        "Mapping alert behaviour to SOC triage playbook",
        "Writing triage_result.json for the dashboard",
    ],
    "investigation": [
        "Loading confirmed grouped ticket context",
        "Indexing related alerts, open alerts, and open incident tickets",
        "Running semantic and metadata correlation with RRF-style ranking",
        "Executing the selected investigation playbook against the incident timeline",
        "Preparing analyst-review grouping and archive recommendations",
        "Writing investigation_result.json for Orchestration and Reporting",
    ],
    "reporting": [
        "Loading enriched alert, triage, investigation, and approval context",
        "Building reporting context and validating required fields",
        "Retrieving policy, procedure, and playbook references",
        "Generating executive summary and technical findings",
        "Rendering final report sections and validation status",
        "Writing final_report.json and editable report sections",
    ],
}

AGENT_ADAPTERS = {
    "correlation": {
        "label": "Incident Grouping",
        "script": PROJECT_ROOT / "adapters" / "run_correlation.py",
        "output": OUTPUTS_DIR / "correlation_recommendations.json",
    },
    "orchestration": {
        "label": "Orchestration Agent",
        "script": PROJECT_ROOT / "adapters" / "run_orchestration.py",
        "output": OUTPUTS_DIR / "orchestration_decision.json",
    },
    "parsing": {
        "label": "Parsing & Normalisation",
        "script": PROJECT_ROOT / "adapters" / "run_parser_normalisation.py",
        "output": OUTPUTS_DIR / "parser_result.json",
    },
    "triage": {
        "label": "Triage Agent",
        "script": PROJECT_ROOT / "adapters" / "run_triage.py",
        "output": OUTPUTS_DIR / "triage_result.json",
    },
    "threat_intel": {
        "label": "Threat Intelligence Enrichment",
        "script": PROJECT_ROOT / "adapters" / "run_threat_intel.py",
        "output": OUTPUTS_DIR / "threat_intel_result.json",
    },
    "investigation": {
        "label": "Investigation Agent",
        "script": PROJECT_ROOT / "adapters" / "run_investigation.py",
        "output": OUTPUTS_DIR / "investigation_result.json",
    },
    "reporting": {
        "label": "Reporting Agent",
        "script": PROJECT_ROOT / "adapters" / "run_reporting.py",
        "output": OUTPUTS_DIR / "final_report.json",
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_read_json(path: Path | str, label: str = "file") -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {"ready": False, "status": "Not ready yet", "label": label, "path": str(path.relative_to(PROJECT_ROOT)) if path.is_absolute() else str(path), "data": None}
    try:
        if path.stat().st_size == 0:
            return {"ready": False, "status": "Empty file", "label": label, "path": str(path.relative_to(PROJECT_ROOT)), "data": None}
        return {"ready": True, "status": "Ready", "label": label, "path": str(path.relative_to(PROJECT_ROOT)), "data": json.loads(path.read_text(encoding="utf-8"))}
    except Exception as exc:
        return {"ready": False, "status": f"Invalid JSON: {exc}", "label": label, "path": str(path.relative_to(PROJECT_ROOT)), "data": None}


def read_data(path: Path, default: Any = None) -> Any:
    obj = safe_read_json(path)
    return obj.get("data") if obj.get("ready") else default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def first_value(obj: dict | None, *keys: str, default: Any = None) -> Any:
    if not isinstance(obj, dict):
        return default
    for key in keys:
        cur: Any = obj
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur not in (None, "", [], {}):
            return cur
    return default




STATUS_LABELS = {
    "not_ready": "Not ready",
    "running": "Running",
    "completed": "Completed",
    "completed_limited": "Completed with limitations",
    "completed_with_warnings": "Completed with warnings",
    "completed_with_evidence_gaps": "Completed with evidence gaps",
    "needs_more_data": "Completed with evidence gaps",
    "missing_information_required": "Missing information required",
    "failed": "Failed",
    "execution_error": "Execution error",
    "timed_out": "Timed out",
    "not_configured": "Not configured",
    "no_records": "No records found",
    "skipped": "Skipped",
    "paused": "Paused",
    "insufficient_evidence": "Insufficient evidence",
    "case_context_inconsistent": "Case context inconsistent",
    "case_data_mismatch": "Case data mismatch detected",
    "generated_with_warnings": "Generated with warnings",
}


def display_status(status: Any) -> str:
    key = str(status or "not_ready").strip().lower().replace(" ", "_").replace("-", "_")
    return STATUS_LABELS.get(key, key.replace("_", " ").title() if key else "Not ready")


def parse_possible_json_string(value: Any, depth: int = 0) -> Any:
    """Parse accidentally stringified JSON and nested stringified JSON.

    Several uploaded agents were originally terminal scripts, so they sometimes
    store JSON as escaped text. The analyst dashboard should not render that raw
    escaped object as normal text.
    """
    if depth > 4:
        return value
    if isinstance(value, dict):
        return {k: parse_possible_json_string(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [parse_possible_json_string(v, depth + 1) for v in value]
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    candidates = [text]
    # Sometimes JSON arrives as a quoted string with escaped braces/newlines.
    if text.startswith('"') and text.endswith('"'):
        candidates.append(text[1:-1])
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, (dict, list)):
                return parse_possible_json_string(obj, depth + 1)
            if isinstance(obj, str) and obj != value:
                return parse_possible_json_string(obj, depth + 1)
        except Exception:
            pass
    # Last-resort unescape for displayed short text, but do not force it into JSON.
    if "\\n" in text or '\\"' in text or "\\u001b" in text:
        try:
            unescaped = bytes(text, "utf-8").decode("unicode_escape")
            if unescaped and unescaped != value:
                try:
                    obj = json.loads(unescaped)
                    if isinstance(obj, (dict, list)):
                        return parse_possible_json_string(obj, depth + 1)
                except Exception:
                    return unescaped
        except Exception:
            return text.replace("\\n", "\n").replace('\\"', '"')
    return value


def looks_like_raw_json_text(text: str) -> bool:
    t = str(text or "")
    if len(t) > 800 and (t.count('{') + t.count('}') + t.count('\\"') + t.count('\\n')) > 8:
        return True
    markers = ["netwitness_evidence", "missing_fields_requested", "ioc_summary", "\\u001b", "trace", "raw_thinking"]
    return any(m in t for m in markers) and ("{" in t or "\\\"" in t)



def markdown_to_plain_text(value: Any) -> str:
    """Convert Markdown-ish agent/report text into plain SOC analyst text."""
    text = str(value or "")
    if not text:
        return ""
    text = re.sub(r"```[a-zA-Z0-9_-]*\n?", "", text)
    text = text.replace("```", "")
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"!\[([^\]]*)\]\([^\)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\(([^\)]+)\)", r"\1 (\2)", text)
    text = re.sub(r"^\s{0,3}#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s{0,3}>\s?", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[-*+]\s+", "• ", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"(^|[^*])\*([^*\n]+)\*", r"\1\2", text)
    text = re.sub(r"(^|[^_])_([^_\n]+)_", r"\1\2", text)
    # Markdown table separator rows and table pipes.
    text = re.sub(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$", "", text, flags=re.MULTILINE)
    def _table_row(match: re.Match) -> str:
        row = match.group(1)
        cells = [c.strip() for c in row.split("|") if c.strip()]
        return " | ".join(cells)
    text = re.sub(r"^\s*\|(.+)\|\s*$", _table_row, text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text

def clean_display_text(value: Any, max_len: int = 1400) -> str:
    value = parse_possible_json_string(value)
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, dict):
        # Prefer obvious human text fields from nested objects.
        for k in ("analyst_summary", "summary", "message", "reason", "error", "status"):
            if isinstance(value.get(k), str) and value.get(k).strip() and not looks_like_raw_json_text(value.get(k)):
                return clean_display_text(value.get(k), max_len=max_len)
        return ""
    if isinstance(value, list):
        items = [clean_display_text(v, max_len=300) for v in value]
        return "\n".join(x for x in items if x)[:max_len]
    text = str(value).replace("\\n", "\n").replace('\\"', '"').replace("\\u001b", "")
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = text.strip()
    if looks_like_raw_json_text(text):
        return ""
    text = markdown_to_plain_text(text)
    if len(text) > max_len:
        text = text[:max_len].rstrip() + "..."
    return text


def normalise_list(value: Any) -> list[str]:
    value = parse_possible_json_string(value)
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, dict):
                label = item.get("field") or item.get("name") or item.get("value") or item.get("ioc") or item.get("indicator")
                reason = item.get("reason") or item.get("description") or item.get("status")
                if label and reason:
                    out.append(f"{label}: {reason}")
                elif label:
                    out.append(str(label))
                else:
                    cleaned = clean_display_text(item)
                    if cleaned:
                        out.append(cleaned)
            else:
                cleaned = clean_display_text(item)
                if cleaned:
                    out.append(cleaned)
        return out
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            if k.startswith("raw") or k in {"trace", "stdout", "stderr", "subprocess"}:
                continue
            cleaned = clean_display_text(v, max_len=300)
            if cleaned:
                out.append(f"{k}: {cleaned}")
        return out
    cleaned = clean_display_text(value)
    return [cleaned] if cleaned else []


def normalise_agent_data(data: Any, agent: str) -> dict[str, Any]:
    raw = data if isinstance(data, dict) else {"raw_value": data}
    parsed = parse_possible_json_string(raw)
    if not isinstance(parsed, dict):
        parsed = {"raw_value": parsed}

    status = str(parsed.get("status") or parsed.get("report_status") or "completed").strip().lower()
    nw = parsed.get("netwitness_evidence") if isinstance(parsed.get("netwitness_evidence"), dict) else {}

    missing = (
        normalise_list(parsed.get("missing_evidence"))
        or normalise_list(parsed.get("missing_fields"))
        or normalise_list(parsed.get("required_missing_fields"))
        or normalise_list(parsed.get("missing_fields_requested"))
        or normalise_list(nw.get("missing_fields_requested") if isinstance(nw, dict) else None)
    )
    observed = (
        normalise_list((parsed.get("available_evidence") or {}).get("iocs") if isinstance(parsed.get("available_evidence"), dict) else None)
        + normalise_list(parsed.get("iocs"))
        + normalise_list(parsed.get("observed_iocs"))
        + normalise_list(parsed.get("ioc_summary"))
        + normalise_list(nw.get("matched_metakeys") if isinstance(nw, dict) else None)
    )
    findings = (
        normalise_list(parsed.get("findings"))
        or normalise_list(parsed.get("key_findings"))
        or normalise_list(parsed.get("technical_findings"))
        or normalise_list(parsed.get("analysis_findings"))
    )

    summary = clean_display_text(parsed.get("analyst_summary")) or clean_display_text(parsed.get("summary")) or clean_display_text(parsed.get("executive_summary")) or clean_display_text(parsed.get("reason")) or clean_display_text(parsed.get("message"))

    if status in {"case_context_inconsistent", "case_data_mismatch"} and (not summary or "agent output is available" in summary.lower()):
        summary = (
            "Case data mismatch detected. Some agent outputs are missing, stale, or referring to different case details. "
            "A report can still be generated, but it should be treated as generated with warnings and reviewed by the SOC analyst before use."
        )

    if not summary:
        if agent == "investigation" and status == "needs_more_data":
            summary = "The Investigation Agent could not fully complete the selected playbook because required telemetry is missing. This is an evidence gap, not a dashboard crash."
        elif agent == "triage" and (nw or parsed.get("investigation_throwback")):
            nw_status = str(nw.get("status") or parsed.get("netwitness_status") or status or "unknown") if isinstance(nw, dict) else status
            if nw_status in {"timed_out", "timeout"} or "timed out" in json.dumps(parsed).lower():
                summary = "Triage attempted to collect missing telemetry from NetWitness, but the NetWitness request timed out. The case remains with Triage because only Triage is allowed to query NetWitness."
            elif nw_status in {"not_configured", "missing_config"}:
                summary = "Triage could not query NetWitness because the NetWitness connection is not configured in .env."
            elif nw_status in {"no_records", "no_results"}:
                summary = "Triage queried NetWitness but did not find matching records for the requested missing telemetry."
            else:
                summary = "Triage processed the case and handled the NetWitness evidence refresh route."
        elif agent == "reporting" and status in {"missing_information_required", "needs_more_data"}:
            summary = "The Reporting Agent found that some report fields are missing. A limited report can still be generated if the analyst approves continuing with limitations."
        else:
            summary = "Agent output is available. Open JSON for full raw details."

    recommended = clean_display_text(parsed.get("recommended_next_action")) or clean_display_text(parsed.get("next_action")) or clean_display_text(parsed.get("workflow_next_action"))
    if status in {"case_context_inconsistent", "case_data_mismatch"}:
        recommended = "Review the mismatched case context, verify the incident ID across agent outputs, then generate a report with warnings or re-run the affected agent."
    elif status == "needs_more_data":
        recommended = "Choose an analyst action: return to Triage for NetWitness, continue with current evidence, mark as insufficient evidence, or mark and continue to Reporting."
    elif parsed.get("workflow_override"):
        recommended = recommended or "Continue to Reporting with evidence limitations clearly documented."

    workflow_options = []
    if status == "needs_more_data":
        workflow_options = [
            {"id": "return_to_triage", "label": "Return to Triage for NetWitness", "description": "Triage queries NetWitness because Investigation is not allowed to contact NetWitness directly."},
            {"id": "continue_limited", "label": "Continue with current evidence", "description": "Allow Reporting to proceed while documenting the missing telemetry."},
            {"id": "mark_insufficient", "label": "Mark as insufficient evidence", "description": "Create a case folder containing the evidence gap and pause the workflow."},
            {"id": "mark_and_continue", "label": "Mark and continue to Reporting", "description": "Archive the evidence gap and generate a limited report."},
        ]

    normalised = dict(parsed)
    normalised.update({
        "status": status,
        "status_machine": status,
        "display_status": display_status(status),
        "analyst_summary": summary,
        "observed_evidence": list(dict.fromkeys(observed)),
        "findings": findings,
        "missing_evidence": missing,
        "recommended_next_action": recommended,
        "workflow_options": workflow_options,
        "raw_json_available": True,
    })
    # Keep the raw object out of analyst text, but available for Open JSON.
    normalised["_raw"] = raw
    return normalised


def safe_read_agent_json(path: Path | str, label: str, agent: str) -> dict[str, Any]:
    payload = safe_read_json(path, label)
    if payload.get("ready"):
        raw_data = payload.get("data") or {}
        payload["raw_data"] = raw_data
        payload["data"] = normalise_agent_data(raw_data, agent)
        payload["display_status"] = payload["data"].get("display_status")
    return payload


def report_section_texts(manifest: dict[str, Any]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for key, section in (manifest.get("sections") or {}).items():
        path_value = section.get("draft_path") or section.get("confirmed_path") or section.get("path")
        path = Path(path_value or "")
        if path.exists():
            texts[key] = path.read_text(encoding="utf-8", errors="ignore")
    return texts


def current_incident_id() -> str:
    case = case_summary()
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(case.get("incident_id") or "INC-0001"))[:80]


def update_investigation_to_limited(reason: str, analyst: str = "SOC Analyst") -> dict[str, Any]:
    inv_path = OUTPUTS_DIR / "investigation_result.json"
    inv = read_data(inv_path, {}) or {}
    prev_status = inv.get("status") or "needs_more_data"
    missing = normalise_list(inv.get("missing_evidence") or inv.get("missing_fields") or inv.get("required_missing_fields"))
    inv.update({
        "previous_status": prev_status,
        "status": "completed_limited",
        "display_status": display_status("completed_limited"),
        "workflow_override": True,
        "override_type": "continue_with_limited_evidence",
        "override_reason": reason,
        "approved_by": analyst,
        "limitations": missing or ["Required telemetry was not available at investigation time."],
        "recommended_next_action": "Run Reporting Agent with evidence limitations documented.",
        "updated_at": now_iso(),
    })
    write_json(inv_path, inv)
    write_json(OUTPUTS_DIR / "workflow_override.json", {
        "status": "approved",
        "override_type": "continue_with_limited_evidence",
        "reason": reason,
        "approved_by": analyst,
        "limitations": inv["limitations"],
        "created_at": now_iso(),
    })
    return inv


def mark_case_insufficient(continue_workflow: bool = False, analyst: str = "SOC Analyst", notes: str = "") -> dict[str, Any]:
    incident_id = current_incident_id()
    case_dir = OUTPUTS_DIR / "cases" / incident_id / "insufficient_evidence"
    case_dir.mkdir(parents=True, exist_ok=True)
    triage = read_data(OUTPUTS_DIR / "triage_result.json", {}) or {}
    inv = read_data(OUTPUTS_DIR / "investigation_result.json", {}) or {}
    missing = normalise_list(inv.get("missing_evidence") or inv.get("missing_fields") or inv.get("required_missing_fields"))
    status_payload = {
        "incident_id": incident_id,
        "incident_status": "insufficient_evidence",
        "display_status": display_status("insufficient_evidence"),
        "workflow_status": "continue_to_reporting" if continue_workflow else "paused",
        "continue_workflow": continue_workflow,
        "reason": notes or "Required telemetry could not be found or was unavailable.",
        "missing_evidence": missing,
        "marked_by": analyst,
        "marked_at": now_iso(),
    }
    for name in ["triage_result.json", "investigation_result.json", "final_report.json", "workflow_override.json", "netwitness_evidence.json"]:
        src = OUTPUTS_DIR / name
        if src.exists():
            (case_dir / name).write_text(src.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
    write_json(case_dir / "case_status.json", status_payload)
    write_json(case_dir / "missing_evidence.json", {"missing_evidence": missing, "triage": triage, "investigation_status": inv.get("status")})
    (case_dir / "notes.md").write_text(
        f"# Insufficient Evidence Case Note\n\nIncident: {incident_id}\n\nStatus: {'Mark and continue' if continue_workflow else 'Paused'}\n\nReason: {status_payload['reason']}\n\nMissing evidence:\n" + "\n".join(f"- {m}" for m in missing),
        encoding="utf-8",
    )
    write_json(OUTPUTS_DIR / "case_status.json", status_payload)
    return {"success": True, "case_folder": str(case_dir.relative_to(PROJECT_ROOT)), "case_status": status_payload}


def status_for_file(path: Path) -> str:
    obj = safe_read_json(path)
    if obj.get("ready"):
        data = obj.get("data") or {}
        return str(data.get("status") or data.get("report_status") or "completed")
    return "not_ready"


def normalise_agent_output_status(status: str | None, returncode: int | None = None) -> tuple[str, bool, str]:
    """Map dashboard output JSON status to a truthful run status.

    A subprocess can return 0 even when the agent result says failed.
    The dashboard should trust the agent output JSON first, then the return code.
    """
    s = str(status or "").strip().lower()
    if s in {"completed", "success", "passed", "ready"}:
        return "completed", True, "Completed successfully"
    if s in {"completed_limited", "completed_with_warnings", "partial", "partial_success"}:
        return "completed_limited", True, "Completed with limitations"
    if s in {"completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry"}:
        return "completed_with_evidence_gaps", True, "Completed with evidence gaps; Reporting may continue after SOC approval"
    if s in {"failed", "error", "execution_error", "timeout", "failed_postgres_unavailable", "blocked_missing_triage", "blocked_pending_triage_approval"}:
        return "failed", False, "Agent failed, check logs and output details"
    if returncode == 0:
        return "completed", True, "Completed successfully"
    return "failed", False, "Agent failed, check logs"


def agent_output_path(agent: str, run_output_dir: Path | None = None) -> Path | None:
    cfg = AGENT_ADAPTERS.get(agent)
    if not cfg:
        return None
    legacy_output = cfg["output"]
    if run_output_dir:
        try:
            rel = legacy_output.resolve().relative_to(OUTPUTS_DIR.resolve())
            candidate = run_output_dir / rel
            if candidate.exists():
                return candidate
        except Exception:
            pass
    return legacy_output


def output_status_for_agent(agent: str, run_output_dir: Path | None = None) -> tuple[str | None, dict[str, Any] | None]:
    cfg = AGENT_ADAPTERS.get(agent)
    if not cfg:
        return None, None
    output_path = agent_output_path(agent, run_output_dir=run_output_dir) or cfg["output"]
    obj = safe_read_json(output_path, cfg["label"])
    if not obj.get("ready"):
        # Fallback to the legacy output file if the adapter did not mirror to the run folder.
        obj = safe_read_json(cfg["output"], cfg["label"])
    if not obj.get("ready"):
        return None, None
    data = obj.get("data") or {}
    return str(data.get("status") or data.get("report_status") or "completed"), data


def latest_run_for(agent: str, ticket_id: str | None = None) -> dict | None:
    with RUN_LOCK:
        runs = [r for r in RUNS.values() if r.get("agent") == agent and (ticket_id is None or r.get("ticket_id") == ticket_id)]
        if not runs:
            return None
        return sorted(runs, key=lambda r: r.get("started_at", ""))[-1]


def active_run_for(agent: str | None = None, ticket_id: str | None = None) -> dict | None:
    with RUN_LOCK:
        runs = [
            dict(r) for r in RUNS.values()
            if r.get("running")
            and (agent is None or r.get("agent") == agent)
            and (ticket_id is None or r.get("ticket_id") == ticket_id)
        ]
    if not runs:
        return None
    return sorted(runs, key=lambda r: r.get("started_at", ""))[-1]


def workflow_state() -> dict[str, Any]:
    correlation = safe_read_json(OUTPUTS_DIR / "correlation_recommendations.json", "Incident Grouping")
    parsing = safe_read_json(OUTPUTS_DIR / "parser_result.json", "Parsing & Normalisation")
    triage = safe_read_json(OUTPUTS_DIR / "triage_result.json", "Triage Agent")
    threat = safe_read_json(OUTPUTS_DIR / "threat_intel_result.json", "Threat Intelligence Enrichment")
    inv = safe_read_json(OUTPUTS_DIR / "investigation_result.json", "Investigation Agent")
    rep = safe_read_json(OUTPUTS_DIR / "final_report.json", "Reporting Agent")
    approval = read_data(OUTPUTS_DIR / "approval_result.json", {}) or read_data(INPUTS_DIR / "approval_result.json", {}) or {}
    investigation_approval = read_data(OUTPUTS_DIR / "investigation_approval_result.json", {}) or read_data(INPUTS_DIR / "investigation_approval_result.json", {}) or {}
    soc_review = read_data(OUTPUTS_DIR / "soc_review_result.json", {}) or read_data(INPUTS_DIR / "soc_review_result.json", {}) or {}

    def is_running(agent_key: str) -> bool:
        return bool((latest_run_for(agent_key) or {}).get("running"))

    active = active_agent_run()
    any_running = bool(active)

    triage_approval_complete = str((approval or {}).get("decision") or "").lower() in {"approved", "approve"}
    triage_gate_open = bool(triage.get("ready")) and (not triage.get("approval_required") or triage_approval_complete)

    if not parsing.get("ready"):
        next_step = "Run Parsing & Normalisation"
    elif not triage.get("ready"):
        next_step = "Run Triage"
    elif triage.get("approval_required") and not triage_approval_complete:
        next_step = "Await SOC Analyst Approval before Threat Intelligence Enrichment"
    elif not threat.get("ready"):
        next_step = "Run Threat Intelligence Enrichment"
    elif not inv.get("ready"):
        next_step = "Run Investigation"
    elif str((investigation_approval or {}).get("decision") or "").lower() not in {"approved", "approve"}:
        next_step = "Await SOC Analyst Approval before Reporting"
    elif not rep.get("ready"):
        next_step = "Run Reporting"
    elif not soc_review:
        next_step = "Await SOC Analyst Review"
    else:
        next_step = "Ready for Case Closure"

    return {
        "updated_at": now_iso(),
        "next_step": next_step,
        "active_run": active,
        "any_agent_running": any_running,
        "can_run_parsing": True,
        "can_run_triage": bool(parsing.get("ready")),
        "can_run_threat_intel": bool(triage_gate_open),
        "can_run_investigation": bool(triage_gate_open and threat.get("ready")),
        "can_run_reporting": bool(inv.get("ready") and str((investigation_approval or {}).get("decision") or "").lower() in {"approved", "approve"}),
        "agents": {
            "correlation": {"ready": correlation.get("ready"), "status": "running" if is_running("correlation") else status_for_file(OUTPUTS_DIR / "correlation_recommendations.json"), "display_status": display_status("running" if is_running("correlation") else status_for_file(OUTPUTS_DIR / "correlation_recommendations.json")), "running": is_running("correlation"), "latest_run": latest_run_for("correlation")},
            "parsing": {"ready": parsing.get("ready"), "status": "running" if is_running("parsing") else status_for_file(OUTPUTS_DIR / "parser_result.json"), "display_status": display_status("running" if is_running("parsing") else status_for_file(OUTPUTS_DIR / "parser_result.json")), "running": is_running("parsing"), "latest_run": latest_run_for("parsing")},
            "triage": {"ready": triage.get("ready"), "status": "running" if is_running("triage") else status_for_file(OUTPUTS_DIR / "triage_result.json"), "display_status": display_status("running" if is_running("triage") else status_for_file(OUTPUTS_DIR / "triage_result.json")), "running": is_running("triage"), "latest_run": latest_run_for("triage")},
            "threat_intel": {"ready": threat.get("ready"), "status": "running" if is_running("threat_intel") else status_for_file(OUTPUTS_DIR / "threat_intel_result.json"), "display_status": display_status("running" if is_running("threat_intel") else status_for_file(OUTPUTS_DIR / "threat_intel_result.json")), "running": is_running("threat_intel"), "latest_run": latest_run_for("threat_intel")},
            "investigation": {"ready": inv.get("ready"), "status": "running" if is_running("investigation") else status_for_file(OUTPUTS_DIR / "investigation_result.json"), "display_status": display_status("running" if is_running("investigation") else status_for_file(OUTPUTS_DIR / "investigation_result.json")), "running": is_running("investigation"), "latest_run": latest_run_for("investigation")},
            "reporting": {"ready": rep.get("ready"), "status": "running" if is_running("reporting") else status_for_file(OUTPUTS_DIR / "final_report.json"), "display_status": display_status("running" if is_running("reporting") else status_for_file(OUTPUTS_DIR / "final_report.json")), "running": is_running("reporting"), "latest_run": latest_run_for("reporting")},
        },
        "approval": approval,
        "investigation_approval": investigation_approval,
        "soc_review": soc_review,
    }

def case_summary() -> dict[str, Any]:
    enriched = read_data(INPUTS_DIR / "enriched_alert.json", {}) or {}
    triage = read_data(OUTPUTS_DIR / "triage_result.json", {}) or {}
    inv = read_data(OUTPUTS_DIR / "investigation_result.json", {}) or {}
    rep = read_data(OUTPUTS_DIR / "final_report.json", {}) or {}
    # Prefer the latest Triage refresh when Investigation was thrown back for NetWitness enrichment.
    # Otherwise, prefer Reporting > Investigation > Triage > Enriched alert.
    source = triage if triage.get("investigation_throwback") else (rep or inv or triage or enriched)
    risk_score = first_value(source, "risk_score", "incident_risk_score", "enrichment_risk_score", "riskScore", default=75)
    status = first_value(source, "status", "report_status", "current_stage", default="In Progress")
    summary = clean_display_text(first_value(source, "analyst_summary", "summary", "incident_summary", "description", "alert_detail", default="")) or "SOC case waiting for agent output."
    return {
        "incident_id": first_value(source, "incident_id", "incidentId", "id", default="INC-0001"),
        "title": first_value(source, "title", "incident_title", "alert_name", "alert_title", "name", default="High Risk Endpoint Malware Activity"),
        "summary": summary,
        "severity": first_value(source, "severity", "classification", "priority", default="Unknown"),
        "confidence": first_value(source, "confidence", "confidence_level", default="Unknown"),
        "risk_score": risk_score,
        "host": first_value(source, "host", "hostname", "event_domain", "destination_hostname", default="unknown-host"),
        "ip": first_value(source, "ip", "source_ip", "destination_ip", default=""),
        "status": status,
        "display_status": display_status(status),
        "next_action": first_value(source, "next_action", "recommended_next_action", "recommended_action", default=workflow_state().get("next_step")),
    }



def active_agent_run(ticket_id: str | None = None, agent: str | None = None) -> dict[str, Any] | None:
    return active_run_for(agent=agent, ticket_id=ticket_id)


def workflow_override_allows(agent: str) -> bool:
    override = read_data(OUTPUTS_DIR / "workflow_override.json", {}) or {}
    if agent == "investigation" and override.get("override_type") in {"continue_to_investigation_with_limited_triage", "continue_with_limited_evidence"}:
        return True
    if agent == "reporting" and override.get("override_type") in {"continue_to_reporting_with_limited_investigation", "continue_with_limited_evidence"}:
        return True
    return False


def agent_run_gate(agent: str, ticket_id: str | None = None) -> tuple[bool, str, str]:
    active = active_agent_run(ticket_id=ticket_id, agent=agent) if ticket_id else active_agent_run(agent=agent)
    if active:
        return False, "agent_running_same_ticket", f"{active.get('label') or active.get('agent')} is already running for this ticket. Wait for it to complete or pause it before starting another run of the same agent."
    if agent == "correlation":
        return True, "allowed", "Correlation can run to recommend related alert grouping."
    if agent == "orchestration":
        return True, "allowed", "Orchestration can run to refresh the workflow decision."
    if agent == "parsing":
        return True, "allowed", "Parsing and Normalisation can run."
    correlation = safe_read_json(OUTPUTS_DIR / "correlation_recommendations.json", "Incident Grouping")
    parsing = safe_read_json(OUTPUTS_DIR / "parser_result.json", "Parsing & Normalisation")
    triage = safe_read_json(OUTPUTS_DIR / "triage_result.json", "Triage Agent")
    threat = safe_read_json(OUTPUTS_DIR / "threat_intel_result.json", "Threat Intelligence Enrichment")
    inv = safe_read_json(OUTPUTS_DIR / "investigation_result.json", "Investigation Agent")
    approval = read_data(OUTPUTS_DIR / "approval_result.json", {}) or {}
    inv_approval = read_data(OUTPUTS_DIR / "investigation_approval_result.json", {}) or {}
    selected_ticket = CASEWORK.get_ticket(ticket_id) if ticket_id else None
    if agent == "triage":
        if selected_ticket is not None:
            if not selected_ticket.get("parsing_result"):
                return False, "parser_required", "Run Parsing & Normalisation first."
            return True, "allowed", "Triage can run."
        if not parsing.get("ready"):
            return False, "parser_required", "Run Parsing & Normalisation first."
        return True, "allowed", "Triage can run."
    if agent == "threat_intel":
        if selected_ticket is not None:
            selected_triage = selected_ticket.get("triage_result") or {}
            if not selected_triage:
                return False, "triage_required", "Run Triage Agent first."
            if not selected_triage.get("severity") or not selected_triage.get("confidence"):
                return False, "triage_required", "Triage severity and confidence are required before Threat Intelligence Enrichment."
            if ticket_workflow.triage_requires_approval(selected_triage) and not ticket_workflow.approval_complete(selected_ticket, "triage_approval"):
                return False, "approval_required", "SOC analyst approval is required before Threat Intelligence Enrichment."
            return True, "allowed", "Threat intelligence enrichment can run."
        if not triage.get("ready"):
            return False, "triage_required", "Run Triage Agent first."
        if triage.get("approval_required") and str(approval.get("decision") or "").lower() not in {"approved", "approve"}:
            return False, "approval_required", "SOC analyst approval is required before Threat Intelligence Enrichment."
        return True, "allowed", "Threat intelligence enrichment can run."
    if agent == "investigation":
        if selected_ticket is not None:
            selected_triage = selected_ticket.get("triage_result") or {}
            if not selected_triage:
                return False, "triage_required", "Run Triage Agent first."
            if not selected_ticket.get("threat_intel_result"):
                return False, "threat_intel_required", "Run Threat Intelligence Enrichment first."
            if ticket_workflow.triage_requires_approval(selected_triage) and not ticket_workflow.approval_complete(selected_ticket, "triage_approval"):
                return False, "approval_required", "SOC analyst approval is required before Investigation."
            return True, "allowed", "Investigation can run."
        if not triage.get("ready"):
            return False, "triage_required", "Run Triage Agent first."
        if not threat.get("ready"):
            return False, "threat_intel_required", "Run Threat Intelligence Enrichment first."
        if triage.get("approval_required") and str(approval.get("decision") or "").lower() not in {"approved", "approve"}:
            return False, "approval_required", "SOC analyst approval is required before Investigation."
        return True, "allowed", "Investigation can run."
    if agent == "reporting":
        resolved_inv = resolve_investigation_context(PROJECT_ROOT, ticket_id=ticket_id, ticket=selected_ticket)
        if not resolved_inv.exists:
            return False, "investigation_required", "Run Investigation Agent first. Reporting requires investigation context."
        if not resolved_inv.usable:
            return False, "investigation_not_usable", resolved_inv.message or "Investigation did not produce usable findings. Re-run Investigation or return to Triage for more context."
        inv_data = resolved_inv.data
        resolved_approval = resolve_investigation_approval_context(PROJECT_ROOT, ticket_id=ticket_id, ticket=selected_ticket)
        if not resolved_approval.usable:
            if ticket_workflow.investigation_reporting_mode(inv_data) == "with_limitations":
                return False, "investigation_approval_required", "SOC analyst approval is required before Reporting can run with investigation evidence gaps."
            return False, "investigation_approval_required", "SOC analyst approval is required before Reporting."
        if ticket_workflow.investigation_reporting_mode(inv_data) == "with_limitations":
            return True, "allowed", "Reporting can run with documented investigation limitations."
        return True, "allowed", "Reporting can run."
    return False, "unknown_agent", "Unknown agent."


def start_background_export_preparation(ticket_id: str | None, agent: str) -> None:
    """Prepare cached Word/PDF exports after a stage completes.

    This runs in a daemon thread and must never block the workflow. Export
    failure is recorded as ticket activity only; the agent/stage result remains
    completed because JSON is the workflow source of truth.
    """
    if not ticket_id:
        return

    def worker() -> None:
        try:
            ticket = CASEWORK.get_ticket(ticket_id) or {}
            CASEWORK.append_activity(ticket_id, "System", "exports_preparing", "running", f"Preparing cached Word/PDF exports for {agent}.", {"agent": agent})
            if agent == "reporting":
                for report_key in REPORT_TEMPLATES:
                    generate_reporting_export(PROJECT_ROOT, OUTPUTS_DIR, ticket, report_key, "docx")
                    generate_reporting_export(PROJECT_ROOT, OUTPUTS_DIR, ticket, report_key, "pdf")
            else:
                generate_agent_export(PROJECT_ROOT, OUTPUTS_DIR, ticket, agent, "docx")
                generate_agent_export(PROJECT_ROOT, OUTPUTS_DIR, ticket, agent, "pdf")
            CASEWORK.append_activity(ticket_id, "System", "exports_ready", "completed", f"Cached Word/PDF exports are ready for {agent}.", {"agent": agent})
        except Exception as exc:
            try:
                CASEWORK.append_activity(ticket_id, "System", "exports_failed", "failed", f"Export preparation failed for {agent}: {exc}", {"agent": agent, "error": str(exc)})
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


def start_background_run(agent: str, ticket_id: str | None = None, run_type: str = "run", triggered_by: str = "SOC Analyst", rerun_of_run_id: str | None = None, reason: str = "") -> tuple[dict, int]:
    if agent not in AGENT_ADAPTERS:
        return {"success": False, "status": "Unknown agent"}, 404
    cfg = AGENT_ADAPTERS[agent]
    if not cfg["script"].exists():
        return {"success": False, "status": "Adapter script not found", "script": str(cfg["script"].relative_to(PROJECT_ROOT))}, 404

    if ticket_id:
        ticket = CASEWORK.get_ticket(ticket_id)
        if not ticket:
            return {"success": False, "status": f"Ticket {ticket_id} not found"}, 404

        # Before ticket gating for Reporting, backfill limited investigation context
        # from known JSON output locations into the ticket if the dashboard DB has not
        # captured it yet. This prevents false "Run Investigation first" blocks.
        if agent == "reporting":
            resolved_inv = resolve_investigation_context(PROJECT_ROOT, ticket_id=ticket_id, ticket=ticket)
            resolved_approval = resolve_investigation_approval_context(PROJECT_ROOT, ticket_id=ticket_id, ticket=ticket)
            patch_fields = {}
            if resolved_inv.exists and resolved_inv.usable and not ticket.get("investigation_result"):
                patch_fields["investigation_result"] = resolved_inv.data
            if resolved_approval.exists and resolved_approval.usable and not ticket.get("investigation_approval_result"):
                patch_fields["investigation_approval_result"] = resolved_approval.data
            if patch_fields:
                ticket = CASEWORK.update_ticket(
                    ticket_id,
                    patch_fields,
                    actor="System",
                    action="reporting_context_backfilled",
                    message="Backfilled investigation context for Reporting from existing agent output files.",
                )

        allowed_for_ticket, ticket_gate = ticket_workflow.can_run_agent(ticket, agent)
        if not allowed_for_ticket:
            return {"success": False, "status": ticket_gate, "gate_code": "ticket_workflow_blocked", "ticket": ticket_workflow.decorate_ticket(ticket)}, 409
        prepared_raw_alert = CASEWORK.prepare_agent_inputs(ticket_id, INPUTS_DIR)
        if agent == "parsing":
            removed_outputs = clear_stale_parser_outputs(PROJECT_ROOT, ticket_id=ticket_id)
            # Recreate the selected-ticket raw parser input after clearing the
            # previous parser folder. This keeps the run bound to the selected ticket.
            ticket_parsing_dir = OUTPUTS_DIR / ticket_id / "parsing"
            ticket_parsing_dir.mkdir(parents=True, exist_ok=True)
            write_json(ticket_parsing_dir / "raw_input_alert.json", prepared_raw_alert)
            raw_identity = extract_alert_identity(prepared_raw_alert)
            raw_identity.update({"ticket_id": ticket_id})
            write_json(ticket_parsing_dir / "input_identity.json", raw_identity)
            CASEWORK.append_activity(
                ticket_id,
                "System",
                "parser_context_prepared",
                "completed",
                f"Parser context isolated for selected alert {raw_identity.get('alert_id') or 'unknown alert'}.",
                {"agent": agent, "input_identity": raw_identity, "removed_stale_outputs": removed_outputs},
            )
        write_json(SELECTED_TICKET_FILE, {"ticket_id": ticket_id, "agent": agent, "selected_at": now_iso()})
        CASEWORK.append_activity(ticket_id, "System", f"{agent}_started", "running", f"{cfg['label']} started for this ticket.", {"agent": agent, "run_type": run_type})
        if run_type == "rerun":
            try:
                CASEWORK.mark_downstream_refresh_required(
                    ticket_id,
                    agent,
                    reason=f"{cfg['label']} was re-run. Downstream agent outputs may need refresh before final review.",
                    actor=triggered_by,
                )
            except Exception:
                pass

    allowed, gate_code, gate_message = agent_run_gate(agent, ticket_id=ticket_id)
    if not allowed:
        return {"success": False, "status": gate_message, "gate_code": gate_code, "agent": agent, "workflow": workflow_state()}, 409

    # Bridge ticket/database context into legacy JSON inputs before launching Reporting.
    if agent == "reporting":
        selected_ticket = CASEWORK.get_ticket(ticket_id) if ticket_id else None
        ensure_reporting_inputs(PROJECT_ROOT, ticket_id=ticket_id, ticket=selected_ticket)

    # Prevent duplicate runs of the same agent on the same ticket only.
    # The same agent may run concurrently on different tickets.
    current = latest_run_for(agent, ticket_id=ticket_id)
    if current and current.get("running"):
        return {
            "success": False,
            "status": "Agent is already running for this ticket",
            "run_id": current["run_id"],
            "ticket_id": ticket_id,
            "agent": agent,
            "started_at": current.get("started_at"),
            "run_status": current.get("status"),
            "progress_percent": current.get("progress_percent"),
        }, 409

    run_id = uuid.uuid4().hex[:12]
    run_output_dir = OUTPUTS_DIR / "tickets" / (ticket_id or "global") / "runs" / run_id
    run_output_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": run_id,
        "agent": agent,
        "ticket_id": ticket_id,
        "run_type": run_type,
        "triggered_by": triggered_by,
        "is_rerun": run_type == "rerun",
        "rerun_of_run_id": rerun_of_run_id,
        "reason": reason,
        "run_output_dir": str(run_output_dir.relative_to(PROJECT_ROOT)),
        "label": cfg["label"],
        "script": str(cfg["script"].relative_to(PROJECT_ROOT)),
        "status": "running",
        "running": True,
        "success": None,
        "started_at": now_iso(),
        "finished_at": None,
        "returncode": None,
        "logs": [f"[{cfg['label']}] Started at {now_iso()}", "[System] Waiting for real adapter progress output"],
        "thinking": True,
        "current_step": "Starting agent process...",
        "progress_percent": 3,
        "phase_index": 0,
        "steps": THINKING_STEPS.get(agent, ["Preparing agent run"]),
        "timeout_seconds": AGENT_TIMEOUT_SECONDS.get(agent, 180),
        "pause_requested": False,
        "paused_at": None,
    }
    with RUN_LOCK:
        RUNS[run_id] = run_record
    if ticket_id:
        try:
            CASEWORK.record_agent_run_start(
                run_id,
                ticket_id,
                agent,
                run_type=run_type,
                triggered_by=triggered_by,
                rerun_of_run_id=rerun_of_run_id,
                output_path=str(run_output_dir.relative_to(PROJECT_ROOT)),
                payload={"reason": reason, "label": cfg["label"]},
            )
        except Exception:
            pass

    def thinking_pulse() -> None:
        # Real progress comes from adapter stdout lines like:
        # [PROGRESS 45] Checking IOC reputation
        # This lightweight pulse only keeps the spinner alive if an old agent emits no progress yet.
        while True:
            time.sleep(3)
            with RUN_LOCK:
                rec = RUNS.get(run_id)
                if not rec or not rec.get("running"):
                    break
                if rec.get("progress_percent", 0) <= 8:
                    rec["current_step"] = "Waiting for agent progress output..."

    def worker() -> None:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["SOC_RUN_ID"] = run_id
        env["SOC_AGENT_NAME"] = agent
        env["SOC_RUN_TYPE"] = run_type
        env["SOC_IS_RERUN"] = "true" if run_type == "rerun" else "false"
        env["SOC_RUN_OUTPUT_DIR"] = str(run_output_dir)
        env["SOC_OUTPUT_DIR"] = str(run_output_dir)
        if ticket_id:
            env["SOC_TICKET_ID"] = ticket_id
        try:
            proc = subprocess.Popen(
                [sys.executable, str(cfg["script"])],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                shell=False,
                env=env,
            )
            with RUN_LOCK:
                RUN_PROCESSES[run_id] = proc
                RUNS[run_id]["pid"] = proc.pid

            def timeout_watchdog() -> None:
                timeout = AGENT_TIMEOUT_SECONDS.get(agent, 180)
                time.sleep(timeout)
                with RUN_LOCK:
                    rec = RUNS.get(run_id)
                    still_running = bool(rec and rec.get("running"))
                if still_running and proc.poll() is None:
                    try:
                        proc.terminate()
                        time.sleep(2)
                        if proc.poll() is None:
                            proc.kill()
                    except Exception:
                        pass
                    with RUN_LOCK:
                        rec = RUNS.get(run_id)
                        if rec:
                            rec["status"] = "timed_out"
                            rec["success"] = False
                            rec["current_step"] = f"Agent timed out after {timeout} seconds"
                            rec["logs"].append(f"[TIMEOUT] Agent exceeded {timeout} seconds and was terminated safely.")

            threading.Thread(target=timeout_watchdog, daemon=True).start()

            assert proc.stdout is not None
            for line in proc.stdout:
                clean_line = line.rstrip()
                progress_match = re.search(r"\[PROGRESS\s+(\d{1,3})\]\s*(.*)", clean_line)
                with RUN_LOCK:
                    if progress_match:
                        pct = max(0, min(100, int(progress_match.group(1))))
                        step = progress_match.group(2).strip() or "Agent progress update"
                        RUNS[run_id]["progress_percent"] = pct
                        RUNS[run_id]["current_step"] = step
                        RUNS[run_id]["thinking"] = pct < 100
                        steps = RUNS[run_id].get("steps") or []
                        if steps:
                            RUNS[run_id]["phase_index"] = min(len(steps) - 1, max(0, int((pct / 100) * len(steps))))
                    RUNS[run_id]["logs"].append(clean_line)
                    RUNS[run_id]["logs"] = RUNS[run_id]["logs"][-500:]
                    pause_requested = RUNS[run_id].get("pause_requested")
                if pause_requested and proc.poll() is None:
                    proc.terminate()
                    break
            returncode = proc.wait()
            out_status, out_data = output_status_for_agent(agent, run_output_dir=run_output_dir)
            final_status, final_success, final_step = normalise_agent_output_status(out_status, returncode)
            with RUN_LOCK:
                if RUNS.get(run_id, {}).get("pause_requested"):
                    final_status, final_success, final_step = "paused", False, "Agent pause requested by analyst"
                elif RUNS.get(run_id, {}).get("status") == "timed_out":
                    final_status, final_success, final_step = "timed_out", False, RUNS[run_id].get("current_step") or "Agent timed out"
                RUNS[run_id]["returncode"] = returncode
                RUNS[run_id]["output_status"] = out_status
                RUNS[run_id]["output_summary"] = {
                    "status": out_data.get("status") if isinstance(out_data, dict) else None,
                    "classification": out_data.get("classification") if isinstance(out_data, dict) else None,
                    "recommended_next_action": out_data.get("recommended_next_action") if isinstance(out_data, dict) else None,
                    "recommendation_count": out_data.get("recommendation_count") if isinstance(out_data, dict) else None,
                    "ai_used": out_data.get("ai_used") if isinstance(out_data, dict) else None,
                    "ai_status": out_data.get("ai_status") if isinstance(out_data, dict) else None,
                    "ai_model": out_data.get("ai_model") or out_data.get("model") if isinstance(out_data, dict) else None,
                    "execution_mode": out_data.get("execution_mode") if isinstance(out_data, dict) else None,
                } if isinstance(out_data, dict) else {}
                RUNS[run_id]["success"] = final_success
                RUNS[run_id]["status"] = final_status
                RUNS[run_id]["running"] = False
                RUNS[run_id]["thinking"] = False
                RUNS[run_id]["current_step"] = final_step
                RUNS[run_id]["progress_percent"] = 100 if final_success else max(RUNS[run_id].get("progress_percent", 50), 50)
                steps = RUNS[run_id].get("steps") or []
                if final_success and steps:
                    RUNS[run_id]["phase_index"] = len(steps) - 1
                RUNS[run_id]["finished_at"] = now_iso()
                RUNS[run_id]["logs"].append(f"[{cfg['label']}] Finished with return code {returncode}; output status: {out_status or 'not_found'}")
                if ticket_id and out_data:
                    try:
                        if not (agent == "investigation" and out_data.get("postgres_write_completed")):
                            CASEWORK.attach_agent_result(ticket_id, agent, out_data)
                        if final_success and agent != "orchestration":
                            start_background_export_preparation(ticket_id, agent)
                    except Exception as exc:
                        RUNS[run_id]["logs"].append(f"[Ticket Update Error] {exc}")
            if ticket_id:
                try:
                    output_file = agent_output_path(agent, run_output_dir)
                    CASEWORK.record_agent_run_finish(
                        run_id,
                        final_status,
                        progress=100 if final_success else max(RUNS.get(run_id, {}).get("progress_percent", 50), 50),
                        output_path=str(output_file.relative_to(PROJECT_ROOT)) if output_file and output_file.exists() else str(run_output_dir.relative_to(PROJECT_ROOT)),
                        error_message=None if final_success else final_step,
                        output_summary=RUNS.get(run_id, {}).get("output_summary") or {},
                    )
                except Exception:
                    pass
            with RUN_LOCK:
                RUN_PROCESSES.pop(run_id, None)
        except Exception as exc:
            with RUN_LOCK:
                RUNS[run_id]["returncode"] = -1
                RUNS[run_id]["success"] = False
                RUNS[run_id]["status"] = "execution_error"
                RUNS[run_id]["running"] = False
                RUNS[run_id]["thinking"] = False
                RUNS[run_id]["current_step"] = "Execution error, check logs"
                RUNS[run_id]["progress_percent"] = max(RUNS[run_id].get("progress_percent", 50), 50)
                RUNS[run_id]["finished_at"] = now_iso()
                RUNS[run_id]["logs"].append(f"[ERROR] {exc}")
                if ticket_id:
                    try:
                        CASEWORK.record_agent_run_finish(run_id, "execution_error", progress=RUNS[run_id].get("progress_percent", 50), error_code="EXECUTION_ERROR", error_message=str(exc))
                    except Exception:
                        pass
                RUN_PROCESSES.pop(run_id, None)

    pulse_thread = threading.Thread(target=thinking_pulse, daemon=True)
    pulse_thread.start()
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return {"success": True, "status": "started", "run_id": run_id, "agent": agent, "ticket_id": ticket_id, "label": cfg["label"], "run_type": run_type, "is_rerun": run_type == "rerun", "started_at": run_record["started_at"], "progress_percent": run_record["progress_percent"], "run_output_dir": str(run_output_dir.relative_to(PROJECT_ROOT))}, 202


# -------------------- NetWitness and external API helpers --------------------

def nw_base_url() -> str:
    return NetWitnessClient().base_url


def nw_headers() -> dict[str, str]:
    return NetWitnessClient().headers()


def nw_login_if_needed() -> str:
    return NetWitnessClient().get_token()


@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path: str):
    full = DASHBOARD_DIR / path
    if full.exists():
        return send_from_directory(DASHBOARD_DIR, path)
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/case")
def api_case():
    selected_meta = read_data(SELECTED_TICKET_FILE, {}) or {}
    selected_ticket_id = request.args.get("ticket_id") or selected_meta.get("ticket_id")
    selected_ticket = CASEWORK.get_ticket(selected_ticket_id) if selected_ticket_id else None
    report_payload = safe_read_agent_json(OUTPUTS_DIR / "final_report.json", "Reporting Agent", "reporting")
    txt = OUTPUTS_DIR / "final_report.txt"
    if txt.exists():
        report_text = txt.read_text(encoding="utf-8", errors="ignore")
        report_payload["report_text"] = report_text
    manifest = load_manifest(OUTPUTS_DIR)
    if manifest:
        report_payload["report_manifest"] = manifest
        report_payload["report_sections_text"] = report_section_texts(manifest)
    return jsonify({
        "ready": True,
        "case": case_summary(),
        "ticket": _ticket_response(selected_ticket) if selected_ticket else None,
        "tickets": CASEWORK.list_tickets({"open_only": True, "limit": 100}),
        "ticket_summary": CASEWORK.dashboard_summary(),
        "workflow": workflow_state(),
        "agents": {
            "correlation": attach_agent_review("correlation", safe_read_agent_json(OUTPUTS_DIR / "correlation_recommendations.json", "Incident Grouping", "correlation")),
            "parsing": attach_agent_review("parsing", safe_read_agent_json(OUTPUTS_DIR / "parser_result.json", "Parsing & Normalisation", "parsing")),
            "triage": attach_agent_review("triage", safe_read_agent_json(OUTPUTS_DIR / "triage_result.json", "Triage Agent", "triage")),
            "threat_intel": attach_agent_review("threat_intel", safe_read_agent_json(OUTPUTS_DIR / "threat_intel_result.json", "Threat Intelligence Enrichment", "threat_intel")),
            "investigation": attach_agent_review("investigation", safe_read_agent_json(OUTPUTS_DIR / "investigation_result.json", "Investigation Agent", "investigation")),
            "reporting": attach_agent_review("reporting", report_payload),
        },
        "report_text": report_payload.get("report_text"),
        "report_manifest": manifest,
    })


@app.route("/api/workflow-state")
def api_workflow_state():
    return jsonify(workflow_state())


@app.route("/api/correlation")
def api_correlation():
    return jsonify(attach_agent_review("correlation", safe_read_agent_json(OUTPUTS_DIR / "correlation_recommendations.json", "Incident Grouping", "correlation")))


@app.route("/api/parsing")
def api_parsing():
    return jsonify(attach_agent_review("parsing", safe_read_agent_json(OUTPUTS_DIR / "parser_result.json", "Parsing & Normalisation", "parsing")))


@app.route("/api/tickets/<ticket_id>/parsing/continue-available-data", methods=["POST"])
def api_parsing_continue_available_data(ticket_id: str):
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"success": False, "status": "Ticket not found"}), 404
    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason") or "Analyst chose to continue parser workflow with available local ticket data.").strip()
    flag_dir = RUNTIME_DIR / "parser_flags"
    flag_dir.mkdir(parents=True, exist_ok=True)
    write_json(flag_dir / f"{ticket_id}_continue_available_data.json", {
        "ticket_id": ticket_id,
        "requested_at": now_iso(),
        "reason": reason,
        "note": "The current parser is local-data first. This flag is recorded for auditability and future NetWitness fetch cancellation support.",
    })
    CASEWORK.append_activity(ticket_id, "SOC Analyst", "parser_continue_available_data", "completed", reason, {"ticket_id": ticket_id})
    return jsonify({
        "success": True,
        "status": "continue_available_data_recorded",
        "message": "Parser will continue with available ticket data. If a parser run is already completed, refresh the ticket view.",
    })


@app.route("/api/threat-intel")
def api_threat_intel():
    return jsonify(attach_agent_review("threat_intel", safe_read_agent_json(OUTPUTS_DIR / "threat_intel_result.json", "Threat Intelligence Enrichment", "threat_intel")))


@app.route("/api/triage")
def api_triage():
    return jsonify(attach_agent_review("triage", safe_read_agent_json(OUTPUTS_DIR / "triage_result.json", "Triage Agent", "triage")))


@app.route("/api/investigation")
def api_investigation():
    return jsonify(attach_agent_review("investigation", safe_read_agent_json(OUTPUTS_DIR / "investigation_result.json", "Investigation Agent", "investigation")))


@app.route("/api/reporting")
def api_reporting():
    payload = safe_read_agent_json(OUTPUTS_DIR / "final_report.json", "Reporting Agent", "reporting")
    txt = OUTPUTS_DIR / "final_report.txt"
    if txt.exists():
        payload["report_text"] = txt.read_text(encoding="utf-8", errors="ignore")
    manifest = load_manifest(OUTPUTS_DIR)
    if manifest:
        payload["report_manifest"] = manifest
        payload["report_sections_text"] = report_section_texts(manifest)
    return jsonify(attach_agent_review("reporting", payload))


@app.route("/api/runs")
def api_runs():
    with RUN_LOCK:
        return jsonify({"runs": sorted(RUNS.values(), key=lambda r: r.get("started_at", ""), reverse=True)})


@app.route("/api/runs/<run_id>")
def api_run_status(run_id: str):
    with RUN_LOCK:
        run = RUNS.get(run_id)
    if not run:
        return jsonify({"success": False, "status": "Run not found"}), 404
    return jsonify(run)


@app.route("/api/runs/<run_id>/pause", methods=["POST"])
def api_run_pause(run_id: str):
    with RUN_LOCK:
        run = RUNS.get(run_id)
        proc = RUN_PROCESSES.get(run_id)
        if not run:
            return api_error("Run not found", 404, code="RUN_NOT_FOUND", title="Run not found", analyst_action="Refresh the Agent Workspace and try again.")
        if not run.get("running"):
            return jsonify({"success": True, "status": "not_running", "message": "Run is no longer active.", "run": run})
        run["pause_requested"] = True
        run["status"] = "pause_requested"
        run["paused_at"] = now_iso()
        run["current_step"] = "Pause requested by analyst"
        run["logs"].append("[PAUSE] Analyst requested a safe pause for this run.")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
        except Exception:
            pass
    return jsonify({"success": True, "status": "pause_requested", "run_id": run_id, "message": "Pause requested. The agent process is being stopped safely."})


@app.route("/api/run/<agent>/pause", methods=["POST"])
def api_pause_latest_agent(agent: str):
    run = latest_run_for(agent)
    if not run:
        return api_error("No recent run found for this agent", 404, code="RUN_NOT_FOUND", analyst_action="Start the agent before using Pause.")
    return api_run_pause(run["run_id"])


@app.route("/api/tickets/<ticket_id>/pause-agent", methods=["POST"])
def api_pause_ticket_agent(ticket_id: str):
    body = request.get_json(silent=True) or {}
    agent = body.get("agent")
    run_id = body.get("run_id")
    if run_id:
        return api_run_pause(run_id)
    with RUN_LOCK:
        candidates = [r for r in RUNS.values() if r.get("ticket_id") == ticket_id and r.get("running") and (not agent or r.get("agent") == agent)]
    if not candidates:
        return api_error("No active run found for this ticket", 404, code="RUN_NOT_FOUND", analyst_action="Refresh the Agent Workspace. The run may already be complete.")
    candidates.sort(key=lambda r: r.get("started_at", ""), reverse=True)
    return api_run_pause(candidates[0]["run_id"])


@app.route("/api/run/<agent>", methods=["POST"])
def api_run_agent(agent: str):
    body = request.get_json(silent=True) or {}
    payload, status = start_background_run(
        agent,
        ticket_id=body.get("ticket_id"),
        run_type=body.get("run_type") or "run",
        triggered_by=body.get("analyst") or body.get("triggered_by") or "SOC Analyst",
        reason=body.get("reason") or "",
    )
    return jsonify(payload), status


@app.route("/api/tickets/<ticket_id>/agents/<agent>/run", methods=["POST"])
def api_ticket_agent_run(ticket_id: str, agent: str):
    body = request.get_json(silent=True) or {}
    payload, status = start_background_run(
        agent,
        ticket_id=ticket_id,
        run_type="run",
        triggered_by=body.get("analyst") or "SOC Analyst",
        reason=body.get("reason") or "Manual agent run requested by SOC analyst.",
    )
    return jsonify(payload), status


@app.route("/api/tickets/<ticket_id>/agents/<agent>/rerun", methods=["POST"])
def api_ticket_agent_rerun(ticket_id: str, agent: str):
    body = request.get_json(silent=True) or {}
    existing_active = active_agent_run(ticket_id=ticket_id, agent=agent)
    if existing_active:
        return jsonify({
            "success": False,
            "status": "This agent is already running for this ticket.",
            "run_id": existing_active.get("run_id"),
            "ticket_id": ticket_id,
            "agent": agent,
            "started_at": existing_active.get("started_at"),
            "run_status": existing_active.get("status"),
            "progress_percent": existing_active.get("progress_percent"),
        }), 409
    prior = CASEWORK.latest_agent_run(ticket_id, agent) if ticket_id else None
    payload, status = start_background_run(
        agent,
        ticket_id=ticket_id,
        run_type="rerun",
        triggered_by=body.get("analyst") or "SOC Analyst",
        rerun_of_run_id=(prior or {}).get("run_id"),
        reason=body.get("reason") or "SOC analyst requested agent re-run.",
    )
    return jsonify(payload), status


@app.route("/api/tickets/<ticket_id>/agents/<agent>/runs")
def api_ticket_agent_runs(ticket_id: str, agent: str):
    limit = int(request.args.get("limit") or 25)
    runs = CASEWORK.list_agent_runs(ticket_id, agent, limit=limit)
    with RUN_LOCK:
        live = [dict(r) for r in RUNS.values() if r.get("ticket_id") == ticket_id and r.get("agent") == agent]
    return jsonify({"success": True, "ticket_id": ticket_id, "agent": agent, "runs": runs, "live_runs": sorted(live, key=lambda r: r.get("started_at", ""), reverse=True)})


@app.route("/api/tickets/<ticket_id>/agents/status")
def api_ticket_agents_status(ticket_id: str):
    statuses = {}
    for agent_key in AGENT_ADAPTERS:
        latest_live = latest_run_for(agent_key, ticket_id=ticket_id)
        history = CASEWORK.latest_agent_run(ticket_id, agent_key)
        statuses[agent_key] = {
            "running": bool(latest_live and latest_live.get("running")),
            "run_id": (latest_live or {}).get("run_id") or (history or {}).get("run_id"),
            "status": (latest_live or {}).get("status") or (history or {}).get("status") or "not_run",
            "progress": (latest_live or {}).get("progress_percent") or (history or {}).get("progress") or 0,
            "latest_run": latest_live or history,
        }
    return jsonify({"success": True, "ticket_id": ticket_id, "agents": statuses})


def _ticket_response(ticket: dict[str, Any] | None) -> dict[str, Any]:
    if not ticket:
        return {}
    decorated = ticket_workflow.decorate_ticket(ticket)
    ticket_id = decorated.get("ticket_id")
    if ticket_id:
        decorated["agent_run_history"] = {
            agent_key: CASEWORK.list_agent_runs(ticket_id, agent_key, limit=10)
            for agent_key in AGENT_ADAPTERS
        }
        with RUN_LOCK:
            decorated["active_agent_runs"] = [
                dict(r) for r in RUNS.values()
                if r.get("ticket_id") == ticket_id and r.get("running")
            ]
    return decorated


def _request_filters() -> dict[str, Any]:
    filters = dict(request.args)
    if request.is_json:
        body = request.get_json(silent=True) or {}
        filters.update({k: v for k, v in body.items() if v not in (None, "")})
    return filters


@app.route("/api/dashboard")
def api_dashboard():
    selected_ticket_id = request.args.get("ticket_id")
    analyst = (request.args.get("analyst") or "").strip()
    selected = CASEWORK.get_ticket(selected_ticket_id) if selected_ticket_id else None
    if not selected:
        tickets = CASEWORK.list_tickets({"open_only": True, "limit": 1})
        selected = CASEWORK.get_ticket(tickets[0]["ticket_id"]) if tickets else None
    return jsonify({
        "success": True,
        "summary": CASEWORK.dashboard_summary(owner=analyst or None),
        "analyst": analyst or None,
        "tickets": CASEWORK.list_tickets({"open_only": True, "limit": 100}),
        "selected_ticket": _ticket_response(selected),
        "integrations": {"netwitness": NetWitnessClient().status()},
        "runs": sorted(RUNS.values(), key=lambda r: r.get("started_at", ""), reverse=True),
    })


@app.route("/api/tickets/lookup")
def api_tickets_lookup():
    filters = _request_filters()
    filters["open_only"] = str(filters.get("open_only", "true")).lower() not in {"0", "false", "no"}
    filters["limit"] = int(filters.get("limit") or 50)
    tickets = CASEWORK.list_tickets(filters)
    return jsonify({"success": True, "tickets": tickets})


@app.route("/api/tickets")
def api_tickets():
    filters = _request_filters()
    if filters.get("view") == "closed":
        filters["status"] = "Closed"
    if filters.get("view") == "pending_approval":
        filters["status"] = "Awaiting Approval"
    if filters.get("view") == "my":
        filters["owner"] = "me"
    if not filters.get("status") and not filters.get("stage") and filters.get("view") != "closed":
        filters["open_only"] = True
    tickets = CASEWORK.list_tickets(filters)
    if str(filters.get("multi") or "").lower() in {"1", "true", "yes"}:
        tickets = [ticket for ticket in tickets if int(ticket.get("alert_count") or 0) > 1]
    return jsonify({"success": True, "tickets": tickets, "summary": CASEWORK.dashboard_summary()})


@app.route("/api/tickets/<ticket_id>")
def api_ticket_detail(ticket_id: str):
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"success": False, "status": "Ticket not found"}), 404
    write_json(SELECTED_TICKET_FILE, {"ticket_id": ticket_id, "selected_at": now_iso()})
    return jsonify({"success": True, "ticket": _ticket_response(ticket)})


@app.route("/api/tickets/from-alert/<alert_id>", methods=["POST"])
def api_ticket_from_alert(alert_id: str):
    body = request.get_json(silent=True) or {}
    if not CASEWORK.get_alert(alert_id):
        client_result = NetWitnessClient().fetch_alert(alert_id)
        if client_result.get("alert"):
            CASEWORK.upsert_alert(client_result["alert"])
    try:
        ticket = CASEWORK.create_ticket_from_alert(alert_id, owner=body.get("owner") or "Unassigned")
        return jsonify({"success": True, "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/link-alert", methods=["POST"])
def api_ticket_link_alert(ticket_id: str):
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    if not alert_id:
        return jsonify({"success": False, "status": "alert_id is required"}), 400
    if body.get("alert") and not CASEWORK.get_alert(alert_id):
        CASEWORK.upsert_alert(body["alert"])
    existing = CASEWORK.ticket_for_alert(alert_id)
    if existing and existing.get("ticket_id") == ticket_id:
        return api_error(
            "This alert is already linked to this ticket.",
            409,
            code="DUPLICATE_ALERT_LINK",
            title="Duplicate alert link",
            analyst_action="No action is needed. The alert is already part of this incident ticket.",
            details={"alert_id": alert_id, "ticket_id": ticket_id},
        )
    if existing and existing.get("ticket_id") != ticket_id and not body.get("force_move"):
        return api_error(
            f"This alert is currently linked to {existing.get('ticket_id')}. Move it here instead of linking a duplicate.",
            409,
            code="ALERT_ALREADY_LINKED_TO_OTHER_TICKET",
            title="Alert already belongs to another ticket",
            analyst_action="Use Move Alert and provide an analyst reason if it should be reassigned.",
            details={"alert_id": alert_id, "current_ticket_id": existing.get("ticket_id"), "target_ticket_id": ticket_id},
        )
    try:
        if existing and body.get("force_move"):
            ticket = CASEWORK.move_alert_to_ticket(alert_id, ticket_id, analyst=body.get("analyst") or "SOC Analyst", reason=body.get("reason") or "Analyst moved alert during manual linking.")
        else:
            ticket = CASEWORK.link_alert(ticket_id, alert_id, relationship=body.get("relationship") or "Related alert", linked_by=body.get("analyst") or "SOC Analyst", link_source=body.get("link_source") or "manual", link_reason=body.get("reason") or body.get("relationship") or "Manually linked by analyst.", confirmed_by=body.get("analyst") or "SOC Analyst")
        return jsonify({"success": True, "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/unlink-alert", methods=["POST"])
def api_ticket_unlink_alert(ticket_id: str):
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    if not alert_id:
        return jsonify({"success": False, "status": "alert_id is required"}), 400
    current = CASEWORK.ticket_for_alert(alert_id)
    if not current or current.get("ticket_id") != ticket_id:
        return api_error("This alert is not linked to the selected ticket.", 404, code="ALERT_LINK_NOT_FOUND", analyst_action="Refresh the related alerts table before removing it again.")
    ticket = CASEWORK.unlink_alert(ticket_id, alert_id, analyst=body.get("analyst") or "SOC Analyst", reason=body.get("reason") or "Analyst removed alert from this incident ticket.")
    return jsonify({"success": True, "ticket": _ticket_response(ticket)})


@app.route("/api/correlation/recommendations")
def api_correlation_recommendations():
    filters = _request_filters()
    return jsonify({"success": True, "recommendations": CASEWORK.list_correlation_recommendations(filters)})


@app.route("/api/tickets/<ticket_id>/correlation-recommendations")
def api_ticket_correlation_recommendations(ticket_id: str):
    if not CASEWORK.get_ticket(ticket_id):
        return jsonify({"success": False, "status": "Ticket not found"}), 404
    return jsonify({"success": True, "recommendations": CASEWORK.list_correlation_recommendations({"ticket_id": ticket_id, "limit": 100})})


def _refresh_ticket_after_incident_grouping_review(ticket_id: str | None) -> dict | None:
    """Move a ticket out of grouping-review status once all recommendations are reviewed."""
    if not ticket_id:
        return None
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return None
    pending = CASEWORK.list_correlation_recommendations({"ticket_id": ticket_id, "status": "pending", "limit": 100})
    if pending:
        return ticket
    stage = str(ticket.get("current_stage") or "")
    status = str(ticket.get("status") or "")
    if "grouping" not in stage.lower() and "grouping" not in status.lower():
        return ticket
    fields = {}
    if ticket.get("triage_result") and not ticket.get("approval_result") and (ticket.get("triage_result") or {}).get("approval_required"):
        fields = {"current_stage": "triage_approval", "status": "Awaiting Approval"}
    elif ticket.get("triage_result") and not ticket.get("threat_intel_result"):
        fields = {"current_stage": "threat_intelligence", "status": "Threat Intel Required"}
    elif ticket.get("investigation_result") and not ticket.get("investigation_approval_result"):
        fields = {"current_stage": "investigation_approval", "status": "Investigation Review Required"}
    elif ticket.get("investigation_result") and ticket.get("investigation_approval_result") and not ticket.get("reporting_result"):
        fields = {"current_stage": "reporting", "status": "Reporting Required"}
    elif ticket.get("threat_intel_result") and not ticket.get("investigation_result"):
        fields = {"current_stage": "investigation", "status": "Investigation Required"}
    if fields:
        return CASEWORK.update_ticket(ticket_id, fields, actor="System", action="incident_grouping_review_completed", message="All incident grouping recommendations were reviewed; workflow stage refreshed.")
    return ticket


@app.route("/api/tickets/<ticket_id>/run-correlation", methods=["POST"])
def api_ticket_run_correlation(ticket_id: str):
    payload, status = start_background_run("correlation", ticket_id=ticket_id)
    return jsonify(payload), status


@app.route("/api/correlation/recommendations/<recommendation_id>/confirm", methods=["POST"])
def api_confirm_correlation_recommendation(recommendation_id: str):
    body = request.get_json(silent=True) or {}
    try:
        result = CASEWORK.confirm_correlation_recommendation(
            recommendation_id,
            analyst=body.get("analyst") or "SOC Analyst",
            comments=body.get("comments") or "Confirmed incident grouping recommendation.",
        )
        ticket = _refresh_ticket_after_incident_grouping_review((result.get("ticket") or {}).get("ticket_id")) or result.get("ticket")
        return jsonify({"success": True, "recommendation": result.get("recommendation"), "ticket": _ticket_response(ticket)})
    except (KeyError, ValueError) as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/correlation/recommendations/<recommendation_id>/reject", methods=["POST"])
def api_reject_correlation_recommendation(recommendation_id: str):
    body = request.get_json(silent=True) or {}
    try:
        rec = CASEWORK.reject_correlation_recommendation(
            recommendation_id,
            analyst=body.get("analyst") or "SOC Analyst",
            comments=body.get("comments") or "Rejected by analyst.",
        )
        ticket = _refresh_ticket_after_incident_grouping_review(rec.get("target_ticket_id")) if rec.get("target_ticket_id") else None
        return jsonify({"success": True, "recommendation": rec, "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/correlation/recommendations/<recommendation_id>/edit", methods=["POST"])
def api_edit_correlation_recommendation(recommendation_id: str):
    body = request.get_json(silent=True) or {}
    target_ticket_id = body.get("target_ticket_id")
    if not target_ticket_id:
        return jsonify({"success": False, "status": "target_ticket_id is required"}), 400
    try:
        result = CASEWORK.edit_correlation_recommendation(
            recommendation_id,
            target_ticket_id,
            analyst=body.get("analyst") or "SOC Analyst",
            comments=body.get("comments") or "Analyst edited the target ticket for this alert.",
        )
        ticket = _refresh_ticket_after_incident_grouping_review((result.get("ticket") or {}).get("ticket_id")) or result.get("ticket")
        return jsonify({"success": True, "recommendation": result.get("recommendation"), "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/move-alert", methods=["POST"])
def api_ticket_move_alert(ticket_id: str):
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    target_ticket_id = body.get("target_ticket_id") or ticket_id
    if not alert_id or not target_ticket_id:
        return jsonify({"success": False, "status": "alert_id and target_ticket_id are required"}), 400
    try:
        ticket = CASEWORK.move_alert_to_ticket(alert_id, target_ticket_id, analyst=body.get("analyst") or "SOC Analyst", reason=body.get("reason") or "Analyst manually moved alert.")
        return jsonify({"success": True, "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/split-alert", methods=["POST"])
def api_ticket_split_alert(ticket_id: str):
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    if not alert_id:
        return jsonify({"success": False, "status": "alert_id is required"}), 400
    try:
        ticket = CASEWORK.split_alert_to_new_ticket(ticket_id, alert_id, analyst=body.get("analyst") or "SOC Analyst", reason=body.get("reason") or "Analyst split alert into a separate incident.")
        return jsonify({"success": True, "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/merge", methods=["POST"])
def api_ticket_merge(ticket_id: str):
    body = request.get_json(silent=True) or {}
    source_ticket_id = body.get("source_ticket_id")
    target_ticket_id = body.get("target_ticket_id") or ticket_id
    if not source_ticket_id:
        return jsonify({"success": False, "status": "source_ticket_id is required"}), 400
    try:
        ticket = CASEWORK.merge_tickets(source_ticket_id, target_ticket_id, analyst=body.get("analyst") or "SOC Analyst", reason=body.get("reason") or "Analyst merged related incident tickets.", archive_duplicate=bool(body.get("archive_duplicate", True)))
        return jsonify({"success": True, "ticket": _ticket_response(ticket)})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/run-next-step", methods=["POST"])
def api_ticket_run_next_step(ticket_id: str):
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"success": False, "status": "Ticket not found"}), 404

    decision = build_orchestration_decision(ticket)
    write_json(OUTPUTS_DIR / "orchestration_decision.json", decision)
    write_json(INPUTS_DIR / "orchestration_decision.json", decision)
    ticket_decision_dir = OUTPUTS_DIR / ticket_id / "orchestration"
    write_json(ticket_decision_dir / "orchestration_decision.json", decision)
    ticket = CASEWORK.update_ticket(
        ticket_id,
        {"orchestration_decision_result": decision},
        actor="Orchestration Agent",
        action="orchestration_decision_recorded",
        message=f"Orchestration decision recorded: {decision.get('next_label') or decision.get('label')}.",
    )

    next_step = {
        "agent": decision.get("next_agent"),
        "label": decision.get("next_label") or decision.get("label"),
        "allowed": decision.get("allowed"),
        "reason": decision.get("reason"),
        "workflow_decision": decision.get("workflow_decision"),
        "requires_human_approval": decision.get("requires_human_approval", False),
        "approval_gate": decision.get("approval_gate"),
        "missing_inputs": decision.get("missing_inputs", []),
        "required_inputs": decision.get("required_inputs", []),
        "orchestration_decision": decision,
    }
    if not next_step.get("agent") or not next_step.get("allowed"):
        return jsonify({"success": False, "status": next_step.get("reason"), "next_step": next_step, "orchestration_decision": decision, "ticket": _ticket_response(ticket)}), 409
    payload, status = start_background_run(next_step["agent"], ticket_id=ticket_id)
    payload["next_step"] = next_step
    payload["orchestration_decision"] = decision
    return jsonify(payload), status


@app.route("/api/tickets/<ticket_id>/approve", methods=["POST"])
def api_ticket_approve(ticket_id: str):
    body = request.get_json(silent=True) or {}
    try:
        prior = CASEWORK.get_ticket(ticket_id) or {}
        gate = body.get("gate") or prior.get("current_stage")
        ticket = CASEWORK.record_approval(ticket_id, "approved", comments=body.get("comments") or "", analyst=body.get("analyst") or "SOC Analyst", gate=gate)
        if str(gate or "").lower().replace("-", "_") == "investigation_approval":
            write_json(OUTPUTS_DIR / "investigation_approval_result.json", ticket.get("investigation_approval_result") or {})
            write_json(INPUTS_DIR / "investigation_approval_result.json", ticket.get("investigation_approval_result") or {})
            approval_payload = ticket.get("investigation_approval_result")
        else:
            write_json(OUTPUTS_DIR / "approval_result.json", ticket.get("approval_result") or {})
            write_json(INPUTS_DIR / "approval_result.json", ticket.get("approval_result") or {})
            approval_payload = ticket.get("approval_result")
        return jsonify({"success": True, "ticket": _ticket_response(ticket), "approval": approval_payload})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/reject", methods=["POST"])
def api_ticket_reject(ticket_id: str):
    body = request.get_json(silent=True) or {}
    try:
        prior = CASEWORK.get_ticket(ticket_id) or {}
        ticket = CASEWORK.record_approval(ticket_id, "rejected", comments=body.get("comments") or "", analyst=body.get("analyst") or "SOC Analyst", gate=body.get("gate") or prior.get("current_stage"))
        return jsonify({"success": True, "ticket": _ticket_response(ticket), "approval": ticket.get("approval_result") or ticket.get("investigation_approval_result")})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/request-more-evidence", methods=["POST"])
def api_ticket_more_evidence(ticket_id: str):
    body = request.get_json(silent=True) or {}
    try:
        prior = CASEWORK.get_ticket(ticket_id) or {}
        ticket = CASEWORK.record_approval(ticket_id, "request_more_evidence", comments=body.get("comments") or "More evidence requested.", analyst=body.get("analyst") or "SOC Analyst", gate=body.get("gate") or prior.get("current_stage"))
        return jsonify({"success": True, "ticket": _ticket_response(ticket), "approval": ticket.get("approval_result") or ticket.get("investigation_approval_result")})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/investigation/evidence-gap-decision", methods=["POST"])
def api_ticket_evidence_gap_decision(ticket_id: str):
    body = request.get_json(silent=True) or {}
    decision = body.get("decision") or body.get("action") or ""
    comments = body.get("comments") or ""
    analyst = body.get("analyst") or "SOC Analyst"
    try:
        ticket = CASEWORK.record_evidence_gap_decision(ticket_id, decision, comments=comments, analyst=analyst)
        decision_norm = str(decision or "").strip().lower().replace("-", "_").replace(" ", "_")
        inv_approval = ticket.get("investigation_approval_result") or {}
        if decision_norm in {"continue", "continue_reporting", "continue_to_reporting", "reporting", "with_limitations"}:
            write_json(OUTPUTS_DIR / "investigation_approval_result.json", inv_approval)
            write_json(INPUTS_DIR / "investigation_approval_result.json", inv_approval)
            write_json(INPUTS_DIR / "approval_result.json", inv_approval)
            write_json(OUTPUTS_DIR / "workflow_override.json", {
                "status": "approved",
                "override_type": "continue_to_reporting_with_limited_investigation",
                "reason": comments or "SOC analyst chose to continue to Reporting Agent with documented evidence gaps.",
                "approved_by": analyst,
                "risk_acknowledged": True,
                "ticket_id": ticket_id,
                "created_at": now_iso(),
            })
            return jsonify({
                "success": True,
                "decision": "continue_to_reporting",
                "message": "Evidence-gap decision recorded. Reporting Agent is now ready to run with limitations.",
                "ticket": _ticket_response(ticket),
                "approval": inv_approval,
            })

        triage_request = inv_approval.get("triage_requery_request") or (ticket.get("investigation_result") or {}).get("triage_requery_request") or {}
        write_json(OUTPUTS_DIR / "triage_requery_request.json", triage_request)
        write_json(INPUTS_DIR / "triage_requery_request.json", triage_request)
        write_json(OUTPUTS_DIR / "netwitness_evidence_request.json", triage_request)
        return jsonify({
            "success": True,
            "decision": "return_to_triage",
            "message": "Evidence-gap decision recorded. Case returned to Triage Agent for more NetWitness evidence.",
            "ticket": _ticket_response(ticket),
            "triage_requery_request": triage_request,
        })
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/tickets/<ticket_id>/confirm-soc-review", methods=["POST"])
def api_ticket_confirm_soc_review(ticket_id: str):
    body = request.get_json(silent=True) or {}
    try:
        ticket = CASEWORK.record_soc_review(ticket_id, decision=body.get("decision") or "confirmed", comments=body.get("comments") or "", analyst=body.get("analyst") or "SOC Analyst")
        write_json(OUTPUTS_DIR / "soc_review_result.json", ticket.get("soc_review_result") or {})
        write_json(INPUTS_DIR / "soc_review_result.json", ticket.get("soc_review_result") or {})
        return jsonify({"success": True, "ticket": _ticket_response(ticket), "soc_review": ticket.get("soc_review_result")})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/assign", methods=["POST"])
def api_ticket_assign(ticket_id: str):
    body = request.get_json(silent=True) or {}
    owner = body.get("owner") or "Soong Yang"
    if not CASEWORK.get_ticket(ticket_id):
        return jsonify({"success": False, "status": "Ticket not found"}), 404
    ticket = CASEWORK.update_ticket(ticket_id, {"owner": owner}, actor=body.get("analyst") or "SOC Analyst", action="ticket_assigned", message=f"Ticket assigned to {owner}.")
    return jsonify({"success": True, "ticket": _ticket_response(ticket)})


@app.route("/api/tickets/<ticket_id>/activity")
def api_ticket_activity(ticket_id: str):
    if not CASEWORK.get_ticket(ticket_id):
        return jsonify({"success": False, "status": "Ticket not found"}), 404
    return jsonify({"success": True, "ticket_id": ticket_id, "activity": CASEWORK.activity(ticket_id)})


@app.route("/api/tickets/<ticket_id>/reports")
def api_ticket_reports(ticket_id: str):
    try:
        ticket = CASEWORK.get_ticket(ticket_id)
        if not ticket:
            return jsonify({"success": False, "status": f"Ticket {ticket_id} not found"}), 404
        incident_id = _ticket_report_incident_id(ticket)
        try:
            report_data = list_reports(OUTPUTS_DIR, incident_id=incident_id)
        except Exception:
            report_data = CASEWORK.reports_for_ticket(ticket_id)
            report_data["manifest"] = {}
            report_data["section_order"] = CORE_REPORT_KEYS
            report_data["draft_reports"] = []
            report_data["confirmed_reports"] = []
        return jsonify({"success": True, "ticket_id": ticket_id, "incident_id": incident_id, **report_data})
    except KeyError as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


def _ticket_report_incident_id(ticket: dict[str, Any] | None) -> str:
    ticket = ticket or {}
    candidates = [
        (ticket.get("reporting_result") or {}).get("incident_id"),
        (ticket.get("parsing_result") or {}).get("incident_id"),
        (ticket.get("threat_intel_result") or {}).get("incident_id"),
        (ticket.get("triage_result") or {}).get("incident_id"),
        (ticket.get("investigation_result") or {}).get("incident_id"),
        ticket.get("incident_id"),
    ]
    for value in candidates:
        text = str(value or "").strip()
        if text and text.lower() not in {"unknown", "untitled", "none", "null"}:
            return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)[:80]
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(ticket.get("ticket_id") or "INC-0001"))[:80]


def _ticket_report_response(ticket_id: str, report_key: str | None = None):
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return None, None, ({"success": False, "status": "Ticket not found"}, 404)
    incident_id = _ticket_report_incident_id(ticket)
    if report_key and report_key not in CORE_REPORT_KEYS:
        return ticket, incident_id, ({"success": False, "status": f"Unknown report section: {report_key}"}, 404)
    return ticket, incident_id, None


def _sync_ticket_report_manifest(ticket_id: str, manifest: dict[str, Any] | None, *, actor: str = "System", action: str = "report_manifest_synced") -> None:
    if not manifest:
        return
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return
    rr = dict(ticket.get("reporting_result") or {})
    rr["report_manifest"] = manifest
    rr["report_status"] = manifest.get("report_status") or rr.get("report_status")
    rr["status"] = rr.get("status") or rr.get("report_status") or "completed"
    try:
        CASEWORK.update_ticket(ticket_id, {"reporting_result": rr}, actor=actor, action=action, message="Synchronized SOC report review manifest with the selected ticket.")
    except Exception:
        pass


@app.route("/api/tickets/<ticket_id>/reports/<report_key>")
def api_ticket_report_section(ticket_id: str, report_key: str):
    ticket, incident_id, error = _ticket_report_response(ticket_id, report_key)
    if error:
        body, status_code = error
        return jsonify(body), status_code
    try:
        result = read_section(OUTPUTS_DIR, report_key, incident_id=incident_id)
        return jsonify({"success": True, "ticket_id": ticket_id, "incident_id": incident_id, **result})
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/tickets/<ticket_id>/reports/<report_key>/draft", methods=["POST"])
def api_ticket_report_save_draft(ticket_id: str, report_key: str):
    ticket, incident_id, error = _ticket_report_response(ticket_id, report_key)
    if error:
        body, status_code = error
        return jsonify(body), status_code
    body = request.get_json(silent=True) or {}
    try:
        blocks = body.get("blocks") if isinstance(body.get("blocks"), list) else None
        text = body.get("text") or ""
        result = save_section(OUTPUTS_DIR, report_key, text, analyst=body.get("analyst") or "SOC Analyst", incident_id=incident_id, blocks=blocks)
        _sync_ticket_report_manifest(ticket_id, result.get("manifest"), actor=body.get("analyst") or "SOC Analyst", action="report_draft_saved")
        CASEWORK.append_activity(ticket_id, body.get("analyst") or "SOC Analyst", "report_draft_saved", "completed", f"Draft saved for {report_key.replace('_', ' ')}.", {"report_key": report_key, "incident_id": incident_id})
        return jsonify({"success": True, "ticket_id": ticket_id, "incident_id": incident_id, **result})
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/tickets/<ticket_id>/reports/<report_key>/confirm", methods=["POST"])
def api_ticket_report_confirm(ticket_id: str, report_key: str):
    ticket, incident_id, error = _ticket_report_response(ticket_id, report_key)
    if error:
        body, status_code = error
        return jsonify(body), status_code
    body = request.get_json(silent=True) or {}
    try:
        # The dashboard normally saves the current structured draft first. If a caller
        # provides blocks/text directly here, persist them before confirmation.
        if isinstance(body.get("blocks"), list) or body.get("text"):
            save_section(OUTPUTS_DIR, report_key, body.get("text") or "", analyst=body.get("analyst") or "SOC Analyst", incident_id=incident_id, blocks=body.get("blocks") if isinstance(body.get("blocks"), list) else None)
        result = confirm_section(OUTPUTS_DIR, report_key, analyst=body.get("analyst") or "SOC Analyst", incident_id=incident_id)
        _sync_ticket_report_manifest(ticket_id, result.get("manifest"), actor=body.get("analyst") or "SOC Analyst", action="report_confirmed")
        CASEWORK.append_activity(ticket_id, body.get("analyst") or "SOC Analyst", "report_confirmed", "completed", f"Confirmed reviewed report section: {report_key.replace('_', ' ')}.", {"report_key": report_key, "incident_id": incident_id})
        return jsonify({"success": True, "ticket_id": ticket_id, "incident_id": incident_id, **result})
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/tickets/<ticket_id>/reports/<report_key>/export/<file_type>", methods=["GET", "POST"])
def api_ticket_report_export(ticket_id: str, report_key: str, file_type: str):
    ticket, incident_id, error = _ticket_report_response(ticket_id, report_key)
    if error:
        body, status_code = error
        return jsonify(body), status_code
    try:
        export_type = _normalise_export_type(file_type)
        if export_type == "docx":
            result = export_section_docx(OUTPUTS_DIR, report_key, incident_id=incident_id)
        elif export_type == "pdf":
            result = export_section_pdf(OUTPUTS_DIR, report_key, incident_id=incident_id)
        else:
            raise ValueError("Only DOCX/PDF report export is supported after SOC analyst confirmation.")
        path = Path(result.get("path") or "")
        _sync_ticket_report_manifest(ticket_id, result.get("manifest"), actor="SOC Analyst", action=f"report_export_{export_type}")
        CASEWORK.append_activity(ticket_id, "SOC Analyst", f"report_export_{export_type}", "completed", f"Exported confirmed report section: {report_key.replace('_', ' ')} as {export_type.upper()}.", {"report_key": report_key, "incident_id": incident_id, "path": str(path)})
        return send_file(path, as_attachment=True, download_name=path.name, mimetype=EXPORT_MIME_TYPES.get(export_type))
    except PermissionError as exc:
        return jsonify({"success": False, "status": "locked", "message": str(exc)}), 403
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/netwitness/alerts")
def api_netwitness_alerts():
    result = NetWitnessClient().fetch_alerts(_request_filters())
    for item in result.get("items") or []:
        CASEWORK.upsert_alert(item)
    return jsonify({**result, "items": CASEWORK.list_alerts(_request_filters())})


@app.route("/api/netwitness/alerts/<alert_id>")
def api_netwitness_alert(alert_id: str):
    cached = CASEWORK.get_alert(alert_id)
    if cached:
        return jsonify({"success": True, "alert": cached, "cached": True})
    result = NetWitnessClient().fetch_alert(alert_id)
    if result.get("alert"):
        alert = CASEWORK.upsert_alert(result["alert"])
        return jsonify({"success": True, "alert": alert, "cached": False, "netwitness": result})
    return jsonify(result), 404 if not result.get("success") else 200


@app.route("/api/netwitness/history")
def api_netwitness_history():
    result = NetWitnessClient().search_history(_request_filters())
    for item in result.get("items") or []:
        CASEWORK.upsert_alert(item)
    return jsonify({**result, "results": CASEWORK.list_alerts(_request_filters())})


@app.route("/api/netwitness/sync", methods=["POST"])
def api_netwitness_sync():
    result = NetWitnessClient().fetch_alerts(_request_filters())
    synced = []
    tickets = []
    tickets_created = 0
    tickets_reused = 0
    for item in result.get("items") or []:
        alert = CASEWORK.upsert_alert(item)
        synced.append(alert)
        before = CASEWORK.ticket_for_alert(alert["alert_id"])
        ticket = CASEWORK.create_ticket_from_alert(alert["alert_id"], owner="Unassigned", status="To Parse")
        if ticket:
            tickets.append(ticket)
            if before:
                tickets_reused += 1
            else:
                tickets_created += 1
    return jsonify({
        "success": result.get("success", False),
        "status": result.get("status"),
        "error": result.get("error"),
        "status_code": result.get("status_code"),
        "response_preview": result.get("response_preview"),
        "configured": result.get("configured"),
        "fallback": result.get("fallback", False),
        "synced": len(synced),
        "alerts": synced,
        "tickets_created": tickets_created,
        "tickets_reused": tickets_reused,
        "tickets": tickets,
    })



@app.route("/api/workflow/return-to-triage", methods=["POST"])
def api_workflow_return_to_triage():
    """Lecturer-required route: missing Investigation telemetry goes back to Triage.

    Triage is the only agent allowed to contact NetWitness, so this endpoint
    starts a Triage run rather than querying NetWitness directly here.
    """
    inv = read_data(OUTPUTS_DIR / "investigation_result.json", {}) or {}
    if str(inv.get("status") or "").lower() != "needs_more_data":
        return jsonify({"success": False, "status": "Investigation is not requesting more data", "display_status": "No throwback needed"}), 400
    write_json(OUTPUTS_DIR / "workflow_decision.json", {
        "status": "route_to_triage",
        "display_status": "Return to Triage",
        "workflow_decision": "throw_back_to_triage_for_netwitness",
        "next_agent": "triage_agent",
        "reason": "Investigation requires missing telemetry and only Triage may query NetWitness.",
        "missing_evidence": normalise_list(inv.get("missing_evidence") or inv.get("missing_fields")),
        "created_at": now_iso(),
    })
    payload, status = start_background_run("triage")
    payload["workflow_decision"] = "throw_back_to_triage_for_netwitness"
    payload["display_status"] = "Return to Triage"
    return jsonify(payload), status


@app.route("/api/workflow/continue-limited", methods=["POST"])
def api_workflow_continue_limited():
    body = request.get_json(silent=True) or {}
    reason = body.get("reason") or "Analyst chose to continue with current evidence and document limitations."
    analyst = body.get("analyst") or "SOC Analyst"
    triage = read_data(OUTPUTS_DIR / "triage_result.json", {}) or {}
    inv = read_data(OUTPUTS_DIR / "investigation_result.json", {}) or {}
    triage_status = str(triage.get("status") or "").lower()
    inv_status = str(inv.get("status") or "").lower()

    # If Triage is missing data, this option means continue to Investigation with limitations.
    if triage_status == "needs_more_data" and inv_status not in {"needs_more_data", "completed", "completed_limited"}:
        write_json(OUTPUTS_DIR / "workflow_override.json", {
            "status": "approved",
            "override_type": "continue_to_investigation_with_limited_triage",
            "reason": reason,
            "approved_by": analyst,
            "risk_acknowledged": True,
            "created_at": now_iso(),
        })
        run_payload, run_status = start_background_run("investigation")
        return jsonify({
            "success": True,
            "status": "continue_to_investigation_with_limitations",
            "display_status": "Continue to Investigation with limitations",
            "message": "Analyst approved continuing to Investigation with current Triage evidence.",
            "investigation_run": run_payload,
        }), 202 if run_status == 202 else 200

    # If Investigation is missing data, this option means mark Investigation completed_limited so Reporting can run.
    inv = update_investigation_to_limited(reason, analyst)
    write_json(OUTPUTS_DIR / "workflow_override.json", {
        "status": "approved",
        "override_type": "continue_to_reporting_with_limited_investigation",
        "reason": reason,
        "approved_by": analyst,
        "risk_acknowledged": True,
        "created_at": now_iso(),
    })
    return jsonify({
        "success": True,
        "status": "completed_limited",
        "display_status": display_status("completed_limited"),
        "message": "Investigation marked as completed with limitations. Reporting may continue.",
        "investigation": normalise_agent_data(inv, "investigation"),
    })


@app.route("/api/workflow/mark-insufficient", methods=["POST"])
def api_workflow_mark_insufficient():
    body = request.get_json(silent=True) or {}
    result = mark_case_insufficient(
        continue_workflow=False,
        analyst=body.get("analyst") or "SOC Analyst",
        notes=body.get("notes") or "Analyst marked the incident as insufficient evidence.",
    )
    result["display_status"] = display_status("insufficient_evidence")
    return jsonify(result)


@app.route("/api/workflow/mark-and-continue", methods=["POST"])
def api_workflow_mark_and_continue():
    body = request.get_json(silent=True) or {}
    reason = body.get("reason") or "Analyst marked evidence as insufficient but approved continuing to Reporting with limitations."
    analyst = body.get("analyst") or "SOC Analyst"
    inv = update_investigation_to_limited(reason, analyst)
    mark_result = mark_case_insufficient(continue_workflow=True, analyst=analyst, notes=reason)
    run_payload, run_status = start_background_run("reporting")
    return jsonify({
        "success": True,
        "status": "completed_limited",
        "display_status": display_status("completed_limited"),
        "message": "Case marked as insufficient evidence and Reporting Agent started with limitation notes.",
        "investigation": normalise_agent_data(inv, "investigation"),
        "case_marking": mark_result,
        "reporting_run": run_payload,
    }), 202 if run_status == 202 else 200


@app.route("/api/approval", methods=["POST"])
def api_approval():
    body = request.get_json(silent=True) or {}
    decision = body.get("decision", "pending")
    comments = body.get("comments", "")
    payload = {
        "agent": "SOC Analyst Approval",
        "status": decision,
        "decision": decision,
        "comments": comments,
        "analyst": body.get("analyst", "SOC Analyst"),
        "created_at": now_iso(),
    }
    write_json(OUTPUTS_DIR / "approval_result.json", payload)
    write_json(INPUTS_DIR / "approval_result.json", payload)
    ticket_id = body.get("ticket_id") or (read_data(SELECTED_TICKET_FILE, {}) or {}).get("ticket_id")
    if ticket_id and CASEWORK.get_ticket(ticket_id):
        CASEWORK.record_approval(ticket_id, decision, comments=comments, analyst=payload["analyst"])
    return jsonify({"success": True, "approval": payload})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    for file_name in ["triage_result.json", "investigation_result.json", "final_report.json", "final_report.txt", "approval_result.json", "workflow_result.json"]:
        for folder in [OUTPUTS_DIR, INPUTS_DIR]:
            p = folder / file_name
            if p.exists():
                p.unlink()
    return jsonify({"success": True, "status": "Generated outputs reset"})


def build_local_agent_answer(question: str, agent: str, context: dict[str, Any]) -> str:
    """Useful deterministic fallback so Ask Agent always works, even without OpenAI."""
    q = question.lower()
    case = context.get("case") or {}
    workflow = context.get("workflow") or {}
    triage = context.get("triage") or {}
    investigation = context.get("investigation") or {}
    reporting = context.get("reporting") or {}

    incident_id = case.get("incident_id") or "the current incident"
    severity = case.get("severity") or triage.get("severity") or "unknown"
    confidence = case.get("confidence") or triage.get("confidence") or "unknown"
    risk_score = case.get("risk_score") or triage.get("risk_score") or "unknown"
    next_step = workflow.get("next_step") or case.get("next_action") or "review the available agent outputs"
    next_action = case.get("next_action") or triage.get("next_action") or next_step

    if "explain" in q or "why" in q or "decision" in q or "critical" in q:
        return (
            f"{agent}: For {incident_id}, the current triage decision is based on severity={severity}, "
            f"confidence={confidence}, and risk_score={risk_score}. The recommended next action is: {next_action}. "
            "The dashboard is using the latest JSON outputs from the agents, so check the raw triage and investigation outputs if you need the exact evidence fields."
        )
    inv_status = str((investigation or {}).get("status") or "").lower()
    if inv_status == "needs_more_data" and ("next" in q or "what should" in q or "investigation" in q):
        missing = investigation.get("missing_fields") or []
        missing_txt = ", ".join(missing) if missing else "the requested missing telemetry"
        return (
            f"{agent}: Do not run Reporting yet. The Investigation Agent needs more data. "
            f"Per the workflow rule, throw the case back to the Triage Agent because only Triage may query NetWitness. "
            f"Missing telemetry: {missing_txt}. Next action: Run Triage Agent for NetWitness enrichment, then re-run Investigation."
        )
    if "next" in q or "what should" in q:
        return f"{agent}: The next workflow step is: {next_step}. Recommended action: {next_action}."
    if "summaris" in q or "summariz" in q or "summary" in q:
        parts = [
            f"Incident: {incident_id}",
            f"Title: {case.get('title') or 'Not available'}",
            f"Severity: {severity}",
            f"Confidence: {confidence}",
            f"Risk score: {risk_score}",
            f"Next step: {next_step}",
        ]
        if investigation:
            parts.append(f"Investigation status: {investigation.get('status') or investigation.get('classification') or 'available'}")
        if reporting:
            parts.append(f"Report status: {reporting.get('status') or reporting.get('report_status') or 'available'}")
        return f"{agent}:\n" + "\n".join(f"- {p}" for p in parts)
    if "error" in q or "failed" in q or "logs" in q:
        runs = []
        # The current context intentionally does not include full RUNS to keep prompt size smaller.
        return f"{agent}: Check the Live Activity Log and /api/runs for the latest adapter stdout/stderr. Current workflow state is: {next_step}."

    return (
        f"{agent}: I can answer using the current case context. For {incident_id}, severity is {severity}, "
        f"confidence is {confidence}, risk score is {risk_score}, and the next step is: {next_step}."
    )


ASK_AGENT_SYSTEM_PROMPT = """
You are the Ask Agent assistant inside an Agentic SOC Assistant dashboard.

Role:
You answer as the selected SOC agent, for example Triage Agent, Investigation Agent, Reporting Agent, or SOC Assistant.
You are supporting a human SOC analyst. You must not take actions automatically. You should explain, recommend, and give clear next options.

Response style:
Use plain text only. Do not use Markdown headings, Markdown tables, bullet syntax, code fences, or JSON in the answer.
Give an in-depth but readable response. Prefer short labelled sections such as:
Assessment
Evidence considered
Why this matters
Recommended next action
Risks or limitations
Follow-up options

Grounding rules:
Use only the case context JSON given by the backend.
If the evidence is missing, say exactly what is missing.
If a status is needs_more_data, display it as Need more data.
If Investigation needs more telemetry, say that the case should be returned to Triage because only Triage is allowed to query NetWitness.
Do not say to run Full Workflow. The SOC analyst must manually run Triage, Investigation, and Reporting stage by stage.
Do not invent NetWitness results, threat intelligence results, hostnames, usernames, or remediation actions.
If OpenAI is asked for a decision, frame it as a recommendation for the SOC analyst to approve or reject.

Required answer content:
1. Direct answer to the analyst's question.
2. Evidence from Triage, Investigation, Reporting, and workflow state where relevant.
3. Operational impact for the SOC analyst.
4. Recommended next manual action.
5. Limitations or assumptions.
6. Three to five follow-up questions the analyst may ask next, written as clickable-style option text.
""".strip()


def build_followup_options(question: str, agent: str, context: dict[str, Any]) -> list[str]:
    """Predict useful next questions for clickable follow-up chips."""
    q = (question or "").lower()
    workflow = context.get("workflow") or {}
    triage = context.get("triage") or {}
    investigation = context.get("investigation") or {}
    reporting = context.get("reporting") or {}
    inv_status = str(investigation.get("status") or "").lower()
    triage_status = str(triage.get("status") or "").lower()
    rep_status = str(reporting.get("status") or reporting.get("report_status") or "").lower()

    options: list[str] = []
    if inv_status == "needs_more_data":
        options.extend([
            "What exact telemetry is missing for Investigation?",
            "Why must this be returned to Triage instead of querying NetWitness directly?",
            "What should Triage query in NetWitness next?",
            "Can we continue with current evidence and document limitations?",
        ])
    elif "triage" in agent.lower() or triage_status:
        options.extend([
            "Explain the triage severity and confidence decision.",
            "What evidence supports the current triage decision?",
            "What should the SOC analyst review before approving the next step?",
        ])
    if "report" in agent.lower() or rep_status in {"missing_information_required", "completed_limited"}:
        options.extend([
            "What limitations should be included in the report?",
            "Is the report ready for analyst review?",
        ])
    if "error" in q or "connection" in q or "openai" in q or "netwitness" in q:
        options.extend([
            "How do I verify the API configuration?",
            "What does this connection error mean operationally?",
        ])
    options.extend([
        "What is the safest next manual step?",
        "Summarise the current case status for handover.",
    ])
    seen = set()
    deduped = []
    for option in options:
        key = option.lower().strip()
        if key not in seen:
            seen.add(key)
            deduped.append(option)
    return deduped[:5]


def clean_ask_answer_for_ui(text: str) -> str:
    """Keep Ask Agent output as readable plain text for the analyst."""
    text = markdown_to_plain_text(text or "")
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def align_answer_with_suggestions(answer: str, suggestions: list[str]) -> str:
    answer = clean_ask_answer_for_ui(answer)
    # Remove model-generated follow-up blocks so the visible options and clickable chips match exactly.
    answer = re.split(r"(?i)\n\s*(follow[- ]?up options|suggested follow[- ]?ups|you may ask next)\s*:?", answer)[0].strip()
    if suggestions:
        answer += "\n\nFollow-up options\n" + "\n".join(f"{idx + 1}. {s}" for idx, s in enumerate(suggestions))
    return answer.strip()


@app.route("/api/ask", methods=["POST"])
def api_ask():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()
    agent = body.get("agent") or "SOC Assistant"
    if not question:
        return jsonify({"success": False, "answer": "Enter a question first.", "suggestions": []}), 400
    ticket_id = body.get("ticket_id") or (read_data(SELECTED_TICKET_FILE, {}) or {}).get("ticket_id")
    selected_ticket = CASEWORK.get_ticket(ticket_id) if ticket_id else None
    context = {
        "case": case_summary(),
        "selected_ticket": ticket_workflow.decorate_ticket(selected_ticket) if selected_ticket else None,
        "workflow": workflow_state(),
        "triage": read_data(OUTPUTS_DIR / "triage_result.json", {}),
        "investigation": read_data(OUTPUTS_DIR / "investigation_result.json", {}),
        "reporting": read_data(OUTPUTS_DIR / "final_report.json", {}),
    }
    suggestions = build_followup_options(question, agent, context)
    local_answer = build_local_agent_answer(question, agent, context)
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or api_key.startswith("replace_"):
        return jsonify({
            "success": True,
            "provider": "local_context",
            "answer": align_answer_with_suggestions(local_answer, suggestions),
            "suggestions": suggestions,
        })
    try:
        model = os.getenv("OPENAI_MODEL", "gpt-5.4-mini")
        prompt = (
            f"Selected agent: {agent}\n"
            f"Analyst question: {question}\n\n"
            "Case context JSON:\n"
            f"{json.dumps(context, indent=2, ensure_ascii=False)[:14000]}\n\n"
            "Return a plain text answer only. Include useful follow-up option text at the bottom. "
            "Do not recommend Full Workflow. The analyst should manually run agent stages."
        )
        ai_text = invoke_openai_text(
            prompt,
            system=ASK_AGENT_SYSTEM_PROMPT,
            model=model,
            temperature=0.25,
            max_output_tokens=900,
            timeout=60,
        )
        answer = align_answer_with_suggestions(ai_text or local_answer, suggestions)
        return jsonify({
            "success": True,
            "provider": "openai",
            "model": model,
            "answer": answer,
            "suggestions": suggestions,
        })
    except Exception as exc:
        # Keep the chat usable even when OpenAI is temporarily unavailable.
        answer = (
            "I could not reach OpenAI, so I answered using local case context instead.\n\n"
            f"Reason: {exc}\n\n"
            f"{local_answer}"
        )
        return jsonify({
            "success": True,
            "provider": "local_context_after_openai_error",
            "answer": align_answer_with_suggestions(answer, suggestions),
            "suggestions": suggestions,
        })


@app.route("/api/integrations/status")
def api_integrations_status():
    netwitness = NetWitnessClient().status()
    postgres_configured = bool(os.getenv("POSTGRES_DSN") or os.getenv("REPORTING_POSTGRES_DSN") or os.getenv("POSTGRES_HOST"))
    postgres = {
        "configured": postgres_configured,
        "available": False,
        "status": "not_configured" if not postgres_configured else "unavailable",
    }
    try:
        if postgres_configured:
            postgres["available"] = bool(CASEWORK.healthcheck())
            postgres["status"] = "available" if postgres["available"] else "unavailable"
    except Exception as exc:
        postgres["error"] = str(exc)
    openai_sdk = {"installed": False, "responses_api_available": False, "version": None}
    try:
        import openai  # type: ignore
        from openai import OpenAI  # type: ignore
        openai_sdk["installed"] = True
        openai_sdk["version"] = getattr(openai, "__version__", "unknown")
        try:
            openai_sdk["responses_api_available"] = hasattr(OpenAI(api_key="sk-placeholder"), "responses")
        except Exception:
            openai_sdk["responses_api_available"] = True
    except Exception as exc:
        openai_sdk["error"] = str(exc)
    return jsonify({
        "openai": {
            "configured": bool(os.getenv("OPENAI_API_KEY")),
            "model": os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
            "triage_model": os.getenv("TRIAGE_LLM_MODEL", os.getenv("OPENAI_MODEL", "gpt-5.4-mini")),
            "reporting_model": os.getenv("REPORTING_LLM_MODEL", os.getenv("OPENAI_MODEL", "gpt-5.4-mini")),
            "investigation_model": os.getenv("INVESTIGATION_OPENAI_MODEL", os.getenv("OPENAI_MODEL", "gpt-5.4-mini")),
            "triage_uses_responses_api": os.getenv("TRIAGE_USE_RESPONSES_API", "true"),
            "triage_require_openai": os.getenv("TRIAGE_REQUIRE_OPENAI", "true"),
            "investigation_use_llm": os.getenv("INVESTIGATION_USE_LLM", "true"),
            "investigation_require_openai": os.getenv("INVESTIGATION_REQUIRE_OPENAI", "true"),
            "fallback_allowed": os.getenv("ALLOW_AGENT_FALLBACK", "false"),
            "sdk": openai_sdk,
        },
        "netwitness": netwitness,
        "virustotal": {"configured": bool(os.getenv("VT_API_KEY"))},
        "abuseipdb": {"configured": bool(os.getenv("ABUSEIPDB_API_KEY"))},
        "otx": {"configured": bool(os.getenv("OTX_API_KEY"))},
        "postgres": postgres,
    })


@app.route("/api/integrations/openai-test", methods=["POST"])
def api_openai_test():
    body = request.get_json(silent=True) or {}
    model = body.get("model") or os.getenv("OPENAI_MODEL", "gpt-5.4-mini")
    try:
        text = invoke_openai_text(
            "Reply with exactly: OPENAI_OK",
            system="You are a connectivity test endpoint.",
            model=model,
            max_output_tokens=20,
            timeout=45,
        )
        return jsonify({"success": True, "provider": "openai_responses", "model": model, "text": text})
    except Exception as exc:
        return jsonify({"success": False, "provider": "openai_responses", "model": model, "error": str(exc)}), 502


@app.route("/api/netwitness/test", methods=["POST"])
def api_netwitness_test():
    client = NetWitnessClient()
    result = client.query("/rest/api/incidents", {"pageSize": 1, "pageNumber": 0})
    status = 200 if result.get("success") else 400 if not result.get("configured", True) else result.get("status_code", 500)
    return jsonify({**result, "client_status": client.status()}), status


@app.route("/api/netwitness/incidents")
def api_netwitness_incidents():
    client = NetWitnessClient()
    page_size = int(request.args.get("pageSize", "50"))
    result = client.query("/rest/api/incidents", {"pageSize": page_size, "pageNumber": 0})
    if result.get("success"):
        items = result.get("items") or []
        write_json(RUNTIME_DIR / "netwitness_incidents_cache.json", items)
        return jsonify({"success": True, "count": len(items), "items": items, "raw": result.get("raw"), "client_status": client.status()})
    status = 400 if not result.get("configured", True) else result.get("status_code", 500)
    return jsonify({**result, "client_status": client.status()}), status




# -------------------- Editable analyst review for agent outputs --------------------

def current_agent_payload(agent_key: str) -> dict[str, Any]:
    files = {
        "parsing": OUTPUTS_DIR / "parser_result.json",
        "parsing_normalisation": OUTPUTS_DIR / "parser_result.json",
        "triage": OUTPUTS_DIR / "triage_result.json",
        "threat_intel": OUTPUTS_DIR / "threat_intel_result.json",
        "threat_intelligence": OUTPUTS_DIR / "threat_intel_result.json",
        "triage_approval": OUTPUTS_DIR / "approval_result.json",
        "approval": OUTPUTS_DIR / "approval_result.json",
        "investigation": OUTPUTS_DIR / "investigation_result.json",
        "investigation_approval": OUTPUTS_DIR / "investigation_approval_result.json",
        "reporting": OUTPUTS_DIR / "final_report.json",
        "soc_review": OUTPUTS_DIR / "soc_review_result.json",
        "soc_analyst_review": OUTPUTS_DIR / "soc_review_result.json",
    }
    path = files.get(agent_key)
    if not path:
        return {}
    data = read_data(path, {}) or {}
    return normalise_agent_data(data, agent_key)


def agent_review_dir(agent_key: str, incident_id: str | None = None) -> Path:
    incident_id = incident_id or current_incident_id()
    return OUTPUTS_DIR / incident_id / "analyst_edits"


def agent_review_paths(agent_key: str, incident_id: str | None = None) -> tuple[Path, Path]:
    base = agent_review_dir(agent_key, incident_id)
    return base / f"{agent_key}_output_review.txt", base / f"{agent_key}_review_meta.json"


def _lines(title: str, body: Any) -> str:
    text = markdown_to_plain_text(clean_display_text(body, max_len=4000) or str(body or "")).strip()
    if not text:
        return ""
    return f"{title}\n\n{text}\n"


def _list_text(title: str, items: Any) -> str:
    values = normalise_list(items)
    if not values:
        return ""
    return f"{title}\n\n" + "\n".join(f"- {markdown_to_plain_text(v)}" for v in values) + "\n"


def build_agent_analyst_text(agent_key: str, payload: dict[str, Any] | None = None) -> str:
    payload = payload or current_agent_payload(agent_key)
    if not payload:
        return "No output generated yet. Run the selected agent to generate analyst-readable output."
    status = display_status(payload.get("status") or payload.get("report_status") or "not_ready")
    summary = payload.get("analyst_summary") or payload.get("summary") or payload.get("executive_summary") or payload.get("reason") or payload.get("message")
    severity = first_value(payload, "severity", "priority", default="Unknown")
    confidence = first_value(payload, "confidence", "confidence_level", default="Unknown")
    risk = first_value(payload, "risk_score", "incident_risk_score", "enrichment_risk_score", default="Unknown")
    next_action = first_value(payload, "recommended_next_action", "next_action", "workflow_next_action", "workflow_decision", default="Review output and choose the next manual action.")
    observed = normalise_list(payload.get("observed_evidence")) + normalise_list((payload.get("available_evidence") or {}).get("iocs") if isinstance(payload.get("available_evidence"), dict) else None) + normalise_list(payload.get("iocs")) + normalise_list(payload.get("ioc_summary"))
    findings = payload.get("findings") or payload.get("key_findings") or payload.get("technical_findings") or payload.get("analysis_findings")
    missing = payload.get("missing_evidence") or payload.get("missing_fields") or payload.get("required_missing_fields") or payload.get("missing_report_fields")
    if agent_key == "triage":
        nw = payload.get("netwitness_evidence") if isinstance(payload.get("netwitness_evidence"), dict) else {}
        nw_items = [
            f"NetWitness Owner: {display_status(payload.get('netwitness_owner_agent') or 'triage_agent')}",
            f"NetWitness Status: {display_status(nw.get('status'))}" if nw.get("status") else "",
            f"Records Found: {nw.get('records_count')}" if nw.get("records_count") is not None else "",
            f"Error: {clean_display_text(nw.get('error'), max_len=600)}" if nw.get("error") else "",
        ]
        parts = [
            _lines("TRIAGE SUMMARY", summary or f"Triage reviewed the case context and classified the incident as {severity} with {confidence} confidence."),
            _lines("TRIAGE DECISION", f"Severity: {severity}\nConfidence: {confidence}\nRisk Score: {risk}\nNext Action: {next_action}"),
            _list_text("KEY EVIDENCE", observed),
            _list_text("KEY FINDINGS", findings),
            _list_text("MISSING INFORMATION", missing),
            _lines("NETWITNESS ENRICHMENT", "\n".join(x for x in nw_items if x) or "NetWitness enrichment is owned by the Triage Agent. No additional NetWitness result is available in this output."),
            _lines("RECOMMENDED NEXT ACTION", next_action),
            _lines("ANALYST NOTES", "Edit this section if the SOC analyst wants to clarify the triage decision, evidence limitations, or approval rationale."),
        ]
        return "\n".join(p for p in parts if p).strip()
    if agent_key == "investigation":
        case_type = first_value(payload, "case_type", "selected_case_type", default="Unknown")
        playbook = first_value(payload, "selected_playbook", "playbook", default="Not specified")
        classification = first_value(payload, "classification", default=status)
        needs_more = str(payload.get("status") or "").lower() == "needs_more_data"
        parts = [
            _lines("INVESTIGATION SUMMARY", summary or ("The Investigation Agent could not fully complete the selected playbook because required telemetry is missing." if needs_more else "The Investigation Agent reviewed the available evidence and produced an investigation decision.")),
            _lines("INVESTIGATION DECISION", f"Status: {status}\nCase Type: {case_type}\nClassification: {classification}\nSeverity: {severity}\nConfidence: {confidence}\nRisk Score: {risk}\nSelected Playbook: {playbook}"),
            _list_text("AVAILABLE EVIDENCE", observed or payload.get("available_evidence")),
            _list_text("KEY FINDINGS", findings),
            _list_text("MISSING INFORMATION", missing),
            _lines("WORKFLOW OPTIONS", "The workflow should not stop. The SOC analyst can return the case to Triage for NetWitness enrichment, continue with current evidence, mark the case as insufficient evidence, or mark and continue to Reporting with limitations." if needs_more else "Investigation output is ready for Reporting or analyst review."),
            _lines("RECOMMENDED NEXT ACTION", next_action),
            _lines("ANALYST NOTES", "Edit this section if the SOC analyst wants to document investigation judgement, evidence limitations, or manual pivots performed."),
        ]
        return "\n".join(p for p in parts if p).strip()
    if agent_key == "reporting":
        sections = ["Executive Summary", "Technical Findings", "SOC Triage Review", "SOC Analyst Review", "Final Incident Report"]
        manifest = payload.get("report_manifest") if isinstance(payload.get("report_manifest"), dict) else load_manifest(OUTPUTS_DIR)
        if manifest.get("sections"):
            sections = [v.get("title") or k for k, v in manifest.get("sections", {}).items()]
        parts = [
            _lines("REPORTING SUMMARY", summary or "The Reporting Agent generated editable report sections for SOC analyst review."),
            _lines("REPORTING STATUS", f"Report Status: {display_status(payload.get('report_status') or payload.get('status') or 'not_ready')}\nValidation / Context Status: {display_status(payload.get('validation_status') or payload.get('data_consistency_status') or 'unknown')}") ,
            _list_text("REPORT SECTIONS GENERATED", sections),
            _list_text("MISSING INFORMATION", missing),
            _lines("RECOMMENDED NEXT ACTION", "Open the Reports page, review and edit each generated section, save the draft, confirm the report, then export Word or PDF."),
            _lines("ANALYST NOTES", "Edit this section if the SOC analyst wants to add reporting review notes before confirmation and export."),
        ]
        return "\n".join(p for p in parts if p).strip()
    return _lines("AGENT SUMMARY", summary or "Agent output is available.").strip()


def load_agent_review(agent_key: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    text_path, meta_path = agent_review_paths(agent_key)
    agent_text = build_agent_analyst_text(agent_key, payload)
    if text_path.exists():
        text = text_path.read_text(encoding="utf-8", errors="ignore")
        saved = True
    else:
        text = agent_text
        saved = False
    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    return {
        "agent": agent_key,
        "text": text,
        "agent_generated_text": agent_text,
        "saved": saved,
        "editable": True,
        "review_status": meta.get("review_status") or ("draft_saved" if saved else "draft_review"),
        "last_saved_at": meta.get("last_saved_at"),
        "last_saved_by": meta.get("last_saved_by"),
        "confirmed_at": meta.get("confirmed_at"),
        "confirmed_by": meta.get("confirmed_by"),
        "path": str(text_path.relative_to(PROJECT_ROOT)) if text_path.exists() else str(text_path.relative_to(PROJECT_ROOT)),
    }


def attach_agent_review(agent_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict) and payload.get("ready") and isinstance(payload.get("data"), dict):
        payload["data"]["analyst_review"] = load_agent_review(agent_key, payload.get("data"))
    return payload


@app.route("/api/agent-output/<agent_key>/analyst-view")
def api_agent_output_analyst_view(agent_key: str):
    if agent_key not in {"triage", "investigation", "reporting"}:
        return jsonify({"success": False, "status": "Unknown agent"}), 404
    payload = current_agent_payload(agent_key)
    return jsonify({"success": True, "agent": agent_key, "review": load_agent_review(agent_key, payload), "payload": payload})


@app.route("/api/agent-output/<agent_key>/save-edit", methods=["POST"])
def api_agent_output_save_edit(agent_key: str):
    if agent_key not in {"triage", "investigation", "reporting"}:
        return jsonify({"success": False, "status": "Unknown agent"}), 404
    body = request.get_json(silent=True) or {}
    text = markdown_to_plain_text(body.get("text") or "")
    text_path, meta_path = agent_review_paths(agent_key)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.write_text(text, encoding="utf-8")
    meta = {
        "agent": agent_key,
        "review_status": "draft_saved",
        "last_saved_at": now_iso(),
        "last_saved_by": body.get("analyst") or "SOC Analyst",
        "confirmed_at": None,
        "confirmed_by": None,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return jsonify({"success": True, "review": load_agent_review(agent_key, current_agent_payload(agent_key)), "status": "Draft saved"})


@app.route("/api/agent-output/<agent_key>/reset-edit", methods=["POST"])
def api_agent_output_reset_edit(agent_key: str):
    if agent_key not in {"triage", "investigation", "reporting"}:
        return jsonify({"success": False, "status": "Unknown agent"}), 404
    text_path, meta_path = agent_review_paths(agent_key)
    if text_path.exists():
        text_path.unlink()
    if meta_path.exists():
        meta_path.unlink()
    return jsonify({"success": True, "review": load_agent_review(agent_key, current_agent_payload(agent_key)), "status": "Reset to agent version"})


@app.route("/api/agent-output/<agent_key>/confirm-review", methods=["POST"])
def api_agent_output_confirm_review(agent_key: str):
    if agent_key not in {"triage", "investigation", "reporting"}:
        return jsonify({"success": False, "status": "Unknown agent"}), 404
    body = request.get_json(silent=True) or {}
    text = markdown_to_plain_text(body.get("text") or build_agent_analyst_text(agent_key, current_agent_payload(agent_key)))
    text_path, meta_path = agent_review_paths(agent_key)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.write_text(text, encoding="utf-8")
    meta = {
        "agent": agent_key,
        "review_status": "confirmed_by_analyst",
        "last_saved_at": now_iso(),
        "last_saved_by": body.get("analyst") or "SOC Analyst",
        "confirmed_at": now_iso(),
        "confirmed_by": body.get("analyst") or "SOC Analyst",
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return jsonify({"success": True, "review": load_agent_review(agent_key, current_agent_payload(agent_key)), "status": "Confirmed by analyst"})


# -------------------- Editable report review and export routes --------------------

@app.route("/api/reports")
def api_reports_list():
    try:
        return jsonify(list_reports(OUTPUTS_DIR))
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/reports/manifest")
def api_reports_manifest():
    try:
        result = list_reports(OUTPUTS_DIR)
        return jsonify({"success": True, "manifest": result["manifest"], "sections": result["reports"], "section_order": result["section_order"], "draft_reports": result["draft_reports"], "confirmed_reports": result["confirmed_reports"]})
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/reports/section/<section_key>")
def api_reports_section(section_key: str):
    try:
        result = read_section(OUTPUTS_DIR, section_key)
        return jsonify({"success": True, "manifest": result["manifest"], "section": result["section"], "text": result["text"], "blocks": result.get("blocks", []), "source": result.get("source"), "block_source": result.get("block_source")})
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/reports/<section_key>")
def api_reports_section_alias(section_key: str):
    return api_reports_section(section_key)


@app.route("/api/reports/<section_key>/drafts")
def api_reports_section_drafts(section_key: str):
    try:
        return jsonify(list_section_drafts(OUTPUTS_DIR, section_key))
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/reports/section/<section_key>/save", methods=["POST"])
def api_reports_section_save(section_key: str):
    body = request.get_json(silent=True) or {}
    try:
        result = save_section(OUTPUTS_DIR, section_key, body.get("text", ""), analyst=body.get("analyst") or "SOC Analyst", blocks=body.get("blocks") if isinstance(body.get("blocks"), list) else None)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/<section_key>/save-draft", methods=["POST"])
def api_reports_section_save_alias(section_key: str):
    return api_reports_section_save(section_key)


@app.route("/api/reports/section/<section_key>/improve", methods=["POST"])
def api_reports_section_improve(section_key: str):
    body = request.get_json(silent=True) or {}
    current_text = str(body.get("text") or "")
    instruction = str(body.get("instruction") or "Improve clarity while preserving incident facts and evidence limitations.")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or api_key.startswith("replace_"):
        improved = (current_text.strip() + "\n\nAnalyst editing note: OpenAI is not configured, so no AI rewrite was applied. Review this section manually and ensure all limitations are clearly stated.").strip()
        return jsonify({"success": True, "provider": "local_no_openai", "text": improved, "message": "OpenAI not configured. Manual review note appended."})
    try:
        model = os.getenv("OPENAI_MODEL", "gpt-5.4-mini")
        prompt = (
            "You are improving one editable SOC incident report section.\n"
            "Rules: plain text only, no Markdown, no invented facts, keep limitations explicit, preserve SOC analyst tone.\n"
            f"Report section: {section_key}\n"
            f"Instruction: {instruction}\n\n"
            f"Current text:\n{current_text[:12000]}"
        )
        ai_text = invoke_openai_text(
            prompt,
            system="Rewrite SOC report sections as plain text. Do not invent evidence.",
            model=model,
            temperature=0.2,
            max_output_tokens=1200,
            timeout=60,
        )
        improved = markdown_to_plain_text(ai_text or current_text)
        return jsonify({"success": True, "provider": "openai", "model": model, "text": improved, "message": "AI improvement applied. Review before saving."})
    except Exception as exc:
        improved = (current_text.strip() + f"\n\nAnalyst editing note: OpenAI improvement failed ({exc}). Review this section manually.").strip()
        return jsonify({"success": True, "provider": "local_after_openai_error", "text": improved, "error": str(exc), "message": "AI unavailable. Manual review note appended."})


@app.route("/api/reports/<section_key>/improve", methods=["POST"])
def api_reports_section_improve_alias(section_key: str):
    return api_reports_section_improve(section_key)


@app.route("/api/reports/section/<section_key>/confirm", methods=["POST"])
def api_reports_section_confirm(section_key: str):
    body = request.get_json(silent=True) or {}
    try:
        result = confirm_section(OUTPUTS_DIR, section_key, analyst=body.get("analyst") or "SOC Analyst")
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/<section_key>/confirm", methods=["POST"])
def api_reports_section_confirm_alias(section_key: str):
    return api_reports_section_confirm(section_key)


@app.route("/api/reports/confirm", methods=["POST"])
def api_reports_confirm():
    body = request.get_json(silent=True) or {}
    try:
        result = confirm_report(OUTPUTS_DIR, analyst=body.get("analyst") or "SOC Analyst")
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/<section_key>/export/docx", methods=["POST"])
def api_reports_section_export_docx(section_key: str):
    try:
        return jsonify(export_section_docx(OUTPUTS_DIR, section_key))
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/<section_key>/export/pdf", methods=["POST"])
def api_reports_section_export_pdf(section_key: str):
    try:
        return jsonify(export_section_pdf(OUTPUTS_DIR, section_key))
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/<section_key>/download/<file_type>")
def api_reports_section_download(section_key: str, file_type: str):
    try:
        return send_file(download_path(OUTPUTS_DIR, section_key, file_type), as_attachment=True)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404


@app.route("/api/reports/export/docx", methods=["POST"])
def api_reports_export_docx():
    try:
        result = export_docx(OUTPUTS_DIR)
        result["download_url"] = "/api/reports/download/docx"
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/export/pdf", methods=["POST"])
def api_reports_export_pdf():
    try:
        result = export_pdf(OUTPUTS_DIR)
        result["download_url"] = "/api/reports/download/pdf"
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/reports/download/<file_type>")
def api_reports_download(file_type: str):
    try:
        return send_file(download_path(OUTPUTS_DIR, None, file_type), as_attachment=True)
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 404



# -------------------- Template-based agent/report document export routes --------------------

EXPORT_MIME_TYPES = {
    "json": "application/json",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "word": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}


def _normalise_export_type(file_type: str) -> str:
    value = str(file_type or "").lower().strip()
    if value in {"word", "doc", "docx"}:
        return "docx"
    if value in {"json", "pdf"}:
        return value
    raise ValueError(f"Unsupported file type: {file_type}")



@app.route("/api/tickets/<ticket_id>/exports/status")
def api_ticket_export_status(ticket_id: str):
    ticket = CASEWORK.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"success": False, "status": "Ticket not found"}), 404
    return jsonify({"success": True, "exports": collect_ticket_export_status(OUTPUTS_DIR, ticket_id)})


@app.route("/api/tickets/<ticket_id>/exports/<agent_key>/<file_type>")
def api_ticket_agent_template_export(ticket_id: str, agent_key: str, file_type: str):
    try:
        export_type = _normalise_export_type(file_type)
        ticket = CASEWORK.get_ticket(ticket_id) or {}
        path = generate_agent_export(PROJECT_ROOT, OUTPUTS_DIR, ticket, agent_key, export_type)
        return send_file(path, as_attachment=True, download_name=path.name, mimetype=EXPORT_MIME_TYPES.get(export_type))
    except Exception as exc:
        return jsonify({"success": False, "status": str(exc)}), 400


@app.route("/api/tickets/<ticket_id>/exports/reporting/<report_key>/<file_type>")
def api_ticket_reporting_template_export(ticket_id: str, report_key: str, file_type: str):
    # Final Reporting exports must use the SOC analyst-confirmed editable report,
    # not the raw generated template output. This backend gate prevents direct URL
    # downloads before review/confirmation.
    return api_ticket_report_export(ticket_id, report_key, file_type)

install_api_guards(app)

@app.errorhandler(404)
def not_found(_error):
    return jsonify({"success": False, "status": "Not found"}), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("DASHBOARD_PORT", "5001")), debug=False, use_reloader=False, threaded=True)
