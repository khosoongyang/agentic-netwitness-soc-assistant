"""Case-scoped tools for Ask Aegis chatbot to inspect evidence and execute workflow actions."""

from __future__ import annotations

import json
from typing import Any

from workflow import commands
from workflow import state_store as wss
from .case_service import _get_case_row


def get_raw_incident_data(case_id: str) -> dict[str, Any]:
    """Retrieve the full raw incident / alert JSON for the current case.
    
    Use this tool when the analyst asks to inspect the original alert, NetWitness
    metadata, raw log fields, payload, or full unparsed alert properties.
    """
    try:
        row = _get_case_row(case_id)
        raw_json_str = row.get("raw_json") or "{}"
        data = json.loads(raw_json_str)
        return {
            "case_id": case_id,
            "incident_id": row.get("id", case_id),
            "title": row.get("title", ""),
            "severity": row.get("severity", ""),
            "status": row.get("status", ""),
            "created_at": row.get("created_at", ""),
            "raw_incident": data,
        }
    except Exception as exc:
        return {"case_id": case_id, "error": f"Failed to retrieve raw incident: {exc}"}


def get_stage_details(case_id: str, stage: str) -> dict[str, Any]:
    """Retrieve detailed execution results, traces, and reasoning for a specific stage.
    
    stage must be one of: 'parsing', 'triage', 'threat_intel', 'investigation', 'reporting'.
    Use this tool to explain HOW a specific agent made its decision, inspect risk rationales,
    examine IOC checklists, evidence gaps, or intermediate AI thinking.
    """
    stage_key = stage.lower().strip()
    state = wss.get_state(case_id)
    if not state:
        return {"case_id": case_id, "error": f"No workflow state found for case {case_id}"}
    
    result_col_map = {
        "parsing": "parsing_result_json",
        "triage": "triage_result_json",
        "threat_intel": "threat_intel_result_json",
        "threat_intelligence": "threat_intel_result_json",
        "investigation": "investigation_result_json",
        "reporting": "reporting_result_json",
    }
    
    col = result_col_map.get(stage_key)
    if not col:
        return {
            "case_id": case_id,
            "error": f"Invalid stage '{stage}'. Must be one of: parsing, triage, threat_intel, investigation, reporting.",
        }
    
    raw_res = state.get(col)
    if not raw_res:
        return {
            "case_id": case_id,
            "stage": stage_key,
            "status": state.get(f"{stage_key}_status", "Not Started"),
            "data": None,
            "message": f"Stage '{stage_key}' has not produced results yet or is not completed.",
        }
    
    try:
        parsed_data = json.loads(raw_res) if isinstance(raw_res, str) else raw_res
    except Exception:
        parsed_data = str(raw_res)
        
    return {
        "case_id": case_id,
        "stage": stage_key,
        "status": state.get(f"{stage_key}_status", "Completed"),
        "attempt": state.get(f"{stage_key}_attempt", 1),
        "stage_result": parsed_data,
    }


def get_threat_intel_iocs(case_id: str) -> dict[str, Any]:
    """Retrieve detailed Threat Intelligence enrichment and reputation lookups for the case IOCs.
    
    Use this tool when explaining why an indicator is considered malicious or benign according to
    VirusTotal, AlienVault OTX, AbuseIPDB, or local threat databases.
    """
    state = wss.get_state(case_id)
    if not state:
        return {"case_id": case_id, "error": f"No workflow state found for case {case_id}"}
    
    ti_json = state.get("threat_intel_result_json")
    if not ti_json:
        return {
            "case_id": case_id,
            "message": "Threat Intelligence Enrichment has not run or produced results for this case yet.",
        }
    
    try:
        ti_data = json.loads(ti_json) if isinstance(ti_json, str) else ti_json
    except Exception as exc:
        return {"case_id": case_id, "error": f"Failed to parse Threat Intel data: {exc}"}
        
    return {
        "case_id": case_id,
        "enrichment_risk_level": ti_data.get("enrichment_risk_level"),
        "enrichment_risk_score": ti_data.get("enrichment_risk_score"),
        "enrichment_risk_reasons": ti_data.get("enrichment_risk_reasons", []),
        "threat_intelligence": ti_data.get("threat_intelligence", {}),
    }


def rerun_workflow_stage(case_id: str, stage: str) -> dict[str, Any]:
    """Rerun an existing workflow stage for the current case.
    
    CRITICAL: ONLY invoke this tool when the user EXPLICITLY commands to rerun, restart, or re-execute
    a stage (e.g. 'rerun triage', 're-run threat intel', 'restart investigation').
    Do NOT invoke this tool if the user is merely asking a question or asking for an explanation!
    
    stage must be one of: 'parsing', 'triage', 'threat_intel', 'investigation', 'reporting'.
    """
    try:
        norm_stage = commands.normalise_stage(stage)
    except Exception as exc:
        return {"case_id": case_id, "error": str(exc), "success": False}
        
    try:
        res = commands.rerun_stage(case_id, norm_stage)
        return {
            "case_id": case_id,
            "stage": norm_stage,
            "success": True,
            "message": f"Successfully initiated rerun for stage '{norm_stage}'.",
            "details": res,
        }
    except commands.WorkflowCommandError as exc:
        return {
            "case_id": case_id,
            "stage": norm_stage,
            "success": False,
            "error_code": exc.code,
            "error": exc.message,
        }
    except Exception as exc:
        return {
            "case_id": case_id,
            "stage": norm_stage,
            "success": False,
            "error": str(exc),
        }
