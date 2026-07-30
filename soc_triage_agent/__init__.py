# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: soc_triage_agent.
# =============================================================================
# File: soc_triage_agent/__init__.py
# Purpose: This module soc_triage_agent package ======================== The implementation lives in soc_triage_agent.py inside this folder.
# Main functionality: package initialisation and import-time configuration.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis triage component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: soc_triage_agent.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: package initialisation and import-time configuration, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
soc_triage_agent package
========================
The implementation lives in soc_triage_agent.py inside this folder.
This re-export keeps app.py's original import working unchanged:

    from soc_triage_agent import CiscoLLMConfig, soc_triage_chat_respond, ...
"""

from .soc_triage_agent import (
    CiscoLLMConfig,
    build_llm,
    TriageAgent,
    soc_triage_chat_respond,
    deep_triage_supplement,
    _TRIAGE_TRIGGER,
    render_triage_trace,
    format_ticket_display,
)

__all__ = [
    "CiscoLLMConfig",
    "build_llm",
    "TriageAgent",
    "soc_triage_chat_respond",
    "deep_triage_supplement",
    "_TRIAGE_TRIGGER",
    "render_triage_trace",
    "format_ticket_display",
]
