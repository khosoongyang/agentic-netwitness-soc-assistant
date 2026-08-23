# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: Python standard runtime.
# =============================================================================
# File: soc_reporting_agent/services/__init__.py
# Purpose: This module backend services shared by dashboard adapters and Flask routes.
# Main functionality: package initialisation and import-time configuration.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis parsing and reporting service component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: Python standard runtime; no direct imported dependency.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: package initialisation and import-time configuration, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""Backend services shared by dashboard adapters and Flask routes."""
