"""
[FYP-FILE] reporting/__init__.py
# File: soc_reporting_agent/reporting/__init__.py
# Purpose: This module implements report generation and export behaviour for init.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: Python standard runtime.
# Key evaluator search terms: __init__, [FYP-FUNCTION].
Package marker for the `reporting` package (soc_reporting_agent/reporting/).

[FYP-SECTION] Package overview
This package implements the Reporting Agent's report-generation pipeline:
input loading (input_loader.py) -> context normalisation (context_builder.py,
schema_normaliser.py) -> knowledge-base retrieval (rag_context.py) ->
template rendering (report_renderer.py, structured_report.py,
compact_renderer.py) -> status/quality scoring (status_display.py) ->
post-generation validation (report_validator.py) -> persistence
(output_writer.py). The pipeline's [FYP-ENTRY-POINT] is
agents/reporting_agent.py:main(), which is OUTSIDE this file set and is
not modified here.

Reporting Agent package.
"""
