"""Deterministic investigation-analysis tools.

Each module here is a standalone, deterministic (no LLM, no network of its
own) skill: Diamond Model construction, IOC correlation, unified triage/
investigation verdict aggregation, asset criticality assessment, mitigation
coverage mapping, compliance evidence, and entity-graph/MITRE-tactic
extraction. They cross-reference each other (e.g. diamond_model.py calls
into asset_criticality.py and ioc_correlation.py) and are orchestrated
together by agents/investigation/skills_sidecar.py, which bridges their
combined output into the reporting agent's handoff. Also consumed directly
by workflow/engine.py (ioc_correlation), backend/services/case_view_service.py
(incident_map, tactic_inference, triage_verdict), and scripts/eval_harness.py.
"""
