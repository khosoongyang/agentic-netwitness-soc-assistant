# File: agents/reporting/backend/__init__.py
# Purpose: Package marker for agents/reporting/backend/, which holds the
# Reporting subsystem's filesystem/ticket-context bridge:
# reporting_context_resolver.py (resolves and materialises the investigation/
# approval context Reporting needs) and reporting_eligibility.py (the
# is_investigation_usable_for_reporting decision it relies on). This package
# is subprocess-adjacent, not a Flask API/service layer -- it is imported by
# adapters/run_reporting.py before the Reporting agent runs.
"""Backend package for the SOC Reporting subsystem's context bridge."""
