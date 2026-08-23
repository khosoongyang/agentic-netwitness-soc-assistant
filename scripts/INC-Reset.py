# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: glob, os, shutil, sqlite3.
# =============================================================================
# File: INC-Reset.py
# Purpose: This module provides a command-line reset action for the named incident and its persisted workflow state.
# Main functionality: package initialisation and import-time configuration.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis SOC analysis support component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: glob, os, shutil, sqlite3.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: package initialisation and import-time configuration, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

import sqlite3, os, shutil, glob

inc_id = "INC-51772"  # Target incident ID
inc_num = inc_id.replace("INC-", "")

# 1. Reset workflow state in soc_incidents.db
with sqlite3.connect("soc_db/soc_incidents.db") as con:
    con.execute("""
        UPDATE incidents SET 
            workflow_status=NULL, approval_stage=NULL, run_id=NULL,
            triage_status=NULL, triage_result_json=NULL,
            parsing_status=NULL, parsing_result_json=NULL,
            threat_intel_status=NULL, threat_intel_result_json=NULL,
            investigation_status=NULL, investigation_result_json=NULL,
            reporting_status=NULL, reporting_result_json=NULL,
            approved_by=NULL, approved_at=NULL, approval_comments=NULL,
            worker_id=NULL, worker_stage=NULL, last_error=NULL
        WHERE id=?
    """, (inc_id,))
    con.execute("DELETE FROM workflow_approvals WHERE incident_id=?", (inc_id,))
    con.execute("DELETE FROM workflow_activity WHERE incident_id=?", (inc_id,))
    con.execute("DELETE FROM report_edits WHERE incident_id=?", (inc_id,))

# 2. Clear records from soc_pipeline.db
if os.path.exists("soc_db/soc_pipeline.db"):
    with sqlite3.connect("soc_db/soc_pipeline.db") as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tables:
            try:
                con.execute(f"DELETE FROM {t} WHERE incident_id=?", (inc_id,))
            except Exception:
                pass

# 3. Clear records from soc_tickets.db
if os.path.exists("soc_db/soc_tickets.db"):
    with sqlite3.connect("soc_db/soc_tickets.db") as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tables:
            try:
                con.execute(f"DELETE FROM {t} WHERE incident_id=?", (inc_id,))
            except Exception:
                pass

# 4. Clear run-cache JSON files
if os.path.exists("soc_db/last_workflow_result.json"):
    os.remove("soc_db/last_workflow_result.json")

# 5. Clear disk output directories (Removes Parsed JSON files)
for root_dir in ["outputs", "agents/reporting/outputs"]:
    if os.path.exists(root_dir):
        for item in os.listdir(root_dir):
            if inc_id in item or inc_num in item:
                target_path = os.path.join(root_dir, item)
                if os.path.isdir(target_path):
                    shutil.rmtree(target_path, ignore_errors=True)
                elif os.path.isfile(target_path):
                    os.remove(target_path)

print(f"Incident {inc_id} (database + disk files) cleared completely.")