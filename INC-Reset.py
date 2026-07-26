import sqlite3, os

inc_id = "INC-52825"  # Replace with target incident ID

# 1. Reset workflow state & triage status in soc_incidents.db
with sqlite3.connect("soc_db/soc_incidents.db") as con:
    con.execute("""
        UPDATE incidents SET 
            workflow_status=NULL, 
            approval_stage=NULL, 
            run_id=NULL,
            triage_status=NULL, 
            triage_result_json=NULL,
            parsing_status=NULL, 
            parsing_result_json=NULL,
            threat_intel_status=NULL, 
            threat_intel_result_json=NULL,
            investigation_status=NULL, 
            investigation_result_json=NULL,
            reporting_status=NULL, 
            reporting_result_json=NULL,
            approved_by=NULL, 
            approved_at=NULL, 
            approval_comments=NULL,
            worker_id=NULL, 
            worker_stage=NULL, 
            last_error=NULL
        WHERE id=?
    """, (inc_id,))
    con.execute("DELETE FROM workflow_approvals WHERE incident_id=?", (inc_id,))
    con.execute("DELETE FROM workflow_activity WHERE incident_id=?", (inc_id,))
    con.execute("DELETE FROM report_edits WHERE incident_id=?", (inc_id,))

# 2. Reset records in soc_pipeline.db (Correct Database File)
if os.path.exists("soc_db/soc_pipeline.db"):
    with sqlite3.connect("soc_db/soc_pipeline.db") as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tables:
            try:
                con.execute(f"DELETE FROM {t} WHERE incident_id=?", (inc_id,))
            except Exception:
                pass

# 3. Reset records in soc_tickets.db
if os.path.exists("soc_db/soc_tickets.db"):
    with sqlite3.connect("soc_db/soc_tickets.db") as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tables:
            try:
                con.execute(f"DELETE FROM {t} WHERE incident_id=?", (inc_id,))
            except Exception:
                pass

# 4. Remove cached run result file
if os.path.exists("soc_db/last_workflow_result.json"):
    os.remove("soc_db/last_workflow_result.json")

print(f"Incident {inc_id} cleared successfully.")