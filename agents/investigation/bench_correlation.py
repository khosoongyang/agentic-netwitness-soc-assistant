# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: asyncio, chromadb, correlation_engine, main, os, shutil, sync_engine, sys.
# =============================================================================
# File: soc_investigation_agent_revised/bench_correlation.py
# Purpose: This module benchmarks investigation correlation behaviour against representative alert inputs.
# Main functionality: clean_environment, copy_test_alerts, analyze_results, main_bench.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis investigation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: asyncio, chromadb, correlation_engine, main, os, shutil, sync_engine, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: clean_environment, copy_test_alerts, analyze_results, main_bench, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

import os
import sys
import shutil
import time
import asyncio
import chromadb

# Add parent directory to path to ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import main
import vector_engine
import correlation_engine
from sync_engine import ChromaIncidentVectorStore

COPY_DIR = "triaged_alerts_copy"
TARGET_DIR = "triaged_alerts"
REPORTS_DIR = "incident_reports"

# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `clean_environment` — implements the clean environment operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ChromaIncidentVectorStore`, `clear_collection`, `delete_collection`, `exists`, `makedirs`, `print`, `rmtree`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def clean_environment():
    print("[*] Cleaning test environment...")
    
    # 1. Clear directories
    if os.path.exists(TARGET_DIR):
        shutil.rmtree(TARGET_DIR)
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    if os.path.exists(REPORTS_DIR):
        shutil.rmtree(REPORTS_DIR)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # 2. Reset ChromaDB
    print("[*] Resetting ChromaDB collections...")
    vector_engine.clear_collection()
    
    # Also reset the soc_incidents collection
    try:
        store = ChromaIncidentVectorStore("ChromaDatabase")
        store.client.delete_collection("soc_incidents")
    except Exception:
        pass
    
    # Re-initialize
    store = ChromaIncidentVectorStore("ChromaDatabase")
    print("[+] Test environment clean.")

# [FYP-FUNCTION] `copy_test_alerts` — implements the copy test alerts operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `copy2`, `endswith`, `exists`, `exit`, `join`, `listdir`, `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def copy_test_alerts():
    print(f"[*] Copying alerts from '{COPY_DIR}' to '{TARGET_DIR}'...")
    if not os.path.exists(COPY_DIR):
        print(f"[-] Error: '{COPY_DIR}' does not exist.")
        sys.exit(1)
        
    copied_count = 0
    for f in os.listdir(COPY_DIR):
        if f.endswith('.json'):
            src = os.path.join(COPY_DIR, f)
            dst = os.path.join(TARGET_DIR, f)
            shutil.copy2(src, dst)
            copied_count += 1
            
    print(f"[+] Copied {copied_count} test alert files.")

# [FYP-FUNCTION] `analyze_results` — implements the analyze results operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exists`, `get`, `join`, `len`, `listdir`, `load`, `open`, `print`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def analyze_results():
    print("\n" + "="*50)
    print("ANALYSIS OF CORRELATED INCIDENTS")
    print("="*50)
    
    if not os.path.exists(REPORTS_DIR):
        print("No incident reports found.")
        return
        
    incidents = sorted([d for d in os.listdir(REPORTS_DIR) if d.startswith("Incident-")])
    for inc in incidents:
        inc_dir = os.path.join(REPORTS_DIR, inc)
        data_file = os.path.join(inc_dir, "incident_data.json")
        if os.path.exists(data_file):
            try:
                import json
                with open(data_file, "r") as f:
                    data = json.load(f)
                metadata = data.get("metadata", {})
                raw_alerts = data.get("raw_alerts", [])
                indicators = data.get("indicators", [])
                similar_to = metadata.get("similar_to_incident")
                
                print(f"\n{inc}:")
                print(f"  Severity:   {metadata.get('severity')}")
                print(f"  Alerts:     {len(raw_alerts)} total")
                for a in raw_alerts:
                    print(f"    - {a['id']} (mitre: {a.get('metadata', {}).get('mitre_att&ck', {}).get('tactic', 'N/A')})")
                print(f"  Indicators: {', '.join(indicators[:6])}...")
                if similar_to:
                    print(f"  [RELATION] Similar but Unrelated to: {similar_to}")
            except Exception as e:
                print(f"Error reading incident {inc}: {e}")

# [FYP-FUNCTION] `main_bench` — implements the main bench operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/bench_correlation.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `analyze_results`, `clean_environment`, `copy_test_alerts`, `endswith`, `len`, `listdir`, `main`, `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main_bench():
    clean_environment()
    copy_test_alerts()
    
    print("\n[*] Starting execution pipeline benchmarking...")
    start_time = time.time()
    
    # Run the main pipeline (Bulk ingest + drain queue)
    main.main()
    
    total_time = time.time() - start_time
    print("\n" + "="*50)
    print("BENCHMARK EXECUTION SUMMARY")
    print("="*50)
    print(f"Total pipeline execution time: {total_time:.2f} seconds")
    
    # Check how many alerts were processed
    # Since files are moved, triaged_alerts/ should be empty
    remaining = len([f for f in os.listdir(TARGET_DIR) if f.endswith('.json')])
    print(f"Remaining unprocessed alerts in queue: {remaining}")
    
    analyze_results()

if __name__ == "__main__":
    main_bench()
