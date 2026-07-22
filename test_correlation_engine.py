import os
import sys
import time
import asyncio

# Ensure parent directory imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from correlation_engine import CorrelationEngine
from sync_engine import Incident, IncidentMetadata, IncidentSeverity, IncidentStatus

def engine_fixture():
    # Use a temporary test directory for incident reports
    test_reports_dir = "test_incident_reports"
    test_db_dir = "ChromaDatabase"
    
    eng = CorrelationEngine(base_folder=test_reports_dir, db_path=test_db_dir)
    eng.active_incidents.clear()
    return eng
    
    # Cleanup reports folder after test
    import shutil
    if os.path.exists(test_reports_dir):
        shutil.rmtree(test_reports_dir)

def test_similar_but_unrelated(engine):
    """
    Test Case: Two alerts have identical tactics and description (high semantic similarity)
    but target completely different hosts, IPs, and users (zero infrastructure crossover).
    Verify that the correlation engine flags the decision as SIMILAR_BUT_UNRELATED
    and applies the zero-crossover penalty.
    """
    # 1. Setup an active incident (d) targeting HostA, IP A, User A
    incident_alerts = [
        {
            "id": "INC-001A",
            "document": "Suspicious privilege escalation alert. Malicious command execution detected on system host.",
            "metadata": {
                "incident_id": "INC-001A",
                "source_type": "WinEventLog",
                "username": "admin_alpha",
                "hostname": "HostA",
                "timestamp_str": "2026-01-01T00:00:00Z",
                "timestamp_epoch": 1767225600,
                "ips": "10.0.0.1",
                "tactic": "privilege-escalation",
                "sha256s": "",
                "md5s": "",
                "emails": "",
                "domains": ""
            }
        }
    ]
    
    inc = Incident(
        id="Incident-999",
        metadata=IncidentMetadata(
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.TRIAGED,
            assigned_analyst="Test Analyst",
            created_at=1767225600,
            updated_at=1767225600,
            source_type="WinEventLog"
        ),
        raw_alerts=incident_alerts,
        summary_text="Suspicious privilege escalation alert. Malicious command execution detected on system host.",
        indicators=["10.0.0.1", "hosta", "admin_alpha"]
    )
    
    # Save & index incident in ChromaDB and disk
    asyncio.run(engine.sync_create_incident(inc))
    
    # 2. Setup a new alert (a) with identical behavior (similar text description/mitre)
    # but targeting HostB, IP B, User B (NO crossover)
    new_alert = {
        "id": "INC-001B",
        "document": "Suspicious privilege escalation alert. Malicious command execution detected on system host.",
        "metadata": {
            "incident_id": "INC-001B",
            "source_type": "WinEventLog",
            "username": "admin_beta",
            "hostname": "HostB",
            "timestamp_str": "2026-01-01T00:05:00Z",
            "timestamp_epoch": 1767225900,
            "ips": "192.168.1.1",
            "tactic": "privilege-escalation",
            "sha256s": "",
            "md5s": "",
            "emails": "",
            "domains": ""
        }
    }
    
    # Execute Tier 1 evaluation
    # Let's run custom diagnostic print
    print("\n=== DIAGNOSTICS ===")
    print(f"Active Incidents Cache: {list(engine.active_incidents.keys())}")
    
    # Query semantic search directly to inspect
    sem_res = asyncio.run(engine.vector_index.query(new_alert["document"], limit=10))
    print(f"Direct Semantic Query Results: {sem_res}")
    
    # Run evaluation
    decision, score, matched_inc_id = asyncio.run(engine.evaluate_tier1(new_alert))
    
    # Compute component scores manually for printing
    inc = engine.active_incidents["Incident-999"]
    s_rel = engine._calculate_relational_score(engine._extract_indicators(new_alert), inc)
    s_mitre = engine._calculate_mitre_score(new_alert, inc)
    s_temporal = engine._calculate_temporal_score(new_alert["metadata"]["timestamp_epoch"], inc)
    
    print(f"Relational Score (S_rel): {s_rel}")
    print(f"MITRE Score:              {s_mitre}")
    print(f"Temporal Score:           {s_temporal}")
    print(f"Combined Correlation Score: {score}")
    print(f"Decision:                 {decision}")
    print(f"Matched Incident ID:      {matched_inc_id}")
    print("===================\n")
    
    # Verify that the decision is SIMILAR_BUT_UNRELATED because of the zero-crossover infrastructure penalty
    assert decision == "SIMILAR_BUT_UNRELATED"
    assert matched_inc_id == "Incident-999"

def test_low_and_slow_beaconing(engine):
    """
    Test Case: An incident has multiple alerts showing a periodic beaconing rhythm (spaced exactly 1 hour apart).
    A new alert arrives 1 hour after the latest alert.
    Verify that the temporal rhythm calculation detects the beaconing pattern and yields a high temporal score (1.0).
    """
    # 1. Setup an incident with periodic alerts at T=0, T=3600, T=7200
    incident_alerts = [
        {
            "id": "A1",
            "document": "Periodic beaconing network logs.",
            "metadata": {
                "incident_id": "Incident-BEACON",
                "timestamp_epoch": 10000,
                "ips": "10.0.0.5",
                "hostname": "WorkstationX"
            }
        },
        {
            "id": "A2",
            "document": "Periodic beaconing network logs.",
            "metadata": {
                "incident_id": "Incident-BEACON",
                "timestamp_epoch": 13600, # +3600s
                "ips": "10.0.0.5",
                "hostname": "WorkstationX"
            }
        },
        {
            "id": "A3",
            "document": "Periodic beaconing network logs.",
            "metadata": {
                "incident_id": "Incident-BEACON",
                "timestamp_epoch": 17200, # +3600s
                "ips": "10.0.0.5",
                "hostname": "WorkstationX"
            }
        }
    ]
    
    inc = Incident(
        id="Incident-BEACON",
        metadata=IncidentMetadata(
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.INVESTIGATING,
            created_at=10000,
            updated_at=17200
        ),
        raw_alerts=incident_alerts,
        summary_text="Periodic beaconing logs detected on WorkstationX.",
        indicators=["10.0.0.5", "workstationx"]
    )
    
    # 2. Evaluate alert arriving at T=20800 (+3600s again, matching the interval exactly)
    # The normal decay for a 3600s gap would be e^(-3600/43200) = 0.92,
    # but the rhythm detection should boost the score to exactly 1.0.
    rhythm_score = engine._calculate_temporal_score(20800, inc)
    
    # Evaluate alert arriving at T=22000 (+4800s, which does NOT fit the 3600s rhythm)
    non_rhythm_score = engine._calculate_temporal_score(22000, inc)
    
    print(f"\n[Test] Rhythm temporal score: {rhythm_score}")
    print(f"[Test] Non-rhythm temporal score: {non_rhythm_score}")
    
    assert rhythm_score == 1.0
    assert non_rhythm_score < 1.0

def test_sla_latency_check(engine):
    """
    Test Case: Assert that a correlation run processes within the sub-second SLA (under 1000ms).
    """
    alert = {
        "id": "INC-TEST-SLA",
        "document": "Test alert for SLA constraints.",
        "metadata": {
            "incident_id": "INC-TEST-SLA",
            "timestamp_epoch": int(time.time()),
            "ips": "10.100.10.1",
            "hostname": "DC-WIN2022"
        }
    }
    
    start_time = time.time()
    
    # Run full correlation logic with empty unassigned queue
    res = asyncio.run(engine.correlate_alert(alert, []))
    
    duration = time.time() - start_time
    print(f"\n[Test] SLA processing took {duration*1000:.2f}ms")
    
    assert duration < 1.0  # Execution SLA: must complete in under 1 second

if __name__ == "__main__":
    print("="*60)
    print("Running Standalone Correlation Engine Unit Tests...")
    print("="*60)
    
    class TestFixture:
        def __init__(self):
            self.test_reports_dir = "test_incident_reports"
            self.test_db_dir = "ChromaDatabase"
            self.eng = None
        def __enter__(self):
            self.eng = CorrelationEngine(base_folder=self.test_reports_dir, db_path=self.test_db_dir)
            self.eng.active_incidents.clear()
            return self.eng
        def __exit__(self, exc_type, exc_val, exc_tb):
            import shutil
            if os.path.exists(self.test_reports_dir):
                shutil.rmtree(self.test_reports_dir)

    try:
        with TestFixture() as eng:
            print("\n[*] Running: test_similar_but_unrelated")
            test_similar_but_unrelated(eng)
            print("[+] Passed: test_similar_but_unrelated")
            
        with TestFixture() as eng:
            print("\n[*] Running: test_low_and_slow_beaconing")
            test_low_and_slow_beaconing(eng)
            print("[+] Passed: test_low_and_slow_beaconing")
            
        with TestFixture() as eng:
            print("\n[*] Running: test_sla_latency_check")
            test_sla_latency_check(eng)
            print("[+] Passed: test_sla_latency_check")
            
        print("\n" + "="*60)
        print("[SUCCESS] All unit tests completed successfully!")
        print("="*60)
    except AssertionError as ae:
        print(f"\n[FAILURE] Assertion failed during testing: {ae}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Test runner crashed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
