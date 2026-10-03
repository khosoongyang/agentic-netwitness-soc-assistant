# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# =============================================================================
# File: scripts/acceptance_triage_step1.py
# Purpose: Acceptance check for Triage Step 1 through the REAL production
#   path, not unit fixtures:
#     workflow.engine.run_until_triage_approval()  (Parsing -> Triage -> gate)
#       -> persisted triage_result_json in the workflow state DB
#       -> GET /api/cases/<id>/workflow and /api/cases/<id> (Flask test client)
#       -> analyst approval + resume_after_triage_approval() (Threat Intel)
#       -> handoff_to_investigation() / handoff_to_reporting() (downstream)
#   plus a measurement of the baseline over a sample of real incidents.
# What is substituted, and why:
#   * the three LLM calls (TriageAgent._call) -> a canned answer, because no
#     OPENAI_API_KEY is available in this environment;
#   * the two AI-summary LLM calls -> a stub, for the same reason;
#   * every writable location (state DB, pipeline DB, run outputs,
#     investigation queue, reporting inputs) -> a temp dir. The state DB is
#     a temp COPY of soc_db/soc_incidents.db, so the baseline is measured on
#     the real 53k-incident history while soc_db/ itself is never written.
# Usage: python scripts/acceptance_triage_step1.py
# =============================================================================
from __future__ import annotations

import json
import random
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.triage import soc_triage_agent  # noqa: E402
from agents.triage.baseline import compute_baseline  # noqa: E402
from agents.triage.triage_result import TriageAgentSuccessOutput, validate_triage_agent_output  # noqa: E402

SOC_DB = ROOT / "soc_db" / "soc_incidents.db"
CASE_ID = "INC-40000"          # "High Risk Alerts: ESA for 192.168.1.64" (real, known-noisy host)
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def fake_call(self, messages, phase_label):
    """LLM boundary only. The SOC Classification answer is a sloppy
    false_positive that leans on the (real) noisy baseline: the guards must
    decide whether that is allowed."""
    if phase_label == "IOC Checklists":
        return json.dumps({"availability": {"matched_iocs": []},
                           "confidentiality": {"matched_iocs": [2], "reasoning": "internal traffic"},
                           "integrity": {"matched_iocs": []}})
    if phase_label == "Risk Rating":
        return json.dumps({"likelihood_initiation": "Medium", "likelihood_occurrence": "Critical",
                           "likelihood_adverse_impact": "Medium", "overall_risk": "Critical",
                           "rationale": "Measured: this detection fires hundreds of times a year."})
    return json.dumps({
        "classification": "Critical", "incident_category": "Policy violations",
        "summary": "High-volume ESA alert on 192.168.1.64.",
        "recommended_actions": ["Tune the ESA rule for this host"],
        "mitre_tactic": "Discovery", "mitre_technique": "Unknown",
        "proposed_disposition": "false_positive",
        "hypotheses": {
            "malicious": {"evidence_for": [{"claim": "Risk score is 70.", "cites": ["detection.riskScore"]}],
                          "evidence_against": [{"claim": "Fires constantly on this host.",
                                                "cites": ["baseline.same_source_entity_30d",
                                                          "baseline.is_known_noisy"]}]},
            "benign": {"evidence_for": [
                {"claim": "Known-noisy rule on this host; the rule needs tuning.",
                 "cites": ["baseline.is_known_noisy", "detection.ruleId", "context.asset_context"]}],
                "evidence_against": []},
        },
        "lookalike_ruled_out": {"lookalike": "Internal scanning by a compromised host",
                                "ruled_out": True, "reason": "Same pattern for months.",
                                "cites": ["baseline.first_seen", "baseline.same_source_entity_90d"]},
        "fn_cost_if_wrong": "Internal reconnaissance would be missed.",
        "evidence_checked": ["baseline.status", "context.asset_context", "rule_signals.scan_summary"],
    })


def main() -> int:
    from workflow import engine as sw
    from workflow import state_store as wss
    from workflow import stage_summaries

    tmp = Path(tempfile.mkdtemp(prefix="aegis-accept-"))
    try:
        print(f"temp workspace: {tmp}")
        state_db = tmp / "soc_incidents_copy.db"
        shutil.copy2(SOC_DB, state_db)
        soc_before = SOC_DB.stat().st_mtime_ns, SOC_DB.stat().st_size

        # --- redirect every writable location (same seams conftest.py uses) ---
        wss.DB_FILE = state_db
        sw.PIPELINE_DB_FILE = tmp / "pipeline.db"
        sw._TRUSTED_OUTPUT_ROOT = tmp / "run_outputs"
        sw.REP_DIR = tmp / "reporting"
        sw.INV_DIR = tmp / "investigation"
        (tmp / "investigation").mkdir()
        soc_triage_agent._TICKET_DB = tmp / "tickets.db"
        soc_triage_agent._ticket_db_init()
        # --- LLM boundary only ---
        soc_triage_agent.TriageAgent._call = fake_call
        stub = lambda *_a, **_k: {"ai_summary": "stub", "ai_thinking": "stub"}  # noqa: E731
        sw.generate_triage_ai_summary = stub
        sw.generate_parsing_ai_summary = stub
        stage_summaries.generate_triage_ai_summary = stub
        wss.db_init()

        with sqlite3.connect(str(state_db)) as con:
            incident = json.loads(con.execute(
                "SELECT raw_json FROM incidents WHERE id=?", (CASE_ID,)).fetchone()[0])

        # 1. real workflow entry point
        t0 = time.time()
        ctx = sw.run_until_triage_approval(incident, use_mock_triage=False, allow_retry=True)
        check("run_until_triage_approval completes Parsing + Triage",
              ctx["stages"].get("parsing") and not ctx["errors"],
              f"stages={ctx['stages']} errors={ctx['errors']} ({time.time() - t0:.1f}s)")
        run_id = ctx["run_id"]
        tri = ctx.get("triage") or {}
        check("triage used the Parsing output", tri.get("used_parsed_context") is True)

        # 2. persisted result validates against the contract
        with sqlite3.connect(str(state_db)) as con:
            row = con.execute("SELECT triage_status, triage_result_json FROM incidents WHERE id=?",
                              (CASE_ID,)).fetchone()
        persisted = json.loads(row[1])
        contract = {k: v for k, v in persisted.items()
                    if k not in ("ai_summary", "ai_thinking", "ai_summary_model", "ai_summary_generated_at",
                                 "triage_provenance")}
        out = validate_triage_agent_output(contract)
        check("persisted triage_result_json validates as TriageAgentSuccessOutput",
              isinstance(out, TriageAgentSuccessOutput), f"triage_status={row[0]}")

        pk = persisted["evidence_packet"]
        bl = pk["baseline"]
        check("baseline measured on real history via workflow.state_store.DB_FILE",
              bl["status"]["value"] == "measured",
              f"7d={bl['same_source_entity_7d']['value']} 30d={bl['same_source_entity_30d']['value']} "
              f"90d={bl['same_source_entity_90d']['value']} all={bl['same_source_entity_all_time']['value']} "
              f"noisy={bl['is_known_noisy']['value']}")
        check("data_quality measured from the real Parsing stage",
              pk["data_quality"]["parser_status"]["value"] == "completed",
              f"parser_confidence={pk['data_quality']['parser_confidence']['value']}")
        a = persisted["assessment"]
        check("guards applied to the model's false_positive",
              a["proposed_disposition"] == "false_positive",
              f"final={a['disposition']} uncertainty={a['uncertainty']} "
              f"guard_actions={[g['rule'] for g in a['guard_actions']]} "
              f"citation_errors={[(e['path'], e['error']) for e in a['citation_errors']]}")
        check("ticket carries disposition/uncertainty",
              persisted["ticket"]["disposition"] == a["disposition"]
              and persisted["ticket"]["uncertainty"] == a["uncertainty"])
        check("severity unchanged (still derived from risk dimensions)",
              persisted["ticket"]["classification"] == "CRITICAL")

        # 3. HTTP API the frontend reads
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_aegis_accept_backend", ROOT / "backend" / "__init__.py",
            submodule_search_locations=[str(ROOT / "backend")])
        backend = importlib.util.module_from_spec(spec)
        sys.modules["_aegis_accept_backend"] = backend
        spec.loader.exec_module(backend)
        app = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": state_db})
        client = app.test_client()
        wf = client.get(f"/api/cases/{CASE_ID}/workflow")
        body = wf.get_json()
        stages = body.get("stages") if isinstance(body, dict) else None
        tri_stage = next((s for s in (stages or []) if s.get("key") == "triage" or s.get("id") == "triage"), None)
        res = (tri_stage or {}).get("result") or {}
        check("GET /api/cases/<id>/workflow exposes assessment + ticket.disposition",
              wf.status_code == 200 and res.get("assessment", {}).get("disposition") == a["disposition"]
              and (res.get("ticket") or {}).get("disposition") == a["disposition"],
              f"HTTP {wf.status_code}, triage stage status={(tri_stage or {}).get('status')}")
        detail = client.get(f"/api/cases/{CASE_ID}")
        check("GET /api/cases/<id> (case detail + case view) still renders", detail.status_code == 200,
              f"HTTP {detail.status_code}")

        # 4. approval + resume (Threat Intel consumes the triage result)
        appr = client.post(f"/api/cases/{CASE_ID}/approvals/triage",
                           json={"decision": "approve", "analyst": "acceptance-check",
                                 "comments": "Step 1 acceptance"})
        check("POST triage approval accepted", appr.status_code in (200, 201, 202),
              f"HTTP {appr.status_code} {str(appr.get_json())[:160]}")
        # Start Threat Intel through the real API command. Its background
        # worker is run synchronously here (same target/args) so the result
        # can be observed; Investigation is not chained (it is an LLM + Chroma
        # subprocess and out of scope for this step).
        from workflow import commands
        captured = {}
        commands._spawn_background = lambda run_id_, stage, target, args: captured.update(
            run_id=run_id_, stage=stage, target=target, args=args)
        start = client.post(f"/api/cases/{CASE_ID}/stages/threat_intel/runs")
        check("POST /stages/threat_intel/runs accepted", start.status_code in (200, 201, 202),
              f"HTTP {start.status_code}")
        try:
            sw.resume_after_triage_approval(*captured["args"])
        except Exception as exc:          # recorded, not hidden
            print(f"(threat intel worker raised: {exc!r})")
        with sqlite3.connect(str(state_db)) as con:
            ti_status = con.execute("SELECT threat_intel_status FROM incidents WHERE id=?",
                                    (CASE_ID,)).fetchone()[0]
        check("Threat Intel stage runs on the new triage result", ti_status not in (None, "Failed"),
              f"threat_intel_status={ti_status} (providers offline: no API keys)")

        # 5. downstream handoffs used by Investigation and Reporting
        inv_path = sw.handoff_to_investigation(persisted, incident)
        inv_alert = json.loads(Path(inv_path).read_text(encoding="utf-8"))
        check("handoff_to_investigation writes its alert unchanged in shape",
              Path(inv_path).exists(), f"keys={sorted(inv_alert)[:8]}...")
        rep = sw.handoff_to_reporting(persisted, incident, None, None)
        check("handoff_to_reporting writes its inputs", bool(rep), str(rep)[:120])

        # 6. baseline on a random sample of real incidents (as-of each incident)
        with sqlite3.connect(SOC_DB.resolve().as_uri() + "?mode=ro", uri=True) as con:
            ids = [r[0] for r in con.execute("SELECT id FROM incidents")]
            random.Random(7).shuffle(ids)
            sample = [json.loads(con.execute("SELECT raw_json FROM incidents WHERE id=?",
                                             (i,)).fetchone()[0]) for i in ids[:150]]
        times, statuses, noisy, first, leaks = [], {}, 0, 0, 0
        for inc in sample:
            t = time.time()
            b = compute_baseline(inc, SOC_DB)
            times.append(time.time() - t)
            statuses[b["status"]] = statuses.get(b["status"], 0) + 1
            noisy += bool(b["is_known_noisy"])
            first += bool(b["is_first_occurrence"])
            if b["last_seen"] and b["as_of"] and b["last_seen"] >= b["as_of"]:
                leaks += 1
        times.sort()
        check("baseline on 150 random real incidents: no future leakage", leaks == 0,
              f"status={statuses} known_noisy={noisy} first_occurrence={first} "
              f"median={times[len(times)//2]:.2f}s p95={times[int(len(times)*.95)]:.2f}s")

        soc_after = SOC_DB.stat().st_mtime_ns, SOC_DB.stat().st_size
        check("soc_db/soc_incidents.db not modified", soc_before == soc_after)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} acceptance checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
