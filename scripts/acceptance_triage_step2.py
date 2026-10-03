# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# =============================================================================
# File: scripts/acceptance_triage_step2.py
# Purpose: Acceptance check for Triage Step 2 through the REAL production
#   path (same seams as scripts/acceptance_triage_step1.py):
#     workflow.engine.run_until_triage_approval()  (ingestion enrichment from
#       the on-disk Respond-API export -> data_availability -> Parsing ->
#       Triage -> approval gate)
#       -> persisted triage_result_json in the workflow state DB
#       -> GET /api/cases/<id>/workflow (Flask test client)
#       -> POST /api/cases/<id>/stages/triage/reruns -> run_triage_stage()
#          (durable path: load_data_availability_for_run())
#   on three real incidents:
#     INC-40000  slim SQLite only    -> full path incl. HTTP API + durable re-run;
#                                       raw_alerts missing -> cannot close benign
#     INC-53021  raw alerts on disk  -> raw_alerts measured, masquerade floor
#     INC-52825  1,000 raw alerts    -> ranked signatures in the real prompt
# Parsing constraint (history): until the Step-3 housekeeping fix
#   (parser_normaliser.detect_input_format "flat_incident_with_alerts"),
#   incidents enriched from a Respond-API export stopped at PARSING
#   ("Parser input mismatch", reproduced on baseline bdbb077). The fallback
#   branch below (real ingestion artifacts -> run_triage()) is kept so this
#   script stays informative if that ever regresses; it prints [NOTE].
# What is substituted, and why:
#   * the three LLM calls -> an ADVERSARIAL canned answer that always proposes
#     false_positive with plausible citations (no OPENAI_API_KEY here, and it
#     is the worst case the guards must withstand);
#   * AI-summary LLM calls -> a stub;
#   * every writable location -> a temp dir; the state DB is a temp COPY of
#     soc_db/soc_incidents.db. soc_db/ is checked unchanged at the end.
# Usage: python scripts/acceptance_triage_step2.py
# =============================================================================
from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.triage import lolbas, soc_triage_agent  # noqa: E402
from agents.triage.triage_result import TriageAgentSuccessOutput, validate_triage_agent_output  # noqa: E402

SOC_DB = ROOT / "soc_db" / "soc_incidents.db"
RESULTS: list[tuple[str, bool, str]] = []
PROMPTS: dict[str, dict[str, str]] = {}


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def fake_call(self, messages, phase_label):
    """LLM boundary only: always argues for closing the alert."""
    inc_id = str((self._evidence_packet or {}).get("_inc") or "")
    PROMPTS.setdefault(self._accept_inc, {})[phase_label] = "\n".join(m.content for m in messages)
    if phase_label == "IOC Checklists":
        return json.dumps({"availability": {"matched_iocs": []}, "confidentiality": {"matched_iocs": []},
                           "integrity": {"matched_iocs": []}})
    if phase_label == "Risk Rating":
        return json.dumps({"likelihood_initiation": "Low", "likelihood_occurrence": "High",
                           "likelihood_adverse_impact": "Low", "overall_risk": "High",
                           "rationale": "Fires all the time." + inc_id})
    return json.dumps({
        "classification": "Low", "incident_category": "Policy violations",
        "summary": "Routine, signed Windows activity.", "recommended_actions": ["Close"],
        "mitre_tactic": "Execution", "mitre_technique": "Unknown",
        "proposed_disposition": "false_positive",
        "hypotheses": {"benign": {"evidence_for": [
            {"claim": "Known rule, Microsoft-signed processes, parsed cleanly.",
             "cites": ["detection.ruleId", "data_quality.parser_status", "raw_alerts.signers",
                       "baseline.is_known_noisy"]}]}},
        "lookalike_ruled_out": {"lookalike": "LOLBin abuse", "ruled_out": True, "reason": "signed",
                                "cites": ["raw_alerts.signers"]},
        "fn_cost_if_wrong": "low", "evidence_checked": ["raw_alerts.available"]})


def main() -> int:
    from workflow import commands, stage_summaries
    from workflow import engine as sw
    from workflow import state_store as wss

    tmp = Path(tempfile.mkdtemp(prefix="aegis-accept2-"))
    soc_before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in SOC_DB.parent.glob("*.db")}
    try:
        print(f"temp workspace: {tmp}")
        ds, reason = lolbas.load_lolbas_dataset()
        print(f"LOLBAS: {ds.source if ds else 'MISSING: ' + reason}")
        state_db = tmp / "soc_incidents_copy.db"
        shutil.copy2(SOC_DB, state_db)
        wss.DB_FILE = state_db
        sw.PIPELINE_DB_FILE = tmp / "pipeline.db"
        sw._TRUSTED_OUTPUT_ROOT = tmp / "run_outputs"
        sw.REP_DIR = tmp / "reporting"
        sw.INV_DIR = tmp / "investigation"
        (tmp / "investigation").mkdir()
        soc_triage_agent._TICKET_DB = tmp / "tickets.db"
        soc_triage_agent._ticket_db_init()
        soc_triage_agent.TriageAgent._call = fake_call
        soc_triage_agent.TriageAgent._accept_inc = ""
        stub = lambda *_a, **_k: {"ai_summary": "stub", "ai_thinking": "stub"}  # noqa: E731
        sw.generate_triage_ai_summary = stub
        sw.generate_parsing_ai_summary = stub
        stage_summaries.generate_triage_ai_summary = stub
        wss.db_init()

        def slim(case_id: str) -> dict:
            with sqlite3.connect(str(state_db)) as con:
                return json.loads(con.execute("SELECT raw_json FROM incidents WHERE id=?",
                                              (case_id,)).fetchone()[0])

        def persisted(case_id: str) -> dict:
            with sqlite3.connect(str(state_db)) as con:
                row = con.execute("SELECT triage_result_json FROM incidents WHERE id=?",
                                  (case_id,)).fetchone()
            return json.loads(row[0])

        def run(case_id: str) -> dict:
            soc_triage_agent.TriageAgent._accept_inc = case_id
            inc = slim(case_id)
            check(f"{case_id}: SQLite copy is the slim incident (no raw alerts)", "alerts" not in inc)
            t0 = time.time()
            ctx = sw.run_until_triage_approval(inc, use_mock_triage=False, allow_retry=True)
            run_id = ctx["run_id"]
            if ctx["errors"].get("parsing"):
                # Pre-existing Parsing identity-guard failure (see header).
                print(f"[NOTE] {case_id}: combined path stopped at Parsing "
                      f"(REGRESSION of the Step-3 parser fix?): {ctx['errors']['parsing'][:110]}")
                RESULTS.append((f"{case_id}: combined path blocked at Parsing", False, ""))
                raw = sw.load_raw_incident_for_run(case_id, run_id)
                da = sw.load_data_availability_for_run(case_id, run_id)
                check(f"{case_id}: ingestion persisted raw alerts + data_availability for the run",
                      raw is not None and len(raw.get("alerts") or []) > 0 and da is not None,
                      f"alerts={len((raw or {}).get('alerts') or [])} data_availability={da and {k: da[k] for k in ('incident_source', 'alerts_fetch_succeeded', 'alerts_count')}}")
                parsed = sw.run_parsing(raw, run_id).get("processed_alert") or None
                res = sw.run_triage(raw, parsed_context=parsed, force=True, data_availability=da)
                check(f"{case_id}: real stage runner run_triage() succeeds with them",
                      res.get("error") is None, f"({time.time() - t0:.1f}s)")
            else:
                check(f"{case_id}: run_until_triage_approval completes Parsing + Triage",
                      not ctx["errors"] and ctx.get("triage"),
                      f"stages={ctx['stages']} ({time.time() - t0:.1f}s)")
                res = persisted(case_id)
            contract = {k: v for k, v in res.items()
                        if k not in ("ai_summary", "ai_thinking", "ai_summary_model", "ai_summary_generated_at",
                                 "triage_provenance")}
            check(f"{case_id}: persisted result validates (Step 2 contract)",
                  isinstance(validate_triage_agent_output(contract), TriageAgentSuccessOutput))
            return res

        # ---------------- INC-40000: slim copy, FULL real path ---------------
        r = run("INC-40000")
        ra, a = r["evidence_packet"]["raw_alerts"], r["assessment"]
        check("INC-40000: no raw alerts fetched -> raw_alerts.available is missing (recorded by ingestion)",
              ra["available"]["status"] == "missing" and "recorded by ingestion" in ra["incident_source"]["source"],
              f"incident_source={ra['incident_source']['value']}; {ra['available']['source'][:90]}")
        check("INC-40000: adversarial false_positive blocked by mandatory raw-alert evidence",
              a["proposed_disposition"] == "false_positive" and a["disposition"] == "needs_info"
              and "raw_alerts_available" in a["guard_actions"][0]["reason"],
              f"guard_actions={[g['rule'] for g in a['guard_actions']]} uncertainty={a['uncertainty']}")

        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_aegis_accept2_backend", ROOT / "backend" / "__init__.py",
            submodule_search_locations=[str(ROOT / "backend")])
        backend = importlib.util.module_from_spec(spec)
        sys.modules["_aegis_accept2_backend"] = backend
        spec.loader.exec_module(backend)
        client = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": state_db}).test_client()
        wf = client.get("/api/cases/INC-40000/workflow")
        stages = (wf.get_json() or {}).get("stages") or []
        tri = next((s for s in stages if s.get("key") == "triage" or s.get("id") == "triage"), {})
        res = tri.get("result") or {}
        ep = res.get("evidence_packet") or {}
        check("GET /api/cases/INC-40000/workflow exposes raw_alerts + lolbas + needs_info",
              wf.status_code == 200 and "raw_alerts" in ep and "lolbas" in ep.get("rule_signals", {})
              and (res.get("ticket") or {}).get("disposition") == "needs_info",
              f"HTTP {wf.status_code}, rule_signals.lolbas status={ep.get('rule_signals', {}).get('lolbas', {}).get('status')}")
        check("GET /api/cases/INC-40000 (case view) still renders",
              client.get("/api/cases/INC-40000").status_code == 200)
        captured = {}
        commands._spawn_background = lambda run_id_, stage, target, args: captured.update(target=target, args=args)
        rr = client.post("/api/cases/INC-40000/stages/triage/reruns")
        check("POST /api/cases/INC-40000/stages/triage/reruns accepted", rr.status_code in (200, 201, 202),
              f"HTTP {rr.status_code}")
        if captured:
            captured["target"](*captured["args"])
        r2 = persisted("INC-40000")
        ra2 = r2["evidence_packet"]["raw_alerts"]
        # [AUDIT T-12] a re-run is a fresh result (new created_at) but keeps
        # the incident's ticket number instead of burning a new UNC.
        check("durable re-run (run_triage_stage) reloads the run's data_availability",
              r2["ticket"]["unc"] == r["ticket"]["unc"]
              and r2["ticket"]["created_at"] != r["ticket"]["created_at"]
              and "recorded by ingestion" in ra2["incident_source"]["source"]
              and r2["assessment"]["disposition"] == "needs_info",
              f"same ticket {r2['ticket']['unc']} (was {r['ticket']['unc']}), "
              f"guard={[g['rule'] for g in r2['assessment']['guard_actions']]}")

        # ---------------- INC-53021: raw alerts from the on-disk export ------
        r = run("INC-53021")
        ra, a = r["evidence_packet"]["raw_alerts"], r["assessment"]
        check("INC-53021: ingestion's data_availability reached Triage (measured)",
              ra["incident_source"]["value"] == "netwitness_live" and ra["available"]["value"] is True
              and ra["available"]["status"] == "measured",
              f"alerts_count={ra['alerts_count']['value']} coverage={ra['coverage_ratio']['value']}")
        td = ra["threat_desc"]["value"]["items"]
        check("INC-53021: raw digest surfaces the trojan verdict and process folder",
              td and td[0]["threat_desc"] == "Win64.Trojan.Goldera",
              f"threat_desc={[(t['threat_desc'], t['processes']) for t in td]}")
        masq = r["evidence_packet"]["rule_signals"]["masquerade"]["value"]["floor_labels"]
        check("INC-53021: masquerade flagged (splunkd.exe in C:\\Users\\Public\\)",
              masq == ["masquerade:splunkd.exe"], str(masq))
        check("INC-53021: adversarial false_positive forced to needs_info by the floor",
              a["proposed_disposition"] == "false_positive" and a["disposition"] == "needs_info"
              and any(g["rule"] == "b_strong_signal_floor" for g in a["guard_actions"]),
              f"guard_actions={[g['rule'] for g in a['guard_actions']]}")
        cls_prompt = PROMPTS["INC-53021"]["SOC Classification"]
        check("INC-53021: real prompt carries raw_alerts + abused-tool evidence",
              "raw_alerts.threat_desc [measured]" in cls_prompt
              and "rule_signals.masquerade [measured]" in cls_prompt
              and '"process": "splunkd.exe"' in cls_prompt)

        # ---------------- INC-52825: ranking in the real prompt --------------
        r = run("INC-52825")
        ra = r["evidence_packet"]["raw_alerts"]
        ioc_prompt = PROMPTS["INC-52825"]["IOC Checklists"]
        block = ioc_prompt[ioc_prompt.rindex("<untrusted_incident_data>\n") + len("<untrusted_incident_data>\n"):
                           ioc_prompt.rindex("\n</untrusted_incident_data>")]
        data = json.loads(block)
        top = data["alert_signatures"][0]
        check("INC-52825: all 1,000 raw alerts digested (1000/1558 coverage recorded)",
              ra["events_digested"]["value"] == 1000 and ra["coverage_ratio"]["value"] == 0.642)
        check("INC-52825: real prompt leads with the rare 'Disables UAC' signature (not first-12)",
              top["alert_name"] == "Disables UAC" and "first 12" not in data["alerts_note"],
              f"{data['alerts_note']}; top={top['alert_name']} x{top['count']} -> "
              f"{top.get('child_command_lines', [''])[0][:70]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    soc_after = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in SOC_DB.parent.glob("*.db")}
    check("soc_db/*.db not modified", soc_before == soc_after)
    failed = [x for x in RESULTS if not x[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} acceptance checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
