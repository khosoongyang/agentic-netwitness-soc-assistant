# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# =============================================================================
# File: scripts/acceptance_triage_step3.py
# Purpose: [FYP-TRIAGE-STEP3] Acceptance check for Step 3 through the REAL
#   production path (same seams as scripts/acceptance_triage_step2.py), on
#   real incidents from a temp COPY of soc_db/soc_incidents.db:
#     run_until_triage_approval()  (ingestion -> Parsing -> Triage -> gate)
#     -> POST /api/cases/<id>/approvals/triage {review}        (X1, HTTP)
#     -> GET  /api/cases/<id>/triage/reviews                   (X1)
#     -> handoff_to_investigation() alert file on disk         (canonical verdict)
#     -> handoff_to_reporting() triage_result.json on disk     (canonical verdict)
#     -> GET /api/cases/<id>/reports  ticket blocks            ("AI -> Analyst")
#     -> POST .../approvals/triage reject + POST .../reruns {analyst_note}
#        -> run_triage_stage() (durable)                       (context.analyst_note)
#     -> suppression propose/approve over HTTP, then a durable re-run of a
#        masquerade incident: context.suppression_match present but IGNORED
#        for the strong-signal floor                            (X3)
#     -> GET /api/triage/{tuning-backlog,noisy-rules,metrics}   (X3/X6)
#     -> scripts/blind_review.py export/import + triage_metrics (X6)
# Substituted (no OPENAI_API_KEY here): the three LLM calls -> a canned answer
#   that proposes benign_expected citing context (the analyst note once one is
#   attached), AI-summary calls -> stub. Everything writable -> temp dir;
#   soc_db/ is checked unchanged at the end.
# Usage: python scripts/acceptance_triage_step3.py
# =============================================================================
from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.triage import soc_triage_agent  # noqa: E402

SOC_DB = ROOT / "soc_db" / "soc_incidents.db"
RESULTS: list[tuple[str, bool, str]] = []
PROMPTS: dict[str, str] = {}


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def fake_call(self, messages, phase_label):
    """LLM boundary only: proposes benign_expected, citing context.* (the
    analyst note / suppression if the packet has them)."""
    text = "\n".join(m.content for m in messages)
    PROMPTS[phase_label] = text
    if phase_label == "IOC Checklists":
        return json.dumps({"availability": {"matched_iocs": []}, "confidentiality": {"matched_iocs": []},
                           "integrity": {"matched_iocs": []}})
    if phase_label == "Risk Rating":
        return json.dumps({"likelihood_initiation": "Low", "likelihood_occurrence": "High",
                           "likelihood_adverse_impact": "Low", "overall_risk": "Medium", "rationale": "x"})
    cites = ["context.analyst_note", "context.suppression_match", "detection.createdBy"]
    return json.dumps({
        "classification": "Medium", "incident_category": "Malware", "summary": "s",
        "recommended_actions": ["Review"], "mitre_tactic": "Execution", "mitre_technique": "Unknown",
        "proposed_disposition": "benign_expected",
        "hypotheses": {"benign": {"evidence_for": [{"claim": "Expected maintenance activity", "cites": cites}]},
                       "malicious": {"evidence_against": [{"claim": "Known source", "cites": ["detection.createdBy"]}]}},
        "lookalike_ruled_out": {"lookalike": "masquerading malware", "ruled_out": False, "reason": "", "cites": []},
        "fn_cost_if_wrong": "missed intrusion", "evidence_checked": ["raw_alerts.available"]})


def _load(name, path, pkg=False):
    spec = importlib.util.spec_from_file_location(
        name, path, submodule_search_locations=[str(path.parent)] if pkg else None)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    from workflow import commands, stage_summaries
    from workflow import engine as sw
    from workflow import state_store as wss

    tmp = Path(tempfile.mkdtemp(prefix="aegis-accept3-"))
    soc_before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in SOC_DB.parent.glob("*.db")}
    try:
        print(f"temp workspace: {tmp}")
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
        stub = lambda *_a, **_k: {"ai_summary": "stub", "ai_thinking": "stub"}  # noqa: E731
        sw.generate_triage_ai_summary = stub
        sw.generate_parsing_ai_summary = stub
        stage_summaries.generate_triage_ai_summary = stub
        wss.db_init()
        captured: dict = {}
        commands._spawn_background = lambda run_id_, stage, target, args: captured.update(target=target, args=args)

        backend = _load("_aegis_accept3_backend", ROOT / "backend" / "__init__.py", pkg=True)
        client = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": state_db}).test_client()

        def slim(case_id):
            with wss.db_connect() as con:
                return json.loads(con.execute("SELECT raw_json FROM incidents WHERE id=?", (case_id,)).fetchone()[0])

        def persisted(case_id):
            return json.loads(wss.get_state(case_id)["triage_result_json"])

        # =============== INC-53021 (raw alerts, masquerade) =================
        case = "INC-53021"
        ctx = sw.run_until_triage_approval(slim(case), use_mock_triage=False, allow_retry=True)
        check(f"{case}: real path reaches the triage gate", not ctx["errors"] and wss.get_state(case)["triage_status"] == "Awaiting Approval",
              str(ctx["stages"]))
        tri = persisted(case)
        a = tri["assessment"]
        check(f"{case}: no note yet -> context.analyst_note missing, benign_expected blocked",
              tri["evidence_packet"]["context"]["analyst_note"]["status"] == "missing" and a["disposition"] == "needs_info",
              f"proposed={a['proposed_disposition']} final={a['disposition']} guards={[g['rule'] for g in a['guard_actions']]}")
        check(f"{case}: triage_provenance recorded (prompt version)",
              tri.get("triage_provenance", {}).get("prompt_version") == soc_triage_agent.TRIAGE_PROMPT_VERSION)

        # HTTP: invalid review rejected with canonical error, state untouched
        bad = client.post(f"/api/cases/{case}/approvals/triage", json={
            "decision": "approve", "analyst": "Alice", "review": {"analyst_disposition": "false_positive",
                                                                 "evidence_checked": ["raw_alerts"], "justification": "j"}})
        check("HTTP invalid review -> 400 INVALID_REVIEW, nothing written",
              bad.status_code == 400 and bad.get_json()["error"]["code"] == "INVALID_REVIEW"
              and wss.get_state(case)["triage_status"] == "Awaiting Approval"
              and wss.get_approval_history(case) == [])

        # HTTP: reject with review, then re-triage with an analyst note
        rej = client.post(f"/api/cases/{case}/approvals/triage", json={
            "decision": "reject", "analyst": "Alice", "comments": "splunkd in Public is the vendor's portable agent",
            "review": {"analyst_disposition": "needs_info", "evidence_checked": ["raw_alerts", "rule_signals"],
                       "justification": "Need vendor confirmation.", "lookalike_considered": "masquerading malware"}})
        check("HTTP reject with structured review", rej.status_code == 200 and rej.get_json().get("review_id"))
        note = "Vendor ticket V-77: splunkd.exe portable build is deployed in C:\\Users\\Public\\ on this host."
        rr = client.post(f"/api/cases/{case}/stages/triage/reruns", json={"analyst_note": note, "analyst": "Alice"})
        check("HTTP re-triage with analyst_note accepted", rr.status_code == 202 and rr.get_json()["analyst_note"]["note"] == note)
        if captured.get("target"):
            captured["target"](*captured["args"])
        tri2 = persisted(case)
        leaf = tri2["evidence_packet"]["context"]["analyst_note"]
        check("durable re-run: context.analyst_note measured with analyst + time",
              leaf["status"] == "measured" and leaf["value"] == note and leaf["source"].startswith("analyst Alice @ "))
        check("durable re-run: real prompt carries the delimited analyst context",
              f"<analyst_provided_context>{json.dumps(note)}</analyst_provided_context>" in PROMPTS["SOC Classification"])
        a2 = tri2["assessment"]
        check("analyst note explains the masquerade floor -> benign_expected reachable (human-attested)",
              a2["disposition"] == "benign_expected", f"final={a2['disposition']} guards={[g['rule'] for g in a2['guard_actions']]}")

        # HTTP: approve with a benign_expected review + suppression proposal
        from agents.triage.suppression import scope_from_packet
        sc = scope_from_packet(tri2["evidence_packet"])
        ok = client.post(f"/api/cases/{case}/approvals/triage", json={
            "decision": "approve", "analyst": "Alice", "review": {
                "analyst_disposition": "benign_expected", "evidence_checked": ["raw_alerts", "context"],
                "justification": "Vendor-confirmed portable agent.", "lookalike_considered": "masquerading malware",
                "benign_context": {"who": "Splunk admin team", "when": "since 2026-07", "why": "vendor ticket V-77"},
                "suppression_proposal": {"scope": {"detection_source": sc["detection_source"], "entity": sc["entity"]},
                                         "expiry_days": 30}}})
        body = ok.get_json()
        check("HTTP approve with benign_expected review + suppression proposal",
              ok.status_code == 200 and body.get("review_id") and body.get("suppression_proposal_id"))
        reviews = client.get(f"/api/cases/{case}/triage/reviews").get_json()
        check("GET reviews: reject + approve recorded, AI side + snapshot hash + raw sha",
              reviews["count"] == 2 and reviews["reviews"][0]["evidence_packet_sha256"]
              and reviews["reviews"][0]["raw_incident_sha256"] and reviews["reviews"][0]["ai_final_disposition"] == "benign_expected",
              f"decisions={[r['decision'] for r in reviews['reviews']]}")

        # canonical downstream: real handoff writers
        run_id = wss.get_state(case)["run_id"]
        tri_ds = sw._attach_triage_review(persisted(case), case, run_id)
        path = sw.handoff_to_investigation(tri_ds, sw.load_raw_incident_for_run(case, run_id) or slim(case))
        alert = json.loads(Path(path).read_text(encoding="utf-8"))
        check("investigation alert file carries triage_review (analyst = canonical)",
              alert.get("triage_review", {}).get("final_disposition") == "benign_expected"
              and alert["triage_review"]["analyst"] == "Alice", Path(path).name)
        tid = sw.handoff_to_reporting(tri_ds, slim(case), None, incident_id=case, run_id=run_id, reporting_stage_attempt=1)
        tdoc = json.loads((sw.reporting_attempt_dir(case, run_id, 1) / "outputs" / "triage_result.json").read_text(encoding="utf-8"))
        check("reporting triage_result.json carries triage_review; classification unchanged",
              tdoc.get("triage_review", {}).get("final_disposition") == "benign_expected"
              and tdoc["classification"] == persisted(case)["ticket"]["classification"])
        rep = client.get(f"/api/cases/{case}/reports")
        ticket_row = (rep.get_json() or {}).get("triage_ticket") if rep.status_code == 200 else None
        blocks_text = json.dumps((ticket_row or {}).get("blocks") or [])
        check("ticket export blocks show 'AI: X -> Analyst: Y'",
              "AI: Benign-expected -> Analyst: Benign-expected" in blocks_text, f"HTTP {rep.status_code}")

        # suppression lifecycle over HTTP
        pid = body["suppression_proposal_id"]
        p = client.get("/api/triage/suppressions").get_json()["items"][0]
        selfapp = client.post(f"/api/triage/suppressions/{pid}/approve", json={"analyst": "Alice", "confirmation": p["scope_text"]})
        wrong = client.post(f"/api/triage/suppressions/{pid}/approve", json={"analyst": "Bob", "confirmation": "yes"})
        good = client.post(f"/api/triage/suppressions/{pid}/approve", json={"analyst": "Bob", "confirmation": p["scope_text"]})
        check("suppression: self-approval 403, wrong scope 403, typed scope by 2nd analyst approved",
              selfapp.status_code == 403 and wrong.status_code == 403 and good.get_json()["status"] == "approved",
              p["scope_text"])

        # A NEW triage of the same masquerade incident (no note): suppression
        # matches, but never satisfies the strong-signal floor.
        ctx = sw.run_until_triage_approval(slim(case), use_mock_triage=False, allow_retry=True)
        tri3 = persisted(case)
        sm = tri3["evidence_packet"]["context"]["suppression_match"]
        a3 = tri3["assessment"]
        check("new run: context.suppression_match measured (approved by Bob) but ignored_for_guards",
              sm["status"] == "measured" and "approved by Bob" in sm["source"] and sm["value"]["ignored_for_guards"] is True,
              (sm.get("value") or {}).get("ignored_reason", "")[:80])
        check("new run: suppression NEVER satisfies the masquerade floor -> needs_info (not auto-closed)",
              a3["disposition"] == "needs_info" and any(g["rule"] == "b_strong_signal_floor" for g in a3["guard_actions"])
              and wss.get_state(case)["triage_status"] == "Awaiting Approval")

        # =============== INC-40000: FP -> tuning backlog =====================
        case2 = "INC-40000"
        sw.run_until_triage_approval(slim(case2), use_mock_triage=False, allow_retry=True)
        fp = client.post(f"/api/cases/{case2}/approvals/triage", json={
            "decision": "approve", "analyst": "Carol", "review": {
                "analyst_disposition": "false_positive", "evidence_checked": ["detection", "baseline"],
                "justification": "Rule fires on the backup job.", "lookalike_considered": "data staging",
                "rule_tuning_note": "Exclude the backup service account from this ESA rule",
                "disagreement_reason": "rule broken"}})
        check("HTTP approve with false_positive review (old gate semantics intact)",
              fp.status_code == 200 and wss.get_state(case2)["triage_status"] == "Approved"
              and wss.get_state(case2)["threat_intel_status"] == "Pending")
        bl = client.get("/api/triage/tuning-backlog").get_json()
        check("tuning backlog shows the FP with its note", bl["count"] == 1
              and "backup service account" in bl["items"][0]["tuning_notes"][0])
        nr = client.get("/api/triage/noisy-rules?limit=5").get_json()
        check("noisy rules measured from the (read-only) incidents copy", nr["status"] == "measured" and nr["pairs"],
              nr["reason"])

        # =============== X6: blind review + metrics =========================
        br = _load("_acc3_blind", ROOT / "scripts" / "blind_review.py")
        exp = br.export(tmp / "blind", 10, 7, "disposition")
        html = Path(exp["html"]).read_text(encoding="utf-8").split("</p>", 1)[1]
        check("blind export: no AI/analyst disposition in any case",
              not any(d in html for d in ("true_positive", "false_positive", "benign_expected", "needs_info")),
              f"{exp['cases']} cases")
        rows = list(csv.DictReader(Path(exp["csv"]).read_text(encoding="utf-8").splitlines()))
        lab = tmp / "lab.csv"
        with lab.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            for r in rows:
                r.update(disposition="needs_info", evidence_note="n", reviewer="Mentor")
                w.writerow(r)
        imp = br.import_csv(lab)
        m = client.get("/api/triage/metrics").get_json()
        check("blind import + /api/triage/metrics: kappa pairs + small-sample caveat",
              imp["imported"] == len(rows) and m["n_mentor_labelled"] == len(rows) and m["small_sample"]
              and "analyst_vs_mentor" in m["pairs"], f"n={m['n_reviews']} override={m['override_rate']}")
        print("\nSample metrics:", json.dumps({k: m[k] for k in ("n_reviews", "override_rate", "guard_intervention_rate",
                                                                 "needs_info_rate", "label_provenance")}),
              json.dumps({k: (v["n"], v["kappa"]) for k, v in m["pairs"].items()}))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    soc_after = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in SOC_DB.parent.glob("*.db")}
    check("soc_db/*.db not modified", soc_before == soc_after)
    failed = [x for x in RESULTS if not x[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} acceptance checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
