"""tests/test_investigation_correlated_timeline.py -- canonical audit Phase 2D.

The Investigation model timeline is structured by case: the CURRENT CASE (the
Investigation subject, whole) first, then labelled CORRELATED HISTORICAL
CASES -- identical repeated entries collapsed, materially different versions
summarised, ranked by existing deterministic signals, bounded with explicit
omission counts. Correlation itself, the persisted cluster, policy/risk
inputs and the Reporting contract are unchanged. No LLM, no subprocess, no
network.
"""
from __future__ import annotations

import asyncio
import copy
import importlib.util
import sys
import types
from pathlib import Path

import pytest

from workflow import engine as wf

INV_DIR = Path(__file__).resolve().parent.parent / "agents" / "investigation"
if str(INV_DIR) not in sys.path:
    sys.path.insert(0, str(INV_DIR))
import ingest_pipeline as ip  # noqa: E402
import timeline_context as tc  # noqa: E402

CASE = "INC-53011"
HIST = "INC-52825"
HIST_2 = "INC-52901"
PLAYBOOK = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")
LEGACY_DOC = ("Incident {id} details are as follows: === THREAT INTELLIGENCE SUMMARY === Risk Level: Low "
              "Risk Score: 0 The classification alert type is Unknown Source IP. The classification severity "
              "is {sev}. The classification triage risk rating rationale is " + "Rationale prose. " * 120
              + "The endpoint indicators hostname is {host}. Incident {id} contains 2 correlated alert(s): "
              "Alert #1 - 'Beacon' at [t] Severity: Medium, User: x. The network indicators source ip "
              "address is {ip}. The incident details title is {title}.")


def _entry(case_id, epoch, doc="doc", **meta):
    base = {"timestamp_epoch": epoch, "timestamp_str": f"2025-07-14T10:{epoch % 60:02d}:00+00:00",
            "incident_id": case_id, "source_type": "Network", "ips": "", "sha256s": "", "md5s": "",
            "hostname": "Unknown", "username": "Unknown", "tactic": "Discovery", "technique": "Unknown"}
    base.update(meta)
    return {"id": case_id, "document": doc, "metadata": base}


def _legacy(case_id, epoch, *, sev="MEDIUM", host="KELLYWANG", ip="192.168.10.204", **meta):
    doc = LEGACY_DOC.format(id=case_id, sev=sev, host=host, ip=ip, title=f"Title of {case_id}")
    return _entry(case_id, epoch, doc, severity=sev, ips=meta.pop("ips", ip),
                  hostname=meta.pop("hostname", host), **meta)


def _current_doc(supplement=None):
    triage = {"ticket": {"incident_id": CASE, "classification": "HIGH", "title": "Current case",
                         "incident_category": "Malware", "summary": "Current case triage."},
              "metakeys_payload": {"incident_id": CASE, "incident_title": "Current case",
                                   "metakey_values": {"ip.src": "192.168.10.204", "host.name": "KELLYWANG"}}}
    alert = wf.build_investigation_alert(triage, {"id": CASE, "alerts": []}, supplement=supplement)
    doc = ip.serialize_json_to_narrative(alert)
    return doc[:12000] + " [TRUNCATED]" if len(doc) > 12000 else doc


def _current(epoch=200, supplement=None):
    return _entry(CASE, epoch, _current_doc(supplement), severity="HIGH", ips="192.168.10.204",
                  hostname="KELLYWANG", tactic="Execution")


def _build(entries, subject=CASE, **kw):
    return tc.build_case_timeline(entries, subject, **kw)


# ── orchestrator (Pass 1 / Pass 2) fixture ──────────────────────────────────

def _install_stub(monkeypatch, name, **attrs):
    stub = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(stub, k, v)
    monkeypatch.setitem(sys.modules, name, stub)


@pytest.fixture
def orch(monkeypatch, tmp_path):
    _install_stub(monkeypatch, "vector_engine")
    _install_stub(monkeypatch, "chroma_compat", open_persistent_collection=lambda *a, **k: (None, False))
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location("_orch_2d", INV_DIR / "orchestrator.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    module.calls = {"p1": [], "p2": [], "retrieve": [], "compliance": []}

    class _Chain:
        def __init__(self, name, respond):
            self.name, self.respond = name, respond

        async def ainvoke(self, payload):
            module.calls[self.name].append(dict(payload))
            return self.respond(payload)

    monkeypatch.setattr(module, "get_chain_p1", lambda: _Chain("p1", lambda p: types.SimpleNamespace(
        execution_trace=[], suggested_pivots=[])))
    monkeypatch.setattr(module, "get_chain_p2", lambda: _Chain("p2", lambda p: module.FinalIncidentAnalysis(
        incident_id=HIST, severity="High", confidence="Medium", execution_trace=[],     # model echoes a wrong id
        incident_summary="s", actions_taken=[], recommended_containment=["Isolate host"],
        business_impact_checklist=module.BusinessImpactChecklist(
            critical_system="no", essential_service="no", data_sensitivity="no", operational_impact="no"),
        severity_justification="j", confidence_justification="j", policy_audit_logs=[])))

    def _retrieve(text, limit=2):
        module.calls["retrieve"].append(text)
        return []

    def _compliance(**kw):
        module.calls["compliance"].append(kw)
        return {"escalation_required": False, "modified_containment": kw["recommended_containment"],
                "audit_records": []}
    monkeypatch.setattr(module, "get_policy_manager", lambda: (
        types.SimpleNamespace(get_section=lambda k: None), types.SimpleNamespace(retrieve=_retrieve)))
    monkeypatch.setattr(module, "run_policy_compliance_rules", _compliance)
    return module


def _both_passes(orch, alerts, subject=CASE, ctx=None):
    async def go():
        p1 = await orch.analyze_alert_group_p1(alerts, PLAYBOOK, subject_id=subject, timeline_context=ctx)
        return await orch.compile_final_report(alerts, PLAYBOOK, p1["execution_trace"], subject_id=subject,
                                               timeline_context=ctx)
    return asyncio.run(go())


# ── 1-3: labelling and canonical subject ────────────────────────────────────

def test_01_current_case_is_explicitly_labelled():
    text, _ = _build([_legacy(HIST, 100), _current()])
    assert text.startswith(tc.TIMELINE_HEADER)
    assert f"Investigation subject: {CASE}." in text
    assert f"=== CURRENT CASE: {CASE} (Investigation subject) ===" in text
    assert f"[CURRENT CASE: {CASE}]" in text
    assert text.count("[CURRENT CASE:") == 1


def test_02_correlated_cases_are_explicitly_labelled():
    text, meta = _build([_legacy(HIST, 100), _legacy(HIST_2, 150), _current()])
    assert "=== CORRELATED HISTORICAL CASES (supporting evidence; NOT the Investigation subject) ===" in text
    assert f"[CORRELATED CASE: {HIST}]" in text and f"[CORRELATED CASE: {HIST_2}]" in text
    assert f"[CURRENT CASE: {HIST}]" not in text
    assert meta["correlated_cases"] == 2


def test_03_current_case_remains_the_canonical_subject(orch):
    alerts = [_legacy(HIST, 100), _current()]                 # historical member FIRST in the cluster
    report = _both_passes(orch, alerts)
    assert orch.calls["p1"][0]["incident_id"] == CASE and orch.calls["p2"][0]["incident_id"] == CASE
    assert report.incident_id == CASE                         # pinned although the model echoed HIST
    timeline = orch.calls["p2"][0]["timeline"]
    assert timeline.index(f"[CURRENT CASE: {CASE}]") < timeline.index(f"[CORRELATED CASE: {HIST}]")
    with pytest.raises(ValueError):
        _build([_legacy(HIST, 100)], subject=CASE)            # subject must be in the group


# ── 4-5: historical evidence reaches both passes ────────────────────────────

def test_04_05_historical_evidence_reaches_pass_1_and_pass_2(orch):
    alerts = [_legacy(HIST, 100), _current()]
    _both_passes(orch, alerts, ctx={"correlation": {"cluster_id": "Incident-001", "decision": "MERGE",
                                                    "score": 0.73}})
    p1, p2 = orch.calls["p1"][0]["timeline"], orch.calls["p2"][0]["timeline"]
    assert p1 == p2                                            # same bounded, labelled timeline
    for timeline in (p1, p2):
        assert f"[CORRELATED CASE: {HIST}]" in timeline
        assert f"The endpoint indicators hostname is KELLYWANG" in timeline
        assert "merged into existing correlation cluster Incident-001 (Tier-1 MERGE, cluster-level " \
               "correlation score 0.730)" in timeline


# ── 6-8: duplicates, versions, current-case copy ────────────────────────────

def test_06_identical_historical_duplicates_collapse():
    a = _legacy(HIST, 100, ips="192.168.10.204,224.0.0.251")
    b = copy.deepcopy(a)
    b["metadata"]["ips"] = "224.0.0.251,192.168.10.204"       # list order is not a difference
    b["document"] = b["document"].replace(" ", "  ")           # nor is whitespace
    text, meta = _build([a, b, copy.deepcopy(a), copy.deepcopy(a), _current()])
    assert meta["duplicates_collapsed"] == 3
    assert f"[CORRELATED CASE: {HIST}] (historical; 4 cluster entries; 3 identical repeats collapsed)" in text
    assert text.count("The endpoint indicators hostname is KELLYWANG") == 1
    assert "Earlier version" not in text


def test_07_materially_different_versions_of_one_case_are_retained():
    v1 = _legacy(HIST, 100, sev="MEDIUM", tactic="Execution")
    v2 = _legacy(HIST, 100, sev="LOW", tactic="Initial Access")
    v2["document"] += " The triage deep dive gap findings step 4 is answered."
    text, meta = _build([v1, v2, _current()])
    assert meta["duplicates_collapsed"] == 0
    assert "2 distinct versions, latest shown" in text
    line = next(l for l in text.splitlines() if "Earlier version 1 differs in:" in l)
    assert "Triage severity MEDIUM (latest: LOW)" in line
    assert "tactic Execution (latest: Initial Access)" in line
    assert "deep-dive supplement absent (latest: present)" in line
    assert "The classification severity is LOW" in text       # latest version's evidence


def test_08_current_case_feedback_copy_is_not_collapsed_or_replaced():
    pass1 = _current()
    feedback = _current(supplement={"feedback_pass": 1, "requested_gaps": ["step_2: process tree"],
                                    "gap_findings": {"step_2: process tree": "FEEDBACK-ANSWER-TOKEN"}})
    # the cluster as Phase 1's merge_alert_into_cluster leaves it (newest copy in place)
    text, meta = _build([_legacy(HIST, 100), feedback])
    assert "FEEDBACK-ANSWER-TOKEN" in text and meta["current_superseded"] == 0
    # even if two copies of the subject were present, the newest is used, never collapsed into history
    text2, meta2 = _build([pass1, _legacy(HIST, 100), feedback])
    assert "FEEDBACK-ANSWER-TOKEN" in text2 and meta2["current_superseded"] == 1
    assert "1 earlier copy of the current case in this group superseded" in text2
    assert meta2["duplicates_collapsed"] == 0 and meta2["correlated_cases"] == 1


# ── 9-13: budget ────────────────────────────────────────────────────────────

def _large_cluster(n=60, current=None):
    entries = [_legacy(f"INC-6{i:04d}", 1000 + i, ip=f"10.1.{i // 250}.{i % 250}",
                       host=f"HOST-{i}") for i in range(n)]
    entries += [copy.deepcopy(entries[i]) for i in range(0, n, 3)]          # historical repeats
    entries.insert(n // 2, current or _current(epoch=1030))
    return entries


def test_09_10_11_current_case_brief_and_deep_dive_answers_always_survive():
    current = _current(epoch=1030, supplement={
        "feedback_pass": 1, "requested_gaps": ["step_2: process tree"],
        "gap_findings": {"step_2: process tree": "DEEP-DIVE-ANSWER-TOKEN"}})
    text, meta = _build(_large_cluster(current=current))
    assert current["document"] in text                         # whole, not excerpted
    assert wf.INVESTIGATION_BRIEF_HEADER in text and wf.INVESTIGATION_BRIEF_FOOTER in text
    assert "[DEEP-DIVE ANSWERS (feedback pass)]" in text and "DEEP-DIVE-ANSWER-TOKEN" in text
    assert text.index(current["document"]) < text.index("=== CORRELATED HISTORICAL CASES")
    assert meta["omitted"]                                      # history was what got cut


def test_12_large_historical_cluster_is_bounded():
    entries = _large_cluster()
    legacy_size = sum(len(e["document"]) for e in entries)
    text, meta = _build(entries)
    assert meta["historical_chars"] <= tc.HISTORICAL_BUDGET + 200
    assert len(text) <= meta["current_chars"] + tc.HISTORICAL_BUDGET + 200
    assert len(text) < legacy_size / 3


def test_13_omitted_historical_cases_are_counted_explicitly():
    text, meta = _build(_large_cluster())
    n = meta["correlated_cases"]
    assert n == 60 and len(meta["full"]) + len(meta["summarised"]) + len(meta["omitted"]) == n
    assert (f"Showing {len(meta['full'])} of 60 correlated cases in full, {len(meta['summarised'])} as "
            f"one-line summaries (+{len(meta['omitted'])} additional historical cases omitted from model "
            "context)") in text
    assert f"(+{len(meta['omitted'])} additional historical cases omitted from model context: " in text
    assert meta["duplicates_collapsed"] == 20 and "20 identical repeated entries collapsed" in text


# ── 14-16: determinism, timestamps, no false chronology ─────────────────────

def test_14_selection_and_order_are_deterministic():
    entries = _large_cluster()
    assert _build(entries) == _build(copy.deepcopy(entries))
    # ranking: shared indicators with the current case first, then time proximity
    near_no_share = _legacy(HIST, 201, ip="10.9.9.9", host="OTHER")
    far_shared = _legacy(HIST_2, 5000, ip="192.168.10.204", host="OTHER")
    text, meta = _build([near_no_share, far_shared, _current(epoch=200)])
    assert meta["full"] == [HIST_2, HIST]
    assert "indicators shared with the current case (1): 192.168.10.204" in text


def test_15_timestamps_stay_with_their_own_case():
    hist = _legacy(HIST, 100)
    hist["metadata"]["timestamp_str"] = "2025-07-14T11:21:34+00:00"
    current = _current()
    current["metadata"]["timestamp_str"] = "2025-12-01T08:59:00+00:00"
    text, _ = _build([hist, current])
    assert f"[2025-12-01T08:59:00+00:00] [CURRENT CASE: {CASE}]" in text
    block = text.split(f"[CORRELATED CASE: {HIST}]")[1]
    assert block.splitlines()[1].strip() == "Case time: 2025-07-14T11:21:34+00:00 (this case's own time)"


def test_16_no_cross_case_chronology_is_implied():
    later_hist = _legacy(HIST, 900)                           # historical case AFTER the current case
    text, _ = _build([_current(epoch=200), later_hist])
    assert "Alert Entry #" not in text                         # no single cross-case sorted list
    assert "do not read timestamps across different cases as one continuous chain or as cause and effect" in text
    assert text.index(f"[CURRENT CASE: {CASE}]") < text.index(f"[CORRELATED CASE: {HIST}]")


# ── 17-18: terminology and legacy formats ───────────────────────────────────

def test_17_correlated_alert_terminology_collision_is_removed():
    doc = ip.serialize_json_to_narrative({"incident_id": CASE, "alerts": [{"title": "a"}, {"title": "b"}]})
    assert f"Incident {CASE} has 2 NetWitness sub-alert record(s) (this case's own source alerts):" in doc
    assert "correlated alert" not in doc
    text, _ = _build([_legacy(HIST, 100), _current()])        # stored legacy text renamed for the model
    assert "correlated alert(s)" not in text
    assert "has 2 NetWitness sub-alert record(s) (this case's own source alerts):" in text


def test_18_legacy_and_canonical_historical_formats_are_handled_and_labelled():
    canonical_hist = _current()
    canonical_hist["id"] = HIST_2
    sparse = {"id": "INC-50000", "document": "", "metadata": {}}             # minimal old entry
    text, meta = _build([_legacy(HIST, 100), canonical_hist, sparse, _current()])
    legacy_block = text.split(f"[CORRELATED CASE: {HIST}]")[1].split("[CORRELATED CASE")[0]
    assert "legacy narrative format (pre-canonical handoff" in legacy_block
    assert "lower evidential quality than the current case's Context Brief" in legacy_block
    assert "The endpoint indicators hostname is KELLYWANG" in legacy_block       # evidence kept first
    assert "statements of this historical document omitted from model context" in legacy_block
    assert "canonical Context Brief format" in text.split(f"[CORRELATED CASE: {HIST_2}]")[1]
    assert "INC-50000" in text and "not recorded" in text and meta["correlated_cases"] == 3


# ── 19-25 + regressions ─────────────────────────────────────────────────────

def test_cli_without_subject_keeps_the_legacy_timeline(orch):
    alerts = [_legacy(HIST, 100), _current()]
    assert orch.build_model_timeline(alerts, None) == orch.build_timeline_text(alerts)
    assert orch.build_model_timeline(alerts, "INC-NOT-HERE") == orch.build_timeline_text(alerts)


def test_pivot_retrieved_entries_are_labelled_as_such():
    text, meta = _build([_current(), _legacy(HIST, 100)], pivot_ids=[HIST])
    assert "added by Pass-1 pivot retrieval (not a cluster member)" in text
    assert meta["pivot_entries"] == [HIST]


def test_23_agent_activity_timeline_line_keeps_the_subject(tmp_path):
    from observability import context, emitter
    from observability.adapters.investigation_adapter import _LogReader
    from observability.store import ActivityStore, query_events

    store = ActivityStore(tmp_path / "a.db")
    emitter.attach_store(store)
    token = context.set_scope(context.RunScope(case_id=CASE, run_id="run-t", stage="investigation",
                                               data={"run_no": 1}))
    try:
        reader = _LogReader(context.current_scope(), "runspan")
        reader.feed(f"\x1b[96m[*] Investigation timeline (Pass 1) for subject {CASE}: 10 correlated case(s) "
                    "as supporting evidence -- 6 in full, 4 summarised, 0 omitted; 3 identical repeated "
                    "entries collapsed; 19833 chars\x1b[0m")
    finally:
        context.reset_scope(token)
    assert store.flush()
    event = query_events(case_id=CASE, path=store.path)[0]
    assert event["title"] == "Pass 1 timeline: 10 correlated case(s) as supporting evidence"
    assert event["detail"].startswith(f"Investigation subject remains {CASE} · 6 in full")
    assert reader.unclassified == 0
    emitter.detach_store()
    store.close()


def test_24_full_data_is_preserved_and_report_schema_unchanged(orch):
    alerts = _large_cluster(20)
    snapshot = copy.deepcopy(alerts)
    report = _both_passes(orch, alerts)
    assert alerts == snapshot                                   # cluster entries untouched
    assert set(type(report).model_fields) == set(orch.FinalIncidentAnalysis.model_fields)
    assert report.incident_id == CASE


def test_25_policy_and_risk_inputs_are_unchanged(orch):
    alerts = [_legacy(HIST, 100, host="ransomware-host"), _current()]
    _both_passes(orch, alerts)
    legacy = orch.build_timeline_text(alerts)
    assert orch.calls["compliance"][0]["timeline_text"] == legacy      # escalation/containment input
    assert orch.calls["retrieve"] == [legacy]                          # policy grounding query
    assert orch.calls["p2"][0]["timeline"] != legacy                   # only the model view changed
