"""tests/test_parsing_alerts_identity_r1.py -- R1 Parsing identity guard.

A bare workflow incident carrying alerts[] ({"id": "INC-X", ..., "alerts":
[...]}) is parsed as ONE aggregate record whose id is the incident id, but
the input fingerprint used to take alerts[0]._id as the alert identity, so
the hard alert_id check compared a child alert id against the case id and
every such incident failed Parsing ("Parser input mismatch").

R1 makes extract_alert_identity() pick the same primary record the parser
does. Child alert ids / incidentId back-references are kept as provenance;
a differing child incidentId is a warning only. Phase 5 case identity is
unchanged (only a match passes), and so is aggregation and every alert
object handed downstream.

Real parser + real workflow persistence on temporary DB/output roots; no
LLM, no provider calls, no network (sockets blocked), and any connect aimed
at the real soc_db/ is redirected and recorded.
"""
from __future__ import annotations

import copy
import json
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

import agents.investigation.skills_sidecar as skills_sidecar
import agents.parsing.parser_normaliser as pn
from agents.parsing.parser_context_guard import extract_alert_identity, validate_parser_identity
from agents.reporting.reporting.context_builder import build_context
from agents.threat_intelligence import threat_intel as ti
import canonical_seed as seed
from workflow import engine as wf
from workflow import readiness as wr
from workflow import state_store as wss
from workflow import validation as wv

CASE = "INC-R1-0001"
_REAL_SOC_DB = (Path(wf.ROOT) / "soc_db").resolve()
_REAL_EXPORT = Path(wf.ROOT) / "demo" / "incident_INC-53021_respond_api_export.json"


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 1, 1, tzinfo=timezone.utc) if tz else datetime(2026, 1, 1)


@pytest.fixture(autouse=True)
def real_db_attempts(tmp_path, monkeypatch):
    """Redirect (and record) any connect aimed at the real soc_db/ directory."""
    attempts: list[str] = []
    real_connect = sqlite3.connect

    def guarded(database, *args, **kwargs):
        text = str(database)
        text = text[5:].split("?", 1)[0] if text.startswith("file:") else text
        try:
            target = Path(text).resolve()
        except Exception:
            target = None
        if target is not None and _REAL_SOC_DB in target.parents:
            attempts.append(str(target))
            redirected = tmp_path / "redirected_soc_db" / target.name
            redirected.parent.mkdir(exist_ok=True)
            kwargs.pop("uri", None)
            return real_connect(str(redirected), *args, **kwargs)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", guarded)
    return attempts


@pytest.fixture(autouse=True)
def network_attempts(monkeypatch):
    """Any outbound socket connect is refused and recorded."""
    attempts: list = []

    def refuse(self, address, *args, **kwargs):
        attempts.append(address)
        raise OSError(f"network blocked in R1 tests: {address!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    return attempts


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch, real_db_attempts, network_attempts):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(wf, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", tmp_path / "trusted")
    monkeypatch.setattr(wf, "REP_DIR", tmp_path / "rep")
    monkeypatch.setattr(wf, "enrich_incident_with_apiretrieval_fetch",
                        lambda incident, host=None, token=None: incident)
    monkeypatch.setattr(wf, "generate_parsing_ai_summary", lambda result: {})   # no LLM
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: {"available": False})
    monkeypatch.setattr(pn, "datetime", _FrozenDatetime)
    wss.db_init()


# ── fixtures shaped like the real NetWitness Respond export ──────────────────

def _child(tag, incident_id=CASE):
    """One attached alert in the real Respond schema: Mongo _id, incidentId
    back-reference, originalHeaders, and per-event meta (list-valued, as
    NetWitness Endpoint emits it) under originalAlert.events."""
    return {
        "_id": f"ALERT-{tag}", "incidentId": incident_id, "receivedTime": "2025-12-01T07:33:39.338Z",
        "originalHeaders": {"name": f"Alert {tag}", "severity": 90},
        "originalAlert": {"severity": 90, "moduleName": f"Module {tag}", "events": [{
            "ip_src": f"10.1.1.{ord(tag) % 250}", "ip_dst": f"203.0.113.{ord(tag) % 250}",
            "alias_host": [f"HOST-{tag}"], "param_src": [f"cmd.exe /c whoami-{tag}"],
            "checksum_src": [f"{ord(tag):064x}"],
        }]},
    }


def _incident(case=CASE, children=None, **extra):
    """The real workflow shape: a bare NetWitness incident record (no
    "incident" wrapper), optionally with attached alerts[]."""
    incident = {
        "id": case, "title": "High Risk Alerts: NetWitness Endpoint for WIN-HOST-1",
        "riskScore": 80, "severity": "High",
        "alertMeta": {"SourceIp": ["10.0.0.5"], "DestinationIp": ["203.0.113.9"]},
    }
    if children is not None:
        incident["alerts"] = children
    incident.update(extra)
    return incident


def _one():
    return _incident(children=[_child("A")])


def _three():
    return _incident(children=[_child("A"), _child("B"), _child("C")])


def _parse_direct(raw, tmp_path, expected=CASE, name="p"):
    return pn.run_parser_normalisation_for_dashboard(copy.deepcopy(raw), tmp_path / name, expected_case_id=expected)


def _parse(incident):
    ctx = wf.run_until_triage_approval(copy.deepcopy(incident), allow_retry=True, parsing_only=True)
    return ctx, ctx.get("run_id")


def _envelope(case=CASE):
    return json.loads(wss.get_state(case)["parsing_result_json"])


def _json(value):
    return json.loads(json.dumps(pn.make_json_safe(value)))


def _reference(incident, tmp_path):
    """Extraction recomputed independently of the identity guard."""
    normalised = pn.build_standard_alert(copy.deepcopy(incident), output_dir=str(tmp_path / "ref"))["normalised_alert"]
    return _json(normalised), _json(pn.build_agent_friendly_processed_alert(normalised))


def _checks(result):
    return {c["field"]: c for c in result["identity_validation"]["checks"]}


def _triage(case=CASE):
    return {"ticket": {"incident_id": case, "unc": "#00077A", "classification": "HIGH", "title": "Case"},
            "metakeys_payload": {"incident_id": case, "incident_title": "Case"}}


# ── 1-4: every alerts[] shape now parses; case identity is a match ──────────

@pytest.mark.parametrize("make, events", [
    (lambda: _incident(), 0),                       # 1 bare, no alerts
    (lambda: _incident(children=[]), 0),            # 2 alerts: []
    (_one, 1),                                      # 3 one child
    (_three, 3),                                    # 4 several children
], ids=["bare", "empty_alerts", "one_child", "three_children"])
def test_bare_incident_shapes_parse_with_case_identity_match(make, events, tmp_path):
    result = _parse_direct(make(), tmp_path)
    assert result["status"] == "completed", result["identity_validation"]
    assert result["identity_validation"]["hard_failures"] == []
    assert (result["case_identity"]["status"], result["case_identity"]["basis"]) == (
        "match", "bare_incident_record_id")
    assert result["incident_id"] == CASE
    assert (result["input_shape"], result["normalised_alert_count"], result["event_count"]) == (
        "generic_dictionary", 1, events)
    assert _checks(result)["alert_id"]["outcome"] == "match"


def test_empty_alert_list_behaves_exactly_like_a_bare_incident(tmp_path):
    bare = _parse_direct(_incident(), tmp_path, name="a")
    empty = _parse_direct(_incident(children=[]), tmp_path, name="b")
    assert empty["input_identity"] == bare["input_identity"]
    assert "child_alert_ids" not in empty["input_identity"]
    assert empty["identity_validation"] == bare["identity_validation"]
    assert empty["normalised_alert"] == bare["normalised_alert"]


# ── 5-8: the case id stays the record identity; children are provenance ─────

def test_no_child_alert_id_replaces_the_case_id(tmp_path):
    result = _parse_direct(_three(), tmp_path)
    child_ids = ["ALERT-A", "ALERT-B", "ALERT-C"]
    assert result["input_identity"]["alert_id"] == CASE
    assert result["selected_alert_id"] == CASE
    assert result["normalised_alert"]["alert_summary"]["alert_id"] == CASE
    assert result["raw_record_id"] == CASE
    assert result["case_identity"]["parsed_case_reference"] == CASE
    for field in ("incident_id", "selected_alert_id", "raw_record_id"):
        assert result[field] not in child_ids
    # Child identities are preserved, in order, as provenance only.
    assert result["input_identity"]["child_alert_ids"] == child_ids
    assert result["input_identity"]["child_alert_incident_ids"] == [CASE]
    assert _checks(result)["child_alert_incident_id"]["outcome"] == "match"


def test_child_identity_is_never_an_ioc_or_alert_object_field(tmp_path):
    result = _parse_direct(_three(), tmp_path)
    blob = json.dumps([result["processed_alert"], result["normalised_alert"]])
    assert not any(f"ALERT-{tag}" in blob for tag in "ABC")


# ── 9-10: attached-alert evidence is still aggregated ───────────────────────

def test_attached_alert_events_and_indicators_are_preserved(tmp_path):
    result = _parse_direct(_three(), tmp_path)
    normalised, processed = result["normalised_alert"], result["processed_alert"]
    network = normalised["network_indicators"]
    assert {"10.1.1.65", "10.1.1.66", "10.1.1.67"} <= set(network["source_ips"])
    assert {"203.0.113.65", "203.0.113.66", "203.0.113.67"} <= set(network["destination_ips"])
    assert normalised["alert_summary"]["raw_event_count"] == 3
    commands = json.dumps(normalised["process_indicators"]["command_lines"])
    assert all(f"whoami-{tag}" in commands for tag in "ABC")
    hashes = set(normalised["file_indicators"]["file_hashes"])
    assert {f"{ord(tag):064x}" for tag in "ABC"} <= hashes
    assert processed["command_line"]


def test_extraction_is_independent_of_the_identity_verdict(tmp_path):
    for incident in (_one(), _three()):
        result = _parse_direct(incident, tmp_path)
        reference_normalised, reference_processed = _reference(incident, tmp_path)
        assert result["normalised_alert"] == reference_normalised
        assert result["processed_alert"] == reference_processed


# ── 11-13: wrong-case protection is unchanged ───────────────────────────────

def test_wrong_top_level_case_still_fails(tmp_path):
    # Expected INC-A, raw incident is INC-B (children consistent with INC-B).
    raw = _incident(case="INC-B", children=[_child("A", "INC-B")])
    result = _parse_direct(raw, tmp_path, expected="INC-A")
    assert result["status"] == "failed"
    assert result["case_identity"]["status"] == "mismatch"
    assert result["case_identity"]["parsed_case_reference"] == "INC-B"
    assert result["identity_validation"]["hard_failures"] == ["case_id"]
    assert "incident_id" not in result


def test_bare_wrong_case_without_alerts_still_fails(tmp_path):
    result = _parse_direct(_incident(case="INC-B"), tmp_path, expected="INC-A")
    assert result["status"] == "failed"
    assert result["case_identity"]["status"] == "mismatch"


def test_case_identity_not_available_still_fails_workflow_mode(tmp_path):
    raw = _three()
    raw.pop("id")
    result = _parse_direct(raw, tmp_path)
    assert result["status"] == "failed"
    assert result["case_identity"]["status"] == "not_available"
    assert "case_id" in result["identity_validation"]["hard_failures"]


# ── foreign child incidentId: surfaced, never fatal, never the case ─────────

def test_foreign_child_incident_id_is_a_warning_and_never_the_case(tmp_path):
    raw = _incident(case="INC-X", children=[_child("A", "INC-X"), _child("B", "INC-Y")])
    result = _parse_direct(raw, tmp_path, expected="INC-X")
    # Canonical case remains INC-X and Parsing is not failed by this rule.
    assert result["status"] == "completed"
    assert result["identity_validation"]["passed"] is True
    assert result["identity_validation"]["hard_failures"] == []
    assert result["incident_id"] == "INC-X"
    assert result["case_identity"]["parsed_case_reference"] == "INC-X"
    assert result["selected_alert_id"] == "INC-X"
    assert result["normalised_alert"]["alert_summary"]["alert_id"] == "INC-X"
    assert "INC-Y" not in json.dumps([result["processed_alert"], result["normalised_alert"]])
    # The mismatch is explicitly surfaced as a non-blocking diagnostic.
    assert result["input_identity"]["child_alert_incident_ids"] == ["INC-X", "INC-Y"]
    check = _checks(result)["child_alert_incident_id"]
    assert (check["outcome"], check["severity"], check["hard"]) == ("mismatch", "warning", False)
    assert (check["expected"], check["foreign_incident_ids"]) == ("INC-X", ["INC-Y"])
    assert "child_alert_incident_id" in result["identity_validation"]["warnings"]
    assert result["identity_validation"]["status"] == "passed_with_warnings"


def test_foreign_child_never_rescues_a_wrong_case(tmp_path):
    # Children claiming the expected case cannot make a foreign record pass.
    raw = _incident(case="INC-B", children=[_child("A", "INC-A")])
    result = _parse_direct(raw, tmp_path, expected="INC-A")
    assert result["status"] == "failed"
    assert result["case_identity"]["status"] == "mismatch"
    assert result["case_identity"]["parsed_case_reference"] == "INC-B"


def test_children_without_back_reference_are_not_available_and_non_blocking(tmp_path):
    child = _child("A")
    child.pop("incidentId")
    result = _parse_direct(_incident(children=[child]), tmp_path)
    assert result["status"] == "completed"
    assert _checks(result)["child_alert_incident_id"]["outcome"] == "not_available"


# ── 14: legacy / wrapped shapes keep their existing contract ────────────────

def test_wrapped_incident_with_alerts_keeps_selected_child_identity(tmp_path):
    wrapped = {"incident": {"id": CASE, "title": "Wrapped"},
               "alerts": [{"id": "ALERT-1", "title": "Alert one", "severity": "High"},
                          {"id": "ALERT-2", "title": "Alert two", "severity": "Low"}]}
    identity = extract_alert_identity(wrapped)
    assert (identity["incident_id"], identity["alert_id"]) == (CASE, "ALERT-1")
    assert "child_alert_ids" not in identity
    result = _parse_direct(wrapped, tmp_path)
    assert result["status"] == "completed"
    assert (result["input_shape"], result["normalised_alert_count"]) == ("incident_with_alerts", 2)
    assert (result["case_identity"]["status"], result["case_identity"]["basis"]) == ("match", "parsed_incident_id")
    assert "child_alert_incident_id" not in _checks(result)


def test_dashboard_wrapper_keeps_its_existing_identity():
    wrapper = {"alert_id": "WRAPPER-ALERT",
               "raw": {"incident": {"id": "INC-REAL"}, "alerts": [{"id": "ALERT-REAL"}]}}
    assert extract_alert_identity(wrapper)["alert_id"] == "ALERT-REAL"
    bare_under_wrapper = {"alert_id": "WRAPPER-ALERT", "raw": {"id": "INC-REAL", "alerts": [{"_id": "ALERT-REAL"}]}}
    identity = extract_alert_identity(bare_under_wrapper)
    assert identity["alert_id"] == "ALERT-REAL" and "child_alert_ids" not in identity


@pytest.mark.parametrize("raw", [
    _incident(), _incident(children=[]), _incident(children=[_child("A")]),
    {"incident": {"id": CASE}, "alerts": [_child("A")]},
    {"incident_details": {"id": CASE}, "alerts": [_child("A")]},
    _incident(children=[_child("A")], events=[{"ip_src": "10.9.9.9"}]),
], ids=["bare", "empty", "bare_alerts", "incident", "incident_details", "bare_alerts_events"])
def test_fingerprint_primary_record_agrees_with_parser_record_selection(raw, tmp_path):
    """Drift guard: the fingerprint's alert_id is the record the parser selects."""
    std = pn.build_standard_alert(copy.deepcopy(raw), output_dir=str(tmp_path))
    assert extract_alert_identity(raw)["alert_id"] == std["selected_alert_id"]


def test_full_export_carrying_both_alert_lists_keeps_its_legacy_fingerprint():
    """Characterisation only (not an R1 shape): a full export that also has a
    stray alerts[] still fingerprints alerts[0] while the parser reads
    alerts_full_raw. Pre-existing and deliberately left unchanged by R1."""
    raw = {"incident_raw": {"id": CASE}, "alerts_full_raw": [_child("A")], "alerts": [_child("B")]}
    identity = extract_alert_identity(raw)
    assert (identity["incident_id"], identity["alert_id"]) == (CASE, "ALERT-B")
    assert "child_alert_ids" not in identity


def test_validator_contract_without_expected_case_is_unchanged():
    parsed = {"normalised_alert": {"alert_summary": {"alert_id": "A-1"}}, "selected_alert_id": "A-1"}
    plain = validate_parser_identity({"alert_id": "A-1", "incident_id": None}, parsed)
    assert plain["passed"] is True
    assert "child_alert_incident_id" not in {c["field"] for c in plain["checks"]}


# ── 15-20: canonical envelope, loader, readiness ────────────────────────────

def test_workflow_parse_persists_a_matching_canonical_envelope():
    ctx, run = _parse(_three())
    assert ctx["stages"]["parsing"] == "completed"
    envelope = _envelope()
    assert (envelope["incident_id"], envelope["run_id"]) == (CASE, run)
    assert envelope["case_identity"]["status"] == "match"
    assert envelope["selected_alert_id"] == CASE
    assert envelope["input_identity"]["child_alert_ids"] == ["ALERT-A", "ALERT-B", "ALERT-C"]
    assert ctx["parsing_validation"]["checks_passed"][-1] == "case_identity_match:bare_incident_record_id"


def test_structured_and_flat_views_stay_separate(tmp_path):
    _, run = _parse(_three())
    loaded = wf.load_parsing_result_for_run(CASE, run)
    reference_normalised, reference_processed = _reference(_three(), tmp_path)
    assert loaded["normalised_alert"] == reference_normalised
    assert {"alert_summary", "network_indicators", "process_indicators"} <= set(loaded["normalised_alert"])
    assert loaded["processed_alert"] == reference_processed
    assert loaded["processed_alert"]["current_stage"] == "parsing_normalisation_completed"
    assert isinstance(loaded["processed_alert"]["source_ip"], str)


def test_loader_accepts_the_result_and_rejects_a_foreign_copy():
    _, run = _parse(_three())
    assert wf.load_parsing_result_for_run(CASE, run)["case_identity"]["status"] == "match"
    tampered = _envelope()
    tampered["raw_record_id"] = "INC-FOREIGN"
    tampered["normalised_alert"]["alert_summary"]["alert_id"] = "INC-FOREIGN"
    wss.save_parsing_result(CASE, run, tampered)
    assert wf.load_parsing_result_for_run(CASE, run) is None
    with pytest.raises(wv.ParsingValidationError, match="belongs to case 'INC-FOREIGN'"):
        wv.validate_parsing_result(incident_id=CASE, parsing_result={**tampered, "status": "completed"})


def test_phase6_triage_readiness_accepts_the_newly_valid_result():
    _, run = _parse(_three())
    readiness = wr.evaluate_stage_readiness(CASE, "triage", run_id=run)
    assert readiness["ready"] is True, readiness
    assert readiness["inputs"]["parsing"]["case_identity"]["status"] == "match"


# ── 21-25: downstream subject stays the case ────────────────────────────────

def test_triage_receives_the_aggregate_processed_alert(monkeypatch, tmp_path):
    _, run = _parse(_three())
    captured = {}

    def capture(incident, progress_fn=None, parsed_context=None, force=False):
        captured.update(incident=incident, parsed_context=parsed_context)
        return {"error": "captured by the R1 test"}

    monkeypatch.setattr(wf, "run_triage", capture)
    wss.set_triage_status(CASE, run, "Processing")
    wf.run_triage_stage(CASE, run)
    _, reference_processed = _reference(_three(), tmp_path)
    assert captured["parsed_context"] == reference_processed
    assert captured["parsed_context"]["alert_id"] == CASE
    assert captured["incident"]["id"] == CASE


def test_threat_intel_input_carries_parsing_iocs_but_no_child_ids(monkeypatch, tmp_path):
    _, run = _parse(_three())
    captured = {}

    def capture(incident_id, run_id, normalised_alert, triage_result, incident=None):
        captured.update(incident_id=incident_id, normalised_alert=normalised_alert, incident=incident)
        raise RuntimeError("captured by the R1 test")

    monkeypatch.setattr(wf, "run_threat_intel", capture)
    seed.approve_triage(CASE, run, _triage())
    wss._guarded_update(CASE, run, {"threat_intel_status": "Processing"})
    wf.resume_after_triage_approval(CASE, run)
    assert captured["incident_id"] == CASE
    flat = ti.flatten_alert_for_enrichment(ti._build_flat_alert(captured["incident"], {}, captured["normalised_alert"]))
    iocs = ti.extract_iocs(flat)
    assert {f"{ord(tag):064x}" for tag in "ABC"} <= set(iocs["file_hashes"])
    assert not any(f"ALERT-{tag}" in json.dumps(iocs) for tag in "ABC")


def test_investigation_subject_is_the_case_and_sub_alerts_keep_their_ids():
    _, run = _parse(_three())
    loaded = wf.load_parsing_result_for_run(CASE, run)
    incident = wf.load_raw_incident_for_run(CASE, run)
    alert = wf.build_investigation_alert(_triage(), incident, parsing_result=loaded)
    assert alert["incident_id"] == CASE
    sub_ids = [sub.get("alert_id") for sub in alert.get("alerts") or []]
    assert sub_ids == ["ALERT-A", "ALERT-B", "ALERT-C"]


def test_reporting_case_identity_is_the_case():
    _, run = _parse(_three())
    wf.handoff_to_reporting(_triage(), {"id": CASE},
                            {"agent": "Investigation Agent", "incident_id": CASE, "investigated_for": CASE,
                             "status": "completed", "severity": "High", "confidence": "Medium"},
                            threat_intel_result={"incident_id": CASE, "status": "completed",
                                                 "enrichment_risk_level": "Low", "enrichment_risk_score": 5,
                                                 "warnings": [], "enriched_alert": {"incident_id": CASE, "alert_id": CASE},
                                                 "threat_intelligence": {"indicators": []}},
                            incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    attempt_dir = wf.reporting_attempt_dir(CASE, run, 1)
    read = lambda rel: json.loads((attempt_dir / rel).read_text(encoding="utf-8"))
    handed = read("inputs/processed_alert.json")
    assert handed == _envelope()["processed_alert"]
    context = build_context({
        "processed_alert": handed,
        "enriched_alert": read("inputs/enriched_alert.json"),
        "triage_result": read("outputs/triage_result.json"),
        "investigation_result": read("outputs/investigation_result.json"),
        "threat_intel_result": read("inputs/threat_intel_result.json"),
        "approval_history": read("inputs/approval_history.json"),
        "workflow_metadata": read("inputs/workflow_metadata.json"),
    })
    assert context["incident_id"] == CASE


# ── real data (read-only, skipped when the export is absent) ────────────────

@pytest.mark.skipif(not _REAL_EXPORT.is_file(), reason="real INC-53021 export not present")
def test_real_inc_53021_bare_shape_parses_with_case_match(tmp_path):
    export = json.loads(_REAL_EXPORT.read_text(encoding="utf-8"))
    raw = dict(export["incident"], alerts=export["alerts"])        # the enrichment's bare shape
    result = _parse_direct(raw, tmp_path, expected="INC-53021")
    assert result["status"] == "completed"
    assert result["case_identity"]["status"] == "match"
    assert result["incident_id"] == result["selected_alert_id"] == "INC-53021"
    assert result["input_identity"]["child_alert_ids"] == [a["_id"] for a in export["alerts"]]
    assert result["input_identity"]["child_alert_incident_ids"] == ["INC-53021"]
    assert result["normalised_alert_count"] == 1


# ── 26: isolation ───────────────────────────────────────────────────────────

def test_r1_paths_never_open_the_real_db_or_network(real_db_attempts, network_attempts):
    _, run = _parse(_three())
    wf.load_parsing_result_for_run(CASE, run)
    wr.evaluate_stage_readiness(CASE, "triage", run_id=run)
    assert real_db_attempts == []
    assert network_attempts == []
    assert Path(wss.DB_FILE).parent != _REAL_SOC_DB
