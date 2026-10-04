"""Regression tests for the Aegis stage interaction model across all stages.

Three separate analyst actions, never combined:

    APPROVE  -> unlocks the next stage (backend leaves it "Pending")
    CONTINUE -> navigation only: the workspace selects the next stage, which
                stays "Pending" and shows its own Run <Stage> button
    RUN      -> execution: POST /api/cases/<id>/stages/<key>/runs ->
                commands.start_stage -> wss.begin_stage (Pending ->
                Processing) -> run_stage_chain

Re-running a stage runs that stage only.

Backend side: the real Flask routes, state store, commands adapter and
engine.run_stage_chain dispatcher, with the LLM-backed stage workers
(Triage/Investigation/Reporting) replaced by fakes that write exactly the
status columns their real counterparts write on success. Threat Intelligence
runs for real (provider keys absent -> no network).

Frontend side: the real GET /api/cases/<id>/workflow payload is fed into
frontend/js/stageContinue.js under Node — both the button model the
workspace renders and the actual Continue click binding (with fetch /
XMLHttpRequest stubbed to count any request it might make).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from backend.app import create_app
from workflow import commands
from workflow import engine as sw
from workflow import state_store as wss


ROOT = Path(__file__).resolve().parent.parent
STAGE_CONTINUE_JS = ROOT / "frontend" / "js" / "stageContinue.js"
WORKSPACE_JS = ROOT / "frontend" / "js" / "pages" / "workspace.js"
CASE = "CASE-CONT"

NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

RUN_LABELS = {
    "parsing": "Run Parsing",
    "triage": "Run Triage",
    "threat_intel": "Run Threat Intelligence Enrichment",
    "investigation": "Run Investigation",
    "reporting": "Run Reporting",
}


# ══════════════════════════════════════════════════════════════════════════
# Fixtures / helpers
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _isolated_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    for key in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    # No live NetWitness re-fetch / LLM summary calls in these tests.
    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch",
                        lambda incident, host=None, token=None: incident)
    monkeypatch.setattr(sw, "run_parsing", lambda incident, run_id: _fake_parsing_result())
    monkeypatch.setattr(sw, "generate_stage_ai_summary", lambda *args, **kwargs: {})
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    with wss.db_connect() as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, status, raw_json) VALUES (?, ?, ?, ?, ?)",
            (CASE, "Continue controls", "HIGH", "New",
             json.dumps({"id": CASE, "title": "Continue controls", "alertMeta": {}})),
        )
        connection.commit()
    yield
    with commands._TASKS_LOCK:
        commands._TASKS.clear()


@pytest.fixture
def api(monkeypatch):
    """Flask test client plus a record of every stage start the backend
    ACCEPTED (Pending -> Processing) via the only stage-start command.
    Refused attempts (e.g. a locked stage -> 409) are not starts."""
    starts: list[str] = []
    real_start_stage = commands.start_stage

    def counting_start_stage(case_id, stage, **kwargs):
        result = real_start_stage(case_id, stage, **kwargs)
        starts.append(commands.normalise_stage(stage))
        return result

    monkeypatch.setattr(commands, "start_stage", counting_start_stage)
    app = create_app({
        "TESTING": True,
        "AEGIS_CASE_DB_PATH": wss.DB_FILE,
        "AEGIS_CASE_VIEW_BUILDER": lambda *_: {},
    })
    client = app.test_client()
    client.starts = starts
    return client


def _fake_parsing_result() -> dict:
    return {
        "status": "completed",
        "parser_confidence": "High",
        "summary": "Parsed.",
        "important_extracted_fields": {},
        "missing_important_fields": [],
        "warnings": [],
        "parser_summary_card": {"parser_confidence": "High"},
        "normalised_alert": {"alert_summary": {"raw_event_count": 1}},
        "processed_alert": {"host": "WIN-TEST-01"},
        "output_files": {},
    }


class _Workers:
    """Fake LLM-backed stage workers. Each records its call and writes the
    SAME success status columns the real worker writes via complete_stage()
    (engine.py: run_triage_stage / run_investigation_stage /
    run_reporting_stage). Threat Intelligence is the real worker, wrapped
    only to record the call."""

    def __init__(self, monkeypatch):
        self.calls: list[str] = []
        monkeypatch.setattr(sw, "run_triage_stage", self.triage)
        monkeypatch.setattr(sw, "run_investigation_stage", self.investigation)
        monkeypatch.setattr(sw, "run_reporting_stage", self.reporting)
        real_ti = sw.resume_after_triage_approval

        def threat_intel(case_id, run_id):
            self.calls.append("threat_intel")
            return real_ti(case_id, run_id)

        monkeypatch.setattr(sw, "resume_after_triage_approval", threat_intel)
        # Triage must never run inside the Parsing entry point either.
        monkeypatch.setattr(sw, "run_triage", Mock(side_effect=AssertionError("Parsing ran Triage")))
        monkeypatch.setattr(sw, "mock_triage_result", Mock(side_effect=AssertionError("Parsing ran Triage")))

    def triage(self, case_id, run_id):
        self.calls.append("triage")
        wss.save_triage_result(case_id, run_id, {
            "ticket": {"incident_id": case_id, "unc": "#001", "classification": "high"},
            "metakeys_payload": {"incident_id": case_id, "metakey_values": {}},
        })
        wss._guarded_update(case_id, run_id, {
            "triage_status": "Awaiting Approval", "workflow_status": "Awaiting Approval",
            "approval_stage": "triage",
        })
        return {"status": "awaiting_approval"}

    def investigation(self, case_id, run_id):
        self.calls.append("investigation")
        wss._guarded_update(case_id, run_id, {
            "investigation_status": "Awaiting Approval", "investigation_result_json": "{}",
            "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
        })
        return {"status": "awaiting_approval"}

    def reporting(self, case_id, run_id):
        self.calls.append("reporting")
        wss._guarded_update(case_id, run_id, {
            "reporting_status": "Awaiting Approval", "reporting_result_json": "{}",
            "workflow_status": "Awaiting Approval", "approval_stage": "reporting",
        })
        return {"status": "awaiting_approval"}


def _state() -> dict:
    return wss.get_state(CASE)


def _join_worker(run_id: str) -> None:
    with commands._TASKS_LOCK:
        task = commands._TASKS.get(run_id)
    assert task is not None, "expected a worker to have been spawned"
    task.thread.join(timeout=30)
    assert not task.thread.is_alive()
    assert task.error is None, task.error


def _worker_alive(run_id: str) -> bool:
    with commands._TASKS_LOCK:
        task = commands._TASKS.get(run_id)
    return bool(task and task.thread.is_alive())


def _run(api, stage: str) -> None:
    """What a Run <Stage> click does: POST /stages/<key>/runs (the request
    workspace.js::actionRequest() builds for action "start"), then wait for
    the real run_stage_chain worker."""
    response = api.post(f"/api/cases/{CASE}/stages/{stage}/runs")
    assert response.status_code == 202, response.get_json()
    _join_worker(response.get_json()["run_id"])


def _rerun(stage: str) -> None:
    result = commands.rerun_stage(CASE, stage)
    _join_worker(result["run_id"])


def _dispatch_idle_chain() -> None:
    """Run the dispatcher with no explicit start — the 'did anything
    auto-advance?' probe."""
    sw.run_stage_chain(CASE, _state()["run_id"])


def _complete_parsing() -> str:
    ctx = sw.run_until_triage_approval(
        {"id": CASE, "title": "Continue controls", "alertMeta": {}}, parsing_only=True)
    assert ctx["stages"]["parsing"] == "completed"
    return ctx["run_id"]


def _action(stage: str, action_type: str) -> dict | None:
    actions = commands.available_actions(_state())["stages"][stage]
    return next((action for action in actions if action["type"] == action_type), None)


def _workflow(api) -> dict:
    response = api.get(f"/api/cases/{CASE}/workflow")
    assert response.status_code == 200
    return response.get_json()


def _node(script: str, payload: dict) -> dict:
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", script],
        input=json.dumps(payload, default=str), capture_output=True, text=True,
        encoding="utf-8", timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


_JS_MODELS = """
import { stageActionModel } from __MODULE__;
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const workflow = JSON.parse(input);
const out = {};
for (const stage of workflow.stages) {
  const model = stageActionModel(stage, workflow);
  const slim = (b) => ({ type: b.type, label: b.label, enabled: b.enabled });
  out[stage.key] = {
    primary: model.primary.map(slim),
    decision: model.decision.map(slim),
    continueTo: model.continueTo ? {
      label: model.continueTo.label,
      next: model.continueTo.nextStage.key,
      enabled: model.continueTo.enabled,
      reason: model.continueTo.reason,
    } : null,
  };
}
process.stdout.write(JSON.stringify(out));
"""

# Renders each stage's Continue button (data-continue-stage, exactly as
# workspace.js::stageActionButtons() does), binds it with the real
# bindContinueButton(), clicks it, and reports what happened. fetch and
# XMLHttpRequest are replaced with counters first, so any request the click
# path could make — e.g. a POST to /stages/<key>/runs — would be recorded.
_JS_CLICK_CONTINUE = """
import { bindContinueButton, continueControl } from __MODULE__;
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const { workflow, stageKey } = JSON.parse(input);
const requests = [];
globalThis.fetch = (...args) => { requests.push(String(args[0])); return Promise.reject(new Error("no network")); };
globalThis.XMLHttpRequest = class { open(method, url) { requests.push(`${method} ${url}`); } send() {} };
const stage = workflow.stages.find((s) => s.key === stageKey);
const cont = continueControl(workflow, stage);
const button = {
  dataset: { continueStage: cont ? cont.nextStage.key : "" },
  listeners: [],
  addEventListener(type, fn) { if (type === "click") this.listeners.push(fn); },
  click() { this.listeners.forEach((fn) => fn({ type: "click" })); },
};
const root = { querySelectorAll: (selector) => (selector === "[data-continue-stage]" && cont ? [button] : []) };
const navigated = [];
bindContinueButton(root, workflow, stage, (key) => navigated.push(key));
button.click();
await new Promise((resolve) => setTimeout(resolve, 20));
process.stdout.write(JSON.stringify({
  rendered: Boolean(cont),
  label: cont ? cont.label : null,
  listeners: button.listeners.length,
  navigated,
  requests,
}));
"""


def _module(script: str) -> str:
    return script.replace("__MODULE__", json.dumps(STAGE_CONTINUE_JS.as_uri()))


def _js_models(workflow: dict) -> dict:
    return _node(_module(_JS_MODELS), workflow)


def _click_continue(workflow: dict, stage_key: str) -> dict:
    return _node(_module(_JS_CLICK_CONTINUE), {"workflow": workflow, "stageKey": stage_key})


def _labels(buttons: list[dict]) -> list[str]:
    return [button["label"] for button in buttons]


def _assert_continue_only_navigates(api, workers, from_stage: str, to_stage: str, label: str) -> None:
    """Click Continue on `from_stage`: it must navigate to `to_stage`, make
    zero requests and zero stage starts, run no agent, and leave `to_stage`
    Pending with its own enabled Run <Stage> button."""
    starts_before = list(api.starts)
    calls_before = list(workers.calls)
    workflow = _workflow(api)

    clicked = _click_continue(workflow, from_stage)
    assert clicked["rendered"] and clicked["label"] == label
    assert clicked["listeners"] == 1
    assert clicked["navigated"] == [to_stage]
    assert clicked["requests"] == []          # no fetch/XHR of any kind

    assert api.starts == starts_before        # no /stages/<key>/runs request
    _dispatch_idle_chain()
    assert workers.calls == calls_before      # no agent executed
    assert _state()[f"{to_stage}_status"] == "Pending"

    ui = _js_models(_workflow(api))           # the page Continue landed on
    assert ui[to_stage]["primary"] == [
        {"type": "start", "label": RUN_LABELS[to_stage], "enabled": True}]


# ══════════════════════════════════════════════════════════════════════════
# End-to-end: Complete -> Continue (navigate) -> Run (execute) at every step
# ══════════════════════════════════════════════════════════════════════════

@requires_node
def test_full_workflow_continue_navigates_and_only_run_executes(monkeypatch, api):
    workers = _Workers(monkeypatch)

    # ── Parsing completes -> Triage Pending, NOT executed ─────────────────
    run_id = _complete_parsing()
    _dispatch_idle_chain()
    state = _state()
    assert (state["parsing_status"], state["triage_status"], state["workflow_status"]) == (
        "Complete", "Pending", "Awaiting Action")
    assert workers.calls == []
    ui = _js_models(_workflow(api))
    assert _labels(ui["parsing"]["primary"]) == ["Re-run Parsing"]
    assert ui["parsing"]["continueTo"] == {
        "label": "Continue to Triage", "next": "triage", "enabled": True, "reason": None}

    # ── Continue to Triage: navigate only ─────────────────────────────────
    _assert_continue_only_navigates(api, workers, "parsing", "triage", "Continue to Triage")

    # ── Run Triage: starts Triage exactly once ────────────────────────────
    _run(api, "triage")
    assert api.starts == ["triage"]
    assert workers.calls == ["triage"]
    state = _state()
    assert state["triage_status"] == "Awaiting Approval"
    assert state["threat_intel_status"] == "Pending"

    # ── Triage awaiting approval: no Continue, TI cannot be started ───────
    ui = _js_models(_workflow(api))
    assert _labels(ui["triage"]["primary"]) == ["Re-run Triage"]
    assert _labels(ui["triage"]["decision"]) == ["Approve Triage"]
    assert ui["triage"]["continueTo"] is None
    assert _click_continue(_workflow(api), "triage")["rendered"] is False
    assert ui["parsing"]["continueTo"] is None   # Triage has already been started
    assert _action("threat_intel", "start")["enabled"] is False
    assert api.post(f"/api/cases/{CASE}/stages/threat_intel/runs").status_code == 409
    assert _state()["threat_intel_status"] == "Pending"

    # ── Approve Triage: unlocks TI (Pending); no navigation, no run ───────
    commands.approve_stage(CASE, "triage", analyst="Analyst")
    assert not _worker_alive(run_id)
    _dispatch_idle_chain()
    state = _state()
    assert (state["triage_status"], state["threat_intel_status"], state["workflow_status"]) == (
        "Approved", "Pending", "Awaiting Action")
    assert workers.calls == ["triage"]
    ui = _js_models(_workflow(api))
    assert _labels(ui["triage"]["primary"]) == ["Re-run Triage"]
    assert ui["triage"]["decision"] == []
    assert ui["triage"]["continueTo"] == {
        "label": "Continue to Threat Intelligence Enrichment", "next": "threat_intel",
        "enabled": True, "reason": None}

    # ── Continue to TI: navigate only; Run TI: executes once, then stops ──
    _assert_continue_only_navigates(api, workers, "triage", "threat_intel",
                                    "Continue to Threat Intelligence Enrichment")
    _run(api, "threat_intel")
    assert api.starts == ["triage", "threat_intel"]
    assert workers.calls == ["triage", "threat_intel"]
    state = _state()
    assert state["threat_intel_status"] in {"Complete", "Complete with Warnings"}
    assert (state["investigation_status"], state["workflow_status"]) == ("Pending", "Awaiting Action")
    _dispatch_idle_chain()
    assert workers.calls == ["triage", "threat_intel"]
    ui = _js_models(_workflow(api))
    assert ui["triage"]["continueTo"] is None
    assert _labels(ui["threat_intel"]["primary"]) == ["Re-run Threat Intelligence"]
    assert ui["threat_intel"]["continueTo"] == {
        "label": "Continue to Investigation", "next": "investigation",
        "enabled": True, "reason": None}

    # ── Continue to Investigation: navigate only; Run Investigation ───────
    _assert_continue_only_navigates(api, workers, "threat_intel", "investigation",
                                    "Continue to Investigation")
    _run(api, "investigation")
    assert api.starts == ["triage", "threat_intel", "investigation"]
    assert workers.calls == ["triage", "threat_intel", "investigation"]
    state = _state()
    assert state["investigation_status"] == "Awaiting Approval"
    assert state["reporting_status"] == "Pending"

    # ── Investigation awaiting approval: no Continue, Reporting locked ────
    ui = _js_models(_workflow(api))
    assert ui["threat_intel"]["continueTo"] is None
    assert _labels(ui["investigation"]["primary"]) == ["Re-run Investigation"]
    assert _labels(ui["investigation"]["decision"]) == ["Approve Investigation"]
    assert ui["investigation"]["continueTo"] is None
    assert _click_continue(_workflow(api), "investigation")["rendered"] is False
    assert _action("reporting", "start")["enabled"] is False
    assert api.post(f"/api/cases/{CASE}/stages/reporting/runs").status_code == 409
    assert _state()["reporting_status"] == "Pending"

    # ── Approve Investigation: unlocks Reporting; no navigation, no run ───
    commands.approve_stage(CASE, "investigation", analyst="Analyst")
    assert not _worker_alive(run_id)
    _dispatch_idle_chain()
    state = _state()
    assert (state["investigation_status"], state["reporting_status"], state["workflow_status"]) == (
        "Approved", "Pending", "Awaiting Action")
    assert workers.calls == ["triage", "threat_intel", "investigation"]
    ui = _js_models(_workflow(api))
    assert ui["investigation"]["decision"] == []
    assert ui["investigation"]["continueTo"] == {
        "label": "Continue to Reporting", "next": "reporting", "enabled": True, "reason": None}

    # ── Continue to Reporting: navigate only; Run Reporting ───────────────
    _assert_continue_only_navigates(api, workers, "investigation", "reporting",
                                    "Continue to Reporting")
    _run(api, "reporting")
    assert api.starts == ["triage", "threat_intel", "investigation", "reporting"]
    assert workers.calls == ["triage", "threat_intel", "investigation", "reporting"]
    assert _state()["reporting_status"] == "Awaiting Approval"

    # ── Reporting: final stage, never a Continue ──────────────────────────
    ui = _js_models(_workflow(api))
    assert ui["investigation"]["continueTo"] is None
    assert _labels(ui["reporting"]["primary"]) == ["Re-run Reporting"]
    assert _labels(ui["reporting"]["decision"]) == ["Approve Reporting"]
    # Reporting approval stays gated on a submitted reviewed report set.
    approve = next(b for b in ui["reporting"]["decision"] if b["type"] == "approve")
    assert approve["enabled"] is False
    assert ui["reporting"]["continueTo"] is None
    assert _click_continue(_workflow(api), "reporting")["rendered"] is False


def test_approval_only_unlocks_and_never_spawns_a_worker(monkeypatch, api):
    workers = _Workers(monkeypatch)
    run_id = _complete_parsing()
    _run(api, "triage")
    with commands._TASKS_LOCK:
        tasks_before = dict(commands._TASKS)

    commands.approve_stage(CASE, "triage", analyst="Analyst")

    with commands._TASKS_LOCK:
        assert commands._TASKS == tasks_before   # approval spawned nothing
    assert not _worker_alive(run_id)
    assert _state()["threat_intel_status"] == "Pending"
    assert workers.calls == ["triage"]
    assert api.starts == ["triage"]


# ══════════════════════════════════════════════════════════════════════════
# Re-runs never cascade
# ══════════════════════════════════════════════════════════════════════════

def test_parsing_rerun_does_not_start_triage(monkeypatch):
    workers = _Workers(monkeypatch)
    first_run = _complete_parsing()

    _rerun("parsing")

    state = _state()
    assert state["run_id"] != first_run   # Parsing re-run mints a fresh run
    assert (state["parsing_status"], state["triage_status"], state["workflow_status"]) == (
        "Complete", "Pending", "Awaiting Action")
    assert state["triage_result_json"] is None
    assert workers.calls == []
    assert _action("triage", "start")["enabled"] is True


def test_triage_rerun_does_not_cascade(monkeypatch, api):
    workers = _Workers(monkeypatch)
    _complete_parsing()
    _run(api, "triage")
    commands.approve_stage(CASE, "triage", analyst="Analyst")
    _run(api, "threat_intel")
    workers.calls.clear()

    _rerun("triage")

    assert workers.calls == ["triage"]
    state = _state()
    assert state["triage_status"] == "Awaiting Approval"
    assert (state["threat_intel_status"], state["investigation_status"], state["reporting_status"]) == (
        "Pending", "Pending", "Pending")
    assert state["threat_intel_result_json"] is None
    assert _action("threat_intel", "start")["enabled"] is False   # needs re-approval


def test_threat_intel_rerun_does_not_cascade(monkeypatch, api):
    workers = _Workers(monkeypatch)
    _complete_parsing()
    _run(api, "triage")
    commands.approve_stage(CASE, "triage", analyst="Analyst")
    _run(api, "threat_intel")
    workers.calls.clear()

    _rerun("threat_intel")

    assert workers.calls == ["threat_intel"]
    state = _state()
    assert state["threat_intel_status"] in {"Complete", "Complete with Warnings"}
    assert (state["investigation_status"], state["reporting_status"], state["workflow_status"]) == (
        "Pending", "Pending", "Awaiting Action")
    assert _action("investigation", "start")["enabled"] is True


def test_investigation_rerun_does_not_cascade(monkeypatch, api):
    workers = _Workers(monkeypatch)
    _complete_parsing()
    _run(api, "triage")
    commands.approve_stage(CASE, "triage", analyst="Analyst")
    _run(api, "threat_intel")
    _run(api, "investigation")
    commands.approve_stage(CASE, "investigation", analyst="Analyst")
    workers.calls.clear()

    _rerun("investigation")

    assert workers.calls == ["investigation"]
    state = _state()
    assert state["investigation_status"] == "Awaiting Approval"
    assert state["reporting_status"] == "Pending"
    assert _action("reporting", "start")["enabled"] is False   # needs re-approval


def test_reporting_rerun_runs_reporting_only(monkeypatch, api):
    workers = _Workers(monkeypatch)
    _complete_parsing()
    _run(api, "triage")
    commands.approve_stage(CASE, "triage", analyst="Analyst")
    _run(api, "threat_intel")
    _run(api, "investigation")
    commands.approve_stage(CASE, "investigation", analyst="Analyst")
    _run(api, "reporting")
    workers.calls.clear()

    _rerun("reporting")

    assert workers.calls == ["reporting"]
    state = _state()
    assert (state["reporting_status"], state["workflow_status"]) == (
        "Awaiting Approval", "Awaiting Approval")
    assert (state["triage_status"], state["investigation_status"]) == ("Approved", "Approved")


# ══════════════════════════════════════════════════════════════════════════
# stageContinue.js unit behaviour (synthetic payloads)
# ══════════════════════════════════════════════════════════════════════════

_START = {"type": "start", "label": "Run", "enabled": True, "reason": None}
_RERUN = {"type": "rerun", "label": "Re-run", "enabled": True, "reason": None}


def _synthetic_workflow(**overrides) -> dict:
    def stage(key, name):
        return {"key": key, "name": name, "completed": True, "actions": [dict(_RERUN)]}

    stages = {
        "parsing": stage("parsing", "Parsing & Normalisation"),
        "triage": stage("triage", "Triage"),
        "threat_intel": stage("threat_intel", "Threat Intelligence Enrichment"),
        "investigation": stage("investigation", "Investigation"),
        "reporting": stage("reporting", "Reporting"),
    }
    for key, value in overrides.items():
        stages[key].update(value)
    return {"stages": list(stages.values())}


@requires_node
def test_all_rerun_labels_are_stage_specific():
    ui = _js_models(_synthetic_workflow())
    assert {key: _labels(model["primary"]) for key, model in ui.items()} == {
        "parsing": ["Re-run Parsing"],
        "triage": ["Re-run Triage"],
        "threat_intel": ["Re-run Threat Intelligence"],
        "investigation": ["Re-run Investigation"],
        "reporting": ["Re-run Reporting"],
    }


@requires_node
def test_all_run_labels_are_stage_specific():
    ui = _js_models(_synthetic_workflow(**{
        key: {"completed": False, "actions": [dict(_START)]} for key in RUN_LABELS
    }))
    assert {key: _labels(model["primary"]) for key, model in ui.items()} == {
        key: [label] for key, label in RUN_LABELS.items()
    }


@requires_node
def test_continue_labels_follow_the_fixed_stage_mapping_and_reporting_has_none():
    workflow = _synthetic_workflow(**{
        key: {"actions": [dict(_START)]} for key in ("triage", "threat_intel", "investigation", "reporting")
    })
    ui = _js_models(workflow)
    assert {key: (model["continueTo"] or {}).get("label") for key, model in ui.items()} == {
        "parsing": "Continue to Triage",
        "triage": "Continue to Threat Intelligence Enrichment",
        "threat_intel": "Continue to Investigation",
        "investigation": "Continue to Reporting",
        "reporting": None,
    }
    assert {key: (model["continueTo"] or {}).get("next") for key, model in ui.items()} == {
        "parsing": "triage", "triage": "threat_intel", "threat_intel": "investigation",
        "investigation": "reporting", "reporting": None,
    }


@requires_node
def test_every_continue_click_navigates_with_zero_requests():
    workflow = _synthetic_workflow(**{
        key: {"actions": [dict(_START)]} for key in ("triage", "threat_intel", "investigation", "reporting")
    })
    expected = {"parsing": "triage", "triage": "threat_intel",
                "threat_intel": "investigation", "investigation": "reporting"}
    for stage_key, next_key in expected.items():
        clicked = _click_continue(workflow, stage_key)
        assert clicked["navigated"] == [next_key], stage_key
        assert clicked["requests"] == [], stage_key
    assert _click_continue(workflow, "reporting")["rendered"] is False


@requires_node
def test_continue_enabled_state_mirrors_the_next_stage_start_action():
    locked = {"type": "start", "label": "Run", "enabled": False,
              "reason": "This stage is locked by canonical workflow state."}
    ui = _js_models(_synthetic_workflow(reporting={"actions": [locked]}))
    assert ui["investigation"]["continueTo"] == {
        "label": "Continue to Reporting", "next": "reporting", "enabled": False,
        "reason": "This stage is locked by canonical workflow state."}


@requires_node
def test_no_continue_without_a_completed_stage_or_an_available_next_stage():
    approve = {"type": "approve", "label": "Approve", "enabled": True, "reason": None}
    ui = _js_models(_synthetic_workflow(
        # Awaiting approval: not completed, so no Continue even though the
        # (hypothetical) next start action is enabled.
        triage={"completed": False, "actions": [approve]},
        threat_intel={"actions": [dict(_START)]},
        # Next stage exposes no start action (already started/finished).
        investigation={"actions": []},
    ))
    assert ui["triage"]["continueTo"] is None
    assert _labels(ui["triage"]["decision"]) == ["Approve Triage"]
    assert ui["threat_intel"]["continueTo"] is None


# ══════════════════════════════════════════════════════════════════════════
# Structural guards
# ══════════════════════════════════════════════════════════════════════════

def test_stage_continue_module_cannot_issue_requests():
    source = STAGE_CONTINUE_JS.read_text(encoding="utf-8")
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//"))
    assert not re.search(r"^\s*import\b", code, re.MULTILINE)
    for forbidden in ("fetch", "XMLHttpRequest", "/runs", "onAction", "handleAction"):
        assert forbidden not in code, forbidden


def test_workspace_continue_is_wired_to_navigation_only():
    source = WORKSPACE_JS.read_text(encoding="utf-8")
    assert 'import { bindContinueButton, stageActionModel } from "../stageContinue.js";' in source
    # Continue gets the navigation callback, never the action handler.
    assert "bindContinueButton(root, workflow, stage, onNavigate);" in source
    assert 'onAction("start"' not in source
    # The navigation callback is the stage-selection re-render — no request.
    body = re.search(r"function selectStage\(stageKey\) \{(.*?)\n    \}", source, re.DOTALL)
    assert body and body.group(1).split() == ["selectedStageKey", "=", "stageKey;", "renderWorkflow();"]
    assert "handleAction, selectStage, workflow, detail.workspace" in source
    # Run (and every other stage action) is still the stage's own backend action.
    assert 'if (action === "start") return [`${base}/stages/${stage.key}/runs`, {}];' in source
    for removed in ("Approve & Continue", "_PARSING_ACTION_LABELS", "_TRIAGE_ACTION_LABELS",
                    "_TI_ACTION_LABELS", "continue-to-triage", "continue-to-investigation"):
        assert removed not in source, removed


def test_no_stage_specific_continuation_endpoint_exists():
    rules = [rule.rule for rule in create_app({"TESTING": True}).url_map.iter_rules()]
    assert not [rule for rule in rules if "continue" in rule.lower()]
