"""tests/test_triage_approval_frontend_r5.py -- canonical audit R5, frontend.

The workspace sends the Triage attempt the analyst is LOOKING AT as
expected_stage_attempt: the stage_attempt the backend put on the rendered
Triage approve/reject action (GET /api/cases/<id>/workflow). A stale view is
refused by the backend (409 STALE_ATTEMPT / approval_stage_attempt_mismatch,
nothing written) and the UI reports it instead of a success.

Backend: the real Flask app, commands and state store on a temporary DB.
Frontend: the real frontend/js/pages/workspace.js (actionRequest, the real
api.js fetchJSON error path, the stale-attempt notice) imported under Node
with only window.prompt and fetch stubbed. The request body Node builds is
POSTed unchanged to the real approval route. No LLM, no network.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import canonical_seed as seed
from backend.app import create_app
from workflow import commands
from workflow import engine as wf
from workflow import state_store as wss

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_JS = ROOT / "frontend" / "js" / "pages" / "workspace.js"
API_JS = ROOT / "frontend" / "js" / "api.js"
CASE = "INC-R5-UI"
NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
_NOOP = lambda *a, **k: None   # noqa: E731


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(wf, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", tmp_path / "trusted")
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    wf.pipeline_db_init()
    with wss.db_connect() as con:
        con.execute("INSERT INTO incidents (id, title, raw_json) VALUES (?, ?, ?)",
                    (CASE, "R5 UI", json.dumps({"id": CASE, "title": "R5 UI"})))
        con.commit()
    yield
    with commands._TASKS_LOCK:
        commands._TASKS.clear()


@pytest.fixture
def client():
    return create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": wss.DB_FILE,
                       "AEGIS_CASE_VIEW_BUILDER": lambda *_: {}}).test_client()


# ── backend drivers (real transitions) ─────────────────────────────────────

def _new_run():
    run = wss.start_run(CASE, allow_retry=True)
    seed.seed_parsing_and_raw_incident(CASE, run, {"id": CASE, "title": "R5 UI"})
    wss.set_workflow_status(CASE, run, "Awaiting Action")
    return run


def _execute_triage(run):
    if wss.get_state(CASE)["triage_status"] == "Pending":
        commands.start_stage(CASE, "triage", executor=_NOOP)
    worker, attempt = wss.claim_stage(CASE, run, stage="triage", status_column="triage_status",
                                      expect_status="Processing")
    result = {"ticket": {"incident_id": CASE, "unc": "#00UI1", "classification": "HIGH", "title": "R5 UI"},
              "metakeys_payload": {"incident_id": CASE}, "run_id": run}
    assert wss.complete_stage(CASE, run, worker, stage="triage", result_column="triage_result_json",
                              result=result, expected_stage_attempt=attempt,
                              status_updates={"triage_status": "Awaiting Approval",
                                              "workflow_status": "Awaiting Approval", "approval_stage": "triage"})


def _rerun_triage(run):
    commands.rerun_stage(CASE, "triage", executor=_NOOP)
    _execute_triage(run)


def _rows(run):
    return [(r["decision"], r["stage_attempt"]) for r in wss.get_approval_history(CASE, run)
            if r["approval_stage"] == "triage"]


def _displayed_stage(client, key="triage"):
    """The stage object the workspace renders (and hands to onAction)."""
    workflow = client.get(f"/api/cases/{CASE}/workflow").get_json()
    return next(stage for stage in workflow["stages"] if stage["key"] == key)


# ── frontend driver (real workspace.js under Node) ─────────────────────────

_JS = r"""
globalThis.window = { prompt: (label) => (label.startsWith("Rejection") ? "Wrong host" : "Looks right") };
const responses = { "/api/settings": { status: 200, body: { analyst_name: "alice" } } };
globalThis.fetch = async (path) => {
  const stub = responses[path] || responses.__post__;
  if (!stub) throw new Error(`unexpected request ${path}`);
  return { ok: stub.status < 400, status: stub.status, json: async () => stub.body };
};
const ws = await import(__WORKSPACE__);
const api = await import(__API__);
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const d = JSON.parse(input);
const out = {};
if (d.request) out.request = await ws.actionRequest(d.case, d.request.action, d.request.stage);
if (d.response) {
  // The real api.js error path for the backend's actual response.
  responses.__post__ = d.response;
  try {
    out.result = await api.fetchJSON("/api/cases/x/approvals/triage", { method: "POST", body: {} });
    out.stale = false;
  } catch (error) {
    out.error = { code: error.code, status: error.status, details: error.details };
    out.stale = ws.isStaleAttemptError(error);
    out.notice = out.stale ? ws.staleAttemptNotice(error, d.response.action) : null;
  }
}
process.stdout.write(JSON.stringify(out));
"""


def _node(payload: dict) -> dict:
    script = (_JS.replace("__WORKSPACE__", json.dumps(WORKSPACE_JS.as_uri()))
              .replace("__API__", json.dumps(API_JS.as_uri())))
    done = subprocess.run([NODE, "--input-type=module", "-e", script], input=json.dumps(payload),
                          capture_output=True, text=True, encoding="utf-8", timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _build(action, stage):
    return _node({"case": CASE, "request": {"action": action, "stage": stage}})["request"]


def _ui_outcome(response, action):
    return _node({"response": {"status": response.status_code, "body": response.get_json(), "action": action}})


# ── 1, 2, 5, 6: current attempt — the displayed attempt is sent and accepted ─

@requires_node
# Reject is no longer offered as a stage action (d9c5d6d), so only Approve is
# served with the displayed attempt.
@pytest.mark.parametrize("action,decision", [("approve", "approved")])
def test_current_attempt_decision_sends_and_binds_the_displayed_attempt(client, action, decision):
    run = _new_run()
    _execute_triage(run)
    _rerun_triage(run)                                       # current attempt is 2
    stage = _displayed_stage(client)
    shown = {a["type"]: a["stage_attempt"] for a in stage["actions"] if a["type"] in ("approve", "reject")}
    assert shown == {"approve": 2}                           # served by /workflow
    path, body = _build(action, stage)
    assert path == f"/api/cases/{CASE}/approvals/triage"
    expected_body = {"decision": action, "analyst": "alice",
                     "comments": "Looks right" if action == "approve" else "Wrong host",
                     "expected_stage_attempt": 2}
    assert body == expected_body
    response = client.post(path, json=body)
    assert response.status_code == 200 and response.get_json()["stage_attempt"] == 2
    outcome = _ui_outcome(response, action)
    assert outcome["stale"] is False and outcome["result"]["decision"] == action
    assert _rows(run) == [(decision, 2)]


@requires_node
def test_first_attempt_approval_sends_attempt_1(client):
    run = _new_run()
    _execute_triage(run)
    path, body = _build("approve", _displayed_stage(client))
    assert body["expected_stage_attempt"] == 1
    assert client.post(path, json=body).status_code == 200
    assert _rows(run) == [("approved", 1)]


# ── 3, 4: stale view (attempt 1 displayed, backend now at attempt 2) ───────

@requires_node
@pytest.mark.parametrize("action", ["approve"])
def test_stale_view_decision_is_refused_and_not_shown_as_success(client, action):
    run = _new_run()
    _execute_triage(run)
    opened = _displayed_stage(client)                        # analyst opens attempt 1
    _rerun_triage(run)                                       # Triage re-run elsewhere
    before = wss.get_state(CASE)
    path, body = _build(action, opened)                      # click on the old view
    assert body["expected_stage_attempt"] == 1               # the DISPLAYED attempt, not refetched
    response = client.post(path, json=body)
    assert response.status_code == 409
    error = response.get_json()["error"]
    assert error["code"] == "STALE_ATTEMPT"
    assert error["details"]["reason_code"] == "approval_stage_attempt_mismatch"
    assert (error["details"]["expected_stage_attempt"], error["details"]["current_stage_attempt"]) == (1, 2)
    assert _rows(run) == [] and wss.get_state(CASE) == before   # nothing written; attempt 2 undecided
    outcome = _ui_outcome(response, action)
    assert outcome["stale"] is True and "result" not in outcome
    notice = outcome["notice"]
    decision = "approval" if action == "approve" else "rejection"
    assert f"Your {decision} was not recorded." in notice
    assert "changed or been re-run" in notice and "review the current attempt" in notice
    assert "You reviewed attempt 1; the current attempt is 2." in notice
    # The refreshed view offers attempt 2; deciding it from there succeeds.
    path, body = _build(action, _displayed_stage(client))
    assert body["expected_stage_attempt"] == 2 and client.post(path, json=body).status_code == 200
    assert [attempt for _, attempt in _rows(run)] == [2]


@requires_node
def test_other_conflicts_are_not_reported_as_stale_attempts(client):
    run = _new_run()
    _execute_triage(run)
    response = client.post(f"/api/cases/{CASE}/approvals/triage",
                           json={"decision": "approve", "analyst": "a", "expected_stage_attempt": 0})
    outcome = _ui_outcome(response, "approve")
    assert outcome["error"]["code"] == "INVALID_REQUEST" and outcome["stale"] is False
    assert _rows(run) == []


# ── 7: non-Triage approval requests are unchanged ──────────────────────────

@requires_node
@pytest.mark.parametrize("key", ["investigation", "reporting"])
@pytest.mark.parametrize("action", ["approve", "reject"])
def test_non_triage_request_bodies_are_unchanged(key, action):
    # Even an action that carried a stage_attempt would not be sent for a
    # non-Triage gate (the backend accepts expected_stage_attempt for Triage only).
    stage = {"key": key, "name": key.title(), "actions": [
        {"type": "approve", "enabled": True, "stage_attempt": 3},
        {"type": "reject", "enabled": True, "stage_attempt": 3}]}
    path, body = _build(action, stage)
    assert path == f"/api/cases/{CASE}/approvals/{key}"
    assert body == {"decision": action, "analyst": "alice",
                    "comments": "Looks right" if action == "approve" else "Wrong host"}


# ── 8: no frontend attempt logic ───────────────────────────────────────────

@requires_node
def test_triage_action_without_a_backend_attempt_sends_none():
    stage = {"key": "triage", "name": "Triage", "actions": [{"type": "approve", "enabled": True}]}
    _, body = _build("approve", stage)
    assert "expected_stage_attempt" not in body


def test_workspace_has_no_attempt_counter_of_its_own():
    source = WORKSPACE_JS.read_text(encoding="utf-8")
    assert "triage_attempt" not in source
    # The only source of expected_stage_attempt is the rendered action's
    # backend-provided stage_attempt, passed through unchanged.
    assert re.findall(r"expected_stage_attempt:\s*([\w.]+)", source) == ["attempt"]
    assert "rendered?.stage_attempt" in source
    # (pollRun's own `attempt += 1` is a poll counter, unrelated to stages.)
    assert not re.search(r"stage_attempt\s*([-+]|[-+]=|\+\+)", source)
