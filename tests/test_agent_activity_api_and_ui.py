"""Agent Activity transport (history + SSE) and frontend renderer checks."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import observability
from backend import create_app
from observability import emitter
from observability.store import ActivityStore
from workflow import state_store as wss

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = (ROOT / "frontend" / "js" / "components" / "agentActivity.js").read_text(encoding="utf-8")
WORKSPACE = (ROOT / "frontend" / "js" / "pages" / "workspace.js").read_text(encoding="utf-8")


@pytest.fixture()
def api(tmp_path):
    store = ActivityStore(tmp_path / "activity.db")
    emitter.attach_store(store)
    app = create_app({"TESTING": True, "AGENT_ACTIVITY_DB_PATH": str(store.path),
                      "AGENT_ACTIVITY_STREAM_SECONDS": 0.5})
    run_id = wss.start_run("INC-API-1")
    yield app.test_client(), store, run_id
    emitter.detach_store()
    store.close()


def _emit(n, run_id, case_id="INC-API-1", **extra):
    for index in range(n):
        emitter.emit(source="system", event_type="step", status="completed", title=f"step {index}",
                     case_id=case_id, run_id=run_id, stage="triage", stage_attempt=1, **extra)


def _sse_events(body: str) -> list[dict]:
    frames = [f for f in body.split("\n\n") if "event: activity" in f]
    return [json.loads(re.search(r"^data: (.*)$", f, re.M).group(1)) for f in frames]


def test_history_endpoint_returns_ordered_events_for_the_current_run(api):
    client, store, run_id = api
    _emit(3, run_id)
    _emit(2, "other-run")
    assert store.flush()
    body = client.get("/api/cases/INC-API-1/activity?stage=triage").get_json()
    assert body["run_id"] == run_id
    assert [e["title"] for e in body["events"]] == ["step 0", "step 1", "step 2"]
    assert body["last_sequence"] == body["events"][-1]["sequence"]
    after = client.get(f"/api/cases/INC-API-1/activity?after={body['events'][0]['sequence']}").get_json()
    assert [e["title"] for e in after["events"]] == ["step 1", "step 2"]


def test_unknown_case_is_404(api):
    client, _, _ = api
    assert client.get("/api/cases/NOPE/activity").status_code == 404
    assert client.get("/api/cases/NOPE/activity/stream").status_code == 404


def test_sse_stream_delivers_events_with_ids_and_resumes_without_duplicates(api):
    client, store, run_id = api
    _emit(4, run_id)
    assert store.flush()
    response = client.get("/api/cases/INC-API-1/activity/stream?stage=triage")
    assert response.mimetype == "text/event-stream"
    body = response.get_data(as_text=True)
    assert body.startswith("retry: ")
    events = _sse_events(body)
    assert [e["title"] for e in events] == [f"step {i}" for i in range(4)]
    ids = re.findall(r"^id: (\d+)$", body, re.M)
    assert [int(i) for i in ids] == [e["sequence"] for e in events]

    # Reconnect: the browser sends Last-Event-ID; only newer events follow.
    _emit(2, run_id)
    assert store.flush()
    resumed = client.get("/api/cases/INC-API-1/activity/stream?stage=triage",
                         headers={"Last-Event-ID": ids[-1]}).get_data(as_text=True)
    resumed_events = _sse_events(resumed)
    assert len(resumed_events) == 2
    assert all(e["sequence"] > int(ids[-1]) for e in resumed_events)


def test_sse_stream_never_leaks_another_case(api):
    client, store, run_id = api
    other_run = wss.start_run("INC-API-2")
    _emit(2, other_run, case_id="INC-API-2")
    _emit(1, run_id)
    assert store.flush()
    events = _sse_events(client.get("/api/cases/INC-API-1/activity/stream").get_data(as_text=True))
    assert [e["case_id"] for e in events] == ["INC-API-1"]


def test_test_apps_do_not_install_instrumentation_by_default():
    create_app({"TESTING": True})
    assert not observability.is_enabled()


# ── Frontend: a renderer, not a script ─────────────────────────────────────

def test_component_has_no_scripted_steps_or_simulated_progress():
    # No hard-coded stage step lists or stage-specific knowledge.
    for forbidden in ("IOC", "Risk rating", "Classification", "Analysing", "triageSteps",
                      "Loading incident", "Extracting"):
        assert forbidden not in COMPONENT, forbidden
    # Timers only for the elapsed-time label of a running row and deferring a
    # callback - never to add rows.
    assert COMPONENT.count("setTimeout") == 1 and COMPONENT.count("setInterval") == 1
    assert "elapsedSince(el.dataset.since)" in COMPONENT
    # Rows come only from fetched/streamed backend events.
    assert "/activity?" in COMPONENT and "/activity/stream?" in COMPONENT
    assert "new window.EventSource(" in COMPONENT


def test_component_never_labels_anything_as_ai_reasoning():
    assert "REASONING" not in COMPONENT
    assert re.search(r'assessment: "AI ASSESSMENT"', COMPONENT)
    assert re.search(r'explanation: "AI EXPLANATION"', COMPONENT)
    assert re.search(r'summary: "AI SUMMARY"', COMPONENT)


def test_component_escapes_all_event_content_and_dedupes_by_sequence():
    assert "innerHTML" in COMPONENT
    # Every interpolated event field passes through escapeHTML.
    for field in ("event.title", "event.detail", "event.timestamp", "block.text", "field.value"):
        assert re.search(rf"escapeHTML\({re.escape(field)}", COMPONENT), field
    assert "events.has(event.sequence)" in COMPONENT


def test_workspace_replaces_the_generic_triage_message_with_the_activity_panel():
    assert "Analysing IOCs · assessing risk · classifying the incident…" not in WORKSPACE
    assert 'mountStageActivity(root.querySelector("#triage-agent-activity"), caseId, stage, workflow, { live: true })' in WORKSPACE
    # Existing Triage result views remain.
    for kept in ("triageAssessment(ticket)", "triageSummarySection(ticket, result)",
                 'data-triage-view="ticket"'):
        assert kept in WORKSPACE
    # Other stages are untouched in this proof of concept.
    for kept in ('loadingState("Parsing incident…")',
                 'loadingState("Querying VirusTotal · AbuseIPDB · AlienVault OTX…")',
                 'loadingState("Running Investigation…")'):
        assert kept in WORKSPACE
    assert "destroyStageActivity();" in WORKSPACE
