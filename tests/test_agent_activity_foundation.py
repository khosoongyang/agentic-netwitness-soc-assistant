"""Agent Activity foundation: wrapper transparency, event contract, store,
ordering, sanitisation, install/uninstall and wrap-point contracts.

These tests never call a real model or provider and never touch the real
soc_db/agent_activity.db (every store lives under tmp_path).
"""

from __future__ import annotations

import inspect
import threading

import pytest

import observability
from observability import context, emitter
from observability.adapters import triage_adapter
from observability.events import AI_CONTENT_KINDS, build_event
from observability.instrument import ORIGINAL_ATTR, Hooks, Patcher, Target, actual_params, make_wrapper
from observability.sanitize import REDACTED, describe_exception, sanitize_text, sanitize_value
from observability.store import ActivityStore, query_events


@pytest.fixture()
def store(tmp_path):
    activity = ActivityStore(tmp_path / "activity.db")
    emitter.attach_store(activity)
    yield activity
    emitter.detach_store()
    activity.close()


def _scope(case_id="INC-A", run_id="run-A", stage="triage", attempt=1):
    return context.RunScope(case_id=case_id, run_id=run_id, stage=stage, stage_attempt=attempt)


# ── 1. Pass-through wrapper transparency ───────────────────────────────────

def test_wrapper_preserves_arguments_return_object_and_exception_identity():
    received = {}
    sentinel_result = object()

    def original(a, b=None, *, c=None):
        received.update(a=a, b=b, c=c)
        return sentinel_result

    arg_a, arg_c = {"k": [1]}, ["x"]
    wrapper = make_wrapper(original, Hooks(before=lambda call: None,
                                           after=lambda call, token, result: None))
    assert wrapper(arg_a, c=arg_c) is sentinel_result
    assert received["a"] is arg_a and received["c"] is arg_c and received["b"] is None
    assert arg_a == {"k": [1]}  # never mutated

    boom = ValueError("original failure")

    def failing():
        raise boom

    with pytest.raises(ValueError) as caught:
        make_wrapper(failing, Hooks(error=lambda call, token, exc: None))()
    assert caught.value is boom


def test_hook_failures_are_swallowed_and_never_reach_the_caller():
    def explode(*_args):
        raise RuntimeError("observability bug")

    wrapper = make_wrapper(lambda x: x * 2, Hooks(scope=explode, before=explode, after=explode,
                                                   error=explode, cleanup=explode))
    assert wrapper(21) == 42

    def failing():
        raise KeyError("workflow error")

    with pytest.raises(KeyError):
        make_wrapper(failing, Hooks(error=explode, cleanup=explode))()


def test_wrapper_keeps_signature_and_marks_original():
    def original(incident_id, run_id):
        return incident_id

    wrapper = make_wrapper(original, Hooks())
    assert inspect.signature(wrapper) == inspect.signature(original)
    assert getattr(wrapper, ORIGINAL_ATTR) is original


def test_scope_is_opened_for_the_call_and_reset_afterwards():
    seen = []
    wrapper = make_wrapper(lambda: seen.append(context.current_scope()),
                           Hooks(scope=lambda call: _scope()))
    assert context.current_scope() is None
    wrapper()
    assert seen[0].case_id == "INC-A"
    assert context.current_scope() is None


# ── 2. Event contract ──────────────────────────────────────────────────────

def test_event_contract_rejects_reasoning_labels_and_unknown_values():
    base = dict(case_id="INC-A", run_id="r", stage="triage", stage_attempt=1,
                event_type="x", status="completed", title="t")
    assert build_event(source="system", **base)["source"] == "system"
    assert "reasoning" not in AI_CONTENT_KINDS and "reasoning_summary" not in AI_CONTENT_KINDS
    for bad in (dict(source="ai", ai_content_kind="reasoning"),
                dict(source="ai"),                       # AI must declare its content kind
                dict(source="system", ai_content_kind="explanation"),
                dict(source="magic")):
        with pytest.raises(ValueError):
            build_event(**base, **bad)


def test_emit_is_a_no_op_without_a_store_and_never_raises():
    emitter.detach_store()
    assert emitter.emit(source="system", event_type="x", status="info", title="t",
                        case_id="INC-A") is None
    assert emitter.emit(source="nonsense", event_type="x", status="info", title="t") is None


# ── 3. Store: persistence, ordering, independence ──────────────────────────

def test_events_persist_in_emission_order_and_survive_reload(tmp_path, store):
    token = context.set_scope(_scope())
    try:
        for index in range(25):
            emitter.emit(source="system", event_type="step", status="completed", title=f"step {index}")
    finally:
        context.reset_scope(token)
    assert store.flush()
    events = query_events(case_id="INC-A", run_id="run-A", path=store.path)
    assert [e["title"] for e in events] == [f"step {i}" for i in range(25)]
    sequences = [e["sequence"] for e in events]
    assert sequences == sorted(sequences) and len(set(sequences)) == 25
    # "Reload": a fresh reader sees the same history; `after` resumes cleanly.
    resumed = query_events(case_id="INC-A", run_id="run-A", after=sequences[9], path=store.path)
    assert [e["title"] for e in resumed] == [f"step {i}" for i in range(10, 25)]


def test_two_incidents_emitting_concurrently_stay_independent(store):
    def worker(case_id):
        token = context.set_scope(_scope(case_id=case_id, run_id=f"run-{case_id}"))
        try:
            for index in range(40):
                emitter.emit(source="tool", event_type="step", status="completed",
                             title=f"{case_id} step {index}")
        finally:
            context.reset_scope(token)

    threads = [threading.Thread(target=worker, args=(case,)) for case in ("INC-1", "INC-2")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert store.flush()
    for case in ("INC-1", "INC-2"):
        events = query_events(case_id=case, run_id=f"run-{case}", path=store.path)
        assert len(events) == 40
        assert all(e["title"].startswith(case) and e["case_id"] == case for e in events)
        assert [e["title"] for e in events] == [f"{case} step {i}" for i in range(40)]


def test_full_queue_drops_events_without_blocking(tmp_path):
    activity = ActivityStore(tmp_path / "small.db", max_queue=1)
    try:
        event = build_event(case_id="INC-A", run_id="r", stage="triage", stage_attempt=1,
                            source="system", event_type="x", status="info", title="t")
        results = [activity.enqueue(dict(event, event_id=f"e{i}")) for i in range(200)]
        assert results.count(False) == activity.dropped
    finally:
        activity.close()


def test_unwritable_store_never_breaks_emit(tmp_path, store):
    store.path = tmp_path / "missing-dir" / "nested" / "db.sqlite"   # writer cannot open this
    emitter.emit(source="system", event_type="x", status="info", title="t", case_id="INC-A")
    assert store.flush()


def test_wait_for_new_wakes_on_commit(store):
    baseline = store.latest_sequence
    emitter.emit(source="system", event_type="x", status="info", title="t", case_id="INC-A")
    assert store.wait_for_new(baseline, timeout=5)


# ── 4. Sanitisation ────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw, leaked", [
    ("OpenAI key sk-abcdefghijklmnop1234 rejected", "sk-abcdefghijklmnop1234"),
    ("Authorization: Bearer abc.def.ghijklmnop", "abc.def.ghijklmnop"),
    ("x-apikey=0123456789abcdef", "0123456789abcdef"),
    ("GET https://api.example.com/v3/files/x?apikey=SECRET123&a=b failed", "SECRET123"),
    (r"error opening C:\Users\analyst\secrets\creds.json", "analyst"),
    ("Traceback (most recent call last):\n  File \"engine.py\", line 1", "engine.py"),
])
def test_sanitizer_removes_secrets_paths_and_stack_traces(raw, leaked):
    assert leaked not in sanitize_text(raw)


def test_sanitizer_redacts_secret_keys_but_keeps_legitimate_fields():
    cleaned = sanitize_value({"api_key": "abc", "headers": {"x": 1}, "token": "t",
                              "usage": {"input": 10, "reasoning": 4}, "matched_metakeys": ["ip.src"]})
    assert cleaned["api_key"] == REDACTED and cleaned["headers"] == REDACTED and cleaned["token"] == REDACTED
    assert cleaned["usage"] == {"input": 10, "reasoning": 4}
    assert cleaned["matched_metakeys"] == ["ip.src"]


def test_configured_secret_values_are_redacted_wherever_they_appear(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-key-ZXCV-9876")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-not-a-real-key-123")
    text = sanitize_text("rate limit exceeded for key abuse-key-ZXCV-9876; also abuse-key-ZXCV-9876")
    assert "abuse-key-ZXCV-9876" not in text and text.count(REDACTED) == 2
    assert "sk-proj-not-a-real-key-123" not in sanitize_value({"note": "used sk-proj-not-a-real-key-123"})["note"]


def test_describe_exception_has_no_traceback():
    try:
        raise RuntimeError("failed calling https://x.example/api?key=K")
    except RuntimeError as exc:
        text = describe_exception(exc)
    assert text.startswith("RuntimeError:") and "key=K" not in text and "Traceback" not in text


# ── 5. Install / uninstall and wrap-point contracts ────────────────────────

def _triage_targets():
    patcher = Patcher()
    recorded: list[Target] = []
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    triage_adapter.install(patcher)
    return recorded


def test_every_triage_wrap_point_exists_with_the_expected_signature():
    targets = _triage_targets()
    assert len(targets) == 17
    for target in targets:
        assert actual_params(target) == target.params, target.label


def _parsing_targets():
    from observability.adapters import parsing_adapter

    patcher = Patcher()
    recorded: list[Target] = []
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    parsing_adapter.install(patcher)
    return recorded


def _threat_intel_targets():
    from observability.adapters import threat_intel_adapter

    patcher = Patcher()
    recorded: list[Target] = []
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    threat_intel_adapter.install(patcher)
    return recorded


def _investigation_targets():
    from observability.adapters import investigation_adapter

    patcher = Patcher()
    recorded: list[Target] = []
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    investigation_adapter.install(patcher)
    return recorded


def test_install_wraps_every_target_and_uninstall_restores_original_objects(tmp_path):
    from observability.instrument import HOOKS_ATTR, resolve_owner

    all_targets = (_parsing_targets() + _triage_targets() + _threat_intel_targets()
                   + _investigation_targets())
    targets = list({t.label: t for t in all_targets}.values())
    assert len(targets) == 61  # shared points (claim/complete/requests/summary/model call) once each
    originals = {t.label: getattr(resolve_owner(t), t.attr) for t in targets}
    try:
        state = observability.install(str(tmp_path / "activity.db"))
        assert state["enabled"], state
        assert set(state["wrappers"]) == set(originals)
        assert all(value == "installed" for value in state["wrappers"].values())
        for target in targets:
            wrapper = getattr(resolve_owner(target), target.attr)
            assert getattr(wrapper, ORIGINAL_ATTR) is originals[target.label]
            # One wrapper per function, one hook set per adapter that uses it.
            expected = sum(1 for t in all_targets if t.label == target.label)
            assert len(getattr(wrapper, HOOKS_ATTR)) == expected, target.label
        assert observability.install()["enabled"]  # idempotent: no double wrapping
    finally:
        assert observability.uninstall() == []
    for target in targets:
        assert getattr(resolve_owner(target), target.attr) is originals[target.label]
    assert not observability.is_enabled()


def test_shared_wrapper_calls_the_original_exactly_once_for_all_hook_sets():
    calls, seen = [], []
    patcher = Patcher()

    def original(incident_id, run_id):
        calls.append((incident_id, run_id))
        return "result"

    import types
    module = types.ModuleType("aegis_shared_wrap_test")
    module.fn = original
    import sys
    sys.modules[module.__name__] = module
    try:
        target = Target(module.__name__, "fn", ("incident_id", "run_id"))
        assert patcher.wrap(target, Hooks(after=lambda call, token, result: seen.append(("a", result))))
        assert patcher.wrap(target, Hooks(after=lambda call, token, result: seen.append(("b", result))))
        assert module.fn("INC", "run") == "result"
        assert calls == [("INC", "run")] and seen == [("a", "result"), ("b", "result")]
        assert patcher.restore() == [] and module.fn is original
    finally:
        sys.modules.pop(module.__name__, None)


def test_tee_callback_observes_and_still_calls_the_original_callback():
    received, observed = [], []

    def original(lines, line_cb=None, other=None):
        for line in lines:
            if line_cb:
                line_cb(line)
        return other

    sentinel = object()
    caller_cb = received.append

    def factory(call, original_cb):
        def tee(line):
            observed.append(line)
            if original_cb is not None:
                original_cb(line)
        return tee

    wrapper = make_wrapper(original, Hooks(tee_callback=("line_cb", factory)))
    assert wrapper(["a", "b"], line_cb=caller_cb, other=sentinel) is sentinel
    assert observed == ["a", "b"] and received == ["a", "b"]
    observed.clear()
    assert wrapper(["c"], other=sentinel) is sentinel  # no caller callback: only observed
    assert observed == ["c"]
    # A factory that declines leaves the call exactly as it was.
    passthrough = make_wrapper(original, Hooks(tee_callback=("line_cb", lambda call, cb: None)))
    assert passthrough(["d"], line_cb=caller_cb) is None and received[-1] == "d"


def test_signature_mismatch_skips_the_wrapper_instead_of_guessing():
    patcher = Patcher()
    ok = patcher.wrap(Target("workflow.engine", "run_triage_stage", ("unexpected",)), Hooks())
    assert ok is False and "signature mismatch" in patcher.report["workflow.engine.run_triage_stage"]


def test_install_can_be_disabled_by_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_ACTIVITY", "off")
    state = observability.install(str(tmp_path / "activity.db"))
    assert state["enabled"] is False and "disabled" in state["error"]
