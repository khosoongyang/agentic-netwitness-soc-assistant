"""tests/test_triage_business_context.py -- improvement #2.

The three business-context leaves were permanent placeholders
(context.asset_context / change_context / confirmed_benign_history =
"not yet integrated"), so benign_expected was only reachable through an
analyst note and 38% of eval runs ended needs_info. They are now fed from
real, attributable sources supplied by workflow/ (agents/ reads no DB):

* confirmed_benign_history -- prior APPROVED analyst reviews for the same
  detection source + entity (measured; counts by disposition).
* change_context -- an analyst-maintained change-window list
  (AEGIS_CHANGE_WINDOWS JSON): measured only when an active window covers
  this entity at the incident time.
* asset_context -- an asset inventory (AEGIS_ASSET_INVENTORY JSON) when the
  entity is listed (measured); otherwise the hostname naming-pattern tier
  (inferred); IPs without inventory stay missing.

Guards are unchanged: a strong rule signal still needs cited context and a
suppression still never satisfies the floor. As the Step-1 design intended,
MEASURED context now counts toward evidence completeness (so "low"
uncertainty becomes reachable); [inferred] context and the free-text
analyst note do not.
"""
from __future__ import annotations

import json

import pytest

from agents.triage import business_context as bc
from agents.triage import guards
from agents.triage.evidence_packet import build_evidence_packet, get_leaf

from triage_step1_payloads import (SAMPLE_DATA_AVAILABILITY, SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT,
                                   measured_baseline)


def _packet(**ctx):
    return build_evidence_packet(SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT, measured_baseline(),
                                 SAMPLE_DATA_AVAILABILITY, business_context=ctx or None)


def test_default_packet_context_is_missing_with_honest_sources():
    p = _packet()
    for leaf in ("asset_context", "change_context", "confirmed_benign_history"):
        node = get_leaf(p, f"context.{leaf}")
        assert node["status"] == "missing"
        assert "placeholder" not in node["source"].lower()


# ── confirmed_benign_history ────────────────────────────────────────────────

def test_benign_history_from_prior_reviews_is_measured():
    reviews = [
        {"analyst_disposition": "benign_expected", "decision": "approved", "analyst": "A",
         "decided_at": "2026-09-01T00:00:00+00:00", "incident_id": "INC-1"},
        {"analyst_disposition": "benign_expected", "decision": "approved", "analyst": "B",
         "decided_at": "2026-09-02T00:00:00+00:00", "incident_id": "INC-2"},
        {"analyst_disposition": "true_positive", "decision": "approved", "analyst": "A",
         "decided_at": "2026-09-03T00:00:00+00:00", "incident_id": "INC-3"},
    ]
    leaf = bc.benign_history_leaf(reviews)
    assert leaf["status"] == "measured"
    assert leaf["value"]["benign_expected"] == 2 and leaf["value"]["true_positive"] == 1
    assert leaf["value"]["prior_reviews"] == 3
    assert "analyst-reviewed" in leaf["source"]


def test_no_prior_reviews_is_missing_not_safe():
    assert bc.benign_history_leaf([])["status"] == "missing"


def test_rejected_or_superseded_reviews_do_not_count():
    reviews = [{"analyst_disposition": "benign_expected", "decision": "rejected", "analyst": "A",
                "decided_at": "t", "incident_id": "INC-1"}]
    assert bc.benign_history_leaf(reviews)["status"] == "missing"


# ── change_context ──────────────────────────────────────────────────────────

WINDOWS = [{"id": "CHG-1234", "entity": "10.0.0.5", "start": "2026-03-01T00:00:00Z",
            "end": "2026-03-01T06:00:00Z", "description": "WSUS patch rollout", "approved_by": "IT-Ops"}]


def test_active_change_window_covering_entity_is_measured():
    leaf = bc.change_context_leaf(WINDOWS, entity="10.0.0.5", when="2026-03-01T02:00:00")
    assert leaf["status"] == "measured"
    assert leaf["value"]["change_id"] == "CHG-1234"
    assert "CHG-1234" in leaf["source"]


@pytest.mark.parametrize("entity,when", [("10.0.0.6", "2026-03-01T02:00:00"),
                                         ("10.0.0.5", "2026-03-02T02:00:00"),
                                         ("10.0.0.5", None)])
def test_no_matching_window_is_missing(entity, when):
    assert bc.change_context_leaf(WINDOWS, entity=entity, when=when)["status"] == "missing"


def test_malformed_window_never_matches():
    bad = [{"id": "X", "entity": "10.0.0.5", "start": "not-a-date", "end": "2026-03-01T06:00:00Z"}]
    assert bc.change_context_leaf(bad, entity="10.0.0.5", when="2026-03-01T02:00:00")["status"] == "missing"


# ── asset_context ───────────────────────────────────────────────────────────

def test_inventory_entry_is_measured():
    inv = {"10.0.0.5": {"role": "WSUS server", "tier": "production_server", "owner": "IT-Ops"}}
    leaf = bc.asset_context_leaf(inv, entity="10.0.0.5", entity_kind="ip_internal")
    assert leaf["status"] == "measured" and leaf["value"]["role"] == "WSUS server"


def test_hostname_without_inventory_is_inferred_from_naming():
    leaf = bc.asset_context_leaf({}, entity="DC01", entity_kind="hostname")
    assert leaf["status"] == "inferred" and leaf["value"]["tier"] == "critical_infrastructure"


def test_ip_without_inventory_is_missing():
    assert bc.asset_context_leaf({}, entity="10.0.0.5", entity_kind="ip_internal")["status"] == "missing"


# ── loading the analyst-maintained files ────────────────────────────────────

def test_loaders_fail_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CHANGE_WINDOWS", str(tmp_path / "nope.json"))
    monkeypatch.setenv("AEGIS_ASSET_INVENTORY", str(tmp_path / "bad.json"))
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert bc.load_change_windows() == []
    assert bc.load_asset_inventory() == {}
    (tmp_path / "w.json").write_text(json.dumps(WINDOWS), encoding="utf-8")
    monkeypatch.setenv("AEGIS_CHANGE_WINDOWS", str(tmp_path / "w.json"))
    assert bc.load_change_windows()[0]["id"] == "CHG-1234"


# ── guards: context helps only when measured, never past the strong floor ──

def _assessment(disposition, cites):
    return {"proposed_disposition": disposition,
            "hypotheses": {"benign": {"evidence_for": [{"claim": "c", "cites": cites}]},
                           "malicious": {"evidence_against": [{"claim": "c", "cites": cites}]}},
            "lookalike_ruled_out": {"lookalike": "x", "ruled_out": True, "reason": "r", "cites": cites},
            "evidence_checked": cites}


def test_measured_change_window_makes_benign_expected_reachable():
    ctx = {"change_context": bc.change_context_leaf(WINDOWS, entity="10.0.0.5", when="2026-03-01T02:00:00")}
    p = _packet(**ctx)
    out = guards.build_assessment(_assessment("benign_expected", ["context.change_context",
                                                                  "baseline.same_source_entity_30d"]), p)
    assert not any(g["rule"] == "c_benign_expected_requires_context" for g in out["guard_actions"])


def test_missing_context_still_blocks_benign_expected():
    p = _packet()
    out = guards.build_assessment(_assessment("benign_expected", ["context.change_context"]), p)
    assert out["disposition"] == "needs_info"


def test_measured_context_counts_toward_completeness_as_step1_designed():
    """Step-1 design (guards.CORE_EVIDENCE comment): "low" uncertainty is
    reachable only once business context is integrated. Measured inventory /
    change-window / history leaves now count; [inferred] (hostname guess)
    does not, and the free-text analyst note still does not (T-18)."""
    from agents.triage.guards import evidence_completeness
    base = evidence_completeness(_packet())
    ctx = {"change_context": bc.change_context_leaf(WINDOWS, entity="10.0.0.5", when="2026-03-01T02:00:00")}
    assert evidence_completeness(_packet(**ctx)) > base
    inferred = {"asset_context": bc.asset_context_leaf({}, entity="DC01", entity_kind="hostname")}
    assert inferred["asset_context"]["status"] == "inferred"
    assert evidence_completeness(_packet(**inferred)) == base


# ── workflow wiring: real prior review -> context leaf in the next triage ──

def test_prior_approved_review_feeds_the_next_triage_of_same_scope(tmp_path, monkeypatch):
    import json as _json
    from workflow import commands, engine as sw, review_store
    from workflow import state_store as wss
    import test_triage_step3_review as T
    monkeypatch.setenv("AEGIS_CHANGE_WINDOWS", str(tmp_path / "none.json"))
    monkeypatch.setenv("AEGIS_ASSET_INVENTORY", str(tmp_path / "none.json"))
    wss.db_init()
    with wss.db_connect() as con:
        con.execute("INSERT INTO incidents (id,title,severity,status,raw_json) VALUES (?,?,?,?,?)",
                    (T.CASE, "ESA for 10.0.0.5", "HIGH", "New", "{}"))
        con.commit()
    T._awaiting("true_positive")
    commands.approve_stage(T.CASE, "triage", analyst="Alice", review=T._review())
    prior = review_store.list_reviews()[0]
    # a NEW incident from the same detection source + entity
    created_by, rule_id = prior["detection_source"].split(" / ")
    nxt = {"id": "INC-NEXT", "title": "High Risk Alerts: ESA for 10.0.0.5", "createdBy": created_by,
           "ruleId": rule_id, "created": "2026-03-02T00:00:00.000Z"}
    ctx = sw._business_context_for(nxt)
    leaf = ctx["confirmed_benign_history"]
    assert leaf["status"] == "measured" and leaf["value"]["true_positive"] == 1
    # the same incident's own review is never its own "history"
    same = dict(nxt, id=T.CASE)
    assert sw._business_context_for(same) is None


def test_no_context_sources_keeps_cache_key_unchanged(tmp_path, monkeypatch):
    from workflow import engine as sw
    monkeypatch.setenv("AEGIS_CHANGE_WINDOWS", str(tmp_path / "none.json"))
    monkeypatch.setenv("AEGIS_ASSET_INVENTORY", str(tmp_path / "none.json"))
    assert sw._business_context_for({"id": "INC-X", "title": "t for 10.9.9.9"}) is None


def test_mock_triage_packet_carries_business_context_like_run_triage(tmp_path, monkeypatch):
    """Parity (audit T-21 style): the offline --mock-triage path builds the
    REAL packet, so it must see the same business context run_triage does."""
    from workflow import engine as sw
    from workflow import state_store as wss
    windows = tmp_path / "windows.json"
    windows.write_text(json.dumps([{"id": "CHG-7", "entity": "10.0.0.5",
                                    "start": "2026-07-20T00:00:00Z", "end": "2026-07-20T23:59:59Z",
                                    "description": "patching"}]), encoding="utf-8")
    monkeypatch.setenv("AEGIS_CHANGE_WINDOWS", str(windows))
    monkeypatch.setenv("AEGIS_ASSET_INVENTORY", str(tmp_path / "none.json"))
    wss.db_init()
    ctx = sw._business_context_for(SAMPLE_INCIDENT)
    assert ctx and ctx["change_context"]["status"] == "measured"
    res = sw.mock_triage_result(SAMPLE_INCIDENT, data_availability=SAMPLE_DATA_AVAILABILITY,
                                business_context=ctx)
    leaf = get_leaf(res["evidence_packet"], "context.change_context")
    assert leaf["status"] == "measured" and leaf["value"]["change_id"] == "CHG-7"
