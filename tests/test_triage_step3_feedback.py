"""tests/test_triage_step3_feedback.py -- [FYP-TRIAGE-STEP3] X3 + X6.

Offline (temp DBs only; soc_db is never touched). Covers:
  * suppression lifecycle: propose -> approve (typed scope, second analyst)
    -> revoke; reject; expiry (default 30, max 90); expired = no match;
  * scope matching (source + entity [+ signature]);
  * a suppression NEVER satisfies the strong-signal floor (rule b), only
    rule c, and is ignored entirely when strong signals are present;
  * tuning-backlog aggregation + ADS export (TODO, never invented);
  * the noisy-rules query on a read-only temp baseline DB;
  * Cohen's kappa vs hand-computed values (perfect / zero / chance /
    textbook example), metrics on an empty DB, blind_first storage;
  * HTTP endpoints (canonical error shape).
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agents.triage import feedback, metrics, suppression as supp
from agents.triage.baseline import noisy_pairs
from agents.triage.evidence_packet import build_evidence_packet, get_leaf
from agents.triage.guards import build_assessment, strong_rule_signals
from workflow import commands, review_store
from workflow import state_store as wss

from triage_step1_payloads import (SAMPLE_DATA_AVAILABILITY, SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT,
                                   measured_baseline)
from test_triage_step3_review import CASE, _awaiting, _review, backend

SRC = "High Risk Alerts: ESA / 6618e5a2dddef60d6853bec1"


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "wf.db")
    wss.db_init()
    with wss.db_connect() as con:
        con.execute("INSERT INTO incidents (id, title, severity, status, raw_json) VALUES (?,?,?,?,?)",
                    (CASE, "ESA for 10.0.0.5", "HIGH", "New", json.dumps({"id": CASE})))
        con.commit()
    return tmp_path / "wf.db"


def _be_review(**kw):
    return _review(analyst_disposition="benign_expected", lookalike_considered="masquerade",
                   benign_context={"who": "IT ops", "when": "Sun 02:00", "why": "WSUS"},
                   disagreement_reason="note supplied", **kw)


def _approved_be_review() -> int:
    _awaiting("needs_info")
    return commands.approve_stage(CASE, "triage", analyst="Alice", review=_be_review())["review_id"]


# =============================================================================
# Suppression lifecycle
# =============================================================================

def test_expiry_constants_and_bounds():
    assert supp.DEFAULT_SUPPRESSION_EXPIRY_DAYS == 30 and supp.MAX_SUPPRESSION_EXPIRY_DAYS == 90
    assert supp.clamp_expiry_days(None) == 30 and supp.clamp_expiry_days(90) == 90
    for bad in (0, 91, "x"):
        with pytest.raises(ValueError):
            supp.clamp_expiry_days(bad)


def test_propose_approve_revoke_lifecycle(db):
    rid = _approved_be_review()
    p = review_store.propose_suppression_from_review(rid, proposed_by="Alice")
    assert p["status"] == "proposed" and p["detection_source"] == SRC and p["entity"] == "10.0.0.5"
    created = datetime.fromisoformat(p["created_at"])
    assert datetime.fromisoformat(p["expires_at"]) - created == timedelta(days=30)
    # wrong confirmation text
    with pytest.raises(review_store.SuppressionError) as e1:
        review_store.approve_suppression(p["id"], analyst="Bob", confirmation="yes")
    assert e1.value.code == "CONFIRMATION_REQUIRED"
    # proposer cannot self-approve
    with pytest.raises(review_store.SuppressionError) as e2:
        review_store.approve_suppression(p["id"], analyst="alice", confirmation=p["scope_text"])
    assert e2.value.code == "FORBIDDEN_OPERATION"
    ok = review_store.approve_suppression(p["id"], analyst="Bob", confirmation=p["scope_text"])
    assert ok["status"] == "approved" and ok["decided_by"] == "Bob"
    assert [a["id"] for a in review_store.active_suppressions()] == [p["id"]]
    with pytest.raises(review_store.SuppressionError) as e3:   # cannot approve twice
        review_store.approve_suppression(p["id"], analyst="Bob", confirmation=p["scope_text"])
    assert e3.value.code == "SUPPRESSION_CONFLICT"
    rv = review_store.revoke_suppression(p["id"], analyst="Carol", note="change window over")
    assert rv["status"] == "revoked" and review_store.active_suppressions() == []


def test_reject_and_propose_only_from_benign_expected(db):
    rid = _approved_be_review()
    p = review_store.propose_suppression_from_review(rid, proposed_by="Alice", expiry_days=7)
    assert review_store.reject_suppression(p["id"], analyst="Bob")["status"] == "rejected"
    with pytest.raises(review_store.SuppressionError):
        review_store.revoke_suppression(p["id"], analyst="Bob")      # only approved can be revoked
    # a true_positive review cannot spawn a suppression
    with wss.db_connect() as con:
        con.execute("UPDATE triage_reviews SET analyst_disposition='false_positive' WHERE id=?", (rid,))
        con.commit()
    with pytest.raises(review_store.SuppressionError) as e:
        review_store.propose_suppression_from_review(rid, proposed_by="Alice")
    assert "tuning backlog" in e.value.message


def test_expired_proposals_are_marked_and_never_match(db):
    rid = _approved_be_review()
    p = review_store.propose_suppression_from_review(rid, proposed_by="Alice", expiry_days=1)
    review_store.approve_suppression(p["id"], analyst="Bob", confirmation=p["scope_text"])
    future = datetime.now(timezone.utc) + timedelta(days=2)
    assert review_store.expire_suppressions(now=future) == 1
    assert review_store.get_suppression(p["id"])["status"] == "expired"
    row = dict(review_store.get_suppression(p["id"]), status="approved")   # even if mislabelled...
    assert supp.match_suppressions(_packet(), [row], now=future) == []     # ...expired = no match


def _approved(**kw) -> dict:
    base = {"id": 7, "status": "approved", "detection_source": SRC, "entity": "10.0.0.5",
            "alert_signature": None, "decided_by": "Bob", "decided_at": "2026-10-01T00:00:00+00:00",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=10)).isoformat(),
            "benign_context": {"who": "IT", "when": "w", "why": "y"}}
    base.update(kw)
    return base


def _packet(incident=None, suppressions=None):
    return build_evidence_packet(incident or SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT,
                                 measured_baseline(), SAMPLE_DATA_AVAILABILITY,
                                 suppressions=suppressions)


def test_scope_match_rules():
    assert len(supp.match_suppressions(_packet(), [_approved()])) == 1
    assert supp.match_suppressions(_packet(), [_approved(entity="10.0.0.9")]) == []
    assert supp.match_suppressions(_packet(), [_approved(detection_source="Other")]) == []
    assert supp.match_suppressions(_packet(), [_approved(status="proposed")]) == []
    assert supp.match_suppressions(_packet(), [_approved(expires_at="garbage")]) == []
    sig = supp.scope_from_packet(_packet())["signatures"][0]
    assert len(supp.match_suppressions(_packet(), [_approved(alert_signature=sig)])) == 1
    assert supp.match_suppressions(_packet(), [_approved(alert_signature="Other :: x.exe")]) == []


def test_suppression_match_leaf_in_packet():
    p = _packet(suppressions=[_approved()])
    leaf = get_leaf(p, "context.suppression_match")
    assert leaf["status"] == "measured"
    assert leaf["source"].startswith("suppression #7 approved by Bob, expires ")
    assert leaf["value"]["ignored_for_guards"] is False
    assert get_leaf(_packet(suppressions=[]), "context.suppression_match")["status"] == "missing"


def _be_output(cites):
    return {"proposed_disposition": "benign_expected",
            "hypotheses": {"benign": {"evidence_for": [{"claim": "approved suppression", "cites": cites}]}},
            "lookalike_ruled_out": {"lookalike": "x", "ruled_out": False, "reason": "", "cites": []},
            "fn_cost_if_wrong": "missed intrusion"}


def test_suppression_satisfies_rule_c_without_strong_signals():
    p = _packet(suppressions=[_approved()])
    assert strong_rule_signals(p) == []
    a = build_assessment(_be_output(["context.suppression_match"]), p)
    assert a["disposition"] == "benign_expected", a["guard_actions"]


def _strong_incident():
    inc = json.loads(json.dumps(SAMPLE_INCIDENT))
    inc["summary"] = "mimikatz credential dump: privilege escalation via sekurlsa"
    return inc


def test_suppression_never_satisfies_the_strong_signal_floor():
    p = _packet(_strong_incident(), suppressions=[_approved()])
    assert strong_rule_signals(p), "fixture must carry a strong signal"
    leaf = get_leaf(p, "context.suppression_match")
    assert leaf["status"] == "measured" and leaf["value"]["ignored_for_guards"] is True
    assert "adversarial mimicry" in leaf["value"]["ignored_reason"]
    for disposition in ("benign_expected", "false_positive"):
        out = _be_output(["context.suppression_match", "detection.createdBy"])
        out["proposed_disposition"] = disposition
        a = build_assessment(out, p)
        assert a["disposition"] == "needs_info"
        assert any(g["rule"] == "b_strong_signal_floor" for g in a["guard_actions"])


def test_hand_built_packet_cannot_bypass_floor_by_flag():
    p = _packet(_strong_incident(), suppressions=[_approved()])
    p["context"]["suppression_match"]["value"]["ignored_for_guards"] = False   # tampered
    a = build_assessment(_be_output(["context.suppression_match"]), p)
    assert a["disposition"] == "needs_info"


def test_analyst_note_can_still_explain_strong_signal_but_suppression_cannot():
    inc = _strong_incident()
    p = build_evidence_packet(inc, SAMPLE_PARSED_CONTEXT, measured_baseline(), SAMPLE_DATA_AVAILABILITY,
                              analyst_note={"note": "authorised red-team exercise RT-9",
                                            "analyst": "A", "created_at": "t"},
                              suppressions=[_approved()])
    a = build_assessment(_be_output(["context.analyst_note"]), p)
    assert a["disposition"] == "benign_expected"
    b = build_assessment(_be_output(["context.suppression_match"]), p)
    assert b["disposition"] == "needs_info"


# =============================================================================
# Tuning backlog + ADS
# =============================================================================

def _fp(i, src="S", sig="Alert :: a.exe", ent="h1", note="tune me", when=None):
    return {"id": i, "analyst_disposition": "false_positive", "detection_source": src,
            "alert_signature": sig, "entity": ent, "rule_tuning_note": note,
            "incident_id": f"INC-{i}", "decided_at": when or f"2026-10-0{i}T00:00:00", "analyst": "A"}


def test_backlog_aggregation():
    rows = [_fp(1, note="n1"), _fp(2, note="n2"), _fp(3, note="n2"), _fp(4, ent="h2"),
            {"analyst_disposition": "benign_expected", "detection_source": "S", "entity": "h1"}]
    items = feedback.aggregate_tuning_backlog(rows)
    assert len(items) == 2
    top = items[0]
    assert top["fp_count"] == 3 and top["entity"] == "h1"
    assert top["tuning_notes"] == ["n2", "n1"]           # latest first, de-duplicated
    assert top["example_incident_ids"] == ["INC-1", "INC-2", "INC-3"]
    assert top["first_seen"].startswith("2026-10-01") and top["last_seen"].startswith("2026-10-03")


def test_ads_stub_has_all_sections_and_todos_and_escapes():
    item = feedback.aggregate_tuning_backlog([_fp(1, note="exclude <script>x</script> | host")])[0]
    md = feedback.render_ads_stub(item)
    for section in ("## Goal", "## Categorization", "## Strategy Abstract", "## Technical Context",
                    "## Blind Spots and Assumptions", "## False Positives", "## Validation",
                    "## Priority", "## Response"):
        assert section in md
    assert md.count("TODO") >= 6
    assert "<script>" not in md and "\\<script\\>" in md
    assert feedback.ads_filename(item).startswith("ADS_") and "/" not in feedback.ads_filename(item)


def test_export_tuning_backlog_script(db, tmp_path):
    from test_triage_step3_scripts import _load
    exp = _load("export_tuning_backlog")
    _awaiting("true_positive")
    commands.approve_stage(CASE, "triage", analyst="Alice", review=_review(
        analyst_disposition="false_positive", lookalike_considered="x",
        rule_tuning_note="exclude the WSUS server", disagreement_reason="rule broken"))
    out = exp.export(tmp_path / "backlog")
    assert len(out["files"]) == 1
    text = Path(out["files"][0]).read_text(encoding="utf-8")
    assert "exclude the WSUS server" in text and "## False Positives" in text


# =============================================================================
# Noisy rules (read-only temp baseline DB)
# =============================================================================

def _baseline_db(path: Path) -> Path:
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE incidents (id TEXT PRIMARY KEY, title TEXT, created TEXT, raw_json TEXT)")
    end = datetime(2026, 7, 27)
    n = 0
    for days, ent, count in ((5, "10.0.0.5", 35), (60, "10.0.0.5", 5), (10, "HOST-B", 3)):
        for i in range(count):
            n += 1
            created = (end - timedelta(days=days, minutes=i)).strftime("%Y-%m-%dT%H:%M:%S")
            raw = {"createdBy": "High Risk Alerts: ESA", "ruleId": "6618e5a2dddef60d6853bec1"}
            con.execute("INSERT INTO incidents VALUES (?,?,?,?)",
                        (f"I{n}", f"High Risk Alerts: ESA for {ent}", created, json.dumps(raw)))
    con.execute("INSERT INTO incidents VALUES ('LAST', 'x', '2026-07-27T00:00:00', '{}')")
    con.commit()
    con.close()
    return path


def test_noisy_pairs_read_only(tmp_path):
    dbp = _baseline_db(tmp_path / "base.db")
    before = dbp.read_bytes()
    rep = noisy_pairs(dbp)
    assert rep["status"] == "measured"
    top = rep["pairs"][0]
    assert top["detection_source"] == SRC and top["entity"] == "10.0.0.5"
    assert top["count_30d"] == 35 and top["count_90d"] == 40 and top["known_noisy"] is True
    assert rep["pairs"][1]["entity"] == "HOST-B" and rep["pairs"][1]["count_30d"] == 3
    assert dbp.read_bytes() == before
    assert noisy_pairs(tmp_path / "missing.db")["status"] == "unknown"


def test_noisy_rules_join_with_reviews():
    pairs = [{"detection_source": SRC, "entity": "10.0.0.5", "count_30d": 3}]
    revs = [{"analyst_disposition": "false_positive", "detection_source": SRC, "entity": "10.0.0.5"},
            {"analyst_disposition": "benign_expected", "detection_source": SRC.lower(), "entity": "10.0.0.5"}]
    j = feedback.join_noisy_rules(pairs, revs)[0]
    assert j["fp_reviews"] == 1 and j["benign_expected_reviews"] == 1


# =============================================================================
# Cohen's kappa + metrics
# =============================================================================

def test_kappa_perfect_agreement():
    k = metrics.cohens_kappa(["tp", "fp", "ni", "tp"], ["tp", "fp", "ni", "tp"])
    assert k["kappa"] == pytest.approx(1.0) and k["observed_agreement"] == 1.0


def test_kappa_zero_agreement_hand_computed():
    # a=[tp,fp], b=[fp,tp]: p_o = 0, p_e = .5*.5 + .5*.5 = .5 -> kappa = -1
    k = metrics.cohens_kappa(["tp", "fp"], ["fp", "tp"])
    assert k["observed_agreement"] == 0 and k["expected_agreement"] == pytest.approx(0.5)
    assert k["kappa"] == pytest.approx(-1.0)


def test_kappa_chance_agreement_is_zero():
    # Independent marginals: A = 50/50, B = 50/50, agreement on exactly half.
    a = ["x", "x", "y", "y"]
    b = ["x", "y", "x", "y"]
    k = metrics.cohens_kappa(a, b)
    assert k["observed_agreement"] == 0.5 and k["expected_agreement"] == pytest.approx(0.5)
    assert k["kappa"] == pytest.approx(0.0)


def test_kappa_textbook_example():
    # Classic 2x2: 20 yes/yes, 5 yes/no, 10 no/yes, 15 no/no (n = 50).
    # p_o = 35/50 = .7; p_A(yes) = .5, p_B(yes) = .6; p_e = .5*.6 + .5*.4 = .5;
    # kappa = (.7 - .5) / .5 = .4
    a = ["y"] * 25 + ["n"] * 25
    b = ["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15
    k = metrics.cohens_kappa(a, b)
    assert k["observed_agreement"] == pytest.approx(0.7)
    assert k["expected_agreement"] == pytest.approx(0.5)
    assert k["kappa"] == pytest.approx(0.4)


def test_kappa_degenerate_and_empty():
    assert metrics.cohens_kappa([], [])["kappa"] is None
    d = metrics.cohens_kappa(["x", "x"], ["x", "x"])
    assert d["degenerate"] is True and d["kappa"] == 1.0
    with pytest.raises(ValueError):
        metrics.cohens_kappa(["x"], [])


def test_metrics_on_empty_db(db):
    m = metrics.compute_triage_metrics(review_store.list_reviews(), review_store.list_blind_reviews())
    assert m["n_reviews"] == 0 and m["override_rate"] is None and m["small_sample"] is True
    assert m["pairs"]["analyst_vs_mentor"]["kappa"] is None
    assert any("Small sample" in c for c in m["caveats"])
    md = metrics.render_metrics_markdown(m)
    assert "CAVEAT" in md and md.isascii()


def test_metrics_rates_and_mentor_pairs():
    reviews = [
        {"id": 1, "analyst_disposition": "true_positive", "ai_final_disposition": "true_positive",
         "ai_proposed_disposition": "true_positive", "review_mode": "assisted"},
        {"id": 2, "analyst_disposition": "false_positive", "ai_final_disposition": "needs_info",
         "ai_proposed_disposition": "false_positive", "review_mode": "blind_first",
         "revised_after_ai_reveal": True},
        {"id": 3, "analyst_disposition": "needs_info", "ai_final_disposition": "needs_info",
         "ai_proposed_disposition": "benign_expected", "review_mode": "blind_first",
         "revised_after_ai_reveal": False},
    ]
    blind = [{"review_id": 1, "reviewer": "Mentor", "disposition": "true_positive"},
             {"review_id": 2, "reviewer": "Mentor", "disposition": "false_positive"}]
    m = metrics.compute_triage_metrics(reviews, blind)
    assert m["override_rate"] == pytest.approx(1 / 3)
    assert m["guard_intervention_rate"] == pytest.approx(2 / 3)
    assert m["needs_info_rate"] == pytest.approx(1 / 3)
    assert m["blind_first"]["revision_after_reveal_rate"] == pytest.approx(0.5)
    assert m["pairs"]["analyst_vs_mentor"]["n"] == 2
    assert m["pairs"]["analyst_vs_mentor"]["observed_agreement"] == 1.0
    assert m["pairs"]["ai_final_vs_mentor"]["observed_agreement"] == 0.5
    assert m["mentor"] == "Mentor"


def test_blind_first_storage(db):
    _awaiting("true_positive")
    out = commands.approve_stage(CASE, "triage", analyst="Alice", review=_review(
        review_mode="blind_first", analyst_initial_disposition="needs_info",
        revision_reason="the LOLBAS hit convinced me"))
    r = review_store.get_review(out["review_id"])
    assert r["review_mode"] == "blind_first" and r["analyst_initial_disposition"] == "needs_info"
    assert r["revised_after_ai_reveal"] is True and r["analyst_disposition"] == "true_positive"


def test_blind_import_sets_label_provenance(db):
    _awaiting("true_positive")
    rid = commands.approve_stage(CASE, "triage", analyst="Alice", review=_review())["review_id"]
    res = review_store.import_blind_reviews([
        {"review_id": str(rid), "reviewer": "Mentor", "disposition": "True Positive"},
        {"review_id": "999", "reviewer": "Mentor", "disposition": "true_positive"},
        {"review_id": "x", "reviewer": "Mentor", "disposition": "true_positive"},
        {"review_id": str(rid), "reviewer": "", "disposition": "bogus"}])
    assert res["imported"] == 1 and len(res["skipped"]) == 3
    assert review_store.get_review(rid)["label_provenance"] == "mentor_agreed"
    review_store.import_blind_reviews([{"review_id": rid, "reviewer": "Mentor",
                                        "disposition": "needs_info"}])
    assert review_store.get_review(rid)["label_provenance"] == "mentor_disputed"
    assert len(review_store.list_blind_reviews()) == 1


# =============================================================================
# HTTP endpoints
# =============================================================================

@pytest.fixture
def client(db, tmp_path, monkeypatch):
    monkeypatch.setattr(commands, "_spawn_background", lambda *_a, **_k: None)
    app = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": db,
                              "AEGIS_CASE_VIEW_BUILDER": lambda *_: {},
                              "AEGIS_BASELINE_DB_PATH": _baseline_db(tmp_path / "base.db")})
    return app.test_client()


def test_http_suppression_lifecycle_and_errors(client):
    rid = _approved_be_review()
    bad = client.post("/api/triage/suppressions", json={"review_id": "nope", "analyst": "A"})
    assert bad.status_code == 400 and bad.get_json()["error"]["code"] == "INVALID_REQUEST"
    created = client.post("/api/triage/suppressions", json={"review_id": rid, "analyst": "Alice"})
    assert created.status_code == 201
    p = created.get_json()
    deny = client.post(f"/api/triage/suppressions/{p['id']}/approve",
                       json={"analyst": "Bob", "confirmation": "wrong"})
    assert deny.status_code == 403 and deny.get_json()["error"]["code"] == "CONFIRMATION_REQUIRED"
    ok = client.post(f"/api/triage/suppressions/{p['id']}/approve",
                     json={"analyst": "Bob", "confirmation": p["scope_text"]})
    assert ok.status_code == 200 and ok.get_json()["status"] == "approved"
    listed = client.get("/api/triage/suppressions?status=approved").get_json()
    assert listed["count"] == 1
    assert client.post(f"/api/triage/suppressions/{p['id']}/revoke",
                       json={"analyst": "Carol"}).get_json()["status"] == "revoked"
    assert client.post(f"/api/triage/suppressions/{p['id']}/explode",
                       json={"analyst": "Carol"}).status_code == 400
    assert client.get("/api/triage/suppressions?status=weird").status_code == 400


def test_http_backlog_noisy_rules_metrics(client):
    _awaiting("true_positive")
    commands.approve_stage(CASE, "triage", analyst="Alice", review=_review(
        analyst_disposition="false_positive", lookalike_considered="x",
        rule_tuning_note="tune", disagreement_reason="rule broken"))
    backlog = client.get("/api/triage/tuning-backlog").get_json()
    assert backlog["count"] == 1 and backlog["items"][0]["fp_count"] == 1
    noisy = client.get("/api/triage/noisy-rules").get_json()
    assert noisy["status"] == "measured"
    assert noisy["pairs"][0]["entity"] == "10.0.0.5" and noisy["pairs"][0]["fp_reviews"] == 1
    assert client.get("/api/triage/noisy-rules?limit=x").status_code == 400
    m = client.get("/api/triage/metrics").get_json()
    assert m["n_reviews"] == 1 and m["override_rate"] == 1.0 and m["small_sample"] is True


def test_settings_review_mode(db, monkeypatch):
    # Use the SAME loaded package as the app (a different import path would
    # give a different SettingsError class, which the route would not catch).
    SettingsService = sys.modules[f"{backend.__name__}.services.settings_service"].SettingsService
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")      # update() writes it; restored after
    app = backend.create_app({"TESTING": True, "AEGIS_SETTINGS_SERVICE": SettingsService()})
    client = app.test_client()
    assert client.get("/api/settings").get_json()["review_mode"] == "assisted"
    bad = client.put("/api/settings", json={"review_mode": "yolo"})
    assert bad.status_code == 400 and bad.get_json()["error"]["code"] == "SETTINGS_INVALID"
    ok = client.put("/api/settings", json={"review_mode": "blind_first"}).get_json()
    assert ok["review_mode"] == "blind_first"
