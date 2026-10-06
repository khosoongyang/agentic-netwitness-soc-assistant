"""tests/test_triage_step2_eval_harness.py -- Triage Step 2 / X7: the
evaluation harness itself (scripts/eval_triage.py) in OFFLINE mode.

"Measure before you claim": these tests check the harness computes the
metrics it reports, honours label provenance (unlabelled cases excluded
from accuracy), fails loudly (exit code 1) on any must_not violation or
canary failure, refuses --mode live without a key (exit 2), and never
writes to soc_db/.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def ev(monkeypatch, tmp_path):
    from agents.triage import soc_triage_agent
    # Let redirect_ticket_db() patch these; monkeypatch restores them after.
    monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", soc_triage_agent._TICKET_DB)
    monkeypatch.setenv("AEGIS_TICKET_DB", str(tmp_path / "unused.db"))
    return _load_script("eval_triage")


def _fast_parse(incident, workdir):
    return ({"parser_status": "completed",
             "parser_metadata": {"parser_confidence": "High", "missing_fields": []}}, "completed")


CANARIES = "tests/triage_eval/canaries/*.json"
GOLDEN_LOW = "tests/triage_eval/cases/golden_benign_generic_low.json"


def _report(out_dir: Path) -> dict:
    files = sorted(out_dir.glob("*.json"))
    assert len(files) == 1 and files[0].with_suffix(".md").exists()
    return json.loads(files[0].read_text(encoding="utf-8"))


# =============================================================================
# Case files
# =============================================================================

def test_all_committed_cases_are_valid(ev):
    cases = ev.load_cases(list(ev.DEFAULT_CASE_GLOBS))
    names = {c["name"] for c in cases}
    assert {"golden_benign_generic_low", "golden_endpoint_hta_c2", "golden_endpoint_lateral_movement",
            "golden_phishing_email", "golden_ransomware_impact", "INC-53021_splunkd_user_root",
            "INC-52825_lateral_move_noise"} <= names
    by = {c["name"]: c for c in cases}
    assert by["golden_benign_generic_low"]["expected"]["disposition_acceptable"] == ["needs_info", "benign_expected"]
    assert by["golden_ransomware_impact"]["expected"]["must_not"] == ["false_positive", "benign_expected"]
    assert by["golden_ransomware_impact"]["label"]["source"] == "synthetic"
    assert not ev.is_labelled(by["INC-52825_lateral_move_noise"])
    assert ev.is_labelled(by["INC-53021_splunkd_user_root"])
    inc = ev.load_incident(by["INC-53021_splunkd_user_root"])
    assert len(inc["alerts"]) == 6 and inc["id"] == "INC-53021"


@pytest.mark.parametrize("mutation, message", [
    (lambda c: c["label"].update(source="vibes"), "label.source"),
    (lambda c: c["label"].update(labeller=None), "label.labeller"),
    (lambda c: c["expected"].update(must_not=["needs_info"]), "both acceptable and must_not"),
    (lambda c: c.pop("incident"), "incident or incident_file"),
])
def test_invalid_cases_are_rejected(ev, mutation, message):
    case = json.loads((ROOT / GOLDEN_LOW).read_text(encoding="utf-8"))
    mutation(case)
    assert any(message in e for e in ev.validate_case(case))


# =============================================================================
# Offline end-to-end: metrics, exit 0, soc_db untouched
# =============================================================================

def test_offline_run_reports_metrics_and_passes(ev, tmp_path, capsys):
    out = tmp_path / "reports"
    code = ev.main(["--mode", "offline", "--repeats", "2", "--cases", CANARIES,
                    "--cases", GOLDEN_LOW, "--out-dir", str(out)], parse=_fast_parse)
    printed = capsys.readouterr().out
    assert "7 case(s) x 2 repeat(s) x 3 calls = 42 planned LLM call(s)" in printed
    assert code == 0
    rep = _report(out)
    m = rep["metrics"]
    assert rep["meta"]["soc_db_untouched"] is True
    assert rep["meta"]["ticket_db"] != str(ROOT / "soc_db" / "soc_tickets.db")
    assert m["n_cases"] == 7 and m["n_runs"] == 14 and m["n_labelled_cases"] == 7
    assert m["must_not_violation_count"] == 0
    assert m["canaries"]["failures"] == []
    assert len(m["canaries"]["malicious"]) == 3 and all(c["passed"] for c in m["canaries"]["malicious"])
    assert m["consistency_rate"] == 1.0                 # scripted model is deterministic
    for key in ("acceptable_hit_rate", "needs_info_rate", "uncertainty_distribution",
                "guard_actions_frequency", "citation_errors_frequency", "latency_s_median"):
        assert key in m
    assert m["acceptable_hit_rate_by_label_source"]["synthetic"]["runs"] == 14
    # the scripted "lazy closer" cites a non-existent path -> citation errors are measured
    assert m["citation_errors_frequency"].get("unknown_path", 0) > 0
    # golden_benign_generic_low has no raw alerts -> mandatory evidence guard fires
    assert m["guard_actions_frequency"].get("a_missing_mandatory_evidence", 0) >= 2
    md = sorted(out.glob("*.md"))[0].read_text(encoding="utf-8")
    assert "**Result: PASS**" in md and "Canaries" in md and "beware circular labels" in md


def test_always_benign_model_still_has_no_canary_failure(ev, tmp_path):
    """Adversarial scripted model: proposes benign_expected for EVERYTHING.
    The guards alone must keep every malicious canary off the benign side."""
    out = tmp_path / "r"
    code = ev.main(["--mode", "offline", "--offline-policy", "always_benign", "--repeats", "1",
                    "--cases", CANARIES, "--out-dir", str(out)], parse=_fast_parse)
    m = _report(out)["metrics"]
    assert m["proposed_disposition_distribution"] == {"benign_expected": 6}
    assert m["canaries"]["failures"] == [] and m["must_not_violation_count"] == 0
    assert code == 0


def test_unlabelled_cases_are_reported_but_excluded_from_accuracy(ev, tmp_path):
    out = tmp_path / "r"
    ev.main(["--mode", "offline", "--repeats", "1", "--out-dir", str(out),
             "--cases", "tests/triage_eval/cases/INC-52825_lateral_move_noise.json",
             "--cases", GOLDEN_LOW], parse=_fast_parse)
    rep = _report(out)
    assert rep["metrics"]["n_unlabelled_cases"] == 1
    assert rep["metrics"]["acceptable_hit_rate_by_label_source"]["synthetic"]["runs"] == 1
    unl = next(c for c in rep["cases"] if c["name"] == "INC-52825_lateral_move_noise")
    assert unl["labelled"] is False and unl["dispositions"]


# =============================================================================
# Exit codes
# =============================================================================

def _fixed_runner(disposition: str):
    def run(incident, parsed, da):
        return ({"error": None, "ticket": {"classification": "HIGH"},
                 "assessment": {"disposition": disposition, "proposed_disposition": disposition,
                                "uncertainty": "high", "guard_actions": [], "citation_errors": []}},
                {"latency_s": 0.01, "tokens": {"total_tokens": 10}})
    return run


def test_must_not_violation_and_canary_failure_exit_1(ev, tmp_path):
    out = tmp_path / "r"
    code = ev.main(["--mode", "offline", "--repeats", "1", "--cases", CANARIES, "--out-dir", str(out)],
                   runner=_fixed_runner("false_positive"), parse=_fast_parse)
    assert code == 1
    rep = _report(out)
    assert rep["exit_code"] == 1
    assert rep["metrics"]["must_not_violation_count"] == 3
    assert len(rep["metrics"]["canaries"]["failures"]) == 3
    assert rep["metrics"]["total_tokens"] == 60
    assert "**Result: FAIL**" in sorted(out.glob("*.md"))[0].read_text(encoding="utf-8")


def test_inconsistent_runs_are_measured(ev, tmp_path):
    seq = iter(["true_positive", "needs_info"] * 10)
    out = tmp_path / "r"
    ev.main(["--mode", "offline", "--repeats", "2", "--cases", GOLDEN_LOW, "--out-dir", str(out)],
            runner=lambda i, p, d: _fixed_runner(next(seq))(i, p, d), parse=_fast_parse)
    m = _report(out)["metrics"]
    assert m["consistency_rate"] == 0.0 and m["inconsistent_cases"] == ["golden_benign_generic_low"]


def test_live_without_key_is_a_config_error(ev, monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ev, "_load_dotenv", lambda: None)
    assert ev.main(["--mode", "live", "--cases", GOLDEN_LOW, "--out-dir", str(tmp_path)]) == 2


def test_dry_run_prints_planned_calls_without_running(ev, capsys, tmp_path):
    assert ev.main(["--mode", "live", "--dry-run", "--repeats", "3", "--cases", CANARIES,
                    "--out-dir", str(tmp_path)]) == 0
    assert "6 case(s) x 3 repeat(s) x 3 calls = 54 planned LLM call(s)" in capsys.readouterr().out
    assert not list(tmp_path.glob("*.json"))


# =============================================================================
# [IMPROVEMENT #3] Abstention must not look like accuracy on independent labels
# =============================================================================

def _labelled_case(tmp_path, name, value, source="mentor_reviewed", slim=True):
    case = {"name": name, "incident": {"id": name, "title": f"t for 10.0.0.{len(name)}"},
            "data_availability": ({"incident_source": "sqlite_slim", "alerts_fetch_attempted": False,
                                   "alerts_fetch_succeeded": False, "alerts_complete": False,
                                   "alerts_count": 0} if slim else None),
            "expected": {"disposition_acceptable": [value, "needs_info"] if value != "needs_info" else ["needs_info"],
                         "must_not": []},
            "label": {"value": value, "source": source, "labeller": "M", "date": "2026-10-06",
                      "rationale": "r"}}
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(case), encoding="utf-8")
    return p


def test_always_needs_info_scores_zero_exact_match_on_mentor_labels(ev, tmp_path):
    """needs_info is 'acceptable' for every label, so acceptable_hit_rate alone
    would award 1.0 to a model that never decides. exact_match_rate and
    decisive_rate expose it, per label source."""
    _labelled_case(tmp_path, "m_tp", "true_positive")
    _labelled_case(tmp_path, "m_be", "benign_expected")
    out = tmp_path / "r"
    ev.main(["--mode", "offline", "--repeats", "2", "--cases", str(tmp_path / "m_*.json"),
             "--out-dir", str(out)], runner=_fixed_runner("needs_info"), parse=_fast_parse)
    rep = _report(out)
    m = rep["metrics"]
    assert m["acceptable_hit_rate"] == 1.0          # the old, flattering number
    assert m["exact_match_rate"] == 0.0
    assert m["decisive_rate"] == 0.0
    src = m["acceptable_hit_rate_by_label_source"]["mentor_reviewed"]
    assert src["exact_match_rate"] == 0.0 and src["decisive_rate"] == 0.0
    assert m["n_labelled_cases_without_raw_alerts"] == 2
    md = sorted(out.glob("*.md"))[0].read_text(encoding="utf-8")
    assert "exact-match" in md and "without raw alerts" in md


def test_exact_match_counts_only_the_labelled_disposition(ev, tmp_path):
    _labelled_case(tmp_path, "m_tp", "true_positive", slim=False)
    out = tmp_path / "r"
    seq = iter(["true_positive", "needs_info"])
    ev.main(["--mode", "offline", "--repeats", "2", "--cases", str(tmp_path / "m_*.json"),
             "--out-dir", str(out)], runner=lambda i, p, d: _fixed_runner(next(seq))(i, p, d),
            parse=_fast_parse)
    m = _report(out)["metrics"]
    assert m["exact_match_rate"] == 0.5 and m["decisive_rate"] == 0.5
    assert m["n_labelled_cases_without_raw_alerts"] == 0
