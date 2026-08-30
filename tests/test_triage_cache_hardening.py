"""tests/test_triage_cache_hardening.py -- Phase 5A of the Triage Result
migration: cache compatibility and stale-cache hardening.

Covers two fixes in agents/triage/soc_triage_agent.py::TriageAgent.triage():

1. A cached row that predates the current strict Triage Pydantic contract
   (missing a field TriageAgentSuccessOutput now requires, or carrying an
   extra field extra="forbid" now rejects) must be treated as an ordinary
   cache miss -- triage() recomputes fresh rather than letting
   pydantic.ValidationError escape as an unhandled exception. The stale row
   is then naturally overwritten (same fingerprint) by the fresh result via
   the existing _cache_put() call, with no second cache-cleanup mechanism.

2. _incident_fingerprint() now folds in parsed_context when supplied, so a
   materially different parsed_context for the same incident cannot
   incorrectly reuse another call's cached result -- while a call with no
   parsed_context still produces the exact same fingerprint as before this
   change (existing cache rows for that common case remain valid).

Same isolation conventions as tests/test_triage_result_contract.py: an
isolated tmp_path ticket/cache SQLite DB (never soc_db/soc_tickets.db), the
three internal LLM-calling phases (_run_ioc/_run_risk/_run_cls) stubbed so
no OpenAI call is ever made.
"""
from __future__ import annotations

import json
import sqlite3

import pytest
from pydantic import ValidationError

from agents.triage import soc_triage_agent
from agents.triage.triage_result import validate_triage_agent_output


@pytest.fixture()
def isolated_ticket_db(tmp_path, monkeypatch):
    """Redirect the module-level ticket/cache SQLite DB to a temp file so
    these tests never touch the real soc_db/soc_tickets.db."""
    db_path = tmp_path / "test_tickets.db"
    monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", db_path)
    soc_triage_agent._ticket_db_init()
    yield db_path


def _patch_llm_phases(monkeypatch, agent):
    """Stub the three internal LLM-calling phases so .triage() runs the
    real assembly logic without any network call. Mirrors
    tests/test_triage_result_contract.py's helper of the same name."""
    monkeypatch.setattr(
        agent, "_run_ioc",
        lambda incident, parsed_context=None: {
            "per_category": {},
            "all_metakeys": ["ip.src", "user.name"],
            "ioc_summary": "[NETWORK] 10.0.0.5 — brute-force pattern",
            "total_ioc_count": 2,
        },
    )
    monkeypatch.setattr(
        agent, "_run_risk",
        lambda incident, ioc_summary, parsed_context=None: {
            "likelihood_initiation": "high",
            "likelihood_occurrence": "medium",
            "likelihood_adverse_impact": "high",
            "rationale": "Repeated failed logons preceded a privileged success.",
        },
    )
    monkeypatch.setattr(
        agent, "_run_cls",
        lambda incident, risk_level, ioc_summary, parsed_context=None: {
            "incident_category": "Internal Hacking (attempted)",
            "summary": "Repeated failed logons from 10.0.0.5.",
            "recommended_actions": ["Isolate the affected host"],
            "mitre_tactic": "credential access",
            "mitre_technique": "Brute Force",
        },
    )


def _pre_contract_cache_row(incident_id: str = "INC-1") -> dict:
    """A real historical shape found in soc_db/soc_tickets.db's
    triage_cache table during the Phase 5 readiness audit: missing
    used_parsed_context and the ticket/metakeys_payload mitre_tactic/
    mitre_technique fields the current contract requires."""
    return {
        "metakeys_payload": {
            "incident_id": incident_id, "incident_title": "t", "timestamp": "ts",
            "matched_metakeys": [], "metakey_values": {}, "ioc_summary": "s",
            "risk_level": "high", "classification": "high",
            # mitre_tactic/mitre_technique deliberately absent
        },
        "ticket": {
            "unc": "#001A", "incident_id": incident_id, "title": "t",
            "incident_time": "it", "created_at": "ca", "classification": "HIGH",
            "risk_rating": {
                "likelihood_initiation": "High", "likelihood_occurrence": "High",
                "likelihood_adverse_impact": "High", "overall_risk": "High", "rationale": "r",
            },
            "incident_category": "c",
            # mitre_tactic/mitre_technique deliberately absent
            "initial_response_time": "rt", "summary": "sum",
            "recommended_actions": [], "matched_ioc_count": 0, "metakeys": [],
        },
        "trace": [],
        "error": None,
        # used_parsed_context deliberately absent
    }


def _insert_raw_cache_row(db_path, fingerprint: str, incident_id: str, result_json_str: str) -> None:
    """Write directly to triage_cache, bypassing _cache_put(), so a
    deliberately non-contract-shaped or malformed row can be seeded."""
    with sqlite3.connect(str(db_path)) as con:
        con.execute(
            "INSERT OR REPLACE INTO triage_cache VALUES (?,?,?,?)",
            (fingerprint, incident_id, "2026-01-01T00:00:00", result_json_str),
        )
        con.commit()


# =============================================================================
# 1 & 2. Valid cache hit still returns cached=True; fresh run still omits
# the "cached" key entirely (Phase 1 follow-up behaviour unaffected).
# =============================================================================

def test_valid_cache_hit_still_returns_cached_true(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-VALID-HIT", "title": "Cache hit test"}

    first = agent.triage(incident)
    second = agent.triage(incident)

    assert "cached" not in first
    assert second["cached"] is True


def test_fresh_run_still_omits_cached_key(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)

    result = agent.triage({"id": "INC-FRESH", "title": "Fresh run"})

    assert "cached" not in result


# =============================================================================
# 3 & 4. A pre-contract cached payload fails validation internally but does
# NOT escape as an exception, and real Triage computation runs instead.
# =============================================================================

def test_pre_contract_cached_payload_does_not_raise_and_triggers_recomputation(
    monkeypatch, isolated_ticket_db,
):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-PRECONTRACT", "title": "Pre-contract cache row"}

    fingerprint = soc_triage_agent._incident_fingerprint(incident)
    stale = _pre_contract_cache_row(incident["id"])

    # Sanity: this exact row really does fail current validation --
    # confirms the test fixture reproduces the audit's finding.
    with pytest.raises(ValidationError):
        validate_triage_agent_output(dict(stale, cached=True))

    soc_triage_agent._cache_put(fingerprint, incident["id"], stale)

    # Must not raise -- this is the core Phase 5A fix.
    result = agent.triage(incident)

    # Real recomputation ran (fresh output, not the stale row's content).
    assert "cached" not in result
    assert result["ticket"]["mitre_tactic"] == "Credential Access"
    assert result["metakeys_payload"]["incident_id"] == incident["id"]


# =============================================================================
# 5. The recomputed result replaces/refreshes the stale cache entry (same
# fingerprint), with no second cache-cleanup mechanism -- just the existing
# _cache_put() call at the end of a fresh run.
# =============================================================================

def test_recomputed_result_refreshes_the_stale_cache_entry(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-REFRESH", "title": "Stale cache refresh"}

    fingerprint = soc_triage_agent._incident_fingerprint(incident)
    soc_triage_agent._cache_put(fingerprint, incident["id"], _pre_contract_cache_row(incident["id"]))

    # First call: stale row treated as a miss, recomputes, refreshes cache.
    first = agent.triage(incident)
    assert "cached" not in first

    # Second call: the refreshed row is now a valid, real cache hit.
    second = agent.triage(incident)
    assert second["cached"] is True
    assert second["ticket"]["mitre_tactic"] == "Credential Access"

    # Confirm exactly one row exists at this fingerprint (overwritten in
    # place, not duplicated).
    with sqlite3.connect(str(isolated_ticket_db)) as con:
        count = con.execute(
            "SELECT COUNT(*) FROM triage_cache WHERE fingerprint=?", (fingerprint,)
        ).fetchone()[0]
    assert count == 1


# =============================================================================
# 6 & 7. Malformed (non-dict) and extra-field-invalid cached payloads both
# behave as an ordinary cache miss.
# =============================================================================

def test_malformed_non_dict_cached_payload_behaves_as_cache_miss(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-MALFORMED", "title": "Malformed cache row"}

    fingerprint = soc_triage_agent._incident_fingerprint(incident)
    # A bare JSON list, not a dict -- _cache_put() itself never writes this
    # shape; simulates corrupted/manually-written cache data.
    _insert_raw_cache_row(isolated_ticket_db, fingerprint, incident["id"], json.dumps([1, 2, 3]))

    result = agent.triage(incident)

    assert "cached" not in result
    assert result["ticket"]["incident_id"] == incident["id"]


def test_extra_field_invalid_cached_payload_behaves_as_cache_miss(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-EXTRAFIELD", "title": "Extra-field cache row"}

    fingerprint = soc_triage_agent._incident_fingerprint(incident)
    with_extra_field = _pre_contract_cache_row(incident["id"])
    with_extra_field["used_parsed_context"] = False
    with_extra_field["metakeys_payload"]["mitre_tactic"] = "Credential Access"
    with_extra_field["metakeys_payload"]["mitre_technique"] = "Brute Force"
    with_extra_field["ticket"]["mitre_tactic"] = "Credential Access"
    with_extra_field["ticket"]["mitre_technique"] = "Brute Force"
    with_extra_field["confidence"] = "High"  # extra="forbid" rejects this

    with pytest.raises(ValidationError):
        validate_triage_agent_output(dict(with_extra_field, cached=True))

    soc_triage_agent._cache_put(fingerprint, incident["id"], with_extra_field)

    result = agent.triage(incident)

    assert "cached" not in result
    assert result["ticket"]["incident_id"] == incident["id"]


# =============================================================================
# 8 & 9. force=True still bypasses a valid cache hit, and still refreshes
# the cache afterward.
# =============================================================================

def test_force_true_bypasses_a_valid_cache_hit(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-FORCE", "title": "Force bypass test"}

    first = agent.triage(incident)
    assert "cached" not in first

    second_cached = agent.triage(incident)
    assert second_cached["cached"] is True

    forced = agent.triage(incident, force=True)
    assert "cached" not in forced  # bypassed the cache-hit path entirely


def test_force_true_refreshes_cache_after_recompute(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-FORCE-REFRESH", "title": "Force refresh test"}

    agent.triage(incident)
    agent.triage(incident, force=True)

    # The cache was refreshed by the forced run -- the next non-forced call
    # is a cache hit again (not a miss due to a stale/removed entry).
    third = agent.triage(incident)
    assert third["cached"] is True


# =============================================================================
# 10 & 11. parsed_context fingerprint sensitivity.
# =============================================================================

def test_same_incident_and_same_parsed_context_reuses_cache(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-PC-SAME", "title": "Same parsed_context"}
    parsed_context = {"command_line": "powershell.exe -enc ...", "hostname": "WIN-01"}

    first = agent.triage(incident, parsed_context=parsed_context)
    # A structurally-identical but distinct dict object, different key order.
    second_context = {"hostname": "WIN-01", "command_line": "powershell.exe -enc ..."}
    second = agent.triage(incident, parsed_context=second_context)

    assert "cached" not in first
    assert second["cached"] is True


def test_same_incident_different_parsed_context_does_not_reuse_cache(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-PC-DIFF", "title": "Different parsed_context"}

    first = agent.triage(incident, parsed_context={"hostname": "WIN-01"})
    second = agent.triage(incident, parsed_context={"hostname": "WIN-02"})

    assert "cached" not in first
    assert "cached" not in second  # materially different input -- must NOT be a cache hit


def test_no_parsed_context_keeps_prior_fingerprint_scheme_compatible(monkeypatch, isolated_ticket_db):
    """A call with no parsed_context at all must produce the exact same
    fingerprint as before this phase's change, so existing cache rows for
    that (very common) case remain valid."""
    incident = {"id": "INC-PC-NONE"}
    assert (soc_triage_agent._incident_fingerprint(incident)
            == soc_triage_agent._incident_fingerprint(incident, None)
            == soc_triage_agent._incident_fingerprint(incident, {}))
