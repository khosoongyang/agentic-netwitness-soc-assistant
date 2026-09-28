"""tests/test_triage_result_contract.py -- Phase 1 of the canonical Triage
Result contract migration.

Covers two layers:
  1. Pure model tests for `agents.triage.triage_result` -- field shape,
     required/optional semantics, and round-trip serialization -- mirroring
     tests/test_investigation_result_contract.py's structure for the
     analogous Investigation contract.
  2. Assembly-boundary tests that call the REAL
     `agents.triage.soc_triage_agent.TriageAgent.triage()` method (the
     actual result-assembly function this Phase 1 wires validation into),
     with only the three internal LLM-calling phases
     (_run_ioc/_run_risk/_run_cls) monkeypatched and the ticket/cache SQLite
     database redirected to a temp file -- no live OpenAI call is made and
     the real soc_db/soc_tickets.db is never touched.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agents.triage import soc_triage_agent
from agents.triage.triage_result import (
    TriageAgentErrorOutput,
    TriageAgentSuccessOutput,
    TriageMetakeysPayload,
    TriageRiskRating,
    TriageTicket,
    dump_triage_agent_output,
    validate_triage_agent_output,
)


# =============================================================================
# Fixture payloads
# =============================================================================

def _risk_rating_kwargs() -> dict:
    return dict(
        likelihood_initiation="High",
        likelihood_occurrence="Medium",
        likelihood_adverse_impact="High",
        overall_risk="High",
        rationale="Repeated failed logons followed by a privileged success.",
    )


def _ticket_kwargs() -> dict:
    return dict(
        unc="#00042A",
        incident_id="INC-1001",
        title="Suspicious privileged logon",
        incident_time="2026-08-20 10:00:00 UTC",
        created_at="2026-08-20T10:00:05.123456",
        classification="HIGH",
        risk_rating=_risk_rating_kwargs(),
        incident_category="Internal Hacking (attempted)",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        initial_response_time="<= 30 minutes",
        summary="Repeated failed logons from 10.0.0.5 preceded a successful "
                "privileged logon for user jdoe.",
        recommended_actions=["Isolate the affected host",
                              "Reset the targeted account credentials"],
        matched_ioc_count=3,
        metakeys=["ip.src", "user.name", "host.name"],
    )


def _metakeys_payload_kwargs() -> dict:
    return dict(
        incident_id="INC-1001",
        incident_title="Suspicious privileged logon",
        timestamp="2026-08-20T10:00:00.000000",
        matched_metakeys=["ip.src", "user.name", "host.name"],
        metakey_values={"ip.src": "10.0.0.5", "user.name": "jdoe"},
        ioc_summary="[NETWORK] 10.0.0.5 — brute-force pattern",
        risk_level="high",
        classification="high",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
    )


def _success_output_kwargs() -> dict:
    """A realistic, fully-populated successful TriageAgent.triage() payload."""
    return dict(
        metakeys_payload=_metakeys_payload_kwargs(),
        ticket=_ticket_kwargs(),
        trace=[
            {"step": "IOC Checklist", "status": "ok",
             "matched_metakeys": ["ip.src", "user.name", "host.name"],
             "ioc_summary": "[NETWORK] 10.0.0.5 — brute-force pattern",
             "total_ioc_count": 3, "per_category": {}},
            {"step": "Risk Rating", "status": "ok", "data": _risk_rating_kwargs()},
            {"step": "SOC Classification", "status": "ok",
             "data": {"classification": "High", "response_time": "<= 30 minutes",
                      "mitre_tactic": "Credential Access", "mitre_technique": "Brute Force",
                      "incident_category": "Internal Hacking (attempted)",
                      "summary": "Repeated failed logons...",
                      "recommended_actions": ["Isolate the affected host",
                                               "Reset the targeted account credentials"]}},
        ],
        used_parsed_context=False,
        error=None,
    )


# =============================================================================
# 1. Real representative successful payload validates
# =============================================================================

def test_real_representative_successful_payload_validates():
    output = TriageAgentSuccessOutput.model_validate(_success_output_kwargs())
    assert output.ticket.incident_id == "INC-1001"
    assert output.metakeys_payload.incident_id == "INC-1001"
    assert output.error is None
    assert output.cached is False


# =============================================================================
# 2 & 3. Ticket / metakeys_payload fields round-trip without loss
# =============================================================================

def test_all_ticket_fields_round_trip_without_loss():
    ticket_kwargs = _ticket_kwargs()
    ticket = TriageTicket.model_validate(ticket_kwargs)
    dumped = ticket.model_dump(mode="json")
    for key, value in ticket_kwargs.items():
        assert dumped[key] == value, key


def test_all_metakeys_payload_fields_round_trip_without_loss():
    payload_kwargs = _metakeys_payload_kwargs()
    payload = TriageMetakeysPayload.model_validate(payload_kwargs)
    dumped = payload.model_dump(mode="json")
    for key, value in payload_kwargs.items():
        assert dumped[key] == value, key


# =============================================================================
# 4. risk_rating retains its current structured dict shape
# =============================================================================

def test_risk_rating_retains_structured_dict_shape():
    ticket = TriageTicket.model_validate(_ticket_kwargs())
    assert isinstance(ticket.risk_rating, TriageRiskRating)
    dumped = ticket.model_dump(mode="json")
    assert dumped["risk_rating"] == _risk_rating_kwargs()
    assert isinstance(dumped["risk_rating"], dict)  # not flattened/stringified


# =============================================================================
# 5. recommended_actions retains list[str]
# =============================================================================

def test_recommended_actions_retains_list_of_str():
    ticket = TriageTicket.model_validate(_ticket_kwargs())
    assert ticket.recommended_actions == [
        "Isolate the affected host", "Reset the targeted account credentials",
    ]
    assert isinstance(ticket.recommended_actions, list)
    assert all(isinstance(a, str) for a in ticket.recommended_actions)


# =============================================================================
# 6. classification casing / current behaviour is preserved
# =============================================================================

def test_classification_casing_is_preserved_independently():
    output = TriageAgentSuccessOutput.model_validate(_success_output_kwargs())
    # ticket.classification is upper-cased (classification.upper() in the
    # producer); metakeys_payload.classification is the raw lowercase
    # risk_level-derived value. Both are real, independent values -- the
    # contract must not silently normalise one to match the other.
    assert output.ticket.classification == "HIGH"
    assert output.metakeys_payload.classification == "high"


# =============================================================================
# 7. mitre_tactic / mitre_technique are preserved (scalar, not a list)
# =============================================================================

def test_mitre_tactic_and_technique_are_preserved_as_scalars():
    output = TriageAgentSuccessOutput.model_validate(_success_output_kwargs())
    assert output.ticket.mitre_tactic == "Credential Access"
    assert output.ticket.mitre_technique == "Brute Force"
    assert output.metakeys_payload.mitre_tactic == "Credential Access"
    assert output.metakeys_payload.mitre_technique == "Brute Force"
    assert isinstance(output.ticket.mitre_tactic, str)
    assert isinstance(output.ticket.mitre_technique, str)


# =============================================================================
# 8. used_parsed_context is preserved
# =============================================================================

@pytest.mark.parametrize("used_parsed_context", [True, False])
def test_used_parsed_context_is_preserved(used_parsed_context):
    payload = _success_output_kwargs()
    payload["used_parsed_context"] = used_parsed_context
    output = TriageAgentSuccessOutput.model_validate(payload)
    assert output.used_parsed_context is used_parsed_context
    assert output.model_dump(mode="json")["used_parsed_context"] is used_parsed_context


# =============================================================================
# 9. trace is preserved verbatim (heterogeneous per-step shapes)
# =============================================================================

def test_trace_is_preserved_verbatim():
    payload = _success_output_kwargs()
    output = TriageAgentSuccessOutput.model_validate(payload)
    assert output.model_dump(mode="json")["trace"] == payload["trace"]
    assert len(output.trace) == 3
    assert output.trace[0]["step"] == "IOC Checklist"
    assert output.trace[1]["data"]["overall_risk"] == "High"


# =============================================================================
# 10. Legitimate error output validates under the error contract
# =============================================================================

def test_legitimate_error_output_validates():
    error_payload = {
        "error": "OpenAI request timed out",
        "metakeys_payload": {},
        "ticket": {},
        # a partial trace from Phase 1 completing before Phase 2 raised
        "trace": [{"step": "IOC Checklist", "status": "ok",
                   "matched_metakeys": [], "ioc_summary": "No IOCs matched.",
                   "total_ioc_count": 0, "per_category": {}}],
    }
    output = validate_triage_agent_output(error_payload)
    assert isinstance(output, TriageAgentErrorOutput)
    assert output.error == "OpenAI request timed out"
    assert output.metakeys_payload == {}
    assert output.ticket == {}
    assert len(output.trace) == 1
    # the real error branch never sets this key at all -- it must not be a
    # field on this model
    assert "used_parsed_context" not in TriageAgentErrorOutput.model_fields


def test_error_output_trace_may_be_empty():
    output = TriageAgentErrorOutput.model_validate({"error": "boom"})
    assert output.metakeys_payload == {}
    assert output.ticket == {}
    assert output.trace == []


# =============================================================================
# 11. Malformed success output fails validation
# =============================================================================

def test_malformed_recommended_actions_type_fails_validation():
    payload = _success_output_kwargs()
    payload["ticket"]["recommended_actions"] = "Isolate the host"  # str, not list
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_malformed_risk_rating_type_fails_validation():
    payload = _success_output_kwargs()
    payload["ticket"]["risk_rating"] = "High"  # flat string, not a dict
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_malformed_matched_ioc_count_type_fails_validation():
    payload = _success_output_kwargs()
    payload["ticket"]["matched_ioc_count"] = "three"  # not coercible to int
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


# =============================================================================
# 12. Missing required success field fails validation
# =============================================================================

@pytest.mark.parametrize("missing_top_level_field", ["metakeys_payload", "ticket", "trace", "used_parsed_context"])
def test_missing_required_top_level_field_fails_validation(missing_top_level_field):
    payload = _success_output_kwargs()
    del payload[missing_top_level_field]
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


@pytest.mark.parametrize(
    "missing_ticket_field",
    ["unc", "incident_id", "title", "classification", "risk_rating",
     "incident_category", "mitre_tactic", "mitre_technique", "summary",
     "recommended_actions", "matched_ioc_count", "metakeys"],
)
def test_missing_required_ticket_field_fails_validation(missing_ticket_field):
    payload = _success_output_kwargs()
    del payload["ticket"][missing_ticket_field]
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


@pytest.mark.parametrize(
    "missing_metakeys_field",
    ["incident_id", "matched_metakeys", "metakey_values", "ioc_summary",
     "risk_level", "classification", "mitre_tactic", "mitre_technique"],
)
def test_missing_required_metakeys_payload_field_fails_validation(missing_metakeys_field):
    payload = _success_output_kwargs()
    del payload["metakeys_payload"][missing_metakeys_field]
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


# =============================================================================
# 13. mock_triage_result() remains compatible with the real contract
# =============================================================================

def test_mock_triage_result_validates_against_success_contract():
    from workflow import engine as sw

    mock_result = sw.mock_triage_result({"id": "INC-9999", "title": "Mock incident"})
    # mock_triage_result()'s own top-level "mock": True is a marker specific
    # to that offline substitute -- it is not part of the real
    # TriageAgent.triage() shape this contract models (see triage_result.py
    # module docstring), so it is stripped before validating against the
    # canonical contract, the same way a real API contract test excludes a
    # non-contractual envelope key before schema-validating a payload. With
    # `extra="forbid"` now enforced, leaving it in would make this
    # contract-parity check fail for the wrong reason.
    contract_fields = {k: v for k, v in mock_result.items() if k != "mock"}
    output = validate_triage_agent_output(contract_fields)
    assert isinstance(output, TriageAgentSuccessOutput)
    assert output.ticket.classification == "HIGH"
    assert output.metakeys_payload.mitre_tactic == "Credential Access"
    assert output.used_parsed_context is False


def test_mock_triage_result_round_trips_without_gaining_or_losing_contract_fields():
    from workflow import engine as sw
    from agents.triage.triage_result import dump_triage_agent_output

    mock_result = sw.mock_triage_result({"id": "INC-9999", "title": "Mock incident"})
    contract_fields = {k: v for k, v in mock_result.items() if k != "mock"}
    output = validate_triage_agent_output(contract_fields)
    dumped = dump_triage_agent_output(output)
    assert set(dumped.keys()) == set(contract_fields.keys())
    assert dumped == contract_fields


# =============================================================================
# 14. Cached-result behaviour remains compatible
# =============================================================================

def test_cached_true_validates_and_defaults_to_false():
    fresh_payload = _success_output_kwargs()
    fresh = TriageAgentSuccessOutput.model_validate(fresh_payload)
    assert fresh.cached is False  # absent on a freshly-computed run

    cached_payload = dict(fresh_payload)
    cached_payload["cached"] = True
    cached = TriageAgentSuccessOutput.model_validate(cached_payload)
    assert cached.cached is True
    assert cached.model_dump(mode="json")["cached"] is True


# =============================================================================
# 14b. `dump_triage_agent_output()` preserves the exact pre-Phase-1 external
#      dict shape -- a fresh result must NOT gain a "cached" key it never
#      had, and a cache-hit must keep exposing "cached": true exactly as
#      before. (Verifies the Phase-1 follow-up fix: plain `model_dump()`
#      alone would emit "cached": false for every fresh result, which the
#      real producer's dict never contained pre-Phase-1.)
# =============================================================================

def test_fresh_result_does_not_gain_a_cached_key():
    fresh = TriageAgentSuccessOutput.model_validate(_success_output_kwargs())
    dumped = dump_triage_agent_output(fresh)
    assert "cached" not in dumped


def test_cache_hit_result_keeps_cached_true_key():
    cached_payload = _success_output_kwargs()
    cached_payload["cached"] = True
    cached = TriageAgentSuccessOutput.model_validate(cached_payload)
    dumped = dump_triage_agent_output(cached)
    assert dumped["cached"] is True


def test_error_output_dump_is_unaffected_by_cached_handling():
    error_output = TriageAgentErrorOutput.model_validate({"error": "boom"})
    dumped = dump_triage_agent_output(error_output)
    assert "cached" not in dumped
    assert dumped == {"error": "boom", "metakeys_payload": {}, "ticket": {}, "trace": []}


def test_triage_agent_assembly_boundary_fresh_dict_has_no_cached_key(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)

    result = agent.triage({"id": "INC-ASSEMBLY-NOCACHE", "title": "No cached key on fresh run"})

    assert "cached" not in result


def test_triage_agent_assembly_boundary_cache_hit_dict_has_cached_true(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-ASSEMBLY-CACHEKEY", "title": "Cache key test", "cache_marker": "stable"}

    first = agent.triage(incident)
    second = agent.triage(incident)

    assert "cached" not in first
    assert second["cached"] is True


# =============================================================================
# 14c. Extra/unexpected fields are rejected (extra="forbid"), not silently
#      dropped -- at the top level and inside every nested model. Silent
#      dropping would hide future producer/schema drift (e.g. Triage
#      starting to emit a `confidence` or `severity` field the prompt was
#      never meant to produce) from anyone reading the validated result.
# =============================================================================

def test_top_level_unexpected_field_is_rejected():
    payload = _success_output_kwargs()
    payload["confidence"] = "High"
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_top_level_unexpected_severity_field_is_rejected():
    payload = _success_output_kwargs()
    payload["severity"] = "Critical"
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_nested_ticket_unexpected_field_is_rejected():
    payload = _success_output_kwargs()
    payload["ticket"]["severity"] = "Critical"
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_nested_metakeys_payload_unexpected_field_is_rejected():
    payload = _success_output_kwargs()
    payload["metakeys_payload"]["confidence"] = "High"
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_nested_risk_rating_unexpected_field_is_rejected():
    payload = _success_output_kwargs()
    payload["ticket"]["risk_rating"]["confidence"] = "High"
    with pytest.raises(ValidationError):
        TriageAgentSuccessOutput.model_validate(payload)


def test_no_invented_confidence_or_severity_field_can_silently_pass_through():
    # Before extra="forbid", both of these validated successfully and the
    # invented field was simply dropped on re-serialization -- indistinguishable
    # from a producer that never sent it. Now both must raise instead.
    base = _success_output_kwargs()

    with_confidence = dict(base, confidence="High")
    with pytest.raises(ValidationError):
        validate_triage_agent_output(with_confidence)

    with_severity = dict(base, severity="Critical")
    with pytest.raises(ValidationError):
        validate_triage_agent_output(with_severity)


# =============================================================================
# 15-17. No invented fields appear anywhere on the contract
# =============================================================================

_FORBIDDEN_FIELDS = (
    "severity", "confidence", "likely_scenario", "iocs", "evidence",
    "timeline", "missing_evidence", "missing_fields", "containment_action",
    "recommended_containment_action", "approval_required", "approval_status",
    "current_stage", "next_action", "recommended_next_action", "mitre_mappings",
)


@pytest.mark.parametrize("forbidden_field", _FORBIDDEN_FIELDS)
def test_no_invented_fields_on_success_output(forbidden_field):
    assert forbidden_field not in TriageAgentSuccessOutput.model_fields
    assert forbidden_field not in TriageTicket.model_fields
    assert forbidden_field not in TriageMetakeysPayload.model_fields


def test_classification_is_the_only_real_triage_owned_status_field():
    # classification IS a real Triage field on both nested objects.
    assert "classification" in TriageTicket.model_fields
    assert "classification" in TriageMetakeysPayload.model_fields
    # severity/confidence are not -- Triage never produces either.
    assert "severity" not in TriageTicket.model_fields
    assert "confidence" not in TriageTicket.model_fields


# =============================================================================
# Round-trip serialization (mirrors test_investigation_result_contract.py)
# =============================================================================

def test_full_payload_round_trips_through_json():
    payload = _success_output_kwargs()
    output = TriageAgentSuccessOutput.model_validate(payload)

    dumped = output.model_dump(mode="json")
    reparsed_from_json_text = json.loads(json.dumps(dumped))
    round_tripped = TriageAgentSuccessOutput.model_validate(reparsed_from_json_text)

    assert round_tripped == output
    assert round_tripped.model_dump(mode="json") == dumped


# =============================================================================
# Round-trip integrity via dump_triage_agent_output(): raw dict -> validate
# -> dump -> returned dict must not add, drop, or rename any field, and
# must not alter classification casing, risk_rating structure, or the
# scalar MITRE fields -- for every real return shape (fresh success,
# cached success, error output).
# =============================================================================

def _assert_clean_round_trip(raw: dict) -> dict:
    output = validate_triage_agent_output(raw)
    dumped = dump_triage_agent_output(output)
    assert set(dumped.keys()) == set(raw.keys()), (
        f"added={set(dumped) - set(raw)} dropped={set(raw) - set(dumped)}"
    )
    return dumped


def test_fresh_success_round_trip_adds_or_drops_nothing():
    raw = _success_output_kwargs()
    dumped = _assert_clean_round_trip(raw)
    assert dumped["ticket"]["classification"] == "HIGH"
    assert dumped["metakeys_payload"]["classification"] == "high"
    assert dumped["ticket"]["risk_rating"] == _risk_rating_kwargs()
    assert dumped["ticket"]["mitre_tactic"] == "Credential Access"
    assert dumped["ticket"]["mitre_technique"] == "Brute Force"
    assert dumped["metakeys_payload"]["mitre_tactic"] == "Credential Access"
    assert dumped["metakeys_payload"]["mitre_technique"] == "Brute Force"


def test_cached_success_round_trip_adds_or_drops_nothing():
    raw = _success_output_kwargs()
    raw["cached"] = True
    dumped = _assert_clean_round_trip(raw)
    assert dumped["cached"] is True
    assert dumped["ticket"]["classification"] == "HIGH"
    assert dumped["ticket"]["risk_rating"] == _risk_rating_kwargs()


def test_error_output_round_trip_adds_or_drops_nothing():
    raw = {
        "error": "OpenAI request timed out",
        "metakeys_payload": {},
        "ticket": {},
        "trace": [],
    }
    dumped = _assert_clean_round_trip(raw)
    assert dumped["error"] == "OpenAI request timed out"


# =============================================================================
# Assembly-boundary tests: the real TriageAgent.triage() method
# =============================================================================

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
    real assembly logic (Phase 3's derivation/normalisation code) without
    any network call."""
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


def test_triage_agent_assembly_boundary_produces_valid_success_output(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)

    result = agent.triage({"id": "INC-ASSEMBLY-1", "title": "Assembly boundary test"})

    output = validate_triage_agent_output(result)
    assert isinstance(output, TriageAgentSuccessOutput)
    assert output.ticket.incident_id == "INC-ASSEMBLY-1"
    assert output.ticket.mitre_tactic == "Credential Access"  # normalised by _normalize_mitre_tactic
    assert output.used_parsed_context is False
    assert output.cached is False


def test_triage_agent_assembly_boundary_second_call_is_cached_and_valid(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()
    _patch_llm_phases(monkeypatch, agent)
    incident = {"id": "INC-ASSEMBLY-2", "title": "Cache test", "cache_marker": "stable"}

    first = agent.triage(incident)
    second = agent.triage(incident)

    first_output = validate_triage_agent_output(first)
    second_output = validate_triage_agent_output(second)
    assert isinstance(first_output, TriageAgentSuccessOutput)
    assert isinstance(second_output, TriageAgentSuccessOutput)
    assert first_output.cached is False
    assert second_output.cached is True
    assert second_output.ticket.incident_id == first_output.ticket.incident_id


def test_triage_agent_assembly_boundary_error_path_validates(monkeypatch, isolated_ticket_db):
    agent = soc_triage_agent.TriageAgent()

    def _boom(incident, parsed_context=None):
        raise RuntimeError("simulated LLM failure")

    monkeypatch.setattr(agent, "_run_ioc", _boom)

    result = agent.triage({"id": "INC-ASSEMBLY-ERR", "title": "Error path test"})

    output = validate_triage_agent_output(result)
    assert isinstance(output, TriageAgentErrorOutput)
    assert "simulated LLM failure" in output.error
    assert output.metakeys_payload == {}
    assert output.ticket == {}
    assert "used_parsed_context" not in result
