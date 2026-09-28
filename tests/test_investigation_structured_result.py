"""tests/test_investigation_structured_result.py -- Phase 3 of the canonical
Investigation Result contract migration.

Verifies that workflow/engine.py::run_investigation() prefers the structured
investigation_analysis.json (Phase 2) over Markdown reconstruction whenever
it validates against the canonical InvestigationAgentOutput contract (Phase
1), falls back safely to the existing Markdown-regex path on every failure
mode, and that detect_evidence_gaps() sources its (step_id, instruction,
status) rows from the structured execution_trace when available while
leaving its threshold/priority/cap decision logic untouched.

No real `python main.py` subprocess is ever launched: workflow.engine's
`_run_subprocess` is monkeypatched to a fake that writes the same files
(incident_data.json, final_analysis_report.md, optionally
investigation_analysis.json) the real subprocess would have produced, into a
tmp_path-backed INV_DIR, so run_investigation()'s own folder-discovery,
freshness, and structured/Markdown selection logic runs unmodified and for
real.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from workflow import engine as sw


ALERT_ID = "ALERT-1"
FOLDER_NAME = "Incident-Test-001"


@pytest.fixture
def inv_dir(tmp_path, monkeypatch):
    d = tmp_path / "investigation"
    (d / "incident_reports").mkdir(parents=True)
    monkeypatch.setattr(sw, "INV_DIR", d)
    return d


def _valid_structured_payload(
    incident_id=ALERT_ID,
    *,
    severity="High",
    confidence="Medium",
    recommended_containment=None,
    mitre_mappings=None,
    execution_trace=None,
):
    return {
        "incident_id": incident_id,
        "severity": severity,
        "confidence": confidence,
        "execution_trace": execution_trace if execution_trace is not None else [
            {"step_id": "step_1", "instruction": "Check auth logs",
             "status": "MET", "findings": "Single failed login."},
            {"step_id": "step_2", "instruction": "Check lateral movement",
             "status": "NOT_MET", "findings": "No data found."},
            {"step_id": "step_3", "instruction": "Check exfiltration",
             "status": "NOT_MET", "findings": "No data found."},
        ],
        "incident_summary": "A phishing email led to a single compromised host.",
        "actions_taken": ["Isolated host"],
        "recommended_containment": (
            recommended_containment if recommended_containment is not None else
            ["Block sender domain (structured)", "Force password reset (structured)"]
        ),
        "business_impact_checklist": {
            "critical_system": "no", "essential_service": "no",
            "data_sensitivity": "unknown", "operational_impact": "no",
        },
        "severity_justification": "Single host, contained quickly.",
        "confidence_justification": "Strong correlation across all evidence sources.",
        "mitre_mappings": (
            mitre_mappings if mitre_mappings is not None else
            [{
                "timeline_phase": "Initial Access (structured)",
                "observed_evidence": "Phishing email received (structured)",
                "tactic": "Initial Access",
                "technique_name": "Phishing: Spearphishing Link",
                "technique_id": "T1566.002",
            }]
        ),
        "mitre_attack_table": "| Phase | Tactic | Technique |\n| --- | --- | --- |\n",
        "policy_audit_logs": [],
    }


_FALLBACK_MARKDOWN = """# INVESTIGATION SUMMARY: ALERT-1 (Incident-Test-001)

**Final Severity:** High
*Some justification.*

**Confidence Level:** Medium

## Investigative Workflow
- Isolated host

## Technical Chronology & MITRE ATT&CK TTP Mapping

Narrative text describing the incident.

| Timeline Phase | MITRE Tactic | MITRE Technique Name | MITRE Technique ID | Observed Evidence |
| --- | --- | --- | --- | --- |
| Initial Access (markdown) | Initial Access | Phishing: Spearphishing Link | T1566.002 | Phishing email received (markdown) |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Check auth logs | **MET** | Single failed login. |
| `step_2` | Check lateral movement | **NOT_MET** | No data found. |
| `step_3` | Check exfiltration | **NOT_MET** | No data found. |

## Recommended Containment Actions
- Block sender domain (markdown)
- Force password reset (markdown)

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| N/A | N/A | N/A | No policy audit logs recorded | N/A | N/A | N/A | N/A |
"""


def _fake_run_subprocess(
    *,
    folder_name=FOLDER_NAME,
    alert_id=ALERT_ID,
    success=True,
    markdown=_FALLBACK_MARKDOWN,
    structured=None,
    structured_raw_text=None,
    severity="High",
    summary_text="Investigation summary.",
    indicators=None,
):
    """Builds a fake for workflow.engine._run_subprocess() that -- as its
    side effect, exactly like the real `python main.py` subprocess -- writes
    incident_data.json/final_analysis_report.md/investigation_analysis.json
    into the INV_DIR/incident_reports/<folder_name> folder run_investigation()
    will then discover."""

    def _fake(cmd, cwd, timeout, extra_env=None):
        folder = Path(cwd) / "incident_reports" / folder_name
        folder.mkdir(parents=True, exist_ok=True)
        incident_data = {
            "metadata": {"severity": severity},
            "raw_alerts": [{"id": alert_id}],
            "summary_text": summary_text,
            "indicators": indicators or [],
        }
        (folder / "incident_data.json").write_text(
            json.dumps(incident_data), encoding="utf-8"
        )
        (folder / "final_analysis_report.md").write_text(markdown or "", encoding="utf-8")
        if structured_raw_text is not None:
            (folder / "investigation_analysis.json").write_text(
                structured_raw_text, encoding="utf-8"
            )
        elif structured is not None:
            (folder / "investigation_analysis.json").write_text(
                json.dumps(structured), encoding="utf-8"
            )
        return {"started_at": "now", "returncode": 0 if success else 1,
                "success": success, "stdout": "", "stderr": ""}

    return _fake


# =============================================================================
# 1-3. Structured JSON preferred over Markdown; containment/MITRE sourced
# from it directly, not regex-reconstructed
# =============================================================================

def test_valid_structured_json_is_preferred_over_markdown(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload()))

    result = sw.run_investigation(ALERT_ID)

    assert result["workflow"]["investigation_source"] == "structured_json"
    assert result["recommended_containment"] == [
        "Block sender domain (structured)", "Force password reset (structured)"
    ]
    assert result["mitre_mappings"][0]["timeline_phase"] == "Initial Access (structured)"
    # Proves the Markdown-derived (different) values were NOT used.
    assert "(markdown)" not in json.dumps(result["recommended_containment"])
    assert "(markdown)" not in json.dumps(result["mitre_mappings"])


def test_recommended_containment_comes_from_structured_json(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload(
            recommended_containment=["Isolate host X", "Rotate credential Y"])))

    result = sw.run_investigation(ALERT_ID)

    assert result["recommended_containment"] == ["Isolate host X", "Rotate credential Y"]


def test_mitre_mappings_come_from_structured_json(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload(mitre_mappings=[{
            "timeline_phase": "Execution",
            "observed_evidence": "PowerShell spawned",
            "tactic": "Execution",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "technique_id": "T1059.001",
        }])))

    result = sw.run_investigation(ALERT_ID)

    assert result["mitre_mappings"] == [{
        "timeline_phase": "Execution",
        "observed_evidence": "PowerShell spawned",
        "tactic": "Execution",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "technique_id": "T1059.001",
    }]


# =============================================================================
# 4-7. confidence / severity_justification / confidence_justification /
# execution_trace preserved through the handoff
# =============================================================================

def test_confidence_is_preserved(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload(confidence="High")))

    result = sw.run_investigation(ALERT_ID)

    assert result["confidence"] == "High"
    assert result["investigation_analysis"]["confidence"] == "High"


def test_severity_justification_is_preserved(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload()))

    result = sw.run_investigation(ALERT_ID)

    assert result["severity_justification"] == "Single host, contained quickly."


def test_confidence_justification_is_preserved(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload()))

    result = sw.run_investigation(ALERT_ID)

    assert result["confidence_justification"] == (
        "Strong correlation across all evidence sources."
    )


def test_execution_trace_is_preserved(inv_dir, monkeypatch):
    trace = [
        {"step_id": "step_1", "instruction": "Check auth logs",
         "status": "MET", "findings": "Single failed login."},
    ]
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload(execution_trace=trace)))

    result = sw.run_investigation(ALERT_ID)

    assert result["execution_trace"] == trace
    assert result["investigation_analysis"]["execution_trace"] == trace


# =============================================================================
# 8 & 16. Evidence-gap detection sources structured execution_trace; the
# decision logic (threshold/priority/cap) and its output are unchanged
# =============================================================================

def test_evidence_gap_detection_uses_structured_execution_trace(inv_dir, monkeypatch):
    """2 of 3 steps NOT_MET (66%) exceeds the default 0.4 threshold -- gaps
    must be detected purely from execution_trace, with an EMPTY
    narrative_report proving Markdown is not required on this path."""
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        markdown="",  # deliberately empty -- must not be needed
        structured=_valid_structured_payload()))

    result = sw.run_investigation(ALERT_ID)
    # completed_limited because narrative is empty, but execution_trace is
    # still populated from the structured contract regardless of report text.
    assert result["execution_trace"]
    gaps = sw.detect_evidence_gaps(result)

    assert any(g.startswith("step_2:") for g in gaps)
    assert any(g.startswith("step_3:") for g in gaps)
    assert not any(g.startswith("step_1:") for g in gaps)


def test_evidence_gap_detection_parity_between_structured_and_markdown_sources():
    """Same underlying step data, one via structured execution_trace, one
    via the legacy Markdown table -- detect_evidence_gaps() must return
    identical gaps either way, proving only the data source changed."""
    structured_inv = {
        "narrative_report": "",
        "status": "completed",
        "execution_trace": [
            {"step_id": "step_1", "instruction": "Check auth logs",
             "status": "MET", "findings": "x"},
            {"step_id": "step_2", "instruction": "Check lateral movement",
             "status": "NOT_MET", "findings": "x"},
            {"step_id": "step_3", "instruction": "Check exfiltration",
             "status": "NOT_MET", "findings": "x"},
        ],
    }
    markdown_inv = {
        "narrative_report": _FALLBACK_MARKDOWN,
        "status": "completed",
    }

    assert sw.detect_evidence_gaps(structured_inv) == sw.detect_evidence_gaps(markdown_inv)


def test_evidence_gap_detection_below_threshold_yields_no_gaps_from_structured_trace():
    inv = {
        "narrative_report": "",
        "status": "completed",
        "execution_trace": [
            {"step_id": "step_1", "instruction": "a", "status": "MET", "findings": ""},
            {"step_id": "step_2", "instruction": "b", "status": "MET", "findings": ""},
            {"step_id": "step_3", "instruction": "c", "status": "NOT_MET", "findings": ""},
            {"step_id": "step_4", "instruction": "d", "status": "MET", "findings": ""},
        ],
    }
    assert sw.detect_evidence_gaps(inv) == []


# =============================================================================
# 9-11. Fallback triggers: malformed JSON, missing JSON, incident-id mismatch
# =============================================================================

def test_malformed_json_text_falls_back_to_markdown(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured_raw_text="{not valid json"))

    result = sw.run_investigation(ALERT_ID)

    assert result["workflow"]["investigation_source"] == "markdown_fallback"
    assert "investigation_analysis" not in result
    assert result["recommended_containment"] == [
        "Block sender domain (markdown)", "Force password reset (markdown)"
    ]


def test_schema_invalid_json_falls_back_to_markdown(inv_dir, monkeypatch):
    """Valid JSON, but missing required contract fields (e.g. confidence) --
    must fail Pydantic validation and fall back safely."""
    broken_payload = _valid_structured_payload()
    del broken_payload["confidence"]
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=broken_payload))

    result = sw.run_investigation(ALERT_ID)

    assert result["workflow"]["investigation_source"] == "markdown_fallback"
    assert "investigation_analysis" not in result
    assert "confidence" not in result
    assert result["mitre_mappings"][0]["timeline_phase"] == "Initial Access (markdown)"


def test_missing_json_falls_back_to_markdown(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(structured=None))

    result = sw.run_investigation(ALERT_ID)

    assert result["workflow"]["investigation_source"] == "markdown_fallback"
    assert "investigation_analysis" not in result
    assert result["recommended_containment"] == [
        "Block sender domain (markdown)", "Force password reset (markdown)"
    ]


def test_incident_id_mismatch_falls_back_safely(inv_dir, monkeypatch):
    """The structured JSON is otherwise perfectly valid, but its incident_id
    isn't a member of this folder's alert cluster (e.g. a stale artifact from
    a different incident) -- must fall back, not raise, not misattribute."""
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload(incident_id="SOME-OTHER-ALERT")))

    result = sw.run_investigation(ALERT_ID)

    assert result["workflow"]["investigation_source"] == "markdown_fallback"
    assert "investigation_analysis" not in result
    assert result["recommended_containment"] == [
        "Block sender domain (markdown)", "Force password reset (markdown)"
    ]


# =============================================================================
# 12. Fallback output is equivalent to pre-Phase-3 behaviour
# =============================================================================

def test_fallback_output_matches_direct_markdown_parsing(inv_dir, monkeypatch):
    from workflow.stage_summaries import (
        _investigation_recommended_containment_actions,
        _investigation_mitre_mappings,
    )

    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(structured=None))

    result = sw.run_investigation(ALERT_ID)

    assert result["recommended_containment"] == (
        _investigation_recommended_containment_actions(_FALLBACK_MARKDOWN)
    )
    assert result["mitre_mappings"] == _investigation_mitre_mappings(_FALLBACK_MARKDOWN)
    assert result["narrative_report"] == _FALLBACK_MARKDOWN
    assert "confidence" not in result
    assert "execution_trace" not in result
    assert "investigation_analysis" not in result


# =============================================================================
# 13-14. workflow.investigation_source values
# =============================================================================

def test_investigation_source_is_structured_json_on_canonical_path(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        structured=_valid_structured_payload()))
    result = sw.run_investigation(ALERT_ID)
    assert result["workflow"] == {"investigation_source": "structured_json"}


def test_investigation_source_is_markdown_fallback_on_fallback_path(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(structured=None))
    result = sw.run_investigation(ALERT_ID)
    assert result["workflow"] == {"investigation_source": "markdown_fallback"}


# =============================================================================
# 15. completed_limited behaviour preserved regardless of structured JSON
# =============================================================================

def test_completed_limited_when_subprocess_unsuccessful_with_structured_json(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        success=False, structured=_valid_structured_payload()))

    result = sw.run_investigation(ALERT_ID)

    assert result["status"] == "completed_limited"
    assert result["missing_evidence"] == ["Final analysis report was not generated."]
    # Structured JSON is still preferred for the agent-owned fields even
    # though the run is otherwise flagged completed_limited.
    assert result["workflow"]["investigation_source"] == "structured_json"


def test_completed_limited_when_markdown_missing_without_structured_json(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        markdown="", structured=None))

    result = sw.run_investigation(ALERT_ID)

    assert result["status"] == "completed_limited"
    assert result["missing_evidence"] == ["Final analysis report was not generated."]
    assert result["workflow"]["investigation_source"] == "markdown_fallback"


def test_completed_status_unaffected_by_structured_json(inv_dir, monkeypatch):
    monkeypatch.setattr(sw, "_run_subprocess", _fake_run_subprocess(
        success=True, structured=_valid_structured_payload()))

    result = sw.run_investigation(ALERT_ID)

    assert result["status"] == "completed"
    assert "missing_evidence" not in result
