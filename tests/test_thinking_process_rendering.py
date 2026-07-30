"""
[FYP-FILE]
# Important dependencies: __future__, soc_workflow.
File: tests/test_thinking_process_rendering.py
Purpose: Verifies soc_workflow.render_agent_thinking_plain() — the plain-
    text "Thinking Process" panel shown per stage in app.py's My Workspace,
    which explains what each agent did/is doing without dumping the raw
    stage result or any hidden model chain-of-thought.
Main functionalities: Calls render_agent_thinking_plain(stage, result,
    workflow_state=..., activity=...) with representative per-stage result
    dicts (Parsing/Triage/Threat Intelligence Enrichment/
    Investigation/Reporting) and with workflow_state/activity timelines for
    a completed vs. a currently-processing stage, then asserts the
    rendered plain-text narrative contains the expected derived phrases
    (indicator counts, risk level/score, MITRE mapping, playbook step
    MET/NOT_MET status, timestamps, elapsed time, live heartbeat note) and
    does not leak the raw result payload or agent-module implementation
    detail language once a stage is complete.
Inputs: Hand-built per-stage result dicts, and (for the last two tests)
    workflow_state/activity dicts shaped like the durable rows
    workflow_state_store.py persists. No database or LLM call is involved
    — render_agent_thinking_plain() is pure string formatting.
Outputs: Assertions (substring/equality) on the plain-text string returned
    by render_agent_thinking_plain().
Workflow position: Presentation layer over the same per-stage results
    exercised functionally in tests/test_threat_intel_workflow.py,
    tests/test_investigation_stage.py and tests/test_reporting_stage.py —
    this file only checks how those results are narrated to the analyst,
    not how they are produced.
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_thinking_process_rendering.py`.
Calls: soc_workflow.render_agent_thinking_plain().
Key evaluator search terms: render_agent_thinking_plain, Thinking Process,
    stage_started, stage_succeeded, worker_heartbeat_at, elapsed stage
    time, MET, NOT_MET.
[/FYP-FILE]
"""
from __future__ import annotations

import soc_workflow as sw


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] render_agent_thinking_plain() — per-stage result-only
# narration (no workflow_state/activity timeline supplied)
# ══════════════════════════════════════════════════════════════════════════

def test_parsing_thinking_prefers_persisted_parser_narrative():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain("Parsing", ...)
    prefers an already-persisted ai_thinking narrative over reconstructing
    one from the raw result fields, returning it verbatim.
    """
    result = {
        "status": "completed",
        "selected_alert_id": "ALERT-7",
        "ai_thinking": "Host WS-7 and file sample.exe drove the parser summary.",
    }

    text = sw.render_agent_thinking_plain("Parsing", result)

    assert text == "Host WS-7 and file sample.exe drove the parser summary."


def test_triage_thinking_comes_from_trace():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain("Triage", ...)
    reconstructs the narrative from the triage agent's step-by-step
    `trace` list (IOC Checklist, Risk Rating, SOC Classification steps),
    asserting the rendered text reports the matched indicator count, the
    rated risk level, and the final classification.
    """
    result = {
        "trace": [
            {
                "step": "IOC Checklist",
                "total_ioc_count": 1,
                "ioc_summary": "Suspicious file observed",
                "matched_metakeys": ["file.name"],
            },
            {
                "step": "Risk Rating",
                "data": {
                    "overall_risk": "Medium",
                    "likelihood_initiation": "Medium",
                    "likelihood_occurrence": "Low",
                    "likelihood_adverse_impact": "Medium",
                    "rationale": "The file requires validation.",
                },
            },
            {
                "step": "SOC Classification",
                "data": {
                    "classification": "medium",
                    "summary": "Investigation is warranted.",
                    "mitre_tactic": "Execution",
                    "mitre_technique": "T1204",
                },
            },
        ]
    }

    text = sw.render_agent_thinking_plain("Triage", result)

    assert "matched 1 indicator" in text
    assert "risk was rated Medium" in text
    assert "classified as MEDIUM" in text


def test_threat_intel_thinking_uses_persisted_risk_and_next_action():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain("Threat
    Intelligence Enrichment", ...) surfaces the persisted enrichment risk
    level/score, the leading enrichment_risk_reasons entry, and the
    recommended_next_action text in the rendered narrative.
    """
    result = {
        "enrichment_risk_level": "High",
        "enrichment_risk_score": 82,
        "enrichment_risk_reasons": ["VirusTotal confirmed a malicious hash."],
        "warnings": ["OTX was not queried because its key is unavailable."],
        "recommended_next_action": "Continue to Investigation.",
    }

    text = sw.render_agent_thinking_plain(
        "Threat Intelligence Enrichment", result
    )

    assert "risk High with a score of 82" in text
    assert "VirusTotal confirmed" in text
    assert "Continue to Investigation" in text


# [FYP-EVALUATOR]
def test_investigation_thinking_uses_sync_and_orchestrator_outputs():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain("Investigation",
    ...) names the two collaborating investigation-agent modules
    (sync_engine.py, orchestrator.py) and parses the Markdown "Playbook
    Execution Trace" table out of narrative_report, asserting each step's
    MET/NOT_MET status and the overall severity appear in the rendered
    narrative.
    """
    result = {
        "incident_id": "INC-42",
        "investigated_for": "INC-42",
        "incident_folder": "Incident-007",
        "cluster_alert_ids": ["INC-42", "INC-43"],
        "severity": "High",
        "summary": "The available evidence supports lateral movement.",
        "narrative_report": """
## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify the affected host | **MET** | Host WS-42 was identified. |
| `step_2` | Validate a process tree | **NOT_MET** | Process telemetry is missing. |

## Recommended Containment Actions
""",
    }

    text = sw.render_agent_thinking_plain("Investigation", result)

    assert "sync_engine.py synchronized" in text
    assert "orchestrator.py evaluated" in text
    assert "step_1 MET" in text
    assert "step_2 NOT_MET" in text
    assert "severity is High" in text


def test_reporting_thinking_uses_persisted_manifest_and_quality_checks():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain("Reporting",
    ...) counts sections in report_manifest, and reports the
    completeness/quality scores and the "analyst review and approval gate"
    framing rather than a raw dump of the manifest.
    """
    result = {
        "report_status_display": "Draft ready for analyst review",
        "report_completeness_score": 94,
        "report_quality_score": 91,
        "validation_status_display": "Requires analyst validation",
        "report_manifest": {
            "sections": {
                "executive_summary": {},
                "technical_findings": {},
                "final_incident_report": {},
            }
        },
    }

    text = sw.render_agent_thinking_plain("Reporting", result)

    assert "produced 3 report section(s)" in text
    assert "completeness 94" in text
    assert "quality 91" in text
    assert "analyst review and approval gate" in text


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] render_agent_thinking_plain() — durable workflow_state /
# activity timeline branch (My Workspace's live progress narrative)
# ══════════════════════════════════════════════════════════════════════════

def test_completed_stage_thinking_is_timestamped_progress_not_result_dump():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain() with
    workflow_state + activity supplied for a stage that has already
    finished: asserts the rendered text reports the
    stage_started/stage_succeeded activity timestamps, the elapsed stage
    time, and the "awaiting SOC analyst approval" current-stage phrase —
    and, critically, does NOT leak the raw result's long free-text
    "summary" field or agent-module implementation detail (orchestrator.py,
    sync_engine.py) once the durable timeline is available, unlike the
    result-only fallback branch exercised above.
    """
    result = {
        "status": "completed",
        "summary": "Very long investigation finding that belongs in output.",
        "investigation_updated_at": "2026-07-26T08:15:30+00:00",
    }
    workflow_state = {
        "investigation_status": "Awaiting Approval",
        "investigation_updated_at": "2026-07-26T08:15:30+00:00",
        "workflow_updated_at": "2026-07-26T08:15:30+00:00",
    }
    activity = [
        {
            "stage": "investigation",
            "action": "stage_started",
            "timestamp": "2026-07-26T08:10:00+00:00",
        },
        {
            "stage": "investigation",
            "action": "stage_succeeded",
            "timestamp": "2026-07-26T08:15:30+00:00",
        },
    ]

    text = sw.render_agent_thinking_plain(
        "Investigation",
        result,
        workflow_state=workflow_state,
        activity=activity,
    )

    assert "2026-07-26 08:10:00 UTC — Investigation started." in text
    assert "2026-07-26 08:15:30 UTC — Investigation processing completed." in text
    assert "Current stage: Investigation is complete and awaiting SOC analyst approval." in text
    assert "Elapsed stage time: 00:05:30." in text
    assert "Very long investigation finding" not in text
    assert "orchestrator.py" not in text
    assert "sync_engine.py" not in text


def test_processing_stage_thinking_shows_live_heartbeat_and_progress_note():
    """[FYP-FUNCTION] Validates render_agent_thinking_plain() with
    workflow_state for a stage that is still "Processing": asserts the
    rendered text reports the stage-started timestamp, the current worker
    heartbeat timestamp as a "processing" progress line, and the
    worker_progress_note text (live status, not a finished-stage summary),
    even though `activity` is empty and `result` is `{}`.
    """
    workflow_state = {
        "investigation_status": "Processing",
        "worker_stage": "investigation",
        "worker_started_at": "2026-07-26T08:20:00+00:00",
        "worker_heartbeat_at": "2026-07-26T08:22:10+00:00",
        "worker_progress_note": "Waiting for Investigation capacity",
    }

    text = sw.render_agent_thinking_plain(
        "Investigation",
        {},
        workflow_state=workflow_state,
        activity=[],
    )

    assert "2026-07-26 08:20:00 UTC — Investigation started." in text
    assert "2026-07-26 08:22:10 UTC — Current stage: Investigation is processing" in text
    assert "Waiting for Investigation capacity" in text
