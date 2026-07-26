from __future__ import annotations

import soc_workflow as sw


def test_parsing_thinking_prefers_persisted_parser_narrative():
    result = {
        "status": "completed",
        "selected_alert_id": "ALERT-7",
        "ai_thinking": "Host WS-7 and file sample.exe drove the parser summary.",
    }

    text = sw.render_agent_thinking_plain("Parsing", result)

    assert text == "Host WS-7 and file sample.exe drove the parser summary."


def test_triage_thinking_comes_from_trace():
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


def test_investigation_thinking_uses_sync_and_orchestrator_outputs():
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


def test_completed_stage_thinking_is_timestamped_progress_not_result_dump():
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
