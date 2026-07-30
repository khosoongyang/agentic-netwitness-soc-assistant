# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, json, os, pathlib, shutil, sys.
# =============================================================================
# File: soc_reporting_agent/scripts/test_merged_report_context.py
# Purpose: This module implements test and validation behaviour for test merged report context.
# Main functionality: write_json, reset_fixture, seed_inputs, test_merged_context, main.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, json, os, pathlib, shutil, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: write_json, reset_fixture, seed_inputs, test_merged_context, main, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASE = ROOT / "testdata" / "merged_report_context"
INPUTS = BASE / "inputs"
OUTPUTS = BASE / "outputs"


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `write_json` — persists or updates write json state used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `path`, `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main, soc_reporting_agent/adapters/run_reporting.py:_copy_report_artifacts, soc_reporting_agent/adapters/run_reporting.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `mkdir`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# [FYP-FUNCTION] `reset_fixture` — persists or updates reset fixture state used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_merged_report_context.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exists`, `mkdir`, `rmtree`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def reset_fixture() -> None:
    if BASE.exists():
        shutil.rmtree(BASE)
    INPUTS.mkdir(parents=True, exist_ok=True)
    OUTPUTS.mkdir(parents=True, exist_ok=True)


# [FYP-FUNCTION] `seed_inputs` — implements the seed inputs operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_merged_report_context.py:main, soc_reporting_agent/scripts/test_reporting_appendix_context.py:main, soc_reporting_agent/scripts/test_reporting_appendix_context.py:test_failed_subprocess_not_completed; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def seed_inputs() -> None:
    evidence = [
        "severity: Critical",
        "risk_score: 98.0",
        "host: FINANCE-WKS-017",
        "ip: 10.20.14.117",
        "username: ACME\\\\lim.huiwen",
        "file_name: mssecsvc.exe",
        "process_path: C:\\Windows\\mssecsvc.exe",
        "parent_process_name: lsass.exe",
        "command_line: C:\\Windows\\mssecsvc.exe -m security",
        "destination_ip: 104.17.244.81",
        "destination_port: 80",
        "protocol: HTTP",
        "domain: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "url: http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/",
        "sha256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "mitre_technique_id: T1486",
    ]
    write_json(INPUTS / "processed_alert.json", {
        "incident_id": "INC-WANNACRY-TEST",
        "alert_id": "NW-WCRY-445-0001",
        "alert_title": "WannaCry Ransomware Activity - mssecsvc.exe",
        "hostname": "FINANCE-WKS-017",
        "source_ip": "10.20.14.117",
        "destination_ip": "104.17.244.81",
        "file_hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "url": "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/",
        "event_domain": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
    })
    write_json(INPUTS / "enriched_alert.json", {
        "incident_id": "INC-WANNACRY-TEST",
        "alert_id": "NW-WCRY-445-0001",
        "host": "FINANCE-WKS-017",
        "hostname": "FINANCE-WKS-017",
        "source_ip": "10.20.14.117",
        "destination_ip": "104.17.244.81",
        "domain": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "url": "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/",
        "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "file_name": "mssecsvc.exe",
        "process_name": "mssecsvc.exe",
        "process_path": "C:\\Windows\\mssecsvc.exe",
        "mitre_technique_id": "T1486",
        "severity": "Critical",
        "confidence": "High",
        "iocs": [
            {"type": "ip", "value": "104.17.244.81"},
            {"type": "file_name", "value": "WannaCry Ransomware Activity - mssecsvc.exe"},
            {"type": "file_name", "value": "mssecsvc.exe"},
            {"type": "file_hash", "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
        ],
        "threat_intelligence": {
            "virustotal": {
                "file_hash": {
                    "indicator": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
                    "malicious": 63,
                    "reputation": -2986,
                },
                "ip_results": [{"indicator": "104.17.244.81", "malicious": 1, "reputation": -113}],
                "domain_results": [{"indicator": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "malicious": 10, "reputation": -165}],
            }
        },
    })
    write_json(INPUTS / "triage_result.json", {
        "incident_id": "INC-WANNACRY-TEST",
        "alert_id": "NW-WCRY-445-0001",
        "severity": "Critical",
        "confidence": "High",
        "classification": "Ransomware",
        "likely_scenario": "WannaCry ransomware activity",
        "matched_iocs": [
            "104.17.244.81",
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        ],
        "evidence": evidence,
        "metakeys_payload": {
            "host": "FINANCE-WKS-017",
            "source_ip": "10.20.14.117",
            "destination_ip": "104.17.244.81",
            "domain": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
            "url": "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/",
            "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "file_name": "mssecsvc.exe",
            "mitre_technique_id": "T1486",
            "mitre_technique": "Data Encrypted for Impact",
        },
        "recommended_actions": [
            "Isolate FINANCE-WKS-017 from the network pending SOC Analyst Approval.",
            "Validate whether mssecsvc.exe is present and running on the host.",
        ],
    })
    write_json(INPUTS / "investigation_result.json", {
        "status": "completed_with_evidence_gaps",
        "incident_id": "INC-WANNACRY-TEST",
        "severity": "Critical",
        "confidence": "High",
        "classification": "Likely True Positive",
        "likely_scenario": "WannaCry ransomware activity",
        "affected_assets": ["FINANCE-WKS-017"],
        "affected_users": ["ACME\\lim.huiwen"],
        "iocs": [
            "104.17.244.81",
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
            "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/",
            "mssecsvc.exe",
        ],
        "evidence": evidence,
        "recommended_actions": [
            "Isolate FINANCE-WKS-017 from the network pending SOC Analyst Approval.",
            "Validate whether mssecsvc.exe is present and running on the host.",
        ],
        "missing_evidence": ["No additional host telemetry was supplied."],
        "reporting_mode": "with_limitations",
    })
    write_json(INPUTS / "approval_result.json", {"approval_status": "approved", "decision": "approved", "analyst": "Soong Yang", "approval_gate": "investigation_evidence_gap_decision"})


# [FYP-FUNCTION] `test_merged_context` — verifies merged context behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_merged_report_context.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `all`, `build_context`, `count`, `enhance_export_context`, `join`, `len`, `load_reporting_inputs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_merged_context() -> None:
    os.environ["REPORTING_USE_LLM"] = "false"
    from reporting.input_loader import load_reporting_inputs
    from reporting.context_builder import build_context
    from reporting.export_context_enhancer import enhance_export_context
    from reporting.report_renderer import render_reports
    from reporting.output_writer import write_outputs

    inputs, warnings = load_reporting_inputs(INPUTS)
    context = enhance_export_context(build_context(inputs, warnings, output_dir=OUTPUTS), ticket=None)
    assets = context["affected_assets"]
    assert assets[0]["hostname"] == "FINANCE-WKS-017", assets
    assert assets[0]["ip_address"] == "10.20.14.117", assets

    iocs = context["iocs"]
    values = [item["value"] for item in iocs]
    assert len(values) == len(set((item["type"], item["value"].lower()) for item in iocs)), iocs
    assert "WannaCry Ransomware Activity - mssecsvc.exe" not in values, iocs
    by_value = {item["value"]: item for item in iocs}
    assert by_value["104.17.244.81"]["evidence_refs"] == ["EV-010"], by_value["104.17.244.81"]
    assert by_value["www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]["evidence_refs"] == ["EV-013"], by_value
    assert by_value["http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/"]["evidence_refs"] == ["EV-014"], by_value
    assert by_value["ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"]["evidence_refs"] == ["EV-015"], by_value
    assert by_value["104.17.244.81"]["source"] == "VirusTotal", by_value["104.17.244.81"]
    assert by_value["104.17.244.81"]["confidence"] == "High", by_value["104.17.244.81"]
    assert context["mitre_attack_mapping"][0]["technique_id"] == "T1486", context["mitre_attack_mapping"]
    assert context["mitre_attack_mapping"][0]["evidence_refs"] == ["EV-016"], context["mitre_attack_mapping"]
    assert context["approval"]["approved_by"] == "Soong Yang", context["approval"]
    assert context["report_generation_approval"]["status"] == "approved", context["report_generation_approval"]
    assert context["report_generation_approval"]["approved_by"] == "Soong Yang", context["report_generation_approval"]
    assert context["final_analyst_review_status"] == "Requires final analyst review", context["final_analyst_review_status"]
    assert context["containment"]["recommended_action"].startswith("Isolate FINANCE-WKS-017"), context["containment"]
    assert context["containment"]["approval_status"] == "Pending analyst approval", context["containment"]
    assert context["containment"]["execution_status"] == "not_contained", context["containment"]
    assert context["original_alert_risk_score"] == "98.0", context["original_alert_risk_score"]
    assert context["final_risk_rating"] == "Critical", context["final_risk_rating"]
    assert context["relevant_playbook"] == "ransomware_response_playbook.md", context["relevant_playbook"]
    assert "playbooks/ransomware_response_playbook.md" in context["loaded_knowledge_files"], context["loaded_knowledge_files"]
    assert "ransomware_response_playbook.md" not in context["excluded_playbooks"], context["excluded_playbooks"]
    assert "Report generation approval status: Approved by Soong Yang." in "\n".join(context["approval_summary"].values()), context["approval_summary"]

    checks = context["quality_checks"]
    assert checks["fields_recovered_from_fallback_sources"] > 0, checks
    assert checks["iocs_deduplicated"] > 0, checks
    assert checks["evidence_links_recovered"] > 0, checks
    assert checks["placeholders_reduced"] > 0, checks
    assert checks["fallback_logic_used"] == "Yes", checks

    generated = render_reports(context, output_dir=OUTPUTS)
    reporting_result = write_outputs(context, generated, output_dir=OUTPUTS)
    assert reporting_result["quality_checks"]["fallback_logic_used"] == "Yes", reporting_result
    assert "field_provenance" in reporting_result, reporting_result
    assert "evidence_index" in reporting_result, reporting_result
    final_text = Path(generated["final_incident_report"]).read_text(encoding="utf-8")
    assert "FINANCE-WKS-017 | 10.20.14.117" in final_text, final_text
    assert "104.17.244.81 | ip | -113 | High | VirusTotal | EV-010" in final_text, final_text
    assert "Report generation approval status: Approved by Soong Yang." in final_text, final_text
    assert "Report Generation Approval Status" in final_text, final_text
    assert "Containment Approval Status" in final_text, final_text
    assert "Containment Execution Status" in final_text, final_text
    assert "Final Analyst Review Status" in final_text, final_text
    assert "Original Alert Risk Score: 98.0" in final_text, final_text
    assert "Final Risk Rating: Critical" in final_text, final_text
    assert "ransomware_response_playbook.md" in final_text, final_text
    assert "No framework mappings were generated" not in final_text, final_text
    assert "|---" not in final_text and "---|" not in final_text, final_text
    assert "\nApproval Status:" not in final_text, final_text
    assert "\nAnalyst Decision:" not in final_text, final_text
    assert "Recommended containment action: Isolate FINANCE-WKS-017" in final_text, final_text
    assert "No MITRE ATT&CK mapping was provided" not in final_text, final_text
    assert all(final_text.count(item) <= 1 for item in ["Not linked", "Evidence link unavailable", "Unavailable from source telemetry"]), final_text


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `dumps`, `print`, `reset_fixture`, `seed_inputs`, `str`, `sum`, `test_merged_context`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def main() -> int:
    reset_fixture()
    seed_inputs()
    results = []
    try:
        test_merged_context()
        results.append({"test": "test_merged_context", "status": "passed"})
    except Exception as exc:
        results.append({"test": "test_merged_context", "status": "failed", "error": str(exc)})
    out = {"passed": sum(1 for r in results if r["status"] == "passed"), "failed": sum(1 for r in results if r["status"] != "passed"), "results": results}
    write_json(BASE / "test_results.json", out)
    print(json.dumps(out, indent=2))
    return 0 if out["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
