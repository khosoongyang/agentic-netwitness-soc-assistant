"""tests/test_investigation_key_findings.py -- the Investigation stage's
"Key findings" card (backend/services/case_view_service.py::
_build_investigation_key_findings() and frontend/js/pages/workspace.js::
findings()).

Covers: analyst-facing titles derived from each playbook step's own
conclusion (never the raw playbook question), truthful categories with no
fabricated confidence, deterministic ranking, deterministic de-duplication,
presentation-only shortening (the stored result is never mutated), evidence
chips that are literal substrings of the stored text, the fallbacks, stage
isolation from Threat Intelligence, the Processing-state gate, and the
frontend card rendering.
"""
from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import backend.services.case_view_service as cv

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_JS = ROOT / "frontend" / "js" / "pages" / "workspace.js"
UI_JS = ROOT / "frontend" / "js" / "ui.js"
NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

Q_IDENTITY = "Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System"
Q_MOVEMENT = "Was it horizontal or vertical"
Q_PROCESS = "Was any malicious process spawned on the victim's machine?"
Q_TREE = ("Analyze the process tree for signs of malicious activity, such as privilege "
          "escalation, lateral movement, or data exfiltration.")
Q_DECISION = ("Based on the analysis, determine if further investigation is necessary and "
              "the containment steps")
RAW_QUESTIONS = {Q_IDENTITY, Q_MOVEMENT, Q_PROCESS, Q_TREE, Q_DECISION}


def _step(step_id: str, instruction: str, findings: str, status: str = "MET") -> dict:
    return {"step_id": step_id, "instruction": instruction, "status": status, "findings": findings}


def _mitre(tid: str, tactic: str, name: str, evidence: str, phase: str = "Activity phase") -> dict:
    return {"technique_id": tid, "tactic": tactic, "technique_name": name,
            "observed_evidence": evidence, "timeline_phase": phase}


def _endpoint_result() -> dict:
    """Shaped like a real stored privilege-escalation playbook result."""
    return {
        "status": "completed", "severity": "High", "confidence": "Medium",
        "severity_justification": "Multiple high-risk endpoint behaviours were observed.",
        "recommended_containment": ["Isolate host WS-ALPHA from the network immediately."],
        "execution_trace": [
            _step("step_1", Q_IDENTITY,
                  "Username observed in the incident is NT AUTHORITY\\SYSTEM. Source IPv4 "
                  "10.1.1.20. Computer name is WS-ALPHA. Operating system is Windows 10 Pro."),
            _step("step_2", Q_MOVEMENT,
                  "The evidence supports horizontal movement/lateral activity rather than vertical "
                  "privilege escalation. Internal host-to-host activity was observed."),
            _step("step_3", Q_PROCESS,
                  "Yes. The timeline shows suspicious process activity on WS-ALPHA including "
                  "evil.exe running as NT AUTHORITY\\SYSTEM, along with cmd.exe and powershell.exe."),
            _step("step_4", Q_TREE,
                  "The timeline does not include a reconstructable process tree.", status="NOT_MET"),
            _step("step_5", Q_DECISION,
                  "Further investigation is necessary and containment is warranted. Isolate WS-ALPHA."),
        ],
        "mitre_mappings": [
            _mitre("T1059", "Execution", "Command and Scripting Interpreter",
                   "cmd.exe and powershell.exe -ExecutionPolicy Bypass were present in telemetry."),
            _mitre("T1021", "Lateral Movement", "Remote Services",
                   "Internal IPs such as 10.1.1.20 and 10.1.1.21 were referenced in grouped alerts."),
            _mitre("T1071.001", "Command and Control", "Application Layer Protocol: Web Protocols",
                   "evil.exe on WS-ALPHA generated outbound HTTPS to 203.0.113.50."),
            _mitre("T1548", "Privilege Escalation", "Abuse Elevation Control Mechanism",
                   'reg.exe ADD "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
                   "/v EnableLUA /d 0 modified the UAC policy key."),
            _mitre("T1562", "Defense Evasion", "Impair Defenses",
                   "wevtutil.exe uninstall-manifest commands were observed."),
        ],
    }


def _titles(findings: list[dict]) -> list[str]:
    return [f["title"] for f in findings]


# ── Titles ────────────────────────────────────────────────────────────────

def test_titles_are_conclusions_not_raw_playbook_questions():
    findings = cv._build_investigation_key_findings(_endpoint_result())
    assert not RAW_QUESTIONS & set(_titles(findings))
    assert _titles(findings)[:3] == ["Suspicious Process Activity Identified",
                                     "Horizontal Movement Identified",
                                     "User and Host Context Identified"]


def test_movement_title_only_when_the_findings_text_supports_it():
    undetermined = _step("step_2", Q_MOVEMENT,
                         "Horizontal vs vertical movement cannot be determined from the timeline.")
    vertical = _step("step_2", Q_MOVEMENT, "Vertical movement. A higher-privilege token was obtained.")
    both = _step("step_2", Q_MOVEMENT, "Both horizontal and vertical activity appear in the timeline.")
    for step, expected in ((undetermined, "Movement Direction Assessment"),
                           (vertical, "Vertical Movement Identified"),
                           (both, "Movement Direction Assessment")):
        [finding] = cv._build_investigation_key_findings({"execution_trace": [step]})[:1]
        assert finding["title"] == expected


def test_process_title_reads_the_answer_and_falls_back_to_neutral():
    yes = _step("step_3", Q_PROCESS, "Yes. powershell.exe was spawned by winword.exe on the host.")
    no = _step("step_3", Q_PROCESS, "No. Only signed vendor processes were observed on the host.")
    unclear = _step("step_3", Q_PROCESS, "The telemetry shows several processes on the host machine.")
    no_telemetry = _step("step_3", Q_PROCESS,
                         "No process creation telemetry is present, so this cannot be confirmed.")
    assert cv._build_investigation_key_findings({"execution_trace": [yes]})[0]["title"] == \
        "Suspicious Process Activity Identified"
    assert cv._build_investigation_key_findings({"execution_trace": [no]})[0]["title"] == \
        "No Malicious Process Identified"
    assert cv._build_investigation_key_findings({"execution_trace": [unclear]})[0]["title"] == \
        "Process Execution Review"
    # "No process creation telemetry" is a data gap, not a "no malicious process" verdict.
    assert cv._build_investigation_key_findings({"execution_trace": [no_telemetry]})[0]["title"] == \
        "Process Execution Review"


def test_phishing_and_unrecognised_steps_get_readable_titles():
    trace = [
        _step("step_2", "Does phishing attempt contain a URL or attachment?",
              "Yes. The email contains a URL pointing to a credential-harvesting page."),
        _step("step_9", "Check whether the mailbox rules were tampered with?",
              "Mailbox forwarding rules were reviewed and none were altered."),
        _step("step_8", "Summarise it?", "Nothing unusual was recorded for this particular step."),
    ]
    titles = _titles(cv._build_investigation_key_findings({"execution_trace": trace}))
    assert titles == ["Phishing Email Contains URL", "Email / Phishing Review",
                      "Playbook step_8 Finding"]


def test_raw_question_is_kept_only_as_source_detail():
    findings = cv._build_investigation_key_findings(_endpoint_result())
    movement = next(f for f in findings if f["title"] == "Horizontal Movement Identified")
    assert movement["source"]["label"] == "Playbook step_2"
    assert movement["source"]["detail"] == f"Playbook question: {Q_MOVEMENT}"


# ── Categories / confidence ───────────────────────────────────────────────

def test_no_fabricated_confidence_and_truthful_categories():
    findings = cv._build_investigation_key_findings(_endpoint_result())
    assert all("confidence" not in f for f in findings)
    by_title = {f["title"]: f["category"] for f in findings}
    assert by_title["Suspicious Process Activity Identified"] == "agent_inference"
    assert by_title["Command-and-Control Activity"] == "correlation"
    assert "observed" not in by_title.values()


def test_decision_step_is_an_assessment_and_only_fills_spare_slots():
    result = _endpoint_result()
    assert "Further Investigation Required" not in _titles(
        cv._build_investigation_key_findings(result))
    result["mitre_mappings"] = []
    findings = cv._build_investigation_key_findings(result)
    decision = next(f for f in findings if f["title"] == "Further Investigation Required")
    assert decision["category"] == "assessment"
    assert findings[-1] is decision


def test_not_met_steps_are_excluded():
    result = _endpoint_result()
    findings = cv._build_investigation_key_findings(result)
    assert "Process Tree Analysis" not in _titles(findings)


# ── Ranking / cap ─────────────────────────────────────────────────────────

def test_ranking_is_by_significance_not_list_order():
    result = _endpoint_result()
    result["execution_trace"].reverse()
    result["mitre_mappings"].reverse()
    findings = cv._build_investigation_key_findings(result)
    assert _titles(findings) == ["Suspicious Process Activity Identified",
                                 "Horizontal Movement Identified",
                                 "User and Host Context Identified",
                                 "Command-and-Control Activity",
                                 "Privilege Escalation Activity"]


def test_cap_is_five_and_higher_priority_tactics_win():
    tactics = [("T1046", "Discovery"), ("T1070", "Defense Evasion"), ("T1053", "Persistence"),
               ("T1041", "Exfiltration"), ("T1003", "Credential Access"),
               ("T1486", "Impact"), ("T1566", "Initial Access")]
    result = {"mitre_mappings": [_mitre(tid, tactic, f"Technique {i}", f"Evidence line number {i}.")
                                 for i, (tid, tactic) in enumerate(tactics)]}
    findings = cv._build_investigation_key_findings(result)
    assert len(findings) == 5
    assert [f["mitre_ids"][0] for f in findings] == ["T1041", "T1486", "T1003", "T1053", "T1070"]


def test_hedged_mapping_is_labelled_possible_and_ranked_below_confirmed():
    result = {"mitre_mappings": [
        _mitre("T1021", "Lateral Movement", "Remote Services",
               "The alert label flagged lateral movement, but no internal peer host was present.",
               phase="Unconfirmed lateral-movement label"),
        _mitre("T1046", "Discovery", "Network Service Discovery", "mDNS traffic to 224.0.0.251."),
    ]}
    findings = cv._build_investigation_key_findings(result)
    assert _titles(findings) == ["Discovery Activity", "Possible Lateral Movement Activity"]


# ── De-duplication ────────────────────────────────────────────────────────

def test_mitre_folds_into_matching_conclusion_and_same_family_merges():
    findings = cv._build_investigation_key_findings(_endpoint_result())
    by_title = {f["title"]: f for f in findings}
    assert by_title["Suspicious Process Activity Identified"]["mitre_ids"] == ["T1059"]
    movement = by_title["Horizontal Movement Identified"]
    assert movement["mitre_ids"] == ["T1021"]
    # Chips absorbed from the folded mapping are literal values from its text.
    assert "10.1.1.21" in movement["evidence_values"]

    family = {"mitre_mappings": [
        _mitre("T1071", "Command and Control", "Application Layer Protocol", "DNS to 8.8.8.8."),
        _mitre("T1071.004", "Command and Control", "Application Layer Protocol: DNS",
               "UDP/53 to 8.8.8.8 repeatedly."),
    ]}
    [merged] = cv._build_investigation_key_findings(family)[:1]
    assert merged["mitre_ids"] == ["T1071", "T1071.004"]


def test_theme_match_is_preferred_over_token_match():
    result = _endpoint_result()
    # A Lateral Movement mapping that also shares two process names with
    # the process conclusion must fold into the movement conclusion.
    result["mitre_mappings"] = [_mitre("T1021.002", "Lateral Movement", "SMB/Windows Admin Shares",
                                       "cmd.exe and powershell.exe ran over admin shares.")]
    by_title = {f["title"]: f for f in cv._build_investigation_key_findings(result)}
    assert by_title["Horizontal Movement Identified"]["mitre_ids"] == ["T1021.002"]
    assert by_title["Suspicious Process Activity Identified"]["mitre_ids"] == []


def test_token_overlap_merges_but_ambient_tokens_do_not():
    overlapping = {"mitre_mappings": [
        _mitre("T1071.001", "Command and Control", "Web Protocols",
               "evil.exe beaconed to 203.0.113.50 over HTTPS."),
        _mitre("T1569.002", "Execution", "Service Execution",
               "evil.exe ran as a service and contacted 203.0.113.50."),
    ]}
    assert len(cv._build_investigation_key_findings(overlapping)) == 1

    ambient = {"mitre_mappings": [
        _mitre("T1543", "Persistence", "System Services", "svchost.exe and services.exe activity."),
        _mitre("T1047", "Lateral Movement", "WMI", "services.exe and svchost.exe under SYSTEM."),
    ]}
    assert len(cv._build_investigation_key_findings(ambient)) == 2


def test_distinct_same_tactic_mappings_get_distinct_titles():
    result = {"mitre_mappings": [
        _mitre("T1071.001", "Command and Control", "Application Layer Protocol: Web Protocols",
               "beacon.exe contacted 203.0.113.50 over HTTPS."),
        _mitre("T1105", "Command and Control", "Ingress Tool Transfer",
               "powershell.exe downloaded C:\\Users\\Public\\tool.msi from 198.51.100.7."),
    ]}
    titles = _titles(cv._build_investigation_key_findings(result))
    assert len(titles) == len(set(titles)) == 2
    assert "Command-and-Control Activity" in titles


def test_assessments_are_never_folded_into_behaviour_findings():
    result = {"execution_trace": [
        _step("step_5", Q_DECISION, "Further investigation is necessary. Block 203.0.113.50 and "
                                    "10.1.1.20 at the perimeter."),
    ], "mitre_mappings": [
        _mitre("T1071", "Command and Control", "Application Layer Protocol",
               "10.1.1.20 connected to 203.0.113.50."),
    ]}
    assert _titles(cv._build_investigation_key_findings(result)) == [
        "Command-and-Control Activity", "Further Investigation Required"]


# ── Shortening / evidence chips / immutability ────────────────────────────

def test_long_text_is_shortened_for_display_only():
    long_sentence = ("The host executed " + ", ".join(f"proc{i}.exe" for i in range(60))
                     + " during the incident window.")
    result = {"execution_trace": [_step("step_3", Q_PROCESS, f"Yes. {long_sentence} More detail.")]}
    stored = copy.deepcopy(result)
    [finding] = cv._build_investigation_key_findings(result)
    assert result == stored
    assert len(finding["desc"]) <= cv._INV_SUMMARY_MAX_CHARS + 1
    assert finding["desc"].endswith("…")
    assert finding["truncated"] is True
    assert not finding["desc"].startswith("Yes.")
    assert len(finding["evidence_values"]) <= cv._INV_MAX_CHIPS


def test_short_text_is_kept_whole():
    text = "cmd.exe ran whoami on the host."
    [finding] = cv._build_investigation_key_findings(
        {"mitre_mappings": [_mitre("T1033", "Discovery", "System Owner/User Discovery", text)]})
    assert finding["desc"] == text
    assert finding["truncated"] is False


def test_evidence_chips_are_literal_substrings_of_stored_text():
    result = _endpoint_result()
    result["mitre_mappings"].append(_mitre(
        "T1071.004", "Command and Control", "DNS",
        "Lookups for starhub.net.sg and bad-domain.com via 8.8.8.8 with hash "
        "8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c."))
    stored_text = json.dumps(result)
    for finding in cv._build_investigation_key_findings(result):
        for chip in finding["evidence_values"]:
            assert json.dumps(chip)[1:-1] in stored_text
    tokens = cv._inv_evidence_tokens("Lookups for starhub.net.sg and bad-domain.com at 999.1.1.1.")
    assert tokens == ["bad-domain.com"]


# ── Fallbacks / isolation / gating ────────────────────────────────────────

def test_fallbacks():
    containment = cv._build_investigation_key_findings(
        {"recommended_containment": ["Isolate 10.1.1.20 now."]})
    assert _titles(containment) == ["Containment Recommended"]
    assert containment[0]["category"] == "assessment"

    severity = cv._build_investigation_key_findings(
        {"severity": "High", "severity_justification": "Endpoint compromise indicators."})
    assert _titles(severity) == ["Severity Assessment: High"]

    [placeholder] = cv._build_investigation_key_findings({"status": "completed"})
    assert placeholder["title"] == "Limited investigation telemetry"
    assert placeholder["category"] == ""
    assert cv._build_investigation_key_findings(None) == []


def test_threat_intel_reputation_is_not_pulled_in():
    result = _endpoint_result()
    result["threat_intelligence"] = {"virustotal": {"ip_results": [
        {"indicator": "203.0.113.50", "status": "completed", "malicious": 12}]}}
    rendered = json.dumps(cv._build_investigation_key_findings(result))
    assert "VirusTotal" not in rendered and "malicious_vendors" not in rendered


@pytest.mark.parametrize("status, expect_findings", [
    ("Processing", False), ("Failed", False), ("Awaiting Approval", True), ("Approved", True)])
def test_overview_only_populates_for_completed_investigation(status, expect_findings):
    state = {"triage_result_json": None, "threat_intel_status": None,
             "investigation_status": status,
             "investigation_result_json": json.dumps(_endpoint_result()),
             "ioc_correlation_status": None, "severity": "HIGH", "status": "New",
             "workflow_status": status}
    incident = {"id": "INC-KF", "title": "Test", "alertMeta": {"Hostname": ["WS-ALPHA"]}}
    overview = cv.build_overview(state, incident, "INC-KF", "run-1")
    findings = overview["key_findings_by_stage"]["investigation"]
    assert bool(findings) is expect_findings
    if expect_findings:
        assert all(f["evidence"].get("host") == "WS-ALPHA" for f in findings)


# ── Frontend card rendering ───────────────────────────────────────────────

def _findings_block() -> str:
    source = WORKSPACE_JS.read_text(encoding="utf-8")
    start = source.index("const KEY_FINDINGS_STAGES")
    end = source.index("// One action bar for every stage")
    return source[start:end]


def _render(items: list[dict], state: str = "awaiting_approval") -> str:
    script = (
        f"import {{ escapeHTML, emptyState }} from {json.dumps(UI_JS.as_uri())};\n"
        + _findings_block()
        + "\nlet input = ''; process.stdin.setEncoding('utf8');"
        "for await (const c of process.stdin) input += c;"
        "const { items, state } = JSON.parse(input);"
        "process.stdout.write(findings({ overview: { key_findings_by_stage: { investigation: items } } },"
        " { key: 'investigation', state }));"
    )
    completed = subprocess.run([NODE, "--input-type=module", "-e", script],
                               input=json.dumps({"items": items, "state": state}),
                               capture_output=True, text=True, encoding="utf-8",
                               timeout=60, check=False)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


@requires_node
def test_frontend_card_structure():
    findings = cv._build_investigation_key_findings(_endpoint_result())
    html = _render(findings)
    assert html.count('class="finding-item"') == 5
    assert "Agent inference" in html and "Correlation" in html
    assert "MITRE T1071.001" in html
    assert 'title="Playbook question: Was it horizontal or vertical"' in html
    assert 'class="finding-evidence"' in html
    # No investigation card carries a confidence span.
    assert not re.search(r"</div>\s*<span>", html)


@requires_node
def test_frontend_chip_row_skips_values_already_in_summary():
    item = {"title": "T", "desc": "evil.exe ran.", "category": "agent_inference",
            "evidence_values": ["evil.exe", "203.0.113.50"], "evidence": {}, "mitre_ids": [],
            "source": {"label": "Playbook step_3", "detail": "", "full_text": "Output tab"},
            "truncated": True}
    html = _render([item])
    row = html[html.index('class="finding-evidence"'):]
    assert "203.0.113.50" in row and "evil.exe" not in row
    assert "full text in Output tab" in html


@requires_node
def test_frontend_processing_state_shows_empty_message():
    findings = cv._build_investigation_key_findings(_endpoint_result())
    html = _render(findings, state="in_progress")
    assert "No key findings have been distilled for this stage yet." in html
    assert "finding-item" not in html
