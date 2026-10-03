"""tests/test_triage_step3_frontend.py -- [FYP-TRIAGE-STEP3] X1/X3 frontend.

Runs the REAL frontend/js/components/triageReview.js under Node (skipped if
Node.js is not installed) to check, without a browser:
  * XSS: attacker-controlled evidence (command line / alert text) renders
    inert -- `<img src=x onerror=alert(1)>` only ever appears escaped;
  * blind_first: the AI verdict and hypotheses are absent until revealed;
  * the review form's required-field rules (buildReview mirrors TriageReview);
  * the dropdown starts EMPTY (never preselects the AI's disposition);
plus static checks: sidebar links for every router view + Triage Feedback,
the route registration, and that workspace.js only wires the component.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from test_triage_step3_review import _triage_result

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "frontend" / "js" / "components" / "triageReview.js"
NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
XSS = "<img src=x onerror=alert(1)>"


def _node(script: str, payload: dict) -> dict:
    module = json.dumps(COMPONENT.as_uri())
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", script.replace("__MODULE__", module)],
        input=json.dumps(payload, default=str), capture_output=True, text=True,
        encoding="utf-8", timeout=60, check=False)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


_READ = """
let input = ""; process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const payload = JSON.parse(input);
"""


def _xss_result() -> dict:
    tri = _triage_result("needs_info", proposed="benign_expected")
    p = tri["evidence_packet"]
    p["detection"]["createdBy"]["value"] = XSS
    sig = p["raw_alerts"]["signatures"]
    sig["value"]["items"][0]["alert_name"] = XSS
    sig["value"]["items"][0]["command_line"] = f"powershell -enc {XSS}"
    tri["assessment"]["hypotheses"]["malicious"]["evidence_for"][0]["claim"] = XSS
    tri["assessment"]["guard_actions"] = [{"rule": "a_missing_mandatory_evidence", "from": "benign_expected",
                                          "to": "needs_info", "reason": XSS}]
    tri["assessment"]["citation_errors"] = [{"location": "x", "path": XSS, "error": "unknown_path"}]
    return tri


@requires_node
def test_review_screen_escapes_every_attacker_controlled_value():
    out = _node("import { reviewScreenHTML } from __MODULE__;" + _READ +
                "process.stdout.write(JSON.stringify({html: reviewScreenHTML(payload, "
                "{revealed: true, awaitingApproval: true})}));", _xss_result())
    html = out["html"]
    assert XSS not in html
    assert "<img" not in html and "onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    # Plain-language guard change + invalid citation struck through.
    assert "Changed to Needs-info" in html and "<s><code>&lt;img" in html


@requires_node
def test_blind_first_hides_ai_verdict_and_hypotheses_until_reveal():
    out = _node("import { reviewScreenHTML } from __MODULE__;" + _READ +
                "process.stdout.write(JSON.stringify({blind: reviewScreenHTML(payload, "
                "{revealed: false, awaitingApproval: true}), open: reviewScreenHTML(payload, "
                "{revealed: true, awaitingApproval: true})}));", _triage_result("needs_info"))
    blind, opened = out["blind"], out["open"]
    assert "ai-final-disposition" not in blind and "Competing hypotheses" not in blind
    assert "Record initial verdict" in blind
    assert "ai-final-disposition" in opened and "Competing hypotheses" in opened
    # Dropdown starts empty in both modes (no option is preselected).
    assert re.search(r'<option value="[a-z_]+" selected>', blind) is None
    assert re.search(r'<option value="[a-z_]+" selected>', opened) is None


_BUILD = "import { buildReview } from __MODULE__;" + _READ + \
    "process.stdout.write(JSON.stringify(buildReview(payload.values, payload.opts)));"


@requires_node
@pytest.mark.parametrize(("values", "opts", "expect_error"), [
    ({}, {"aiFinal": "true_positive", "reviewMode": "assisted"}, "Choose an analyst disposition"),
    ({"analyst_disposition": "true_positive", "justification": "j"},
     {"aiFinal": "true_positive", "reviewMode": "assisted"}, "at least one piece of evidence"),
    ({"analyst_disposition": "needs_info", "evidence_checked": ["baseline"], "justification": "j"},
     {"aiFinal": "needs_info", "reviewMode": "assisted"}, "lookalike"),
    ({"analyst_disposition": "false_positive", "evidence_checked": ["baseline"], "justification": "j",
      "lookalike_considered": "x", "disagreement_reason": "r"},
     {"aiFinal": "needs_info", "reviewMode": "assisted"}, "rule tuning note"),
    ({"analyst_disposition": "benign_expected", "evidence_checked": ["baseline"], "justification": "j",
      "lookalike_considered": "x", "bc_who": "it"},
     {"aiFinal": "benign_expected", "reviewMode": "assisted"}, "who, when and why"),
    ({"analyst_disposition": "true_positive", "evidence_checked": ["baseline"], "justification": "j"},
     {"aiFinal": "needs_info", "reviewMode": "assisted"}, "You disagree with the AI"),
    ({"analyst_disposition": "true_positive", "evidence_checked": ["baseline"], "justification": "j",
      "disagreement_reason": "r"},
     {"aiFinal": "needs_info", "reviewMode": "blind_first", "initialDisposition": "needs_info"},
     "revised your initial disposition"),
])
def test_form_required_field_rules(values, opts, expect_error):
    out = _node(_BUILD, {"values": values, "opts": opts})
    assert any(expect_error in e for e in out["errors"]), out["errors"]


@requires_node
def test_form_builds_a_server_valid_review():
    from agents.triage.review import validate_review
    out = _node(_BUILD, {"values": {
        "analyst_disposition": "benign_expected", "evidence_checked": ["baseline", "raw_alerts"],
        "evidence_other": "called the IT owner", "justification": "Approved WSUS push.",
        "lookalike_considered": "masquerading updater", "bc_who": "IT ops", "bc_when": "Sun 02:00",
        "bc_why": "CHG-1", "disagreement_reason": "context known", "propose_suppression": True,
        "sp_source": "ESA / r1", "sp_entity": "10.0.0.5", "sp_days": "14"},
        "opts": {"aiFinal": "needs_info", "reviewMode": "assisted"}})
    assert out["errors"] == []
    r = validate_review(out["review"], ai_final_disposition="needs_info")
    assert r.suppression_proposal.expiry_days == 14 and r.evidence_checked[-1] == "called the IT owner"


def test_sidebar_has_every_router_view_and_triage_feedback():
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    router = (ROOT / "frontend" / "js" / "router.js").read_text(encoding="utf-8")
    views = re.search(r"\[(\"case\".*?)\]\.includes", router).group(1)
    for view in [v.strip().strip('"') for v in views.split(",")]:
        if view == "case":
            continue      # a single case is reached from Cases, not the sidebar
        assert f'data-nav="{view}"' in html, view
    assert 'data-nav="triage-feedback"' in html and '"triage-feedback"' in router
    assert "renderTriageFeedback" in (ROOT / "frontend" / "js" / "app.js").read_text(encoding="utf-8")


def test_workspace_only_wires_the_component_and_never_renders_markdown_evidence():
    ws = (ROOT / "frontend" / "js" / "pages" / "workspace.js").read_text(encoding="utf-8")
    assert 'from "../components/triageReview.js"' in ws and "mountTriageReview(" in ws
    comp = COMPONENT.read_text(encoding="utf-8")
    page = (ROOT / "frontend" / "js" / "pages" / "triageFeedback.js").read_text(encoding="utf-8")
    for src in (comp, page):
        assert "marked" not in src and "DOMPurify" not in src
