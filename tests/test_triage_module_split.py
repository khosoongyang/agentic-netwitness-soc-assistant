"""tests/test_triage_module_split.py -- audit T-22.

soc_triage_agent.py (2,577 lines) was split by responsibility into
checklists.py, llm_json.py, incident_fields.py and display.py. The split is
a pure move: every public/private name the rest of the code base (and the
test suite) reads from soc_triage_agent must still be there, and must be the
SAME object as in its new home (so monkeypatching / mutation stays shared).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agents.triage import checklists, display, incident_fields, llm_json
from agents.triage import soc_triage_agent as sta

MOVED = {
    checklists: ["IOC_AVAILABILITY", "IOC_CONFIDENTIALITY", "IOC_INTEGRITY", "ALL_IOCS",
                 "RISK_RATING_GUIDANCE", "SOC_CLASSIFICATION_TABLE", "MITRE_TACTICS",
                 "_normalize_mitre_tactic", "_normalize_mitre_technique"],
    llm_json: ["_coerce_dict", "_extract_json", "_normalize_level", "_repair_json",
               "_VALID_LEVELS", "_SEV_ORDER"],
    incident_fields: ["_TIME_FIELDS", "_flatten", "_parse_time_utc", "_extract_incident_time",
                      "_METAKEY_MAP", "_METAKEY_NOISE", "_extract_metakey_values",
                      "_observed_metakeys", "_resolve_ioc_matches"],
    display: ["render_triage_trace", "format_ticket_display"],
}


@pytest.mark.parametrize("module,name", [(m, n) for m, ns in MOVED.items() for n in ns])
def test_moved_name_is_reexported_as_the_same_object(module, name):
    assert getattr(sta, name) is getattr(module, name)


def test_package_public_api_unchanged():
    import agents.triage as pkg
    for name in ("OpenAILLMConfig", "build_llm", "TriageAgent", "soc_triage_chat_respond",
                 "deep_triage_supplement", "_TRIAGE_TRIGGER", "render_triage_trace",
                 "format_ticket_display"):
        assert hasattr(pkg, name), name


def test_new_modules_do_not_import_workflow_or_flask():
    root = Path(sta.__file__).resolve().parent
    for mod in ("checklists", "llm_json", "incident_fields", "display"):
        text = (root / f"{mod}.py").read_text(encoding="utf-8")
        assert "from workflow" not in text and "import workflow" not in text
        assert "flask" not in text.lower()


def test_agent_module_is_smaller():
    lines = len(Path(sta.__file__).read_text(encoding="utf-8").splitlines())
    assert lines < 2000, lines
