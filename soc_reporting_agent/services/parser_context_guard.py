"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to agents/parsing/parser_context_guard.py
during Phase 8. Kept here only because soc_reporting_agent/backend/{app,
casework_store,postgres_casework_store}.py — donor code not used by the
canonical Aegis application — still import it by this path under
soc_reporting_agent/'s own sys.path convention (which does not include the
repository root). There is only one implementation.

soc_reporting_agent/ also has its own agents/ package (the donor
reporting_agent.py). Whenever soc_reporting_agent/ precedes the repository
root on sys.path (as it does for every soc_reporting_agent-internal script
and test), a same-named "agents" package on both paths resolves to whichever
one sys.path reaches first — so the repository root must be forced to the
very front, not merely appended if absent, or `import agents.parsing` would
silently resolve to soc_reporting_agent/agents/ (no `parsing` submodule)
instead of the canonical one.
"""

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
sys.path = [p for p in sys.path if p != _REPO_ROOT]
sys.path.insert(0, _REPO_ROOT)

from agents.parsing import parser_context_guard as _parser_context_guard

sys.modules[__name__] = _parser_context_guard
