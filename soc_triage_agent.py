"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to agents/triage/ (package) during
Phase 8. This module replaces itself in sys.modules with the real package
object so `import soc_triage_agent` / `from soc_triage_agent import ...`
keep working identically to `from agents.triage import ...` for
not-yet-migrated callers. There is only one implementation.
"""

import sys

from agents import triage as _triage

sys.modules[__name__] = _triage
