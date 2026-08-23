"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to
agents/reporting/triage_ticket_editing.py during Phase 8. This module
replaces itself in sys.modules with the real module object so
`import triage_ticket_editing` keeps working for not-yet-migrated callers.
There is only one implementation.
"""

import sys

from agents.reporting import triage_ticket_editing as _triage_ticket_editing

sys.modules[__name__] = _triage_ticket_editing
