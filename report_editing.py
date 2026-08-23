"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to agents/reporting/report_editing.py
during Phase 8. This module replaces itself in sys.modules with the real
module object so `import report_editing` keeps working for not-yet-migrated
callers. There is only one implementation.
"""

import sys

from agents.reporting import report_editing as _report_editing

sys.modules[__name__] = _report_editing
