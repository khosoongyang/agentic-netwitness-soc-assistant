"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to agents/reporting/reporting_approval.py
during Phase 8. This module replaces itself in sys.modules with the real
module object so `import reporting_approval` keeps working for
not-yet-migrated callers. There is only one implementation.
"""

import sys

from agents.reporting import reporting_approval as _reporting_approval

sys.modules[__name__] = _reporting_approval
