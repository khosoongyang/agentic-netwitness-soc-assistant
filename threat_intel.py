"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to
agents/threat_intelligence/threat_intel.py during Phase 8. This module
replaces itself in sys.modules with the real module object so
`import threat_intel` keeps working identically to
`from agents.threat_intelligence import threat_intel` for not-yet-migrated
callers. There is only one implementation.
"""

import sys

from agents.threat_intelligence import threat_intel as _threat_intel

sys.modules[__name__] = _threat_intel
