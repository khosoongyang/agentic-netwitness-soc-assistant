"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to workflow/state_store.py during Phase 8.
This module replaces itself in sys.modules with the real module object (not
a wildcard re-export) so every attribute — including underscore-prefixed
internals that tests/conftest.py monkeypatch directly (e.g. DB_FILE) —
stays live and identical to workflow.state_store. There is only one
implementation; this file exists solely so `import workflow_state_store`
keeps working for not-yet-migrated callers.
"""

import sys

from workflow import state_store as _state_store

sys.modules[__name__] = _state_store
