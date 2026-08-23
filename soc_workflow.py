"""DEPRECATED COMPATIBILITY SHIM — REMOVE IN PHASE 9.

The canonical implementation moved to workflow/engine.py during Phase 8.
This module replaces itself in sys.modules with the real module object (not
a wildcard re-export) so every attribute — including underscore-prefixed
internals that tests/conftest.py monkeypatch directly (e.g.
_TRUSTED_OUTPUT_ROOT, PIPELINE_DB_FILE) — stays live and identical to
workflow.engine. There is only one implementation; this file exists solely
so `import soc_workflow` and the documented
`python soc_workflow.py --incident-file ...` CLI entry point keep working
for not-yet-migrated callers.
"""

import sys

from workflow import engine as _engine

sys.modules[__name__] = _engine

if __name__ == "__main__":
    raise SystemExit(_engine.main())
