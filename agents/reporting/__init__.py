"""Canonical Reporting agent.

Owns report generation, editing, approval, export (DOCX/PDF), templates,
schemas and the CLI/subprocess adapters workflow/engine.py's reporting
stage shells out to. This package was moved here wholesale from
soc_reporting_agent/ (formerly the repository's largest single subtree) —
its internal structure (reporting/, config/, adapters/, report_templates/,
report_assets/, ...) is preserved unchanged rather than flattened, since
those internal modules cross-reference each other by bare top-level names
(`from reporting.X import Y`, `from config import settings`, ...) throughout,
and a Phase 8 move is not licence to rewrite dozens of call sites.

Those bare cross-references rely on this package's own directory being on
sys.path (the same convention every subprocess adapter and workflow/engine.py
already use via REP_DIR). Importing this package guarantees that once, here,
so every submodule underneath it — reached however it's reached — sees the
exact same `reporting`/`config`/`adapters`/... module objects rather than a
second, divergent copy imported under a different sys.path entry.

soc_reporting_agent/backend/app.py (a donor Flask application never used by
the canonical Aegis app) and soc_reporting_agent/dashboard/ (its UI) moved
along inside backend/ and dashboard/ - still unused by the canonical app,
still a Phase 9 deletion candidate.
"""

import sys as _sys
from pathlib import Path as _Path

_REP_DIR = _Path(__file__).resolve().parent
_REPO_ROOT = str(_REP_DIR.parent.parent)
_REP_DIR_STR = str(_REP_DIR)

# Repo root must win first for top-level names both trees define (this
# package has its own donor agents/reporting/agents/ - without repo root
# forced ahead of it, bare `import agents.parsing` etc. from elsewhere in
# the same process could silently resolve into that donor package instead).
_sys.path = [p for p in _sys.path if p not in (_REPO_ROOT, _REP_DIR_STR)]
_sys.path.insert(0, _REPO_ROOT)
_sys.path.insert(1, _REP_DIR_STR)

del _sys, _Path, _REP_DIR, _REPO_ROOT, _REP_DIR_STR
