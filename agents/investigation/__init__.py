"""Canonical Investigation agent.

Invoked out-of-process by workflow/engine.py (`python main.py`, cwd set to
this package's directory) via a file-queue handoff: incidents are dropped
into triaged_alerts/ and results collected from incident_reports/. This
package also exposes importable helpers used directly by tests
(chroma_compat) and other in-process callers.
"""
