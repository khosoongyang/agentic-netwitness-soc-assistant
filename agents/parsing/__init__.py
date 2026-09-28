"""Canonical parsing/normalisation agent.

Turns a raw NetWitness alert/incident into the normalised processed_alert
structure consumed by Triage. run_parser_normalisation_for_dashboard() is
called in-process by workflow/engine.py's run_parsing() -- via this
package's own __init__, not by reaching into parser_normaliser.py
directly, so this is the supported import boundary for the subsystem:

    from agents.parsing import run_parser_normalisation_for_dashboard

parser_context_guard.py and powershell_decoder.py are internal
collaborators of run_parser_normalisation_for_dashboard() (input/output
identity validation and PowerShell -EncodedCommand decoding,
respectively) and are not re-exported here; import them directly from
their own modules if a caller genuinely needs those primitives on their
own, as agents/reporting/adapters/run_parser_normalisation.py does.
"""

from agents.parsing.parser_normaliser import run_parser_normalisation_for_dashboard

__all__ = ["run_parser_normalisation_for_dashboard"]
