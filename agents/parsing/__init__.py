"""Canonical parsing/normalisation agent.

Turns a raw NetWitness alert/incident into the normalised processed_alert
structure consumed by Triage. run_parser_normalisation_for_dashboard() is
called in-process by workflow/engine.py's run_parsing().
"""
