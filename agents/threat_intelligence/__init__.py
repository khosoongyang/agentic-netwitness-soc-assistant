"""Canonical Threat Intelligence Enrichment agent.

threat_intel.py orchestrates provider lookups (VirusTotal, AbuseIPDB,
AlienVault OTX) for the Threat Intelligence Enrichment stage. Provider
clients themselves belong under integrations/threat_intel/ if/when they are
separated out; that split is deferred (Phase 9 territory), so this stage
module still owns provider calls directly for now.
"""
