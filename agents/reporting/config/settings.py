# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: os, pathlib.
# =============================================================================
# File: soc_reporting_agent/config/settings.py
# Purpose: This module loads reporting-service paths and runtime configuration from environment variables.
# Main functionality: configured_llm_providers, selected_model_for_provider, selected_llm_model.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis reporting configuration component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: os, pathlib.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: configured_llm_providers, selected_model_for_provider, selected_llm_model, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Repository root — Phase 8 moved schemas/ and knowledge_base/ to canonical,
# domain-owned top-level locations shared across agents, and later moved
# this package itself from soc_reporting_agent/ to agents/reporting/ (one
# extra nesting level under the repo root — update this again if that
# depth ever changes).
REPO_ROOT = Path(__file__).resolve().parents[3]
INPUT_DIR = Path(os.getenv("REPORTING_INPUT_DIR", PROJECT_ROOT / "inputs"))
OUTPUT_DIR = Path(os.getenv("REPORTING_OUTPUT_DIR", PROJECT_ROOT / "outputs"))
TEMPLATE_DIR = Path(os.getenv("REPORTING_TEMPLATE_DIR", PROJECT_ROOT / "report_templates"))
KNOWLEDGE_BASE_DIR = Path(os.getenv("REPORTING_KB_DIR", REPO_ROOT / "knowledge_base" / "reporting"))

USE_LLM = os.getenv("REPORTING_USE_LLM", "false").lower() == "true"
LLM_PROVIDER = os.getenv("REPORTING_LLM_PROVIDER", "openai").strip().lower()
LLM_MODEL = os.getenv("REPORTING_LLM_MODEL", "gpt-4o-mini").strip()
OLLAMA_MODEL = os.getenv("REPORTING_OLLAMA_MODEL", "llama3.2:3b").strip()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", os.getenv("REPORTING_OLLAMA_BASE_URL", "http://localhost:11434")).strip().rstrip("/")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

# LLM reliability controls. These are deliberately conservative for SOC reporting.
LLM_TIMEOUT_SECONDS = int(os.getenv("REPORTING_LLM_TIMEOUT", os.getenv("REPORTING_LLM_TIMEOUT_SECONDS", os.getenv("REPORTING_OLLAMA_TIMEOUT_SECONDS", "120"))))
LLM_NUM_PREDICT = int(os.getenv("REPORTING_LLM_NUM_PREDICT", "2200"))
LLM_TEMPERATURE = float(os.getenv("REPORTING_LLM_TEMPERATURE", "0.2"))
# Fixed sampling seed for reproducible narratives (OpenAI chat completions and
# TGI both accept it). Empty/unset -> no seed sent.
_seed_raw = os.getenv("REPORTING_LLM_SEED", "").strip()
LLM_SEED = int(_seed_raw) if _seed_raw.lstrip("-").isdigit() else None
LLM_NARRATIVE_DEPTH = os.getenv("REPORTING_LLM_NARRATIVE_DEPTH", "analyst").strip().lower()
REPORTING_REPORT_DETAIL_LEVEL = os.getenv("REPORTING_REPORT_DETAIL_LEVEL", LLM_NARRATIVE_DEPTH).strip().lower()
REPORT_DETAIL_LEVEL = REPORTING_REPORT_DETAIL_LEVEL
LLM_MOCK_MODE = os.getenv("REPORTING_LLM_MOCK_MODE", "good").strip().lower()
LLM_MAX_RETRIES = int(os.getenv("REPORTING_LLM_MAX_RETRIES", "2"))
LLM_ENABLE_PROVIDER_FALLBACK = os.getenv("REPORTING_LLM_ENABLE_PROVIDER_FALLBACK", "true").lower() == "true"
LLM_FALLBACK_PROVIDER = os.getenv("REPORTING_LLM_FALLBACK_PROVIDER", "").strip().lower()
LLM_CACHE_ENABLED = os.getenv("REPORTING_LLM_CACHE_ENABLED", "true").lower() == "true"
LLM_CACHE_DIR = Path(os.getenv("REPORTING_LLM_CACHE_DIR", PROJECT_ROOT / "outputs" / "report_cache"))

USE_RAG = os.getenv("REPORTING_USE_RAG", "true").lower() == "true"
USE_CHROMADB = os.getenv("REPORTING_USE_CHROMADB", "false").lower() == "true"
FORCE_RAG_FAILURE = os.getenv("REPORTING_FORCE_RAG_FAILURE", "false").lower() == "true"
CHROMA_DB_PATH = Path(os.getenv("REPORTING_CHROMA_DB_PATH", PROJECT_ROOT / "database" / "chromadb" / "chroma_store"))
CHROMA_COLLECTION_NAME = os.getenv("REPORTING_CHROMA_COLLECTION_NAME", "reporting_knowledge_base")

USE_POSTGRES = os.getenv("REPORTING_USE_POSTGRES", "false").lower() == "true"
POSTGRES_DSN = os.getenv("POSTGRES_DSN") or os.getenv("REPORTING_POSTGRES_DSN", "postgresql://postgres:postgres@localhost:5432/aegis_soc")

REQUIRED_KB_FILES = [
    "policies/incident_severity_policy.md",
    "policies/containment_approval_policy.md",
    "policies/reporting_timeline_policy.md",
    "procedures/report_writing_sop.md",
    "procedures/evidence_collection_sop.md",
    "procedures/investigation_sop.md",
    "playbooks/phishing_response_playbook.md",
    "playbooks/ransomware_response_playbook.md",
]


# =============================================================================
# [FYP-SECTION] REPORTING CONFIGURATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `configured_llm_providers` — implements the configured llm providers operation used by the surrounding reporting configuration workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting configuration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/llm_narrative.py:invoke_llm_with_retries; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `lower`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def configured_llm_providers() -> list[str]:
    """Return provider order for LLM calls.

    The first provider is the configured primary provider. If provider fallback is
    enabled, a secondary provider can be set with REPORTING_LLM_FALLBACK_PROVIDER.
    This avoids silently trying unrelated providers unless explicitly configured.
    """
    primary = (LLM_PROVIDER or "").strip().lower()
    providers: list[str] = []
    allowed = {"openai", "ollama", "mock"}
    if primary in allowed:
        providers.append(primary)
    if LLM_ENABLE_PROVIDER_FALLBACK and LLM_FALLBACK_PROVIDER in allowed and LLM_FALLBACK_PROVIDER not in providers:
        providers.append(LLM_FALLBACK_PROVIDER)
    return providers or ["openai"]


# [FYP-FUNCTION] `selected_model_for_provider` — implements the selected model for provider operation used by the surrounding reporting configuration workflow.
# [FYP-INPUT] Parameters: `provider`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting configuration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/config/settings.py:selected_llm_model, soc_reporting_agent/reporting/llm_narrative.py:invoke_llm, soc_reporting_agent/reporting/llm_narrative.py:invoke_llm_with_retries; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `lower`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def selected_model_for_provider(provider: str) -> str:
    provider = (provider or "").strip().lower()
    if provider == "openai":
        return LLM_MODEL
    if provider == "ollama":
        return OLLAMA_MODEL
    if provider == "mock":
        return f"mock-{LLM_MOCK_MODE}"
    return LLM_MODEL or OLLAMA_MODEL


# [FYP-FUNCTION] `selected_llm_model` — implements the selected llm model operation used by the surrounding reporting configuration workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting configuration workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/agents/reporting_agent.py:main, soc_reporting_agent/reporting/llm_narrative.py:selected_model; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `selected_model_for_provider`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def selected_llm_model() -> str:
    """Return the model that should be used for the active primary provider.

    Important: OpenAI provider must never be overridden by REPORTING_OLLAMA_MODEL.
    """
    return selected_model_for_provider(LLM_PROVIDER)
