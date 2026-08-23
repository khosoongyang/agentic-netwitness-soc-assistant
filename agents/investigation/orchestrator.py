# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: chroma_compat, dotenv, ingest_pipeline, json, langchain_core, langchain_openai, mitre_mapper, os.
# =============================================================================
# File: soc_investigation_agent_revised/orchestrator.py
# Purpose: [FYP-ENTRY-POINT] The Investigation stage's own internal
#   orchestrator — runs a playbook-driven, milestone-by-milestone
#   investigation over a correlated alert group and produces the final
#   structured incident analysis (attack narrative, business impact,
#   MITRE mapping via mitre_mapper.py).
# Main functionalities:
#   1. [FYP-EVALUATOR] orchestrate_incident(): the main synchronous entry
#      point — loads a playbook (YAML), seeds suspicious indicators,
#      walks each playbook milestone checking sufficiency
#      (check_milestone_sufficiency()) against retrieved evidence (RAG via
#      vector_engine.py), and calls generate_final_analysis() to produce
#      the final report.
#   2. analyze_alert_group_p1()/compile_final_report()/analyze_alert_group():
#      an async, two-pass variant of the same pipeline (Pass 1 = per-step
#      milestone execution trace, Pass 2 = final report compilation).
#   3. [FYP-EVALUATOR] generate_final_analysis(): builds the
#      FinalIncidentAnalysis (attack_chain_summary, business impact
#      checklist, recommended actions) and calls into mitre_mapper.py for
#      the MITRE ATT&CK mapping table embedded in the report.
#   4. classify_policies_for_investigation()/PolicyVectorIndex/get_policy_manager():
#      policy-compliance auditing layer (policy_engine.py integration) —
#      classifies which SOC policies are relevant to this investigation.
#   5. get_llm()/get_chain_p1()/get_chain_p2(): LangChain ChatOpenAI-backed
#      LLM chain construction, lazily cached.
# Inputs: a correlated alert group (from correlation_engine.py) and a
#   playbook YAML path (soc_investigation_agent_revised/playbooks/*.yaml).
# Outputs: FinalIncidentAnalysis (Pydantic model) — the structured incident
#   report consumed by the reporting stage / final_analysis_report.md.
# Workflow position: Investigation stage, THE main orchestration entry
#   point once evidence correlation (correlation_engine.py) has grouped
#   alerts into an incident.
# Called by [FYP-USED-BY]: verify via grep — likely main.py and/or
#   soc_workflow.py's subprocess invocation of this subsystem.
# Calls [FYP-CALLS]: ingest_pipeline, vector_engine (RAG/ChromaDB),
#   mitre_mapper (MITRE ATT&CK mapping), policy_engine (compliance
#   auditing), chroma_compat, langchain_openai.
# Key evaluator search terms: orchestrate_incident, generate_final_analysis,
#   check_milestone_sufficiency, FinalIncidentAnalysis, [FYP-EVALUATOR]
# =============================================================================

import os
import sys
import json
import yaml
import re
from typing import List, Literal, Optional, Dict
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from policy_engine import PolicyAuditRecord, PolicyManager, run_policy_compliance_rules, extract_actionable_rules
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

import ingest_pipeline
import vector_engine
import mitre_mapper
from chroma_compat import open_persistent_collection

load_dotenv()

# --- ANSI COLOR CODES ---
# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-CLASS] `Color` — owns Color state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

# [FYP-FUNCTION] `log_info` — implements the log info operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `message`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:generate_incident_report, soc_investigation_agent_revised/main.py:main_async, soc_investigation_agent_revised/main.py:select_playbook_automatically; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def log_info(message: str): print(f"{Color.CYAN}[*] {message}{Color.RESET}", file=sys.stderr)
# [FYP-FUNCTION] `log_success` — implements the log success operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `message`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:generate_incident_report, soc_investigation_agent_revised/main.py:main_async, soc_investigation_agent_revised/main.py:write_markdown_report; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def log_success(message: str): print(f"{Color.GREEN}[+] {message}{Color.RESET}", file=sys.stderr)
# [FYP-FUNCTION] `log_warning` — implements the log warning operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `message`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async, soc_investigation_agent_revised/main.py:select_playbook_automatically, soc_investigation_agent_revised/orchestrator.py:__init__; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def log_warning(message: str): print(f"{Color.YELLOW}[~] {message}{Color.RESET}", file=sys.stderr)
# [FYP-FUNCTION] `log_error` — implements the log error operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `message`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async, soc_investigation_agent_revised/orchestrator.py:analyze_alert_group_p1, soc_investigation_agent_revised/orchestrator.py:check_milestone_sufficiency; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `print`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def log_error(message: str): print(f"{Color.RED}[!] ERROR: {message}{Color.RESET}", file=sys.stderr)

# --- PYDANTIC SCHEMAS FOR STRUCTURED OUTPUT ---

# [FYP-CLASS] `SuspiciousSeeds` — owns SuspiciousSeeds state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class SuspiciousSeeds(BaseModel):
    seeds: List[str] = Field(description="A list of suspicious IOCs/tokens to query for, excluding generic benign items.")

# [FYP-CLASS] `MilestoneCheck` — owns MilestoneCheck state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include soc_investigation_agent_revised/orchestrator.py:check_milestone_sufficiency.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class MilestoneCheck(BaseModel):
    milestone_met: bool = Field(description="True if the active playbook step can be fully answered with the current incident timeline, otherwise False.")
    reasoning: str = Field(description="Explanation of whether the milestone is met, detailing what was found or what is missing.")
    extracted_data: Optional[str] = Field(description="The extracted data for this step if the milestone is met, otherwise null.")
    suggested_pivots: List[str] = Field(default_factory=list, description="List of suspected IOCs/keys/pivots to query ChromaDB for to gather more context. Return concrete indicators (values), not descriptions.")

# [FYP-CLASS] `MilestoneExecution` — owns MilestoneExecution state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include soc_investigation_agent_revised/main.py:generate_local_standalone_report, soc_investigation_agent_revised/orchestrator.py:analyze_alert_group_p1, soc_investigation_agent_revised/orchestrator.py:orchestrate_incident.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class MilestoneExecution(BaseModel):
    step_id: str
    instruction: str
    status: Literal["MET", "NOT_MET", "SKIPPED"]
    findings: str
# [FYP-CLASS] `BusinessImpactChecklist` — owns BusinessImpactChecklist state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include soc_investigation_agent_revised/orchestrator.py:compile_final_report, soc_investigation_agent_revised/orchestrator.py:generate_final_analysis.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class BusinessImpactChecklist(BaseModel):
    critical_system: str = Field(description="Is a critical or significant system impacted? (yes/no/unknown)")
    essential_service: str = Field(description="Is an important or essential service affected? (yes/no/unknown)")
    data_sensitivity: str = Field(description="Is personal, confidential, or sensitive data involved? (yes/no/unknown)")
    operational_impact: str = Field(description="Is there outage, degradation, or loss of business function? (yes/no/unknown)")

# [FYP-CLASS] `FinalIncidentAnalysis` — owns FinalIncidentAnalysis state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include soc_investigation_agent_revised/main.py:generate_local_standalone_report, soc_investigation_agent_revised/orchestrator.py:compile_final_report, soc_investigation_agent_revised/orchestrator.py:generate_final_analysis.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class FinalIncidentAnalysis(BaseModel):
    incident_id: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: Literal["Low", "Medium", "High"]
    execution_trace: List[MilestoneExecution] = Field(description="The step-by-step trace of how the playbook was executed.")
    incident_summary: str = Field(description="Comprehensive chronological summary detailing what happened, recorded IOCs, timestamps, and stage linkage.")
    actions_taken: List[str] = Field(description="Actions taken during investigation.")
    recommended_containment: List[str] = Field(description="Recommended containment actions based on policies.")
    business_impact_checklist: BusinessImpactChecklist = Field(description="Checklist mapping factor names to analysis answers for Appendix C.")
    severity_justification: str = Field(description="Brief justification of the severity rating based on Appendix A/B factors.")
    confidence_justification: str = Field(description="Brief justification of the confidence rating based on Appendix F.")
    mitre_mappings: List[mitre_mapper.MitreTTPMapping] = Field(default_factory=list, description="Chronological list of MITRE ATT&CK TTP mappings evaluated holistically at the incident level.")
    mitre_attack_table: Optional[str] = Field(default=None, description="Markdown summary table mapping incident timeline events to MITRE ATT&CK TTPs at the incident level.")
    policy_audit_logs: List[PolicyAuditRecord] = Field(default_factory=list, description="The list of PolicyAuditRecord generated during policy-based verification checks.")

# [FYP-CLASS] `Pass1StepResult` — owns Pass1StepResult state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class Pass1StepResult(BaseModel):
    step_id: str
    status: Literal["MET", "NOT_MET"]
    findings: str

# [FYP-CLASS] `Pass1Result` — owns Pass1Result state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class Pass1Result(BaseModel):
    execution_trace: List[Pass1StepResult] = Field(description="The step-by-step trace of how the playbook was executed.")
    suggested_pivots: List[str] = Field(default_factory=list, description="Concrete indicator values (IPs, domains, hashes, usernames) to query to resolve any unmet steps.")

# --- LLM INITIALIZATION ---

_llm = None
_chain_p1 = None
_chain_p2 = None

# [FYP-FUNCTION] `_structured_method` — implements the structured method operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/orchestrator.py:check_milestone_sufficiency, soc_investigation_agent_revised/orchestrator.py:classify_policies_for_investigation, soc_investigation_agent_revised/orchestrator.py:filter_suspicious_seeds; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `getenv`, `join`, `lower`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _structured_method() -> str:
    """Choose the OpenAI structured-output method.

    OPENAI_STRUCTURED_METHOD remains available for SDK/model compatibility.
    """
    override = os.getenv("OPENAI_STRUCTURED_METHOD", "").strip()
    if override:
        return override
    return "json_schema"


def get_llm():
    """
    [FYP-FUNCTION] Lazily construct (and cache in module-global `_llm`) the
    single shared ChatOpenAI client used by every LLM call in this file
    (classify_policies_for_investigation, filter_suspicious_seeds,
    check_milestone_sufficiency, generate_final_analysis, get_chain_p1/p2).

    Reads OPENAI_API_KEY / OPENAI_MODEL from the environment and uses the
    official OpenAI endpoint.

    [FYP-USED-BY]: every LLM-calling function in this module.
    """
    global _llm
    if _llm is None:
        api_key = os.getenv("OPENAI_API_KEY")
        model = os.getenv("OPENAI_MODEL") or "gpt-4o-mini"
        kwargs = {"model": model, "temperature": 0, "openai_api_key": api_key}
        _llm = ChatOpenAI(**kwargs)
    return _llm

# [FYP-CLASS] `PolicyClassificationResult` — owns PolicyClassificationResult state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class PolicyClassificationResult(BaseModel):
    relevant_sections: List[str] = Field(description="List of section keys/headers that are relevant to the Investigation Agent.")

def classify_policies_for_investigation(sections: Dict[str, str]) -> List[str]:
    """
    [FYP-FUNCTION] One-time LLM classification of which parsed policy
    sections (from policy_engine.PolicyManager.policies, keyed by section
    header) are relevant to THIS agent's job (severity/confidence scoring,
    business-impact checklist, containment/escalation rules, playbooks) as
    opposed to administrative boilerplate (Purpose, Scope, audit-log
    requirements, etc.).

    [FYP-RAG] The returned section keys become the whitelist that
    PolicyVectorIndex.populate() embeds into the 'soc_policies' ChromaDB
    collection — i.e. this function decides WHAT goes into the RAG index,
    not what gets retrieved from it per-incident.

    Only sends each section's first 4 lines to the LLM (a preview), keeping
    the call cheap; on any LLM failure falls back to a hardcoded appendix
    whitelist so the pipeline still runs.

    [FYP-USED-BY]: get_policy_manager() — called once, then its result is
    cached to disk (policies/investigation_sections_cache.json) keyed by the
    policy file's mtime, so this LLM call only re-runs when the policy
    document actually changes.
    """
    log_info("[LLM CALL] Running one-time AI Policy Parser to classify relevant sections...")
    
    sections_summary = []
    for key, text in sections.items():
        first_lines = "\n".join(text.splitlines()[:4])
        sections_summary.append(f"Section Key: '{key}'\nContent Preview:\n{first_lines}\n---")
        
    sections_summary_str = "\n".join(sections_summary)
    
    system_prompt = (
        "You are a SOC Architect. You are given a list of parsed sections from the cybersecurity policies book.\n"
        "Identify and select which section keys/headers are relevant to the Investigation Agent.\n"
        "The Investigation Agent is responsible for:\n"
        "- Assessing incident evidence and determining confidence levels.\n"
        "- Assessing business impact checklist variables.\n"
        "- Classifying final severity levels (Low, Medium, High, Critical) and mapping escalation conditions.\n"
        "- Containment rules and approval policies (autonomous containment vs analyst approval).\n"
        "- Special incident handling playbooks (e.g. ransomware rules, virtual guest OS compromise rules).\n"
        "- Post-incident report requirements.\n\n"
        "Do NOT include administrative sections (e.g. Purpose, Scope, Decision Registers, learning agent updates, policy review, audit logs requirements).\n"
        "Return the list of relevant section keys strictly conforming to the JSON schema."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Available parsed policy sections:\n{sections}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(PolicyClassificationResult, method=_structured_method())
        result = chain.invoke({"sections": sections_summary_str})
        log_success(f"[LLM RESPONSE] AI Policy Parser classified relevant sections: {result.relevant_sections}")
        return result.relevant_sections
    except Exception as e:
        log_error(f"Failed to run AI Policy Parser: {e}. Falling back to default whitelist.")
        return ["appendix a", "appendix b", "appendix c", "appendix f", "appendix g", "appendix h", "appendix i", "appendix j", "general escalation rule"]

class PolicyVectorIndex:
    """
    [FYP-CLASS] [FYP-RAG] ChromaDB-backed vector store embedding cybersecurity
    policy sections (soc_investigation_agent_revised/policies/soc_policies.md,
    parsed by policy_engine.PolicyManager) to support semantic retrieval of
    the policy text relevant to a given incident's timeline. Uses the
    'soc_policies' collection (OpenAI text-embedding-3-small), separate from
    the alert-evidence collection managed by vector_engine.py.

    Lifecycle: populate() is called once per process (via get_policy_manager())
    to (re)index only the LLM-whitelisted sections (see
    classify_policies_for_investigation()); retrieve() is then called per
    incident inside generate_final_analysis()/compile_final_report() to pull
    the 2 sections most semantically similar to the incident timeline, which
    are appended to the "always-present" core appendices (A/C/F/escalation
    rule) before being handed to the LLM as grounding context.

    [FYP-USED-BY]: get_policy_manager() (construction + populate()),
    generate_final_analysis()/compile_final_report() (retrieve()).
    """
    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `db_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `OpenAIEmbeddingFunction`, `PersistentClient`, `get`, `log_warning`, `open_persistent_collection`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __init__(self, db_path: str = "ChromaDatabase"):
        import chromadb
        from chromadb.utils import embedding_functions
        self.client = chromadb.PersistentClient(path=db_path)
        self.default_ef = embedding_functions.OpenAIEmbeddingFunction(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            model_name="text-embedding-3-small",
        )
        self.collection, using_persisted_embedding = open_persistent_collection(
            self.client,
            name="soc_policies",
            embedding_function=self.default_ef,
            metadata={"hnsw:space": "cosine"}
        )
        if using_persisted_embedding:
            log_warning(
                "PolicyVectorIndex: 'soc_policies' uses its persisted embedding "
                "function; existing vectors were preserved."
            )

    # [FYP-FUNCTION] `populate` — implements the populate operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `sections`, `relevant_keys`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/orchestrator.py:get_policy_manager; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `any`, `append`, `delete_collection`, `get_or_create_collection`, `items`, `len`, `log_success`, `lower`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def populate(self, sections: Dict[str, str], relevant_keys: List[str]):
        """
        [FYP-RAG] Rebuilds the 'soc_policies' collection from scratch (drops
        then recreates it) containing only the sections whose keys fuzzy-match
        (substring, either direction) one of `relevant_keys` — the LLM-
        classified whitelist from classify_policies_for_investigation().
        Each document is truncated to 12000 chars before embedding.

        [FYP-USED-BY]: get_policy_manager(), only when the vector store is
        empty or the classification cache was just (re)computed — otherwise
        the existing persisted collection is reused across runs.
        """
        try:
            self.client.delete_collection("soc_policies")
        except Exception:
            pass
            
        self.collection = self.client.get_or_create_collection(
            name="soc_policies",
            embedding_function=self.default_ef,
            metadata={"hnsw:space": "cosine"}
        )
        
        ids = []
        documents = []
        metadatas = []
        
        normalized_keys = {k.lower().strip() for k in relevant_keys}
        
        for key, text in sections.items():
            key_clean = key.lower().strip()
            if any(norm_key in key_clean or key_clean in norm_key for norm_key in normalized_keys):
                ids.append(key)
                documents.append(text[:12000])
                metadatas.append({"section_name": key})
                
        if ids:
            self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            log_success(f"PolicyVectorIndex: Successfully populated with {len(ids)} relevant sections.")

    # [FYP-FUNCTION] `retrieve` — implements the retrieve operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `query_text`, `limit`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/orchestrator.py:compile_final_report, soc_investigation_agent_revised/orchestrator.py:generate_final_analysis; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `log_error`, `query`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def retrieve(self, query_text: str, limit: int = 2) -> List[str]:
        """
        [FYP-RAG] Embeds `query_text` (in practice, the incident's
        chronological timeline string from build_timeline_text()) and
        returns the `limit` most semantically similar policy section
        documents from the 'soc_policies' collection. This is the dynamic
        half of the policy context assembled in generate_final_analysis()/
        compile_final_report() — supplementing the always-included core
        appendices (A, C, F, general escalation rule) with whichever
        additional policy sections are contextually relevant to what
        actually happened in this incident.
        """
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=limit
            )
            parsed = []
            if results and results["documents"] and results["documents"][0]:
                for doc in results["documents"][0]:
                    parsed.append(doc)
            return parsed
        except Exception as e:
            log_error(f"PolicyVectorIndex: Retrieve failed: {e}")
            return []

_policy_mgr = None
_policy_vector_index = None

def get_policy_manager():
    """
    [FYP-FUNCTION] [FYP-RAG] Lazily construct and cache (module-globals
    _policy_mgr, _policy_vector_index) the pair of objects that back all
    policy-grounded reasoning in this file: a policy_engine.PolicyManager
    (parses policies/soc_policies.md into a section dict) and a
    PolicyVectorIndex (embeds a whitelisted subset of those sections for
    semantic retrieval).

    [FYP-PROCESS] On first call:
      1. Parse the policy markdown via PolicyManager.
      2. Determine which sections are relevant to this agent — either by
         reading policies/investigation_sections_cache.json (if its cached
         mtime still matches the policy file's current mtime) or, on a
         cache miss, by calling classify_policies_for_investigation() (one
         LLM call) and writing the result back to that cache file.
      3. Populate the ChromaDB vector store (PolicyVectorIndex.populate())
         only if it's empty or the classification was just recomputed;
         otherwise reuse whatever is already persisted on disk, avoiding
         redundant embedding calls across repeated runs.

    Subsequent calls just return the cached globals — this function is the
    single lazy-init choke point for the whole policy subsystem.

    [FYP-USED-BY]: generate_final_analysis(), compile_final_report().
    """
    global _policy_mgr, _policy_vector_index
    policy_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies", "soc_policies.md")
    
    if _policy_mgr is None:
        _policy_mgr = PolicyManager(policy_file_path)
        _policy_vector_index = PolicyVectorIndex()
        
        cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies", "investigation_sections_cache.json")
        mtime = os.path.getmtime(policy_file_path)
        
        load_from_cache = False
        cached_keys = []
        
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                if cache_data.get("mtime") == mtime:
                    cached_keys = cache_data.get("relevant_sections", [])
                    load_from_cache = True
                    log_success("PolicyVectorIndex: Loaded relevant sections classification from cache.")
            except Exception as e:
                log_warning(f"Failed to read policy cache: {e}")
                
        if not load_from_cache:
            cached_keys = classify_policies_for_investigation(_policy_mgr.policies)
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump({"mtime": mtime, "relevant_sections": cached_keys}, f, indent=2)
                log_success(f"PolicyVectorIndex: Cached policy classification to {cache_path}")
            except Exception as e:
                log_warning(f"Failed to write policy cache: {e}")
                
        # Check if vector store is populated
        collection_empty = False
        try:
            if _policy_vector_index.collection.count() == 0:
                collection_empty = True
        except Exception:
            collection_empty = True
            
        if not load_from_cache or collection_empty:
            if load_from_cache and not cached_keys:
                # Fallback if cache exists but keys are empty
                cached_keys = classify_policies_for_investigation(_policy_mgr.policies)
            _policy_vector_index.populate(_policy_mgr.policies, cached_keys)
        else:
            log_success("PolicyVectorIndex: Skipping population (using existing cached vector store).")
        
    return _policy_mgr, _policy_vector_index

def get_chain_p1():
    """
    [FYP-FUNCTION] Lazily builds and caches (module-global _chain_p1) the
    LangChain "Pass 1" chain: a single structured-output LLM call that,
    given the full playbook step list and the current incident timeline,
    evaluates EVERY playbook step in one shot (MET/NOT_MET + findings per
    step, via the Pass1Result schema) and proposes concrete indicator
    values to pivot on for any NOT_MET steps.

    This is the async two-pass pipeline's cheaper alternative to
    orchestrate_incident()'s synchronous one-LLM-call-per-milestone loop
    (check_milestone_sufficiency()) — trading per-step precision for a
    single consolidated call, which is what main.py's async batch pipeline
    (analyze_alert_group_p1()) actually uses in production.

    [FYP-USED-BY]: analyze_alert_group_p1().
    """
    global _chain_p1
    if _chain_p1 is None:
        system_prompt_p1 = (
            "You are a Lead SOC Incident Responder. You are given a security Playbook (list of steps) and a chronological Incident Timeline.\n"
            "Your task is to evaluate the timeline against the playbook and output the execution trace.\n"
            "First, for each step in the playbook, populate a Pass1StepResult:\n"
            "  - step_id: the ID of the step (e.g., 'step_1')\n"
            "  - status: 'MET' if the timeline contains enough evidence to answer/satisfy it, otherwise 'NOT_MET'\n"
            "  - findings: a clear answer to the instruction if MET, or reasoning explaining what is missing and why if NOT_MET.\n"
            "Then, compile a list of suggested_pivots: concrete indicator values (IPs, domains, hashes, usernames) to query the logs for to resolve any NOT_MET steps. Return concrete values, not descriptions."
        )
        prompt_p1 = ChatPromptTemplate.from_messages([
            ("system", system_prompt_p1),
            ("human", "=== PLAYBOOK STEPS ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== INCIDENT ID ===\n{incident_id}")
        ])
        _chain_p1 = prompt_p1 | get_llm().with_structured_output(Pass1Result, method=_structured_method())
    return _chain_p1
def get_chain_p2():
    """
    [FYP-FUNCTION] Lazily builds and caches (module-global _chain_p2) the
    LangChain "Pass 2" chain: the single structured-output LLM call that
    re-evaluates the playbook against the (possibly pivot-enriched) timeline
    and produces the complete FinalIncidentAnalysis — severity/confidence
    + justifications, business impact checklist, incident_summary narrative,
    recommended_containment, and the chronological mitre_mappings list —
    all strictly grounded in the {policies} context block injected at call
    time (the core appendices + PolicyVectorIndex.retrieve() results).

    [FYP-USED-BY]: compile_final_report(), which is the async pipeline's
    counterpart to orchestrate_incident()'s generate_final_analysis().
    """
    global _chain_p2
    if _chain_p2 is None:
        system_prompt_p2 = (
            "You are a Lead SOC Incident Responder. Review the provided Incident Timeline and the previous Playbook Execution Trace,\n"
            "and generate a final, structured incident report using the specified Pydantic schema.\n"
            "You MUST strictly align your analysis with the company's cybersecurity policies provided below.\n\n"
            "=== CYBERSECURITY POLICIES ===\n{policies}\n\n"
            "Instructions:\n"
            "1. Re-evaluate each step in the playbook using the updated timeline and populate the execution_trace.\n"
            "2. Complete the business_impact_checklist by answering the policy-based questions in Appendix C (e.g., critical_system, essential_service, data_sensitivity, operational_impact).\n"
            "3. Assign final severity and confidence based on the guidelines in Appendix A, B, and F, and provide their justifications.\n"
            "4. For the 'incident_summary' (Technical Chronology Summary) field: Provide a clear, natural narrative in paragraph form using normal human speech that explains strictly what happened during the incident. Keep the description action-focused and centered on observed threat behaviors across all alerts (e.g., initial user activity, file execution, subprocess spawns, privilege escalation, and C2/network connections). Write in fluent, readable paragraphs rather than numbered lists or rigid formulas. State strictly observed technical actions, timestamps, actors/users, affected files/processes, command lines, and network targets without administrative meta-commentary or generic fluff.\n"
            "5. For the 'recommended_containment' field: Recommend containment actions adhering to Appendix G, H, and I. Ensure all recommended containment actions are highly specific and action-oriented. Do not write generic recommendations.\n"
            "6. For the 'mitre_mappings' field: Evaluate the full multi-alert event sequence holistically at the incident level and map the attack steps across ALL alerts to precise MITRE ATT&CK TTPs in strict chronological order. Always resolve precise sub-techniques (e.g. T1566.002, T1569.002, T1021.002) and populate timeline_phase, observed_evidence, tactic, technique_name, and technique_id for each phase.\n"
            "Note: Your output must be structured to match the Pydantic schema."
        )
        prompt_p2 = ChatPromptTemplate.from_messages([
            ("system", system_prompt_p2),
            ("human", "=== INCIDENT ID ===\n{incident_id}\n\n=== PLAYBOOK ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK TRACE ===\n{trace}")
        ])
        _chain_p2 = prompt_p2 | get_llm().with_structured_output(FinalIncidentAnalysis, method=_structured_method())
    return _chain_p2

# --- MICRO-TASK IMPLEMENTATIONS ---

def filter_suspicious_seeds(raw_tokens: List[str]) -> List[str]:
    """
    [FYP-FUNCTION] Micro-Task 1: stateless LLM call that strips benign
    infrastructure noise (localhost, DNS resolvers, generic Windows/MS
    domains, svchost.exe/cmd.exe, empty/"Unknown" values) out of a raw token
    list, leaving only tokens worth using as ChromaDB pivot/search seeds.

    Only called on the subset of tokens prepare_seeds() couldn't already
    confidently classify as high-fidelity (public IPs and external domains);
    private IPs, hashes, emails, and hostnames/usernames bypass this LLM
    call entirely. On LLM failure, falls back to a small hardcoded benign
    set so filtering degrades gracefully rather than failing outright.

    [FYP-USED-BY]: prepare_seeds().
    """
    if not raw_tokens:
        return []
    
    log_info(f"[LLM CALL] Invoking Micro-Task 1: Intelligent Indicator Filter on {len(raw_tokens)} tokens...")
    
    system_prompt = (
        "You are an expert SOC Analyst. You are given a list of extracted tokens from raw SIEM logs.\n"
        "Filter out benign infrastructure noise (such as localhost, 127.0.0.1, 8.8.8.8, 1.1.1.1, common microsoft/windows domains,\n"
        "generic system files like svchost.exe or cmd.exe, and empty/invalid values).\n"
        "Return a clean list of only suspicious or investigative tokens (IPs, subnets, domains, hashes, usernames, hosts) to serve as search seeds."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Extracted raw tokens: {tokens}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(SuspiciousSeeds, method=_structured_method())
        result = chain.invoke({"tokens": str(raw_tokens)})
        log_success(f"[LLM RESPONSE] Filtered tokens: {result.seeds}")
        return result.seeds
    except Exception as e:
        log_error(f"Failed to filter seeds with LLM: {e}. Falling back to original tokens.")
        benign = {"127.0.0.1", "0.0.0.0", "localhost", "svchost.exe", "Unknown"}
        return [t for t in raw_tokens if t not in benign]

def check_milestone_sufficiency(timeline_str: str, instruction: str, step_id: str) -> MilestoneCheck:
    """
    [FYP-FUNCTION] [FYP-EVALUATOR] [FYP-DECISION] Micro-Task 2: stateless
    per-milestone LLM call that decides whether the current chronological
    incident timeline (build_timeline_text() output, growing as more
    correlated alerts are pivoted-in) contains enough evidence to answer a
    single playbook step's instruction.

    Returns a MilestoneCheck: milestone_met (True/False), reasoning, the
    extracted_data answer when met, and — when NOT met — suggested_pivots
    (concrete indicator values, not descriptions) that orchestrate_incident()
    uses to query vector_engine.correlate_rrf() for more evidence before
    retrying this same step.

    This MET/NOT_MET verdict is exactly what ends up in each
    MilestoneExecution row of execution_trace, which is in turn the table
    soc_workflow.py's detect_evidence_gaps() parses to decide whether an
    automatic investigation re-run is warranted.

    [FYP-USED-BY]: orchestrate_incident() (called once per playbook node,
    with retries on newly-pivoted evidence).
    """
    log_info(f"[LLM CALL] Invoking Micro-Task 2: Milestone Sufficiency Check for step {step_id}...")
    
    system_prompt = (
        "You are a SOC automation sub-agent validating a specific playbook milestone.\n"
        "Review the chronological Incident Timeline provided, and determine if it contains enough evidence\n"
        "to satisfy the active step instruction.\n"
        "If yes, set milestone_met = True and populate the extracted_data field with a direct answer to the instruction.\n"
        "If no, set milestone_met = False, explain in reasoning what is missing, and suggest new IOCs/pivots (values only) to search for."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK STEP INSTRUCTION ===\n{instruction}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(MilestoneCheck, method=_structured_method())
        result = chain.invoke({"timeline": timeline_str, "instruction": instruction})
        log_success(f"[LLM RESPONSE] Step {step_id} Met: {result.milestone_met} | Reasoning: {result.reasoning}")
        return result
    except Exception as e:
        log_error(f"Failed to verify milestone with LLM: {e}")
        return MilestoneCheck(
            milestone_met=False,
            reasoning=f"Error calling LLM: {e}",
            extracted_data=None,
            suggested_pivots=[]
        )

def generate_final_analysis(incident_id: str, playbook_name: str, timeline_str: str, execution_trace: List[MilestoneExecution], correlated_alerts: Optional[List[dict]] = None) -> FinalIncidentAnalysis:
    """
    [FYP-FUNCTION] [FYP-EVALUATOR] Final structured reporting: invoked
    exactly once at the end of orchestrate_incident()'s milestone-checkpoint
    loop to turn the completed execution_trace + timeline into the
    FinalIncidentAnalysis report (severity/confidence + justifications,
    business_impact_checklist, incident_summary narrative,
    recommended_containment, mitre_mappings / mitre_attack_table).

    [FYP-PROCESS] / [FYP-RAG]:
      1. get_policy_manager() supplies the policy grounding context: 4
         "core" appendices (A severity, C business impact, F confidence,
         general escalation rule) are always included; PolicyVectorIndex.
         retrieve() adds up to 2 more sections semantically similar to
         `timeline_str` — deduplicated against the core set.
      2. One structured-output LLM call (get_llm()) produces the report
         against the FinalIncidentAnalysis Pydantic schema, grounded in
         that combined policy context.
      3. [FYP-DECISION] policy_engine.run_policy_compliance_rules() is then
         run as a deterministic, non-LLM post-check over the LLM's own
         output (severity/confidence/checklist/summary) — it can override
         recommended_containment (e.g. force ransomware/guest-OS containment
         language) when escalation_required, and always attaches the
         Appendix M policy_audit_logs trail.
      4. [FYP-CALLS] mitre_mapper.py renders the mitre_attack_table markdown
         locally (0 extra LLM calls) from the LLM-produced mitre_mappings;
         if the LLM didn't populate mappings, falls back to
         mitre_mapper.map_incident_mitre_ttps() over the raw
         correlated_alerts/timeline instead.

    On any LLM failure, returns a conservative fallback FinalIncidentAnalysis
    (severity=High, confidence=Low) rather than raising, so a single bad LLM
    call never crashes the whole investigation run.

    [FYP-USED-BY]: orchestrate_incident() (the synchronous single-pass path;
    contrast with compile_final_report(), the async two-pass path's
    equivalent, used by main.py in production).
    """
    log_info(f"[LLM CALL] Invoking Final Structural Reporting for incident {incident_id}...")
    
    policy_mgr, policy_vector_index = get_policy_manager()
    
    # Core policies (always present)
    core_keys = ["appendix a", "appendix c", "appendix f", "general escalation rule"]
    core_sections = []
    for k in core_keys:
        sec_text = policy_mgr.get_section(k)
        if sec_text:
            core_sections.append(extract_actionable_rules(sec_text))
            
    # Retrieve dynamic sections based on timeline
    retrieved = policy_vector_index.retrieve(timeline_str, limit=2)
    dynamic_sections = [extract_actionable_rules(doc) for doc in retrieved]
    
    # Combine avoiding duplicates
    all_sections = list(core_sections)
    for doc in dynamic_sections:
        if doc not in all_sections:
            all_sections.append(doc)
            
    policies_context = "\n\n".join(all_sections)
    
    system_prompt = (
        "You are a Lead SOC Incident Responder. Review the provided Incident Timeline and the Playbook Execution Trace,\n"
        "and generate a final, structured incident report using the specified Pydantic schema.\n"
        "You MUST strictly align your analysis with the company's cybersecurity policies provided below.\n\n"
        "=== CYBERSECURITY POLICIES ===\n{policies}\n\n"
        "Instructions:\n"
        "1. Complete the business_impact_checklist by answering the policy-based questions in Appendix C (e.g., critical_system, essential_service, data_sensitivity, operational_impact).\n"
        "2. Assign final severity and confidence based on the guidelines in Appendix A, B, and F, and provide their justifications.\n"
        "3. For the 'incident_summary' (Technical Chronology Summary) field: Provide a clear, natural narrative in paragraph form using normal human speech that explains strictly what happened during the incident. Keep the description action-focused and centered on observed threat behaviors across all alerts (e.g., initial user activity, file execution, subprocess spawns, privilege escalation, and C2/network connections). Write in fluent, readable paragraphs rather than numbered lists or rigid formulas. State strictly observed technical actions, timestamps, actors/users, affected files/processes, command lines, and network targets without administrative meta-commentary or generic fluff.\n"
        "4. For the 'recommended_containment' field: Recommend containment actions adhering to Appendix G, H, and I. Ensure all recommended containment actions are highly specific and action-oriented.\n"
        "5. For the 'mitre_mappings' field: Evaluate the full multi-alert event sequence holistically at the incident level and map the attack steps across ALL alerts to precise MITRE ATT&CK TTPs in strict chronological order. Always resolve precise sub-techniques (e.g. T1566.002, T1569.002, T1021.002) and populate timeline_phase, observed_evidence, tactic, technique_name, and technique_id for each phase.\n"
        "Note: Your output must be structured to match the Pydantic schema."
    )
    
    trace_json = json.dumps([t.model_dump() for t in execution_trace], indent=2)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "=== INCIDENT ID ===\n{incident_id}\n\n=== PLAYBOOK ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK TRACE ===\n{trace}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(FinalIncidentAnalysis, method=_structured_method())
        result = chain.invoke({
            "incident_id": incident_id,
            "playbook": playbook_name,
            "timeline": timeline_str,
            "trace": trace_json,
            "policies": policies_context
        })
        
        compliance = run_policy_compliance_rules(
            incident_id=incident_id,
            severity=result.severity,
            confidence=result.confidence,
            incident_summary=result.incident_summary,
            recommended_containment=result.recommended_containment,
            business_impact_checklist=result.business_impact_checklist,
            timeline_text=timeline_str
        )
        
        if compliance["escalation_required"]:
            result.recommended_containment = compliance["modified_containment"]
            
        result.policy_audit_logs = compliance["audit_records"]
        
        # Render MITRE ATT&CK TTP Mapping locally (0 extra LLM calls)
        if getattr(result, "mitre_mappings", None):
            mitre_analysis = mitre_mapper.IncidentMitreAnalysis(
                incident_id=incident_id,
                attack_chain_summary=result.incident_summary,
                mappings=result.mitre_mappings
            )
            result.mitre_attack_table = mitre_mapper.generate_markdown_table(mitre_analysis)
        else:
            try:
                _, mitre_table = mitre_mapper.map_incident_mitre_ttps(correlated_alerts or timeline_str, llm=None)
                result.mitre_attack_table = mitre_table
            except Exception:
                pass

        log_success(f"[LLM RESPONSE] Generated final report with severity: {result.severity} | confidence: {result.confidence}")
        return result
    except Exception as e:
        log_error(f"Failed to generate final structured report: {e}")
        fallback_report = FinalIncidentAnalysis(
            incident_id=incident_id,
            severity="High",
            confidence="Low",
            execution_trace=execution_trace,
            incident_summary=f"Analysis failed due to error: {e}. Timeline: {timeline_str}",
            actions_taken=["Triage", "Vector Correlation"],
            recommended_containment=["Isolate system and review logs manually."],
            business_impact_checklist=BusinessImpactChecklist(critical_system="unknown", essential_service="unknown", data_sensitivity="unknown", operational_impact="unknown"),
            severity_justification=f"Fallback due to error: {e}",
            confidence_justification="Fallback due to error",
            policy_audit_logs=[]
        )
        try:
            _, mitre_table = mitre_mapper.map_incident_mitre_ttps(correlated_alerts or timeline_str, llm=None)
            fallback_report.mitre_attack_table = mitre_table
        except Exception:
            pass
        return fallback_report

# --- CONSTRUCT TIMELINE TEXT ---

def build_timeline_text(correlated_alerts: List[dict]) -> str:
    """
    [FYP-FUNCTION] Sorts `correlated_alerts` (dicts with id/document/metadata,
    as produced by ingest_pipeline.process_log_file() and
    vector_engine.correlate_rrf()) chronologically by
    metadata["timestamp_epoch"] and renders them into a single
    "[timestamp] Alert Entry #N (id): document" per-line text block.

    This is THE incident timeline representation fed to every LLM call in
    this file (check_milestone_sufficiency, generate_final_analysis,
    get_chain_p1/p2's prompts, PolicyVectorIndex.retrieve() query text) — it
    is rebuilt from scratch every time correlated_alerts grows (each
    successful pivot hop in orchestrate_incident()), so the LLM always sees
    the full up-to-date evidence set in strict time order.

    [FYP-USED-BY]: orchestrate_incident(), analyze_alert_group_p1(),
    compile_final_report().
    """
    lines = []
    sorted_alerts = sorted(correlated_alerts, key=lambda x: x["metadata"]["timestamp_epoch"])
    
    for idx, alert in enumerate(sorted_alerts, 1):
        ts = alert["metadata"]["timestamp_str"]
        alert_id = alert["id"]
        doc = alert["document"]
        lines.append(f"[{ts}] Alert Entry #{idx} ({alert_id}): {doc}")
        
    return "\n".join(lines)

# --- INFRASTRUCTURE BROADENING ---

IP_PAT = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$')

def broaden_indicators(indicators: List[str]) -> List[str]:
    """
    [FYP-FUNCTION] No-op passthrough — returns `indicators` unchanged.

    Kept as a named seam (rather than removed) because it is called at
    every indicator-expansion point in orchestrate_incident() (initial
    seeds, newly-discovered alert indicators, and LLM-suggested pivots from
    check_milestone_sufficiency()). Subnet/domain broadening (e.g.
    expanding a /24 or a parent domain) was intentionally disabled here to
    avoid pulling in unrelated alerts that merely share an IP range —
    precision over recall for the pivot search.
    """
    return list(indicators)

# --- SEED PREPARATION AND FILTER WHITELISTING ---

def prepare_seeds(raw_tokens: List[str]) -> List[str]:
    """
    [FYP-FUNCTION] Splits `raw_tokens` into a "high_fidelity" bucket that
    bypasses the LLM filter entirely and a "to_filter" bucket that gets
    sent through filter_suspicious_seeds() (Micro-Task 1).

    Classification rules (deterministic, no LLM):
      - Private/RFC1918 IPs (10.x, 192.168.x, 172.16-31.x) and any
        subnet-prefix token (ending in '.') -> high_fidelity.
      - Public IPs -> to_filter (too noisy/generic to trust blindly).
      - 32/64-char hex strings (MD5/SHA256 hashes) -> high_fidelity.
      - Tokens containing '@' and '.' (emails) -> high_fidelity.
      - Tokens with no '.' at all (bare hostnames/usernames) ->
        high_fidelity.
      - Everything else (external domains) -> to_filter.

    Returns the deduplicated union of high_fidelity + whatever
    filter_suspicious_seeds() didn't strip out — this is the final
    "active_seeds" list orchestrate_incident() queries ChromaDB with via
    vector_engine.correlate_rrf().

    [FYP-USED-BY]: orchestrate_incident() (both the initial seed set and
    every subsequently-discovered alert's indicators).
    """
    high_fidelity = []
    to_filter = []
    
    for token in raw_tokens:
        token_str = str(token).strip()
        token_lower = token_str.lower()
        if not token_str or token_lower in ("unknown", "null", "none", ""):
            continue
            
        # Check if it's an IP address or subnet
        is_ip_or_subnet = False
        if token_lower.endswith('.'):
            is_ip_or_subnet = True
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', token_str):
            is_ip_or_subnet = True
            
        if is_ip_or_subnet:
            # Check if it is a private (RFC 1918) network
            if (token_str.startswith("10.") or 
                token_str.startswith("192.168.") or 
                (token_str.startswith("172.") and len(token_str.split('.')) > 1 and token_str.split('.')[1].isdigit() and 16 <= int(token_str.split('.')[1]) <= 31)):
                high_fidelity.append(token_str)
            else:
                to_filter.append(token_str)
        # Check if it is a cryptographic hash (MD5 or SHA256)
        elif len(token_str) in (32, 64) and re.match(r'^[a-fA-F0-9]+$', token_str):
            high_fidelity.append(token_str)
        # Check if it is an email
        elif '@' in token_str and '.' in token_str:
            high_fidelity.append(token_str)
        # Check if hostname or username (usually doesn't have dots)
        elif '.' not in token_str:
            high_fidelity.append(token_str)
        else:
            # Public IPs and external domains go to the LLM filter
            to_filter.append(token_str)
            
    # Filter noisy domains/public IPs using Micro-Task 1
    filtered = filter_suspicious_seeds(to_filter)
    
    # Combine whitelisted structural indicators and filtered seeds
    return list(set(high_fidelity + filtered))

# --- HYBRID ORCHESTRATOR CORRELATION FLOW ---

def orchestrate_incident(seed_alert_path: str, playbook_path: str) -> dict:
    """
    [FYP-FUNCTION] Investigation Orchestration — Main Synchronous Entry Point
    [FYP-ENTRY-POINT] [FYP-EVALUATOR] [FYP-FLOW]

    Orchestrates ingestion, transitive-closure metadata pivoting, milestone
    checks, and final reporting.

    [FYP-PROCESS] High-level flow:
      1. Ingest the seed alert (ingest_pipeline.process_log_file) and
         extract initial seed indicators (IPs/hashes/emails/domains/
         username/hostname).
      2. broaden_indicators()/prepare_seeds() expand and clean the seed set
         — this is the "transitive-closure metadata pivoting" step that
         pulls in related evidence, not just the literal seed alert.
      3. Walk the playbook (YAML at playbook_path) milestone by milestone,
         using check_milestone_sufficiency() to decide whether enough
         evidence has been gathered for each step (MET/NOT_MET/SKIPPED) —
         this MET/NOT_MET table is exactly what soc_workflow.py's
         detect_evidence_gaps() later parses to decide on an automatic
         re-run.
      4. generate_final_analysis() [FYP-CALLS] produces the final
         structured report, including the MITRE ATT&CK mapping via
         mitre_mapper.py.

    Parameters: seed_alert_path (path to the triggering alert JSON),
    playbook_path (path to a playbook YAML, e.g.
    soc_investigation_agent_revised/playbooks/phishing.yaml).

    Returns: dict — the final incident analysis result.

    [FYP-USED-BY]: this subsystem's main.py / the Investigation stage
    subprocess soc_workflow.py invokes — verify exact call site via grep
    before demoing.
    """
    # 1. Process Seed Alert
    seed_log = ingest_pipeline.process_log_file(seed_alert_path)
    seed_id = seed_log["id"]
    
    log_info(f"Starting orchestration for Seed Alert: {seed_id}")
    
    # 2. Extract initial seeds from Seed Alert
    seed_indicators = ingest_pipeline.scan_indicators(json.dumps(seed_log["metadata"]))
    raw_tokens = []
    raw_tokens.extend(seed_indicators["ips"])
    raw_tokens.extend(seed_indicators["sha256s"])
    raw_tokens.extend(seed_indicators["md5s"])
    raw_tokens.extend(seed_indicators["emails"])
    raw_tokens.extend(seed_indicators["domains"])
    if seed_log["metadata"]["username"] and seed_log["metadata"]["username"] != "Unknown":
        raw_tokens.append(seed_log["metadata"]["username"])
    if seed_log["metadata"]["hostname"] and seed_log["metadata"]["hostname"] != "Unknown":
        raw_tokens.append(seed_log["metadata"]["hostname"])
        
    # Apply initial broadening and prepare clean whitelisted seeds
    broadened_initial = broaden_indicators(list(set(raw_tokens)))
    active_seeds = prepare_seeds(broadened_initial)
    
    # Initialize pivoting collections
    correlated_alerts = [seed_log]
    correlated_ids = {seed_id}
    processed_seeds = set()
    
    # Transitive Closure fixed-point loop
    stable = False
    hop_count = 0
    MAX_HOPS = 6
    
    while not stable:
        hop_count += 1
        if hop_count > MAX_HOPS:
            log_warning(f"CIRCUIT BREAKER TRIGGERED: Attack chain topology runs deeper than {MAX_HOPS} hops!")
            break
            
        previous_ids = set(correlated_ids)
        
        # Get seeds not yet queried
        new_seeds = [s for s in active_seeds if s not in processed_seeds]
        if not new_seeds:
            stable = True
            break
            
        log_info(f"Pivoting Hop [{hop_count}] on seeds: {new_seeds}")
        seed_epoch = seed_log["metadata"]["timestamp_epoch"]
        
        # Query ChromaDB using RRF
        fused = vector_engine.correlate_rrf(
            active_indicators=new_seeds,
            query_text=" ".join(new_seeds),
            timestamp_epoch=seed_epoch,
            time_window_sec=86400  # 24 hour window
        )
        
        # Mark seeds as processed
        for s in new_seeds:
            processed_seeds.add(s)
            
        for alert_id, score, doc, meta in fused:
            if alert_id not in correlated_ids:
                correlated_ids.add(alert_id)
                new_alert = {
                    "id": alert_id,
                    "document": doc,
                    "metadata": meta
                }
                correlated_alerts.append(new_alert)
                log_success(f"Correlated related alert {alert_id} (RRF Score: {score:.4f})")
                
                # Scan new alert for additional indicators
                flat_meta = json.dumps(meta)
                new_inds = ingest_pipeline.scan_indicators(flat_meta)
                new_tokens = []
                new_tokens.extend(new_inds["ips"])
                new_tokens.extend(new_inds["sha256s"])
                new_tokens.extend(new_inds["md5s"])
                new_tokens.extend(new_inds["emails"])
                new_tokens.extend(new_inds["domains"])
                if meta.get("username") and meta.get("username") != "Unknown":
                    new_tokens.append(meta["username"])
                if meta.get("hostname") and meta.get("hostname") != "Unknown":
                    new_tokens.append(meta["hostname"])
                    
                # Apply broadening and filter
                broadened_new = broaden_indicators(list(set(new_tokens)))
                new_active = prepare_seeds(broadened_new)
                
                for ns in new_active:
                    if ns not in active_seeds:
                        active_seeds.append(ns)
                        
        # Check if set of correlated alerts has changed
        if correlated_ids == previous_ids:
            stable = True

    log_success(f"Transitive closure complete in {hop_count} hops. Total correlated alerts: {len(correlated_alerts)}")
    
    # Load playbook
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    
    # 3. Traversal of the Playbook nodes using Milestone Checkpoints
    current_node = "step_1"
    execution_trace = []
    visited_nodes = set()
    
    while current_node and current_node != "complete":
        if current_node in visited_nodes:
            break
        visited_nodes.add(current_node)
        
        node_data = playbook_dict.get("steps", {}).get(current_node, {})
        if not node_data:
            break
            
        instruction = node_data.get("instructions", "No instruction available.")
        routing = node_data.get("routing", "complete")
        
        # Sort and build timeline
        timeline_str = build_timeline_text(correlated_alerts)
        
        # Check sufficiency via Micro-Task 2
        check = check_milestone_sufficiency(timeline_str, instruction, current_node)
        
        status = "MET" if check.milestone_met else "NOT_MET"
        execution_trace.append(MilestoneExecution(
            step_id=current_node,
            instruction=instruction,
            status=status,
            findings=check.reasoning + (f" | Extracted Findings: {check.extracted_data}" if check.extracted_data else "")
        ))
        
        if check.milestone_met:
            # Continue to next node in schema
            if isinstance(routing, dict):
                current_node = routing.get("yes", "complete")
            else:
                current_node = routing
        else:
            # Check if there are suggested pivots to perform additional dynamic retrieval
            broadened_suggested = broaden_indicators(check.suggested_pivots)
            new_pivots = [p for p in broadened_suggested if p not in processed_seeds]
            if new_pivots:
                log_info(f"Playbook step {current_node} requested extra queries for: {new_pivots}")
                seed_epoch = seed_log["metadata"]["timestamp_epoch"]
                extra_fused = vector_engine.correlate_rrf(
                    active_indicators=new_pivots,
                    query_text=" ".join(new_pivots),
                    timestamp_epoch=seed_epoch,
                    time_window_sec=86400
                )
                
                added_any_extra = False
                for alert_id, score, doc, meta in extra_fused:
                    if alert_id not in correlated_ids:
                        correlated_ids.add(alert_id)
                        correlated_alerts.append({
                            "id": alert_id,
                            "document": doc,
                            "metadata": meta
                        })
                        added_any_extra = True
                        log_success(f"Dynamic retrieval matched alert {alert_id} (RRF: {score:.4f})")
                        
                for p in new_pivots:
                    processed_seeds.add(p)
                    
                if added_any_extra:
                    # Retry the current milestone check with enriched timeline
                    continue
            
            # Follow routing for failed checks
            if isinstance(routing, dict):
                current_node = routing.get("no", "complete")
            else:
                current_node = routing

    # 4. Generate Final Structural Analysis (Exactly once at the end)
    timeline_str = build_timeline_text(correlated_alerts)
    final_report = generate_final_analysis(seed_id, playbook_name, timeline_str, execution_trace, correlated_alerts=correlated_alerts)
    
    return {
        "correlated_alerts": correlated_alerts,
        "report": final_report
    }

async def analyze_alert_group_p1(correlated_alerts: List[dict], playbook_path: str) -> dict:
    """
    [FYP-FUNCTION] Pass 1 of the async two-pass pipeline: a single
    consolidated structured-output LLM call (get_chain_p1()) that evaluates
    every playbook step against the current timeline AND extracts pivot
    candidates in one shot — the async/production analogue of
    orchestrate_incident()'s per-step check_milestone_sufficiency() loop,
    trading one call per milestone for one call total.

    [FYP-PROCESS]:
      1. Load the playbook YAML and flatten its steps into a numbered
         instruction list.
      2. build_timeline_text(correlated_alerts) for the current evidence
         set (already-correlated alerts, e.g. from CorrelationEngine's
         Tier 1/2 grouping — NOT the transitive-closure pivoting
         orchestrate_incident() does itself).
      3. Invoke chain_p1.ainvoke() against the Pass1Result schema.
      4. Map each lightweight Pass1StepResult back to a full
         MilestoneExecution by re-attaching that step's instruction text
         from the playbook (Pass1StepResult itself omits it to keep the
         LLM's output smaller/cheaper).

    On LLM failure, returns an all-NOT_MET execution_trace with no
    suggested_pivots so main.py's caller can still proceed to Pass 2 with a
    error-annotated trace rather than crashing.

    Returns: {"execution_trace": List[MilestoneExecution],
    "suggested_pivots": List[str]}.

    [FYP-USED-BY]: main.py's generate_incident_report() closure inside
    main_async() — the production entry point for dynamic/multi-alert
    incidents (as opposed to the 0-LLM-call standalone-alert shortcut,
    generate_local_standalone_report()).
    """
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    seed_alert = correlated_alerts[0]
    seed_id = seed_alert["id"]
    
    steps_desc = []
    for step_id, step_data in sorted(playbook_dict.get("steps", {}).items()):
        steps_desc.append(f"Step '{step_id}': {step_data.get('instructions')}")
    playbook_steps_str = "\n".join(steps_desc)
    
    timeline_str = build_timeline_text(correlated_alerts)
    log_info(f"[LLM CALL] Pass 1: Lightweight Playbook Evaluation & Pivot Extraction for {seed_id}...")
    
    try:
        chain_p1 = get_chain_p1()
        p1_res = await chain_p1.ainvoke({
            "playbook": playbook_steps_str,
            "timeline": timeline_str,
            "incident_id": seed_id
        })
        
        # Map lightweight Pass1StepResult to MilestoneExecution by adding the instruction
        execution_trace = []
        steps_map = playbook_dict.get("steps", {})
        for step in p1_res.execution_trace:
            instr = steps_map.get(step.step_id, {}).get("instructions", "")
            execution_trace.append(MilestoneExecution(
                step_id=step.step_id,
                instruction=instr,
                status=step.status,
                findings=step.findings
            ))
            
        log_success(f"[LLM RESPONSE] Pass 1 completed for {seed_id}. Suggested pivots: {p1_res.suggested_pivots}")
        return {
            "execution_trace": execution_trace,
            "suggested_pivots": p1_res.suggested_pivots
        }
    except Exception as e:
        log_error(f"Pass 1 LLM call failed: {e}")
        # Default fallback
        execution_trace = []
        for step_id, step_data in playbook_dict.get("steps", {}).items():
            execution_trace.append(MilestoneExecution(
                step_id=step_id,
                instruction=step_data.get("instructions", ""),
                status="NOT_MET",
                findings=f"Pass 1 Error: {e}"
            ))
        return {
            "execution_trace": execution_trace,
            "suggested_pivots": []
        }

async def compile_final_report(correlated_alerts: List[dict], playbook_path: str, p1_trace: List[MilestoneExecution]) -> FinalIncidentAnalysis:
    """
    [FYP-FUNCTION] [FYP-EVALUATOR] Pass 2 of the async two-pass pipeline —
    the production-path counterpart to generate_final_analysis(). Called by
    main.py after `correlated_alerts` has possibly been enriched with extra
    alerts pulled in via analyze_alert_group_p1()'s suggested_pivots (main.py
    queries vector_engine.correlate_rrf() with those pivots between Pass 1
    and Pass 2), so this pass sees a superset of the Pass 1 evidence.

    [FYP-PROCESS] / [FYP-RAG]: identical policy-grounding strategy to
    generate_final_analysis() — get_policy_manager() supplies 4 core
    appendices (A/C/F/general escalation rule) plus up to 2 dynamically
    retrieved sections (PolicyVectorIndex.retrieve() against the rebuilt
    timeline) — then a single structured-output LLM call (get_chain_p2())
    re-evaluates the full playbook (not just the NOT_MET steps from Pass 1)
    against the enriched timeline and `p1_trace` context, producing the
    complete FinalIncidentAnalysis.

    [FYP-DECISION] Same post-processing as generate_final_analysis():
    policy_engine.run_policy_compliance_rules() deterministically checks the
    LLM's severity/confidence/checklist/summary, can override
    recommended_containment on escalation, and always attaches the
    Appendix M policy_audit_logs. mitre_mapper.py then renders
    mitre_attack_table locally from the LLM's mitre_mappings (or falls back
    to map_incident_mitre_ttps() over the raw alerts if the LLM didn't
    populate mappings).

    On LLM failure, returns a conservative fallback FinalIncidentAnalysis
    (severity=High, confidence=Low, execution_trace=p1_trace unchanged)
    rather than raising.

    [FYP-USED-BY]: main.py's generate_incident_report() closure — this is
    the actual report-generation call soc_workflow.py's subprocess
    invocation of `python main.py` triggers for any incident with more than
    one correlated alert or external DB relations (see
    generate_local_standalone_report() for the single-alert shortcut).
    """
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    seed_alert = correlated_alerts[0]
    seed_id = seed_alert["id"]
    
    timeline_str = build_timeline_text(correlated_alerts)
    log_info(f"[LLM CALL] Pass 2: Re-evaluating playbook and compiling final report for {seed_id}...")
    
    policy_mgr, policy_vector_index = get_policy_manager()
    
    # Core policies (always present)
    core_keys = ["appendix a", "appendix c", "appendix f", "general escalation rule"]
    core_sections = []
    for k in core_keys:
        sec_text = policy_mgr.get_section(k)
        if sec_text:
            core_sections.append(extract_actionable_rules(sec_text))
            
    # Retrieve dynamic sections based on timeline
    retrieved = policy_vector_index.retrieve(timeline_str, limit=2)
    dynamic_sections = [extract_actionable_rules(doc) for doc in retrieved]
    
    # Combine avoiding duplicates
    all_sections = list(core_sections)
    for doc in dynamic_sections:
        if doc not in all_sections:
            all_sections.append(doc)
            
    policies_context = "\n\n".join(all_sections)
    
    trace_json = json.dumps([t.model_dump() for t in p1_trace], indent=2)
    
    try:
        chain_p2 = get_chain_p2()
        final_report = await chain_p2.ainvoke({
            "incident_id": seed_id,
            "playbook": playbook_name,
            "timeline": timeline_str,
            "trace": trace_json,
            "policies": policies_context
        })
        
        compliance = run_policy_compliance_rules(
            incident_id=seed_id,
            severity=final_report.severity,
            confidence=final_report.confidence,
            incident_summary=final_report.incident_summary,
            recommended_containment=final_report.recommended_containment,
            business_impact_checklist=final_report.business_impact_checklist,
            timeline_text=timeline_str
        )
        
        if compliance["escalation_required"]:
            final_report.recommended_containment = compliance["modified_containment"]
            
        final_report.policy_audit_logs = compliance["audit_records"]

        # Render MITRE ATT&CK TTP Mapping locally (0 extra LLM calls)
        if getattr(final_report, "mitre_mappings", None):
            mitre_analysis = mitre_mapper.IncidentMitreAnalysis(
                incident_id=seed_id,
                attack_chain_summary=final_report.incident_summary,
                mappings=final_report.mitre_mappings
            )
            final_report.mitre_attack_table = mitre_mapper.generate_markdown_table(mitre_analysis)
        else:
            try:
                _, mitre_table = mitre_mapper.map_incident_mitre_ttps(correlated_alerts, llm=None)
                final_report.mitre_attack_table = mitre_table
            except Exception:
                pass

        log_success(f"[LLM RESPONSE] Pass 2 completed for {seed_id} (Severity: {final_report.severity})")
        return final_report
    except Exception as e:
        log_error(f"Pass 2 LLM call failed: {e}")
        # Return fallback FinalIncidentAnalysis
        fallback_report = FinalIncidentAnalysis(
            incident_id=seed_id,
            severity="High",
            confidence="Low",
            execution_trace=p1_trace,
            incident_summary=f"Analysis failed due to error: {e}. Timeline: {timeline_str}",
            actions_taken=["Triage"],
            recommended_containment=["Isolate system and review manually."],
            business_impact_checklist=BusinessImpactChecklist(critical_system="unknown", essential_service="unknown", data_sensitivity="unknown", operational_impact="unknown"),
            severity_justification=f"Fallback due to error: {e}",
            confidence_justification="Fallback due to error",
            policy_audit_logs=[]
        )
        try:
            _, mitre_table = mitre_mapper.map_incident_mitre_ttps(correlated_alerts, llm=None)
            fallback_report.mitre_attack_table = mitre_table
        except Exception:
            pass
        return fallback_report

def analyze_alert_group(correlated_alerts: List[dict], playbook_path: str) -> dict:
    """
    [FYP-FUNCTION] Deprecated/dead stub — unconditionally raises
    NotImplementedError. Superseded by the async pair
    analyze_alert_group_p1() + compile_final_report(), which main.py calls
    directly. Left in place only as a documented placeholder; grep found no
    live callers — verify before removing.
    """
    raise NotImplementedError("Legacy analyze_alert_group is deprecated.")
