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

load_dotenv()

# --- ANSI COLOR CODES ---
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

def log_info(message: str): print(f"{Color.CYAN}[*] {message}{Color.RESET}", file=sys.stderr)
def log_success(message: str): print(f"{Color.GREEN}[+] {message}{Color.RESET}", file=sys.stderr)
def log_warning(message: str): print(f"{Color.YELLOW}[~] {message}{Color.RESET}", file=sys.stderr)
def log_error(message: str): print(f"{Color.RED}[!] ERROR: {message}{Color.RESET}", file=sys.stderr)

# --- PYDANTIC SCHEMAS FOR STRUCTURED OUTPUT ---

class SuspiciousSeeds(BaseModel):
    seeds: List[str] = Field(description="A list of suspicious IOCs/tokens to query for, excluding generic benign items.")

class MilestoneCheck(BaseModel):
    milestone_met: bool = Field(description="True if the active playbook step can be fully answered with the current incident timeline, otherwise False.")
    reasoning: str = Field(description="Explanation of whether the milestone is met, detailing what was found or what is missing.")
    extracted_data: Optional[str] = Field(description="The extracted data for this step if the milestone is met, otherwise null.")
    suggested_pivots: List[str] = Field(default_factory=list, description="List of suspected IOCs/keys/pivots to query ChromaDB for to gather more context. Return concrete indicators (values), not descriptions.")

class MilestoneExecution(BaseModel):
    step_id: str
    instruction: str
    status: Literal["MET", "NOT_MET", "SKIPPED"]
    findings: str
class BusinessImpactChecklist(BaseModel):
    critical_system: str = Field(description="Is a critical or significant system impacted? (yes/no/unknown)")
    essential_service: str = Field(description="Is an important or essential service affected? (yes/no/unknown)")
    data_sensitivity: str = Field(description="Is personal, confidential, or sensitive data involved? (yes/no/unknown)")
    operational_impact: str = Field(description="Is there outage, degradation, or loss of business function? (yes/no/unknown)")

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

class Pass1StepResult(BaseModel):
    step_id: str
    status: Literal["MET", "NOT_MET"]
    findings: str

class Pass1Result(BaseModel):
    execution_trace: List[Pass1StepResult] = Field(description="The step-by-step trace of how the playbook was executed.")
    suggested_pivots: List[str] = Field(default_factory=list, description="Concrete indicator values (IPs, domains, hashes, usernames) to query to resolve any unmet steps.")

# --- LLM INITIALIZATION ---

_llm = None
_chain_p1 = None
_chain_p2 = None

def get_llm():
    global _llm
    if _llm is None:
        api_key = os.getenv("OPENAI_API_KEY")
        _llm = ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0,
            openai_api_key=api_key
        )
    return _llm

class PolicyClassificationResult(BaseModel):
    relevant_sections: List[str] = Field(description="List of section keys/headers that are relevant to the Investigation Agent.")

def classify_policies_for_investigation(sections: Dict[str, str]) -> List[str]:
    """Uses a one-time LLM call to classify policy sections relevant to the Investigation Agent."""
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
        chain = prompt | get_llm().with_structured_output(PolicyClassificationResult, method="json_schema")
        result = chain.invoke({"sections": sections_summary_str})
        log_success(f"[LLM RESPONSE] AI Policy Parser classified relevant sections: {result.relevant_sections}")
        return result.relevant_sections
    except Exception as e:
        log_error(f"Failed to run AI Policy Parser: {e}. Falling back to default whitelist.")
        return ["appendix a", "appendix b", "appendix c", "appendix f", "appendix g", "appendix h", "appendix i", "appendix j", "general escalation rule"]

class PolicyVectorIndex:
    """
    ChromaDB vector store mapping policy sections into embeddings to support semantic retrieval.
    Uses the 'soc_policies' collection.
    """
    def __init__(self, db_path: str = "ChromaDatabase"):
        import chromadb
        from chromadb.utils import embedding_functions
        self.client = chromadb.PersistentClient(path=db_path)
        self.default_ef = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="soc_policies",
            embedding_function=self.default_ef,
            metadata={"hnsw:space": "cosine"}
        )

    def populate(self, sections: Dict[str, str], relevant_keys: List[str]):
        """Populates the collection with only the whitelisted/classified sections."""
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
                documents.append(text)
                metadatas.append({"section_name": key})
                
        if ids:
            self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            log_success(f"PolicyVectorIndex: Successfully populated with {len(ids)} relevant sections.")

    def retrieve(self, query_text: str, limit: int = 2) -> List[str]:
        """Queries the policy store to semantically retrieve relevant sections."""
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
        _chain_p1 = prompt_p1 | get_llm().with_structured_output(Pass1Result, method="json_schema")
    return _chain_p1
def get_chain_p2():
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
            "4. For the 'incident_summary' (Technical Chronology Summary) field: Provide a clear, chronological step-by-step summary listing exactly what actions were taken in this incident (e.g., phishing email sent -> user clicked and executed attachment -> executable spawned process -> reverse shell created), including timestamps, recorded IOCs, and affected assets.\n"
            "5. For the 'recommended_containment' field: Recommend containment actions adhering to Appendix G, H, and I. Ensure all recommended containment actions are highly specific and action-oriented. Do not write generic recommendations.\n"
            "6. For the 'mitre_mappings' field: Evaluate the full event sequence holistically at the incident level and map the attack steps to precise MITRE ATT&CK TTPs in chronological order. Always resolve precise sub-techniques (e.g. T1566.002, T1569.002, T1021.002) and populate timeline_phase, observed_evidence, tactic, technique_name, and technique_id.\n"
            "Note: Your output must be structured to match the Pydantic schema."
        )
        prompt_p2 = ChatPromptTemplate.from_messages([
            ("system", system_prompt_p2),
            ("human", "=== INCIDENT ID ===\n{incident_id}\n\n=== PLAYBOOK ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK TRACE ===\n{trace}")
        ])
        _chain_p2 = prompt_p2 | get_llm().with_structured_output(FinalIncidentAnalysis, method="json_schema")
    return _chain_p2

# --- MICRO-TASK IMPLEMENTATIONS ---

def filter_suspicious_seeds(raw_tokens: List[str]) -> List[str]:
    """Micro-Task 1: Stateless LLM filtering to strip benign infrastructure noise from seeds."""
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
        chain = prompt | get_llm().with_structured_output(SuspiciousSeeds, method="json_schema")
        result = chain.invoke({"tokens": str(raw_tokens)})
        log_success(f"[LLM RESPONSE] Filtered tokens: {result.seeds}")
        return result.seeds
    except Exception as e:
        log_error(f"Failed to filter seeds with LLM: {e}. Falling back to original tokens.")
        benign = {"127.0.0.1", "0.0.0.0", "localhost", "svchost.exe", "Unknown"}
        return [t for t in raw_tokens if t not in benign]

def check_milestone_sufficiency(timeline_str: str, instruction: str, step_id: str) -> MilestoneCheck:
    """Micro-Task 2: Stateless LLM checking to verify if timeline evidence meets playbook step criteria."""
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
        chain = prompt | get_llm().with_structured_output(MilestoneCheck, method="json_schema")
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
    """Final Structural Reporting: Invoked exactly once at the end of the analysis phase."""
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
        "3. For the 'incident_summary' (Technical Chronology Summary) field: Provide a clear, chronological step-by-step summary listing exactly what actions were taken in this incident (e.g., phishing email sent -> user clicked and executed attachment -> executable spawned process -> reverse shell created), including timestamps, recorded IOCs, and affected assets.\n"
        "4. For the 'recommended_containment' field: Recommend containment actions adhering to Appendix G, H, and I. Ensure all recommended containment actions are highly specific and action-oriented.\n"
        "5. For the 'mitre_mappings' field: Evaluate the full event sequence holistically at the incident level and map the attack steps to precise MITRE ATT&CK TTPs in chronological order. Always resolve precise sub-techniques (e.g. T1566.002, T1569.002, T1021.002) and populate timeline_phase, observed_evidence, tactic, technique_name, and technique_id.\n"
        "Note: Your output must be structured to match the Pydantic schema."
    )
    
    trace_json = json.dumps([t.model_dump() for t in execution_trace], indent=2)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "=== INCIDENT ID ===\n{incident_id}\n\n=== PLAYBOOK ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK TRACE ===\n{trace}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(FinalIncidentAnalysis, method="json_schema")
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
    """Formats list of correlated alerts into a chronological summary string."""
    lines = []
    sorted_alerts = sorted(correlated_alerts, key=lambda x: x["metadata"]["timestamp_epoch"])
    
    for alert in sorted_alerts:
        ts = alert["metadata"]["timestamp_str"]
        alert_id = alert["id"]
        doc = alert["document"]
        lines.append(f"[{ts}] {alert_id}: {doc}")
        
    return "\n".join(lines)

# --- INFRASTRUCTURE BROADENING ---

IP_PAT = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$')

def broaden_indicators(indicators: List[str]) -> List[str]:
    """Returns the indicators list directly without broadening (subnet/domain expansion disabled)."""
    return list(indicators)

# --- SEED PREPARATION AND FILTER WHITELISTING ---

def prepare_seeds(raw_tokens: List[str]) -> List[str]:
    """Protects high-fidelity indicators (private IPs, subnets, hashes, emails, names) from LLM filter."""
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
    """Orchestrates ingestion, transitive-closure metadata pivoting, milestone checks, and final reporting."""
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
    Pass 1: Consolidated playbook check + lightweight trace extraction + pivot extraction (1 LLM call).
    Returns a dict with {"execution_trace": List[MilestoneExecution], "suggested_pivots": List[str]}.
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
    Pass 2: Re-runs playbook step checks and generates updated report using enriched timeline.
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
    """Legacy synchronous wrapper for two-pass evaluation."""
    raise NotImplementedError("Legacy analyze_alert_group is deprecated.")

