# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: asyncio, correlation_config, ingest_pipeline, json, math, os, sync_engine, time.
# =============================================================================
# File: soc_investigation_agent_revised/correlation_engine.py
# Purpose: [FYP-PROCESS] THE evidence-correlation engine for the Investigation
#   stage — decides whether an incoming alert belongs to an existing active
#   incident (Tier 1: direct scoring against each active incident) or should
#   be bridged with other unassigned alerts into a new incident (Tier 2).
# Main functionalities:
#   1. CorrelationEngine.__init__/load_active_incidents(): loads all
#      non-resolved/closed incidents from incident_reports/*/incident_data.json
#      into an in-memory cache on startup.
#   2. [FYP-EVALUATOR] evaluate_tier1(): scores an alert against every active
#      incident using a weighted blend of _calculate_relational_score()
#      (shared IOCs), _calculate_mitre_score() (tactic-chain proximity via
#      TACTIC_ORDER), and _calculate_temporal_score() (time proximity).
#   3. evaluate_tier2()/_should_bridge_alerts(): when Tier 1 finds no strong
#      match, checks whether the alert should be bridged with other
#      currently-unassigned alerts to seed a brand-new incident.
#   4. [FYP-EVALUATOR] correlate_alert(): the public entry point that runs
#      Tier 1 then Tier 2 and returns the correlation decision.
#   5. sync_create_incident()/sync_update_incident(): write-through
#      (dual-write) to both the file repository and the ChromaDB vector
#      index (via sync_engine.IncidentSyncManager), keeping the in-memory
#      cache consistent.
# Inputs: alert_log dicts, the in-memory active_incidents cache (sourced
#   from incident_reports/ + ChromaDB via sync_engine/vector_engine).
# Outputs: correlate_alert() -> a correlation decision (which incident, or
#   new-incident-bridge, with a confidence score).
# Workflow position: Investigation stage, evidence-correlation layer —
#   called for each alert as it enters the investigation pipeline.
# Called by [FYP-USED-BY]: verify via grep — likely orchestrator.py.
# Calls [FYP-CALLS]: ingest_pipeline, vector_engine, sync_engine
#   (FileIncidentRepository, ChromaIncidentVectorStore, IncidentSyncManager).
# Key evaluator search terms: correlate_alert, evaluate_tier1, evaluate_tier2,
#   CorrelationEngine, [FYP-EVALUATOR]
# =============================================================================

import os
import json
import time
import math
import asyncio
from typing import Dict, List, Tuple, Optional, Set

import correlation_config as config
import ingest_pipeline
import vector_engine
from sync_engine import (
    FileIncidentRepository,
    ChromaIncidentVectorStore,
    IncidentSyncManager,
    Incident,
    IncidentMetadata,
    IncidentSeverity,
    IncidentStatus
)

# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-CLASS] `CorrelationEngine` — owns CorrelationEngine state or behaviour for the investigation component.
# [FYP-PROCESS] Important methods: __init__, load_active_incidents, sync_create_incident, sync_update_incident, _extract_indicators, _calculate_relational_score, _calculate_mitre_score, _calculate_temporal_score.
# [FYP-USED-BY] Static constructor/type references include soc_investigation_agent_revised/main.py:main_async.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class CorrelationEngine:
    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `base_folder`, `db_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `ChromaIncidentVectorStore`, `FileIncidentRepository`, `IncidentSyncManager`, `load_active_incidents`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __init__(self, base_folder: str = "incident_reports", db_path: str = "ChromaDatabase"):
        self.base_folder = base_folder
        self.db_path = db_path
        
        # Instantiate sync-related repositories
        self.repo = FileIncidentRepository(self.base_folder)
        self.vector_index = ChromaIncidentVectorStore(self.db_path)
        self.sync_manager = IncidentSyncManager(self.repo, self.vector_index)
        
        # In-memory cache of active incidents: incident_id -> Incident
        self.active_incidents: Dict[str, Incident] = {}
        self.load_active_incidents()

    # [FYP-FUNCTION] `load_active_incidents` — retrieves load active incidents data for the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `clear`, `exists`, `isdir`, `join`, `len`, `listdir`, `load`, `model_validate`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def load_active_incidents(self):
        """Loads all active incidents from the filesystem into the memory cache."""
        self.active_incidents.clear()
        if not os.path.exists(self.base_folder):
            return
        
        for folder in os.listdir(self.base_folder):
            folder_path = os.path.join(self.base_folder, folder)
            if os.path.isdir(folder_path):
                json_path = os.path.join(folder_path, "incident_data.json")
                if os.path.exists(json_path):
                    try:
                        with open(json_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        incident = Incident.model_validate(data)
                        if incident.metadata.status.value not in ("RESOLVED", "CLOSED"):
                            self.active_incidents[incident.id] = incident
                    except Exception as e:
                        print(f"[-] CorrelationEngine: Failed to load incident {folder} into cache: {e}")
        print(f"[+] CorrelationEngine: Loaded {len(self.active_incidents)} active incidents into memory cache.")

    # [FYP-FUNCTION] `sync_create_incident` — implements the sync create incident operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `create_incident`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    async def sync_create_incident(self, incident: Incident):
        """Performs a synchronous write-through (dual-write) creation and updates cache."""
        await self.sync_manager.create_incident(incident)
        if incident.metadata.status.value not in ("RESOLVED", "CLOSED"):
            self.active_incidents[incident.id] = incident

    # [FYP-FUNCTION] `sync_update_incident` — implements the sync update incident operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `pop`, `update_incident`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    async def sync_update_incident(self, incident: Incident):
        """Performs a synchronous write-through (dual-write) update and updates cache."""
        await self.sync_manager.update_incident(incident)
        if incident.metadata.status.value in ("RESOLVED", "CLOSED"):
            self.active_incidents.pop(incident.id, None)
        else:
            self.active_incidents[incident.id] = incident

    # --- TACTIC ORDERING MAP ---
    TACTIC_ORDER = {
        "initial-access": 1,
        "execution": 2,
        "persistence": 3,
        "privilege-escalation": 4,
        "credential-access": 5,
        "discovery": 6,
        "lateral-movement": 7,
        "collection": 8,
        "exfiltration": 9,
        "command-and-control": 10,
        "impact": 11
    }

    # [FYP-FUNCTION] `_extract_indicators` — transforms extract indicators input into the stable representation required by downstream investigation processing.
    # [FYP-INPUT] Parameters: `alert_log`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:_should_bridge_alerts, soc_investigation_agent_revised/correlation_engine.py:evaluate_tier1, soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `add`, `get`, `join`, `len`, `lower`, `set`, `split`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _extract_indicators(self, alert_log: dict) -> Set[str]:
        """Extracts normalized forensic indicators from a raw or processed alert log."""
        meta = alert_log.get("metadata", {})
        indicators = set()
        
        # IPs and subnets
        ips_str = meta.get("ips", "")
        if ips_str:
            for ip in [x.strip().lower() for x in ips_str.split(",") if x.strip()]:
                indicators.add(ip)
                parts = ip.split(".")
                if len(parts) == 4:
                    indicators.add(".".join(parts[:3]) + ".") # Subnet tracker
        
        # Domains
        dom_str = meta.get("domains", "")
        if dom_str:
            for dom in [x.strip().lower() for x in dom_str.split(",") if x.strip()]:
                indicators.add(dom)
        
        # Hashes
        for hash_field in ["sha256s", "md5s"]:
            val = meta.get(hash_field, "")
            if val:
                for h in [x.strip().lower() for x in val.split(",") if x.strip()]:
                    indicators.add(h)
                    
        # Username and hostname
        for field in ["username", "hostname"]:
            val = meta.get(field)
            if val and str(val).lower() not in ("unknown", "null", "none", ""):
                indicators.add(str(val).strip().lower())
                
        return indicators

    # [FYP-FUNCTION] `_calculate_relational_score` — implements the calculate relational score operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `alert_indicators`, `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:evaluate_tier1; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `endswith`, `get`, `join`, `len`, `lower`, `split`, `str`, `strip`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _calculate_relational_score(self, alert_indicators: Set[str], incident: Incident) -> float:
        """Calculates the physical asset/infrastructure overlap score S_rel."""
        meta = incident.metadata
        inc_indicators = {str(ind).lower() for ind in incident.indicators}
        
        has_ip = False
        has_subnet = False
        has_host = False
        has_user = False
        
        # Clean inputs (exclude subnets from exact matching checks)
        alert_clean_inds = {ind for ind in alert_indicators if not ind.endswith(".")}
        
        # Check raw alert details for overlaps
        for alert in incident.raw_alerts:
            alert_meta = alert.get("metadata", {})
            
            # IP check
            ips = [x.strip().lower() for x in alert_meta.get("ips", "").split(",") if x.strip()]
            for ip in ips:
                if ip in alert_clean_inds:
                    has_ip = True
                parts = ip.split(".")
                if len(parts) == 4:
                    sub = ".".join(parts[:3]) + "."
                    if sub in alert_indicators:
                        has_subnet = True
                        
            # Host check
            host = alert_meta.get("hostname", "").lower()
            if host != "unknown" and host in alert_clean_inds:
                has_host = True
                
            # User check
            user = alert_meta.get("username", "").lower()
            if user != "unknown" and user in alert_clean_inds:
                has_user = True

        # Check explicit incident indicator list
        for ind in inc_indicators:
            if ind in alert_clean_inds:
                if "." in ind:
                    has_ip = True
                else:
                    # Could be host or user
                    has_host = True
                    has_user = True
            elif ind.endswith(".") and ind in alert_indicators:
                has_subnet = True

        # Score mapping: exact IP or Host matches give maximum relational significance (1.0)
        if has_ip or has_host:
            return 1.0
        elif has_user:
            return 0.6
        elif has_subnet:
            return 0.2
        else:
            return 0.0

    # [FYP-FUNCTION] `_calculate_mitre_score` — implements the calculate mitre score operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `alert_log`, `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:evaluate_tier1; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `get`, `lower`, `max`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _calculate_mitre_score(self, alert_log: dict, incident: Incident) -> float:
        """Calculates MITRE ATT&CK Lifecycle Sequencing progression score S_mitre."""
        alert_tactic = alert_log.get("metadata", {}).get("tactic", "").lower()
        if not alert_tactic or alert_tactic == "unknown":
            return 0.1 # Default small baseline if untagged
            
        alert_order = self.TACTIC_ORDER.get(alert_tactic, 0)
        
        # Extract incident's tactics
        incident_orders = []
        for alert in incident.raw_alerts:
            t = alert.get("metadata", {}).get("tactic")
            if t and t != "Unknown":
                ord_val = self.TACTIC_ORDER.get(t.lower(), 0)
                if ord_val > 0:
                    incident_orders.append(ord_val)
                    
        if not incident_orders:
            return 0.5 # Neutral if incident has no mitre info yet
            
        max_inc_order = max(incident_orders)
        
        # Sequencing Rules
        if alert_order > max_inc_order:
            return 1.0  # Clear downstream progression
        elif alert_order in incident_orders:
            return 0.5  # Parallel step at the same stage
        else:
            return 0.1  # Upstream transition (backwards progression or out-of-order)

    # [FYP-FUNCTION] `_calculate_temporal_score` — implements the calculate temporal score operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `alert_epoch`, `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:evaluate_tier1; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `abs`, `append`, `exp`, `get`, `int`, `len`, `max`, `range`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _calculate_temporal_score(self, alert_epoch: int, incident: Incident) -> float:
        """Calculates temporal proximity and anti-evasion rhythmic similarity S_temporal."""
        # Find maximum/latest timestamp in incident raw alerts
        epochs = []
        for alert in incident.raw_alerts:
            ep = alert.get("metadata", {}).get("timestamp_epoch")
            if ep:
                epochs.append(int(ep))
                
        if not epochs:
            return 0.0
            
        latest_epoch = max(epochs)
        delta_t = abs(alert_epoch - latest_epoch)
        
        # Proximity score decay
        s_prox = math.exp(-delta_t / config.TEMPORAL_DECAY_SEC)
        
        # Anti-evasion rhythmic check:
        # If incident has >= 3 alerts, check if there is a periodic pattern (beaconing)
        if len(epochs) >= 3:
            sorted_epochs = sorted(epochs)
            intervals = [sorted_epochs[i+1] - sorted_epochs[i] for i in range(len(sorted_epochs)-1)]
            mean_int = sum(intervals) / len(intervals)
            
            # Simple check if standard deviation is small relative to mean
            variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            
            if mean_int > 60 and std_dev / mean_int < 0.15: # Regular beaconing sequence (> 1 min)
                # Check if the new alert matches the periodic pattern (interval matches mean_int)
                last_interval = abs(alert_epoch - latest_epoch)
                # Allow a 15% tolerance or 60s tolerance, whichever is larger
                tolerance = max(0.15 * mean_int, 60.0)
                if abs(last_interval - mean_int) <= tolerance:
                    return 1.0 # High match score due to rhythm matching
                    
        return s_prox

    # --- TIER 1 AGGREGATION ---
    async def evaluate_tier1(self, alert_log: dict) -> Tuple[str, float, Optional[str]]:
        """
        [FYP-FUNCTION] Evidence Correlation — Tier 1 (match against active incidents)
        [FYP-PROCESS] [FYP-EVALUATOR] [FYP-DECISION]

        Evaluates the incoming alert against all ongoing active incidents,
        combining _calculate_relational_score() (shared indicators),
        _calculate_mitre_score() (tactic-chain proximity), and
        _calculate_temporal_score() (time proximity/periodicity) into one
        weighted score per candidate incident, then picks the best match.

        Returns: Tuple of (Decision, Score, IncidentID_or_None).
        Decisions: "MERGE", "SIMILAR_BUT_UNRELATED", "UNRELATED".

        [FYP-USED-BY]: correlate_alert() below, which runs this first and
        only falls through to evaluate_tier2() (new-incident bridging) when
        this returns "UNRELATED".
        """
        alert_id = alert_log["id"]
        alert_epoch = alert_log["metadata"]["timestamp_epoch"]
        alert_doc = alert_log["document"]
        alert_indicators = self._extract_indicators(alert_log)
        
        if not self.active_incidents:
            return "UNRELATED", 0.0, None

        # 1. Lexical Search: rank based on number of overlapping indicators
        lexical_ranks: List[Tuple[str, int]] = []
        for inc_id, incident in self.active_incidents.items():
            inc_inds = {str(ind).lower() for ind in incident.indicators}
            overlap = len(alert_indicators.intersection(inc_inds))
            if overlap > 0:
                lexical_ranks.append((inc_id, overlap))
        
        # Sort Lexical Ranks (descending match count)
        lexical_ranks.sort(key=lambda x: x[1], reverse=True)
        lex_rank_map = {item[0]: idx + 1 for idx, item in enumerate(lexical_ranks)}

        # 2. Semantic Search: Query ChromaDB incidents collection
        semantic_results = await self.vector_index.query(alert_doc, limit=10)
        # Sort Semantic Ranks (ascending distance / descending similarity)
        # Note: ChromaDB distances are cosine distance: 0 is identical, 1 is orthogonal
        sem_rank_map = {}
        sem_sim_map = {}
        for rank, res in enumerate(semantic_results):
            inc_id = res["id"]
            if inc_id in self.active_incidents:
                sem_rank_map[inc_id] = rank + 1
                # Convert cosine distance to cosine similarity
                sem_sim_map[inc_id] = max(0.0, 1.0 - res["score"])

        # 3. Compute RRF ranks
        rrf_scores = {}
        for inc_id in self.active_incidents:
            lex_rank = lex_rank_map.get(inc_id)
            sem_rank = sem_rank_map.get(inc_id)
            
            score = 0.0
            if lex_rank is not None:
                score += 1.0 / (config.RRF_K + lex_rank)
            if sem_rank is not None:
                score += 1.0 / (config.RRF_K + sem_rank)
                
            rrf_scores[inc_id] = score

        # Max possible RRF score
        rrf_max = 2.0 / (config.RRF_K + 1)

        # 4. Core Multi-Vector Evaluation
        best_inc_id = None
        best_corr_score = -1.0
        best_tact_score = 0.0
        best_rel_score = 0.0

        for inc_id, incident in self.active_incidents.items():
            # Vector 1: RRF Normalized
            s_rrf = rrf_scores.get(inc_id, 0.0) / rrf_max
            
            # Vector 2: Temporal & Rhythm
            s_temporal = self._calculate_temporal_score(alert_epoch, incident)
            
            # Vector 3: MITRE TTP progression
            s_mitre = self._calculate_mitre_score(alert_log, incident)
            
            # Vector 4: Playbook & Historical CBR (represented as a simplified heuristic)
            # Check if alert contains a potential playbook pivot/instruction satisfaction
            s_playbook = 0.0
            alert_flat = json.dumps(alert_log).lower()
            if "process" in alert_flat or "parent" in alert_flat:
                # If playbook steps are looking for spawned processes, alert helps
                s_playbook = 0.5
                
            s_cbr = 0.0
            # Simulating closed CBR check via simple keyword search or indicators
            for ind in alert_indicators:
                if ind in incident.indicators:
                    s_cbr = 0.5
            s_playbook_cbr = s_playbook + s_cbr
            
            # Semantic cosine similarity
            cos_sim = sem_sim_map.get(inc_id, 0.0)
            
            # Calculate Contextual & Tactical Score
            s_tact = (
                config.TACTICAL_WEIGHTS["semantic"] * cos_sim +
                config.TACTICAL_WEIGHTS["mitre"] * s_mitre +
                config.TACTICAL_WEIGHTS["temporal"] * s_temporal +
                config.TACTICAL_WEIGHTS["rrf"] * s_rrf
            )
            
            # Calculate Relational Score
            s_rel = self._calculate_relational_score(alert_indicators, incident)
            
            # Combined Correlation Score with Crossover Penalty
            s_corr = config.COMBINED_WEIGHT * s_rel + (1.0 - config.COMBINED_WEIGHT) * s_tact
            if s_rel == 0.0:
                s_corr -= config.PENALTY_NO_CROSS

            if s_corr > best_corr_score:
                best_corr_score = s_corr
                best_inc_id = inc_id
                best_tact_score = s_tact
                best_rel_score = s_rel

        # Decision Routing Matrix
        if best_corr_score >= config.THETA_MATCH:
            return "MERGE", best_corr_score, best_inc_id
        elif best_tact_score >= config.THETA_TACT_HIGH and best_rel_score == 0.0:
            return "SIMILAR_BUT_UNRELATED", best_corr_score, best_inc_id
        else:
            return "UNRELATED", best_corr_score, None

    # --- TIER 2 CLUSTERING ---
    # [FYP-FUNCTION] `_should_bridge_alerts` — implements the should bridge alerts operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `a1`, `a2`, `window_sec`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:evaluate_tier2; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_extract_indicators`, `abs`, `endswith`, `get`, `intersection`, `len`, `lower`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _should_bridge_alerts(self, a1: dict, a2: dict, window_sec: int) -> bool:
        """Determines if two orphan alerts exhibit clustering characteristics."""
        m1 = a1.get("metadata", {})
        m2 = a2.get("metadata", {})
        
        # Asset overlap checks (exclude subnets from exact matching)
        a1_inds = {ind for ind in self._extract_indicators(a1) if not ind.endswith(".")}
        a2_inds = {ind for ind in self._extract_indicators(a2) if not ind.endswith(".")}
        
        asset_overlap = len(a1_inds.intersection(a2_inds)) > 0
        
        t1 = m1.get("timestamp_epoch", 0)
        t2 = m2.get("timestamp_epoch", 0)
        delta_t = abs(t1 - t2)
        
        # Case A: Rapid time-window proximity on a single asset
        if asset_overlap and delta_t <= window_sec:
            return True
            
        # Case B: Immediate multi-stage MITRE ATT&CK sequencing happening back-to-back
        tactic1 = m1.get("mitre_att&ck", {}).get("tactic", "")
        tactic2 = m2.get("mitre_att&ck", {}).get("tactic", "")
        if not tactic1:
            tactic1 = a1.get("incident_details", {}).get("mitre_att&ck", {}).get("tactic", "")
        if not tactic2:
            tactic2 = a2.get("incident_details", {}).get("mitre_att&ck", {}).get("tactic", "")
            
        if tactic1 and tactic2:
            ord1 = self.TACTIC_ORDER.get(tactic1.lower(), 0)
            ord2 = self.TACTIC_ORDER.get(tactic2.lower(), 0)
            
            # If sequential/close tactics within 30 minutes on shared asset boundary
            if asset_overlap and abs(ord1 - ord2) <= 2 and delta_t <= 1800:
                return True
                
        return False

    # [FYP-FUNCTION] `evaluate_tier2` — implements the evaluate tier2 operation used by the surrounding investigation workflow.
    # [FYP-INPUT] Parameters: `target_alert`, `unassigned_alerts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/correlation_engine.py:correlate_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_should_bridge_alerts`, `abs`, `add`, `append`, `len`, `pop`, `print`, `range`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    async def evaluate_tier2(self, target_alert: dict, unassigned_alerts: List[dict]) -> Tuple[str, List[dict]]:
        """
        Runs the dynamic sliding-window micro-graphing algorithm on recent unassigned alerts.
        Returns: Tuple of (Decision, List_of_alerts_in_cluster)
        Decisions: "NEW_CLUSTER", "STANDALONE"
        """
        if not unassigned_alerts:
            return "STANDALONE", [target_alert]

        current_window = config.INITIAL_WINDOW_SEC
        
        while current_window <= config.MAX_WINDOW_SEC:
            # 1. Filter candidates inside the window
            t_target = target_alert["metadata"]["timestamp_epoch"]
            window_candidates = []
            for alert in unassigned_alerts:
                if alert["id"] == target_alert["id"]:
                    continue
                t_alert = alert["metadata"]["timestamp_epoch"]
                if abs(t_alert - t_target) <= current_window:
                    window_candidates.append(alert)
                    
            if not window_candidates:
                # No candidates in window, expand window and try again
                current_window += config.WINDOW_STEP_SEC
                continue
                
            # 2. Build graph edges
            all_nodes = [target_alert] + window_candidates
            n = len(all_nodes)
            adj = {i: [] for i in range(n)}
            
            for i in range(n):
                for j in range(i + 1, n):
                    if self._should_bridge_alerts(all_nodes[i], all_nodes[j], current_window):
                        adj[i].append(j)
                        adj[j].append(i)
                        
            # 3. Find connected component of target_alert (node 0)
            visited = set()
            queue = [0]
            visited.add(0)
            
            while queue:
                curr = queue.pop(0)
                for neighbor in adj[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
                        
            cluster = [all_nodes[idx] for idx in visited]
            
            if len(cluster) >= 2:
                # Cluster critical mass reached!
                print(f"[+] CorrelationEngine: Alert clusters with {len(cluster)-1} other alerts at window size {current_window/60:.1f}m.")
                return "NEW_CLUSTER", cluster
                
            # No cluster of size >= 2 formed around target_alert, expand and try again
            current_window += config.WINDOW_STEP_SEC
            
        # If we exit the loop, the alert remains isolated
        print(f"[~] CorrelationEngine: Alert remains isolated after dynamic window searches.")
        return "STANDALONE", [target_alert]

    # --- MAIN CORRELATION ENTRY POINT ---
    async def correlate_alert(self, alert_log: dict, unassigned_alerts: List[dict]) -> dict:
        """
        [FYP-FUNCTION] Evidence Correlation — Public Entry Point
        [FYP-ENTRY-POINT] [FYP-EVALUATOR] [FYP-PROCESS]

        Coordinates the entire two-tier routing workflow for a new incoming
        alert: runs evaluate_tier1() (match against active incidents) first;
        only if that returns "UNRELATED" does it fall through to
        evaluate_tier2() (bridge with other unassigned alerts into a new
        incident). Returns a decision dictionary.

        [FYP-USED-BY]: this is the CorrelationEngine class's main public
        method — the whole class exists to support this call.
        """
        alert_id = alert_log["id"]
        print(f"[*] CorrelationEngine: Processing alert {alert_id} through two-tier engine...")
        
        start_time = time.time()
        
        # Tier 1 Analysis
        decision, score, inc_id = await self.evaluate_tier1(alert_log)
        duration = time.time() - start_time
        print(f"[*] CorrelationEngine: Tier 1 took {duration*1000:.2f}ms. Decision: {decision} (Score: {score:.3f})")
        
        if decision == "MERGE":
            return {
                "decision": "MERGE",
                "incident_id": inc_id,
                "score": score,
                "latency_ms": duration * 1000
            }
            
        ref_inc_id = None
        if decision == "SIMILAR_BUT_UNRELATED":
            ref_inc_id = inc_id
            print(f"[~] CorrelationEngine: Flagged Similar but Unrelated to {ref_inc_id}. Routing to Tier 2...")
            
        # Tier 2 Analysis
        t2_start = time.time()
        t2_decision, cluster_alerts = await self.evaluate_tier2(alert_log, unassigned_alerts)
        t2_duration = time.time() - t2_start
        total_duration = time.time() - start_time
        print(f"[*] CorrelationEngine: Tier 2 took {t2_duration*1000:.2f}ms. Decision: {t2_decision}. Total Latency: {total_duration*1000:.2f}ms.")
        
        return {
            "decision": t2_decision,
            "cluster_alerts": cluster_alerts,
            "similar_to_incident": ref_inc_id,
            "latency_ms": total_duration * 1000
        }
