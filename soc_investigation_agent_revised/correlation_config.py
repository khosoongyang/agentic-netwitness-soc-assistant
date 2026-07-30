# ==========================================================================
# [FYP-FILE]
# Important dependencies: Python standard runtime.
# File: soc_investigation_agent_revised/correlation_config.py
# Purpose: Central tunable-constants module for the Two-Tier SOC Alert
#   Correlation Engine (correlation_engine.py). Holds every weight, penalty,
#   threshold and window size used by the correlation scoring formulas so
#   they are not hardcoded/scattered across correlation_engine.py.
# Main functionalities:
#   - Relational (infrastructure overlap) score weights (S_rel)
#   - Tactical/contextual score weights (S_tact): semantic, MITRE, temporal, RRF
#   - Combined-score blend weight and no-crossover penalty
#   - Decision thresholds for MERGE vs SIMILAR_BUT_UNRELATED vs UNRELATED
#   - Dynamic sliding-window clustering bounds (Tier 2 micro-graph clustering)
#   - Reciprocal Rank Fusion (RRF) constant and temporal decay constant
# Inputs: none (static constants module, no runtime inputs).
# Outputs: module-level constants imported by other files.
# Workflow position: Investigation stage / evidence-correlation config layer.
#   Sits underneath correlation_engine.py; does not run standalone.
# Called by: correlation_engine.py (imported as `import correlation_config as
#   config`) for every scoring/threshold/window decision in Tier 1 (semantic +
#   relational + tactical fusion) and Tier 2 (dynamic window clustering).
# Calls: nothing (pure constants, no imports besides none needed).
# Key evaluator search terms: correlation weights, S_rel, S_tact, S_corr,
#   THETA_MATCH, THETA_TACT_HIGH, RRF_K, dynamic window clustering, temporal
#   decay, evidence correlation configuration.
# ==========================================================================

# [FYP-CONFIG] Configuration parameters for the Two-Tier SOC Alert Correlation Engine

# [FYP-CONFIG] Relational Infrastructure Weights (S_rel) — how much each shared
# asset type (IP, subnet, host, user) contributes to the relational/infrastructure
# overlap score between a new alert and an existing incident. Used by
# CorrelationEngine._calculate_relational_score() in correlation_engine.py.
RELATIONAL_WEIGHTS = {
    "ip": 0.4,
    "subnet": 0.1,
    "host": 0.3,
    "user": 0.2
}

# [FYP-CONFIG] Tactical & Contextual Weights (S_tact) — blend weights for the four
# tactical signal components (semantic similarity, MITRE tactic progression,
# temporal proximity/rhythm, RRF rank-fusion score) combined in
# CorrelationEngine.evaluate_tier1() to produce S_tact.
TACTICAL_WEIGHTS = {
    "semantic": 0.3,
    "mitre": 0.3,
    "temporal": 0.2,
    "rrf": 0.2
}

# [FYP-CONFIG] [FYP-DECISION] Combined Score Weights — how S_rel and S_tact are
# blended into the final S_corr correlation score, and the penalty subtracted
# when there is no infrastructure crossover at all (guards against
# semantically-similar-but-unrelated incidents being merged).
COMBINED_WEIGHT = 0.6  # omega: weight for relational score (1 - omega for tactical)
PENALTY_NO_CROSS = 0.5  # Lambda: penalty if there is zero infrastructure crossover

# [FYP-CONFIG] [FYP-DECISION] Decision Thresholds — the cutoffs that route an
# alert to MERGE (join an existing incident), SIMILAR_BUT_UNRELATED (flagged
# but not merged, see sync_engine.IncidentMetadata.similar_to_incident), or
# UNRELATED (falls through to Tier 2 clustering) in
# CorrelationEngine.evaluate_tier1().
THETA_MATCH = 0.65       # S_corr threshold for merging
THETA_TACT_HIGH = 0.70   # S_tact threshold for Similar-but-Unrelated tagging

# [FYP-CONFIG] [FYP-PROCESS] Dynamic Window Clustering Settings (seconds) — bounds
# for the expanding sliding-window micro-graph clustering used by
# CorrelationEngine.evaluate_tier2() / _should_bridge_alerts() when an alert
# does not merge into any existing incident and must be tested for forming a
# brand-new multi-alert incident cluster.
INITIAL_WINDOW_SEC = 900    # 15 minutes
MAX_WINDOW_SEC = 7200       # 2 hours
WINDOW_STEP_SEC = 900       # 15 minutes increment

# [FYP-CONFIG] Reciprocal Rank Fusion (RRF) Constant — smoothing constant `k` used
# in both vector_engine.correlate_rrf() (RAG-side alert retrieval) and
# CorrelationEngine.evaluate_tier1() (incident-level RRF of lexical + semantic
# ranks) to fuse ranked result lists.
RRF_K = 60

# [FYP-CONFIG] Temporal Decay Constant (tau) for basic proximity scoring (seconds)
# — controls how quickly the temporal proximity score S_temporal decays with
# elapsed time between an alert and the latest event in a candidate incident.
# See CorrelationEngine._calculate_temporal_score().
TEMPORAL_DECAY_SEC = 43200  # 12 hours
