# Configuration parameters for the Two-Tier SOC Alert Correlation Engine

# Relational Infrastructure Weights (S_rel)
RELATIONAL_WEIGHTS = {
    "ip": 0.4,
    "subnet": 0.1,
    "host": 0.3,
    "user": 0.2
}

# Tactical & Contextual Weights (S_tact)
TACTICAL_WEIGHTS = {
    "semantic": 0.3,
    "mitre": 0.3,
    "temporal": 0.2,
    "rrf": 0.2
}

# Combined Score Weights
COMBINED_WEIGHT = 0.6  # omega: weight for relational score (1 - omega for tactical)
PENALTY_NO_CROSS = 0.5  # Lambda: penalty if there is zero infrastructure crossover

# Decision Thresholds
THETA_MATCH = 0.65       # S_corr threshold for merging
THETA_TACT_HIGH = 0.70   # S_tact threshold for Similar-but-Unrelated tagging

# Dynamic Window Clustering Settings (seconds)
INITIAL_WINDOW_SEC = 900    # 15 minutes
MAX_WINDOW_SEC = 7200       # 2 hours
WINDOW_STEP_SEC = 900       # 15 minutes increment

# Reciprocal Rank Fusion (RRF) Constant
RRF_K = 60

# Temporal Decay Constant (tau) for basic proximity scoring (seconds)
TEMPORAL_DECAY_SEC = 43200  # 12 hours
