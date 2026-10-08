import json
import os
import re

chunk_file = r'C:\C300 FYPIntegrated-7\graphify-out\.graphify_chunk_02.json'

nodes = []
edges = []
hyperedges = []

def add_node(id, label, file_type, source_file, rationale=None):
    assert re.match(r'^[a-z0-9_]+$', id), f'Invalid node id: {id}'
    assert file_type in ['code', 'document', 'paper', 'image', 'rationale', 'concept'], f'Invalid file_type: {file_type}'
    node = {
        'id': id,
        'label': label,
        'file_type': file_type,
        'source_file': source_file,
        'source_location': None,
        'source_url': None,
        'captured_at': None,
        'author': None,
        'contributor': None
    }
    if rationale:
        node['rationale'] = rationale
    nodes.append(node)
    return id

def add_edge(source, target, relation, confidence, confidence_score, source_file, weight=1.0):
    assert re.match(r'^[a-z0-9_]+$', source), f'Invalid source: {source}'
    assert re.match(r'^[a-z0-9_]+$', target), f'Invalid target: {target}'
    valid_relations = ['calls', 'implements', 'references', 'cites', 'conceptually_related_to', 'shares_data_with', 'semantically_similar_to', 'rationale_for']
    assert relation in valid_relations, f'Invalid relation: {relation}'
    assert confidence in ['EXTRACTED', 'INFERRED', 'AMBIGUOUS'], f'Invalid confidence: {confidence}'
    if confidence == 'EXTRACTED':
        assert confidence_score == 1.0, f'EXTRACTED must have score 1.0, got {confidence_score}'
    elif confidence == 'INFERRED':
        assert confidence_score in [0.95, 0.85, 0.75, 0.65, 0.55], f'Invalid INFERRED score: {confidence_score}'
    elif confidence == 'AMBIGUOUS':
        assert 0.1 <= confidence_score <= 0.3, f'Invalid AMBIGUOUS score: {confidence_score}'
    edges.append({
        'source': source,
        'target': target,
        'relation': relation,
        'confidence': confidence,
        'confidence_score': confidence_score,
        'source_file': source_file,
        'source_location': None,
        'weight': weight
    })

def add_hyperedge(id, label, node_ids, relation, confidence, confidence_score, source_file):
    assert re.match(r'^[a-z0-9_]+$', id), f'Invalid hyperedge id: {id}'
    assert relation in ['participate_in', 'implement', 'form'], f'Invalid relation: {relation}'
    assert len(node_ids) >= 3, 'Hyperedge requires >= 3 nodes'
    hyperedges.append({
        'id': id,
        'label': label,
        'nodes': node_ids,
        'relation': relation,
        'confidence': confidence,
        'confidence_score': confidence_score,
        'source_file': source_file
    })

# --- File 1: agents/reporting/testdata/structured_report_review_exports/generated/executive_summary.txt ---
f1 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\generated\executive_summary.txt'
n1_doc = add_node('agents_reporting_testdata_structured_report_review_exports_generated_executive_summary_doc', 'Generated Executive Summary Export', 'document', f1)
n1_inc = add_node('agents_reporting_testdata_structured_report_review_exports_generated_executive_summary_incident_inc_structured_0001', 'Incident INC-STRUCTURED-0001 Generated Review Data', 'concept', f1)
add_edge(n1_doc, n1_inc, 'references', 'EXTRACTED', 1.0, f1)

# --- File 2: agents/reporting/testdata/structured_report_review_exports/generated/final_incident_report.txt ---
f2 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\generated\final_incident_report.txt'
n2_doc = add_node('agents_reporting_testdata_structured_report_review_exports_generated_final_incident_report_doc', 'Generated Final Incident Report Export', 'document', f2)
n2_rec = add_node('agents_reporting_testdata_structured_report_review_exports_generated_final_incident_report_record', 'Final Incident Report Generated Record', 'concept', f2)
add_edge(n2_doc, n2_rec, 'references', 'EXTRACTED', 1.0, f2)

# --- File 3: agents/reporting/testdata/structured_report_review_exports/generated/soc_analyst_review.txt ---
f3 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\generated\soc_analyst_review.txt'
n3_doc = add_node('agents_reporting_testdata_structured_report_review_exports_generated_soc_analyst_review_doc', 'Generated SOC Analyst Review Export', 'document', f3)
n3_tmpl = add_node('agents_reporting_testdata_structured_report_review_exports_generated_soc_analyst_review_template', 'Analyst Review Template Draft Structure', 'concept', f3)
add_edge(n3_doc, n3_tmpl, 'references', 'EXTRACTED', 1.0, f3)

# --- File 4: agents/reporting/testdata/structured_report_review_exports/generated/technical_findings.txt ---
f4 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\generated\technical_findings.txt'
n4_doc = add_node('agents_reporting_testdata_structured_report_review_exports_generated_technical_findings_doc', 'Generated Technical Findings Export', 'document', f4)
n4_data = add_node('agents_reporting_testdata_structured_report_review_exports_generated_technical_findings_data', 'Technical Findings Generated Artifact Data', 'concept', f4)
add_edge(n4_doc, n4_data, 'references', 'EXTRACTED', 1.0, f4)

# --- File 5: outputs/INC-STRUCTURED-0001/reports/confirmed/executive_summary.txt ---
f5 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\outputs\INC-STRUCTURED-0001\reports\confirmed\executive_summary.txt'
n5_doc = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_confirmed_executive_summary_confirmed_executive_summary', 'Confirmed Executive Summary INC-STRUCTURED-0001', 'document', f5)
n5_dec = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_confirmed_executive_summary_analyst_approval_decision', 'Analyst Decision Reviewed and Approved', 'concept', f5)
add_edge(n5_doc, n5_dec, 'references', 'EXTRACTED', 1.0, f5)
add_edge(n1_doc, n5_doc, 'shares_data_with', 'EXTRACTED', 1.0, f5)

# --- File 6: outputs/INC-STRUCTURED-0001/reports/draft_history/executive_summary/20260703T092225261810Z.txt ---
f6 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\outputs\INC-STRUCTURED-0001\reports\draft_history\executive_summary\20260703T092225261810Z.txt'
n6_doc = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_draft_history_executive_summary_20260703t092225261810z_snapshot', 'Executive Summary Draft Snapshot 20260703', 'document', f6)
n6_audit = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_draft_history_executive_summary_20260703t092225261810z_draft_history_audit', 'Draft History Audit Trail', 'concept', f6)
add_edge(n6_doc, n6_audit, 'implements', 'EXTRACTED', 1.0, f6)
add_edge(n6_doc, n5_doc, 'conceptually_related_to', 'INFERRED', 0.95, f6)

# --- File 7: outputs/INC-STRUCTURED-0001/reports/drafts/final_incident_report.txt ---
f7 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\outputs\INC-STRUCTURED-0001\reports\drafts\final_incident_report.txt'
n7_doc = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_drafts_final_incident_report_draft_final_report', 'Draft Final Incident Report INC-STRUCTURED-0001', 'document', f7)
add_edge(n7_doc, n2_doc, 'semantically_similar_to', 'INFERRED', 0.95, f7)

# --- File 8: outputs/INC-STRUCTURED-0001/reports/drafts/soc_analyst_review.txt ---
f8 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\outputs\INC-STRUCTURED-0001\reports\drafts\soc_analyst_review.txt'
n8_doc = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_drafts_soc_analyst_review_draft_soc_review', 'Draft SOC Analyst Review INC-STRUCTURED-0001', 'document', f8)
add_edge(n8_doc, n3_doc, 'semantically_similar_to', 'INFERRED', 0.95, f8)

# --- File 9: outputs/INC-STRUCTURED-0001/reports/drafts/technical_findings.txt ---
f9 = r'C:\C300 FYPIntegrated-7\agents\reporting\testdata\structured_report_review_exports\outputs\INC-STRUCTURED-0001\reports\drafts\technical_findings.txt'
n9_doc = add_node('agents_reporting_testdata_structured_report_review_exports_outputs_inc_structured_0001_reports_drafts_technical_findings_draft_technical_findings', 'Draft Technical Findings INC-STRUCTURED-0001', 'document', f9)
add_edge(n9_doc, n4_doc, 'semantically_similar_to', 'INFERRED', 0.95, f9)

# --- File 10: docs/api.md ---
f10 = r'C:\C300 FYPIntegrated-7\docs\api.md'
n10_api = add_node('docs_api_overview', 'Aegis REST API Specification', 'document', f10)
n10_query = add_node('docs_api_case_query_language', 'Case Query Language Specification', 'concept', f10)
n10_wf = add_node('docs_api_workflow_endpoints', 'Workflow Stage Runs and Approvals API', 'concept', f10)
n10_nw = add_node('docs_api_netwitness_endpoints', 'NetWitness Integration API Endpoints', 'concept', f10)
n10_rep = add_node('docs_api_reports_endpoints', 'Structured Reports API Endpoints', 'concept', f10)
n10_chat = add_node('docs_api_ask_aegis_endpoints', 'Ask Aegis Assistant API Endpoints', 'concept', f10)
n10_admin = add_node('docs_api_admin_pipeline_endpoints', 'Admin Pipeline and Vector Management API', 'concept', f10)
add_edge(n10_api, n10_query, 'references', 'EXTRACTED', 1.0, f10)
add_edge(n10_api, n10_wf, 'references', 'EXTRACTED', 1.0, f10)
add_edge(n10_api, n10_nw, 'references', 'EXTRACTED', 1.0, f10)
add_edge(n10_api, n10_rep, 'references', 'EXTRACTED', 1.0, f10)
add_edge(n10_api, n10_chat, 'references', 'EXTRACTED', 1.0, f10)
add_edge(n10_api, n10_admin, 'references', 'EXTRACTED', 1.0, f10)

# --- File 11: docs/architecture.md ---
f11 = r'C:\C300 FYPIntegrated-7\docs\architecture.md'
n11_arch = add_node('docs_architecture_system_overview', 'Aegis System Architecture', 'document', f11)
n11_stages = add_node('docs_architecture_five_soc_stages', 'Five SOC Pipeline Stages Architecture', 'concept', f11)
n11_factory = add_node('docs_architecture_backend_factory', 'Flask Application Factory Pattern', 'rationale', f11, rationale='Thin HTTP routing decoupling business logic in backend services from Flask request/response lifecycles')
n11_isolation = add_node('docs_architecture_investigation_process_isolation', 'Investigation Subprocess Process Isolation', 'rationale', f11, rationale='Subprocess execution prevents heavy correlation engine, MITRE mapper, and Chroma policy index from blocking the web server')
n11_rep_bound = add_node('docs_architecture_reporting_agent_boundary', 'Reporting Agent Modular Boundary', 'rationale', f11, rationale='Decoupled from historical bundled Flask apps and dashboards to serve strictly as an autonomous reporting agent')
n11_nw_dual = add_node('docs_architecture_netwitness_dual_client', 'NetWitness Dual Client Architecture', 'rationale', f11, rationale='Interactive client for UI operations and fetch_api client for comprehensive background payload enrichment fallback')
n11_store = add_node('docs_architecture_state_store_single_source_of_truth', 'Single Source of Truth State Store', 'rationale', f11, rationale='workflow/state_store.py is the sole authority for run, attempt, stage, and approval states')
add_edge(n11_arch, n11_stages, 'references', 'EXTRACTED', 1.0, f11)
add_edge(n11_arch, n11_factory, 'references', 'EXTRACTED', 1.0, f11)
add_edge(n11_arch, n11_isolation, 'references', 'EXTRACTED', 1.0, f11)
add_edge(n11_arch, n11_rep_bound, 'references', 'EXTRACTED', 1.0, f11)
add_edge(n11_arch, n11_nw_dual, 'references', 'EXTRACTED', 1.0, f11)
add_edge(n11_arch, n11_store, 'references', 'EXTRACTED', 1.0, f11)
add_edge(n10_wf, n11_stages, 'conceptually_related_to', 'INFERRED', 0.95, f11)

# --- File 12: docs/configuration.md ---
f12 = r'C:\C300 FYPIntegrated-7\docs\configuration.md'
n12_cfg = add_node('docs_configuration_guide', 'Aegis Configuration Reference Guide', 'document', f12)
n12_openai = add_node('docs_configuration_openai_settings', 'OpenAI Configuration Settings', 'concept', f12)
n12_ti = add_node('docs_configuration_threat_intel_providers', 'Threat Intelligence Provider Configuration', 'concept', f12)
n12_nw_cfg = add_node('docs_configuration_netwitness_config', 'NetWitness Environment Configuration', 'concept', f12)
n12_chroma = add_node('docs_configuration_chroma_settings', 'Chroma Vector Store Configuration', 'concept', f12)
n12_local = add_node('docs_configuration_local_only_assumption', 'Local-Only Application Security Assumption', 'rationale', f12, rationale='Designed for isolated local or air-gapped SOC evaluation environments with explicit localhost bindings')
add_edge(n12_cfg, n12_openai, 'references', 'EXTRACTED', 1.0, f12)
add_edge(n12_cfg, n12_ti, 'references', 'EXTRACTED', 1.0, f12)
add_edge(n12_cfg, n12_nw_cfg, 'references', 'EXTRACTED', 1.0, f12)
add_edge(n12_cfg, n12_chroma, 'references', 'EXTRACTED', 1.0, f12)
add_edge(n12_cfg, n12_local, 'references', 'EXTRACTED', 1.0, f12)
add_edge(n12_nw_cfg, n11_nw_dual, 'conceptually_related_to', 'INFERRED', 0.85, f12)

# --- File 13: docs/investigation-agent.md ---
f13 = r'C:\C300 FYPIntegrated-7\docs\investigation-agent.md'
n13_inv = add_node('docs_investigation_agent_specification', 'SOC Investigation Agent Technical Specification', 'document', f13)
n13_corr = add_node('docs_investigation_agent_two_tier_correlation', 'Two-Tier Alert Correlation Engine', 'concept', f13)
n13_tier1 = add_node('docs_investigation_agent_tier1_multi_vector_scoring', 'Tier 1 Multi-Vector Correlation Scoring', 'concept', f13)
n13_tier2 = add_node('docs_investigation_agent_tier2_micro_graphing', 'Tier 2 Micro-Graphing Dynamic Clustering', 'concept', f13)
n13_rrf = add_node('docs_investigation_agent_rrf_vector_search', 'Reciprocal Rank Fusion Vector Search', 'concept', f13)
n13_orch = add_node('docs_investigation_agent_multi_pass_orchestration', 'Multi-Pass LLM Investigation Orchestration', 'concept', f13)
n13_sync = add_node('docs_investigation_agent_dual_write_persistence', 'Dual-Write State Persistence Engine', 'concept', f13)
n13_fast = add_node('docs_investigation_agent_zero_llm_fast_path', 'Zero-LLM Standalone Fast Path', 'rationale', f13, rationale='Heuristic fast-path generates local reports for isolated standalone alerts without incurring LLM latency or cost')
add_edge(n13_inv, n13_corr, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_corr, n13_tier1, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_corr, n13_tier2, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_inv, n13_rrf, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_inv, n13_orch, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_inv, n13_sync, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_inv, n13_fast, 'references', 'EXTRACTED', 1.0, f13)
add_edge(n13_corr, n11_isolation, 'conceptually_related_to', 'INFERRED', 0.95, f13)

# --- File 14: docs/workflow.md ---
f14 = r'C:\C300 FYPIntegrated-7\docs\workflow.md'
n14_wf = add_node('docs_workflow_specification', 'Aegis Workflow Orchestration Specification', 'document', f14)
n14_order = add_node('docs_workflow_stage_execution_order', 'Stage Execution Order and Transitions', 'concept', f14)
n14_claim = add_node('docs_workflow_stage_claim_and_lease', 'Atomic Stage Claims and Heartbeat Lease Mechanism', 'rationale', f14, rationale='Single transaction claim with expiration window eliminates worker race conditions')
n14_stale = add_node('docs_workflow_stale_write_rejection', 'Optimistic Concurrency and Stale-Write Rejection', 'rationale', f14, rationale='Run ID and attempt counters prevent stale background tasks from overwriting newer user changes')
n14_hitl = add_node('docs_workflow_human_in_the_loop_gates', 'Human-in-the-Loop Approval Gates', 'concept', f14)
n14_gap = add_node('docs_workflow_evidence_gap_handling', 'Investigation Evidence-Gap Loopback Mechanism', 'concept', f14)
n14_rec = add_node('docs_workflow_durable_resume_recovery', 'Durable Resume and Crash Recovery Path', 'rationale', f14, rationale='Enables resilient resume after restart by inspecting stage lease and status states in SQLite')
add_edge(n14_wf, n14_order, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_wf, n14_claim, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_wf, n14_stale, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_wf, n14_hitl, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_wf, n14_gap, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_wf, n14_rec, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_order, n11_stages, 'references', 'EXTRACTED', 1.0, f14)
add_edge(n14_claim, n11_store, 'conceptually_related_to', 'INFERRED', 0.95, f14)

# --- File 15: documentation/Aegis_FYP_Code_Evaluation_Quick_Reference.md ---
f15 = r'C:\C300 FYPIntegrated-7\documentation\Aegis_FYP_Code_Evaluation_Quick_Reference.md'
n15_ref = add_node('documentation_aegis_fyp_code_evaluation_quick_reference_guide', 'FYP Code Evaluation Quick Reference Guide', 'document', f15)
n15_10s = add_node('documentation_aegis_fyp_code_evaluation_quick_reference_ten_second_method', 'Ten-Second Evaluator Answer Method', 'concept', f15)
n15_nav = add_node('documentation_aegis_fyp_code_evaluation_quick_reference_navigation_strategy', 'Evaluation Code Navigation Strategy', 'concept', f15)
add_edge(n15_ref, n15_10s, 'references', 'EXTRACTED', 1.0, f15)
add_edge(n15_ref, n15_nav, 'references', 'EXTRACTED', 1.0, f15)

# --- File 16: documentation/CODE_FUNCTIONALITY_INDEX.md ---
f16 = r'C:\C300 FYPIntegrated-7\documentation\CODE_FUNCTIONALITY_INDEX.md'
n16_cfi = add_node('documentation_code_functionality_index_index', 'Aegis Code Functionality Index', 'document', f16)
n16_tbl = add_node('documentation_code_functionality_index_master_table', 'Master Functionality Catalog', 'concept', f16)
n16_flow = add_node('documentation_code_functionality_index_cross_file_call_flows', 'Cross-File Call Flow Architecture', 'concept', f16)
n16_state = add_node('documentation_code_functionality_index_workflow_states', 'Aegis Workflow State Machine Reference', 'concept', f16)
add_edge(n16_cfi, n16_tbl, 'references', 'EXTRACTED', 1.0, f16)
add_edge(n16_cfi, n16_flow, 'references', 'EXTRACTED', 1.0, f16)
add_edge(n16_cfi, n16_state, 'references', 'EXTRACTED', 1.0, f16)
add_edge(n16_state, n14_order, 'conceptually_related_to', 'INFERRED', 0.85, f16)

# --- File 17: documentation/FYP_CODE_DOCUMENTATION_COVERAGE.md ---
f17 = r'C:\C300 FYPIntegrated-7\documentation\FYP_CODE_DOCUMENTATION_COVERAGE.md'
n17_cov = add_node('documentation_fyp_code_documentation_coverage_report', 'FYP Code Documentation Coverage Report', 'document', f17)
n17_chk = add_node('documentation_fyp_code_documentation_coverage_checklist', 'Per-File Code Verification Checklist', 'concept', f17)
n17_scope = add_node('documentation_fyp_code_documentation_coverage_scope', '131 Canonical Files Verification Scope', 'concept', f17)
add_edge(n17_cov, n17_chk, 'references', 'EXTRACTED', 1.0, f17)
add_edge(n17_cov, n17_scope, 'references', 'EXTRACTED', 1.0, f17)

# --- File 18: documentation/FYP_SEARCH_TERMS.md ---
f18 = r'C:\C300 FYPIntegrated-7\documentation\FYP_SEARCH_TERMS.md'
n18_st = add_node('documentation_fyp_search_terms_index', 'FYP Search Terms Verified Index', 'document', f18)
n18_lbl = add_node('documentation_fyp_search_terms_standard_labels', 'Standard FYP Code Evaluation Labels', 'concept', f18)
add_edge(n18_st, n18_lbl, 'references', 'EXTRACTED', 1.0, f18)
add_edge(n18_lbl, n15_nav, 'conceptually_related_to', 'INFERRED', 0.85, f18)

# --- File 19: documentation/Phase_6_Feature_Parity.md ---
f19 = r'C:\C300 FYPIntegrated-7\documentation\Phase_6_Feature_Parity.md'
n19_p6 = add_node('documentation_phase_6_feature_parity_inventory', 'Phase 6 Feature Parity Inventory', 'document', f19)
n19_rep = add_node('documentation_phase_6_feature_parity_replacement_decisions', 'Streamlit-to-Flask Replacement Decisions', 'rationale', f19, rationale='Streamlit transient animations and duplicate orchestration were intentionally replaced with persistent polling and canonical commands')
add_edge(n19_p6, n19_rep, 'references', 'EXTRACTED', 1.0, f19)

# --- File 20: documentation/Phase_7_Streamlit_Cutover.md ---
f20 = r'C:\C300 FYPIntegrated-7\documentation\Phase_7_Streamlit_Cutover.md'
n20_p7 = add_node('documentation_phase_7_streamlit_cutover_report', 'Phase 7 Final Parity and Cutover Report', 'document', f20)
n20_mat = add_node('documentation_phase_7_streamlit_cutover_matrix', 'Final Parity Verification Matrix', 'concept', f20)
n20_own = add_node('documentation_phase_7_streamlit_cutover_session_state_ownership', 'Session State Ownership Migration', 'rationale', f20, rationale='Former Streamlit st.session_state cleanly transferred to backend service stores and client JavaScript state')
add_edge(n20_p7, n20_mat, 'references', 'EXTRACTED', 1.0, f20)
add_edge(n20_p7, n20_own, 'references', 'EXTRACTED', 1.0, f20)
add_edge(n19_rep, n20_own, 'semantically_similar_to', 'INFERRED', 0.85, f20)

# --- File 21: frontend/index.html ---
f21 = r'C:\C300 FYPIntegrated-7\frontend\index.html'
n21_shell = add_node('frontend_index_app_shell', 'Aegis Web Application Shell', 'code', f21)
n21_side = add_node('frontend_index_sidebar_navigation', 'Sidebar Navigation Component', 'code', f21)
n21_top = add_node('frontend_index_topbar_search', 'Topbar Search and Case Query Bar', 'code', f21)
n21_dock = add_node('frontend_index_ask_aegis_dock', 'Ask Aegis Assistant Dock and Composer', 'code', f21)
add_edge(n21_shell, n21_side, 'references', 'EXTRACTED', 1.0, f21)
add_edge(n21_shell, n21_top, 'references', 'EXTRACTED', 1.0, f21)
add_edge(n21_shell, n21_dock, 'references', 'EXTRACTED', 1.0, f21)
add_edge(n21_top, n10_query, 'conceptually_related_to', 'INFERRED', 0.85, f21)
add_edge(n21_dock, n10_chat, 'conceptually_related_to', 'INFERRED', 0.85, f21)

# --- File 22: graphify-out/converted/Aegis_FYP_Code_Evaluation_Quick_Reference_b4cd3063.md ---
f22 = r'C:\C300 FYPIntegrated-7\graphify-out\converted\Aegis_FYP_Code_Evaluation_Quick_Reference_b4cd3063.md'
n22_doc = add_node('graphify_out_converted_aegis_fyp_code_evaluation_quick_reference_b4cd3063_converted_doc', 'Converted Evaluation Quick Reference Guide', 'document', f22)
n22_qa = add_node('graphify_out_converted_aegis_fyp_code_evaluation_quick_reference_b4cd3063_evaluator_qa_structure', 'Evaluator Question Answering Methodology', 'concept', f22)
add_edge(n22_doc, n22_qa, 'references', 'EXTRACTED', 1.0, f22)
add_edge(n22_doc, n15_ref, 'semantically_similar_to', 'INFERRED', 0.95, f22)

# --- Hyperedges (max 3) ---
add_hyperedge(
    'hyperedge_soc_hitl_pipeline',
    'Human-in-the-Loop Pipeline Flow',
    [n11_stages, n14_hitl, n10_wf],
    'participate_in',
    'INFERRED',
    0.95,
    f14
)

add_hyperedge(
    'hyperedge_investigation_two_tier_correlation',
    'Investigation Multi-Vector and Micro-Graphing Architecture',
    [n13_corr, n13_tier1, n13_tier2, n13_orch],
    'form',
    'EXTRACTED',
    1.0,
    f13
)

add_hyperedge(
    'hyperedge_streamlit_cutover_governance',
    'Streamlit to Flask Cutover Architecture Governance',
    [n19_p6, n20_p7, n20_own],
    'form',
    'EXTRACTED',
    1.0,
    f20
)

# Build JSON payload
payload = {
    'nodes': nodes,
    'edges': edges,
    'hyperedges': hyperedges,
    'input_tokens': 0,
    'output_tokens': 0
}

os.makedirs(os.path.dirname(chunk_file), exist_ok=True)
with open(chunk_file, 'w', encoding='utf-8') as out_fp:
    json.dump(payload, out_fp, indent=2)

print('Success: wrote', len(nodes), 'nodes,', len(edges), 'edges,', len(hyperedges), 'hyperedges to', chunk_file)
