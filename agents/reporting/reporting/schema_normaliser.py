"""
[FYP-FILE] reporting/schema_normaliser.py (209 lines)
# File: soc_reporting_agent/reporting/schema_normaliser.py
# Purpose: This module implements report generation and export behaviour for schema normaliser.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: re, typing.
# Key evaluator search terms: get_nested, first_present, to_list, yes_no, classify_ioc, _extract_label, [FYP-FUNCTION].

[FYP-SECTION] Responsibility
A dotted-path/dict-normalisation utility library for reconciling
triage_result.json and investigation_result.json fields (severity,
confidence, assets, users, IOCs, evidence, recommended actions) into a
single normalised shape, with conflict detection (triage vs. investigation
disagreement) and "recovered field" bookkeeping (a field only found in
triage but not investigation).

[FYP-EVALUATOR] Import-graph note: of all functions in this file, only
get_nested() is actually imported elsewhere (by report_validator.py, for
REQUIRED_FIELDS lookups). first_present/to_list/yes_no/classify_ioc/
normalise_severity/normalise_confidence/normalise_asset/normalise_user/
normalise_ioc/normalise_evidence/normalise_action/combine_iocs have no
other in-repo callers found via search — context_builder.py implements its
own parallel (and more elaborate, with more field-name fallbacks) version
of this same normalisation logic (_normalise_asset/_normalise_user/
_normalise_ioc/etc.) rather than calling into this module. Confirm during
evaluation whether this module is legacy/superseded or intentionally kept
as an alternate/simpler normalisation path.

[FYP-USED-BY] reporting/report_validator.py (get_nested only, via
`from reporting.schema_normaliser import get_nested`).
"""
import re
from typing import Any
def get_nested(data: dict[str, Any], path: str, default: Any=None) -> Any:
    """[FYP-FUNCTION] Resolve a dot-separated path (e.g. "triage.severity")
    against nested dicts, returning `default` as soon as any segment is
    missing or the current value stops being a dict. [FYP-USED-BY]
    report_validator.validate_required_fields() (REQUIRED_FIELDS entries
    like "severity.label" are resolved through this)."""
    cur=data
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur: cur=cur[part]
        else: return default
    return cur
def first_present(*values: Any, fallback: Any='Not Provided') -> Any:
    """[FYP-FUNCTION] Return the first value in `values` that is not one of
    None/''/[]/{} (i.e. the first "meaningfully present" value), else
    `fallback`. The core building block every other normaliser in this
    file uses to pick between triage/investigation/enriched-alert
    candidates for the same logical field."""
    for v in values:
        if v not in [None,'',[],{}]: return v
    return fallback
def to_list(value: Any) -> list[Any]:
    """[FYP-FUNCTION] Coerce a scalar/None/list into a list: None -> [],
    an existing list is passed through unchanged, anything else is wrapped
    in a single-element list."""
    if value is None: return []
    return value if isinstance(value, list) else [value]
def yes_no(value: Any) -> str:
    """[FYP-FUNCTION] Render a boolean-ish field for display: True->"Yes",
    False->"No", None/''->"Not Provided", anything else -> str(value)."""
    if value is True: return 'Yes'
    if value is False: return 'No'
    if value in [None,'']: return 'Not Provided'
    return str(value)
def classify_ioc(value: str) -> str:
    """[FYP-FUNCTION] Heuristically classify a raw indicator string into a
    display type (URL / IP Address / File Hash / Email Address / Domain /
    generic "Indicator") using URL-scheme prefixes, an IPv4 regex, MD5/
    SHA1/SHA256-length hex regexes, and a simple '@'/'.' presence check.
    Used as classify_ioc's fallback `type` when the source data has no
    explicit `type`/`ioc_type` field."""
    value=str(value)
    if value.startswith(('http://','https://','hxxp://','hxxps://')): return 'URL'
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', value): return 'IP Address'
    if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', value): return 'File Hash'
    if '@' in value: return 'Email Address'
    if '.' in value: return 'Domain'
    return 'Indicator'
def _extract_label(value):
    """[FYP-FUNCTION] Pull a comparable label out of either a raw scalar or
    a dict-shaped severity/confidence value (checking 'label', then
    'severity', then 'confidence' keys), for the triage-vs-investigation
    equality check in normalise_severity()/normalise_confidence()."""
    if isinstance(value, dict):
        return first_present(value.get('label'), value.get('severity'), value.get('confidence'), fallback=None)
    return first_present(value, fallback=None)


def normalise_severity(triage, investigation, recovered_fields, conflicts=None):
    """[FYP-FUNCTION] Reconcile severity across triage_result.json and
    investigation_result.json into one normalised {label, score, reason}
    dict.

    [FYP-PROCESS] Investigation's severity takes precedence when both are
    present and differ (recorded as a conflict entry with
    reason="Investigation severity takes precedence because it reflects
    deeper analysis."). If investigation left severity blank, triage's
    value is used and recorded in `recovered_fields` as recovered from
    triage_result.json. Mutates `conflicts`/`recovered_fields` in place (as
    well as returning the resolved value) so a single call site can
    accumulate both lists across every normalised field.
    [FYP-VALIDATION] This is the conflict-detection mechanism for
    severity — analogous data-consistency logic also exists independently
    in context_builder.py/export_context_enhancer.py; this function is not
    currently wired into that pipeline (see module-level [FYP-EVALUATOR]
    note)."""
    conflicts = conflicts if conflicts is not None else []
    triage_sev = first_present(get_nested(triage, 'triage.severity'), triage.get('severity'), fallback=None)
    inv_sev = first_present(investigation.get('updated_severity'), investigation.get('severity'), fallback=None)
    triage_label = _extract_label(triage_sev)
    inv_label = _extract_label(inv_sev)
    if triage_label and inv_label and str(triage_label).lower() != str(inv_label).lower():
        conflicts.append({'field':'severity','triage_value':triage_label,'investigation_value':inv_label,'selected_value':inv_label,'reason':'Investigation severity takes precedence because it reflects deeper analysis.'})
    value = inv_sev if inv_sev is not None else triage_sev
    if triage_sev is not None and inv_sev in [None,'',{},[]]:
        recovered_fields.append({'field':'severity','recovered_from':'triage_result.json','reason':'Investigation output did not explicitly provide severity.'})
    if isinstance(value, dict):
        return {'label':first_present(value.get('label'), value.get('severity')), 'score':first_present(value.get('score')), 'reason':first_present(value.get('reason'), value.get('severity_reason'))}
    return {'label':first_present(value), 'score':first_present(investigation.get('severity_score'), triage.get('risk_score')), 'reason':first_present(investigation.get('severity_change_reason'), triage.get('severity_reason'))}


def normalise_confidence(triage, investigation, recovered_fields, conflicts=None):
    """[FYP-FUNCTION] Confidence counterpart to normalise_severity() — same
    precedence rule (investigation wins on conflict, triage is the
    recovery fallback), same in-place mutation of `conflicts`/
    `recovered_fields`. See normalise_severity() docstring for the shared
    algorithm."""
    conflicts = conflicts if conflicts is not None else []
    triage_conf = first_present(get_nested(triage, 'triage.confidence'), triage.get('confidence'), fallback=None)
    inv_conf = first_present(investigation.get('updated_confidence'), investigation.get('confidence'), fallback=None)
    triage_label = _extract_label(triage_conf)
    inv_label = _extract_label(inv_conf)
    if triage_label and inv_label and str(triage_label).lower() != str(inv_label).lower():
        conflicts.append({'field':'confidence','triage_value':triage_label,'investigation_value':inv_label,'selected_value':inv_label,'reason':'Investigation confidence takes precedence because it reflects deeper analysis.'})
    value = inv_conf if inv_conf is not None else triage_conf
    if triage_conf is not None and inv_conf in [None,'',{},[]]:
        recovered_fields.append({'field':'confidence','recovered_from':'triage_result.json','reason':'Investigation output did not explicitly provide confidence.'})
    if isinstance(value, dict):
        return {'label':first_present(value.get('label'), value.get('confidence')), 'score':first_present(value.get('score')), 'reason':first_present(value.get('reason'), value.get('confidence_reason'))}
    return {'label':first_present(value), 'score':first_present(investigation.get('confidence_score'), triage.get('confidence_score')), 'reason':first_present(investigation.get('confidence_change_reason'), triage.get('confidence_reason'))}


def normalise_asset(asset):
    """[FYP-FUNCTION] Normalise one raw affected-asset entry (dict or bare
    string/hostname) into a fixed-shape dict with hostname/ip_address/
    asset_type/criticality/owner/business_function/isolation_status keys,
    each falling back through several possible upstream field-name
    aliases via first_present(). A bare string input produces a dict with
    only `hostname` populated and every other field "Not Provided"."""
    if isinstance(asset, dict):
        return {'hostname':first_present(asset.get('hostname'),asset.get('host'),asset.get('name')), 'ip_address':first_present(asset.get('ip_address'),asset.get('ip'),asset.get('host_ip')), 'asset_type':first_present(asset.get('asset_type'),asset.get('type')), 'criticality':first_present(asset.get('criticality'),asset.get('asset_criticality')), 'owner':first_present(asset.get('owner'),asset.get('business_owner')), 'business_function':first_present(asset.get('business_function'),asset.get('role')), 'isolation_status':yes_no(first_present(asset.get('isolation_status'), fallback='Not Provided'))}
    return {'hostname':str(asset),'ip_address':'Not Provided','asset_type':'Not Provided','criticality':'Not Provided','owner':'Not Provided','business_function':'Not Provided','isolation_status':'Not Provided'}
def normalise_user(user):
    """[FYP-FUNCTION] Normalise one raw affected-user entry (dict or bare
    string/username) into a fixed-shape dict with username/email/role/
    privilege_level/groups/mfa_status/account_status keys. `groups` is
    coerced to a list (wrapping a non-list value as [str(value)]); a bare
    string input is treated as email if it contains '@'."""
    if isinstance(user, dict):
        groups=user.get('group_memberships', [])
        return {'username':first_present(user.get('username'),user.get('email'),user.get('name')), 'email':first_present(user.get('email'),user.get('username')), 'role':first_present(user.get('role'),user.get('user_role')), 'privilege_level':first_present(user.get('privilege_level'),user.get('privilege')), 'groups':groups if isinstance(groups,list) else [str(groups)], 'mfa_status':first_present(user.get('mfa_status'),user.get('mfa')), 'account_status':first_present(user.get('account_status'),user.get('status'))}
    text=str(user); return {'username':text,'email':text if '@' in text else 'Not Provided','role':'Not Provided','privilege_level':'Not Provided','groups':[],'mfa_status':'Not Provided','account_status':'Not Provided'}
def normalise_ioc(ioc, source):
    """[FYP-FUNCTION] Normalise one raw IOC entry (dict or bare
    value/string) into a fixed-shape dict with value/type/reputation/
    confidence/source/evidence_refs keys. `type` falls back to
    classify_ioc(val) when the source data has no explicit type; `source`
    falls back to the caller-supplied `source` label (e.g.
    'enriched_alert.json' or 'investigation_result.json')."""
    if isinstance(ioc, dict):
        val=first_present(ioc.get('value'), ioc.get('ioc'), ioc.get('indicator'))
        return {'value':val,'type':first_present(ioc.get('type'), ioc.get('ioc_type'), fallback=classify_ioc(val)), 'reputation':first_present(ioc.get('reputation'), ioc.get('verdict'), ioc.get('risk_level')), 'confidence':first_present(ioc.get('confidence'), ioc.get('confidence_level')), 'source':first_present(ioc.get('source'), fallback=source), 'evidence_refs':to_list(ioc.get('evidence_refs', []))}
    val=str(ioc); return {'value':val,'type':classify_ioc(val),'reputation':'Not Provided','confidence':'Not Provided','source':source,'evidence_refs':[]}
def normalise_evidence(evidence, index):
    """[FYP-FUNCTION] Normalise one raw evidence entry (dict or bare
    string) into a fixed-shape dict with id/source/type/description/
    timestamp/confidence/raw_reference keys. `id` falls back to a
    generated 'EVID-{index:03d}' when the source has no id/evidence_id; a
    bare string input is stamped with source='investigation_result.json'
    and type='Observation'."""
    if isinstance(evidence, dict):
        return {'id':first_present(evidence.get('id'), evidence.get('evidence_id'), fallback=f'EVID-{index:03d}'), 'source':first_present(evidence.get('source')), 'type':first_present(evidence.get('type'), evidence.get('evidence_type')), 'description':first_present(evidence.get('description'), evidence.get('summary'), fallback=str(evidence)), 'timestamp':first_present(evidence.get('timestamp'), evidence.get('time')), 'confidence':first_present(evidence.get('confidence')), 'raw_reference':first_present(evidence.get('raw_reference'), evidence.get('reference'))}
    return {'id':f'EVID-{index:03d}','source':'investigation_result.json','type':'Observation','description':str(evidence),'timestamp':'Not Provided','confidence':'Not Provided','raw_reference':'Not Provided'}
def normalise_action(action, index):
    """[FYP-FUNCTION] Normalise one raw recommended-action entry (dict or
    bare string) into a fixed-shape dict with priority/action/owner/
    approval_required/rationale keys. `priority` falls back to a generated
    'P{index}' label; `approval_required` is rendered via yes_no()."""
    if isinstance(action, dict):
        return {'priority':first_present(action.get('priority'), fallback=f'P{index}'), 'action':first_present(action.get('action'), action.get('recommendation'), fallback=str(action)), 'owner':first_present(action.get('owner')), 'approval_required':yes_no(action.get('approval_required')), 'rationale':first_present(action.get('rationale'), action.get('reason'))}
    return {'priority':f'P{index}','action':str(action),'owner':'Not Provided','approval_required':'Not Provided','rationale':'Not Provided'}
def combine_iocs(enriched_alert, investigation):
    """[FYP-FUNCTION] Merge IOCs from enriched_alert.json (iocs/
    extracted_iocs/enrichment.iocs/threat_intelligence.iocs, tagged source
    'enriched_alert.json') and investigation_result.json (iocs/
    final_iocs/extracted_iocs, tagged source 'investigation_result.json')
    into one de-duplicated list, normalised via normalise_ioc(). De-dup key
    is (type, value); entries whose normalised value is the 'Not Provided'
    sentinel are dropped entirely rather than kept as noise."""
    raw=[]
    for path in ['iocs','extracted_iocs','enrichment.iocs','threat_intelligence.iocs']:
        found=get_nested(enriched_alert,path)
        if found: raw += [(x,'enriched_alert.json') for x in to_list(found)]
    for path in ['iocs','final_iocs','extracted_iocs']:
        found=get_nested(investigation,path)
        if found: raw += [(x,'investigation_result.json') for x in to_list(found)]
    out=[]; seen=set()
    for item, src in raw:
        n=normalise_ioc(item, src); key=(n['type'],n['value'])
        if n['value']!='Not Provided' and key not in seen: out.append(n); seen.add(key)
    return out
