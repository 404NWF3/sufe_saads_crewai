GET_ATTACK_BY_CODE = """
SELECT
    attack_id, attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
    exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload,
    created_at, updated_at
FROM wp11.attack_entry
WHERE attack_code = %(attack_code)s
"""

GET_ATTACK_BY_ID = """
SELECT
    attack_id, attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
    exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload,
    created_at, updated_at
FROM wp11.attack_entry
WHERE attack_id = %(attack_id)s
"""

CREATE_ATTACK_ENTRY = """
INSERT INTO wp11.attack_entry (
    attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
    exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload
)
VALUES (
    %(attack_code)s, %(canonical_name)s, %(attack_family)s, %(severity_level)s, %(entry_status)s, %(summary)s,
    %(description)s, %(exploit_preconditions)s, %(impact_scope)s, %(confidence_score)s, %(first_seen_at)s,
    %(last_seen_at)s, %(primary_stix_bundle_id)s, %(primary_stix_object_id)s, %(stix_graph_status)s,
    %(stix_type)s, %(stix_payload)s
)
RETURNING
    attack_id, attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
    exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload,
    created_at, updated_at
"""

UPSERT_ATTACK_ENTRY_BY_CODE = """
INSERT INTO wp11.attack_entry (
    attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
    exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload
)
VALUES (
    %(attack_code)s, %(canonical_name)s, %(attack_family)s, %(severity_level)s, %(entry_status)s, %(summary)s,
    %(description)s, %(exploit_preconditions)s, %(impact_scope)s, %(confidence_score)s, %(first_seen_at)s,
    %(last_seen_at)s, %(primary_stix_bundle_id)s, %(primary_stix_object_id)s, %(stix_graph_status)s,
    %(stix_type)s, %(stix_payload)s
)
ON CONFLICT (attack_code) DO UPDATE SET
    canonical_name = EXCLUDED.canonical_name,
    attack_family = EXCLUDED.attack_family,
    severity_level = EXCLUDED.severity_level,
    entry_status = EXCLUDED.entry_status,
    summary = EXCLUDED.summary,
    description = EXCLUDED.description,
    exploit_preconditions = EXCLUDED.exploit_preconditions,
    impact_scope = EXCLUDED.impact_scope,
    confidence_score = EXCLUDED.confidence_score,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at,
    primary_stix_bundle_id = EXCLUDED.primary_stix_bundle_id,
    primary_stix_object_id = EXCLUDED.primary_stix_object_id,
    stix_graph_status = EXCLUDED.stix_graph_status,
    stix_type = EXCLUDED.stix_type,
    stix_payload = EXCLUDED.stix_payload
RETURNING
    attack_id, attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
    exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload,
    created_at, updated_at
"""

INSERT_ATTACK_EVIDENCE = """
INSERT INTO wp11.attack_evidence (
    attack_id, raw_id, evidence_role, extractor_name, evidence_snippet
)
VALUES (
    %(attack_id)s, %(raw_id)s, %(evidence_role)s, %(extractor_name)s, %(evidence_snippet)s
)
ON CONFLICT (attack_id, raw_id) DO UPDATE SET
    evidence_role = EXCLUDED.evidence_role,
    extractor_name = EXCLUDED.extractor_name,
    evidence_snippet = EXCLUDED.evidence_snippet,
    extracted_at = now()
RETURNING
    attack_id, raw_id, evidence_role, extractor_name, extracted_at, evidence_snippet
"""

LIST_ATTACK_EVIDENCE = """
SELECT attack_id, raw_id, evidence_role, extractor_name, extracted_at, evidence_snippet
FROM wp11.attack_evidence
WHERE attack_id = %(attack_id)s
ORDER BY extracted_at DESC
"""

INSERT_CVSS_ASSESSMENT = """
INSERT INTO wp11.attack_cvss_assessment (
    attack_id, source_raw_id, cvss_version, vector_string, base_score, temporal_score, environmental_score,
    severity_label, exploitability_subscore, impact_subscore, score_origin, score_provider, confidence_score,
    is_primary, published_at, calculated_at
)
VALUES (
    %(attack_id)s, %(source_raw_id)s, %(cvss_version)s, %(vector_string)s, %(base_score)s, %(temporal_score)s,
    %(environmental_score)s, %(severity_label)s, %(exploitability_subscore)s, %(impact_subscore)s, %(score_origin)s,
    %(score_provider)s, %(confidence_score)s, %(is_primary)s, %(published_at)s, %(calculated_at)s
)
RETURNING
    score_id, attack_id, source_raw_id, cvss_version, vector_string, base_score, temporal_score, environmental_score,
    severity_label, exploitability_subscore, impact_subscore, score_origin, score_provider, confidence_score,
    is_primary, published_at, calculated_at, created_at
"""

LIST_CVSS_ASSESSMENTS = """
SELECT
    score_id, attack_id, source_raw_id, cvss_version, vector_string, base_score, temporal_score, environmental_score,
    severity_label, exploitability_subscore, impact_subscore, score_origin, score_provider, confidence_score,
    is_primary, published_at, calculated_at, created_at
FROM wp11.attack_cvss_assessment
WHERE attack_id = %(attack_id)s
ORDER BY created_at DESC
"""

GET_CVSS_BY_SCORE_ID = """
SELECT
    score_id, attack_id, source_raw_id, cvss_version, vector_string, base_score, temporal_score, environmental_score,
    severity_label, exploitability_subscore, impact_subscore, score_origin, score_provider, confidence_score,
    is_primary, published_at, calculated_at, created_at
FROM wp11.attack_cvss_assessment
WHERE score_id = %(score_id)s
"""

UNSET_PRIMARY_CVSS_BY_ATTACK_VERSION = """
UPDATE wp11.attack_cvss_assessment
SET is_primary = FALSE
WHERE attack_id = %(attack_id)s AND cvss_version = %(cvss_version)s AND is_primary = TRUE
"""

SET_PRIMARY_CVSS_BY_SCORE_ID = """
UPDATE wp11.attack_cvss_assessment
SET is_primary = TRUE
WHERE score_id = %(score_id)s
RETURNING
    score_id, attack_id, source_raw_id, cvss_version, vector_string, base_score, temporal_score, environmental_score,
    severity_label, exploitability_subscore, impact_subscore, score_origin, score_provider, confidence_score,
    is_primary, published_at, calculated_at, created_at
"""

UPSERT_ATTACK_TAXONOMY = """
INSERT INTO wp11.attack_taxonomy_map (
    attack_id, taxonomy_type, taxonomy_code, taxonomy_name, is_primary, confidence_score
)
VALUES (
    %(attack_id)s, %(taxonomy_type)s, %(taxonomy_code)s, %(taxonomy_name)s, %(is_primary)s, %(confidence_score)s
)
ON CONFLICT (attack_id, taxonomy_type, taxonomy_code) DO UPDATE SET
    taxonomy_name = EXCLUDED.taxonomy_name,
    is_primary = EXCLUDED.is_primary,
    confidence_score = EXCLUDED.confidence_score
RETURNING
    map_id, attack_id, taxonomy_type, taxonomy_code, taxonomy_name, is_primary, confidence_score
"""

RESET_PRIMARY_TAXONOMY = """
UPDATE wp11.attack_taxonomy_map
SET is_primary = FALSE
WHERE attack_id = %(attack_id)s AND taxonomy_type = %(taxonomy_type)s AND is_primary = TRUE
"""

LIST_TAXONOMY_BY_ATTACK = """
SELECT map_id, attack_id, taxonomy_type, taxonomy_code, taxonomy_name, is_primary, confidence_score
FROM wp11.attack_taxonomy_map
WHERE attack_id = %(attack_id)s
ORDER BY taxonomy_type, taxonomy_code
"""

INSERT_SEED_ASSET = """
INSERT INTO wp11.attack_seed_asset (
    attack_id, asset_type, asset_name, artifact_uri, checksum, language, modality, qa_status, is_template, metadata_json
)
VALUES (
    %(attack_id)s, %(asset_type)s, %(asset_name)s, %(artifact_uri)s, %(checksum)s, %(language)s, %(modality)s,
    %(qa_status)s, %(is_template)s, %(metadata_json)s
)
RETURNING
    asset_id, attack_id, asset_type, asset_name, artifact_uri, checksum, language, modality, qa_status, is_template,
    metadata_json, created_at
"""

LIST_PUBLISHED_SEED_ASSETS = """
SELECT
    asset_id, attack_id, asset_type, asset_name, artifact_uri, checksum, language, modality, qa_status, is_template,
    metadata_json, created_at
FROM wp11.attack_seed_asset
WHERE attack_id = %(attack_id)s AND qa_status IN ('reviewed', 'published')
ORDER BY created_at DESC
"""

INSERT_REMEDIATION_ADVICE = """
INSERT INTO wp11.remediation_advice (
    attack_id, advice_type, title, content, priority_level, source_uri
)
VALUES (
    %(attack_id)s, %(advice_type)s, %(title)s, %(content)s, %(priority_level)s, %(source_uri)s
)
RETURNING
    advice_id, attack_id, advice_type, title, content, priority_level, source_uri, created_at
"""


def build_update_attack_entry_query(set_fields: list[str]) -> str:
    assignments = ", ".join(f"{field} = %({field})s" for field in set_fields)
    return f"""
    UPDATE wp11.attack_entry
    SET {assignments}
    WHERE attack_id = %(attack_id)s
    RETURNING
        attack_id, attack_code, canonical_name, attack_family, severity_level, entry_status, summary, description,
        exploit_preconditions, impact_scope, confidence_score, first_seen_at, last_seen_at,
        primary_stix_bundle_id, primary_stix_object_id, stix_graph_status, stix_type, stix_payload,
        created_at, updated_at
    """

