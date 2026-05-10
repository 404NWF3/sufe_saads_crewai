GET_COMPONENT_BY_CODE = """
SELECT
    component_id, component_code, component_name, component_layer, vendor_name, component_type, modality,
    purl, homepage_uri, lifecycle_status, created_at
FROM wp11.ai_component
WHERE component_code = %(component_code)s
"""

GET_COMPONENT_BY_NAME = """
SELECT
    component_id, component_code, component_name, component_layer, vendor_name, component_type, modality,
    purl, homepage_uri, lifecycle_status, created_at
FROM wp11.ai_component
WHERE lower(component_name) = lower(%(component_name)s)
"""

CREATE_COMPONENT = """
INSERT INTO wp11.ai_component (
    component_code, component_name, component_layer, vendor_name, component_type, modality, purl, homepage_uri, lifecycle_status
)
VALUES (
    %(component_code)s, %(component_name)s, %(component_layer)s, %(vendor_name)s, %(component_type)s, %(modality)s,
    %(purl)s, %(homepage_uri)s, %(lifecycle_status)s
)
RETURNING
    component_id, component_code, component_name, component_layer, vendor_name, component_type, modality,
    purl, homepage_uri, lifecycle_status, created_at
"""

UPSERT_COMPONENT = """
INSERT INTO wp11.ai_component (
    component_code, component_name, component_layer, vendor_name, component_type, modality, purl, homepage_uri, lifecycle_status
)
VALUES (
    %(component_code)s, %(component_name)s, %(component_layer)s, %(vendor_name)s, %(component_type)s, %(modality)s,
    %(purl)s, %(homepage_uri)s, %(lifecycle_status)s
)
ON CONFLICT (component_code)
DO UPDATE SET
    component_name = EXCLUDED.component_name,
    component_layer = EXCLUDED.component_layer,
    vendor_name = EXCLUDED.vendor_name,
    component_type = EXCLUDED.component_type,
    modality = EXCLUDED.modality,
    purl = EXCLUDED.purl,
    homepage_uri = EXCLUDED.homepage_uri,
    lifecycle_status = EXCLUDED.lifecycle_status
RETURNING
    component_id, component_code, component_name, component_layer, vendor_name, component_type, modality,
    purl, homepage_uri, lifecycle_status, created_at
"""

INSERT_COMPONENT_ALIAS = """
INSERT INTO wp11.ai_component_alias (
    component_id, alias_name, alias_type, normalized_alias, is_preferred
)
VALUES (
    %(component_id)s, %(alias_name)s, %(alias_type)s, %(normalized_alias)s, %(is_preferred)s
)
RETURNING alias_id, component_id, alias_name, alias_type, normalized_alias, is_preferred
"""

UPSERT_COMPONENT_ALIAS = """
INSERT INTO wp11.ai_component_alias (
    component_id, alias_name, alias_type, normalized_alias, is_preferred
)
VALUES (
    %(component_id)s, %(alias_name)s, %(alias_type)s, %(normalized_alias)s, %(is_preferred)s
)
ON CONFLICT (component_id, normalized_alias)
DO UPDATE SET
    alias_name = EXCLUDED.alias_name,
    alias_type = EXCLUDED.alias_type,
    is_preferred = EXCLUDED.is_preferred
RETURNING alias_id, component_id, alias_name, alias_type, normalized_alias, is_preferred
"""

LIST_COMPONENT_ALIASES = """
SELECT alias_id, component_id, alias_name, alias_type, normalized_alias, is_preferred
FROM wp11.ai_component_alias
WHERE component_id = %(component_id)s
ORDER BY is_preferred DESC, alias_id ASC
"""

GET_COMPONENT_BY_NORMALIZED_ALIAS = """
SELECT
    ac.component_id, ac.component_code, ac.component_name, ac.component_layer, ac.vendor_name, ac.component_type, ac.modality,
    ac.purl, ac.homepage_uri, ac.lifecycle_status, ac.created_at
FROM wp11.ai_component_alias a
JOIN wp11.ai_component ac ON ac.component_id = a.component_id
WHERE a.normalized_alias = %(normalized_alias)s
ORDER BY a.is_preferred DESC, ac.component_name ASC
"""

LIST_COMPONENTS_BY_NORMALIZED_ALIAS = GET_COMPONENT_BY_NORMALIZED_ALIAS

SEARCH_COMPONENT_ALIAS = """
SELECT
    a.alias_id,
    a.component_id,
    ac.component_code,
    ac.component_name,
    ac.component_layer,
    ac.vendor_name,
    ac.component_type,
    ac.modality,
    ac.purl,
    ac.homepage_uri,
    a.alias_name,
    a.alias_type,
    a.normalized_alias,
    a.is_preferred,
    similarity(a.normalized_alias, %(normalized_alias)s) AS similarity
FROM wp11.ai_component_alias a
JOIN wp11.ai_component ac ON ac.component_id = a.component_id
WHERE a.normalized_alias %% %(normalized_alias)s
ORDER BY similarity DESC, a.is_preferred DESC
LIMIT %(limit)s
"""

UPSERT_ATTACK_COMPONENT_IMPACT = """
INSERT INTO wp11.attack_component_impact (
    attack_id, component_id, mention_id, source_raw_id, version_constraint_raw,
    normalized_constraint, match_mode, impact_scope, review_status, resolver_strategy,
    confidence_score, evidence_uri, evidence_snippet
)
VALUES (
    %(attack_id)s, %(component_id)s, %(mention_id)s, %(source_raw_id)s,
    %(version_constraint_raw)s, %(normalized_constraint)s, %(match_mode)s,
    %(impact_scope)s, %(review_status)s, %(resolver_strategy)s, %(confidence_score)s,
    %(evidence_uri)s, %(evidence_snippet)s
)
ON CONFLICT (
    attack_id, component_id, COALESCE(normalized_constraint, ''), impact_scope
)
DO UPDATE SET
    mention_id = EXCLUDED.mention_id,
    source_raw_id = EXCLUDED.source_raw_id,
    match_mode = EXCLUDED.match_mode,
    review_status = EXCLUDED.review_status,
    resolver_strategy = EXCLUDED.resolver_strategy,
    confidence_score = EXCLUDED.confidence_score,
    evidence_uri = EXCLUDED.evidence_uri,
    evidence_snippet = EXCLUDED.evidence_snippet,
    version_constraint_raw = EXCLUDED.version_constraint_raw
RETURNING
    impact_id, attack_id, component_id, mention_id, source_raw_id, version_constraint_raw,
    normalized_constraint, match_mode, impact_scope, review_status, resolver_strategy,
    confidence_score, evidence_uri, evidence_snippet, created_at
"""

LIST_COMPONENT_IMPACTS_BY_ATTACK = """
SELECT
    impact_id, attack_id, component_id, mention_id, source_raw_id, version_constraint_raw,
    normalized_constraint, match_mode, impact_scope, review_status, resolver_strategy,
    confidence_score, evidence_uri, evidence_snippet, created_at
FROM wp11.attack_component_impact
WHERE attack_id = %(attack_id)s
ORDER BY confidence_score DESC, created_at DESC
"""

LIST_ATTACKS_BY_COMPONENT = """
SELECT
    impact_id, attack_id, component_id, mention_id, source_raw_id, version_constraint_raw,
    normalized_constraint, match_mode, impact_scope, review_status, resolver_strategy,
    confidence_score, evidence_uri, evidence_snippet, created_at
FROM wp11.attack_component_impact
WHERE component_id = %(component_id)s
ORDER BY confidence_score DESC, created_at DESC
"""

INSERT_ATTACK_COMPONENT_MENTION = """
INSERT INTO wp11.attack_component_mention (
    attack_id, raw_id, mentioned_name, mentioned_vendor, mentioned_version, normalized_alias,
    normalized_vendor, component_layer, impact_scope, dependency_role, evidence_snippet,
    extractor_name, extraction_confidence
)
VALUES (
    %(attack_id)s, %(raw_id)s, %(mentioned_name)s, %(mentioned_vendor)s, %(mentioned_version)s,
    %(normalized_alias)s, %(normalized_vendor)s, %(component_layer)s, %(impact_scope)s,
    %(dependency_role)s, %(evidence_snippet)s, %(extractor_name)s, %(extraction_confidence)s
)
RETURNING
    mention_id, attack_id, raw_id, mentioned_name, mentioned_vendor, mentioned_version, normalized_alias,
    normalized_vendor, component_layer, impact_scope, dependency_role, evidence_snippet,
    extractor_name, extraction_confidence, created_at
"""

LIST_COMPONENT_MENTIONS_BY_ATTACK = """
SELECT
    mention_id, attack_id, raw_id, mentioned_name, mentioned_vendor, mentioned_version, normalized_alias,
    normalized_vendor, component_layer, impact_scope, dependency_role, evidence_snippet,
    extractor_name, extraction_confidence, created_at
FROM wp11.attack_component_mention
WHERE attack_id = %(attack_id)s
ORDER BY created_at DESC
"""
