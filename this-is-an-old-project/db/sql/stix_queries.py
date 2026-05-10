CREATE_STIX_BUNDLE = """
INSERT INTO wp11.stix_bundle (
    attack_id, bundle_stix_id, spec_version, bundle_role, graph_confidence,
    review_status, primary_object_stix_id, bundle_payload
)
VALUES (
    %(attack_id)s, %(bundle_stix_id)s, %(spec_version)s, %(bundle_role)s, %(graph_confidence)s,
    %(review_status)s, %(primary_object_stix_id)s, %(bundle_payload)s
)
RETURNING
    bundle_id, attack_id, bundle_stix_id, spec_version, bundle_role, graph_confidence,
    review_status, primary_object_stix_id, bundle_payload, created_at, updated_at
"""

CREATE_STIX_OBJECT = """
INSERT INTO wp11.stix_object (
    bundle_id, attack_id, stix_id, object_type, spec_version, name, description,
    created_ts, modified_ts, revoked, confidence, lang, is_primary, raw_payload
)
VALUES (
    %(bundle_id)s, %(attack_id)s, %(stix_id)s, %(object_type)s, %(spec_version)s, %(name)s, %(description)s,
    %(created_ts)s, %(modified_ts)s, %(revoked)s, %(confidence)s, %(lang)s, %(is_primary)s, %(raw_payload)s
)
RETURNING
    object_pk, bundle_id, attack_id, stix_id, object_type, spec_version, name, description,
    created_ts, modified_ts, revoked, confidence, lang, is_primary, raw_payload, created_at, updated_at
"""

INSERT_STIX_RELATIONSHIP_PROJECTION = """
INSERT INTO wp11.stix_relationship_projection (
    object_pk, bundle_id, relationship_type, source_ref, target_ref
)
VALUES (
    %(object_pk)s, %(bundle_id)s, %(relationship_type)s, %(source_ref)s, %(target_ref)s
)
RETURNING
    relationship_pk, object_pk, bundle_id, relationship_type, source_ref, target_ref, created_at
"""

INSERT_STIX_EXTERNAL_REFERENCE = """
INSERT INTO wp11.stix_external_reference (
    object_pk, source_name, external_id, url, description
)
VALUES (
    %(object_pk)s, %(source_name)s, %(external_id)s, %(url)s, %(description)s
)
RETURNING ext_ref_id, object_pk, source_name, external_id, url, description
"""

INSERT_STIX_KILL_CHAIN_PHASE = """
INSERT INTO wp11.stix_kill_chain_phase (
    object_pk, kill_chain_name, phase_name
)
VALUES (
    %(object_pk)s, %(kill_chain_name)s, %(phase_name)s
)
RETURNING phase_id, object_pk, kill_chain_name, phase_name
"""

INSERT_STIX_OBJECT_LABEL = """
INSERT INTO wp11.stix_object_label (object_pk, label)
VALUES (%(object_pk)s, %(label)s)
ON CONFLICT (object_pk, label) DO NOTHING
"""

INSERT_STIX_OBJECT_ALIAS = """
INSERT INTO wp11.stix_object_alias (object_pk, alias)
VALUES (%(object_pk)s, %(alias)s)
ON CONFLICT (object_pk, alias) DO NOTHING
"""

UPSERT_ATTACK_STIX_BINDING = """
INSERT INTO wp11.attack_stix_binding (
    attack_id, active_bundle_id, primary_object_pk, publication_status, published_at
)
VALUES (
    %(attack_id)s, %(active_bundle_id)s, %(primary_object_pk)s, %(publication_status)s, %(published_at)s
)
ON CONFLICT (attack_id)
DO UPDATE SET
    active_bundle_id = EXCLUDED.active_bundle_id,
    primary_object_pk = EXCLUDED.primary_object_pk,
    publication_status = EXCLUDED.publication_status,
    published_at = EXCLUDED.published_at
RETURNING
    binding_id, attack_id, active_bundle_id, primary_object_pk, publication_status, published_at,
    created_at, updated_at
"""

INSERT_STIX_REVIEW_QUEUE = """
INSERT INTO wp11.stix_review_queue (
    attack_id, bundle_id, reason_code, queue_status, review_payload
)
VALUES (
    %(attack_id)s, %(bundle_id)s, %(reason_code)s, %(queue_status)s, %(review_payload)s
)
RETURNING
    review_id, attack_id, bundle_id, reason_code, queue_status, review_payload, created_at, resolved_at
"""

INSERT_STIX_EXTRACTION_AUDIT = """
INSERT INTO wp11.stix_extraction_audit (
    attack_id, bundle_id, extractor_model, reviewer_model, prompt_version,
    review_decision, graph_confidence, reasoning_summary, reasoning_trace, finding_count
)
VALUES (
    %(attack_id)s, %(bundle_id)s, %(extractor_model)s, %(reviewer_model)s, %(prompt_version)s,
    %(review_decision)s, %(graph_confidence)s, %(reasoning_summary)s, %(reasoning_trace)s, %(finding_count)s
)
RETURNING
    audit_id, attack_id, bundle_id, extractor_model, reviewer_model, prompt_version,
    review_decision, graph_confidence, reasoning_summary, reasoning_trace, finding_count, created_at
"""

LIST_STIX_BUNDLES_BY_ATTACK = """
SELECT
    bundle_id, attack_id, bundle_stix_id, spec_version, bundle_role, graph_confidence,
    review_status, primary_object_stix_id, bundle_payload, created_at, updated_at
FROM wp11.stix_bundle
WHERE attack_id = %(attack_id)s
ORDER BY created_at DESC
"""
