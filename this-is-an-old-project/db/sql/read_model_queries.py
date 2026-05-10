GET_PRIMARY_CVSS = """
SELECT
    score_id, attack_id, cvss_version, vector_string, base_score, temporal_score, environmental_score,
    severity_label, exploitability_subscore, impact_subscore, score_origin, score_provider, confidence_score,
    published_at, calculated_at, created_at
FROM wp11.v_primary_cvss_score
WHERE attack_id = %(attack_id)s
"""

LIST_WP12_ATTACK_FEED_BASE = """
SELECT
    attack_id, attack_code, canonical_name, attack_family, severity_level, entry_status, summary, last_seen_at,
    primary_cvss_version, primary_cvss_base_score, primary_cvss_vector, primary_cvss_severity_label,
    taxonomy_type, taxonomy_code, taxonomy_name, component_id, component_name, version_constraint_raw,
    normalized_constraint, component_impact_scope, asset_id, asset_type, asset_name, artifact_uri, qa_status
FROM wp11.v_wp12_attack_feed
WHERE 1 = 1
"""

LIST_WP12_ATTACK_EXECUTION_FEED_BASE = """
SELECT
    attack_id, attack_code, canonical_name, attack_family, severity_level, summary,
    component_id, component_name, normalized_constraint, component_impact_scope,
    primary_stix_bundle_id, primary_stix_object_id, stix_graph_status,
    primary_attack_pattern_stix_id, stix_bundle_payload
FROM wp11.v_wp12_attack_execution_feed
WHERE 1 = 1
"""

LIST_COMPONENT_RISK_OVERVIEW_BASE = """
SELECT
    component_id, component_code, component_name, vendor_name, component_type, attack_count,
    high_cvss_attack_count, critical_cvss_attack_count, latest_seen_at, max_primary_cvss_score, avg_primary_cvss_score
FROM wp11.v_component_risk_overview
WHERE 1 = 1
"""

LIST_UNRESOLVED_BOM_QUEUE = """
SELECT
    queue_id, attack_id, attack_code, canonical_name, raw_id, source_uri, mentioned_name,
    mentioned_vendor, mentioned_version, reason_code, queue_status, created_at, resolved_at
FROM wp11.v_unresolved_bom_queue
ORDER BY created_at DESC
LIMIT %(limit)s
"""

LIST_SOURCE_QUALITY_DASHBOARD_BASE = """
SELECT
    source_id, source_name, source_type, raw_record_count, parsed_record_count, effective_attack_count,
    dedup_merge_count, avg_relevance_score, latest_fetched_at, failed_task_count
FROM wp11.v_source_quality_dashboard
WHERE 1 = 1
"""

LIST_OWASP_COVERAGE = """
SELECT
    taxonomy_code, taxonomy_name, attack_count, impacted_component_count, high_cvss_attack_count,
    critical_cvss_attack_count, max_primary_cvss_score, avg_primary_cvss_score, latest_seen_at
FROM wp11.mv_owasp_coverage
ORDER BY taxonomy_code ASC
LIMIT %(limit)s
"""

REFRESH_MV_OWASP_COVERAGE = "REFRESH MATERIALIZED VIEW wp11.mv_owasp_coverage"
REFRESH_MV_OWASP_COVERAGE_CONCURRENTLY = (
    "REFRESH MATERIALIZED VIEW CONCURRENTLY wp11.mv_owasp_coverage"
)

