GET_SOURCE_BY_NAME = """
SELECT source_id, source_name, source_type, base_uri, trust_level, default_qps, enabled, created_at
FROM wp11.intel_source
WHERE source_name = %(source_name)s
"""

GET_SOURCE_BY_ID = """
SELECT source_id, source_name, source_type, base_uri, trust_level, default_qps, enabled, created_at
FROM wp11.intel_source
WHERE source_id = %(source_id)s
"""

LIST_ENABLED_SOURCES_BASE = """
SELECT source_id, source_name, source_type, base_uri, trust_level, default_qps, enabled, created_at
FROM wp11.intel_source
WHERE enabled = TRUE
"""

UPSERT_INTEL_SOURCE = """
INSERT INTO wp11.intel_source (
    source_name, source_type, base_uri, trust_level, default_qps, enabled
)
VALUES (
    %(source_name)s, %(source_type)s, %(base_uri)s, %(trust_level)s, %(default_qps)s, %(enabled)s
)
ON CONFLICT (source_name) DO UPDATE SET
    source_type = EXCLUDED.source_type,
    base_uri = EXCLUDED.base_uri,
    trust_level = EXCLUDED.trust_level,
    default_qps = EXCLUDED.default_qps,
    enabled = EXCLUDED.enabled
RETURNING source_id, source_name, source_type, base_uri, trust_level, default_qps, enabled, created_at
"""

CREATE_COLLECTION_TASK = """
INSERT INTO wp11.collection_task (
    source_id, task_mode, trigger_type, task_status, scheduled_at, created_by, retry_count, trace_id
)
VALUES (
    %(source_id)s, %(task_mode)s, %(trigger_type)s, %(task_status)s, %(scheduled_at)s, %(created_by)s,
    %(retry_count)s, %(trace_id)s
)
RETURNING
    task_id, source_id, task_mode, trigger_type, task_status, scheduled_at, started_at, finished_at,
    created_by, retry_count, trace_id
"""

GET_COLLECTION_TASK_BY_ID = """
SELECT
    task_id, source_id, task_mode, trigger_type, task_status, scheduled_at, started_at, finished_at,
    created_by, retry_count, trace_id
FROM wp11.collection_task
WHERE task_id = %(task_id)s
"""

INSERT_RAW_INTEL_RECORD = """
INSERT INTO wp11.raw_intel_record (
    source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, is_deleted
)
VALUES (
    %(source_id)s, %(task_id)s, %(source_uri)s, %(title)s, %(content_hash)s, %(raw_format)s, %(payload_uri)s,
    %(language_code)s, %(relevance_score)s, %(parser_status)s, %(fetched_at)s, %(is_deleted)s
)
RETURNING
    raw_id, source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, created_at, is_deleted
"""

INSERT_RAW_INTEL_RECORD_IDEMPOTENT = """
INSERT INTO wp11.raw_intel_record (
    source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, is_deleted
)
VALUES (
    %(source_id)s, %(task_id)s, %(source_uri)s, %(title)s, %(content_hash)s, %(raw_format)s, %(payload_uri)s,
    %(language_code)s, %(relevance_score)s, %(parser_status)s, %(fetched_at)s, %(is_deleted)s
)
ON CONFLICT (source_id, content_hash) DO NOTHING
RETURNING
    raw_id, source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, created_at, is_deleted
"""

GET_RAW_BY_SOURCE_HASH = """
SELECT
    raw_id, source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, created_at, is_deleted
FROM wp11.raw_intel_record
WHERE source_id = %(source_id)s AND content_hash = %(content_hash)s
"""

GET_RAW_BY_ID = """
SELECT
    raw_id, source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, created_at, is_deleted
FROM wp11.raw_intel_record
WHERE raw_id = %(raw_id)s
"""

MARK_RAW_PARSER_STATUS = """
UPDATE wp11.raw_intel_record
SET parser_status = %(parser_status)s
WHERE raw_id = %(raw_id)s
RETURNING
    raw_id, source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, created_at, is_deleted
"""

LIST_PENDING_RAW_RECORDS = """
SELECT
    raw_id, source_id, task_id, source_uri, title, content_hash, raw_format, payload_uri, language_code,
    relevance_score, parser_status, fetched_at, created_at, is_deleted
FROM wp11.raw_intel_record
WHERE parser_status = 'pending' AND is_deleted = FALSE
ORDER BY fetched_at DESC
LIMIT %(limit)s
"""


def build_update_collection_task_status_query(
    *, include_started_at: bool, include_finished_at: bool, include_retry_count: bool
) -> str:
    sets = ["task_status = %(task_status)s"]
    if include_started_at:
        sets.append("started_at = %(started_at)s")
    if include_finished_at:
        sets.append("finished_at = %(finished_at)s")
    if include_retry_count:
        sets.append("retry_count = %(retry_count)s")

    return f"""
    UPDATE wp11.collection_task
    SET {", ".join(sets)}
    WHERE task_id = %(task_id)s
    RETURNING
        task_id, source_id, task_mode, trigger_type, task_status, scheduled_at, started_at, finished_at,
        created_by, retry_count, trace_id
    """
