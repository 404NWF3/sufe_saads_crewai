INSERT_DEDUP_AUDIT = """
INSERT INTO wp11.dedup_audit (
    candidate_raw_id, matched_attack_id, similarity_score, rule_name, decision, reviewer_name
)
VALUES (
    %(candidate_raw_id)s, %(matched_attack_id)s, %(similarity_score)s, %(rule_name)s, %(decision)s, %(reviewer_name)s
)
RETURNING
    audit_id, candidate_raw_id, matched_attack_id, similarity_score, rule_name, decision, reviewer_name, created_at
"""

LIST_DEDUP_REVIEW_ITEMS = """
SELECT
    audit_id, candidate_raw_id, matched_attack_id, similarity_score, rule_name, decision, reviewer_name, created_at
FROM wp11.dedup_audit
WHERE decision = 'review'
ORDER BY created_at DESC
LIMIT %(limit)s
"""

ENQUEUE_BOM_RESOLUTION = """
INSERT INTO wp11.bom_resolution_queue (
    attack_id, raw_id, mention_id, mentioned_name, mentioned_vendor, mentioned_version,
    reason_code, queue_status, candidate_snapshot, reasoning_summary
)
VALUES (
    %(attack_id)s, %(raw_id)s, %(mention_id)s, %(mentioned_name)s, %(mentioned_vendor)s, %(mentioned_version)s,
    %(reason_code)s, 'open', %(candidate_snapshot)s, %(reasoning_summary)s
)
RETURNING
    queue_id, attack_id, raw_id, mention_id, mentioned_name, mentioned_vendor, mentioned_version, reason_code,
    queue_status, resolved_component_id, candidate_snapshot, reasoning_summary, created_at, resolved_at
"""

LIST_OPEN_BOM_QUEUE = """
SELECT
    queue_id, attack_id, raw_id, mention_id, mentioned_name, mentioned_vendor, mentioned_version, reason_code,
    queue_status, resolved_component_id, candidate_snapshot, reasoning_summary, created_at, resolved_at
FROM wp11.bom_resolution_queue
WHERE queue_status = 'open'
ORDER BY created_at DESC
LIMIT %(limit)s
"""

RESOLVE_BOM_QUEUE_ITEM = """
UPDATE wp11.bom_resolution_queue
SET queue_status = 'resolved', resolved_component_id = %(resolved_component_id)s, resolved_at = now()
WHERE queue_id = %(queue_id)s
RETURNING
    queue_id, attack_id, raw_id, mention_id, mentioned_name, mentioned_vendor, mentioned_version, reason_code,
    queue_status, resolved_component_id, candidate_snapshot, reasoning_summary, created_at, resolved_at
"""

REJECT_BOM_QUEUE_ITEM = """
UPDATE wp11.bom_resolution_queue
SET queue_status = 'rejected', resolved_at = NULL, resolved_component_id = NULL
WHERE queue_id = %(queue_id)s
RETURNING
    queue_id, attack_id, raw_id, mention_id, mentioned_name, mentioned_vendor, mentioned_version, reason_code,
    queue_status, resolved_component_id, candidate_snapshot, reasoning_summary, created_at, resolved_at
"""

INSERT_BOM_RESOLUTION_AUDIT = """
INSERT INTO wp11.bom_resolution_audit (
    mention_id, attack_id, raw_id, strategy_requested, strategy_executed, llm_model,
    prompt_version, llm_decision, llm_confidence, selected_component_code, reasoning_summary, reasoning_trace,
    candidate_count, evidence_quotes
)
VALUES (
    %(mention_id)s, %(attack_id)s, %(raw_id)s, %(strategy_requested)s, %(strategy_executed)s, %(llm_model)s,
    %(prompt_version)s, %(llm_decision)s, %(llm_confidence)s, %(selected_component_code)s, %(reasoning_summary)s, %(reasoning_trace)s,
    %(candidate_count)s, %(evidence_quotes)s
)
RETURNING
    audit_id, mention_id, attack_id, raw_id, strategy_requested, strategy_executed, llm_model,
    prompt_version, llm_decision, llm_confidence, selected_component_code, reasoning_summary, reasoning_trace,
    candidate_count, evidence_quotes, created_at
"""

INSERT_QUERY_FEEDBACK_BATCH = """
INSERT INTO wp11.query_feedback_log (
    run_id, query_run_id, source_name, query_text, query_intent,
    rewrite_round, result_count, parsed_count, duplicate_count,
    novelty_yield, noise_ratio, source_mismatch,
    reflection_diagnosis, reflection_action, should_retry,
    expected_gain_dim, llm_confidence
)
VALUES (
    %(run_id)s, %(query_run_id)s, %(source_name)s, %(query_text)s, %(query_intent)s,
    %(rewrite_round)s, %(result_count)s, %(parsed_count)s, %(duplicate_count)s,
    %(novelty_yield)s, %(noise_ratio)s, %(source_mismatch)s,
    %(reflection_diagnosis)s, %(reflection_action)s, %(should_retry)s,
    %(expected_gain_dim)s, %(llm_confidence)s
)
RETURNING
    feedback_id, run_id, query_run_id, source_name, query_text, query_intent,
    rewrite_round, result_count, parsed_count, duplicate_count,
    novelty_yield, noise_ratio, source_mismatch,
    reflection_diagnosis, reflection_action, should_retry,
    expected_gain_dim, llm_confidence, created_at
"""

LOAD_RECENT_QUERY_FEEDBACK = """
SELECT
    feedback_id, run_id, query_run_id, source_name, query_text, query_intent,
    rewrite_round, result_count, parsed_count, duplicate_count,
    novelty_yield, noise_ratio, source_mismatch,
    reflection_diagnosis, reflection_action, should_retry,
    expected_gain_dim, llm_confidence, created_at
FROM wp11.query_feedback_log
ORDER BY created_at DESC
LIMIT %(limit)s
"""

