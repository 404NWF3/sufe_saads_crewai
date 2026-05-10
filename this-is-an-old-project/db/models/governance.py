from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID


@dataclass(slots=True)
class QueryFeedbackLog:
    feedback_id: int
    run_id: str
    query_run_id: str
    source_name: str
    query_text: str
    query_intent: str
    rewrite_round: int
    result_count: int
    parsed_count: int
    duplicate_count: int
    novelty_yield: Decimal
    noise_ratio: Decimal
    source_mismatch: bool
    reflection_diagnosis: str | None
    reflection_action: str | None
    should_retry: bool
    expected_gain_dim: str | None
    llm_confidence: Decimal | None
    created_at: datetime


@dataclass(slots=True)
class DedupAudit:
    audit_id: int
    candidate_raw_id: UUID
    matched_attack_id: UUID | None
    similarity_score: Decimal
    rule_name: str
    decision: str
    reviewer_name: str | None
    created_at: datetime


@dataclass(slots=True)
class BomResolutionQueueItem:
    queue_id: int
    attack_id: UUID | None
    raw_id: UUID | None
    mention_id: UUID | None
    mentioned_name: str
    mentioned_vendor: str | None
    mentioned_version: str | None
    reason_code: str
    queue_status: str
    resolved_component_id: UUID | None
    candidate_snapshot: dict | None
    reasoning_summary: str | None
    created_at: datetime
    resolved_at: datetime | None


@dataclass(slots=True)
class BomResolutionAudit:
    audit_id: int
    mention_id: UUID | None
    attack_id: UUID | None
    raw_id: UUID | None
    strategy_requested: str
    strategy_executed: str
    llm_model: str
    prompt_version: str
    llm_decision: str
    llm_confidence: Decimal
    selected_component_code: str | None
    reasoning_summary: str
    reasoning_trace: list[str] | None
    candidate_count: int
    evidence_quotes: list[str] | None
    created_at: datetime

