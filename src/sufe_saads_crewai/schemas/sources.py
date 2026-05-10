from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .actions import SearchQueryPlan
from .common import (
    ApprovalStatus,
    EvidenceRef,
    FlexibleModel,
    Score,
    SourceType,
    utcnow,
)


class ApprovedSource(FlexibleModel):
    source_name: str
    base_uri: str
    source_type: SourceType
    trust_level: Score = 0.5
    enabled: bool = True
    notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceProposal(FlexibleModel):
    source_name: str
    base_uri: str
    source_type: SourceType
    expected_coverage_gain: Score = 0.0
    trust_rationale: str = ""
    risk_notes: list[str] = Field(default_factory=list)
    approval_status: ApprovalStatus = "pending"
    proposed_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceExecutionStat(FlexibleModel):
    source_name: str
    query_count: int = Field(default=0, ge=0)
    result_count: int = Field(default=0, ge=0)
    success: bool = True
    latency_ms: float | None = Field(default=None, ge=0.0)
    error_type: str | None = None
    notes: str | None = None


class RawIntelItem(FlexibleModel):
    item_id: str
    source_name: str
    source_uri: str
    title: str = ""
    summary: str = ""
    published_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=utcnow)
    raw_text: str | None = None
    content_ref: str | None = None
    relevance_score: Score = 0.0
    extraction_notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RawIntelItemBatch(FlexibleModel):
    items: list[RawIntelItem] = Field(default_factory=list)
    query_plan: SearchQueryPlan | None = None
    source_stats: list[SourceExecutionStat] = Field(default_factory=list)
    batch_notes: str | None = None


class EvidenceExtraction(FlexibleModel):
    item_id: str
    source_uri: str
    evidence_text: str
    evidence_type: str = "claim"
    confidence: Score = 0.0
    supports_claims: list[str] = Field(default_factory=list)
    uncertainty_notes: str | None = None
    evidence_ref: EvidenceRef | None = None


class EvidenceExtractionBatch(FlexibleModel):
    evidence_items: list[EvidenceExtraction] = Field(default_factory=list)


class QueryHistoryEntry(FlexibleModel):
    query_text: str
    source_names: list[str] = Field(default_factory=list)
    result_count: int = Field(default=0, ge=0)
    novelty_score: Score = 0.0
    noise_ratio: Score = 0.0
    duplicate_ratio: Score = 0.0
    round_index: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
