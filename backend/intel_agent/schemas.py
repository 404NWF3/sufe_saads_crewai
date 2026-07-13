"""Self-contained Pydantic models for the intel_agent package.

A trimmed, standalone descendant of the legacy ``sufe_saads_crewai.schemas``
package: it keeps only what the agentic collection loop needs and drops the
unused future-stage models (STIX, DB persistence, alerts, KG). No imports from
the legacy package.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


Score = Annotated[float, Field(ge=0.0, le=1.0)]
NonNegativeFloat = Annotated[float, Field(ge=0.0)]
NonNegativeInt = Annotated[int, Field(ge=0)]

RunMode = Literal["bootstrap", "incremental", "gap_fill", "deep_research"]
Priority = Literal["low", "medium", "high", "critical"]
SourceType = Literal["security_db", "paper", "advisory", "research", "web"]
EvidenceChannel = Literal["research", "vulnerability_advisory", "exploitation"]
QueryIntent = Literal["gap_fill", "discovery", "entity_expand", "confirmation"]
GapStatus = Literal["open", "satisfied", "exhausted_this_run", "failed", "not_applicable"]

REGISTERED_SOURCE_NAMES = ("nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api")
RegisteredSourceName = Literal["nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api"]


class FlexibleModel(BaseModel):
    """Runtime models: tolerate extra keys so engine annotations never break."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class StrictDecision(BaseModel):
    """Agent decision outputs: reject unknown keys for a stable tool schema."""

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------- sources


class ApprovedSource(FlexibleModel):
    source_name: str
    base_uri: str
    source_type: SourceType
    trust_level: Score = 0.5
    enabled: bool = True
    notes: str | None = None
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
    relevance_score: Score = 0.0
    extraction_notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchQueryPlan(FlexibleModel):
    plan_id: str | None = None
    query_text: str
    source_names: list[str] = Field(default_factory=list)
    target_topics: list[str] = Field(default_factory=list)
    query_intent: str = "broad_recall"
    time_window_days: int | None = Field(default=None, ge=1)
    max_results: int = Field(default=10, ge=1)
    priority: Priority = "medium"
    rationale: str = ""
    round_index: int = Field(default=0, ge=0)


class RawIntelItemBatch(FlexibleModel):
    items: list[RawIntelItem] = Field(default_factory=list)
    query_plan: SearchQueryPlan | None = None
    source_stats: list[SourceExecutionStat] = Field(default_factory=list)
    batch_notes: str | None = None


class QueryHistoryEntry(FlexibleModel):
    query_text: str
    source_names: list[str] = Field(default_factory=list)
    result_count: int = Field(default=0, ge=0)
    novelty_score: Score = 0.0
    noise_ratio: Score = 0.0
    duplicate_ratio: Score = 0.0
    round_index: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------- coverage


class CoverageGap(FlexibleModel):
    gap_id: str
    dimension: str = "topic"
    taxonomy_or_component: str
    current_coverage: Score = 0.0
    target_coverage: Score = 1.0
    estimated_gap_fill_roi: Score = 0.0
    recommended_sources: list[str] = Field(default_factory=list)
    priority: Priority = "medium"
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorpusGap(FlexibleModel):
    """A persistent Core-topic evidence deficit in one evidence channel."""

    gap_id: str
    topic: str
    evidence_channel: EvidenceChannel
    effective_evidence: NonNegativeFloat = 0.0
    target_evidence: NonNegativeFloat = 0.0
    coverage_gap: Score = 0.0
    channel_diversity_gap: Score = 0.0
    freshness_gap: Score = 0.0
    priority_score: Score = 0.0
    status: GapStatus = "open"
    recommended_sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunGap(FlexibleModel):
    """An unfinished search obligation inside one incremental run."""

    gap_id: str
    gap_type: Literal[
        "source_window", "pagination", "retry", "discovery", "entity_confirmation"
    ]
    status: GapStatus = "open"
    source_name: str | None = None
    topic: str | None = None
    evidence_channel: EvidenceChannel | None = None
    priority: Priority = "medium"
    attempts: NonNegativeInt = 0
    expected_utility: float = 0.0
    retryable: bool = False
    rationale: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class QueryCandidate(StrictDecision):
    """One source-specific query proposed by the SDK collection agent."""

    candidate_id: str
    source_name: RegisteredSourceName
    query_text: str
    params: dict[str, Any] = Field(default_factory=dict)
    query_intent: QueryIntent = "gap_fill"
    evidence_channel: EvidenceChannel
    target_topics: list[str] = Field(default_factory=list)
    target_gap_ids: list[str] = Field(default_factory=list)
    rationale: str = ""


class QueryCallOutcome(FlexibleModel):
    """Per-call telemetry retained before and after filtering/classification."""

    call_id: str
    candidate_id: str | None = None
    source_name: RegisteredSourceName
    query_text: str
    params: dict[str, Any] = Field(default_factory=dict)
    query_intent: QueryIntent = "gap_fill"
    evidence_channel: EvidenceChannel
    target_topics: list[str] = Field(default_factory=list)
    target_gap_ids: list[str] = Field(default_factory=list)
    operator_signature: str = ""
    raw_count: NonNegativeInt = 0
    in_scope_count: NonNegativeInt = 0
    duplicate_count: NonNegativeInt = 0
    new_count: NonNegativeInt = 0
    relevant_new: NonNegativeInt = 0
    noise_count: NonNegativeInt = 0
    uncertain_count: NonNegativeInt = 0
    latency_ms: NonNegativeFloat | None = None
    success: bool = True
    error_type: str | None = None
    has_more: bool = False
    filled_gap_ids: list[str] = Field(default_factory=list)
    gap_priority_before: NonNegativeFloat = 0.0
    gap_priority_after: NonNegativeFloat = 0.0
    reward: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceCheckpoint(FlexibleModel):
    source_name: RegisteredSourceName
    watermark: datetime | None = None
    overlap_hours: NonNegativeInt = 72
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    complete: bool = False
    cursor: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CandidateTopic(FlexibleModel):
    candidate_id: str
    proposed_name: str
    status: Literal["proposed", "confirmed", "rejected"] = "proposed"
    supporting_item_ids: list[str] = Field(default_factory=list)
    source_names: list[str] = Field(default_factory=list)
    mean_relevance: Score = 0.0
    max_anchor_similarity: Score = 0.0
    emergence_score: Score = 0.0
    rationale: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchReflectionDecision(FlexibleModel):
    rewritten_queries: list[SearchQueryPlan] = Field(default_factory=list)
    topics_to_expand: list[str] = Field(default_factory=list)
    topics_to_stop: list[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: Score = 0.0


class SearchCompletenessAssessment(FlexibleModel):
    completeness_score: Score = 0.0
    should_continue: bool = True
    missing_dimensions: list[str] = Field(default_factory=list)
    recommended_next_mode: RunMode | None = None
    stop_rationale: str | None = None


# --------------------------------------------------------------------- runtime


class ActionDecision(FlexibleModel):
    action_type: str
    priority: Priority = "medium"
    rationale: str
    expected_gain: str | None = None
    required_context: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ErrorRecord(FlexibleModel):
    error_type: str
    message: str
    retryable: bool = False
    occurred_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunBudget(FlexibleModel):
    max_rounds: NonNegativeInt | None = 10
    max_seconds: NonNegativeFloat | None = None
    max_api_calls: NonNegativeInt | None = None
    max_sources: NonNegativeInt | None = None


class RunMetrics(FlexibleModel):
    round_index: NonNegativeInt = 0
    elapsed_seconds: NonNegativeFloat = 0.0
    api_calls_used: NonNegativeInt = 0
    sources_used: NonNegativeInt = 0


class IntelRunBlackboard(FlexibleModel):
    run_id: str
    run_goal: str
    run_mode: RunMode = "bootstrap"
    budget: RunBudget = Field(default_factory=RunBudget)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    approved_sources: list[ApprovedSource] = Field(default_factory=list)
    query_history: list[QueryHistoryEntry] = Field(default_factory=list)
    raw_items: list[RawIntelItem] = Field(default_factory=list)
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    corpus_gaps: list[CorpusGap] = Field(default_factory=list)
    run_gaps: list[RunGap] = Field(default_factory=list)
    query_outcomes: list[QueryCallOutcome] = Field(default_factory=list)
    source_checkpoints: list[SourceCheckpoint] = Field(default_factory=list)
    candidate_topics: list[CandidateTopic] = Field(default_factory=list)
    extended_trends: dict[str, dict[str, float]] = Field(default_factory=dict)
    sdk_session_id: str | None = None
    stop_reason: str | None = None
    collection_strategy: Literal["adaptive", "legacy"] = "legacy"
    reflection_notes: list[SearchReflectionDecision] = Field(default_factory=list)
    action_history: list[ActionDecision] = Field(default_factory=list)
    errors: list[ErrorRecord] = Field(default_factory=list)


# ------------------------------------------------------- agent decision outputs


class TerminationDecision(StrictDecision):
    """Critic verdict on whether to run another collection round."""

    should_continue: bool
    completeness_score: Score = 0.0
    missing_topics: list[str] = Field(default_factory=list)
    stop_reason: str = ""
    rationale: str = ""


class CandidateTopicNamingDecision(StrictDecision):
    """LLM label for an already deterministically gated residual cluster."""

    proposed_name: str
    rationale: str = ""
