from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class QueryTelemetryDTO(_StrictModel):
    query_run_id: str
    source_name: str = Field(min_length=1)
    source_type: str | None = None
    query_text: str = Field(min_length=1)
    query_intent: str = Field(min_length=1)
    query_provenance: str | None = None
    rewrite_round: int = Field(ge=0)
    rewrite_reason: str | None = None
    result_count: int = Field(ge=0)
    parsed_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    new_candidate_count: int = Field(ge=0)
    novelty_yield: float = Field(ge=0.0, le=1.0)
    noise_ratio: float = Field(ge=0.0, le=1.0)
    source_mismatch: bool = False
    time_window_days: int | None = Field(default=None, ge=1)
    llm_reflection_hint: str | None = None


class CollectionYieldSummaryDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    total_queries: int = Field(ge=0)
    total_results: int = Field(ge=0)
    total_parsed: int = Field(ge=0)
    low_yield: bool = False
    high_noise: bool = False
    reflection_recommended: bool = False
    recommended_actions: list[str] = Field(default_factory=list)
    reflection_evidence_summary: str | None = None


class SearchRewriteQueryDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    query_text: str = Field(min_length=3)
    query_intent: Literal[
        "broad_recall",
        "precision_probe",
        "weak_signal_probe",
        "evidence_corroboration",
        "source_specific_rewrite",
        "component_anchor",
        "taxonomy_anchor",
    ]
    rewrite_reason: str = Field(min_length=1)
    rewrite_action: Literal[
        "broader",
        "narrower",
        "source_specific",
        "corroboration",
        "component_anchored",
        "taxonomy_anchored",
    ]
    expected_gain_dimension: Literal["recall", "precision", "novelty", "balanced"]
    parent_query_run_id: str | None = None
    parent_query_text: str | None = None
    template_name: str | None = None


class SearchReflectionDecisionDTO(_StrictModel):
    should_retry: bool = False
    stop_reason: str = Field(min_length=1)
    diagnosis: Literal[
        "low_recall",
        "high_noise",
        "source_mismatch",
        "saturated",
        "uncertain",
    ] = "uncertain"
    recommended_actions: list[str] = Field(default_factory=list)
    rewritten_queries: list[SearchRewriteQueryDTO] = Field(default_factory=list)
    expected_gain_dimension: Literal["recall", "precision", "novelty", "balanced"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_summary: str = Field(min_length=1)
    fallback_reason: str | None = None


class LlmSearchReflectionAuditDTO(_StrictModel):
    reflection_round: int = Field(ge=0)
    strategy_requested: str = Field(min_length=1)
    strategy_executed: str = Field(min_length=1)
    llm_model: str = Field(min_length=1)
    llm_profile_id: str | None = None
    llm_profile: str | None = None
    prompt_version: str = Field(min_length=1)
    should_retry: bool = False
    stop_reason: str = Field(min_length=1)
    diagnosis: str = Field(min_length=1)
    expected_gain_dimension: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    rewritten_query_count: int = Field(ge=0)
    rewritten_sources: list[str] = Field(default_factory=list)
    evidence_summary: str = Field(min_length=1)
    fallback_reason: str | None = None
    llm_wait_seconds: float | None = Field(default=None, ge=0.0)
    attempted_profiles: list[str] = Field(default_factory=list)
    attempted_profile_labels: list[str] = Field(default_factory=list)
    invoked_at: str = Field(min_length=1)


class QueryFeedbackRowDTO(_StrictModel):
    query_run_id: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    query_text: str = Field(min_length=1)
    query_intent: str = Field(min_length=1)
    rewrite_round: int = Field(ge=0)
    result_count: int = Field(ge=0)
    parsed_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    novelty_yield: float = Field(ge=0.0, le=1.0)
    noise_ratio: float = Field(ge=0.0, le=1.0)
    source_mismatch: bool = False
    reflection_diagnosis: str | None = None
    reflection_action: str | None = None
    should_retry: bool = False
    expected_gain_dimension: str | None = None
    llm_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class LlmPlanningAuditDTO(_StrictModel):
    strategy_requested: str = Field(min_length=1)
    strategy_executed: str = Field(min_length=1)
    llm_model: str = Field(min_length=1)
    llm_profile_id: str | None = None
    llm_profile: str | None = None
    prompt_version: str = Field(min_length=1)
    plan_rationale: str = Field(min_length=1)
    source_plan_count: int = Field(ge=0)
    target_taxonomy_count: int = Field(ge=0)
    max_parallel_sources: int = Field(ge=1)
    max_reflection_rounds: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    feedback_rows_used: int = Field(ge=0)
    fallback_reason: str | None = None
    llm_wait_seconds: float | None = Field(default=None, ge=0.0)
    attempted_profiles: list[str] = Field(default_factory=list)
    attempted_profile_labels: list[str] = Field(default_factory=list)
    invoked_at: str = Field(min_length=1)


class NodeResultDTO(_StrictModel):
    node_name: str = Field(min_length=1)
    status: str = Field(pattern="^(succeeded|failed)$")
    attempts: int = Field(ge=1)
    started_at: str
    finished_at: str
    summary: str = Field(min_length=1)
    reason: str | None = None
    retryable: bool = False
    subject_id: str | None = None
    artifact_ref: str | None = None
