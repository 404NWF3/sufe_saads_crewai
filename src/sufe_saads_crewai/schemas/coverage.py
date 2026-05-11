from __future__ import annotations

from typing import Any

from pydantic import Field

from .actions import SearchQueryPlan
from .common import FlexibleModel, Priority, RunMode, Score


class SourceYieldMetric(FlexibleModel):
    source_name: str
    result_count: int = Field(default=0, ge=0)
    novelty_score: Score = 0.0
    noise_ratio: Score = 0.0
    duplicate_ratio: Score = 0.0
    evidence_quality: Score = 0.0
    notes: str | None = None


class CollectionYieldAssessment(FlexibleModel):
    per_source_metrics: list[SourceYieldMetric] = Field(default_factory=list)
    low_yield_sources: list[str] = Field(default_factory=list)
    high_noise_queries: list[str] = Field(default_factory=list)
    useful_queries: list[str] = Field(default_factory=list)
    novelty_summary: str = ""
    recommended_adjustments: list[str] = Field(default_factory=list)


class SearchReflectionDecision(FlexibleModel):
    rewritten_queries: list[SearchQueryPlan] = Field(default_factory=list)
    source_priority_changes: dict[str, Any] = Field(default_factory=dict)
    topics_to_expand: list[str] = Field(default_factory=list)
    topics_to_stop: list[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: Score = 0.0


class CoverageGap(FlexibleModel):
    gap_id: str
    dimension: str
    taxonomy_or_component: str
    current_coverage: Score = 0.0
    target_coverage: Score = 1.0
    estimated_gap_fill_roi: Score = 0.0
    recommended_queries: list[SearchQueryPlan] = Field(default_factory=list)
    recommended_sources: list[str] = Field(default_factory=list)
    priority: Priority = "medium"
    metadata: dict[str, Any] = Field(default_factory=dict)


class CoverageGapAnalysis(FlexibleModel):
    gaps: list[CoverageGap] = Field(default_factory=list)
    overall_coverage_score: Score = 0.0
    analysis_rationale: str = ""


class SearchCompletenessAssessment(FlexibleModel):
    completeness_score: Score = 0.0
    should_continue: bool = True
    missing_dimensions: list[str] = Field(default_factory=list)
    diminishing_returns_evidence: list[str] = Field(default_factory=list)
    recommended_next_mode: RunMode | None = None
    recommended_next_query: str | None = None
    stop_rationale: str | None = None
