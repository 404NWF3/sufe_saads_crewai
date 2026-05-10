from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


ActionName = Literal[
    "PLAN_COLLECTION",
    "SEARCH_REGISTERED_SOURCE",
    "ASSESS_COLLECTION_YIELD",
    "ANALYZE_COVERAGE_GAPS",
    "REFLECT_SEARCH_STRATEGY",
    "PROPOSE_NEW_SOURCE",
    "STOP",
]
PriorityName = Literal["low", "medium", "high", "critical"]
CostLevel = Literal["low", "medium", "high"]
SourceKind = Literal[
    "structured",
    "code",
    "paper",
    "community",
    "advisory",
    "vendor",
    "web",
    "security_db",
    "research",
]


class StrictCrewOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NextAction(StrictCrewOutput):
    action_type: ActionName
    priority: PriorityName
    rationale: str
    expected_gain: str
    required_context: list[str]
    success_criteria: list[str]
    retry_conditions: list[str]
    stop_conditions: list[str]
    estimated_cost_level: CostLevel


class PlannerDecisionOutput(StrictCrewOutput):
    actions: list[NextAction]
    planner_rationale: str
    should_start_collection: bool


class CollectedItem(StrictCrewOutput):
    source_name: str
    source_uri: str
    title: str
    summary: str
    relevance_score: float
    topics: list[str]
    evidence_snippet: str


class CollectionBatchOutput(StrictCrewOutput):
    query_text: str
    source_names: list[str]
    items: list[CollectedItem]
    batch_notes: str


class ProposedSource(StrictCrewOutput):
    source_name: str
    base_uri: str
    source_type: SourceKind
    coverage_topics: list[str]
    expected_coverage_gain: float
    trust_rationale: str
    risk_notes: list[str]
    approval_status: Literal["pending"]


class SourceProposalBatchOutput(StrictCrewOutput):
    proposals: list[ProposedSource]
    rationale: str


class YieldMetric(StrictCrewOutput):
    source_name: str
    result_count: int
    novelty_score: float
    noise_ratio: float
    evidence_quality: float


class YieldAssessmentOutput(StrictCrewOutput):
    metrics: list[YieldMetric]
    low_yield_sources: list[str]
    high_noise_queries: list[str]
    useful_queries: list[str]
    novelty_summary: str
    recommended_adjustments: list[str]


class CoverageGapOutput(StrictCrewOutput):
    topic: str
    current_coverage: float
    target_coverage: float
    estimated_roi: float
    recommended_query: str
    priority: PriorityName


class CoverageAnalysisOutput(StrictCrewOutput):
    gaps: list[CoverageGapOutput]
    overall_coverage_score: float
    analysis_rationale: str


class RewriteDecisionOutput(StrictCrewOutput):
    should_rewrite: bool
    rewritten_query: str | None
    target_topics: list[str]
    topics_to_stop: list[str]
    rationale: str
    confidence: float


class CompletenessDecisionOutput(StrictCrewOutput):
    should_continue: bool
    completeness_score: float
    missing_topics: list[str]
    recommended_next_query: str | None
    stop_reason: str | None
    rationale: str
