from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import ActionType, FlexibleModel, Priority, RunMode, Score, utcnow


class ActionDecision(FlexibleModel):
    action_type: ActionType
    priority: Priority = "medium"
    rationale: str
    expected_gain: str | None = None
    required_context: list[str] = Field(default_factory=list)
    budget_cost_estimate: dict[str, Any] = Field(default_factory=dict)
    success_criteria: list[str] = Field(default_factory=list)
    retry_conditions: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionDecisionBatch(FlexibleModel):
    actions: list[ActionDecision] = Field(default_factory=list, max_length=5)
    planner_rationale: str = ""
    overall_risk: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


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
    locale: str | None = None
    search_mode: str | None = None
    expected_coverage_gain: Score = 0.0


class GapFillPlan(FlexibleModel):
    plan_id: str | None = None
    target_gaps: list[str] = Field(default_factory=list)
    recommended_queries: list[SearchQueryPlan] = Field(default_factory=list)
    recommended_sources: list[str] = Field(default_factory=list)
    expected_coverage_gain: Score = 0.0
    budget_cost_estimate: dict[str, Any] = Field(default_factory=dict)
    priority: Priority = "medium"
    next_mode: RunMode = "gap_fill"
    stop_conditions: list[str] = Field(default_factory=list)
