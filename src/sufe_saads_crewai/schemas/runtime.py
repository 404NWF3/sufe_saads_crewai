from __future__ import annotations

from pydantic import Field

from .actions import ActionDecision
from .alerts import AlertCandidate
from .common import ErrorRecord, FlexibleModel, NonNegativeFloat, NonNegativeInt, RunMode
from .coverage import CoverageGap, SearchReflectionDecision
from .intel import BomResolution, DedupDecision, StandardizedIntelRecord
from .persistence import PersistenceBundle
from .sources import ApprovedSource, QueryHistoryEntry, RawIntelItem, SourceProposal


class RunBudget(FlexibleModel):
    max_rounds: NonNegativeInt | None = 10
    max_seconds: NonNegativeFloat | None = None
    max_tokens: NonNegativeInt | None = None
    max_api_calls: NonNegativeInt | None = None
    max_sources: NonNegativeInt | None = None
    max_cost_usd: NonNegativeFloat | None = None


class RunMetrics(FlexibleModel):
    round_index: NonNegativeInt = 0
    elapsed_seconds: NonNegativeFloat = 0.0
    tokens_used: NonNegativeInt = 0
    api_calls_used: NonNegativeInt = 0
    sources_used: NonNegativeInt = 0
    cost_used: NonNegativeFloat = 0.0


class IntelRunBlackboard(FlexibleModel):
    run_id: str
    run_goal: str
    run_mode: RunMode = "bootstrap"
    budget: RunBudget = Field(default_factory=RunBudget)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    approved_sources: list[ApprovedSource] = Field(default_factory=list)
    source_scores: dict[str, float] = Field(default_factory=dict)
    source_low_yield_streaks: dict[str, int] = Field(default_factory=dict)
    source_proposals: list[SourceProposal] = Field(default_factory=list)
    query_history: list[QueryHistoryEntry] = Field(default_factory=list)
    raw_items: list[RawIntelItem] = Field(default_factory=list)
    standardized_items: list[StandardizedIntelRecord] = Field(default_factory=list)
    dedup_decisions: list[DedupDecision] = Field(default_factory=list)
    bom_resolutions: list[BomResolution] = Field(default_factory=list)
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    reflection_notes: list[SearchReflectionDecision] = Field(default_factory=list)
    persistence_bundles: list[PersistenceBundle] = Field(default_factory=list)
    alerts: list[AlertCandidate] = Field(default_factory=list)
    action_history: list[ActionDecision] = Field(default_factory=list)
    errors: list[ErrorRecord] = Field(default_factory=list)
