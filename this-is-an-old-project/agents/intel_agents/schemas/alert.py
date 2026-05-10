from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CoverageGapDTO(_StrictModel):
    gap_id: str | None = None
    gap_axis: str | None = None
    taxonomy_code: str = Field(min_length=1)
    taxonomy_name: str = Field(min_length=1)
    attack_family: str | None = None
    component_family: str | None = None
    vendor_name: str | None = None
    model_family: str | None = None
    framework_family: str | None = None
    current_attack_count: int = Field(ge=0)
    target_attack_count: int = Field(ge=0)
    gap_score: float = Field(ge=0.0, le=1.0)
    source_diversity_gap: float = Field(ge=0.0, le=1.0)
    component_coverage_gap: float = Field(ge=0.0, le=1.0)
    corroboration_gap: float = Field(ge=0.0, le=1.0)
    vendor_model_gap: float = Field(default=0.0, ge=0.0, le=1.0)
    severity_pressure: float = Field(default=0.0, ge=0.0, le=1.0)
    recent_activity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_queries: list[str] = Field(default_factory=list)
    recommended_sources: list[str] = Field(default_factory=list)
    recommended_query_intents: list[str] = Field(default_factory=list)
    expected_evidence_type: list[str] = Field(default_factory=list)
    estimated_gap_fill_roi: float = Field(ge=0.0, le=1.0)
    should_dispatch_gap_fill: bool = False
    dispatch_priority: float = Field(default=0.0, ge=0.0, le=1.0)
    target_gain_dimension: str | None = None
    reason: str | None = None


class AlertCandidateDTO(_StrictModel):
    alert_type: str = Field(min_length=1)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    related_attack_id: str | None = None
    related_cluster_id: str | None = None
    evidence_uris: list[str] = Field(default_factory=list)
    trigger_reason: str = Field(min_length=1)


class NodeErrorDTO(_StrictModel):
    node_name: str = Field(min_length=1)
    error_type: str = Field(min_length=1)
    message: str = Field(min_length=1)
    subject_id: str | None = None
    retryable: bool = False
    trace_id: str | None = None
    occurred_at: str
