from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CoverageSliceDTO(_StrictModel):
    coverage_axis: Literal["taxonomy_component_source", "vendor_model_source_taxonomy"]
    taxonomy_code: str | None = None
    taxonomy_name: str | None = None
    attack_family: str | None = None
    source_name: str | None = None
    component_family: str | None = None
    vendor_name: str | None = None
    model_family: str | None = None
    framework_family: str | None = None
    attack_count: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)
    source_diversity_count: int = Field(ge=0)
    corroborated_attack_count: int = Field(ge=0)
    version_mapped_count: int = Field(ge=0)
    last_seen_at: str | None = None
    stable_attack_ids: list[str] = Field(default_factory=list)
    high_severity_attack_ids: list[str] = Field(default_factory=list)
    corroborated_attack_ids: list[str] = Field(default_factory=list)
    version_mapped_attack_ids: list[str] = Field(default_factory=list)


class CoverageGapCandidateDTO(_StrictModel):
    gap_id: str = Field(min_length=1)
    gap_axis: Literal[
        "taxonomy",
        "component_family",
        "vendor_model",
        "corroboration",
        "source_diversity",
    ]
    taxonomy_code: str | None = None
    taxonomy_name: str | None = None
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
    vendor_model_gap: float = Field(ge=0.0, le=1.0)
    severity_pressure: float = Field(ge=0.0, le=1.0)
    recent_activity_score: float = Field(ge=0.0, le=1.0)
    estimated_gap_fill_roi: float = Field(ge=0.0, le=1.0)
    evidence_summary: str = Field(min_length=1)


class GapFillRecommendationDTO(_StrictModel):
    gap_id: str = Field(min_length=1)
    should_dispatch_gap_fill: bool = False
    dispatch_priority: float = Field(ge=0.0, le=1.0)
    recommended_sources: list[str] = Field(default_factory=list)
    recommended_queries: list[str] = Field(default_factory=list)
    recommended_query_intents: list[str] = Field(default_factory=list)
    expected_evidence_type: list[str] = Field(default_factory=list)
    recommended_time_window_days: int = Field(default=14, ge=1, le=365)
    recommended_fetch_mode: Literal["targeted_gap_fill"] = "targeted_gap_fill"
    estimated_gap_fill_roi: float = Field(ge=0.0, le=1.0)
    target_gain_dimension: Literal[
        "coverage", "corroboration", "component_mapping", "vendor_model"
    ] = "coverage"
    rationale: str = Field(min_length=1)
    stop_reason: str | None = None


class VendorModelCoverageRowDTO(_StrictModel):
    vendor_name: str | None = None
    model_family: str | None = None
    framework_family: str | None = None
    source_name: str = Field(min_length=1)
    taxonomy_code: str | None = None
    taxonomy_name: str | None = None
    attack_count: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)
    corroborated_attack_count: int = Field(ge=0)
    version_mapped_count: int = Field(ge=0)
    stable_attack_ids: list[str] = Field(default_factory=list)
    high_severity_attack_ids: list[str] = Field(default_factory=list)
    corroborated_attack_ids: list[str] = Field(default_factory=list)
    version_mapped_attack_ids: list[str] = Field(default_factory=list)


class LlmCoverageGapDecisionDTO(_StrictModel):
    should_dispatch_gap_fill: bool = False
    gap_type: Literal[
        "taxonomy",
        "component_family",
        "vendor_model",
        "corroboration",
        "source_diversity",
        "uncertain",
    ] = "uncertain"
    diagnosis: str = Field(min_length=1)
    recommended_sources: list[str] = Field(default_factory=list)
    recommended_queries: list[str] = Field(default_factory=list)
    recommended_query_intents: list[str] = Field(default_factory=list)
    expected_evidence_type: list[str] = Field(default_factory=list)
    recommended_time_window_days: int = Field(default=14, ge=1, le=365)
    estimated_gap_fill_roi: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)
    fallback_reason: str | None = None


class LlmCoverageAnalysisAuditDTO(_StrictModel):
    gap_id: str = Field(min_length=1)
    strategy_requested: str = Field(min_length=1)
    strategy_executed: str = Field(min_length=1)
    llm_model: str = Field(min_length=1)
    llm_profile_id: str | None = None
    llm_profile: str | None = None
    prompt_version: str = Field(min_length=1)
    gap_type: str = Field(min_length=1)
    should_dispatch_gap_fill: bool = False
    estimated_gap_fill_roi: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_source_count: int = Field(ge=0)
    recommended_query_count: int = Field(ge=0)
    fallback_reason: str | None = None
    llm_wait_seconds: float | None = Field(default=None, ge=0.0)
    attempted_profiles: list[str] = Field(default_factory=list)
    attempted_profile_labels: list[str] = Field(default_factory=list)
    invoked_at: str = Field(min_length=1)
