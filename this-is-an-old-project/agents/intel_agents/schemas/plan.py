from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceExecutionPlanDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    source_type: str = Field(min_length=1)
    priority: float = Field(ge=0.0)
    queries: list[str] = Field(default_factory=list)
    query_intent: Literal[
        "broad_recall",
        "precision_probe",
        "weak_signal_probe",
        "evidence_corroboration",
        "source_specific_rewrite",
        "component_anchor",
        "taxonomy_anchor",
    ]
    query_provenance: str = Field(min_length=1)
    rewrite_reason: str | None = None
    max_results: int = Field(ge=1)
    fetch_mode: Literal["bootstrap", "incremental", "targeted_gap_fill", "weak_signal"]
    time_window_days: int | None = Field(default=None, ge=1)


class CollectionPlanDTO(_StrictModel):
    run_mode: Literal[
        "bootstrap", "incremental", "gap_fill", "mixed"
    ]
    rationale: str = Field(min_length=1)
    target_taxonomies: list[str] = Field(default_factory=list)
    source_plans: list[SourceExecutionPlanDTO] = Field(default_factory=list)
    max_parallel_sources: int = Field(ge=1)
    max_items_per_source: int = Field(ge=1)
    max_reflection_rounds: int = Field(ge=0, default=1)
    reflection_enabled: bool = True
