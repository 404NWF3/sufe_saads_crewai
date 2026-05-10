"""Service layer for WP1-1 source collection and ingestion."""

from __future__ import annotations

from typing import Any

__all__ = [
    "AttackSignatureMemory",
    "ComponentResolutionService",
    "ConfidenceScoringService",
    "CoverageReadModelService",
    "DedupMemoryService",
    "GapScoringService",
    "QueryFeedbackMemoryService",
    "RawIngestFlow",
    "RuntimeTuningOverridesDTO",
    "SourceTuningOverrideDTO",
    "apply_tuning_overrides",
    "build_runtime_parameter_catalog",
    "SourceHealthService",
    "SourceQueryTemplateService",
    "SourceRegistryService",
    "SourceScheduler",
    "StixGraphService",
]


def __getattr__(name: str) -> Any:
    if name == "AttackSignatureMemory":
        from .attack_signature_memory import AttackSignatureMemory

        return AttackSignatureMemory
    if name == "ComponentResolutionService":
        from .component_resolution_service import ComponentResolutionService

        return ComponentResolutionService
    if name == "ConfidenceScoringService":
        from .confidence_scoring_service import ConfidenceScoringService

        return ConfidenceScoringService
    if name == "CoverageReadModelService":
        from .coverage_read_model_service import CoverageReadModelService

        return CoverageReadModelService
    if name == "DedupMemoryService":
        from .dedup_memory_service import DedupMemoryService

        return DedupMemoryService
    if name == "GapScoringService":
        from .gap_scoring_service import GapScoringService

        return GapScoringService
    if name == "QueryFeedbackMemoryService":
        from .query_feedback_memory import QueryFeedbackMemoryService

        return QueryFeedbackMemoryService
    if name == "RawIngestFlow":
        from .raw_ingest_flow import RawIngestFlow

        return RawIngestFlow
    if name in {
        "RuntimeTuningOverridesDTO",
        "SourceTuningOverrideDTO",
        "apply_tuning_overrides",
        "build_runtime_parameter_catalog",
    }:
        from .runtime_tuning_service import (
            RuntimeTuningOverridesDTO,
            SourceTuningOverrideDTO,
            apply_tuning_overrides,
            build_runtime_parameter_catalog,
        )

        return {
            "RuntimeTuningOverridesDTO": RuntimeTuningOverridesDTO,
            "SourceTuningOverrideDTO": SourceTuningOverrideDTO,
            "apply_tuning_overrides": apply_tuning_overrides,
            "build_runtime_parameter_catalog": build_runtime_parameter_catalog,
        }[name]
    if name == "SourceHealthService":
        from .source_health_service import SourceHealthService

        return SourceHealthService
    if name == "SourceQueryTemplateService":
        from .source_query_template_service import SourceQueryTemplateService

        return SourceQueryTemplateService
    if name == "SourceRegistryService":
        from .source_registry import SourceRegistryService

        return SourceRegistryService
    if name == "SourceScheduler":
        from .source_scheduler import SourceScheduler

        return SourceScheduler
    if name == "StixGraphService":
        from .stix_graph_service import StixGraphService

        return StixGraphService
    raise AttributeError(name)
