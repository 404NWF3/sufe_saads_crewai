from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..schemas.runtime import RuntimeContextDTO
from ..tools.llm_client_factory import describe_model_pool


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceTuningOverrideDTO(_StrictModel):
    enabled: bool | None = None
    default_max_results: int | None = Field(default=None, ge=1, le=100)
    default_time_window_days: int | None = Field(default=None, ge=1, le=365)


class RuntimeTuningOverridesDTO(_StrictModel):
    llm_route_preset: str | None = Field(default=None, min_length=1)
    llm_task_routes: dict[str, list[str]] | None = None
    llm_retry_attempts: int | None = Field(default=None, ge=1, le=8)
    llm_backoff_base_seconds: float | None = Field(default=None, gt=0.0, le=120.0)
    llm_backoff_max_seconds: float | None = Field(default=None, gt=0.0, le=600.0)
    llm_short_wait_threshold_seconds: float | None = Field(
        default=None, gt=0.0, le=900.0
    )
    llm_resume_on_exhausted_retry: bool | None = None
    standardization_max_concurrency: int | None = Field(default=None, ge=1, le=32)
    planning_max_parallel_sources: int | None = Field(default=None, ge=1, le=8)
    planning_max_items_per_source: int | None = Field(default=None, ge=1, le=100)
    planning_max_reflection_rounds: int | None = Field(default=None, ge=0, le=3)
    planning_reflection_enabled: bool | None = None
    source_overrides: dict[str, SourceTuningOverrideDTO] | None = None


_TOP_LEVEL_TUNING_FIELDS = (
    "llm_route_preset",
    "llm_task_routes",
    "llm_retry_attempts",
    "llm_backoff_base_seconds",
    "llm_backoff_max_seconds",
    "llm_short_wait_threshold_seconds",
    "llm_resume_on_exhausted_retry",
    "standardization_max_concurrency",
    "planning_max_parallel_sources",
    "planning_max_items_per_source",
    "planning_max_reflection_rounds",
    "planning_reflection_enabled",
)


def apply_tuning_overrides(
    runtime_context: dict[str, Any],
    tuning_overrides: RuntimeTuningOverridesDTO | dict[str, Any] | None,
) -> dict[str, Any]:
    context = RuntimeContextDTO.ensure_defaults(runtime_context or {})
    merged = context.model_dump(mode="python")
    if tuning_overrides is None:
        return merged

    if isinstance(tuning_overrides, RuntimeTuningOverridesDTO):
        overrides = tuning_overrides.model_dump(mode="python", exclude_none=True)
    else:
        overrides = RuntimeTuningOverridesDTO.model_validate(tuning_overrides).model_dump(
            mode="python",
            exclude_none=True,
        )

    for field_name in _TOP_LEVEL_TUNING_FIELDS:
        if field_name in overrides:
            merged[field_name] = overrides[field_name]

    source_overrides = overrides.get("source_overrides") or {}
    if source_overrides:
        updated_registry: list[dict[str, Any]] = []
        for row in merged.get("source_registry", []):
            source_name = str(row.get("source_name", ""))
            source_override = source_overrides.get(source_name)
            if source_override:
                updated_registry.append(
                    {
                        **row,
                        **{
                            key: value
                            for key, value in source_override.items()
                            if value is not None
                        },
                    }
                )
            else:
                updated_registry.append(row)
        merged["source_registry"] = updated_registry

    return RuntimeContextDTO.model_validate(merged).model_dump(mode="python")


def build_runtime_parameter_catalog(
    runtime_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = RuntimeContextDTO.ensure_defaults(
        runtime_context or RuntimeContextDTO.default_live().model_dump(mode="python")
    )
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    api_key = os.getenv("OPENAI_API_KEY")
    model_pool = describe_model_pool(
        default_model=context.llm_model,
        base_url=base_url,
        api_key=api_key,
        runtime_config=context.model_dump(mode="python"),
    )
    route_preset_options = sorted(model_pool.get("route_presets", {}).keys())
    defaults = {
        field_name: getattr(context, field_name)
        for field_name in _TOP_LEVEL_TUNING_FIELDS
    }
    sources = [
        {
            "source_name": row.source_name,
            "source_type": row.source_type,
            "enabled": row.enabled,
            "default_max_results": row.default_max_results,
            "default_time_window_days": row.default_time_window_days,
        }
        for row in context.source_registry
    ]
    tunables = [
        {
            "key": "llm_route_preset",
            "group": "llm_tasks",
            "type": "string",
            "default": context.llm_route_preset,
            "options": route_preset_options,
            "description": "Selects the default ordered profile-label route for all LLM tasks.",
        },
        {
            "key": "llm_task_routes",
            "group": "llm_tasks",
            "type": "object",
            "default": context.llm_task_routes,
            "description": "Overrides the ordered profile-label route per task, for example ['cheap_fast', 'fallback'].",
        },
        {
            "key": "llm_retry_attempts",
            "group": "llm_resilience",
            "type": "integer",
            "default": context.llm_retry_attempts,
            "min": 1,
            "max": 8,
            "description": "Maximum retries for retryable LLM failures per profile.",
        },
        {
            "key": "llm_backoff_base_seconds",
            "group": "llm_resilience",
            "type": "number",
            "default": context.llm_backoff_base_seconds,
            "min": 0.1,
            "max": 120.0,
            "description": "Base delay used for exponential backoff on retryable LLM failures.",
        },
        {
            "key": "llm_backoff_max_seconds",
            "group": "llm_resilience",
            "type": "number",
            "default": context.llm_backoff_max_seconds,
            "min": 1.0,
            "max": 600.0,
            "description": "Upper bound for a single LLM backoff wait.",
        },
        {
            "key": "llm_short_wait_threshold_seconds",
            "group": "llm_resilience",
            "type": "number",
            "default": context.llm_short_wait_threshold_seconds,
            "min": 1.0,
            "max": 900.0,
            "description": "Threshold used by the UI to classify a retry wait as short.",
        },
        {
            "key": "llm_resume_on_exhausted_retry",
            "group": "llm_resilience",
            "type": "boolean",
            "default": context.llm_resume_on_exhausted_retry,
            "description": "When true, exhausted LLM failures produce resume hints and tuning suggestions.",
        },
        {
            "key": "standardization_max_concurrency",
            "group": "llm_tasks",
            "type": "integer",
            "default": context.standardization_max_concurrency,
            "min": 1,
            "max": 32,
            "description": "Maximum concurrent LLM standardization workers.",
        },
        {
            "key": "planning_max_parallel_sources",
            "group": "collection",
            "type": "integer",
            "default": context.planning_max_parallel_sources,
            "min": 1,
            "max": 8,
            "description": "Upper bound for concurrent source collection in a run plan.",
        },
        {
            "key": "planning_max_items_per_source",
            "group": "collection",
            "type": "integer",
            "default": context.planning_max_items_per_source,
            "min": 1,
            "max": 100,
            "description": "Global cap for max_results generated into each source plan.",
        },
        {
            "key": "planning_max_reflection_rounds",
            "group": "collection",
            "type": "integer",
            "default": context.planning_max_reflection_rounds,
            "min": 0,
            "max": 3,
            "description": "Maximum Phase 6 reflection loops allowed in a run.",
        },
        {
            "key": "planning_reflection_enabled",
            "group": "collection",
            "type": "boolean",
            "default": context.planning_reflection_enabled,
            "description": "Enables or disables Phase 6 reflection-driven query rewrites.",
        },
    ]
    return {
        "defaults": defaults,
        "sources": sources,
        "tunables": tunables,
        "model_pool": model_pool,
    }
