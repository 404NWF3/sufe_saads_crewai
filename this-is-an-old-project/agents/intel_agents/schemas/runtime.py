from __future__ import annotations

import os
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


RunModeValue: TypeAlias = Literal[
    "bootstrap", "incremental", "gap_fill", "mixed"
]
SourceRuntimeModeValue: TypeAlias = Literal["stub", "live", "hybrid"]
StandardizationStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]
ReflectionStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]
PlanningStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]
CoverageStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]
BomResolutionStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]
StixStrategyValue: TypeAlias = Literal[
    "disabled", "llm_optional", "llm_required", "rules_only_degraded"
]
DedupMergeStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]
DedupAdjudicationStrategyValue: TypeAlias = Literal[
    "rules_only", "llm_optional", "llm_required"
]
ResumePolicyValue: TypeAlias = Literal["full_restart", "from_node", "partial_replay"]


class SourceConfigDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    source_type: Literal["structured", "code", "paper", "community", "advisory"]
    enabled: bool = True
    default_max_results: int = Field(default=5, ge=1)
    default_time_window_days: int = Field(default=7, ge=1)


class DebugInjectionDTO(_StrictModel):
    fail_once_nodes: list[str] = Field(default_factory=list)
    always_fail_nodes: list[str] = Field(default_factory=list)
    force_low_yield: bool = False
    force_gap_fill: bool = False
    force_no_results: bool = False


def _default_runtime_llm_model() -> str:
    return (
        os.getenv("OPENAI_MODEL")
        or os.getenv("OPENAI_FAST_MODEL")
        or "qwen3.5-plus"
    )


class RuntimeContextDTO(_StrictModel):
    run_mode: RunModeValue = "bootstrap"
    base_run_mode: RunModeValue = "bootstrap"
    source_runtime_mode: SourceRuntimeModeValue = "stub"
    planning_strategy: PlanningStrategyValue = "llm_required"
    coverage_strategy: CoverageStrategyValue = "llm_required"
    reflection_strategy: ReflectionStrategyValue = "llm_required"
    standardization_strategy: StandardizationStrategyValue = "llm_required"
    bom_resolution_strategy: BomResolutionStrategyValue = "llm_required"
    stix_strategy: StixStrategyValue = "llm_required"
    dedup_merge_strategy: DedupMergeStrategyValue = "llm_required"
    dedup_adjudication_strategy: DedupAdjudicationStrategyValue = "rules_only"
    llm_model: str = Field(default_factory=_default_runtime_llm_model, min_length=1)
    llm_temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    validate_llm_online: bool = False
    llm_route_preset: str = Field(default="default", min_length=1)
    llm_task_routes: dict[str, list[str]] = Field(default_factory=dict)
    llm_retry_attempts: int = Field(default=3, ge=1, le=8)
    llm_backoff_base_seconds: float = Field(default=2.0, gt=0.0, le=120.0)
    llm_backoff_max_seconds: float = Field(default=30.0, gt=0.0, le=600.0)
    llm_short_wait_threshold_seconds: float = Field(
        default=60.0, gt=0.0, le=900.0
    )
    llm_resume_on_exhausted_retry: bool = True
    standardization_max_concurrency: int = Field(default=2, ge=1, le=32)
    bom_resolve_max_concurrency: int = Field(default=4, ge=1, le=32)
    bom_review_max_concurrency: int = Field(default=4, ge=1, le=32)
    stix_max_concurrency: int = Field(default=4, ge=1, le=32)
    stix_auto_publish_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    bom_auto_publish_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    review_queue_threshold: float = Field(default=0.60, ge=0.0, le=1.0)
    planning_max_parallel_sources: int | None = Field(default=None, ge=1, le=8)
    planning_max_items_per_source: int | None = Field(default=None, ge=1, le=100)
    planning_max_reflection_rounds: int | None = Field(default=None, ge=0, le=3)
    planning_reflection_enabled: bool | None = None
    source_registry: list[SourceConfigDTO] = Field(default_factory=list)
    coverage_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    vendor_model_coverage_rows: list[dict[str, Any]] = Field(default_factory=list)
    recent_attacks_summary: list[dict[str, Any]] = Field(default_factory=list)
    source_quality_rows: list[dict[str, Any]] = Field(default_factory=list)
    query_feedback_rows: list[dict[str, Any]] = Field(default_factory=list)
    gap_fill_dispatch_plans: list[dict[str, Any]] = Field(default_factory=list)
    coverage_feedback_rows: list[dict[str, Any]] = Field(default_factory=list)
    pending_queue_summary: dict[str, Any] = Field(default_factory=dict)
    latest_ingested_query_run_ids: list[str] = Field(default_factory=list)
    cursor_state: dict[str, dict[str, Any]] = Field(default_factory=dict)
    coverage_refreshed_at: str | None = None
    coverage_min_roi_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    coverage_max_gap_fill_plans: int = Field(default=3, ge=1, le=20)
    coverage_max_gap_fill_rounds: int = Field(default=1, ge=0, le=10)
    artifact_store_dir: str | None = None
    audit_store_dir: str | None = None
    dedup_store_dir: str | None = None
    qdrant_local_path: str | None = None
    qdrant_collection_name: str = Field(
        default="wp11_attack_signature_memory", min_length=1
    )
    payload_cleanup_removed: list[str] = Field(default_factory=list)
    registry_alignment_report: dict[str, Any] = Field(default_factory=dict)
    persist_raw_records_to_db: bool = False
    prefer_db_source_registry: bool = False
    source_retry_attempts: int = Field(default=2, ge=1, le=5)
    source_request_timeout_seconds: float = Field(default=20.0, gt=0.0)
    source_health_drift_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    payload_retention_days: int = Field(default=30, ge=1)
    cleanup_expired_payloads: bool = False
    collection_task_mode: str = Field(default="fast", pattern="^(fast|deep)$")
    collection_trigger_type: str = Field(
        default="manual", pattern="^(cron|event|manual)$"
    )
    collection_created_by: str = Field(default="phase2_collector", min_length=1)
    resume_policy: ResumePolicyValue = "full_restart"
    resume_from_node: str | None = None
    replay_query_run_ids: list[str] = Field(default_factory=list)
    skip_completed_nodes: bool = False
    failure_injection: DebugInjectionDTO | None = None

    @model_validator(mode="before")
    @classmethod
    def _fill_base_run_mode(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        if payload.get("base_run_mode"):
            return payload
        return {
            **payload,
            "base_run_mode": payload.get("run_mode", "bootstrap"),
        }

    @classmethod
    def default_live(
        cls,
        *,
        run_mode: RunModeValue = "bootstrap",
        llm_model: str | None = None,
        coverage_max_gap_fill_rounds: int = 1,
    ) -> "RuntimeContextDTO":
        """生产模式：真实 API 采集 + LLM 全链路推理。
        llm_model 默认读取环境变量 OPENAI_MODEL，未设置时降级为 qwen3.5-plus。
        """
        from ..tools.llm_client_factory import (
            recommended_task_concurrency,
            resolve_default_model,
        )

        model = resolve_default_model(llm_model)
        route_preset = os.getenv("WP11_LLM_DEFAULT_ROUTE_PRESET", "default")
        runtime_llm_config = {
            "llm_model": model,
            "llm_route_preset": route_preset,
            "llm_task_routes": {},
        }
        standardization_default_concurrency = recommended_task_concurrency(
            task_name="standardization",
            default_model=model,
            base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
            api_key=os.getenv("OPENAI_API_KEY"),
            runtime_config=runtime_llm_config,
            upper_bound=32,
        )
        return cls.model_validate(
            {
                "run_mode": run_mode,
                "base_run_mode": run_mode,
                "source_runtime_mode": "live",
                "planning_strategy": "llm_required",
                "coverage_strategy": "llm_required",
                "reflection_strategy": "llm_required",
                "standardization_strategy": "llm_required",
                "bom_resolution_strategy": "llm_required",
                "stix_strategy": "llm_required",
                "dedup_merge_strategy": "llm_required",
                "dedup_adjudication_strategy": "rules_only",
                "llm_model": model,
                "llm_temperature": 0.0,
                "validate_llm_online": False,
                "llm_route_preset": route_preset,
                "llm_task_routes": {},
                "llm_retry_attempts": 3,
                "llm_backoff_base_seconds": 2.0,
                "llm_backoff_max_seconds": 30.0,
                "llm_short_wait_threshold_seconds": 60.0,
                "llm_resume_on_exhausted_retry": True,
                "standardization_max_concurrency": standardization_default_concurrency,
                "bom_resolve_max_concurrency": 4,
                "bom_review_max_concurrency": 4,
                "stix_max_concurrency": 4,
                "stix_auto_publish_threshold": 0.85,
                "bom_auto_publish_threshold": 0.85,
                "review_queue_threshold": 0.60,
                "planning_max_parallel_sources": 4,
                "planning_max_items_per_source": 10,
                "planning_max_reflection_rounds": 1,
                "planning_reflection_enabled": True,
                "source_registry": [
                    SourceConfigDTO(source_name="nvd", source_type="structured", default_max_results=20, default_time_window_days=30),
                    SourceConfigDTO(source_name="github_advisories", source_type="code", default_max_results=20, default_time_window_days=30),
                    SourceConfigDTO(source_name="github_discussions", source_type="code", default_max_results=20, default_time_window_days=30),
                    SourceConfigDTO(source_name="arxiv", source_type="paper", default_max_results=15, default_time_window_days=30),
                    SourceConfigDTO(source_name="reddit", source_type="community", default_max_results=10, default_time_window_days=7),
                    SourceConfigDTO(source_name="hackernews", source_type="community", default_max_results=10, default_time_window_days=7),
                    SourceConfigDTO(source_name="cisa_kev", source_type="advisory", default_max_results=50, default_time_window_days=90),
                    SourceConfigDTO(source_name="mitre_attack", source_type="structured", default_max_results=30, default_time_window_days=90),
                    SourceConfigDTO(source_name="vendor_advisories", source_type="advisory", default_max_results=15, default_time_window_days=30),
                    SourceConfigDTO(source_name="huggingface", source_type="code", default_max_results=10, default_time_window_days=30),
                ],
                "coverage_snapshot": [
                    {"taxonomy_code": "OWASP-LLM-01", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-02", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-03", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-04", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-05", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-06", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-07", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-08", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-09", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-10", "attack_count": 0},
                ],
                "source_quality_rows": [
                    {"source_name": "nvd", "trust_level": 0.95},
                    {"source_name": "github_advisories", "trust_level": 0.90},
                    {"source_name": "github_discussions", "trust_level": 0.80},
                    {"source_name": "arxiv", "trust_level": 0.85},
                    {"source_name": "reddit", "trust_level": 0.60},
                    {"source_name": "hackernews", "trust_level": 0.65},
                    {"source_name": "cisa_kev", "trust_level": 0.98},
                    {"source_name": "mitre_attack", "trust_level": 0.97},
                    {"source_name": "vendor_advisories", "trust_level": 0.75},
                    {"source_name": "huggingface", "trust_level": 0.70},
                ],
                "query_feedback_rows": [],
                "gap_fill_dispatch_plans": [],
                "coverage_feedback_rows": [],
                "pending_queue_summary": {"unresolved_bom": 0},
                "cursor_state": {},
                "coverage_max_gap_fill_rounds": coverage_max_gap_fill_rounds,
                "coverage_max_gap_fill_plans": 3,
                "coverage_min_roi_threshold": 0.65,
                "artifact_store_dir": ".runtime/wp11/raw_records",
                "audit_store_dir": ".runtime/wp11/audit",
                "dedup_store_dir": ".runtime/wp11/dedup",
                "qdrant_local_path": ".runtime/wp11/vector_memory",
                "qdrant_collection_name": "wp11_attack_signature_memory",
                "persist_raw_records_to_db": True,
                "prefer_db_source_registry": False,
                "source_retry_attempts": 2,
                "source_request_timeout_seconds": 30.0,
                "source_health_drift_threshold": 0.5,
                "payload_retention_days": 30,
                "cleanup_expired_payloads": False,
                "collection_task_mode": "fast",
                "collection_trigger_type": "manual",
                "collection_created_by": "api_live_run",
                "resume_policy": "full_restart",
                "resume_from_node": None,
                "replay_query_run_ids": [],
                "skip_completed_nodes": False,
                "failure_injection": None,
            }
        )

    @classmethod
    def ensure_defaults(cls, payload: dict[str, Any]) -> "RuntimeContextDTO":
        if payload:
            return cls.model_validate(payload)
        return cls.default_stub()

    @classmethod
    def default_stub(
        cls,
        *,
        run_mode: RunModeValue = "bootstrap",
        fail_once_nodes: list[str] | None = None,
        always_fail_nodes: list[str] | None = None,
        force_low_yield: bool = False,
        force_gap_fill: bool = False,
        force_no_results: bool = False,
        coverage_max_gap_fill_rounds: int = 1,
    ) -> "RuntimeContextDTO":
        return cls.model_validate(
            {
                "run_mode": run_mode,
                "base_run_mode": run_mode,
                "source_runtime_mode": "stub",
                "planning_strategy": "rules_only",  # stub mode; production default is llm_required
                "coverage_strategy": "rules_only",  # stub mode; production default is llm_required
                "reflection_strategy": "rules_only",  # stub mode; production default is llm_required
                "standardization_strategy": "rules_only",  # stub mode; production default is llm_required
                "bom_resolution_strategy": "rules_only",  # stub mode; production default is llm_required
                "stix_strategy": "disabled",
                "dedup_merge_strategy": "rules_only",  # stub mode; production default is llm_required
                "dedup_adjudication_strategy": "rules_only",
                "llm_model": _default_runtime_llm_model(),
                "llm_temperature": 0.0,
                "validate_llm_online": False,
                "llm_route_preset": "default",
                "llm_task_routes": {},
                "llm_retry_attempts": 2,
                "llm_backoff_base_seconds": 1.0,
                "llm_backoff_max_seconds": 8.0,
                "llm_short_wait_threshold_seconds": 15.0,
                "llm_resume_on_exhausted_retry": True,
                "standardization_max_concurrency": 2,
                "bom_resolve_max_concurrency": 1,
                "bom_review_max_concurrency": 1,
                "stix_max_concurrency": 1,
                "stix_auto_publish_threshold": 0.85,
                "bom_auto_publish_threshold": 0.85,
                "review_queue_threshold": 0.60,
                "planning_max_parallel_sources": 4,
                "planning_max_items_per_source": 10,
                "planning_max_reflection_rounds": 1,
                "planning_reflection_enabled": True,
                "source_registry": [
                    SourceConfigDTO(source_name="nvd", source_type="structured"),
                    SourceConfigDTO(
                        source_name="github_advisories", source_type="code"
                    ),
                    SourceConfigDTO(source_name="arxiv", source_type="paper"),
                    SourceConfigDTO(source_name="reddit", source_type="community"),
                    SourceConfigDTO(source_name="hackernews", source_type="community"),
                    SourceConfigDTO(source_name="cisa_kev", source_type="advisory"),
                    SourceConfigDTO(
                        source_name="mitre_attack", source_type="structured"
                    ),
                ],
                "coverage_snapshot": [
                    {"taxonomy_code": "OWASP-LLM-01", "attack_count": 0},
                    {"taxonomy_code": "OWASP-LLM-02", "attack_count": 0},
                ],
                "source_quality_rows": [
                    {"source_name": "nvd", "trust_level": 0.95},
                    {"source_name": "github_advisories", "trust_level": 0.9},
                ],
                "query_feedback_rows": [],
                "gap_fill_dispatch_plans": [],
                "coverage_feedback_rows": [],
                "pending_queue_summary": {"unresolved_bom": 0},
                "cursor_state": {},
                "coverage_max_gap_fill_rounds": coverage_max_gap_fill_rounds,
                "artifact_store_dir": ".runtime/wp11/raw_records",
                "audit_store_dir": ".runtime/wp11/audit",
                "dedup_store_dir": ".runtime/wp11/dedup",
                "qdrant_local_path": ".runtime/wp11/vector_memory",
                "qdrant_collection_name": "wp11_attack_signature_memory",
                "persist_raw_records_to_db": False,
                "prefer_db_source_registry": False,
                "source_retry_attempts": 2,
                "source_request_timeout_seconds": 20.0,
                "source_health_drift_threshold": 0.5,
                "payload_retention_days": 30,
                "cleanup_expired_payloads": False,
                "collection_task_mode": "fast",
                "collection_trigger_type": "manual",
                "collection_created_by": "phase2_collector",
                "resume_policy": "full_restart",
                "resume_from_node": None,
                "replay_query_run_ids": [],
                "skip_completed_nodes": False,
                "failure_injection": DebugInjectionDTO(
                    fail_once_nodes=fail_once_nodes or [],
                    always_fail_nodes=always_fail_nodes or [],
                    force_low_yield=force_low_yield,
                    force_gap_fill=force_gap_fill,
                    force_no_results=force_no_results,
                ),
            }
        )
