from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


SourceRuntimeMode = Literal["stub", "live", "hybrid"]


class RegisteredSourceDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    source_type: Literal["structured", "code", "paper", "community", "advisory"]
    base_uri: str = Field(min_length=1)
    adapter_name: str = Field(min_length=1)
    enabled: bool = True
    default_qps: float = Field(default=1.0, gt=0.0)
    default_time_window_days: int = Field(default=7, ge=1)
    default_max_results: int = Field(default=20, ge=1)
    supports_cursor: bool = False
    auth_env_var: str | None = None
    auth_type: Literal["none", "header_bearer", "header_api_key"] = "none"
    pagination_style: Literal["none", "offset", "cursor", "feed"] = "none"
    page_size_param: str | None = None
    result_path: str | None = None
    backoff_base_seconds: float = Field(default=1.0, gt=0.0)
    circuit_breaker_threshold: int = Field(default=3, ge=1)
    circuit_breaker_cooldown_seconds: float = Field(default=60.0, gt=0.0)
    default_params: dict[str, Any] = Field(default_factory=dict)


class QueryRunDTO(_StrictModel):
    query_run_id: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    query_text: str = Field(min_length=1)
    query_intent: str = Field(min_length=1)
    reflection_round: int = Field(ge=0)
    max_results: int = Field(ge=1)
    time_window_days: int | None = Field(default=None, ge=1)
    trace_id: str = Field(min_length=1)
    run_mode: str = Field(min_length=1)
    page_cursor: str | None = None


class SourceFetchedItemDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    source_uri: str = Field(min_length=1)
    external_id: str | None = None
    title: str | None = None
    summary: str | None = None
    author: str | None = None
    published_at: str | None = None
    raw_format: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    language_code: str | None = None
    relevance_score: float | None = Field(default=None, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceFetchBatchDTO(_StrictModel):
    query_run: QueryRunDTO
    items: list[SourceFetchedItemDTO] = Field(default_factory=list)
    fetched_at: str
    latency_ms: float = Field(ge=0.0)
    attempt_count: int = Field(ge=1)
    success: bool = True
    error_type: str | None = None
    error_message: str | None = None
    used_stub: bool = False
    next_cursor: str | None = None
    degraded_from_live: bool = False
    request_audit: dict[str, Any] = Field(default_factory=dict)


class SourceExecutionStatDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    query_run_id: str = Field(min_length=1)
    query_text: str = Field(min_length=1)
    query_intent: str | None = None
    success: bool
    item_count: int = Field(ge=0)
    attempt_count: int = Field(ge=1)
    latency_ms: float = Field(ge=0.0)
    error_type: str | None = None
    error_message: str | None = None
    used_stub: bool = False
    rate_limited: bool = False
    degraded_from_live: bool = False
    collector_role: str | None = None
    execution_profile: str | None = None
    source_specific_hint: str | None = None


class SourceHealthRowDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    success_rate: float = Field(ge=0.0, le=1.0)
    degraded_rate: float = Field(ge=0.0, le=1.0)
    avg_latency_ms: float = Field(ge=0.0)
    total_queries: int = Field(ge=0)
    total_items: int = Field(ge=0)
    drift_detected: bool = False
    drift_reason: str | None = None


class SourceFetchAuditDTO(_StrictModel):
    query_run_id: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    requested_at: str
    completed_at: str
    runtime_mode: str = Field(min_length=1)
    attempt_count: int = Field(ge=1)
    success: bool
    degraded_from_live: bool = False
    request_meta: dict[str, Any] = Field(default_factory=dict)
    error_type: str | None = None
    error_message: str | None = None


class ArtifactWriteResultDTO(_StrictModel):
    artifact_ref: str = Field(min_length=1)
    payload_uri: str = Field(min_length=1)
    content_hash: str = Field(min_length=32)


class StoredRawRecordDTO(_StrictModel):
    raw_id: str = Field(min_length=1)
    query_run_id: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    payload_uri: str = Field(min_length=1)
    stored_via: Literal["db", "local_manifest"]
    task_id: str | None = None
    content_hash: str | None = None
    ingest_audit_ref: str | None = None
