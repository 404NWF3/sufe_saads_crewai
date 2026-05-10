from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from .common import FlexibleModel, ValidationStatus

ContextSlice = Literal[
    "source_registry",
    "source_quality_rows",
    "coverage_snapshot",
    "recent_attacks_summary",
    "query_feedback_memory",
    "stable_attack_candidates",
    "component_catalog",
    "pending_review_queues",
]

PersistenceOperationGroup = Literal[
    "upsert_raw_intel",
    "upsert_stable_attack",
    "insert_evidence",
    "upsert_bom_resolution",
    "insert_stix_bundle",
    "insert_alert_candidate",
    "append_query_feedback",
    "append_run_audit",
]


class DbContextRequest(FlexibleModel):
    requested_slices: list[ContextSlice] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    time_windows: dict[str, Any] = Field(default_factory=dict)
    request_reasons: dict[str, str] = Field(default_factory=dict)


class DbContextSummary(FlexibleModel):
    source_registry: list[dict[str, Any]] = Field(default_factory=list)
    source_quality_rows: list[dict[str, Any]] = Field(default_factory=list)
    coverage_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    recent_attacks_summary: list[dict[str, Any]] = Field(default_factory=list)
    query_feedback_memory: list[dict[str, Any]] = Field(default_factory=list)
    stable_attack_candidates: list[dict[str, Any]] = Field(default_factory=list)
    component_catalog: list[dict[str, Any]] = Field(default_factory=list)
    pending_review_queues: list[dict[str, Any]] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)


class PersistenceOperation(FlexibleModel):
    operation_group: PersistenceOperationGroup
    idempotency_key: str
    records: list[dict[str, Any]] = Field(default_factory=list)
    dependency_refs: list[str] = Field(default_factory=list)
    validation_status: ValidationStatus = "pending"
    audit_notes: str | None = None
    review_required: bool = False


class PersistenceBundle(FlexibleModel):
    bundle_id: str = Field(default_factory=lambda: f"bundle_{uuid4().hex[:12]}")
    operation_groups: list[PersistenceOperationGroup] = Field(default_factory=list)
    operations: list[PersistenceOperation] = Field(default_factory=list)
    review_queue_entries: list[dict[str, Any]] = Field(default_factory=list)
    dead_letter_records: list[dict[str, Any]] = Field(default_factory=list)
    audit_notes: str | None = None

    @model_validator(mode="after")
    def derive_operation_groups(self) -> "PersistenceBundle":
        if not self.operation_groups and self.operations:
            self.operation_groups = list(
                dict.fromkeys(operation.operation_group for operation in self.operations)
            )
        return self


class PersistenceOperationResult(FlexibleModel):
    operation_group: PersistenceOperationGroup
    idempotency_key: str
    applied: bool = False
    error: str | None = None
    affected_count: int = Field(default=0, ge=0)


class DbWriteResult(FlexibleModel):
    bundle_id: str
    applied_counts: dict[str, int] = Field(default_factory=dict)
    failed_counts: dict[str, int] = Field(default_factory=dict)
    operation_results: list[PersistenceOperationResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DbIntegrityReport(FlexibleModel):
    applied_counts: dict[str, int] = Field(default_factory=dict)
    failed_counts: dict[str, int] = Field(default_factory=dict)
    duplicate_warnings: list[str] = Field(default_factory=list)
    missing_dependencies: list[str] = Field(default_factory=list)
    retryable_failures: list[str] = Field(default_factory=list)
    non_retryable_failures: list[str] = Field(default_factory=list)
    audit_summary: str = ""


class DbAuditSummary(FlexibleModel):
    read_context_summary: dict[str, Any] = Field(default_factory=dict)
    write_operation_summary: dict[str, Any] = Field(default_factory=dict)
    integrity_status: str = "unknown"
    failed_operations: list[str] = Field(default_factory=list)
    dead_letter_summary: dict[str, Any] = Field(default_factory=dict)
    review_queue_summary: dict[str, Any] = Field(default_factory=dict)
    recommended_remediation: list[str] = Field(default_factory=list)
