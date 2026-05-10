from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GraphNodePatchDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    started_at: str | None = None
    finished_at: str | None = None
    run_mode: str | None = None
    run_status: str | None = None
    runtime_context: dict[str, Any] | None = None
    collection_plan: dict[str, Any] | None = None
    collection_coordination: dict[str, Any] | None = None
    collector_plans: dict[str, list[dict[str, Any]]] | None = None
    resume_hint: dict[str, Any] | None = None
    source_cursors: dict[str, dict[str, Any]] | None = None
    source_execution_stats: list[dict[str, Any]] | None = None
    source_health_dashboard: list[dict[str, Any]] | None = None
    source_drift_alerts: list[dict[str, Any]] | None = None
    fetch_audits: list[dict[str, Any]] | None = None
    stored_raw_records: list[dict[str, Any]] | None = None
    stored_raw_ids: list[str] | None = None
    ingest_audits: list[dict[str, Any]] | None = None
    raw_items: list[dict[str, Any]] | None = None
    query_telemetry: list[dict[str, Any]] | None = None
    collection_yield_summary: list[dict[str, Any]] | None = None
    llm_planning_audits: list[dict[str, Any]] | None = None
    llm_reflection_audits: list[dict[str, Any]] | None = None
    standardized_items: list[dict[str, Any]] | None = None
    llm_standardization_audits: list[dict[str, Any]] | None = None
    llm_bom_resolution_audits: list[dict[str, Any]] | None = None
    stix_bundle_refs: list[dict[str, Any]] | None = None
    llm_dedup_judgments: list[dict[str, Any]] | None = None
    dedup_decisions: list[dict[str, Any]] | None = None
    stable_attack_records: list[dict[str, Any]] | None = None
    merge_audits: list[dict[str, Any]] | None = None
    dedup_persist_summary: dict[str, Any] | None = None
    dedup_audit_summary: dict[str, Any] | None = None
    weak_signal_clusters: list[dict[str, Any]] | None = None
    coverage_gaps: list[dict[str, Any]] | None = None
    gap_fill_dispatch_plans: list[dict[str, Any]] | None = None
    llm_coverage_analysis_audits: list[dict[str, Any]] | None = None
    alert_candidates: list[dict[str, Any]] | None = None
    node_attempts: dict[str, int] | None = None
    node_results: list[dict[str, Any]] | None = None
    errors: list[dict[str, Any]] | None = None
    completed_nodes: list[str] | None = None
    processed_subject_ids: list[str] | None = None
    skipped_subject_ids: list[str] | None = None
    processed_count: int | None = None
    dedup_merged_count: int | None = None
    new_attack_count: int | None = None
    bom_queue_count: int | None = None
    reflection_round: int | None = None
    gap_fill_round: int | None = None
    reflection_needed: bool | None = None
    reflection_rationale: str | None = None
    gap_fill_needed: bool | None = None
    gap_fill_rationale: str | None = None
    resume_target_node: str | None = None
    current_node: str | None = None


def validate_patch(patch: dict[str, Any]) -> dict[str, Any]:
    return GraphNodePatchDTO.model_validate(patch).model_dump(
        mode="python", exclude_none=True
    )
