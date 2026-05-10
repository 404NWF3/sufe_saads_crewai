from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict
from uuid import uuid4

RunMode = Literal["bootstrap", "incremental", "gap_fill", "mixed"]
RunStatus = Literal["queued", "running", "partial_success", "succeeded", "failed"]


def merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    merged.update(right)
    return merged


class WP11GraphState(TypedDict, total=False):
    run_id: str
    trace_id: str
    started_at: str
    finished_at: str | None
    run_mode: RunMode
    run_status: RunStatus
    runtime_context: dict[str, Any]
    collection_plan: dict[str, Any] | None
    collection_coordination: dict[str, Any] | None
    collector_plans: dict[str, list[dict[str, Any]]]
    resume_hint: dict[str, Any] | None
    resume_target_node: str | None
    current_node: str | None

    source_cursors: Annotated[dict[str, dict[str, Any]], merge_dicts]
    source_execution_stats: Annotated[list[dict[str, Any]], operator.add]
    source_health_dashboard: Annotated[list[dict[str, Any]], operator.add]
    source_drift_alerts: Annotated[list[dict[str, Any]], operator.add]
    fetch_audits: Annotated[list[dict[str, Any]], operator.add]
    stored_raw_records: Annotated[list[dict[str, Any]], operator.add]
    stored_raw_ids: Annotated[list[str], operator.add]
    ingest_audits: Annotated[list[dict[str, Any]], operator.add]
    raw_items: Annotated[list[dict[str, Any]], operator.add]
    query_telemetry: Annotated[list[dict[str, Any]], operator.add]
    collection_yield_summary: Annotated[list[dict[str, Any]], operator.add]
    llm_planning_audits: Annotated[list[dict[str, Any]], operator.add]
    llm_reflection_audits: Annotated[list[dict[str, Any]], operator.add]
    standardized_items: list[dict[str, Any]]
    llm_standardization_audits: Annotated[list[dict[str, Any]], operator.add]
    llm_bom_resolution_audits: Annotated[list[dict[str, Any]], operator.add]
    stix_bundle_refs: Annotated[list[dict[str, Any]], operator.add]
    llm_dedup_judgments: Annotated[list[dict[str, Any]], operator.add]
    dedup_decisions: Annotated[list[dict[str, Any]], operator.add]
    stable_attack_records: list[dict[str, Any]]
    merge_audits: Annotated[list[dict[str, Any]], operator.add]
    dedup_persist_summary: dict[str, Any] | None
    dedup_audit_summary: dict[str, Any] | None
    weak_signal_clusters: Annotated[list[dict[str, Any]], operator.add]
    coverage_gaps: Annotated[list[dict[str, Any]], operator.add]
    gap_fill_dispatch_plans: Annotated[list[dict[str, Any]], operator.add]
    llm_coverage_analysis_audits: Annotated[list[dict[str, Any]], operator.add]
    alert_candidates: Annotated[list[dict[str, Any]], operator.add]
    node_attempts: Annotated[dict[str, int], merge_dicts]
    node_results: Annotated[list[dict[str, Any]], operator.add]
    errors: Annotated[list[dict[str, Any]], operator.add]
    completed_nodes: Annotated[list[str], operator.add]
    processed_subject_ids: Annotated[list[str], operator.add]
    skipped_subject_ids: Annotated[list[str], operator.add]

    processed_count: int
    dedup_merged_count: int
    new_attack_count: int
    bom_queue_count: int
    reflection_round: int
    gap_fill_round: int
    reflection_needed: bool
    reflection_rationale: str
    gap_fill_needed: bool
    gap_fill_rationale: str


def build_initial_state(
    *,
    run_mode: RunMode = "bootstrap",
    runtime_context: dict[str, Any] | None = None,
    run_id: str | None = None,
    trace_id: str | None = None,
    resume_target_node: str | None = None,
) -> WP11GraphState:
    return {
        "run_id": run_id or f"run_{uuid4().hex[:12]}",
        "trace_id": trace_id or f"trace_{uuid4().hex[:16]}",
        "run_mode": run_mode,
        "run_status": "queued",
        "runtime_context": runtime_context or {},
        "collection_plan": None,
        "collection_coordination": None,
        "collector_plans": {},
        "resume_hint": None,
        "resume_target_node": resume_target_node,
        "current_node": None,
        "source_cursors": {},
        "source_execution_stats": [],
        "source_health_dashboard": [],
        "source_drift_alerts": [],
        "fetch_audits": [],
        "stored_raw_records": [],
        "stored_raw_ids": [],
        "ingest_audits": [],
        "raw_items": [],
        "query_telemetry": [],
        "collection_yield_summary": [],
        "llm_planning_audits": [],
        "llm_reflection_audits": [],
        "standardized_items": [],
        "llm_standardization_audits": [],
        "llm_bom_resolution_audits": [],
        "stix_bundle_refs": [],
        "llm_dedup_judgments": [],
        "dedup_decisions": [],
        "stable_attack_records": [],
        "merge_audits": [],
        "dedup_persist_summary": None,
        "dedup_audit_summary": None,
        "weak_signal_clusters": [],
        "coverage_gaps": [],
        "gap_fill_dispatch_plans": [],
        "llm_coverage_analysis_audits": [],
        "alert_candidates": [],
        "node_attempts": {},
        "node_results": [],
        "errors": [],
        "completed_nodes": [],
        "processed_subject_ids": [],
        "skipped_subject_ids": [],
        "processed_count": 0,
        "dedup_merged_count": 0,
        "new_attack_count": 0,
        "bom_queue_count": 0,
        "reflection_round": 0,
        "gap_fill_round": 0,
        "reflection_needed": False,
        "reflection_rationale": "",
        "gap_fill_needed": False,
        "gap_fill_rationale": "",
    }
