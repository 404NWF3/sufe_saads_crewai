from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

from langgraph.types import Send

from ..agents.bom_mapper_agent import BomMapperAgent
from ..agents.bom_resolution_reviewer_agent import BomResolutionReviewerAgent
from ..agents.coverage_analyst_agent import CoverageAnalystAgent
from ..agents.dedup_adjudicator_agent import DedupAdjudicatorAgent
from ..agents.dedup_merge_agent import DedupMergeAgent
from ..agents.search_reflection_agent import SearchReflectionAgent
from ..agents.standardizer_agent import StandardizerAgent
from ..agents.supervisor_agent import SupervisorAgent
from ..crews import SourceCollectionCrew
from ..schemas import validate_patch
from ..schemas.alert import AlertCandidateDTO, CoverageGapDTO, NodeErrorDTO
from ..schemas.intel import DedupDecisionDTO, RawCollectedItemDTO, StandardizedIntelDTO
from ..schemas.plan import CollectionPlanDTO
from ..schemas.query import (
    CollectionYieldSummaryDTO,
    LlmPlanningAuditDTO,
    LlmSearchReflectionAuditDTO,
    NodeResultDTO,
    QueryTelemetryDTO,
)
from ..schemas.runtime import RuntimeContextDTO
from ..services.attack_signature_memory import AttackSignatureMemory
from ..services.confidence_scoring_service import ConfidenceScoringService
from ..services.coverage_read_model_service import CoverageReadModelService
from ..services.dedup_memory_service import DedupMemoryService
from ..services.gap_scoring_service import GapScoringService
from ..services.query_feedback_memory import QueryFeedbackMemoryService
from ..services.raw_ingest_flow import RawIngestFlow
from ..services.source_health_service import SourceHealthService
from ..tools.llm_client_factory import LlmInvocationError
from .subgraphs import run_ai_bom_subgraph, run_stix_subgraph


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _with_state_defaults(state: dict[str, Any]) -> dict[str, Any]:
    cloned = deepcopy(state)
    cloned.setdefault("errors", [])
    cloned.setdefault("node_attempts", {})
    cloned.setdefault("node_results", [])
    cloned.setdefault("raw_items", [])
    cloned.setdefault("source_execution_stats", [])
    cloned.setdefault("source_health_dashboard", [])
    cloned.setdefault("source_drift_alerts", [])
    cloned.setdefault("fetch_audits", [])
    cloned.setdefault("stored_raw_records", [])
    cloned.setdefault("stored_raw_ids", [])
    cloned.setdefault("ingest_audits", [])
    cloned.setdefault("query_telemetry", [])
    cloned.setdefault("collection_yield_summary", [])
    cloned.setdefault("llm_planning_audits", [])
    cloned.setdefault("llm_reflection_audits", [])
    cloned.setdefault("standardized_items", [])
    cloned.setdefault("llm_standardization_audits", [])
    cloned.setdefault("llm_bom_resolution_audits", [])
    cloned.setdefault("stix_bundle_refs", [])
    cloned.setdefault("llm_dedup_judgments", [])
    cloned.setdefault("dedup_decisions", [])
    cloned.setdefault("dedup_persist_summary", None)
    cloned.setdefault("dedup_audit_summary", None)
    cloned.setdefault("weak_signal_clusters", [])
    cloned.setdefault("coverage_gaps", [])
    cloned.setdefault("gap_fill_dispatch_plans", [])
    cloned.setdefault("llm_coverage_analysis_audits", [])
    cloned.setdefault("alert_candidates", [])
    cloned.setdefault("completed_nodes", [])
    cloned.setdefault("processed_subject_ids", [])
    cloned.setdefault("skipped_subject_ids", [])
    cloned.setdefault("reflection_round", 0)
    cloned.setdefault("gap_fill_round", 0)
    cloned.setdefault("gap_fill_needed", False)
    cloned.setdefault("gap_fill_rationale", "")
    cloned.setdefault("collector_plans", {})
    cloned.setdefault("resume_hint", None)
    return cloned


def _runtime_context(state: dict[str, Any]) -> RuntimeContextDTO:
    return RuntimeContextDTO.model_validate(state.get("runtime_context") or {})


def _record_node_result(
    state: dict[str, Any],
    *,
    node_name: str,
    status: str,
    attempts: int,
    summary: str,
    reason: str | None = None,
    retryable: bool = False,
    subject_id: str | None = None,
    artifact_ref: str | None = None,
) -> list[dict[str, Any]]:
    return [
        NodeResultDTO(
            node_name=node_name,
            status=status,
            attempts=attempts,
            started_at=_utcnow(),
            finished_at=_utcnow(),
            summary=summary,
            reason=reason,
            retryable=retryable,
            subject_id=subject_id,
            artifact_ref=artifact_ref,
        ).model_dump(mode="python")
    ]


def _record_error(
    state: dict[str, Any],
    *,
    node_name: str,
    exc: Exception,
    retryable: bool,
    subject_id: str | None = None,
) -> list[dict[str, Any]]:
    return [
        NodeErrorDTO(
            node_name=node_name,
            error_type=exc.__class__.__name__,
            message=str(exc),
            subject_id=subject_id,
            retryable=retryable,
            trace_id=state.get("trace_id"),
            occurred_at=_utcnow(),
        ).model_dump(mode="python")
    ]


def _find_llm_invocation_error(exc: Exception) -> LlmInvocationError | None:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, LlmInvocationError):
            return current
        current = current.__cause__ or current.__context__
    return None


def _build_resume_hint(
    state: dict[str, Any], *, node_name: str, exc: Exception
) -> dict[str, Any] | None:
    context = _runtime_context(state)
    if not context.llm_resume_on_exhausted_retry:
        return None
    llm_error = _find_llm_invocation_error(exc)
    if llm_error is None:
        return None
    resume_map = {
        "parse_and_standardize": "parse_and_standardize",
        "resolve_ai_bom": "resolve_ai_bom",
        "build_stix_graph": "build_stix_graph",
        "coverage_gap_analysis": "coverage_gap_analysis",
    }
    resume_from_node = resume_map.get(node_name)
    if resume_from_node is None:
        return None
    hint = {
        "resume_from_node": resume_from_node,
        "reason": str(exc),
        "error_family": llm_error.error_family,
        "recommended_tuning_changes": list(llm_error.recommended_tuning_changes),
        "attempted_profiles": list(llm_error.attempted_profiles),
        "attempted_profile_labels": list(llm_error.attempted_profile_labels),
        "failed_profile_errors": list(llm_error.failed_profile_errors),
    }
    if llm_error.retry_after_seconds > 0:
        hint["retry_after_seconds"] = llm_error.retry_after_seconds
    return hint


def _maybe_inject_failure(state: dict[str, Any], node_name: str, attempt: int) -> None:
    context = _runtime_context(state)
    injection = context.failure_injection
    if injection is None:
        return
    aliases = {node_name}
    if node_name.startswith("collect_") and node_name.endswith("_sources"):
        aliases.add("collect_from_sources")
    if any(alias in injection.always_fail_nodes for alias in aliases):
        raise RuntimeError(f"Injected persistent failure for node '{node_name}'.")
    if any(alias in injection.fail_once_nodes for alias in aliases) and attempt == 1:
        raise RuntimeError(f"Injected transient failure for node '{node_name}'.")


def _should_skip_node(state: dict[str, Any], node_name: str) -> bool:
    context = _runtime_context(state)
    return context.skip_completed_nodes and node_name in state.get(
        "completed_nodes", []
    )


def _finalize_success_patch(
    current_state: dict[str, Any], node_name: str, attempt: int, patch: dict[str, Any]
) -> dict[str, Any]:
    validated_patch = validate_patch(patch)
    validated_patch.setdefault("node_attempts", {node_name: attempt})
    validated_patch.setdefault(
        "node_results",
        _record_node_result(
            current_state,
            node_name=node_name,
            status="succeeded",
            attempts=attempt,
            summary=f"{node_name} completed successfully.",
        ),
    )
    validated_patch.setdefault("completed_nodes", [node_name])
    return validate_patch(validated_patch)


def _execute_with_retries(
    state: dict[str, Any],
    node_name: str,
    worker: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    max_attempts: int = 2,
) -> dict[str, Any]:
    current_state = _with_state_defaults(state)
    if _should_skip_node(current_state, node_name):
        return validate_patch(
            {
                "node_results": _record_node_result(
                    current_state,
                    node_name=node_name,
                    status="succeeded",
                    attempts=current_state.get("node_attempts", {}).get(node_name, 0)
                    or 1,
                    summary=f"{node_name} skipped because it already completed in a previous run.",
                ),
            }
        )

    attempt_patch: dict[str, int] = {}
    for attempt in range(1, max_attempts + 1):
        attempt_patch = {node_name: attempt}
        try:
            _maybe_inject_failure(current_state, node_name, attempt)
            patch = worker(current_state)
            return _finalize_success_patch(current_state, node_name, attempt, patch)
        except Exception as exc:
            llm_error = _find_llm_invocation_error(exc)
            should_retry_node = attempt < max_attempts and llm_error is None
            retryable = should_retry_node or llm_error is not None
            if should_retry_node:
                continue
            return validate_patch(
                {
                    "node_attempts": attempt_patch,
                    "node_results": _record_node_result(
                        current_state,
                        node_name=node_name,
                        status="failed",
                        attempts=attempt,
                        summary=f"{node_name} failed after retries.",
                        reason=str(exc),
                    ),
                    "errors": _record_error(
                        current_state,
                        node_name=node_name,
                        exc=exc,
                        retryable=retryable,
                    ),
                    "resume_hint": _build_resume_hint(
                        current_state,
                        node_name=node_name,
                        exc=exc,
                    ),
                }
            )
    return {}


def load_runtime_context_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = RuntimeContextDTO.ensure_defaults(
            current_state.get("runtime_context") or {}
        )
        return {
            "started_at": current_state.get("started_at") or _utcnow(),
            "run_status": "running",
            "run_mode": context.run_mode,
            "runtime_context": context.model_dump(mode="python"),
            "source_cursors": context.cursor_state,
            "resume_target_node": context.resume_from_node,
        }

    return _execute_with_retries(state, "load_runtime_context", worker, max_attempts=1)


def supervisor_plan_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        plan, audit = SupervisorAgent(
            strategy=context.planning_strategy,
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            validate_online=context.validate_llm_online,
            llm_runtime_config=context.model_dump(mode="python"),
        ).plan_run(
            context.model_dump(mode="python"),
            context.coverage_snapshot,
            context.source_quality_rows,
            query_feedback_rows=context.query_feedback_rows,
        )
        return {
            "collection_plan": CollectionPlanDTO.model_validate(plan).model_dump(
                mode="python"
            ),
            "llm_planning_audits": [
                LlmPlanningAuditDTO.model_validate(audit).model_dump(mode="python")
            ],
        }

    return _execute_with_retries(state, "supervisor_plan", worker)


def dispatch_collection_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        plan = CollectionPlanDTO.model_validate(
            current_state.get("collection_plan") or {}
        )
        coordination = SourceCollectionCrew().collaboration_service.coordinate(
            [plan_item.model_dump(mode="python") for plan_item in plan.source_plans],
            run_mode=current_state.get("run_mode", plan.run_mode),
            trace_id=current_state["trace_id"],
            planning_audits=current_state.get("llm_planning_audits", []),
            reflection_audits=current_state.get("llm_reflection_audits", []),
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            llm_runtime_config=context.model_dump(mode="python"),
        )
        coordination = {
            **coordination,
            "planning_audits": current_state.get("llm_planning_audits", []),
            "reflection_audits": current_state.get("llm_reflection_audits", []),
        }
        collector_plans = {
            "StructuredIntelCollector": [],
            "CodeSecurityCollector": [],
            "PaperIntelCollector": [],
            "CommunitySignalCollector": [],
            "AdvisoryCollector": [],
        }
        raw_assignments = coordination.get("assignments", [])
        assignment_map = {
            assignment.get("source_name", ""): assignment
            for assignment in raw_assignments
            if isinstance(assignment, dict) and assignment.get("source_name")
        }
        for plan_item in plan.source_plans:
            dump = plan_item.model_dump(mode="python")
            collector_role = assignment_map.get(plan_item.source_name, {}).get(
                "collector_role"
            )
            if collector_role:
                collector_plans.setdefault(collector_role, []).append(dump)
        return {
            "collection_plan": {
                **plan.model_dump(mode="python"),
                "source_plans": [
                    p.model_dump(mode="python") for p in plan.source_plans
                ],
            },
            "collection_coordination": coordination,
            "collector_plans": collector_plans,
        }

    return _execute_with_retries(state, "dispatch_collection", worker, max_attempts=1)


# ---------------------------------------------------------------------------
# Send API fan-out router for the 5 collection nodes
# ---------------------------------------------------------------------------

_COLLECTOR_ROLE_TO_NODE: dict[str, str] = {
    "StructuredIntelCollector": "collect_structured_sources",
    "CodeSecurityCollector": "collect_code_sources",
    "PaperIntelCollector": "collect_paper_sources",
    "CommunitySignalCollector": "collect_community_sources",
    "AdvisoryCollector": "collect_advisory_sources",
}


def route_collectors_fan_out(state: dict[str, Any]) -> list[Send]:
    """Send API router: spawn one Send per collector role that has assigned plans.

    Only roles with non-empty collector_plans entries are spawned, avoiding
    no-op node invocations for roles with no source assignments.  If all
    roles are empty (degraded / bootstrap edge case), all 5 nodes are sent
    so the graph never stalls at the fan-in.
    """
    collector_plans: dict[str, list] = state.get("collector_plans") or {}
    full_state = dict(state)
    sends = [
        Send(node_name, full_state)
        for role, node_name in _COLLECTOR_ROLE_TO_NODE.items()
        if collector_plans.get(role)
    ]
    if not sends:
        sends = [Send(node_name, full_state) for node_name in _COLLECTOR_ROLE_TO_NODE.values()]
    return sends


def _collector_node(
    state: dict[str, Any], *, collector_role: str, node_name: str
) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        plan = CollectionPlanDTO.model_validate(
            current_state.get("collection_plan") or {}
        )
        collector_plans = current_state.get("collector_plans", {})
        selected_plans = collector_plans.get(collector_role, [])
        if not selected_plans:
            return {
                "node_results": _record_node_result(
                    current_state,
                    node_name=node_name,
                    status="succeeded",
                    attempts=1,
                    summary=f"{node_name} had no assigned source plans.",
                ),
                "completed_nodes": [node_name],
            }
        crew = SourceCollectionCrew()
        collected = crew.collect(
            selected_plans,
            trace_id=current_state["trace_id"],
            run_mode=current_state.get("run_mode", context.run_mode),
            reflection_round=current_state.get("reflection_round", 0),
            runtime_mode=context.source_runtime_mode,
            retry_attempts=context.source_retry_attempts,
            request_timeout_seconds=context.source_request_timeout_seconds,
            artifact_store_dir=context.artifact_store_dir,
            source_registry_overrides=None,
            source_cursors=current_state.get("source_cursors", {}),
            force_no_results=context.failure_injection.force_no_results
            if context.failure_injection
            else False,
            max_parallel_sources=max(
                1, min(plan.max_parallel_sources, len(selected_plans))
            ),
            prefer_db_source_registry=context.prefer_db_source_registry,
            collector_role_filter=collector_role,
            collection_coordination=current_state.get("collection_coordination"),
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            llm_runtime_config=context.model_dump(mode="python"),
        )
        return {
            "raw_items": [
                RawCollectedItemDTO.model_validate(item).model_dump(mode="python")
                for item in collected["raw_items"]
            ],
            "source_execution_stats": collected["source_execution_stats"],
            "source_cursors": collected["source_cursors"],
            "fetch_audits": collected.get("fetch_audits", []),
        }

    return _execute_with_retries(state, node_name, worker)


def collect_structured_sources_node(state: dict[str, Any]) -> dict[str, Any]:
    return _collector_node(
        state,
        collector_role="StructuredIntelCollector",
        node_name="collect_structured_sources",
    )


def collect_code_sources_node(state: dict[str, Any]) -> dict[str, Any]:
    return _collector_node(
        state, collector_role="CodeSecurityCollector", node_name="collect_code_sources"
    )


def collect_paper_sources_node(state: dict[str, Any]) -> dict[str, Any]:
    return _collector_node(
        state, collector_role="PaperIntelCollector", node_name="collect_paper_sources"
    )


def collect_community_sources_node(state: dict[str, Any]) -> dict[str, Any]:
    return _collector_node(
        state,
        collector_role="CommunitySignalCollector",
        node_name="collect_community_sources",
    )


def collect_advisory_sources_node(state: dict[str, Any]) -> dict[str, Any]:
    return _collector_node(
        state, collector_role="AdvisoryCollector", node_name="collect_advisory_sources"
    )


def store_raw_records_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        ingestor = RawIngestFlow(context.artifact_store_dir, context.audit_store_dir)
        raw_items = current_state.get("raw_items", [])
        processed_query_run_ids = set(current_state.get("processed_subject_ids", []))
        if processed_query_run_ids:
            raw_items = [
                item
                for item in raw_items
                if str(item.get("query_run_id", "")) not in processed_query_run_ids
            ]
        stored_records, ingest_audits = ingestor.ingest(
            raw_items,
            run_id=current_state["run_id"],
            trace_id=current_state["trace_id"],
            persist_to_db=context.persist_raw_records_to_db,
            task_mode=context.collection_task_mode,
            trigger_type=context.collection_trigger_type,
            created_by=context.collection_created_by,
        )
        removed_payloads = []
        if context.cleanup_expired_payloads:
            removed_payloads = ingestor.cleanup_expired_payloads(
                retention_days=context.payload_retention_days
            )
        return {
            "stored_raw_records": stored_records,
            "stored_raw_ids": [item["raw_id"] for item in stored_records],
            "ingest_audits": ingest_audits,
            "processed_count": len(stored_records),
            "runtime_context": {
                **current_state.get("runtime_context", {}),
                "payload_cleanup_removed": removed_payloads,
                "latest_ingested_query_run_ids": [
                    item["query_run_id"] for item in stored_records
                ],
            },
            "processed_subject_ids": [item["query_run_id"] for item in stored_records],
        }

    return _execute_with_retries(state, "store_raw_records", worker)


def assess_collection_yield_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        telemetry_rows: list[dict[str, Any]] = []
        summary_rows: list[dict[str, Any]] = []
        force_low_yield = (
            context.failure_injection.force_low_yield
            if context.failure_injection
            else False
        )
        latest_query_run_ids = set(context.latest_ingested_query_run_ids or [])
        stats = current_state.get("source_execution_stats", [])
        raw_items = current_state.get("raw_items", [])
        if latest_query_run_ids:
            stats = [
                item
                for item in stats
                if str(item.get("query_run_id", "")) in latest_query_run_ids
            ]
            raw_items = [
                item
                for item in raw_items
                if str(item.get("query_run_id", "")) in latest_query_run_ids
            ]
        raw_by_query_run: dict[str, list[dict[str, Any]]] = {}
        for item in raw_items:
            raw_by_query_run.setdefault(str(item.get("query_run_id", "")), []).append(
                item
            )
        plan = CollectionPlanDTO.model_validate(
            current_state.get("collection_plan") or {}
        )
        source_plan_map = {
            row.source_name: row.model_dump(mode="python") for row in plan.source_plans
        }
        for stat in stats:
            result_count = 0 if force_low_yield else stat.get("item_count", 0)
            query_items = raw_by_query_run.get(str(stat.get("query_run_id", "")), [])
            parsed_count = 0 if force_low_yield else len(query_items)
            duplicate_count = max(0, result_count - parsed_count)
            new_candidate_count = max(0, parsed_count - duplicate_count)
            source_name = str(stat["source_name"])
            plan_row = source_plan_map.get(source_name, {})
            source_type = plan_row.get("source_type")
            query_intent = str(plan_row.get("query_intent", "broad_recall"))
            novelty_yield = (
                0.0
                if force_low_yield or parsed_count == 0
                else round(new_candidate_count / max(parsed_count, 1), 4)
            )
            noise_ratio = _estimate_noise_ratio(
                force_low_yield=force_low_yield,
                result_count=result_count,
                parsed_count=parsed_count,
                duplicate_count=duplicate_count,
                novelty_yield=novelty_yield,
                query_items=query_items,
                query_intent=query_intent,
                source_type=source_type,
            )
            llm_hint = _build_reflection_hint(
                result_count=result_count,
                novelty_yield=novelty_yield,
                noise_ratio=noise_ratio,
                source_mismatch=not stat.get("success", True),
                query_intent=query_intent,
                source_type=source_type,
            )
            telemetry_rows.append(
                QueryTelemetryDTO(
                    query_run_id=stat["query_run_id"],
                    source_name=source_name,
                    source_type=source_type,
                    query_text=stat["query_text"],
                    query_intent=query_intent,
                    query_provenance=plan_row.get("query_provenance"),
                    rewrite_round=current_state.get("reflection_round", 0),
                    rewrite_reason=plan_row.get("rewrite_reason"),
                    result_count=result_count,
                    parsed_count=parsed_count,
                    duplicate_count=duplicate_count,
                    new_candidate_count=new_candidate_count,
                    novelty_yield=novelty_yield,
                    noise_ratio=noise_ratio,
                    source_mismatch=not stat.get("success", True),
                    time_window_days=plan_row.get("time_window_days"),
                    llm_reflection_hint=llm_hint,
                ).model_dump(mode="python")
            )
            summary_rows.append(
                CollectionYieldSummaryDTO(
                    source_name=source_name,
                    total_queries=1,
                    total_results=result_count,
                    total_parsed=parsed_count,
                    low_yield=force_low_yield or result_count == 0,
                    high_noise=force_low_yield or noise_ratio > 0.6,
                    reflection_recommended=(
                        force_low_yield
                        or result_count == 0
                        or noise_ratio > 0.6
                        or (not stat.get("success", True))
                    ),
                    recommended_actions=(
                        ["broaden_query", "switch_template"]
                        if force_low_yield or result_count == 0
                        else []
                    ),
                    reflection_evidence_summary=llm_hint,
                ).model_dump(mode="python")
            )
        dashboard, drift_alerts = SourceHealthService().build_dashboard(
            stats,
            drift_threshold=context.source_health_drift_threshold,
        )
        return {
            "query_telemetry": telemetry_rows,
            "collection_yield_summary": summary_rows,
            "source_health_dashboard": dashboard,
            "source_drift_alerts": drift_alerts,
        }

    return _execute_with_retries(state, "assess_collection_yield", worker)


def reflect_search_strategy_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        plan = CollectionPlanDTO.model_validate(
            current_state.get("collection_plan") or {}
        )
        reflection_result, audit, feedback_rows = SearchReflectionAgent(
            strategy=context.reflection_strategy,
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            validate_online=context.validate_llm_online,
            llm_runtime_config=context.model_dump(mode="python"),
        ).reflect(
            current_state.get("source_execution_stats", []),
            current_state.get("query_telemetry", []),
            {
                "run_mode": context.run_mode,
                "max_reflection_rounds": plan.max_reflection_rounds,
                "reflection_round": current_state.get("reflection_round", 0),
            },
            query_feedback_rows=context.query_feedback_rows,
        )
        audit_row = LlmSearchReflectionAuditDTO.model_validate(audit).model_dump(
            mode="python"
        )
        # Persist new feedback rows to DB (enables cross-run adaptive adjustment)
        updated_feedback = QueryFeedbackMemoryService().append_feedback(
            context.query_feedback_rows,
            feedback_rows,
            run_id=current_state.get("run_id"),
            trace_id=current_state.get("trace_id"),
        )
        patch: dict[str, Any] = {
            "reflection_needed": reflection_result["should_retry"],
            "reflection_rationale": reflection_result["evidence_summary"],
            "gap_fill_needed": False,
            "gap_fill_rationale": "",
            "llm_reflection_audits": [audit_row],
            "runtime_context": {
                **current_state.get("runtime_context", {}),
                "query_feedback_rows": updated_feedback,
            },
        }
        if reflection_result["should_retry"]:
            source_plans = deepcopy(plan.source_plans)
            rewrite_map: dict[str, dict[str, Any]] = {}
            for entry in reflection_result["rewritten_queries"]:
                rewrite_map[str(entry["source_name"])] = entry
            updated_plans = []
            for source_plan in source_plans:
                rewrite = rewrite_map.get(source_plan.source_name)
                if rewrite:
                    source_plan.queries = [rewrite["query_text"]]
                    source_plan.query_intent = rewrite["query_intent"]
                    source_plan.rewrite_reason = rewrite["rewrite_reason"]
                    source_plan.query_provenance = "phase6_reflection_rewrite"
                updated_plans.append(source_plan.model_dump(mode="python"))
            patch["collection_plan"] = {
                **plan.model_dump(mode="python"),
                "source_plans": updated_plans,
            }
            patch["reflection_round"] = current_state.get("reflection_round", 0) + 1
            patch["collection_coordination"] = None
        return patch

    return _execute_with_retries(
        state, "reflect_search_strategy", worker, max_attempts=1
    )


def _build_reflection_hint(
    *,
    result_count: int,
    novelty_yield: float,
    noise_ratio: float,
    source_mismatch: bool,
    query_intent: str,
    source_type: str | None,
) -> str:
    if source_mismatch:
        return (
            f"Source mismatch suspected for source_type={source_type or 'unknown'} "
            f"under query_intent={query_intent}."
        )
    if result_count == 0 or novelty_yield < 0.2:
        return f"Low recall signature: result_count={result_count}, novelty_yield={novelty_yield}."
    if noise_ratio > 0.6:
        return f"High noise signature: noise_ratio={noise_ratio}."
    return "Telemetry suggests query is productive or near saturation."


def _estimate_noise_ratio(
    *,
    force_low_yield: bool,
    result_count: int,
    parsed_count: int,
    duplicate_count: int,
    novelty_yield: float,
    query_items: list[dict[str, Any]],
    query_intent: str,
    source_type: str | None,
) -> float:
    if force_low_yield:
        return 0.9
    if result_count <= 0:
        return 0.0

    duplicate_ratio = duplicate_count / max(result_count, 1)
    parse_drop_ratio = max(0.0, (result_count - parsed_count) / max(result_count, 1))
    low_relevance_ratio = 0.0
    sparse_summary_ratio = 0.0
    weak_signal_penalty = 0.0

    if query_items:
        low_relevance_count = 0
        sparse_summary_count = 0
        weak_signal_count = 0
        for item in query_items:
            relevance = float(item.get("relevance_score") or 0.0)
            summary = str(item.get("summary") or "")
            metadata = item.get("metadata") or {}
            if relevance < 0.7:
                low_relevance_count += 1
            if len(summary.strip()) < 40:
                sparse_summary_count += 1
            if metadata.get("execution_profile") == "weak_signal_scan":
                weak_signal_count += 1
        low_relevance_ratio = low_relevance_count / len(query_items)
        sparse_summary_ratio = sparse_summary_count / len(query_items)
        weak_signal_penalty = weak_signal_count / len(query_items)

    source_prior = 0.0
    if source_type == "community":
        source_prior = 0.18
    elif source_type == "paper":
        source_prior = 0.06

    intent_prior = 0.0
    if query_intent == "weak_signal_probe":
        intent_prior = 0.15
    elif query_intent == "broad_recall":
        intent_prior = 0.08
    elif query_intent == "precision_probe":
        intent_prior = -0.08

    novelty_penalty = max(0.0, 1.0 - novelty_yield)
    score = (
        0.25 * duplicate_ratio
        + 0.15 * parse_drop_ratio
        + 0.20 * low_relevance_ratio
        + 0.15 * sparse_summary_ratio
        + 0.10 * weak_signal_penalty
        + 0.10 * novelty_penalty
        + source_prior
        + intent_prior
    )
    return round(min(1.0, max(0.0, score)), 4)


def _forced_gap_fill_candidate() -> dict[str, Any]:
    return {
        "gap_id": "forced_gap::owasp-llm-01",
        "gap_axis": "taxonomy",
        "taxonomy_code": "OWASP-LLM-01",
        "taxonomy_name": "Prompt Injection",
        "attack_family": "prompt_injection",
        "current_attack_count": 0,
        "target_attack_count": 3,
        "gap_score": 0.95,
        "source_diversity_gap": 0.8,
        "component_coverage_gap": 0.7,
        "corroboration_gap": 0.6,
        "vendor_model_gap": 0.0,
        "severity_pressure": 0.6,
        "recent_activity_score": 0.4,
        "estimated_gap_fill_roi": 0.8,
        "evidence_summary": "Forced gap-fill candidate for testing.",
    }


def parse_and_standardize_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        standardized, llm_audits = StandardizerAgent(
            strategy=context.standardization_strategy,
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            validate_online=context.validate_llm_online,
            llm_runtime_config=context.model_dump(mode="python"),
            standardization_max_concurrency=context.standardization_max_concurrency,
        ).standardize_batch(
            current_state.get("raw_items", []),
            current_state.get("stored_raw_records", []),
        )
        validated = [
            StandardizedIntelDTO.model_validate(item).model_dump(mode="python")
            for item in standardized
        ]
        return {
            "standardized_items": validated,
            "llm_standardization_audits": llm_audits,
        }

    return _execute_with_retries(state, "parse_and_standardize", worker)


def semantic_dedup_and_merge_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        memory = DedupMemoryService(context.dedup_store_dir)
        existing_records = memory.load_records(trace_id=current_state.get("trace_id"))
        vector_memory = AttackSignatureMemory(
            base_dir=context.qdrant_local_path or context.dedup_store_dir,
            collection_name=context.qdrant_collection_name,
        )
        try:
            dedup_result, llm_dedup_judgments = DedupMergeAgent(
                vector_memory=vector_memory,
                adjudicator=DedupAdjudicatorAgent(
                    strategy=context.dedup_adjudication_strategy,
                    llm_model=context.llm_model,
                    llm_temperature=context.llm_temperature,
                    validate_online=context.validate_llm_online,
                    llm_runtime_config=context.model_dump(mode="python"),
                ),
                strategy=context.dedup_merge_strategy,
                llm_model=context.llm_model,
                llm_temperature=context.llm_temperature,
                validate_online=context.validate_llm_online,
                llm_runtime_config=context.model_dump(mode="python"),
            ).dedup_and_merge(
                current_state.get("standardized_items", []),
                existing_records=existing_records,
            )
        finally:
            vector_memory.close()
        persist_summary = memory.save_records(
            dedup_result["stable_attack_records"],
            trace_id=current_state.get("trace_id"),
        )
        audit_summary = memory.append_audits(
            dedup_result["merge_audits"], trace_id=current_state.get("trace_id")
        )
        decisions = [
            DedupDecisionDTO.model_validate(item).model_dump(mode="python")
            for item in dedup_result["dedup_decisions"]
        ]
        return {
            "dedup_decisions": decisions,
            "stable_attack_records": dedup_result["stable_attack_records"],
            "merge_audits": dedup_result["merge_audits"],
            "dedup_persist_summary": persist_summary,
            "dedup_audit_summary": audit_summary,
            "llm_dedup_judgments": llm_dedup_judgments,
            "standardized_items": dedup_result["resolved_items"],
            "new_attack_count": dedup_result["new_attack_count"],
            "dedup_merged_count": dedup_result["dedup_merged_count"],
        }

    return _execute_with_retries(state, "semantic_dedup_and_merge", worker)


def resolve_ai_bom_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        return run_ai_bom_subgraph(current_state)

    return _execute_with_retries(state, "resolve_ai_bom", worker)


def review_ai_bom_resolution_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        mapper = BomMapperAgent(
            strategy=context.bom_resolution_strategy,
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            validate_online=context.validate_llm_online,
            llm_runtime_config=context.model_dump(mode="python"),
        )
        reviewed = BomResolutionReviewerAgent(
            strategy=context.bom_resolution_strategy,
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            validate_online=context.validate_llm_online,
            llm_runtime_config=context.model_dump(mode="python"),
        ).review_batch(
            current_state.get("standardized_items", [])
        )
        persisted_items, queue_count = mapper.persist_batch(
            reviewed["standardized_items"],
            audits=current_state.get("llm_bom_resolution_audits", []),
            trace_id=current_state.get("trace_id"),
        )
        pending_summary = {
            **current_state.get("runtime_context", {}).get("pending_queue_summary", {}),
            "unresolved_bom": queue_count,
        }
        return {
            "standardized_items": persisted_items,
            "bom_queue_count": queue_count,
            "runtime_context": {
                **current_state.get("runtime_context", {}),
                "pending_queue_summary": pending_summary,
            },
        }

    return _execute_with_retries(state, "review_ai_bom_resolution", worker)


def build_stix_graph_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        if context.stix_strategy == "disabled":
            return {"stix_bundle_refs": []}
        return run_stix_subgraph(current_state)

    return _execute_with_retries(state, "build_stix_graph", worker)


def score_confidence_and_novelty_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        scored = ConfidenceScoringService().score_items(
            deepcopy(current_state.get("standardized_items", [])),
            dedup_decisions=current_state.get("dedup_decisions", []),
            source_quality_rows=context.source_quality_rows,
        )
        return {"standardized_items": scored}

    return _execute_with_retries(state, "score_confidence_and_novelty", worker)


def refresh_coverage_view_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        service = CoverageReadModelService()
        stable_records = current_state.get("stable_attack_records", [])
        coverage_snapshot = service.build_taxonomy_component_source_view(stable_records)
        vendor_rows = service.build_vendor_model_source_view(stable_records)
        recent_summary = service.build_recent_attack_summary(stable_records)
        return {
            "runtime_context": {
                **current_state.get("runtime_context", {}),
                "coverage_snapshot": coverage_snapshot,
                "vendor_model_coverage_rows": vendor_rows,
                "recent_attacks_summary": recent_summary,
                "coverage_refreshed_at": _utcnow(),
            }
        }

    return _execute_with_retries(state, "refresh_coverage_view", worker, max_attempts=1)


def coverage_gap_analysis_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        should_force_gap = (
            context.failure_injection.force_gap_fill
            if context.failure_injection
            else False
        )
        scorer = GapScoringService()
        candidate_rows = scorer.rank_gap_candidates(
            [
                *scorer.score_taxonomy_gaps(context.coverage_snapshot),
                *scorer.score_vendor_model_gaps(context.vendor_model_coverage_rows),
            ],
            max_candidates=max(4, context.coverage_max_gap_fill_plans * 2),
        )
        if should_force_gap and not any(
            float(row.get("estimated_gap_fill_roi", 0.0))
            >= context.coverage_min_roi_threshold
            for row in candidate_rows
        ):
            candidate_rows = [
                _forced_gap_fill_candidate(),
                *candidate_rows,
            ]
        gaps, dispatch_plans, audits = CoverageAnalystAgent(
            strategy=context.coverage_strategy,
            llm_model=context.llm_model,
            llm_temperature=context.llm_temperature,
            validate_online=context.validate_llm_online,
            llm_runtime_config=context.model_dump(mode="python"),
        ).analyze(
            candidate_rows,
            runtime_context=current_state.get("runtime_context", {}),
            max_gap_fill_plans=context.coverage_max_gap_fill_plans,
            min_roi_threshold=context.coverage_min_roi_threshold,
        )
        should_trigger_gap_fill = bool(
            dispatch_plans
            and current_state.get("gap_fill_round", 0)
            < context.coverage_max_gap_fill_rounds
        )
        coverage_feedback_rows = [
            {
                "gap_id": gap.get("gap_id"),
                "gap_axis": gap.get("gap_axis"),
                "taxonomy_code": gap.get("taxonomy_code"),
                "vendor_name": gap.get("vendor_name"),
                "model_family": gap.get("model_family"),
                "framework_family": gap.get("framework_family"),
                "should_dispatch_gap_fill": gap.get("should_dispatch_gap_fill", False),
                "dispatch_priority": gap.get("dispatch_priority", 0.0),
                "estimated_gap_fill_roi": gap.get("estimated_gap_fill_roi", 0.0),
                "recommended_sources": gap.get("recommended_sources", []),
                "recommended_query_intents": gap.get("recommended_query_intents", []),
                "reason": gap.get("reason"),
                "captured_at": _utcnow(),
            }
            for gap in gaps
        ]
        return {
            "coverage_gaps": [
                CoverageGapDTO.model_validate(item).model_dump(mode="python")
                for item in gaps
            ],
            "gap_fill_dispatch_plans": dispatch_plans,
            "llm_coverage_analysis_audits": audits,
            "gap_fill_needed": should_trigger_gap_fill,
            "gap_fill_rationale": (
                "coverage_gap_fill_dispatch"
                if should_trigger_gap_fill
                else "coverage_gap_fill_not_required"
            ),
            "gap_fill_round": (
                current_state.get("gap_fill_round", 0) + 1
                if should_trigger_gap_fill
                else current_state.get("gap_fill_round", 0)
            ),
            "reflection_needed": False,
            "reflection_rationale": "",
            "run_mode": "gap_fill"
            if should_trigger_gap_fill
            else context.base_run_mode,
            "collection_coordination": None
            if should_trigger_gap_fill
            else current_state.get("collection_coordination"),
            "runtime_context": {
                **current_state.get("runtime_context", {}),
                "run_mode": (
                    "gap_fill" if should_trigger_gap_fill else context.base_run_mode
                ),
                "gap_fill_dispatch_plans": dispatch_plans,
                "coverage_feedback_rows": [
                    *(context.coverage_feedback_rows or []),
                    *coverage_feedback_rows,
                ][-200:],
            },
        }

    return _execute_with_retries(state, "coverage_gap_analysis", worker, max_attempts=1)


def weak_signal_mining_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        return {"weak_signal_clusters": []}

    return _execute_with_retries(state, "weak_signal_mining", worker, max_attempts=1)


def generate_alerts_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        alerts = []
        for gap in current_state.get("coverage_gaps", []):
            if gap.get("estimated_gap_fill_roi", 0.0) >= 0.75:
                alerts.append(
                    AlertCandidateDTO(
                        alert_type="coverage_gap",
                        severity="medium",
                        title=f"Coverage gap detected: {gap['taxonomy_name']}",
                        summary="Targeted coverage-gap alert candidate.",
                        related_attack_id=None,
                        related_cluster_id=None,
                        evidence_uris=[],
                        trigger_reason="gap_fill_roi_above_threshold",
                    ).model_dump(mode="python")
                )
        for drift in current_state.get("source_drift_alerts", []):
            alerts.append(
                AlertCandidateDTO(
                    alert_type="source_drift",
                    severity="low",
                    title=f"Source drift detected: {drift['source_name']}",
                    summary=f"Drift reason: {drift['drift_reason']}",
                    related_attack_id=None,
                    related_cluster_id=None,
                    evidence_uris=[],
                    trigger_reason="source_health_drift_detection",
                ).model_dump(mode="python")
            )
        return {"alert_candidates": alerts}

    return _execute_with_retries(state, "generate_alerts", worker, max_attempts=1)


def finalize_run_node(state: dict[str, Any]) -> dict[str, Any]:
    def worker(current_state: dict[str, Any]) -> dict[str, Any]:
        context = _runtime_context(current_state)
        has_errors = bool(current_state.get("errors"))
        status = "partial_success" if has_errors else "succeeded"
        return {
            "finished_at": _utcnow(),
            "run_status": status,
            "reflection_needed": False,
            "gap_fill_needed": False,
            "run_mode": context.base_run_mode,
            "runtime_context": {
                **current_state.get("runtime_context", {}),
                "run_mode": context.base_run_mode,
                "gap_fill_dispatch_plans": current_state.get(
                    "gap_fill_dispatch_plans", []
                ),
            },
        }

    return _execute_with_retries(state, "finalize_run", worker, max_attempts=1)
