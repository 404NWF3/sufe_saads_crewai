from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast
from langgraph.checkpoint.memory import MemorySaver

from ..schemas.runtime import RuntimeContextDTO
from .graph import build_phase1_graph
from .state import RunMode, WP11GraphState, build_initial_state


@dataclass
class Phase1GraphRuntime:
    """Phase 1 runtime wrapper around the WP1-1 LangGraph skeleton."""

    checkpointer: Any | None = None
    app: Any = field(init=False)

    def __post_init__(self) -> None:
        self.checkpointer = self.checkpointer or MemorySaver()
        self.app = build_phase1_graph(checkpointer=self.checkpointer)

    def invoke(self, initial_state: WP11GraphState) -> dict[str, Any]:
        run_id = initial_state.get("run_id")
        if run_id is None:
            raise ValueError("initial_state must include run_id")
        config: Any = {"configurable": {"thread_id": run_id}}
        return self.app.invoke(initial_state, config=config)

    def get_state(self, run_id: str) -> dict[str, Any]:
        config: Any = {"configurable": {"thread_id": run_id}}
        return dict(self.app.get_state(config).values)

    def recover(
        self,
        run_id: str,
        *,
        reuse_run_id: bool = False,
        runtime_context_override: dict[str, Any] | None = None,
        resume_from_node: str | None = None,
        replay_query_run_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        recovered_state = self.prepare_recovered_state(
            run_id,
            reuse_run_id=reuse_run_id,
            runtime_context_override=runtime_context_override,
            resume_from_node=resume_from_node,
            replay_query_run_ids=replay_query_run_ids,
        )
        return self.invoke(recovered_state)

    def prepare_recovered_state(
        self,
        run_id: str,
        *,
        reuse_run_id: bool = False,
        runtime_context_override: dict[str, Any] | None = None,
        resume_from_node: str | None = None,
        replay_query_run_ids: list[str] | None = None,
    ) -> WP11GraphState:
        saved_state = self.get_state(run_id)
        saved_run_mode = cast(RunMode, saved_state.get("run_mode", "bootstrap"))
        merged_context = {
            **(saved_state.get("runtime_context") or {}),
            **(runtime_context_override or {}),
        }
        if resume_from_node:
            merged_context["resume_policy"] = "from_node"
            merged_context["resume_from_node"] = resume_from_node
            merged_context["skip_completed_nodes"] = True
        if replay_query_run_ids:
            merged_context["resume_policy"] = "partial_replay"
            merged_context["resume_from_node"] = resume_from_node or "store_raw_records"
            merged_context["replay_query_run_ids"] = replay_query_run_ids
            merged_context["skip_completed_nodes"] = True
        recovered_state = build_initial_state(
            run_mode=saved_run_mode,
            runtime_context=merged_context,
            run_id=run_id if reuse_run_id else None,
            trace_id=saved_state.get("trace_id"),
            resume_target_node=resume_from_node,
        )
        if merged_context.get("skip_completed_nodes"):
            completed_nodes = list(saved_state.get("completed_nodes", []))
            if resume_from_node:
                completed_nodes = _prune_completed_nodes(
                    completed_nodes, resume_from_node
                )
            recovered_state["completed_nodes"] = completed_nodes
            recovered_state["stored_raw_records"] = list(
                saved_state.get("stored_raw_records", [])
            )
            recovered_state["stored_raw_ids"] = list(
                saved_state.get("stored_raw_ids", [])
            )
            recovered_state["raw_items"] = list(saved_state.get("raw_items", []))
            recovered_state["source_cursors"] = dict(
                saved_state.get("source_cursors", {})
            )
            recovered_state["collection_plan"] = saved_state.get("collection_plan")
            recovered_state["collection_coordination"] = saved_state.get(
                "collection_coordination"
            )
            recovered_state["collector_plans"] = dict(
                saved_state.get("collector_plans", {})
            )
        return recovered_state

    def invoke_stub_run(
        self,
        *,
        run_mode: RunMode = "bootstrap",
        fail_once_nodes: list[str] | None = None,
        always_fail_nodes: list[str] | None = None,
        force_low_yield: bool = False,
        force_gap_fill: bool = False,
        force_no_results: bool = False,
    ) -> dict[str, Any]:
        runtime_context = RuntimeContextDTO.default_stub(
            run_mode=run_mode,
            fail_once_nodes=fail_once_nodes or [],
            always_fail_nodes=always_fail_nodes or [],
            force_low_yield=force_low_yield,
            force_gap_fill=force_gap_fill,
            force_no_results=force_no_results,
        )
        state = build_initial_state(
            run_mode=run_mode,
            runtime_context=runtime_context.model_dump(mode="python"),
        )
        return self.invoke(state)

    def invoke_live_run(
        self,
        *,
        run_mode: RunMode = "bootstrap",
        coverage_max_gap_fill_rounds: int = 1,
    ) -> dict[str, Any]:
        runtime_context = RuntimeContextDTO.default_live(
            run_mode=run_mode,
            coverage_max_gap_fill_rounds=coverage_max_gap_fill_rounds,
        )
        state = build_initial_state(
            run_mode=run_mode,
            runtime_context=runtime_context.model_dump(mode="python"),
        )
        return self.invoke(state)


def _prune_completed_nodes(
    completed_nodes: list[str], resume_from_node: str
) -> list[str]:
    node_order = [
        "load_runtime_context",
        "supervisor_plan",
        "dispatch_collection",
        "collect_structured_sources",
        "collect_code_sources",
        "collect_paper_sources",
        "collect_community_sources",
        "collect_advisory_sources",
        "store_raw_records",
        "assess_collection_yield",
        "reflect_search_strategy",
        "parse_and_standardize",
        "semantic_dedup_and_merge",
        "resolve_ai_bom",
        "review_ai_bom_resolution",
        "build_stix_graph",
        "score_confidence_and_novelty",
        "refresh_coverage_view",
        "coverage_gap_analysis",
        "weak_signal_mining",
        "generate_alerts",
        "finalize_run",
    ]
    if resume_from_node not in node_order:
        return completed_nodes
    cutoff = node_order.index(resume_from_node)
    allowed = set(node_order[:cutoff])
    return [node for node in completed_nodes if node in allowed]
