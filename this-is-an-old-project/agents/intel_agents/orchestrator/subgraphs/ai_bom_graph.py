from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from ...agents.bom_mapper_agent import BomMapperAgent
from ...agents.bom_resolution_reviewer_agent import BomResolutionReviewerAgent
from ...schemas.runtime import RuntimeContextDTO


class AiBomSubgraphState(TypedDict, total=False):
    standardized_items: list[dict[str, Any]]
    llm_bom_resolution_audits: list[dict[str, Any]]
    runtime_context: dict[str, Any]
    trace_id: str | None
    bom_queue_count: int


def _resolve_bom(state: AiBomSubgraphState) -> AiBomSubgraphState:
    context = RuntimeContextDTO.model_validate(state.get("runtime_context") or {})
    resolved_items, audits = BomMapperAgent(
        strategy=context.bom_resolution_strategy,
        llm_model=context.llm_model,
        llm_temperature=context.llm_temperature,
        validate_online=context.validate_llm_online,
        llm_runtime_config=context.model_dump(mode="python"),
        max_concurrency=context.bom_resolve_max_concurrency,
    ).resolve_batch(
        state.get("standardized_items", []),
        trace_id=state.get("trace_id"),
    )
    queue_count = sum(
        1
        for item in resolved_items
        for resolution in item.get("bom_resolutions", [])
        if resolution.get("resolution_status") != "resolved"
    )
    return {
        "standardized_items": resolved_items,
        "llm_bom_resolution_audits": audits,
        "bom_queue_count": queue_count,
    }


def _review_bom(state: AiBomSubgraphState) -> AiBomSubgraphState:
    context = RuntimeContextDTO.model_validate(state.get("runtime_context") or {})
    reviewed = BomResolutionReviewerAgent(
        strategy=context.bom_resolution_strategy,
        llm_model=context.llm_model,
        llm_temperature=context.llm_temperature,
        validate_online=context.validate_llm_online,
        llm_runtime_config=context.model_dump(mode="python"),
        max_concurrency=context.bom_review_max_concurrency,
    ).review_batch(state.get("standardized_items", []))
    pending_summary = {
        **state.get("runtime_context", {}).get("pending_queue_summary", {}),
        "unresolved_bom": reviewed["bom_queue_count"],
    }
    return {
        "standardized_items": reviewed["standardized_items"],
        "llm_bom_resolution_audits": state.get("llm_bom_resolution_audits", []),
        "bom_queue_count": reviewed["bom_queue_count"],
        "runtime_context": {
            **state.get("runtime_context", {}),
            "pending_queue_summary": pending_summary,
        },
    }


def _persist_bom(state: AiBomSubgraphState) -> AiBomSubgraphState:
    context = RuntimeContextDTO.model_validate(state.get("runtime_context") or {})
    persisted_items, queue_count = BomMapperAgent(
        strategy=context.bom_resolution_strategy,
        llm_model=context.llm_model,
        llm_temperature=context.llm_temperature,
        validate_online=context.validate_llm_online,
        llm_runtime_config=context.model_dump(mode="python"),
        max_concurrency=context.bom_resolve_max_concurrency,
    ).persist_batch(
        state.get("standardized_items", []),
        audits=state.get("llm_bom_resolution_audits", []),
        trace_id=state.get("trace_id"),
    )
    pending_summary = {
        **state.get("runtime_context", {}).get("pending_queue_summary", {}),
        "unresolved_bom": queue_count,
    }
    return {
        "standardized_items": persisted_items,
        "bom_queue_count": queue_count,
        "runtime_context": {
            **state.get("runtime_context", {}),
            "pending_queue_summary": pending_summary,
        },
    }


def build_ai_bom_subgraph():
    graph = StateGraph(AiBomSubgraphState)
    graph.add_node("resolve_bom", _resolve_bom)
    graph.add_node("review_bom", _review_bom)
    graph.add_node("persist_bom", _persist_bom)
    graph.set_entry_point("resolve_bom")
    graph.add_edge("resolve_bom", "review_bom")
    graph.add_edge("review_bom", "persist_bom")
    graph.add_edge("persist_bom", END)
    return graph.compile()


_GRAPH = build_ai_bom_subgraph()


def run_ai_bom_subgraph(state: dict[str, Any]) -> dict[str, Any]:
    result = _GRAPH.invoke(
        {
            "standardized_items": state.get("standardized_items", []),
            "runtime_context": state.get("runtime_context", {}),
            "trace_id": state.get("trace_id"),
            "llm_bom_resolution_audits": state.get("llm_bom_resolution_audits", []),
            "bom_queue_count": state.get("bom_queue_count", 0),
        }
    )
    return {
        "standardized_items": result.get("standardized_items", []),
        "llm_bom_resolution_audits": result.get("llm_bom_resolution_audits", []),
        "bom_queue_count": int(result.get("bom_queue_count", 0) or 0),
        "runtime_context": result.get("runtime_context", state.get("runtime_context", {})),
    }
