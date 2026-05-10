from __future__ import annotations

from langgraph.graph import END, StateGraph
from langgraph.types import Send  # noqa: F401 — imported for Send API fan-out

from .nodes import (
    assess_collection_yield_node,
    build_stix_graph_node,
    collect_advisory_sources_node,
    collect_code_sources_node,
    collect_community_sources_node,
    collect_paper_sources_node,
    collect_structured_sources_node,
    coverage_gap_analysis_node,
    dispatch_collection_node,
    finalize_run_node,
    generate_alerts_node,
    load_runtime_context_node,
    parse_and_standardize_node,
    reflect_search_strategy_node,
    refresh_coverage_view_node,
    review_ai_bom_resolution_node,
    resolve_ai_bom_node,
    route_collectors_fan_out,
    score_confidence_and_novelty_node,
    semantic_dedup_and_merge_node,
    store_raw_records_node,
    supervisor_plan_node,
    weak_signal_mining_node,
)
from .router import (
    route_after_coverage_gap_analysis,
    route_after_reflection,
    route_after_runtime_load,
)
from .state import WP11GraphState


def build_phase1_graph(*, checkpointer=None):
    graph = StateGraph(WP11GraphState)

    graph.add_node("load_runtime_context", load_runtime_context_node)
    graph.add_node("supervisor_plan", supervisor_plan_node)
    graph.add_node("dispatch_collection", dispatch_collection_node)
    graph.add_node("collect_structured_sources", collect_structured_sources_node)
    graph.add_node("collect_code_sources", collect_code_sources_node)
    graph.add_node("collect_paper_sources", collect_paper_sources_node)
    graph.add_node("collect_community_sources", collect_community_sources_node)
    graph.add_node("collect_advisory_sources", collect_advisory_sources_node)
    graph.add_node("store_raw_records", store_raw_records_node)
    graph.add_node("assess_collection_yield", assess_collection_yield_node)
    graph.add_node("reflect_search_strategy", reflect_search_strategy_node)
    graph.add_node("parse_and_standardize", parse_and_standardize_node)
    graph.add_node("semantic_dedup_and_merge", semantic_dedup_and_merge_node)
    graph.add_node("resolve_ai_bom", resolve_ai_bom_node)
    graph.add_node("review_ai_bom_resolution", review_ai_bom_resolution_node)
    graph.add_node("build_stix_graph", build_stix_graph_node)
    graph.add_node("score_confidence_and_novelty", score_confidence_and_novelty_node)
    graph.add_node("refresh_coverage_view", refresh_coverage_view_node)
    graph.add_node("coverage_gap_analysis", coverage_gap_analysis_node)
    graph.add_node("weak_signal_mining", weak_signal_mining_node)
    graph.add_node("generate_alerts", generate_alerts_node)
    graph.add_node("finalize_run", finalize_run_node)

    graph.set_entry_point("load_runtime_context")
    graph.add_conditional_edges(
        "load_runtime_context",
        route_after_runtime_load,
        {
            "supervisor_plan": "supervisor_plan",
            "dispatch_collection": "dispatch_collection",
            "collect_structured_sources": "collect_structured_sources",
            "collect_code_sources": "collect_code_sources",
            "collect_paper_sources": "collect_paper_sources",
            "collect_community_sources": "collect_community_sources",
            "collect_advisory_sources": "collect_advisory_sources",
            "store_raw_records": "store_raw_records",
            "assess_collection_yield": "assess_collection_yield",
            "reflect_search_strategy": "reflect_search_strategy",
            "parse_and_standardize": "parse_and_standardize",
            "semantic_dedup_and_merge": "semantic_dedup_and_merge",
            "resolve_ai_bom": "resolve_ai_bom",
            "review_ai_bom_resolution": "review_ai_bom_resolution",
            "build_stix_graph": "build_stix_graph",
            "score_confidence_and_novelty": "score_confidence_and_novelty",
            "refresh_coverage_view": "refresh_coverage_view",
            "coverage_gap_analysis": "coverage_gap_analysis",
            "weak_signal_mining": "weak_signal_mining",
            "generate_alerts": "generate_alerts",
            "finalize_run": "finalize_run",
        },
    )
    graph.add_edge("supervisor_plan", "dispatch_collection")

    # Send API fan-out: route_collectors_fan_out returns [Send(node, {}), ...]
    # for each collector role that has assigned source plans, ensuring parallel
    # execution.  Roles with no plans are skipped at runtime.
    graph.add_conditional_edges(
        "dispatch_collection",
        route_collectors_fan_out,
        [
            "collect_structured_sources",
            "collect_code_sources",
            "collect_paper_sources",
            "collect_community_sources",
            "collect_advisory_sources",
        ],
    )

    graph.add_edge("collect_structured_sources", "store_raw_records")
    graph.add_edge("collect_code_sources", "store_raw_records")
    graph.add_edge("collect_paper_sources", "store_raw_records")
    graph.add_edge("collect_community_sources", "store_raw_records")
    graph.add_edge("collect_advisory_sources", "store_raw_records")

    graph.add_edge("store_raw_records", "assess_collection_yield")
    graph.add_edge("assess_collection_yield", "reflect_search_strategy")
    graph.add_conditional_edges(
        "reflect_search_strategy",
        route_after_reflection,
        {
            "dispatch_collection": "dispatch_collection",
            "parse_and_standardize": "parse_and_standardize",
        },
    )
    graph.add_edge("parse_and_standardize", "semantic_dedup_and_merge")
    graph.add_edge("semantic_dedup_and_merge", "resolve_ai_bom")
    graph.add_edge("resolve_ai_bom", "build_stix_graph")
    graph.add_edge("build_stix_graph", "score_confidence_and_novelty")
    graph.add_edge("score_confidence_and_novelty", "refresh_coverage_view")
    graph.add_edge("refresh_coverage_view", "coverage_gap_analysis")
    graph.add_conditional_edges(
        "coverage_gap_analysis",
        route_after_coverage_gap_analysis,
        {
            "supervisor_plan": "supervisor_plan",
            "weak_signal_mining": "weak_signal_mining",
        },
    )
    graph.add_edge("weak_signal_mining", "generate_alerts")
    graph.add_edge("generate_alerts", "finalize_run")
    graph.add_edge("finalize_run", END)

    return graph.compile(checkpointer=checkpointer)
