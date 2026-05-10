from __future__ import annotations

from typing import Literal, cast

from .state import WP11GraphState


def route_after_runtime_load(
    state: WP11GraphState,
) -> Literal[
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
]:
    target = state.get("resume_target_node") or "supervisor_plan"
    return cast(
        Literal[
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
        ],
        target,
    )


def route_after_reflection(
    state: WP11GraphState,
) -> Literal["dispatch_collection", "parse_and_standardize"]:
    if state.get("reflection_needed", False):
        return "dispatch_collection"
    return "parse_and_standardize"


def route_after_coverage_gap_analysis(
    state: WP11GraphState,
) -> Literal["supervisor_plan", "weak_signal_mining"]:
    if state.get("gap_fill_needed", False):
        return "supervisor_plan"
    return "weak_signal_mining"
