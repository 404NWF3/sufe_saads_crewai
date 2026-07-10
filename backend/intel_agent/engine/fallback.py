"""Deterministic rules-only round, run when the agent session is unavailable.

Reuses the same in-process source execution path as the agent tools (budget,
dedup, time scope, recording) so a fallback round populates the ToolContext
identically -- only the query planning is deterministic instead of agentic.
"""

from __future__ import annotations

from ..analysis import build_fallback_specs, quota_open_gaps, coverage_quota
from ..schemas import IntelRunBlackboard, SearchQueryPlan
from ..tools.context import ToolContext
from ..tools.source_tools import _run_call


def run_fallback_round(
    ctx: ToolContext,
    blackboard: IntelRunBlackboard,
    query_plan: SearchQueryPlan,
    target_topics: list[str],
) -> None:
    specs = build_fallback_specs(
        blackboard=blackboard,
        query_plan=query_plan,
        target_topics=target_topics,
        max_results=ctx.max_results_per_call * 4,
        executed_keys=ctx.executed_keys,
    )
    for spec in specs:
        if not ctx.budget_remaining():
            break
        _run_call(ctx, spec.source_name, {"query_text": spec.query_text})

    open_gaps = quota_open_gaps(blackboard.raw_items, target_topics, coverage_quota())
    ctx.notes.append(
        {
            "summary": f"Rules-only fallback round: swept {len(specs)} source queries.",
            "covered_topics": [t for t in target_topics if t not in open_gaps],
            "remaining_gaps": open_gaps,
        }
    )
