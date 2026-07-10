"""Round-termination critic: agent verdict tempered by deterministic safety valves.

The critic (a fast, tool-forced decision) proposes continue/stop from marginal
yield features. Its verdict is then overridden, in priority order, by hard
valves: max_rounds > stall > coverage gate (topics below quota) > min_rounds.
If the SDK decision fails, a pure-rules verdict is used -- the fallback contract.
"""

from __future__ import annotations

import json
from typing import Any

from ..runtime.structured import StructuredDecisionEngine
from ..schemas import SearchCompletenessAssessment, TerminationDecision

SYSTEM_PROMPT = (
    "You judge whether an LLM-security collection loop should run another round. "
    "Continue only while the marginal new-relevant-items-per-call justifies the API "
    "cost. Answer via the submit_decision tool."
)


def decide_termination(
    engine: StructuredDecisionEngine | None,
    digest: str,
    features: dict[str, Any],
    round_index: int,
    max_rounds: int,
    min_rounds: int,
    open_gaps: list[str],
    stalled: bool,
    api_budget_remains: bool,
    on_fallback: Any | None = None,
) -> SearchCompletenessAssessment:
    assessment = _agent_or_rules(
        engine, digest, features, round_index, max_rounds, open_gaps, stalled, on_fallback
    )
    _apply_safety_valves(
        assessment, round_index, max_rounds, min_rounds, open_gaps, stalled, api_budget_remains
    )
    return assessment


def _agent_or_rules(
    engine: StructuredDecisionEngine | None,
    digest: str,
    features: dict[str, Any],
    round_index: int,
    max_rounds: int,
    open_gaps: list[str],
    stalled: bool,
    on_fallback: Any | None,
) -> SearchCompletenessAssessment:
    if engine is not None:
        prompt = (
            f"{digest}\n\nMarginal yield features: {json.dumps(features)}\n"
            f"Round {round_index + 1} of max {max_rounds}.\n\n"
            "Decide whether to continue for another round."
        )
        parsed = engine.decide(
            "termination", prompt, TerminationDecision, system_prompt=SYSTEM_PROMPT, fast=True
        )
        if parsed is not None:
            return SearchCompletenessAssessment(
                completeness_score=parsed.completeness_score,
                should_continue=parsed.should_continue,
                missing_dimensions=parsed.missing_topics,
                recommended_next_mode="gap_fill" if parsed.should_continue else None,
                stop_rationale=parsed.stop_reason or parsed.rationale,
            )
        if on_fallback is not None:
            on_fallback("termination", "decision failed")

    # Deterministic fallback: continue while gaps remain and search is not stalled.
    should_continue = bool(open_gaps) and not stalled
    return SearchCompletenessAssessment(
        completeness_score=0.0 if open_gaps else 1.0,
        should_continue=should_continue,
        missing_dimensions=open_gaps,
        recommended_next_mode="gap_fill" if should_continue else None,
        stop_rationale=None if should_continue else "no open coverage gaps or search stalled",
    )


def _apply_safety_valves(
    assessment: SearchCompletenessAssessment,
    round_index: int,
    max_rounds: int,
    min_rounds: int,
    open_gaps: list[str],
    stalled: bool,
    api_budget_remains: bool,
) -> None:
    if round_index + 1 >= max_rounds:
        assessment.should_continue = False
        assessment.stop_rationale = assessment.stop_rationale or "max_rounds reached"
        return
    if stalled:
        assessment.should_continue = False
        reason = "search exhausted: marginal new-relevant yield below threshold"
        if open_gaps:
            reason += f"; unreached topics: {open_gaps}"
        assessment.stop_rationale = reason
        assessment.missing_dimensions = open_gaps
        return
    if open_gaps and api_budget_remains:
        assessment.should_continue = True
        assessment.stop_rationale = None
        assessment.missing_dimensions = open_gaps
        return
    if round_index + 1 < min_rounds:
        assessment.should_continue = True
