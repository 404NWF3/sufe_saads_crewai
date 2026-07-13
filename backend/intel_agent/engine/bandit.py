"""Deterministic UCB ranking and reward attribution for adaptive queries."""

from __future__ import annotations

import math
from collections import defaultdict

from ..analysis import operator_signature
from ..schemas import CorpusGap, QueryCallOutcome, QueryCandidate


def arm_key(candidate: QueryCandidate) -> str:
    topic = candidate.target_topics[0] if candidate.target_topics else "general"
    return "|".join(
        [
            topic,
            candidate.evidence_channel,
            candidate.source_name,
            candidate.query_intent,
            operator_signature(candidate.source_name, candidate.params),
        ]
    )


def _outcome_arm(outcome: QueryCallOutcome) -> str:
    topic = outcome.target_topics[0] if outcome.target_topics else "general"
    return "|".join(
        [topic, outcome.evidence_channel, outcome.source_name, outcome.query_intent, outcome.operator_signature]
    )


def score_candidates(
    candidates: list[QueryCandidate],
    outcomes: list[QueryCallOutcome],
    corpus_gaps: list[CorpusGap],
) -> list[tuple[QueryCandidate, float]]:
    stats: dict[str, list[float]] = defaultdict(list)
    for outcome in outcomes:
        stats[_outcome_arm(outcome)].append(float(outcome.reward))
    total_calls = len(outcomes)
    gaps = {gap.gap_id: gap for gap in corpus_gaps}
    ranked: list[tuple[QueryCandidate, float]] = []
    for candidate in candidates:
        rewards = stats.get(arm_key(candidate), [])
        history_mean = sum(rewards) / len(rewards) if rewards else 0.0
        target_priority = sum(
            gaps[gap_id].priority_score
            for gap_id in candidate.target_gap_ids
            if gap_id in gaps and gaps[gap_id].status == "open"
        )
        if not candidate.target_gap_ids and candidate.query_intent == "discovery":
            target_priority = 0.2
        expected_reduction = min(1.0, 0.6 * target_priority + 0.4 * max(0.0, history_mean))
        exploration = math.sqrt(2.0 * math.log(total_calls + 2) / (len(rewards) + 1))
        historical = [outcome for outcome in outcomes if _outcome_arm(outcome) == arm_key(candidate)]
        noise = (
            sum(outcome.noise_count / max(1, outcome.new_count) for outcome in historical) / len(historical)
            if historical else 0.0
        )
        duplicate = (
            sum(outcome.duplicate_count / max(1, outcome.in_scope_count) for outcome in historical)
            / len(historical)
            if historical else 0.0
        )
        utility = expected_reduction - 0.2 * noise - 0.2 * duplicate + exploration
        ranked.append((candidate, round(utility, 4)))
    return sorted(ranked, key=lambda row: (-row[1], row[0].candidate_id))


def select_portfolio(
    candidates: list[QueryCandidate],
    outcomes: list[QueryCallOutcome],
    corpus_gaps: list[CorpusGap],
    max_calls: int = 4,
    max_total_calls: int | None = None,
    discovery_unbounded: bool = False,
    budget_outcomes: list[QueryCallOutcome] | None = None,
) -> list[tuple[QueryCandidate, float]]:
    ranked = score_candidates(candidates, outcomes, corpus_gaps)
    selected: list[tuple[QueryCandidate, float]] = []
    total_budget = max_total_calls or max(1, len(outcomes) + max_calls)
    prior_counts: dict[str, int] = defaultdict(int)
    for outcome in budget_outcomes if budget_outcomes is not None else outcomes:
        prior_counts[outcome.query_intent] += 1
    discovery_remaining = max(0, math.ceil(total_budget * 0.20) - prior_counts["discovery"])
    confirmation_remaining = max(0, math.ceil(total_budget * 0.10) - prior_counts["confirmation"])
    intent_caps = {
        "discovery": max_calls if discovery_unbounded else min(1, discovery_remaining),
        "confirmation": min(1, confirmation_remaining),
    }
    intent_counts: dict[str, int] = defaultdict(int)
    for row in ranked:
        candidate = row[0]
        cap = intent_caps.get(candidate.query_intent)
        if cap is not None and intent_counts[candidate.query_intent] >= cap:
            continue
        selected.append(row)
        intent_counts[candidate.query_intent] += 1
        if len(selected) >= max_calls:
            break
    return selected


def normalized_reward(
    before_priority: float,
    after_priority: float,
    outcome: QueryCallOutcome,
    residual_support: float = 0.0,
) -> float:
    denominator = max(1.0, before_priority)
    gap_reduction = max(0.0, before_priority - after_priority) / denominator
    noise_ratio = outcome.noise_count / max(1, outcome.new_count)
    duplicate_ratio = outcome.duplicate_count / max(1, outcome.in_scope_count)
    discovery_bonus = 0.0
    if outcome.query_intent == "discovery":
        extended_new = int(outcome.metadata.get("extended_new_count") or 0)
        discovery_bonus = min(0.25, 0.05 * extended_new + 0.1 * residual_support)
    confirmation_bonus = (
        min(0.25, 0.1 * outcome.relevant_new)
        if outcome.query_intent == "confirmation" and outcome.success
        else 0.0
    )
    reward = (
        gap_reduction + discovery_bonus + confirmation_bonus
        - 0.2 * noise_ratio - 0.2 * duplicate_ratio - 0.05
    )
    return round(max(-1.0, min(1.0, reward)), 4)
