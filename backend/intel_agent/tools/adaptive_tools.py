"""Planning tools that keep LLM proposals behind deterministic scoring."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from ..engine.bandit import select_portfolio
from ..engine.gaps import SOURCE_CHANNEL
from ..schemas import QueryCandidate
from ..topics import ALL_SECURITY_TOPICS
from .context import ToolContext

_STATE_SCHEMA = {"type": "object", "properties": {}}
_CANDIDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "source_name": {
                        "type": "string",
                        "enum": ["nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api"],
                    },
                    "query_text": {"type": "string"},
                    "params": {
                        "type": "object",
                        "description": (
                            "All source-specific operators must be nested here, e.g. "
                            "arxiv_search_query, nvd_cwe_id, osv_ecosystem, or cisa_keyword."
                        ),
                    },
                    "query_intent": {
                        "type": "string",
                        "enum": ["gap_fill", "discovery", "entity_expand", "confirmation"],
                    },
                    "evidence_channel": {
                        "type": "string",
                        "enum": ["research", "vulnerability_advisory", "exploitation"],
                    },
                    "target_topics": {"type": "array", "items": {"type": "string"}},
                    "target_gap_ids": {"type": "array", "items": {"type": "string"}},
                    "rationale": {"type": "string"},
                },
                "required": [
                    "candidate_id", "source_name", "query_text", "query_intent",
                    "evidence_channel", "target_topics", "target_gap_ids",
                ],
            },
        }
    },
    "required": ["candidates"],
}


def build_adaptive_tools(ctx: ToolContext) -> list[Any]:
    from claude_agent_sdk import tool

    @tool(
        "get_collection_state",
        "Return the authoritative Core CorpusGaps, current RunGaps, source checkpoints, and "
        "recent per-call rewards. Extended topics never appear as coverage gaps.",
        _STATE_SCHEMA,
    )
    async def get_collection_state(args: dict[str, Any]) -> dict[str, Any]:
        state = {
            "corpus_gaps": [
                gap.model_dump(mode="json")
                for gap in ctx.corpus_gaps
                if gap.status == "open"
            ][:24],
            "run_gaps": [gap.model_dump(mode="json") for gap in ctx.run_gaps if gap.status == "open"],
            "source_checkpoints": [checkpoint.model_dump(mode="json") for checkpoint in ctx.source_checkpoints],
            "extended_trends": ctx.extended_trends,
            "historical_reward_summary": _historical_reward_summary(ctx),
            "api_calls_remaining": (
                None if ctx.max_api_calls is None else max(0, ctx.max_api_calls - ctx.api_calls_used)
            ),
        }
        return _text(json.dumps(state, ensure_ascii=False))

    @tool(
        "score_query_candidates",
        "Submit 1-8 source-specific query candidates. Deterministic UCB scoring approves at "
        "most four. Only approved candidate IDs may be passed to source tools.",
        _CANDIDATE_SCHEMA,
    )
    async def score_query_candidates(args: dict[str, Any]) -> dict[str, Any]:
        raw = list(args.get("candidates") or [])[:8]
        candidates: list[QueryCandidate] = []
        errors: list[str] = []
        seen: set[str] = set()
        for entry in raw:
            try:
                candidate = QueryCandidate.model_validate(entry)
            except ValidationError as exc:
                errors.append(str(exc.errors(include_url=False))[:300])
                continue
            if candidate.candidate_id in seen:
                errors.append(f"duplicate candidate_id: {candidate.candidate_id}")
                continue
            validation_error = candidate_validation_error(candidate, ctx)
            if validation_error:
                errors.append(f"{candidate.candidate_id}: {validation_error}")
                continue
            seen.add(candidate.candidate_id)
            candidates.append(candidate)
        remaining = (
            ctx.max_calls_this_round
            if ctx.max_api_calls is None
            else min(ctx.max_calls_this_round, max(0, ctx.max_api_calls - ctx.api_calls_used))
        )
        selected = select_portfolio(
            candidates,
            ctx.prior_outcomes,
            ctx.corpus_gaps,
            max_calls=remaining,
            max_total_calls=ctx.max_api_calls,
            discovery_unbounded=ctx.extended_focus,
            budget_outcomes=ctx.current_run_outcomes,
        )
        ctx.approved_candidates = {candidate.candidate_id: candidate for candidate, _ in selected}
        ctx.candidate_utilities = {candidate.candidate_id: utility for candidate, utility in selected}
        payload = {
            "approved": [
                {**candidate.model_dump(mode="json"), "utility": utility}
                for candidate, utility in selected
            ],
            "rejected_count": len(candidates) - len(selected),
            "validation_errors": errors,
        }
        return _text(json.dumps(payload, ensure_ascii=False))

    return [get_collection_state, score_query_candidates]


def candidate_validation_error(
    candidate: QueryCandidate, ctx: ToolContext
) -> str | None:
    from .source_tools import candidate_exceeds_time_scope

    if candidate.evidence_channel != SOURCE_CHANNEL[candidate.source_name]:
        return "source and evidence_channel do not match"
    unknown_topics = sorted(set(candidate.target_topics) - set(ALL_SECURITY_TOPICS))
    if unknown_topics:
        return f"unknown taxonomy topics: {unknown_topics}"
    open_gap_ids = {
        gap.gap_id for gap in ctx.corpus_gaps if gap.status == "open"
    } | {gap.gap_id for gap in ctx.run_gaps if gap.status == "open"}
    invalid_gap_ids = sorted(set(candidate.target_gap_ids) - open_gap_ids)
    if invalid_gap_ids:
        return f"target gaps are not open: {invalid_gap_ids}"
    if candidate_exceeds_time_scope(
        ctx, candidate.source_name, candidate.params
    ):
        return "candidate time operators exceed the authoritative incremental window"
    if candidate.query_intent == "gap_fill" and not candidate.target_gap_ids:
        return "gap_fill candidates require an open target gap"
    return None


def _historical_reward_summary(ctx: ToolContext) -> list[dict[str, Any]]:
    arms: dict[tuple[str, str, str, str, str], dict[str, float]] = {}
    for outcome in ctx.prior_outcomes:
        topic = outcome.target_topics[0] if outcome.target_topics else "general"
        key = (
            topic,
            outcome.evidence_channel,
            outcome.source_name,
            outcome.query_intent,
            outcome.operator_signature,
        )
        row = arms.setdefault(
            key,
            {"calls": 0.0, "reward": 0.0, "noise": 0.0, "duplicate": 0.0},
        )
        row["calls"] += 1
        row["reward"] += outcome.reward
        row["noise"] += outcome.noise_count / max(1, outcome.new_count)
        row["duplicate"] += outcome.duplicate_count / max(1, outcome.in_scope_count)
    summary = []
    for key, totals in arms.items():
        calls = int(totals["calls"])
        summary.append(
            {
                "arm": key,
                "calls": calls,
                "mean_reward": round(totals["reward"] / calls, 4),
                "mean_noise_ratio": round(totals["noise"] / calls, 4),
                "mean_duplicate_ratio": round(totals["duplicate"] / calls, 4),
            }
        )
    return sorted(
        summary,
        key=lambda row: (-row["mean_reward"], -row["calls"], row["arm"]),
    )[:12]


def _text(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}]}
