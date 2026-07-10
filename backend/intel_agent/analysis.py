"""Deterministic analysis + fallback helpers for the collection loop.

A lean, self-contained replacement for the legacy ``intel/rules.py``: it keeps
only the pure functions the agentic controller needs -- batch merging with
novelty/noise/duplicate accounting, quota-based coverage gaps, stall detection,
and deterministic query building for the rules-only fallback round.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .schemas import (
    CoverageGap,
    IntelRunBlackboard,
    QueryHistoryEntry,
    RawIntelItem,
    RawIntelItemBatch,
    SearchQueryPlan,
)
from .topics import ALL_SECURITY_TOPICS, CORE_SECURITY_TOPICS, build_gap_query, detect_topics

RELEVANT_SCORE_THRESHOLD = 0.5
DEFAULT_COVERAGE_QUOTA = 3


@dataclass(frozen=True)
class SourceQuerySpec:
    source_name: str
    query_text: str
    target_topics: list[str]
    max_results: int
    strategy_name: str = "rules"
    params: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------ env knobs


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def coverage_quota() -> int:
    return _env_int("INTEL_COVERAGE_QUOTA", DEFAULT_COVERAGE_QUOTA)


def stall_patience() -> int:
    return _env_int("INTEL_STALL_PATIENCE", 2)


def min_new_relevant_per_call() -> float:
    return _env_float("INTEL_MIN_NEW_RELEVANT_PER_CALL", 0.5)


# ------------------------------------------------------------------ relevance


def item_is_relevant(item: RawIntelItem) -> bool:
    relevance = item.metadata.get("relevance")
    if isinstance(relevance, dict) and relevance.get("label"):
        return relevance["label"] == "relevant"
    return float(item.relevance_score) >= RELEVANT_SCORE_THRESHOLD


def item_topics(item: RawIntelItem, target_topics: list[str]) -> set[str]:
    topics: set[str] = set()
    relevance = item.metadata.get("relevance")
    if isinstance(relevance, dict) and relevance.get("topic") in target_topics:
        topics.add(relevance["topic"])
    topics.update(t for t in item.metadata.get("topics", []) if t in target_topics)
    topics.update(detect_topics(f"{item.title} {item.summary} {item.raw_text or ''}"))
    return topics & set(target_topics)


def operator_signature(source_name: str, params: dict[str, Any]) -> str:
    keys = sorted(key for key, value in params.items() if value not in (None, "", [], {}))
    return f"{source_name}[{'+'.join(keys)}]" if keys else f"{source_name}[base]"


def source_query_key(spec: SourceQuerySpec) -> str:
    return json.dumps(
        {"source": spec.source_name, "query": spec.query_text, "params": spec.params},
        ensure_ascii=False, sort_keys=True,
    )


# ------------------------------------------------------------------ merging


def merge_batch_into_blackboard(
    blackboard: IntelRunBlackboard,
    query_plan: SearchQueryPlan,
    batch: RawIntelItemBatch,
) -> QueryHistoryEntry:
    """Add newly-seen items and record a query-history entry with round metrics."""
    existing_ids = {item.item_id for item in blackboard.raw_items}
    new_items = [item for item in batch.items if item.item_id not in existing_ids]
    blackboard.raw_items.extend(new_items)

    total = len(batch.items)
    new_count = len(new_items)
    relevant_new = sum(1 for item in new_items if item_is_relevant(item))
    novelty = new_count / total if total else 0.0
    duplicate_ratio = (total - new_count) / total if total else 0.0
    noise_ratio = (new_count - relevant_new) / new_count if new_count else 0.0

    source_plans = [
        {"source_name": stat.source_name, "params": {}} for stat in batch.source_stats
    ] or [{"source_name": name, "params": {}} for name in query_plan.source_names]

    entry = QueryHistoryEntry(
        query_text=query_plan.query_text,
        source_names=query_plan.source_names,
        result_count=total,
        novelty_score=round(novelty, 4),
        noise_ratio=round(noise_ratio, 4),
        duplicate_ratio=round(duplicate_ratio, 4),
        round_index=query_plan.round_index,
        metadata={
            "new_item_ids": [item.item_id for item in new_items],
            "relevant_new": relevant_new,
            "target_topics": query_plan.target_topics,
            "source_query_plans": source_plans,
        },
    )
    blackboard.query_history.append(entry)
    return entry


def combine_batches(batches: list[RawIntelItemBatch]) -> RawIntelItemBatch:
    items: list[RawIntelItem] = []
    stats = []
    seen: set[str] = set()
    for batch in batches:
        for item in batch.items:
            if item.item_id in seen:
                continue
            seen.add(item.item_id)
            items.append(item)
        stats.extend(batch.source_stats)
    return RawIntelItemBatch(items=items, source_stats=stats)


# ------------------------------------------------------------------ coverage


def topic_coverage_counts(
    items: list[RawIntelItem], target_topics: list[str]
) -> dict[str, int]:
    counts = {topic: 0 for topic in target_topics}
    for item in items:
        if not item_is_relevant(item):
            continue
        for topic in item_topics(item, target_topics):
            counts[topic] += 1
    return counts


def quota_open_gaps(
    items: list[RawIntelItem], target_topics: list[str], quota: int
) -> list[str]:
    counts = topic_coverage_counts(items, target_topics)
    return [topic for topic in target_topics if counts.get(topic, 0) < quota]


def analyze_coverage_gaps(
    items: list[RawIntelItem], target_topics: list[str], quota: int
) -> list[CoverageGap]:
    counts = topic_coverage_counts(items, target_topics)
    gaps: list[CoverageGap] = []
    for topic in target_topics:
        count = counts.get(topic, 0)
        if count >= quota:
            continue
        coverage = count / quota if quota else 0.0
        gaps.append(
            CoverageGap(
                gap_id=f"gap:{topic.replace(' ', '_')}",
                taxonomy_or_component=topic,
                current_coverage=round(coverage, 3),
                estimated_gap_fill_roi=round(1.0 - coverage, 3),
                priority="high" if count == 0 else "medium",
            )
        )
    return gaps


# ------------------------------------------------------------------ stall


def is_search_stalled(
    blackboard: IntelRunBlackboard, patience: int, min_new_relevant_per_call: float
) -> bool:
    history = blackboard.query_history
    if len(history) < patience:
        return False
    for entry in history[-patience:]:
        calls = len(entry.metadata.get("source_query_plans") or []) or len(entry.source_names) or 1
        relevant_new = int(entry.metadata.get("relevant_new", 0))
        if relevant_new / calls >= min_new_relevant_per_call:
            return False
    return True


def new_relevant_per_call(entry: QueryHistoryEntry) -> float:
    calls = len(entry.metadata.get("source_query_plans") or []) or len(entry.source_names) or 1
    return int(entry.metadata.get("relevant_new", 0)) / calls


# ------------------------------------------------------------------ fallback


def build_fallback_specs(
    blackboard: IntelRunBlackboard,
    query_plan: SearchQueryPlan,
    target_topics: list[str],
    max_results: int,
    executed_keys: set[str],
) -> list[SourceQuerySpec]:
    """Deterministic breadth sweep used by the rules-only fallback round."""
    open_gaps = quota_open_gaps(blackboard.raw_items, target_topics, coverage_quota())
    focus_topics = open_gaps or target_topics
    query_text = query_plan.query_text or build_gap_query(focus_topics[:3])
    per_source = max(5, min(20, max_results // 4))
    specs: list[SourceQuerySpec] = []
    for source_name in query_plan.source_names or list(_DEFAULT_SOURCES):
        spec = SourceQuerySpec(
            source_name=source_name,
            query_text=query_text,
            target_topics=focus_topics,
            max_results=per_source,
            strategy_name="rules_fallback",
            params={},
        )
        if source_query_key(spec) in executed_keys:
            continue
        specs.append(spec)
    return specs


_DEFAULT_SOURCES = ("nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api")


def topic_bucket(topics: list[str]) -> str:
    lowered = " ".join(topics).lower()
    for topic in CORE_SECURITY_TOPICS:
        if topic in lowered:
            return topic
    for topic in ALL_SECURITY_TOPICS:
        if topic in lowered:
            return topic
    return "general"
