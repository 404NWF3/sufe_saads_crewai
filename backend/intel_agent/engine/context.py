"""Render the blackboard into a compact metric digest for the agent.

Roadmap principle: feed summaries, never raw documents. The digest is the only
dynamic context each round's session sees, and it is persisted with the run so
every decision input is reproducible.
"""

from __future__ import annotations

from typing import Any

from ..analysis import new_relevant_per_call, topic_coverage_counts
from ..schemas import IntelRunBlackboard

DEFAULT_MAX_CHARS = 8000


def _truncate(text: str, limit: int) -> str:
    cleaned = " ".join(str(text).split())
    return cleaned if len(cleaned) <= limit else f"{cleaned[: limit - 3]}..."


def render_digest(
    blackboard: IntelRunBlackboard,
    round_index: int,
    max_rounds: int,
    target_topics: list[str],
    quota: int,
    playbook_recall: str | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    lines: list[str] = [f"Run goal: {_truncate(blackboard.run_goal, 200)}"]
    budget = blackboard.budget
    used = blackboard.metrics.api_calls_used
    cap = f"/{budget.max_api_calls}" if budget.max_api_calls is not None else ""
    lines.append(
        f"Round {round_index + 1}/{max_rounds} | total items {len(blackboard.raw_items)} "
        f"| api_calls_used {used}{cap}"
    )

    counts = topic_coverage_counts(blackboard.raw_items, target_topics)
    lines.append("")
    lines.append(f"Coverage vs quota={quota} (relevant items per topic):")
    for topic in target_topics:
        got = counts.get(topic, 0)
        flag = "OK" if got >= quota else "GAP"
        lines.append(f"- {topic}: {got}/{quota} [{flag}]")

    history = blackboard.query_history
    if history:
        lines.append("")
        lines.append("Recent queries (newest last): round | new/total | dup% | noise% | new/call | query")
        for entry in history[-8:]:
            new_count = len(entry.metadata.get("new_item_ids") or [])
            lines.append(
                f"r{entry.round_index} | {new_count}/{entry.result_count} "
                f"| dup={entry.duplicate_ratio:.0%} | noise={entry.noise_ratio:.0%} "
                f"| {new_relevant_per_call(entry):.2f} | {_truncate(entry.query_text, 70)}"
            )

        per_source = _per_source_yield(history)
        if per_source:
            lines.append("")
            lines.append("Per-source yield: source | calls | new items | new/call")
            for source, row in sorted(per_source.items()):
                rate = row["new"] / row["calls"] if row["calls"] else 0.0
                lines.append(f"{source} | {row['calls']:.0f} | {row['new']:.0f} | {rate:.2f}")

    if playbook_recall:
        lines.append("")
        lines.append(playbook_recall)

    if blackboard.raw_items:
        lines.append("")
        lines.append("Newest item titles (metadata only):")
        for item in blackboard.raw_items[-6:]:
            lines.append(f"- [{item.source_name}] {_truncate(item.title, 100)} (rel={item.relevance_score:.2f})")

    rendered = "\n".join(lines)
    return rendered if len(rendered) <= max_chars else rendered[: max_chars - 20] + "\n...[truncated]"


def _per_source_yield(history: list) -> dict[str, dict[str, float]]:
    per_source: dict[str, dict[str, float]] = {}
    for entry in history:
        new_ids = set(entry.metadata.get("new_item_ids") or [])
        plans = entry.metadata.get("source_query_plans") or []
        prefixes = {
            "nvd_cve_api": "nvd:", "arxiv_api": "arxiv:",
            "cisa_kev_json": "cisa-kev:", "osv_dev_api": "osv:",
        }
        sources = [str(plan.get("source_name", "")) for plan in plans] or entry.source_names
        for source in sources:
            row = per_source.setdefault(source, {"calls": 0.0, "new": 0.0})
            row["calls"] += 1
            prefix = prefixes.get(source)
            if prefix:
                row["new"] += sum(1 for item_id in new_ids if str(item_id).startswith(prefix))
    return per_source
