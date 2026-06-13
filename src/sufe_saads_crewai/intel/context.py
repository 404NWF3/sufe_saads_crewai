"""Context engineering: render the blackboard into a compact metric digest.

Roadmap chapter 8: feed summaries, never raw documents. The digest is the only
dynamic context an SDK decision session sees each round; it is also persisted
with the run so every decision input is reproducible and auditable.
"""

from __future__ import annotations

from typing import Any

from sufe_saads_crewai.schemas import IntelRunBlackboard

DEFAULT_MAX_CHARS = 9000  # ~2-3K tokens


def _truncate(text: str, limit: int) -> str:
    cleaned = " ".join(str(text).split())
    return cleaned if len(cleaned) <= limit else f"{cleaned[: limit - 3]}..."


def render_round_context(
    blackboard: IntelRunBlackboard,
    round_index: int,
    max_rounds: int,
    bandit_summary: str | None = None,
    recent_queries: int = 8,
    sample_titles: int = 8,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    lines: list[str] = []
    lines.append(f"Run goal: {_truncate(blackboard.run_goal, 200)}")
    lines.append(
        f"Round {round_index + 1}/{max_rounds} | total items {len(blackboard.raw_items)} | "
        f"api_calls_used {blackboard.metrics.api_calls_used}"
        + (
            f"/{blackboard.budget.max_api_calls}"
            if blackboard.budget.max_api_calls is not None
            else ""
        )
    )

    history = blackboard.query_history
    if history:
        lines.append("")
        lines.append("Recent queries (newest last): round | new/total | dup% | noise% | query")
        for entry in history[-recent_queries:]:
            new_count = len(entry.metadata.get("new_item_ids") or [])
            lines.append(
                f"r{entry.round_index} | {new_count}/{entry.result_count} "
                f"| dup={entry.duplicate_ratio:.0%} | noise={entry.noise_ratio:.0%} "
                f"| {_truncate(entry.query_text, 90)}"
            )

        per_source: dict[str, dict[str, float]] = {}
        for entry in history:
            plans = entry.metadata.get("source_query_plans") or []
            calls: dict[str, int] = {}
            for plan in plans:
                source = str(plan.get("source_name", ""))
                if source:
                    calls[source] = calls.get(source, 0) + 1
            if not calls:
                calls = {source: 1 for source in entry.source_names}
            new_ids = entry.metadata.get("new_item_ids") or []
            for source, call_count in calls.items():
                row = per_source.setdefault(source, {"calls": 0.0, "new": 0.0})
                row["calls"] += call_count
                prefix = {
                    "nvd_cve_api": "nvd:",
                    "arxiv_api": "arxiv:",
                    "cisa_kev_json": "cisa-kev:",
                    "osv_dev_api": "osv:",
                }.get(source)
                if prefix:
                    row["new"] += sum(1 for item_id in new_ids if str(item_id).startswith(prefix))
        if per_source:
            lines.append("")
            lines.append("Per-source totals: source | calls | new items | new/call")
            for source, row in sorted(per_source.items()):
                rate = row["new"] / row["calls"] if row["calls"] else 0.0
                lines.append(
                    f"{source} | {row['calls']:.0f} | {row['new']:.0f} | {rate:.2f}"
                )

    if bandit_summary:
        lines.append("")
        lines.append(bandit_summary)

    if blackboard.coverage_gaps:
        lines.append("")
        lines.append("Open coverage gaps (topic | roi | priority):")
        for gap in blackboard.coverage_gaps[:8]:
            lines.append(
                f"- {gap.taxonomy_or_component} | roi={gap.estimated_gap_fill_roi:.2f} "
                f"| {gap.priority}"
            )

    if blackboard.reflection_notes:
        last_note = blackboard.reflection_notes[-1]
        lines.append("")
        lines.append(f"Last reflection: {_truncate(last_note.rationale, 200)}")

    if blackboard.raw_items and sample_titles > 0:
        lines.append("")
        lines.append("Sample of newest item titles (metadata only, no full text):")
        for item in blackboard.raw_items[-sample_titles:]:
            lines.append(
                f"- [{item.source_name}] {_truncate(item.title, 110)} "
                f"(rel={item.relevance_score:.2f})"
            )

    rendered = "\n".join(lines)
    if len(rendered) > max_chars:
        rendered = rendered[: max_chars - 20] + "\n...[context truncated]"
    return rendered


def render_decision_telemetry(telemetry: dict[str, Any]) -> str:
    return (
        f"decision attempts={telemetry.get('attempts', 0)} "
        f"successes={telemetry.get('successes', 0)} "
        f"fallbacks={telemetry.get('failure_count', 0)}"
    )
