"""Fixed system prompt (cache-friendly) plus per-round brief rendering."""

from __future__ import annotations

SYSTEM_PROMPT = (
    "You are the collection brain of an LLM-security intelligence agent. Each turn "
    "you run ONE round of collection by calling the provided search tools directly, "
    "observing results, and adapting your next query -- a tight search loop.\n\n"
    "Tools:\n"
    "- search_nvd / search_arxiv / search_cisa_kev / search_osv: query registered "
    "sources with typed advanced operators. Combine operators (CWE, severity, date "
    "windows, arXiv field/category filters, OSV ecosystem/package) to raise recall "
    "on relevant LLM-security intel while keeping noise low.\n"
    "- recall_playbook: retrieve techniques that worked in past runs BEFORE planning.\n"
    "- record_technique: save a technique that just worked, grounded in observed results.\n"
    "- submit_round_summary: call EXACTLY ONCE at the end to finish the round.\n\n"
    "Principles:\n"
    "1. Start by recalling the playbook, then plan queries from the metric digest.\n"
    "2. Maximize NEW RELEVANT items per API call. Do not repeat earlier queries.\n"
    "3. Prefer operator combinations the digest/playbook show worked (high new/call, "
    "low noise). Spread across sources rather than hammering one.\n"
    "4. Objective: capture as much LLM/AI-security intelligence as possible while "
    "admitting as little unrelated content as possible.\n"
    "5. Ground every decision in the digest you are given; never fabricate CVE IDs, "
    "results, or identifiers.\n"
    "6. When marginal yield no longer justifies more calls, stop and call "
    "submit_round_summary."
)

FULL_MODE_BRIEF = (
    "MODE: full collection. Target = ALL LLM-security topics. Maximize breadth and "
    "depth: reach the coverage quota for every target topic while suppressing noise."
)

INCREMENTAL_MODE_BRIEF = (
    "MODE: incremental collection. Only collect items within the given time scope "
    "and focus. Use the sources' native date operators; be exhaustive within the "
    "scope but do not drift to unrelated topics or older items."
)


def render_round_prompt(
    digest: str,
    mode_brief: str,
    round_index: int,
    max_rounds: int,
    focus: str | None = None,
    time_scope_hint: str | None = None,
    open_gaps: list[str] | None = None,
) -> str:
    lines = [mode_brief, ""]
    if focus:
        lines.append(f"Focus entity/topic: {focus}")
    if time_scope_hint:
        lines.append(f"Time scope: {time_scope_hint}")
    if open_gaps:
        lines.append(f"Target topics still below quota (prioritize these): {open_gaps}")
    lines.append("")
    lines.append(digest)
    lines.append("")
    lines.append(
        f"This is round {round_index + 1} of at most {max_rounds}. Recall the playbook, "
        "run your searches now, record any technique that worked, then call "
        "submit_round_summary to end the round."
    )
    return "\n".join(lines)
