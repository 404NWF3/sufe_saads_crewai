"""Playbook tools: let the agent recall past techniques and record new ones."""

from __future__ import annotations

from typing import Any

from .context import ToolContext

_RECALL_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "What you are trying to find right now."},
        "source_name": {"type": "string", "description": "Optional: restrict to one source."},
    },
    "required": ["query"],
}

_RECORD_SCHEMA = {
    "type": "object",
    "properties": {
        "technique_text": {"type": "string", "description": "The reusable search technique, in plain language."},
        "source_name": {"type": "string", "description": "Source the technique applies to."},
        "reason": {"type": "string", "description": "Why it worked (what it found, why low-noise)."},
    },
    "required": ["technique_text", "source_name"],
}


def build_memory_tools(ctx: ToolContext) -> list[Any]:
    from claude_agent_sdk import tool

    @tool("recall_playbook", "Recall proven search techniques from past runs before planning "
          "queries. Returns techniques ranked by semantic match and historical payoff.", _RECALL_SCHEMA)
    async def recall_playbook(args: dict[str, Any]) -> dict[str, Any]:
        if ctx.playbook is None:
            return _text("Playbook memory is disabled for this run.")
        entries = ctx.playbook.recall(
            query_text=str(args.get("query") or ""),
            topic_bucket=ctx.topic_bucket,
            source_name=args.get("source_name"),
            top_k=5,
        )
        rendered = ctx.playbook.render_recall(entries)
        return _text(rendered or "No matching techniques recorded yet.")

    @tool("record_technique", "Record a search technique that just worked so future runs can reuse "
          "it. Only record techniques grounded in this round's observed results.", _RECORD_SCHEMA)
    async def record_technique(args: dict[str, Any]) -> dict[str, Any]:
        ctx.recorded_techniques.append(
            {
                "technique_text": str(args.get("technique_text") or "").strip(),
                "source_name": str(args.get("source_name") or "").strip(),
                "reason": str(args.get("reason") or "").strip(),
            }
        )
        return _text("Technique noted; it will be scored against this round's yield.")

    return [recall_playbook, record_technique]


def _text(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}]}
