"""Round control tool: the agent's explicit exit from a collection round."""

from __future__ import annotations

from typing import Any

from .context import ToolContext

_SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "1-3 sentences on what this round collected."},
        "covered_topics": {
            "type": "array", "items": {"type": "string"},
            "description": "Target topics you believe are now well covered.",
        },
        "remaining_gaps": {
            "type": "array", "items": {"type": "string"},
            "description": "Target topics still thin or unaddressed.",
        },
    },
    "required": ["summary"],
}


def build_control_tools(ctx: ToolContext) -> list[Any]:
    from claude_agent_sdk import tool

    @tool("submit_round_summary", "Call this once when you have finished searching for this round. "
          "It ends your turn; the controller then merges results and decides whether to continue.",
          _SUMMARY_SCHEMA)
    async def submit_round_summary(args: dict[str, Any]) -> dict[str, Any]:
        ctx.notes.append(
            {
                "summary": str(args.get("summary") or "").strip(),
                "covered_topics": list(args.get("covered_topics") or []),
                "remaining_gaps": list(args.get("remaining_gaps") or []),
            }
        )
        return _text("Round summary recorded. You may stop now.")

    return [submit_round_summary]


def _text(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}]}
