"""Agent-loop hooks: an auditing layer over the in-process tool control plane.

The source-tool handlers already enforce the API-call budget and cross-round
query dedup deterministically (``tools/context.ToolContext``), so hooks here are
intentionally light: a PreToolUse guard that blocks source calls once the budget
is spent, and a PostToolUse recorder for the per-round audit trail. Hooks are
opt-in (``INTEL_AGENT_HOOKS``, default on) and degrade to no-ops if the SDK hook
surface is unavailable.
"""

from __future__ import annotations

import os
from typing import Any

from .tools.context import ToolContext
from .tools.server import SERVER_NAME

_SOURCE_TOOLS = {
    f"mcp__{SERVER_NAME}__{name}"
    for name in ("search_nvd", "search_arxiv", "search_cisa_kev", "search_osv")
}


def hooks_enabled() -> bool:
    return os.getenv("INTEL_AGENT_HOOKS", "1").strip().lower() not in {"0", "false", "no", "off"}


def build_hooks(ctx: ToolContext) -> dict[str, Any] | None:
    """Return a ClaudeAgentOptions.hooks dict, or None when disabled/unavailable."""
    if not hooks_enabled():
        return None
    try:
        from claude_agent_sdk import HookMatcher
    except ImportError:
        return None

    audit: list[dict[str, Any]] = []
    ctx.notes  # touch to keep ctx referenced; audit is stored on ctx below
    setattr(ctx, "hook_audit", audit)

    async def pre_tool_use(input_data: dict[str, Any], tool_use_id: Any, context: Any) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        if tool_name in _SOURCE_TOOLS and not ctx.budget_remaining():
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "API-call budget exhausted for this run.",
                }
            }
        return {}

    async def post_tool_use(input_data: dict[str, Any], tool_use_id: Any, context: Any) -> dict[str, Any]:
        audit.append(
            {
                "tool": str(input_data.get("tool_name", "")),
                "api_calls_used": ctx.api_calls_used,
            }
        )
        return {}

    return {
        "PreToolUse": [HookMatcher(hooks=[pre_tool_use])],
        "PostToolUse": [HookMatcher(hooks=[post_tool_use])],
    }
