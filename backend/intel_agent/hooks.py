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
from .tools.constants import SERVER_NAME
from .schemas import RunGap

_SOURCE_TOOLS = {
    f"mcp__{SERVER_NAME}__search_nvd": "nvd_cve_api",
    f"mcp__{SERVER_NAME}__search_arxiv": "arxiv_api",
    f"mcp__{SERVER_NAME}__search_cisa_kev": "cisa_kev_json",
    f"mcp__{SERVER_NAME}__search_osv": "osv_dev_api",
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

    async def pre_tool_use(input_data: dict[str, Any], tool_use_id: Any, context: Any) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        tool_input = input_data.get("tool_input") or {}
        reason: str | None = None
        if tool_name in _SOURCE_TOOLS and not ctx.budget_remaining():
            reason = "API-call budget exhausted for this run."
        elif tool_name in _SOURCE_TOOLS and len(ctx.executed_calls) >= ctx.max_calls_this_round:
            reason = "Per-round source-call budget exhausted."
        elif tool_name in _SOURCE_TOOLS and ctx.adaptive:
            # Lazy import keeps the hook definitions independent from MCP server
            # construction during clean-process imports.
            from .tools.source_tools import validate_adaptive_candidate_call

            candidate_id = str(tool_input.get("candidate_id") or "")
            reason = validate_adaptive_candidate_call(
                ctx, _SOURCE_TOOLS[tool_name], candidate_id
            )
        if reason:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        return {}

    async def post_tool_use(input_data: dict[str, Any], tool_use_id: Any, context: Any) -> dict[str, Any]:
        audit = getattr(ctx, "hook_audit", None)
        if not isinstance(audit, list):
            audit = []
            setattr(ctx, "hook_audit", audit)
        audit.append(
            {
                "tool": str(input_data.get("tool_name", "")),
                "api_calls_used": ctx.api_calls_used,
            }
        )
        return {}

    async def post_tool_failure(
        input_data: dict[str, Any], tool_use_id: Any, context: Any
    ) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        if tool_name in _SOURCE_TOOLS:
            short_name = tool_name.rsplit("__", 1)[-1]
            ctx.run_gaps.append(
                RunGap(
                    gap_id=f"run:tool_failure:{short_name}:{len(ctx.run_gaps)}",
                    gap_type="retry",
                    status="open",
                    priority="high",
                    retryable=True,
                    rationale=str(input_data.get("error") or "source tool failed")[:300],
                    metadata={"tool_name": tool_name},
                )
            )
        return {}

    return {
        "PreToolUse": [HookMatcher(hooks=[pre_tool_use])],
        "PostToolUse": [HookMatcher(hooks=[post_tool_use])],
        "PostToolUseFailure": [HookMatcher(hooks=[post_tool_failure])],
    }
