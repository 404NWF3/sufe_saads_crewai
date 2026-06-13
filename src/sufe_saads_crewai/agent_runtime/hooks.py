"""PreToolUse / PostToolUse hooks for the agentic collection session.

These run in the local Python process (no endpoint dependency): PreToolUse
enforces the API-call budget and blocks repeated source queries; PostToolUse
records every tool call for blackboard accounting and bandit updates.

The callbacks follow the claude-agent-sdk hook signature
``async (input_data, tool_use_id, context) -> dict`` but are plain Python and
fully unit-testable without the SDK.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

INTEL_SOURCE_TOOL_PREFIX = "mcp__intel_sources__"


@dataclass
class HookState:
    max_api_calls: int = 100
    max_calls_per_round: int = 25
    calls_used: int = 0
    calls_this_round: int = 0
    executed_query_keys: set[str] = field(default_factory=set)
    denied: list[dict[str, Any]] = field(default_factory=list)
    recorded: list[dict[str, Any]] = field(default_factory=list)

    def begin_round(self) -> None:
        self.calls_this_round = 0


def tool_query_key(tool_name: str, tool_input: dict[str, Any]) -> str:
    significant = {
        key: value
        for key, value in sorted(tool_input.items())
        if value not in (None, "", [], {})
    }
    return json.dumps({"tool": tool_name, "input": significant}, ensure_ascii=False, sort_keys=True)


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def build_pre_tool_use_hook(state: HookState) -> Callable[..., Any]:
    async def pre_tool_use(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        if not tool_name.startswith(INTEL_SOURCE_TOOL_PREFIX):
            return {}
        tool_input = input_data.get("tool_input") or {}

        if state.calls_used >= state.max_api_calls:
            state.denied.append({"tool": tool_name, "reason": "run_budget_exhausted"})
            return _deny(
                f"API call budget exhausted ({state.calls_used}/{state.max_api_calls}). "
                "Stop collecting and summarize what you have."
            )
        if state.calls_this_round >= state.max_calls_per_round:
            state.denied.append({"tool": tool_name, "reason": "round_budget_exhausted"})
            return _deny(
                f"Per-round call cap reached ({state.calls_this_round}/{state.max_calls_per_round}). "
                "Finish this round with the items already collected."
            )
        key = tool_query_key(tool_name, tool_input)
        if key in state.executed_query_keys:
            state.denied.append({"tool": tool_name, "reason": "duplicate_query"})
            return _deny(
                "This exact source query was already executed in this run. "
                "Change the query text or parameters instead of repeating it."
            )
        return {}

    return pre_tool_use


def build_post_tool_use_hook(
    state: HookState,
    on_record: Callable[[dict[str, Any]], None] | None = None,
) -> Callable[..., Any]:
    async def post_tool_use(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        if not tool_name.startswith(INTEL_SOURCE_TOOL_PREFIX):
            return {}
        tool_input = input_data.get("tool_input") or {}
        state.calls_used += 1
        state.calls_this_round += 1
        state.executed_query_keys.add(tool_query_key(tool_name, tool_input))
        record = {
            "tool": tool_name,
            "input": tool_input,
            "tool_use_id": tool_use_id,
        }
        state.recorded.append(record)
        if on_record is not None:
            on_record(record)
        return {}

    return post_tool_use
