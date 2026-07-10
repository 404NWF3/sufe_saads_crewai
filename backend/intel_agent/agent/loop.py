"""One agentic collection round = one claude-agent-sdk session.

The agent calls the source/memory/control tools itself inside the SDK's native
tool loop; results accumulate in the shared ``ToolContext``. A fresh session per
round keeps cost bounded and every decision input (the digest) reproducible.
Hard session failures with no collected items degrade to the deterministic rules
path; turn-limit / truncated sessions that already gathered items soft-complete
so the controller keeps the agent yield instead of re-running rules fallback.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from ..observability import TraceSink
from ..runtime import client as runtime_client
from ..runtime.structured import _run_coro_sync
from ..hooks import build_hooks
from ..tools.context import ToolContext
from ..tools.server import build_round_server
from .system_prompt import SYSTEM_PROMPT

DEFAULT_ROUND_TIMEOUT_SECONDS = 300.0
# Search-heavy bootstrap rounds often need many parallel tool batches; 12 was
# too tight and triggered "Reached maximum number of turns" mid-sweep.
DEFAULT_MAX_TURNS = 24


def resolve_max_turns(explicit: int | None = None) -> int:
    if explicit is not None:
        return max(1, int(explicit))
    raw = (os.getenv("INTEL_AGENT_MAX_TURNS") or "").strip()
    if raw.isdigit():
        return max(1, int(raw))
    return DEFAULT_MAX_TURNS


@dataclass
class RoundSessionResult:
    completed: bool
    assistant_text: str
    error: str | None = None


class IntelAgentLoop:
    def __init__(
        self,
        model: str | None = None,
        max_turns: int | None = None,
        timeout_seconds: float = DEFAULT_ROUND_TIMEOUT_SECONDS,
        runner: Any | None = None,
    ) -> None:
        self.model = model or runtime_client.main_model()
        self.max_turns = resolve_max_turns(max_turns)
        self.timeout_seconds = timeout_seconds
        # Test seam: async (ctx, prompt, model, max_turns) -> str (assistant text)
        self._runner = runner or _default_session_runner

    def available(self) -> bool:
        if self._runner is not _default_session_runner:
            return True
        ok, _ = runtime_client.sdk_runtime_available()
        return ok

    def run_round(
        self, ctx: ToolContext, prompt: str, trace: TraceSink | None = None
    ) -> RoundSessionResult:
        if not self.available():
            return RoundSessionResult(False, "", "sdk runtime unavailable")
        try:
            coro = (
                self._runner(ctx, prompt, self.model, self.max_turns, trace)
                if self._runner is _default_session_runner
                else self._runner(ctx, prompt, self.model, self.max_turns)
            )
            text = _run_coro_sync(coro, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - round-level fallback / soft-complete
            return _finalize_round(ctx, "", f"{exc.__class__.__name__}: {exc}", trace)
        return _finalize_round(ctx, text or "", None, trace)


def _finalize_round(
    ctx: ToolContext,
    text: str,
    error: str | None,
    trace: TraceSink | None,
) -> RoundSessionResult:
    """Keep agent yield on turn-limit / SDK error if searches already wrote items."""
    has_yield = bool(ctx.collected_items) or bool(ctx.notes)
    if error and has_yield:
        _ensure_truncated_note(ctx, error)
        if trace is not None:
            trace.emit(
                "session_truncated",
                reason=error,
                collected=len(ctx.collected_items),
            )
        return RoundSessionResult(True, text, error)
    if error:
        return RoundSessionResult(False, text, error)
    return RoundSessionResult(has_yield, text, None)


def _ensure_truncated_note(ctx: ToolContext, error: str) -> None:
    if ctx.notes:
        return
    ctx.notes.append(
        {
            "summary": (
                f"Round truncated ({error[:160]}). Kept {len(ctx.collected_items)} "
                "items already collected before the session ended."
            ),
            "covered_topics": [],
            "remaining_gaps": list(ctx.target_topics),
        }
    )


def _short_tool_name(name: str) -> str:
    return name.rsplit("__", 1)[-1] if name.startswith("mcp__") else name


async def _default_session_runner(
    ctx: ToolContext, prompt: str, model: str, max_turns: int, trace: TraceSink | None = None
) -> str:
    from claude_agent_sdk import (
        AssistantMessage,
        ResultMessage,
        TextBlock,
        ThinkingBlock,
        ToolResultBlock,
        ToolUseBlock,
        UserMessage,
        query,
    )

    mcp_servers, allowed_tools = build_round_server(ctx)
    options = runtime_client.build_options(
        model=model,
        max_turns=max_turns,
        system_prompt=SYSTEM_PROMPT,
        mcp_servers=mcp_servers,
        allowed_tools=allowed_tools,
        hooks=build_hooks(ctx),
    )
    texts: list[str] = []
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    texts.append(block.text)
                    if trace and block.text.strip():
                        trace.emit("assistant_text", text=block.text)
                elif isinstance(block, ThinkingBlock) and trace:
                    trace.emit("thinking", text=block.thinking)
                elif isinstance(block, ToolUseBlock) and trace:
                    trace.emit("tool_call", tool=_short_tool_name(block.name), input=block.input)
        elif isinstance(message, UserMessage) and trace and isinstance(message.content, list):
            for block in message.content:
                if isinstance(block, ToolResultBlock):
                    trace.emit("tool_result", content=block.content, is_error=block.is_error)
        elif isinstance(message, ResultMessage):
            if trace:
                trace.emit(
                    "session_end",
                    turns=message.num_turns,
                    cost_usd=message.total_cost_usd,
                    is_error=message.is_error,
                )
            # Empty yield + error → hard fail (controller rules fallback).
            # Non-empty yield → return normally; if the SDK also raises after this
            # message, run_round soft-completes via _finalize_round.
            if message.is_error and not ctx.collected_items and not ctx.notes:
                raise RuntimeError(f"sdk session error: {str(message.result)[:200]}")
    return "\n".join(texts)
