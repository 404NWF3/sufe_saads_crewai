"""One agentic collection round = one claude-agent-sdk session.

The agent calls the source/memory/control tools itself inside the SDK's native
tool loop; results accumulate in the shared ``ToolContext``. A fresh session per
round keeps cost bounded and every decision input (the digest) reproducible.
Hard session failures with no collected items degrade to the deterministic rules
path; turn-limit / truncated sessions that already gathered items soft-complete
so the controller keeps the agent yield instead of re-running rules fallback.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import threading
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
        client_factory: Any | None = None,
    ) -> None:
        self.model = model or runtime_client.main_model()
        self.max_turns = resolve_max_turns(max_turns)
        self.timeout_seconds = timeout_seconds
        # Test seam: async (ctx, prompt, model, max_turns) -> str (assistant text)
        self._runner = runner
        self._client_factory = client_factory
        self._session: _ContinuousSDKSession | None = None
        self._continuous_enabled = True

    def available(self) -> bool:
        if self._runner is not None:
            return True
        ok, _ = runtime_client.sdk_runtime_available()
        return ok

    def start_run(self, run_id: str, continuous: bool = True) -> None:
        if self._runner is not None:
            return
        self.end_run()
        self._continuous_enabled = continuous
        if not continuous:
            return
        self._session = _ContinuousSDKSession(
            model=self.model,
            max_turns=self.max_turns,
            timeout_seconds=self.timeout_seconds,
            client_factory=self._client_factory,
        )

    def end_run(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    @property
    def session_id(self) -> str | None:
        return self._session.session_id if self._session is not None else None

    def run_round(
        self, ctx: ToolContext, prompt: str, trace: TraceSink | None = None
    ) -> RoundSessionResult:
        if not self.available():
            return RoundSessionResult(False, "", "sdk runtime unavailable")
        try:
            if self._runner is None:
                if self._continuous_enabled:
                    if self._session is None:
                        self.start_run(ctx.run_id)
                    assert self._session is not None
                    text = self._session.run_round(ctx, prompt, trace)
                else:
                    text = _run_coro_sync(
                        _one_off_session_runner(
                            ctx, prompt, self.model, self.max_turns, trace
                        ),
                        timeout_seconds=self.timeout_seconds,
                    )
            else:
                text = _run_coro_sync(
                    self._runner(ctx, prompt, self.model, self.max_turns),
                    timeout_seconds=self.timeout_seconds,
                )
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


async def _one_off_session_runner(
    ctx: ToolContext,
    prompt: str,
    model: str,
    max_turns: int,
    trace: TraceSink | None,
) -> str:
    """Legacy/full behavior: one isolated SDK query per controller round."""
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
            if message.is_error and not ctx.collected_items and not ctx.notes:
                raise RuntimeError(f"sdk session error: {str(message.result)[:200]}")
    return "\n".join(texts)


class _ToolContextProxy:
    """Stable object captured by MCP handlers while the active round context changes."""

    def __init__(self) -> None:
        object.__setattr__(self, "_current", None)

    def bind(self, ctx: ToolContext) -> None:
        object.__setattr__(self, "_current", ctx)

    def __getattr__(self, name: str) -> Any:
        current = object.__getattribute__(self, "_current")
        if current is None:
            raise RuntimeError("SDK tool context is not bound to a round")
        return getattr(current, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_current":
            object.__setattr__(self, name, value)
            return
        current = object.__getattribute__(self, "_current")
        if current is None:
            raise RuntimeError("SDK tool context is not bound to a round")
        setattr(current, name, value)


class _AsyncWorker:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, name="intel-agent-sdk", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro: Any, timeout: float) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError(f"SDK round exceeded {timeout:.0f}s") from None

    def close(self) -> None:
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=5)
        if not self.loop.is_closed():
            self.loop.close()


class _ContinuousSDKSession:
    """One ClaudeSDKClient and event loop for the lifetime of an incremental run."""

    def __init__(
        self,
        model: str,
        max_turns: int,
        timeout_seconds: float,
        client_factory: Any | None = None,
    ) -> None:
        self.model = model
        self.max_turns = max_turns
        self.timeout_seconds = timeout_seconds
        self.proxy = _ToolContextProxy()
        self.worker = _AsyncWorker()
        self.client: Any | None = None
        self.session_id: str | None = None
        self.client_factory = client_factory

    def run_round(
        self, ctx: ToolContext, prompt: str, trace: TraceSink | None
    ) -> str:
        self.proxy.bind(ctx)
        return str(self.worker.submit(self._run_with_recovery(prompt, trace), self.timeout_seconds))

    async def _connect(self, resume: str | None = None) -> None:
        from claude_agent_sdk import ClaudeSDKClient

        mcp_servers, allowed_tools = build_round_server(self.proxy)  # type: ignore[arg-type]
        options = runtime_client.build_options(
            model=self.model,
            max_turns=self.max_turns,
            system_prompt=SYSTEM_PROMPT,
            mcp_servers=mcp_servers,
            allowed_tools=allowed_tools,
            hooks=build_hooks(self.proxy),  # type: ignore[arg-type]
            resume=resume,
        )
        factory = self.client_factory or ClaudeSDKClient
        self.client = factory(options=options)
        await self.client.connect()

    async def _disconnect(self) -> None:
        if self.client is not None:
            try:
                await self.client.disconnect()
            finally:
                self.client = None

    async def _run_with_recovery(self, prompt: str, trace: TraceSink | None) -> str:
        if self.client is None:
            await self._connect()
        try:
            return await self._query_once(prompt, trace)
        except Exception as original:
            if self.proxy.collected_items or self.proxy.notes:
                raise
            last_error: Exception = original
            recovery_modes = [self.session_id] if self.session_id else []
            recovery_modes.append(None)
            for resume in recovery_modes:
                try:
                    await self._disconnect()
                    await self._connect(resume=resume)
                    if trace is not None:
                        trace.emit("session_recovery", mode="resume" if resume else "fresh")
                    return await self._query_once(prompt, trace)
                except Exception as exc:  # noqa: BLE001 - try next recovery tier
                    last_error = exc
            raise last_error from original

    async def _query_once(self, prompt: str, trace: TraceSink | None) -> str:
        from claude_agent_sdk import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ThinkingBlock,
            ToolResultBlock,
            ToolUseBlock,
            UserMessage,
        )

        assert self.client is not None
        await self.client.query(prompt)
        texts: list[str] = []
        async for message in self.client.receive_response():
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
                self.session_id = message.session_id or self.session_id
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
                if message.is_error and not self.proxy.collected_items and not self.proxy.notes:
                    raise RuntimeError(f"sdk session error: {str(message.result)[:200]}")
        return "\n".join(texts)

    def close(self) -> None:
        try:
            if self.client is not None:
                self.worker.submit(self._disconnect(), timeout=10)
        finally:
            self.worker.close()
