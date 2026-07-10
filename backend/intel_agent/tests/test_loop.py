from __future__ import annotations

from datetime import datetime, timezone

from intel_agent.agent.loop import IntelAgentLoop, resolve_max_turns
from intel_agent.schemas import RawIntelItem
from intel_agent.tools.context import ToolContext


def _ctx() -> ToolContext:
    return ToolContext(
        run_id="t",
        target_topics=["model denial of service"],
        topic_bucket="general",
    )


def test_resolve_max_turns_default_and_env(monkeypatch):
    monkeypatch.delenv("INTEL_AGENT_MAX_TURNS", raising=False)
    assert resolve_max_turns(None) == 24
    assert resolve_max_turns(8) == 8
    monkeypatch.setenv("INTEL_AGENT_MAX_TURNS", "30")
    assert resolve_max_turns(None) == 30


def test_soft_complete_keeps_items_on_turn_limit():
    async def runner(ctx, prompt, model, max_turns):
        ctx.collected_items["nvd:1"] = RawIntelItem(
            item_id="nvd:1",
            source_name="nvd_cve_api",
            source_uri="https://x/1",
            title="LLM DoS",
            summary="model denial of service",
            published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        raise Exception("Claude Code returned an error result: Reached maximum number of turns (12)")

    loop = IntelAgentLoop(runner=runner, max_turns=12)
    result = loop.run_round(_ctx(), "go")
    assert result.completed is True
    assert "maximum number of turns" in (result.error or "")
    assert result.assistant_text == ""


def test_hard_fail_without_yield_triggers_incomplete():
    async def runner(ctx, prompt, model, max_turns):
        raise Exception("Claude Code returned an error result: Reached maximum number of turns (12)")

    loop = IntelAgentLoop(runner=runner, max_turns=12)
    result = loop.run_round(_ctx(), "go")
    assert result.completed is False
    assert result.error
