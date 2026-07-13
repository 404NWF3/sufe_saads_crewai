from __future__ import annotations

import subprocess
import sys
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


def test_sdk_mcp_modules_import_from_a_clean_process():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from intel_agent.tools.context import ToolContext; "
                "from intel_agent.tools.server import build_round_server; "
                "from intel_agent.hooks import build_hooks; "
                "c=ToolContext(run_id='t', target_topics=[], topic_bucket='general', adaptive=True); "
                "build_round_server(c); build_hooks(c)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_adaptive_mcp_surface_contains_only_the_planned_whitelist():
    from intel_agent.tools.server import build_round_server

    ctx = _ctx()
    ctx.adaptive = True
    _, allowed = build_round_server(ctx)
    assert len(allowed) == 8
    assert all(not name.endswith("__record_technique") for name in allowed)
    assert any(name.endswith("__get_collection_state") for name in allowed)
    assert any(name.endswith("__score_query_candidates") for name in allowed)


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


def test_default_loop_reuses_one_claude_sdk_client_across_rounds():
    from claude_agent_sdk import ResultMessage

    instances = []

    class FakeClient:
        def __init__(self, options):
            self.options = options
            self.queries = []
            self.disconnected = False
            instances.append(self)

        async def connect(self):
            return None

        async def query(self, prompt):
            self.queries.append(prompt)

        async def receive_response(self):
            yield ResultMessage(
                subtype="success",
                duration_ms=1,
                duration_api_ms=1,
                is_error=False,
                num_turns=1,
                session_id=f"session-{len(self.queries)}",
            )

        async def disconnect(self):
            self.disconnected = True

    loop = IntelAgentLoop(client_factory=FakeClient)
    loop.start_run("run")
    first = _ctx()
    first.notes.append({"summary": "first"})
    second = _ctx()
    second.notes.append({"summary": "second"})
    assert loop.run_round(first, "round one").completed is True
    assert loop.run_round(second, "round two").completed is True
    assert len(instances) == 1
    assert instances[0].queries == ["round one", "round two"]
    assert instances[0].options.tools == []
    assert instances[0].options.setting_sources == []
    assert loop.session_id == "session-2"
    loop.end_run()
    assert instances[0].disconnected is True


def test_default_loop_resumes_failed_sdk_session_before_fresh_fallback():
    from claude_agent_sdk import ResultMessage

    options_seen = []

    class FakeClient:
        def __init__(self, options):
            self.options = options
            options_seen.append(options)

        async def connect(self):
            return None

        async def query(self, prompt):
            return None

        async def receive_response(self):
            if len(options_seen) == 1:
                yield ResultMessage(
                    subtype="error_during_execution",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=True,
                    num_turns=1,
                    session_id="failed-session",
                    result="transient",
                )
            else:
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="recovered-session",
                )

        async def disconnect(self):
            return None

    loop = IntelAgentLoop(client_factory=FakeClient)
    result = loop.run_round(_ctx(), "recover")
    assert result.completed is False  # transport recovered, but no source yield was fabricated
    assert len(options_seen) == 2
    assert options_seen[1].resume == "failed-session"
    assert loop.session_id == "recovered-session"
    loop.end_run()


def test_default_loop_uses_fresh_session_when_resume_also_fails():
    from claude_agent_sdk import ResultMessage

    options_seen = []

    class FakeClient:
        def __init__(self, options):
            self.options = options
            options_seen.append(options)

        async def connect(self):
            return None

        async def query(self, prompt):
            return None

        async def receive_response(self):
            attempt = len(options_seen)
            if attempt == 1:
                yield ResultMessage(
                    subtype="error_during_execution",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=True,
                    num_turns=1,
                    session_id="resume-me",
                    result="initial failure",
                )
            elif attempt == 2:
                raise RuntimeError("resume failed")
            else:
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="fresh-session",
                )

        async def disconnect(self):
            return None

    loop = IntelAgentLoop(client_factory=FakeClient)
    result = loop.run_round(_ctx(), "recover twice")
    assert result.completed is False
    assert [options.resume for options in options_seen] == [None, "resume-me", None]
    assert loop.session_id == "fresh-session"
    loop.end_run()
