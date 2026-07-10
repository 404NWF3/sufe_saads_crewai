from __future__ import annotations

import json
from datetime import datetime, timezone

from intel_agent.agent.loop import IntelAgentLoop
from intel_agent.engine.controller import IntelAgentController
from intel_agent.engine.modes import FullCollectionMode
from intel_agent.memory.playbook import PlaybookStore
from intel_agent.observability import TraceSink, _format
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.runtime.structured import StructuredDecisionEngine
from intel_agent.schemas import RawIntelItem, RunBudget


def _read_events(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_trace_sink_writes_jsonl_and_binds_run(tmp_path):
    sink = TraceSink(console=False, trace_dir=tmp_path)
    sink.bind_run("run/with:unsafe*chars")
    sink.emit("tool_call", tool="search_nvd", input={"q": "prompt injection"})
    sink.emit("session_end", turns=3, cost_usd=0.01, is_error=False)
    sink.close()

    assert sink.path is not None and sink.path.exists()
    events = _read_events(sink.path)
    assert [e["event"] for e in events] == ["tool_call", "session_end"]
    assert events[0]["tool"] == "search_nvd"
    assert all("ts" in e for e in events)


def test_format_renders_known_events_and_skips_unknown():
    assert "round 1/4" in _format({"event": "round_start", "round": 1, "max_rounds": 4, "mode": "bootstrap"})
    assert "search_nvd" in _format({"event": "tool_call", "tool": "search_nvd", "input": {}})
    assert "[critic]" in _format(
        {"event": "critic", "should_continue": False, "completeness_score": 1.0, "rationale": "done"}
    )
    assert _format({"event": "mystery"}) == ""


def test_on_event_callback_receives_records(tmp_path):
    seen: list[dict] = []
    sink = TraceSink(console=False, trace_dir=tmp_path, on_event=seen.append)
    sink.bind_run("cb-run")
    sink.emit("tool_call", tool="search_nvd", input={"q": "x"})
    sink.close()
    assert len(seen) == 1
    assert seen[0]["event"] == "tool_call"
    assert seen[0]["tool"] == "search_nvd"


def _fake_loop() -> IntelAgentLoop:
    async def runner(ctx, prompt, model, max_turns):
        item_id = "nvd:1"
        ctx.collected_items[item_id] = RawIntelItem(
            item_id=item_id,
            source_name="nvd_cve_api",
            source_uri="https://x/1",
            title="prompt injection 1",
            summary="prompt injection against a large language model",
            published_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            relevance_score=0.9,
            metadata={"topics": ["prompt injection"]},
        )
        ctx.api_calls_used += 1
        ctx.executed_calls.append(
            {
                "source_name": "nvd_cve_api",
                "query_text": "prompt injection",
                "params": {"nvd_cwe_id": "CWE-94"},
                "new_item_ids": [item_id],
                "signature": "nvd_cve_api[nvd_cwe_id]",
            }
        )
        ctx.notes.append({"summary": "found", "covered_topics": [], "remaining_gaps": []})
        return "done"

    return IntelAgentLoop(runner=runner)


def _stop_engine() -> StructuredDecisionEngine:
    async def runner(prompt, schema, system_prompt, model, max_turns):
        return {
            "should_continue": False,
            "completeness_score": 1.0,
            "missing_topics": [],
            "stop_reason": "sufficient",
            "rationale": "sufficient",
        }

    return StructuredDecisionEngine(runner=runner)


def test_controller_emits_round_and_critic_events(tmp_path):
    trace = TraceSink(console=False, trace_dir=tmp_path / "traces")
    controller = IntelAgentController(
        store=JsonIntelRunStore(root_dir=tmp_path),
        playbook=PlaybookStore(path=None),
        relevance=None,
        loop=_fake_loop(),
        decision_engine=_stop_engine(),
    )
    controller.run(
        mode=FullCollectionMode(),
        budget=RunBudget(max_rounds=2, max_api_calls=10),
        run_id="trace-run",
        trace=trace,
    )

    events = {e["event"] for e in _read_events(trace.path)}
    assert {"round_start", "round_summary", "critic"} <= events
