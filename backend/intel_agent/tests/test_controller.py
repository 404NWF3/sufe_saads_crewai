from __future__ import annotations

from datetime import datetime, timezone

from intel_agent.agent.loop import IntelAgentLoop
from intel_agent.engine.controller import IntelAgentController
from intel_agent.engine.modes import FullCollectionMode
from intel_agent.memory.playbook import PlaybookStore
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.runtime.structured import StructuredDecisionEngine
from intel_agent.schemas import RawIntelItem, RunBudget


def _fake_loop() -> IntelAgentLoop:
    counter = {"n": 0}

    async def runner(ctx, prompt, model, max_turns):
        counter["n"] += 1
        base = counter["n"] * 10
        new_ids = []
        for offset in range(2):
            item_id = f"nvd:{base + offset}"
            ctx.collected_items[item_id] = RawIntelItem(
                item_id=item_id,
                source_name="nvd_cve_api",
                source_uri=f"https://x/{item_id}",
                title=f"prompt injection {item_id}",
                summary="prompt injection against a large language model",
                published_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
                relevance_score=0.9,
                metadata={"topics": ["prompt injection"]},
            )
            new_ids.append(item_id)
        ctx.api_calls_used += 1
        ctx.executed_calls.append(
            {
                "source_name": "nvd_cve_api",
                "query_text": "prompt injection",
                "params": {"nvd_cwe_id": "CWE-94"},
                "new_item_ids": new_ids,
                "signature": "nvd_cve_api[nvd_cwe_id]",
            }
        )
        ctx.notes.append({"summary": "found prompt injection CVEs", "covered_topics": [], "remaining_gaps": []})
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


def test_controller_end_to_end_offline(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    playbook = PlaybookStore(path=tmp_path / "playbook.jsonl")
    controller = IntelAgentController(
        store=store,
        playbook=playbook,
        relevance=None,
        loop=_fake_loop(),
        decision_engine=_stop_engine(),
    )
    blackboard = controller.run(
        mode=FullCollectionMode(),
        budget=RunBudget(max_rounds=2, max_api_calls=10),
        run_id="test-run",
    )

    assert len(blackboard.raw_items) >= 2
    assert blackboard.query_history
    assert blackboard.metrics.api_calls_used >= 1
    # run persisted + readable
    assert store.run_path("test-run").exists()
    assert store.load_latest_payload()["run_id"] == "test-run"
    # playbook harvested a technique from the high-yield call
    assert any(e.source_name == "nvd_cve_api" for e in playbook.entries.values())


def test_controller_falls_back_when_agent_unavailable(tmp_path, monkeypatch):
    store = JsonIntelRunStore(root_dir=tmp_path)

    unavailable_loop = IntelAgentLoop()
    monkeypatch.setattr(unavailable_loop, "available", lambda: False)

    called = {"fallback": 0}

    def fake_fallback(ctx, blackboard, query_plan, target_topics):
        called["fallback"] += 1
        ctx.notes.append({"summary": "fallback", "covered_topics": [], "remaining_gaps": target_topics})

    monkeypatch.setattr("intel_agent.engine.controller.run_fallback_round", fake_fallback)

    controller = IntelAgentController(
        store=store,
        playbook=PlaybookStore(path=None),
        relevance=None,
        loop=unavailable_loop,
        decision_engine=_stop_engine(),
    )
    controller.run(mode=FullCollectionMode(), budget=RunBudget(max_rounds=1, max_api_calls=5))
    assert called["fallback"] == 1
