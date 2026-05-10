from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sufe_saads_crewai.crew import SufeSaadsCrewai
from sufe_saads_crewai.intel import RealIntelAgentSet, RealIntelRunController
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import RawIntelItem, RawIntelItemBatch, SearchQueryPlan, SourceExecutionStat


class FailingAgent:
    def kickoff(self, prompt: str):
        raise RuntimeError("LLM disabled for deterministic unit test")


class FakeRegisteredSourceTool:
    def _run(
        self,
        query_text: str,
        source_names: list[str] | None = None,
        target_topics: list[str] | None = None,
        max_results: int = 10,
        round_index: int = 0,
        approved_sources_json: str = "[]",
    ) -> str:
        if "jailbreak" in query_text.lower():
            topics = ["jailbreak", "model supply chain", "rag poisoning"]
            title = "Jailbreak and model supply chain intelligence from registered APIs"
            item_id = "fake-real-round-2"
        else:
            topics = ["prompt injection"]
            title = "Prompt injection intelligence from registered APIs"
            item_id = "fake-real-round-1"

        batch = RawIntelItemBatch(
            items=[
                RawIntelItem(
                    item_id=item_id,
                    source_name="arxiv_api",
                    source_uri=f"https://example.test/{item_id}",
                    title=title,
                    summary=title,
                    relevance_score=0.8,
                    metadata={"topics": topics},
                )
            ],
            query_plan=SearchQueryPlan(
                query_text=query_text,
                source_names=source_names or [],
                target_topics=target_topics or [],
                max_results=max_results,
                round_index=round_index,
            ),
            source_stats=[
                SourceExecutionStat(
                    source_name="arxiv_api",
                    query_count=1,
                    result_count=1,
                    success=True,
                )
            ],
            batch_notes="fake real registered API response",
        )
        return batch.model_dump_json()


class RealIntelLoopTests(unittest.TestCase):
    def test_production_agents_use_glm_and_collector_has_no_mock_tools(self) -> None:
        crew = SufeSaadsCrewai().crew()
        models = [getattr(agent.llm, "model", "") for agent in crew.agents]
        collector = next(agent for agent in crew.agents if "多源情报采集员" in agent.role)
        tool_names = {tool.name for tool in collector.tools}

        self.assertNotIn("gpt-4.1-mini", models)
        self.assertTrue(any(model.lower().startswith("glm") for model in models))
        self.assertEqual(tool_names, {"registered_api_source_search"})

    def test_real_controller_rewrites_query_and_runs_second_round(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")
            agents = RealIntelAgentSet(
                planner=FailingAgent(),
                collector=FailingAgent(),
                critic=FailingAgent(),
            )

            result = RealIntelRunController(
                run_goal="Collect LLM security intelligence",
                initial_query="LLM prompt injection",
                max_rounds=2,
                run_store=run_store,
                agents=agents,
                source_tool=FakeRegisteredSourceTool(),
            ).run()

            self.assertEqual(len(result.query_history), 2)
            self.assertNotEqual(
                result.query_history[0].query_text,
                result.query_history[1].query_text,
            )
            self.assertTrue(result.reflection_notes)
            self.assertEqual(result.action_history[-1].action_type, "STOP")
            payload = json.loads(run_store.run_path(result.run_id).read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(len(payload["raw_item_batches"]), 2)


if __name__ == "__main__":
    unittest.main()
