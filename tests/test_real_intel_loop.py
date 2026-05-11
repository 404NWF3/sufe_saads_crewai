from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from sufe_saads_crewai.crew import SufeSaadsCrewai
from sufe_saads_crewai.intel import RealIntelAgentSet, RealIntelRunController
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import (
    RawIntelItem,
    RawIntelItemBatch,
    SearchQueryPlan,
    SourceExecutionStat,
)


class FailingAgent:
    def kickoff(self, prompt: str):
        raise RuntimeError("LLM disabled for deterministic unit test")


class FakeAgentResult:
    def __init__(self, raw: str) -> None:
        self.raw = raw


class RecommendedQueryCriticAgent:
    def __init__(self, recommended_next_query: str) -> None:
        self.recommended_next_query = recommended_next_query

    def kickoff(self, prompt: str):
        if not prompt.startswith(
            "Decide whether the real-source intelligence search should continue"
        ):
            raise RuntimeError("Use deterministic fallbacks before completeness")
        return FakeAgentResult(
            json.dumps(
                {
                    "should_continue": True,
                    "completeness_score": 0.35,
                    "missing_topics": ["agent tool abuse"],
                    "recommended_next_query": self.recommended_next_query,
                    "stop_reason": None,
                    "rationale": "Continue with the high-ROI agent tool abuse gap.",
                }
            )
        )


class FakeRegisteredSourceTool:
    def _run(
        self,
        query_text: str,
        source_names: list[str] | None = None,
        target_topics: list[str] | None = None,
        max_results: int = 10,
        round_index: int = 0,
        approved_sources_json: str = "[]",
        **kwargs,
    ) -> str:
        if kwargs.get("nvd_keyword_search"):
            topics = ["model supply chain"]
            title = f"NVD CVE candidate for {kwargs['nvd_keyword_search']}"
            item_id = f"fake-nvd-{kwargs['nvd_keyword_search']}".replace(
                " ", "-"
            ).lower()
            source_name = "nvd_cve_api"
        elif kwargs.get("osv_package_name"):
            topics = ["model supply chain"]
            title = f"OSV advisory for {kwargs['osv_package_name']}"
            item_id = f"fake-osv-{kwargs['osv_package_name']}".replace(" ", "-").lower()
            source_name = "osv_dev_api"
        elif "jailbreak" in query_text.lower():
            topics = ["jailbreak", "model supply chain", "rag poisoning"]
            title = "Jailbreak and model supply chain intelligence from registered APIs"
            item_id = "fake-real-round-2"
            source_name = "arxiv_api"
        else:
            topics = ["prompt injection"]
            title = "Prompt injection intelligence from registered APIs"
            item_id = "fake-real-round-1"
            source_name = source_names[0] if source_names else "arxiv_api"

        batch = RawIntelItemBatch(
            items=[
                RawIntelItem(
                    item_id=item_id,
                    source_name=source_name,
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
                    source_name=source_name,
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
        collector = next(
            agent for agent in crew.agents if "多源情报采集员" in agent.role
        )
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
            payload = json.loads(
                run_store.run_path(result.run_id).read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(len(payload["raw_item_batches"]), 2)
            self.assertIn(
                "EXPAND_SEARCH_SEMANTICS",
                [
                    action["action_type"]
                    for action in payload["blackboard"]["action_history"]
                ],
            )
            first_round_plans = payload["blackboard"]["query_history"][0]["metadata"][
                "source_query_plans"
            ]
            self.assertTrue(
                any(plan["source_name"] == "nvd_cve_api" for plan in first_round_plans)
            )
            self.assertTrue(
                any(plan["source_name"] == "osv_dev_api" for plan in first_round_plans)
            )

    def test_critic_recommended_query_becomes_next_round_query(self) -> None:
        recommended_query = "LLM agent tool abuse code execution exploit"
        with TemporaryDirectory() as temp_dir:
            agents = RealIntelAgentSet(
                planner=FailingAgent(),
                collector=FailingAgent(),
                critic=RecommendedQueryCriticAgent(recommended_query),
            )
            with patch.dict(os.environ, {"INTEL_ENABLE_AGENT_KICKOFF": "true"}):
                result = RealIntelRunController(
                    run_goal="Collect LLM security intelligence",
                    initial_query="LLM prompt injection",
                    max_rounds=2,
                    run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                    agents=agents,
                    source_tool=FakeRegisteredSourceTool(),
                ).run()

            self.assertEqual(len(result.query_history), 2)
            self.assertEqual(result.query_history[1].query_text, recommended_query)

    def test_source_specific_strategy_generates_distinct_nvd_queries(self) -> None:
        with TemporaryDirectory() as temp_dir:
            agents = RealIntelAgentSet(
                planner=FailingAgent(),
                collector=FailingAgent(),
                critic=FailingAgent(),
            )
            controller = RealIntelRunController(
                run_goal="Collect LLM security intelligence",
                initial_query="LLM prompt injection",
                max_rounds=2,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                agents=agents,
                source_tool=FakeRegisteredSourceTool(),
            )
            blackboard = controller.run()

            nvd_queries = [
                plan["query_text"]
                for history in blackboard.query_history
                for plan in history.metadata.get("source_query_plans", [])
                if plan["source_name"] == "nvd_cve_api"
            ]

            self.assertGreaterEqual(len(set(nvd_queries)), 2)
            self.assertTrue(any("keywordSearch" in query for query in nvd_queries))

    def test_semantic_expansion_feeds_agent_tool_abuse_terms(self) -> None:
        with TemporaryDirectory() as temp_dir:
            agents = RealIntelAgentSet(
                planner=FailingAgent(),
                collector=FailingAgent(),
                critic=FailingAgent(),
            )
            result = RealIntelRunController(
                run_goal="Collect LLM security intelligence",
                initial_query="LLM agent tool abuse",
                max_rounds=2,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                agents=agents,
                source_tool=FakeRegisteredSourceTool(),
            ).run()

            semantic_actions = [
                action
                for action in result.action_history
                if action.action_type == "EXPAND_SEARCH_SEMANTICS"
            ]
            self.assertTrue(semantic_actions)
            serialized = json.dumps(semantic_actions[0].metadata, ensure_ascii=False)
            self.assertIn("unsafe tool execution", serialized)
            self.assertIn("nvd_cve_api", serialized)


if __name__ == "__main__":
    unittest.main()
