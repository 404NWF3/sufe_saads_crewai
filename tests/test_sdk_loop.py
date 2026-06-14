from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pydantic import BaseModel

from sufe_saads_crewai.agent_runtime.structured import StructuredDecisionEngine
from sufe_saads_crewai.intel import rules
from sufe_saads_crewai.intel.bandit import SourceBandit
from sufe_saads_crewai.intel.sdk_loop import SdkIntelRunController
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import (
    RawIntelItem,
    RawIntelItemBatch,
    SearchQueryPlan,
    SourceExecutionStat,
)


class FakeRegisteredSourceTool:
    """Mirrors the fake in test_real_intel_loop.py for deterministic batches."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

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
        self.calls.append({"query_text": query_text, "source_names": source_names, **kwargs})
        source_name = source_names[0] if source_names else "arxiv_api"
        prefix = {
            "nvd_cve_api": "nvd",
            "arxiv_api": "arxiv",
            "cisa_kev_json": "cisa-kev",
            "osv_dev_api": "osv",
        }[source_name]
        item_id = f"{prefix}:{abs(hash(query_text + source_name)) % 10_000_000}"
        batch = RawIntelItemBatch(
            items=[
                RawIntelItem(
                    item_id=item_id,
                    source_name=source_name,
                    source_uri=f"https://example.test/{item_id}",
                    title=f"prompt injection finding for {query_text[:40]}",
                    summary="prompt injection evidence",
                    relevance_score=0.8,
                    metadata={"topics": ["prompt injection"]},
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
            batch_notes="fake sdk-engine response",
        )
        return batch.model_dump_json()


def _failing_engine() -> StructuredDecisionEngine:
    async def runner(prompt, schema, system_prompt, model, max_turns):
        raise RuntimeError("decision LLM disabled for unit test")

    return StructuredDecisionEngine(model="fake", fast_model="fake", runner=runner)


def _scripted_engine(script: dict[str, dict]) -> StructuredDecisionEngine:
    """Returns canned decisions keyed by schema title."""

    async def runner(prompt, schema, system_prompt, model, max_turns):
        return script.get(schema.get("title", ""), None)

    return StructuredDecisionEngine(model="fake", fast_model="fake", runner=runner)


class SdkLoopFallbackTests(unittest.TestCase):
    def test_all_decisions_failing_degrades_to_rules_and_completes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")
            controller = SdkIntelRunController(
                run_goal="Collect LLM security intelligence",
                initial_query="LLM prompt injection",
                max_rounds=2,
                run_store=run_store,
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_failing_engine(),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
            )
            result = controller.run()

            self.assertEqual(len(result.query_history), 2)
            self.assertEqual(result.action_history[-1].action_type, "STOP")
            # fallbacks are observable, not silent
            fallback_errors = [
                error for error in result.errors if error.error_type == "decision_fallback"
            ]
            self.assertTrue(fallback_errors)
            payload = json.loads(
                run_store.run_path(result.run_id).read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(payload["blackboard"]["engine"], "sdk")
            telemetry = payload["blackboard"]["engine_telemetry"]
            self.assertGreater(telemetry["decisions"]["failure_count"], 0)

    def test_blackboard_schema_matches_rules_engine_contract(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection",
                max_rounds=1,
                run_store=run_store,
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_failing_engine(),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
            ).run()
            payload = json.loads(
                run_store.run_path(result.run_id).read_text(encoding="utf-8")
            )
            blackboard = payload["blackboard"]
            for key in (
                "run_id",
                "query_history",
                "raw_items",
                "coverage_gaps",
                "action_history",
                "metrics",
                "budget",
            ):
                self.assertIn(key, blackboard)
            self.assertTrue(blackboard["run_id"].startswith("real-"))
            entry = blackboard["query_history"][0]
            for key in ("novelty_score", "noise_ratio", "duplicate_ratio", "metadata"):
                self.assertIn(key, entry)
            self.assertIn("source_query_plans", entry["metadata"])


class SdkLoopDecisionTests(unittest.TestCase):
    def test_scripted_decisions_drive_sources_queries_and_termination(self) -> None:
        script = {
            "SourceSelectionDecision": {
                "selected_sources": ["arxiv_api", "nvd_cve_api"],
                "follow_bandit": True,
                "rationale": "follow ranking",
            },
            "CollectionPlanDecision": {
                "proposals": [
                    {
                        "source_name": "nvd_cve_api",
                        "query_text": "agent-chosen MLflow deserialization",
                        "params": {
                            "nvd_keyword_search": "MLflow",
                            "nvd_cwe_id": "CWE-502",
                            "nvd_bogus_param": "dropped",
                        },
                        "rationale": "supply chain focus",
                    },
                    {
                        "source_name": "arxiv_api",
                        "query_text": "agent-chosen arxiv query",
                        "params": {
                            "arxiv_search_query": '(all:"prompt injection") AND (cat:cs.CR)'
                        },
                        "rationale": "paper recall",
                    },
                ],
                "rationale": "two-pronged plan",
            },
            "RewriteDecisionOutput": {
                "should_rewrite": True,
                "rewritten_query": "agent rewritten query for rag poisoning",
                "target_topics": ["rag poisoning"],
                "topics_to_stop": [],
                "rationale": "gap remains",
                "confidence": 0.9,
            },
            "CompletenessDecisionOutput": {
                "should_continue": False,
                "completeness_score": 0.9,
                "missing_topics": [],
                "recommended_next_query": None,
                "stop_reason": "marginal yield too low",
                "rationale": "diminishing returns",
            },
        }
        with TemporaryDirectory() as temp_dir:
            tool = FakeRegisteredSourceTool()
            engine = _scripted_engine(script)
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection",
                max_rounds=3,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                source_tool=tool,
                decision_engine=engine,
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
                target_topics=["prompt injection"],
                coverage_quota=1,
            ).run()

            # coverage met (1 prompt-injection item >= quota), so the agent's stop
            # decision is honored: one round despite max_rounds=3
            self.assertEqual(len(result.query_history), 1)
            # agent collection plan executed with whitelisted advanced params only
            executed_queries = {call["query_text"] for call in tool.calls}
            self.assertIn("agent-chosen MLflow deserialization", executed_queries)
            nvd_call = next(c for c in tool.calls if c.get("nvd_keyword_search"))
            self.assertEqual(nvd_call["nvd_cwe_id"], "CWE-502")
            self.assertNotIn("nvd_bogus_param", nvd_call)
            # source-query plan metadata records the agent strategy for auditing
            plans = result.query_history[0].metadata["source_query_plans"]
            self.assertTrue(
                all(plan["strategy_name"] == "sdk_agent_proposal" for plan in plans)
            )
            self.assertEqual(engine.telemetry.successes, 4)
            self.assertFalse(result.errors)

    def test_min_rounds_floor_overrides_agent_stop(self) -> None:
        script = {
            "CompletenessDecisionOutput": {
                "should_continue": False,
                "completeness_score": 0.2,
                "missing_topics": ["rag poisoning"],
                "recommended_next_query": None,
                "stop_reason": "premature stop attempt",
                "rationale": "agent wants to stop early",
            },
            "RewriteDecisionOutput": {
                "should_rewrite": True,
                "rewritten_query": "second round query",
                "target_topics": ["rag poisoning"],
                "topics_to_stop": [],
                "rationale": "gap",
                "confidence": 0.8,
            },
        }
        with TemporaryDirectory() as temp_dir:
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection",
                max_rounds=3,
                min_rounds=2,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_scripted_engine(script),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
                target_topics=["prompt injection"],
                coverage_quota=1,
            ).run()
            self.assertGreaterEqual(len(result.query_history), 2)


class SdkLoopCoverageGateTests(unittest.TestCase):
    def test_coverage_gate_blocks_early_stop_until_max_rounds(self) -> None:
        # Agent always wants to stop, but the fake source only yields
        # prompt-injection items, so the "jailbreak" target stays below quota and
        # the coverage gate forces collection to continue to max_rounds.
        script = {
            "SourceSelectionDecision": {
                "selected_sources": ["arxiv_api"],
                "follow_bandit": True,
                "rationale": "r",
            },
            "CollectionPlanDecision": {
                "proposals": [
                    {
                        "source_name": "arxiv_api",
                        "query_text": "scripted arxiv",
                        "params": {"arxiv_search_query": '(all:"x") AND (cat:cs.CR)'},
                        "rationale": "r",
                    }
                ],
                "rationale": "r",
            },
            "RewriteDecisionOutput": {
                "should_rewrite": True,
                "rewritten_query": "next mission query",
                "target_topics": ["jailbreak"],
                "topics_to_stop": [],
                "rationale": "r",
                "confidence": 0.8,
            },
            "CompletenessDecisionOutput": {
                "should_continue": False,
                "completeness_score": 0.95,
                "missing_topics": [],
                "recommended_next_query": None,
                "stop_reason": "agent wants to stop",
                "rationale": "r",
            },
        }
        with TemporaryDirectory() as temp_dir:
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection jailbreak",
                max_rounds=4,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_scripted_engine(script),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
                target_topics=["prompt injection", "jailbreak"],
                coverage_quota=1,
                min_new_relevant_per_call=0.0,  # isolate: disable the stall valve
            ).run()
            # coverage gate overrides the agent's stop until the hard round cap
            self.assertEqual(len(result.query_history), 4)
            self.assertIn(
                "jailbreak",
                rules.quota_open_gaps(
                    result.raw_items, ["prompt injection", "jailbreak"], 1
                ),
            )

    def test_coverage_gate_synthesizes_query_when_agent_offers_none(self) -> None:
        # Agent declines to rewrite (no next query), but a target topic is still
        # uncovered: the loop must synthesize a gap-targeted query and continue.
        script = {
            "SourceSelectionDecision": {
                "selected_sources": ["arxiv_api"],
                "follow_bandit": True,
                "rationale": "r",
            },
            "CollectionPlanDecision": {
                "proposals": [
                    {
                        "source_name": "arxiv_api",
                        "query_text": "scripted arxiv",
                        "params": {},
                        "rationale": "r",
                    }
                ],
                "rationale": "r",
            },
            "RewriteDecisionOutput": {
                "should_rewrite": False,
                "rewritten_query": None,
                "target_topics": [],
                "topics_to_stop": ["prompt injection", "jailbreak"],
                "rationale": "agent thinks it is done",
                "confidence": 0.9,
            },
            "CompletenessDecisionOutput": {
                "should_continue": False,
                "completeness_score": 0.95,
                "missing_topics": [],
                "recommended_next_query": None,
                "stop_reason": "agent wants to stop",
                "rationale": "r",
            },
        }
        with TemporaryDirectory() as temp_dir:
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection jailbreak",
                max_rounds=3,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_scripted_engine(script),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
                target_topics=["prompt injection", "jailbreak"],
                coverage_quota=1,
                min_new_relevant_per_call=0.0,  # isolate: disable the stall valve
            ).run()
            self.assertGreaterEqual(len(result.query_history), 2)
            self.assertTrue(
                any(
                    "Coverage gate" in (action.rationale or "")
                    for action in result.action_history
                )
            )


class SdkLoopStallTerminationTests(unittest.TestCase):
    def test_stall_overrides_coverage_gate_and_stops_early(self) -> None:
        # The "jailbreak" target is never satisfied (fake source only yields
        # prompt-injection items), so the coverage gate would otherwise run to
        # max_rounds. A high stall threshold marks every round as low-yield, so
        # the stall valve must stop the run early and report the unreached topic.
        with TemporaryDirectory() as temp_dir:
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection jailbreak",
                max_rounds=6,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_failing_engine(),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
                target_topics=["prompt injection", "jailbreak"],
                coverage_quota=1,
                stall_patience=2,
                min_new_relevant_per_call=10_000.0,  # force "stalled" after 2 rounds
            ).run()
            self.assertGreaterEqual(len(result.query_history), 2)
            self.assertLess(len(result.query_history), 6)  # stopped before the cap
            self.assertIn(
                "jailbreak",
                rules.quota_open_gaps(
                    result.raw_items, ["prompt injection", "jailbreak"], 1
                ),
            )
            self.assertIn("search exhausted", result.action_history[-1].rationale)

    def test_high_yield_does_not_stall_and_runs_to_cap(self) -> None:
        # With the stall threshold at 0, no round is ever "stalled", so the
        # coverage gate keeps the run going to max_rounds while a gap is open.
        with TemporaryDirectory() as temp_dir:
            result = SdkIntelRunController(
                run_goal="g",
                initial_query="LLM prompt injection jailbreak",
                max_rounds=4,
                run_store=JsonIntelRunStore(Path(temp_dir) / "intel_runs"),
                source_tool=FakeRegisteredSourceTool(),
                decision_engine=_failing_engine(),
                bandit=SourceBandit(state_path=None),
                relevance_pipeline=None,
                target_topics=["prompt injection", "jailbreak"],
                coverage_quota=1,
                stall_patience=2,
                min_new_relevant_per_call=0.0,
            ).run()
            self.assertEqual(len(result.query_history), 4)


if __name__ == "__main__":
    unittest.main()

