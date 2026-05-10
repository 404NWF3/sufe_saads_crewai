from __future__ import annotations

import unittest
import json

from sufe_saads_crewai.intel import AutonomousIntelLoop, create_mock_blackboard
from sufe_saads_crewai.tools.mock_source_tools import MockSourceSearchTool


class AutonomousLoopTests(unittest.TestCase):
    def test_mock_loop_rewrites_query_and_stops(self) -> None:
        initial_query = "LLM prompt injection and agent tool abuse"
        blackboard = create_mock_blackboard(max_rounds=3)

        result = AutonomousIntelLoop(blackboard).run(initial_query=initial_query)

        action_types = [action.action_type for action in result.action_history]
        self.assertIn("PLAN_COLLECTION", action_types)
        self.assertIn("SEARCH_REGISTERED_SOURCE", action_types)
        self.assertIn("ASSESS_COLLECTION_YIELD", action_types)
        self.assertIn("ANALYZE_COVERAGE_GAPS", action_types)
        self.assertIn("REFLECT_SEARCH_STRATEGY", action_types)
        self.assertEqual(action_types[-1], "STOP")

        self.assertGreaterEqual(len(result.query_history), 2)
        self.assertGreaterEqual(len(result.reflection_notes), 1)
        rewritten_query = result.reflection_notes[0].rewritten_queries[0].query_text
        self.assertNotEqual(rewritten_query, initial_query)
        self.assertTrue(
            any(topic in rewritten_query.lower() for topic in ("jailbreak", "model supply chain", "rag poisoning"))
        )
        self.assertGreaterEqual(len(result.raw_items), 5)
        self.assertLessEqual(len(result.coverage_gaps), 1)

    def test_pending_source_proposals_are_created_without_collection(self) -> None:
        blackboard = create_mock_blackboard(max_rounds=1)

        result = AutonomousIntelLoop(blackboard).run(
            initial_query="LLM prompt injection and agent tool abuse"
        )

        self.assertGreaterEqual(len(result.source_proposals), 1)
        self.assertTrue(
            all(proposal.approval_status == "pending" for proposal in result.source_proposals)
        )
        approved_names = {source.source_name for source in result.approved_sources}
        proposed_names = {proposal.source_name for proposal in result.source_proposals}
        self.assertTrue(approved_names.isdisjoint(proposed_names))
        self.assertEqual(result.action_history[-1].action_type, "STOP")

    def test_query_history_tracks_yield_metrics(self) -> None:
        blackboard = create_mock_blackboard(max_rounds=2)

        result = AutonomousIntelLoop(blackboard).run(
            initial_query="LLM prompt injection and agent tool abuse"
        )

        self.assertTrue(result.query_history)
        for entry in result.query_history:
            self.assertGreaterEqual(entry.result_count, 0)
            self.assertGreaterEqual(entry.novelty_score, 0.0)
            self.assertLessEqual(entry.novelty_score, 1.0)
            self.assertLessEqual(entry.noise_ratio, 1.0)
            self.assertLessEqual(entry.duplicate_ratio, 1.0)

    def test_mock_source_tool_falls_back_on_invalid_source_arguments(self) -> None:
        raw_result = MockSourceSearchTool()._run(
            query_text="LLM prompt injection",
            source_names=["CVE_Details"],
            approved_sources_json='["CVE Details"]',
        )
        result = json.loads(raw_result)

        self.assertGreaterEqual(len(result["items"]), 1)
        self.assertEqual(result["query_plan"]["query_text"], "LLM prompt injection")


if __name__ == "__main__":
    unittest.main()
