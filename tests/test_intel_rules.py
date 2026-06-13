from __future__ import annotations

import unittest

from sufe_saads_crewai.intel import rules
from sufe_saads_crewai.schemas import (
    IntelRunBlackboard,
    QueryHistoryEntry,
    RawIntelItem,
    SearchQueryPlan,
    SearchReflectionDecision,
)
from sufe_saads_crewai.tools import default_registered_api_sources


def _item(item_id: str, title: str, topics: list[str]) -> RawIntelItem:
    return RawIntelItem(
        item_id=item_id,
        source_name="arxiv_api",
        source_uri=f"https://example.test/{item_id}",
        title=title,
        summary=title,
        relevance_score=0.7,
        metadata={"topics": topics},
    )


class RulesModuleTests(unittest.TestCase):
    def test_covered_topics_matches_metadata_and_text(self) -> None:
        items = [
            _item("a", "Indirect prompt injection in chatbots", []),
            _item("b", "Some unrelated paper", ["jailbreak"]),
        ]
        covered = rules.covered_topics(items, ["prompt injection", "jailbreak", "rag poisoning"])
        self.assertEqual(covered, {"prompt injection", "jailbreak"})

    def test_fallback_coverage_analysis_reports_missing_topics(self) -> None:
        items = [_item("a", "prompt injection study", [])]
        analysis = rules.fallback_coverage_analysis(items, ["prompt injection", "rag poisoning"])
        self.assertEqual(
            [gap.taxonomy_or_component for gap in analysis.gaps], ["rag poisoning"]
        )
        self.assertAlmostEqual(analysis.overall_coverage_score, 0.5)

    def test_non_repeating_gap_query_avoids_previous_queries(self) -> None:
        previous = {"prompt injection indirect prompt injection chatbot vulnerability"}
        query = rules.non_repeating_gap_query(["prompt injection"], previous, None)
        self.assertNotIn(query, previous)

    def test_fallback_completeness_stops_at_round_budget(self) -> None:
        analysis = rules.fallback_coverage_analysis([], ["prompt injection"])
        reflection = SearchReflectionDecision(
            rewritten_queries=[SearchQueryPlan(query_text="next")],
            rationale="more rounds",
            confidence=0.8,
        )
        ok = rules.fallback_completeness(analysis, reflection, round_index=0, max_rounds=2)
        self.assertTrue(ok.should_continue)
        stop = rules.fallback_completeness(analysis, reflection, round_index=1, max_rounds=2)
        self.assertFalse(stop.should_continue)

    def test_build_source_query_specs_skips_executed_keys(self) -> None:
        blackboard = IntelRunBlackboard(
            run_id="t",
            run_goal="g",
            approved_sources=default_registered_api_sources(),
        )
        plan = SearchQueryPlan(
            query_text="LLM prompt injection",
            source_names=["nvd_cve_api", "arxiv_api"],
            target_topics=["prompt injection"],
            round_index=0,
        )
        first = rules.build_source_query_specs(blackboard, plan, ["prompt injection"], 80, set(), None)
        self.assertTrue(first)
        executed = {rules.source_query_key(spec) for spec in first}
        second = rules.build_source_query_specs(
            blackboard, plan, ["prompt injection"], 80, executed, None
        )
        # all first-round specs are excluded; capped retry slice returned instead
        self.assertTrue(len(second) <= 4)

    def test_merge_batch_records_target_topics_for_bandit(self) -> None:
        blackboard = IntelRunBlackboard(run_id="t", run_goal="g")
        plan = SearchQueryPlan(
            query_text="q",
            source_names=["arxiv_api"],
            target_topics=["prompt injection"],
            round_index=0,
        )
        batch = rules.combine_source_batches(
            plan,
            [
                rules.SourceQuerySpec(
                    source_name="arxiv_api",
                    query_text="q",
                    target_topics=["prompt injection"],
                    max_results=5,
                    strategy_name="s",
                    params={},
                )
            ],
            [
                __import__("sufe_saads_crewai.schemas", fromlist=["RawIntelItemBatch"]).RawIntelItemBatch(
                    items=[_item("arxiv:1", "prompt injection", [])],
                    query_plan=plan,
                    source_stats=[],
                )
            ],
            80,
        )
        rules.merge_batch_into_blackboard(blackboard, plan, batch)
        entry: QueryHistoryEntry = blackboard.query_history[0]
        self.assertEqual(entry.metadata["target_topics"], ["prompt injection"])
        self.assertEqual(entry.metadata["new_item_ids"], ["arxiv:1"])


if __name__ == "__main__":
    unittest.main()
