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

    def test_quota_coverage_counts_relevant_items_per_topic(self) -> None:
        items = [
            _item("a", "prompt injection one", ["prompt injection"]),
            _item("b", "prompt injection two", ["prompt injection"]),
            _item("c", "jailbreak bypass", ["jailbreak"]),
        ]
        counts = rules.relevant_topic_counts(
            items, ["prompt injection", "jailbreak", "rag poisoning"]
        )
        self.assertEqual(counts["prompt injection"], 2)
        self.assertEqual(counts["jailbreak"], 1)
        self.assertEqual(counts["rag poisoning"], 0)
        gaps = rules.quota_open_gaps(items, ["prompt injection", "jailbreak"], quota=2)
        self.assertEqual(gaps, ["jailbreak"])
        self.assertAlmostEqual(
            rules.coverage_completeness(items, ["prompt injection", "jailbreak"], quota=2),
            0.5,
        )

    def test_quota_coverage_prefers_relevance_topic_label(self) -> None:
        item = _item("a", "ambiguous title", ["jailbreak"])
        item.metadata["relevance"] = {
            "label": "relevant",
            "topic": "prompt injection",
            "score": 0.9,
            "method": "embedding",
        }
        counts = rules.relevant_topic_counts([item], ["prompt injection", "jailbreak"])
        self.assertEqual(counts["prompt injection"], 1)
        self.assertEqual(counts["jailbreak"], 0)

    def test_quota_coverage_excludes_irrelevant_items(self) -> None:
        item = _item("a", "prompt injection weak", ["prompt injection"])
        item.relevance_score = 0.1
        item.metadata["relevance"] = {"label": "irrelevant", "score": 0.1, "method": "rule"}
        counts = rules.relevant_topic_counts([item], ["prompt injection"])
        self.assertEqual(counts["prompt injection"], 0)

    def _entry(self, rnd: int, new_ids: list[str], calls: int = 1, **kwargs):
        return QueryHistoryEntry(
            query_text=f"q{rnd}",
            source_names=["arxiv_api"],
            result_count=kwargs.get("result_count", 5),
            duplicate_ratio=kwargs.get("duplicate_ratio", 0.0),
            round_index=rnd,
            metadata={
                "new_item_ids": new_ids,
                "source_query_plans": [{"source_name": "arxiv_api"}] * calls,
            },
        )

    def test_round_information_gain_counts_new_relevant_only(self) -> None:
        items = [
            _item("arxiv:1", "prompt injection a", ["prompt injection"]),
            _item("arxiv:2", "prompt injection b", ["prompt injection"]),
            _item("arxiv:3", "noise item", ["prompt injection"]),
        ]
        items[2].relevance_score = 0.1  # irrelevant
        index = {item.item_id: item for item in items}
        entry = self._entry(0, ["arxiv:1", "arxiv:2", "arxiv:3"], calls=2, result_count=4)
        gain = rules.round_information_gain(entry, index)
        self.assertEqual(gain["new_relevant"], 2)
        self.assertEqual(gain["new_total"], 3)
        self.assertEqual(gain["calls"], 2)
        self.assertAlmostEqual(gain["new_relevant_per_call"], 1.0)
        self.assertAlmostEqual(gain["irrelevant_share"], round(1 - 2 / 3, 3))

    def test_is_search_stalled_detects_low_yield_streak(self) -> None:
        blackboard = IntelRunBlackboard(run_id="t", run_goal="g")
        blackboard.raw_items = [_item("arxiv:1", "prompt injection", ["prompt injection"])]
        # round 0 productive (1 new relevant / 1 call), rounds 1-2 add nothing new
        blackboard.query_history = [
            self._entry(0, ["arxiv:1"]),
            self._entry(1, []),
            self._entry(2, []),
        ]
        self.assertTrue(rules.is_search_stalled(blackboard, patience=2, min_yield=0.5))
        # patience 3 includes the productive round 0, so not stalled
        self.assertFalse(rules.is_search_stalled(blackboard, patience=3, min_yield=0.5))
        # fewer rounds than patience -> not stalled
        blackboard.query_history = [self._entry(0, ["arxiv:1"])]
        self.assertFalse(rules.is_search_stalled(blackboard, patience=2, min_yield=0.5))

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
