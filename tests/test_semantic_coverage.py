from __future__ import annotations

import unittest

from sufe_saads_crewai.intel.adaptive_loop import ReflectionCoverageCriticRuntime
from sufe_saads_crewai.schemas import IntelRunBlackboard, RawIntelItem
from sufe_saads_crewai.topic_utils import (
    build_gap_query,
    detect_topic_matches,
    detect_topics,
    semantic_terms_for_topic,
    topic_coverage_scores,
)


class SemanticCoverageTests(unittest.TestCase):
    def test_detect_topics_uses_semantic_aliases(self) -> None:
        text = (
            "A paper describes corpus poisoning in a vector store where attacker "
            "controlled documents manipulate retrieval context."
        )

        self.assertIn("rag poisoning", detect_topics(text))
        match = next(match for match in detect_topic_matches(text) if match.topic == "rag poisoning")
        self.assertGreaterEqual(match.score, 0.7)
        self.assertIn("corpus poisoning", match.matched_terms)

    def test_topic_coverage_scores_use_relevance_and_semantics(self) -> None:
        items = [
            RawIntelItem(
                item_id="semantic-1",
                source_name="paper_feed",
                source_uri="https://example.test/rag",
                title="Vector database poisoning against retrieval augmented generation",
                summary="Poisoned documents alter the retrieval context for generated answers.",
                relevance_score=0.9,
            ),
            RawIntelItem(
                item_id="semantic-2",
                source_name="security_db",
                source_uri="https://example.test/model-loader",
                title="Unsafe deserialization in model weight artifact loader",
                summary="Pickle payloads in model weights create supply-chain execution risk.",
                relevance_score=0.85,
            ),
        ]

        scores = topic_coverage_scores(items)

        self.assertGreaterEqual(scores["rag poisoning"], 0.65)
        self.assertGreaterEqual(scores["model supply chain"], 0.65)
        self.assertEqual(scores["jailbreak"], 0.0)

    def test_coverage_gap_analysis_retains_partial_semantic_context(self) -> None:
        blackboard = IntelRunBlackboard(
            run_id="semantic-run",
            run_goal="Assess semantic coverage",
            raw_items=[
                RawIntelItem(
                    item_id="semantic-3",
                    source_name="osv_dev_api",
                    source_uri="https://example.test/agent-tool",
                    title="Agent dependency enables unsafe tool execution",
                    summary="The package mishandles tool permissions in tool calling workflows.",
                    relevance_score=0.8,
                )
            ],
        )

        analysis = ReflectionCoverageCriticRuntime().analyze_coverage_gaps(blackboard)
        gap_by_topic = {gap.taxonomy_or_component: gap for gap in analysis.gaps}

        self.assertNotIn("agent tool abuse", gap_by_topic)
        self.assertIn("prompt injection", gap_by_topic)
        prompt_gap = gap_by_topic["prompt injection"]
        self.assertIn("semantic_terms", prompt_gap.metadata)
        self.assertIn("nvd_cve_api", prompt_gap.metadata["source_hints"])
        self.assertGreater(prompt_gap.estimated_gap_fill_roi, 0.6)

    def test_gap_query_and_source_terms_expand_beyond_topic_label(self) -> None:
        terms = semantic_terms_for_topic("model supply chain", source_name="nvd_cve_api")
        query = build_gap_query(["model supply chain"])

        self.assertIn("artifact loader", " ".join(terms))
        self.assertIn("model artifact", query)
        self.assertIn("pickle deserialization", query)


if __name__ == "__main__":
    unittest.main()
