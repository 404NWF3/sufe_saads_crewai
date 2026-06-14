from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sufe_saads_crewai.intel.relevance import (
    RelevanceConfig,
    RelevancePipeline,
    content_hash,
    cosine_similarity,
)
from sufe_saads_crewai.schemas import RawIntelItem


def _item(item_id: str, score: float, title: str = "title") -> RawIntelItem:
    return RawIntelItem(
        item_id=item_id,
        source_name="arxiv_api",
        source_uri=f"https://example.test/{item_id}",
        title=title,
        summary=f"summary of {title}",
        relevance_score=score,
    )


def _config(temp_dir: str) -> RelevanceConfig:
    return RelevanceConfig(
        cache_path=Path(temp_dir) / "relevance_cache.jsonl",
        anchors={"prompt injection": ["anchor text"]},
    )


class FakeEmbedder:
    """Anchor maps to [1,0]; items embed by keyword so similarity is controllable."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, texts):
        self.calls += 1
        vectors = []
        for text in texts:
            if "anchor" in text:
                vectors.append([1.0, 0.0])
            elif "similar" in text:
                vectors.append([0.9, 0.1])
            else:
                vectors.append([0.1, 0.9])
        return vectors


class RelevancePipelineTests(unittest.TestCase):
    def test_tier1_rule_decides_clear_cases_without_models(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pipeline = RelevancePipeline(config=_config(temp_dir))
            high = _item("a", 0.9)
            low = _item("b", 0.1)
            counts = pipeline.annotate([high, low])
            self.assertEqual(counts["rule"], 2)
            self.assertEqual(high.metadata["relevance"]["label"], "relevant")
            self.assertEqual(high.metadata["relevance"]["method"], "rule")
            self.assertEqual(low.metadata["relevance"]["label"], "irrelevant")

    def test_tier2_embedding_decides_middle_band_and_caches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            embedder = FakeEmbedder()
            pipeline = RelevancePipeline(config=_config(temp_dir), embedder=embedder)
            similar = _item("a", 0.5, title="similar work on prompt injection")
            far = _item("b", 0.5, title="totally different robotics")
            pipeline.annotate([similar, far])
            self.assertEqual(similar.metadata["relevance"]["method"], "embedding")
            self.assertEqual(similar.metadata["relevance"]["label"], "relevant")
            self.assertEqual(far.metadata["relevance"]["label"], "irrelevant")

            # cache hit: second pipeline never embeds the same items again
            embedder2 = FakeEmbedder()
            pipeline2 = RelevancePipeline(config=_config(temp_dir), embedder=embedder2)
            similar_again = _item("a2", 0.5, title="similar work on prompt injection")
            pipeline2.annotate([similar_again])
            self.assertEqual(
                similar_again.metadata["relevance"]["label"], "relevant"
            )
            # one call for anchors at most; item itself came from cache
            self.assertLessEqual(embedder2.calls, 1)

    def test_tier3_llm_judges_uncertain_band_and_failure_falls_back(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = _config(temp_dir)
            config.embedding_accept = 1.01  # unreachable: force middle band to tier 3
            config.embedding_reject = 0.01

            def judge(entries):
                return [True for _ in entries]

            pipeline = RelevancePipeline(
                config=config, embedder=FakeEmbedder(), llm_judge=judge
            )
            uncertain = _item("a", 0.5, title="similar borderline item")
            pipeline.annotate([uncertain])
            self.assertEqual(uncertain.metadata["relevance"]["method"], "llm")
            self.assertEqual(uncertain.metadata["relevance"]["label"], "relevant")

            def broken_judge(entries):
                raise RuntimeError("flash model down")

            config2 = _config(temp_dir)
            config2.embedding_accept = 1.01
            config2.embedding_reject = 0.01
            pipeline2 = RelevancePipeline(
                config=config2, embedder=FakeEmbedder(), llm_judge=broken_judge
            )
            fallback = _item("b", 0.5, title="similar borderline item two")
            pipeline2.annotate([fallback])
            self.assertEqual(fallback.metadata["relevance"]["method"], "embedding")
            self.assertEqual(fallback.metadata["relevance"]["label"], "uncertain")

    def test_helpers(self) -> None:
        self.assertAlmostEqual(cosine_similarity([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(cosine_similarity([1, 0], [0, 1]), 0.0)
        self.assertEqual(content_hash(_item("x", 0.5)), content_hash(_item("y", 0.9)))


class TopicAssignmentTests(unittest.TestCase):
    @staticmethod
    def _embedder(texts):
        vectors = []
        for text in texts:
            if "PI anchor" in text:
                vectors.append([1.0, 0.0])
            elif "JB anchor" in text:
                vectors.append([0.0, 1.0])
            elif "pi item" in text:
                vectors.append([0.96, 0.04])
            else:
                vectors.append([0.04, 0.96])
        return vectors

    def _config(self, temp_dir: str) -> RelevanceConfig:
        return RelevanceConfig(
            cache_path=Path(temp_dir) / "relevance_cache.jsonl",
            anchors={"prompt injection": ["PI anchor"], "jailbreak": ["JB anchor"]},
        )

    def test_embedding_tier_assigns_best_target_topic(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pipeline = RelevancePipeline(
                config=self._config(temp_dir), embedder=self._embedder
            )
            item = _item("a", 0.5, title="pi item borderline")
            pipeline.annotate([item])
            self.assertEqual(item.metadata["relevance"]["method"], "embedding")
            self.assertEqual(item.metadata["relevance"]["label"], "relevant")
            self.assertEqual(item.metadata["relevance"]["topic"], "prompt injection")

    def test_assign_topic_public_helper(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pipeline = RelevancePipeline(
                config=self._config(temp_dir), embedder=self._embedder
            )
            topic, score = pipeline.assign_topic(_item("b", 0.5, title="pi item two"))
            self.assertEqual(topic, "prompt injection")
            self.assertIsNotNone(score)


if __name__ == "__main__":
    unittest.main()
