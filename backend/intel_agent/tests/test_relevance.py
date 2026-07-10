from __future__ import annotations

from intel_agent.relevance import RelevanceConfig, RelevancePipeline
from intel_agent.tests.conftest import make_item


def test_rule_tier_accepts_and_rejects_without_model(tmp_path):
    config = RelevanceConfig(cache_path=tmp_path / "cache.jsonl")
    pipeline = RelevancePipeline(config=config)  # no embedder / judge
    high = make_item("nvd:hi", relevance=0.9)
    low = make_item("nvd:lo", relevance=0.05, topics=[])
    counts = pipeline.annotate([high, low])
    assert high.metadata["relevance"]["label"] == "relevant"
    assert low.metadata["relevance"]["label"] == "irrelevant"
    assert counts["rule"] == 2


def test_embedding_tier_uses_injected_embedder(tmp_path):
    config = RelevanceConfig(cache_path=tmp_path / "cache.jsonl")

    def embedder(texts):
        # anchors + item; return vectors that make the item highly similar.
        return [[1.0, 0.0] for _ in texts]

    pipeline = RelevancePipeline(config=config, embedder=embedder)
    mid = make_item("nvd:mid", relevance=0.5)
    pipeline.annotate([mid])
    assert mid.metadata["relevance"]["method"] == "embedding"
    assert mid.metadata["relevance"]["label"] == "relevant"


def test_llm_tier_adjudicates_uncertain_band(tmp_path):
    config = RelevanceConfig(
        cache_path=tmp_path / "cache.jsonl", embedding_accept=0.9, embedding_reject=0.1
    )

    def embedder(texts):
        # item text (starts with "Item ") sits at cosine ~0.7 to the anchors.
        return [[0.7, 0.714] if t.startswith("Item ") else [1.0, 0.0] for t in texts]

    def judge(entries):
        return [True for _ in entries]

    pipeline = RelevancePipeline(config=config, embedder=embedder, llm_judge=judge)
    mid = make_item("nvd:mid", relevance=0.5)
    pipeline.annotate([mid])
    assert mid.metadata["relevance"]["method"] == "llm"
    assert mid.metadata["relevance"]["label"] == "relevant"
