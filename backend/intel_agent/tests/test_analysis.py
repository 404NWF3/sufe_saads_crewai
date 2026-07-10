from __future__ import annotations

from intel_agent import analysis
from intel_agent.schemas import IntelRunBlackboard, RawIntelItemBatch, SearchQueryPlan
from intel_agent.tests.conftest import make_item


def _blackboard() -> IntelRunBlackboard:
    return IntelRunBlackboard(run_id="t", run_goal="g")


def test_merge_batch_computes_novelty_noise_duplicate():
    bb = _blackboard()
    bb.raw_items.append(make_item("nvd:a"))
    batch = RawIntelItemBatch(
        items=[
            make_item("nvd:a"),  # duplicate
            make_item("nvd:b", relevance=0.9),  # new relevant
            make_item("nvd:c", relevance=0.1, topics=[]),  # new noise
        ]
    )
    plan = SearchQueryPlan(query_text="q", source_names=["nvd_cve_api"])
    entry = analysis.merge_batch_into_blackboard(bb, plan, batch)
    assert len(bb.raw_items) == 3  # a already present, b + c added
    assert entry.result_count == 3
    assert round(entry.duplicate_ratio, 2) == round(1 / 3, 2)
    assert round(entry.novelty_score, 2) == round(2 / 3, 2)
    assert round(entry.noise_ratio, 2) == 0.5  # of 2 new, 1 relevant
    assert entry.metadata["relevant_new"] == 1


def test_quota_open_gaps_and_coverage():
    items = [
        make_item(
            f"nvd:{i}",
            topics=["prompt injection"],
            summary="prompt injection against a large language model",
            raw_text="indirect prompt injection payload",
        )
        for i in range(3)
    ]
    target = ["prompt injection", "jailbreak"]
    gaps = analysis.quota_open_gaps(items, target, quota=3)
    assert "prompt injection" not in gaps
    assert "jailbreak" in gaps


def test_is_search_stalled_detects_low_yield():
    bb = _blackboard()
    for r in range(2):
        plan = SearchQueryPlan(query_text="q", source_names=["nvd_cve_api"], round_index=r)
        analysis.merge_batch_into_blackboard(
            bb, plan, RawIntelItemBatch(items=[make_item(f"nvd:{r}", relevance=0.05, topics=[])])
        )
    assert analysis.is_search_stalled(bb, patience=2, min_new_relevant_per_call=0.5) is True


def test_operator_signature_stable():
    sig = analysis.operator_signature("nvd_cve_api", {"nvd_cwe_id": "CWE-94", "empty": None})
    assert sig == "nvd_cve_api[nvd_cwe_id]"
    assert analysis.operator_signature("arxiv_api", {}) == "arxiv_api[base]"
