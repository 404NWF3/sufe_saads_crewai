from __future__ import annotations

from intel_agent.memory.harvest import harvest_round
from intel_agent.memory.playbook import PlaybookStore


def _store() -> PlaybookStore:
    return PlaybookStore(path=None)  # in-memory


def test_upsert_rolling_reward_and_promotion():
    store = _store()
    for _ in range(3):
        entry = store.upsert(
            technique_text="query nvd with CWE-94",
            source_name="nvd_cve_api",
            operator_signature="nvd_cve_api[nvd_cwe_id]",
            topic_bucket="general",
            reward=2.0,
            run_id="r1",
        )
    assert entry.pulls == 3
    assert entry.reward == 2.0
    assert entry.status == "verified"


def test_recall_filters_deprecated_and_ranks_by_reward():
    store = _store()
    store.upsert("strong", "nvd_cve_api", "nvd_cve_api[a]", "general", reward=3.0, run_id="r")
    weak = store.upsert("weak", "arxiv_api", "arxiv_api[base]", "general", reward=0.0, run_id="r")
    weak.status = "deprecated"
    results = store.recall("prompt injection", top_k=5)
    ids = [e.entry_id for e in results]
    assert "general::nvd_cve_api::nvd_cve_api[a]" in ids
    assert weak.entry_id not in ids


def test_decay_unused_deprecates_persistently_weak():
    store = PlaybookStore(path=None, decay=0.5, deprecate_below_reward=0.2, deprecate_min_pulls=1)
    entry = store.upsert("t", "nvd_cve_api", "nvd_cve_api[a]", "general", reward=0.3, run_id="r")
    entry.pulls = 5
    store.decay_unused(used_ids=set())  # 0.3 -> 0.15 < 0.2
    assert entry.status == "deprecated"


def test_harvest_round_only_keeps_high_yield_calls():
    store = _store()
    calls = [
        {"source_name": "nvd_cve_api", "query_text": "prompt injection", "params": {"nvd_cwe_id": "CWE-94"}, "new_relevant": 3},
        {"source_name": "osv_dev_api", "query_text": "x", "params": {}, "new_relevant": 0},
    ]
    used = harvest_round(store, "run1", calls, topic_bucket="general")
    assert len(used) == 1
    assert "general::nvd_cve_api::nvd_cve_api[nvd_cwe_id]" in used
    assert store.entries[used[0]].reward == 3.0
