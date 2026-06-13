from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sufe_saads_crewai.intel.bandit import SourceBandit, replay_history, topic_bucket
from sufe_saads_crewai.schemas import QueryHistoryEntry


def _entry(
    round_index: int,
    new_per_source: dict[str, int],
    calls_per_source: dict[str, int],
    topics: list[str] | None = None,
) -> QueryHistoryEntry:
    prefix = {
        "nvd_cve_api": "nvd",
        "arxiv_api": "arxiv",
        "cisa_kev_json": "cisa-kev",
        "osv_dev_api": "osv",
    }
    new_ids = [
        f"{prefix[source]}:{round_index}-{i}"
        for source, count in new_per_source.items()
        for i in range(count)
    ]
    plans = [
        {"source_name": source, "strategy_name": "s", "query_text": f"q{round_index}"}
        for source, calls in calls_per_source.items()
        for _ in range(calls)
    ]
    return QueryHistoryEntry(
        query_text=f"query {round_index}",
        source_names=list(calls_per_source),
        result_count=sum(new_per_source.values()),
        novelty_score=0.5,
        round_index=round_index,
        metadata={
            "new_item_ids": new_ids,
            "source_query_plans": plans,
            "target_topics": topics or ["prompt injection"],
        },
    )


class BanditTests(unittest.TestCase):
    def test_topic_bucket_maps_to_target_topics(self) -> None:
        self.assertEqual(topic_bucket(["RAG poisoning attacks"]), "rag poisoning")
        self.assertEqual(topic_bucket(["something else"]), "general")

    def test_bandit_learns_to_prefer_high_yield_source(self) -> None:
        bandit = SourceBandit(state_path=None)
        for index in range(12):
            bandit.update_from_history_entry(
                _entry(
                    index,
                    new_per_source={"arxiv_api": 4, "osv_dev_api": 0},
                    calls_per_source={"arxiv_api": 2, "osv_dev_api": 2},
                )
            )
        ranking = bandit.recommend("prompt injection", ["arxiv_api", "osv_dev_api"])
        self.assertEqual(ranking[0]["source_name"], "arxiv_api")
        self.assertGreater(ranking[0]["mean_reward"], ranking[1]["mean_reward"])

    def test_unexplored_arm_ranks_first_for_exploration(self) -> None:
        bandit = SourceBandit(state_path=None)
        bandit.update("arxiv_api", "general", reward=0.5, pulls=10)
        ranking = bandit.recommend("general", ["arxiv_api", "nvd_cve_api"])
        self.assertEqual(ranking[0]["source_name"], "nvd_cve_api")
        self.assertEqual(ranking[0]["ucb_score"], float("inf"))

    def test_state_persistence_roundtrip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bandit_state.json"
            bandit = SourceBandit(state_path=path)
            bandit.update("arxiv_api", "jailbreak", reward=2.0, pulls=3)
            bandit.save()
            reloaded = SourceBandit(state_path=path)
            pulls, mean = reloaded.stats("arxiv_api", "jailbreak")
            self.assertEqual(pulls, 3.0)
            self.assertAlmostEqual(mean, 2.0)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("arxiv_api|jailbreak", payload["arms"])

    def test_offline_replay_beats_round_robin_on_skewed_history(self) -> None:
        history = [
            _entry(
                index,
                new_per_source={"arxiv_api": 5, "nvd_cve_api": 1, "osv_dev_api": 0, "cisa_kev_json": 0},
                calls_per_source={
                    "arxiv_api": 2,
                    "nvd_cve_api": 2,
                    "osv_dev_api": 2,
                    "cisa_kev_json": 2,
                },
            )
            for index in range(20)
        ]
        report = replay_history([history])
        self.assertEqual(report["rounds"], 20)
        self.assertGreaterEqual(
            report["bandit_avg_reward"], report["round_robin_avg_reward"]
        )
        self.assertLessEqual(report["bandit_regret"], report["round_robin_regret"])


if __name__ == "__main__":
    unittest.main()
