from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sufe_saads_crewai.intel.strategy_memory import StrategyMemory
from sufe_saads_crewai.schemas import QueryHistoryEntry, RawIntelItem


def _item(item_id: str, source_name: str, params: dict, score: float = 0.8) -> RawIntelItem:
    return RawIntelItem(
        item_id=item_id,
        source_name=source_name,
        source_uri=f"https://example.test/{item_id}",
        title="prompt injection finding",
        summary="prompt injection evidence",
        relevance_score=score,
        metadata={"source_query_params": params, "topics": ["prompt injection"]},
    )


def _entry(new_ids: list[str], plans: list[dict]) -> QueryHistoryEntry:
    return QueryHistoryEntry(
        query_text="q",
        source_names=[plan["source_name"] for plan in plans],
        result_count=len(new_ids),
        novelty_score=0.5,
        round_index=0,
        metadata={
            "new_item_ids": new_ids,
            "source_query_plans": plans,
            "target_topics": ["prompt injection"],
        },
    )


class StrategyMemoryTests(unittest.TestCase):
    def test_attributes_new_relevant_to_operator_signature(self) -> None:
        memory = StrategyMemory(state_path=None)
        osv_params = {"osv_ecosystem": "PyPI", "osv_package_name": "langchain"}
        nvd_params = {"nvd_keyword_search": "agent"}
        items = [
            _item("osv:1", "osv_dev_api", osv_params),
            _item("osv:2", "osv_dev_api", osv_params),
            _item("osv:3", "osv_dev_api", osv_params),
        ]
        index = {item.item_id: item for item in items}
        entry = _entry(
            new_ids=["osv:1", "osv:2", "osv:3"],
            plans=[
                {"source_name": "osv_dev_api", "params": osv_params},
                {"source_name": "nvd_cve_api", "params": nvd_params},
            ],
        )
        rewards = memory.update_from_history_entry(entry, index)
        self.assertAlmostEqual(rewards["osv:package"], 3.0)  # 3 relevant / 1 call
        self.assertAlmostEqual(rewards["nvd:keyword"], 0.0)
        self.assertGreater(
            memory.mean_reward("prompt injection", "osv:package"),
            memory.mean_reward("prompt injection", "nvd:keyword"),
        )
        ranking = memory.recommend("prompt injection")
        self.assertEqual(ranking[0]["signature"], "osv:package")

    def test_cold_start_is_optimistic(self) -> None:
        memory = StrategyMemory(state_path=None, optimistic_reward=1.0)
        self.assertEqual(memory.mean_reward("jailbreak", "nvd:keyword+cwe"), 1.0)

    def test_state_persistence_roundtrip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "strategy_state.json"
            memory = StrategyMemory(state_path=path)
            memory.update("prompt injection", "osv:package", reward=2.0, pulls=3)
            memory.save()
            reloaded = StrategyMemory(state_path=path)
            self.assertAlmostEqual(reloaded.mean_reward("prompt injection", "osv:package"), 2.0)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("prompt injection|osv:package", payload["arms"])


if __name__ == "__main__":
    unittest.main()
