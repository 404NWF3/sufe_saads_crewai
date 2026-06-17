"""Cross-run operator-strategy memory (plan WS3).

Arm = ``(topic_bucket, operator_signature)``; reward = new relevant items per
API call for source calls using that operator signature. This mirrors
``intel/bandit.py``'s persistence and optimistic cold-start, but keyed by the
*operator combination* rather than the source, so the agent reuses query/operator
patterns that worked in earlier runs. Like the bandit it only *recommends*: the
historical means are rendered into the context digest (and seed gap-targeting),
never executed directly.

State persists across runs in ``data/strategy_state.json``; pass
``state_path=None`` for an isolated, in-memory instance (used by the A/B harness
and tests so repeats stay independent).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sufe_saads_crewai.schemas import QueryHistoryEntry, RawIntelItem
from sufe_saads_crewai.intel.bandit import topic_bucket
from sufe_saads_crewai.intel import rules

DEFAULT_STATE_PATH = Path("data") / "strategy_state.json"


def strategy_memory_enabled() -> bool:
    return os.getenv("INTEL_STRATEGY_MEMORY", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


class StrategyMemory:
    def __init__(
        self,
        state_path: Path | None = DEFAULT_STATE_PATH,
        optimistic_reward: float = 1.0,
        reward_cap: float = 5.0,
    ) -> None:
        self.state_path = state_path
        self.optimistic_reward = optimistic_reward
        self.reward_cap = reward_cap
        self.arms: dict[str, dict[str, float]] = {}
        if state_path is not None and state_path.is_file():
            try:
                payload = json.loads(state_path.read_text(encoding="utf-8"))
                self.arms = {
                    key: {"pulls": float(value["pulls"]), "reward_sum": float(value["reward_sum"])}
                    for key, value in payload.get("arms", {}).items()
                }
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                self.arms = {}

    # ------------------------------------------------------------- state

    def _arm_key(self, bucket: str, signature: str) -> str:
        return f"{bucket}|{signature}"

    def save(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps({"arms": self.arms}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------- updates

    def update(self, bucket: str, signature: str, reward: float, pulls: float = 1.0) -> None:
        arm = self.arms.setdefault(self._arm_key(bucket, signature), {"pulls": 0.0, "reward_sum": 0.0})
        arm["pulls"] += pulls
        arm["reward_sum"] += min(self.reward_cap, max(0.0, reward)) * pulls

    def update_from_history_entry(
        self,
        entry: QueryHistoryEntry,
        item_index: dict[str, RawIntelItem],
    ) -> dict[str, float]:
        """Attribute one round's new relevant items to operator signatures."""
        bucket = topic_bucket(entry.metadata.get("target_topics") or [])
        calls: dict[str, int] = {}
        for plan in entry.metadata.get("source_query_plans") or []:
            sig = rules.operator_signature(str(plan.get("source_name", "")), plan.get("params") or {})
            calls[sig] = calls.get(sig, 0) + 1

        new_relevant: dict[str, int] = {}
        for item_id in entry.metadata.get("new_item_ids") or []:
            item = item_index.get(item_id)
            if item is None or not rules.item_is_relevant(item):
                continue
            sig = rules.operator_signature(item.source_name, item.metadata.get("source_query_params") or {})
            new_relevant[sig] = new_relevant.get(sig, 0) + 1

        rewards: dict[str, float] = {}
        for sig, call_count in calls.items():
            reward = new_relevant.get(sig, 0) / max(1, call_count)
            rewards[sig] = reward
            self.update(bucket, sig, reward, pulls=float(call_count))
        return rewards

    # ------------------------------------------------------------- queries

    def mean_reward(self, bucket: str, signature: str) -> float:
        arm = self.arms.get(self._arm_key(bucket, signature))
        if not arm or arm["pulls"] <= 0:
            return self.optimistic_reward
        return arm["reward_sum"] / arm["pulls"]

    def recommend(self, bucket: str, signatures: list[str] | None = None) -> list[dict[str, Any]]:
        keys: set[str] = set(signatures or [])
        for full_key in self.arms:
            stored_bucket, _, sig = full_key.partition("|")
            if stored_bucket == bucket:
                keys.add(sig)
        rows = [
            {
                "signature": sig,
                "mean_reward": round(self.mean_reward(bucket, sig), 4),
                "pulls": self.arms.get(self._arm_key(bucket, sig), {}).get("pulls", 0.0),
            }
            for sig in keys
        ]
        rows.sort(key=lambda row: row["mean_reward"], reverse=True)
        return rows
