"""UCB1 multi-armed bandit for source selection (roadmap 6.1).

Arm = (source_name, topic_bucket). Reward = new deduplicated items per API
call, derived entirely from blackboard ``QueryHistoryEntry`` records: per-source
calls come from ``metadata.source_query_plans`` and per-source new items from
``metadata.new_item_ids`` prefixes. State persists across runs in a JSON file
(default ``data/bandit_state.json``); cold-start uses optimistic initial values
so unexplored arms are tried first.

The bandit only *recommends*: rankings are rendered into the agent context and
the agent may veto with a rationale. Without an agent, executing the ranking
directly is still better than round-robin polling.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from sufe_saads_crewai.schemas import QueryHistoryEntry
from sufe_saads_crewai.topic_utils import TARGET_SECURITY_TOPICS

ITEM_PREFIX_TO_SOURCE = {
    "nvd:": "nvd_cve_api",
    "arxiv:": "arxiv_api",
    "cisa-kev:": "cisa_kev_json",
    "osv:": "osv_dev_api",
}

DEFAULT_STATE_PATH = Path("data") / "bandit_state.json"
DEFAULT_SOURCES = list(ITEM_PREFIX_TO_SOURCE.values())


def source_for_item_id(item_id: str) -> str | None:
    for prefix, source in ITEM_PREFIX_TO_SOURCE.items():
        if item_id.startswith(prefix):
            return source
    return None


def topic_bucket(topics: list[str]) -> str:
    lowered = " ".join(topics).lower()
    for topic in TARGET_SECURITY_TOPICS:
        if topic in lowered:
            return topic
    return "general"


class SourceBandit:
    def __init__(
        self,
        state_path: Path | None = DEFAULT_STATE_PATH,
        exploration: float = 1.4,
        optimistic_reward: float = 1.0,
        reward_cap: float = 5.0,
    ) -> None:
        self.state_path = state_path
        self.exploration = exploration
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

    def _arm_key(self, source: str, bucket: str) -> str:
        return f"{source}|{bucket}"

    def save(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps({"arms": self.arms}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------- updates

    def update(self, source: str, bucket: str, reward: float, pulls: float = 1.0) -> None:
        arm = self.arms.setdefault(self._arm_key(source, bucket), {"pulls": 0.0, "reward_sum": 0.0})
        arm["pulls"] += pulls
        arm["reward_sum"] += min(self.reward_cap, max(0.0, reward)) * pulls

    def update_from_history_entry(self, entry: QueryHistoryEntry) -> dict[str, float]:
        """Derive per-source rewards from one round's blackboard record."""
        bucket = topic_bucket(entry.metadata.get("target_topics") or [])
        plans = entry.metadata.get("source_query_plans") or []
        calls_per_source: dict[str, int] = {}
        for plan in plans:
            source = str(plan.get("source_name", ""))
            if source:
                calls_per_source[source] = calls_per_source.get(source, 0) + 1
        if not calls_per_source:
            calls_per_source = {source: 1 for source in entry.source_names}

        new_per_source: dict[str, int] = {}
        for item_id in entry.metadata.get("new_item_ids") or []:
            source = source_for_item_id(str(item_id))
            if source:
                new_per_source[source] = new_per_source.get(source, 0) + 1

        rewards: dict[str, float] = {}
        for source, calls in calls_per_source.items():
            reward = new_per_source.get(source, 0) / max(1, calls)
            rewards[source] = reward
            self.update(source, bucket, reward, pulls=float(calls))
        return rewards

    # ------------------------------------------------------------- queries

    def stats(self, source: str, bucket: str) -> tuple[float, float]:
        """(pulls, mean reward) merging the topic bucket with the general bucket."""
        pulls = 0.0
        reward_sum = 0.0
        for key in {self._arm_key(source, bucket), self._arm_key(source, "general")}:
            arm = self.arms.get(key)
            if arm:
                pulls += arm["pulls"]
                reward_sum += arm["reward_sum"]
        mean = (reward_sum / pulls) if pulls else self.optimistic_reward
        return pulls, mean

    def recommend(
        self,
        bucket: str,
        sources: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        sources = sources or DEFAULT_SOURCES
        total_pulls = sum(self.stats(source, bucket)[0] for source in sources)
        ranking: list[dict[str, Any]] = []
        for source in sources:
            pulls, mean = self.stats(source, bucket)
            if pulls <= 0:
                ucb = float("inf")
                bonus = self.optimistic_reward
            else:
                bonus = self.exploration * math.sqrt(
                    math.log(max(math.e, total_pulls)) / pulls
                )
                ucb = mean + bonus
            ranking.append(
                {
                    "source_name": source,
                    "ucb_score": ucb,
                    "mean_reward": round(mean, 4),
                    "pulls": pulls,
                    "confidence_bonus": round(bonus, 4) if bonus != float("inf") else None,
                }
            )
        ranking.sort(key=lambda row: row["ucb_score"], reverse=True)
        return ranking

    def render_summary(self, bucket: str, sources: list[str] | None = None) -> str:
        lines = [f"Bandit ranking for topic bucket '{bucket}' (UCB1, reward = new items/call):"]
        for rank, row in enumerate(self.recommend(bucket, sources), start=1):
            ucb = "inf (unexplored)" if row["ucb_score"] == float("inf") else f"{row['ucb_score']:.3f}"
            lines.append(
                f"{rank}. {row['source_name']}: ucb={ucb} "
                f"mean={row['mean_reward']:.3f} pulls={row['pulls']:.0f}"
            )
        return "\n".join(lines)


def replay_history(
    histories: list[list[QueryHistoryEntry]],
    sources: list[str] | None = None,
) -> dict[str, Any]:
    """Offline replay (roadmap 9.4): bandit ranking regret vs round-robin polling.

    For each recorded round we compare the realized reward of the bandit's
    top-2 recommended sources against (a) the round-robin average over all
    sources and (b) the hindsight-best source. No API calls are made.
    """
    sources = sources or DEFAULT_SOURCES
    bandit = SourceBandit(state_path=None)
    bandit_reward = 0.0
    round_robin_reward = 0.0
    best_reward = 0.0
    rounds = 0

    for history in histories:
        for entry in history:
            bucket = topic_bucket(entry.metadata.get("target_topics") or [])
            ranking = [row["source_name"] for row in bandit.recommend(bucket, sources)]
            rewards = bandit.update_from_history_entry(entry)
            if not rewards:
                continue
            rounds += 1
            top = [source for source in ranking if source in rewards][:2]
            if top:
                bandit_reward += sum(rewards[source] for source in top) / len(top)
            round_robin_reward += sum(rewards.values()) / len(rewards)
            best_reward += max(rewards.values())

    return {
        "rounds": rounds,
        "bandit_avg_reward": round(bandit_reward / rounds, 4) if rounds else 0.0,
        "round_robin_avg_reward": round(round_robin_reward / rounds, 4) if rounds else 0.0,
        "hindsight_best_avg_reward": round(best_reward / rounds, 4) if rounds else 0.0,
        "bandit_regret": round((best_reward - bandit_reward) / rounds, 4) if rounds else 0.0,
        "round_robin_regret": round((best_reward - round_robin_reward) / rounds, 4) if rounds else 0.0,
    }
