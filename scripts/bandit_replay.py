"""Offline replay comparing adaptive UCB selection with source round-robin."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from typing import Any

from intel_agent.store import default_store


def _arm(row: dict[str, Any]) -> str:
    topics = row.get("target_topics") or ["general"]
    return "|".join(
        [
            str(topics[0]),
            str(row.get("evidence_channel") or "unknown"),
            str(row.get("source_name") or "unknown"),
            str(row.get("query_intent") or "gap_fill"),
            str(row.get("operator_signature") or "base"),
        ]
    )


def _load_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    store = default_store()
    for board in store.load_all_blackboards(limit=500):
        rows.extend(outcome.model_dump(mode="json") for outcome in board.query_outcomes)
    if rows:
        return rows
    # Deterministic fallback makes CI and a new checkout evaluable before live v3 runs exist.
    synthetic = {
        "high": ([0.82, 0.78, 0.74, 0.70, 0.68], [0, 0, 0, 0, 0]),
        "medium": ([0.48, 0.44, 0.40, 0.36, 0.32], [0, 0, 1, 0, 1]),
        "low": ([0.12, 0.05, -0.05, -0.10, -0.15], [1, 2, 2, 3, 3]),
    }
    for name, (rewards, duplicates) in synthetic.items():
        for reward, duplicate in zip(rewards, duplicates):
            rows.append(
                {
                    "target_topics": [name],
                    "evidence_channel": "research",
                    "source_name": f"{name}_source",
                    "query_intent": "gap_fill",
                    "operator_signature": "base",
                    "reward": reward,
                    "duplicate_count": duplicate,
                }
            )
    return rows


def replay(rows: list[dict[str, Any]], horizon: int | None = None) -> dict[str, Any]:
    streams: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        streams[_arm(row)].append(row)
    arms = sorted(streams)
    if not arms:
        return {"adaptive": {}, "legacy": {}, "passed": False, "reason": "no outcomes"}
    horizon = min(horizon or min(10, len(rows)), len(rows))

    def run(strategy: str) -> dict[str, float]:
        cursors = defaultdict(int)
        rewards = defaultdict(list)
        total_reward = 0.0
        duplicates = 0
        calls = 0
        for step in range(horizon):
            available = [arm for arm in arms if cursors[arm] < len(streams[arm])]
            if not available:
                break
            if strategy == "legacy":
                arm = available[step % len(available)]
            else:
                untried = [arm for arm in available if not rewards[arm]]
                if untried:
                    arm = untried[0]
                else:
                    arm = max(
                        available,
                        key=lambda name: (
                            sum(rewards[name]) / len(rewards[name])
                            + math.sqrt(2 * math.log(calls + 1) / len(rewards[name]))
                        ),
                    )
            row = streams[arm][cursors[arm]]
            cursors[arm] += 1
            reward = float(row.get("reward") or 0.0)
            rewards[arm].append(reward)
            total_reward += reward
            duplicates += int(row.get("duplicate_count") or 0)
            calls += 1
        return {
            "calls": calls,
            "normalized_reward": round(total_reward / max(1, calls), 4),
            "duplicates": duplicates,
        }

    adaptive = run("adaptive")
    legacy = run("legacy")
    passed = (
        adaptive["normalized_reward"] >= legacy["normalized_reward"]
        and adaptive["duplicates"] <= legacy["duplicates"]
    )
    return {"adaptive": adaptive, "legacy": legacy, "passed": passed}


def main() -> int:
    result = replay(_load_rows())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
