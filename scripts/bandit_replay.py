"""Offline bandit validation (roadmap 9.4): replay stored runs, zero API cost.

Usage (repo root):
    uv run python scripts/bandit_replay.py [--runs-dir data/intel_runs] [--limit 200]

Loads query_history from persisted runs (oldest first), replays them through
the UCB1 bandit, and reports the average reward/regret of the bandit's ranking
versus round-robin polling and the hindsight-best source.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sufe_saads_crewai.intel.bandit import replay_history
from sufe_saads_crewai.schemas import QueryHistoryEntry


def load_histories(runs_dir: Path, limit: int) -> list[list[QueryHistoryEntry]]:
    histories: list[list[QueryHistoryEntry]] = []
    paths = sorted(
        (path for path in runs_dir.glob("*.json") if path.name != "latest.json"),
        key=lambda path: path.stat().st_mtime,
    )[:limit]
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        blackboard = payload.get("blackboard") or {}
        entries = [
            QueryHistoryEntry.model_validate(entry)
            for entry in blackboard.get("query_history", [])
        ]
        if entries:
            histories.append(entries)
    return histories


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-dir", default="data/intel_runs")
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()

    histories = load_histories(Path(args.runs_dir), args.limit)
    if not histories:
        print(f"no replayable runs found under {args.runs_dir}")
        return
    report = replay_history(histories)
    print(json.dumps(report, indent=2))
    verdict = (
        "bandit beats round-robin"
        if report["bandit_regret"] <= report["round_robin_regret"]
        else "bandit does NOT beat round-robin yet (need more history)"
    )
    print(f"runs={len(histories)} rounds={report['rounds']} -> {verdict}")


if __name__ == "__main__":
    main()
