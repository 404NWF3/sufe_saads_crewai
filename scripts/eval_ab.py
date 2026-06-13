"""A/B evaluation harness: INTEL_ENGINE=rules vs sdk on the frozen goal set.

Usage (repo root):
    uv run python scripts/eval_ab.py [--goals tests/eval_goals.json] [--engines rules,sdk]
                                     [--repeats 3] [--goal-ids id1,id2] [--out data/eval]

For every (goal, engine, repeat) it runs a fresh controller with identical
budgets, persists runs under <out>/<goal>/<engine>/, and derives the roadmap
chapter-9 metrics from the blackboards. Results land in <out>/report.json plus
a console summary. Live source APIs (and for sdk, the GLM Anthropic endpoint)
are required — this script spends real quota; precision spot-checking and the
default-engine switch remain manual review steps.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from pathlib import Path
from typing import Any

from sufe_saads_crewai.intel.engine import create_intel_controller
from sufe_saads_crewai.persistence import JsonIntelRunStore


# Plain keyword params; anything beyond these marks an advanced-operator call
# (arXiv queries count as advanced when they use field/boolean syntax).
_BASIC_PARAM_KEYS = {"nvd_keyword_search", "cisa_keyword"}
_ARXIV_ADVANCED = re.compile(r"\b(?:AND|OR|ANDNOT)\b|\b(?:all|ti|abs|au|cat):")


def _is_advanced_call(plan: dict[str, Any]) -> bool:
    params = plan.get("params") or {}
    if any(key not in _BASIC_PARAM_KEYS for key in params if key != "arxiv_search_query"):
        return True
    arxiv_query = params.get("arxiv_search_query") or ""
    return bool(_ARXIV_ADVANCED.search(arxiv_query))


def advanced_param_usage(blackboard: Any) -> dict[str, Any]:
    """Roadmap 6.3 acceptance: share of source calls using advanced operators."""
    per_round: list[dict[str, Any]] = []
    total_calls = 0
    advanced_calls = 0
    for entry in blackboard.query_history:
        plans = entry.metadata.get("source_query_plans") or []
        round_advanced = sum(1 for plan in plans if _is_advanced_call(plan))
        total_calls += len(plans)
        advanced_calls += round_advanced
        per_round.append(
            {
                "round": entry.round_index,
                "calls": len(plans),
                "advanced": round_advanced,
                "share": round(round_advanced / len(plans), 3) if plans else 0.0,
            }
        )
    return {
        "advanced_call_share": round(advanced_calls / total_calls, 4) if total_calls else 0.0,
        "by_round": per_round,
    }


def stop_round_deviation(blackboard: Any) -> dict[str, Any]:
    """Roadmap 9: actual stop round vs hindsight stop (last round with
    meaningful marginal yield, >=20% of the best round's new items)."""
    new_counts = [
        len(entry.metadata.get("new_item_ids") or []) for entry in blackboard.query_history
    ]
    actual = len(new_counts)
    peak = max(new_counts, default=0)
    if peak == 0:
        return {"actual_rounds": actual, "hindsight_stop_round": min(actual, 1), "deviation": max(0, actual - 1)}
    threshold = max(1, round(0.2 * peak))
    hindsight = max(index + 1 for index, count in enumerate(new_counts) if count >= threshold)
    return {
        "actual_rounds": actual,
        "hindsight_stop_round": hindsight,
        "deviation": actual - hindsight,
    }


def run_metrics(blackboard: Any) -> dict[str, Any]:
    raw_items = blackboard.raw_items
    api_calls = max(1, blackboard.metrics.api_calls_used)
    relevant = [
        item
        for item in raw_items
        if (item.metadata.get("relevance") or {}).get("label") == "relevant"
        or item.relevance_score >= 0.68
    ]
    covered = {
        topic
        for item in raw_items
        for topic in item.metadata.get("topics", [])
    }
    novelty_curve = [round(entry.novelty_score, 3) for entry in blackboard.query_history]
    telemetry = getattr(blackboard, "engine_telemetry", None) or {}
    decisions = telemetry.get("decisions", {})
    return {
        "rounds": len(blackboard.query_history),
        "api_calls": blackboard.metrics.api_calls_used,
        "total_items": len(raw_items),
        "relevant_items": len(relevant),
        "relevant_per_call": round(len(relevant) / api_calls, 4),
        "items_per_call": round(len(raw_items) / api_calls, 4),
        "novelty_curve": novelty_curve,
        "topics_covered": sorted(covered),
        "open_gaps": [gap.taxonomy_or_component for gap in blackboard.coverage_gaps],
        "decision_attempts": decisions.get("attempts", 0),
        "decision_successes": decisions.get("successes", 0),
        "decision_fallbacks": decisions.get("failure_count", 0),
        "relevance_methods": _relevance_method_counts(raw_items),
        "advanced_params": advanced_param_usage(blackboard),
        "stop_round": stop_round_deviation(blackboard),
    }


def _relevance_method_counts(items: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        method = (item.metadata.get("relevance") or {}).get("method", "none")
        counts[method] = counts.get(method, 0) + 1
    return counts


def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any]:
    def stat(key: str) -> dict[str, float]:
        values = [float(sample[key]) for sample in samples]
        return {
            "mean": round(statistics.mean(values), 4),
            "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }

    return {
        "n": len(samples),
        "relevant_per_call": stat("relevant_per_call"),
        "items_per_call": stat("items_per_call"),
        "relevant_items": stat("relevant_items"),
        "rounds": stat("rounds"),
        "topics_covered_count": {
            "mean": round(
                statistics.mean(len(sample["topics_covered"]) for sample in samples), 2
            )
        },
        "advanced_call_share": {
            "mean": round(
                statistics.mean(
                    sample["advanced_params"]["advanced_call_share"] for sample in samples
                ),
                4,
            )
        },
        "decision_fallback_rate": {
            "mean": round(
                statistics.mean(
                    sample["decision_fallbacks"] / sample["decision_attempts"]
                    if sample["decision_attempts"]
                    else 0.0
                    for sample in samples
                ),
                4,
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--goals", default="tests/eval_goals.json")
    parser.add_argument("--engines", default="rules,sdk")
    parser.add_argument("--repeats", type=int, default=None)
    parser.add_argument("--goal-ids", default="")
    parser.add_argument("--out", default="data/eval")
    args = parser.parse_args()

    spec = json.loads(Path(args.goals).read_text(encoding="utf-8-sig"))
    repeats = args.repeats or spec.get("protocol", {}).get("repeats_per_engine", 3)
    engines = [engine.strip() for engine in args.engines.split(",") if engine.strip()]
    wanted = {goal_id.strip() for goal_id in args.goal_ids.split(",") if goal_id.strip()}
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {"goals_version": spec.get("version"), "results": {}}
    for goal in spec["goals"]:
        if wanted and goal["goal_id"] not in wanted:
            continue
        goal_report: dict[str, Any] = {}
        for engine in engines:
            samples: list[dict[str, Any]] = []
            for repeat in range(repeats):
                store = JsonIntelRunStore(out_dir / goal["goal_id"] / engine)
                started = time.perf_counter()
                controller = create_intel_controller(
                    run_goal=goal["run_goal"],
                    initial_query=goal["initial_query"],
                    max_rounds=goal["max_rounds"],
                    max_results_per_round=goal["max_results_per_round"],
                    run_store=store,
                    target_topics=goal.get("target_topics"),
                    engine=engine,
                )
                blackboard = controller.run()
                metrics = run_metrics(blackboard)
                metrics["run_id"] = blackboard.run_id
                metrics["wall_seconds"] = round(time.perf_counter() - started, 1)
                samples.append(metrics)
                print(
                    f"[eval] {goal['goal_id']} engine={engine} repeat={repeat + 1}/{repeats} "
                    f"relevant/call={metrics['relevant_per_call']} rounds={metrics['rounds']}",
                    flush=True,
                )
            goal_report[engine] = {"samples": samples, "aggregate": aggregate(samples)}
        report["results"][goal["goal_id"]] = goal_report
        (out_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    print(f"\n[eval] report written to {out_dir / 'report.json'}")
    for goal_id, goal_report in report["results"].items():
        line = [goal_id]
        for engine, payload in goal_report.items():
            line.append(
                f"{engine}: relevant/call={payload['aggregate']['relevant_per_call']['mean']}"
            )
        print("  " + " | ".join(line))


if __name__ == "__main__":
    main()
