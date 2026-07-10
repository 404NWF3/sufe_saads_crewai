"""Command-line entry points for the intel_agent collection engine.

    intel-agent full --max-rounds 6 --max-api-calls 40
    intel-agent incremental --focus "agent tool abuse" --window-days 1
    intel-agent latest
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone

from .engine.controller import IntelAgentController
from .engine.modes import FullCollectionMode, IncrementalCollectionMode
from .observability import TraceSink
from .runtime import client as runtime_client
from .schemas import RunBudget
from .store import default_store


def _parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(raw)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _make_trace(args: argparse.Namespace) -> TraceSink | None:
    return TraceSink(console=True) if getattr(args, "verbose", False) else None


def _run_full(args: argparse.Namespace) -> int:
    controller = IntelAgentController()
    blackboard = controller.run(
        mode=FullCollectionMode(),
        budget=RunBudget(max_rounds=args.max_rounds, max_api_calls=args.max_api_calls),
        run_id=args.run_id,
        trace=_make_trace(args),
    )
    _report(blackboard)
    return 0


def _run_incremental(args: argparse.Namespace) -> int:
    controller = IntelAgentController()
    mode = IncrementalCollectionMode(
        focus=args.focus,
        window_days=args.window_days,
        since=_parse_since(args.since),
        use_watermark=not args.no_watermark,
    )
    blackboard = controller.run(
        mode=mode,
        budget=RunBudget(max_rounds=args.max_rounds, max_api_calls=args.max_api_calls),
        run_id=args.run_id,
        trace=_make_trace(args),
    )
    _report(blackboard)
    return 0


def _show_latest(_: argparse.Namespace) -> int:
    print(default_store().format_latest_intel(limit=20))
    return 0


def _report(blackboard) -> None:
    print(f"\nRun {blackboard.run_id} [{blackboard.run_mode}] finished.")
    print(f"  rounds: {len(blackboard.query_history)}")
    print(f"  items collected: {len(blackboard.raw_items)}")
    print(f"  api calls used: {blackboard.metrics.api_calls_used}")
    if blackboard.coverage_gaps:
        print(f"  open coverage gaps: {[g.taxonomy_or_component for g in blackboard.coverage_gaps]}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="intel-agent", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--max-rounds", type=int, default=6)
        sub.add_argument("--max-api-calls", type=int, default=40)
        sub.add_argument("--run-id", type=str, default=None)
        sub.add_argument(
            "--verbose", "-v", action="store_true",
            help="Stream per-turn model text + tool calls; also dump "
            "data/intel_agent/traces/<run_id>.jsonl.",
        )

    full = subparsers.add_parser("full", help="Full LLM-security collection across all topics.")
    add_common(full)
    full.set_defaults(func=_run_full)

    inc = subparsers.add_parser("incremental", help="Incremental collection by focus + time window.")
    add_common(inc)
    inc.add_argument("--focus", type=str, default=None, help="Topic/entity focus, e.g. 'jailbreak'.")
    inc.add_argument("--window-days", type=int, default=1, help="Look-back window in days.")
    inc.add_argument("--since", type=str, default=None, help="Explicit lower bound (ISO-8601).")
    inc.add_argument("--no-watermark", action="store_true", help="Ignore prior-run watermark.")
    inc.set_defaults(func=_run_incremental)

    latest = subparsers.add_parser("latest", help="Show the most recent persisted run.")
    latest.set_defaults(func=_show_latest)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) in {"full", "incremental"}:
        ok, reason = runtime_client.sdk_runtime_available()
        if not ok:
            print(f"[warn] SDK runtime unavailable ({reason}); running deterministic fallback.")
    return args.func(args)


def run_full() -> None:
    raise SystemExit(main(["full"]))


def run_incremental() -> None:
    raise SystemExit(main(["incremental"]))


def show_latest() -> None:
    raise SystemExit(main(["latest"]))


if __name__ == "__main__":
    raise SystemExit(main())
