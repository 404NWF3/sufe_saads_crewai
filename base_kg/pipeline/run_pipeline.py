"""CLI entry point for the standalone base-KG construction pipeline.

Usage (from repo root):
    uv run --group basekg python -m base_kg.pipeline.run_pipeline corpus --limit 5
    uv run --group basekg python -m base_kg.pipeline.run_pipeline extract --limit 5
    uv run --group basekg python -m base_kg.pipeline.run_pipeline load
    uv run --group basekg python -m base_kg.pipeline.run_pipeline evaluate --skip-accuracy
    uv run --group basekg python -m base_kg.pipeline.run_pipeline all --limit 5
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import BaseKgConfig


def main() -> None:
    # Windows consoles may default to GBK; corpus text contains arbitrary Unicode.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="LLM security base-KG pipeline")
    sub = parser.add_subparsers(dest="stage", required=True)

    p_corpus = sub.add_parser("corpus", help="extract text from data/kg-source PDFs")
    p_extract = sub.add_parser("extract", help="run 3-stage LLM extraction per document")
    p_extract.add_argument("--overwrite", action="store_true")
    sub.add_parser("load", help="load extractions into Neo4j")
    p_eval = sub.add_parser("evaluate", help="dual-perspective quality assessment")
    p_eval.add_argument("--skip-accuracy", action="store_true")
    p_all = sub.add_parser("all", help="corpus -> extract -> load -> evaluate")
    p_all.add_argument("--overwrite", action="store_true")
    p_all.add_argument("--skip-accuracy", action="store_true")

    for p in (p_corpus, p_extract, p_eval, p_all, sub.choices["load"]):
        p.add_argument("--limit", type=int, default=None, help="max documents to process")

    args = parser.parse_args()
    cfg = BaseKgConfig.from_env()

    if args.stage in ("corpus", "all"):
        from .corpus import build_corpus

        counts = build_corpus(cfg.source_dir, cfg.corpus_path, cfg.max_chunk_chars, args.limit)
        print(f"[corpus] done: {counts} -> {cfg.corpus_path}")

    if args.stage in ("extract", "all"):
        from .extract import run_extraction

        counts = run_extraction(cfg, limit=args.limit, overwrite=args.overwrite)
        print(f"[extract] done: {counts} -> {cfg.extractions_dir}")

    if args.stage in ("load", "all"):
        from .neo4j_store import run_load

        totals = run_load(cfg, limit=args.limit)
        print(f"[load] done: {totals} -> {cfg.neo4j_uri}")

    if args.stage in ("evaluate", "all"):
        from .evaluate import run_evaluation

        report = run_evaluation(cfg, limit=args.limit, skip_accuracy=args.skip_accuracy)
        print(json.dumps(report.get("complexity", {}), ensure_ascii=False, indent=2))
        if "accuracy" in report:
            accuracy = dict(report["accuracy"])
            accuracy.pop("per_doc", None)
            print(json.dumps(accuracy, ensure_ascii=False, indent=2))
        print(f"[evaluate] full report -> {cfg.evaluation_path}")


if __name__ == "__main__":
    main()
