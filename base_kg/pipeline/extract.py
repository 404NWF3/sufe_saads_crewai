"""Three-stage schema-guided extraction: NER -> entity standardization -> relation extraction.

Each stage is a separate LLM call with a one-shot prompt, mirroring the
chain-of-thought decomposition in the reference paper. Triplets are validated
programmatically against the schema's domain/range constraints before being kept.
"""

from __future__ import annotations

import json
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .config import PROMPTS_DIR, BaseKgConfig
from .corpus import load_corpus
from .llm import LLMClient
from .relevance import load_relevance
from .schema_loader import (
    entity_type_names,
    load_schema,
    relation_specs,
    render_entity_types,
    render_relations,
)


def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def _fill(template: str, **slots: str) -> str:
    for key, value in slots.items():
        template = template.replace(f"[[{key}]]", value)
    return template


class ExtractionPipeline:
    def __init__(self, cfg: BaseKgConfig, llm: LLMClient):
        self.cfg = cfg
        self.llm = llm
        self.schema = load_schema()
        self.entity_types_text = render_entity_types(self.schema)
        self.relations_text = render_relations(self.schema)
        self.valid_types = entity_type_names(self.schema)
        self.relation_specs = relation_specs(self.schema)
        self.ner_prompt = _load_prompt("ner.txt")
        self.std_prompt = _load_prompt("entity_standardization.txt")
        self.re_prompt = _load_prompt("relation_extraction.txt")

    def run_doc(self, doc: dict) -> dict[str, Any]:
        t0 = time.monotonic()
        entities = self._ner(doc["text"])
        t1 = time.monotonic()
        entities = self._standardize(entities)
        t2 = time.monotonic()
        triplets, dropped = self._relations(doc["text"], entities)
        t3 = time.monotonic()
        return {
            "doc_id": doc["doc_id"],
            "category": doc["category"],
            "lang": doc.get("lang", "unknown"),
            "entities": entities,
            "triplets": triplets,
            "dropped_triplets": dropped,
            "stage_seconds": {
                "ner": round(t1 - t0, 1),
                "std": round(t2 - t1, 1),
                "re": round(t3 - t2, 1),
            },
        }

    def _ner(self, text: str) -> list[dict]:
        prompt = _fill(self.ner_prompt, ENTITY_TYPES=self.entity_types_text, TEXT=text)
        result = self.llm.chat_json(prompt, model=self.cfg.ner_model)
        entities = [e for e in result.get("entities", []) if isinstance(e, dict)]
        return [e for e in entities if e.get("type") in self.valid_types and e.get("name")]

    def _standardize(self, entities: list[dict]) -> list[dict]:
        if not entities:
            return []
        prompt = _fill(
            self.std_prompt,
            ENTITY_TYPES=self.entity_types_text,
            ENTITIES=json.dumps({"entities": entities}, ensure_ascii=False, indent=2),
        )
        result = self.llm.chat_json(prompt, model=self.cfg.std_model)
        standardized = [e for e in result.get("entities", []) if isinstance(e, dict)]
        kept = [
            e
            for e in standardized
            if e.get("type") in self.valid_types and (e.get("canonicalName") or e.get("name"))
        ]
        for entity in kept:
            entity.setdefault("canonicalName", entity["name"])
            entity.setdefault("mergedIds", [])
        return kept

    def _relations(self, text: str, entities: list[dict]) -> tuple[list[dict], list[dict]]:
        if len(entities) < 2:
            return [], []
        prompt = _fill(
            self.re_prompt,
            RELATIONS=self.relations_text,
            TEXT=text,
            ENTITIES=json.dumps({"entities": entities}, ensure_ascii=False, indent=2),
        )
        result = self.llm.chat_json(prompt, model=self.cfg.re_model)
        by_id = {e["id"]: e for e in entities if e.get("id")}
        kept: list[dict] = []
        dropped: list[dict] = []
        for triplet in result.get("triplets", []):
            if not isinstance(triplet, dict):
                continue
            reason = self._validate_triplet(triplet, by_id)
            if reason is None:
                kept.append(triplet)
            else:
                triplet["drop_reason"] = reason
                dropped.append(triplet)
        return kept, dropped

    def _validate_triplet(self, triplet: dict, by_id: dict[str, dict]) -> str | None:
        subject = by_id.get(triplet.get("subject"))
        obj = by_id.get(triplet.get("object"))
        spec = self.relation_specs.get(triplet.get("relation", ""))
        if subject is None or obj is None:
            return "unknown_entity_id"
        if spec is None:
            return "unknown_relation"
        if triplet["subject"] == triplet["object"]:
            return "self_loop"
        if subject["type"] not in spec["domain"]:
            return f"domain_violation:{subject['type']}"
        if obj["type"] not in spec["range"]:
            return f"range_violation:{obj['type']}"
        return None


def _extract_one(pipeline: ExtractionPipeline, doc: dict, out_path: Path) -> str:
    result = pipeline.run_doc(doc)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    timing = result["stage_seconds"]
    return (
        f"[extract] {doc['doc_id']}: {len(result['entities'])} entities, "
        f"{len(result['triplets'])} triplets ({len(result['dropped_triplets'])} dropped) "
        f"| ner={timing['ner']}s std={timing['std']}s re={timing['re']}s"
    )


def run_extraction(
    cfg: BaseKgConfig, limit: int | None = None, overwrite: bool = False
) -> dict[str, int]:
    docs = load_corpus(cfg.corpus_path, limit=limit)
    cfg.extractions_dir.mkdir(parents=True, exist_ok=True)
    relevance = load_relevance(cfg.relevance_path)
    counts = {"extracted": 0, "skipped": 0, "filtered": 0, "failed": 0}

    pending: list[dict] = []
    for doc in docs:
        decision = relevance.get(doc["doc_id"])
        if decision is not None and not decision.get("relevant", True):
            counts["filtered"] += 1
            continue
        if (cfg.extractions_dir / f"{doc['doc_id']}.json").exists() and not overwrite:
            counts["skipped"] += 1
            continue
        pending.append(doc)
    if not pending:
        return counts

    # One pipeline per worker, each bound to one API key (round-robin), so the
    # per-client throttle/backoff applies per key.
    keys = cfg.llm_api_keys or [cfg.llm_api_key]
    n_workers = min(cfg.concurrency, len(pending))
    pipelines = [
        ExtractionPipeline(cfg, LLMClient(cfg, api_key=keys[i % len(keys)]))
        for i in range(n_workers)
    ]
    pool: queue.SimpleQueue[ExtractionPipeline] = queue.SimpleQueue()
    for pipeline in pipelines:
        pool.put(pipeline)

    def worker(doc: dict) -> str:
        pipeline = pool.get()
        try:
            return _extract_one(
                pipeline, doc, cfg.extractions_dir / f"{doc['doc_id']}.json"
            )
        finally:
            pool.put(pipeline)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        futures = {executor.submit(worker, doc): doc for doc in pending}
        for future in as_completed(futures):
            doc = futures[future]
            try:
                print(future.result())
                counts["extracted"] += 1
            except Exception as exc:  # noqa: BLE001 - one bad doc must not kill the run
                print(f"[extract] failed: {doc['doc_id']}: {exc}")
                counts["failed"] += 1
    elapsed = time.monotonic() - started
    done = counts["extracted"] + counts["failed"]
    if done:
        print(
            f"[extract] {done} docs in {elapsed:.0f}s "
            f"({elapsed / done:.0f}s/doc effective, {n_workers} workers, {len(keys)} keys)"
        )
    return counts


def load_extractions(extractions_dir: Path, limit: int | None = None) -> list[dict]:
    results: list[dict] = []
    for path in sorted(extractions_dir.glob("*.json")):
        if limit is not None and len(results) >= limit:
            break
        results.append(json.loads(path.read_text(encoding="utf-8")))
    return results
