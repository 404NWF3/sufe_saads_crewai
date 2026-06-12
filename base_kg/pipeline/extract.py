"""Three-stage schema-guided extraction: NER -> entity standardization -> relation extraction.

Each stage is a separate LLM call with a one-shot prompt, mirroring the
chain-of-thought decomposition in the reference paper. Triplets are validated
programmatically against the schema's domain/range constraints before being kept.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import PROMPTS_DIR, BaseKgConfig
from .corpus import load_corpus
from .llm import LLMClient
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
        entities = self._ner(doc["text"])
        entities = self._standardize(entities)
        triplets, dropped = self._relations(doc["text"], entities)
        return {
            "doc_id": doc["doc_id"],
            "category": doc["category"],
            "lang": doc.get("lang", "unknown"),
            "entities": entities,
            "triplets": triplets,
            "dropped_triplets": dropped,
        }

    def _ner(self, text: str) -> list[dict]:
        prompt = _fill(self.ner_prompt, ENTITY_TYPES=self.entity_types_text, TEXT=text)
        result = self.llm.chat_json(prompt)
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
        result = self.llm.chat_json(prompt)
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
        result = self.llm.chat_json(prompt)
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


def run_extraction(
    cfg: BaseKgConfig, limit: int | None = None, overwrite: bool = False
) -> dict[str, int]:
    docs = load_corpus(cfg.corpus_path, limit=limit)
    cfg.extractions_dir.mkdir(parents=True, exist_ok=True)
    pipeline = ExtractionPipeline(cfg, LLMClient(cfg))
    counts = {"extracted": 0, "skipped": 0, "failed": 0}
    for doc in docs:
        out_path = cfg.extractions_dir / f"{doc['doc_id']}.json"
        if out_path.exists() and not overwrite:
            counts["skipped"] += 1
            continue
        try:
            result = pipeline.run_doc(doc)
        except Exception as exc:  # noqa: BLE001 - one bad doc must not kill the run
            print(f"[extract] failed: {doc['doc_id']}: {exc}")
            counts["failed"] += 1
            continue
        out_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        counts["extracted"] += 1
        print(
            f"[extract] {doc['doc_id']}: {len(result['entities'])} entities, "
            f"{len(result['triplets'])} triplets ({len(result['dropped_triplets'])} dropped)"
        )
    return counts


def load_extractions(extractions_dir: Path, limit: int | None = None) -> list[dict]:
    results: list[dict] = []
    for path in sorted(extractions_dir.glob("*.json")):
        if limit is not None and len(results) >= limit:
            break
        results.append(json.loads(path.read_text(encoding="utf-8")))
    return results
