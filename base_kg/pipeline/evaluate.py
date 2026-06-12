"""Dual-perspective KG quality assessment, following the reference paper.

Structural complexity: entity redundancy (embedding clusters of same-type
entities), relation redundancy (duplicate SPO facts), self-loop rate (from
validation drops), and basic graph statistics.

Semantic accuracy: reconstruct each document from its extracted subgraph, then
score sentence-level max cosine similarity of original sentences against the
reconstruction (bi-encoder style, using the embedding API).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

import numpy as np

from .config import PROMPTS_DIR, BaseKgConfig
from .corpus import load_corpus
from .extract import load_extractions
from .llm import LLMClient

_SENTENCE_SPLIT = re.compile(r"(?<=[。！？!?\.])\s+|\n+")


def _cosine_matrix(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    a_norm = a / (np.linalg.norm(a, axis=1, keepdims=True) + 1e-12)
    b_norm = b / (np.linalg.norm(b, axis=1, keepdims=True) + 1e-12)
    return a_norm @ b_norm.T


def _split_sentences(text: str, max_sentences: int) -> list[str]:
    sentences = [s.strip() for s in _SENTENCE_SPLIT.split(text) if len(s.strip()) >= 10]
    return sentences[:max_sentences]


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        self.parent[self.find(x)] = self.find(y)


def assess_complexity(
    extractions: list[dict], llm: LLMClient, threshold: float
) -> dict[str, Any]:
    entities: list[tuple[str, str]] = []  # (type, canonicalName)
    seen: set[tuple[str, str]] = set()
    triplet_counts: dict[tuple[str, str, str], int] = defaultdict(int)
    dropped_self_loops = 0
    total_dropped = 0

    for extraction in extractions:
        by_id = {e["id"]: e for e in extraction["entities"] if e.get("id")}
        for entity in by_id.values():
            key = (entity["type"], (entity.get("canonicalName") or entity["name"]).lower())
            if key not in seen:
                seen.add(key)
                entities.append(key)
        for triplet in extraction["triplets"]:
            subject = by_id.get(triplet["subject"])
            obj = by_id.get(triplet["object"])
            if subject and obj:
                triplet_counts[
                    (
                        (subject.get("canonicalName") or subject["name"]).lower(),
                        triplet["relation"],
                        (obj.get("canonicalName") or obj["name"]).lower(),
                    )
                ] += 1
        for dropped in extraction.get("dropped_triplets", []):
            total_dropped += 1
            if dropped.get("drop_reason") == "self_loop":
                dropped_self_loops += 1

    # Entity redundancy: cluster same-type entities whose name embeddings are
    # close; redundancy is the fraction of entities collapsed by clustering.
    redundancy = 0.0
    redundant_clusters: list[list[str]] = []
    if len(entities) >= 2:
        vectors = np.asarray(llm.embed([name for _, name in entities]))
        uf = UnionFind(len(entities))
        sim = _cosine_matrix(vectors, vectors)
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                if entities[i][0] == entities[j][0] and sim[i, j] >= threshold:
                    uf.union(i, j)
        clusters: dict[int, list[int]] = defaultdict(list)
        for idx in range(len(entities)):
            clusters[uf.find(idx)].append(idx)
        n_clusters = len(clusters)
        redundancy = 1.0 - n_clusters / len(entities)
        redundant_clusters = [
            [entities[idx][1] for idx in members]
            for members in clusters.values()
            if len(members) > 1
        ]

    n_relationship_instances = sum(triplet_counts.values())
    duplicate_facts = sum(count - 1 for count in triplet_counts.values() if count > 1)
    return {
        "n_entities": len(entities),
        "n_unique_facts": len(triplet_counts),
        "n_relationship_instances": n_relationship_instances,
        "entity_redundancy": round(redundancy, 4),
        "redundant_clusters": redundant_clusters[:50],
        "relation_redundancy": round(
            duplicate_facts / n_relationship_instances, 4
        )
        if n_relationship_instances
        else 0.0,
        "self_loops_dropped": dropped_self_loops,
        "triplets_dropped_total": total_dropped,
        "avg_degree": round(2 * len(triplet_counts) / len(entities), 2) if entities else 0.0,
    }


def assess_accuracy(
    extractions: list[dict], corpus_docs: list[dict], cfg: BaseKgConfig, llm: LLMClient
) -> dict[str, Any]:
    reconstruction_prompt = (PROMPTS_DIR / "text_reconstruction.txt").read_text(
        encoding="utf-8"
    )
    texts_by_doc = {doc["doc_id"]: doc["text"] for doc in corpus_docs}
    per_doc: list[dict[str, Any]] = []
    for extraction in extractions:
        original = texts_by_doc.get(extraction["doc_id"])
        if not original or not extraction["triplets"]:
            continue
        prompt = reconstruction_prompt.replace(
            "[[ENTITIES]]",
            json.dumps(extraction["entities"], ensure_ascii=False, indent=2),
        ).replace(
            "[[TRIPLETS]]",
            json.dumps(extraction["triplets"], ensure_ascii=False, indent=2),
        )
        reconstructed = llm.chat(prompt)
        original_sentences = _split_sentences(original, cfg.max_eval_sentences)
        reconstructed_sentences = _split_sentences(reconstructed, cfg.max_eval_sentences)
        if not original_sentences or not reconstructed_sentences:
            continue
        orig_vecs = np.asarray(llm.embed(original_sentences))
        recon_vecs = np.asarray(llm.embed(reconstructed_sentences))
        max_sims = _cosine_matrix(orig_vecs, recon_vecs).max(axis=1)
        per_doc.append(
            {
                "doc_id": extraction["doc_id"],
                "reconstruction_accuracy": round(float(max_sims.mean()), 4),
                "n_original_sentences": len(original_sentences),
            }
        )
    scores = [d["reconstruction_accuracy"] for d in per_doc]
    return {
        "mean_reconstruction_accuracy": round(float(np.mean(scores)), 4) if scores else None,
        "std_reconstruction_accuracy": round(float(np.std(scores)), 4) if scores else None,
        "n_docs_evaluated": len(per_doc),
        "per_doc": per_doc,
    }


def run_evaluation(
    cfg: BaseKgConfig, limit: int | None = None, skip_accuracy: bool = False
) -> dict[str, Any]:
    extractions = load_extractions(cfg.extractions_dir, limit=limit)
    if not extractions:
        raise FileNotFoundError(f"no extractions found in {cfg.extractions_dir}")
    llm = LLMClient(cfg)
    report: dict[str, Any] = {
        "complexity": assess_complexity(
            extractions, llm, cfg.entity_redundancy_threshold
        )
    }
    if not skip_accuracy:
        corpus_docs = load_corpus(cfg.corpus_path)
        report["accuracy"] = assess_accuracy(extractions, corpus_docs, cfg, llm)
    cfg.evaluation_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.evaluation_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report
