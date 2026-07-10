"""Gradio Memory panel: playbook techniques + relevance embedding cache."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from intel_agent.memory.playbook import PlaybookStore, default_playbook_path
from intel_agent.relevance import RelevanceConfig
from intel_agent.topics import TARGET_SECURITY_TOPICS

from .db_browser import _write_csv

PLAYBOOK_HEADERS = [
    "entry_id",
    "status",
    "source_name",
    "topic_bucket",
    "reward",
    "pulls",
    "hits",
    "hit_rate",
    "operator_signature",
    "time_scope_hint",
    "technique_text",
    "has_embedding",
    "created_run_id",
    "last_used_at",
    "provenance_runs",
]

CACHE_HEADERS = ["hash", "embedding_score", "topic"]


def _playbook_path() -> Path:
    return default_playbook_path()


def _cache_path() -> Path:
    return RelevanceConfig().cache_path


def memory_status() -> str:
    pb = _playbook_path()
    cache = _cache_path()
    n_pb = 0
    by_status: dict[str, int] = {}
    with_emb = 0
    if pb.is_file():
        store = PlaybookStore(path=pb, embedder=None)
        n_pb = len(store.entries)
        for e in store.entries.values():
            by_status[e.status] = by_status.get(e.status, 0) + 1
            if e.embedding:
                with_emb += 1
    n_cache = 0
    if cache.is_file():
        n_cache = sum(1 for line in cache.read_text(encoding="utf-8").splitlines() if line.strip())
    status_bits = ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())) or "none"
    return (
        f"Playbook: {pb} ({'exists' if pb.is_file() else 'missing'})\n"
        f"Techniques: {n_pb} ({status_bits}); with embedding: {with_emb}\n"
        f"Relevance cache: {cache} ({'exists' if cache.is_file() else 'missing'})\n"
        f"Cached embedding scores: {n_cache}"
    )


def playbook_topic_choices() -> list[str]:
    return [""] + list(TARGET_SECURITY_TOPICS) + ["general"]


def playbook_status_choices() -> list[str]:
    return ["", "active", "verified", "deprecated", "retired"]


def load_playbook(
    topic: str = "",
    source: str = "",
    status: str = "",
    text: str = "",
    limit: float | int = 200,
) -> tuple[str, list[list[Any]], str | None]:
    path = _playbook_path()
    if not path.is_file():
        return f"No playbook at {path}", [], None
    store = PlaybookStore(path=path, embedder=None)
    topic_f = (topic or "").strip().lower()
    source_f = (source or "").strip().lower()
    status_f = (status or "").strip().lower()
    needle = (text or "").strip().lower()
    lim = max(1, int(limit or 200))

    rows_data: list[list[Any]] = []
    for entry in sorted(
        store.entries.values(),
        key=lambda e: (e.reward, e.pulls, e.created_at),
        reverse=True,
    ):
        if topic_f and entry.topic_bucket.lower() != topic_f:
            continue
        if source_f and entry.source_name.lower() != source_f:
            continue
        if status_f and entry.status.lower() != status_f:
            continue
        if needle:
            blob = f"{entry.technique_text} {entry.operator_signature} {entry.entry_id}".lower()
            if needle not in blob:
                continue
        rows_data.append(
            [
                entry.entry_id,
                entry.status,
                entry.source_name,
                entry.topic_bucket,
                round(float(entry.reward), 3),
                int(entry.pulls),
                int(entry.hits),
                f"{entry.hit_rate:.0%}",
                entry.operator_signature,
                entry.time_scope_hint or "",
                entry.technique_text,
                "yes" if entry.embedding else "no",
                entry.created_run_id,
                entry.last_used_at or "",
                ", ".join(entry.provenance_runs),
            ]
        )
        if len(rows_data) >= lim:
            break

    csv_path = _write_csv(PLAYBOOK_HEADERS, rows_data, "playbook") if rows_data else None
    return f"{len(rows_data)} technique(s) (of {len(store.entries)} total)", rows_data, csv_path


def load_relevance_cache(
    topic: str = "",
    min_score: float | int = 0.0,
    limit: float | int = 500,
) -> tuple[str, list[list[Any]], str | None]:
    path = _cache_path()
    if not path.is_file():
        return f"No relevance cache at {path}", [], None

    topic_f = (topic or "").strip().lower()
    try:
        floor = float(min_score or 0.0)
    except (TypeError, ValueError):
        floor = 0.0
    lim = max(1, int(limit or 500))

    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    records.sort(key=lambda r: float(r.get("embedding_score") or 0.0), reverse=True)
    rows: list[list[Any]] = []
    for rec in records:
        score = float(rec.get("embedding_score") or 0.0)
        topic_v = rec.get("topic")
        topic_s = topic_v if isinstance(topic_v, str) else ""
        if topic_f and topic_s.lower() != topic_f:
            continue
        if score < floor:
            continue
        rows.append([rec.get("hash", ""), round(score, 4), topic_s])
        if len(rows) >= lim:
            break

    csv_path = _write_csv(CACHE_HEADERS, rows, "relevance_cache") if rows else None
    return f"{len(rows)} cache row(s) (file has {len(records)})", rows, csv_path
