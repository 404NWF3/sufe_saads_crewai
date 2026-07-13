"""Gradio database panel helpers: query persisted runs/items and export CSV."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel_agent.store import default_store
from intel_agent.topics import ALL_SECURITY_TOPICS, CORE_SECURITY_TOPICS

EXPORT_DIR = Path("data") / "exports"

RUN_HEADERS = [
    "run_id",
    "status",
    "saved_at",
    "item_count",
    "run_mode",
    "rounds",
    "run_goal",
    "coverage_gaps",
    "stop_reason",
    "core_gap_count",
    "extended_item_count",
    "candidate_topic_count",
    "engine",
]

ITEM_HEADERS = [
    "item_id",
    "source_name",
    "title",
    "summary",
    "relevance_score",
    "topics",
    "published_at",
    "source_uri",
    "first_seen_at",
    "last_seen_at",
    "first_run_id",
    "last_run_id",
    "run_ids",
]


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._") or "export"


def store_status() -> str:
    store = default_store()
    backend = getattr(store, "store_backend", lambda: type(store).__name__)()
    try:
        runs = int(getattr(store, "run_count", lambda: 0)())
    except Exception as exc:  # noqa: BLE001
        return f"Store: {backend}\nError reading runs: {exc.__class__.__name__}: {exc}"
    try:
        items = int(getattr(store, "distinct_item_count", lambda: 0)())
    except Exception as exc:  # noqa: BLE001
        return f"Store: {backend}\nRuns: {runs}\nError reading items: {exc.__class__.__name__}: {exc}"
    kgs = 0
    try:
        kgs = int(getattr(store, "knowledge_graph_count", lambda: 0)())
    except Exception:  # noqa: BLE001
        kgs = 0
    return f"Store: {backend}\nRuns: {runs}\nDistinct items: {items}\nKnowledge graphs: {kgs}"


def source_choices() -> list[str]:
    store = default_store()
    try:
        sources = list(getattr(store, "distinct_sources", lambda: [])())
    except Exception:  # noqa: BLE001
        sources = []
    return [""] + sources


def topic_choices() -> list[str]:
    return [""] + list(ALL_SECURITY_TOPICS)


def _run_table(rows: list[dict[str, Any]]) -> list[list[Any]]:
    return [[r.get(h, "") for h in RUN_HEADERS] for r in rows]


def _item_table(docs: list[dict[str, Any]]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for doc in docs:
        topics = doc.get("topics")
        if not topics:
            topics = (doc.get("metadata") or {}).get("topics") or []
        run_ids = doc.get("run_ids") or []
        rows.append(
            [
                doc.get("item_id") or doc.get("_id") or "",
                doc.get("source_name") or "",
                (doc.get("title") or "")[:200],
                (doc.get("summary") or "")[:300],
                doc.get("relevance_score", ""),
                ", ".join(topics) if isinstance(topics, list) else str(topics or ""),
                doc.get("published_at") or "",
                doc.get("source_uri") or "",
                doc.get("first_seen_at") or "",
                doc.get("last_seen_at") or "",
                doc.get("first_run_id") or "",
                doc.get("last_run_id") or "",
                ", ".join(run_ids) if isinstance(run_ids, list) else str(run_ids or ""),
            ]
        )
    return rows


def _write_csv(headers: list[str], rows: list[list[Any]], prefix: str) -> str:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = EXPORT_DIR / f"{_safe_name(prefix)}_{stamp}.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
    return str(path)


def refresh_runs(limit: float | int = 50) -> tuple[str, list[list[Any]], str | None]:
    store = default_store()
    try:
        rows = store.list_run_summaries(limit=int(limit or 50))
    except Exception as exc:  # noqa: BLE001
        return f"Failed to list runs: {exc.__class__.__name__}: {exc}", [], None
    table = _run_table(rows)
    path = _write_csv(RUN_HEADERS, table, "runs") if table else None
    return f"{len(table)} run(s)", table, path


def query_items_panel(
    source_name: str,
    topic: str,
    text: str,
    run_id: str,
    limit: float | int,
) -> tuple[str, list[list[Any]], str | None]:
    store = default_store()
    try:
        docs = store.query_items(
            source_name=source_name or None,
            topic=topic or None,
            text=text or None,
            run_id=run_id or None,
            limit=int(limit or 200),
        )
    except Exception as exc:  # noqa: BLE001
        return f"Failed to query items: {exc.__class__.__name__}: {exc}", [], None
    table = _item_table(docs)
    path = _write_csv(ITEM_HEADERS, table, "items") if table else None
    return f"{len(table)} item(s)", table, path


def load_run_detail(run_id: str) -> tuple[str, list[list[Any]], str | None]:
    rid = (run_id or "").strip()
    if not rid:
        return "Provide a run_id.", [], None
    store = default_store()
    try:
        payload = store.load_run_payload(rid)
    except Exception as exc:  # noqa: BLE001
        return f"Failed to load run: {exc.__class__.__name__}: {exc}", [], None
    if not payload:
        return f"Run {rid!r} not found.", [], None

    # Prefer global items filtered by run_id when available; else blackboard items.
    try:
        docs = store.query_items(run_id=rid, limit=5000)
    except Exception:  # noqa: BLE001
        docs = []
    if not docs:
        for raw in (payload.get("blackboard") or {}).get("raw_items") or []:
            docs.append(raw)

    table = _item_table(docs)
    path = _write_csv(ITEM_HEADERS, table, f"run_{rid}_items") if table else None
    summary = {
        "run_id": payload.get("run_id"),
        "status": payload.get("status"),
        "saved_at": payload.get("saved_at"),
        "item_count": payload.get("item_count")
        or (payload.get("summary") or {}).get("raw_items"),
        "summary": payload.get("summary"),
        "item_ids_sample": (payload.get("item_ids") or [])[:30],
    }
    return json.dumps(summary, ensure_ascii=False, indent=2), table, path
