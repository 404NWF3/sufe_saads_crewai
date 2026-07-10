"""Gradio Knowledge Graphs panel: env-based GLM config, DB items, Mongo persist."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import gradio as gr

from ctinexus_kg import KgGenerationConfig, generate_for_item, list_kg_ready
from ctinexus_kg.topics import ALL_SECURITY_TOPICS
from intel_agent.store import default_store

from .db_browser import _write_csv

KG_RECORD_HEADERS = [
    "item_id",
    "run_id",
    "status",
    "source_name",
    "triplet_count",
    "entity_count",
    "model",
    "embedding_model",
    "saved_at",
    "error",
    "ctinexus_json_path",
]


def default_kg_config() -> KgGenerationConfig:
    return KgGenerationConfig.from_env()


def kg_config_summary() -> str:
    cfg = default_kg_config()
    return (
        f"model={cfg.model} · embedding={cfg.embedding_model} · "
        f"base_url={cfg.base_url or '(from CTINEXUS_/GLM_/OPENAI_ env)'} · "
        f"threshold={cfg.similarity_threshold}"
    )


def _persist_record(record: Any) -> None:
    store = default_store()
    payload = record.model_dump(mode="json") if hasattr(record, "model_dump") else dict(record)
    graph: dict[str, Any] | None = None
    path = payload.get("ctinexus_json_path")
    if path and Path(path).is_file():
        try:
            loaded = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                graph = loaded
        except (OSError, json.JSONDecodeError):
            graph = None
    if hasattr(store, "save_knowledge_graph"):
        store.save_knowledge_graph(payload, graph)


def _run_id_for_item(item: dict[str, Any], fallback: str = "db-kg") -> str:
    run_ids = item.get("run_ids") or []
    first_from_list = run_ids[0] if run_ids else None
    return str(
        item.get("last_run_id")
        or item.get("first_run_id")
        or first_from_list
        or fallback
    )


def _kg_table(records: list[Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for r in records:
        if hasattr(r, "model_dump"):
            d = r.model_dump(mode="json")
        else:
            d = dict(r)
        excluded = ""
        elig = d.get("eligibility")
        if isinstance(elig, dict):
            excluded = elig.get("excluded_reason") or ""
        rows.append(
            [
                d.get("item_id"),
                d.get("status"),
                d.get("triplet_count", 0),
                d.get("entity_count", 0),
                excluded,
                d.get("error") or "",
                d.get("ctinexus_json_path") or "",
            ]
        )
    return rows


def refresh_db_ready(
    run_id: str = "",
    topic: str = "",
    source: str = "",
    limit: float | int = 100,
):
    store = default_store()
    cfg = default_kg_config()
    docs = store.query_items(
        source_name=source or None,
        topic=topic or None,
        run_id=run_id or None,
        limit=int(limit or 100),
    )
    ready = list_kg_ready(docs, config=cfg, target_topics=list(ALL_SECURITY_TOPICS))
    choices = [i.item_id for i in ready]
    msg = (
        f"{len(choices)} kg_ready of {len(docs)} queried "
        f"(config: {cfg.model} / {cfg.embedding_model})"
    )
    return msg, gr.update(choices=choices, value=choices[0] if choices else None)


def generate_selected_from_db(item_id: str) -> tuple[str, list[list[Any]]]:
    iid = (item_id or "").strip()
    if not iid:
        return "Select a kg_ready item_id.", []
    store = default_store()
    match = None
    if hasattr(store, "get_item"):
        match = store.get_item(iid)
    if match is None:
        for d in store.query_items(limit=5000):
            if str(d.get("item_id") or d.get("_id")) == iid:
                match = d
                break
    if match is None:
        return f"Item {iid!r} not found in store.", []

    cfg = default_kg_config()
    run_id = _run_id_for_item(match)
    record = generate_for_item(run_id, match, config=cfg)
    try:
        _persist_record(record)
    except Exception as exc:  # noqa: BLE001
        return (
            json.dumps(
                {
                    "warning": f"KG generated but persist failed: {exc}",
                    "record": record.model_dump(mode="json"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            _kg_table([record]),
        )
    return (
        json.dumps(record.model_dump(mode="json"), ensure_ascii=False, indent=2),
        _kg_table([record]),
    )


def generate_batch_from_db(
    run_id: str = "",
    topic: str = "",
    source: str = "",
    limit: float | int = 20,
) -> tuple[str, list[list[Any]]]:
    store = default_store()
    cfg = default_kg_config()
    docs = store.query_items(
        source_name=source or None,
        topic=topic or None,
        run_id=run_id or None,
        limit=int(limit or 20),
    )
    ready = list_kg_ready(docs, config=cfg, target_topics=list(ALL_SECURITY_TOPICS))
    if not ready:
        return "No kg_ready items for the current filters.", []

    records = []
    for item in ready:
        rid = _run_id_for_item(item.model_dump(mode="json"))
        rec = generate_for_item(rid, item, config=cfg)
        try:
            _persist_record(rec)
        except Exception as exc:  # noqa: BLE001
            rec.error = f"{rec.error or ''}; persist failed: {exc}".strip("; ")
        records.append(rec)

    summary = {
        "attempted": len(records),
        "succeeded": sum(1 for r in records if r.status == "succeeded"),
        "failed": sum(1 for r in records if r.status == "failed"),
        "skipped": sum(1 for r in records if r.status == "skipped"),
        "config": {"model": cfg.model, "embedding_model": cfg.embedding_model},
    }
    return json.dumps(summary, ensure_ascii=False, indent=2), _kg_table(records)


def list_kg_records(
    status: str = "",
    run_id: str = "",
    item_id: str = "",
    limit: float | int = 100,
) -> tuple[str, list[list[Any]], str | None]:
    store = default_store()
    if not hasattr(store, "list_knowledge_graphs"):
        return "Store does not support knowledge_graphs.", [], None
    docs = store.list_knowledge_graphs(
        status=status or None,
        run_id=run_id or None,
        item_id=item_id or None,
        limit=int(limit or 100),
    )
    rows = [
        [
            d.get("item_id"),
            d.get("run_id"),
            d.get("status"),
            d.get("source_name"),
            d.get("triplet_count", 0),
            d.get("entity_count", 0),
            d.get("model"),
            d.get("embedding_model"),
            d.get("saved_at"),
            d.get("error") or "",
            d.get("ctinexus_json_path") or "",
        ]
        for d in docs
    ]
    path = _write_csv(KG_RECORD_HEADERS, rows, "knowledge_graphs") if rows else None
    return f"{len(rows)} KG record(s)", rows, path
