"""Gradio console: intel_agent collection + live verbose trace + ctinexus_kg.

Orchestrates the two backend packages without coupling them to each other.
"""

from __future__ import annotations

import json
import os
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import gradio as gr

from ctinexus_kg.topics import ALL_SECURITY_TOPICS, CORE_SECURITY_TOPICS
from intel_agent.engine.controller import IntelAgentController
from intel_agent.engine.modes import FullCollectionMode, IncrementalCollectionMode
from intel_agent.observability import TraceSink, format_event_line, load_trace_jsonl
from intel_agent.schemas import RunBudget
from intel_agent.store import default_store

from .db_browser import (
    load_run_detail,
    query_items_panel,
    refresh_runs,
    source_choices,
    store_status,
    topic_choices,
)
from .kg_panel import (
    generate_batch_from_db,
    generate_selected_from_db,
    kg_config_summary,
    list_kg_records,
    refresh_db_ready,
)
from .memory_browser import (
    load_playbook,
    load_relevance_cache,
    memory_status,
    playbook_status_choices,
    playbook_topic_choices,
)
DEFAULT_TRACE_DIR = Path("data") / "intel_agent" / "traces"


def _item_rows(items: list[Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for item in items:
        meta = item.metadata if hasattr(item, "metadata") else {}
        topics = ", ".join(meta.get("topics", []) or []) or "unclassified"
        published = ""
        if getattr(item, "published_at", None):
            published = item.published_at.isoformat()
        rows.append(
            [
                item.item_id,
                item.source_name,
                (item.title or "")[:120],
                round(float(item.relevance_score), 3),
                topics,
                published,
                (item.source_uri or "")[:80],
            ]
        )
    return rows


def _run_collection(
    mode_name: str,
    focus: str,
    window_days: int,
    max_rounds: int,
    max_api_calls: int,
    verbose: bool,
) -> Iterator[tuple[str, str, list[list[Any]], dict[str, Any]]]:
    """Generator: stream trace lines while collection runs in a worker thread."""
    event_q: queue.Queue[dict[str, Any] | None] = queue.Queue()
    result_box: dict[str, Any] = {}
    lines: list[str] = []

    def on_event(record: dict[str, Any]) -> None:
        event_q.put(record)

    def worker() -> None:
        try:
            if mode_name == "incremental":
                mode = IncrementalCollectionMode(
                    focus=focus.strip() or None,
                    window_days=int(window_days) if window_days else 1,
                )
            else:
                mode = FullCollectionMode()
            trace = TraceSink(console=False, on_event=on_event if verbose else None)
            controller = IntelAgentController()
            blackboard = controller.run(
                mode=mode,
                budget=RunBudget(max_rounds=int(max_rounds), max_api_calls=int(max_api_calls)),
                trace=trace,
            )
            result_box["blackboard"] = blackboard
            result_box["ok"] = True
        except Exception as exc:  # noqa: BLE001
            result_box["error"] = f"{exc.__class__.__name__}: {exc}"
            result_box["ok"] = False
        finally:
            event_q.put(None)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    while True:
        record = event_q.get()
        if record is None:
            break
        line = format_event_line(record)
        if line:
            lines.append(line)
            yield (
                "\n".join(lines),
                "Collecting…",
                [],
                {"status": "running"},
            )

    thread.join(timeout=5)
    if not result_box.get("ok"):
        err = result_box.get("error", "unknown error")
        lines.append(f"\n[error] {err}")
        yield "\n".join(lines), f"Failed: {err}", [], {"status": "failed", "error": err}
        return

    bb = result_box["blackboard"]
    summary = {
        "status": "succeeded",
        "run_id": bb.run_id,
        "run_mode": bb.run_mode,
        "rounds": len(bb.query_history),
        "items": len(bb.raw_items),
        "api_calls_used": bb.metrics.api_calls_used,
        "open_gaps": [g.taxonomy_or_component for g in bb.coverage_gaps],
        "trace_path": str(DEFAULT_TRACE_DIR / f"{bb.run_id}.jsonl"),
    }
    lines.append(f"\n[done] run={bb.run_id} items={len(bb.raw_items)}")
    state = {
        "run_id": bb.run_id,
        "raw_items": [i.model_dump(mode="json") for i in bb.raw_items],
        "summary": summary,
    }
    yield "\n".join(lines), json.dumps(summary, ensure_ascii=False, indent=2), _item_rows(bb.raw_items), state


def _load_latest() -> tuple[str, list[list[Any]], dict[str, Any]]:
    store = default_store()
    payload = store.load_latest_payload()
    if not payload:
        return "No runs found.", [], {}
    bb = payload.get("blackboard") or {}
    items_raw = bb.get("raw_items") or []
    from intel_agent.schemas import RawIntelItem

    items = [RawIntelItem.model_validate(i) for i in items_raw]
    summary = {
        "run_id": payload.get("run_id"),
        "status": payload.get("status"),
        "saved_at": payload.get("saved_at"),
        "items": len(items),
    }
    state = {
        "run_id": payload.get("run_id"),
        "raw_items": items_raw,
        "summary": summary,
    }
    return json.dumps(summary, ensure_ascii=False, indent=2), _item_rows(items), state


def _replay_trace(run_id: str) -> str:
    rid = (run_id or "").strip()
    if not rid:
        return "Provide a run_id."
    path = DEFAULT_TRACE_DIR / f"{rid}.jsonl"
    events = load_trace_jsonl(path)
    if not events:
        return f"No trace at {path}"
    return "\n".join(line for e in events if (line := format_event_line(e)))


def build_app() -> gr.Blocks:
    with gr.Blocks(title="LLM Security Intel Console") as app:
        gr.Markdown(
            "# LLM Security Intelligence Console\n"
            "Collect with **intel_agent** (live verbose trace) → optionally generate "
            "item KGs with **ctinexus_kg**."
        )
        state = gr.State({})

        with gr.Tab("Collect"):
            with gr.Row():
                mode = gr.Radio(["full", "incremental"], value="full", label="Mode")
                focus = gr.Textbox(label="Incremental focus", placeholder="agent tool abuse")
                window_days = gr.Number(value=7, label="Window days", precision=0)
            with gr.Row():
                max_rounds = gr.Number(value=4, label="Max rounds", precision=0)
                max_api_calls = gr.Number(value=20, label="Max API calls", precision=0)
                verbose = gr.Checkbox(value=True, label="Verbose (live agent trace)")
            run_btn = gr.Button("Run collection", variant="primary")
            load_btn = gr.Button("Load latest run")
            with gr.Row():
                summary_box = gr.Code(label="Run summary", language="json")
                trace_box = gr.Textbox(label="Agent verbose trace", lines=22)
            items_table = gr.Dataframe(
                headers=["item_id", "source", "title", "relevance", "topics", "published", "uri"],
                label="Collected items",
                interactive=False,
            )
            run_btn.click(
                _run_collection,
                inputs=[mode, focus, window_days, max_rounds, max_api_calls, verbose],
                outputs=[trace_box, summary_box, items_table, state],
            )
            load_btn.click(_load_latest, outputs=[summary_box, items_table, state])

        with gr.Tab("Trace replay"):
            rid = gr.Textbox(label="run_id")
            replay_btn = gr.Button("Load trace JSONL")
            replay_out = gr.Textbox(label="Trace", lines=24)
            replay_btn.click(_replay_trace, inputs=[rid], outputs=[replay_out])

        with gr.Tab("Knowledge Graphs"):
            gr.Markdown(
                "Generate item-level KGs from **persisted intel** (Mongo/JSON store). "
                "Model settings come from `.env` (`CTINEXUS_*` → `GLM_*`); UI model pickers are hidden. "
                "Succeeded graphs are written to disk and upserted into the `knowledge_graphs` store."
            )
            kg_cfg_box = gr.Textbox(
                label="Active CTINexus config (from env)",
                value=kg_config_summary(),
                interactive=False,
            )
            with gr.Row():
                kg_run = gr.Textbox(label="Filter run_id (optional)")
                kg_topic = gr.Dropdown(
                    label="Topic (Core + Extended)",
                    choices=[""] + list(ALL_SECURITY_TOPICS),
                    value="",
                )
                kg_source = gr.Textbox(label="Source filter", placeholder="nvd_cve_api")
                kg_limit = gr.Number(value=50, label="Query limit", precision=0)
            with gr.Row():
                refresh_ready = gr.Button("Refresh kg_ready from database", variant="secondary")
                batch_limit = gr.Number(value=10, label="Batch size", precision=0)
            kg_ready_msg = gr.Textbox(label="Ready list status", interactive=False)
            item_dd = gr.Dropdown(label="KG-ready item", choices=[], allow_custom_value=True)
            with gr.Row():
                one_btn = gr.Button("Generate KG for selected")
                batch_btn = gr.Button("Batch generate kg_ready", variant="primary")
            kg_out = gr.Code(label="KG result", language="json")
            kg_table = gr.Dataframe(
                headers=["item_id", "status", "triplets", "entities", "excluded", "error", "path"],
                label="KG generation results",
                interactive=False,
            )
            refresh_ready.click(
                refresh_db_ready,
                inputs=[kg_run, kg_topic, kg_source, kg_limit],
                outputs=[kg_ready_msg, item_dd],
            )
            one_btn.click(
                generate_selected_from_db,
                inputs=[item_dd],
                outputs=[kg_out, kg_table],
            )
            batch_btn.click(
                generate_batch_from_db,
                inputs=[kg_run, kg_topic, kg_source, batch_limit],
                outputs=[kg_out, kg_table],
            )
            app.load(kg_config_summary, outputs=[kg_cfg_box])

        with gr.Tab("Database"):
            gr.Markdown(
                "Browse persisted **runs** and the global deduplicated **items** store "
                "(MongoDB when `INTEL_MONGO_URI` is set, otherwise JSON under `data/intel_runs`). "
                "CSV exports are written to `data/exports/`."
            )
            db_status = gr.Textbox(label="Store status", lines=3, interactive=False)
            status_btn = gr.Button("Refresh store status")
            status_btn.click(store_status, outputs=[db_status])

            with gr.Accordion("Runs", open=True):
                with gr.Row():
                    runs_limit = gr.Number(value=50, label="Limit", precision=0)
                    runs_btn = gr.Button("List runs", variant="primary")
                runs_msg = gr.Textbox(label="Runs result", interactive=False)
                runs_table = gr.Dataframe(
                    headers=[
                        "run_id",
                        "status",
                        "saved_at",
                        "item_count",
                        "run_mode",
                        "rounds",
                        "run_goal",
                        "coverage_gaps",
                        "engine",
                    ],
                    label="Runs",
                    interactive=False,
                )
                runs_csv = gr.File(label="Download runs CSV")
                runs_btn.click(
                    refresh_runs,
                    inputs=[runs_limit],
                    outputs=[runs_msg, runs_table, runs_csv],
                )

            with gr.Accordion("Items (global intel)", open=True):
                with gr.Row():
                    item_source = gr.Dropdown(
                        label="Source",
                        choices=source_choices(),
                        value="",
                        allow_custom_value=True,
                    )
                    item_topic = gr.Dropdown(
                        label="Topic",
                        choices=topic_choices(),
                        value="",
                    )
                    item_limit = gr.Number(value=200, label="Limit", precision=0)
                with gr.Row():
                    item_text = gr.Textbox(
                        label="Text search (title / summary / item_id)",
                        placeholder="prompt injection",
                    )
                    item_run = gr.Textbox(label="Filter by run_id (optional)")
                with gr.Row():
                    items_btn = gr.Button("Query items", variant="primary")
                    refresh_sources_btn = gr.Button("Refresh source list")
                items_msg = gr.Textbox(label="Items result", interactive=False)
                items_table = gr.Dataframe(
                    headers=[
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
                    ],
                    label="Items",
                    interactive=False,
                )
                items_csv = gr.File(label="Download items CSV")
                items_btn.click(
                    query_items_panel,
                    inputs=[item_source, item_topic, item_text, item_run, item_limit],
                    outputs=[items_msg, items_table, items_csv],
                )
                refresh_sources_btn.click(
                    lambda: gr.update(choices=source_choices()),
                    outputs=[item_source],
                )

            with gr.Accordion("Run detail", open=False):
                detail_rid = gr.Textbox(label="run_id")
                detail_btn = gr.Button("Load run + its items")
                detail_json = gr.Code(label="Run summary", language="json")
                detail_table = gr.Dataframe(
                    headers=[
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
                    ],
                    label="Items in run",
                    interactive=False,
                )
                detail_csv = gr.File(label="Download run items CSV")
                detail_btn.click(
                    load_run_detail,
                    inputs=[detail_rid],
                    outputs=[detail_json, detail_table, detail_csv],
                )

            with gr.Accordion("Knowledge graph records", open=True):
                gr.Markdown(
                    "Persisted item KGs (`knowledge_graphs` collection or "
                    "`data/intel_agent/knowledge_graphs/`)."
                )
                with gr.Row():
                    kgdb_status = gr.Dropdown(
                        label="Status",
                        choices=["", "succeeded", "failed", "skipped", "pending"],
                        value="",
                    )
                    kgdb_run = gr.Textbox(label="run_id filter")
                    kgdb_item = gr.Textbox(label="item_id filter")
                    kgdb_limit = gr.Number(value=100, label="Limit", precision=0)
                kgdb_btn = gr.Button("List KG records", variant="primary")
                kgdb_msg = gr.Textbox(label="KG records result", interactive=False)
                kgdb_table = gr.Dataframe(
                    headers=[
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
                    ],
                    label="Knowledge graphs",
                    interactive=False,
                )
                kgdb_csv = gr.File(label="Download KG records CSV")
                kgdb_btn.click(
                    list_kg_records,
                    inputs=[kgdb_status, kgdb_run, kgdb_item, kgdb_limit],
                    outputs=[kgdb_msg, kgdb_table, kgdb_csv],
                )

            app.load(store_status, outputs=[db_status])

        with gr.Tab("Memory"):
            gr.Markdown(
                "Self-evolving **playbook** (harvested search techniques) and the "
                "**relevance embedding cache** (`title|summary` hash → score/topic). "
                "CSV exports go to `data/exports/`."
            )
            mem_status = gr.Textbox(label="Memory status", lines=4, interactive=False)
            mem_status_btn = gr.Button("Refresh memory status")
            mem_status_btn.click(memory_status, outputs=[mem_status])

            with gr.Accordion("Playbook (query strategies)", open=True):
                with gr.Row():
                    pb_topic = gr.Dropdown(
                        label="Topic",
                        choices=playbook_topic_choices(),
                        value="",
                    )
                    pb_source = gr.Textbox(label="Source filter", placeholder="nvd_cve_api")
                    pb_status = gr.Dropdown(
                        label="Status",
                        choices=playbook_status_choices(),
                        value="",
                    )
                    pb_limit = gr.Number(value=200, label="Limit", precision=0)
                pb_text = gr.Textbox(
                    label="Text search (technique / operator / id)",
                    placeholder="CWE-94",
                )
                pb_btn = gr.Button("Load playbook", variant="primary")
                pb_msg = gr.Textbox(label="Playbook result", interactive=False)
                pb_table = gr.Dataframe(
                    headers=[
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
                    ],
                    label="Techniques",
                    interactive=False,
                    wrap=True,
                )
                pb_csv = gr.File(label="Download playbook CSV")
                pb_btn.click(
                    load_playbook,
                    inputs=[pb_topic, pb_source, pb_status, pb_text, pb_limit],
                    outputs=[pb_msg, pb_table, pb_csv],
                )

            with gr.Accordion("Relevance embedding cache", open=True):
                with gr.Row():
                    cache_topic = gr.Dropdown(
                        label="Topic",
                        choices=playbook_topic_choices(),
                        value="",
                    )
                    cache_min = gr.Number(value=0.0, label="Min embedding score")
                    cache_limit = gr.Number(value=500, label="Limit", precision=0)
                cache_btn = gr.Button("Load relevance cache", variant="primary")
                cache_msg = gr.Textbox(label="Cache result", interactive=False)
                cache_table = gr.Dataframe(
                    headers=["hash", "embedding_score", "topic"],
                    label="Cached embedding scores",
                    interactive=False,
                )
                cache_csv = gr.File(label="Download cache CSV")
                cache_btn.click(
                    load_relevance_cache,
                    inputs=[cache_topic, cache_min, cache_limit],
                    outputs=[cache_msg, cache_table, cache_csv],
                )

            app.load(memory_status, outputs=[mem_status])

        gr.Markdown(
            f"_Coverage Core: {len(CORE_SECURITY_TOPICS)} topics · "
            f"Searchable All: {len(ALL_SECURITY_TOPICS)} · "
            f"_Server time {datetime.now(timezone.utc).isoformat()}_"
        )
    return app

def main() -> None:
    host = os.getenv("GRADIO_SERVER_NAME", "0.0.0.0")
    port = int(os.getenv("GRADIO_SERVER_PORT", "8000"))
    build_app().launch(server_name=host, server_port=port)


if __name__ == "__main__":
    main()
