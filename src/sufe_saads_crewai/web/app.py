from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sufe_saads_crewai.kg import CtinexusKgGenerator, assess_kg_eligibility
from sufe_saads_crewai.intel import create_intel_controller
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import IntelRunBlackboard, KgGenerationConfig, RawIntelItem
from sufe_saads_crewai.topic_utils import TARGET_SECURITY_TOPICS


def build_app():
    try:
        import gradio as gr
    except Exception as exc:
        raise RuntimeError("Gradio is not installed. Run `uv sync` before launching the web UI.") from exc

    with gr.Blocks(title="SUFE SAADS CrewAI Intelligence Console") as demo:
        last_run_state = gr.State(value={})
        gr.Markdown("# SUFE SAADS CrewAI Intelligence Console")
        with gr.Tab("Run"):
            with gr.Row():
                run_goal = gr.Textbox(
                    label="Search goal",
                    value="Collect comprehensive LLM security intelligence.",
                    lines=2,
                )
                search_query = gr.Textbox(
                    label="Initial query",
                    value="LLM prompt injection jailbreak RAG poisoning model supply chain",
                    lines=2,
                )
            with gr.Row():
                max_rounds = gr.Slider(label="Max rounds", minimum=1, maximum=50, value=5, step=1)
                max_results = gr.Slider(
                    label="Max results per round",
                    minimum=5,
                    maximum=120,
                    value=80,
                    step=5,
                )
                kg_enabled = gr.Checkbox(label="Show KG-ready eligibility", value=True)

        with gr.Tab("LLM"):
            with gr.Row():
                model = gr.Textbox(label="CTINexus model", value="gpt-4.1")
                temperature = gr.Slider(label="Stage temperature", minimum=0.0, maximum=1.5, value=0.8, step=0.05)
            with gr.Row():
                base_url = gr.Textbox(label="OpenAI-compatible base URL", value="")
                api_key = gr.Textbox(label="API key", type="password", value="")
            with gr.Row():
                embedding_model = gr.Textbox(label="Embedding model", value="text-embedding-3-large")
                similarity_threshold = gr.Slider(
                    label="Entity alignment threshold",
                    minimum=0.1,
                    maximum=0.95,
                    value=0.6,
                    step=0.05,
                )
            with gr.Row():
                ie_shot = gr.Slider(label="IE shots", minimum=0, maximum=8, value=2, step=1)
                et_shot = gr.Slider(label="ET shots", minimum=0, maximum=12, value=8, step=1)
                lp_shot = gr.Slider(label="LP shots", minimum=0, maximum=8, value=2, step=1)

        with gr.Tab("Results"):
            run_button = gr.Button("Run intelligence collection", variant="primary")
            summary_json = gr.JSON(label="Run summary")
            items_table = gr.Dataframe(
                headers=[
                    "index",
                    "item_id",
                    "source",
                    "relevance",
                    "kg_ready",
                    "kg_block_reason",
                    "text_chars",
                    "title",
                    "uri",
                ],
                label="Raw intelligence",
                wrap=True,
            )

        with gr.Tab("Knowledge Graphs"):
            kg_table = gr.Dataframe(
                headers=[
                    "item_id",
                    "source",
                    "status",
                    "reason_or_error",
                    "triplets",
                    "entities",
                    "json",
                    "html",
                ],
                label="Per-item KG records",
                wrap=True,
            )
            kg_json = gr.Code(label="Selected KG JSON", language="json")
            kg_index = gr.Number(label="KG row index", value=0, precision=0)
            load_kg_button = gr.Button("Load selected KG JSON")
            raw_item_selector = gr.Dropdown(
                label="KG-ready intelligence item",
                choices=[],
                value=None,
                interactive=True,
            )
            selected_item_preview = gr.JSON(label="Selected intelligence preview")
            selected_kg_button = gr.Button("Generate KG for selected intelligence")

        run_button.click(
            fn=_run_collection,
            inputs=[
                run_goal,
                search_query,
                max_rounds,
                max_results,
                kg_enabled,
                model,
                temperature,
                base_url,
                api_key,
                embedding_model,
                similarity_threshold,
                ie_shot,
                et_shot,
                lp_shot,
            ],
            outputs=[summary_json, items_table, kg_table, raw_item_selector, last_run_state],
        )
        load_kg_button.click(
            fn=_load_kg_json,
            inputs=[last_run_state, kg_index],
            outputs=[kg_json],
        )
        selected_kg_button.click(
            fn=_generate_selected_kg,
            inputs=[
                last_run_state,
                raw_item_selector,
                model,
                temperature,
                base_url,
                api_key,
                embedding_model,
                similarity_threshold,
                ie_shot,
                et_shot,
                lp_shot,
            ],
            outputs=[summary_json, kg_table, kg_json, last_run_state],
        )
        raw_item_selector.change(
            fn=_preview_raw_item,
            inputs=[last_run_state, raw_item_selector],
            outputs=[selected_item_preview],
        )

    return demo


def _run_collection(
    run_goal: str,
    search_query: str,
    max_rounds: int,
    max_results: int,
    kg_enabled: bool,
    model: str,
    temperature: float,
    base_url: str,
    api_key: str,
    embedding_model: str,
    similarity_threshold: float,
    ie_shot: int,
    et_shot: int,
    lp_shot: int,
) -> tuple[dict[str, Any], list[list[Any]], list[list[Any]], Any, dict[str, Any]]:
    import gradio as gr

    if api_key:
        os.environ["CTINEXUS_API_KEY"] = api_key
    if base_url:
        os.environ["CTINEXUS_BASE_URL"] = base_url

    run_store = JsonIntelRunStore()
    kg_config = _make_kg_config(
        enabled=kg_enabled,
        model=model,
        temperature=temperature,
        base_url=base_url,
        embedding_model=embedding_model,
        similarity_threshold=similarity_threshold,
        ie_shot=ie_shot,
        et_shot=et_shot,
        lp_shot=lp_shot,
    )

    result = create_intel_controller(
        run_goal=run_goal,
        initial_query=search_query,
        max_rounds=int(max_rounds),
        max_results_per_round=int(max_results),
        run_store=run_store,
    ).run()
    payload = run_store.load_run_payload(result.run_id)
    summary = payload["summary"]
    items = _item_rows(result.raw_items, kg_config)
    kg_rows = _kg_rows(result.item_knowledge_graphs)
    state = {
        "run_id": result.run_id,
        "raw_items": [item.model_dump(mode="json") for item in result.raw_items],
        "kg_config": kg_config.model_dump(mode="json"),
        "kg_json_paths": [
            record.ctinexus_json_path for record in result.item_knowledge_graphs
        ],
    }
    choices = _raw_item_choices(result.raw_items, kg_config)
    selector_update = gr.update(choices=choices, value=choices[0][1] if choices else None)
    return summary, items, kg_rows, selector_update, state


def _load_kg_json(state: dict[str, Any], kg_index: int) -> str:
    paths = state.get("kg_json_paths") or []
    index = int(kg_index)
    if index < 0 or index >= len(paths):
        return "{}"
    path = paths[index]
    if not path or not Path(path).exists():
        return "{}"
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _generate_selected_kg(
    state: dict[str, Any],
    raw_item_selection: str | int | float | None,
    model: str,
    temperature: float,
    base_url: str,
    api_key: str,
    embedding_model: str,
    similarity_threshold: float,
    ie_shot: int,
    et_shot: int,
    lp_shot: int,
) -> tuple[dict[str, Any], list[list[Any]], str, dict[str, Any]]:
    run_id = state.get("run_id")
    raw_items = state.get("raw_items") or []
    index = _selected_item_index(raw_item_selection)
    if not run_id or index < 0 or index >= len(raw_items):
        valid_range = f"0-{len(raw_items) - 1}" if raw_items else "empty"
        return {
            "error": "Select a valid raw intelligence item first.",
            "valid_raw_item_index_range": valid_range,
            "selected": raw_item_selection,
        }, [], "{}", state

    if api_key:
        os.environ["CTINEXUS_API_KEY"] = api_key
    if base_url:
        os.environ["CTINEXUS_BASE_URL"] = base_url

    item = RawIntelItem.model_validate(raw_items[index])
    kg_config = _make_kg_config(
        enabled=True,
        model=model,
        temperature=temperature,
        base_url=base_url,
        embedding_model=embedding_model,
        similarity_threshold=similarity_threshold,
        ie_shot=ie_shot,
        et_shot=et_shot,
        lp_shot=lp_shot,
    )
    decision = assess_kg_eligibility(
        item,
        kg_config,
        target_topics=list(TARGET_SECURITY_TOPICS),
    )
    if not decision.eligible:
        return {
            "error": "Selected item is not KG-ready and will not be processed.",
            "item_id": item.item_id,
            "kg_block_reason": decision.excluded_reason,
        }, [], "{}", state

    run_store = JsonIntelRunStore()
    generator = CtinexusKgGenerator(kg_config)
    record = generator.generate_for_item(
        str(run_id),
        item,
        target_topics=list(TARGET_SECURITY_TOPICS),
    )

    payload = run_store.load_run_payload(str(run_id))
    blackboard = IntelRunBlackboard.model_validate(payload["blackboard"])
    blackboard.item_knowledge_graphs = [
        existing
        for existing in blackboard.item_knowledge_graphs
        if existing.item_id != record.item_id
    ]
    blackboard.item_knowledge_graphs.append(record)
    generator.write_manifest(str(run_id), blackboard.item_knowledge_graphs)
    _write_updated_run_payload(run_store, payload, blackboard)

    kg_rows = _kg_rows(blackboard.item_knowledge_graphs)
    state = {
        **state,
        "kg_config": kg_config.model_dump(mode="json"),
        "kg_json_paths": [
            existing.ctinexus_json_path for existing in blackboard.item_knowledge_graphs
        ],
    }
    summary = payload["summary"]
    loaded_json = _load_kg_json(state, len(blackboard.item_knowledge_graphs) - 1)
    return summary, kg_rows, loaded_json, state


def _preview_raw_item(
    state: dict[str, Any],
    raw_item_selection: str | int | float | None,
) -> dict[str, Any]:
    raw_items = state.get("raw_items") or []
    index = _selected_item_index(raw_item_selection)
    if index < 0 or index >= len(raw_items):
        return {"message": "No KG-ready intelligence item selected."}
    item = RawIntelItem.model_validate(raw_items[index])
    text = (item.raw_text or item.summary or "").strip()
    return {
        "index": index,
        "item_id": item.item_id,
        "source": item.source_name,
        "relevance_score": item.relevance_score,
        "text_chars": len(text),
        "title": item.title,
        "source_uri": item.source_uri,
        "kg_input_preview": text[:800],
    }


def _make_kg_config(
    enabled: bool,
    model: str,
    temperature: float,
    base_url: str,
    embedding_model: str,
    similarity_threshold: float,
    ie_shot: int,
    et_shot: int,
    lp_shot: int,
) -> KgGenerationConfig:
    kg_config = KgGenerationConfig(
        enabled=enabled,
        model=model,
        embedding_model=embedding_model,
        similarity_threshold=similarity_threshold,
        base_url=base_url or None,
    )
    kg_config.ie.temperature = temperature
    kg_config.et.temperature = temperature
    kg_config.lp.temperature = temperature
    kg_config.ie.shot = int(ie_shot)
    kg_config.et.shot = int(et_shot)
    kg_config.lp.shot = int(lp_shot)
    return kg_config


def _item_rows(items: list[RawIntelItem], kg_config: KgGenerationConfig) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for index, item in enumerate(items):
        decision = assess_kg_eligibility(
            item,
            kg_config,
            target_topics=list(TARGET_SECURITY_TOPICS),
        )
        text_chars = len((item.raw_text or item.summary or "").strip())
        rows.append(
            [
                index,
                item.item_id,
                item.source_name,
                item.relevance_score,
                decision.eligible,
                decision.excluded_reason or "",
                text_chars,
                item.title,
                item.source_uri,
            ]
        )
    return rows


def _raw_item_choices(
    items: list[RawIntelItem],
    kg_config: KgGenerationConfig,
) -> list[tuple[str, str]]:
    choices: list[tuple[str, str]] = []
    for index, item in enumerate(items):
        decision = assess_kg_eligibility(
            item,
            kg_config,
            target_topics=list(TARGET_SECURITY_TOPICS),
        )
        if not decision.eligible:
            continue
        text_chars = len((item.raw_text or item.summary or "").strip())
        title = (item.title or item.summary or item.item_id).replace("\n", " ").strip()
        if len(title) > 72:
            title = title[:69].rstrip() + "..."
        label = (
            f"#{index} | {item.source_name} | score={item.relevance_score:.2f} "
            f"| text={text_chars} | {title}"
        )
        choices.append((label, str(index)))
    return choices


def _selected_item_index(selection: str | int | float | None) -> int:
    if selection is None:
        return -1
    if isinstance(selection, (int, float)):
        return int(selection)
    first_part = str(selection).split("|", 1)[0].strip()
    try:
        return int(first_part)
    except ValueError:
        return -1


def _kg_rows(records) -> list[list[Any]]:
    return [
        [
            record.item_id,
            record.source_name,
            record.status,
            record.error or record.eligibility.excluded_reason or "",
            record.triplet_count,
            record.entity_count,
            record.ctinexus_json_path,
            record.graph_html_path,
        ]
        for record in records
    ]


def _write_updated_run_payload(
    run_store: JsonIntelRunStore,
    payload: dict[str, Any],
    blackboard: IntelRunBlackboard,
) -> None:
    payload["blackboard"] = blackboard.model_dump(mode="json")
    kg_counts = {
        "total": len(blackboard.item_knowledge_graphs),
        "succeeded": sum(1 for record in blackboard.item_knowledge_graphs if record.status == "succeeded"),
        "failed": sum(1 for record in blackboard.item_knowledge_graphs if record.status == "failed"),
        "skipped": sum(1 for record in blackboard.item_knowledge_graphs if record.status == "skipped"),
    }
    payload.setdefault("summary", {})["knowledge_graphs"] = kg_counts
    payload["summary"]["knowledge_graph_manifest_path"] = str(
        run_store.root_dir / f"{run_id_safe(blackboard.run_id)}_kg" / "manifest.json"
    )
    run_store.run_path(blackboard.run_id).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def run_id_safe(run_id: str) -> str:
    return "".join(char if char.isalnum() or char in "_.-" else "_" for char in run_id).strip("._")


def main() -> None:
    app = build_app()
    app.launch(
        server_name=os.getenv("GRADIO_SERVER_NAME", "0.0.0.0"),
        server_port=int(os.getenv("GRADIO_SERVER_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
