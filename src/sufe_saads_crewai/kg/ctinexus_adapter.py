from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Callable, Iterator

from sufe_saads_crewai.kg.eligibility import assess_kg_eligibility
from sufe_saads_crewai.kg.prompting import build_ctinexus_input_text
from sufe_saads_crewai.schemas import (
    ItemKnowledgeGraphRecord,
    KgGenerationConfig,
    KnowledgeGraphManifest,
    RawIntelItem,
)


ProcessCtiReport = Callable[..., dict[str, Any]]


class CtinexusKgGenerator:
    """Generate per-item knowledge graphs through CTINexus when available."""

    def __init__(
        self,
        config: KgGenerationConfig | None = None,
        process_func: ProcessCtiReport | None = None,
    ) -> None:
        self.config = config or KgGenerationConfig()
        self._process_func = process_func

    def generate_for_items(
        self,
        run_id: str,
        items: list[RawIntelItem],
        target_topics: list[str] | None = None,
    ) -> list[ItemKnowledgeGraphRecord]:
        records = [
            self.generate_for_item(run_id, item, target_topics=target_topics)
            for item in items
        ]
        self.write_manifest(run_id, records)
        return records

    def generate_for_item(
        self,
        run_id: str,
        item: RawIntelItem,
        target_topics: list[str] | None = None,
    ) -> ItemKnowledgeGraphRecord:
        decision = assess_kg_eligibility(item, self.config, target_topics=target_topics)
        record = self._base_record(run_id, item, decision)
        if not decision.eligible:
            record.status = "skipped"
            return record

        input_text = build_ctinexus_input_text(
            item,
            matched_topics=decision.matched_topics,
            max_chars=self.config.max_input_chars,
        )
        record.input_hash = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
        output_path = self._item_json_path(run_id, item.item_id)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            process_func = self._process_func or self._load_ctinexus()
            with self._ctinexus_env(), self._ctinexus_litellm_provider_patch():
                result = process_func(
                    text=input_text,
                    provider=self.config.provider,
                    model=self._ctinexus_model_name(self.config.model),
                    embedding_model=self.config.embedding_model,
                    ie_model=self._stage_model(self.config.ie.model),
                    et_model=self._stage_model(self.config.et.model),
                    ea_model=self._stage_model(self.config.ea.model),
                    lp_model=self._stage_model(self.config.lp.model),
                    similarity_threshold=self.config.similarity_threshold,
                    output=str(output_path),
                )
            record.status = "succeeded"
            record.ctinexus_json_path = str(output_path)
            self._write_json_if_needed(output_path, result)
            self._populate_counts(record, result)
            self._copy_graph_html(record, result, run_id, item.item_id)
            record.metadata.update(
                {
                    "ctinexus_prompt_parameters": self._prompt_parameters(),
                    "ctinexus_output_keys": sorted(result.keys()) if isinstance(result, dict) else [],
                }
            )
        except Exception as exc:
            record.status = "failed"
            record.error = str(exc)
            record.metadata["error_type"] = type(exc).__name__
            if self.config.fail_on_error:
                raise
        return record

    def write_manifest(
        self,
        run_id: str,
        records: list[ItemKnowledgeGraphRecord],
    ) -> Path:
        output_dir = self._run_output_dir(run_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "total": len(records),
            "succeeded": sum(1 for record in records if record.status == "succeeded"),
            "failed": sum(1 for record in records if record.status == "failed"),
            "skipped": sum(1 for record in records if record.status == "skipped"),
            "triplets": sum(record.triplet_count for record in records),
            "entities": sum(record.entity_count for record in records),
            "predicted_links": sum(record.predicted_link_count for record in records),
        }
        manifest = KnowledgeGraphManifest(run_id=run_id, records=records, summary=summary)
        path = output_dir / "manifest.json"
        path.write_text(
            json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path

    def _base_record(self, run_id: str, item: RawIntelItem, decision) -> ItemKnowledgeGraphRecord:
        return ItemKnowledgeGraphRecord(
            run_id=run_id,
            item_id=item.item_id,
            source_name=item.source_name,
            source_uri=item.source_uri,
            eligibility=decision,
            matched_topics=decision.matched_topics,
            relevance_score=item.relevance_score,
            template_version=self.config.template_version,
            provider=self.config.provider,
            model=self.config.model,
            embedding_model=self.config.embedding_model,
            similarity_threshold=self.config.similarity_threshold,
            generated_at=datetime.now(timezone.utc),
            metadata={
                "retriever_type": self.config.retriever_type,
                "demo_permutation": self.config.demo_permutation,
            },
        )

    def _load_ctinexus(self) -> ProcessCtiReport:
        try:
            from ctinexus import process_cti_report
        except Exception as exc:
            raise RuntimeError(
                "ctinexus is not installed or cannot be imported. "
                "Install dependencies with `uv sync` before enabling KG generation."
            ) from exc
        return process_cti_report

    @contextmanager
    def _ctinexus_env(self) -> Iterator[None]:
        updates = {
            "CUSTOM_BASE_URL": self.config.base_url
            or os.getenv(self.config.base_url_env)
            or os.getenv("OPENAI_BASE_URL")
            or os.getenv("OPENAI_API_BASE")
            or os.getenv("GLM_BASE_URL"),
            "CUSTOM_API_KEY": os.getenv(self.config.api_key_env)
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("GLM_API_KEY"),
        }
        old_values = {key: os.environ.get(key) for key in updates}
        try:
            for key, value in updates.items():
                if value:
                    os.environ[key] = value
            yield
        finally:
            for key, old_value in old_values.items():
                if old_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old_value

    @contextmanager
    def _ctinexus_litellm_provider_patch(self) -> Iterator[None]:
        if self.config.provider.lower() != "openai":
            yield
            return

        try:
            from ctinexus import graph_constructor, llm_processor
        except Exception:
            yield
            return

        original_completion = llm_processor.call_litellm_completion
        original_embedding = graph_constructor.litellm.embedding

        def patched_completion(model: str, *args: Any, **kwargs: Any):
            return original_completion(_litellm_openai_model_name(model), *args, **kwargs)

        def patched_embedding(*args: Any, **kwargs: Any):
            if "model" in kwargs:
                kwargs = {**kwargs, "model": _litellm_openai_model_name(kwargs["model"])}
            return original_embedding(*args, **kwargs)

        llm_processor.call_litellm_completion = patched_completion
        graph_constructor.litellm.embedding = patched_embedding
        try:
            yield
        finally:
            llm_processor.call_litellm_completion = original_completion
            graph_constructor.litellm.embedding = original_embedding

    def _prompt_parameters(self) -> dict[str, Any]:
        return {
            "ie_shot": self.config.ie.shot,
            "ie_temperature": self.config.ie.temperature,
            "et_shot": self.config.et.shot,
            "et_temperature": self.config.et.temperature,
            "lp_shot": self.config.lp.shot,
            "lp_temperature": self.config.lp.temperature,
            "similarity_threshold": self.config.similarity_threshold,
            "embedding_model": self.config.embedding_model,
            "demo_permutation": self.config.demo_permutation,
        }

    def _stage_model(self, value: str | None) -> str | None:
        return self._ctinexus_model_name(value) if value else None

    def _ctinexus_model_name(self, model: str) -> str:
        if self.config.provider.lower() == "openai" and model.lower().startswith("openai/"):
            return model.split("/", 1)[1]
        return model

    def _populate_counts(self, record: ItemKnowledgeGraphRecord, result: dict[str, Any]) -> None:
        triplets = _extract_list(result, ["IE", "triplets"]) or _extract_list(result, ["triplets"])
        aligned_triplets = _extract_list(result, ["EA", "aligned_triplets"])
        predicted_links = _extract_list(result, ["LP", "predicted_links"]) or _extract_list(
            result, ["predicted_links"]
        )
        record.triplet_count = len(triplets)
        record.predicted_link_count = len(predicted_links)
        record.hallucination_count = _count_hallucinations(triplets + aligned_triplets)
        record.invalid_triplet_count = _count_invalid_triplets(triplets)
        record.entity_count = len(_unique_entities(aligned_triplets or triplets))

    def _copy_graph_html(
        self,
        record: ItemKnowledgeGraphRecord,
        result: dict[str, Any],
        run_id: str,
        item_id: str,
    ) -> None:
        candidates = [
            result.get("entity_relation_graph") if isinstance(result, dict) else None,
            result.get("graph_html_path") if isinstance(result, dict) else None,
        ]
        for candidate in candidates:
            if not candidate:
                continue
            source_path = Path(str(candidate))
            if not source_path.exists():
                continue
            graph_path = self._run_output_dir(run_id) / f"{_safe_name(item_id)}.html"
            shutil.copy2(source_path, graph_path)
            record.graph_html_path = str(graph_path)
            return

    def _write_json_if_needed(self, output_path: Path, result: dict[str, Any]) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            return
        output_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    def _item_json_path(self, run_id: str, item_id: str) -> Path:
        return self._run_output_dir(run_id) / f"{_safe_name(item_id)}.json"

    def _run_output_dir(self, run_id: str) -> Path:
        return Path(self.config.output_root) / f"{_safe_name(run_id)}_kg"


def _extract_list(payload: dict[str, Any], path: list[str]) -> list[Any]:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    return current if isinstance(current, list) else []


def _unique_entities(triplets: list[Any]) -> set[str]:
    entities: set[str] = set()
    for triplet in triplets:
        if not isinstance(triplet, dict):
            continue
        for key in ("subject", "object", "source", "target"):
            value = triplet.get(key)
            if isinstance(value, dict):
                label = value.get("entity_id") or value.get("mention_text") or value.get("name")
            else:
                label = value
            if label:
                entities.add(str(label).lower())
    return entities


def _count_hallucinations(triplets: list[Any]) -> int:
    count = 0
    for triplet in triplets:
        text = json.dumps(triplet, ensure_ascii=False).lower() if isinstance(triplet, dict) else str(triplet).lower()
        if "hallucination" in text or "not in report" in text:
            count += 1
    return count


def _count_invalid_triplets(triplets: list[Any]) -> int:
    invalid = 0
    for triplet in triplets:
        if not isinstance(triplet, dict):
            invalid += 1
            continue
        if not any(key in triplet for key in ("subject", "source")):
            invalid += 1
        elif not any(key in triplet for key in ("object", "target")):
            invalid += 1
        elif "relation" not in triplet and "predicate" not in triplet:
            invalid += 1
    return invalid


def _safe_name(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._")
    return safe or "kg_item"


def _litellm_openai_model_name(model: str | None) -> str | None:
    if not model or "/" in model:
        return model
    return f"openai/{model}"
