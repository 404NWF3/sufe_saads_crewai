from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..schemas.intel import RawCollectedItemDTO
from ..schemas.source import RegisteredSourceDTO, SourceFetchBatchDTO
from .crew_collaboration import CrewCollaborationService
from ..services import SourceRegistryService, SourceScheduler


class SourceCollectionCrew:
    """Crew-compatible collection facade backed by a scheduler and adapters."""

    def __init__(
        self,
        *,
        registry_service: SourceRegistryService | None = None,
        scheduler: SourceScheduler | None = None,
        collaboration_service: CrewCollaborationService | None = None,
    ) -> None:
        self.registry_service = registry_service or SourceRegistryService()
        self.scheduler = scheduler or SourceScheduler()
        self.collaboration_service = collaboration_service or CrewCollaborationService()

    def collect(
        self,
        source_plans: list[dict[str, Any]],
        *,
        trace_id: str,
        run_mode: str,
        reflection_round: int,
        runtime_mode: str,
        retry_attempts: int,
        request_timeout_seconds: float,
        artifact_store_dir: str | None,
        source_registry_overrides: list[dict[str, Any]] | None = None,
        source_cursors: dict[str, dict[str, Any]] | None = None,
        force_no_results: bool = False,
        max_parallel_sources: int = 4,
        prefer_db_source_registry: bool = False,
        collector_role_filter: str | None = None,
        collection_coordination: dict[str, Any] | None = None,
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        llm_runtime_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if force_no_results:
            return {
                "raw_items": [],
                "source_execution_stats": [],
                "source_cursors": source_cursors or {},
                "fetch_audits": [],
                "collection_coordination": {
                    "engine": "fallback",
                    "crewai_available": self.collaboration_service.crewai_available,
                    "collector_agents": [],
                    "assignments": [],
                    "summary": "Collection skipped because force_no_results was enabled.",
                },
            }
        coordination = collection_coordination or self.collaboration_service.coordinate(
            source_plans,
            run_mode=run_mode,
            trace_id=trace_id,
            planning_audits=(collection_coordination or {}).get("planning_audits"),
            reflection_audits=(collection_coordination or {}).get("reflection_audits"),
            llm_model=llm_model,
            llm_temperature=llm_temperature,
            llm_runtime_config=llm_runtime_config,
        )
        if collector_role_filter:
            source_plans = [
                plan
                for plan in source_plans
                if _assignment_for(coordination, plan.get("source_name")).get(
                    "collector_role"
                )
                == collector_role_filter
            ]
        registry, registry_alignment = self.registry_service.load_aligned_registry(
            prefer_db=prefer_db_source_registry,
            trace_id=trace_id,
            overrides=source_registry_overrides,
        )
        scheduled = self.scheduler.run(
            source_plans,
            registry=registry,
            trace_id=trace_id,
            run_mode=run_mode,
            reflection_round=reflection_round,
            runtime_mode=runtime_mode,
            retry_attempts=retry_attempts,
            request_timeout_seconds=request_timeout_seconds,
            max_parallel_sources=max_parallel_sources,
            source_cursors=source_cursors,
            collector_role_map={
                assignment["source_name"]: assignment.get("collector_role")
                for assignment in coordination.get("assignments", [])
            },
            assignment_map={
                assignment["source_name"]: assignment
                for assignment in coordination.get("assignments", [])
            },
        )
        batches = [
            SourceFetchBatchDTO.model_validate(item)
            for item in scheduled["fetch_batches"]
        ]
        raw_items = self._materialize_raw_items(
            batches,
            trace_id=trace_id,
            artifact_store_dir=artifact_store_dir,
            collection_coordination=coordination,
        )
        return {
            "raw_items": raw_items,
            "source_execution_stats": scheduled["source_execution_stats"],
            "source_cursors": scheduled["source_cursors"],
            "fetch_audits": scheduled["fetch_audits"],
            "collection_coordination": coordination,
            "registry_alignment": registry_alignment,
        }

    def _materialize_raw_items(
        self,
        batches: list[SourceFetchBatchDTO],
        *,
        trace_id: str,
        artifact_store_dir: str | None,
        collection_coordination: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        target_dir = Path(artifact_store_dir or ".runtime/wp11/artifacts") / trace_id
        target_dir.mkdir(parents=True, exist_ok=True)
        raw_items: list[dict[str, Any]] = []
        assignment_map = {
            assignment["source_name"]: assignment
            for assignment in (collection_coordination or {}).get("assignments", [])
        }
        for batch in batches:
            for item in batch.items:
                assignment = assignment_map.get(item.source_name, {})
                content_hash = sha256(item.payload.encode("utf-8")).hexdigest()
                file_name = f"{batch.query_run.query_run_id}_{content_hash[:12]}.{self._suffix(item.raw_format)}"
                file_path = target_dir / file_name
                if item.raw_format == "json":
                    try:
                        parsed = json.loads(item.payload)
                        file_path.write_text(
                            json.dumps(parsed, ensure_ascii=True, indent=2),
                            encoding="utf-8",
                        )
                    except json.JSONDecodeError:
                        file_path.write_text(item.payload, encoding="utf-8")
                else:
                    file_path.write_text(item.payload, encoding="utf-8")

                raw_items.append(
                    RawCollectedItemDTO(
                        query_run_id=batch.query_run.query_run_id,
                        source_name=item.source_name,
                        source_uri=item.source_uri,
                        external_id=item.external_id,
                        title=item.title,
                        summary=item.summary,
                        author=item.author,
                        published_at=item.published_at,
                        fetched_at=batch.fetched_at,
                        raw_format=item.raw_format,
                        artifact_ref=file_path.as_posix(),
                        payload_uri=file_path.as_posix(),
                        language_code=item.language_code,
                        relevance_score=item.relevance_score,
                        parser_status="pending",
                        metadata={
                            **item.metadata,
                            "query_text": batch.query_run.query_text,
                            "query_intent": batch.query_run.query_intent,
                            "reflection_round": batch.query_run.reflection_round,
                            "used_stub": batch.used_stub,
                            "latency_ms": batch.latency_ms,
                            "collector_role": assignment.get("collector_role"),
                            "collector_agent": assignment.get("collector_agent"),
                            "execution_profile": assignment.get("execution_profile"),
                            "source_specific_hint": assignment.get(
                                "source_specific_hint"
                            ),
                            "execution_notes": assignment.get("execution_notes"),
                            "planning_signal": assignment.get("planning_signal"),
                            "reflection_signal": assignment.get("reflection_signal"),
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                        content_hash=content_hash,
                    ).model_dump(mode="python")
                )
        return raw_items

    @staticmethod
    def _suffix(raw_format: str) -> str:
        return {
            "json": "json",
            "text": "txt",
            "html": "html",
            "rss": "xml",
            "pdf": "txt",
        }.get(raw_format, "txt")


def _assignment_for(
    coordination: dict[str, Any], source_name: str | None
) -> dict[str, Any]:
    if source_name is None:
        return {}
    for assignment in coordination.get("assignments", []):
        if assignment.get("source_name") == source_name:
            return assignment
    return {}
