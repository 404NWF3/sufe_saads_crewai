from __future__ import annotations

from datetime import datetime, timezone

from ..dtos import CollectionTaskCreateDTO, RawIntelRecordCreateDTO
from ..exceptions import NotFoundError
from ..models import CollectionTask, RawIntelRecord
from ..unit_of_work import UnitOfWork


class IngestionService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def create_collection_task(
        self,
        *,
        source_name: str,
        task_mode: str,
        trigger_type: str,
        created_by: str = "system",
        scheduled_at: datetime | None = None,
        trace_id: str | None = None,
    ) -> CollectionTask:
        payload = CollectionTaskCreateDTO(
            source_name=source_name,
            task_mode=task_mode,
            trigger_type=trigger_type,
            created_by=created_by,
            scheduled_at=scheduled_at,
            trace_id=trace_id,
        )
        source = self.uow.sources.get_source_by_name(payload.source_name)
        if source is None:
            raise NotFoundError(f"intel_source not found: source_name={payload.source_name}")

        return self.uow.sources.create_collection_task(
            source_id=source.source_id,
            task_mode=payload.task_mode,
            trigger_type=payload.trigger_type,
            task_status="queued",
            scheduled_at=payload.scheduled_at,
            created_by=payload.created_by,
            retry_count=0,
            trace_id=payload.trace_id,
        )

    def mark_task_running(self, task_id: str) -> CollectionTask:
        task = self.uow.sources.update_collection_task_status(
            task_id=task_id,
            task_status="running",
            started_at=datetime.now(tz=timezone.utc),
        )
        if task is None:
            raise NotFoundError(f"collection_task not found: task_id={task_id}")
        return task

    def finish_task(self, task_id: str, *, success: bool, retry_count: int | None = None) -> CollectionTask:
        task = self.uow.sources.update_collection_task_status(
            task_id=task_id,
            task_status="succeeded" if success else "failed",
            finished_at=datetime.now(tz=timezone.utc),
            retry_count=retry_count,
        )
        if task is None:
            raise NotFoundError(f"collection_task not found: task_id={task_id}")
        return task

    def store_raw_intel_record(
        self,
        *,
        task_id: str,
        source_uri: str,
        title: str | None,
        content_hash: str,
        raw_format: str,
        payload_uri: str,
        language_code: str | None = None,
        relevance_score: float | None = None,
        parser_status: str = "pending",
        fetched_at: datetime,
        is_deleted: bool = False,
    ) -> RawIntelRecord:
        payload = RawIntelRecordCreateDTO(
            task_id=task_id,
            source_uri=source_uri,
            title=title,
            content_hash=content_hash,
            raw_format=raw_format,
            payload_uri=payload_uri,
            language_code=language_code,
            relevance_score=relevance_score,
            parser_status=parser_status,
            fetched_at=fetched_at,
            is_deleted=is_deleted,
        )
        task = self.uow.sources.get_collection_task(payload.task_id)
        if task is None:
            raise NotFoundError(f"collection_task not found: task_id={payload.task_id}")

        return self.uow.sources.insert_or_get_raw_record(
            source_id=task.source_id,
            task_id=payload.task_id,
            source_uri=payload.source_uri,
            title=payload.title,
            content_hash=payload.content_hash,
            raw_format=payload.raw_format,
            payload_uri=payload.payload_uri,
            language_code=payload.language_code,
            relevance_score=payload.relevance_score,
            parser_status=payload.parser_status,
            fetched_at=payload.fetched_at,
            is_deleted=payload.is_deleted,
        )

    def mark_raw_parser_status(self, raw_id: str, status: str) -> RawIntelRecord:
        raw = self.uow.sources.mark_raw_record_parser_status(raw_id=raw_id, status=status)
        if raw is None:
            raise NotFoundError(f"raw_intel_record not found: raw_id={raw_id}")
        return raw

    def list_pending_raw_records(self, *, limit: int = 100) -> list[RawIntelRecord]:
        return self.uow.sources.list_pending_raw_records(limit=limit)

