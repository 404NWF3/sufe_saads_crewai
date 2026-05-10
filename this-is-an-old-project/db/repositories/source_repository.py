from __future__ import annotations

from datetime import datetime
from typing import Any

from ..exceptions import NotFoundError
from ..models import CollectionTask, IntelSource, RawIntelRecord
from ..sql import source_queries as q
from .base import BaseRepository


class SourceRepository(BaseRepository):
    def get_source_by_name(self, source_name: str) -> IntelSource | None:
        row = self._fetch_one(q.GET_SOURCE_BY_NAME, {"source_name": source_name})
        return self._row_to_model(IntelSource, row)

    def get_source_by_id(self, source_id: str) -> IntelSource | None:
        row = self._fetch_one(q.GET_SOURCE_BY_ID, {"source_id": source_id})
        return self._row_to_model(IntelSource, row)

    def list_enabled_sources(self, source_type: str | None = None) -> list[IntelSource]:
        query = q.LIST_ENABLED_SOURCES_BASE
        params: dict[str, Any] = {}
        if source_type:
            query += " AND source_type = %(source_type)s"
            params["source_type"] = source_type
        query += " ORDER BY source_name ASC"

        rows = self._fetch_all(query, params or None)
        return [IntelSource(**row) for row in rows]

    def upsert_source(
        self,
        *,
        source_name: str,
        source_type: str,
        base_uri: str,
        trust_level: int,
        default_qps: float,
        enabled: bool = True,
    ) -> IntelSource:
        row = self._fetch_one(
            q.UPSERT_INTEL_SOURCE,
            {
                "source_name": source_name,
                "source_type": source_type,
                "base_uri": base_uri,
                "trust_level": trust_level,
                "default_qps": default_qps,
                "enabled": enabled,
            },
        )
        return self._require_model(
            IntelSource, row, message="Failed to upsert intel_source"
        )

    def create_collection_task(
        self,
        *,
        source_id: str,
        task_mode: str,
        trigger_type: str,
        task_status: str = "queued",
        scheduled_at: datetime | None = None,
        created_by: str = "system",
        retry_count: int = 0,
        trace_id: str | None = None,
    ) -> CollectionTask:
        row = self._fetch_one(
            q.CREATE_COLLECTION_TASK,
            {
                "source_id": source_id,
                "task_mode": task_mode,
                "trigger_type": trigger_type,
                "task_status": task_status,
                "scheduled_at": scheduled_at,
                "created_by": created_by,
                "retry_count": retry_count,
                "trace_id": trace_id,
            },
        )
        return self._require_model(
            CollectionTask, row, message="Failed to create collection_task row"
        )

    def get_collection_task(self, task_id: str) -> CollectionTask | None:
        row = self._fetch_one(q.GET_COLLECTION_TASK_BY_ID, {"task_id": task_id})
        return self._row_to_model(CollectionTask, row)

    def update_collection_task_status(
        self,
        *,
        task_id: str,
        task_status: str,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        retry_count: int | None = None,
    ) -> CollectionTask | None:
        query = q.build_update_collection_task_status_query(
            include_started_at=started_at is not None,
            include_finished_at=finished_at is not None,
            include_retry_count=retry_count is not None,
        )
        params = {
            "task_id": task_id,
            "task_status": task_status,
            "started_at": started_at,
            "finished_at": finished_at,
            "retry_count": retry_count,
        }
        row = self._fetch_one(query, params)
        return self._row_to_model(CollectionTask, row)

    def insert_raw_intel_record(
        self,
        *,
        source_id: str,
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
        row = self._fetch_one(
            q.INSERT_RAW_INTEL_RECORD,
            {
                "source_id": source_id,
                "task_id": task_id,
                "source_uri": source_uri,
                "title": title,
                "content_hash": content_hash,
                "raw_format": raw_format,
                "payload_uri": payload_uri,
                "language_code": language_code,
                "relevance_score": relevance_score,
                "parser_status": parser_status,
                "fetched_at": fetched_at,
                "is_deleted": is_deleted,
            },
        )
        return self._require_model(
            RawIntelRecord, row, message="Failed to insert raw_intel_record"
        )

    def insert_or_get_raw_record(
        self,
        *,
        source_id: str,
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
        row = self._fetch_one(
            q.INSERT_RAW_INTEL_RECORD_IDEMPOTENT,
            {
                "source_id": source_id,
                "task_id": task_id,
                "source_uri": source_uri,
                "title": title,
                "content_hash": content_hash,
                "raw_format": raw_format,
                "payload_uri": payload_uri,
                "language_code": language_code,
                "relevance_score": relevance_score,
                "parser_status": parser_status,
                "fetched_at": fetched_at,
                "is_deleted": is_deleted,
            },
        )
        if row:
            return RawIntelRecord(**row)
        existing = self.get_raw_record_by_hash(
            source_id=source_id, content_hash=content_hash
        )
        if existing is None:
            raise NotFoundError("raw_intel_record missing after idempotent insert")
        return existing

    def get_raw_record_by_hash(
        self, *, source_id: str, content_hash: str
    ) -> RawIntelRecord | None:
        row = self._fetch_one(
            q.GET_RAW_BY_SOURCE_HASH,
            {"source_id": source_id, "content_hash": content_hash},
        )
        return self._row_to_model(RawIntelRecord, row)

    def get_raw_record_by_id(self, raw_id: str) -> RawIntelRecord | None:
        row = self._fetch_one(q.GET_RAW_BY_ID, {"raw_id": raw_id})
        return self._row_to_model(RawIntelRecord, row)

    def mark_raw_record_parser_status(
        self, *, raw_id: str, status: str
    ) -> RawIntelRecord | None:
        row = self._fetch_one(
            q.MARK_RAW_PARSER_STATUS,
            {"raw_id": raw_id, "parser_status": status},
        )
        return self._row_to_model(RawIntelRecord, row)

    def list_pending_raw_records(self, limit: int) -> list[RawIntelRecord]:
        rows = self._fetch_all(q.LIST_PENDING_RAW_RECORDS, {"limit": limit})
        return [RawIntelRecord(**row) for row in rows]
