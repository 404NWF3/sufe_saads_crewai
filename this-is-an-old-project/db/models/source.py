from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID


@dataclass(slots=True)
class SourceType:
    type_code: str
    type_name: str
    description: str | None
    enabled: bool
    created_at: datetime


@dataclass(slots=True)
class IntelSource:
    source_id: UUID
    source_name: str
    source_type: str
    base_uri: str
    trust_level: int
    default_qps: Decimal
    enabled: bool
    created_at: datetime


@dataclass(slots=True)
class CollectionTask:
    task_id: UUID
    source_id: UUID
    task_mode: str
    trigger_type: str
    task_status: str
    scheduled_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    created_by: str
    retry_count: int
    trace_id: str | None


@dataclass(slots=True)
class RawIntelRecord:
    raw_id: UUID
    source_id: UUID
    task_id: UUID
    source_uri: str
    title: str | None
    content_hash: str
    raw_format: str
    payload_uri: str
    language_code: str | None
    relevance_score: Decimal | None
    parser_status: str
    fetched_at: datetime
    created_at: datetime
    is_deleted: bool

