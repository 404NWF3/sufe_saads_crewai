from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID


@dataclass(slots=True)
class StixBundle:
    bundle_id: UUID
    attack_id: UUID | None
    bundle_stix_id: str
    spec_version: str
    bundle_role: str
    graph_confidence: Decimal | None
    review_status: str
    primary_object_stix_id: str | None
    bundle_payload: dict[str, Any]
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class StixObject:
    object_pk: UUID
    bundle_id: UUID
    attack_id: UUID | None
    stix_id: str
    object_type: str
    spec_version: str
    name: str | None
    description: str | None
    created_ts: datetime | None
    modified_ts: datetime | None
    revoked: bool
    confidence: Decimal | None
    lang: str | None
    is_primary: bool
    raw_payload: dict[str, Any]
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class StixRelationshipProjection:
    relationship_pk: UUID
    object_pk: UUID
    bundle_id: UUID
    relationship_type: str
    source_ref: str
    target_ref: str
    created_at: datetime


@dataclass(slots=True)
class StixExternalReference:
    ext_ref_id: int
    object_pk: UUID
    source_name: str
    external_id: str | None
    url: str | None
    description: str | None


@dataclass(slots=True)
class StixKillChainPhase:
    phase_id: int
    object_pk: UUID
    kill_chain_name: str
    phase_name: str


@dataclass(slots=True)
class AttackStixBinding:
    binding_id: UUID
    attack_id: UUID
    active_bundle_id: UUID
    primary_object_pk: UUID
    publication_status: str
    published_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class StixReviewQueueItem:
    review_id: int
    attack_id: UUID | None
    bundle_id: UUID | None
    reason_code: str
    queue_status: str
    review_payload: dict[str, Any] | None
    created_at: datetime
    resolved_at: datetime | None


@dataclass(slots=True)
class StixExtractionAudit:
    audit_id: int
    attack_id: UUID | None
    bundle_id: UUID | None
    extractor_model: str
    reviewer_model: str | None
    prompt_version: str
    review_decision: str
    graph_confidence: Decimal | None
    reasoning_summary: str
    reasoning_trace: list[str] | None
    finding_count: int
    created_at: datetime
