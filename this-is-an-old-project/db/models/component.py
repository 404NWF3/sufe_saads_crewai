from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID


@dataclass(slots=True)
class AiComponent:
    component_id: UUID
    component_code: str
    component_name: str
    component_layer: str | None
    vendor_name: str | None
    component_type: str
    modality: str | None
    purl: str | None
    homepage_uri: str | None
    lifecycle_status: str
    created_at: datetime


@dataclass(slots=True)
class AiComponentAlias:
    alias_id: int
    component_id: UUID
    alias_name: str
    alias_type: str
    normalized_alias: str
    is_preferred: bool


@dataclass(slots=True)
class AttackComponentImpact:
    impact_id: UUID
    attack_id: UUID
    component_id: UUID
    mention_id: UUID | None
    source_raw_id: UUID | None
    version_constraint_raw: str | None
    normalized_constraint: str | None
    match_mode: str
    impact_scope: str
    review_status: str
    resolver_strategy: str | None
    confidence_score: Decimal
    evidence_uri: str | None
    evidence_snippet: str | None
    created_at: datetime


@dataclass(slots=True)
class AttackComponentMention:
    mention_id: UUID
    attack_id: UUID | None
    raw_id: UUID | None
    mentioned_name: str
    mentioned_vendor: str | None
    mentioned_version: str | None
    normalized_alias: str
    normalized_vendor: str | None
    component_layer: str | None
    impact_scope: str | None
    dependency_role: str | None
    evidence_snippet: str | None
    extractor_name: str
    extraction_confidence: Decimal
    created_at: datetime
