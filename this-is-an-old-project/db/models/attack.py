from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID


@dataclass(slots=True)
class AttackEntry:
    attack_id: UUID
    attack_code: str
    canonical_name: str
    attack_family: str
    severity_level: str
    entry_status: str
    summary: str
    description: str
    exploit_preconditions: str | None
    impact_scope: str | None
    confidence_score: Decimal
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    primary_stix_bundle_id: UUID | None
    primary_stix_object_id: UUID | None
    stix_graph_status: str | None
    stix_type: str | None
    stix_payload: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class AttackCvssAssessment:
    score_id: int
    attack_id: UUID
    source_raw_id: UUID | None
    cvss_version: str
    vector_string: str | None
    base_score: Decimal | None
    temporal_score: Decimal | None
    environmental_score: Decimal | None
    severity_label: str
    exploitability_subscore: Decimal | None
    impact_subscore: Decimal | None
    score_origin: str
    score_provider: str | None
    confidence_score: Decimal
    is_primary: bool
    published_at: datetime | None
    calculated_at: datetime | None
    created_at: datetime


@dataclass(slots=True)
class AttackEvidence:
    attack_id: UUID
    raw_id: UUID
    evidence_role: str
    extractor_name: str
    extracted_at: datetime
    evidence_snippet: str | None


@dataclass(slots=True)
class AttackTaxonomyMap:
    map_id: int
    attack_id: UUID
    taxonomy_type: str
    taxonomy_code: str
    taxonomy_name: str
    is_primary: bool
    confidence_score: Decimal


@dataclass(slots=True)
class AttackSeedAsset:
    asset_id: UUID
    attack_id: UUID
    asset_type: str
    asset_name: str
    artifact_uri: str
    checksum: str
    language: str | None
    modality: str | None
    qa_status: str
    is_template: bool
    metadata_json: dict[str, Any] | None
    created_at: datetime


@dataclass(slots=True)
class RemediationAdvice:
    advice_id: UUID
    attack_id: UUID
    advice_type: str
    title: str
    content: str
    priority_level: int
    source_uri: str | None
    created_at: datetime

