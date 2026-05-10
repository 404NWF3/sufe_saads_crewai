from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID


@dataclass(slots=True)
class PrimaryCvssView:
    score_id: int
    attack_id: UUID
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
    published_at: datetime | None
    calculated_at: datetime | None
    created_at: datetime


@dataclass(slots=True)
class Wp12AttackFeedRow:
    attack_id: UUID
    attack_code: str
    canonical_name: str
    attack_family: str
    severity_level: str
    entry_status: str
    summary: str
    last_seen_at: datetime | None
    primary_cvss_version: str | None
    primary_cvss_base_score: Decimal | None
    primary_cvss_vector: str | None
    primary_cvss_severity_label: str | None
    taxonomy_type: str | None
    taxonomy_code: str | None
    taxonomy_name: str | None
    component_id: UUID | None
    component_name: str | None
    version_constraint_raw: str | None
    normalized_constraint: str | None
    component_impact_scope: str | None
    asset_id: UUID | None
    asset_type: str | None
    asset_name: str | None
    artifact_uri: str | None
    qa_status: str | None


@dataclass(slots=True)
class Wp12AttackExecutionFeedRow:
    attack_id: UUID
    attack_code: str
    canonical_name: str
    attack_family: str
    severity_level: str
    summary: str
    component_id: UUID | None
    component_name: str | None
    normalized_constraint: str | None
    component_impact_scope: str | None
    primary_stix_bundle_id: UUID | None
    primary_stix_object_id: UUID | None
    stix_graph_status: str | None
    primary_attack_pattern_stix_id: str | None
    stix_bundle_payload: dict | None


@dataclass(slots=True)
class ComponentRiskOverviewRow:
    component_id: UUID
    component_code: str
    component_name: str
    vendor_name: str | None
    component_type: str
    attack_count: int
    high_cvss_attack_count: int
    critical_cvss_attack_count: int
    latest_seen_at: datetime | None
    max_primary_cvss_score: Decimal | None
    avg_primary_cvss_score: Decimal | None


@dataclass(slots=True)
class UnresolvedBomQueueRow:
    queue_id: int
    attack_id: UUID | None
    attack_code: str | None
    canonical_name: str | None
    raw_id: UUID | None
    source_uri: str | None
    mentioned_name: str
    mentioned_vendor: str | None
    mentioned_version: str | None
    reason_code: str
    queue_status: str
    created_at: datetime
    resolved_at: datetime | None


@dataclass(slots=True)
class SourceQualityDashboardRow:
    source_id: UUID
    source_name: str
    source_type: str
    raw_record_count: int
    parsed_record_count: int
    effective_attack_count: int
    dedup_merge_count: int
    avg_relevance_score: Decimal | None
    latest_fetched_at: datetime | None
    failed_task_count: int


@dataclass(slots=True)
class OwaspCoverageRow:
    taxonomy_code: str
    taxonomy_name: str
    attack_count: int
    impacted_component_count: int
    high_cvss_attack_count: int
    critical_cvss_attack_count: int
    max_primary_cvss_score: Decimal | None
    avg_primary_cvss_score: Decimal | None
    latest_seen_at: datetime | None

