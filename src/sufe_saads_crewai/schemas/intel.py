from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from .common import (
    EvidenceRef,
    FlexibleModel,
    Priority,
    PublicationStatus,
    ReviewStatus,
    Score,
    ScoreBreakdown,
)

DedupAction = Literal["new", "merge", "update", "review", "discard"]


class TaxonomyItem(FlexibleModel):
    taxonomy_system: str
    taxonomy_code: str
    taxonomy_name: str | None = None
    confidence: Score = 0.0
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class AffectedComponent(FlexibleModel):
    name: str
    component_type: str
    vendor: str | None = None
    version_range: str | None = None
    confidence: Score = 0.0
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class StandardizedIntelRecord(FlexibleModel):
    item_id: str
    canonical_name: str
    attack_family: str | None = None
    taxonomy_items: list[TaxonomyItem] = Field(default_factory=list)
    affected_components: list[AffectedComponent] = Field(default_factory=list)
    cve_refs: list[str] = Field(default_factory=list)
    evidence_spans: list[EvidenceRef] = Field(default_factory=list)
    source_refs: list[EvidenceRef] = Field(default_factory=list)
    confidence_by_field: dict[str, Score] = Field(default_factory=dict)
    conflict_flags: list[str] = Field(default_factory=list)
    extraction_rationale: str = ""
    severity_hint: str | None = None


class StandardizedIntelBatch(FlexibleModel):
    records: list[StandardizedIntelRecord] = Field(default_factory=list)


class TaxonomyEvidenceItem(FlexibleModel):
    item_id: str
    taxonomy_items: list[TaxonomyItem] = Field(default_factory=list)
    supporting_evidence: list[EvidenceRef] = Field(default_factory=list)
    confidence: Score = 0.0
    alternative_taxonomies: list[TaxonomyItem] = Field(default_factory=list)
    classification_rationale: str = ""
    unresolved_questions: list[str] = Field(default_factory=list)


class TaxonomyEvidenceBatch(FlexibleModel):
    items: list[TaxonomyEvidenceItem] = Field(default_factory=list)


class DedupDecision(FlexibleModel):
    item_id: str
    action: DedupAction
    target_record_id: str | None = None
    confidence: Score = 0.0
    rationale: str = ""
    conflict_reasons: list[str] = Field(default_factory=list)
    review_required: bool = False


class DedupDecisionBatch(FlexibleModel):
    decisions: list[DedupDecision] = Field(default_factory=list)


class BomResolution(FlexibleModel):
    item_id: str
    mentioned_component: str
    normalized_component: str | None = None
    component_type: str | None = None
    match_confidence: Score = 0.0
    match_rationale: str = ""
    review_status: ReviewStatus = "review"
    alternatives: list[str] = Field(default_factory=list)


class BomResolutionBatch(FlexibleModel):
    resolutions: list[BomResolution] = Field(default_factory=list)


class StixGraphBundle(FlexibleModel):
    objects: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    external_references: list[EvidenceRef] = Field(default_factory=list)
    confidence: Score = 0.0
    validation_warnings: list[str] = Field(default_factory=list)
    publication_recommendation: PublicationStatus = "draft"


class ScoredIntelRecord(FlexibleModel):
    item_id: str
    confidence_score: Score = 0.0
    novelty_score: Score = 0.0
    impact_score: Score = 0.0
    priority: Priority = "medium"
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    recommended_handling: str = ""


class ScoredIntelBatch(FlexibleModel):
    records: list[ScoredIntelRecord] = Field(default_factory=list)
