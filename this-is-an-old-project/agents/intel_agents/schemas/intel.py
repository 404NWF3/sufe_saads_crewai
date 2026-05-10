from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RawCollectedItemDTO(_StrictModel):
    query_run_id: str
    source_name: str = Field(min_length=1)
    source_uri: str = Field(min_length=1)
    external_id: str | None = None
    title: str | None = None
    summary: str | None = None
    author: str | None = None
    published_at: str | None = None
    fetched_at: str
    raw_format: str = Field(min_length=1)
    artifact_ref: str = Field(min_length=1)
    payload_uri: str = Field(min_length=1)
    language_code: str | None = None
    relevance_score: float | None = Field(default=None, ge=0.0, le=1.0)
    parser_status: str = Field(
        default="pending", pattern="^(pending|parsed|failed|skipped)$"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = Field(min_length=32)


class StandardizedIntelDTO(_StrictModel):
    raw_id: str
    attack_code: str = Field(min_length=1)
    canonical_name: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    severity_level: str = Field(pattern="^(info|low|medium|high|critical)$")
    summary: str | None = None
    description: str = Field(min_length=1)
    exploit_preconditions: str | None = None
    impact_scope: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    primary_stix_bundle_id: str | None = None
    primary_stix_object_id: str | None = None
    stix_graph_status: str | None = None
    stix_type: str | None = None
    stix_payload: dict[str, Any] | None = None
    evidence_snippet: str | None = None
    artifact_ref: str = Field(min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)
    extraction_reason: str = Field(min_length=1)
    source_confidence: float = Field(ge=0.0, le=1.0)
    extraction_confidence: float = Field(ge=0.0, le=1.0)
    taxonomy_items: list[dict[str, Any]] = Field(default_factory=list)
    cvss_hint: dict[str, Any] | None = None
    bom_mentions: list[dict[str, Any]] = Field(default_factory=list)
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    field_confidence: dict[str, float] = Field(default_factory=dict)
    conflict_flags: list[str] = Field(default_factory=list)
    validation_findings: list[str] = Field(default_factory=list)
    normalization_trace: list[str] = Field(default_factory=list)


class BomCandidateDTO(_StrictModel):
    component_id: str | None = None
    component_code: str | None = None
    component_name: str = Field(min_length=1)
    vendor_name: str | None = None
    component_type: str | None = None
    component_modality: str | None = None
    match_mode: str = Field(min_length=1)
    match_score: float = Field(ge=0.0, le=1.0)
    vendor_score: float = Field(ge=-1.0, le=1.0)
    final_score: float = Field(ge=0.0, le=1.0)
    aliases: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class BomResolutionReviewDTO(_StrictModel):
    decision: str = Field(pattern="^(accept|revise|review_queue)$")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    ambiguity_notes: list[str] = Field(default_factory=list)
    review_trace: list[str] = Field(default_factory=list)
    component_suggestion: dict[str, Any] | None = None


class BomResolutionDTO(_StrictModel):
    mentioned_name: str = Field(min_length=1)
    mentioned_vendor: str | None = None
    mentioned_version: str | None = None
    normalized_alias: str = Field(min_length=1)
    normalized_vendor: str | None = None
    normalized_version_constraint: str | None = None
    resolution_status: str = Field(pattern="^(resolved|review_queue|unresolved)$")
    selected_component: dict[str, Any] | None = None
    candidate_components: list[BomCandidateDTO] = Field(default_factory=list)
    match_mode: str | None = None
    match_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list)
    queue_ref: str | None = None
    review: BomResolutionReviewDTO | None = None


class ConfidenceScoreBreakdownDTO(_StrictModel):
    source_trust: float = Field(ge=0.0, le=1.0)
    extraction_confidence: float = Field(ge=0.0, le=1.0)
    dedup_certainty: float = Field(ge=0.0, le=1.0)
    bom_resolution_confidence: float = Field(ge=0.0, le=1.0)
    evidence_density: float = Field(ge=0.0, le=1.0)
    source_diversity_bonus: float = Field(ge=0.0, le=1.0)
    final_confidence: float = Field(ge=0.0, le=1.0)
    novelty_score: float = Field(ge=0.0, le=1.0)


class DedupDecisionDTO(_StrictModel):
    decision: str = Field(pattern="^(new|merge|review)$")
    matched_attack_id: str | None = None
    similarity_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    bom_delta_detected: bool = False
    narrative_delta_detected: bool = False
    content_hash_match: bool = False
    simhash_score: float = Field(default=0.0, ge=0.0, le=1.0)
    minhash_score: float = Field(default=0.0, ge=0.0, le=1.0)
    embedding_score: float = Field(default=0.0, ge=0.0, le=1.0)
    rerank_score: float = Field(default=0.0, ge=0.0, le=1.0)
    taxonomy_overlap_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cve_overlap_score: float = Field(default=0.0, ge=0.0, le=1.0)
    bom_overlap_score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_candidate_ids: list[str] = Field(default_factory=list)
    merge_audit_ref: str | None = None
    adjudicator_summary: dict[str, Any] | None = None


class StableAttackRecordDTO(_StrictModel):
    stable_attack_id: str = Field(min_length=1)
    stable_attack_code: str = Field(min_length=1)
    canonical_name: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    severity_level: str = Field(pattern="^(info|low|medium|high|critical)$")
    summary: str | None = None
    description: str = Field(min_length=1)
    primary_stix_bundle_id: str | None = None
    primary_stix_object_id: str | None = None
    stix_graph_status: str | None = None
    taxonomy_items: list[dict[str, Any]] = Field(default_factory=list)
    cvss_hint: dict[str, Any] | None = None
    bom_mentions: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    source_coverage: list[str] = Field(default_factory=list)
    related_raw_ids: list[str] = Field(default_factory=list)
    member_attack_codes: list[str] = Field(default_factory=list)
    last_decision: str = Field(pattern="^(new|merge|review)$")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)


class MergeAuditRecordDTO(_StrictModel):
    merge_audit_id: str = Field(min_length=1)
    stable_attack_id: str = Field(min_length=1)
    candidate_raw_id: str = Field(min_length=1)
    decision: str = Field(pattern="^(new|merge|review)$")
    incoming_attack_code: str = Field(min_length=1)
    matched_attack_id: str | None = None
    similarity_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    bom_delta_detected: bool = False
    narrative_delta_detected: bool = False
    evidence_refs: list[str] = Field(default_factory=list)
    source_coverage: list[str] = Field(default_factory=list)
    created_at: str


# ---------------------------------------------------------------------------
# Phase 3 LLM-Primary Standardization DTOs
# ---------------------------------------------------------------------------


class LlmExtractionEvidenceDTO(_StrictModel):
    """Evidence span extracted by the LLM to justify a field value."""

    field_name: str = Field(min_length=1)
    evidence_text: str = Field(min_length=1)
    source_offset: str | None = None
    context_window: str | None = None


class LlmFieldConfidenceDTO(_StrictModel):
    """Per-field confidence from the LLM primary extractor."""

    field_name: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)


class LLMStandardizationDecisionDTO(_StrictModel):
    """Full structured output of the LLM primary standardizer."""

    canonical_name: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    severity_level: Literal["info", "low", "medium", "high", "critical"]
    summary: str = Field(min_length=1)
    description: str = Field(min_length=1)
    exploit_preconditions: str | None = None
    impact_scope: str | None = None
    extraction_reason: str = Field(min_length=1)
    taxonomy_items: list[dict[str, Any]] = Field(default_factory=list)
    cvss_hint: dict[str, Any] | None = None
    bom_mentions: list[dict[str, Any]] = Field(default_factory=list)
    evidence_spans: list[LlmExtractionEvidenceDTO] = Field(default_factory=list)
    field_confidences: list[LlmFieldConfidenceDTO] = Field(default_factory=list)
    llm_confidence: float = Field(ge=0.0, le=1.0)


class LlmStandardizationAuditDTO(_StrictModel):
    """Audit record for one LLM-primary standardization invocation."""

    raw_id: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    strategy_requested: str = Field(min_length=1)
    strategy_executed: str = Field(min_length=1)
    llm_model: str = Field(min_length=1)
    llm_profile_id: str | None = None
    llm_profile: str | None = None
    prompt_version: str = Field(min_length=1)
    llm_confidence: float = Field(ge=0.0, le=1.0)
    llm_reason: str = Field(min_length=1)
    fallback_reason: str | None = None
    evidence_span_count: int = Field(ge=0)
    field_confidence_count: int = Field(ge=0)
    validation_finding_count: int = Field(ge=0)
    conflict_flag_count: int = Field(ge=0)
    rule_validation_passed: bool = True
    llm_wait_seconds: float | None = Field(default=None, ge=0.0)
    attempted_profiles: list[str] = Field(default_factory=list)
    attempted_profile_labels: list[str] = Field(default_factory=list)
    invoked_at: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Phase 5 LLM BOM Resolution DTOs
# ---------------------------------------------------------------------------


class LlmBomResolutionDecisionDTO(_StrictModel):
    """Structured output of the LLM BOM resolver for a single mention."""

    mentioned_name: str = Field(min_length=1)
    selected_component_code: str | None = None
    selected_component_name: str | None = None
    selected_component_layer: (
        Literal[
            "vendor_platform",
            "model_family",
            "framework",
            "plugin",
            "runtime",
            "vector_stack",
            "unknown",
        ]
        | None
    ) = None
    selected_vendor: str | None = None
    version_constraint_raw: str | None = None
    normalized_version_constraint: str | None = None
    decision: Literal["accept", "review_queue", "no_match"] = "review_queue"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_quotes: list[str] = Field(default_factory=list)
    reasoning_summary: str = Field(min_length=1)
    candidate_ranking_used: list[str] = Field(default_factory=list)


class LlmBomResolutionAuditDTO(_StrictModel):
    """Audit record for one LLM BOM resolution invocation."""

    raw_id: str = Field(min_length=1)
    mention_index: int = Field(ge=-1)
    mentioned_name: str = Field(min_length=1)
    strategy_requested: str = Field(min_length=1)
    strategy_executed: str = Field(min_length=1)
    llm_model: str = Field(min_length=1)
    llm_profile_id: str | None = None
    llm_profile: str | None = None
    prompt_version: str = Field(min_length=1)
    llm_confidence: float = Field(ge=0.0, le=1.0)
    llm_decision: str = Field(min_length=1)
    llm_reasoning: str = Field(min_length=1)
    fallback_reason: str | None = None
    candidate_count: int = Field(ge=0)
    selected_component_code: str | None = None
    reasoning_trace: list[str] = Field(default_factory=list)
    evidence_quotes: list[str] = Field(default_factory=list)
    llm_wait_seconds: float | None = Field(default=None, ge=0.0)
    attempted_profiles: list[str] = Field(default_factory=list)
    attempted_profile_labels: list[str] = Field(default_factory=list)
    invoked_at: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Phase 4 LLM Merge Judge DTOs
# ---------------------------------------------------------------------------


class LlmMergeJudgmentDTO(_StrictModel):
    """Structured output of the LLM merge judge for a single candidate pair."""

    candidate_attack_code: str = Field(min_length=1)
    existing_stable_id: str | None = None
    verdict: Literal[
        "same_attack",
        "different_attack",
        "same_attack_but_component_delta",
        "uncertain",
    ] = "uncertain"
    recommended_action: Literal["merge", "new", "review"] = "review"
    explanation: str = Field(min_length=1)
    risk_notes: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_quotes: list[str] = Field(default_factory=list)


class LlmDedupJudgmentAuditDTO(_StrictModel):
    """Audit record for one LLM merge judge invocation."""

    candidate_raw_id: str = Field(min_length=1)
    candidate_attack_code: str = Field(min_length=1)
    existing_stable_id: str | None = None
    strategy_requested: str = Field(min_length=1)
    strategy_executed: str = Field(min_length=1)
    llm_model: str = Field(min_length=1)
    llm_profile_id: str | None = None
    llm_profile: str | None = None
    prompt_version: str = Field(min_length=1)
    llm_confidence: float = Field(ge=0.0, le=1.0)
    llm_verdict: str = Field(min_length=1)
    llm_recommended_action: str = Field(min_length=1)
    llm_explanation: str = Field(min_length=1)
    fallback_reason: str | None = None
    rule_prior_decision: str = Field(min_length=1)
    fused_final_decision: str = Field(min_length=1)
    fusion_agreed: bool = True
    overall_similarity_score: float = Field(ge=0.0, le=1.0)
    bom_delta_detected: bool = False
    llm_wait_seconds: float | None = Field(default=None, ge=0.0)
    attempted_profiles: list[str] = Field(default_factory=list)
    attempted_profile_labels: list[str] = Field(default_factory=list)
    invoked_at: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# STIX graph extraction DTOs
# ---------------------------------------------------------------------------


class StixExternalReferenceDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    external_id: str | None = None
    url: str | None = None
    description: str | None = None


class StixKillChainPhaseDTO(_StrictModel):
    kill_chain_name: str = Field(min_length=1)
    phase_name: str = Field(min_length=1)


class StixDraftObjectDTO(_StrictModel):
    local_ref: str = Field(min_length=1)
    object_type: Literal[
        "report",
        "attack-pattern",
        "vulnerability",
        "indicator",
        "tool",
        "malware",
        "course-of-action",
        "identity",
    ]
    name: str = Field(min_length=1)
    description: str | None = None
    labels: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    external_references: list[StixExternalReferenceDTO] = Field(default_factory=list)
    kill_chain_phases: list[StixKillChainPhaseDTO] = Field(default_factory=list)
    pattern: str | None = None
    pattern_type: str | None = None
    is_primary: bool = False
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_quotes: list[str] = Field(default_factory=list)


class StixDraftRelationshipDTO(_StrictModel):
    local_ref: str = Field(min_length=1)
    relationship_type: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    target_ref: str = Field(min_length=1)
    description: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_quotes: list[str] = Field(default_factory=list)


class StixGraphDraftDTO(_StrictModel):
    bundle_name: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    objects: list[StixDraftObjectDTO] = Field(default_factory=list)
    relationships: list[StixDraftRelationshipDTO] = Field(default_factory=list)
    graph_confidence: float = Field(ge=0.0, le=1.0)
    reasoning_summary: str = Field(min_length=1)
    reasoning_trace: list[str] = Field(default_factory=list)


class StixReviewDecisionDTO(_StrictModel):
    decision: Literal["accept", "review_queue"]
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning_summary: str = Field(min_length=1)
    finding_codes: list[str] = Field(default_factory=list)
    flagged_object_refs: list[str] = Field(default_factory=list)
    flagged_relationship_refs: list[str] = Field(default_factory=list)
    review_trace: list[str] = Field(default_factory=list)
