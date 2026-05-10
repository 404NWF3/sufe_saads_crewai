from __future__ import annotations

from typing import Any

from ..models import (
    AttackStixBinding,
    StixBundle,
    StixExternalReference,
    StixExtractionAudit,
    StixKillChainPhase,
    StixObject,
    StixRelationshipProjection,
    StixReviewQueueItem,
)
from ..sql import stix_queries as q
from .base import BaseRepository


class StixRepository(BaseRepository):
    def create_bundle(
        self,
        *,
        attack_id: str | None,
        bundle_stix_id: str,
        spec_version: str,
        bundle_role: str,
        graph_confidence: float | None,
        review_status: str,
        primary_object_stix_id: str | None,
        bundle_payload: dict[str, Any],
    ) -> StixBundle:
        row = self._fetch_one(
            q.CREATE_STIX_BUNDLE,
            {
                "attack_id": attack_id,
                "bundle_stix_id": bundle_stix_id,
                "spec_version": spec_version,
                "bundle_role": bundle_role,
                "graph_confidence": graph_confidence,
                "review_status": review_status,
                "primary_object_stix_id": primary_object_stix_id,
                "bundle_payload": bundle_payload,
            },
        )
        return self._require_model(StixBundle, row, message="Failed to create stix_bundle")

    def create_object(
        self,
        *,
        bundle_id: str,
        attack_id: str | None,
        stix_id: str,
        object_type: str,
        spec_version: str,
        name: str | None,
        description: str | None,
        created_ts: Any | None,
        modified_ts: Any | None,
        revoked: bool,
        confidence: float | None,
        lang: str | None,
        is_primary: bool,
        raw_payload: dict[str, Any],
    ) -> StixObject:
        row = self._fetch_one(
            q.CREATE_STIX_OBJECT,
            {
                "bundle_id": bundle_id,
                "attack_id": attack_id,
                "stix_id": stix_id,
                "object_type": object_type,
                "spec_version": spec_version,
                "name": name,
                "description": description,
                "created_ts": created_ts,
                "modified_ts": modified_ts,
                "revoked": revoked,
                "confidence": confidence,
                "lang": lang,
                "is_primary": is_primary,
                "raw_payload": raw_payload,
            },
        )
        return self._require_model(StixObject, row, message="Failed to create stix_object")

    def insert_relationship_projection(
        self,
        *,
        object_pk: str,
        bundle_id: str,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
    ) -> StixRelationshipProjection:
        row = self._fetch_one(
            q.INSERT_STIX_RELATIONSHIP_PROJECTION,
            {
                "object_pk": object_pk,
                "bundle_id": bundle_id,
                "relationship_type": relationship_type,
                "source_ref": source_ref,
                "target_ref": target_ref,
            },
        )
        return self._require_model(
            StixRelationshipProjection,
            row,
            message="Failed to insert stix_relationship_projection",
        )

    def insert_external_reference(
        self,
        *,
        object_pk: str,
        source_name: str,
        external_id: str | None,
        url: str | None,
        description: str | None,
    ) -> StixExternalReference:
        row = self._fetch_one(
            q.INSERT_STIX_EXTERNAL_REFERENCE,
            {
                "object_pk": object_pk,
                "source_name": source_name,
                "external_id": external_id,
                "url": url,
                "description": description,
            },
        )
        return self._require_model(
            StixExternalReference,
            row,
            message="Failed to insert stix_external_reference",
        )

    def insert_kill_chain_phase(
        self,
        *,
        object_pk: str,
        kill_chain_name: str,
        phase_name: str,
    ) -> StixKillChainPhase:
        row = self._fetch_one(
            q.INSERT_STIX_KILL_CHAIN_PHASE,
            {
                "object_pk": object_pk,
                "kill_chain_name": kill_chain_name,
                "phase_name": phase_name,
            },
        )
        return self._require_model(
            StixKillChainPhase,
            row,
            message="Failed to insert stix_kill_chain_phase",
        )

    def insert_object_label(self, *, object_pk: str, label: str) -> None:
        self._execute(q.INSERT_STIX_OBJECT_LABEL, {"object_pk": object_pk, "label": label})

    def insert_object_alias(self, *, object_pk: str, alias: str) -> None:
        self._execute(q.INSERT_STIX_OBJECT_ALIAS, {"object_pk": object_pk, "alias": alias})

    def upsert_attack_binding(
        self,
        *,
        attack_id: str,
        active_bundle_id: str,
        primary_object_pk: str,
        publication_status: str,
        published_at: Any | None,
    ) -> AttackStixBinding:
        row = self._fetch_one(
            q.UPSERT_ATTACK_STIX_BINDING,
            {
                "attack_id": attack_id,
                "active_bundle_id": active_bundle_id,
                "primary_object_pk": primary_object_pk,
                "publication_status": publication_status,
                "published_at": published_at,
            },
        )
        return self._require_model(
            AttackStixBinding,
            row,
            message="Failed to upsert attack_stix_binding",
        )

    def enqueue_review(
        self,
        *,
        attack_id: str | None,
        bundle_id: str | None,
        reason_code: str,
        queue_status: str = "open",
        review_payload: dict[str, Any] | None = None,
    ) -> StixReviewQueueItem:
        row = self._fetch_one(
            q.INSERT_STIX_REVIEW_QUEUE,
            {
                "attack_id": attack_id,
                "bundle_id": bundle_id,
                "reason_code": reason_code,
                "queue_status": queue_status,
                "review_payload": review_payload,
            },
        )
        return self._require_model(
            StixReviewQueueItem,
            row,
            message="Failed to insert stix_review_queue",
        )

    def insert_extraction_audit(
        self,
        *,
        attack_id: str | None,
        bundle_id: str | None,
        extractor_model: str,
        reviewer_model: str | None,
        prompt_version: str,
        review_decision: str,
        graph_confidence: float | None,
        reasoning_summary: str,
        reasoning_trace: list[str] | None,
        finding_count: int,
    ) -> StixExtractionAudit:
        row = self._fetch_one(
            q.INSERT_STIX_EXTRACTION_AUDIT,
            {
                "attack_id": attack_id,
                "bundle_id": bundle_id,
                "extractor_model": extractor_model,
                "reviewer_model": reviewer_model,
                "prompt_version": prompt_version,
                "review_decision": review_decision,
                "graph_confidence": graph_confidence,
                "reasoning_summary": reasoning_summary,
                "reasoning_trace": reasoning_trace,
                "finding_count": finding_count,
            },
        )
        return self._require_model(
            StixExtractionAudit,
            row,
            message="Failed to insert stix_extraction_audit",
        )

    def list_bundles_by_attack(self, attack_id: str) -> list[StixBundle]:
        rows = self._fetch_all(q.LIST_STIX_BUNDLES_BY_ATTACK, {"attack_id": attack_id})
        return [StixBundle(**row) for row in rows]
