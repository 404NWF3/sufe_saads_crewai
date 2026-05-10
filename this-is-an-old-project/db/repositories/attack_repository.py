from __future__ import annotations

from typing import Any

from ..exceptions import NotFoundError, ValidationError
from ..models import (
    AttackCvssAssessment,
    AttackEntry,
    AttackEvidence,
    AttackSeedAsset,
    AttackTaxonomyMap,
    RemediationAdvice,
)
from ..sql import attack_queries as q
from .base import BaseRepository

_ATTACK_UPDATE_ALLOWLIST = {
    "canonical_name",
    "attack_family",
    "severity_level",
    "entry_status",
    "summary",
    "description",
    "exploit_preconditions",
    "impact_scope",
    "confidence_score",
    "first_seen_at",
    "last_seen_at",
    "primary_stix_bundle_id",
    "primary_stix_object_id",
    "stix_graph_status",
    "stix_type",
    "stix_payload",
}


class AttackRepository(BaseRepository):
    def get_attack_by_code(self, attack_code: str) -> AttackEntry | None:
        row = self._fetch_one(q.GET_ATTACK_BY_CODE, {"attack_code": attack_code})
        return self._row_to_model(AttackEntry, row)

    def get_attack_by_id(self, attack_id: str) -> AttackEntry | None:
        row = self._fetch_one(q.GET_ATTACK_BY_ID, {"attack_id": attack_id})
        return self._row_to_model(AttackEntry, row)

    def create_attack_entry(
        self,
        *,
        attack_code: str,
        canonical_name: str,
        attack_family: str,
        severity_level: str,
        entry_status: str,
        summary: str,
        description: str,
        exploit_preconditions: str | None = None,
        impact_scope: str | None = None,
        confidence_score: float,
        first_seen_at: Any | None = None,
        last_seen_at: Any | None = None,
        primary_stix_bundle_id: str | None = None,
        primary_stix_object_id: str | None = None,
        stix_graph_status: str | None = None,
        stix_type: str | None = None,
        stix_payload: dict[str, Any] | None = None,
    ) -> AttackEntry:
        row = self._fetch_one(
            q.CREATE_ATTACK_ENTRY,
            {
                "attack_code": attack_code,
                "canonical_name": canonical_name,
                "attack_family": attack_family,
                "severity_level": severity_level,
                "entry_status": entry_status,
                "summary": summary,
                "description": description,
                "exploit_preconditions": exploit_preconditions,
                "impact_scope": impact_scope,
                "confidence_score": confidence_score,
                "first_seen_at": first_seen_at,
                "last_seen_at": last_seen_at,
                "primary_stix_bundle_id": primary_stix_bundle_id,
                "primary_stix_object_id": primary_stix_object_id,
                "stix_graph_status": stix_graph_status,
                "stix_type": stix_type,
                "stix_payload": stix_payload,
            },
        )
        return self._require_model(AttackEntry, row, message="Failed to create attack_entry")

    def update_attack_entry(self, attack_id: str, **updates: Any) -> AttackEntry:
        updates = {k: v for k, v in updates.items() if v is not None}
        if not updates:
            attack = self.get_attack_by_id(attack_id)
            if attack is None:
                raise NotFoundError(f"attack_entry not found: attack_id={attack_id}")
            return attack

        unknown = sorted(set(updates) - _ATTACK_UPDATE_ALLOWLIST)
        if unknown:
            raise ValidationError(f"Unsupported attack_entry update fields: {unknown}")

        params = {"attack_id": attack_id, **updates}
        query = q.build_update_attack_entry_query(sorted(updates.keys()))
        row = self._fetch_one(query, params)
        return self._require_model(
            AttackEntry,
            row,
            message=f"attack_entry not found for update: attack_id={attack_id}",
        )

    def upsert_attack_entry_by_code(
        self,
        *,
        attack_code: str,
        canonical_name: str,
        attack_family: str,
        severity_level: str,
        entry_status: str,
        summary: str,
        description: str,
        exploit_preconditions: str | None = None,
        impact_scope: str | None = None,
        confidence_score: float,
        first_seen_at: Any | None = None,
        last_seen_at: Any | None = None,
        primary_stix_bundle_id: str | None = None,
        primary_stix_object_id: str | None = None,
        stix_graph_status: str | None = None,
        stix_type: str | None = None,
        stix_payload: dict[str, Any] | None = None,
    ) -> AttackEntry:
        row = self._fetch_one(
            q.UPSERT_ATTACK_ENTRY_BY_CODE,
            {
                "attack_code": attack_code,
                "canonical_name": canonical_name,
                "attack_family": attack_family,
                "severity_level": severity_level,
                "entry_status": entry_status,
                "summary": summary,
                "description": description,
                "exploit_preconditions": exploit_preconditions,
                "impact_scope": impact_scope,
                "confidence_score": confidence_score,
                "first_seen_at": first_seen_at,
                "last_seen_at": last_seen_at,
                "primary_stix_bundle_id": primary_stix_bundle_id,
                "primary_stix_object_id": primary_stix_object_id,
                "stix_graph_status": stix_graph_status,
                "stix_type": stix_type,
                "stix_payload": stix_payload,
            },
        )
        return self._require_model(
            AttackEntry, row, message=f"Failed to upsert attack_entry: {attack_code}"
        )

    def insert_attack_evidence(
        self,
        *,
        attack_id: str,
        raw_id: str,
        evidence_role: str,
        extractor_name: str,
        evidence_snippet: str | None = None,
    ) -> AttackEvidence:
        row = self._fetch_one(
            q.INSERT_ATTACK_EVIDENCE,
            {
                "attack_id": attack_id,
                "raw_id": raw_id,
                "evidence_role": evidence_role,
                "extractor_name": extractor_name,
                "evidence_snippet": evidence_snippet,
            },
        )
        return self._require_model(AttackEvidence, row, message="Failed to insert attack_evidence")

    def list_attack_evidence(self, attack_id: str) -> list[AttackEvidence]:
        rows = self._fetch_all(q.LIST_ATTACK_EVIDENCE, {"attack_id": attack_id})
        return [AttackEvidence(**row) for row in rows]

    def insert_cvss_assessment(
        self,
        *,
        attack_id: str,
        source_raw_id: str | None,
        cvss_version: str,
        vector_string: str | None,
        base_score: float | None,
        temporal_score: float | None,
        environmental_score: float | None,
        severity_label: str,
        exploitability_subscore: float | None,
        impact_subscore: float | None,
        score_origin: str,
        score_provider: str | None,
        confidence_score: float,
        is_primary: bool,
        published_at: Any | None = None,
        calculated_at: Any | None = None,
    ) -> AttackCvssAssessment:
        row = self._fetch_one(
            q.INSERT_CVSS_ASSESSMENT,
            {
                "attack_id": attack_id,
                "source_raw_id": source_raw_id,
                "cvss_version": cvss_version,
                "vector_string": vector_string,
                "base_score": base_score,
                "temporal_score": temporal_score,
                "environmental_score": environmental_score,
                "severity_label": severity_label,
                "exploitability_subscore": exploitability_subscore,
                "impact_subscore": impact_subscore,
                "score_origin": score_origin,
                "score_provider": score_provider,
                "confidence_score": confidence_score,
                "is_primary": is_primary,
                "published_at": published_at,
                "calculated_at": calculated_at,
            },
        )
        return self._require_model(
            AttackCvssAssessment, row, message="Failed to insert attack_cvss_assessment"
        )

    def list_cvss_assessments(self, attack_id: str) -> list[AttackCvssAssessment]:
        rows = self._fetch_all(q.LIST_CVSS_ASSESSMENTS, {"attack_id": attack_id})
        return [AttackCvssAssessment(**row) for row in rows]

    def set_primary_cvss(self, score_id: int) -> AttackCvssAssessment:
        target = self._fetch_one(q.GET_CVSS_BY_SCORE_ID, {"score_id": score_id})
        if target is None:
            raise NotFoundError(f"CVSS score not found: score_id={score_id}")

        self._execute(
            q.UNSET_PRIMARY_CVSS_BY_ATTACK_VERSION,
            {"attack_id": target["attack_id"], "cvss_version": target["cvss_version"]},
        )
        row = self._fetch_one(q.SET_PRIMARY_CVSS_BY_SCORE_ID, {"score_id": score_id})
        return self._require_model(
            AttackCvssAssessment, row, message=f"Failed to set primary CVSS: score_id={score_id}"
        )

    def upsert_taxonomy_map(
        self,
        *,
        attack_id: str,
        taxonomy_type: str,
        taxonomy_code: str,
        taxonomy_name: str,
        is_primary: bool,
        confidence_score: float,
    ) -> AttackTaxonomyMap:
        row = self._fetch_one(
            q.UPSERT_ATTACK_TAXONOMY,
            {
                "attack_id": attack_id,
                "taxonomy_type": taxonomy_type,
                "taxonomy_code": taxonomy_code,
                "taxonomy_name": taxonomy_name,
                "is_primary": is_primary,
                "confidence_score": confidence_score,
            },
        )
        return self._require_model(
            AttackTaxonomyMap, row, message="Failed to upsert attack_taxonomy_map"
        )

    def clear_primary_taxonomy(self, *, attack_id: str, taxonomy_type: str) -> int:
        return self._execute(
            q.RESET_PRIMARY_TAXONOMY,
            {"attack_id": attack_id, "taxonomy_type": taxonomy_type},
        )

    def replace_primary_taxonomy(
        self,
        *,
        attack_id: str,
        taxonomy_type: str,
        taxonomy_code: str,
        taxonomy_name: str,
        confidence_score: float,
    ) -> AttackTaxonomyMap:
        self.clear_primary_taxonomy(attack_id=attack_id, taxonomy_type=taxonomy_type)
        return self.upsert_taxonomy_map(
            attack_id=attack_id,
            taxonomy_type=taxonomy_type,
            taxonomy_code=taxonomy_code,
            taxonomy_name=taxonomy_name,
            is_primary=True,
            confidence_score=confidence_score,
        )

    def list_taxonomy_maps(self, attack_id: str) -> list[AttackTaxonomyMap]:
        rows = self._fetch_all(q.LIST_TAXONOMY_BY_ATTACK, {"attack_id": attack_id})
        return [AttackTaxonomyMap(**row) for row in rows]

    def insert_seed_asset(
        self,
        *,
        attack_id: str,
        asset_type: str,
        asset_name: str,
        artifact_uri: str,
        checksum: str,
        language: str | None = None,
        modality: str | None = None,
        qa_status: str = "draft",
        is_template: bool = True,
        metadata_json: dict[str, Any] | None = None,
    ) -> AttackSeedAsset:
        row = self._fetch_one(
            q.INSERT_SEED_ASSET,
            {
                "attack_id": attack_id,
                "asset_type": asset_type,
                "asset_name": asset_name,
                "artifact_uri": artifact_uri,
                "checksum": checksum,
                "language": language,
                "modality": modality,
                "qa_status": qa_status,
                "is_template": is_template,
                "metadata_json": metadata_json,
            },
        )
        return self._require_model(AttackSeedAsset, row, message="Failed to insert attack_seed_asset")

    def list_published_seed_assets(self, attack_id: str) -> list[AttackSeedAsset]:
        rows = self._fetch_all(q.LIST_PUBLISHED_SEED_ASSETS, {"attack_id": attack_id})
        return [AttackSeedAsset(**row) for row in rows]

    def insert_remediation_advice(
        self,
        *,
        attack_id: str,
        advice_type: str,
        title: str,
        content: str,
        priority_level: int,
        source_uri: str | None = None,
    ) -> RemediationAdvice:
        row = self._fetch_one(
            q.INSERT_REMEDIATION_ADVICE,
            {
                "attack_id": attack_id,
                "advice_type": advice_type,
                "title": title,
                "content": content,
                "priority_level": priority_level,
                "source_uri": source_uri,
            },
        )
        return self._require_model(
            RemediationAdvice, row, message="Failed to insert remediation_advice"
        )

