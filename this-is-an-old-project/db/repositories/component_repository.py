from __future__ import annotations

import re
from typing import Any

from ..models import (
    AiComponent,
    AiComponentAlias,
    AttackComponentImpact,
    AttackComponentMention,
)
from ..sql import bom_queries as q
from .base import BaseRepository

_ALIAS_CLEAN_RE = re.compile(r"[\s_\-]+")


def normalize_component_alias(alias: str, vendor_name: str | None = None) -> str:
    normalized = _ALIAS_CLEAN_RE.sub("", alias.strip().lower())
    if vendor_name:
        vendor_norm = _ALIAS_CLEAN_RE.sub("", vendor_name.strip().lower())
        if vendor_norm and normalized.startswith(vendor_norm):
            normalized = normalized[len(vendor_norm) :]
    return normalized


class ComponentRepository(BaseRepository):
    def get_component_by_code(self, component_code: str) -> AiComponent | None:
        row = self._fetch_one(
            q.GET_COMPONENT_BY_CODE, {"component_code": component_code}
        )
        return self._row_to_model(AiComponent, row)

    def get_component_by_name(self, component_name: str) -> AiComponent | None:
        row = self._fetch_one(
            q.GET_COMPONENT_BY_NAME, {"component_name": component_name}
        )
        return self._row_to_model(AiComponent, row)

    def find_component_by_alias(self, normalized_alias: str) -> AiComponent | None:
        matches = self.list_components_by_alias(normalized_alias)
        if len(matches) != 1:
            return None
        return matches[0]

    def list_components_by_alias(self, normalized_alias: str) -> list[AiComponent]:
        rows = self._fetch_all(
            q.LIST_COMPONENTS_BY_NORMALIZED_ALIAS,
            {"normalized_alias": normalized_alias},
        )
        return [AiComponent(**row) for row in rows]

    def search_component_alias(
        self, normalized_alias: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        return self._fetch_all(
            q.SEARCH_COMPONENT_ALIAS,
            {"normalized_alias": normalized_alias, "limit": limit},
        )

    def create_component(
        self,
        *,
        component_code: str,
        component_name: str,
        vendor_name: str | None,
        component_type: str,
        component_layer: str | None = None,
        modality: str | None = None,
        purl: str | None = None,
        homepage_uri: str | None = None,
        lifecycle_status: str = "active",
    ) -> AiComponent:
        row = self._fetch_one(
            q.CREATE_COMPONENT,
            {
                "component_code": component_code,
                "component_name": component_name,
                "component_layer": component_layer,
                "vendor_name": vendor_name,
                "component_type": component_type,
                "modality": modality,
                "purl": purl,
                "homepage_uri": homepage_uri,
                "lifecycle_status": lifecycle_status,
            },
        )
        return self._require_model(
            AiComponent, row, message="Failed to create ai_component"
        )

    def upsert_component(
        self,
        *,
        component_code: str,
        component_name: str,
        vendor_name: str | None,
        component_type: str,
        component_layer: str | None = None,
        modality: str | None = None,
        purl: str | None = None,
        homepage_uri: str | None = None,
        lifecycle_status: str = "active",
    ) -> AiComponent:
        row = self._fetch_one(
            q.UPSERT_COMPONENT,
            {
                "component_code": component_code,
                "component_name": component_name,
                "component_layer": component_layer,
                "vendor_name": vendor_name,
                "component_type": component_type,
                "modality": modality,
                "purl": purl,
                "homepage_uri": homepage_uri,
                "lifecycle_status": lifecycle_status,
            },
        )
        return self._require_model(
            AiComponent, row, message="Failed to upsert ai_component"
        )

    def insert_component_alias(
        self,
        *,
        component_id: str,
        alias_name: str,
        alias_type: str,
        normalized_alias: str | None = None,
        vendor_name: str | None = None,
        is_preferred: bool = False,
    ) -> AiComponentAlias:
        normalized_alias = normalized_alias or normalize_component_alias(
            alias_name, vendor_name
        )
        row = self._fetch_one(
            q.INSERT_COMPONENT_ALIAS,
            {
                "component_id": component_id,
                "alias_name": alias_name,
                "alias_type": alias_type,
                "normalized_alias": normalized_alias,
                "is_preferred": is_preferred,
            },
        )
        return self._require_model(
            AiComponentAlias, row, message="Failed to insert component alias"
        )

    def upsert_component_alias(
        self,
        *,
        component_id: str,
        alias_name: str,
        alias_type: str,
        normalized_alias: str | None = None,
        vendor_name: str | None = None,
        is_preferred: bool = False,
    ) -> AiComponentAlias:
        normalized_alias = normalized_alias or normalize_component_alias(
            alias_name, vendor_name
        )
        row = self._fetch_one(
            q.UPSERT_COMPONENT_ALIAS,
            {
                "component_id": component_id,
                "alias_name": alias_name,
                "alias_type": alias_type,
                "normalized_alias": normalized_alias,
                "is_preferred": is_preferred,
            },
        )
        return self._require_model(
            AiComponentAlias, row, message="Failed to upsert component alias"
        )

    def list_component_aliases(self, component_id: str) -> list[AiComponentAlias]:
        rows = self._fetch_all(q.LIST_COMPONENT_ALIASES, {"component_id": component_id})
        return [AiComponentAlias(**row) for row in rows]

    def upsert_attack_component_impact(
        self,
        *,
        attack_id: str,
        component_id: str,
        mention_id: str | None = None,
        source_raw_id: str | None = None,
        version_constraint_raw: str | None = None,
        normalized_constraint: str | None = None,
        match_mode: str,
        impact_scope: str,
        review_status: str = "accepted",
        resolver_strategy: str | None = None,
        confidence_score: float,
        evidence_uri: str | None = None,
        evidence_snippet: str | None = None,
    ) -> AttackComponentImpact:
        row = self._fetch_one(
            q.UPSERT_ATTACK_COMPONENT_IMPACT,
            {
                "attack_id": attack_id,
                "component_id": component_id,
                "mention_id": mention_id,
                "source_raw_id": source_raw_id,
                "version_constraint_raw": version_constraint_raw,
                "normalized_constraint": normalized_constraint,
                "match_mode": match_mode,
                "impact_scope": impact_scope,
                "review_status": review_status,
                "resolver_strategy": resolver_strategy,
                "confidence_score": confidence_score,
                "evidence_uri": evidence_uri,
                "evidence_snippet": evidence_snippet,
            },
        )
        return self._require_model(
            AttackComponentImpact,
            row,
            message="Failed to upsert attack_component_impact",
        )

    def list_component_impacts_by_attack(
        self, attack_id: str
    ) -> list[AttackComponentImpact]:
        rows = self._fetch_all(
            q.LIST_COMPONENT_IMPACTS_BY_ATTACK, {"attack_id": attack_id}
        )
        return [AttackComponentImpact(**row) for row in rows]

    def list_attacks_by_component(
        self, component_id: str
    ) -> list[AttackComponentImpact]:
        rows = self._fetch_all(
            q.LIST_ATTACKS_BY_COMPONENT, {"component_id": component_id}
        )
        return [AttackComponentImpact(**row) for row in rows]

    def insert_attack_component_mention(
        self,
        *,
        attack_id: str | None,
        raw_id: str | None,
        mentioned_name: str,
        mentioned_vendor: str | None = None,
        mentioned_version: str | None = None,
        normalized_alias: str,
        normalized_vendor: str | None = None,
        component_layer: str | None = None,
        impact_scope: str | None = None,
        dependency_role: str | None = None,
        evidence_snippet: str | None = None,
        extractor_name: str = "bom_llm_extractor",
        extraction_confidence: float = 0.0,
    ) -> AttackComponentMention:
        row = self._fetch_one(
            q.INSERT_ATTACK_COMPONENT_MENTION,
            {
                "attack_id": attack_id,
                "raw_id": raw_id,
                "mentioned_name": mentioned_name,
                "mentioned_vendor": mentioned_vendor,
                "mentioned_version": mentioned_version,
                "normalized_alias": normalized_alias,
                "normalized_vendor": normalized_vendor,
                "component_layer": component_layer,
                "impact_scope": impact_scope,
                "dependency_role": dependency_role,
                "evidence_snippet": evidence_snippet,
                "extractor_name": extractor_name,
                "extraction_confidence": extraction_confidence,
            },
        )
        return self._require_model(
            AttackComponentMention,
            row,
            message="Failed to insert attack_component_mention",
        )

    def list_component_mentions_by_attack(
        self, attack_id: str
    ) -> list[AttackComponentMention]:
        rows = self._fetch_all(
            q.LIST_COMPONENT_MENTIONS_BY_ATTACK,
            {"attack_id": attack_id},
        )
        return [AttackComponentMention(**row) for row in rows]
