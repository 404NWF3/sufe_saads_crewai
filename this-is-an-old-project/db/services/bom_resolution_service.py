from __future__ import annotations

from dataclasses import dataclass

from ..dtos import ComponentMentionDTO
from ..models import BomResolutionQueueItem
from ..repositories.component_repository import normalize_component_alias
from ..unit_of_work import UnitOfWork


@dataclass(slots=True)
class BomResolutionResult:
    status: str
    component_id: str | None = None
    queue_id: int | None = None
    similarity: float | None = None


class BomResolutionService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def resolve_or_enqueue(
        self,
        *,
        attack_id: str,
        mentioned_name: str,
        raw_id: str | None = None,
        mentioned_vendor: str | None = None,
        mentioned_version: str | None = None,
        reason_code: str = "alias_not_found",
        min_similarity: float = 0.75,
        ambiguity_margin: float = 0.05,
    ) -> BomResolutionResult:
        payload = ComponentMentionDTO(
            mentioned_name=mentioned_name,
            mentioned_vendor=mentioned_vendor,
            mentioned_version=mentioned_version,
            reason_code=reason_code,
        )

        direct = self.uow.components.get_component_by_name(payload.mentioned_name)
        if direct is not None:
            self.uow.components.upsert_attack_component_impact(
                attack_id=attack_id,
                component_id=direct.component_id,
                version_constraint_raw=payload.mentioned_version,
                normalized_constraint=payload.mentioned_version,
                match_mode="exact",
                impact_scope="direct",
                confidence_score=1.0,
                evidence_uri=None,
            )
            return BomResolutionResult(status="resolved", component_id=str(direct.component_id), similarity=1.0)

        normalized_alias = normalize_component_alias(
            payload.mentioned_name, payload.mentioned_vendor
        )
        alias_match = self.uow.components.find_component_by_alias(normalized_alias)
        if alias_match is not None:
            self.uow.components.upsert_attack_component_impact(
                attack_id=attack_id,
                component_id=alias_match.component_id,
                version_constraint_raw=payload.mentioned_version,
                normalized_constraint=payload.mentioned_version,
                match_mode="vendor_fallback",
                impact_scope="direct",
                confidence_score=0.9,
                evidence_uri=None,
            )
            return BomResolutionResult(
                status="resolved",
                component_id=str(alias_match.component_id),
                similarity=0.9,
            )

        candidates = self.uow.components.search_component_alias(normalized_alias, limit=5)
        if candidates:
            top = candidates[0]
            second_similarity = candidates[1]["similarity"] if len(candidates) > 1 else None
            top_similarity = float(top["similarity"])
            if (
                top_similarity >= min_similarity
                and (second_similarity is None or top_similarity - float(second_similarity) >= ambiguity_margin)
            ):
                self.uow.components.upsert_attack_component_impact(
                    attack_id=attack_id,
                    component_id=top["component_id"],
                    version_constraint_raw=payload.mentioned_version,
                    normalized_constraint=payload.mentioned_version,
                    match_mode="range",
                    impact_scope="direct",
                    confidence_score=top_similarity,
                    evidence_uri=None,
                )
                return BomResolutionResult(
                    status="resolved",
                    component_id=str(top["component_id"]),
                    similarity=top_similarity,
                )

        queue_item = self.uow.governance.enqueue_bom_resolution(
            attack_id=attack_id,
            raw_id=raw_id,
            mention_id=None,
            mentioned_name=payload.mentioned_name,
            mentioned_vendor=payload.mentioned_vendor,
            mentioned_version=payload.mentioned_version,
            reason_code=payload.reason_code,
            candidate_snapshot=None,
            reasoning_summary=None,
        )
        return BomResolutionResult(status="queued", queue_id=queue_item.queue_id)

    def resolve_bom_queue_item(self, *, queue_id: int, resolved_component_id: str) -> BomResolutionQueueItem | None:
        return self.uow.governance.resolve_bom_queue_item(
            queue_id=queue_id,
            resolved_component_id=resolved_component_id,
        )

    def reject_bom_queue_item(self, *, queue_id: int) -> BomResolutionQueueItem | None:
        return self.uow.governance.reject_bom_queue_item(queue_id=queue_id)

