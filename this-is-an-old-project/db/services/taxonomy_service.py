from __future__ import annotations

from collections import Counter

from ..dtos import TaxonomyItemDTO
from ..exceptions import ValidationError
from ..models import AttackTaxonomyMap
from ..unit_of_work import UnitOfWork


class TaxonomyService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def replace_taxonomy_set(
        self, *, attack_id: str, taxonomy_items: list[dict] | list[TaxonomyItemDTO]
    ) -> list[AttackTaxonomyMap]:
        normalized_items = [
            item if isinstance(item, TaxonomyItemDTO) else TaxonomyItemDTO(**item)
            for item in taxonomy_items
        ]

        primary_counter: Counter[str] = Counter(
            item.taxonomy_type for item in normalized_items if item.is_primary
        )
        duplicated_primary = [t for t, count in primary_counter.items() if count > 1]
        if duplicated_primary:
            raise ValidationError(
                f"Each taxonomy_type can have only one primary item: {duplicated_primary}"
            )

        for taxonomy_type in {item.taxonomy_type for item in normalized_items}:
            self.uow.attacks.clear_primary_taxonomy(
                attack_id=attack_id, taxonomy_type=taxonomy_type
            )

        results: list[AttackTaxonomyMap] = []
        for item in normalized_items:
            mapped = self.uow.attacks.upsert_taxonomy_map(
                attack_id=attack_id,
                taxonomy_type=item.taxonomy_type,
                taxonomy_code=item.taxonomy_code,
                taxonomy_name=item.taxonomy_name,
                is_primary=item.is_primary,
                confidence_score=item.confidence_score,
            )
            results.append(mapped)
        return results

    def replace_primary_taxonomy(
        self,
        *,
        attack_id: str,
        taxonomy_type: str,
        taxonomy_code: str,
        taxonomy_name: str,
        confidence_score: float,
    ) -> AttackTaxonomyMap:
        item = TaxonomyItemDTO(
            taxonomy_type=taxonomy_type,
            taxonomy_code=taxonomy_code,
            taxonomy_name=taxonomy_name,
            is_primary=True,
            confidence_score=confidence_score,
        )
        return self.uow.attacks.replace_primary_taxonomy(
            attack_id=attack_id,
            taxonomy_type=item.taxonomy_type,
            taxonomy_code=item.taxonomy_code,
            taxonomy_name=item.taxonomy_name,
            confidence_score=item.confidence_score,
        )

