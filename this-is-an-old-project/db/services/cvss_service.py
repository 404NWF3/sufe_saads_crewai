from __future__ import annotations

from ..dtos import CvssAssessmentCreateDTO
from ..exceptions import ValidationError
from ..models import AttackCvssAssessment
from ..unit_of_work import UnitOfWork


class CvssService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def add_cvss_assessment(
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
        is_primary: bool = False,
        published_at=None,
        calculated_at=None,
    ) -> AttackCvssAssessment:
        payload = CvssAssessmentCreateDTO(
            attack_id=attack_id,
            source_raw_id=source_raw_id,
            cvss_version=cvss_version,
            vector_string=vector_string,
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            severity_label=severity_label,
            exploitability_subscore=exploitability_subscore,
            impact_subscore=impact_subscore,
            score_origin=score_origin,
            score_provider=score_provider,
            confidence_score=confidence_score,
            is_primary=is_primary,
            published_at=published_at,
            calculated_at=calculated_at,
        )

        if payload.is_primary and payload.base_score is None:
            raise ValidationError("Primary CVSS requires base_score")

        created = self.uow.attacks.insert_cvss_assessment(
            attack_id=payload.attack_id,
            source_raw_id=payload.source_raw_id,
            cvss_version=payload.cvss_version,
            vector_string=payload.vector_string,
            base_score=payload.base_score,
            temporal_score=payload.temporal_score,
            environmental_score=payload.environmental_score,
            severity_label=payload.severity_label,
            exploitability_subscore=payload.exploitability_subscore,
            impact_subscore=payload.impact_subscore,
            score_origin=payload.score_origin,
            score_provider=payload.score_provider,
            confidence_score=payload.confidence_score,
            is_primary=False if payload.is_primary else payload.is_primary,
            published_at=payload.published_at,
            calculated_at=payload.calculated_at,
        )
        if payload.is_primary:
            return self.uow.attacks.set_primary_cvss(created.score_id)
        return created

    def set_primary_cvss(self, score_id: int) -> AttackCvssAssessment:
        return self.uow.attacks.set_primary_cvss(score_id)

    def list_cvss_assessments(self, attack_id: str) -> list[AttackCvssAssessment]:
        return self.uow.attacks.list_cvss_assessments(attack_id)

