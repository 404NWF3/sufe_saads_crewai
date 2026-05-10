from __future__ import annotations

from dataclasses import dataclass

from ..dtos import AttackMergeDTO
from ..models import AttackEntry
from ..unit_of_work import UnitOfWork


@dataclass(slots=True)
class AttackMergeResult:
    attack_id: str
    attack_entry: AttackEntry


class AttackMergeService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def merge_parsed_attack(
        self,
        *,
        raw_id: str,
        attack_code: str,
        canonical_name: str,
        attack_family: str,
        severity_level: str,
        summary: str,
        description: str,
        exploit_preconditions: str | None = None,
        impact_scope: str | None = None,
        confidence_score: float,
        first_seen_at=None,
        last_seen_at=None,
        stix_type: str | None = None,
        stix_payload: dict | None = None,
        entry_status: str = "active",
        evidence_role: str = "primary",
        extractor_name: str = "parser_agent",
        evidence_snippet: str | None = None,
        dedup_similarity_score: float | None = None,
        dedup_rule_name: str = "merge_by_code",
        dedup_decision: str | None = None,
        dedup_matched_attack_id: str | None = None,
    ) -> AttackMergeResult:
        payload = AttackMergeDTO(
            raw_id=raw_id,
            attack_code=attack_code,
            canonical_name=canonical_name,
            attack_family=attack_family,
            severity_level=severity_level,
            summary=summary,
            description=description,
            exploit_preconditions=exploit_preconditions,
            impact_scope=impact_scope,
            confidence_score=confidence_score,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            stix_type=stix_type,
            stix_payload=stix_payload,
            entry_status=entry_status,
            evidence_role=evidence_role,
            extractor_name=extractor_name,
            evidence_snippet=evidence_snippet,
        )

        attack = self.uow.attacks.upsert_attack_entry_by_code(
            attack_code=payload.attack_code,
            canonical_name=payload.canonical_name,
            attack_family=payload.attack_family,
            severity_level=payload.severity_level,
            entry_status=payload.entry_status,
            summary=payload.summary,
            description=payload.description,
            exploit_preconditions=payload.exploit_preconditions,
            impact_scope=payload.impact_scope,
            confidence_score=payload.confidence_score,
            first_seen_at=payload.first_seen_at,
            last_seen_at=payload.last_seen_at,
            stix_type=payload.stix_type,
            stix_payload=payload.stix_payload,
        )

        self.uow.attacks.insert_attack_evidence(
            attack_id=attack.attack_id,
            raw_id=payload.raw_id,
            evidence_role=payload.evidence_role,
            extractor_name=payload.extractor_name,
            evidence_snippet=payload.evidence_snippet,
        )
        self.uow.sources.mark_raw_record_parser_status(raw_id=payload.raw_id, status="parsed")

        if dedup_similarity_score is not None and dedup_decision is not None:
            matched_attack_id = dedup_matched_attack_id
            if matched_attack_id is None and dedup_decision == "merge":
                matched_attack_id = attack.attack_id
            self.uow.governance.insert_dedup_audit(
                candidate_raw_id=payload.raw_id,
                matched_attack_id=matched_attack_id,
                similarity_score=dedup_similarity_score,
                rule_name=dedup_rule_name,
                decision=dedup_decision,
                reviewer_name=None,
            )

        return AttackMergeResult(attack_id=str(attack.attack_id), attack_entry=attack)
