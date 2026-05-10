from __future__ import annotations

from ..models import (
    BomResolutionAudit,
    BomResolutionQueueItem,
    DedupAudit,
    QueryFeedbackLog,
)
from ..sql import governance_queries as q
from .base import BaseRepository


class GovernanceRepository(BaseRepository):
    def insert_dedup_audit(
        self,
        *,
        candidate_raw_id: str,
        matched_attack_id: str | None,
        similarity_score: float,
        rule_name: str,
        decision: str,
        reviewer_name: str | None = None,
    ) -> DedupAudit:
        row = self._fetch_one(
            q.INSERT_DEDUP_AUDIT,
            {
                "candidate_raw_id": candidate_raw_id,
                "matched_attack_id": matched_attack_id,
                "similarity_score": similarity_score,
                "rule_name": rule_name,
                "decision": decision,
                "reviewer_name": reviewer_name,
            },
        )
        return self._require_model(DedupAudit, row, message="Failed to insert dedup_audit")

    def list_dedup_candidates_for_review(self, limit: int = 100) -> list[DedupAudit]:
        rows = self._fetch_all(q.LIST_DEDUP_REVIEW_ITEMS, {"limit": limit})
        return [DedupAudit(**row) for row in rows]

    def enqueue_bom_resolution(
        self,
        *,
        attack_id: str | None,
        raw_id: str | None,
        mention_id: str | None,
        mentioned_name: str,
        mentioned_vendor: str | None,
        mentioned_version: str | None,
        reason_code: str,
        candidate_snapshot: dict | None = None,
        reasoning_summary: str | None = None,
    ) -> BomResolutionQueueItem:
        row = self._fetch_one(
            q.ENQUEUE_BOM_RESOLUTION,
            {
                "attack_id": attack_id,
                "raw_id": raw_id,
                "mention_id": mention_id,
                "mentioned_name": mentioned_name,
                "mentioned_vendor": mentioned_vendor,
                "mentioned_version": mentioned_version,
                "reason_code": reason_code,
                "candidate_snapshot": candidate_snapshot,
                "reasoning_summary": reasoning_summary,
            },
        )
        return self._require_model(
            BomResolutionQueueItem, row, message="Failed to enqueue bom_resolution_queue"
        )

    def list_open_bom_queue(self, limit: int = 100) -> list[BomResolutionQueueItem]:
        rows = self._fetch_all(q.LIST_OPEN_BOM_QUEUE, {"limit": limit})
        return [BomResolutionQueueItem(**row) for row in rows]

    def resolve_bom_queue_item(
        self, *, queue_id: int, resolved_component_id: str
    ) -> BomResolutionQueueItem | None:
        row = self._fetch_one(
            q.RESOLVE_BOM_QUEUE_ITEM,
            {"queue_id": queue_id, "resolved_component_id": resolved_component_id},
        )
        return self._row_to_model(BomResolutionQueueItem, row)

    def reject_bom_queue_item(self, *, queue_id: int) -> BomResolutionQueueItem | None:
        row = self._fetch_one(q.REJECT_BOM_QUEUE_ITEM, {"queue_id": queue_id})
        return self._row_to_model(BomResolutionQueueItem, row)

    def insert_bom_resolution_audit(
        self,
        *,
        mention_id: str | None,
        attack_id: str | None,
        raw_id: str | None,
        strategy_requested: str,
        strategy_executed: str,
        llm_model: str,
        prompt_version: str,
        llm_decision: str,
        llm_confidence: float,
        selected_component_code: str | None,
        reasoning_summary: str,
        reasoning_trace: list[str] | None,
        candidate_count: int,
        evidence_quotes: list[str] | None,
    ) -> BomResolutionAudit:
        row = self._fetch_one(
            q.INSERT_BOM_RESOLUTION_AUDIT,
            {
                "mention_id": mention_id,
                "attack_id": attack_id,
                "raw_id": raw_id,
                "strategy_requested": strategy_requested,
                "strategy_executed": strategy_executed,
                "llm_model": llm_model,
                "prompt_version": prompt_version,
                "llm_decision": llm_decision,
                "llm_confidence": llm_confidence,
                "selected_component_code": selected_component_code,
                "reasoning_summary": reasoning_summary,
                "reasoning_trace": reasoning_trace,
                "candidate_count": candidate_count,
                "evidence_quotes": evidence_quotes,
            },
        )
        return self._require_model(
            BomResolutionAudit,
            row,
            message="Failed to insert bom_resolution_audit",
        )

    def insert_query_feedback(self, row: dict) -> QueryFeedbackLog | None:
        result = self._fetch_one(q.INSERT_QUERY_FEEDBACK_BATCH, row)
        return self._row_to_model(QueryFeedbackLog, result)

    def load_recent_query_feedback(self, limit: int = 100) -> list[QueryFeedbackLog]:
        rows = self._fetch_all(q.LOAD_RECENT_QUERY_FEEDBACK, {"limit": limit})
        return [QueryFeedbackLog(**row) for row in rows]

