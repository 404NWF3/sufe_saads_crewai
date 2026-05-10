from __future__ import annotations

from ..models import (
    ComponentRiskOverviewRow,
    OwaspCoverageRow,
    PrimaryCvssView,
    SourceQualityDashboardRow,
    UnresolvedBomQueueRow,
    Wp12AttackFeedRow,
    Wp12AttackExecutionFeedRow,
)
from ..sql import read_model_queries as q
from .base import BaseRepository


class ReadModelRepository(BaseRepository):
    def get_primary_cvss(self, attack_id: str) -> PrimaryCvssView | None:
        row = self._fetch_one(q.GET_PRIMARY_CVSS, {"attack_id": attack_id})
        return self._row_to_model(PrimaryCvssView, row)

    def list_wp12_attack_feed(
        self,
        *,
        min_cvss: float | None = None,
        active_only: bool = True,
        qa_statuses: list[str] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Wp12AttackFeedRow]:
        query = q.LIST_WP12_ATTACK_FEED_BASE
        params: dict[str, object] = {}

        if min_cvss is not None:
            query += " AND (primary_cvss_base_score IS NULL OR primary_cvss_base_score >= %(min_cvss)s)"
            params["min_cvss"] = min_cvss
        if active_only:
            query += " AND entry_status = 'active'"
        if qa_statuses:
            query += " AND (qa_status = ANY(%(qa_statuses)s) OR qa_status IS NULL)"
            params["qa_statuses"] = qa_statuses

        query += " ORDER BY primary_cvss_base_score DESC NULLS LAST, last_seen_at DESC NULLS LAST"
        query += " LIMIT %(limit)s OFFSET %(offset)s"
        params["limit"] = limit
        params["offset"] = offset

        rows = self._fetch_all(query, params)
        return [Wp12AttackFeedRow(**row) for row in rows]

    def list_component_risk_overview(
        self,
        *,
        component_type: str | None = None,
        min_attack_count: int | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[ComponentRiskOverviewRow]:
        query = q.LIST_COMPONENT_RISK_OVERVIEW_BASE
        params: dict[str, object] = {}
        if component_type:
            query += " AND component_type = %(component_type)s"
            params["component_type"] = component_type
        if min_attack_count is not None:
            query += " AND attack_count >= %(min_attack_count)s"
            params["min_attack_count"] = min_attack_count
        query += " ORDER BY attack_count DESC, max_primary_cvss_score DESC NULLS LAST"
        query += " LIMIT %(limit)s OFFSET %(offset)s"
        params["limit"] = limit
        params["offset"] = offset

        rows = self._fetch_all(query, params)
        return [ComponentRiskOverviewRow(**row) for row in rows]

    def list_wp12_attack_execution_feed(
        self,
        *,
        active_only: bool = True,
        published_only: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Wp12AttackExecutionFeedRow]:
        query = q.LIST_WP12_ATTACK_EXECUTION_FEED_BASE
        params: dict[str, object] = {}
        if active_only:
            query += " AND stix_graph_status IS NOT NULL"
        if published_only:
            query += " AND stix_graph_status = 'published'"
        query += " ORDER BY attack_code ASC LIMIT %(limit)s OFFSET %(offset)s"
        params["limit"] = limit
        params["offset"] = offset
        rows = self._fetch_all(query, params)
        return [Wp12AttackExecutionFeedRow(**row) for row in rows]

    def list_unresolved_bom_queue(self, limit: int = 100) -> list[UnresolvedBomQueueRow]:
        rows = self._fetch_all(q.LIST_UNRESOLVED_BOM_QUEUE, {"limit": limit})
        return [UnresolvedBomQueueRow(**row) for row in rows]

    def get_source_quality_dashboard(
        self, source_type: str | None = None
    ) -> list[SourceQualityDashboardRow]:
        query = q.LIST_SOURCE_QUALITY_DASHBOARD_BASE
        params: dict[str, object] = {}
        if source_type:
            query += " AND source_type = %(source_type)s"
            params["source_type"] = source_type
        query += " ORDER BY source_name ASC"

        rows = self._fetch_all(query, params or None)
        return [SourceQualityDashboardRow(**row) for row in rows]

    def list_owasp_coverage(self, limit: int = 100) -> list[OwaspCoverageRow]:
        rows = self._fetch_all(q.LIST_OWASP_COVERAGE, {"limit": limit})
        return [OwaspCoverageRow(**row) for row in rows]

    def refresh_mv_owasp_coverage(self, *, concurrently: bool = False) -> None:
        sql = (
            q.REFRESH_MV_OWASP_COVERAGE_CONCURRENTLY
            if concurrently
            else q.REFRESH_MV_OWASP_COVERAGE
        )
        self._execute(sql)

