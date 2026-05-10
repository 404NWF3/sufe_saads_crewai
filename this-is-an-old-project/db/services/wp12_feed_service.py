from __future__ import annotations

from ..models import (
    ComponentRiskOverviewRow,
    OwaspCoverageRow,
    SourceQualityDashboardRow,
    UnresolvedBomQueueRow,
    Wp12AttackFeedRow,
    Wp12AttackExecutionFeedRow,
)
from ..unit_of_work import UnitOfWork


class Wp12FeedService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def get_attack_feed(
        self,
        *,
        min_cvss: float | None = 7.0,
        active_only: bool = True,
        qa_statuses: list[str] | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Wp12AttackFeedRow]:
        qa_statuses = qa_statuses or ["reviewed", "published"]
        return self.uow.read_models.list_wp12_attack_feed(
            min_cvss=min_cvss,
            active_only=active_only,
            qa_statuses=qa_statuses,
            limit=limit,
            offset=offset,
        )

    def get_component_risk_overview(
        self, *, component_type: str | None = None, limit: int = 200
    ) -> list[ComponentRiskOverviewRow]:
        return self.uow.read_models.list_component_risk_overview(
            component_type=component_type,
            limit=limit,
        )

    def list_unresolved_bom_queue(self, *, limit: int = 100) -> list[UnresolvedBomQueueRow]:
        return self.uow.read_models.list_unresolved_bom_queue(limit=limit)

    def get_source_quality_dashboard(
        self, *, source_type: str | None = None
    ) -> list[SourceQualityDashboardRow]:
        return self.uow.read_models.get_source_quality_dashboard(source_type=source_type)

    def list_owasp_coverage(self, *, limit: int = 100) -> list[OwaspCoverageRow]:
        return self.uow.read_models.list_owasp_coverage(limit=limit)

    def refresh_owasp_coverage(self, *, concurrently: bool = False) -> None:
        self.uow.read_models.refresh_mv_owasp_coverage(concurrently=concurrently)

    def get_attack_execution_feed(
        self,
        *,
        active_only: bool = True,
        published_only: bool = True,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Wp12AttackExecutionFeedRow]:
        return self.uow.read_models.list_wp12_attack_execution_feed(
            active_only=active_only,
            published_only=published_only,
            limit=limit,
            offset=offset,
        )

