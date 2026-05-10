from __future__ import annotations

from typing import Any

from pydantic import Field

from .common import EvidenceRef, FlexibleModel, Priority, PublicationStatus, Score
from .intel import AffectedComponent


class AlertCandidate(FlexibleModel):
    title: str
    severity: Priority = "medium"
    affected_components: list[AffectedComponent] = Field(default_factory=list)
    summary: str = ""
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    confidence: Score = 0.0
    recommended_action: str = ""
    publication_status: PublicationStatus = "draft"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertCandidateBatch(FlexibleModel):
    alerts: list[AlertCandidate] = Field(default_factory=list)


class IntelRunSummary(FlexibleModel):
    run_status: str
    key_findings: list[str] = Field(default_factory=list)
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    source_summary: dict[str, Any] = Field(default_factory=dict)
    reflection_summary: dict[str, Any] = Field(default_factory=dict)
    db_audit_summary: dict[str, Any] = Field(default_factory=dict)
    alert_summary: dict[str, Any] = Field(default_factory=dict)
    unresolved_items: list[str] = Field(default_factory=list)
    recommended_followups: list[str] = Field(default_factory=list)
