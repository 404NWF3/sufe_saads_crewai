from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


Score = Annotated[float, Field(ge=0.0, le=1.0)]
NonNegativeFloat = Annotated[float, Field(ge=0.0)]
NonNegativeInt = Annotated[int, Field(ge=0)]

RunMode = Literal["bootstrap", "incremental", "gap_fill", "deep_research"]
RunStatus = Literal["queued", "running", "partial_success", "succeeded", "failed"]
ActionType = Literal[
    "LOAD_DB_CONTEXT",
    "PLAN_COLLECTION",
    "SEARCH_REGISTERED_SOURCE",
    "PROPOSE_NEW_SOURCE",
    "EXTRACT_SOURCE_EVIDENCE",
    "ASSESS_COLLECTION_YIELD",
    "REFLECT_SEARCH_STRATEGY",
    "STANDARDIZE_INTEL",
    "DEDUP_AND_MERGE",
    "MAP_AI_BOM",
    "BUILD_STIX_GRAPH",
    "SCORE_CONFIDENCE_NOVELTY",
    "ANALYZE_COVERAGE_GAPS",
    "PLAN_DB_WRITE",
    "COMMIT_DB_WRITE",
    "VERIFY_DB_INTEGRITY",
    "GENERATE_ALERTS",
    "STOP",
]
SourceType = Literal[
    "structured",
    "code",
    "paper",
    "community",
    "advisory",
    "vendor",
    "web",
    "security_db",
    "research",
]
ApprovalStatus = Literal["pending", "approved", "rejected"]
Priority = Literal["low", "medium", "high", "critical"]
ReviewStatus = Literal["accepted", "review", "rejected"]
PublicationStatus = Literal["draft", "ready", "published", "suppressed"]
ValidationStatus = Literal["pending", "valid", "invalid", "applied", "failed"]


class FlexibleModel(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class EvidenceRef(FlexibleModel):
    source_name: str = ""
    source_uri: str = ""
    item_id: str | None = None
    evidence_text: str | None = None
    confidence: Score = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScoreBreakdown(FlexibleModel):
    overall: Score = 0.0
    factors: dict[str, float] = Field(default_factory=dict)
    rationale: str = ""


class ErrorRecord(FlexibleModel):
    error_type: str
    message: str
    retryable: bool = False
    action_type: ActionType | None = None
    occurred_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)
