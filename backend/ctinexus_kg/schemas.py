"""Self-contained Pydantic models for ctinexus_kg.

No dependency on the legacy crew package or on intel_agent. Item DTOs are
structurally compatible with intel_agent RawIntelItem via model_dump/validate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


Score = Annotated[float, Field(ge=0.0, le=1.0)]

KgGenerationStatus = Literal["skipped", "pending", "succeeded", "failed"]
KgFeedbackStatus = Literal["accepted", "rejected", "needs_edit"]


class FlexibleModel(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class RawIntelItem(FlexibleModel):
    """Minimal intel item DTO consumed by KG generation."""

    item_id: str
    source_name: str
    source_uri: str
    title: str = ""
    summary: str = ""
    published_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=utcnow)
    raw_text: str | None = None
    relevance_score: Score = 0.0
    extraction_notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CtinexusStageConfig(FlexibleModel):
    model: str | None = None
    temperature: float | None = None
    shot: int | None = None
    enabled: bool = True


class KgGenerationConfig(FlexibleModel):
    enabled: bool = True
    provider: str = "OpenAI"
    model: str = "glm-4.7"
    embedding_model: str = "embedding-3"
    similarity_threshold: float = 0.6
    max_input_chars: int = 12_000
    min_relevance_score: Score = 0.5
    exclude_sources: list[str] = Field(default_factory=lambda: ["arxiv_api"])
    output_root: str = "data/intel_runs"
    base_url: str | None = None
    api_key_env: str = "CTINEXUS_API_KEY"
    base_url_env: str = "CTINEXUS_BASE_URL"
    fail_on_error: bool = False
    retriever_type: str = "kNN"
    demo_permutation: str = "asc"
    template_version: str = "ctinexus-paper-v1"
    ie: CtinexusStageConfig = Field(
        default_factory=lambda: CtinexusStageConfig(shot=2, temperature=0.8)
    )
    et: CtinexusStageConfig = Field(
        default_factory=lambda: CtinexusStageConfig(shot=8, temperature=0.8)
    )
    ea: CtinexusStageConfig = Field(default_factory=CtinexusStageConfig)
    lp: CtinexusStageConfig = Field(
        default_factory=lambda: CtinexusStageConfig(shot=2, temperature=0.8)
    )

    @classmethod
    def from_env(cls) -> "KgGenerationConfig":
        """Prefer CTINEXUS_* then GLM_* / OPENAI_* from the process environment."""
        import os

        model = (
            os.getenv("CTINEXUS_MODEL")
            or os.getenv("GLM_MODEL")
            or "glm-4.7"
        )
        embedding = (
            os.getenv("CTINEXUS_EMBEDDING_MODEL")
            or os.getenv("GLM_EMBEDDING_MODEL")
            or "embedding-3"
        )
        base_url = (
            os.getenv("CTINEXUS_BASE_URL")
            or os.getenv("GLM_BASE_URL")
            or os.getenv("OPENAI_BASE_URL")
            or os.getenv("OPENAI_API_BASE")
            or None
        )
        return cls(model=model, embedding_model=embedding, base_url=base_url or None)


class KgEligibilityDecision(FlexibleModel):
    item_id: str
    eligible: bool
    reasons: list[str] = Field(default_factory=list)
    excluded_reason: str | None = None
    matched_topics: list[str] = Field(default_factory=list)
    relevance_score: Score = 0.0
    source_name: str = ""


class ItemKnowledgeGraphRecord(FlexibleModel):
    run_id: str
    item_id: str
    source_name: str
    source_uri: str = ""
    status: KgGenerationStatus = "pending"
    eligibility: KgEligibilityDecision
    matched_topics: list[str] = Field(default_factory=list)
    relevance_score: Score = 0.0
    input_hash: str | None = None
    template_version: str = "ctinexus-paper-v1"
    provider: str = "OpenAI"
    model: str = ""
    embedding_model: str = ""
    similarity_threshold: float = 0.6
    ctinexus_json_path: str | None = None
    graph_html_path: str | None = None
    triplet_count: int = 0
    entity_count: int = 0
    predicted_link_count: int = 0
    invalid_triplet_count: int = 0
    hallucination_count: int = 0
    generated_at: datetime = Field(default_factory=utcnow)
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeGraphManifest(FlexibleModel):
    run_id: str
    generated_at: datetime = Field(default_factory=utcnow)
    records: list[ItemKnowledgeGraphRecord] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class TripletFeedbackRecord(FlexibleModel):
    run_id: str
    item_id: str
    triplet_index: int
    feedback: KgFeedbackStatus
    comment: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


def coerce_raw_item(item: Any) -> RawIntelItem:
    """Accept intel_agent items, dicts, or already-local RawIntelItem."""
    if isinstance(item, RawIntelItem):
        return item
    if hasattr(item, "model_dump"):
        return RawIntelItem.model_validate(item.model_dump(mode="python"))
    if isinstance(item, dict):
        return RawIntelItem.model_validate(item)
    raise TypeError(f"Cannot coerce {type(item)!r} to RawIntelItem")
