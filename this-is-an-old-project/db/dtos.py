from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CollectionTaskCreateDTO(_StrictModel):
    source_name: str = Field(min_length=1)
    task_mode: str = Field(pattern="^(fast|deep)$")
    trigger_type: str = Field(pattern="^(cron|event|manual)$")
    created_by: str = Field(default="system", min_length=1, max_length=80)
    scheduled_at: datetime | None = None
    trace_id: str | None = Field(default=None, max_length=64)


class RawIntelRecordCreateDTO(_StrictModel):
    task_id: str
    source_uri: str = Field(min_length=1)
    title: str | None = None
    content_hash: str = Field(min_length=64, max_length=64)
    raw_format: str = Field(pattern="^(html|json|pdf|rss|text)$")
    payload_uri: str = Field(min_length=1)
    language_code: str | None = Field(default=None, max_length=12)
    relevance_score: float | None = Field(default=None, ge=0.0, le=1.0)
    parser_status: str = Field(default="pending", pattern="^(pending|parsed|failed|skipped)$")
    fetched_at: datetime
    is_deleted: bool = False


class AttackMergeDTO(_StrictModel):
    raw_id: str
    attack_code: str = Field(min_length=1, max_length=40)
    canonical_name: str = Field(min_length=1)
    attack_family: str = Field(min_length=1, max_length=80)
    severity_level: str = Field(pattern="^(info|low|medium|high|critical)$")
    summary: str = Field(min_length=1)
    description: str = Field(min_length=1)
    exploit_preconditions: str | None = None
    impact_scope: str | None = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    stix_type: str | None = Field(default=None, max_length=40)
    stix_payload: dict[str, Any] | None = None
    entry_status: str = Field(default="active", pattern="^(draft|active|deprecated|archived)$")
    evidence_role: str = Field(default="primary", pattern="^(primary|supporting|contradictory)$")
    extractor_name: str = Field(default="parser_agent", min_length=1, max_length=80)
    evidence_snippet: str | None = None


class CvssAssessmentCreateDTO(_StrictModel):
    attack_id: str
    source_raw_id: str | None = None
    cvss_version: str = Field(pattern="^(3\\.0|3\\.1|4\\.0)$")
    vector_string: str | None = Field(default=None, max_length=255)
    base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    temporal_score: float | None = Field(default=None, ge=0.0, le=10.0)
    environmental_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity_label: str = Field(pattern="^(None|Low|Medium|High|Critical)$")
    exploitability_subscore: float | None = Field(default=None, ge=0.0, le=10.0)
    impact_subscore: float | None = Field(default=None, ge=0.0, le=10.0)
    score_origin: str = Field(pattern="^(supplied|calculated|estimated|manual)$")
    score_provider: str | None = Field(default=None, max_length=80)
    confidence_score: float = Field(ge=0.0, le=1.0)
    is_primary: bool = False
    published_at: datetime | None = None
    calculated_at: datetime | None = None


class TaxonomyItemDTO(_StrictModel):
    taxonomy_type: str = Field(pattern="^(OWASP_LLM|CWE|CAPEC|ATTACK)$")
    taxonomy_code: str = Field(min_length=1, max_length=80)
    taxonomy_name: str = Field(min_length=1, max_length=200)
    is_primary: bool = False
    confidence_score: float = Field(ge=0.0, le=1.0)


class ComponentMentionDTO(_StrictModel):
    mentioned_name: str = Field(min_length=1, max_length=160)
    mentioned_vendor: str | None = Field(default=None, max_length=120)
    mentioned_version: str | None = Field(default=None, max_length=80)
    reason_code: str = Field(default="alias_not_found", pattern="^(alias_not_found|version_ambiguous|conflict)$")

