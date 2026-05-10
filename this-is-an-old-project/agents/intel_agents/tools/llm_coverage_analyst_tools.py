from __future__ import annotations

import os
from typing import Any, Literal

from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, ConfigDict, Field

from .llm_client_factory import (
    invoke_structured_with_model_pool,
    list_available_profile_ids,
    resolve_default_model,
)


PROMPT_VERSION = "v1.0-llm-coverage-analyst"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LlmCoverageGapDecision(_StrictModel):
    should_dispatch_gap_fill: bool = False
    gap_type: Literal[
        "taxonomy",
        "component_family",
        "vendor_model",
        "corroboration",
        "source_diversity",
        "uncertain",
    ] = "uncertain"
    diagnosis: str = Field(min_length=1)
    recommended_sources: list[str] = Field(default_factory=list)
    recommended_queries: list[str] = Field(default_factory=list)
    recommended_query_intents: list[str] = Field(default_factory=list)
    expected_evidence_type: list[str] = Field(default_factory=list)
    recommended_time_window_days: int = Field(default=14, ge=1, le=365)
    estimated_gap_fill_roi: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)


_SYSTEM_PROMPT = "你是 WP1-1 的 CoverageAnalystAgent。不要重新计算 gap 数值；只根据给定 gap candidate 决定是否值得 gap fill、应该用哪些 source、哪些 query intent、哪些 queries。taxonomy gap 偏 taxonomy_anchor / broad_recall；source diversity 或 corroboration gap 偏 evidence_corroboration；component 或 vendor/model gap 偏 component_anchor / precision_probe。只输出 JSON 格式的结构化字段。"
_USER_TEMPLATE = "## Gap candidate\n{gap_candidate}\n\n## Source registry\n{source_registry}\n\n## Source quality rows\n{source_quality_rows}\n\n## Query feedback rows\n{query_feedback_rows}\n\n## Recent attacks summary\n{recent_attacks_summary}\n"


class LangChainLlmCoverageAnalyst:
    PROMPT_VERSION: str = PROMPT_VERSION

    def __init__(
        self,
        *,
        model: str | None = None,
        temperature: float = 0.0,
        base_url: str | None = None,
        api_key: str | None = None,
        runtime_config: dict[str, Any] | None = None,
    ) -> None:
        self.runtime_config = runtime_config or {}
        self.model = resolve_default_model(
            model,
            runtime_config=self.runtime_config,
        )
        self.temperature = temperature
        self.base_url = (
            base_url or os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
        )
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.last_invocation_meta: dict[str, Any] = {}

    def is_available(self) -> bool:
        return bool(
            list_available_profile_ids(
                task_name="coverage",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError(
                "LLM coverage analyst requested but OPENAI_API_KEY is not configured."
            )

    def analyze(self, payload: dict) -> dict:
        if not self.is_available():
            raise RuntimeError(
                "LLM coverage analyst requested but OPENAI_API_KEY is not configured."
            )
        self.last_invocation_meta = {}
        prompt = ChatPromptTemplate.from_messages(
            [("system", _SYSTEM_PROMPT), ("user", _USER_TEMPLATE)]
        )
        invoke_payload = {
            "gap_candidate": str(payload.get("gap_candidate", ""))[:4000],
            "source_registry": str(payload.get("source_registry", ""))[:3000],
            "source_quality_rows": str(payload.get("source_quality_rows", ""))[:3000],
            "query_feedback_rows": str(payload.get("query_feedback_rows", ""))[:4000],
            "recent_attacks_summary": str(payload.get("recent_attacks_summary", ""))[
                :4000
            ],
        }
        result, meta = invoke_structured_with_model_pool(
            task_name="coverage",
            prompt=prompt,
            schema=LlmCoverageGapDecision,
            payload=invoke_payload,
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result
