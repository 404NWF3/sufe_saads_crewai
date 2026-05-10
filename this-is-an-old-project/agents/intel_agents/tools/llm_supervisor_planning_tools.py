from __future__ import annotations

import os
from typing import Literal

from langchain_core.prompts import ChatPromptTemplate
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from .llm_client_factory import (
    invoke_structured_with_model_pool,
    list_available_profile_ids,
    resolve_default_model,
)


PROMPT_VERSION = "v1.0-llm-supervisor-planner"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LlmSourcePlan(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    source_name: str = Field(min_length=1)
    query_text: str = Field(min_length=3)
    query_intent: Literal[
        "broad_recall",
        "precision_probe",
        "weak_signal_probe",
        "evidence_corroboration",
        "source_specific_rewrite",
        "component_anchor",
        "taxonomy_anchor",
    ]
    query_provenance: str = Field(min_length=1)
    rewrite_reason: str | None = None
    priority: float = Field(ge=0.0, le=1.0)
    max_results: int = Field(ge=1, le=50)
    time_window_days: int | None = Field(default=None, ge=1, le=365)
    fetch_mode: Literal[
        "bootstrap",
        "incremental",
        "targeted_gap_fill",
        "weak_signal",
    ] = "bootstrap"


class LlmPlanningResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    rationale: str = Field(default="", validation_alias=AliasChoices("rationale", "reasoning", "explanation"))
    target_taxonomies: list[str] = Field(default_factory=list)
    source_plans: list[LlmSourcePlan] = Field(
        default_factory=list,
        validation_alias=AliasChoices("source_plans", "collection_plan", "plans"),
    )
    max_parallel_sources: int = Field(default=3, ge=1, le=8)
    max_items_per_source: int = Field(default=10, ge=1, le=100)
    max_reflection_rounds: int = Field(default=1, ge=0, le=3)
    reflection_enabled: bool = True
    confidence: float = Field(
        default=0.7, ge=0.0, le=1.0,
        validation_alias=AliasChoices("confidence", "confidence_score"),
    )


_SYSTEM_PROMPT = """\
你是 WP1-1 的 Intel Supervisor Agent。你的任务是为本轮情报采集生成初始 collection plan。

## 你的职责
- 基于 run_mode、coverage snapshot、source quality、query feedback memory 规划一轮采集
- 输出 source-aware、agentic 的初始 query plan
- 你的计划应当为后续 Phase 6 reflection 提供良好起点

## 规划原则
1. 不要为所有 source 机械地给出同质 query
2. 优先让 query intent 与 source type 匹配
3. 如果历史 feedback 显示某类 query 高噪声，避免重复使用相同模式
4. 如果某些 taxonomy coverage 明显不足，应优先纳入 target_taxonomies
5. source_plans 需要可执行，query_text 不能空，priority 要有区分度
6. 结构化/公告源偏 broad_recall 或 precision_probe；社区/讨论源偏 evidence_corroboration
7. 只输出当前 registry 中存在的 source_name
8. 每个 source_name 只能出现一次，不要为同一 source 生成多个 plan

只输出 JSON 格式的结构化字段，不输出额外解释。"""

_USER_TEMPLATE = """\
run_mode: {run_mode}

## Source registry
{source_registry}

## Coverage snapshot
{coverage_snapshot}

## Source quality rows
{source_quality_rows}

## Query feedback memory
{query_feedback_rows}

## Pending queue summary
{pending_queue_summary}
"""


class LangChainLlmSupervisorPlanner:
    PROMPT_VERSION: str = PROMPT_VERSION

    def __init__(
        self,
        *,
        model: str | None = None,
        temperature: float = 0.0,
        base_url: str | None = None,
        api_key: str | None = None,
        runtime_config: dict | None = None,
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
        self.last_invocation_meta: dict[str, str | int | float | list[str] | None] = {}

    def is_available(self) -> bool:
        return bool(
            list_available_profile_ids(
                task_name="planning",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError(
                "LLM supervisor planning requested but OPENAI_API_KEY is not configured."
            )

    def plan(self, payload: dict) -> dict:
        if not self.is_available():
            raise RuntimeError(
                "LLM supervisor planning requested but OPENAI_API_KEY is not configured."
            )
        self.last_invocation_meta = {}

        prompt = ChatPromptTemplate.from_messages(
            [("system", _SYSTEM_PROMPT), ("user", _USER_TEMPLATE)]
        )
        invoke_payload = {
            "run_mode": str(payload.get("run_mode", "bootstrap"))[:50],
            "source_registry": str(payload.get("source_registry", ""))[:4000],
            "coverage_snapshot": str(payload.get("coverage_snapshot", ""))[:4000],
            "source_quality_rows": str(payload.get("source_quality_rows", ""))[:3000],
            "query_feedback_rows": str(payload.get("query_feedback_rows", ""))[:5000],
            "pending_queue_summary": str(payload.get("pending_queue_summary", ""))[
                :1500
            ],
        }
        result, meta = invoke_structured_with_model_pool(
            task_name="planning",
            prompt=prompt,
            schema=LlmPlanningResult,
            payload=invoke_payload,
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result
