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


PROMPT_VERSION = "v1.0-llm-search-reflection"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LlmRewriteQuery(_StrictModel):
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
    rewrite_reason: str = Field(min_length=1)
    rewrite_action: Literal[
        "broader",
        "narrower",
        "source_specific",
        "corroboration",
        "component_anchored",
        "taxonomy_anchored",
    ]
    expected_gain_dimension: Literal["recall", "precision", "novelty", "balanced"]
    parent_query_run_id: str | None = None
    parent_query_text: str | None = None
    template_name: str | None = None


class LlmSearchReflectionResult(_StrictModel):
    should_retry: bool = False
    stop_reason: str = Field(min_length=1)
    diagnosis: Literal[
        "low_recall",
        "high_noise",
        "source_mismatch",
        "saturated",
        "uncertain",
    ] = "uncertain"
    recommended_actions: list[str] = Field(default_factory=list)
    rewritten_queries: list[LlmRewriteQuery] = Field(default_factory=list)
    expected_gain_dimension: Literal["recall", "precision", "novelty", "balanced"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_summary: str = Field(min_length=1)


_SYSTEM_PROMPT = """\
你是 AI/ML 安全情报系统中的 Search Reflection Agent。你的任务不是抓取数据，而是根据 query telemetry 判断当前检索策略是否应该继续、停止、还是改写。

## 你的角色
- 你是 **query strategy 的主决策者**
- telemetry 是你的观察窗口，不是最终决策器
- 你必须输出结构化 reflection decision

## 核心目标
在 recall、precision、novelty 三者中，判断当前 query 最值得优化的维度，并决定是否发起下一轮 rewrite。

## diagnosis 取值
- low_recall: 结果太少、parsed 太少、novelty 也低，说明 query 太窄或 source coverage 不够
- high_noise: 结果不少，但 parse/novelty 很低，说明 query 太泛或 source 语法不对
- source_mismatch: query 与 source 类型不匹配
- saturated: 当前 source/query 已经接近收益上限，不值得继续反思
- uncertain: 信息不足，保守处理

## rewrite_action 取值
- broader
- narrower
- source_specific
- corroboration
- component_anchored
- taxonomy_anchored

## 决策约束
1. 不要生成空 query 或无意义 query
2. 不要重复已有 query_text
3. rewrite 必须与 diagnosis 一致
4. should_retry=False 时，rewritten_queries 应为空
5. confidence < 0.60 时，通常 should_retry=False 或最多给出单条保守 rewrite
6. 目标是 agentic strategy adaptation，而不是机械阈值判断

只输出 JSON 格式的结构化字段，不输出额外解释。"""

_USER_TEMPLATE = """\
run_mode: {run_mode}
reflection_round: {reflection_round}
max_reflection_rounds: {max_reflection_rounds}

## Source execution summary
{source_summary}

## Query telemetry
{query_telemetry}

## Historical query feedback memory
{query_feedback_memory}

## Source-specific query templates
{source_templates}
"""


class LangChainLlmSearchReflectionAgent:
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
                task_name="reflection",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError(
                "LLM search reflection requested but OPENAI_API_KEY is not configured."
            )

    def reflect(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.is_available():
            raise RuntimeError(
                "LLM search reflection requested but OPENAI_API_KEY is not configured."
            )
        self.last_invocation_meta = {}

        prompt = ChatPromptTemplate.from_messages(
            [("system", _SYSTEM_PROMPT), ("user", _USER_TEMPLATE)]
        )
        invoke_payload = {
            "run_mode": str(payload.get("run_mode", "bootstrap"))[:50],
            "reflection_round": str(payload.get("reflection_round", 0)),
            "max_reflection_rounds": str(payload.get("max_reflection_rounds", 1)),
            "source_summary": str(payload.get("source_summary", ""))[:4000],
            "query_telemetry": str(payload.get("query_telemetry", ""))[:8000],
            "query_feedback_memory": str(payload.get("query_feedback_memory", ""))[
                :4000
            ],
            "source_templates": str(payload.get("source_templates", ""))[:4000],
        }
        result, meta = invoke_structured_with_model_pool(
            task_name="reflection",
            prompt=prompt,
            schema=LlmSearchReflectionResult,
            payload=invoke_payload,
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result
