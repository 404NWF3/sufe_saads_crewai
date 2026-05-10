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


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LlmDedupAdjudicationResult(_StrictModel):
    final_decision: Literal["new", "merge", "review"]
    matched_attack_id: str | None = None
    rationale: list[str] = Field(default_factory=list)
    risk_notes: list[str] = Field(default_factory=list)


class LangChainLlmDedupAdjudicator:
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
                task_name="dedup_adjudication",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError(
                "LLM dedup adjudication requested but OPENAI_API_KEY is not configured."
            )

    def adjudicate(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.validate_connectivity()
        self.last_invocation_meta = {}
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是去重审查专家。你不负责召回，只负责审查系统对 new/merge/review 的判断。"
                    "如果语义相似高但 BOM 差异显著，优先 review。"
                    "如果 semantic/rerank/taxonomy 支持强且无明显 BOM 冲突，可 merge。"
                    "输出结构化结果，不要输出多余解释。",
                ),
                (
                    "user",
                    "candidate_attack_code={candidate_attack_code}\n"
                    "system_decision={system_decision}\n"
                    "top_k_candidates={top_k_candidates}\n"
                    "best_signals={best_signals}\n",
                ),
            ]
        )
        result, meta = invoke_structured_with_model_pool(
            task_name="dedup_adjudication",
            prompt=prompt,
            schema=LlmDedupAdjudicationResult,
            payload=payload,
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result
