from __future__ import annotations

import os
from typing import Any

from langchain_core.prompts import ChatPromptTemplate

from ..schemas.intel import BomResolutionReviewDTO
from .llm_client_factory import (
    invoke_structured_with_model_pool,
    list_available_profile_ids,
    resolve_default_model,
)

PROMPT_VERSION = "v1.0-llm-bom-review"

_SYSTEM_PROMPT = """\
You are an AI BOM resolution reviewer.

Your job is to review a previously generated component-resolution result.
Do not re-extract from scratch. Critique the proposed resolution based on:
1. evidence sufficiency
2. vendor consistency
3. version stability
4. candidate ambiguity
5. whether the selected component is actually supported by the evidence

Decision policy:
- accept: evidence is sufficient and the selected component is credible
- review_queue: evidence is insufficient, ambiguous, or conflicting
- revise: another listed candidate is clearly better and you can name it safely

Requirements:
- Base all judgments on the provided evidence and candidate list
- Do not guess
- Keep reasons concise and factual
- Return a calibrated `confidence`
- Return a visible `review_trace` with 2-4 short grounded steps
- Only provide component_suggestion when decision=revise and the replacement is clearly justified
- Return structured JSON only
"""

_USER_TEMPLATE = """\
attack_name: {attack_name}
attack_family: {attack_family}
attack_summary: {attack_summary}

resolution_json:
{resolution_json}

candidate_list_json:
{candidate_list_json}

evidence_text:
{evidence_text}
"""


class LangChainLlmBomReviewer:
    PROMPT_VERSION = PROMPT_VERSION

    def __init__(
        self,
        *,
        model: str | None = None,
        temperature: float = 0.0,
        runtime_config: dict[str, Any] | None = None,
    ) -> None:
        self.runtime_config = runtime_config or {}
        self.model = resolve_default_model(model, runtime_config=self.runtime_config)
        self.temperature = temperature
        self.base_url = (
            os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
        )
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.last_invocation_meta: dict[str, Any] = {}

    def is_available(self) -> bool:
        return bool(
            list_available_profile_ids(
                task_name="bom_review",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError("LLM BOM review requested but no profile is available.")

    def review(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.is_available():
            raise RuntimeError("LLM BOM review requested but no profile is available.")
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", _SYSTEM_PROMPT),
                ("user", _USER_TEMPLATE),
            ]
        )
        result, meta = invoke_structured_with_model_pool(
            task_name="bom_review",
            prompt=prompt,
            schema=BomResolutionReviewDTO,
            payload={
                "attack_name": str(payload.get("attack_name", ""))[:200],
                "attack_family": str(payload.get("attack_family", ""))[:100],
                "attack_summary": str(payload.get("attack_summary", ""))[:500],
                "resolution_json": str(payload.get("resolution_json", ""))[:4000],
                "candidate_list_json": str(payload.get("candidate_list_json", ""))[:4000],
                "evidence_text": str(payload.get("evidence_text", ""))[:2500],
            },
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result
