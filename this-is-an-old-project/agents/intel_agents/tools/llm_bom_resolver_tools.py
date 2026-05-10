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


PROMPT_VERSION = "v1.1-llm-bom-resolver"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LlmSelectedComponent(_StrictModel):
    component_code: str | None = None
    component_name: str = Field(min_length=1)
    component_layer: Literal[
        "vendor_platform",
        "model_family",
        "framework",
        "plugin",
        "runtime",
        "vector_stack",
        "unknown",
    ] = "unknown"
    vendor_name: str | None = None


class LlmBomResolutionResult(_StrictModel):
    selected_component: LlmSelectedComponent | None = None
    version_constraint_raw: str | None = None
    normalized_version_constraint: str | None = None
    decision: Literal["accept", "review_queue", "no_match"] = "review_queue"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_quotes: list[str] = Field(default_factory=list)
    reasoning_summary: str = Field(min_length=1)
    reasoning_trace: list[str] = Field(default_factory=list)
    candidate_ranking: list[str] = Field(
        default_factory=list,
        description="Ordered list of candidate component_codes considered, best first.",
    )


_SYSTEM_PROMPT = """\
You are the primary AI BOM resolver for a security-intelligence pipeline.

Your task is to map one attacked AI/ML component mention to the best component
candidate from a controlled catalog.

Think carefully before answering, but do not expose hidden chain-of-thought.
Instead, express your reasoning through:
- a concise `reasoning_summary`
- a short visible `reasoning_trace` with 3-5 grounded steps
- grounded `evidence_quotes`
- a calibrated `decision`

Core rules:
1. Evidence first. Select a component only when the evidence text supports it.
2. No guessing. If the candidates do not support a reliable match, use `no_match`.
3. Treat vendor mismatch as a major risk.
4. Extract and normalize version constraints only when the evidence supports them.
5. Prefer exact or alias matches over fuzzy matches when the evidence is otherwise similar.
6. If the top candidates are close or the mention is vague, use `review_queue`.
7. `candidate_ranking` must reflect the candidates you actually considered.
8. `evidence_quotes` must be short excerpts from the provided evidence text.
9. `reasoning_trace` must be explicit, concise, and evidence-grounded.
10. Do not include hidden reasoning, only visible audit-safe steps.

Decision rubric:
- `accept`: clear evidence, credible candidate, no major ambiguity
- `review_queue`: some support exists, but ambiguity or conflict remains
- `no_match`: no candidate is reliably supported

Version normalization:
- before / prior to X.Y.Z -> <X.Y.Z
- up to / through X.Y.Z -> <=X.Y.Z
- after / later than X.Y.Z -> >X.Y.Z
- at least / from X.Y.Z -> >=X.Y.Z
- plain version X.Y.Z -> ==X.Y.Z

Return structured JSON only.
"""

_USER_TEMPLATE = """\
attack_name: {attack_name}
attack_family: {attack_family}
attack_summary: {attack_summary}

current_mention:
- mentioned_name: {mentioned_name}
- mentioned_vendor: {mentioned_vendor}
- mentioned_version: {mentioned_version}
- component_layer_hint: {component_layer_hint}

candidate_list:
{candidate_list}

evidence_text:
{evidence_text}
"""


class LangChainLlmBomResolver:
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
                task_name="bom_resolution",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError(
                "LLM BOM resolution requested but OPENAI_API_KEY is not configured."
            )

    def resolve(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.is_available():
            raise RuntimeError(
                "LLM BOM resolution requested but OPENAI_API_KEY is not configured."
            )
        self.last_invocation_meta = {}

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", _SYSTEM_PROMPT),
                ("user", _USER_TEMPLATE),
            ]
        )

        invoke_payload = {
            "attack_name": str(payload.get("attack_name", ""))[:200],
            "attack_family": str(payload.get("attack_family", ""))[:100],
            "attack_summary": str(payload.get("attack_summary", ""))[:500],
            "mentioned_name": str(payload.get("mentioned_name", "")),
            "mentioned_vendor": str(payload.get("mentioned_vendor", "") or "unknown"),
            "mentioned_version": str(
                payload.get("mentioned_version", "") or "unspecified"
            ),
            "component_layer_hint": str(
                payload.get("component_layer_hint", "") or "unknown"
            ),
            "candidate_list": str(payload.get("candidate_list", ""))[:3000],
            "evidence_text": str(payload.get("evidence_text", ""))[:2000],
        }
        result, meta = invoke_structured_with_model_pool(
            task_name="bom_resolution",
            prompt=prompt,
            schema=LlmBomResolutionResult,
            payload=invoke_payload,
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result

    @staticmethod
    def format_candidate_list(candidates: list[dict[str, Any]]) -> str:
        if not candidates:
            return "(no candidates retrieved)"
        lines: list[str] = []
        for idx, candidate in enumerate(candidates, 1):
            code = candidate.get("component_code") or "N/A"
            name = candidate.get("component_name", "?")
            vendor = candidate.get("vendor_name") or "unknown"
            layer = candidate.get("component_type") or "unknown"
            mode = candidate.get("match_mode", "?")
            score = candidate.get("final_score", 0.0)
            aliases = ", ".join(candidate.get("aliases", [])[:5]) or "none"
            modality = candidate.get("component_modality") or "unknown"
            lines.append(
                f"{idx}. [{code}] {name} (vendor={vendor}, layer={layer}, "
                f"modality={modality}, match={mode}, score={score:.3f}, "
                f"aliases=[{aliases}])"
            )
        return "\n".join(lines)
