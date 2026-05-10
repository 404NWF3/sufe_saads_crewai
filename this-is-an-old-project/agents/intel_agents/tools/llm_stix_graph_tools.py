from __future__ import annotations

import os
from typing import Any

from langchain_core.prompts import ChatPromptTemplate

from ..schemas.intel import StixGraphDraftDTO, StixReviewDecisionDTO
from .llm_client_factory import (
    invoke_structured_with_model_pool,
    list_available_profile_ids,
    resolve_default_model,
)

EXTRACTION_PROMPT_VERSION = "v1.1-stix-graph"
REVIEW_PROMPT_VERSION = "v1.1-stix-review"

_EXTRACTION_SYSTEM_PROMPT = """\
You are a STIX 2.1 graph extraction specialist.

Build a minimal but useful STIX draft graph from the supplied attack evidence.

Think carefully before answering, but do not expose hidden chain-of-thought.
Express your conclusion through the structured graph plus a short visible `reasoning_trace`.

Extraction rules:
1. Produce exactly one primary `attack-pattern`.
2. Produce one `report` object that represents the source intelligence summary.
3. Create additional objects only when the evidence clearly supports them.
4. Allowed non-report object types: `attack-pattern`, `vulnerability`, `indicator`,
   `tool`, `malware`, `course-of-action`, `identity`.
5. Do not invent objects or relationships that are not grounded in evidence.
6. Use temporary `local_ref` values only. Do not fabricate final STIX ids.
7. Prefer a sparse and reliable graph over a large speculative graph.
8. Use `external_references`, `labels`, and `kill_chain_phases` only when supported.
9. `reasoning_trace` must contain 3-5 short audit-safe steps grounded in evidence.

Relationship rules:
- Add a relationship only when the source and target semantics are clear.
- If the evidence is insufficient, omit the relationship.

Return structured JSON only.
"""

_EXTRACTION_USER_TEMPLATE = """\
attack_code: {attack_code}
canonical_name: {canonical_name}
attack_family: {attack_family}
severity_level: {severity_level}
summary: {summary}
description: {description}
taxonomy_json: {taxonomy_json}
cvss_json: {cvss_json}
bom_json: {bom_json}
evidence_text: {evidence_text}
"""

_REVIEW_SYSTEM_PROMPT = """\
You are the critic for a STIX 2.1 draft graph.

Review the proposed graph for reliability, not completeness.

Review checks:
1. Is there exactly one primary `attack-pattern`?
2. Are any objects speculative or unsupported by evidence?
3. Are relationships semantically valid and directionally plausible?
4. Is the graph small, coherent, and usable for downstream execution?
5. Are there obvious duplicate or conflicting objects?
6. Is the graph confidence high enough for automatic publication?

Decision policy:
- `accept` when the graph is credible and minimally sufficient
- `review_queue` when there is overreach, ambiguity, duplication, or invalid structure

Return structured JSON only.
"""

_REVIEW_USER_TEMPLATE = """\
attack_code: {attack_code}
graph_draft_json: {graph_draft_json}
graph_validation_json: {graph_validation_json}
evidence_text: {evidence_text}
"""


class LangChainLlmStixExtractor:
    PROMPT_VERSION = EXTRACTION_PROMPT_VERSION

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
        self.base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.last_invocation_meta: dict[str, Any] = {}

    def is_available(self) -> bool:
        return bool(
            list_available_profile_ids(
                task_name="stix_graph",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def extract(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.is_available():
            raise RuntimeError("LLM STIX extraction requested but no profile is available.")
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", _EXTRACTION_SYSTEM_PROMPT),
                ("user", _EXTRACTION_USER_TEMPLATE),
            ]
        )
        result, meta = invoke_structured_with_model_pool(
            task_name="stix_graph",
            prompt=prompt,
            schema=StixGraphDraftDTO,
            payload={
                "attack_code": str(payload.get("attack_code", "")),
                "canonical_name": str(payload.get("canonical_name", ""))[:200],
                "attack_family": str(payload.get("attack_family", ""))[:80],
                "severity_level": str(payload.get("severity_level", ""))[:20],
                "summary": str(payload.get("summary", ""))[:800],
                "description": str(payload.get("description", ""))[:2500],
                "taxonomy_json": str(payload.get("taxonomy_json", ""))[:2500],
                "cvss_json": str(payload.get("cvss_json", ""))[:1000],
                "bom_json": str(payload.get("bom_json", ""))[:2500],
                "evidence_text": str(payload.get("evidence_text", ""))[:3500],
            },
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result


class LangChainLlmStixReviewer:
    PROMPT_VERSION = REVIEW_PROMPT_VERSION

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
        self.base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.last_invocation_meta: dict[str, Any] = {}

    def is_available(self) -> bool:
        return bool(
            list_available_profile_ids(
                task_name="stix_review",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def review(
        self,
        *,
        attack_code: str,
        graph_draft_json: str,
        graph_validation_json: str,
        evidence_text: str,
    ) -> dict[str, Any]:
        if not self.is_available():
            raise RuntimeError("LLM STIX review requested but no profile is available.")
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", _REVIEW_SYSTEM_PROMPT),
                ("user", _REVIEW_USER_TEMPLATE),
            ]
        )
        result, meta = invoke_structured_with_model_pool(
            task_name="stix_review",
            prompt=prompt,
            schema=StixReviewDecisionDTO,
            payload={
                "attack_code": attack_code,
                "graph_draft_json": graph_draft_json[:5000],
                "graph_validation_json": graph_validation_json[:2500],
                "evidence_text": evidence_text[:2500],
            },
            default_model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key,
            runtime_config=self.runtime_config,
        )
        self.last_invocation_meta = meta
        return result
