from __future__ import annotations

import os
from typing import Any, Literal

from langchain_core.prompts import ChatPromptTemplate
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from .llm_client_factory import (
    invoke_structured_with_model_pool,
    list_available_profile_ids,
    resolve_default_model,
)


# ---------------------------------------------------------------------------
# Prompt version -- bump when system message or schema changes meaningfully
# ---------------------------------------------------------------------------
PROMPT_VERSION = "v1.0-llm-merge-judge"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Structured output models (LLM returns these)
# ---------------------------------------------------------------------------


class LlmMergeJudgment(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    """Full structured output of the LLM merge judge.

    The LLM receives a candidate item, the best matching existing stable
    record, and supporting signals (taxonomy/CVE/BOM overlap, rerank scores,
    evidence snippets).  It must determine whether the candidate describes the
    *same attack* as the existing record, a *different attack*, or the
    *same attack but with a significant BOM / component delta*.

    The ``recommended_action`` tells the fusion layer what to do — but the
    final decision is made by a fusion function that reconciles the LLM verdict
    with the rule-based prior.
    """

    verdict: Literal[
        "same_attack",
        "different_attack",
        "same_attack_but_component_delta",
        "uncertain",
    ] = "uncertain"
    recommended_action: Literal["merge", "new", "review"] = "review"
    explanation: str = Field(
        min_length=1,
        validation_alias=AliasChoices("explanation", "reasoning"),
        description="Brief explanation of why this verdict was reached.",
    )
    risk_notes: list[str] = Field(
        default_factory=list,
        description="Any risk or ambiguity notes the judge wants to flag.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices("confidence", "confidence_score"),
        description="Judge confidence in the verdict (0=random guess, 1=certain).",
    )
    evidence_quotes: list[str] = Field(
        default_factory=list,
        description="Short quotes from candidate or stable record supporting the verdict.",
    )


# ---------------------------------------------------------------------------
# System prompt -- v1.0 LLM merge judge (Chinese)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
你是 AI/ML 安全攻击情报的去重合并判官。你不负责召回 (retrieval)，只负责在已召回的\
候选对中做最终判断：当前待入库的攻击条目 (candidate) 和已有稳定记录 (existing) 是否\
描述同一个攻击事件/攻击模式。

## 核心判断标准

### verdict 取值
- **same_attack**: 两者描述的是同一攻击事件或同一攻击模式，BOM/组件覆盖一致或差异\
  可以忽略。应 merge。
- **different_attack**: 两者描述的是不同攻击事件或不同攻击模式。应 new。
- **same_attack_but_component_delta**: 攻击描述高度相似，但涉及的 BOM 组件/框架/\
  平台有显著差异（如一个针对 LangChain，另一个针对 LlamaIndex）。这种情况需要\
  人工审核 (review)，因为它可能是：(a) 同一攻击影响多个组件——应 merge 并扩展 BOM；\
  (b) 本质上不同的攻击但描述相似——应 new。
- **uncertain**: 无法确定。应 review。

### recommended_action 取值
- **merge**: 建议合并到已有稳定记录。
- **new**: 建议作为全新攻击入库。
- **review**: 建议人工审核。

## 判断依据优先级
1. **攻击描述语义**：canonical_name、summary、description 是否描述相同行为/漏洞
2. **分类信息 (taxonomy)**：OWASP/MITRE/CWE 分类是否一致
3. **CVE 关联**：是否引用相同 CVE ID
4. **BOM 组件覆盖**：涉及的框架/模型/平台是否一致
5. **证据来源**：来自同一数据源的重复报告 vs 独立验证

## 决策规则
- 如果 taxonomy 一致 + 语义高度相似 + BOM 无显著差异 → same_attack / merge
- 如果 taxonomy 一致 + 语义高度相似 + BOM 有显著差异 → same_attack_but_component_delta / review
- 如果 taxonomy 不同 或 语义差异明显 → different_attack / new
- 如果信息不足以判断 → uncertain / review

## 置信度指引
- >= 0.85: 高置信度判断，verdict 和 action 可直接执行
- 0.60 ~ 0.85: 中等置信度，建议 review 除非 verdict 明确
- < 0.60: 低置信度，必须 review

## evidence_quotes 要求
- 必须提供至少 1 条证据引用
- 引用候选项或已有记录中支持你判断的关键文本片段

只输出 JSON 格式的结构化字段，不输出额外解释。"""

_USER_TEMPLATE = """\
## 候选攻击条目 (candidate)
canonical_name: {candidate_canonical_name}
attack_family: {candidate_attack_family}
summary: {candidate_summary}
description: {candidate_description}
taxonomy_items: {candidate_taxonomy}
bom_mentions: {candidate_bom}
evidence_refs: {candidate_evidence_refs}

## 已有稳定记录 (existing best match)
stable_attack_id: {existing_stable_id}
canonical_name: {existing_canonical_name}
attack_family: {existing_attack_family}
summary: {existing_summary}
description: {existing_description}
taxonomy_items: {existing_taxonomy}
bom_mentions: {existing_bom}
source_coverage: {existing_source_coverage}

## 系统计算的相似度信号
content_hash_match: {content_hash_match}
rerank_score: {rerank_score}
embedding_score: {embedding_score}
taxonomy_overlap: {taxonomy_overlap}
cve_overlap: {cve_overlap}
bom_overlap: {bom_overlap}
bom_delta_detected: {bom_delta_detected}
bom_delta_reasons: {bom_delta_reasons}
overall_score: {overall_score}

## 系统规则先验判断 (rule prior)
rule_prior_decision: {rule_prior_decision}
rule_prior_reasons: {rule_prior_reasons}
"""


# ---------------------------------------------------------------------------
# LangChain LLM Merge Judge
# ---------------------------------------------------------------------------


class LangChainLlmMergeJudge:
    """LLM-primary merge judge for Phase 4 dedup.

    After the retrieval + reranking pipeline produces ranked candidates with
    similarity signals, this judge receives the candidate item and the best
    matched existing stable record, along with all computed signals, and makes
    the final same/different/delta/uncertain verdict.

    The caller (``DedupMergeAgent``) then fuses this LLM verdict with the
    rule-based prior to produce the final decision.

    Callers should check ``is_available()`` and decide whether to fall back
    to rule-only dedup.
    """

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
                task_name="dedup_merge",
                default_model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                runtime_config=self.runtime_config,
            )
        )

    def validate_connectivity(self) -> None:
        if not self.is_available():
            raise RuntimeError(
                "LLM merge judge requested but OPENAI_API_KEY is not configured."
            )

    def judge(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run the LLM merge judgment.

        Parameters
        ----------
        payload : dict
            Must contain keys for both the candidate and existing record,
            plus computed similarity signals.  See ``format_judge_payload``
            for the expected shape.

        Returns
        -------
        dict
            Validated ``LlmMergeJudgment`` dumped as a dict.
        """
        if not self.is_available():
            raise RuntimeError(
                "LLM merge judge requested but OPENAI_API_KEY is not configured."
            )
        self.last_invocation_meta = {}

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", _SYSTEM_PROMPT),
                ("user", _USER_TEMPLATE),
            ]
        )

        invoke_payload = {
            "candidate_canonical_name": str(
                payload.get("candidate_canonical_name", "")
            )[:200],
            "candidate_attack_family": str(payload.get("candidate_attack_family", ""))[
                :100
            ],
            "candidate_summary": str(payload.get("candidate_summary", ""))[:500],
            "candidate_description": str(payload.get("candidate_description", ""))[
                :1500
            ],
            "candidate_taxonomy": str(payload.get("candidate_taxonomy", ""))[:500],
            "candidate_bom": str(payload.get("candidate_bom", ""))[:500],
            "candidate_evidence_refs": str(payload.get("candidate_evidence_refs", ""))[
                :500
            ],
            "existing_stable_id": str(payload.get("existing_stable_id", "")),
            "existing_canonical_name": str(payload.get("existing_canonical_name", ""))[
                :200
            ],
            "existing_attack_family": str(payload.get("existing_attack_family", ""))[
                :100
            ],
            "existing_summary": str(payload.get("existing_summary", ""))[:500],
            "existing_description": str(payload.get("existing_description", ""))[:1500],
            "existing_taxonomy": str(payload.get("existing_taxonomy", ""))[:500],
            "existing_bom": str(payload.get("existing_bom", ""))[:500],
            "existing_source_coverage": str(
                payload.get("existing_source_coverage", "")
            )[:300],
            "content_hash_match": str(payload.get("content_hash_match", False)),
            "rerank_score": str(payload.get("rerank_score", 0.0)),
            "embedding_score": str(payload.get("embedding_score", 0.0)),
            "taxonomy_overlap": str(payload.get("taxonomy_overlap", 0.0)),
            "cve_overlap": str(payload.get("cve_overlap", 0.0)),
            "bom_overlap": str(payload.get("bom_overlap", 0.0)),
            "bom_delta_detected": str(payload.get("bom_delta_detected", False)),
            "bom_delta_reasons": str(payload.get("bom_delta_reasons", [])),
            "overall_score": str(payload.get("overall_score", 0.0)),
            "rule_prior_decision": str(payload.get("rule_prior_decision", "unknown")),
            "rule_prior_reasons": str(payload.get("rule_prior_reasons", [])),
        }
        result, meta = invoke_structured_with_model_pool(
            task_name="dedup_merge",
            prompt=prompt,
            schema=LlmMergeJudgment,
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
    def format_judge_payload(
        candidate: dict[str, Any],
        existing: dict[str, Any],
        best_signals: dict[str, Any],
        rule_prior_decision: str,
        rule_prior_reasons: list[str],
    ) -> dict[str, Any]:
        """Build the payload dict expected by ``judge()``.

        Parameters
        ----------
        candidate : dict
            The incoming candidate item (with dedup_text, taxonomy, bom, etc.).
        existing : dict
            The best-matched existing stable record.
        best_signals : dict
            The scoring row from ``_score_candidate()``.
        rule_prior_decision : str
            The rule-based decision before LLM involvement (new/merge/review).
        rule_prior_reasons : list[str]
            Reasons backing the rule-based prior.

        Returns
        -------
        dict
            Ready to pass to ``judge()``.
        """
        return {
            "candidate_canonical_name": candidate.get("canonical_name", ""),
            "candidate_attack_family": candidate.get("attack_family", ""),
            "candidate_summary": candidate.get("summary", ""),
            "candidate_description": candidate.get("description", ""),
            "candidate_taxonomy": _format_taxonomy(candidate.get("taxonomy_items", [])),
            "candidate_bom": _format_bom(candidate.get("bom_mentions", [])),
            "candidate_evidence_refs": ", ".join(
                candidate.get("evidence_refs", [])[:5]
            ),
            "existing_stable_id": existing.get("stable_attack_id", ""),
            "existing_canonical_name": existing.get("canonical_name", ""),
            "existing_attack_family": existing.get("attack_family", ""),
            "existing_summary": existing.get("summary", ""),
            "existing_description": existing.get("description", ""),
            "existing_taxonomy": _format_taxonomy(existing.get("taxonomy_items", [])),
            "existing_bom": _format_bom(existing.get("bom_mentions", [])),
            "existing_source_coverage": ", ".join(
                existing.get("source_coverage", [])[:5]
            ),
            "content_hash_match": best_signals.get("content_hash_match", False),
            "rerank_score": best_signals.get("rerank_score", 0.0),
            "embedding_score": best_signals.get("embedding_score", 0.0),
            "taxonomy_overlap": best_signals.get("taxonomy_score", 0.0),
            "cve_overlap": best_signals.get("cve_score", 0.0),
            "bom_overlap": best_signals.get("bom_score", 0.0),
            "bom_delta_detected": best_signals.get("bom_delta_detected", False),
            "bom_delta_reasons": best_signals.get("bom_delta_reasons", []),
            "overall_score": best_signals.get("score", 0.0),
            "rule_prior_decision": rule_prior_decision,
            "rule_prior_reasons": rule_prior_reasons,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_taxonomy(items: list[dict[str, Any]]) -> str:
    if not items:
        return "(none)"
    parts: list[str] = []
    for item in items[:10]:
        code = item.get("taxonomy_code", "?")
        name = item.get("taxonomy_name", "")
        primary = " [PRIMARY]" if item.get("is_primary") else ""
        parts.append(f"{code} ({name}){primary}")
    return "; ".join(parts)


def _format_bom(mentions: list[dict[str, Any]]) -> str:
    if not mentions:
        return "(none)"
    parts: list[str] = []
    for mention in mentions[:10]:
        name = mention.get("mentioned_name", "?")
        vendor = mention.get("mentioned_vendor") or "unknown"
        version = mention.get("mentioned_version") or "unspecified"
        parts.append(f"{name} (vendor={vendor}, version={version})")
    return "; ".join(parts)
