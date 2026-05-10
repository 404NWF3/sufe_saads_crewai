from __future__ import annotations

from typing import Any

from ..tools.llm_client_factory import resolve_default_model
from ..tools import LangChainLlmDedupAdjudicator


class DedupAdjudicatorAgent:
    """Second-pass adjudicator for Phase 4 dedup decisions.

    Supports rule-only review and optional/required LLM-backed review.

    LLM-awareness: when the primary merge judge has already been invoked
    (detectable via ``adjudicator_summary.llm_merge_judge``), the adjudicator
    respects high-confidence LLM verdicts and avoids contradicting them
    unless structural signals strongly disagree.
    """

    def __init__(
        self,
        *,
        strategy: str = "rules_only",
        llm_adjudicator: Any | None = None,
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        llm_runtime_config: dict[str, Any] | None = None,
    ) -> None:
        self.strategy = strategy
        self.validate_online = validate_online
        self.llm_runtime_config = llm_runtime_config or {}
        self.llm_model = resolve_default_model(
            llm_model,
            runtime_config=self.llm_runtime_config,
        )
        self.llm_adjudicator = llm_adjudicator or LangChainLlmDedupAdjudicator(
            model=self.llm_model,
            temperature=llm_temperature,
            runtime_config=self.llm_runtime_config,
        )

    def adjudicate(
        self,
        *,
        candidate: dict[str, Any],
        system_decision: dict[str, Any],
        top_k_candidates: list[dict[str, Any]],
        best_signals: dict[str, Any] | None,
    ) -> dict[str, Any]:
        # Detect if LLM merge judge was already involved
        llm_judge_active = self._is_llm_merge_judge_active(system_decision)

        rule_decision = self._rule_adjudicate(
            candidate=candidate,
            system_decision=system_decision,
            top_k_candidates=top_k_candidates,
            best_signals=best_signals,
            llm_judge_active=llm_judge_active,
        )
        if self.strategy == "rules_only":
            return rule_decision

        try:
            if self.validate_online:
                self.llm_adjudicator.validate_connectivity()
            llm_result = self.llm_adjudicator.adjudicate(
                {
                    "candidate_attack_code": candidate.get("attack_code"),
                    "system_decision": system_decision,
                    "top_k_candidates": top_k_candidates,
                    "best_signals": best_signals or {},
                }
            )
        except Exception:
            if self.strategy == "llm_required":
                raise
            return rule_decision

        decision = dict(rule_decision)
        decision["decision"] = llm_result.get("final_decision", decision["decision"])
        if llm_result.get("matched_attack_id"):
            decision["matched_attack_id"] = llm_result["matched_attack_id"]
        decision["reasons"] = [
            *decision.get("reasons", []),
            *llm_result.get("rationale", []),
        ]
        summary = dict(decision.get("adjudicator_summary") or {})
        summary.update(
            {
                "llm_review": True,
                "llm_risk_notes": llm_result.get("risk_notes", []),
                "llm_final_decision": llm_result.get("final_decision"),
            }
        )
        decision["adjudicator_summary"] = summary
        return decision

    @staticmethod
    def _is_llm_merge_judge_active(system_decision: dict[str, Any]) -> bool:
        """Check if the primary LLM merge judge was already invoked."""
        summary = system_decision.get("adjudicator_summary")
        if not isinstance(summary, dict):
            return False
        return bool(summary.get("llm_merge_judge"))

    def _rule_adjudicate(
        self,
        *,
        candidate: dict[str, Any],
        system_decision: dict[str, Any],
        top_k_candidates: list[dict[str, Any]],
        best_signals: dict[str, Any] | None,
        llm_judge_active: bool = False,
    ) -> dict[str, Any]:
        decision = dict(system_decision)
        rationale = list(decision.get("reasons", []))
        semantic_best = top_k_candidates[0] if top_k_candidates else None
        semantic_score = (
            float(semantic_best.get("semantic_score", 0.0)) if semantic_best else 0.0
        )
        rerank_score = (
            float(best_signals.get("rerank_score", 0.0)) if best_signals else 0.0
        )
        taxonomy_overlap = (
            float(best_signals.get("taxonomy_score", 0.0)) if best_signals else 0.0
        )
        bom_overlap = float(best_signals.get("bom_score", 0.0)) if best_signals else 0.0
        bom_delta = (
            bool(best_signals.get("bom_delta_detected", False))
            if best_signals
            else False
        )

        # LLM-awareness: if the merge judge already decided with high
        # confidence, respect it — only override for strong structural
        # reasons (bom_delta blocks merge).
        if llm_judge_active:
            summary = decision.get("adjudicator_summary") or {}
            llm_confidence = float(summary.get("llm_confidence", 0.0))

            if llm_confidence >= 0.85:
                # High confidence LLM merge judge — only override if
                # bom_delta would block a merge.
                if decision["decision"] == "merge" and bom_delta:
                    decision["decision"] = "review"
                    rationale.append("adjudicator_override=bom_delta_blocks_llm_merge")
                else:
                    rationale.append(
                        "adjudicator_defers=llm_merge_judge_high_confidence"
                    )
                decision["reasons"] = rationale
                decision["adjudicator_summary"] = {
                    **(decision.get("adjudicator_summary") or {}),
                    "semantic_top_k": top_k_candidates,
                    "semantic_best_score": semantic_score,
                    "rerank_score": rerank_score,
                    "taxonomy_overlap": taxonomy_overlap,
                    "bom_overlap": bom_overlap,
                    "bom_delta": bom_delta,
                    "llm_review": False,
                    "llm_judge_deferred": True,
                }
                return decision

        # Standard rule adjudication (original logic)
        if decision["decision"] == "merge" and bom_delta:
            decision["decision"] = "review"
            rationale.append("adjudicator_override=bom_delta_blocks_merge")

        if (
            decision["decision"] == "new"
            and semantic_best is not None
            and semantic_score >= 0.82
            and rerank_score >= 0.75
            and not bom_delta
        ):
            decision["decision"] = "merge"
            decision["matched_attack_id"] = semantic_best.get("stable_attack_id")
            rationale.append("adjudicator_override=semantic_and_rerank_support_merge")

        if (
            decision["decision"] == "merge"
            and semantic_score < 0.45
            and taxonomy_overlap < 0.3
            and bom_overlap < 0.3
        ):
            decision["decision"] = "review"
            rationale.append("adjudicator_override=weak_structural_support_for_merge")

        if (
            decision["decision"] == "review"
            and semantic_score < 0.35
            and rerank_score < 0.45
        ):
            decision["decision"] = "new"
            rationale.append("adjudicator_override=insufficient_evidence_for_review")

        decision["reasons"] = rationale
        decision["adjudicator_summary"] = {
            "semantic_top_k": top_k_candidates,
            "semantic_best_score": semantic_score,
            "rerank_score": rerank_score,
            "taxonomy_overlap": taxonomy_overlap,
            "bom_overlap": bom_overlap,
            "bom_delta": bom_delta,
            "llm_review": False,
        }
        return decision
