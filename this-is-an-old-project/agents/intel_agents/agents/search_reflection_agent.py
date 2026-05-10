from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..schemas.query import (
    LlmSearchReflectionAuditDTO,
    QueryFeedbackRowDTO,
    SearchReflectionDecisionDTO,
)
from ..services.query_feedback_memory import QueryFeedbackMemoryService
from ..services.source_query_template_service import SourceQueryTemplateService
from ..tools.llm_client_factory import resolve_default_model
from ..tools import LangChainLlmSearchReflectionAgent


class SearchReflectionAgent:
    """LLM-primary search reflection agent for Phase 6.

    Reflection strategy:
        - ``rules_only``: deterministic heuristic reflection
        - ``llm_optional``: try LLM, fall back to heuristic with audit
        - ``llm_required``: LLM must succeed
        - ``rules_only_degraded``: explicit degraded rules-only mode
    """

    def __init__(
        self,
        *,
        strategy: str = "rules_only",
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        llm_reflector: Any | None = None,
        feedback_memory: QueryFeedbackMemoryService | None = None,
        template_service: SourceQueryTemplateService | None = None,
        llm_runtime_config: dict[str, Any] | None = None,
    ) -> None:
        self.strategy = strategy
        self.llm_runtime_config = llm_runtime_config or {}
        self.llm_model = resolve_default_model(
            llm_model,
            runtime_config=self.llm_runtime_config,
        )
        self.llm_temperature = llm_temperature
        self.validate_online = validate_online
        self.llm_reflector = llm_reflector or LangChainLlmSearchReflectionAgent(
            model=self.llm_model,
            temperature=llm_temperature,
            runtime_config=self.llm_runtime_config,
        )
        self.feedback_memory = feedback_memory or QueryFeedbackMemoryService()
        self.template_service = template_service or SourceQueryTemplateService()

    def reflect(
        self,
        source_runs: list[dict[str, Any]],
        query_telemetry: list[dict[str, Any]],
        collection_goals: dict[str, Any],
        *,
        query_feedback_rows: list[dict[str, Any]] | None = None,
        source_templates: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        current_round = int(collection_goals.get("reflection_round", 0))
        max_rounds = int(collection_goals.get("max_reflection_rounds", 1))
        invoked_at = datetime.now(timezone.utc).isoformat()

        if current_round >= max_rounds:
            decision = SearchReflectionDecisionDTO(
                should_retry=False,
                stop_reason="reflection_budget_exhausted",
                diagnosis="saturated",
                recommended_actions=["stop_reflection"],
                rewritten_queries=[],
                expected_gain_dimension="balanced",
                confidence=1.0,
                evidence_summary="Reflection budget exhausted; stop further query rewrites.",
                fallback_reason=None,
            ).model_dump(mode="python")
            audit = self._build_audit(
                decision,
                strategy_executed="budget_stop",
                invoked_at=invoked_at,
                fallback_reason=None,
                current_round=current_round,
            )
            feedback = self._build_feedback_rows(query_telemetry, decision, [])
            return decision, audit, feedback

        if self.strategy in ("rules_only", "rules_only_degraded"):
            decision = self._heuristic_reflect(query_telemetry)
            audit = self._build_audit(
                decision,
                strategy_executed=self.strategy,
                invoked_at=invoked_at,
                fallback_reason=(
                    "explicit_rules_only_degraded"
                    if self.strategy == "rules_only_degraded"
                    else None
                ),
                current_round=current_round,
            )
            feedback = self._build_feedback_rows(
                query_telemetry,
                decision,
                self._derive_feedback_diagnostics(query_telemetry, decision),
            )
            return decision, audit, feedback

        try:
            if self.validate_online:
                self.llm_reflector.validate_connectivity()
            recent_feedback = self.feedback_memory.load_recent_feedback(
                query_feedback_rows
            )
            templates = source_templates or self.template_service.get_templates(
                [row.get("source_name", "unknown") for row in query_telemetry]
            )
            payload = {
                "run_mode": collection_goals.get("run_mode", "bootstrap"),
                "reflection_round": current_round,
                "max_reflection_rounds": max_rounds,
                "source_summary": self._format_source_runs(source_runs),
                "query_telemetry": self._format_query_telemetry(query_telemetry),
                "query_feedback_memory": recent_feedback,
                "source_templates": templates,
            }
            decision = SearchReflectionDecisionDTO.model_validate(
                self.llm_reflector.reflect(payload)
            ).model_dump(mode="python")
            llm_meta = dict(
                getattr(self.llm_reflector, "last_invocation_meta", {}) or {}
            )
            decision = self._constrain_decision(decision, query_telemetry)
            feedback_diagnostics = self._derive_feedback_diagnostics(
                query_telemetry,
                decision,
            )
            audit = self._build_audit(
                decision,
                strategy_executed="llm_primary",
                invoked_at=invoked_at,
                fallback_reason=None,
                current_round=current_round,
                llm_meta=llm_meta,
            )
            feedback = self._build_feedback_rows(
                query_telemetry,
                decision,
                feedback_diagnostics,
            )
            return decision, audit, feedback
        except Exception as exc:
            if self.strategy == "llm_required":
                raise RuntimeError(
                    f"LLM search reflection required but failed: {exc}"
                ) from exc
            decision = self._heuristic_reflect(query_telemetry)
            decision["fallback_reason"] = str(exc)
            audit = self._build_audit(
                decision,
                strategy_executed="rules_only_degraded",
                invoked_at=invoked_at,
                fallback_reason=str(exc),
                current_round=current_round,
            )
            feedback = self._build_feedback_rows(
                query_telemetry,
                decision,
                self._derive_feedback_diagnostics(query_telemetry, decision),
            )
            return decision, audit, feedback

    def _heuristic_reflect(
        self,
        query_telemetry: list[dict[str, Any]],
    ) -> dict[str, Any]:
        rewrites: list[dict[str, Any]] = []
        diagnosis = "saturated"
        recommended_actions = ["stop_reflection"]
        evidence_parts: list[str] = []
        for telemetry in query_telemetry:
            low_yield = (
                telemetry.get("result_count", 0) <= 0
                or telemetry.get("novelty_yield", 0.0) < 0.2
            )
            high_noise = telemetry.get("noise_ratio", 0.0) > 0.6
            source_mismatch = telemetry.get("source_mismatch", False)
            if source_mismatch:
                diagnosis = "source_mismatch"
                recommended_actions = ["switch_source_template", "retry_once"]
                rewrites.append(
                    {
                        "source_name": telemetry.get("source_name", "unknown"),
                        "query_text": f"{telemetry.get('query_text', '').strip()} source-specific",
                        "query_intent": "source_specific_rewrite",
                        "rewrite_reason": "source_mismatch",
                        "rewrite_action": "source_specific",
                        "expected_gain_dimension": "precision",
                        "parent_query_run_id": telemetry.get("query_run_id"),
                        "parent_query_text": telemetry.get("query_text"),
                        "template_name": "heuristic_source_specific",
                    }
                )
                evidence_parts.append(
                    f"{telemetry.get('source_name')}: source mismatch detected"
                )
            elif high_noise:
                diagnosis = "high_noise"
                recommended_actions = ["narrow_query", "retry_once"]
                rewrites.append(
                    {
                        "source_name": telemetry.get("source_name", "unknown"),
                        "query_text": f"{telemetry.get('query_text', '').strip()} exploit OR vulnerability",
                        "query_intent": "precision_probe",
                        "rewrite_reason": "high_noise",
                        "rewrite_action": "narrower",
                        "expected_gain_dimension": "precision",
                        "parent_query_run_id": telemetry.get("query_run_id"),
                        "parent_query_text": telemetry.get("query_text"),
                        "template_name": "heuristic_precision_probe",
                    }
                )
                evidence_parts.append(
                    f"{telemetry.get('source_name')}: high noise ratio {telemetry.get('noise_ratio', 0.0)}"
                )
            elif low_yield:
                diagnosis = "low_recall"
                recommended_actions = ["broaden_query", "retry_once"]
                rewrites.append(
                    {
                        "source_name": telemetry.get("source_name", "unknown"),
                        "query_text": f"{telemetry.get('query_text', '').strip()} ai security",
                        "query_intent": "broad_recall",
                        "rewrite_reason": "low_yield",
                        "rewrite_action": "broader",
                        "expected_gain_dimension": "recall",
                        "parent_query_run_id": telemetry.get("query_run_id"),
                        "parent_query_text": telemetry.get("query_text"),
                        "template_name": "heuristic_broad_recall",
                    }
                )
                evidence_parts.append(
                    f"{telemetry.get('source_name')}: low yield with result_count={telemetry.get('result_count', 0)}"
                )

        should_retry = bool(rewrites)
        if not should_retry:
            diagnosis = "saturated"
            recommended_actions = ["stop_reflection"]
            evidence_parts.append(
                "No telemetry pattern justified another rewrite round."
            )

        return SearchReflectionDecisionDTO(
            should_retry=should_retry,
            stop_reason=(
                "reflection_rewrite_generated" if should_retry else "no_rewrite_needed"
            ),
            diagnosis=diagnosis,
            recommended_actions=recommended_actions,
            rewritten_queries=rewrites,
            expected_gain_dimension=(
                rewrites[0]["expected_gain_dimension"] if rewrites else "balanced"
            ),
            confidence=0.65 if should_retry else 0.9,
            evidence_summary="; ".join(evidence_parts),
            fallback_reason=None,
        ).model_dump(mode="python")

    def _constrain_decision(
        self,
        decision: dict[str, Any],
        query_telemetry: list[dict[str, Any]],
    ) -> dict[str, Any]:
        seen_queries = {
            str(row.get("query_text", "")).strip().lower()
            for row in query_telemetry
            if row.get("query_text")
        }
        valid_source_names = {
            str(row.get("source_name", "unknown")) for row in query_telemetry
        }
        rewritten: list[dict[str, Any]] = []
        for entry in decision.get("rewritten_queries", []):
            source_name = str(entry.get("source_name", "unknown"))
            query_text = str(entry.get("query_text", "")).strip()
            if source_name not in valid_source_names:
                continue
            if len(query_text) < 3:
                continue
            if query_text.lower() in seen_queries:
                continue
            rewritten.append(entry)
        decision["rewritten_queries"] = rewritten
        if not rewritten:
            decision["should_retry"] = False
            decision["stop_reason"] = "guardrails_removed_invalid_rewrites"
            actions = [
                item
                for item in decision.get("recommended_actions", [])
                if item != "retry_once"
            ]
            decision["recommended_actions"] = actions or ["stop_reflection"]
        return SearchReflectionDecisionDTO.model_validate(decision).model_dump(
            mode="python"
        )

    def _build_audit(
        self,
        decision: dict[str, Any],
        *,
        strategy_executed: str,
        invoked_at: str,
        fallback_reason: str | None,
        current_round: int,
        llm_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        llm_meta = llm_meta or {}
        return LlmSearchReflectionAuditDTO(
            reflection_round=current_round,
            strategy_requested=self.strategy,
            strategy_executed=strategy_executed,
            llm_model=str(llm_meta.get("llm_model", self.llm_model)),
            llm_profile_id=llm_meta.get("profile_id"),
            llm_profile=llm_meta.get("profile"),
            prompt_version=getattr(self.llm_reflector, "PROMPT_VERSION", "rules-only"),
            should_retry=bool(decision.get("should_retry", False)),
            stop_reason=str(decision.get("stop_reason", "unknown")),
            diagnosis=str(decision.get("diagnosis", "uncertain")),
            expected_gain_dimension=str(
                decision.get("expected_gain_dimension", "balanced")
            ),
            confidence=float(decision.get("confidence", 0.0)),
            rewritten_query_count=len(decision.get("rewritten_queries", [])),
            rewritten_sources=[
                str(item.get("source_name", "unknown"))
                for item in decision.get("rewritten_queries", [])
            ],
            evidence_summary=str(decision.get("evidence_summary", "no evidence")),
            fallback_reason=fallback_reason,
            llm_wait_seconds=llm_meta.get("wait_seconds"),
            attempted_profiles=list(llm_meta.get("attempted_profiles", []) or []),
            attempted_profile_labels=list(
                llm_meta.get("attempted_profile_labels", []) or []
            ),
            invoked_at=invoked_at,
        ).model_dump(mode="python")

    def _build_feedback_rows(
        self,
        query_telemetry: list[dict[str, Any]],
        decision: dict[str, Any],
        feedback_diagnostics: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        action_map = {
            str(item.get("parent_query_run_id", "")): str(
                item.get("rewrite_action", "")
            )
            for item in decision.get("rewritten_queries", [])
        }
        diagnostic_map = {
            str(item.get("query_run_id", "")): item for item in feedback_diagnostics
        }
        rows: list[dict[str, Any]] = []
        for telemetry in query_telemetry:
            query_run_id = str(telemetry.get("query_run_id", "unknown"))
            diagnostic = diagnostic_map.get(query_run_id, {})
            rows.append(
                QueryFeedbackRowDTO(
                    query_run_id=query_run_id,
                    source_name=str(telemetry.get("source_name", "unknown")),
                    query_text=str(telemetry.get("query_text", "unknown")),
                    query_intent=str(telemetry.get("query_intent", "unknown")),
                    rewrite_round=int(telemetry.get("rewrite_round", 0)),
                    result_count=int(telemetry.get("result_count", 0)),
                    parsed_count=int(telemetry.get("parsed_count", 0)),
                    duplicate_count=int(telemetry.get("duplicate_count", 0)),
                    novelty_yield=float(telemetry.get("novelty_yield", 0.0)),
                    noise_ratio=float(telemetry.get("noise_ratio", 0.0)),
                    source_mismatch=bool(telemetry.get("source_mismatch", False)),
                    reflection_diagnosis=str(
                        diagnostic.get(
                            "diagnosis", decision.get("diagnosis", "uncertain")
                        )
                    ),
                    reflection_action=action_map.get(query_run_id),
                    should_retry=bool(
                        diagnostic.get(
                            "should_retry", decision.get("should_retry", False)
                        )
                    ),
                    expected_gain_dimension=str(
                        diagnostic.get(
                            "expected_gain_dimension",
                            decision.get("expected_gain_dimension", "balanced"),
                        )
                    ),
                    llm_confidence=float(decision.get("confidence", 0.0)),
                ).model_dump(mode="python")
            )
        return rows

    def _derive_feedback_diagnostics(
        self,
        query_telemetry: list[dict[str, Any]],
        decision: dict[str, Any],
    ) -> list[dict[str, Any]]:
        rewrite_map = {
            str(item.get("parent_query_run_id", "")): item
            for item in decision.get("rewritten_queries", [])
        }
        diagnostics: list[dict[str, Any]] = []
        for telemetry in query_telemetry:
            query_run_id = str(telemetry.get("query_run_id", ""))
            low_yield = (
                telemetry.get("result_count", 0) <= 0
                or telemetry.get("novelty_yield", 0.0) < 0.2
            )
            high_noise = telemetry.get("noise_ratio", 0.0) > 0.6
            source_mismatch = bool(telemetry.get("source_mismatch", False))
            rewrite = rewrite_map.get(query_run_id)
            if rewrite:
                diagnosis = {
                    "source_specific": "source_mismatch",
                    "narrower": "high_noise",
                    "broader": "low_recall",
                    "corroboration": "uncertain",
                    "component_anchored": "uncertain",
                    "taxonomy_anchored": "uncertain",
                }.get(
                    str(rewrite.get("rewrite_action", "")),
                    str(decision.get("diagnosis", "uncertain")),
                )
                expected_gain_dimension = str(
                    rewrite.get(
                        "expected_gain_dimension",
                        decision.get("expected_gain_dimension", "balanced"),
                    )
                )
                should_retry = True
            elif source_mismatch:
                diagnosis = "source_mismatch"
                expected_gain_dimension = "precision"
                should_retry = bool(decision.get("should_retry", False))
            elif high_noise:
                diagnosis = "high_noise"
                expected_gain_dimension = "precision"
                should_retry = bool(decision.get("should_retry", False))
            elif low_yield:
                diagnosis = "low_recall"
                expected_gain_dimension = "recall"
                should_retry = bool(decision.get("should_retry", False))
            else:
                diagnosis = "saturated"
                expected_gain_dimension = "balanced"
                should_retry = False
            diagnostics.append(
                {
                    "query_run_id": query_run_id,
                    "diagnosis": diagnosis,
                    "expected_gain_dimension": expected_gain_dimension,
                    "should_retry": should_retry,
                }
            )
        return diagnostics

    @staticmethod
    def _format_source_runs(source_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "source_name": row.get("source_name"),
                "success": row.get("success"),
                "item_count": row.get("item_count"),
                "latency_ms": row.get("latency_ms"),
                "used_stub": row.get("used_stub"),
                "degraded_from_live": row.get("degraded_from_live"),
                "error_type": row.get("error_type"),
            }
            for row in source_runs[:20]
        ]

    @staticmethod
    def _format_query_telemetry(
        query_telemetry: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            {
                "query_run_id": row.get("query_run_id"),
                "source_name": row.get("source_name"),
                "query_text": row.get("query_text"),
                "query_intent": row.get("query_intent"),
                "result_count": row.get("result_count"),
                "parsed_count": row.get("parsed_count"),
                "duplicate_count": row.get("duplicate_count"),
                "new_candidate_count": row.get("new_candidate_count"),
                "novelty_yield": row.get("novelty_yield"),
                "noise_ratio": row.get("noise_ratio"),
                "source_mismatch": row.get("source_mismatch"),
                "llm_reflection_hint": row.get("llm_reflection_hint"),
            }
            for row in query_telemetry[:30]
        ]
