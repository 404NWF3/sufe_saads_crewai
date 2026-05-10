from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, cast

from ..schemas.plan import CollectionPlanDTO, SourceExecutionPlanDTO
from ..schemas.query import LlmPlanningAuditDTO
from ..schemas.runtime import RuntimeContextDTO
from ..tools.llm_client_factory import resolve_default_model
from ..tools import LangChainLlmSupervisorPlanner


class SupervisorAgent:
    """LLM-aware supervisor planner for WP1-1 initial collection plans."""

    def __init__(
        self,
        *,
        strategy: str = "rules_only",
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        planner: Any | None = None,
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
        self.planner = planner or LangChainLlmSupervisorPlanner(
            model=self.llm_model,
            temperature=llm_temperature,
            runtime_config=self.llm_runtime_config,
        )

    def plan_run(
        self,
        runtime_context: dict[str, Any],
        coverage_snapshot: list[dict[str, Any]],
        source_quality_rows: list[dict[str, Any]],
        query_feedback_rows: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        context = RuntimeContextDTO.model_validate(
            {
                **runtime_context,
                "coverage_snapshot": coverage_snapshot,
                "source_quality_rows": source_quality_rows,
                "query_feedback_rows": query_feedback_rows
                or runtime_context.get("query_feedback_rows", []),
            }
        )
        invoked_at = datetime.now(timezone.utc).isoformat()

        if context.run_mode == "gap_fill" and context.gap_fill_dispatch_plans:
            plan = self._apply_plan_limits(context, self._gap_fill_plan(context))
            return plan, self._build_audit(
                plan,
                strategy_executed="gap_fill_dispatch",
                confidence=0.82,
                feedback_rows_used=len(context.query_feedback_rows),
                fallback_reason=None,
                invoked_at=invoked_at,
            )

        if self.strategy in ("rules_only", "rules_only_degraded"):
            plan = self._apply_plan_limits(context, self._heuristic_plan(context))
            return plan, self._build_audit(
                plan,
                strategy_executed=self.strategy,
                confidence=0.72,
                feedback_rows_used=len(context.query_feedback_rows),
                fallback_reason=(
                    "explicit_rules_only_degraded"
                    if self.strategy == "rules_only_degraded"
                    else None
                ),
                invoked_at=invoked_at,
            )

        try:
            if self.validate_online:
                self.planner.validate_connectivity()
            llm_plan = self.planner.plan(
                {
                    "run_mode": context.run_mode,
                    "source_registry": [
                        row.model_dump(mode="python") for row in context.source_registry
                    ],
                    "coverage_snapshot": context.coverage_snapshot,
                    "source_quality_rows": context.source_quality_rows,
                    "query_feedback_rows": context.query_feedback_rows[-20:],
                    "pending_queue_summary": context.pending_queue_summary,
                }
            )
            llm_meta = dict(getattr(self.planner, "last_invocation_meta", {}) or {})
            plan, fusion_fallback_reason = self._fuse_llm_plan(context, llm_plan)
            plan = self._apply_plan_limits(context, plan)
            confidence = float(llm_plan.get("confidence", 0.0))
            return plan, self._build_audit(
                plan,
                strategy_executed=(
                    "rules_only_degraded" if fusion_fallback_reason else "llm_primary"
                ),
                confidence=confidence,
                feedback_rows_used=len(context.query_feedback_rows),
                fallback_reason=fusion_fallback_reason,
                invoked_at=invoked_at,
                llm_meta=llm_meta,
            )
        except Exception as exc:
            if self.strategy == "llm_required":
                raise RuntimeError(
                    f"LLM supervisor planning required but failed: {exc}"
                ) from exc
            plan = self._apply_plan_limits(context, self._heuristic_plan(context))
            return plan, self._build_audit(
                plan,
                strategy_executed="rules_only_degraded",
                confidence=0.68,
                feedback_rows_used=len(context.query_feedback_rows),
                fallback_reason=str(exc),
                invoked_at=invoked_at,
            )

    def _heuristic_plan(self, context: RuntimeContextDTO) -> dict[str, Any]:
        if context.run_mode == "gap_fill" and context.gap_fill_dispatch_plans:
            return self._gap_fill_plan(context)

        feedback_by_source: dict[str, list[dict[str, Any]]] = {}
        for row in context.query_feedback_rows:
            feedback_by_source.setdefault(
                str(row.get("source_name", "unknown")), []
            ).append(row)

        source_plans: list[SourceExecutionPlanDTO] = []
        for rank, source in enumerate(context.source_registry, start=1):
            seed_query = _seed_query_for(source.source_name)
            intent = _default_query_intent_for(source.source_type)
            rewrite_reason = None
            feedback_rows = feedback_by_source.get(source.source_name, [])
            if feedback_rows:
                last_feedback = feedback_rows[-1]
                diagnosis = str(last_feedback.get("reflection_diagnosis") or "")
                last_query = str(last_feedback.get("query_text") or seed_query)
                if diagnosis == "high_noise":
                    seed_query = f"{last_query} exploit OR vulnerability"
                    intent = "precision_probe"
                    rewrite_reason = "feedback_high_noise"
                elif diagnosis == "low_recall":
                    seed_query = f"{last_query} ai security"
                    intent = "broad_recall"
                    rewrite_reason = "feedback_low_recall"
                elif diagnosis == "source_mismatch":
                    seed_query = f"{last_query} source specific"
                    intent = "source_specific_rewrite"
                    rewrite_reason = "feedback_source_mismatch"
            source_plans.append(
                SourceExecutionPlanDTO(
                    source_name=source.source_name,
                    source_type=source.source_type,
                    priority=max(0.1, 1.0 - ((rank - 1) * 0.1)),
                    queries=[seed_query],
                    query_intent=_normalize_query_intent(intent),
                    query_provenance="supervisor_heuristic_seed",
                    rewrite_reason=rewrite_reason,
                    max_results=source.default_max_results,
                    fetch_mode=(
                        "weak_signal"
                        if source.source_type == "community"
                        else "bootstrap"
                    ),
                    time_window_days=source.default_time_window_days,
                )
            )

        target_taxonomies = [
            row.get("taxonomy_code", "OWASP-LLM-UNKNOWN")
            for row in context.coverage_snapshot[:3]
        ] or ["OWASP-LLM-01"]
        return CollectionPlanDTO(
            run_mode=context.run_mode,
            rationale="Supervisor heuristic plan generated from runtime context, source quality, and query feedback memory.",
            target_taxonomies=target_taxonomies,
            source_plans=[item.model_dump(mode="python") for item in source_plans],
            max_parallel_sources=min(4, max(1, len(source_plans))),
            max_items_per_source=10,
            max_reflection_rounds=1,
            reflection_enabled=True,
        ).model_dump(mode="python")

    def _gap_fill_plan(self, context: RuntimeContextDTO) -> dict[str, Any]:
        registry_map = {row.source_name: row for row in context.source_registry}
        source_plans: list[SourceExecutionPlanDTO] = []
        target_taxonomies: list[str] = []
        for dispatch in context.gap_fill_dispatch_plans:
            if not dispatch.get("should_dispatch_gap_fill", True):
                continue
            queries = [
                str(item) for item in dispatch.get("recommended_queries", []) if item
            ]
            if not queries:
                continue
            intents = [
                str(item)
                for item in dispatch.get("recommended_query_intents", [])
                if item
            ]
            query_intent = intents[0] if intents else "taxonomy_anchor"
            for source_name in dispatch.get("recommended_sources", []):
                source = registry_map.get(str(source_name))
                if source is None:
                    continue
                source_plans.append(
                    SourceExecutionPlanDTO(
                        source_name=source.source_name,
                        source_type=source.source_type,
                        priority=float(dispatch.get("dispatch_priority", 0.5)),
                        queries=queries,
                        query_intent=_normalize_query_intent(query_intent),
                        query_provenance="phase7_gap_fill_dispatch",
                        rewrite_reason=str(dispatch.get("gap_id", "gap_fill_dispatch")),
                        max_results=source.default_max_results,
                        fetch_mode="targeted_gap_fill",
                        time_window_days=int(
                            dispatch.get("recommended_time_window_days")
                            or source.default_time_window_days
                        ),
                    )
                )
            gap_id = str(dispatch.get("gap_id", ""))
            tail = gap_id.split("::")[-1].upper() if "::" in gap_id else ""
            if tail.startswith("OWASP-") and tail not in target_taxonomies:
                target_taxonomies.append(tail)

        deduped: list[SourceExecutionPlanDTO] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for row in sorted(
            source_plans,
            key=lambda item: float(item.priority),
            reverse=True,
        ):
            key = (
                str(row.source_name),
                str(row.query_intent),
                tuple(str(item) for item in row.queries),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)

        if not deduped:
            return CollectionPlanDTO(
                run_mode="gap_fill",
                rationale="Gap-fill mode was requested but no executable dispatch plans were available.",
                target_taxonomies=target_taxonomies or ["OWASP-LLM-01"],
                source_plans=[],
                max_parallel_sources=1,
                max_items_per_source=10,
                max_reflection_rounds=0,
                reflection_enabled=False,
            ).model_dump(mode="python")

        return CollectionPlanDTO(
            run_mode="gap_fill",
            rationale="Supervisor heuristic plan generated from Phase 7 targeted gap-fill dispatch plans.",
            target_taxonomies=target_taxonomies[:5] or ["OWASP-LLM-01"],
            source_plans=[item.model_dump(mode="python") for item in deduped],
            max_parallel_sources=min(
                context.coverage_max_gap_fill_plans,
                max(1, len(deduped)),
            ),
            max_items_per_source=max(int(item.max_results) for item in deduped),
            max_reflection_rounds=0,
            reflection_enabled=False,
        ).model_dump(mode="python")

    def _fuse_llm_plan(
        self,
        context: RuntimeContextDTO,
        llm_plan: dict[str, Any],
    ) -> tuple[dict[str, Any], str | None]:
        registry_map = {row.source_name: row for row in context.source_registry}
        source_plans: list[SourceExecutionPlanDTO] = []
        for item in llm_plan.get("source_plans", []):
            source_name = str(item.get("source_name", ""))
            source = registry_map.get(source_name)
            if source is None:
                continue
            source_plans.append(
                SourceExecutionPlanDTO(
                    source_name=source_name,
                    source_type=source.source_type,
                    priority=float(item.get("priority", 0.5)),
                    queries=[str(item.get("query_text", _seed_query_for(source_name)))],
                    query_intent=_normalize_query_intent(
                        item.get(
                            "query_intent",
                            _default_query_intent_for(source.source_type),
                        )
                    ),
                    query_provenance=str(
                        item.get("query_provenance", "llm_supervisor_plan")
                    ),
                    rewrite_reason=item.get("rewrite_reason"),
                    max_results=min(
                        max(
                            1, int(item.get("max_results", source.default_max_results))
                        ),
                        50,
                    ),
                    fetch_mode=item.get(
                        "fetch_mode",
                        "bootstrap",
                    ),
                    time_window_days=item.get("time_window_days")
                    or source.default_time_window_days,
                )
            )

        if not source_plans:
            return self._heuristic_plan(context), "llm_plan_filtered_out"

        # Keep highest-priority plan per source_name (LLM may generate duplicates)
        by_source: dict[str, SourceExecutionPlanDTO] = {}
        for sp in source_plans:
            existing = by_source.get(sp.source_name)
            if existing is None or sp.priority > existing.priority:
                by_source[sp.source_name] = sp
        source_plans = list(by_source.values())

        return (
            CollectionPlanDTO(
                run_mode=context.run_mode,
                rationale=str(
                    llm_plan.get("rationale", "LLM-generated supervisor plan.")
                ),
                target_taxonomies=[
                    str(item) for item in llm_plan.get("target_taxonomies", [])[:5]
                ]
                or ["OWASP-LLM-01"],
                source_plans=[item.model_dump(mode="python") for item in source_plans],
                max_parallel_sources=min(
                    max(
                        1, int(llm_plan.get("max_parallel_sources", len(source_plans)))
                    ),
                    max(1, len(source_plans)),
                ),
                max_items_per_source=min(
                    max(1, int(llm_plan.get("max_items_per_source", 10))), 50
                ),
                max_reflection_rounds=min(
                    max(0, int(llm_plan.get("max_reflection_rounds", 1))), 3
                ),
                reflection_enabled=bool(llm_plan.get("reflection_enabled", True)),
            ).model_dump(mode="python"),
            None,
        )

    def _build_audit(
        self,
        plan: dict[str, Any],
        *,
        strategy_executed: str,
        confidence: float,
        feedback_rows_used: int,
        fallback_reason: str | None,
        invoked_at: str,
        llm_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        llm_meta = llm_meta or {}
        return LlmPlanningAuditDTO(
            strategy_requested=self.strategy,
            strategy_executed=strategy_executed,
            llm_model=str(llm_meta.get("llm_model", self.llm_model)),
            llm_profile_id=llm_meta.get("profile_id"),
            llm_profile=llm_meta.get("profile"),
            prompt_version=getattr(self.planner, "PROMPT_VERSION", "rules-only"),
            plan_rationale=str(plan.get("rationale", "")),
            source_plan_count=len(plan.get("source_plans", [])),
            target_taxonomy_count=len(plan.get("target_taxonomies", [])),
            max_parallel_sources=int(plan.get("max_parallel_sources", 1)),
            max_reflection_rounds=int(plan.get("max_reflection_rounds", 0)),
            confidence=confidence,
            feedback_rows_used=feedback_rows_used,
            fallback_reason=fallback_reason,
            llm_wait_seconds=llm_meta.get("wait_seconds"),
            attempted_profiles=list(llm_meta.get("attempted_profiles", []) or []),
            attempted_profile_labels=list(
                llm_meta.get("attempted_profile_labels", []) or []
            ),
            invoked_at=invoked_at,
        ).model_dump(mode="python")

    def _apply_plan_limits(
        self, context: RuntimeContextDTO, plan: dict[str, Any]
    ) -> dict[str, Any]:
        source_plans: list[dict[str, Any]] = []
        for row in plan.get("source_plans", []):
            source_plan = dict(row)
            if context.planning_max_items_per_source is not None:
                source_plan["max_results"] = min(
                    int(
                        source_plan.get(
                            "max_results", context.planning_max_items_per_source
                        )
                    ),
                    context.planning_max_items_per_source,
                )
            source_plans.append(source_plan)

        default_parallel = max(
            1,
            min(len(source_plans), int(plan.get("max_parallel_sources", 1))),
        )
        if context.planning_max_parallel_sources is not None:
            max_parallel_sources = min(
                context.planning_max_parallel_sources,
                max(1, len(source_plans)) if source_plans else 1,
            )
        else:
            max_parallel_sources = default_parallel

        if context.planning_reflection_enabled is None:
            reflection_enabled = bool(plan.get("reflection_enabled", True))
        else:
            reflection_enabled = context.planning_reflection_enabled
        if context.planning_max_reflection_rounds is None:
            max_reflection_rounds = int(plan.get("max_reflection_rounds", 1))
        else:
            max_reflection_rounds = context.planning_max_reflection_rounds
        if not reflection_enabled:
            max_reflection_rounds = 0

        max_items_per_source = int(
            context.planning_max_items_per_source
            if context.planning_max_items_per_source is not None
            else plan.get("max_items_per_source", 10)
        )
        return {
            **plan,
            "source_plans": source_plans,
            "max_parallel_sources": max_parallel_sources,
            "max_items_per_source": max(1, max_items_per_source),
            "max_reflection_rounds": max(0, max_reflection_rounds),
            "reflection_enabled": reflection_enabled,
        }


def _seed_query_for(source_name: str) -> str:
    query_map = {
        "nvd": "prompt injection langchain",
        "github_advisories": "langchain prompt injection",
        "arxiv": "prompt injection jailbreak language model",
        "reddit": "LLM jailbreak",
        "hackernews": "AI security vulnerability",
        "cisa_kev": "langchain",
        "mitre_attack": "agent hijack",
    }
    return query_map.get(source_name, f"{source_name} ai security")


def _default_query_intent_for(source_type: str) -> str:
    if source_type == "community":
        return "evidence_corroboration"
    if source_type == "paper":
        return "evidence_corroboration"
    return "broad_recall"


def _normalize_query_intent(
    value: str,
) -> Literal[
    "broad_recall",
    "precision_probe",
    "evidence_corroboration",
    "source_specific_rewrite",
    "component_anchor",
    "taxonomy_anchor",
]:
    normalized = str(value or "broad_recall")
    allowed = {
        "broad_recall",
        "precision_probe",
        "evidence_corroboration",
        "source_specific_rewrite",
        "component_anchor",
        "taxonomy_anchor",
    }
    # treat legacy weak_signal_probe as evidence_corroboration
    if normalized == "weak_signal_probe":
        normalized = "evidence_corroboration"
    return cast(
        Literal[
            "broad_recall",
            "precision_probe",
            "evidence_corroboration",
            "source_specific_rewrite",
            "component_anchor",
            "taxonomy_anchor",
        ],
        normalized if normalized in allowed else "broad_recall",
    )
