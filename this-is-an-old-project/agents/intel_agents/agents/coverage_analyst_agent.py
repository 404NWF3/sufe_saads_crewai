from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Literal, cast

from ..schemas.alert import CoverageGapDTO
from ..schemas.coverage import (
    GapFillRecommendationDTO,
    LlmCoverageAnalysisAuditDTO,
    LlmCoverageGapDecisionDTO,
)
from ..tools.llm_client_factory import resolve_default_model
from ..tools import LangChainLlmCoverageAnalyst


class CoverageAnalystAgent:
    def __init__(
        self,
        *,
        strategy: str = "rules_only",
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        analyst: Any | None = None,
        llm_runtime_config: dict[str, Any] | None = None,
        max_concurrency: int = 4,
    ) -> None:
        self.strategy = strategy
        self.max_concurrency = max(1, max_concurrency)
        self.llm_runtime_config = llm_runtime_config or {}
        self.llm_model = resolve_default_model(
            llm_model,
            runtime_config=self.llm_runtime_config,
        )
        self.llm_temperature = llm_temperature
        self.validate_online = validate_online
        self.analyst = analyst or LangChainLlmCoverageAnalyst(
            model=self.llm_model,
            temperature=llm_temperature,
            runtime_config=self.llm_runtime_config,
        )

    def analyze(
        self,
        gap_candidates: list[dict[str, Any]],
        *,
        runtime_context: dict[str, Any],
        max_gap_fill_plans: int,
        min_roi_threshold: float,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        coverage_gaps: list[dict[str, Any]] = []
        dispatch_plans: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []
        allowed_sources = {
            str(item.get("source_name", "")).strip()
            for item in runtime_context.get("source_registry", [])
            if item.get("source_name")
        }

        candidates_slice = gap_candidates[:max_gap_fill_plans]
        if not candidates_slice:
            return coverage_gaps, dispatch_plans, audits

        def _process_candidate(
            candidate: dict[str, Any],
        ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
            decision, audit = self._decide_gap_fill(
                candidate,
                runtime_context=runtime_context,
                min_roi_threshold=min_roi_threshold,
            )
            decision = _filter_decision_sources(decision, allowed_sources=allowed_sources)
            return candidate, decision, audit

        max_workers = min(self.max_concurrency, max(1, len(candidates_slice)))
        proc_results: list[Any] = [None] * len(candidates_slice)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {
                executor.submit(_process_candidate, c): i
                for i, c in enumerate(candidates_slice)
            }
            for future in as_completed(future_to_idx):
                proc_results[future_to_idx[future]] = future.result()

        for candidate, decision, audit in proc_results:
            coverage_gaps.append(
                CoverageGapDTO(
                    gap_id=candidate.get("gap_id"),
                    gap_axis=candidate.get("gap_axis"),
                    taxonomy_code=candidate.get("taxonomy_code") or "OWASP-LLM-UNKNOWN",
                    taxonomy_name=candidate.get("taxonomy_name") or "Unknown",
                    attack_family=candidate.get("attack_family"),
                    component_family=candidate.get("component_family"),
                    vendor_name=candidate.get("vendor_name"),
                    model_family=candidate.get("model_family"),
                    framework_family=candidate.get("framework_family"),
                    current_attack_count=int(candidate.get("current_attack_count", 0)),
                    target_attack_count=int(candidate.get("target_attack_count", 0)),
                    gap_score=float(candidate.get("gap_score", 0.0)),
                    source_diversity_gap=float(
                        candidate.get("source_diversity_gap", 0.0)
                    ),
                    component_coverage_gap=float(
                        candidate.get("component_coverage_gap", 0.0)
                    ),
                    corroboration_gap=float(candidate.get("corroboration_gap", 0.0)),
                    vendor_model_gap=float(candidate.get("vendor_model_gap", 0.0)),
                    severity_pressure=float(candidate.get("severity_pressure", 0.0)),
                    recent_activity_score=float(
                        candidate.get("recent_activity_score", 0.0)
                    ),
                    recommended_queries=decision.get("recommended_queries", []),
                    recommended_sources=decision.get("recommended_sources", []),
                    recommended_query_intents=decision.get(
                        "recommended_query_intents", []
                    ),
                    expected_evidence_type=decision.get("expected_evidence_type", []),
                    estimated_gap_fill_roi=float(
                        decision.get(
                            "estimated_gap_fill_roi",
                            candidate.get("estimated_gap_fill_roi", 0.0),
                        )
                    ),
                    should_dispatch_gap_fill=bool(
                        decision.get("should_dispatch_gap_fill", False)
                    ),
                    dispatch_priority=float(
                        decision.get(
                            "estimated_gap_fill_roi",
                            candidate.get("estimated_gap_fill_roi", 0.0),
                        )
                    ),
                    target_gain_dimension=_target_gain_dimension(candidate),
                    reason=str(
                        decision.get(
                            "reason", candidate.get("evidence_summary", "gap candidate")
                        )
                    ),
                ).model_dump(mode="python")
            )
            audits.append(audit)
            if decision.get("should_dispatch_gap_fill", False):
                dispatch_plans.append(
                    GapFillRecommendationDTO(
                        gap_id=str(candidate.get("gap_id", "unknown_gap")),
                        should_dispatch_gap_fill=True,
                        dispatch_priority=float(
                            decision.get(
                                "estimated_gap_fill_roi",
                                candidate.get("estimated_gap_fill_roi", 0.0),
                            )
                        ),
                        recommended_sources=decision.get("recommended_sources", []),
                        recommended_queries=decision.get("recommended_queries", []),
                        recommended_query_intents=decision.get(
                            "recommended_query_intents", []
                        ),
                        expected_evidence_type=decision.get(
                            "expected_evidence_type", []
                        ),
                        recommended_time_window_days=int(
                            decision.get("recommended_time_window_days", 14)
                        ),
                        estimated_gap_fill_roi=float(
                            decision.get(
                                "estimated_gap_fill_roi",
                                candidate.get("estimated_gap_fill_roi", 0.0),
                            )
                        ),
                        target_gain_dimension=_target_gain_dimension(candidate),
                        rationale=str(
                            decision.get(
                                "reason", candidate.get("evidence_summary", "gap fill")
                            )
                        ),
                    ).model_dump(mode="python")
                )
        return coverage_gaps, dispatch_plans, audits

    def _decide_gap_fill(
        self,
        candidate: dict[str, Any],
        *,
        runtime_context: dict[str, Any],
        min_roi_threshold: float,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        invoked_at = datetime.now(timezone.utc).isoformat()
        if self.strategy in {"rules_only", "rules_only_degraded"}:
            decision = self._rules_decision(candidate, min_roi_threshold)
            return decision, self._build_audit(
                candidate,
                decision,
                self.strategy,
                invoked_at,
                decision.get("fallback_reason"),
            )
        try:
            if self.validate_online:
                self.analyst.validate_connectivity()
            decision = LlmCoverageGapDecisionDTO.model_validate(
                self.analyst.analyze(
                    {
                        "gap_candidate": candidate,
                        "source_registry": runtime_context.get("source_registry", []),
                        "source_quality_rows": runtime_context.get(
                            "source_quality_rows", []
                        ),
                        "query_feedback_rows": runtime_context.get(
                            "query_feedback_rows", []
                        )[-20:],
                        "recent_attacks_summary": runtime_context.get(
                            "recent_attacks_summary", []
                        ),
                    }
                )
            ).model_dump(mode="python")
            llm_meta = dict(getattr(self.analyst, "last_invocation_meta", {}) or {})
            decision["should_dispatch_gap_fill"] = bool(
                decision.get("should_dispatch_gap_fill", False)
                and float(decision.get("estimated_gap_fill_roi", 0.0))
                >= min_roi_threshold
            )
            return decision, self._build_audit(
                candidate,
                decision,
                "llm_primary",
                invoked_at,
                None,
                llm_meta=llm_meta,
            )
        except Exception as exc:
            if self.strategy == "llm_required":
                raise RuntimeError(
                    f"LLM coverage analysis required but failed: {exc}"
                ) from exc
            decision = self._rules_decision(candidate, min_roi_threshold)
            decision["fallback_reason"] = str(exc)
            return decision, self._build_audit(
                candidate, decision, "rules_only_degraded", invoked_at, str(exc)
            )

    def _rules_decision(
        self, candidate: dict[str, Any], min_roi_threshold: float
    ) -> dict[str, Any]:
        axis = str(candidate.get("gap_axis", "taxonomy"))
        taxonomy_name = str(
            candidate.get("taxonomy_name")
            or candidate.get("taxonomy_code")
            or "ai security"
        )
        component_family = str(candidate.get("component_family") or "ai component")
        vendor_model = str(
            candidate.get("vendor_name")
            or candidate.get("model_family")
            or taxonomy_name
        )
        sources, intents, queries, evidence_types = _rules_gap_strategy(
            axis,
            taxonomy_name=taxonomy_name,
            component_family=component_family,
            vendor_model=vendor_model,
        )
        roi = float(candidate.get("estimated_gap_fill_roi", 0.0))
        return {
            "should_dispatch_gap_fill": roi >= min_roi_threshold,
            "gap_type": axis,
            "diagnosis": f"rules_{axis}_gap",
            "recommended_sources": sources,
            "recommended_queries": queries,
            "recommended_query_intents": intents,
            "expected_evidence_type": evidence_types,
            "recommended_time_window_days": 14,
            "estimated_gap_fill_roi": roi,
            "confidence": 0.72,
            "reason": str(candidate.get("evidence_summary", f"{axis} gap detected")),
            "fallback_reason": (
                "explicit_rules_only_degraded"
                if self.strategy == "rules_only_degraded"
                else None
            ),
        }

    def _build_audit(
        self,
        candidate: dict[str, Any],
        decision: dict[str, Any],
        strategy_executed: str,
        invoked_at: str,
        fallback_reason: str | None,
        llm_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        llm_meta = llm_meta or {}
        return LlmCoverageAnalysisAuditDTO(
            gap_id=str(candidate.get("gap_id", "unknown_gap")),
            strategy_requested=self.strategy,
            strategy_executed=strategy_executed,
            llm_model=str(llm_meta.get("llm_model", self.llm_model)),
            llm_profile_id=llm_meta.get("profile_id"),
            llm_profile=llm_meta.get("profile"),
            prompt_version=getattr(self.analyst, "PROMPT_VERSION", "rules-only"),
            gap_type=str(
                decision.get("gap_type", candidate.get("gap_axis", "uncertain"))
            ),
            should_dispatch_gap_fill=bool(
                decision.get("should_dispatch_gap_fill", False)
            ),
            estimated_gap_fill_roi=float(decision.get("estimated_gap_fill_roi", 0.0)),
            confidence=float(decision.get("confidence", 0.0)),
            recommended_source_count=len(decision.get("recommended_sources", [])),
            recommended_query_count=len(decision.get("recommended_queries", [])),
            fallback_reason=fallback_reason,
            llm_wait_seconds=llm_meta.get("wait_seconds"),
            attempted_profiles=list(llm_meta.get("attempted_profiles", []) or []),
            attempted_profile_labels=list(
                llm_meta.get("attempted_profile_labels", []) or []
            ),
            invoked_at=invoked_at,
        ).model_dump(mode="python")


def _target_gain_dimension(
    candidate: dict[str, Any],
) -> Literal["coverage", "corroboration", "component_mapping", "vendor_model"]:
    axis = str(candidate.get("gap_axis", "taxonomy"))
    if axis == "vendor_model":
        return cast(
            Literal[
                "coverage",
                "corroboration",
                "component_mapping",
                "vendor_model",
            ],
            "vendor_model",
        )
    if axis == "component_family":
        return cast(
            Literal[
                "coverage",
                "corroboration",
                "component_mapping",
                "vendor_model",
            ],
            "component_mapping",
        )
    if axis == "corroboration" or float(candidate.get("corroboration_gap", 0.0)) > 0.6:
        return cast(
            Literal[
                "coverage",
                "corroboration",
                "component_mapping",
                "vendor_model",
            ],
            "corroboration",
        )
    return cast(
        Literal[
            "coverage",
            "corroboration",
            "component_mapping",
            "vendor_model",
        ],
        "coverage",
    )


def _rules_gap_strategy(
    axis: str, *, taxonomy_name: str, component_family: str, vendor_model: str
) -> tuple[list[str], list[str], list[str], list[str]]:
    if axis == "vendor_model":
        return (
            ["github_advisories", "arxiv", "vendor_advisories"],
            ["component_anchor", "precision_probe", "evidence_corroboration"],
            [
                f"{vendor_model} ai security vulnerability",
                f"{vendor_model} prompt injection exploit",
            ],
            ["advisory", "paper"],
        )
    if axis == "component_family":
        return (
            ["github_advisories", "huggingface", "vendor_advisories"],
            ["component_anchor", "precision_probe"],
            [
                f"{component_family} vulnerability advisory",
                f"{component_family} exploit impact",
            ],
            ["advisory", "repo"],
        )
    if axis in {"source_diversity", "corroboration"}:
        return (
            ["arxiv", "github_advisories", "cisa_kev"],
            ["evidence_corroboration", "taxonomy_anchor"],
            [
                f"{taxonomy_name} ai security evidence",
                f"{taxonomy_name} vulnerability disclosure",
            ],
            ["paper", "advisory", "structured"],
        )
    return (
        ["github_advisories", "arxiv", "reddit"],
        ["taxonomy_anchor", "broad_recall", "evidence_corroboration"],
        [f"{taxonomy_name} large language model", f"{taxonomy_name} ai vulnerability"],
        ["advisory", "paper", "community"],
    )


def _filter_decision_sources(
    decision: dict[str, Any], *, allowed_sources: set[str]
) -> dict[str, Any]:
    if not allowed_sources:
        return decision
    recommended_sources = [
        str(item)
        for item in decision.get("recommended_sources", [])
        if str(item) in allowed_sources
    ]
    if not recommended_sources:
        fallback = sorted(allowed_sources)[:2]
        decision = {
            **decision,
            "recommended_sources": fallback,
            "reason": (
                f"{decision.get('reason', 'gap fill recommendation')} "
                "Recommended sources were filtered by registry availability."
            ).strip(),
        }
        return decision
    if len(recommended_sources) != len(decision.get("recommended_sources", [])):
        decision = {
            **decision,
            "recommended_sources": recommended_sources,
            "reason": (
                f"{decision.get('reason', 'gap fill recommendation')} "
                "Partially filtered by registry availability."
            ).strip(),
        }
    if not decision.get("recommended_sources"):
        decision = {**decision, "should_dispatch_gap_fill": False}
    return decision
