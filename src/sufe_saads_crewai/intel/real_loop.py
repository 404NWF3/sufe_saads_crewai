from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
from time import monotonic
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from sufe_saads_crewai.topic_utils import (
    TARGET_SECURITY_TOPICS,
    build_gap_query,
    detect_topics,
)
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import (
    ActionDecision,
    CollectionBatchOutput,
    CollectionYieldAssessment,
    CompletenessDecisionOutput,
    CoverageAnalysisOutput,
    CoverageGap,
    CoverageGapAnalysis,
    IntelRunBlackboard,
    PlannerDecisionOutput,
    QueryHistoryEntry,
    RawIntelItem,
    RawIntelItemBatch,
    RewriteDecisionOutput,
    RunBudget,
    SearchCompletenessAssessment,
    SearchQueryPlan,
    SearchReflectionDecision,
    SearchSemanticExpansionOutput,
    SemanticGapExpansion,
    SourceSemanticTerms,
    SourceExecutionStat,
    SourceYieldMetric,
    YieldAssessmentOutput,
)
from sufe_saads_crewai.tools import (
    RegisteredApiSourceSearchTool,
    default_registered_api_sources,
)
from sufe_saads_crewai.tools.registered_source_tools import (
    DEFAULT_OSV_PACKAGE_TARGETS,
    NVD_AI_ATTACK_KEYWORDS,
    NVD_AI_PRODUCT_KEYWORDS,
    NVD_AI_RELEVANT_CWE_IDS,
    NVD_EXACT_MATCH_KEYWORDS,
)


@dataclass
class RealIntelAgentSet:
    planner: Any
    collector: Any
    critic: Any


@dataclass(frozen=True)
class SourceQuerySpec:
    source_name: str
    query_text: str
    target_topics: list[str]
    max_results: int
    strategy_name: str
    params: dict[str, Any]


class RealIntelRunController:
    """Runs the real-source intelligence loop used by `crewai run`."""

    def __init__(
        self,
        run_goal: str,
        initial_query: str,
        max_rounds: int = 5,
        max_results_per_round: int = 80,
        run_store: JsonIntelRunStore | None = None,
        agents: RealIntelAgentSet | None = None,
        source_tool: RegisteredApiSourceSearchTool | None = None,
        target_topics: list[str] | None = None,
        run_budget: RunBudget | None = None,
    ) -> None:
        self.run_goal = run_goal
        self.initial_query = initial_query
        self.max_rounds = max_rounds
        self.max_results_per_round = max_results_per_round
        self.run_store = run_store or JsonIntelRunStore()
        self.agents = agents or self._default_agents()
        self.source_tool = source_tool or RegisteredApiSourceSearchTool()
        self.target_topics = target_topics or list(TARGET_SECURITY_TOPICS)
        self.run_budget = run_budget
        self.raw_item_batches: list[RawIntelItemBatch] = []
        self._executed_source_query_keys: set[str] = set()
        self._latest_semantic_expansion: SearchSemanticExpansionOutput | None = None

    def run(self) -> IntelRunBlackboard:
        budget = self.run_budget.model_copy() if self.run_budget is not None else RunBudget()
        budget.max_rounds = self.max_rounds
        if budget.max_api_calls is None:
            budget.max_api_calls = 100
        if budget.max_sources is None:
            budget.max_sources = 12
        blackboard = IntelRunBlackboard(
            run_id=f"real-{uuid4().hex[:8]}",
            run_goal=self.run_goal,
            run_mode="bootstrap",
            budget=budget,
            approved_sources=default_registered_api_sources(),
        )
        current_query = self.initial_query
        started_at = monotonic()
        round_index = 0

        while round_index < self.max_rounds:
            query_plan = self._query_plan(blackboard, current_query, round_index)
            action_batch = self._select_next_actions(blackboard, query_plan)
            blackboard.action_history.extend(action_batch.actions)

            latest_batch = self._collect_real_sources(blackboard, query_plan)
            self.raw_item_batches.append(latest_batch)
            self._merge_batch_into_blackboard(blackboard, query_plan, latest_batch)

            yield_assessment = self._assess_collection_yield(blackboard, latest_batch)
            gap_analysis = self._analyze_coverage_gaps(blackboard)
            semantic_expansion = self._expand_search_semantics(
                blackboard,
                yield_assessment,
                gap_analysis,
            )
            self._latest_semantic_expansion = semantic_expansion
            if semantic_expansion.expansions:
                blackboard.action_history.append(
                    ActionDecision(
                        action_type="EXPAND_SEARCH_SEMANTICS",
                        priority="high",
                        rationale=semantic_expansion.overall_rationale,
                        expected_gain="Translate coverage gaps into source-specific search terms.",
                        required_context=[
                            expansion.gap_topic for expansion in semantic_expansion.expansions
                        ],
                        metadata=semantic_expansion.model_dump(mode="json"),
                    )
                )
            reflection = self._rewrite_search_strategy(
                blackboard,
                yield_assessment,
                gap_analysis,
            )
            if reflection.rewritten_queries:
                blackboard.reflection_notes.append(reflection)
                blackboard.action_history.append(
                    ActionDecision(
                        action_type="REFLECT_SEARCH_STRATEGY",
                        priority="high",
                        rationale=reflection.rationale,
                        expected_gain="Improve recall over uncovered LLM security topics.",
                        required_context=[
                            query.query_text for query in reflection.rewritten_queries
                        ],
                    )
                )

            blackboard.metrics.elapsed_seconds = monotonic() - started_at
            completeness = self._evaluate_search_completeness(
                blackboard,
                yield_assessment,
                gap_analysis,
                reflection,
                round_index,
            )
            blackboard.metrics.round_index = len(blackboard.query_history)
            self._persist(blackboard, status="running")

            if not completeness.should_continue:
                blackboard.action_history.append(
                    ActionDecision(
                        action_type="STOP",
                        priority="high",
                        rationale=completeness.stop_rationale or "Stop criteria met.",
                        required_context=["SearchCompletenessAssessment"],
                    )
                )
                break

            if not reflection.rewritten_queries:
                blackboard.action_history.append(
                    ActionDecision(
                        action_type="STOP",
                        priority="high",
                        rationale="Planner did not produce a next query after coverage review.",
                    )
                )
                break

            current_query = reflection.rewritten_queries[0].query_text
            round_index += 1

        self._persist(blackboard, status="succeeded")
        return blackboard

    def _default_agents(self) -> RealIntelAgentSet:
        from sufe_saads_crewai.crew import SufeSaadsCrewai

        crew_def = SufeSaadsCrewai()
        return RealIntelAgentSet(
            planner=crew_def.autonomous_planner(),
            collector=crew_def.source_intelligence_collector(),
            critic=crew_def.reflection_coverage_critic(),
        )

    def _query_plan(
        self,
        blackboard: IntelRunBlackboard,
        query_text: str,
        round_index: int,
    ) -> SearchQueryPlan:
        return SearchQueryPlan(
            query_text=query_text,
            source_names=[
                source.source_name for source in blackboard.approved_sources if source.enabled
            ],
            target_topics=self.target_topics,
            query_intent="broad_recall" if round_index == 0 else "gap_fill",
            max_results=self.max_results_per_round,
            priority="high",
            rationale="Real-source autonomous intelligence collection.",
            round_index=round_index,
        )

    def _select_next_actions(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> PlannerDecisionOutput:
        prompt = (
            "Choose the next actions for this LLM security intelligence run. "
            "Use only PLAN_COLLECTION, SEARCH_REGISTERED_SOURCE, "
            "ASSESS_COLLECTION_YIELD, ANALYZE_COVERAGE_GAPS, "
            "REFLECT_SEARCH_STRATEGY, or STOP.\n\n"
            f"Run goal: {blackboard.run_goal}\n"
            f"Current query plan: {query_plan.model_dump_json()}\n"
            f"Blackboard summary: {self._blackboard_summary(blackboard)}\n\n"
            "Return JSON matching: actions, planner_rationale, should_start_collection."
        )
        parsed = _kickoff_json(self.agents.planner, prompt, PlannerDecisionOutput)
        if parsed is not None:
            return parsed

        return PlannerDecisionOutput(
            actions=[
                {
                    "action_type": "SEARCH_REGISTERED_SOURCE",
                    "priority": "high",
                    "rationale": "Collect from approved real registered API sources.",
                    "expected_gain": "More real raw intelligence and coverage signals.",
                    "required_context": [query_plan.query_text],
                    "success_criteria": ["RawIntelItemBatch contains source_uri for each item."],
                    "retry_conditions": ["Transient source API failure."],
                    "stop_conditions": ["No enabled approved sources remain."],
                    "estimated_cost_level": "medium",
                },
                {
                    "action_type": "ANALYZE_COVERAGE_GAPS",
                    "priority": "medium",
                    "rationale": "Find missing LLM security topics after collection.",
                    "expected_gain": "A better next query if coverage is incomplete.",
                    "required_context": ["raw_items", "target_topics"],
                    "success_criteria": ["Coverage gaps are explicit."],
                    "retry_conditions": [],
                    "stop_conditions": ["Target coverage reached."],
                    "estimated_cost_level": "low",
                },
            ],
            planner_rationale="Fallback planner selected real-source collection and coverage analysis.",
            should_start_collection=True,
        )

    def _collect_real_sources(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> RawIntelItemBatch:
        prompt = (
            "Call registered_api_source_search exactly once to collect real intelligence. "
            "Do not use mock data. Return concise JSON matching query_text, "
            "source_names, items, and batch_notes.\n\n"
            f"query_text: {query_plan.query_text}\n"
            f"source_names: {query_plan.source_names}\n"
            f"target_topics: {query_plan.target_topics}\n"
            f"max_results: {query_plan.max_results}\n"
            f"approved_sources_json: {self._approved_sources_json(blackboard)}"
        )
        collection_output = _kickoff_json(
            self.agents.collector,
            prompt,
            CollectionBatchOutput,
        )
        if collection_output and collection_output.items:
            return _batch_from_collection_output(collection_output, query_plan)

        return self._direct_real_source_search(blackboard, query_plan)

    def _direct_real_source_search(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> RawIntelItemBatch:
        source_specs = self._source_query_specs(blackboard, query_plan)
        batches: list[RawIntelItemBatch] = []
        approved_sources_json = self._approved_sources_json(blackboard)

        for spec in source_specs:
            raw = self.source_tool._run(
                query_text=spec.query_text,
                source_names=[spec.source_name],
                target_topics=spec.target_topics,
                max_results=spec.max_results,
                round_index=query_plan.round_index,
                approved_sources_json=approved_sources_json,
                **spec.params,
            )
            batch = RawIntelItemBatch.model_validate_json(raw)
            for item in batch.items:
                item.metadata["collection_strategy"] = spec.strategy_name
                item.metadata["source_query"] = spec.query_text
                item.metadata["source_query_params"] = {
                    key: value for key, value in spec.params.items() if value not in (None, [], "")
                }
            batches.append(batch)
            self._executed_source_query_keys.add(self._source_query_key(spec))

        return self._combine_source_batches(query_plan, source_specs, batches)

    def _source_query_specs(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> list[SourceQuerySpec]:
        enabled_sources = set(query_plan.source_names) or {
            source.source_name for source in blackboard.approved_sources if source.enabled
        }
        focus_topics = self._focus_topics(blackboard, query_plan)
        per_source_limit = max(5, min(20, self.max_results_per_round // 4))

        specs: list[SourceQuerySpec] = []
        if "nvd_cve_api" in enabled_sources:
            specs.extend(self._nvd_query_specs(focus_topics, query_plan.round_index))
        if "arxiv_api" in enabled_sources:
            specs.append(
                SourceQuerySpec(
                    source_name="arxiv_api",
                    query_text=self._arxiv_strategy_query(focus_topics),
                    target_topics=focus_topics,
                    max_results=per_source_limit,
                    strategy_name="arxiv_topic_research",
                    params={"arxiv_search_query": self._arxiv_strategy_query(focus_topics)},
                )
            )
        if "cisa_kev_json" in enabled_sources:
            for keyword in self._cisa_keywords(focus_topics, query_plan.round_index):
                specs.append(
                    SourceQuerySpec(
                        source_name="cisa_kev_json",
                        query_text=f"CISA KEV keyword:{keyword}",
                        target_topics=focus_topics,
                        max_results=min(12, per_source_limit),
                        strategy_name="cisa_kev_keyword",
                        params={"cisa_keyword": keyword},
                    )
                )
        if "osv_dev_api" in enabled_sources:
            for package in self._osv_packages(focus_topics, query_plan.round_index):
                specs.append(
                    SourceQuerySpec(
                        source_name="osv_dev_api",
                        query_text=f"OSV package:{package['ecosystem']}/{package['name']}",
                        target_topics=focus_topics,
                        max_results=6,
                        strategy_name="osv_package_ecosystem",
                        params={
                            "osv_ecosystem": package["ecosystem"],
                            "osv_package_name": package["name"],
                        },
                    )
                )

        fresh_specs = [
            spec for spec in specs if self._source_query_key(spec) not in self._executed_source_query_keys
        ]
        if fresh_specs:
            return fresh_specs
        if specs:
            return specs[: max(1, min(4, len(specs)))]

        return [
            SourceQuerySpec(
                source_name=source_name,
                query_text=query_plan.query_text,
                target_topics=query_plan.target_topics,
                max_results=per_source_limit,
                strategy_name="fallback_registered_source_query",
                params={},
            )
            for source_name in sorted(enabled_sources)
        ]

    def _nvd_query_specs(self, focus_topics: list[str], round_index: int) -> list[SourceQuerySpec]:
        query_limit = self._nvd_query_limit()
        keywords = self._rotating_slice(
            self._nvd_keywords_for_topics(focus_topics),
            round_index,
            query_limit,
        )
        specs: list[SourceQuerySpec] = []
        for keyword in keywords:
            specs.append(
                SourceQuerySpec(
                    source_name="nvd_cve_api",
                    query_text=f"NVD keywordSearch:{keyword}",
                    target_topics=focus_topics,
                    max_results=20,
                    strategy_name="nvd_keyword_candidate",
                    params={
                        "nvd_keyword_search": keyword,
                        "nvd_keyword_exact_match": keyword.lower() in NVD_EXACT_MATCH_KEYWORDS,
                        "nvd_no_rejected": True,
                    },
                )
            )

        for keyword, cwe_id in self._nvd_product_cwe_pairs(focus_topics, round_index):
            specs.append(
                SourceQuerySpec(
                    source_name="nvd_cve_api",
                    query_text=f"NVD product+CWE:{keyword} {cwe_id}",
                    target_topics=focus_topics,
                    max_results=20,
                    strategy_name="nvd_product_cwe_candidate",
                    params={
                        "nvd_keyword_search": keyword,
                        "nvd_cwe_id": cwe_id,
                        "nvd_no_rejected": True,
                    },
                )
            )
        return specs

    def _combine_source_batches(
        self,
        query_plan: SearchQueryPlan,
        source_specs: list[SourceQuerySpec],
        batches: list[RawIntelItemBatch],
    ) -> RawIntelItemBatch:
        items: list[RawIntelItem] = []
        overflow_items: list[RawIntelItem] = []
        stats: list[SourceExecutionStat] = []
        seen_candidate_ids: set[str] = set()
        selected_item_ids: set[str] = set()
        source_item_counts: dict[str, int] = {}
        source_plan_summaries: list[dict[str, Any]] = []
        distinct_sources = {spec.source_name for spec in source_specs}
        per_source_cap = max(8, self.max_results_per_round // max(1, len(distinct_sources)))

        for spec, batch in zip(source_specs, batches):
            source_plan_summaries.append(
                {
                    "source_name": spec.source_name,
                    "strategy_name": spec.strategy_name,
                    "query_text": spec.query_text,
                    "params": {
                        key: value for key, value in spec.params.items() if value not in (None, [], "")
                    },
                }
            )
            for stat in batch.source_stats:
                stat.notes = " | ".join(
                    part
                    for part in [
                        stat.notes,
                        f"strategy={spec.strategy_name}",
                        f"query={spec.query_text}",
                    ]
                    if part
                )
                stats.append(stat)
            for item in batch.items:
                if item.item_id in seen_candidate_ids:
                    continue
                seen_candidate_ids.add(item.item_id)
                count = source_item_counts.get(item.source_name, 0)
                if count < per_source_cap and len(items) < self.max_results_per_round:
                    items.append(item)
                    selected_item_ids.add(item.item_id)
                    source_item_counts[item.source_name] = count + 1
                else:
                    overflow_items.append(item)

        for item in overflow_items:
            if len(items) >= self.max_results_per_round:
                break
            if item.item_id in selected_item_ids:
                continue
            items.append(item)
            selected_item_ids.add(item.item_id)
            source_item_counts[item.source_name] = source_item_counts.get(item.source_name, 0) + 1

        source_names = sorted({spec.source_name for spec in source_specs})
        combined_plan = SearchQueryPlan(
            query_text=query_plan.query_text,
            source_names=source_names,
            target_topics=query_plan.target_topics,
            query_intent="source_specific_registered_api_collection",
            max_results=self.max_results_per_round,
            priority=query_plan.priority,
            rationale=query_plan.rationale,
            round_index=query_plan.round_index,
        )
        return RawIntelItemBatch(
            items=items,
            query_plan=combined_plan,
            source_stats=stats,
            batch_notes=json.dumps(
                {
                    "mode": "source_specific_collection",
                    "source_query_plans": source_plan_summaries,
                    "unique_items": len(items),
                },
                ensure_ascii=False,
            ),
        )

    def _merge_batch_into_blackboard(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
        latest_batch: RawIntelItemBatch,
    ) -> None:
        existing_ids = {item.item_id for item in blackboard.raw_items}
        new_items: list[RawIntelItem] = []
        duplicate_count = 0
        for item in latest_batch.items:
            if item.item_id in existing_ids:
                duplicate_count += 1
                continue
            blackboard.raw_items.append(item)
            new_items.append(item)
            existing_ids.add(item.item_id)

        result_count = len(latest_batch.items)
        low_relevance_count = sum(1 for item in latest_batch.items if item.relevance_score < 0.5)
        failed_sources = [
            stat.source_name for stat in latest_batch.source_stats if not stat.success
        ]
        source_query_plans = _batch_source_query_plans(latest_batch.batch_notes)
        blackboard.query_history.append(
            QueryHistoryEntry(
                query_text=query_plan.query_text,
                source_names=query_plan.source_names,
                result_count=result_count,
                novelty_score=(len(new_items) / result_count) if result_count else 0.0,
                noise_ratio=(low_relevance_count / result_count) if result_count else 0.0,
                duplicate_ratio=(duplicate_count / result_count) if result_count else 0.0,
                round_index=query_plan.round_index,
                metadata={
                    "new_item_ids": [item.item_id for item in new_items],
                    "batch_item_ids": [item.item_id for item in latest_batch.items],
                    "failed_sources": failed_sources,
                    "source_query_plans": source_query_plans,
                },
            )
        )
        blackboard.metrics.api_calls_used += max(1, len(latest_batch.source_stats))
        blackboard.metrics.sources_used = len(
            {source for history in blackboard.query_history for source in history.source_names}
        )

    def _assess_collection_yield(
        self,
        blackboard: IntelRunBlackboard,
        latest_batch: RawIntelItemBatch,
    ) -> CollectionYieldAssessment:
        prompt = (
            "Assess the latest real-source collection yield. Return JSON with "
            "metrics, low_yield_sources, high_noise_queries, useful_queries, "
            "novelty_summary, and recommended_adjustments.\n\n"
            f"Latest batch: {latest_batch.model_dump_json()}\n"
            f"Latest query history: {blackboard.query_history[-1].model_dump_json()}"
        )
        parsed = _kickoff_json(self.agents.critic, prompt, YieldAssessmentOutput)
        if parsed is not None:
            return CollectionYieldAssessment(
                per_source_metrics=[
                    SourceYieldMetric(
                        source_name=metric.source_name,
                        result_count=metric.result_count,
                        novelty_score=metric.novelty_score,
                        noise_ratio=metric.noise_ratio,
                        evidence_quality=metric.evidence_quality,
                    )
                    for metric in parsed.metrics
                ],
                low_yield_sources=parsed.low_yield_sources,
                high_noise_queries=parsed.high_noise_queries,
                useful_queries=parsed.useful_queries,
                novelty_summary=parsed.novelty_summary,
                recommended_adjustments=parsed.recommended_adjustments,
            )

        history = blackboard.query_history[-1]
        metrics = []
        for stat in latest_batch.source_stats:
            source_items = [
                item for item in latest_batch.items if item.source_name == stat.source_name
            ]
            evidence_quality = (
                sum(item.relevance_score for item in source_items) / len(source_items)
                if source_items
                else 0.0
            )
            metrics.append(
                SourceYieldMetric(
                    source_name=stat.source_name,
                    result_count=stat.result_count,
                    novelty_score=history.novelty_score,
                    noise_ratio=history.noise_ratio,
                    duplicate_ratio=history.duplicate_ratio,
                    evidence_quality=evidence_quality,
                    notes=stat.notes,
                )
            )
        return CollectionYieldAssessment(
            per_source_metrics=metrics,
            low_yield_sources=[
                metric.source_name
                for metric in metrics
                if metric.result_count == 0 or metric.evidence_quality < 0.45
            ],
            high_noise_queries=[history.query_text] if history.noise_ratio >= 0.5 else [],
            useful_queries=[history.query_text] if history.novelty_score >= 0.2 else [],
            novelty_summary=(
                f"Latest query returned {history.result_count} items with "
                f"novelty={history.novelty_score:.2f}, duplicate={history.duplicate_ratio:.2f}."
            ),
            recommended_adjustments=[],
        )

    def _analyze_coverage_gaps(self, blackboard: IntelRunBlackboard) -> CoverageGapAnalysis:
        prompt = (
            "Analyze coverage gaps for LLM security intelligence. Return JSON with "
            "gaps, overall_coverage_score, and analysis_rationale.\n\n"
            f"Target topics: {self.target_topics}\n"
            f"Collected items: {[item.model_dump(mode='json') for item in blackboard.raw_items]}"
        )
        parsed = _kickoff_json(self.agents.critic, prompt, CoverageAnalysisOutput)
        if parsed is not None:
            gaps = [
                CoverageGap(
                    gap_id=f"gap-{gap.topic.replace(' ', '-')}",
                    dimension="llm_security_taxonomy",
                    taxonomy_or_component=gap.topic,
                    current_coverage=gap.current_coverage,
                    target_coverage=gap.target_coverage,
                    estimated_gap_fill_roi=gap.estimated_roi,
                    recommended_queries=[
                        SearchQueryPlan(
                            query_text=gap.recommended_query,
                            target_topics=[gap.topic],
                            query_intent="gap_fill",
                            priority=gap.priority,
                        )
                    ],
                    priority=gap.priority,
                )
                for gap in parsed.gaps
            ]
            blackboard.coverage_gaps = gaps
            return CoverageGapAnalysis(
                gaps=gaps,
                overall_coverage_score=parsed.overall_coverage_score,
                analysis_rationale=parsed.analysis_rationale,
            )

        covered = self._covered_topics(blackboard.raw_items)
        gaps = [
            CoverageGap(
                gap_id=f"gap-{topic.replace(' ', '-')}",
                dimension="llm_security_taxonomy",
                taxonomy_or_component=topic,
                current_coverage=0.0,
                target_coverage=1.0,
                estimated_gap_fill_roi=0.82,
                recommended_queries=[
                    SearchQueryPlan(
                        query_text=build_gap_query([topic]),
                        target_topics=[topic],
                        query_intent="gap_fill",
                        priority="high",
                    )
                ],
                priority="high",
            )
            for topic in self.target_topics
            if topic not in covered
        ]
        blackboard.coverage_gaps = gaps
        return CoverageGapAnalysis(
            gaps=gaps,
            overall_coverage_score=len(covered) / len(self.target_topics),
            analysis_rationale="Coverage measured against target LLM security topics.",
        )

    def _expand_search_semantics(
        self,
        blackboard: IntelRunBlackboard,
        yield_assessment: CollectionYieldAssessment,
        gap_analysis: CoverageGapAnalysis,
    ) -> SearchSemanticExpansionOutput:
        prompt = (
            "Expand search semantics for the remaining LLM security coverage gaps. "
            "Return JSON with expansions, overall_rationale, and confidence. "
            "For each gap, provide source-specific terms for nvd_cve_api, "
            "arxiv_api, cisa_kev_json, and osv_dev_api. Do not collect data.\n\n"
            f"Yield assessment: {yield_assessment.model_dump_json()}\n"
            f"Coverage analysis: {gap_analysis.model_dump_json()}\n"
            f"Query history: {[entry.model_dump(mode='json') for entry in blackboard.query_history]}"
        )
        parsed = _kickoff_json(self.agents.planner, prompt, SearchSemanticExpansionOutput)
        if parsed is not None:
            return parsed

        high_roi_gaps = [
            gap
            for gap in gap_analysis.gaps
            if gap.priority in {"high", "critical"} or gap.estimated_gap_fill_roi >= 0.55
        ]
        expansions = [
            self._fallback_semantic_gap_expansion(gap.taxonomy_or_component)
            for gap in high_roi_gaps[:4]
        ]
        return SearchSemanticExpansionOutput(
            expansions=expansions,
            overall_rationale=(
                "Fallback semantic expansion maps coverage gaps to source-specific "
                "terms for NVD, OSV, arXiv, and CISA KEV."
            ),
            confidence=0.74 if expansions else 0.0,
        )

    def _fallback_semantic_gap_expansion(self, gap_topic: str) -> SemanticGapExpansion:
        topic = gap_topic.lower()
        expanded_terms: list[str] = []
        nvd_terms: list[str] = []
        osv_terms: list[str] = []
        arxiv_terms: list[str] = []
        cisa_terms: list[str] = []
        nvd_hints = ["noRejected", "keywordExactMatch for multi-word phrases"]

        if "agent" in topic or "tool" in topic:
            expanded_terms.extend(
                [
                    "tool invocation abuse",
                    "unsafe tool execution",
                    "agent code execution",
                    "computer-use agent",
                    "browser agent attack",
                    "MCP server compromise",
                    "confused deputy",
                    "capability misuse",
                ]
            )
            nvd_terms.extend(
                [
                    "code injection",
                    "command injection",
                    "arbitrary code execution",
                    "sandbox escape",
                    "LangChain",
                    "LlamaIndex",
                    "Jupyter",
                    "Ray",
                    "browser agent",
                ]
            )
            osv_terms.extend(["langchain", "llama-index", "langflow", "flowise", "jupyter-server", "ray"])
            arxiv_terms.extend(
                [
                    "agentic AI security",
                    "tool-use agents",
                    "computer-use agents",
                    "indirect prompt injection",
                    "confused deputy",
                    "sandboxing LLM agents",
                ]
            )
            cisa_terms.extend(["code injection", "command injection", "remote code execution", "authentication bypass"])
            nvd_hints.extend(["CWE-78", "CWE-94", "CWE-287"])

        if "rag" in topic or "poison" in topic:
            expanded_terms.extend(
                [
                    "retrieval poisoning",
                    "embedding poisoning",
                    "vector database injection",
                    "knowledge base poisoning",
                ]
            )
            nvd_terms.extend(["RAG", "embedding", "vector database", "Milvus", "Qdrant", "Weaviate", "Chroma"])
            osv_terms.extend(["chromadb", "qdrant-client", "weaviate-client", "llama-index", "langchain"])
            arxiv_terms.extend(["RAG poisoning", "retrieval augmented generation poisoning", "embedding attack"])
            cisa_terms.extend(["injection", "data exposure", "authentication bypass"])
            nvd_hints.extend(["CWE-20", "CWE-89", "CWE-918"])

        if "supply" in topic or "model" in topic:
            expanded_terms.extend(
                [
                    "model loading vulnerability",
                    "unsafe deserialization",
                    "model artifact tampering",
                    "AI package supply chain",
                ]
            )
            nvd_terms.extend(["MLflow", "Gradio", "Hugging Face", "Transformers", "Langflow", "Dify", "model"])
            osv_terms.extend(["mlflow", "gradio", "transformers", "vllm", "open-webui", "langflow"])
            arxiv_terms.extend(["model supply chain", "model artifact security", "LLM supply chain"])
            cisa_terms.extend(["deserialization", "code injection", "file upload", "path traversal"])
            nvd_hints.extend(["CWE-502", "CWE-434", "CWE-22"])

        if "data" in topic or "leak" in topic:
            expanded_terms.extend(
                [
                    "sensitive information exposure",
                    "training data leakage",
                    "prompt data exfiltration",
                    "cross-tenant data leakage",
                ]
            )
            nvd_terms.extend(["sensitive information", "training data", "chatbot", "Jupyter", "Chroma"])
            osv_terms.extend(["jupyter-server", "chromadb", "weaviate-client", "qdrant-client"])
            arxiv_terms.extend(["LLM data leakage", "training data extraction", "privacy attack"])
            cisa_terms.extend(["information disclosure", "sensitive information", "data exposure"])
            nvd_hints.extend(["CWE-200"])

        if "prompt" in topic:
            expanded_terms.extend(["indirect prompt injection", "prompt injection", "instruction hierarchy attack"])
            nvd_terms.extend(["prompt injection", "indirect prompt injection", "chatbot", "AnythingLLM"])
            osv_terms.extend(["anythingllm", "open-webui", "langchain"])
            arxiv_terms.extend(["prompt injection", "indirect prompt injection", "prompt injection defense"])
            cisa_terms.extend(["cross-site scripting", "injection", "chatbot"])
            nvd_hints.extend(["keywordExactMatch"])

        if "jailbreak" in topic:
            expanded_terms.extend(["safety bypass", "policy bypass", "adversarial prompt", "red teaming"])
            nvd_terms.extend(["jailbreak", "large language model", "LLM"])
            arxiv_terms.extend(["jailbreak attack", "safety bypass", "LLM red teaming"])
            cisa_terms.extend(["policy bypass", "authentication bypass"])

        if not expanded_terms:
            expanded_terms.extend([gap_topic, "large language model security", "AI vulnerability"])
            nvd_terms.extend(["large language model", "LLM", "machine learning"])
            osv_terms.extend(["langchain", "llama-index", "mlflow"])
            arxiv_terms.extend([gap_topic, "large language model security"])
            cisa_terms.extend(["code injection", "remote code execution"])

        return SemanticGapExpansion(
            gap_topic=gap_topic,
            expanded_terms=_dedupe_preserve_order(expanded_terms),
            source_specific_terms=[
                SourceSemanticTerms(
                    source_name="nvd_cve_api",
                    positive_terms=_dedupe_preserve_order(nvd_terms),
                    negative_terms=["AI", "ML"],
                    query_templates=[
                        "keywordSearch={term}&noRejected",
                        "keywordSearch={product}&cweId={cwe}&noRejected",
                        "keywordSearch={product}&hasKev&noRejected",
                    ],
                    parameter_hints=_dedupe_preserve_order(nvd_hints),
                    rationale="NVD searches CVE descriptions and product/CWE metadata, not an AI attack taxonomy.",
                ),
                SourceSemanticTerms(
                    source_name="osv_dev_api",
                    positive_terms=_dedupe_preserve_order(osv_terms),
                    negative_terms=[],
                    query_templates=[
                        "package.ecosystem=PyPI package.name={package}",
                        "package.ecosystem=npm package.name={package}",
                        "vulns/{GHSA_OR_CVE_ID}",
                    ],
                    parameter_hints=["ecosystem", "package_name", "purl", "vuln_id"],
                    rationale="OSV is package-centric, so terms should map to ecosystems and package names.",
                ),
                SourceSemanticTerms(
                    source_name="arxiv_api",
                    positive_terms=_dedupe_preserve_order(arxiv_terms),
                    negative_terms=["leaderboard", "video generation", "robotics"],
                    query_templates=[
                        '(all:"{term}") AND (cat:cs.CR OR cat:cs.AI OR cat:cs.CL)',
                    ],
                    parameter_hints=["sortBy=submittedDate", "sortOrder=descending"],
                    rationale="arXiv works best with research phrases and security categories.",
                ),
                SourceSemanticTerms(
                    source_name="cisa_kev_json",
                    positive_terms=_dedupe_preserve_order(cisa_terms),
                    negative_terms=[],
                    query_templates=["keyword={term}", "cve_id={cve}"],
                    parameter_hints=["product", "vendorProject", "shortDescription"],
                    rationale="CISA KEV captures exploitation-prioritized vulnerabilities, often through product and vulnerability type terms.",
                ),
            ],
            global_negative_terms=["marketing", "benchmark only", "unrelated robotics", "pure video generation"],
            rationale=f"Expanded {gap_topic} into terms that match each source's retrieval semantics.",
            confidence=0.76,
        )

    def _rewrite_search_strategy(
        self,
        blackboard: IntelRunBlackboard,
        yield_assessment: CollectionYieldAssessment,
        gap_analysis: CoverageGapAnalysis,
    ) -> SearchReflectionDecision:
        prompt = (
            "Rewrite the search strategy if coverage gaps remain. Return JSON with "
            "should_rewrite, rewritten_query, target_topics, topics_to_stop, "
            "rationale, and confidence.\n\n"
            f"Yield assessment: {yield_assessment.model_dump_json()}\n"
            f"Coverage analysis: {gap_analysis.model_dump_json()}\n"
            f"Query history: {[entry.model_dump(mode='json') for entry in blackboard.query_history]}"
        )
        parsed = _kickoff_json(self.agents.planner, prompt, RewriteDecisionOutput)
        if parsed is not None:
            rewritten_queries = []
            if parsed.should_rewrite and parsed.rewritten_query:
                rewritten_queries.append(
                    SearchQueryPlan(
                        query_text=parsed.rewritten_query,
                        source_names=[
                            source.source_name
                            for source in blackboard.approved_sources
                            if source.enabled
                        ],
                        target_topics=parsed.target_topics,
                        query_intent="gap_fill",
                        max_results=self.max_results_per_round,
                        priority="high",
                        rationale=parsed.rationale,
                        round_index=len(blackboard.query_history),
                    )
                )
            return SearchReflectionDecision(
                rewritten_queries=rewritten_queries,
                topics_to_expand=parsed.target_topics,
                topics_to_stop=parsed.topics_to_stop,
                rationale=parsed.rationale,
                confidence=parsed.confidence,
            )

        high_roi_gaps = [
            gap
            for gap in gap_analysis.gaps
            if gap.estimated_gap_fill_roi >= 0.55 and gap.priority in {"high", "critical"}
        ]
        if not high_roi_gaps:
            return SearchReflectionDecision(
                rewritten_queries=[],
                topics_to_stop=self.target_topics,
                rationale="No high-ROI coverage gaps remain.",
                confidence=0.75,
            )
        topics = [gap.taxonomy_or_component for gap in high_roi_gaps[:4]]
        query_text = self._non_repeating_gap_query(topics, blackboard)
        query = SearchQueryPlan(
            query_text=query_text,
            source_names=[source.source_name for source in blackboard.approved_sources if source.enabled],
            target_topics=topics,
            query_intent="gap_fill",
            max_results=self.max_results_per_round,
            priority="high",
            rationale="Fallback rewrite around missing high-ROI topics.",
            round_index=len(blackboard.query_history),
        )
        return SearchReflectionDecision(
            rewritten_queries=[query],
            topics_to_expand=topics,
            topics_to_stop=sorted(set(self.target_topics) - set(topics)),
            rationale="Coverage gaps remain, so rewrite query for another real-source round.",
            confidence=0.8,
        )

    def _non_repeating_gap_query(
        self,
        topics: list[str],
        blackboard: IntelRunBlackboard,
    ) -> str:
        previous_queries = {entry.query_text for entry in blackboard.query_history}
        topic_text = " ".join(topics).lower()
        templates: list[str] = []
        semantic_terms = []
        for source_name in ("arxiv_api", "nvd_cve_api", "cisa_kev_json"):
            semantic_terms.extend(self._semantic_terms_for_source(source_name, topics))
        if semantic_terms:
            templates.append(" ".join(_dedupe_preserve_order(semantic_terms)[:8]))
        if "agent" in topic_text or "tool" in topic_text:
            templates.extend(
                [
                    "agent tool abuse incidents LLM autonomous agents code execution permissions",
                    "LangChain LlamaIndex agent tool execution vulnerability advisory",
                ]
            )
        if "data" in topic_text or "leak" in topic_text:
            templates.extend(
                [
                    "LLM data leakage sensitive information exposure training data vulnerability",
                    "chatbot data exposure embedding vector database sensitive information",
                ]
            )
        if "supply" in topic_text or "model" in topic_text:
            templates.extend(
                [
                    "AI model supply chain MLflow Gradio Langflow vulnerability advisory",
                    "Hugging Face Transformers model loading deserialization vulnerability",
                ]
            )
        if "rag" in topic_text or "poison" in topic_text:
            templates.extend(
                [
                    "RAG poisoning embedding vector database vulnerability advisory",
                    "retrieval augmented generation data poisoning vector database security",
                ]
            )
        if "prompt" in topic_text:
            templates.append("prompt injection indirect prompt injection chatbot vulnerability")
        if "jailbreak" in topic_text:
            templates.append("LLM jailbreak attack benchmark mitigation security paper")

        templates.append(build_gap_query(topics))
        for template in templates:
            if template not in previous_queries:
                return template
        return f"{templates[0]} latest exploitation mitigation evidence"

    def _evaluate_search_completeness(
        self,
        blackboard: IntelRunBlackboard,
        yield_assessment: CollectionYieldAssessment,
        gap_analysis: CoverageGapAnalysis,
        reflection: SearchReflectionDecision,
        round_index: int,
    ) -> SearchCompletenessAssessment:
        prompt = (
            "Decide whether the real-source intelligence search should continue. "
            "Return JSON with should_continue, completeness_score, missing_topics, "
            "recommended_next_query, stop_reason, and rationale.\n\n"
            f"Coverage analysis: {gap_analysis.model_dump_json()}\n"
            f"Reflection: {reflection.model_dump_json()}\n"
            f"Round index: {round_index}, max rounds: {self.max_rounds}"
        )
        policy_continue, policy_stop_rationale, diminishing_evidence = self._loop_policy_decision(
            blackboard,
            yield_assessment,
            gap_analysis,
            round_index,
        )

        parsed = _kickoff_json(self.agents.critic, prompt, CompletenessDecisionOutput)
        if parsed is not None:
            should_continue = (
                parsed.should_continue
                and policy_continue
                and bool(parsed.recommended_next_query or reflection.rewritten_queries)
            )
            return SearchCompletenessAssessment(
                completeness_score=parsed.completeness_score,
                should_continue=should_continue,
                missing_dimensions=parsed.missing_topics,
                diminishing_returns_evidence=diminishing_evidence,
                recommended_next_mode="gap_fill" if should_continue else None,
                stop_rationale=(
                    None
                    if should_continue
                    else policy_stop_rationale or parsed.stop_reason or parsed.rationale
                ),
            )

        should_continue = policy_continue and bool(reflection.rewritten_queries)
        return SearchCompletenessAssessment(
            completeness_score=gap_analysis.overall_coverage_score,
            should_continue=should_continue,
            missing_dimensions=[gap.taxonomy_or_component for gap in gap_analysis.gaps],
            diminishing_returns_evidence=diminishing_evidence,
            recommended_next_mode="gap_fill" if should_continue else None,
            stop_rationale=(
                None
                if should_continue
                else policy_stop_rationale or "No next query available after coverage review."
            ),
        )

    def _loop_policy_decision(
        self,
        blackboard: IntelRunBlackboard,
        yield_assessment: CollectionYieldAssessment,
        gap_analysis: CoverageGapAnalysis,
        round_index: int,
    ) -> tuple[bool, str | None, list[str]]:
        budget = blackboard.budget
        diminishing_evidence = self._diminishing_return_evidence(
            blackboard.query_history,
            budget.max_low_yield_rounds,
            budget.min_novelty_delta,
            budget.max_duplicate_ratio,
        )
        high_roi_gaps = [
            gap
            for gap in gap_analysis.gaps
            if gap.estimated_gap_fill_roi >= budget.high_roi_gap_min_score
            or gap.priority in {"high", "critical"}
        ]
        low_collection_yield = self._low_collection_yield(
            yield_assessment,
            budget.min_novelty_delta,
            budget.max_duplicate_ratio,
        )

        if round_index + 1 >= self.max_rounds:
            return False, "Round hard limit reached.", diminishing_evidence
        budget_rationale = self._budget_limit_rationale(blackboard)
        if budget_rationale is not None:
            return False, budget_rationale, diminishing_evidence
        if diminishing_evidence:
            return (
                False,
                "Recent collection rounds have persistently low novelty and high duplicate ratio.",
                diminishing_evidence,
            )
        if gap_analysis.overall_coverage_score >= budget.target_coverage_score:
            return False, "Target coverage score reached.", diminishing_evidence
        if not high_roi_gaps:
            return False, "No high-ROI coverage gaps remain.", diminishing_evidence
        if (
            budget.max_low_yield_rounds > 0
            and low_collection_yield
            and len(blackboard.query_history) >= budget.max_low_yield_rounds
        ):
            return (
                False,
                "Collection yield is below novelty and duplicate thresholds.",
                diminishing_evidence,
            )
        return True, None, diminishing_evidence

    def _low_collection_yield(
        self,
        yield_assessment: CollectionYieldAssessment,
        min_novelty_delta: float,
        max_duplicate_ratio: float,
    ) -> bool:
        if not yield_assessment.per_source_metrics:
            return False
        return all(
            (
                metric.novelty_score < min_novelty_delta
                and metric.duplicate_ratio >= max_duplicate_ratio
            )
            or metric.result_count == 0
            for metric in yield_assessment.per_source_metrics
        )

    def _diminishing_return_evidence(
        self,
        history: list[QueryHistoryEntry],
        max_low_yield_rounds: int,
        min_novelty_delta: float,
        max_duplicate_ratio: float,
    ) -> list[str]:
        if max_low_yield_rounds <= 0 or len(history) < max_low_yield_rounds:
            return []
        recent = history[-max_low_yield_rounds:]
        if not all(entry.novelty_score < min_novelty_delta for entry in recent):
            return []
        if not all(entry.duplicate_ratio >= max_duplicate_ratio for entry in recent):
            return []
        return [
            f"round {entry.round_index}: novelty={entry.novelty_score:.2f}, duplicate={entry.duplicate_ratio:.2f}"
            for entry in recent
        ]

    def _budget_limit_rationale(self, blackboard: IntelRunBlackboard) -> str | None:
        budget = blackboard.budget
        warning_ratio = budget.budget_warning_ratio
        budget_checks = (
            (budget.max_api_calls, blackboard.metrics.api_calls_used, "API call budget"),
            (budget.max_tokens, blackboard.metrics.tokens_used, "token budget"),
            (budget.max_cost_usd, blackboard.metrics.cost_used, "cost budget"),
            (budget.max_seconds, blackboard.metrics.elapsed_seconds, "time budget"),
        )
        for limit, used, label in budget_checks:
            if limit is not None and limit > 0 and used / limit >= warning_ratio:
                return f"{label} is near its configured limit."
        return None

    def _semantic_terms_for_source(
        self,
        source_name: str,
        focus_topics: list[str],
    ) -> list[str]:
        if self._latest_semantic_expansion is None:
            return []
        focus = {topic.lower() for topic in focus_topics}
        terms: list[str] = []
        for expansion in self._latest_semantic_expansion.expansions:
            if focus and expansion.gap_topic.lower() not in focus:
                matched = any(topic in expansion.gap_topic.lower() for topic in focus)
                matched = matched or any(expansion.gap_topic.lower() in topic for topic in focus)
                if not matched:
                    continue
            for source_terms in expansion.source_specific_terms:
                if source_terms.source_name == source_name:
                    terms.extend(source_terms.positive_terms)
        return _dedupe_preserve_order(terms)

    def _focus_topics(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> list[str]:
        gap_topics = [
            gap.taxonomy_or_component
            for gap in blackboard.coverage_gaps
            if gap.priority in {"high", "critical"} or gap.estimated_gap_fill_roi >= 0.55
        ]
        topics = gap_topics or query_plan.target_topics or self.target_topics
        normalized: list[str] = []
        for topic in topics:
            lowered = topic.lower()
            if lowered not in normalized:
                normalized.append(lowered)
        return normalized[:6]

    def _nvd_keywords_for_topics(self, focus_topics: list[str]) -> list[str]:
        keywords: list[str] = self._semantic_terms_for_source("nvd_cve_api", focus_topics)
        topic_text = " ".join(focus_topics).lower()
        if "prompt injection" in topic_text:
            keywords.extend(["prompt injection", "indirect prompt injection", "chatbot"])
        if "jailbreak" in topic_text:
            keywords.extend(["jailbreak", "large language model", "LLM"])
        if "rag" in topic_text or "poison" in topic_text:
            keywords.extend(["RAG", "embedding", "vector database", "data poisoning"])
        if "supply" in topic_text or "model" in topic_text:
            keywords.extend(["model extraction", "model inversion", "training data"])
            keywords.extend(["LangChain", "LlamaIndex", "MLflow", "Gradio", "Hugging Face"])
        if "agent" in topic_text or "tool" in topic_text:
            keywords.extend(["LangChain", "LlamaIndex", "Jupyter", "Ray", "code injection"])
        if "data leakage" in topic_text or "leak" in topic_text:
            keywords.extend(["training data", "sensitive information", "Jupyter", "Chroma"])

        keywords.extend(NVD_AI_ATTACK_KEYWORDS)
        keywords.extend(NVD_AI_PRODUCT_KEYWORDS)
        return _dedupe_preserve_order(keywords)

    def _nvd_product_cwe_pairs(
        self,
        focus_topics: list[str],
        round_index: int,
    ) -> list[tuple[str, str]]:
        topic_text = " ".join(focus_topics).lower()
        pairs: list[tuple[str, str]] = []
        if "supply" in topic_text or "model" in topic_text:
            pairs.extend([("MLflow", "CWE-502"), ("Gradio", "CWE-434"), ("Langflow", "CWE-94")])
        if "agent" in topic_text or "tool" in topic_text:
            pairs.extend([("LangChain", "CWE-94"), ("Jupyter", "CWE-78"), ("Ray", "CWE-287")])
        if "rag" in topic_text or "data" in topic_text:
            pairs.extend([("Chroma", "CWE-200"), ("Qdrant", "CWE-287"), ("Weaviate", "CWE-918")])
        if not pairs:
            pairs.extend([("MLflow", "CWE-502"), ("Gradio", "CWE-434"), ("Langflow", "CWE-94")])
        pairs = [pair for pair in pairs if pair[1] in NVD_AI_RELEVANT_CWE_IDS]
        return self._rotating_slice(_dedupe_preserve_order(pairs), round_index, 2)

    def _cisa_keywords(self, focus_topics: list[str], round_index: int) -> list[str]:
        semantic_terms = self._semantic_terms_for_source("cisa_kev_json", focus_topics)
        candidates = semantic_terms + self._nvd_keywords_for_topics(focus_topics)
        product_terms = [term for term in candidates if term in NVD_AI_PRODUCT_KEYWORDS]
        attack_terms = [term for term in candidates if term not in NVD_AI_PRODUCT_KEYWORDS]
        ordered = product_terms + attack_terms
        return self._rotating_slice(_dedupe_preserve_order(ordered), round_index, 3)

    def _osv_packages(self, focus_topics: list[str], round_index: int) -> list[dict[str, str]]:
        topic_text = " ".join(focus_topics).lower()
        preferred_names: list[str] = [
            term.lower()
            for term in self._semantic_terms_for_source("osv_dev_api", focus_topics)
        ]
        if "supply" in topic_text or "model" in topic_text:
            preferred_names.extend(["mlflow", "transformers", "gradio", "vllm", "open-webui"])
        if "agent" in topic_text or "tool" in topic_text:
            preferred_names.extend(["langchain", "llama-index", "langflow", "flowise"])
        if "rag" in topic_text or "data" in topic_text:
            preferred_names.extend(["chromadb", "qdrant-client", "weaviate-client", "llama-index"])

        packages = [
            package
            for name in preferred_names
            for package in DEFAULT_OSV_PACKAGE_TARGETS
            if package["name"].lower() == name.lower()
        ]
        packages.extend(DEFAULT_OSV_PACKAGE_TARGETS)
        deduped: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for package in packages:
            key = (package["ecosystem"], package["name"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(package)
        return self._rotating_slice(deduped, round_index, 5)

    def _arxiv_strategy_query(self, focus_topics: list[str]) -> str:
        semantic_terms = self._semantic_terms_for_source("arxiv_api", focus_topics)
        phrases = _dedupe_preserve_order(semantic_terms + focus_topics)[:6] or self.target_topics[:4]
        phrase_query = " OR ".join(f'all:"{phrase}"' for phrase in phrases)
        return f"({phrase_query}) AND (cat:cs.CR OR cat:cs.AI OR cat:cs.CL)"

    def _nvd_query_limit(self) -> int:
        default_limit = 8 if os.getenv("NVD_API_KEY") else 3
        raw_limit = os.getenv("NVD_STRATEGY_QUERY_LIMIT")
        if not raw_limit:
            return default_limit
        try:
            return max(1, int(raw_limit))
        except ValueError:
            return default_limit

    def _rotating_slice(self, values: list[Any], round_index: int, limit: int) -> list[Any]:
        if not values or limit <= 0:
            return []
        if len(values) <= limit:
            return values
        start = (round_index * limit) % len(values)
        rotated = values[start:] + values[:start]
        return rotated[:limit]

    def _source_query_key(self, spec: SourceQuerySpec) -> str:
        return json.dumps(
            {
                "source_name": spec.source_name,
                "query_text": spec.query_text,
                "strategy_name": spec.strategy_name,
                "params": spec.params,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    def _covered_topics(self, items: list[RawIntelItem]) -> set[str]:
        covered: set[str] = set()
        for item in items:
            covered.update(topic for topic in item.metadata.get("topics", []) if topic in self.target_topics)
            covered.update(detect_topics(f"{item.title} {item.summary} {item.raw_text or ''}"))
        return covered & set(self.target_topics)

    def _persist(self, blackboard: IntelRunBlackboard, status: str) -> None:
        self.run_store.save_run(
            blackboard,
            raw_item_batches=self.raw_item_batches,
            status=status,
        )

    def _approved_sources_json(self, blackboard: IntelRunBlackboard) -> str:
        return json.dumps(
            [source.model_dump(mode="json") for source in blackboard.approved_sources],
            ensure_ascii=False,
        )

    def _blackboard_summary(self, blackboard: IntelRunBlackboard) -> dict[str, Any]:
        return {
            "run_id": blackboard.run_id,
            "raw_items": len(blackboard.raw_items),
            "query_history": [entry.model_dump(mode="json") for entry in blackboard.query_history],
            "coverage_gaps": [gap.taxonomy_or_component for gap in blackboard.coverage_gaps],
            "approved_sources": [source.source_name for source in blackboard.approved_sources],
        }


def _kickoff_json(agent: Any, prompt: str, model: type[BaseModel]) -> Any | None:
    if not _agent_kickoff_enabled():
        return None

    try:
        result = agent.kickoff(prompt)
    except Exception:
        return None

    pydantic_result = getattr(result, "pydantic", None)
    if pydantic_result is not None:
        try:
            return model.model_validate(pydantic_result)
        except ValidationError:
            pass

    raw = getattr(result, "raw", None) or str(result)
    try:
        return model.model_validate_json(raw)
    except ValidationError:
        pass

    try:
        return model.model_validate(_extract_json_object(raw))
    except (json.JSONDecodeError, ValidationError, ValueError):
        return None


def _agent_kickoff_enabled() -> bool:
    value = os.getenv("INTEL_ENABLE_AGENT_KICKOFF", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _extract_json_object(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    elif "{" in cleaned and "}" in cleaned:
        cleaned = cleaned[cleaned.find("{") : cleaned.rfind("}") + 1]
    return json.loads(cleaned)


def _batch_from_collection_output(
    output: CollectionBatchOutput,
    query_plan: SearchQueryPlan,
) -> RawIntelItemBatch:
    items = [
        RawIntelItem(
            item_id=_item_id(item.source_name, item.source_uri, item.title),
            source_name=item.source_name,
            source_uri=item.source_uri,
            title=item.title,
            summary=item.summary,
            raw_text=item.evidence_snippet,
            relevance_score=item.relevance_score,
            extraction_notes="Normalized from source collector agent output.",
            metadata={"topics": item.topics, "source_type": "real_api"},
        )
        for item in output.items
        if "mock.local" not in item.source_uri
    ]
    source_counts: dict[str, int] = {}
    for item in items:
        source_counts[item.source_name] = source_counts.get(item.source_name, 0) + 1
    return RawIntelItemBatch(
        items=items,
        query_plan=query_plan,
        source_stats=[
            SourceExecutionStat(
                source_name=source_name,
                query_count=1,
                result_count=result_count,
                success=True,
                notes="collector agent normalized result",
            )
            for source_name, result_count in sorted(source_counts.items())
        ],
        batch_notes=output.batch_notes,
    )


def _item_id(source_name: str, source_uri: str, title: str) -> str:
    digest = hashlib.sha256(f"{source_name}|{source_uri}|{title}".encode("utf-8")).hexdigest()
    return f"real:{digest[:16]}"


def _dedupe_preserve_order(values: list[Any]) -> list[Any]:
    deduped: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list, tuple)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


def _batch_source_query_plans(batch_notes: str | None) -> list[dict[str, Any]]:
    if not batch_notes:
        return []
    try:
        parsed = json.loads(batch_notes)
    except json.JSONDecodeError:
        return []
    plans = parsed.get("source_query_plans") if isinstance(parsed, dict) else None
    if not isinstance(plans, list):
        return []
    return [plan for plan in plans if isinstance(plan, dict)]
