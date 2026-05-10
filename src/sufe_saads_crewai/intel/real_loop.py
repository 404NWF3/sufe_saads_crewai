from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
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
    SourceExecutionStat,
    SourceYieldMetric,
    YieldAssessmentOutput,
)
from sufe_saads_crewai.tools import (
    RegisteredApiSourceSearchTool,
    default_registered_api_sources,
)


@dataclass
class RealIntelAgentSet:
    planner: Any
    collector: Any
    critic: Any


class RealIntelRunController:
    """Runs the real-source intelligence loop used by `crewai run`."""

    def __init__(
        self,
        run_goal: str,
        initial_query: str,
        max_rounds: int = 5,
        max_results_per_round: int = 20,
        run_store: JsonIntelRunStore | None = None,
        agents: RealIntelAgentSet | None = None,
        source_tool: RegisteredApiSourceSearchTool | None = None,
        target_topics: list[str] | None = None,
    ) -> None:
        self.run_goal = run_goal
        self.initial_query = initial_query
        self.max_rounds = max_rounds
        self.max_results_per_round = max_results_per_round
        self.run_store = run_store or JsonIntelRunStore()
        self.agents = agents or self._default_agents()
        self.source_tool = source_tool or RegisteredApiSourceSearchTool()
        self.target_topics = target_topics or list(TARGET_SECURITY_TOPICS)
        self.raw_item_batches: list[RawIntelItemBatch] = []

    def run(self) -> IntelRunBlackboard:
        blackboard = IntelRunBlackboard(
            run_id=f"real-{uuid4().hex[:8]}",
            run_goal=self.run_goal,
            run_mode="bootstrap",
            budget=RunBudget(max_rounds=self.max_rounds, max_api_calls=100, max_sources=12),
            approved_sources=default_registered_api_sources(),
        )
        current_query = self.initial_query

        for round_index in range(self.max_rounds):
            query_plan = self._query_plan(blackboard, current_query, round_index)
            action_batch = self._select_next_actions(blackboard, query_plan)
            blackboard.action_history.extend(action_batch.actions)

            latest_batch = self._collect_real_sources(blackboard, query_plan)
            self.raw_item_batches.append(latest_batch)
            self._merge_batch_into_blackboard(blackboard, query_plan, latest_batch)

            yield_assessment = self._assess_collection_yield(blackboard, latest_batch)
            gap_analysis = self._analyze_coverage_gaps(blackboard)
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

            completeness = self._evaluate_search_completeness(
                blackboard,
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
        raw = self.source_tool._run(
            query_text=query_plan.query_text,
            source_names=query_plan.source_names,
            target_topics=query_plan.target_topics,
            max_results=query_plan.max_results,
            round_index=query_plan.round_index,
            approved_sources_json=self._approved_sources_json(blackboard),
        )
        return RawIntelItemBatch.model_validate_json(raw)

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
        query = SearchQueryPlan(
            query_text=build_gap_query(topics),
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

    def _evaluate_search_completeness(
        self,
        blackboard: IntelRunBlackboard,
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
        parsed = _kickoff_json(self.agents.critic, prompt, CompletenessDecisionOutput)
        if parsed is not None:
            return SearchCompletenessAssessment(
                completeness_score=parsed.completeness_score,
                should_continue=(
                    parsed.should_continue
                    and round_index + 1 < self.max_rounds
                    and bool(parsed.recommended_next_query or reflection.rewritten_queries)
                ),
                missing_dimensions=parsed.missing_topics,
                recommended_next_mode="gap_fill" if parsed.should_continue else None,
                stop_rationale=parsed.stop_reason or parsed.rationale,
            )

        should_continue = (
            round_index + 1 < self.max_rounds
            and gap_analysis.overall_coverage_score < 0.85
            and bool(gap_analysis.gaps)
            and bool(reflection.rewritten_queries)
        )
        return SearchCompletenessAssessment(
            completeness_score=gap_analysis.overall_coverage_score,
            should_continue=should_continue,
            missing_dimensions=[gap.taxonomy_or_component for gap in gap_analysis.gaps],
            recommended_next_mode="gap_fill" if should_continue else None,
            stop_rationale=None if should_continue else "Coverage threshold, query, or round budget stop condition met.",
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
