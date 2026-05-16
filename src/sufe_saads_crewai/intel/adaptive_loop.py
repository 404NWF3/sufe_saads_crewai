from __future__ import annotations

import json
from typing import Iterable
from uuid import uuid4

from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import (
    ActionDecision,
    ActionDecisionBatch,
    CollectionYieldAssessment,
    CoverageGap,
    CoverageGapAnalysis,
    IntelRunBlackboard,
    QueryHistoryEntry,
    RawIntelItem,
    RawIntelItemBatch,
    RunBudget,
    SearchCompletenessAssessment,
    SearchQueryPlan,
    SearchReflectionDecision,
    SourceProposal,
    SourceYieldMetric,
)
from sufe_saads_crewai.tools.mock_source_tools import (
    MockSourceProposalTool,
    MockSourceRepository,
)
from sufe_saads_crewai.topic_utils import (
    TARGET_SECURITY_TOPICS,
    build_gap_query,
    detect_topic_matches,
    semantic_terms_for_topic,
    topic_coverage_scores,
)
from sufe_saads_crewai.tools.mock_source_tools import default_mock_sources


class AutonomousPlannerRuntime:
    """Deterministic planner used to validate the autonomous loop without an LLM."""

    def __init__(self, target_topics: list[str] | None = None) -> None:
        self.target_topics = target_topics or list(TARGET_SECURITY_TOPICS)

    def create_initial_query_plan(
        self,
        blackboard: IntelRunBlackboard,
        initial_query: str,
    ) -> SearchQueryPlan:
        return SearchQueryPlan(
            query_text=initial_query,
            source_names=[source.source_name for source in blackboard.approved_sources if source.enabled],
            target_topics=self.target_topics,
            query_intent="broad_recall",
            max_results=10,
            priority="high",
            rationale="Initial broad recall over approved mock sources.",
            round_index=0,
        )

    def select_next_actions(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> ActionDecisionBatch:
        actions = [
            ActionDecision(
                action_type="SEARCH_REGISTERED_SOURCE",
                priority=query_plan.priority,
                rationale="Collect from approved sources using the current query plan.",
                expected_gain="More raw intelligence and coverage signals.",
                required_context=[query_plan.query_text],
                success_criteria=["RawIntelItemBatch contains source_uri for each item."],
                stop_conditions=["No enabled approved sources remain."],
            ),
            ActionDecision(
                action_type="ASSESS_COLLECTION_YIELD",
                priority="medium",
                rationale="Measure novelty, duplicate ratio, noise, and evidence quality.",
                expected_gain="Determine whether the query should be rewritten.",
                required_context=["latest RawIntelItemBatch", "query_history"],
                success_criteria=["CollectionYieldAssessment is produced."],
            ),
            ActionDecision(
                action_type="ANALYZE_COVERAGE_GAPS",
                priority="medium",
                rationale="Check whether target LLM security dimensions are still missing.",
                expected_gain="Identify high-ROI gaps for the next query.",
                required_context=["raw_items", "target_topics"],
                success_criteria=["CoverageGapAnalysis is produced."],
            ),
        ]

        if not blackboard.query_history:
            actions.insert(
                0,
                ActionDecision(
                    action_type="PLAN_COLLECTION",
                    priority="high",
                    rationale="Create the first approved-source collection plan.",
                    expected_gain="Start the autonomous collection loop.",
                    required_context=[blackboard.run_goal],
                    success_criteria=["A SearchQueryPlan is available."],
                ),
            )

        return ActionDecisionBatch(actions=actions, planner_rationale="Run the next search-assess-reflect cycle.")

    def rewrite_search_strategy(
        self,
        blackboard: IntelRunBlackboard,
        yield_assessment: CollectionYieldAssessment,
        gap_analysis: CoverageGapAnalysis,
    ) -> SearchReflectionDecision:
        high_value_gaps = [
            gap
            for gap in gap_analysis.gaps
            if gap.estimated_gap_fill_roi >= 0.55 and gap.priority in {"high", "critical"}
        ]
        gap_topics = [gap.taxonomy_or_component for gap in high_value_gaps]
        if not gap_topics:
            return SearchReflectionDecision(
                rewritten_queries=[],
                topics_to_stop=self.target_topics,
                rationale="No high-ROI coverage gaps remain.",
                confidence=0.76,
            )

        query_plan = SearchQueryPlan(
            query_text=build_gap_query(gap_topics[:4]),
            source_names=[source.source_name for source in blackboard.approved_sources if source.enabled],
            target_topics=gap_topics[:4],
            query_intent="gap_fill",
            max_results=10,
            priority="high",
            rationale="Rewrite query around missing high-ROI LLM security topics.",
            round_index=len(blackboard.query_history),
        )
        source_priority_changes = {
            source_name: {"priority_delta": -1, "reason": "low yield in latest round"}
            for source_name in yield_assessment.low_yield_sources
        }

        return SearchReflectionDecision(
            rewritten_queries=[query_plan],
            source_priority_changes=source_priority_changes,
            topics_to_expand=gap_topics,
            topics_to_stop=sorted(set(self.target_topics) - set(gap_topics)),
            rationale="Coverage gaps remain, so rewrite the query instead of repeating the same pattern.",
            confidence=0.82,
        )

    def stop_action(self, completeness: SearchCompletenessAssessment) -> ActionDecision:
        return ActionDecision(
            action_type="STOP",
            priority="high",
            rationale=completeness.stop_rationale or "Autonomous loop stop criteria were met.",
            expected_gain="Avoid low-value repeated collection.",
            required_context=["SearchCompletenessAssessment"],
            success_criteria=["Run summary can explain the stop reason."],
        )

    def reflect_action(self, reflection: SearchReflectionDecision) -> ActionDecision:
        return ActionDecision(
            action_type="REFLECT_SEARCH_STRATEGY",
            priority="high",
            rationale=reflection.rationale,
            expected_gain="Improve recall over uncovered security topics.",
            required_context=[query.query_text for query in reflection.rewritten_queries],
            success_criteria=["At least one rewritten query is ready or stop conditions are clear."],
        )


class SourceCollectorRuntime:
    """Executes approved-source collection against deterministic mock tools."""

    def __init__(self, repository: MockSourceRepository | None = None) -> None:
        self.repository = repository or MockSourceRepository()
        self.proposal_tool = MockSourceProposalTool()

    def search_registered_sources(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
    ) -> RawIntelItemBatch:
        existing_item_ids = {item.item_id for item in blackboard.raw_items}
        batch = self.repository.search(query_plan, blackboard.approved_sources)

        new_items: list[RawIntelItem] = []
        duplicate_count = 0
        for item in batch.items:
            if item.item_id in existing_item_ids:
                duplicate_count += 1
                continue
            blackboard.raw_items.append(item)
            new_items.append(item)

        result_count = len(batch.items)
        low_relevance_count = sum(1 for item in batch.items if item.relevance_score < 0.5)
        query_history = QueryHistoryEntry(
            query_text=query_plan.query_text,
            source_names=query_plan.source_names,
            result_count=result_count,
            novelty_score=(len(new_items) / result_count) if result_count else 0.0,
            noise_ratio=(low_relevance_count / result_count) if result_count else 0.0,
            duplicate_ratio=(duplicate_count / result_count) if result_count else 0.0,
            round_index=query_plan.round_index,
            metadata={
                "new_item_ids": [item.item_id for item in new_items],
                "batch_item_ids": [item.item_id for item in batch.items],
            },
        )
        blackboard.query_history.append(query_history)
        blackboard.metrics.api_calls_used += max(1, len(batch.source_stats))
        blackboard.metrics.sources_used = len(
            {
                source_name
                for history in blackboard.query_history
                for source_name in history.source_names
            }
        )

        return batch

    def propose_new_sources(
        self,
        blackboard: IntelRunBlackboard,
        gaps: Iterable[CoverageGap],
    ) -> list[SourceProposal]:
        approved_names = {source.source_name for source in blackboard.approved_sources}
        existing_proposals = {proposal.source_name for proposal in blackboard.source_proposals}
        missing_topics = [
            gap.taxonomy_or_component
            for gap in gaps
            if gap.estimated_gap_fill_roi >= 0.6
        ]
        raw = self.proposal_tool._run(missing_topics=missing_topics)
        proposals = [SourceProposal.model_validate(item) for item in json.loads(raw)]

        accepted: list[SourceProposal] = []
        for proposal in proposals:
            if proposal.source_name in approved_names or proposal.source_name in existing_proposals:
                continue
            proposal.approval_status = "pending"
            blackboard.source_proposals.append(proposal)
            existing_proposals.add(proposal.source_name)
            accepted.append(proposal)
        return accepted


class ReflectionCoverageCriticRuntime:
    """Evaluates yield, coverage, and stop criteria for the mock loop."""

    def __init__(
        self,
        target_topics: list[str] | None = None,
        target_coverage_score: float = 0.85,
    ) -> None:
        self.target_topics = target_topics or list(TARGET_SECURITY_TOPICS)
        self.target_coverage_score = target_coverage_score

    def assess_collection_yield(
        self,
        blackboard: IntelRunBlackboard,
        latest_batch: RawIntelItemBatch,
    ) -> CollectionYieldAssessment:
        latest_history = blackboard.query_history[-1] if blackboard.query_history else None
        per_source_metrics: list[SourceYieldMetric] = []

        for stat in latest_batch.source_stats:
            source_items = [
                item for item in latest_batch.items if item.source_name == stat.source_name
            ]
            evidence_quality = (
                sum(item.relevance_score for item in source_items) / len(source_items)
                if source_items
                else 0.0
            )
            per_source_metrics.append(
                SourceYieldMetric(
                    source_name=stat.source_name,
                    result_count=stat.result_count,
                    novelty_score=latest_history.novelty_score if latest_history else 0.0,
                    noise_ratio=latest_history.noise_ratio if latest_history else 0.0,
                    duplicate_ratio=latest_history.duplicate_ratio if latest_history else 0.0,
                    evidence_quality=evidence_quality,
                    notes=stat.notes,
                )
            )

        low_yield_sources = [
            metric.source_name
            for metric in per_source_metrics
            if metric.result_count == 0 or metric.evidence_quality < 0.45
        ]
        useful_queries = [
            latest_history.query_text
            for _ in [latest_history]
            if latest_history and latest_history.result_count > 0 and latest_history.novelty_score >= 0.2
        ]
        high_noise_queries = [
            latest_history.query_text
            for _ in [latest_history]
            if latest_history and latest_history.noise_ratio >= 0.5
        ]

        return CollectionYieldAssessment(
            per_source_metrics=per_source_metrics,
            low_yield_sources=low_yield_sources,
            high_noise_queries=high_noise_queries,
            useful_queries=useful_queries,
            novelty_summary=self._novelty_summary(latest_history),
            recommended_adjustments=self._recommended_adjustments(latest_history, low_yield_sources),
        )

    def analyze_coverage_gaps(self, blackboard: IntelRunBlackboard) -> CoverageGapAnalysis:
        coverage_scores = topic_coverage_scores(blackboard.raw_items)
        covered_topics = {
            topic for topic, score in coverage_scores.items() if score >= 0.60
        }
        gaps: list[CoverageGap] = []

        for topic in self.target_topics:
            current_coverage = coverage_scores.get(topic, 0.0)
            if current_coverage >= 0.60:
                continue

            estimated_roi = round(min(1.0, 1.0 - current_coverage + 0.18), 3)
            priority = "critical" if current_coverage < 0.2 else "high"
            source_hints = self._source_hints_for_topic(topic)
            gaps.append(
                CoverageGap(
                    gap_id=f"gap-{topic.replace(' ', '-')}",
                    dimension="llm_security_taxonomy",
                    taxonomy_or_component=topic,
                    current_coverage=current_coverage,
                    target_coverage=0.65,
                    estimated_gap_fill_roi=estimated_roi,
                    recommended_queries=[
                        SearchQueryPlan(
                            query_text=build_gap_query([topic]),
                            target_topics=[topic],
                            query_intent="semantic_gap_fill",
                            priority=priority,
                            rationale=(
                                "Fill semantic coverage gap using aliases, attack indicators, "
                                "and source-specific terms rather than exact topic labels only."
                            ),
                            metadata={
                                "semantic_terms": semantic_terms_for_topic(topic),
                                "source_hints": source_hints,
                            },
                        )
                    ],
                    recommended_sources=list(source_hints),
                    priority=priority,
                    metadata={
                        "covered_topics": sorted(covered_topics),
                        "coverage_scores": coverage_scores,
                        "semantic_terms": semantic_terms_for_topic(topic),
                        "source_hints": source_hints,
                    },
                )
            )

        blackboard.coverage_gaps = gaps
        overall_score = (
            sum(coverage_scores.get(topic, 0.0) for topic in self.target_topics)
            / len(self.target_topics)
        )
        return CoverageGapAnalysis(
            gaps=gaps,
            overall_coverage_score=round(overall_score, 3),
            analysis_rationale=(
                "Coverage is scored semantically with aliases, source-type indicators, "
                "explicit metadata topics, and evidence relevance. A topic is considered "
                "covered at score >= 0.65."
            ),
        )

    def evaluate_search_completeness(
        self,
        blackboard: IntelRunBlackboard,
        gap_analysis: CoverageGapAnalysis,
    ) -> SearchCompletenessAssessment:
        budget_exhausted = self._budget_exhausted(blackboard)
        diminishing_returns = self._diminishing_returns(blackboard.query_history)
        high_roi_gaps = [
            gap
            for gap in gap_analysis.gaps
            if gap.estimated_gap_fill_roi >= 0.65
        ]
        should_continue = (
            not budget_exhausted
            and not diminishing_returns
            and gap_analysis.overall_coverage_score < self.target_coverage_score
            and bool(high_roi_gaps)
        )

        stop_rationale = None
        if not should_continue:
            if budget_exhausted:
                stop_rationale = "Round budget exhausted."
            elif diminishing_returns:
                stop_rationale = "Recent query novelty converged and duplicate ratio is high."
            elif gap_analysis.overall_coverage_score >= self.target_coverage_score:
                stop_rationale = "Target coverage score reached."
            else:
                stop_rationale = "No high-ROI coverage gaps remain."

        return SearchCompletenessAssessment(
            completeness_score=gap_analysis.overall_coverage_score,
            should_continue=should_continue,
            missing_dimensions=[gap.taxonomy_or_component for gap in gap_analysis.gaps],
            diminishing_returns_evidence=self._diminishing_return_evidence(blackboard.query_history),
            recommended_next_mode="gap_fill" if should_continue else None,
            stop_rationale=stop_rationale,
        )

    def covered_topics(self, items: Iterable[RawIntelItem]) -> set[str]:
        scores = topic_coverage_scores(items)
        return {
            topic
            for topic, score in scores.items()
            if topic in self.target_topics and score >= 0.65
        }

    def semantic_topic_matches(self, item: RawIntelItem) -> dict[str, float]:
        text = f"{item.title} {item.summary} {item.raw_text or ''}"
        return {
            match.topic: match.score
            for match in detect_topic_matches(text)
            if match.topic in self.target_topics
        }

    def _source_hints_for_topic(self, topic: str) -> dict[str, list[str]]:
        source_names = ("nvd_cve_api", "osv_dev_api", "arxiv_api", "cisa_kev_json")
        return {
            source_name: semantic_terms_for_topic(topic, source_name=source_name)
            for source_name in source_names
        }

    def _budget_exhausted(self, blackboard: IntelRunBlackboard) -> bool:
        max_rounds = blackboard.budget.max_rounds
        return max_rounds is not None and len(blackboard.query_history) >= max_rounds

    def _diminishing_returns(self, history: list[QueryHistoryEntry]) -> bool:
        if len(history) < 2:
            return False
        recent = history[-2:]
        return all(entry.novelty_score < 0.05 for entry in recent) and all(
            entry.duplicate_ratio >= 0.6 for entry in recent
        )

    def _diminishing_return_evidence(self, history: list[QueryHistoryEntry]) -> list[str]:
        if not self._diminishing_returns(history):
            return []
        return [
            f"round {entry.round_index}: novelty={entry.novelty_score:.2f}, duplicate={entry.duplicate_ratio:.2f}"
            for entry in history[-2:]
        ]

    def _novelty_summary(self, history: QueryHistoryEntry | None) -> str:
        if not history:
            return "No query history yet."
        return (
            f"Latest query returned {history.result_count} items with "
            f"novelty={history.novelty_score:.2f}, noise={history.noise_ratio:.2f}, "
            f"duplicate={history.duplicate_ratio:.2f}."
        )

    def _recommended_adjustments(
        self,
        history: QueryHistoryEntry | None,
        low_yield_sources: list[str],
    ) -> list[str]:
        adjustments: list[str] = []
        if history and history.result_count == 0:
            adjustments.append("Rewrite query with topic-specific terms.")
        if history and history.duplicate_ratio >= 0.5:
            adjustments.append("Avoid repeating prior query terms.")
        if low_yield_sources:
            adjustments.append(f"Lower priority for low-yield sources: {', '.join(low_yield_sources)}.")
        return adjustments


class AutonomousIntelLoop:
    """Runs the search, collection, assessment, reflection, and stop loop."""

    def __init__(
        self,
        blackboard: IntelRunBlackboard,
        planner: AutonomousPlannerRuntime | None = None,
        collector: SourceCollectorRuntime | None = None,
        critic: ReflectionCoverageCriticRuntime | None = None,
        run_store: JsonIntelRunStore | None = None,
    ) -> None:
        self.blackboard = blackboard
        self.planner = planner or AutonomousPlannerRuntime()
        self.collector = collector or SourceCollectorRuntime()
        self.critic = critic or ReflectionCoverageCriticRuntime()
        self.run_store = run_store
        self.raw_item_batches: list[RawIntelItemBatch] = []

    def run(self, initial_query: str) -> IntelRunBlackboard:
        query_plan = self.planner.create_initial_query_plan(self.blackboard, initial_query)

        while True:
            action_batch = self.planner.select_next_actions(self.blackboard, query_plan)
            self.blackboard.action_history.extend(action_batch.actions)

            latest_batch = self.collector.search_registered_sources(self.blackboard, query_plan)
            self.raw_item_batches.append(latest_batch)
            self._persist(status="running")
            yield_assessment = self.critic.assess_collection_yield(self.blackboard, latest_batch)
            gap_analysis = self.critic.analyze_coverage_gaps(self.blackboard)
            self.collector.propose_new_sources(self.blackboard, gap_analysis.gaps)

            completeness = self.critic.evaluate_search_completeness(self.blackboard, gap_analysis)
            self.blackboard.metrics.round_index = len(self.blackboard.query_history)
            if not completeness.should_continue:
                self.blackboard.action_history.append(self.planner.stop_action(completeness))
                break

            reflection = self.planner.rewrite_search_strategy(
                self.blackboard,
                yield_assessment,
                gap_analysis,
            )
            self.blackboard.reflection_notes.append(reflection)
            self.blackboard.action_history.append(self.planner.reflect_action(reflection))
            if not reflection.rewritten_queries:
                stop = SearchCompletenessAssessment(
                    completeness_score=gap_analysis.overall_coverage_score,
                    should_continue=False,
                    stop_rationale="Planner did not produce a useful rewritten query.",
                )
                self.blackboard.action_history.append(self.planner.stop_action(stop))
                break

            query_plan = reflection.rewritten_queries[0]

        self._persist(status="succeeded")
        return self.blackboard

    def _persist(self, status: str) -> None:
        if self.run_store is None:
            return
        self.run_store.save_run(
            self.blackboard,
            raw_item_batches=self.raw_item_batches,
            status=status,
        )


def create_mock_blackboard(
    run_goal: str = "Collect comprehensive LLM security intelligence.",
    max_rounds: int = 3,
) -> IntelRunBlackboard:
    return IntelRunBlackboard(
        run_id=f"mock-{uuid4().hex[:8]}",
        run_goal=run_goal,
        run_mode="bootstrap",
        budget=RunBudget(max_rounds=max_rounds, max_api_calls=50, max_sources=12),
        approved_sources=default_mock_sources(),
    )


def run_mock_autonomous_loop(
    initial_query: str = "LLM prompt injection and agent tool abuse",
    max_rounds: int = 3,
    run_store: JsonIntelRunStore | None = None,
) -> IntelRunBlackboard:
    blackboard = create_mock_blackboard(max_rounds=max_rounds)
    return AutonomousIntelLoop(blackboard, run_store=run_store).run(initial_query=initial_query)
