"""claude-agent-sdk intelligence collection engine (INTEL_ENGINE=sdk).

Hybrid architecture (roadmap 4.1): the Python controller keeps the round
skeleton, safety valves, accounting, and persistence; LLM decisions go through
``StructuredDecisionEngine`` and every failure falls back to the shared
deterministic rules in ``intel/rules.py`` — the same implementation the rules
engine uses, so behavior never drops below the current baseline.

Migrated decision points:
- source selection  (bandit recommendation + agent veto, roadmap 6.1)
- collection plan   (free-form queries + typed advanced operators, 6.2/6.3)
- query rewrite     (replaces template-based gap rewrite)
- termination       (marginal-yield critic with min/max round safety valves, 6.4)

Output conventions are unchanged: blackboard schema, run file layout, and the
``real-`` run-id prefix all match the rules engine; the engine marks itself in
the blackboard's ``engine`` / ``engine_telemetry`` extra fields only.
"""

from __future__ import annotations

import json
import os
from typing import Any
from uuid import uuid4

from sufe_saads_crewai.topic_utils import TARGET_SECURITY_TOPICS
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import (
    ActionDecision,
    CollectionPlanDecision,
    CompletenessDecisionOutput,
    ErrorRecord,
    IntelRunBlackboard,
    RawIntelItemBatch,
    RewriteDecisionOutput,
    RunBudget,
    SearchCompletenessAssessment,
    SearchQueryPlan,
    SearchReflectionDecision,
    SearchSemanticExpansionOutput,
    SourceSelectionDecision,
)
from sufe_saads_crewai.tools import (
    RegisteredApiSourceSearchTool,
    default_registered_api_sources,
)
from sufe_saads_crewai.agent_runtime.structured import StructuredDecisionEngine
from sufe_saads_crewai.intel import rules
from sufe_saads_crewai.intel.bandit import SourceBandit, topic_bucket
from sufe_saads_crewai.intel.context import render_round_context
from sufe_saads_crewai.intel.relevance import RelevancePipeline
from sufe_saads_crewai.intel.rules import SourceQuerySpec

SYSTEM_PROMPT = (
    "You are the planning brain of an LLM-security intelligence collection loop. "
    "You decide which registered sources to query (NVD CVE API, arXiv, CISA KEV, "
    "OSV.dev), what to search for, and when to stop. Optimize new relevant items "
    "per API call. Ground every decision in the metric digest you are given; "
    "never fabricate identifiers or results."
)

ALLOWED_PROPOSAL_PARAMS: dict[str, set[str]] = {
    "nvd_cve_api": {
        "nvd_keyword_search",
        "nvd_keyword_exact_match",
        "nvd_cwe_id",
        "nvd_cvss_v3_severity",
        "nvd_pub_start_date",
        "nvd_pub_end_date",
        "nvd_has_kev",
        "nvd_cve_id",
        "nvd_no_rejected",
    },
    "arxiv_api": {"arxiv_search_query"},
    "cisa_kev_json": {"cisa_keyword", "cisa_cve_ids"},
    "osv_dev_api": {
        "osv_ecosystem",
        "osv_package_name",
        "osv_version",
        "osv_purl",
        "osv_vuln_id",
    },
}

PROPOSAL_GUIDE = (
    "Per-source params (only these keys are honored):\n"
    "- nvd_cve_api: nvd_keyword_search, nvd_keyword_exact_match (multi-word phrases), "
    "nvd_cwe_id (e.g. CWE-502/CWE-94), nvd_cvss_v3_severity (HIGH/CRITICAL), "
    "nvd_pub_start_date+nvd_pub_end_date (ISO-8601 pair), nvd_has_kev, nvd_cve_id\n"
    "- arxiv_api: arxiv_search_query (arXiv query language: all:/ti:/abs:, AND/OR, "
    'quoted phrases, cat:cs.CR etc., e.g. (all:"prompt injection") AND (cat:cs.CR))\n'
    "- cisa_kev_json: cisa_keyword, cisa_cve_ids\n"
    "- osv_dev_api: osv_ecosystem + osv_package_name (e.g. PyPI/mlflow), osv_purl, osv_vuln_id"
)


class SdkIntelRunController:
    """Runs the real-source loop with claude-agent-sdk decisions."""

    def __init__(
        self,
        run_goal: str,
        initial_query: str,
        max_rounds: int = 5,
        max_results_per_round: int = 80,
        run_store: JsonIntelRunStore | None = None,
        source_tool: RegisteredApiSourceSearchTool | None = None,
        target_topics: list[str] | None = None,
        decision_engine: StructuredDecisionEngine | None = None,
        bandit: SourceBandit | None = None,
        relevance_pipeline: RelevancePipeline | None | str = "default",
        min_rounds: int | None = None,
        coverage_quota: int | None = None,
        stall_patience: int | None = None,
        min_new_relevant_per_call: float | None = None,
    ) -> None:
        self.run_goal = run_goal
        self.initial_query = initial_query
        self.max_rounds = max_rounds
        self.max_results_per_round = max_results_per_round
        self.run_store = run_store or JsonIntelRunStore()
        self.source_tool = source_tool or RegisteredApiSourceSearchTool()
        self.target_topics = target_topics or list(TARGET_SECURITY_TOPICS)
        self.decision_engine = decision_engine or StructuredDecisionEngine()
        self.bandit = bandit if bandit is not None else SourceBandit()
        if relevance_pipeline == "default":
            from sufe_saads_crewai.intel.relevance import default_pipeline

            self.relevance_pipeline: RelevancePipeline | None = default_pipeline()
        else:
            self.relevance_pipeline = relevance_pipeline
        self.min_rounds = min_rounds if min_rounds is not None else _env_int("INTEL_MIN_ROUNDS", 1)
        self.coverage_quota = (
            coverage_quota if coverage_quota is not None else rules.coverage_quota()
        )
        self.stall_patience = (
            stall_patience if stall_patience is not None else rules.stall_patience()
        )
        self.min_new_relevant_per_call = (
            min_new_relevant_per_call
            if min_new_relevant_per_call is not None
            else rules.min_new_relevant_per_call()
        )
        self.raw_item_batches: list[RawIntelItemBatch] = []
        self._executed_source_query_keys: set[str] = set()
        self._latest_semantic_expansion: SearchSemanticExpansionOutput | None = None
        self._fallback_events: list[dict[str, str]] = []

    # ------------------------------------------------------------------ run

    def run(self) -> IntelRunBlackboard:
        blackboard = IntelRunBlackboard(
            run_id=f"real-{uuid4().hex[:8]}",
            run_goal=self.run_goal,
            run_mode="bootstrap",
            budget=RunBudget(max_rounds=self.max_rounds, max_api_calls=100, max_sources=12),
            approved_sources=default_registered_api_sources(),
        )
        blackboard.engine = "sdk"
        current_query = self.initial_query

        for round_index in range(self.max_rounds):
            try:
                should_continue, current_query = self._run_round(
                    blackboard, current_query, round_index
                )
            except Exception as exc:  # noqa: BLE001 - round-level fallback (roadmap 4.3)
                self._record_fallback(blackboard, "round", f"{exc.__class__.__name__}: {exc}")
                should_continue, current_query = self._run_rules_round(
                    blackboard, current_query, round_index
                )
            self._write_telemetry(blackboard)
            self._persist(blackboard, status="running")
            if not should_continue:
                break

        self._write_telemetry(blackboard)
        self._persist(blackboard, status="succeeded")
        if self.bandit is not None:
            self.bandit.save()
        return blackboard

    # ------------------------------------------------------------------ rounds

    def _run_round(
        self,
        blackboard: IntelRunBlackboard,
        current_query: str,
        round_index: int,
    ) -> tuple[bool, str]:
        query_plan = self._query_plan(blackboard, current_query, round_index)
        planner_decision = rules.fallback_planner_decision(query_plan)
        blackboard.action_history.extend(planner_decision.actions)

        bucket = topic_bucket(
            [gap.taxonomy_or_component for gap in blackboard.coverage_gaps]
            or query_plan.target_topics
        )
        context_digest = render_round_context(
            blackboard,
            round_index,
            self.max_rounds,
            bandit_summary=(
                self.bandit.render_summary(bucket) if self.bandit is not None else None
            ),
            info_gain=self._latest_info_gain(blackboard),
        )

        selected_sources = self._decide_sources(blackboard, query_plan, bucket, context_digest)
        query_plan.source_names = selected_sources

        source_specs = self._decide_collection_plan(
            blackboard, query_plan, context_digest
        )
        source_specs = self._enforce_call_budget(blackboard, source_specs)
        if not source_specs:
            blackboard.action_history.append(
                ActionDecision(
                    action_type="STOP",
                    priority="high",
                    rationale="API call budget exhausted before collection.",
                )
            )
            return False, current_query

        latest_batch = self._execute_specs(blackboard, query_plan, source_specs)
        self.raw_item_batches.append(latest_batch)
        rules.merge_batch_into_blackboard(blackboard, query_plan, latest_batch)

        if self.bandit is not None and blackboard.query_history:
            self.bandit.update_from_history_entry(blackboard.query_history[-1])

        if self.relevance_pipeline is not None and latest_batch.items:
            new_ids = set(blackboard.query_history[-1].metadata.get("new_item_ids") or [])
            new_items = [item for item in latest_batch.items if item.item_id in new_ids]
            try:
                self.relevance_pipeline.annotate(new_items)
            except Exception as exc:  # noqa: BLE001 - relevance must not break collection
                self._record_fallback(
                    blackboard, "relevance", f"{exc.__class__.__name__}: {exc}"
                )

        yield_assessment = rules.fallback_yield_assessment(
            blackboard.query_history[-1], latest_batch
        )
        gap_analysis = rules.fallback_coverage_analysis(blackboard.raw_items, self.target_topics)
        blackboard.coverage_gaps = gap_analysis.gaps
        semantic_expansion = rules.fallback_semantic_expansion(gap_analysis)
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

        post_context = render_round_context(
            blackboard,
            round_index,
            self.max_rounds,
            bandit_summary=(
                self.bandit.render_summary(bucket) if self.bandit is not None else None
            ),
            info_gain=self._latest_info_gain(blackboard),
        )
        reflection = self._decide_rewrite(blackboard, gap_analysis, post_context)
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

        completeness = self._decide_termination(
            blackboard, gap_analysis, reflection, round_index, post_context
        )
        blackboard.metrics.round_index = len(blackboard.query_history)

        if not completeness.should_continue:
            blackboard.action_history.append(
                ActionDecision(
                    action_type="STOP",
                    priority="high",
                    rationale=completeness.stop_rationale or "Stop criteria met.",
                    required_context=["SearchCompletenessAssessment"],
                )
            )
            return False, current_query

        next_query = (
            reflection.rewritten_queries[0].query_text
            if reflection.rewritten_queries
            else None
        )
        if next_query is None:
            # Coverage gate forced continuation but the agent proposed no query:
            # synthesize a fresh query aimed at the under-quota target topics.
            open_gaps = rules.quota_open_gaps(
                blackboard.raw_items, self.target_topics, self.coverage_quota
            )
            if open_gaps:
                next_query = rules.non_repeating_gap_query(
                    open_gaps,
                    {entry.query_text for entry in blackboard.query_history},
                    self._latest_semantic_expansion,
                )
                blackboard.action_history.append(
                    ActionDecision(
                        action_type="REFLECT_SEARCH_STRATEGY",
                        priority="high",
                        rationale=(
                            f"Coverage gate: target topics below quota "
                            f"{self.coverage_quota}: {open_gaps}."
                        ),
                        expected_gain="Fill under-covered target topics.",
                        required_context=open_gaps,
                    )
                )
        if next_query is None:
            blackboard.action_history.append(
                ActionDecision(
                    action_type="STOP",
                    priority="high",
                    rationale="No next query produced after coverage review.",
                )
            )
            return False, current_query

        _ = yield_assessment  # recorded implicitly through query_history metrics
        return True, next_query

    def _run_rules_round(
        self,
        blackboard: IntelRunBlackboard,
        current_query: str,
        round_index: int,
    ) -> tuple[bool, str]:
        """Round-level degradation: pure-rules round, run does not abort."""
        query_plan = self._query_plan(blackboard, current_query, round_index)
        source_specs = rules.build_source_query_specs(
            blackboard,
            query_plan,
            self.target_topics,
            self.max_results_per_round,
            self._executed_source_query_keys,
            self._latest_semantic_expansion,
        )
        source_specs = self._enforce_call_budget(blackboard, source_specs)
        if not source_specs:
            return False, current_query
        latest_batch = self._execute_specs(blackboard, query_plan, source_specs)
        self.raw_item_batches.append(latest_batch)
        rules.merge_batch_into_blackboard(blackboard, query_plan, latest_batch)
        gap_analysis = rules.fallback_coverage_analysis(blackboard.raw_items, self.target_topics)
        blackboard.coverage_gaps = gap_analysis.gaps
        self._latest_semantic_expansion = rules.fallback_semantic_expansion(gap_analysis)
        reflection = rules.fallback_rewrite_decision(
            gap_analysis,
            self.target_topics,
            blackboard,
            self.max_results_per_round,
            self._latest_semantic_expansion,
        )
        if reflection.rewritten_queries:
            blackboard.reflection_notes.append(reflection)
        completeness = rules.fallback_completeness(
            gap_analysis, reflection, round_index, self.max_rounds
        )
        blackboard.metrics.round_index = len(blackboard.query_history)
        if not completeness.should_continue or not reflection.rewritten_queries:
            return False, current_query
        return True, reflection.rewritten_queries[0].query_text

    # ------------------------------------------------------------------ decisions

    def _decide_sources(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
        bucket: str,
        context_digest: str,
    ) -> list[str]:
        enabled = [
            source.source_name for source in blackboard.approved_sources if source.enabled
        ]
        ranking = (
            [row["source_name"] for row in self.bandit.recommend(bucket, enabled)]
            if self.bandit is not None
            else enabled
        )
        prompt = (
            f"{context_digest}\n\n"
            f"Enabled sources: {enabled}\n"
            f"Bandit recommendation order: {ranking}\n\n"
            "Select which sources to query this round. Follow the bandit ranking "
            "unless the digest gives a concrete reason to deviate (e.g. an "
            "unexplored gap only one source can fill). Select 1-4 sources."
        )
        decision = self.decision_engine.decide(
            "source_selection", prompt, SourceSelectionDecision, system_prompt=SYSTEM_PROMPT
        )
        if decision is None:
            self._record_fallback(blackboard, "source_selection", "decision failed")
            return ranking[: max(2, min(4, len(ranking)))] if ranking else enabled
        selected = [source for source in decision.selected_sources if source in enabled]
        if not selected:
            self._record_fallback(blackboard, "source_selection", "empty/invalid selection")
            return ranking[: max(2, min(4, len(ranking)))] if ranking else enabled
        blackboard.action_history.append(
            ActionDecision(
                action_type="PLAN_COLLECTION",
                priority="medium",
                rationale=decision.rationale,
                expected_gain="Bandit-informed source selection.",
                required_context=selected,
                metadata={
                    "decision": "source_selection",
                    "follow_bandit": decision.follow_bandit,
                    "bandit_ranking": ranking,
                    "selected_sources": selected,
                },
            )
        )
        return selected

    def _decide_collection_plan(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
        context_digest: str,
    ) -> list[SourceQuerySpec]:
        prompt = (
            f"{context_digest}\n\n"
            f"Selected sources for this round: {query_plan.source_names}\n"
            f"Current mission query: {query_plan.query_text}\n\n"
            f"{PROPOSAL_GUIDE}\n\n"
            "Propose 2-6 source-specific search queries for this round. Write new "
            "query text freely (do not repeat earlier queries from the digest); "
            "use advanced params whenever they cut noise. Each proposal needs "
            "source_name, query_text, params, and a short rationale."
        )
        decision = self.decision_engine.decide(
            "collection_plan", prompt, CollectionPlanDecision, system_prompt=SYSTEM_PROMPT
        )
        specs = self._specs_from_proposals(decision, query_plan) if decision else []
        if not specs:
            if decision is not None:
                self._record_fallback(
                    blackboard, "collection_plan", "no valid proposals after validation"
                )
            else:
                self._record_fallback(blackboard, "collection_plan", "decision failed")
            return rules.build_source_query_specs(
                blackboard,
                query_plan,
                self.target_topics,
                self.max_results_per_round,
                self._executed_source_query_keys,
                self._latest_semantic_expansion,
            )
        return specs

    def _specs_from_proposals(
        self,
        decision: CollectionPlanDecision,
        query_plan: SearchQueryPlan,
    ) -> list[SourceQuerySpec]:
        per_source_limit = max(5, min(20, self.max_results_per_round // 4))
        specs: list[SourceQuerySpec] = []
        for proposal in decision.proposals[:8]:
            allowed = ALLOWED_PROPOSAL_PARAMS.get(proposal.source_name)
            if allowed is None or proposal.source_name not in query_plan.source_names:
                continue
            params = {
                key: value
                for key, value in proposal.params.items()
                if key in allowed and value not in (None, "", [], {})
            }
            spec = SourceQuerySpec(
                source_name=proposal.source_name,
                query_text=proposal.query_text.strip() or query_plan.query_text,
                target_topics=query_plan.target_topics,
                max_results=per_source_limit,
                strategy_name="sdk_agent_proposal",
                params=params,
            )
            if rules.source_query_key(spec) in self._executed_source_query_keys:
                continue
            specs.append(spec)
        return specs

    def _decide_rewrite(
        self,
        blackboard: IntelRunBlackboard,
        gap_analysis: Any,
        context_digest: str,
    ) -> SearchReflectionDecision:
        prompt = (
            f"{context_digest}\n\n"
            "Rewrite the mission search query for the next round if coverage gaps "
            "remain. Set should_rewrite=false when remaining gaps are not worth "
            "another round. The rewritten query must differ from every query in "
            "the digest."
        )
        parsed = self.decision_engine.decide(
            "query_rewrite", prompt, RewriteDecisionOutput, system_prompt=SYSTEM_PROMPT
        )
        if parsed is None:
            self._record_fallback(blackboard, "query_rewrite", "decision failed")
            return rules.fallback_rewrite_decision(
                gap_analysis,
                self.target_topics,
                blackboard,
                self.max_results_per_round,
                self._latest_semantic_expansion,
            )
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

    def _decide_termination(
        self,
        blackboard: IntelRunBlackboard,
        gap_analysis: Any,
        reflection: SearchReflectionDecision,
        round_index: int,
        context_digest: str,
    ) -> SearchCompletenessAssessment:
        features = self._marginal_yield_features(blackboard)
        prompt = (
            f"{context_digest}\n\n"
            f"Marginal yield features: {json.dumps(features)}\n"
            f"Round {round_index + 1} of max {self.max_rounds} "
            f"(minimum rounds: {self.min_rounds}).\n\n"
            "Decide whether the collection loop should continue for another round. "
            "Continue only while marginal yield justifies the API cost."
        )
        parsed = self.decision_engine.decide(
            "termination",
            prompt,
            CompletenessDecisionOutput,
            system_prompt=SYSTEM_PROMPT,
            fast=True,
        )
        if parsed is None:
            self._record_fallback(blackboard, "termination", "decision failed")
            assessment = rules.fallback_completeness(
                gap_analysis, reflection, round_index, self.max_rounds
            )
        else:
            assessment = SearchCompletenessAssessment(
                completeness_score=parsed.completeness_score,
                should_continue=parsed.should_continue,
                missing_dimensions=parsed.missing_topics,
                recommended_next_mode="gap_fill" if parsed.should_continue else None,
                stop_rationale=parsed.stop_reason or parsed.rationale,
            )

        # Safety valves, in priority order:
        #   max_rounds (hard cap) > stall (search exhausted) > coverage gate
        #   (topics below quota) > min_rounds floor > agent/rule verdict.
        # Stall overrides the coverage gate so an unreachable sparse topic does
        # not burn the whole budget; the remaining gaps are reported honestly.
        open_gaps = rules.quota_open_gaps(
            blackboard.raw_items, self.target_topics, self.coverage_quota
        )
        stalled = rules.is_search_stalled(
            blackboard, self.stall_patience, self.min_new_relevant_per_call
        )
        if round_index + 1 >= self.max_rounds:
            assessment.should_continue = False
            assessment.stop_rationale = assessment.stop_rationale or "max_rounds reached"
        elif stalled:
            assessment.should_continue = False
            reason = (
                f"search exhausted: < {self.min_new_relevant_per_call} new relevant "
                f"items/call for {self.stall_patience} consecutive rounds"
            )
            if open_gaps:
                reason += f"; coverage incomplete, unreached topics: {open_gaps}"
            assessment.stop_rationale = reason
            assessment.missing_dimensions = open_gaps
        elif open_gaps and self._api_budget_remains(blackboard):
            # Coverage completeness is the hard constraint: never stop while a
            # target topic is under quota, regardless of the agent/rule verdict.
            assessment.should_continue = True
            assessment.stop_rationale = None
            assessment.missing_dimensions = open_gaps
        elif round_index + 1 < self.min_rounds:
            assessment.should_continue = True
        # Only stop for a missing next query when coverage is already satisfied;
        # otherwise _run_round synthesizes a gap-targeted query.
        if assessment.should_continue and not reflection.rewritten_queries and not open_gaps:
            assessment.should_continue = False
            assessment.stop_rationale = "no next query available"
        return assessment

    def _api_budget_remains(self, blackboard: IntelRunBlackboard) -> bool:
        max_calls = blackboard.budget.max_api_calls
        return max_calls is None or blackboard.metrics.api_calls_used < max_calls

    # ------------------------------------------------------------------ execution

    def _execute_specs(
        self,
        blackboard: IntelRunBlackboard,
        query_plan: SearchQueryPlan,
        source_specs: list[SourceQuerySpec],
    ) -> RawIntelItemBatch:
        approved_sources_json = json.dumps(
            [source.model_dump(mode="json") for source in blackboard.approved_sources],
            ensure_ascii=False,
        )
        batches: list[RawIntelItemBatch] = []
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
            self._executed_source_query_keys.add(rules.source_query_key(spec))
        return rules.combine_source_batches(
            query_plan, source_specs, batches, self.max_results_per_round
        )

    def _enforce_call_budget(
        self,
        blackboard: IntelRunBlackboard,
        source_specs: list[SourceQuerySpec],
    ) -> list[SourceQuerySpec]:
        max_api_calls = blackboard.budget.max_api_calls
        if max_api_calls is None:
            return source_specs
        remaining = max_api_calls - blackboard.metrics.api_calls_used
        return source_specs[: max(0, remaining)]

    # ------------------------------------------------------------------ misc

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
            rationale="SDK-engine autonomous intelligence collection.",
            round_index=round_index,
        )

    def _latest_info_gain(self, blackboard: IntelRunBlackboard) -> dict[str, Any] | None:
        if not blackboard.query_history:
            return None
        item_index = {item.item_id: item for item in blackboard.raw_items}
        return rules.round_information_gain(blackboard.query_history[-1], item_index)

    def _marginal_yield_features(self, blackboard: IntelRunBlackboard) -> dict[str, Any]:
        history = blackboard.query_history
        recent = history[-2:]
        new_counts = [len(entry.metadata.get("new_item_ids") or []) for entry in recent]
        calls = blackboard.metrics.api_calls_used
        item_index = {item.item_id: item for item in blackboard.raw_items}
        recent_gain = [rules.round_information_gain(entry, item_index) for entry in recent]
        return {
            "rounds_completed": len(history),
            "recent_novelty": [round(entry.novelty_score, 3) for entry in recent],
            "recent_duplicate_ratio": [round(entry.duplicate_ratio, 3) for entry in recent],
            "recent_new_items": new_counts,
            # New-information signal: new AND relevant items per API call, plus the
            # share of newly fetched items that were off-topic noise.
            "recent_new_relevant_per_call": [g["new_relevant_per_call"] for g in recent_gain],
            "recent_irrelevant_share": [g["irrelevant_share"] for g in recent_gain],
            "stall_threshold_new_relevant_per_call": self.min_new_relevant_per_call,
            "stalled": rules.is_search_stalled(
                blackboard, self.stall_patience, self.min_new_relevant_per_call
            ),
            "new_items_per_call": round(len(blackboard.raw_items) / calls, 3) if calls else 0.0,
            "remaining_api_calls": (
                (blackboard.budget.max_api_calls - calls)
                if blackboard.budget.max_api_calls is not None
                else None
            ),
            "open_coverage_gaps": len(blackboard.coverage_gaps),
        }

    def _record_fallback(
        self,
        blackboard: IntelRunBlackboard,
        decision_name: str,
        reason: str,
    ) -> None:
        # Fallbacks are observable, never silent (roadmap 4.3).
        self._fallback_events.append({"decision": decision_name, "reason": reason[:300]})
        blackboard.errors.append(
            ErrorRecord(
                error_type="decision_fallback",
                message=f"{decision_name}: {reason[:300]}",
                retryable=True,
                metadata={"engine": "sdk", "decision": decision_name},
            )
        )

    def _write_telemetry(self, blackboard: IntelRunBlackboard) -> None:
        blackboard.engine_telemetry = {
            "engine": "sdk",
            "decisions": self.decision_engine.telemetry.summary(),
            "fallback_events": self._fallback_events[-50:],
        }

    def _persist(self, blackboard: IntelRunBlackboard, status: str) -> None:
        self.run_store.save_run(
            blackboard,
            raw_item_batches=self.raw_item_batches,
            status=status,
        )


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default
