"""IntelAgentController: the round loop that ties the agent, memory, and rules.

Per round: recall playbook -> render digest -> run an agentic session (falling
back to deterministic rules if the SDK is unavailable) -> annotate relevance ->
merge -> harvest techniques into the playbook -> recompute coverage -> let the
critic decide whether to continue. All heavy collaborators are injectable so the
loop is fully testable offline.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from ..agent.critic import decide_termination
from ..agent.loop import IntelAgentLoop
from ..agent.system_prompt import render_round_prompt
from ..analysis import (
    analyze_coverage_gaps,
    coverage_quota,
    is_search_stalled,
    item_is_relevant,
    merge_batch_into_blackboard,
    min_new_relevant_per_call,
    new_relevant_per_call,
    quota_open_gaps,
    stall_patience,
)
from ..memory.harvest import harvest_round
from ..memory.playbook import PlaybookStore, default_playbook_path, playbook_enabled
from ..memory.retrieval import default_playbook_embedder
from ..observability import TraceSink
from ..persistence import JsonIntelRunStore
from ..relevance import RelevancePipeline, default_pipeline
from ..runtime.structured import StructuredDecisionEngine
from ..store import default_store
from ..schemas import (
    ActionDecision,
    CandidateTopicNamingDecision,
    IntelRunBlackboard,
    QueryCallOutcome,
    RawIntelItemBatch,
    RunGap,
    RunBudget,
    SearchQueryPlan,
    SearchReflectionDecision,
    SourceCheckpoint,
)
from ..sources import default_registered_api_sources
from ..topics import EXTENDED_SECURITY_TOPICS
from ..tools.context import ToolContext
from .context import render_digest
from .bandit import normalized_reward
from .fallback import run_fallback_round
from .gaps import (
    compatibility_coverage_gaps,
    compute_corpus_gaps,
    detect_candidate_topics,
    extended_topic_trends,
    initial_run_gaps,
    total_open_priority,
)
from .modes import (
    CollectionMode,
    FullCollectionMode,
    IncrementalCollectionMode,
    incremental_overlap_hours,
)

DEFAULT_MAX_RESULTS_PER_CALL = 20


def incremental_strategy() -> str:
    value = os.getenv("INTEL_INCREMENTAL_STRATEGY", "adaptive").strip().lower()
    return value if value in {"adaptive", "legacy"} else "adaptive"


class IntelAgentController:
    def __init__(
        self,
        store: Any | None = None,
        playbook: PlaybookStore | None = None,
        relevance: RelevancePipeline | None = None,
        loop: IntelAgentLoop | None = None,
        decision_engine: StructuredDecisionEngine | None = None,
        max_results_per_call: int = DEFAULT_MAX_RESULTS_PER_CALL,
        min_rounds: int = 1,
    ) -> None:
        self.store = store or default_store()
        self.playbook = playbook if playbook is not None else _default_playbook()
        self.relevance = relevance if relevance is not None else default_pipeline()
        self.loop = loop or IntelAgentLoop()
        self.decision_engine = decision_engine or StructuredDecisionEngine()
        self.max_results_per_call = max_results_per_call
        self.min_rounds = min_rounds

    def run(
        self,
        mode: CollectionMode | None = None,
        budget: RunBudget | None = None,
        run_id: str | None = None,
        trace: TraceSink | None = None,
    ) -> IntelRunBlackboard:
        mode = mode or FullCollectionMode()
        budget = budget or RunBudget(max_rounds=6, max_api_calls=40)
        adaptive = isinstance(mode, IncrementalCollectionMode) and incremental_strategy() == "adaptive"
        adaptive_init_error: str | None = None
        self._corpus_items = []
        checkpoints: list[SourceCheckpoint] = []
        self._historical_outcomes: list[QueryCallOutcome] = []
        if adaptive:
            try:
                corpus_loader = getattr(self.store, "load_corpus_items", None)
                if callable(corpus_loader):
                    self._corpus_items = list(corpus_loader())
                else:
                    self._corpus_items = [
                        item
                        for board in self.store.load_all_blackboards(limit=200)
                        for item in board.raw_items
                    ]
                checkpoint_loader = getattr(self.store, "load_source_checkpoints", None)
                checkpoints = list(checkpoint_loader()) if callable(checkpoint_loader) else []
                self._historical_outcomes = [
                    outcome
                    for board in self.store.load_all_blackboards(limit=500)
                    for outcome in board.query_outcomes
                ]
            except Exception as exc:  # noqa: BLE001 - persistence -> legacy contract
                adaptive = False
                adaptive_init_error = f"{exc.__class__.__name__}: {exc}"
                self._corpus_items = []
                checkpoints = []
                self._historical_outcomes = []
                if not isinstance(self.store, JsonIntelRunStore):
                    self.store = JsonIntelRunStore()
        corpus_gaps = compute_corpus_gaps(self._corpus_items) if adaptive else []
        blackboard = IntelRunBlackboard(
            run_id=run_id or _default_run_id(mode.run_mode),
            run_goal=mode.run_goal,
            run_mode=mode.run_mode,  # type: ignore[arg-type]
            budget=budget,
            approved_sources=default_registered_api_sources(),
            corpus_gaps=corpus_gaps,
            coverage_gaps=compatibility_coverage_gaps(corpus_gaps) if adaptive else [],
            run_gaps=initial_run_gaps(corpus_gaps, checkpoints) if adaptive else [],
            source_checkpoints=checkpoints,
            extended_trends=extended_topic_trends(self._corpus_items) if adaptive else {},
            collection_strategy="adaptive" if adaptive else "legacy",
        )
        if trace is not None:
            trace.bind_run(blackboard.run_id)
        if adaptive_init_error:
            blackboard.errors.append(
                _error("adaptive_persistence_failed", adaptive_init_error)
            )
            if trace is not None:
                trace.emit("strategy_fallback", reason=adaptive_init_error)
        self._batches = []
        self._run_started_at = time.monotonic()
        self._adaptive_stall_rounds = 0
        self._force_rules = False
        if self.loop.available():
            self.loop.start_run(blackboard.run_id, continuous=adaptive)
        rounds_completed = False
        try:
            try:
                self._run_rounds(blackboard, mode, budget, trace)
            except Exception as exc:  # noqa: BLE001 - adaptive run-level fallback contract
                if not adaptive:
                    raise
                blackboard.errors.append(_error("adaptive_strategy_failed", str(exc)))
                blackboard.collection_strategy = "legacy"
                self._force_rules = True
                if trace is not None:
                    trace.emit("strategy_fallback", reason=str(exc)[:300])
                self._run_rounds(blackboard, mode, budget, trace)
            rounds_completed = True
        finally:
            blackboard.sdk_session_id = self.loop.session_id
            self.loop.end_run()
            if not rounds_completed and trace is not None:
                trace.close()
        try:
            blackboard.metrics.round_index = len(blackboard.query_history)
            blackboard.metrics.elapsed_seconds = max(
                0.0, time.monotonic() - self._run_started_at
            )
            if blackboard.collection_strategy == "adaptive":
                embedder = (
                    getattr(self.relevance, "embedder", None)
                    if self.relevance is not None
                    else None
                )
                blackboard.candidate_topics = detect_candidate_topics(
                    self._corpus_items + blackboard.raw_items, embedder
                )
                self._credit_candidate_topic_discovery(blackboard)
                self._name_candidate_topics(blackboard)
            status = "succeeded" if blackboard.raw_items else "partial_success"
            try:
                self.store.save_run(blackboard, self._batches, status=status)
            except Exception as exc:  # noqa: BLE001 - remote store -> durable JSON fallback
                if isinstance(self.store, JsonIntelRunStore):
                    raise
                blackboard.errors.append(_error("persistence_fallback", str(exc)))
                if trace is not None:
                    trace.emit("persistence_fallback", reason=str(exc)[:300])
                JsonIntelRunStore().save_run(
                    blackboard, self._batches, status="partial_success"
                )
            if self.playbook is not None:
                self.playbook.save()
            return blackboard
        finally:
            if trace is not None:
                trace.close()

    def _name_candidate_topics(self, blackboard: IntelRunBlackboard) -> None:
        for candidate in blackboard.candidate_topics:
            prompt = (
                "Name this deterministically gated emerging LLM-security evidence cluster. "
                "Return a short lowercase security topic name and a one-sentence rationale. "
                "Do not claim it is part of the formal taxonomy.\n\n"
                f"Current label: {candidate.proposed_name}\n"
                f"Sources: {candidate.source_names}\n"
                f"Supporting item IDs: {candidate.supporting_item_ids[:10]}"
            )
            parsed = self.decision_engine.decide(
                "candidate_topic_name",
                prompt,
                CandidateTopicNamingDecision,
                system_prompt="You label proposed LLM-security topic clusters via submit_decision.",
                fast=True,
            )
            if parsed is not None:
                candidate.proposed_name = parsed.proposed_name.strip().lower()[:120]
                candidate.rationale = parsed.rationale[:500]

    def _credit_candidate_topic_discovery(
        self, blackboard: IntelRunBlackboard
    ) -> None:
        supporting_ids = {
            item_id
            for candidate in blackboard.candidate_topics
            for item_id in candidate.supporting_item_ids
        }
        for outcome in blackboard.query_outcomes:
            if outcome.query_intent != "discovery":
                continue
            new_ids = set(outcome.metadata.get("new_item_ids") or [])
            residual_support = min(1.0, len(new_ids & supporting_ids) / 3.0)
            outcome.metadata["residual_cluster_support"] = round(residual_support, 4)
            outcome.reward = normalized_reward(
                outcome.gap_priority_before,
                outcome.gap_priority_after,
                outcome,
                residual_support=residual_support,
            )

    def _run_rounds(
        self,
        blackboard: IntelRunBlackboard,
        mode: CollectionMode,
        budget: RunBudget,
        trace: TraceSink | None,
    ) -> None:
        adaptive = blackboard.collection_strategy == "adaptive"
        source_since: dict[str, datetime] = {}
        if adaptive and isinstance(mode, IncrementalCollectionMode):
            source_since, until = mode.resolve_source_scopes(
                self.store,
                checkpoints=blackboard.source_checkpoints,
                corpus_items=self._corpus_items,
            )
            since = min(source_since.values()) if source_since else None
        else:
            since, until = mode.resolve_time_scope(self.store)
        quota = coverage_quota()
        max_rounds = budget.max_rounds or 6
        executed_keys: set[str] = set()
        if not hasattr(self, "_batches"):
            self._batches = []
        engine_available = self.loop.available() and not self._force_rules
        if adaptive and not engine_available:
            blackboard.collection_strategy = "legacy"
            blackboard.errors.append(
                _error("adaptive_sdk_unavailable", "SDK runtime unavailable; using legacy rules")
            )
            if trace is not None:
                trace.emit("strategy_fallback", reason="SDK runtime unavailable")
            self._force_rules = True
            self._run_rounds(blackboard, mode, budget, trace)
            return

        for round_index in range(max_rounds):
            ctx = self._build_context(
                blackboard, mode, since, until, executed_keys, source_since=source_since
            )
            recall_text = self._recall(mode, blackboard.run_goal)
            open_gaps = (
                list(dict.fromkeys(gap.topic for gap in blackboard.corpus_gaps if gap.status == "open"))
                if adaptive
                else quota_open_gaps(blackboard.raw_items, mode.target_topics, quota)
            )
            if trace is not None:
                trace.emit(
                    "round_start", round=round_index + 1, max_rounds=max_rounds,
                    mode=blackboard.run_mode, open_gaps=open_gaps,
                )
            digest = render_digest(
                blackboard, round_index, max_rounds, mode.target_topics, quota, recall_text
            )
            prompt = render_round_prompt(
                digest, mode.mode_brief, round_index, max_rounds,
                focus=mode.focus, time_scope_hint=ctx.time_scope_hint(), open_gaps=open_gaps,
                max_turns=self.loop.max_turns,
            )

            used_agent = engine_available
            if engine_available:
                result = self.loop.run_round(ctx, prompt, trace=trace)
                if not result.completed:
                    if adaptive:
                        blackboard.collection_strategy = "legacy"
                        self._force_rules = True
                        blackboard.errors.append(
                            _error("adaptive_sdk_failed", result.error or "no items collected")
                        )
                        if trace is not None:
                            trace.emit(
                                "strategy_fallback",
                                reason=result.error or "adaptive session produced no yield",
                            )
                        self._run_rounds(blackboard, mode, budget, trace)
                        return
                    used_agent = False
                    if trace is not None:
                        trace.emit("session_fallback", reason=result.error or "no items collected")
                    blackboard.errors.append(
                        _error("agent_round_failed", result.error or "no items collected")
                    )
            if not used_agent:
                was_adaptive = ctx.adaptive
                ctx.adaptive = False
                run_fallback_round(
                    ctx, blackboard, self._round_plan(mode, round_index), mode.target_topics
                )
                ctx.adaptive = was_adaptive

            batch = self._merge_round(blackboard, ctx, mode, round_index)
            self._batches.append(batch)
            self._harvest(ctx, mode, blackboard.run_id)
            if not adaptive:
                blackboard.coverage_gaps = analyze_coverage_gaps(
                    blackboard.raw_items, mode.target_topics, quota
                )
            if trace is not None:
                last_entry = blackboard.query_history[-1] if blackboard.query_history else None
                trace.emit(
                    "round_summary", round=round_index + 1, new_items=len(batch.items),
                    new_relevant=int(last_entry.metadata.get("relevant_new", 0)) if last_entry else 0,
                    api_calls_used=blackboard.metrics.api_calls_used,
                    open_gaps=(
                        [gap.topic for gap in blackboard.corpus_gaps if gap.status == "open"]
                        if adaptive else quota_open_gaps(blackboard.raw_items, mode.target_topics, quota)
                    ),
                )

            should_stop = (
                self._should_stop_adaptive(blackboard, ctx, round_index, max_rounds, digest, trace)
                if adaptive
                else self._should_stop(
                    blackboard, mode, ctx, round_index, max_rounds, quota, digest, trace
                )
            )
            if should_stop:
                break

    # ------------------------------------------------------------- per-round

    def _build_context(
        self,
        blackboard: IntelRunBlackboard,
        mode: CollectionMode,
        since: datetime | None,
        until: datetime | None,
        executed_keys: set[str],
        source_since: dict[str, datetime] | None = None,
    ) -> ToolContext:
        return ToolContext(
            run_id=blackboard.run_id,
            target_topics=mode.target_topics,
            topic_bucket=mode.topic_bucket(),
            max_results_per_call=self.max_results_per_call,
            since=since,
            until=until,
            source_since=source_since or {},
            existing_item_ids={item.item_id for item in self._corpus_items + blackboard.raw_items},
            executed_keys=executed_keys,
            api_calls_used=blackboard.metrics.api_calls_used,
            max_api_calls=blackboard.budget.max_api_calls,
            playbook=self.playbook,
            adaptive=blackboard.collection_strategy == "adaptive",
            corpus_gaps=list(blackboard.corpus_gaps),
            run_gaps=blackboard.run_gaps,
            prior_outcomes=list(self._historical_outcomes) + list(blackboard.query_outcomes),
            current_run_outcomes=list(blackboard.query_outcomes),
            source_checkpoints=blackboard.source_checkpoints,
            extended_trends=blackboard.extended_trends,
            extended_focus=bool(mode.focus and mode.focus.strip().lower() in EXTENDED_SECURITY_TOPICS),
        )

    def _recall(self, mode: CollectionMode, run_goal: str) -> str | None:
        if self.playbook is None:
            return None
        entries = self.playbook.recall(
            query_text=mode.focus or run_goal, topic_bucket=mode.topic_bucket(), top_k=5
        )
        return self.playbook.render_recall(entries) or None

    def _merge_round(
        self,
        blackboard: IntelRunBlackboard,
        ctx: ToolContext,
        mode: CollectionMode,
        round_index: int,
    ) -> RawIntelItemBatch:
        new_items = list(ctx.collected_items.values())
        prior_run_items = list(blackboard.raw_items)
        if self.relevance is not None and new_items:
            try:
                self.relevance.annotate(new_items)
            except Exception as exc:  # noqa: BLE001 - relevance is best-effort
                blackboard.errors.append(_error("relevance_failed", str(exc)))

        batch = RawIntelItemBatch(items=new_items, source_stats=ctx.stats)
        source_names = sorted({call["source_name"] for call in ctx.executed_calls})
        query_text = _round_summary_text(ctx) or mode.focus or mode.run_goal
        query_plan = SearchQueryPlan(
            query_text=query_text,
            source_names=source_names,
            target_topics=mode.target_topics,
            round_index=round_index,
        )
        entry = merge_batch_into_blackboard(blackboard, query_plan, batch)
        entry.metadata["source_query_plans"] = [
            {
                "call_id": call.get("call_id"),
                "candidate_id": call.get("candidate_id"),
                "source_name": call["source_name"],
                "query_text": call.get("query_text", ""),
                "params": call["params"],
                "query_intent": call.get("query_intent", "gap_fill"),
                "target_topics": call.get("target_topics", []),
                "target_gap_ids": call.get("target_gap_ids", []),
            }
            for call in ctx.executed_calls
        ]
        if ctx.adaptive:
            self._attribute_adaptive_outcomes(
                blackboard, ctx, prior_run_items, entry
            )
        blackboard.metrics.api_calls_used = ctx.api_calls_used
        blackboard.metrics.sources_used = len(source_names)
        blackboard.sdk_session_id = self.loop.session_id
        return batch

    def _attribute_adaptive_outcomes(
        self,
        blackboard: IntelRunBlackboard,
        ctx: ToolContext,
        prior_run_items: list,
        entry: Any,
    ) -> None:
        item_by_id = ctx.collected_items
        running_items = list(self._corpus_items) + list(prior_run_items)
        running_gaps = compute_corpus_gaps(running_items)
        outcomes: list[QueryCallOutcome] = []
        total_raw = total_in_scope = total_duplicates = total_new = 0
        total_relevant = total_noise = 0

        for call in ctx.executed_calls:
            call_items = [item_by_id[item_id] for item_id in call.get("new_item_ids", []) if item_id in item_by_id]
            before_gaps = {gap.gap_id: gap for gap in running_gaps}
            before_priority = total_open_priority(running_gaps)
            running_items.extend(call_items)
            running_gaps = compute_corpus_gaps(running_items)
            after_gaps = {gap.gap_id: gap for gap in running_gaps}
            after_priority = total_open_priority(running_gaps)
            relevant_new = sum(1 for item in call_items if item_is_relevant(item))
            uncertain = sum(
                1
                for item in call_items
                if isinstance(item.metadata.get("relevance"), dict)
                and item.metadata["relevance"].get("label") == "uncertain"
            )
            noise = max(0, len(call_items) - relevant_new - uncertain)
            extended_new = sum(
                1
                for item in call_items
                if item_is_relevant(item)
                and set(item.metadata.get("topics") or []) & set(EXTENDED_SECURITY_TOPICS)
            )
            target_gap_ids = list(call.get("target_gap_ids") or [])
            filled = [
                gap_id
                for gap_id in target_gap_ids
                if gap_id in before_gaps
                and gap_id in after_gaps
                and after_gaps[gap_id].priority_score < before_gaps[gap_id].priority_score
            ]
            outcome = QueryCallOutcome(
                call_id=str(call.get("call_id") or f"{blackboard.run_id}:call:{len(blackboard.query_outcomes) + len(outcomes) + 1}"),
                candidate_id=call.get("candidate_id"),
                source_name=call["source_name"],
                query_text=str(call.get("query_text") or ""),
                params=dict(call.get("params") or {}),
                query_intent=call.get("query_intent", "gap_fill"),
                evidence_channel=call.get("evidence_channel", "vulnerability_advisory"),
                target_topics=list(call.get("target_topics") or []),
                target_gap_ids=target_gap_ids,
                operator_signature=str(call.get("signature") or ""),
                raw_count=int(call.get("raw_count", len(call_items))),
                in_scope_count=int(call.get("in_scope_count", len(call_items))),
                duplicate_count=int(call.get("duplicate_count", 0)),
                new_count=len(call_items),
                relevant_new=relevant_new,
                noise_count=noise,
                uncertain_count=uncertain,
                latency_ms=call.get("latency_ms"),
                success=bool(call.get("success", True)),
                error_type=call.get("error_type"),
                has_more=bool(call.get("has_more", False)),
                filled_gap_ids=filled,
                gap_priority_before=round(before_priority, 4),
                gap_priority_after=round(after_priority, 4),
                metadata={
                    "new_item_ids": [item.item_id for item in call_items],
                    "extended_new_count": extended_new,
                },
            )
            outcome.reward = normalized_reward(before_priority, after_priority, outcome)
            outcomes.append(outcome)
            total_raw += outcome.raw_count
            total_in_scope += outcome.in_scope_count
            total_duplicates += outcome.duplicate_count
            total_new += outcome.new_count
            total_relevant += outcome.relevant_new
            total_noise += outcome.noise_count

        blackboard.query_outcomes.extend(outcomes)
        blackboard.corpus_gaps = compute_corpus_gaps(
            list(self._corpus_items) + list(blackboard.raw_items)
        )
        blackboard.coverage_gaps = compatibility_coverage_gaps(blackboard.corpus_gaps)
        blackboard.extended_trends = extended_topic_trends(
            list(self._corpus_items) + list(blackboard.raw_items)
        )
        entry.result_count = total_raw
        entry.novelty_score = round(total_new / total_raw, 4) if total_raw else 0.0
        entry.duplicate_ratio = (
            round(total_duplicates / total_in_scope, 4) if total_in_scope else 0.0
        )
        entry.noise_ratio = round(total_noise / total_new, 4) if total_new else 0.0
        entry.metadata["relevant_new"] = total_relevant
        entry.metadata["call_outcome_ids"] = [outcome.call_id for outcome in outcomes]
        self._update_adaptive_run_state(blackboard, ctx, outcomes)

    def _update_adaptive_run_state(
        self,
        blackboard: IntelRunBlackboard,
        ctx: ToolContext,
        outcomes: list[QueryCallOutcome],
    ) -> None:
        now = datetime.now(timezone.utc)
        checkpoints = {checkpoint.source_name: checkpoint for checkpoint in blackboard.source_checkpoints}
        calls_by_id = {str(call.get("call_id")): call for call in ctx.executed_calls}
        for outcome in outcomes:
            checkpoint = checkpoints.get(outcome.source_name) or SourceCheckpoint(
                source_name=outcome.source_name
            )
            checkpoints[outcome.source_name] = checkpoint
            checkpoint.overlap_hours = incremental_overlap_hours()
            checkpoint.last_attempt_at = now
            checkpoint.complete = False
            if outcome.success:
                checkpoint.last_success_at = now
                if outcome.source_name in {"nvd_cve_api", "arxiv_api"} and not outcome.has_more:
                    checkpoint.watermark = ctx.until
                    checkpoint.complete = True
                    checkpoint.cursor = None
                elif outcome.source_name == "cisa_kev_json":
                    checkpoint.watermark = ctx.until or now
                    checkpoint.complete = True
            for run_gap in blackboard.run_gaps:
                if run_gap.gap_id in outcome.target_gap_ids and outcome.success:
                    run_gap.status = "satisfied"
                    run_gap.attempts += 1
                if (
                    run_gap.gap_type == "source_window"
                    and run_gap.source_name == outcome.source_name
                    and outcome.success
                    and not outcome.has_more
                ):
                    run_gap.status = "satisfied"
                    run_gap.attempts += 1
                elif run_gap.gap_type == "discovery" and outcome.query_intent == "discovery" and outcome.success:
                    run_gap.status = "satisfied"
                    run_gap.attempts += 1
            if outcome.has_more:
                offset_key = "nvd_start_index" if outcome.source_name == "nvd_cve_api" else "arxiv_start"
                current_offset = int(outcome.params.get(offset_key) or 0)
                checkpoint.cursor = str(current_offset + self.max_results_per_call)
                blackboard.run_gaps.append(
                    RunGap(
                        gap_id=f"run:pagination:{outcome.call_id}",
                        gap_type="pagination",
                        source_name=outcome.source_name,
                        evidence_channel=outcome.evidence_channel,
                        priority="high",
                        retryable=True,
                        rationale="Source page was full; fetch the next page.",
                        metadata={offset_key: current_offset + self.max_results_per_call},
                    )
                )
            if not outcome.success:
                blackboard.run_gaps.append(
                    RunGap(
                        gap_id=f"run:retry:{outcome.call_id}",
                        gap_type="retry",
                        source_name=outcome.source_name,
                        evidence_channel=outcome.evidence_channel,
                        priority="high",
                        retryable=True,
                        rationale=outcome.error_type or "source call failed",
                    )
                )
            identifiers: set[str] = set()
            call = calls_by_id.get(outcome.call_id, {})
            call_items = [
                ctx.collected_items[item_id]
                for item_id in call.get("new_item_ids", [])
                if item_id in ctx.collected_items
            ]
            for item in call_items:
                identifiers.update(
                    match.upper()
                    for match in re.findall(
                        r"CVE-\d{4}-\d{4,}", f"{item.item_id} {item.title} {item.summary}", re.IGNORECASE
                    )
                )
            if outcome.query_intent != "confirmation":
                existing_ids = {
                    str(gap.metadata.get("identifier") or "") for gap in blackboard.run_gaps
                }
                for identifier in sorted(identifiers - existing_ids):
                    blackboard.run_gaps.append(
                        RunGap(
                            gap_id=f"run:confirm:{identifier.lower()}",
                            gap_type="entity_confirmation",
                            source_name="cisa_kev_json",
                            evidence_channel="exploitation",
                            priority="medium",
                            rationale=f"Confirm real-world exploitation for {identifier}.",
                            metadata={"identifier": identifier},
                        )
                    )
            else:
                query_blob = f"{outcome.query_text} {outcome.params}".upper()
                for run_gap in blackboard.run_gaps:
                    identifier = str(run_gap.metadata.get("identifier") or "").upper()
                    if run_gap.gap_type == "entity_confirmation" and identifier and identifier in query_blob:
                        run_gap.status = "satisfied"
        blackboard.source_checkpoints = list(checkpoints.values())

    def _harvest(self, ctx: ToolContext, mode: CollectionMode, run_id: str) -> None:
        if self.playbook is None:
            return
        calls = []
        for call in ctx.executed_calls:
            new_relevant = sum(
                1
                for item_id in call["new_item_ids"]
                if item_id in ctx.collected_items and item_is_relevant(ctx.collected_items[item_id])
            )
            calls.append({**call, "new_relevant": new_relevant})

        recorded = {t["source_name"]: t["technique_text"] for t in ctx.recorded_techniques if t.get("technique_text")}

        def distiller(call: dict[str, Any]) -> str | None:
            return recorded.get(call["source_name"])

        used_ids = harvest_round(
            self.playbook, run_id, calls, mode.topic_bucket(),
            time_scope_hint=ctx.time_scope_hint(),
            distiller=lambda c: distiller(c) or _fallback_technique(c, mode.topic_bucket()),
        )
        self.playbook.decay_unused(set(used_ids))

    def _should_stop_adaptive(
        self,
        blackboard: IntelRunBlackboard,
        ctx: ToolContext,
        round_index: int,
        max_rounds: int,
        digest: str,
        trace: TraceSink | None = None,
    ) -> bool:
        last_entry = blackboard.query_history[-1] if blackboard.query_history else None
        yield_per_call = new_relevant_per_call(last_entry) if last_entry else 0.0
        max_utility = max(ctx.candidate_utilities.values(), default=0.0)
        high_retry = any(
            gap.status == "open" and gap.retryable and gap.priority in {"high", "critical"}
            for gap in blackboard.run_gaps
        )
        low_yield = yield_per_call < 0.5 and max_utility < 0.05 and not high_retry
        self._adaptive_stall_rounds = self._adaptive_stall_rounds + 1 if low_yield else 0
        elapsed = max(0.0, time.monotonic() - self._run_started_at)

        stop_reason: str | None = None
        if round_index + 1 >= max_rounds:
            stop_reason = "max_rounds"
        elif not ctx.budget_remaining():
            stop_reason = "budget_exhausted"
        elif blackboard.budget.max_seconds is not None and elapsed >= blackboard.budget.max_seconds:
            stop_reason = "timeout"
        elif self._adaptive_stall_rounds >= 2:
            stop_reason = "saturated"

        features = {
            "new_relevant_per_call": round(yield_per_call, 4),
            "max_candidate_utility": round(max_utility, 4),
            "stall_rounds": self._adaptive_stall_rounds,
            "open_corpus_gaps": sum(1 for gap in blackboard.corpus_gaps if gap.status == "open"),
            "open_run_gaps": sum(1 for gap in blackboard.run_gaps if gap.status == "open"),
            "high_priority_retry": high_retry,
        }
        assessment = decide_termination(
            self.decision_engine,
            digest,
            features,
            round_index,
            max_rounds,
            self.min_rounds,
            [],
            stop_reason == "saturated",
            ctx.budget_remaining(),
        )
        should_continue = stop_reason is None
        rationale = (
            f"adaptive stop: {stop_reason}"
            if stop_reason
            else assessment.stop_rationale or "continue while useful adaptive queries remain"
        )
        blackboard.stop_reason = stop_reason
        if stop_reason == "saturated":
            for gap in blackboard.corpus_gaps:
                if gap.status == "open":
                    gap.status = "exhausted_this_run"
            blackboard.coverage_gaps = compatibility_coverage_gaps(blackboard.corpus_gaps)
        blackboard.reflection_notes.append(
            SearchReflectionDecision(
                topics_to_expand=list(
                    dict.fromkeys(gap.topic for gap in blackboard.corpus_gaps if gap.status == "open")
                ),
                rationale=rationale,
                confidence=assessment.completeness_score,
            )
        )
        blackboard.action_history.append(
            ActionDecision(
                action_type="ASSESS_COLLECTION_YIELD" if should_continue else "STOP",
                rationale=rationale,
                metadata={
                    "features": features,
                    "stop_reason": stop_reason,
                    "decision_telemetry": self.decision_engine.telemetry.summary(),
                },
            )
        )
        if trace is not None:
            trace.emit(
                "critic",
                should_continue=should_continue,
                completeness_score=assessment.completeness_score,
                rationale=rationale,
                stop_reason=stop_reason,
            )
        return not should_continue

    def _should_stop(
        self,
        blackboard: IntelRunBlackboard,
        mode: CollectionMode,
        ctx: ToolContext,
        round_index: int,
        max_rounds: int,
        quota: int,
        digest: str,
        trace: TraceSink | None = None,
    ) -> bool:
        open_gaps = quota_open_gaps(blackboard.raw_items, mode.target_topics, quota)
        stalled = is_search_stalled(blackboard, stall_patience(), min_new_relevant_per_call())
        last_entry = blackboard.query_history[-1] if blackboard.query_history else None
        features = {
            "new_relevant_per_call": round(new_relevant_per_call(last_entry), 3) if last_entry else 0.0,
            "duplicate_ratio": round(last_entry.duplicate_ratio, 3) if last_entry else 0.0,
            "noise_ratio": round(last_entry.noise_ratio, 3) if last_entry else 0.0,
            "open_gaps": open_gaps,
        }
        assessment = decide_termination(
            self.decision_engine, digest, features, round_index, max_rounds, self.min_rounds,
            open_gaps, stalled, ctx.budget_remaining(),
        )
        if trace is not None:
            trace.emit(
                "critic", should_continue=assessment.should_continue,
                completeness_score=assessment.completeness_score,
                rationale=assessment.stop_rationale or "continue: open gaps remain",
            )
        blackboard.reflection_notes.append(
            SearchReflectionDecision(
                topics_to_expand=open_gaps,
                rationale=assessment.stop_rationale or "continue: open gaps remain",
                confidence=assessment.completeness_score,
            )
        )
        blackboard.action_history.append(
            ActionDecision(
                action_type="ASSESS_COLLECTION_YIELD" if assessment.should_continue else "STOP",
                rationale=assessment.stop_rationale or "continue",
                metadata={
                    "features": features,
                    "decision_telemetry": self.decision_engine.telemetry.summary(),
                },
            )
        )
        return not assessment.should_continue

    def _round_plan(self, mode: CollectionMode, round_index: int) -> SearchQueryPlan:
        return SearchQueryPlan(
            query_text=mode.focus or "", source_names=[s for s in _SOURCES],
            target_topics=mode.target_topics, round_index=round_index,
        )


_SOURCES = ("nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api")


def _default_playbook() -> PlaybookStore | None:
    if not playbook_enabled():
        return None
    return PlaybookStore(path=default_playbook_path(), embedder=default_playbook_embedder())


def _default_run_id(run_mode: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"real-intel-agent-{run_mode}-{stamp}"


def _round_summary_text(ctx: ToolContext) -> str | None:
    for note in reversed(ctx.notes):
        if isinstance(note, dict) and note.get("summary"):
            return str(note["summary"])
    return None


def _fallback_technique(call: dict[str, Any], topic_bucket: str) -> str:
    from ..memory.harvest import _default_technique_text

    return _default_technique_text(call, topic_bucket)


def _error(error_type: str, message: str):
    from ..schemas import ErrorRecord

    return ErrorRecord(error_type=error_type, message=message[:500])
