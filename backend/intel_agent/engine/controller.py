"""IntelAgentController: the round loop that ties the agent, memory, and rules.

Per round: recall playbook -> render digest -> run an agentic session (falling
back to deterministic rules if the SDK is unavailable) -> annotate relevance ->
merge -> harvest techniques into the playbook -> recompute coverage -> let the
critic decide whether to continue. All heavy collaborators are injectable so the
loop is fully testable offline.
"""

from __future__ import annotations

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
from ..relevance import RelevancePipeline, default_pipeline
from ..runtime.structured import StructuredDecisionEngine
from ..store import default_store
from ..schemas import (
    ActionDecision,
    IntelRunBlackboard,
    RawIntelItemBatch,
    RunBudget,
    SearchQueryPlan,
    SearchReflectionDecision,
)
from ..sources import default_registered_api_sources
from ..tools.context import ToolContext
from .context import render_digest
from .fallback import run_fallback_round
from .modes import CollectionMode, FullCollectionMode

DEFAULT_MAX_RESULTS_PER_CALL = 20


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
        blackboard = IntelRunBlackboard(
            run_id=run_id or _default_run_id(mode.run_mode),
            run_goal=mode.run_goal,
            run_mode=mode.run_mode,  # type: ignore[arg-type]
            budget=budget,
            approved_sources=default_registered_api_sources(),
        )
        if trace is not None:
            trace.bind_run(blackboard.run_id)
        self._batches = []
        try:
            self._run_rounds(blackboard, mode, budget, trace)
        finally:
            if trace is not None:
                trace.close()

        blackboard.metrics.round_index = len(blackboard.query_history)
        status = "succeeded" if blackboard.raw_items else "partial_success"
        self.store.save_run(blackboard, self._batches, status=status)
        if self.playbook is not None:
            self.playbook.save()
        return blackboard

    def _run_rounds(
        self,
        blackboard: IntelRunBlackboard,
        mode: CollectionMode,
        budget: RunBudget,
        trace: TraceSink | None,
    ) -> None:
        since, until = mode.resolve_time_scope(self.store)
        quota = coverage_quota()
        max_rounds = budget.max_rounds or 6
        executed_keys: set[str] = set()
        self._batches: list[RawIntelItemBatch] = []
        engine_available = self.loop.available()

        for round_index in range(max_rounds):
            ctx = self._build_context(blackboard, mode, since, until, executed_keys)
            recall_text = self._recall(mode, blackboard.run_goal)
            open_gaps = quota_open_gaps(blackboard.raw_items, mode.target_topics, quota)
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
                    used_agent = False
                    if trace is not None:
                        trace.emit("session_fallback", reason=result.error or "no items collected")
                    blackboard.errors.append(
                        _error("agent_round_failed", result.error or "no items collected")
                    )
            if not used_agent:
                run_fallback_round(
                    ctx, blackboard, self._round_plan(mode, round_index), mode.target_topics
                )

            batch = self._merge_round(blackboard, ctx, mode, round_index)
            self._batches.append(batch)
            self._harvest(ctx, mode, blackboard.run_id)
            blackboard.coverage_gaps = analyze_coverage_gaps(
                blackboard.raw_items, mode.target_topics, quota
            )
            if trace is not None:
                last_entry = blackboard.query_history[-1] if blackboard.query_history else None
                trace.emit(
                    "round_summary", round=round_index + 1, new_items=len(batch.items),
                    new_relevant=int(last_entry.metadata.get("relevant_new", 0)) if last_entry else 0,
                    api_calls_used=blackboard.metrics.api_calls_used,
                    open_gaps=quota_open_gaps(blackboard.raw_items, mode.target_topics, quota),
                )

            if self._should_stop(
                blackboard, mode, ctx, round_index, max_rounds, quota, digest, trace
            ):
                break

    # ------------------------------------------------------------- per-round

    def _build_context(
        self,
        blackboard: IntelRunBlackboard,
        mode: CollectionMode,
        since: datetime | None,
        until: datetime | None,
        executed_keys: set[str],
    ) -> ToolContext:
        return ToolContext(
            run_id=blackboard.run_id,
            target_topics=mode.target_topics,
            topic_bucket=mode.topic_bucket(),
            max_results_per_call=self.max_results_per_call,
            since=since,
            until=until,
            existing_item_ids={item.item_id for item in blackboard.raw_items},
            executed_keys=executed_keys,
            api_calls_used=blackboard.metrics.api_calls_used,
            max_api_calls=blackboard.budget.max_api_calls,
            playbook=self.playbook,
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
            {"source_name": call["source_name"], "params": call["params"]}
            for call in ctx.executed_calls
        ]
        blackboard.metrics.api_calls_used = ctx.api_calls_used
        blackboard.metrics.sources_used = len(source_names)
        return batch

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
