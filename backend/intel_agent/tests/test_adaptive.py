from __future__ import annotations

from datetime import datetime, timedelta, timezone
import asyncio
import json
import time

from intel_agent.engine.bandit import normalized_reward, select_portfolio
from intel_agent.engine.controller import IntelAgentController
from intel_agent.engine.gaps import (
    compute_corpus_gaps,
    detect_candidate_topics,
    extended_topic_trends,
    initial_run_gaps,
    total_open_priority,
)
from intel_agent.engine.modes import FullCollectionMode, IncrementalCollectionMode
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.runtime.structured import StructuredDecisionEngine
from intel_agent.schemas import (
    IntelRunBlackboard,
    QueryCallOutcome,
    QueryCandidate,
    RawIntelItem,
    RunBudget,
    SourceCheckpoint,
)
from intel_agent.agent.loop import IntelAgentLoop
from intel_agent.tests.conftest import make_item
from intel_agent.schemas import SourceExecutionStat
from intel_agent.tools.context import ToolContext
from intel_agent.tools.adaptive_tools import candidate_validation_error
from intel_agent.tools.source_tools import _run_call
from intel_agent.hooks import build_hooks


NOW = datetime(2026, 7, 10, tzinfo=timezone.utc)


def _offline_decision_engine() -> StructuredDecisionEngine:
    async def critic(prompt, schema, system_prompt, model, max_turns):
        return {
            "should_continue": False,
            "completeness_score": 0.5,
            "missing_topics": [],
            "stop_reason": "offline test",
            "rationale": "offline test",
        }

    return StructuredDecisionEngine(runner=critic)


def test_corpus_gaps_use_core_only_and_soft_evidence():
    extended = make_item(
        "arxiv:extended",
        source_name="arxiv_api",
        relevance=0.95,
        topics=["model extraction"],
        published=NOW,
        summary="model extraction",
        raw_text="model extraction",
    )
    core = make_item(
        "arxiv:core",
        source_name="arxiv_api",
        relevance=1.0,
        topics=["prompt injection"],
        published=NOW,
        raw_text="prompt injection",
    )
    gaps = compute_corpus_gaps([extended, core], now=NOW)
    assert len(gaps) == 34  # 18 research + 16 vulnerability/advisory cells
    assert not any(gap.topic == "model extraction" for gap in gaps)
    prompt_research = next(
        gap for gap in gaps if gap.topic == "prompt injection" and gap.evidence_channel == "research"
    )
    assert prompt_research.effective_evidence == 0.72
    assert 0 < prompt_research.coverage_gap < 1
    trends = extended_topic_trends([extended, core], now=NOW)
    assert trends["model extraction"]["recent_30d"] == 1


def test_same_event_cross_source_gets_half_corroboration_credit():
    nvd = make_item(
        "nvd:cve-2026-1234",
        source_name="nvd_cve_api",
        relevance=1.0,
        topics=["agent tool abuse"],
        published=NOW,
        summary="CVE-2026-1234 agent tool abuse",
        raw_text="agent tool abuse",
    )
    osv = make_item(
        "osv:ghsa-x",
        source_name="osv_dev_api",
        relevance=1.0,
        topics=["agent tool abuse"],
        published=NOW,
        summary="CVE-2026-1234 agent tool abuse",
        raw_text="agent tool abuse",
    )
    gap = next(
        gap
        for gap in compute_corpus_gaps([nvd, osv], now=NOW)
        if gap.topic == "agent tool abuse" and gap.evidence_channel == "vulnerability_advisory"
    )
    assert gap.effective_evidence == 1.32  # 0.90 first evidence + 0.84*0.5 corroboration


def _candidate(candidate_id: str, intent: str, gap_id: str = "") -> QueryCandidate:
    return QueryCandidate(
        candidate_id=candidate_id,
        source_name="arxiv_api" if intent == "discovery" else "nvd_cve_api",
        query_text=candidate_id,
        query_intent=intent,
        evidence_channel="research" if intent == "discovery" else "vulnerability_advisory",
        target_topics=["prompt injection"],
        target_gap_ids=[gap_id] if gap_id else [],
    )


def test_ucb_portfolio_caps_discovery_and_confirmation():
    gap = next(
        gap
        for gap in compute_corpus_gaps([], now=NOW)
        if gap.topic == "prompt injection" and gap.evidence_channel == "vulnerability_advisory"
    )
    candidates = [
        _candidate("gap-1", "gap_fill", gap.gap_id),
        _candidate("gap-2", "gap_fill", gap.gap_id),
        _candidate("discover-1", "discovery"),
        _candidate("discover-2", "discovery"),
        _candidate("confirm-1", "confirmation", gap.gap_id),
        _candidate("confirm-2", "confirmation", gap.gap_id),
    ]
    selected = select_portfolio(candidates, [], [gap], max_calls=4)
    assert len(selected) == 4
    assert sum(row[0].query_intent == "discovery" for row in selected) <= 1
    assert sum(row[0].query_intent == "confirmation" for row in selected) <= 1


def test_candidate_approval_rejects_unknown_topics_and_closed_gaps():
    gap = next(
        gap
        for gap in compute_corpus_gaps([], now=NOW)
        if gap.topic == "prompt injection" and gap.evidence_channel == "research"
    )
    ctx = ToolContext(
        run_id="approval",
        target_topics=["prompt injection"],
        topic_bucket="general",
        corpus_gaps=[gap],
        since=NOW - timedelta(days=1),
        until=NOW,
    )
    valid = QueryCandidate(
        candidate_id="valid",
        source_name="arxiv_api",
        query_text='all:"prompt injection"',
        evidence_channel="research",
        target_topics=["prompt injection"],
        target_gap_ids=[gap.gap_id],
    )
    assert candidate_validation_error(valid, ctx) is None
    assert "unknown taxonomy" in candidate_validation_error(
        valid.model_copy(update={"target_topics": ["invented threat"]}), ctx
    )
    assert "not open" in candidate_validation_error(
        valid.model_copy(update={"target_gap_ids": ["corpus:closed"]}), ctx
    )
    assert "incremental window" in candidate_validation_error(
        valid.model_copy(
            update={
                "params": {
                    "arxiv_search_query": (
                        'all:"prompt injection" AND '
                        "submittedDate:[202607010000 TO 202607112359]"
                    )
                }
            }
        ),
        ctx,
    )


def test_normalized_reward_penalizes_duplicate_and_noise():
    clean = QueryCallOutcome(
        call_id="clean",
        source_name="nvd_cve_api",
        query_text="q",
        evidence_channel="vulnerability_advisory",
        new_count=2,
        relevant_new=2,
        in_scope_count=2,
    )
    noisy = clean.model_copy(
        update={"call_id": "noisy", "noise_count": 2, "duplicate_count": 2}
    )
    assert normalized_reward(2.0, 1.0, clean) > normalized_reward(2.0, 1.0, noisy)


def test_discovery_reward_only_bonuses_extended_or_gated_residual_support():
    base = QueryCallOutcome(
        call_id="discovery",
        source_name="arxiv_api",
        query_text="q",
        query_intent="discovery",
        evidence_channel="research",
        new_count=2,
        relevant_new=2,
        in_scope_count=2,
    )
    extended = base.model_copy(
        update={"metadata": {"extended_new_count": 2}}
    )
    assert normalized_reward(2.0, 2.0, extended) > normalized_reward(2.0, 2.0, base)
    assert normalized_reward(2.0, 2.0, base, residual_support=1.0) > normalized_reward(
        2.0, 2.0, base
    )


def test_per_source_checkpoint_uses_72_hour_overlap(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    checkpoint = SourceCheckpoint(
        source_name="nvd_cve_api", watermark=NOW, complete=True, last_success_at=NOW
    )
    board = IntelRunBlackboard(
        run_id="previous", run_goal="g", source_checkpoints=[checkpoint]
    )
    store.save_run(board)
    starts, until = IncrementalCollectionMode(until=NOW).resolve_source_scopes(store)
    assert starts["nvd_cve_api"] == NOW - timedelta(hours=72)
    assert until == NOW


def test_json_schema_v3_loads_corpus_and_checkpoints(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    checkpoint = SourceCheckpoint(source_name="arxiv_api", watermark=NOW, complete=True)
    board = IntelRunBlackboard(
        run_id="v3", run_goal="g", source_checkpoints=[checkpoint]
    )
    board.raw_items.append(make_item("arxiv:one", source_name="arxiv_api", published=NOW))
    store.save_run(board)
    assert store.load_run_payload("v3")["schema_version"] == 3
    assert [item.item_id for item in store.load_corpus_items()] == ["arxiv:one"]
    assert store.load_source_checkpoints()[0].source_name == "arxiv_api"
    legacy = IntelRunBlackboard.model_validate({"run_id": "old", "run_goal": "g"})
    assert legacy.corpus_gaps == [] and legacy.query_outcomes == []


def test_json_store_reads_v2_blackboard_with_v3_defaults(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    store.save_run(IntelRunBlackboard(run_id="v2", run_goal="g"))
    path = store.run_path("v2")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 2
    for field in (
        "corpus_gaps",
        "run_gaps",
        "query_outcomes",
        "source_checkpoints",
        "candidate_topics",
        "extended_trends",
        "sdk_session_id",
        "stop_reason",
        "collection_strategy",
    ):
        payload["blackboard"].pop(field, None)
    path.write_text(json.dumps(payload), encoding="utf-8")
    board = store.load_all_blackboards()[0]
    assert board.run_id == "v2"
    assert board.corpus_gaps == [] and board.collection_strategy == "legacy"


def test_incomplete_checkpoint_restores_pagination_run_gap():
    checkpoint = SourceCheckpoint(
        source_name="nvd_cve_api", complete=False, cursor="40"
    )
    gaps = initial_run_gaps(compute_corpus_gaps([], now=NOW), [checkpoint])
    pagination = next(gap for gap in gaps if gap.gap_type == "pagination")
    assert pagination.metadata["nvd_start_index"] == 40


def test_candidate_topic_detector_keeps_proposal_out_of_taxonomy():
    items = [
        make_item(
            f"x:{index}",
            source_name="arxiv_api" if index < 2 else "nvd_cve_api",
            relevance=0.9,
            topics=[],
            published=NOW,
            summary=f"novel quantum agent side channel variant {index}",
        )
        for index in range(3)
    ]
    for item in items:
        item.metadata["topic_scores"] = {}

    def embedder(texts):
        return [[1.0, 0.0] if "novel quantum" in text else [0.0, 1.0] for text in texts]

    candidates = detect_candidate_topics(items, embedder, now=NOW)
    assert len(candidates) == 1
    assert candidates[0].status == "proposed"
    assert set(candidates[0].source_names) == {"arxiv_api", "nvd_cve_api"}
    assert candidates[0].metadata["independent_evidence_count"] == 3


def test_candidate_topic_detector_rejects_duplicate_event_reposts():
    items = [
        make_item(
            f"x:duplicate:{index}",
            source_name="arxiv_api" if index < 2 else "nvd_cve_api",
            relevance=0.9,
            topics=[],
            published=NOW,
            summary="CVE-2026-7777 the same novel quantum agent side channel report",
        )
        for index in range(3)
    ]
    for item in items:
        item.metadata["topic_scores"] = {}

    def embedder(texts):
        return [[1.0, 0.0] if "novel quantum" in text else [0.0, 1.0] for text in texts]

    assert detect_candidate_topics(items, embedder, now=NOW) == []


def test_json_corpus_loader_deduplicates_items_across_runs(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    item = make_item("arxiv:shared", source_name="arxiv_api", published=NOW)
    for run_id in ("run-one", "run-two"):
        store.save_run(
            IntelRunBlackboard(run_id=run_id, run_goal="g", raw_items=[item])
        )
    assert [loaded.item_id for loaded in store.load_corpus_items()] == ["arxiv:shared"]


def test_adaptive_controller_persists_per_call_outcome_and_checkpoint(tmp_path):
    async def runner(ctx, prompt, model, max_turns):
        item = RawIntelItem(
            item_id="arxiv:new",
            source_name="arxiv_api",
            source_uri="https://arxiv.org/abs/new",
            title="Prompt injection research",
            summary="prompt injection against an LLM",
            published_at=NOW,
            relevance_score=0.9,
            metadata={"topics": ["prompt injection"]},
        )
        ctx.collected_items[item.item_id] = item
        ctx.api_calls_used += 1
        gap_id = "corpus:prompt_injection:research"
        ctx.executed_calls.append(
            {
                "call_id": "adaptive:call:1",
                "candidate_id": "c1",
                "source_name": "arxiv_api",
                "query_text": "prompt injection",
                "params": {"arxiv_search_query": 'all:"prompt injection"'},
                "query_intent": "gap_fill",
                "evidence_channel": "research",
                "target_topics": ["prompt injection"],
                "target_gap_ids": [gap_id],
                "new_item_ids": [item.item_id],
                "signature": "arxiv_api[arxiv_search_query]",
                "raw_count": 1,
                "in_scope_count": 1,
                "duplicate_count": 0,
                "has_more": False,
                "success": True,
            }
        )
        ctx.notes.append({"summary": "adaptive result"})
        return "done"

    async def critic(prompt, schema, system_prompt, model, max_turns):
        return {
            "should_continue": False,
            "completeness_score": 0.2,
            "missing_topics": [],
            "stop_reason": "test",
            "rationale": "test",
        }

    controller = IntelAgentController(
        store=JsonIntelRunStore(root_dir=tmp_path),
        loop=IntelAgentLoop(runner=runner),
        decision_engine=StructuredDecisionEngine(runner=critic),
        relevance=None,
    )
    board = controller.run(
        mode=IncrementalCollectionMode(since=NOW - timedelta(days=1), until=NOW),
        budget=RunBudget(max_rounds=1, max_api_calls=4),
        run_id="adaptive",
    )
    assert board.collection_strategy == "adaptive"
    assert board.stop_reason == "max_rounds"
    assert board.query_outcomes[0].raw_count == 1
    assert board.query_outcomes[0].relevant_new == 1
    checkpoint = next(cp for cp in board.source_checkpoints if cp.source_name == "arxiv_api")
    assert checkpoint.complete is True and checkpoint.watermark == NOW
    assert total_open_priority(board.corpus_gaps) < total_open_priority(compute_corpus_gaps([]))


def test_adaptive_source_call_requires_approval_and_counts_prefilter_duplicates(monkeypatch):
    existing = make_item(
        "nvd:existing",
        source_name="nvd_cve_api",
        published=NOW,
        raw_text="agent tool abuse",
        summary="agent tool abuse",
        topics=["agent tool abuse"],
    )
    fresh = make_item(
        "nvd:fresh",
        source_name="nvd_cve_api",
        published=NOW,
        raw_text="agent tool abuse",
        summary="agent tool abuse",
        topics=["agent tool abuse"],
    )

    def fake_search(*args, **kwargs):
        return [existing, fresh], SourceExecutionStat(
            source_name="nvd_cve_api", query_count=1, result_count=2, latency_ms=5
        )

    monkeypatch.setattr("intel_agent.tools.source_tools.search_source", fake_search)
    ctx = ToolContext(
        run_id="run",
        target_topics=["agent tool abuse"],
        topic_bucket="agent tool abuse",
        adaptive=True,
        existing_item_ids={existing.item_id},
        since=NOW - timedelta(days=1),
        until=NOW + timedelta(days=1),
    )
    denied = _run_call(ctx, "nvd_cve_api", {"query_text": "q"})
    assert "approved candidate_id" in denied["content"][0]["text"]
    candidate = QueryCandidate(
        candidate_id="approved",
        source_name="nvd_cve_api",
        query_text="agent tool abuse",
        query_intent="gap_fill",
        evidence_channel="vulnerability_advisory",
        target_topics=["agent tool abuse"],
        target_gap_ids=["corpus:agent_tool_abuse:vulnerability_advisory"],
    )
    ctx.approved_candidates[candidate.candidate_id] = candidate
    _run_call(
        ctx,
        "nvd_cve_api",
        {"query_text": "ignored", "candidate_id": candidate.candidate_id},
    )
    call = ctx.executed_calls[0]
    assert call["raw_count"] == 2
    assert call["in_scope_count"] == 2
    assert call["duplicate_count"] == 1
    assert call["new_item_ids"] == [fresh.item_id]
    duplicate = candidate.model_copy(update={"candidate_id": "approved-again"})
    ctx.approved_candidates[duplicate.candidate_id] = duplicate
    callback = build_hooks(ctx)["PreToolUse"][0].hooks[0]
    denied = asyncio.run(
        callback(
            {
                "tool_name": "mcp__intel_sources__search_nvd",
                "tool_input": {"candidate_id": duplicate.candidate_id},
            },
            "tool-duplicate",
            None,
        )
    )
    assert "already ran" in denied["hookSpecificOutput"]["permissionDecisionReason"]


def test_adaptive_arxiv_candidate_without_operator_keeps_thematic_query(monkeypatch):
    captured = {}

    def fake_search(*args, **kwargs):
        captured.update(kwargs)
        return [], SourceExecutionStat(
            source_name="arxiv_api", query_count=1, result_count=0
        )

    monkeypatch.setattr("intel_agent.tools.source_tools.search_source", fake_search)
    ctx = ToolContext(
        run_id="arxiv-query",
        target_topics=["prompt injection"],
        topic_bucket="general",
        adaptive=True,
        since=NOW - timedelta(days=1),
        until=NOW,
    )
    candidate = QueryCandidate(
        candidate_id="arxiv-approved",
        source_name="arxiv_api",
        query_text="prompt injection",
        evidence_channel="research",
        target_topics=["prompt injection"],
        target_gap_ids=["corpus:prompt_injection:research"],
    )
    ctx.approved_candidates[candidate.candidate_id] = candidate
    _run_call(
        ctx,
        "arxiv_api",
        {"query_text": "ignored", "candidate_id": candidate.candidate_id},
    )
    query = captured["arxiv_search_query"]
    assert "prompt injection" in query
    assert "submittedDate:" in query


def test_pre_tool_hook_blocks_unapproved_adaptive_call():
    ctx = ToolContext(
        run_id="run",
        target_topics=["prompt injection"],
        topic_bucket="general",
        adaptive=True,
    )
    hooks = build_hooks(ctx)
    assert hooks is not None
    callback = hooks["PreToolUse"][0].hooks[0]
    denied = asyncio.run(
        callback(
            {
                "tool_name": "mcp__intel_sources__search_nvd",
                "tool_input": {"candidate_id": "missing"},
            },
            "tool-1",
            None,
        )
    )
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_tool_hook_blocks_candidate_outside_authoritative_window():
    ctx = ToolContext(
        run_id="run",
        target_topics=["prompt injection"],
        topic_bucket="general",
        adaptive=True,
        since=NOW - timedelta(days=1),
        until=NOW,
    )
    candidate = QueryCandidate(
        candidate_id="outside-window",
        source_name="nvd_cve_api",
        query_text="prompt injection",
        params={"nvd_pub_start_date": (NOW - timedelta(days=4)).isoformat()},
        evidence_channel="vulnerability_advisory",
        target_topics=["prompt injection"],
    )
    ctx.approved_candidates[candidate.candidate_id] = candidate
    callback = build_hooks(ctx)["PreToolUse"][0].hooks[0]
    denied = asyncio.run(
        callback(
            {
                "tool_name": "mcp__intel_sources__search_nvd",
                "tool_input": {"candidate_id": candidate.candidate_id},
            },
            "tool-window",
            None,
        )
    )
    assert "incremental window" in denied["hookSpecificOutput"]["permissionDecisionReason"]


def test_incomplete_or_failed_call_does_not_advance_checkpoint(tmp_path):
    controller = IntelAgentController(
        store=JsonIntelRunStore(root_dir=tmp_path),
        loop=IntelAgentLoop(runner=lambda *args: None),
    )
    old = NOW - timedelta(days=2)
    board = IntelRunBlackboard(
        run_id="checkpoint",
        run_goal="g",
        source_checkpoints=[
            SourceCheckpoint(source_name="nvd_cve_api", watermark=old, complete=True)
        ],
    )
    ctx = ToolContext(
        run_id="checkpoint",
        target_topics=["prompt injection"],
        topic_bucket="general",
        until=NOW,
    )
    paged = QueryCallOutcome(
        call_id="paged",
        source_name="nvd_cve_api",
        query_text="q",
        params={"nvd_start_index": 0},
        evidence_channel="vulnerability_advisory",
        has_more=True,
        success=True,
    )
    failed = QueryCallOutcome(
        call_id="failed",
        source_name="arxiv_api",
        query_text="q",
        evidence_channel="research",
        success=False,
        error_type="TimeoutError",
    )
    controller._update_adaptive_run_state(board, ctx, [paged, failed])
    nvd = next(cp for cp in board.source_checkpoints if cp.source_name == "nvd_cve_api")
    arxiv = next(cp for cp in board.source_checkpoints if cp.source_name == "arxiv_api")
    assert nvd.watermark == old and nvd.complete is False and nvd.cursor == "20"
    assert arxiv.watermark is None and arxiv.complete is False
    assert any(gap.gap_type == "pagination" for gap in board.run_gaps)
    assert any(gap.gap_type == "retry" for gap in board.run_gaps)


def test_incremental_sdk_unavailable_downgrades_whole_run_to_legacy(tmp_path, monkeypatch):
    loop = IntelAgentLoop()
    monkeypatch.setattr(loop, "available", lambda: False)

    def fake_fallback(ctx, blackboard, query_plan, target_topics):
        ctx.notes.append({"summary": "legacy fallback"})

    monkeypatch.setattr("intel_agent.engine.controller.run_fallback_round", fake_fallback)
    controller = IntelAgentController(
        store=JsonIntelRunStore(root_dir=tmp_path),
        loop=loop,
        relevance=None,
        decision_engine=_offline_decision_engine(),
    )
    board = controller.run(
        mode=IncrementalCollectionMode(since=NOW - timedelta(days=1), until=NOW),
        budget=RunBudget(max_rounds=1, max_api_calls=1),
        run_id="legacy-downgrade",
    )
    assert board.collection_strategy == "legacy"
    assert any(error.error_type == "adaptive_sdk_unavailable" for error in board.errors)


def test_full_mode_does_not_depend_on_adaptive_history_loaders(tmp_path):
    class LegacyOnlyStore(JsonIntelRunStore):
        def load_corpus_items(self):
            raise AssertionError("full mode must not load the adaptive corpus")

        def load_source_checkpoints(self):
            raise AssertionError("full mode must not load adaptive checkpoints")

    async def runner(ctx, prompt, model, max_turns):
        ctx.notes.append({"summary": "legacy full"})
        return "done"

    controller = IntelAgentController(
        store=LegacyOnlyStore(root_dir=tmp_path),
        loop=IntelAgentLoop(runner=runner),
        relevance=None,
        decision_engine=_offline_decision_engine(),
    )
    board = controller.run(
        mode=FullCollectionMode(),
        budget=RunBudget(max_rounds=1, max_api_calls=1),
        run_id="full-legacy",
    )
    assert board.collection_strategy == "legacy"
    assert board.corpus_gaps == []


def test_adaptive_history_load_failure_downgrades_current_run(tmp_path):
    class FailingAdaptiveStore(JsonIntelRunStore):
        def load_corpus_items(self):
            raise OSError("history unavailable")

    async def runner(ctx, prompt, model, max_turns):
        ctx.notes.append({"summary": "legacy after persistence failure"})
        return "done"

    controller = IntelAgentController(
        store=FailingAdaptiveStore(root_dir=tmp_path),
        loop=IntelAgentLoop(runner=runner),
        relevance=None,
        decision_engine=_offline_decision_engine(),
    )
    board = controller.run(
        mode=IncrementalCollectionMode(since=NOW - timedelta(days=1), until=NOW),
        budget=RunBudget(max_rounds=1, max_api_calls=1),
        run_id="persistence-downgrade",
    )
    assert board.collection_strategy == "legacy"
    assert any(error.error_type == "adaptive_persistence_failed" for error in board.errors)


def test_incremental_sdk_hard_failure_downgrades_to_legacy(tmp_path, monkeypatch):
    async def failing_runner(ctx, prompt, model, max_turns):
        raise RuntimeError("sdk transport failed")

    def fake_fallback(ctx, blackboard, query_plan, target_topics):
        ctx.notes.append({"summary": "legacy after SDK failure"})

    monkeypatch.setattr("intel_agent.engine.controller.run_fallback_round", fake_fallback)
    controller = IntelAgentController(
        store=JsonIntelRunStore(root_dir=tmp_path),
        loop=IntelAgentLoop(runner=failing_runner),
        relevance=None,
        decision_engine=_offline_decision_engine(),
    )
    board = controller.run(
        mode=IncrementalCollectionMode(since=NOW - timedelta(days=1), until=NOW),
        budget=RunBudget(max_rounds=1, max_api_calls=1),
        run_id="sdk-failure-downgrade",
    )
    assert board.collection_strategy == "legacy"
    assert any(error.error_type == "adaptive_sdk_failed" for error in board.errors)


def test_adaptive_stop_marks_remaining_corpus_gaps_exhausted_after_two_stalls(tmp_path):
    async def critic(prompt, schema, system_prompt, model, max_turns):
        return {
            "should_continue": False,
            "completeness_score": 0.1,
            "missing_topics": [],
            "stop_reason": "low yield",
            "rationale": "low yield",
        }

    controller = IntelAgentController(
        store=JsonIntelRunStore(root_dir=tmp_path),
        loop=IntelAgentLoop(runner=lambda *args: None),
        decision_engine=StructuredDecisionEngine(runner=critic),
    )
    controller._run_started_at = time.monotonic()
    controller._adaptive_stall_rounds = 0
    board = IntelRunBlackboard(
        run_id="stall",
        run_goal="g",
        run_mode="incremental",
        collection_strategy="adaptive",
        corpus_gaps=compute_corpus_gaps([], now=NOW),
        budget=RunBudget(max_rounds=5, max_api_calls=10),
    )
    ctx = ToolContext(
        run_id="stall",
        target_topics=["prompt injection"],
        topic_bucket="general",
        max_api_calls=10,
    )
    assert controller._should_stop_adaptive(board, ctx, 0, 5, "digest") is False
    assert controller._should_stop_adaptive(board, ctx, 1, 5, "digest") is True
    assert board.stop_reason == "saturated"
    assert all(gap.status == "exhausted_this_run" for gap in board.corpus_gaps)
