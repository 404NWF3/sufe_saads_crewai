"""run_store.py — 内存运行状态管理（WP1-1 运行生命周期）"""
from __future__ import annotations

import asyncio
import collections
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── 节点顺序与元数据 ────────────────────────────────────────────────

NODE_ORDER: list[str] = [
    "load_runtime_context",
    "supervisor_plan",
    "dispatch_collection",
    "collect_structured_sources",
    "collect_code_sources",
    "collect_paper_sources",
    "collect_community_sources",
    "collect_advisory_sources",
    "store_raw_records",
    "assess_collection_yield",
    "reflect_search_strategy",
    "parse_and_standardize",
    "semantic_dedup_and_merge",
    "resolve_ai_bom",
    "review_ai_bom_resolution",
    "score_confidence_and_novelty",
    "refresh_coverage_view",
    "coverage_gap_analysis",
    "weak_signal_mining",
    "generate_alerts",
    "finalize_run",
]

NODE_DISPLAY_NAMES: dict[str, str] = {
    "load_runtime_context": "加载运行上下文",
    "supervisor_plan": "Supervisor 规划",
    "dispatch_collection": "分发采集任务",
    "collect_structured_sources": "采集结构化源",
    "collect_code_sources": "采集代码源",
    "collect_paper_sources": "采集论文源",
    "collect_community_sources": "采集社区源",
    "collect_advisory_sources": "采集公告源",
    "store_raw_records": "存储原始记录",
    "assess_collection_yield": "评估采集产出",
    "reflect_search_strategy": "反思搜索策略",
    "parse_and_standardize": "解析与标准化",
    "semantic_dedup_and_merge": "语义去重合并",
    "resolve_ai_bom": "解析 AI BOM",
    "review_ai_bom_resolution": "审查 BOM 解析",
    "score_confidence_and_novelty": "置信度与新颖性评分",
    "refresh_coverage_view": "刷新覆盖视图",
    "coverage_gap_analysis": "覆盖缺口分析",
    "weak_signal_mining": "弱信号挖掘",
    "generate_alerts": "生成告警",
    "finalize_run": "完成运行",
}

# load_runtime_context 不可单独触发
NON_TRIGGERABLE_NODES = {"load_runtime_context"}


# ── 数据结构 ─────────────────────────────────────────────────────────

@dataclass
class RunRecord:
    run_id: str
    status: str  # queued | running | succeeded | partial_success | failed
    run_mode: str
    started_at: str
    completed_at: str | None = None
    current_node: str | None = None
    completed_nodes: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    percent: int = 0
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    task: asyncio.Task | None = field(default=None, repr=False)  # type: ignore[type-arg]
    log_queue: asyncio.Queue[dict[str, Any] | None] = field(
        default_factory=asyncio.Queue, repr=False
    )
    # Ring buffer: retains the last N events for replay on SSE reconnect.
    log_history: collections.deque[dict[str, Any]] = field(
        default_factory=lambda: collections.deque(maxlen=200), repr=False
    )


class RunStore:
    """全局内存运行状态管理（单例）。"""

    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}
        self._latest_run_id: str | None = None
        # 每个节点最后一次执行状态: node_name → last_status
        self.node_last_status: dict[str, str] = {}
        self.node_last_run_at: dict[str, str | None] = {}

    def create(self, run_id: str, run_mode: str) -> RunRecord:
        record = RunRecord(
            run_id=run_id,
            status="queued",
            run_mode=run_mode,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._runs[run_id] = record
        self._latest_run_id = run_id
        return record

    def get(self, run_id: str) -> RunRecord | None:
        return self._runs.get(run_id)

    def get_active(self) -> RunRecord | None:
        for r in reversed(list(self._runs.values())):
            if r.status in ("queued", "running"):
                return r
        return None

    def get_latest(self) -> RunRecord | None:
        if self._latest_run_id:
            return self._runs.get(self._latest_run_id)
        return None

    def update_from_state(self, run_id: str, state: dict[str, Any]) -> None:
        record = self._runs.get(run_id)
        if not record:
            return
        record.state_snapshot = state
        record.current_node = state.get("current_node")
        record.completed_nodes = list(state.get("completed_nodes") or [])
        record.errors = list(state.get("errors") or [])
        record.percent = _calc_percent(record.completed_nodes)
        run_status = state.get("run_status")
        if run_status in ("succeeded", "failed", "partial_success"):
            record.status = run_status
            record.completed_at = datetime.now(timezone.utc).isoformat()
        elif run_status == "running":
            record.status = "running"

    def mark_node_done(
        self, node_name: str, status: str, run_at: str | None = None
    ) -> None:
        self.node_last_status[node_name] = status
        self.node_last_run_at[node_name] = run_at or datetime.now(timezone.utc).isoformat()


def _calc_percent(completed_nodes: list[str]) -> int:
    total = len(NODE_ORDER)
    if total == 0:
        return 0
    return min(int(len(completed_nodes) / total * 100), 99)
