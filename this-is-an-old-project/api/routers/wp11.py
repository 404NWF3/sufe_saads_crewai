"""wp11.py — WP1-1 REST API 路由（FastAPI）

挂载点：/api/wp11

端点：
  GET  /status                    → WpStatusResponse（状态 + 指标快照）
  GET  /metrics                   → WpMetricSeries[]（时序指标数据）
  GET  /alerts                    → WpAlert[]（告警列表）
  GET  /state/latest              → WP11StateSnapshot
  GET  /runs/{run_id}/state       → WP11StateSnapshot
  GET  /runtime/parameters        → RuntimeParameterCatalog
  GET  /nodes                     → WpNodeInfo[]
  POST /nodes/{node_name}/run     → 触发单节点
  POST /runs                      → 启动新 run → WpRunStatus
  POST /runs/{run_id}/resume      → 从断点恢复
  GET  /runs/active               → WpRunStatus | 404
  DELETE /runs/{run_id}           → 取消 run
  GET  /logs/stream               → SSE 日志流
"""
from __future__ import annotations

import asyncio
import collections
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ValidationError

from backend.agents.intel_agents.orchestrator.runtime import Phase1GraphRuntime
from backend.agents.intel_agents.orchestrator.state import RunMode, build_initial_state
from backend.agents.intel_agents.schemas.runtime import RuntimeContextDTO
from backend.agents.intel_agents.services.runtime_tuning_service import (
    RuntimeTuningOverridesDTO,
    apply_tuning_overrides,
    build_runtime_parameter_catalog,
)
from backend.api.run_store import (
    NODE_DISPLAY_NAMES,
    NODE_ORDER,
    NON_TRIGGERABLE_NODES,
    RunRecord,
    RunStore,
)

router = APIRouter(prefix="/api/wp11")

# 共享线程池（LangGraph invoke 是阻塞 I/O）
_executor = ThreadPoolExecutor(max_workers=4)

# ── 指标历史（模块级，线程安全：deque.append 受 GIL 保护）────────────
_metrics_history: collections.deque[dict[str, Any]] = collections.deque(maxlen=200)


def _derive_coverage_rate(state: dict[str, Any]) -> float:
    """从节点状态推算 OWASP 覆盖率（%）。"""
    # 优先使用 coverage_view 或 owasp_coverage 字段
    for key in ("coverage_rate", "owasp_coverage", "coverage_view"):
        val = state.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return round(float(val), 1)
    # 回退：用覆盖缺口推算（10 个 OWASP LLM Top 10 类别）
    gaps = state.get("coverage_gaps")
    if isinstance(gaps, list):
        total = 10
        uncovered = len(gaps)
        covered = max(0, total - uncovered)
        return round(covered / total * 100, 1)
    return 0.0


def _push_metrics_snapshot(state: dict[str, Any], ts: str | None = None) -> None:
    """每次节点执行完成后推送一次指标快照（供 /metrics 端点使用）。"""
    _metrics_history.append({
        "ts": ts or datetime.now(timezone.utc).isoformat(),
        "attack_pool_size": float(state.get("processed_count", 0)),
        "coverage_rate": _derive_coverage_rate(state),
        "new_intel_24h": float(state.get("new_attack_count", 0)),
    })


# ── 节点详情事件提取 ───────────────────────────────────────────────


def _extract_node_details(
    node_name: str,
    node_state: dict[str, Any],
    ts: str,
) -> list[dict[str, Any]]:
    """从节点 patch 中提取结构化审计数据，生成 SSE node_detail / node_error_detail 事件列表。
    所有数据均已存在于节点返回值中，无需额外计算。
    """
    events: list[dict[str, Any]] = []
    display = NODE_DISPLAY_NAMES.get(node_name, node_name)

    def _d(msg: str) -> None:
        events.append({"type": "node_detail", "node": node_name,
                        "display_name": display, "ts": ts, "message": msg})

    def _e(msg: str) -> None:
        events.append({"type": "node_error_detail", "node": node_name,
                        "display_name": display, "ts": ts, "message": msg})

    # ── 通用：节点内错误（所有节点）──────────────────────────────
    for err in node_state.get("errors") or []:
        _e(f"[{err.get('error_type', 'Error')}] {err.get('message', '')} "
           f"{'(可重试)' if err.get('retryable') else ''}")

    # ── supervisor_plan ────────────────────────────────────────
    if node_name == "supervisor_plan":
        for a in node_state.get("llm_planning_audits") or []:
            conf = a.get("confidence")
            conf_s = f" | 置信度 {conf:.0%}" if conf is not None else ""
            _d(f"策略: {a.get('strategy_executed', '?')} | "
               f"数据源: {a.get('source_plan_count', 0)} 个 | "
               f"目标分类: {a.get('target_taxonomy_count', 0)} 个{conf_s}")
            if a.get("plan_rationale"):
                _d(f"规划理由: {str(a['plan_rationale'])[:280]}")
            if a.get("fallback_reason"):
                _e(f"降级原因: {a['fallback_reason']}")

    # ── dispatch_collection ────────────────────────────────────
    elif node_name == "dispatch_collection":
        plan = node_state.get("collection_plan") or {}
        sources = plan.get("source_plans") or []
        if sources:
            _d(f"分发 {len(sources)} 个数据源采集计划")

    # ── 采集节点（五个）───────────────────────────────────────
    elif node_name in (
        "collect_structured_sources", "collect_code_sources",
        "collect_paper_sources", "collect_community_sources",
        "collect_advisory_sources",
    ):
        stats = node_state.get("source_execution_stats") or []
        for s in stats:
            ok = "✓" if s.get("success") else "✗"
            stub = " [stub]" if s.get("used_stub") else ""
            lat = s.get("latency_ms")
            lat_s = f" {lat:.0f}ms" if lat else ""
            err_s = f" [{s['error_type']}]" if not s.get("success") and s.get("error_type") else ""
            _d(f"{ok} {s.get('source_name', '?')}{stub}: "
               f"{s.get('item_count', 0)} 条{lat_s}{err_s}")
        raw_count = len(node_state.get("raw_items") or [])
        if raw_count:
            _d(f"本轮合计: {raw_count} 条原始记录")

    # ── store_raw_records ──────────────────────────────────────
    elif node_name == "store_raw_records":
        cnt = node_state.get("processed_count", 0)
        batch = len(node_state.get("stored_raw_records") or [])
        if cnt or batch:
            _d(f"已存储 {cnt} 条记录（本批 {batch} 条）")

    # ── assess_collection_yield ────────────────────────────────
    elif node_name == "assess_collection_yield":
        telemetry = node_state.get("query_telemetry") or []
        if telemetry:
            avg_yield = sum(t.get("novelty_yield", 0) for t in telemetry) / len(telemetry)
            avg_noise = sum(t.get("noise_ratio", 0) for t in telemetry) / len(telemetry)
            _d(f"查询数: {len(telemetry)} | "
               f"平均新颖率: {avg_yield:.0%} | "
               f"平均噪声率: {avg_noise:.0%}")
        for s in node_state.get("collection_yield_summary") or []:
            flags = (["低产出"] if s.get("low_yield") else []) + \
                    (["高噪声"] if s.get("high_noise") else [])
            reco = (s.get("recommended_actions") or [])[:2]
            reco_s = f" → {', '.join(reco)}" if reco else ""
            _d(f"  {s.get('source_name', '?')}: "
               f"查询 {s.get('total_queries', 0)} | "
               f"解析 {s.get('total_parsed', 0)} | "
               f"{' '.join(flags) or '正常'}{reco_s}")

    # ── reflect_search_strategy ────────────────────────────────
    elif node_name == "reflect_search_strategy":
        for a in node_state.get("llm_reflection_audits") or []:
            conf = a.get("confidence")
            conf_s = f" | 置信度 {conf:.0%}" if conf is not None else ""
            _d(f"轮次 {a.get('reflection_round', '?')} | "
               f"诊断: {a.get('diagnosis', '?')} | "
               f"重写查询: {a.get('rewritten_query_count', 0)} 个 | "
               f"继续采集: {'是' if a.get('should_retry') else '否'}{conf_s}")
            if a.get("stop_reason"):
                _d(f"停止原因: {a['stop_reason']}")
            if a.get("evidence_summary"):
                _d(f"诊断依据: {str(a['evidence_summary'])[:220]}")

    # ── parse_and_standardize ──────────────────────────────────
    elif node_name == "parse_and_standardize":
        items = node_state.get("standardized_items") or []
        audits = node_state.get("llm_standardization_audits") or []
        if items:
            _d(f"标准化完成: {len(items)} 条情报")
        if audits:
            confs = [a["llm_confidence"] for a in audits
                     if a.get("llm_confidence") is not None]
            if confs:
                _d(f"提取置信度: 均值 {sum(confs)/len(confs):.0%} | "
                   f"最低 {min(confs):.0%} | 条目 {len(audits)} 条")
            fallbacks = [a for a in audits if a.get("fallback_reason")]
            if fallbacks:
                _e(f"LLM 降级 → 规则解析: {len(fallbacks)} 条")

    # ── semantic_dedup_and_merge ───────────────────────────────
    elif node_name == "semantic_dedup_and_merge":
        new_cnt = node_state.get("new_attack_count", 0)
        merged = node_state.get("dedup_merged_count", 0)
        if new_cnt or merged:
            _d(f"新增攻击记录: {new_cnt} 条 | 语义合并去重: {merged} 条")

    # ── resolve_ai_bom ─────────────────────────────────────────
    elif node_name == "resolve_ai_bom":
        bom = node_state.get("bom_queue_count", 0)
        if bom:
            _d(f"待解析 BOM 条目: {bom} 个")

    # ── coverage_gap_analysis ──────────────────────────────────
    elif node_name == "coverage_gap_analysis":
        gaps = node_state.get("coverage_gaps") or []
        if gaps:
            _d(f"发现覆盖缺口: {len(gaps)} 个")
            top = sorted(gaps, key=lambda g: g.get("gap_score", 0), reverse=True)[:4]
            for g in top:
                roi = g.get("estimated_gap_fill_roi")
                roi_s = f" ROI={roi:.2f}" if roi is not None else ""
                _d(f"  ↳ {g.get('taxonomy_code', '?')} {g.get('taxonomy_name', '')} "
                   f"缺口分={g.get('gap_score', 0):.2f}{roi_s}")
        if node_state.get("gap_fill_needed"):
            _d("已触发缺口填补，将重新规划采集")

    # ── generate_alerts ────────────────────────────────────────
    elif node_name == "generate_alerts":
        alerts = node_state.get("alert_candidates") or []
        _d(f"生成告警: {len(alerts)} 条")
        for alert in alerts[:5]:
            sev = (alert.get("severity") or "").upper()
            title = alert.get("title") or alert.get("summary", "?")
            _d(f"  ↳ [{sev}] {str(title)[:120]}")

    # ── finalize_run ───────────────────────────────────────────
    elif node_name == "finalize_run":
        _d(f"运行状态: {node_state.get('run_status', '?')}")

    return events


# ── 每个节点需要展示的关键状态字段（与 main.py StepDebugger 保持一致）──────
NODE_FOCUS: dict[str, list[str]] = {
    "load_runtime_context": ["run_mode", "run_status", "runtime_context"],
    "supervisor_plan": ["collection_plan", "llm_planning_audits"],
    "dispatch_collection": ["collector_plans", "collection_coordination"],
    "collect_structured_sources": ["raw_items", "source_execution_stats", "query_telemetry"],
    "collect_code_sources": ["raw_items", "source_execution_stats", "query_telemetry"],
    "collect_paper_sources": ["raw_items", "source_execution_stats"],
    "collect_community_sources": ["raw_items", "source_execution_stats"],
    "collect_advisory_sources": ["raw_items", "source_execution_stats"],
    "store_raw_records": ["stored_raw_ids", "stored_raw_records", "ingest_audits"],
    "assess_collection_yield": [
        "collection_yield_summary", "reflection_needed", "reflection_rationale",
    ],
    "reflect_search_strategy": [
        "llm_reflection_audits", "reflection_round", "reflection_needed",
    ],
    "parse_and_standardize": [
        "standardized_items", "llm_standardization_audits", "processed_count",
    ],
    "semantic_dedup_and_merge": [
        "dedup_decisions", "llm_dedup_judgments", "dedup_merged_count",
        "stable_attack_records", "dedup_persist_summary", "dedup_audit_summary",
    ],
    "resolve_ai_bom": [
        "standardized_items", "llm_bom_resolution_audits", "bom_queue_count",
    ],
    "build_stix_graph": ["standardized_items", "stix_bundle_refs"],
    "score_confidence_and_novelty": ["standardized_items", "new_attack_count"],
    "refresh_coverage_view": ["runtime_context"],
    "coverage_gap_analysis": [
        "coverage_gaps", "gap_fill_needed", "gap_fill_rationale", "gap_fill_round",
    ],
    "generate_alerts": ["alert_candidates"],
    "finalize_run": ["run_status", "finished_at", "errors"],
}

# 节点 verbose 数据最大字节限制（超大字段截断，避免 SSE 拥塞）
_VERBOSE_VALUE_MAX = 8000


def _push_verbose_state_events(
    node_name: str,
    node_state: dict[str, Any],
    ts: str,
    put_fn: "Callable[[dict[str, Any]], None]",
) -> None:
    """将节点状态中 NODE_FOCUS 指定的关键字段作为 node_verbose 事件推送到 SSE 流。
    这实现了与 `python main.py --live --verbose` 终端输出等价的详细日志。
    """
    focus_keys = NODE_FOCUS.get(node_name)
    if not focus_keys:
        return
    display = NODE_DISPLAY_NAMES.get(node_name, node_name)
    for key in focus_keys:
        value = node_state.get(key)
        if value is None:
            continue
        try:
            value_json = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            value_json = repr(value)
        truncated = False
        if len(value_json) > _VERBOSE_VALUE_MAX:
            value_json = value_json[:_VERBOSE_VALUE_MAX]
            truncated = True
        put_fn({
            "type": "node_verbose",
            "node": node_name,
            "display_name": display,
            "ts": ts,
            "key": key,
            "value": value_json,
            "truncated": truncated,
        })


# ── Pydantic 请求/响应模型 ─────────────────────────────────────────


class WpRunRequest(BaseModel):
    run_mode: RunMode = "bootstrap"
    target_sources: list[str] | None = None
    runtime_context_overrides: dict[str, Any] | None = None
    tuning_overrides: RuntimeTuningOverridesDTO | None = None


class WpResumeRequest(BaseModel):
    reuse_run_id: bool = False
    resume_from_node: str | None = None
    runtime_context_overrides: dict[str, Any] | None = None
    tuning_overrides: RuntimeTuningOverridesDTO | None = None


# ── 辅助函数 ──────────────────────────────────────────────────────


def _get_deps(request: Request) -> tuple[Phase1GraphRuntime, RunStore]:
    runtime: Phase1GraphRuntime = request.app.state.wp11_runtime
    store: RunStore = request.app.state.run_store
    return runtime, store


def _state_to_snapshot(state: dict[str, Any], run_id: str | None = None) -> dict[str, Any]:
    """将 WP11GraphState 映射为前端 WP11StateSnapshot。"""
    return {
        "run_id": run_id or state.get("run_id"),
        "run_mode": state.get("run_mode"),
        "run_status": state.get("run_status"),
        "current_node": state.get("current_node"),
        "processed_count": state.get("processed_count", 0),
        "dedup_merged_count": state.get("dedup_merged_count", 0),
        "new_attack_count": state.get("new_attack_count", 0),
        "bom_queue_count": state.get("bom_queue_count", 0),
        "reflection_round": state.get("reflection_round", 0),
        "gap_fill_round": state.get("gap_fill_round", 0),
        "errors_count": len(state.get("errors") or []),
        "completed_nodes": list(state.get("completed_nodes") or []),
        "raw_items_count": len(state.get("raw_items") or []),
        "standardized_items_count": len(state.get("standardized_items") or []),
        "reflection_needed": state.get("reflection_needed", False),
        "gap_fill_needed": state.get("gap_fill_needed", False),
        "started_at": state.get("started_at"),
        "finished_at": state.get("finished_at"),
        "resume_hint": state.get("resume_hint"),
    }


def _record_to_run_status(record: RunRecord) -> dict[str, Any]:
    """将 RunRecord 映射为前端 WpRunStatus。"""
    return {
        "run_id": record.run_id,
        "status": record.status,
        "run_mode": record.run_mode,
        "progress": {
            "current_node": record.current_node,
            "completed_nodes": record.completed_nodes,
            "total_nodes": len(NODE_ORDER),
            "percent": record.percent,
        },
        "started_at": record.started_at,
        "completed_at": record.completed_at,
        "resume_hint": (record.state_snapshot or {}).get("resume_hint"),
        "errors": [
            {
                "node_name": e.get("node") or e.get("node_name", "unknown"),
                "error_type": e.get("error_type", "RuntimeError"),
                "message": e.get("message", str(e)),
                "occurred_at": e.get("occurred_at", datetime.now(timezone.utc).isoformat()),
            }
            for e in record.errors
        ],
    }


def _raise_422(detail: str, exc: Exception) -> None:
    raise HTTPException(status_code=422, detail=detail) from exc


async def _run_graph_in_background(
    runtime: Phase1GraphRuntime,
    store: RunStore,
    record: RunRecord,
    initial_state: dict[str, Any],
) -> None:
    """在线程池中执行 LangGraph，完成后更新 RunRecord。"""
    loop = asyncio.get_running_loop()
    record.status = "running"

    def _put(event: dict[str, Any] | None) -> None:
        """线程安全地向 asyncio.Queue 推送事件，同时写入 replay 历史。"""
        if event is not None:
            record.log_history.append(event)
        loop.call_soon_threadsafe(record.log_queue.put_nowait, event)

    async def _stream_events() -> None:
        """在线程中运行 app.stream()，通过 queue 推送 SSE 事件。"""
        def _sync_stream() -> None:
            import time as _time
            run_id = initial_state["run_id"]
            config: Any = {"configurable": {"thread_id": run_id}}

            # ── 推送运行头（等价于 StepDebugger 的 banner）──────────
            ctx = initial_state.get("runtime_context") or {}
            _put({
                "type": "run_header",
                "run_id": run_id,
                "run_mode": initial_state.get("run_mode", "bootstrap"),
                "source_runtime_mode": ctx.get("source_runtime_mode", "?"),
                "trace_id": initial_state.get("trace_id", ""),
                "llm_model": ctx.get("llm_model", ""),
                "ts": datetime.now(timezone.utc).isoformat(),
            })

            try:
                node_index = 0
                for chunk in runtime.app.stream(initial_state, config=config):
                    for node_name, node_state in chunk.items():
                        node_start = _time.perf_counter()
                        node_index += 1
                        # 更新 store
                        merged = {**initial_state, **node_state}
                        store.update_from_state(run_id, merged)
                        store.mark_node_done(node_name, "succeeded")
                        record.current_node = node_name
                        ts_now = datetime.now(timezone.utc).isoformat()
                        # 推送指标快照（供 /metrics 端点使用）
                        _push_metrics_snapshot(merged, ts_now)
                        error_count = len(node_state.get("errors") or [])
                        elapsed_ms = (_time.perf_counter() - node_start) * 1000.0
                        event = {
                            "type": "node_complete",
                            "node": node_name,
                            "display_name": NODE_DISPLAY_NAMES.get(node_name, node_name),
                            "percent": record.percent,
                            "error_count": error_count,
                            "ts": ts_now,
                            "node_index": node_index,
                            "elapsed_ms": round(elapsed_ms, 1),
                        }
                        _put(event)
                        # 推送节点内详情事件（审计数据、采集统计、LLM 置信度等）
                        for detail_evt in _extract_node_details(node_name, node_state, ts_now):
                            _put(detail_evt)
                        # 推送 verbose 状态（NODE_FOCUS 关键字段的完整 JSON）
                        _push_verbose_state_events(node_name, node_state, ts_now, _put)
            except Exception as exc:
                error_event = {
                    "type": "error",
                    "node": record.current_node or "unknown",
                    "message": str(exc),
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
                _put(error_event)
                raise
            finally:
                # None 作为流结束哨兵
                _put(None)

        await loop.run_in_executor(_executor, _sync_stream)

    try:
        await _stream_events()
        # 读取最终状态
        final_state = runtime.get_state(record.run_id)
        store.update_from_state(record.run_id, final_state)
        if record.status not in ("succeeded", "partial_success", "failed"):
            record.status = "succeeded"
        record.completed_at = datetime.now(timezone.utc).isoformat()
        record.percent = 100
    except asyncio.CancelledError:
        record.status = "failed"
        record.completed_at = datetime.now(timezone.utc).isoformat()
        record.errors.append({
            "node_name": record.current_node or "unknown",
            "error_type": "CancelledError",
            "message": "Run was cancelled",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        record.status = "failed"
        record.completed_at = datetime.now(timezone.utc).isoformat()
        record.errors.append({
            "node_name": record.current_node or "unknown",
            "error_type": type(exc).__name__,
            "message": str(exc),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        })


# ── 端点实现 ──────────────────────────────────────────────────────


@router.get("/status")
async def get_wp11_status(request: Request) -> dict[str, Any]:
    """返回 WP1-1 运行状态快照（WpStatusResponse 格式）。"""
    _, store = _get_deps(request)
    active = store.get_active()
    latest = store.get_latest()
    record = active or latest
    now_ts = datetime.now(timezone.utc).isoformat()

    if record is None:
        return {
            "wp_id": "wp11",
            "status": "idle",
            "uptime_seconds": 0,
            "version": "v0.1.0",
            "metrics": {"attack_pool_size": 0, "coverage_rate": 0.0, "new_intel_24h": 0},
            "current_tasks": [],
            "last_updated": now_ts,
        }

    state = record.state_snapshot or {}

    # 状态映射
    if record.status in ("queued", "running"):
        wp_status = "running"
    elif record.status == "failed":
        wp_status = "error"
    elif record.errors:
        wp_status = "warning"
    else:
        wp_status = "idle"

    # uptime 计算
    uptime = 0
    if record.started_at:
        try:
            started_dt = datetime.fromisoformat(record.started_at)
            uptime = max(0, int((datetime.now(timezone.utc) - started_dt).total_seconds()))
        except (ValueError, TypeError):
            pass

    # 当前任务描述
    current_tasks: list[str] = []
    if record.current_node:
        display = NODE_DISPLAY_NAMES.get(record.current_node, record.current_node)
        current_tasks = [f"{display}: 执行中"]

    return {
        "wp_id": "wp11",
        "status": wp_status,
        "uptime_seconds": uptime,
        "version": "v0.1.0",
        "metrics": {
            "attack_pool_size": state.get("processed_count", 0),
            "coverage_rate": _derive_coverage_rate(state),
            "new_intel_24h": state.get("new_attack_count", 0),
        },
        "current_tasks": current_tasks,
        "last_updated": now_ts,
    }


@router.get("/metrics")
async def get_wp11_metrics(
    request: Request,
    keys: str = "",
    window: str = "48h",
) -> list[dict[str, Any]]:
    """返回时序指标数据（WpMetricSeries[] 格式）。
    keys: 逗号分隔的指标键（attack_pool_size, coverage_rate, new_intel_24h）
    window: 时间窗口（暂未过滤，返回全部历史）
    """
    key_list = [k.strip() for k in keys.split(",") if k.strip()]
    if not key_list:
        return []

    if not _metrics_history:
        # 无历史数据：返回来自当前状态快照的单点数据（如果有）
        _, store = _get_deps(request)
        record = store.get_active() or store.get_latest()
        if record and record.state_snapshot:
            state = record.state_snapshot
            ts = datetime.now(timezone.utc).isoformat()
            snap = {
                "attack_pool_size": float(state.get("processed_count", 0)),
                "coverage_rate": _derive_coverage_rate(state),
                "new_intel_24h": float(state.get("new_attack_count", 0)),
            }
            return [
                {"key": k, "points": [{"timestamp": ts, "value": snap.get(k, 0.0)}]}
                for k in key_list
            ]
        return [{"key": k, "points": []} for k in key_list]

    result = []
    for key in key_list:
        points = [
            {"timestamp": snap["ts"], "value": snap.get(key, 0.0)}
            for snap in _metrics_history
            if key in snap
        ]
        result.append({"key": key, "points": points})
    return result


@router.get("/alerts")
async def get_wp11_alerts(
    request: Request,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """从最新运行的 alert_candidates 中返回 WpAlert[] 格式告警列表。"""
    _, store = _get_deps(request)
    rec = store.get_active() or store.get_latest()
    if not rec or not rec.state_snapshot:
        return []

    alert_candidates: list[Any] = rec.state_snapshot.get("alert_candidates") or []
    run_prefix = rec.run_id[:8]
    result: list[dict[str, Any]] = []

    for i, a in enumerate(alert_candidates[:limit]):
        sev = (a.get("severity") or "LOW").upper()
        if sev not in ("HIGH", "MEDIUM", "LOW"):
            sev = "LOW"
        cvss_raw = a.get("cvss") or a.get("score")
        cvss_val: float | None = float(cvss_raw) if isinstance(cvss_raw, (int, float)) else None
        created_at: str = (
            a.get("created_at")
            or a.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )
        result.append({
            "id": a.get("id") or f"alert-{i + 1:03d}-{run_prefix}",
            "severity": sev,
            "title": str(a.get("title") or a.get("summary") or "告警"),
            "cvss": cvss_val,
            "created_at": created_at,
        })

    return result


@router.get("/state/latest")
async def get_latest_state(request: Request) -> dict[str, Any]:
    runtime, store = _get_deps(request)
    latest = store.get_latest()
    if latest is None or not latest.state_snapshot:
        # 返回零值快照
        return _state_to_snapshot({})
    return _state_to_snapshot(latest.state_snapshot, latest.run_id)


@router.get("/runs/{run_id}/state")
async def get_run_state(run_id: str, request: Request) -> dict[str, Any]:
    runtime, store = _get_deps(request)
    record = store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    if record.state_snapshot:
        return _state_to_snapshot(record.state_snapshot, run_id)
    # 尝试从 checkpointer 读取
    try:
        loop = asyncio.get_event_loop()
        state = await loop.run_in_executor(_executor, runtime.get_state, run_id)
        return _state_to_snapshot(state, run_id)
    except Exception:
        return _state_to_snapshot({}, run_id)


@router.get("/runtime/parameters")
async def get_runtime_parameters(request: Request) -> dict[str, Any]:
    _, store = _get_deps(request)
    active = store.get_active() or store.get_latest()
    runtime_context = (
        (active.state_snapshot or {}).get("runtime_context") if active else None
    )
    return build_runtime_parameter_catalog(runtime_context)


@router.get("/nodes")
async def list_nodes(request: Request) -> list[dict[str, Any]]:
    _, store = _get_deps(request)
    return [
        {
            "node_name": name,
            "display_name": NODE_DISPLAY_NAMES.get(name, name),
            "last_run_at": store.node_last_run_at.get(name),
            "last_status": store.node_last_status.get(name, "never_run"),
            "is_triggerable": name not in NON_TRIGGERABLE_NODES,
        }
        for name in NODE_ORDER
    ]


@router.post("/nodes/{node_name}/run", status_code=202)
async def trigger_node(node_name: str, request: Request) -> dict[str, Any]:
    if node_name in NON_TRIGGERABLE_NODES:
        raise HTTPException(status_code=400, detail=f"Node {node_name} is not triggerable")
    if node_name not in NODE_ORDER:
        raise HTTPException(status_code=404, detail=f"Unknown node: {node_name}")

    runtime, store = _get_deps(request)

    # 检查是否有 active run（复用 run_id 进行 recover）
    active = store.get_active()
    if active:
        raise HTTPException(
            status_code=409, detail="A run is already active; cancel it first"
        )

    ctx = RuntimeContextDTO.default_live(run_mode="bootstrap")
    # 将 resume_from_node 写入 runtime_context，确保 load_runtime_context_node
    # 读取后能正确覆盖 resume_target_node，路由到指定节点
    runtime_ctx = {**ctx.model_dump(mode="python"), "resume_from_node": node_name}
    initial_state = build_initial_state(
        run_mode="bootstrap",
        runtime_context=runtime_ctx,
        resume_target_node=node_name,
    )
    run_id = initial_state["run_id"]
    record = store.create(run_id, "bootstrap")
    task = asyncio.create_task(
        _run_graph_in_background(runtime, store, record, initial_state)
    )
    record.task = task
    store.mark_node_done(node_name, "running")

    return {"run_id": run_id, "node_name": node_name, "status": "queued"}


@router.post("/runs", status_code=201)
async def start_run(body: WpRunRequest, request: Request) -> dict[str, Any]:
    runtime, store = _get_deps(request)

    # 拒绝并发 run
    active = store.get_active()
    if active:
        raise HTTPException(
            status_code=409, detail="A run is already active; cancel it first"
        )

    ctx = RuntimeContextDTO.default_live(run_mode=body.run_mode)
    try:
        runtime_ctx = ctx.model_dump(mode="python")
        if body.runtime_context_overrides:
            runtime_ctx.update(body.runtime_context_overrides)
        if body.tuning_overrides:
            runtime_ctx = apply_tuning_overrides(runtime_ctx, body.tuning_overrides)
        runtime_ctx = RuntimeContextDTO.model_validate(runtime_ctx).model_dump(
            mode="python"
        )
    except ValidationError as exc:
        _raise_422("Invalid runtime_context_overrides or tuning_overrides.", exc)

    initial_state = build_initial_state(
        run_mode=body.run_mode,
        runtime_context=runtime_ctx,
    )
    run_id = initial_state["run_id"]
    record = store.create(run_id, body.run_mode)

    task = asyncio.create_task(
        _run_graph_in_background(runtime, store, record, initial_state)
    )
    record.task = task

    return _record_to_run_status(record)


@router.post("/runs/{run_id}/resume", status_code=202)
async def resume_run(
    run_id: str,
    body: WpResumeRequest,
    request: Request,
) -> dict[str, Any]:
    runtime, store = _get_deps(request)

    active = store.get_active()
    if active:
        raise HTTPException(
            status_code=409, detail="A run is already active; cancel it first"
        )

    source_record = store.get(run_id)
    if source_record is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    loop = asyncio.get_running_loop()
    try:
        saved_state = source_record.state_snapshot or await loop.run_in_executor(
            _executor,
            runtime.get_state,
            run_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Run {run_id} has no recoverable state.",
        ) from exc
    saved_runtime_context = dict(saved_state.get("runtime_context") or {})
    runtime_override = dict(body.runtime_context_overrides or {})
    try:
        if body.tuning_overrides:
            runtime_override = apply_tuning_overrides(
                {
                    **saved_runtime_context,
                    **runtime_override,
                },
                body.tuning_overrides,
            )
        elif runtime_override:
            runtime_override = RuntimeContextDTO.model_validate(
                {
                    **saved_runtime_context,
                    **runtime_override,
                }
            ).model_dump(mode="python")
    except ValidationError as exc:
        _raise_422("Invalid runtime_context_overrides or tuning_overrides.", exc)
    resume_hint = saved_state.get("resume_hint") or {}
    resume_from_node = (
        body.resume_from_node
        or resume_hint.get("resume_from_node")
        or saved_state.get("resume_target_node")
        or "store_raw_records"
    )

    initial_state = await loop.run_in_executor(
        _executor,
        lambda: runtime.prepare_recovered_state(
            run_id,
            reuse_run_id=body.reuse_run_id,
            runtime_context_override=runtime_override or None,
            resume_from_node=resume_from_node,
        ),
    )
    new_run_id = initial_state["run_id"]
    record = store.create(new_run_id, initial_state.get("run_mode", "bootstrap"))
    task = asyncio.create_task(
        _run_graph_in_background(runtime, store, record, initial_state)
    )
    record.task = task
    return _record_to_run_status(record)


@router.get("/runs/active")
async def get_active_run(request: Request) -> dict[str, Any]:
    _, store = _get_deps(request)
    record = store.get_active()
    if record is None:
        raise HTTPException(status_code=404, detail="No active run")
    return _record_to_run_status(record)


@router.delete("/runs/{run_id}", status_code=204)
async def cancel_run(run_id: str, request: Request) -> None:
    _, store = _get_deps(request)
    record = store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    if record.task and not record.task.done():
        record.task.cancel()
    record.status = "failed"
    record.completed_at = datetime.now(timezone.utc).isoformat()


@router.get("/logs/stream")
async def stream_logs(
    request: Request,
    last_event_index: int = 0,
) -> StreamingResponse:
    """SSE 日志流。消费最新活跃 run 的 log_queue，支持断线重连回放。"""
    _, store = _get_deps(request)

    async def event_generator():
        # 等待活跃 run（最多 5 秒）
        record: RunRecord | None = None
        for _ in range(50):
            record = store.get_active() or store.get_latest()
            if record:
                break
            await asyncio.sleep(0.1)

        if record is None:
            yield "data: {\"type\": \"idle\"}\n\n"
            return

        # 推送初始状态
        init_event = {
            "type": "init",
            "run_id": record.run_id,
            "run_mode": record.run_mode,
            "status": record.status,
        }
        yield f"data: {json.dumps(init_event, ensure_ascii=False)}\n\n"

        # ── 回放 log_history 中客户端尚未收到的事件 ──
        event_index = 0
        for hist_event in record.log_history:
            event_index += 1
            if event_index <= last_event_index:
                continue
            yield f"id: {event_index}\ndata: {json.dumps(hist_event, ensure_ascii=False)}\n\n"

        # 若 run 已结束且无需实时消费，直接发 done
        if record.status in ("succeeded", "failed", "partial_success"):
            done_event = {
                "type": "done",
                "run_id": record.run_id,
                "status": record.status,
                "percent": record.percent,
            }
            yield f"data: {json.dumps(done_event, ensure_ascii=False)}\n\n"
            return

        # 持续消费 log_queue 直到 None 哨兵
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(record.log_queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield "data: {\"type\": \"heartbeat\"}\n\n"
                continue

            if event is None:
                # 流结束
                done_event = {
                    "type": "done",
                    "run_id": record.run_id,
                    "status": record.status,
                    "percent": record.percent,
                }
                yield f"data: {json.dumps(done_event, ensure_ascii=False)}\n\n"
                break

            event_index += 1
            yield f"id: {event_index}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
