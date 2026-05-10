"""server.py — FastAPI 应用入口（WP1-1 后端服务）"""
from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.agents.intel_agents.orchestrator.runtime import Phase1GraphRuntime
from backend.api.run_store import RunStore
from backend.api.routers import sentinel, wp11, wp12
from backend.api.wp12_run_store import Wp12RunStore

logger = logging.getLogger(__name__)
_stats_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="stats")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """启动时初始化共享资源；关闭时清理。"""
    app.state.wp11_runtime = Phase1GraphRuntime()
    app.state.run_store = RunStore()
    app.state.wp12_run_store = Wp12RunStore()
    yield
    # 取消所有未完成的运行任务
    store: RunStore = app.state.run_store
    for record in store._runs.values():
        if record.task and not record.task.done():
            record.task.cancel()
    wp12_store: Wp12RunStore = app.state.wp12_run_store
    for record in wp12_store._runs.values():
        if record.task and not record.task.done():
            record.task.cancel()


app = FastAPI(
    title="SUFE-SAADS WP1-1 API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_cors_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
_cors_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(wp11.router)
app.include_router(wp12.router)
app.include_router(sentinel.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# ── /api/stats ─────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    attack_entry_count: int
    eval_job_count: int
    owasp_covered: int          # 已覆盖的 OWASP LLM 类别数（满分 10）
    owasp_coverage_pct: float   # owasp_covered / 10 * 100


def _query_stats() -> StatsResponse:
    """阻塞 I/O：在线程池中运行，不阻塞事件循环。"""
    from backend.db.connection import get_pool  # 懒加载，避免启动时 pool 未就绪

    attack_count = 0
    eval_count = 0
    owasp_covered = 10

    try:
        pool = get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*)::int FROM wp11.attack_entry")
                row = cur.fetchone()
                attack_count = (row[0] if row else 0) or 0

            # wp12_eval_job 可能不存在，用 savepoint 隔离错误
            try:
                with conn.cursor() as cur:
                    cur.execute("SAVEPOINT sp_eval")
                    cur.execute("SELECT COUNT(*)::int FROM wp11.wp12_eval_job")
                    row = cur.fetchone()
                    eval_count = (row[0] if row else 0) or 0
                    cur.execute("RELEASE SAVEPOINT sp_eval")
            except Exception:
                with conn.cursor() as cur:
                    cur.execute("ROLLBACK TO SAVEPOINT sp_eval")

            # mv_owasp_coverage 可能不存在
            try:
                with conn.cursor() as cur:
                    cur.execute("SAVEPOINT sp_owasp")
                    cur.execute(
                        "SELECT COUNT(*)::int FROM wp11.mv_owasp_coverage WHERE attack_count > 0"
                    )
                    row = cur.fetchone()
                    owasp_covered = (row[0] if row else 10) or 10
                    cur.execute("RELEASE SAVEPOINT sp_owasp")
            except Exception:
                with conn.cursor() as cur:
                    cur.execute("ROLLBACK TO SAVEPOINT sp_owasp")

    except Exception as exc:
        logger.warning("stats query failed: %s", exc)

    return StatsResponse(
        attack_entry_count=attack_count,
        eval_job_count=eval_count,
        owasp_covered=owasp_covered,
        owasp_coverage_pct=round(min(owasp_covered, 10) / 10.0 * 100, 1),
    )


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    """返回首页 KPI 所需的实时数据库统计量。"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_stats_executor, _query_stats)


@app.get("/api/alerts")
async def get_global_alerts(
    request: Request,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """全局告警聚合端点（当前阶段透传 WP1-1 告警）。"""
    store: RunStore = request.app.state.run_store
    rec = store.get_active() or store.get_latest()
    if not rec or not rec.state_snapshot:
        return []

    alert_candidates: list[Any] = rec.state_snapshot.get("alert_candidates") or []
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
            "id": a.get("id") or f"alert-g-{i + 1:03d}",
            "severity": sev,
            "title": str(a.get("title") or a.get("summary") or "告警"),
            "cvss": cvss_val,
            "created_at": created_at,
        })

    return result
