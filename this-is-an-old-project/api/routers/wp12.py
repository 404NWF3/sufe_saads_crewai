from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.agents.saads_wp12.data.feed_provider import get_attack_feed_provider
from backend.agents.saads_wp12.data.models import Wp12AttackFeedItem
from backend.agents.saads_wp12.graphs.subgraphs.test_package_generation import (
    generate_test_package_subgraph,
)
from backend.agents.saads_wp12.graphs.subgraphs.threat_understanding import (
    understand_threat_subgraph,
)
from backend.agents.saads_wp12.nodes.intel import ingest_intel, normalize_intel
from backend.agents.saads_wp12.nodes.persistence import (
    finalize_plan_result,
    persist_plan_artifacts,
)
from backend.agents.saads_wp12.nodes.validation import validate_test_package
from backend.agents.saads_wp12.reporting.llm_plan_writer import generate_plan_markdown
from backend.agents.saads_wp12.reporting.state_export import build_presentation_export_state
from backend.agents.saads_wp12.state import SecurityEvalState
from backend.api.wp12_run_store import (
    WP12_STAGE_DISPLAY_NAMES,
    WP12_STAGE_ORDER,
    Wp12RunRecord,
    Wp12RunStore,
)

router = APIRouter(prefix="/api/wp12", tags=["wp12"])

_RUN_LOCK = asyncio.Lock()
_TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}

_STAGE_HANDLERS: list[tuple[str, Callable[[SecurityEvalState], dict[str, Any]]]] = [
    ("ingest_intel", ingest_intel),
    ("normalize_intel", normalize_intel),
    ("understand_threat_subgraph", understand_threat_subgraph),
    ("generate_test_package_subgraph", generate_test_package_subgraph),
    ("validate_test_package", validate_test_package),
    ("finalize_plan_result", finalize_plan_result),
    ("persist_plan_artifacts", persist_plan_artifacts),
]


class Wp12RunRequest(BaseModel):
    attack_id: str = Field(min_length=1)
    tenant_id: str = "dashboard"
    scenario_id: str = "dashboard-manual"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_offset(value: str | None) -> str:
    if not value:
        return ""
    if value.endswith("Z") or "+" in value:
        return value
    return f"{value}+00:00"


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(_ensure_offset(value))
    except ValueError:
        return None


def _read_text(path_value: str | None) -> str | None:
    if not path_value:
        return None
    path = Path(path_value)
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _read_json(path_value: str | None) -> dict[str, Any] | None:
    raw = _read_text(path_value)
    if not raw:
        return None
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _runtime_status_to_wp_status(record: Wp12RunRecord | None) -> str:
    if record is None:
        return "idle"
    if record.status in {"queued", "running", "cancelling"}:
        return "running"
    if record.status == "failed":
        return "error"
    if record.status == "cancelled":
        return "warning"
    return "idle"


def _uptime_seconds(record: Wp12RunRecord | None) -> int:
    if record is None:
        return 0
    started_at = _parse_iso(record.started_at)
    if started_at is None:
        return 0
    return max(0, int((datetime.now(timezone.utc) - started_at).total_seconds()))


def _build_wp12_status_payload(store: Wp12RunStore) -> dict[str, Any]:
    active = store.get_active()
    latest = store.get_latest()
    source = active or latest
    current_tasks = [active.current_task] if active and active.current_task else []
    return {
        "wp_id": "wp12",
        "status": _runtime_status_to_wp_status(source),
        "uptime_seconds": _uptime_seconds(active),
        "version": "v1.0.0",
        "metrics": {
            "script_count": 0,
            "owasp_coverage": 0,
            "scripts_24h": 0,
        },
        "current_tasks": current_tasks,
        "last_updated": _now_iso(),
    }


def _run_status_payload(record: Wp12RunRecord) -> dict[str, Any]:
    return {
        "run_id": record.run_id,
        "attack_id": record.attack_id,
        "status": record.status,
        "current_stage": record.current_stage,
        "current_task": record.current_task,
        "completed_stages": list(record.completed_stages),
        "total_stages": len(WP12_STAGE_ORDER),
        "percent": record.percent,
        "started_at": record.started_at,
        "completed_at": record.completed_at,
        "error": record.error,
    }


def _build_result_snapshot(
    run_id: str,
    state: dict[str, Any],
    *,
    status: str,
) -> dict[str, Any]:
    plan_markdown = _read_text(state.get("plan_path")) or generate_plan_markdown(state)
    presentation_state = _read_json(state.get("presentation_state_path")) or (
        build_presentation_export_state(state)
    )
    threat_understanding = presentation_state.get("threat_understanding") or state.get(
        "threat_understanding",
        {},
    )
    execution_assessment = presentation_state.get("execution_assessment") or state.get(
        "execution_assessment",
        {},
    )
    package_validation = presentation_state.get("package_validation") or state.get(
        "package_validation",
        {},
    )
    test_package = presentation_state.get("test_package") or state.get("test_package", {})
    intel_normalized = state.get("intel_normalized", {})

    return {
        "run_id": run_id,
        "attack_id": state.get("attack_id", ""),
        "status": status,
        "verdict": state.get("verdict"),
        "package_kind": test_package.get("package_kind"),
        "generation_mode": test_package.get("generation_mode"),
        "summary": {
            "attack_id": state.get("attack_id", ""),
            "attack_code": intel_normalized.get("attack_code", ""),
            "canonical_name": intel_normalized.get("canonical_name", ""),
            "attack_family": state.get("attack_family", ""),
            "target_surface": state.get("target_surface", ""),
            "verdict": state.get("verdict"),
        },
        "plan_markdown": plan_markdown,
        "presentation_state": presentation_state,
        "threat_understanding": threat_understanding,
        "execution_assessment": execution_assessment,
        "package_validation": package_validation,
        "test_package": test_package,
        "artifacts": {
            "persistence_path": state.get("persistence_path"),
            "raw_state_path": state.get("raw_state_path"),
            "presentation_state_path": state.get("presentation_state_path"),
            "plan_path": state.get("plan_path"),
        },
    }


def _append_event(store: Wp12RunStore, run_id: str, payload: dict[str, Any]) -> None:
    store.append_event(run_id, payload)


def _map_feed_summary(item: Wp12AttackFeedItem) -> dict[str, Any]:
    return {
        "attack_id": item.attack_id,
        "attack_code": item.attack_code,
        "canonical_name": item.canonical_name,
        "attack_family": item.attack_family,
        "summary": item.summary,
        "severity_level": item.severity_level,
        "last_seen_at": _ensure_offset(item.last_seen_at),
        "primary_cvss_base_score": item.primary_cvss_base_score,
        "primary_cvss_severity_label": item.primary_cvss_severity_label,
        "taxonomy_code": item.taxonomy_code,
        "taxonomy_name": item.taxonomy_name,
        "component_name": item.component_name,
        "asset_name": item.asset_name,
        "active": item.active,
    }


def _map_feed_detail(item: Wp12AttackFeedItem) -> dict[str, Any]:
    payload = item.to_dict()
    payload["last_seen_at"] = _ensure_offset(item.last_seen_at)
    return payload


def _filter_feed_items(items: list[Wp12AttackFeedItem], query: str) -> list[Wp12AttackFeedItem]:
    if not query:
        return items
    lowered = query.lower().strip()
    return [
        item
        for item in items
        if lowered in item.attack_code.lower()
        or lowered in item.canonical_name.lower()
        or lowered in item.summary.lower()
    ]


def _sort_feed_items(items: list[Wp12AttackFeedItem]) -> list[Wp12AttackFeedItem]:
    return sorted(
        items,
        key=lambda item: (
            float(item.primary_cvss_base_score or 0.0),
            _ensure_offset(item.last_seen_at),
        ),
        reverse=True,
    )


async def _fetch_feed_snapshots() -> list[Wp12AttackFeedItem]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: get_attack_feed_provider().list_attack_feed_snapshots(),
    )


async def _fetch_feed_detail(attack_id: str) -> Wp12AttackFeedItem:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: get_attack_feed_provider().get_attack_feed_item(attack_id),
    )


async def _run_stage(
    handler: Callable[[SecurityEvalState], dict[str, Any]],
    state: dict[str, Any],
) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: handler(dict(state)))


def _assert_run_store(request: Request) -> Wp12RunStore:
    store = getattr(request.app.state, "wp12_run_store", None)
    if not isinstance(store, Wp12RunStore):
        raise HTTPException(status_code=500, detail="wp12 run store is not initialized")
    return store


async def _run_wp12_pipeline(
    store: Wp12RunStore,
    record: Wp12RunRecord,
    request_body: Wp12RunRequest,
) -> None:
    state: dict[str, Any] = {
        "run_id": record.run_id,
        "attack_id": request_body.attack_id,
        "tenant_id": request_body.tenant_id,
        "scenario_id": request_body.scenario_id,
        "reflection_round": 0,
        "max_reflection_rounds": 1,
    }
    active_stage_name = "wp12"
    _append_event(
        store,
        record.run_id,
        {
            "type": "init",
            "run_id": record.run_id,
            "run_mode": request_body.scenario_id,
            "ts": record.started_at,
        },
    )

    try:
        for index, (stage_name, handler) in enumerate(_STAGE_HANDLERS, start=1):
            active_stage_name = stage_name
            current = store.get(record.run_id)
            if current is None:
                return
            if current.cancel_requested:
                store.mark_terminal(record.run_id, "cancelled", state_snapshot=state)
                _append_event(
                    store,
                    record.run_id,
                    {
                        "type": "done",
                        "status": "cancelled",
                        "percent": 100,
                    },
                )
                return

            store.mark_stage_start(record.run_id, stage_name)
            started_at = time.perf_counter()
            display_name = WP12_STAGE_DISPLAY_NAMES.get(stage_name, stage_name)
            _append_event(
                store,
                record.run_id,
                {
                    "type": "node_detail",
                    "node": stage_name,
                    "display_name": display_name,
                    "message": f"Started {display_name}.",
                    "ts": _now_iso(),
                },
            )

            stage_result = await _run_stage(handler, state)
            if not isinstance(stage_result, dict):
                raise TypeError(f"{stage_name} returned a non-dict result")
            state.update(stage_result)
            store.mark_stage_complete(record.run_id, stage_name, state)

            current = store.get(record.run_id)
            elapsed_ms = round((time.perf_counter() - started_at) * 1000, 1)
            percent = current.percent if current is not None else 0
            _append_event(
                store,
                record.run_id,
                {
                    "type": "node_complete",
                    "node": stage_name,
                    "display_name": display_name,
                    "node_index": index,
                    "percent": percent,
                    "elapsed_ms": elapsed_ms,
                    "error_count": 0,
                    "ts": _now_iso(),
                },
            )
            _append_event(
                store,
                record.run_id,
                {
                    "type": "node_detail",
                    "node": stage_name,
                    "display_name": display_name,
                    "message": f"Completed {display_name}.",
                    "ts": _now_iso(),
                },
            )

            current = store.get(record.run_id)
            if current is not None and current.cancel_requested:
                store.mark_terminal(record.run_id, "cancelled", state_snapshot=state)
                _append_event(
                    store,
                    record.run_id,
                    {
                        "type": "done",
                        "status": "cancelled",
                        "percent": 100,
                    },
                )
                return

        result_snapshot = _build_result_snapshot(record.run_id, state, status="succeeded")
        store.set_result_snapshot(record.run_id, result_snapshot)
        store.mark_terminal(record.run_id, "succeeded", state_snapshot=state)
        _append_event(
            store,
            record.run_id,
            {
                "type": "done",
                "status": "succeeded",
                "percent": 100,
            },
        )
    except asyncio.CancelledError:
        store.mark_terminal(record.run_id, "cancelled", state_snapshot=state)
        _append_event(
            store,
            record.run_id,
            {
                "type": "done",
                "status": "cancelled",
                "percent": 100,
            },
        )
        raise
    except Exception as exc:
        store.mark_terminal(
            record.run_id,
            "failed",
            error=str(exc),
            state_snapshot=state,
        )
        _append_event(
            store,
                record.run_id,
                {
                    "type": "error",
                    "node": active_stage_name,
                    "message": str(exc),
                    "ts": _now_iso(),
                },
        )
        _append_event(
            store,
            record.run_id,
            {
                "type": "done",
                "status": "failed",
                "percent": 100,
            },
        )


def _sse_frame(index: int, payload: dict[str, Any]) -> str:
    return f"id: {index}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.get("/status")
async def get_status(request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    return _build_wp12_status_payload(store)


@router.get("/feed")
async def list_feed(
    limit: int = Query(default=50, ge=1, le=200),
    q: str = "",
) -> list[dict[str, Any]]:
    items = _sort_feed_items(_filter_feed_items(await _fetch_feed_snapshots(), q))
    return [_map_feed_summary(item) for item in items[:limit]]


@router.get("/feed/{attack_id}")
async def get_feed_item(attack_id: str) -> dict[str, Any]:
    try:
        item = await _fetch_feed_detail(attack_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _map_feed_detail(item)


@router.post("/runs", status_code=201)
async def start_run(body: Wp12RunRequest, request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    async with _RUN_LOCK:
        active = store.get_active()
        if active is not None:
            raise HTTPException(status_code=409, detail="a wp12 run is already active")
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        record = store.create(run_id, body.attack_id)
        record.task = asyncio.create_task(_run_wp12_pipeline(store, record, body))
    return _run_status_payload(record)


@router.get("/runs/active")
async def get_active_run(request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    record = store.get_active()
    if record is None:
        raise HTTPException(status_code=404, detail="no active run")
    return _run_status_payload(record)


@router.get("/runs/{run_id}")
async def get_run(run_id: str, request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    record = store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    return _run_status_payload(record)


@router.get("/runs/latest/result")
async def get_latest_result(request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    record = store.get_latest_result()
    if record is None or record.result_snapshot is None:
        raise HTTPException(status_code=404, detail="no latest result")
    return record.result_snapshot


@router.get("/runs/{run_id}/result")
async def get_run_result(run_id: str, request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    record = store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    if record.result_snapshot is None:
        raise HTTPException(status_code=404, detail=f"result not ready for run: {run_id}")
    return record.result_snapshot


@router.delete("/runs/{run_id}")
async def cancel_run(run_id: str, request: Request) -> dict[str, Any]:
    store = _assert_run_store(request)
    record = store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    if record.status in _TERMINAL_STATUSES:
        return _run_status_payload(record)

    store.mark_cancel_requested(run_id)
    _append_event(
        store,
        run_id,
        {
            "type": "node_detail",
            "node": "wp12",
            "display_name": "WP1-2",
            "message": "Cancel requested. The active stage will stop after its current step finishes.",
            "ts": _now_iso(),
        },
    )
    return _run_status_payload(record)


@router.get("/logs/stream")
async def stream_logs(
    request: Request,
    last_event_index: int = Query(default=0, ge=0),
) -> StreamingResponse:
    store = _assert_run_store(request)

    async def event_generator():
        cursor = last_event_index
        source_run_id: str | None = None
        heartbeat_at = asyncio.get_running_loop().time()

        while True:
            source = store.get_active() or store.get_latest()
            if source is not None:
                if source_run_id != source.run_id:
                    source_run_id = source.run_id
                    if cursor > source.event_index:
                        cursor = 0

                pending = [
                    payload
                    for payload in source.log_history
                    if int(payload.get("event_index", 0) or 0) > cursor
                ]
                if pending:
                    for payload in pending:
                        cursor = int(payload.get("event_index", cursor + 1) or cursor + 1)
                        yield _sse_frame(cursor, payload)
                    source.updated.clear()
                    heartbeat_at = asyncio.get_running_loop().time()
                    continue

                source.updated.clear()
                try:
                    await asyncio.wait_for(source.updated.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
            else:
                await asyncio.sleep(1.0)

            if asyncio.get_running_loop().time() - heartbeat_at >= 30:
                yield _sse_frame(cursor + 1, {"type": "heartbeat"})
                heartbeat_at = asyncio.get_running_loop().time()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
