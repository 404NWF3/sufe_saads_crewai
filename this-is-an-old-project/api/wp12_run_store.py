from __future__ import annotations

import asyncio
import collections
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

WP12_STAGE_ORDER: list[str] = [
    "ingest_intel",
    "normalize_intel",
    "understand_threat_subgraph",
    "generate_test_package_subgraph",
    "validate_test_package",
    "finalize_plan_result",
    "persist_plan_artifacts",
]

WP12_STAGE_DISPLAY_NAMES: dict[str, str] = {
    "ingest_intel": "Load Feed Item",
    "normalize_intel": "Normalize Intel",
    "understand_threat_subgraph": "Understand Threat",
    "generate_test_package_subgraph": "Generate Test Package",
    "validate_test_package": "Validate Package",
    "finalize_plan_result": "Finalize Result",
    "persist_plan_artifacts": "Persist Artifacts",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _calc_percent(completed_stages: list[str], *, terminal: bool = False) -> int:
    if terminal:
        return 100
    total = len(WP12_STAGE_ORDER)
    if total == 0:
        return 0
    return min(int(len(completed_stages) / total * 100), 99)


@dataclass
class Wp12RunRecord:
    run_id: str
    attack_id: str
    status: str
    started_at: str
    completed_at: str | None = None
    current_stage: str | None = None
    current_task: str | None = None
    completed_stages: list[str] = field(default_factory=list)
    percent: int = 0
    error: str | None = None
    cancel_requested: bool = False
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    result_snapshot: dict[str, Any] | None = None
    task: asyncio.Task | None = field(default=None, repr=False)  # type: ignore[type-arg]
    event_index: int = 0
    updated: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    log_queue: asyncio.Queue[dict[str, Any] | None] = field(
        default_factory=asyncio.Queue,
        repr=False,
    )
    log_history: collections.deque[dict[str, Any]] = field(
        default_factory=lambda: collections.deque(maxlen=200),
        repr=False,
    )


class Wp12RunStore:
    def __init__(self) -> None:
        self._runs: dict[str, Wp12RunRecord] = {}
        self._active_run_id: str | None = None
        self._latest_run_id: str | None = None
        self._latest_result_run_id: str | None = None

    def create(self, run_id: str, attack_id: str) -> Wp12RunRecord:
        record = Wp12RunRecord(
            run_id=run_id,
            attack_id=attack_id,
            status="queued",
            started_at=_now_iso(),
        )
        self._runs[run_id] = record
        self._active_run_id = run_id
        self._latest_run_id = run_id
        return record

    def get(self, run_id: str) -> Wp12RunRecord | None:
        return self._runs.get(run_id)

    def get_active(self) -> Wp12RunRecord | None:
        if not self._active_run_id:
            return None
        record = self._runs.get(self._active_run_id)
        if record and record.status in {"queued", "running", "cancelling"}:
            return record
        return None

    def get_latest(self) -> Wp12RunRecord | None:
        if not self._latest_run_id:
            return None
        return self._runs.get(self._latest_run_id)

    def get_latest_result(self) -> Wp12RunRecord | None:
        if not self._latest_result_run_id:
            return None
        return self._runs.get(self._latest_result_run_id)

    def mark_stage_start(self, run_id: str, stage_name: str) -> None:
        record = self._runs.get(run_id)
        if not record:
            return
        record.status = "running"
        record.current_stage = stage_name
        record.current_task = WP12_STAGE_DISPLAY_NAMES.get(stage_name, stage_name)
        record.updated.set()

    def mark_stage_complete(
        self,
        run_id: str,
        stage_name: str,
        state_snapshot: dict[str, Any],
    ) -> None:
        record = self._runs.get(run_id)
        if not record:
            return
        if stage_name not in record.completed_stages:
            record.completed_stages.append(stage_name)
        record.state_snapshot = state_snapshot
        record.percent = _calc_percent(record.completed_stages)
        record.updated.set()

    def mark_cancel_requested(self, run_id: str) -> None:
        record = self._runs.get(run_id)
        if not record or record.status in {"succeeded", "failed", "cancelled"}:
            return
        record.cancel_requested = True
        record.status = "cancelling"
        record.current_task = "Cancel requested"
        record.updated.set()

    def set_result_snapshot(self, run_id: str, result_snapshot: dict[str, Any]) -> None:
        record = self._runs.get(run_id)
        if not record:
            return
        record.result_snapshot = result_snapshot
        self._latest_result_run_id = run_id
        record.updated.set()

    def append_event(self, run_id: str, payload: dict[str, Any]) -> None:
        record = self._runs.get(run_id)
        if not record:
            return
        record.event_index += 1
        enriched = dict(payload)
        enriched.setdefault("event_index", record.event_index)
        record.log_history.append(enriched)
        record.updated.set()

    def mark_terminal(
        self,
        run_id: str,
        status: str,
        *,
        error: str | None = None,
        state_snapshot: dict[str, Any] | None = None,
    ) -> None:
        record = self._runs.get(run_id)
        if not record:
            return
        record.status = status
        record.error = error
        record.completed_at = _now_iso()
        if state_snapshot is not None:
            record.state_snapshot = state_snapshot
        if status in {"succeeded", "failed", "cancelled"}:
            record.percent = _calc_percent(record.completed_stages, terminal=True)
        record.current_stage = None
        record.current_task = None
        if self._active_run_id == run_id:
            self._active_run_id = None
        record.updated.set()
