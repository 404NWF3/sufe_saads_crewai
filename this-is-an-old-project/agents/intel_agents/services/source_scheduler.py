from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from typing import Any
from uuid import uuid4

from ..schemas.plan import SourceExecutionPlanDTO
from ..schemas.source import (
    QueryRunDTO,
    RegisteredSourceDTO,
    SourceExecutionStatDTO,
    SourceFetchBatchDTO,
)
from ..tools.source_fetch_tools import (
    SourceFetchToolbox,
    classify_fetch_error,
    compute_backoff_delay,
)


class SourceScheduler:
    """Production-hardened scheduler with retry, backoff, circuit breaker, and audits."""

    def __init__(self, toolbox: SourceFetchToolbox | None = None):
        self.toolbox = toolbox or SourceFetchToolbox()
        self._last_call_at: dict[str, float] = {}
        self._throttle_lock = threading.Lock()
        self._circuit_state: dict[str, dict[str, Any]] = {}

    def run(
        self,
        source_plans: list[dict[str, Any]],
        *,
        registry: list[RegisteredSourceDTO],
        trace_id: str,
        run_mode: str,
        reflection_round: int,
        runtime_mode: str,
        retry_attempts: int,
        request_timeout_seconds: float,
        max_parallel_sources: int,
        source_cursors: dict[str, dict[str, Any]] | None = None,
        collector_role_map: dict[str, str] | None = None,
        assignment_map: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        registry_map = {item.source_name: item for item in registry}
        batches: list[dict[str, Any]] = []
        stats: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []
        next_cursors = dict(source_cursors or {})

        work_items_by_source: dict[
            str, list[tuple[RegisteredSourceDTO, QueryRunDTO, dict[str, Any] | None]]
        ] = {}
        for raw_plan in source_plans:
            plan = SourceExecutionPlanDTO.model_validate(raw_plan)
            source = registry_map[plan.source_name]
            for query_text in plan.queries:
                work_items_by_source.setdefault(source.source_name, []).append(
                    (
                        source,
                        QueryRunDTO(
                            query_run_id=f"qrun_{uuid4().hex[:12]}",
                            source_name=plan.source_name,
                            query_text=query_text,
                            query_intent=plan.query_intent,
                            reflection_round=reflection_round,
                            max_results=plan.max_results,
                            time_window_days=plan.time_window_days,
                            trace_id=trace_id,
                            run_mode=run_mode,
                            page_cursor=(
                                next_cursors.get(source.source_name) or {}
                            ).get("cursor"),
                        ),
                        next_cursors.get(source.source_name),
                    )
                )

        with ThreadPoolExecutor(max_workers=max(1, max_parallel_sources)) as executor:
            future_map = {
                executor.submit(
                    self._execute_source_queue,
                    source_name,
                    queue,
                    runtime_mode=runtime_mode,
                    timeout=request_timeout_seconds,
                    retry_attempts=retry_attempts,
                ): source_name
                for source_name, queue in work_items_by_source.items()
            }
            for future in as_completed(future_map):
                source_name = future_map[future]
                result_batches = future.result()
                for source, query_run, batch in result_batches:
                    batches.append(batch.model_dump(mode="python"))
                    audits.append(
                        batch.request_audit
                        or {
                            "query_run_id": query_run.query_run_id,
                            "source_name": source.source_name,
                            "requested_at": batch.fetched_at,
                            "completed_at": batch.fetched_at,
                            "runtime_mode": runtime_mode,
                            "attempt_count": batch.attempt_count,
                            "success": batch.success,
                            "degraded_from_live": batch.degraded_from_live,
                            "request_meta": {},
                            "error_type": batch.error_type,
                            "error_message": batch.error_message,
                        }
                    )
                    stats.append(
                        SourceExecutionStatDTO(
                            source_name=source.source_name,
                            query_run_id=query_run.query_run_id,
                            query_text=query_run.query_text,
                            query_intent=query_run.query_intent,
                            success=batch.success,
                            item_count=len(batch.items),
                            attempt_count=batch.attempt_count,
                            latency_ms=batch.latency_ms,
                            error_type=batch.error_type,
                            error_message=batch.error_message,
                            used_stub=batch.used_stub,
                            rate_limited=(batch.error_type == "RateLimitFetchError"),
                            degraded_from_live=batch.degraded_from_live,
                            collector_role=(collector_role_map or {}).get(
                                source.source_name
                            ),
                            execution_profile=(assignment_map or {})
                            .get(source.source_name, {})
                            .get("execution_profile"),
                            source_specific_hint=(assignment_map or {})
                            .get(source.source_name, {})
                            .get("source_specific_hint"),
                        ).model_dump(mode="python")
                    )
                    next_cursors[source_name] = {
                        "cursor": batch.next_cursor,
                        "last_seen_at": batch.fetched_at,
                    }

        batches.sort(key=lambda item: item["query_run"]["source_name"])
        stats.sort(key=lambda item: item["source_name"])
        audits.sort(key=lambda item: (item["source_name"], item["query_run_id"]))
        return {
            "fetch_batches": batches,
            "source_execution_stats": stats,
            "source_cursors": next_cursors,
            "fetch_audits": audits,
        }

    def _execute_source_queue(
        self,
        source_name: str,
        queue: list[tuple[RegisteredSourceDTO, QueryRunDTO, dict[str, Any] | None]],
        *,
        runtime_mode: str,
        timeout: float,
        retry_attempts: int,
    ) -> list[tuple[RegisteredSourceDTO, QueryRunDTO, SourceFetchBatchDTO]]:
        results: list[tuple[RegisteredSourceDTO, QueryRunDTO, SourceFetchBatchDTO]] = []
        cursor_state = queue[0][2] if queue else None
        for source, query_run, _ in queue:
            query_run.page_cursor = (cursor_state or {}).get("cursor")
            batch = self._execute_with_retry(
                source,
                query_run,
                runtime_mode=runtime_mode,
                timeout=timeout,
                retry_attempts=retry_attempts,
                cursor_state=cursor_state,
            )
            results.append((source, query_run, batch))
            cursor_state = {
                "cursor": batch.next_cursor,
                "last_seen_at": batch.fetched_at,
            }
        return results

    def _execute_with_retry(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        runtime_mode: str,
        timeout: float,
        retry_attempts: int,
        cursor_state: dict[str, Any] | None,
    ) -> SourceFetchBatchDTO:
        if self._is_circuit_open(source):
            return self._failure_batch(
                source,
                query_run,
                runtime_mode=runtime_mode,
                error_type="CircuitOpen",
                error_message="Source circuit breaker is open.",
                attempt_count=1,
            )

        last_error: Exception | None = None
        for attempt in range(1, retry_attempts + 1):
            self._throttle(source)
            try:
                batch = self.toolbox.fetch(
                    source,
                    query_run,
                    runtime_mode=runtime_mode,
                    timeout=timeout,
                    cursor_state=cursor_state or {},
                )
                batch.attempt_count = attempt
                if batch.request_audit:
                    batch.request_audit["attempt_count"] = attempt
                    batch.request_audit["degraded_from_live"] = batch.degraded_from_live
                self._last_call_at[source.source_name] = time.perf_counter()
                self._reset_circuit(source)
                return batch
            except Exception as exc:
                last_error = exc
                self._record_failure(source)
                self._last_call_at[source.source_name] = time.perf_counter()
                classification = classify_fetch_error(exc)
                if classification in {"fatal", "auth"}:
                    break
                if attempt < retry_attempts:
                    time.sleep(
                        compute_backoff_delay(source.backoff_base_seconds, attempt)
                    )
        assert last_error is not None
        return self._failure_batch(
            source,
            query_run,
            runtime_mode=runtime_mode,
            error_type=last_error.__class__.__name__,
            error_message=str(last_error),
            attempt_count=retry_attempts,
        )

    def _failure_batch(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        runtime_mode: str,
        error_type: str,
        error_message: str,
        attempt_count: int,
    ) -> SourceFetchBatchDTO:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return SourceFetchBatchDTO(
            query_run=query_run,
            fetched_at=now,
            latency_ms=0.0,
            attempt_count=attempt_count,
            success=False,
            error_type=error_type,
            error_message=error_message,
            used_stub=runtime_mode != "live",
            degraded_from_live=runtime_mode == "hybrid",
            request_audit={
                "query_run_id": query_run.query_run_id,
                "source_name": source.source_name,
                "requested_at": now,
                "completed_at": now,
                "runtime_mode": runtime_mode,
                "attempt_count": attempt_count,
                "success": False,
                "degraded_from_live": runtime_mode == "hybrid",
                "request_meta": {"base_uri": source.base_uri},
                "error_type": error_type,
                "error_message": error_message,
            },
        )

    def _throttle(self, source: RegisteredSourceDTO) -> None:
        with self._throttle_lock:
            min_interval = 1.0 / max(source.default_qps, 0.01)
            last_at = self._last_call_at.get(source.source_name)
            if last_at is None:
                return
            elapsed = time.perf_counter() - last_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

    def _is_circuit_open(self, source: RegisteredSourceDTO) -> bool:
        state = self._circuit_state.get(source.source_name)
        if not state:
            return False
        opened_at = state.get("opened_at")
        if not state.get("open", False):
            return False
        if opened_at is None:
            return True
        if (time.time() - opened_at) >= source.circuit_breaker_cooldown_seconds:
            self._circuit_state[source.source_name] = {
                "failures": 0,
                "open": False,
                "opened_at": None,
            }
            return False
        return True

    def _record_failure(self, source: RegisteredSourceDTO) -> None:
        state = self._circuit_state.setdefault(
            source.source_name, {"failures": 0, "open": False, "opened_at": None}
        )
        state["failures"] += 1
        if state["failures"] >= source.circuit_breaker_threshold:
            state["open"] = True
            state["opened_at"] = time.time()

    def _reset_circuit(self, source: RegisteredSourceDTO) -> None:
        self._circuit_state[source.source_name] = {
            "failures": 0,
            "open": False,
            "opened_at": None,
        }
