from __future__ import annotations

from typing import Any

from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork


class QueryFeedbackMemoryService:
    """Query feedback persistence: DB-backed with in-memory fallback.

    Writes new feedback rows to wp11.query_feedback_log so that adaptive
    query adjustment accumulates across runs. Falls back silently to
    in-memory-only behaviour when the DB is unavailable.
    """

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load_recent_feedback(
        self,
        rows: list[dict[str, Any]] | None,
        *,
        limit: int = 20,
        run_id: str | None = None,
        trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the most recent *limit* feedback rows.

        Tries DB first (cross-run history); falls back to the in-memory
        *rows* passed by the caller if the DB is unavailable.
        """
        try:
            with UnitOfWork(
                context=SqlContext(
                    trace_id=trace_id, agent_name="query_feedback_load"
                ),
                read_only=True,
            ) as uow:
                db_rows = uow.governance.load_recent_query_feedback(limit=limit)
                if db_rows:
                    return [_model_to_dict(r) for r in db_rows]
        except Exception:
            pass

        # Fallback: use whatever was already in runtime-context memory
        in_mem = list(rows or [])
        return in_mem[-limit:]

    # ------------------------------------------------------------------
    # Append / persist
    # ------------------------------------------------------------------

    def append_feedback(
        self,
        existing_rows: list[dict[str, Any]] | None,
        new_rows: list[dict[str, Any]],
        *,
        run_id: str | None = None,
        trace_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Persist *new_rows* to DB and return the updated in-memory list.

        The returned list is capped at *limit* entries so the runtime-context
        payload stays bounded even if the DB is unavailable.
        """
        if new_rows:
            self._persist_to_db(new_rows, run_id=run_id, trace_id=trace_id)

        merged = [*(existing_rows or []), *new_rows]
        return merged[-limit:]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _persist_to_db(
        self,
        rows: list[dict[str, Any]],
        *,
        run_id: str | None,
        trace_id: str | None,
    ) -> None:
        try:
            with UnitOfWork(
                context=SqlContext(
                    trace_id=trace_id, agent_name="query_feedback_persist"
                )
            ) as uow:
                for row in rows:
                    uow.governance.insert_query_feedback(
                        _to_db_params(row, run_id=run_id or "")
                    )
        except Exception:
            return


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_db_params(row: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    return {
        "run_id":               run_id,
        "query_run_id":         str(row.get("query_run_id") or ""),
        "source_name":          str(row.get("source_name") or ""),
        "query_text":           str(row.get("query_text") or ""),
        "query_intent":         str(row.get("query_intent") or "broad_recall"),
        "rewrite_round":        int(row.get("rewrite_round") or 0),
        "result_count":         int(row.get("result_count") or 0),
        "parsed_count":         int(row.get("parsed_count") or 0),
        "duplicate_count":      int(row.get("duplicate_count") or 0),
        "novelty_yield":        float(row.get("novelty_yield") or 0.0),
        "noise_ratio":          float(row.get("noise_ratio") or 0.0),
        "source_mismatch":      bool(row.get("source_mismatch", False)),
        "reflection_diagnosis": row.get("reflection_diagnosis"),
        "reflection_action":    row.get("reflection_action"),
        "should_retry":         bool(row.get("should_retry", False)),
        "expected_gain_dim":    row.get("expected_gain_dimension"),
        "llm_confidence":       _float_or_none(row.get("llm_confidence")),
    }


def _float_or_none(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _model_to_dict(m: Any) -> dict[str, Any]:
    return {
        "query_run_id":          m.query_run_id,
        "source_name":           m.source_name,
        "query_text":            m.query_text,
        "query_intent":          m.query_intent,
        "rewrite_round":         m.rewrite_round,
        "result_count":          m.result_count,
        "parsed_count":          m.parsed_count,
        "duplicate_count":       m.duplicate_count,
        "novelty_yield":         float(m.novelty_yield),
        "noise_ratio":           float(m.noise_ratio),
        "source_mismatch":       m.source_mismatch,
        "reflection_diagnosis":  m.reflection_diagnosis,
        "reflection_action":     m.reflection_action,
        "should_retry":          m.should_retry,
        "expected_gain_dimension": m.expected_gain_dim,
        "llm_confidence":        float(m.llm_confidence) if m.llm_confidence is not None else None,
    }
