from __future__ import annotations

import logging
import time
from typing import Any, Iterable

from .exceptions import map_psycopg_error
from .typing import Params, RowMapping, Rows, SqlContext

logger = logging.getLogger(__name__)


def _dict_row_factory() -> Any:
    from psycopg.rows import dict_row

    return dict_row


class DbSession:
    """Thin SQL execution wrapper with consistent logging and exception mapping."""

    def __init__(self, conn: Any, *, context: SqlContext | None = None):
        self._conn = conn
        self._context = context or SqlContext()

    def fetch_one(self, query: str, params: Params = None) -> RowMapping | None:
        start = time.perf_counter()
        try:
            with self._conn.cursor(row_factory=_dict_row_factory()) as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                return dict(row) if row is not None else None
        except Exception as exc:
            raise map_psycopg_error(exc, query=query, params=params) from exc
        finally:
            self._log_sql("fetch_one", query, start)

    def fetch_all(self, query: str, params: Params = None) -> Rows:
        start = time.perf_counter()
        try:
            with self._conn.cursor(row_factory=_dict_row_factory()) as cur:
                cur.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
        except Exception as exc:
            raise map_psycopg_error(exc, query=query, params=params) from exc
        finally:
            self._log_sql("fetch_all", query, start)

    def fetch_scalar(self, query: str, params: Params = None) -> Any:
        start = time.perf_counter()
        try:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                if row is None:
                    return None
                return row[0]
        except Exception as exc:
            raise map_psycopg_error(exc, query=query, params=params) from exc
        finally:
            self._log_sql("fetch_scalar", query, start)

    def execute(self, query: str, params: Params = None) -> int:
        start = time.perf_counter()
        try:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                return cur.rowcount
        except Exception as exc:
            raise map_psycopg_error(exc, query=query, params=params) from exc
        finally:
            self._log_sql("execute", query, start)

    def execute_many(self, query: str, params_seq: Iterable[Params]) -> int:
        start = time.perf_counter()
        try:
            with self._conn.cursor() as cur:
                cur.executemany(query, params_seq)
                return cur.rowcount
        except Exception as exc:
            raise map_psycopg_error(exc, query=query) from exc
        finally:
            self._log_sql("execute_many", query, start)

    def _log_sql(self, action: str, query: str, started_at: float) -> None:
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        fields = self._context.as_log_fields()
        fields.update(
            {
                "db_action": action,
                "elapsed_ms": round(elapsed_ms, 2),
                "query": " ".join(query.strip().split()),
            }
        )
        logger.debug("db_query", extra=fields)

