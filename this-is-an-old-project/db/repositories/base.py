from __future__ import annotations

from dataclasses import is_dataclass
from typing import Any, Iterable, TypeVar

from ..exceptions import NotFoundError
from ..session import DbSession
from ..typing import Params, RowMapping, Rows, SqlContext

T = TypeVar("T")


class BaseRepository:
    def __init__(self, conn: Any, *, context: SqlContext | None = None):
        self._conn = conn
        self._session = DbSession(conn, context=context)

    def _fetch_one(self, query: str, params: Params = None) -> RowMapping | None:
        return self._session.fetch_one(query, params)

    def _fetch_all(self, query: str, params: Params = None) -> Rows:
        return self._session.fetch_all(query, params)

    def _fetch_scalar(self, query: str, params: Params = None) -> Any:
        return self._session.fetch_scalar(query, params)

    def _execute(self, query: str, params: Params = None) -> int:
        return self._session.execute(query, params)

    def _execute_many(self, query: str, params_seq: Iterable[Params]) -> int:
        return self._session.execute_many(query, params_seq)

    def _row_to_model(self, model_cls: type[T], row: RowMapping | None) -> T | None:
        if row is None:
            return None
        if not is_dataclass(model_cls):
            raise TypeError(f"{model_cls} must be dataclass type")
        return model_cls(**row)

    def _require_model(self, model_cls: type[T], row: RowMapping | None, *, message: str) -> T:
        model = self._row_to_model(model_cls, row)
        if model is None:
            raise NotFoundError(message)
        return model

