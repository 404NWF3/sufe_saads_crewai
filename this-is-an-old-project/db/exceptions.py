from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class DatabaseError(Exception):
    """Base exception for all db module failures."""


class ConnectionInitError(DatabaseError):
    """Raised when database connection pool initialization fails."""


class QueryExecutionError(DatabaseError):
    """Raised when SQL execution fails."""


class NotFoundError(DatabaseError):
    """Raised when expected entity is missing."""


class DuplicateEntityError(DatabaseError):
    """Raised when writing a duplicate entity violates uniqueness constraints."""


class ValidationError(DatabaseError):
    """Raised when input or DB check constraints fail."""


class ConcurrencyConflictError(DatabaseError):
    """Raised when concurrent writes conflict."""


class TransactionError(DatabaseError):
    """Raised when commit/rollback/acquire transaction lifecycle fails."""


@dataclass(slots=True)
class QueryContext:
    query: str | None = None
    params: Any | None = None
    entity: str | None = None


def _extract_sqlstate(exc: Exception) -> str | None:
    sqlstate = getattr(exc, "sqlstate", None)
    if sqlstate:
        return str(sqlstate)

    diag = getattr(exc, "diag", None)
    if diag is not None:
        diag_state = getattr(diag, "sqlstate", None)
        if diag_state:
            return str(diag_state)
    return None


def map_psycopg_error(
    exc: Exception,
    *,
    query: str | None = None,
    params: Any | None = None,
    entity: str | None = None,
) -> DatabaseError:
    """Map psycopg low-level errors into project-level exceptions."""

    sqlstate = _extract_sqlstate(exc)
    ctx = QueryContext(query=query, params=params, entity=entity)
    message = str(exc)

    if sqlstate == "23505":
        return DuplicateEntityError(message)
    if sqlstate in {"23503", "23514", "22001", "22003", "22007", "22P02"}:
        return ValidationError(message)
    if sqlstate in {"40001", "40P01"}:
        return ConcurrencyConflictError(message)

    if isinstance(exc, DatabaseError):
        return exc

    if ctx.query:
        return QueryExecutionError(f"{message}; query={ctx.query}")
    return QueryExecutionError(message)

