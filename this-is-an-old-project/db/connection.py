from __future__ import annotations

import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from dotenv import load_dotenv

from .exceptions import ConnectionInitError

_SCHEMA_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_POOL: Any | None = None
_SETTINGS: "DatabaseSettings | None" = None


@dataclass(slots=True, frozen=True)
class DatabaseSettings:
    dsn: str | None
    host: str
    port: int
    dbname: str
    user: str
    password: str
    schema: str
    min_size: int
    max_size: int
    connect_timeout: int
    statement_timeout_ms: int
    application_name: str

    def __post_init__(self) -> None:
        if not self.dsn and (not self.host or not self.dbname or not self.user):
            raise ConnectionInitError(
                "Missing database config: POSTGRES_DSN or POSTGRES_HOST/DB/USER is required"
            )
        if self.port <= 0:
            raise ConnectionInitError("POSTGRES_PORT must be > 0")
        if self.min_size <= 0 or self.max_size <= 0:
            raise ConnectionInitError(
                "POSTGRES_MIN_SIZE and POSTGRES_MAX_SIZE must be > 0"
            )
        if self.min_size > self.max_size:
            raise ConnectionInitError(
                "POSTGRES_MIN_SIZE cannot be larger than POSTGRES_MAX_SIZE"
            )
        if self.connect_timeout <= 0:
            raise ConnectionInitError("POSTGRES_CONNECT_TIMEOUT must be > 0")
        if self.statement_timeout_ms <= 0:
            raise ConnectionInitError("POSTGRES_STATEMENT_TIMEOUT_MS must be > 0")
        if not _SCHEMA_PATTERN.match(self.schema):
            raise ConnectionInitError(f"Invalid schema name: {self.schema}")

    @classmethod
    def from_env(cls) -> "DatabaseSettings":
        load_dotenv()
        return cls(
            dsn=os.getenv("POSTGRES_DSN"),
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            dbname=os.getenv("POSTGRES_DB", "saads"),
            user=os.getenv("POSTGRES_USER", "postgres"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
            schema=os.getenv("POSTGRES_SCHEMA", "wp11"),
            min_size=int(os.getenv("POSTGRES_MIN_SIZE", "1")),
            max_size=int(os.getenv("POSTGRES_MAX_SIZE", "10")),
            connect_timeout=int(os.getenv("POSTGRES_CONNECT_TIMEOUT", "5")),
            statement_timeout_ms=int(
                os.getenv("POSTGRES_STATEMENT_TIMEOUT_MS", "30000")
            ),
            application_name=os.getenv("POSTGRES_APPLICATION_NAME", "saads-db"),
        )

    def to_conninfo(self) -> str:
        if self.dsn:
            return self.dsn
        password_part = f" password={self.password}" if self.password else ""
        return (
            f"host={self.host} port={self.port} dbname={self.dbname} "
            f"user={self.user}{password_part}"
        )


def _import_pool() -> Any:
    try:
        from psycopg_pool import ConnectionPool
    except ModuleNotFoundError as exc:
        raise ConnectionInitError(
            "psycopg_pool is required for db module. Install `psycopg` and `psycopg_pool`."
        ) from exc
    return ConnectionPool


def init_pool(
    settings: DatabaseSettings | None = None,
    *,
    open_immediately: bool = True,
) -> Any:
    global _POOL, _SETTINGS

    if _POOL is not None:
        return _POOL

    settings = settings or DatabaseSettings.from_env()
    ConnectionPool = _import_pool()

    def _configure_connection(conn: Any) -> None:
        with conn.cursor() as cur:
            cur.execute(f"SET search_path TO {settings.schema}, public")
            cur.execute(f"SET statement_timeout = {int(settings.statement_timeout_ms)}")
        conn.commit()

    try:
        pool = ConnectionPool(
            conninfo=settings.to_conninfo(),
            min_size=settings.min_size,
            max_size=settings.max_size,
            open=False,
            configure=_configure_connection,
            kwargs={
                "connect_timeout": settings.connect_timeout,
                "application_name": settings.application_name,
            },
        )
        if open_immediately:
            pool.open(wait=True)
    except Exception as exc:
        raise ConnectionInitError(f"Failed to initialize db pool: {exc}") from exc

    _POOL = pool
    _SETTINGS = settings
    return _POOL


def get_pool() -> Any:
    if _POOL is None:
        return init_pool()
    return _POOL


def close_pool() -> None:
    global _POOL, _SETTINGS
    if _POOL is None:
        return
    _POOL.close()
    _POOL = None
    _SETTINGS = None


@contextmanager
def connection_context() -> Iterator[Any]:
    pool = get_pool()
    with pool.connection() as conn:
        yield conn


def get_connection() -> Any:
    """Compatibility helper: returns a context manager yielding a pooled connection."""
    return get_pool().connection()


def get_settings() -> DatabaseSettings | None:
    return _SETTINGS
