from __future__ import annotations

from types import TracebackType
from typing import Any

from .connection import connection_context
from .exceptions import TransactionError
from .repositories import (
    AttackRepository,
    ComponentRepository,
    GovernanceRepository,
    ReadModelRepository,
    SourceRepository,
    StixRepository,
)
from .typing import SqlContext


class UnitOfWork:
    def __init__(
        self,
        *,
        conn: Any | None = None,
        context: SqlContext | None = None,
        auto_commit: bool = True,
        read_only: bool = False,
    ) -> None:
        self._external_conn = conn
        self._conn = conn
        self._context = context
        self._auto_commit = auto_commit
        self._read_only = read_only
        self._conn_cm: Any | None = None
        self._entered = False

        self.sources: SourceRepository
        self.attacks: AttackRepository
        self.components: ComponentRepository
        self.governance: GovernanceRepository
        self.read_models: ReadModelRepository
        self.stix: StixRepository

    @property
    def conn(self) -> Any:
        return self._conn

    def __enter__(self) -> "UnitOfWork":
        if self._entered:
            return self

        if self._conn is None:
            self._conn_cm = connection_context()
            self._conn = self._conn_cm.__enter__()

        self.sources = SourceRepository(self._conn, context=self._context)
        self.attacks = AttackRepository(self._conn, context=self._context)
        self.components = ComponentRepository(self._conn, context=self._context)
        self.governance = GovernanceRepository(self._conn, context=self._context)
        self.read_models = ReadModelRepository(self._conn, context=self._context)
        self.stix = StixRepository(self._conn, context=self._context)
        self._entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        try:
            if self._conn is not None:
                if exc_type is None and self._auto_commit and not self._read_only:
                    self._conn.commit()
                else:
                    self._conn.rollback()
        except Exception as tx_exc:
            raise TransactionError(f"Failed to finalize DB transaction: {tx_exc}") from tx_exc
        finally:
            if self._conn_cm is not None:
                self._conn_cm.__exit__(exc_type, exc, tb)
            self._entered = False
            if self._external_conn is None:
                self._conn = None
            self._conn_cm = None
        return False

    def commit(self) -> None:
        if self._conn is None:
            raise TransactionError("UnitOfWork has no active connection")
        try:
            self._conn.commit()
        except Exception as exc:
            raise TransactionError(f"Failed to commit transaction: {exc}") from exc

    def rollback(self) -> None:
        if self._conn is None:
            raise TransactionError("UnitOfWork has no active connection")
        try:
            self._conn.rollback()
        except Exception as exc:
            raise TransactionError(f"Failed to rollback transaction: {exc}") from exc

