from __future__ import annotations

from dataclasses import dataclass

from .exceptions import ValidationError


DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 1000


@dataclass(frozen=True, slots=True)
class Pagination:
    limit: int = DEFAULT_PAGE_LIMIT
    offset: int = 0

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValidationError("Pagination limit must be > 0")
        if self.limit > MAX_PAGE_LIMIT:
            raise ValidationError(f"Pagination limit must be <= {MAX_PAGE_LIMIT}")
        if self.offset < 0:
            raise ValidationError("Pagination offset must be >= 0")

    def to_sql(self) -> tuple[str, tuple[int, int]]:
        return " LIMIT %s OFFSET %s", (self.limit, self.offset)

