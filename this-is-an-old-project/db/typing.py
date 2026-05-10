from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, MutableMapping, Sequence

Params = Mapping[str, Any] | Sequence[Any] | None
RowMapping = dict[str, Any]
Rows = list[RowMapping]


@dataclass(slots=True)
class SqlContext:
    trace_id: str | None = None
    task_id: str | None = None
    raw_id: str | None = None
    attack_id: str | None = None
    component_id: str | None = None
    agent_name: str | None = None
    extra: MutableMapping[str, Any] = field(default_factory=dict)

    def as_log_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "raw_id": self.raw_id,
            "attack_id": self.attack_id,
            "component_id": self.component_id,
            "agent_name": self.agent_name,
        }
        fields.update(self.extra)
        return {k: v for k, v in fields.items() if v is not None}

