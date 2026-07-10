"""Shared per-round state the agent's in-process tools read and write.

One ``ToolContext`` is created per round. The source tools append collected
items, record executed calls (for dedup, budget, and playbook harvesting), and
enforce the API-call budget and cross-round query dedup directly -- the reliable
in-process control plane described in the roadmap. Hooks add an auditing layer
on top but the context is authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..schemas import RawIntelItem, SourceExecutionStat


@dataclass
class ToolContext:
    run_id: str
    target_topics: list[str]
    topic_bucket: str
    max_results_per_call: int = 20
    since: datetime | None = None
    until: datetime | None = None
    existing_item_ids: set[str] = field(default_factory=set)
    executed_keys: set[str] = field(default_factory=set)
    api_calls_used: int = 0
    max_api_calls: int | None = None
    playbook: Any | None = None  # PlaybookStore | None (avoid import cycle)

    # per-round outputs
    collected_items: dict[str, RawIntelItem] = field(default_factory=dict)
    stats: list[SourceExecutionStat] = field(default_factory=list)
    executed_calls: list[dict[str, Any]] = field(default_factory=list)
    recorded_techniques: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def budget_remaining(self) -> bool:
        return self.max_api_calls is None or self.api_calls_used < self.max_api_calls

    def time_scope_hint(self) -> str | None:
        if self.since is None:
            return None
        if self.until is not None:
            return f"{self.since.date().isoformat()}..{self.until.date().isoformat()}"
        return f"since {self.since.date().isoformat()}"

    def in_time_scope(self, item: RawIntelItem) -> bool:
        if self.since is None:
            return True
        published = item.published_at
        if published is None:
            return True  # keep undated items; the source-side filter already narrowed
        if published < self.since:
            return False
        if self.until is not None and published > self.until:
            return False
        return True
