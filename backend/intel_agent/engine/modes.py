"""Collection modes: full vs incremental, each resolving its own time scope.

- FullCollectionMode: every target topic, no time window; maximize breadth+depth.
- IncrementalCollectionMode: a focus topic/entity within a time window; the lower
  bound defaults to the watermark (max published_at of prior runs) so repeated
  incremental runs only chase genuinely new intel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..analysis import topic_bucket
from ..agent.system_prompt import FULL_MODE_BRIEF, INCREMENTAL_MODE_BRIEF
from ..persistence import JsonIntelRunStore
from ..topics import ALL_SECURITY_TOPICS, CORE_SECURITY_TOPICS


@dataclass
class CollectionMode:
    run_mode: str = "bootstrap"
    mode_brief: str = FULL_MODE_BRIEF
    # Coverage / critic targets = Core only. Search may still hit Extended via keywords.
    target_topics: list[str] = field(default_factory=lambda: list(CORE_SECURITY_TOPICS))
    focus: str | None = None
    run_goal: str = "Collect LLM/AI security intelligence."

    def topic_bucket(self) -> str:
        if self.focus:
            return topic_bucket([self.focus])
        return "general"

    def resolve_time_scope(
        self, store: JsonIntelRunStore
    ) -> tuple[datetime | None, datetime | None]:
        return None, None


@dataclass
class FullCollectionMode(CollectionMode):
    run_mode: str = "bootstrap"
    mode_brief: str = FULL_MODE_BRIEF
    run_goal: str = (
        "Full collection: maximize relevant LLM/AI security intelligence across Core "
        "coverage topics (and related Extended threats) while admitting as little "
        "unrelated content as possible."
    )


@dataclass
class IncrementalCollectionMode(CollectionMode):
    run_mode: str = "incremental"
    mode_brief: str = INCREMENTAL_MODE_BRIEF
    window_days: int | None = 1
    since: datetime | None = None
    until: datetime | None = None
    use_watermark: bool = True

    def __post_init__(self) -> None:
        if self.focus:
            focus_l = self.focus.strip().lower()
            if focus_l in ALL_SECURITY_TOPICS:
                self.target_topics = [focus_l]
            self.run_goal = (
                f"Incremental collection focused on '{self.focus}' within the given time scope."
            )
        else:
            self.run_goal = "Incremental collection within the given time scope."

    def resolve_time_scope(
        self, store: JsonIntelRunStore
    ) -> tuple[datetime | None, datetime | None]:
        until = self.until or datetime.now(timezone.utc)
        if self.since is not None:
            return self.since, until
        window_start = (
            until - timedelta(days=self.window_days) if self.window_days else None
        )
        if self.use_watermark:
            watermark = _latest_watermark(store)
            if watermark is not None:
                if window_start is None:
                    return watermark, until
                return max(window_start, watermark), until
        return window_start, until


def _latest_watermark(store: JsonIntelRunStore) -> datetime | None:
    latest: datetime | None = None
    for blackboard in store.load_all_blackboards(limit=50):
        for item in blackboard.raw_items:
            if item.published_at is None:
                continue
            if latest is None or item.published_at > latest:
                latest = item.published_at
    return latest
