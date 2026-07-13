"""Collection modes: full vs incremental, each resolving its own time scope.

- FullCollectionMode: every target topic, no time window; maximize breadth+depth.
- IncrementalCollectionMode: a focus topic/entity within a time window; the lower
  bound defaults to the watermark (max published_at of prior runs) so repeated
  incremental runs only chase genuinely new intel.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..analysis import topic_bucket
from ..agent.system_prompt import FULL_MODE_BRIEF, INCREMENTAL_MODE_BRIEF
from ..persistence import JsonIntelRunStore
from ..schemas import RawIntelItem, SourceCheckpoint
from ..topics import ALL_SECURITY_TOPICS, CORE_SECURITY_TOPICS

INCREMENTAL_OVERLAP_HOURS = 72
_CHECKPOINTED_SOURCES = ("nvd_cve_api", "arxiv_api")


def incremental_overlap_hours() -> int:
    raw = os.getenv("INTEL_INCREMENTAL_OVERLAP_HOURS", str(INCREMENTAL_OVERLAP_HOURS))
    try:
        return max(0, int(raw))
    except ValueError:
        return INCREMENTAL_OVERLAP_HOURS


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

    def resolve_source_scopes(
        self,
        store: JsonIntelRunStore,
        checkpoints: list[SourceCheckpoint] | None = None,
        corpus_items: list[RawIntelItem] | None = None,
    ) -> tuple[dict[str, datetime], datetime]:
        """Resolve independent source cursors with a late-arrival overlap window."""
        until = self.until or datetime.now(timezone.utc)
        if self.since is not None:
            return {source: self.since for source in _CHECKPOINTED_SOURCES}, until
        fallback = until - timedelta(days=self.window_days or 1)
        checkpoint_list = (
            checkpoints
            if checkpoints is not None
            else getattr(store, "load_source_checkpoints", lambda: [])()
        )
        checkpoints_by_source = {
            checkpoint.source_name: checkpoint for checkpoint in checkpoint_list
        }
        historical = (
            _latest_watermarks_from_items(corpus_items)
            if corpus_items is not None
            else _latest_watermarks_by_source(store)
        )
        starts: dict[str, datetime] = {}
        for source in _CHECKPOINTED_SOURCES:
            checkpoint = checkpoints_by_source.get(source)
            watermark = checkpoint.watermark if checkpoint and checkpoint.complete else historical.get(source)
            starts[source] = (
                watermark - timedelta(hours=incremental_overlap_hours())
                if watermark is not None
                else fallback
            )
        return starts, until


def _latest_watermark(store: JsonIntelRunStore) -> datetime | None:
    latest: datetime | None = None
    for blackboard in store.load_all_blackboards(limit=50):
        for item in blackboard.raw_items:
            if item.published_at is None:
                continue
            if latest is None or item.published_at > latest:
                latest = item.published_at
    return latest


def _latest_watermarks_by_source(store: JsonIntelRunStore) -> dict[str, datetime]:
    latest: dict[str, datetime] = {}
    for blackboard in store.load_all_blackboards(limit=200):
        for item in blackboard.raw_items:
            if item.published_at is None:
                continue
            current = latest.get(item.source_name)
            if current is None or item.published_at > current:
                latest[item.source_name] = item.published_at
    return latest


def _latest_watermarks_from_items(items: list[RawIntelItem]) -> dict[str, datetime]:
    latest: dict[str, datetime] = {}
    for item in items:
        if item.source_name not in _CHECKPOINTED_SOURCES or item.published_at is None:
            continue
        prior = latest.get(item.source_name)
        if prior is None or item.published_at > prior:
            latest[item.source_name] = item.published_at
    return latest
