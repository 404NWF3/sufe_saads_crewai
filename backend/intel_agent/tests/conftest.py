"""Shared test fixtures/helpers for intel_agent offline tests."""

from __future__ import annotations

from datetime import datetime, timezone

from intel_agent.schemas import RawIntelItem


def make_item(
    item_id: str,
    source_name: str = "nvd_cve_api",
    relevance: float = 0.9,
    published: datetime | None = None,
    topics: list[str] | None = None,
    summary: str = "prompt injection against a large language model",
    raw_text: str = "prompt injection jailbreak",
) -> RawIntelItem:
    return RawIntelItem(
        item_id=item_id,
        source_name=source_name,
        source_uri=f"https://example/{item_id}",
        title=f"Item {item_id}",
        summary=summary,
        published_at=published or datetime(2026, 6, 1, tzinfo=timezone.utc),
        raw_text=raw_text,
        relevance_score=relevance,
        metadata={"topics": topics or ["prompt injection"]},
    )
