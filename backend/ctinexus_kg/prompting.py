from __future__ import annotations

from .schemas import RawIntelItem


def build_ctinexus_input_text(
    item: RawIntelItem,
    matched_topics: list[str],
    max_chars: int,
) -> str:
    """Return exactly the item raw_text, or summary when raw_text is empty."""
    del matched_topics  # reserved for future prompt enrichment
    text = kg_source_text(item)
    if len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 96)].rstrip() + "\n\n[TRUNCATED: input exceeded KG max_input_chars]"


def kg_source_text(item: RawIntelItem) -> str:
    raw_text = (item.raw_text or "").strip()
    if raw_text:
        return raw_text
    return (item.summary or "").strip()
