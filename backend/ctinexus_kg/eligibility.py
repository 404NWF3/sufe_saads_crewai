from __future__ import annotations

from .prompting import kg_source_text
from .schemas import KgEligibilityDecision, KgGenerationConfig, RawIntelItem
from .topics import detect_topics


def assess_kg_eligibility(
    item: RawIntelItem,
    config: KgGenerationConfig,
    target_topics: list[str] | None = None,
) -> KgEligibilityDecision:
    """Decide whether a raw intelligence item should enter CTINexus KG extraction."""
    matched_topics = _matched_topics(item, target_topics)
    reasons: list[str] = []
    excluded_reason: str | None = None

    text = kg_source_text(item)

    if not text:
        excluded_reason = "no_summary_or_raw_text"
    elif item.source_name in set(config.exclude_sources):
        excluded_reason = f"source_excluded:{item.source_name}"
    elif item.relevance_score < config.min_relevance_score:
        excluded_reason = (
            f"relevance_below_threshold:{item.relevance_score:.2f}"
            f"<{config.min_relevance_score:.2f}"
        )
    elif not matched_topics:
        excluded_reason = "no_llm_security_topic_match"

    if matched_topics:
        reasons.append("matched_llm_security_topic")
    if text:
        reasons.append("has_text_for_extraction")
    if item.relevance_score >= config.min_relevance_score:
        reasons.append("relevance_threshold_met")

    return KgEligibilityDecision(
        item_id=item.item_id,
        eligible=excluded_reason is None and config.enabled,
        reasons=reasons,
        excluded_reason=excluded_reason if config.enabled else "kg_generation_disabled",
        matched_topics=matched_topics,
        relevance_score=item.relevance_score,
        source_name=item.source_name,
    )


def _matched_topics(item: RawIntelItem, target_topics: list[str] | None) -> list[str]:
    configured_topics = target_topics or []
    metadata_topics = [
        str(topic).lower()
        for topic in item.metadata.get("topics", [])
        if isinstance(topic, str)
    ]
    detected_topics = detect_topics(kg_source_text(item))
    candidates = metadata_topics + detected_topics
    if configured_topics:
        allowed = {topic.lower() for topic in configured_topics}
        candidates = [topic for topic in candidates if topic.lower() in allowed]
    return _dedupe(candidates)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        lowered = value.strip().lower()
        if not lowered or lowered in seen:
            continue
        seen.add(lowered)
        out.append(lowered)
    return out
