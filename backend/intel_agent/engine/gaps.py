"""Adaptive incremental gap analysis over the persisted intelligence corpus."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Sequence

from ..relevance import cosine_similarity
from ..schemas import (
    CandidateTopic,
    CorpusGap,
    CoverageGap,
    RawIntelItem,
    RunGap,
    SourceCheckpoint,
)
from ..topics import (
    CORE_SECURITY_TOPICS,
    EXTENDED_SECURITY_TOPICS,
    TOPIC_ANCHORS,
    detect_topics,
    tokenize,
)

SOURCE_CHANNEL = {
    "arxiv_api": "research",
    "nvd_cve_api": "vulnerability_advisory",
    "osv_dev_api": "vulnerability_advisory",
    "cisa_kev_json": "exploitation",
}
SOURCE_TRUST = {
    "arxiv_api": 0.72,
    "nvd_cve_api": 0.90,
    "osv_dev_api": 0.84,
    "cisa_kev_json": 0.92,
}
CHANNEL_SOURCES = {
    "research": ["arxiv_api"],
    "vulnerability_advisory": ["nvd_cve_api", "osv_dev_api"],
    "exploitation": ["cisa_kev_json"],
}
HALF_LIFE_DAYS = {
    "research": 365,
    "vulnerability_advisory": 730,
    "exploitation": 365,
}
FRESHNESS_SLA_DAYS = {"research": 180, "vulnerability_advisory": 365}
VULNERABILITY_EXEMPT_TOPICS = {"jailbreak", "model backdoor"}

EmbedFn = Callable[[Sequence[str]], list[list[float]]]


def coverage_targets() -> dict[tuple[str, str], float]:
    targets: dict[tuple[str, str], float] = {}
    for topic in CORE_SECURITY_TOPICS:
        targets[(topic, "research")] = 3.0
        if topic not in VULNERABILITY_EXEMPT_TOPICS:
            targets[(topic, "vulnerability_advisory")] = 3.0
    return targets


def relevance_probability(item: RawIntelItem) -> float:
    relevance = item.metadata.get("relevance")
    if isinstance(relevance, dict):
        if relevance.get("label") == "irrelevant":
            return 0.0
        try:
            return min(1.0, max(0.0, float(relevance.get("score", item.relevance_score))))
        except (TypeError, ValueError):
            pass
    return float(item.relevance_score)


def topic_credits(item: RawIntelItem) -> dict[str, float]:
    raw_scores = item.metadata.get("topic_scores")
    scores: dict[str, float] = {}
    if isinstance(raw_scores, dict):
        for topic, value in raw_scores.items():
            if topic not in CORE_SECURITY_TOPICS:
                continue
            try:
                score = min(1.0, max(0.0, float(value)))
            except (TypeError, ValueError):
                continue
            if score > 0:
                scores[topic] = score
    if not scores:
        topics = set(item.metadata.get("topics") or [])
        relevance = item.metadata.get("relevance")
        if isinstance(relevance, dict) and relevance.get("topic"):
            topics.add(str(relevance["topic"]))
        topics.update(detect_topics(f"{item.title} {item.summary} {item.raw_text or ''}"))
        scores = {topic: 1.0 for topic in topics if topic in CORE_SECURITY_TOPICS}
    total = sum(scores.values())
    if total > 1.0:
        return {topic: score / total for topic, score in scores.items()}
    return scores


def canonical_event_key(item: RawIntelItem) -> str:
    text = f"{item.item_id} {item.title} {item.summary}"
    match = re.search(
        r"(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{14}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)",
        text,
        re.IGNORECASE,
    )
    if match:
        return match.group(1).upper()
    content = " ".join(f"{item.title} {item.summary}".lower().split())
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:24]


def _uniqueness_weights(items: list[RawIntelItem]) -> dict[str, float]:
    weights: dict[str, float] = {}
    seen_ids: set[str] = set()
    event_sources: dict[str, set[str]] = defaultdict(set)
    ordered = sorted(items, key=lambda item: item.published_at or item.fetched_at)
    for item in ordered:
        if item.item_id in seen_ids:
            weights[item.item_id] = 0.0
            continue
        seen_ids.add(item.item_id)
        key = canonical_event_key(item)
        sources = event_sources[key]
        if not sources:
            weight = 1.0
        elif item.source_name not in sources:
            weight = 0.5
        else:
            weight = 0.0
        sources.add(item.source_name)
        weights[item.item_id] = weight
    return weights


def freshness_weight(item: RawIntelItem, channel: str, now: datetime) -> float:
    observed = item.published_at or item.fetched_at
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (now - observed).total_seconds() / 86400.0)
    return max(0.5, 2 ** (-age_days / HALF_LIFE_DAYS[channel]))


def compute_corpus_gaps(
    items: list[RawIntelItem], now: datetime | None = None
) -> list[CorpusGap]:
    now = now or datetime.now(timezone.utc)
    targets = coverage_targets()
    unique = _uniqueness_weights(items)
    evidence: dict[tuple[str, str], float] = defaultdict(float)
    newest: dict[tuple[str, str], datetime] = {}

    for item in items:
        channel = SOURCE_CHANNEL.get(item.source_name)
        if channel not in {"research", "vulnerability_advisory"}:
            continue
        relevance = relevance_probability(item)
        if relevance <= 0:
            continue
        trust = SOURCE_TRUST.get(item.source_name, 0.5)
        uniqueness = unique.get(item.item_id, 1.0)
        if uniqueness <= 0:
            continue
        observed = item.published_at or item.fetched_at
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        for topic, credit in topic_credits(item).items():
            key = (topic, channel)
            if key not in targets:
                continue
            evidence[key] += (
                credit * relevance * trust * uniqueness * freshness_weight(item, channel, now)
            )
            if key not in newest or observed > newest[key]:
                newest[key] = observed

    required_channels: dict[str, set[str]] = defaultdict(set)
    present_channels: dict[str, set[str]] = defaultdict(set)
    for (topic, channel), target in targets.items():
        required_channels[topic].add(channel)
        if evidence[(topic, channel)] >= min(1.0, target):
            present_channels[topic].add(channel)

    gaps: list[CorpusGap] = []
    for (topic, channel), target in targets.items():
        effective = evidence[(topic, channel)]
        coverage_gap = max(0.0, 1.0 - effective / target)
        expected = len(required_channels[topic]) or 1
        diversity_gap = 1.0 - len(present_channels[topic]) / expected
        last_seen = newest.get((topic, channel))
        stale = last_seen is None or now - last_seen > timedelta(days=FRESHNESS_SLA_DAYS[channel])
        freshness_gap = 1.0 if stale else 0.0
        priority = min(1.0, 0.6 * coverage_gap + 0.2 * diversity_gap + 0.2 * freshness_gap)
        gaps.append(
            CorpusGap(
                gap_id=f"corpus:{topic.replace(' ', '_')}:{channel}",
                topic=topic,
                evidence_channel=channel,
                effective_evidence=round(effective, 4),
                target_evidence=target,
                coverage_gap=round(coverage_gap, 4),
                channel_diversity_gap=round(diversity_gap, 4),
                freshness_gap=freshness_gap,
                priority_score=round(priority, 4),
                status="satisfied" if priority == 0 else "open",
                recommended_sources=list(CHANNEL_SOURCES[channel]),
                metadata={"last_evidence_at": last_seen.isoformat() if last_seen else None},
            )
        )
    return sorted(gaps, key=lambda gap: (-gap.priority_score, gap.topic, gap.evidence_channel))


def compatibility_coverage_gaps(gaps: list[CorpusGap]) -> list[CoverageGap]:
    return [
        CoverageGap(
            gap_id=gap.gap_id,
            dimension="topic_evidence_channel",
            taxonomy_or_component=gap.topic,
            current_coverage=round(1.0 - gap.coverage_gap, 4),
            estimated_gap_fill_roi=gap.priority_score,
            recommended_sources=gap.recommended_sources,
            priority=(
                "critical" if gap.priority_score >= 0.85 else
                "high" if gap.priority_score >= 0.65 else
                "medium" if gap.priority_score >= 0.35 else "low"
            ),
            metadata={"evidence_channel": gap.evidence_channel, "status": gap.status},
        )
        for gap in gaps
        if gap.status == "open"
    ]


def initial_run_gaps(
    corpus_gaps: list[CorpusGap], checkpoints: list[SourceCheckpoint] | None = None
) -> list[RunGap]:
    gaps = [
        RunGap(
            gap_id="run:source_window:arxiv_api",
            gap_type="source_window",
            source_name="arxiv_api",
            evidence_channel="research",
            priority="high",
            retryable=True,
            rationale="Assess the incremental research window for active Core gaps.",
        ),
        RunGap(
            gap_id="run:source_window:nvd_cve_api",
            gap_type="source_window",
            source_name="nvd_cve_api",
            evidence_channel="vulnerability_advisory",
            priority="high",
            retryable=True,
            rationale="Assess the incremental vulnerability window for active Core gaps.",
        ),
        RunGap(
            gap_id="run:discovery:extended",
            gap_type="discovery",
            priority="high",
            retryable=True,
            rationale="Reserve one discovery query for Extended or emerging threats.",
        ),
    ]
    if not any(gap.status == "open" for gap in corpus_gaps):
        for gap in gaps[:2]:
            gap.priority = "medium"
    for checkpoint in checkpoints or []:
        if checkpoint.complete or not checkpoint.cursor:
            continue
        offset_key = (
            "nvd_start_index" if checkpoint.source_name == "nvd_cve_api" else "arxiv_start"
        )
        gaps.append(
            RunGap(
                gap_id=f"run:pagination:checkpoint:{checkpoint.source_name}",
                gap_type="pagination",
                source_name=checkpoint.source_name,
                evidence_channel=SOURCE_CHANNEL.get(checkpoint.source_name),
                priority="high",
                retryable=True,
                rationale="Resume an incomplete source page from the previous run.",
                metadata={offset_key: int(checkpoint.cursor)},
            )
        )
    return gaps


def total_open_priority(gaps: list[CorpusGap]) -> float:
    return sum(gap.priority_score for gap in gaps if gap.status == "open")


def extended_topic_trends(
    items: list[RawIntelItem], now: datetime | None = None
) -> dict[str, dict[str, float]]:
    now = now or datetime.now(timezone.utc)
    recent: dict[str, int] = defaultdict(int)
    baseline: dict[str, int] = defaultdict(int)
    for item in items:
        if relevance_probability(item) < 0.5:
            continue
        observed = item.published_at or item.fetched_at
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        age = now - observed
        topics = set(item.metadata.get("topics") or [])
        topics.update(detect_topics(f"{item.title} {item.summary} {item.raw_text or ''}"))
        for topic in topics & set(EXTENDED_SECURITY_TOPICS):
            if age <= timedelta(days=30):
                recent[topic] += 1
            elif age <= timedelta(days=120):
                baseline[topic] += 1
    trends: dict[str, dict[str, float]] = {}
    for topic in EXTENDED_SECURITY_TOPICS:
        monthly_baseline = baseline[topic] / 3.0
        burst = recent[topic] / max(0.5, monthly_baseline)
        if recent[topic] or baseline[topic]:
            trends[topic] = {
                "recent_30d": float(recent[topic]),
                "baseline_monthly": round(monthly_baseline, 3),
                "burst_ratio": round(burst, 3),
            }
    return dict(
        sorted(
            trends.items(),
            key=lambda row: (-row[1]["burst_ratio"], -row[1]["recent_30d"], row[0]),
        )
    )


def detect_candidate_topics(
    items: list[RawIntelItem], embedder: EmbedFn | None, now: datetime | None = None
) -> list[CandidateTopic]:
    """Cluster relevant residual items; never mutates the formal taxonomy."""
    if embedder is None:
        return []
    now = now or datetime.now(timezone.utc)
    residual = []
    for item in items:
        scores = item.metadata.get("topic_scores")
        if isinstance(scores, dict):
            max_score = max((float(v) for v in scores.values()), default=0.0)
        else:
            known = set(item.metadata.get("topics") or [])
            known.update(detect_topics(f"{item.title} {item.summary} {item.raw_text or ''}"))
            max_score = 1.0 if known else 0.0
        observed = item.published_at or item.fetched_at
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        if (
            relevance_probability(item) >= 0.7
            and max_score < 0.55
            and now - observed <= timedelta(days=120)
        ):
            residual.append(item)
    residual.sort(
        key=lambda item: (item.published_at or item.fetched_at).timestamp(), reverse=True
    )
    residual = residual[:500]
    if len(residual) < 3:
        return []

    texts = [f"{item.title}. {item.summary}"[:2000] for item in residual]
    anchor_texts = [text for values in TOPIC_ANCHORS.values() for text in values]
    try:
        vectors = embedder(texts + anchor_texts)
    except Exception:  # noqa: BLE001 - discovery is best effort
        return []
    item_vectors = vectors[: len(texts)]
    anchor_vectors = vectors[len(texts) :]
    clusters: list[list[int]] = []
    for index, vector in enumerate(item_vectors):
        for cluster in clusters:
            if max(cosine_similarity(vector, item_vectors[other]) for other in cluster) >= 0.82:
                cluster.append(index)
                break
        else:
            clusters.append([index])

    candidates: list[CandidateTopic] = []
    for number, cluster in enumerate(clusters, start=1):
        cluster_items = [residual[index] for index in cluster]
        independent_items: dict[str, RawIntelItem] = {}
        for item in cluster_items:
            independent_items.setdefault(canonical_event_key(item), item)
        sources = sorted({item.source_name for item in cluster_items})
        mean_relevance = sum(relevance_probability(item) for item in cluster_items) / len(cluster_items)
        max_anchor = max(
            (cosine_similarity(item_vectors[index], anchor) for index in cluster for anchor in anchor_vectors),
            default=1.0,
        )
        recent_count = 0
        baseline_count = 0
        for item in independent_items.values():
            observed = item.published_at or item.fetched_at
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            age = now - observed
            if age <= timedelta(days=30):
                recent_count += 1
            elif age <= timedelta(days=120):
                baseline_count += 1
        monthly_baseline = baseline_count / 3.0
        burst_ratio = recent_count / max(0.5, monthly_baseline)
        if (
            len(independent_items) < 3
            or len(sources) < 2
            or mean_relevance < 0.7
            or max_anchor >= 0.7
            or recent_count < 2
            or burst_ratio < 1.5
        ):
            continue
        tokens: dict[str, int] = defaultdict(int)
        for item in cluster_items:
            for token in tokenize(f"{item.title} {item.summary}"):
                tokens[token] += 1
        label = " ".join(token for token, _ in sorted(tokens.items(), key=lambda row: (-row[1], row[0]))[:4])
        support = min(1.0, len(independent_items) / 5)
        diversity = min(1.0, len(sources) / 3)
        separation = min(1.0, max(0.0, (1.0 - max_anchor) / 0.3))
        burst = min(1.0, burst_ratio / 4.0)
        score = min(1.0, support * diversity * separation * burst * mean_relevance)
        item_ids = sorted(item.item_id for item in cluster_items)
        digest = hashlib.sha256("|".join(item_ids).encode("utf-8")).hexdigest()[:12]
        candidates.append(
            CandidateTopic(
                candidate_id=f"candidate:{digest}",
                proposed_name=label or f"emerging cluster {number}",
                supporting_item_ids=item_ids,
                source_names=sources,
                mean_relevance=round(mean_relevance, 4),
                max_anchor_similarity=round(max_anchor, 4),
                emergence_score=round(score, 4),
                rationale=(
                    "Residual evidence passed independent-support, source-diversity, "
                    "relevance, separation, and temporal-burst gates."
                ),
                metadata={
                    "independent_evidence_count": len(independent_items),
                    "recent_30d": recent_count,
                    "baseline_monthly": round(monthly_baseline, 3),
                    "burst_ratio": round(burst_ratio, 3),
                },
            )
        )
    return candidates
