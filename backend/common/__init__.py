"""Shared constants for backend packages (topics only; no business logic)."""

from .topics import (
    ALL_SECURITY_TOPICS,
    CORE_SECURITY_TOPICS,
    EXTENDED_SECURITY_TOPICS,
    TARGET_SECURITY_TOPICS,
    TOPIC_ANCHORS,
    TOPIC_KEYWORDS,
    build_gap_query,
    detect_topics,
    is_core_topic,
    tokenize,
)

__all__ = [
    "ALL_SECURITY_TOPICS",
    "CORE_SECURITY_TOPICS",
    "EXTENDED_SECURITY_TOPICS",
    "TARGET_SECURITY_TOPICS",
    "TOPIC_ANCHORS",
    "TOPIC_KEYWORDS",
    "build_gap_query",
    "detect_topics",
    "is_core_topic",
    "tokenize",
]
