"""KG topic helpers — re-export shared taxonomy from ``common.topics``."""

from __future__ import annotations

from common.topics import (  # noqa: F401
    ALL_SECURITY_TOPICS,
    CORE_SECURITY_TOPICS,
    EXTENDED_SECURITY_TOPICS,
    TARGET_SECURITY_TOPICS,
    TOPIC_KEYWORDS,
    detect_topics,
)

__all__ = [
    "ALL_SECURITY_TOPICS",
    "CORE_SECURITY_TOPICS",
    "EXTENDED_SECURITY_TOPICS",
    "TARGET_SECURITY_TOPICS",
    "TOPIC_KEYWORDS",
    "detect_topics",
]
