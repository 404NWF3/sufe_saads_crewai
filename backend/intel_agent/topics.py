"""LLM-security target topics plus lightweight text helpers.

Self-contained: no imports beyond the standard library.
"""

from __future__ import annotations

import re

TARGET_SECURITY_TOPICS = [
    "prompt injection",
    "jailbreak",
    "agent tool abuse",
    "data leakage",
    "model supply chain",
    "rag poisoning",
]

TOPIC_KEYWORDS: dict[str, tuple[str, ...]] = {
    "prompt injection": ("prompt injection", "indirect prompt", "instruction injection"),
    "jailbreak": ("jailbreak", "policy bypass", "guardrail bypass"),
    "agent tool abuse": ("agent tool", "tool abuse", "plugin abuse", "function calling"),
    "data leakage": ("data leakage", "secret exfiltration", "training data extraction"),
    "model supply chain": ("model supply chain", "model artifact", "unsafe model", "pickle"),
    "rag poisoning": ("rag poisoning", "retrieval poisoning", "knowledge base poisoning"),
}

STOPWORDS = {
    "a", "about", "ai", "and", "for", "in", "large", "language", "llm", "llms",
    "model", "models", "of", "on", "or", "security", "the", "to", "with",
}


def detect_topics(text: str) -> list[str]:
    normalized = text.lower()
    return [
        topic
        for topic, keywords in TOPIC_KEYWORDS.items()
        if any(keyword in normalized for keyword in keywords)
    ]


def tokenize(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text.lower())
        if token not in STOPWORDS
    }


def build_gap_query(topics: list[str]) -> str:
    topic_text = " OR ".join(topics)
    return f"{topic_text} LLM vulnerability evidence advisory paper"
