"""Local topic helpers for KG eligibility (copied, not imported from intel_agent)."""

from __future__ import annotations

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


def detect_topics(text: str) -> list[str]:
    normalized = text.lower()
    return [
        topic
        for topic, keywords in TOPIC_KEYWORDS.items()
        if any(keyword in normalized for keyword in keywords)
    ]
