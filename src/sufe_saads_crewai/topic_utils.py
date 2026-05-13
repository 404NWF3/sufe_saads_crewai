from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


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

TOPIC_SEMANTIC_PROFILES: dict[str, dict[str, tuple[str, ...]]] = {
    "prompt injection": {
        "aliases": (
            "prompt injection",
            "indirect prompt injection",
            "instruction injection",
            "malicious instruction",
            "system prompt override",
            "prompt override",
            "prompt leakage",
            "cross prompt injection",
        ),
        "indicators": (
            "untrusted content",
            "developer message",
            "system prompt",
            "hidden instruction",
            "context injection",
            "override instructions",
            "ignore previous instructions",
        ),
        "evidence_types": ("paper", "advisory", "vendor", "community", "structured"),
    },
    "jailbreak": {
        "aliases": (
            "jailbreak",
            "policy bypass",
            "guardrail bypass",
            "safety bypass",
            "red team bypass",
            "alignment bypass",
            "content filter bypass",
        ),
        "indicators": (
            "refusal bypass",
            "harmful content",
            "safety evaluation",
            "red-team report",
            "dan prompt",
            "universal adversarial suffix",
        ),
        "evidence_types": ("paper", "research", "vendor", "community"),
    },
    "agent tool abuse": {
        "aliases": (
            "agent tool abuse",
            "tool abuse",
            "tool misuse",
            "unsafe tool execution",
            "plugin abuse",
            "function calling",
            "tool calling",
            "mcp tool",
            "agentic workflow exploit",
        ),
        "indicators": (
            "tool permission",
            "tool invocation",
            "command execution",
            "sandbox escape",
            "agent dependency",
            "untrusted model output",
            "autonomous agent",
        ),
        "evidence_types": ("structured", "security_db", "advisory", "vendor", "code"),
    },
    "data leakage": {
        "aliases": (
            "data leakage",
            "data leak",
            "secret exfiltration",
            "credential exfiltration",
            "pii exposure",
            "private data exposure",
            "training data extraction",
            "model inversion",
            "membership inference",
        ),
        "indicators": (
            "sensitive data",
            "private training snippets",
            "context window",
            "conversation history",
            "prompt leak",
            "expose model service data",
            "exfiltrate secrets",
        ),
        "evidence_types": ("structured", "advisory", "vendor", "paper"),
    },
    "model supply chain": {
        "aliases": (
            "model supply chain",
            "model artifact",
            "unsafe model",
            "model weight",
            "model weights",
            "pickle deserialization",
            "safetensors",
            "model hub",
            "ml supply chain",
        ),
        "indicators": (
            "artifact loader",
            "dependency confusion",
            "malicious model",
            "trojaned model",
            "backdoored model",
            "unsafe deserialization",
            "supply-chain execution",
            "open model artifacts",
        ),
        "evidence_types": ("structured", "security_db", "vendor", "code", "advisory"),
    },
    "rag poisoning": {
        "aliases": (
            "rag poisoning",
            "retrieval poisoning",
            "knowledge base poisoning",
            "corpus poisoning",
            "vector database poisoning",
            "embedding poisoning",
            "retrieval manipulation",
            "malicious retrieval context",
        ),
        "indicators": (
            "poisoned documents",
            "retrieval context",
            "knowledge base",
            "enterprise kb",
            "vector store",
            "document injection",
            "attacker controlled document",
        ),
        "evidence_types": ("paper", "research", "vendor", "community"),
    },
}

SOURCE_QUERY_HINTS: dict[str, dict[str, tuple[str, ...]]] = {
    "nvd_cve_api": {
        "model supply chain": ("model artifact loader", "pickle deserialization", "machine learning service"),
        "agent tool abuse": ("plugin command execution", "tool permission bypass"),
        "data leakage": ("information disclosure", "credential exposure", "CWE-200"),
    },
    "osv_dev_api": {
        "model supply chain": ("pypi ml package", "model loader", "purl"),
        "agent tool abuse": ("agent framework package", "tool execution dependency"),
    },
    "arxiv_api": {
        "prompt injection": ("indirect prompt injection", "prompt injection defenses"),
        "jailbreak": ("jailbreak evaluation", "guardrail bypass"),
        "rag poisoning": ("retrieval augmented generation poisoning", "knowledge base poisoning"),
    },
    "cisa_kev_json": {
        "data leakage": ("known exploited information disclosure", "edge gateway exposure"),
        "model supply chain": ("known exploited dependency", "AI gateway dependency"),
    },
}

STOPWORDS = {
    "a",
    "about",
    "ai",
    "and",
    "for",
    "in",
    "large",
    "language",
    "llm",
    "llms",
    "model",
    "models",
    "of",
    "on",
    "or",
    "security",
    "the",
    "to",
    "with",
}


@dataclass(frozen=True)
class TopicSemanticMatch:
    topic: str
    score: float
    matched_terms: tuple[str, ...]
    matched_indicators: tuple[str, ...]
    evidence_types: tuple[str, ...]


def detect_topics(text: str) -> list[str]:
    return [match.topic for match in detect_topic_matches(text) if match.score >= 0.42]


def detect_topic_matches(text: str) -> list[TopicSemanticMatch]:
    normalized = normalize_text(text)
    matches: list[TopicSemanticMatch] = []

    for topic, profile in TOPIC_SEMANTIC_PROFILES.items():
        alias_hits = _matched_phrases(normalized, profile["aliases"])
        indicator_hits = _matched_phrases(normalized, profile["indicators"])
        legacy_hits = _matched_phrases(normalized, TOPIC_KEYWORDS.get(topic, ()))
        matched_terms = tuple(dict.fromkeys((*alias_hits, *legacy_hits)))

        if not matched_terms and not indicator_hits:
            continue

        score = min(
            1.0,
            (0.46 if matched_terms else 0.0)
            + 0.16 * max(0, len(matched_terms) - 1)
            + 0.14 * len(indicator_hits),
        )
        matches.append(
            TopicSemanticMatch(
                topic=topic,
                score=round(score, 3),
                matched_terms=matched_terms,
                matched_indicators=tuple(indicator_hits),
                evidence_types=profile["evidence_types"],
            )
        )

    return sorted(matches, key=lambda match: (-match.score, match.topic))


def topic_coverage_scores(items: Iterable[object]) -> dict[str, float]:
    scores = {topic: 0.0 for topic in TARGET_SECURITY_TOPICS}
    for item in items:
        metadata = getattr(item, "metadata", {}) or {}
        explicit_topics = metadata.get("topics", [])
        text = " ".join(
            str(part)
            for part in (
                getattr(item, "title", ""),
                getattr(item, "summary", ""),
                getattr(item, "raw_text", ""),
                metadata.get("source_type", ""),
            )
            if part
        )
        item_relevance = float(getattr(item, "relevance_score", 0.75) or 0.75)

        for topic in explicit_topics:
            if topic in scores:
                scores[topic] = max(scores[topic], min(1.0, 0.84 * item_relevance + 0.16))

        for match in detect_topic_matches(text):
            if match.topic in scores:
                scores[match.topic] = max(scores[match.topic], min(1.0, match.score * item_relevance))

    return {topic: round(score, 3) for topic, score in scores.items()}


def semantic_terms_for_topic(topic: str, source_name: str | None = None) -> list[str]:
    profile = TOPIC_SEMANTIC_PROFILES.get(topic)
    if not profile:
        return [topic]

    terms = [*profile["aliases"][:7], *profile["indicators"][:3]]
    if source_name:
        terms.extend(SOURCE_QUERY_HINTS.get(source_name, {}).get(topic, ()))
    return list(dict.fromkeys(terms))


def tokenize(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text.lower())
        if token not in STOPWORDS
    }


def build_gap_query(topics: list[str]) -> str:
    expanded_terms: list[str] = []
    for topic in topics:
        expanded_terms.extend(semantic_terms_for_topic(topic)[:7])
    topic_text = " OR ".join(dict.fromkeys(expanded_terms or topics))
    return f"{topic_text} LLM vulnerability evidence advisory paper"


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _matched_phrases(normalized_text: str, phrases: Iterable[str]) -> list[str]:
    hits: list[str] = []
    for phrase in phrases:
        normalized_phrase = normalize_text(phrase)
        pattern = rf"(?<![a-z0-9]){re.escape(normalized_phrase)}(?![a-z0-9])"
        if re.search(pattern, normalized_text):
            hits.append(phrase)
    return hits
