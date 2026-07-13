"""Three-tier relevance filter: rule -> embedding -> flash LLM.

Cheapest first. The rule tier reuses the keyword score already on each item; the
embedding tier scores the middle band against per-topic anchor texts (cached by
content hash); the LLM tier adjudicates the remaining uncertain band in batches.
Every item receives ``metadata["relevance"] = {score, label, method, topic?}``.

Self-contained: only stdlib + local schemas. Network clients are injectable so
the pipeline is fully testable offline.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from .schemas import RawIntelItem
from .topics import TOPIC_ANCHORS

EmbedFn = Callable[[Sequence[str]], list[list[float]]]
JudgeFn = Callable[[list[dict[str, str]]], list[bool | None]]


@dataclass
class RelevanceConfig:
    rule_accept: float = 0.75
    rule_reject: float = 0.20
    embedding_accept: float = 0.62
    embedding_reject: float = 0.42
    llm_batch_size: int = 12
    cache_path: Path = Path("data") / "intel_agent" / "relevance_cache.jsonl"
    anchors: dict[str, list[str]] = field(default_factory=lambda: dict(TOPIC_ANCHORS))

    @classmethod
    def from_env(cls) -> "RelevanceConfig":
        config = cls()
        for attr, env_name in (
            ("rule_accept", "INTEL_RELEVANCE_ACCEPT"),
            ("rule_reject", "INTEL_RELEVANCE_REJECT"),
            ("embedding_accept", "INTEL_RELEVANCE_EMB_ACCEPT"),
            ("embedding_reject", "INTEL_RELEVANCE_EMB_REJECT"),
        ):
            raw = os.getenv(env_name)
            if raw:
                try:
                    setattr(config, attr, float(raw))
                except ValueError:
                    pass
        return config


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def content_hash(item: RawIntelItem) -> str:
    return hashlib.sha256(f"{item.title}|{item.summary}".encode("utf-8")).hexdigest()[:24]


class RelevancePipeline:
    def __init__(
        self,
        config: RelevanceConfig | None = None,
        embedder: EmbedFn | None = None,
        llm_judge: JudgeFn | None = None,
    ) -> None:
        self.config = config or RelevanceConfig.from_env()
        self.embedder = embedder
        self.llm_judge = llm_judge
        self._anchor_vectors: dict[str, list[list[float]]] | None = None
        self._cache: dict[str, tuple[float, str | None]] | None = None

    def _load_cache(self) -> dict[str, tuple[float, str | None]]:
        if self._cache is not None:
            return self._cache
        cache: dict[str, tuple[float, str | None]] = {}
        path = self.config.cache_path
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    topic = record.get("topic")
                    cache[str(record["hash"])] = (
                        float(record["embedding_score"]),
                        topic if isinstance(topic, str) else None,
                    )
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
        self._cache = cache
        return cache

    def _append_cache(self, item_hash: str, score: float, topic: str | None) -> None:
        cache = self._load_cache()
        if item_hash in cache:
            return
        cache[item_hash] = (score, topic)
        path = self.config.cache_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(
                json.dumps({"hash": item_hash, "embedding_score": round(score, 4), "topic": topic})
                + "\n"
            )

    def _anchor_groups(self) -> dict[str, list[list[float]]]:
        if self._anchor_vectors is None:
            topics = list(self.config.anchors.keys())
            texts = [text for topic in topics for text in self.config.anchors[topic]]
            assert self.embedder is not None
            vectors = self.embedder(texts)
            groups: dict[str, list[list[float]]] = {}
            cursor = 0
            for topic in topics:
                span = len(self.config.anchors[topic])
                groups[topic] = vectors[cursor : cursor + span]
                cursor += span
            self._anchor_vectors = groups
        return self._anchor_vectors

    def _embedding_assess(self, item: RawIntelItem) -> tuple[float, str | None] | None:
        if self.embedder is None:
            return None
        item_hash = content_hash(item)
        cached = self._load_cache().get(item_hash)
        if cached is not None:
            return cached
        try:
            vector = self.embedder([f"{item.title}. {item.summary}"[:2000]])[0]
            best_topic: str | None = None
            best_score = -1.0
            for topic, anchors in self._anchor_groups().items():
                topic_score = max(cosine_similarity(vector, anchor) for anchor in anchors)
                if topic_score > best_score:
                    best_score, best_topic = topic_score, topic
        except Exception:  # noqa: BLE001 - embedding failure -> stay on rule score
            return None
        self._append_cache(item_hash, best_score, best_topic)
        return best_score, best_topic

    def annotate(self, items: list[RawIntelItem]) -> dict[str, int]:
        counts = {"rule": 0, "embedding": 0, "llm": 0, "uncertain": 0}
        llm_pending: list[tuple[RawIntelItem, float, str | None]] = []

        for item in items:
            rule_score = float(item.relevance_score)
            if rule_score >= self.config.rule_accept:
                _set_relevance(item, rule_score, "relevant", "rule")
                counts["rule"] += 1
                continue
            if rule_score < self.config.rule_reject:
                _set_relevance(item, rule_score, "irrelevant", "rule")
                counts["rule"] += 1
                continue

            assessment = self._embedding_assess(item)
            if assessment is None:
                _set_relevance(item, rule_score, "uncertain", "rule")
                counts["uncertain"] += 1
                continue
            embedding_score, best_topic = assessment
            if embedding_score >= self.config.embedding_accept:
                _set_relevance(item, embedding_score, "relevant", "embedding", best_topic)
                counts["embedding"] += 1
                continue
            if embedding_score < self.config.embedding_reject:
                _set_relevance(item, embedding_score, "irrelevant", "embedding", best_topic)
                counts["embedding"] += 1
                continue
            llm_pending.append((item, embedding_score, best_topic))

        if llm_pending and self.llm_judge is not None:
            for start in range(0, len(llm_pending), self.config.llm_batch_size):
                batch = llm_pending[start : start + self.config.llm_batch_size]
                payload = [
                    {"title": item.title[:200], "summary": item.summary[:400]}
                    for item, _, _ in batch
                ]
                try:
                    verdicts = self.llm_judge(payload)
                except Exception:  # noqa: BLE001 - judge failure -> tier-2 result
                    verdicts = [None] * len(batch)
                for (item, embedding_score, best_topic), verdict in zip(batch, verdicts):
                    if verdict is None:
                        _set_relevance(item, embedding_score, "uncertain", "embedding", best_topic)
                        counts["uncertain"] += 1
                    else:
                        score = 0.85 if verdict else 0.15
                        _set_relevance(
                            item, score, "relevant" if verdict else "irrelevant", "llm", best_topic
                        )
                        counts["llm"] += 1
        else:
            for item, embedding_score, best_topic in llm_pending:
                _set_relevance(item, embedding_score, "uncertain", "embedding", best_topic)
                counts["uncertain"] += 1

        return counts


def _set_relevance(
    item: RawIntelItem, score: float, label: str, method: str, topic: str | None = None
) -> None:
    relevance: dict[str, Any] = {"score": round(float(score), 4), "label": label, "method": method}
    if topic:
        relevance["topic"] = topic
    topic_scores: dict[str, float] = {}
    for detected in item.metadata.get("topics", []):
        if detected in TOPIC_ANCHORS:
            topic_scores[str(detected)] = 1.0
    if topic:
        topic_scores[topic] = max(topic_scores.get(topic, 0.0), round(float(score), 4))
    item.metadata["topic_scores"] = topic_scores
    item.metadata["relevance"] = relevance


# ---------------------------------------------------------------- default clients
# GLM OpenAI-compatible path; no new dependencies.


def _glm_openai_settings() -> tuple[str, str]:
    base_url = os.getenv("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4").rstrip("/")
    return base_url, os.getenv("GLM_API_KEY", "")


def _post_json(url: str, payload: dict[str, Any], api_key: str, timeout: int = 60) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def default_embedder(model: str | None = None) -> EmbedFn:
    embedding_model = model or os.getenv("INTEL_EMBEDDING_MODEL", "embedding-3")
    base_url, api_key = _glm_openai_settings()

    def embed(texts: Sequence[str]) -> list[list[float]]:
        body = _post_json(
            f"{base_url}/embeddings",
            {"model": embedding_model, "input": list(texts)},
            api_key,
        )
        return [entry["embedding"] for entry in body["data"]]

    return embed


def default_llm_judge(model: str | None = None) -> JudgeFn:
    judge_model = (
        model
        or os.getenv("INTEL_RELEVANCE_JUDGE_MODEL")
        or os.getenv("GLM_FAST_MODEL", "glm-4.7-flash")
    )
    base_url, api_key = _glm_openai_settings()

    def judge(entries: list[dict[str, str]]) -> list[bool | None]:
        numbered = "\n".join(
            f"{index}. title: {entry['title']}\n   summary: {entry['summary']}"
            for index, entry in enumerate(entries)
        )
        prompt = (
            "You are filtering a security intelligence feed. For each numbered item, "
            "decide whether it is relevant to LLM/AI security (prompt injection, "
            "jailbreak, RAG poisoning, agent tool abuse, AI data leakage, model "
            "supply chain). Reply with a JSON array only, one object per item: "
            '[{"index": 0, "relevant": true}, ...]\n\n' + numbered
        )
        body = _post_json(
            f"{base_url}/chat/completions",
            {
                "model": judge_model,
                "max_tokens": 1000,
                "temperature": 0.0,
                "messages": [{"role": "user", "content": prompt}],
            },
            api_key,
        )
        text = body["choices"][0]["message"]["content"]
        start, end = text.find("["), text.rfind("]")
        verdicts: list[bool | None] = [None] * len(entries)
        if start == -1 or end == -1:
            return verdicts
        try:
            for entry in json.loads(text[start : end + 1]):
                index = int(entry.get("index", -1))
                if 0 <= index < len(entries):
                    verdicts[index] = bool(entry.get("relevant"))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        return verdicts

    return judge


def default_pipeline() -> RelevancePipeline | None:
    """Live GLM-backed pipeline, or None when disabled / no key configured."""
    if os.getenv("INTEL_RELEVANCE_ENABLED", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    if not os.getenv("GLM_API_KEY"):
        return None
    return RelevancePipeline(embedder=default_embedder(), llm_judge=default_llm_judge())
