"""Three-tier relevance filter for collected intel items (roadmap chapter 7).

Cheapest first, mirroring the validated design in base_kg/pipeline/relevance.py:

1. rule       — the existing keyword score already on RawIntelItem.relevance_score
                (computed by _estimate_relevance/_classify_ai_vulnerability);
                high scores accepted and low scores rejected without any model call.
2. embedding  — middle band scored by cosine similarity between title+summary and
                per-topic anchor texts; results cached as JSONL keyed by content
                hash so an item is never embedded twice across runs.
3. llm        — the remaining uncertain band adjudicated by a flash model in
                batches (JSON array verdicts); failure falls back to tier 2.

Every item gets ``metadata["relevance"] = {score, label, method}``; the
``method`` field powers per-tier precision evaluation (roadmap chapter 9).
Network clients are injectable so the pipeline is fully testable offline.
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

from sufe_saads_crewai.schemas import RawIntelItem

TOPIC_ANCHORS: dict[str, list[str]] = {
    "prompt injection": [
        "An attacker embeds malicious instructions in content that a large language model processes, overriding the system prompt.",
        "Indirect prompt injection hides adversarial instructions in web pages, documents, or tool outputs consumed by an LLM application.",
        "A chatbot is manipulated through crafted user input to ignore its instructions and perform unintended actions.",
    ],
    "jailbreak": [
        "A jailbreak prompt bypasses the safety alignment of a large language model to elicit prohibited content.",
        "Adversarial prompting techniques defeat refusal behavior and guardrails of aligned chat models.",
        "Red-teaming attacks systematically break LLM safety policies through role-play or encoding tricks.",
    ],
    "agent tool abuse": [
        "An autonomous LLM agent is tricked into invoking dangerous tools such as shell commands or code execution.",
        "Vulnerabilities in agent frameworks let attackers escalate from prompt control to arbitrary tool invocation or API misuse.",
        "A confused-deputy attack abuses the permissions of an AI agent's plugins, function calling, or MCP servers.",
    ],
    "data leakage": [
        "A large language model leaks sensitive training data, secrets, or personal information in its responses.",
        "Cross-tenant or session data exposure occurs in an LLM application, revealing other users' prompts or documents.",
        "Training data extraction attacks recover memorized confidential text from a deployed model.",
    ],
    "model supply chain": [
        "Malicious or tampered model artifacts execute code on load, for example through unsafe pickle deserialization.",
        "Vulnerabilities in ML infrastructure such as model registries, serving frameworks, or fine-tuning pipelines compromise the AI supply chain.",
        "A compromised package or model hub distribution channel delivers backdoored AI components.",
    ],
    "rag poisoning": [
        "An attacker poisons the document corpus or vector database of a retrieval-augmented generation system to manipulate answers.",
        "Embedding or knowledge-base poisoning injects adversarial passages that are retrieved and trusted by an LLM.",
        "Retrieval corruption attacks degrade or hijack RAG pipelines through crafted indexed content.",
    ],
}

EmbedFn = Callable[[Sequence[str]], list[list[float]]]
JudgeFn = Callable[[list[dict[str, str]]], list[bool | None]]


@dataclass
class RelevanceConfig:
    rule_accept: float = 0.75
    rule_reject: float = 0.20
    embedding_accept: float = 0.62
    embedding_reject: float = 0.42
    llm_batch_size: int = 12
    cache_path: Path = Path("data") / "relevance_cache.jsonl"
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
        self._anchor_vectors: list[list[float]] | None = None
        self._cache: dict[str, float] | None = None

    # ------------------------------------------------------------- cache

    def _load_cache(self) -> dict[str, float]:
        if self._cache is not None:
            return self._cache
        cache: dict[str, float] = {}
        path = self.config.cache_path
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    cache[str(record["hash"])] = float(record["embedding_score"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
        self._cache = cache
        return cache

    def _append_cache(self, item_hash: str, score: float) -> None:
        cache = self._load_cache()
        if item_hash in cache:
            return
        cache[item_hash] = score
        path = self.config.cache_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"hash": item_hash, "embedding_score": round(score, 4)}) + "\n")

    # ------------------------------------------------------------- tiers

    def _anchor_matrix(self) -> list[list[float]]:
        if self._anchor_vectors is None:
            texts = [text for anchors in self.config.anchors.values() for text in anchors]
            assert self.embedder is not None
            self._anchor_vectors = self.embedder(texts)
        return self._anchor_vectors

    def _embedding_score(self, item: RawIntelItem) -> float | None:
        if self.embedder is None:
            return None
        item_hash = content_hash(item)
        cached = self._load_cache().get(item_hash)
        if cached is not None:
            return cached
        try:
            vector = self.embedder([f"{item.title}. {item.summary}"[:2000]])[0]
            score = max(
                cosine_similarity(vector, anchor) for anchor in self._anchor_matrix()
            )
        except Exception:  # noqa: BLE001 - embedding failure -> stay on rule score
            return None
        self._append_cache(item_hash, score)
        return score

    def annotate(self, items: list[RawIntelItem]) -> dict[str, int]:
        """Annotate items in place; returns per-method counters."""
        counts = {"rule": 0, "embedding": 0, "llm": 0, "uncertain": 0}
        llm_pending: list[tuple[RawIntelItem, float]] = []

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

            embedding_score = self._embedding_score(item)
            if embedding_score is None:
                _set_relevance(item, rule_score, "uncertain", "rule")
                counts["uncertain"] += 1
                continue
            if embedding_score >= self.config.embedding_accept:
                _set_relevance(item, embedding_score, "relevant", "embedding")
                counts["embedding"] += 1
                continue
            if embedding_score < self.config.embedding_reject:
                _set_relevance(item, embedding_score, "irrelevant", "embedding")
                counts["embedding"] += 1
                continue
            llm_pending.append((item, embedding_score))

        if llm_pending and self.llm_judge is not None:
            for start in range(0, len(llm_pending), self.config.llm_batch_size):
                batch = llm_pending[start : start + self.config.llm_batch_size]
                payload = [
                    {"title": item.title[:200], "summary": item.summary[:400]}
                    for item, _ in batch
                ]
                try:
                    verdicts = self.llm_judge(payload)
                except Exception:  # noqa: BLE001 - judge failure -> tier-2 result
                    verdicts = [None] * len(batch)
                for (item, embedding_score), verdict in zip(batch, verdicts):
                    if verdict is None:
                        _set_relevance(item, embedding_score, "uncertain", "embedding")
                        counts["uncertain"] += 1
                    else:
                        score = 0.85 if verdict else 0.15
                        _set_relevance(
                            item, score, "relevant" if verdict else "irrelevant", "llm"
                        )
                        counts["llm"] += 1
        else:
            for item, embedding_score in llm_pending:
                _set_relevance(item, embedding_score, "uncertain", "embedding")
                counts["uncertain"] += 1

        return counts


def _set_relevance(item: RawIntelItem, score: float, label: str, method: str) -> None:
    item.metadata["relevance"] = {
        "score": round(float(score), 4),
        "label": label,
        "method": method,
    }


# ---------------------------------------------------------------- default clients
# Both use the GLM OpenAI-compatible path (kept per roadmap 12.2), no new deps.


def _glm_openai_settings() -> tuple[str, str]:
    base_url = os.getenv("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4").rstrip("/")
    api_key = os.getenv("GLM_API_KEY", "")
    return base_url, api_key


def _post_json(url: str, payload: dict[str, Any], api_key: str, timeout: int = 60) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
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


def default_pipeline() -> RelevancePipeline | None:
    """Pipeline with live GLM clients, or None when disabled / no key configured.

    Controlled by INTEL_RELEVANCE_ENABLED (default on). Tier 2/3 use the GLM
    OpenAI-compatible path; without a key only tier 1 (rule) would run, which
    the caller gets anyway, so we return None to make the state explicit.
    """
    enabled = os.getenv("INTEL_RELEVANCE_ENABLED", "1").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        return None
    if not os.getenv("GLM_API_KEY"):
        return None
    return RelevancePipeline(embedder=default_embedder(), llm_judge=default_llm_judge())


def default_llm_judge(model: str | None = None) -> JudgeFn:
    judge_model = model or os.getenv("INTEL_RELEVANCE_JUDGE_MODEL") or os.getenv(
        "GLM_FAST_MODEL", "glm-4.7-flash"
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
