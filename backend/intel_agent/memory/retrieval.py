"""Embedding helpers for playbook semantic recall.

The embedder is reused from the relevance pipeline (GLM OpenAI-compatible path)
so no new dependency or credential is introduced. Recall degrades gracefully to
reward-only ranking when no embedder / API key is available.
"""

from __future__ import annotations

import math
import os
from typing import Callable, Sequence

EmbedFn = Callable[[list[str]], list[list[float]]]


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def default_playbook_embedder() -> EmbedFn | None:
    """Live GLM embedder, or None when embeddings are unavailable/disabled."""
    if os.getenv("INTEL_PLAYBOOK_EMBED", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    if not os.getenv("GLM_API_KEY"):
        return None
    from ..relevance import default_embedder

    return default_embedder()
