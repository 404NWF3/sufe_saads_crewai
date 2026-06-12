"""Thin OpenAI-compatible client used by the base-KG pipeline."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, TypeVar

from openai import APIConnectionError, APITimeoutError, OpenAI, RateLimitError

from .config import BaseKgConfig

_JSON_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
_BACKOFF_DELAYS = (15, 30, 60, 120)

T = TypeVar("T")


class LLMClient:
    def __init__(self, cfg: BaseKgConfig):
        self.cfg = cfg
        self._client = OpenAI(
            api_key=cfg.llm_api_key or "EMPTY",
            base_url=cfg.llm_base_url or None,
        )
        self._last_request_at = 0.0

    def _throttled(self, fn: Callable[[], T]) -> T:
        """Pace requests and retry rate-limit/transient errors with backoff."""
        wait = self.cfg.request_interval - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        last_exc: Exception | None = None
        for delay in (0, *_BACKOFF_DELAYS):
            if delay:
                print(f"[llm] rate limited, retrying in {delay}s")
                time.sleep(delay)
            try:
                result = fn()
                self._last_request_at = time.monotonic()
                return result
            except (RateLimitError, APIConnectionError, APITimeoutError) as exc:
                last_exc = exc
        raise last_exc  # type: ignore[misc]

    def chat(self, prompt: str, temperature: float | None = None) -> str:
        response = self._throttled(
            lambda: self._client.chat.completions.create(
                model=self.cfg.llm_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.cfg.llm_temperature
                if temperature is None
                else temperature,
            )
        )
        return (response.choices[0].message.content or "").strip()

    def chat_json(self, prompt: str, retries: int = 2) -> dict[str, Any]:
        """Call the LLM and parse a JSON object, retrying with the parse error appended."""
        attempt_prompt = prompt
        last_error: Exception | None = None
        for _ in range(retries + 1):
            raw = self.chat(attempt_prompt)
            try:
                return _parse_json_object(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                attempt_prompt = (
                    prompt
                    + "\n\nYour previous answer was not a valid JSON object"
                    + f" ({exc}). Return ONLY the corrected JSON object."
                )
        raise ValueError(f"LLM did not return valid JSON after retries: {last_error}")

    def embed(self, texts: list[str], batch_size: int = 64) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), batch_size):
            batch = [t[:6000] if t else " " for t in texts[start : start + batch_size]]
            response = self._throttled(
                lambda b=batch: self._client.embeddings.create(
                    model=self.cfg.embedding_model, input=b
                )
            )
            vectors.extend(item.embedding for item in response.data)
        return vectors


def _parse_json_object(raw: str) -> dict[str, Any]:
    cleaned = _JSON_FENCE.sub("", raw).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object found in response")
    parsed = json.loads(cleaned[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("top-level JSON value is not an object")
    return parsed
