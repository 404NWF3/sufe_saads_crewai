from __future__ import annotations

import os
from typing import Literal

from crewai import LLM

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv is present in CrewAI projects.
    load_dotenv = None


GlmProfile = Literal["main", "fast", "cheap_fast"]


def build_glm_llm(profile: GlmProfile = "main") -> LLM:
    """Build an explicit GLM LLM so CrewAI never falls back to its default model."""

    if load_dotenv is not None:
        load_dotenv()

    model_env = {
        "main": "GLM_MODEL",
        "fast": "GLM_FAST_MODEL",
        "cheap_fast": "GLM_CHEAP_FAST_MODEL",
    }[profile]
    fallback_model = {
        "main": "glm-5",
        "fast": "glm-4.7-flash",
        "cheap_fast": "glm-4.7-flash",
    }[profile]

    model = os.getenv(model_env) or fallback_model
    api_key = os.getenv("GLM_API_KEY")
    base_url = os.getenv("GLM_BASE_URL") or "https://open.bigmodel.cn/api/coding/paas/v4"
    timeout = float(os.getenv("GLM_TIMEOUT_SECONDS", "30"))
    max_retries = int(os.getenv("GLM_MAX_RETRIES", "0"))
    if not api_key:
        raise RuntimeError(
            "GLM_API_KEY is required for crewai run. Set GLM_API_KEY in .env."
        )

    return LLM(
        model=model,
        provider="openai",
        api_key=api_key,
        base_url=base_url,
        api_base=base_url,
        temperature=0.2 if profile == "main" else 0.1,
        timeout=timeout,
        max_retries=max_retries,
        max_tokens=1400 if profile == "main" else 900,
    )
