from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Literal

from crewai import LLM

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv is present in CrewAI projects.
    load_dotenv = None


GlmProfile = Literal["main", "fast", "cheap_fast"]
GLM_AGENT_KICKOFF_ENV = "INTEL_ENABLE_AGENT_KICKOFF"
DEFAULT_GLM_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"


@dataclass(frozen=True)
class GlmRuntimeConfig:
    profile: GlmProfile
    model: str
    base_url: str
    timeout: float
    max_retries: int


def load_project_env() -> None:
    if load_dotenv is not None:
        load_dotenv()


def _normalize_glm_model(model: str) -> str:
    normalized = model.strip()
    if normalized.lower().startswith("glm-"):
        return normalized.lower()
    return normalized


def _normalize_glm_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    if normalized.endswith("/chat/completions"):
        normalized = normalized[: -len("/chat/completions")]
    return normalized


def glm_runtime_config(profile: GlmProfile = "main") -> GlmRuntimeConfig:
    load_project_env()

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

    model = _normalize_glm_model(os.getenv(model_env) or fallback_model)
    base_url = _normalize_glm_base_url(os.getenv("GLM_BASE_URL") or DEFAULT_GLM_BASE_URL)
    timeout = float(os.getenv("GLM_TIMEOUT_SECONDS", "120"))
    max_retries = int(os.getenv("GLM_MAX_RETRIES", "1"))
    return GlmRuntimeConfig(
        profile=profile,
        model=model,
        base_url=base_url,
        timeout=timeout,
        max_retries=max_retries,
    )


def require_glm_api_key() -> str:
    load_project_env()
    api_key = os.getenv("GLM_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GLM_API_KEY is required for GLM-backed CrewAI runs. Set GLM_API_KEY in .env."
        )
    return api_key


def configure_glm_runtime(enable_agent_kickoff: bool = True) -> dict[str, str]:
    """Prepare environment knobs that make real runs use GLM-backed agents."""

    api_key = require_glm_api_key()
    if enable_agent_kickoff:
        os.environ[GLM_AGENT_KICKOFF_ENV] = "true"

    main_config = glm_runtime_config("main")
    fast_config = glm_runtime_config("fast")

    # Keep CrewAI or provider fallbacks from silently drifting to OpenAI defaults.
    os.environ["MODEL"] = main_config.model
    os.environ["OPENAI_MODEL_NAME"] = main_config.model
    os.environ["OPENAI_API_KEY"] = api_key
    os.environ["OPENAI_BASE_URL"] = main_config.base_url
    os.environ["OPENAI_API_BASE"] = main_config.base_url
    tracing_enabled = os.getenv("INTEL_ENABLE_CREWAI_TRACING", "false").strip().lower()
    os.environ["CREWAI_TRACING_ENABLED"] = (
        "true" if tracing_enabled in {"1", "true", "yes", "on"} else "false"
    )
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    return {
        "agent_kickoff": os.environ.get(GLM_AGENT_KICKOFF_ENV, "false"),
        "main_model": main_config.model,
        "fast_model": fast_config.model,
        "base_url": main_config.base_url,
    }


def describe_glm_runtime() -> str:
    config = configure_glm_runtime(enable_agent_kickoff=False)
    return (
        "GLM runtime: "
        f"main={config['main_model']}, "
        f"fast={config['fast_model']}, "
        f"base_url={config['base_url']}, "
        f"agent_kickoff={config['agent_kickoff']}"
    )


def build_glm_llm(profile: GlmProfile = "main") -> LLM:
    """Build an explicit GLM LLM so CrewAI never falls back to its default model."""

    config = glm_runtime_config(profile)
    api_key = require_glm_api_key()

    return LLM(
        model=config.model,
        provider="openai",
        api_key=api_key,
        base_url=config.base_url,
        api_base=config.base_url,
        temperature=0.2 if profile == "main" else 0.1,
        timeout=config.timeout,
        max_retries=config.max_retries,
        max_tokens=1400 if profile == "main" else 900,
    )
