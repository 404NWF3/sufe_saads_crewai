"""Shared helpers for the claude-agent-sdk x Anthropic-compatible endpoint spike.

Standalone: does NOT import the sufe_saads_crewai package. Reads provider
credentials from the repo-root .env and builds ClaudeAgentOptions presets.

Provider selection mirrors agent_runtime/client.py: INTEL_SDK_PROVIDER
(deepseek|glm) when set, else the first provider with a key (deepseek first).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions

REPO_ROOT = Path(__file__).resolve().parents[2]

PROVIDERS: dict[str, dict[str, str]] = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/anthropic",
        "key_var": "DEEPSEEK_API_KEY",
        "main": "deepseek-v4-pro",
        "fast": "deepseek-v4-flash",
        "model_var": "DEEPSEEK_MODEL",
        "fast_model_var": "DEEPSEEK_FAST_MODEL",
        # the model whose endpoint availability the matrix verifies explicitly
        "premium": "deepseek-v4-pro",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "key_var": "GLM_API_KEY",
        "main": "glm-4.7",
        "fast": "glm-4.5-air",
        "model_var": "GLM_MODEL",
        "fast_model_var": "GLM_FAST_MODEL",
        "premium": "glm-5",
    },
}

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")

# Kept for probe_keys.py (GLM-specific key prober).
GLM_ANTHROPIC_BASE_URL = PROVIDERS["glm"]["base_url"]


def load_dotenv_values(path: Path | None = None) -> dict[str, str]:
    env_path = path or (REPO_ROOT / ".env")
    values: dict[str, str] = {}
    if not env_path.is_file():
        return values
    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, raw = match.groups()
        values[key] = raw.strip().strip('"').strip("'")
    return values


def _setting(name: str) -> str:
    return os.getenv(name) or load_dotenv_values().get(name, "")


def provider_name() -> str:
    explicit = _setting("INTEL_SDK_PROVIDER").lower()
    if explicit in PROVIDERS:
        return explicit
    for name, spec in PROVIDERS.items():
        if _setting(spec["key_var"]):
            return name
    return "glm"


def provider_models() -> tuple[str, str]:
    """(main_model, fast_model) from .env with provider defaults."""
    spec = PROVIDERS[provider_name()]
    main = _setting("INTEL_SDK_MODEL") or _setting(spec["model_var"]) or spec["main"]
    fast = (
        _setting("INTEL_SDK_FAST_MODEL")
        or _setting(spec["fast_model_var"])
        or spec["fast"]
    )
    return main, fast


def premium_model() -> str:
    return PROVIDERS[provider_name()]["premium"]


# Backwards-compatible alias used by earlier spike scripts.
glm_models = provider_models


def anthropic_env() -> dict[str, str]:
    spec = PROVIDERS[provider_name()]
    api_key = _setting("ANTHROPIC_AUTH_TOKEN") or _setting(spec["key_var"])
    if not api_key:
        raise RuntimeError(
            f"{spec['key_var']} missing in .env; the spike needs a real key"
        )
    main, fast = provider_models()
    return {
        "ANTHROPIC_BASE_URL": _setting("ANTHROPIC_BASE_URL") or spec["base_url"],
        "ANTHROPIC_AUTH_TOKEN": api_key,
        # Keep the bundled CLI from picking up any host-level Anthropic auth.
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": main,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": main,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": fast,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
    }


glm_anthropic_env = anthropic_env


def base_options(
    model: str | None = None,
    max_turns: int = 6,
    **overrides: Any,
) -> ClaudeAgentOptions:
    main, _ = provider_models()
    return ClaudeAgentOptions(
        model=model or main,
        env=anthropic_env(),
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        # No filesystem settings: keep the spike hermetic and reproducible.
        setting_sources=[],
        allowed_tools=overrides.pop("allowed_tools", []),
        **overrides,
    )
