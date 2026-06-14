"""claude-agent-sdk runtime factory for Anthropic-compatible endpoints.

Supported providers (INTEL_SDK_PROVIDER, auto-detected when unset):
- deepseek: https://api.deepseek.com/anthropic (deepseek-v4-pro / deepseek-v4-flash)
- glm: https://open.bigmodel.cn/api/anthropic (requires an active Coding Plan)
An explicit ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN pair overrides both.

All claude_agent_sdk imports are lazy: the sufe_saads_crewai package must work
(and the rules engine must run) without the `agentsdk` dependency group.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

GLM_ANTHROPIC_BASE_URL = "https://open.bigmodel.cn/api/anthropic"
DEEPSEEK_ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    base_url: str
    key_var: str
    default_main_model: str
    default_fast_model: str
    model_var: str
    fast_model_var: str


PROVIDERS: dict[str, ProviderSpec] = {
    "deepseek": ProviderSpec(
        name="deepseek",
        base_url=DEEPSEEK_ANTHROPIC_BASE_URL,
        key_var="DEEPSEEK_API_KEY",
        default_main_model="deepseek-v4-pro",
        default_fast_model="deepseek-v4-flash",
        model_var="DEEPSEEK_MODEL",
        fast_model_var="DEEPSEEK_FAST_MODEL",
    ),
    "glm": ProviderSpec(
        name="glm",
        base_url=GLM_ANTHROPIC_BASE_URL,
        key_var="GLM_API_KEY",
        default_main_model="glm-4.7",
        default_fast_model="glm-4.5-air",
        model_var="GLM_MODEL",
        fast_model_var="GLM_FAST_MODEL",
    ),
}


@lru_cache(maxsize=1)
def _dotenv_values() -> dict[str, str]:
    env_path = Path.cwd() / ".env"
    values: dict[str, str] = {}
    if not env_path.is_file():
        return values
    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if match:
            key, raw = match.groups()
            values[key] = raw.strip().strip('"').strip("'")
    return values


def _setting(name: str, default: str = "") -> str:
    return os.getenv(name) or _dotenv_values().get(name, "") or default


def selected_provider() -> ProviderSpec:
    """Resolve the active provider: explicit choice, else first one with a key."""
    explicit = _setting("INTEL_SDK_PROVIDER").lower()
    if explicit:
        if explicit not in PROVIDERS:
            raise ValueError(
                f"INTEL_SDK_PROVIDER={explicit!r} is not one of {sorted(PROVIDERS)}"
            )
        return PROVIDERS[explicit]
    for spec in PROVIDERS.values():
        if _setting(spec.key_var):
            return spec
    return PROVIDERS["glm"]


def main_model() -> str:
    spec = selected_provider()
    return (
        _setting("INTEL_SDK_MODEL")
        or _setting(spec.model_var)
        or spec.default_main_model
    )


def fast_model() -> str:
    spec = selected_provider()
    return (
        _setting("INTEL_SDK_FAST_MODEL")
        or _setting(spec.fast_model_var)
        or spec.default_fast_model
    )


def api_key() -> str:
    return _setting("ANTHROPIC_AUTH_TOKEN") or _setting(selected_provider().key_var)


def base_url() -> str:
    return _setting("ANTHROPIC_BASE_URL") or selected_provider().base_url


def anthropic_env() -> dict[str, str]:
    """Environment injected into the bundled CLI subprocess (roadmap 3.3)."""
    return {
        "ANTHROPIC_BASE_URL": base_url(),
        "ANTHROPIC_AUTH_TOKEN": api_key(),
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": main_model(),
        "ANTHROPIC_DEFAULT_SONNET_MODEL": main_model(),
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": fast_model(),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
    }


# Backwards-compatible alias (pre-provider name).
glm_anthropic_env = anthropic_env


def sdk_runtime_available() -> tuple[bool, str]:
    """Engine-level availability probe (cheap: no network call)."""
    if not api_key():
        spec = selected_provider()
        return False, f"missing {spec.key_var} / ANTHROPIC_AUTH_TOKEN ({spec.name})"
    try:
        import claude_agent_sdk  # noqa: F401
    except ImportError:
        return False, "claude-agent-sdk not installed (uv sync --group agentsdk)"
    return True, "ok"


def build_options(
    model: str | None = None,
    max_turns: int = 6,
    system_prompt: str | None = None,
    mcp_servers: dict[str, Any] | None = None,
    allowed_tools: list[str] | None = None,
    hooks: dict[str, Any] | None = None,
) -> Any:
    from claude_agent_sdk import ClaudeAgentOptions

    # Note: ClaudeAgentOptions exposes no `temperature`/sampling field (only model,
    # extra_args, settings, effort, thinking), and the DeepSeek reasoning model
    # ignores temperature anyway, so decision-sampling temperature is not
    # controllable here. Run-to-run variance is instead reduced by the coverage
    # gate (deterministic stop, intel/sdk_loop) and per-repeat bandit isolation
    # (scripts/eval_ab.py).
    return ClaudeAgentOptions(
        model=model or main_model(),
        env=anthropic_env(),
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        setting_sources=[],
        system_prompt=system_prompt,
        mcp_servers=mcp_servers or {},
        allowed_tools=allowed_tools or [],
        hooks=hooks,
    )
