from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any
import warnings

from pydantic import SecretStr

from .source_fetch_tools import compute_backoff_delay

LLM_TASK_NAMES = (
    "planning",
    "reflection",
    "standardization",
    "bom_resolution",
    "bom_review",
    "stix_graph",
    "stix_review",
    "dedup_merge",
    "dedup_adjudication",
    "coverage",
)

_PROFILE_STATE_LOCK = Lock()
_PROFILE_COOLDOWN_UNTIL: dict[str, float] = {}
_PROFILE_ACTIVE_COUNT: dict[str, int] = {}
_ROOT_DIR = Path(__file__).resolve().parents[4]
_LLM_PROFILES_FILENAME = "wp11_llm_profiles.json"
_LLM_ROUTE_PRESETS_FILENAME = "wp11_llm_route_presets.json"
_VALID_PROFILE_LABELS = ("cheap_fast", "balanced", "fallback")
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LlmProfile:
    profile_id: str
    profile: str
    provider: str
    model: str
    base_url: str | None
    api_key: str | None
    enabled: bool
    supports_structured_output: bool
    cost_tier: str
    max_concurrency: int
    cooldown_seconds: float


class LlmInvocationError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        error_family: str,
        retry_after_seconds: float = 0.0,
        recommended_tuning_changes: list[str] | None = None,
        attempted_profiles: list[str] | None = None,
        attempted_profile_labels: list[str] | None = None,
        failed_profile_errors: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_family = error_family
        self.retry_after_seconds = round(max(retry_after_seconds, 0.0), 3)
        self.recommended_tuning_changes = recommended_tuning_changes or []
        self.attempted_profiles = attempted_profiles or []
        self.attempted_profile_labels = attempted_profile_labels or []
        self.failed_profile_errors = failed_profile_errors or []


def _profile_log_payload(
    profile: LlmProfile,
    *,
    task_name: str,
    attempt: int | None = None,
    error_family: str | None = None,
    error: Exception | str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "task_name": task_name,
        "profile_id": profile.profile_id,
        "profile": profile.profile,
        "provider": profile.provider,
        "model": profile.model,
        "base_url": profile.base_url,
    }
    if attempt is not None:
        payload["attempt"] = attempt
    if error_family is not None:
        payload["error_family"] = error_family
    if error is not None:
        payload["error_type"] = (
            error.__class__.__name__ if isinstance(error, Exception) else "RuntimeError"
        )
        payload["error"] = str(error)[:300]
    return payload


def _read_bool_env(name: str) -> bool | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _is_dashscope_base_url(base_url: str | None) -> bool:
    if not base_url:
        return False
    lowered = base_url.strip().lower()
    return (
        "dashscope.aliyuncs.com" in lowered
        or "dashscope-intl.aliyuncs.com" in lowered
    )


def _is_qwen_thinking_family(model: str) -> bool:
    lowered = model.strip().lower()
    return lowered.startswith("qwen3") or lowered.startswith("qwen3.5")


def should_disable_thinking_for_structured_output(
    *, model: str, base_url: str | None
) -> bool:
    explicit = _read_bool_env("OPENAI_ENABLE_THINKING")
    if explicit is not None:
        return not explicit
    return _is_dashscope_base_url(base_url) and _is_qwen_thinking_family(model)


def build_structured_chat_openai(
    *,
    model: str,
    temperature: float,
    base_url: str | None,
    api_key: str | None,
) -> Any:
    from langchain_openai import ChatOpenAI

    extra_body: dict[str, Any] | None = None
    explicit_thinking = _read_bool_env("OPENAI_ENABLE_THINKING")

    if explicit_thinking is not None:
        extra_body = {"enable_thinking": explicit_thinking}
    elif should_disable_thinking_for_structured_output(
        model=model,
        base_url=base_url,
    ):
        # DashScope Qwen3/Qwen3.5 mixed-thinking models reject forced
        # `tool_choice` in thinking mode, which LangChain uses for
        # `with_structured_output(..., method="function_calling")`.
        extra_body = {"enable_thinking": False}

    return ChatOpenAI(
        model=model,
        temperature=temperature,
        base_url=base_url,
        api_key=SecretStr(api_key) if api_key else None,
        extra_body=extra_body,
    )


def _read_json_env(name: str) -> Any | None:
    raw = os.getenv(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} must be valid JSON.") from exc


def _read_json_file(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{path.name} must be valid JSON.") from exc


def _load_json_payload(
    *,
    filename: str,
    env_name: str,
) -> tuple[Any | None, dict[str, str]]:
    path = _ROOT_DIR / filename
    file_payload = _read_json_file(path)
    if file_payload is not None:
        return file_payload, {"source": "file", "path": str(path)}

    env_payload = _read_json_env(env_name)
    if env_payload is not None:
        warnings.warn(
            f"{env_name} is deprecated; prefer {filename} in the project root.",
            RuntimeWarning,
            stacklevel=3,
        )
        return env_payload, {"source": "env", "path": env_name}

    return None, {"source": "default", "path": str(path)}


def _resolve_value(raw_value: Any, env_key: str | None) -> Any:
    if raw_value is not None:
        return raw_value
    if env_key:
        return os.getenv(env_key)
    return None


def resolve_default_model(
    default_model: str | None = None,
    *,
    runtime_config: dict[str, Any] | None = None,
) -> str:
    runtime_config = runtime_config if isinstance(runtime_config, dict) else {}
    candidates = (
        default_model,
        runtime_config.get("llm_model"),
        os.getenv("OPENAI_MODEL"),
        os.getenv("OPENAI_FAST_MODEL"),
        "qwen3.5-plus",
    )
    for candidate in candidates:
        if candidate is None:
            continue
        resolved = str(candidate).strip()
        if resolved:
            return resolved
    return "qwen3.5-plus"


def _normalize_profile_id(raw_value: Any, *, idx: int) -> str:
    profile_id = str(raw_value or f"{idx + 1}").strip()
    if not profile_id:
        raise RuntimeError("LLM profile_id cannot be empty.")
    if not profile_id.isdigit():
        raise RuntimeError(
            f"LLM profile_id must be a numeric string, got {profile_id!r}."
        )
    return profile_id


def _normalize_profile_label(raw_value: Any) -> str:
    profile_label = str(raw_value or "").strip().lower()
    if profile_label not in _VALID_PROFILE_LABELS:
        raise RuntimeError(
            "LLM profile must be one of "
            + ", ".join(_VALID_PROFILE_LABELS)
            + f"; got {profile_label!r}."
        )
    return profile_label


def _preferred_default_profile_label(profiles: dict[str, LlmProfile]) -> str:
    available_labels = {
        profile.profile for profile in profiles.values() if profile.enabled
    }
    for label in ("balanced", "cheap_fast", "fallback"):
        if label in available_labels:
            return label
    raise RuntimeError("No enabled LLM profiles are available.")


def _normalize_route_labels(raw_route: Any) -> list[str]:
    normalized: list[str] = []
    for raw_label in raw_route or []:
        label = _normalize_profile_label(raw_label)
        if label not in normalized:
            normalized.append(label)
    if not normalized:
        raise RuntimeError("LLM route cannot be empty.")
    return normalized


def _profile_sort_key(profile: LlmProfile) -> tuple[int, str]:
    try:
        return int(profile.profile_id), profile.profile_id
    except ValueError:
        return 10**9, profile.profile_id


def _expand_route_labels(
    route_labels: list[str],
    profiles: dict[str, LlmProfile],
) -> list[LlmProfile]:
    expanded: list[LlmProfile] = []
    seen_profile_ids: set[str] = set()
    grouped: dict[str, list[LlmProfile]] = {
        label: sorted(
            [
                profile
                for profile in profiles.values()
                if profile.enabled and profile.profile == label
            ],
            key=_profile_sort_key,
        )
        for label in _VALID_PROFILE_LABELS
    }
    for label in route_labels:
        candidates = grouped.get(label) or []
        if not candidates:
            raise RuntimeError(
                f"LLM route references profile label {label!r}, but no enabled profile matches it."
            )
        for profile in candidates:
            if profile.profile_id in seen_profile_ids:
                continue
            seen_profile_ids.add(profile.profile_id)
            expanded.append(profile)
    return expanded


def _build_default_profile(
    *,
    default_model: str | None,
    base_url: str | None,
    api_key: str | None,
) -> LlmProfile:
    resolved_model = resolve_default_model(default_model)
    return LlmProfile(
        profile_id="100",
        profile="balanced",
        provider="openai_compatible",
        model=resolved_model,
        base_url=base_url,
        api_key=api_key,
        enabled=True,
        supports_structured_output=True,
        cost_tier="standard",
        max_concurrency=2,
        cooldown_seconds=30.0,
    )


def _load_profiles(
    *,
    default_model: str | None,
    base_url: str | None,
    api_key: str | None,
) -> tuple[dict[str, LlmProfile], dict[str, str]]:
    resolved_default_model = resolve_default_model(default_model)
    payload, source_meta = _load_json_payload(
        filename=_LLM_PROFILES_FILENAME,
        env_name="WP11_LLM_PROFILES_JSON",
    )
    if payload is None:
        default_profile = _build_default_profile(
            default_model=resolved_default_model,
            base_url=base_url,
            api_key=api_key,
        )
        return {default_profile.profile_id: default_profile}, source_meta

    rows = payload.get("profiles") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise RuntimeError("WP11_LLM_PROFILES_JSON must be a JSON array or object with profiles.")

    profiles: dict[str, LlmProfile] = {}
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            raise RuntimeError("Each LLM profile must be a JSON object.")
        profile_id = _normalize_profile_id(row.get("profile_id"), idx=idx)
        profile_label = _normalize_profile_label(row.get("profile"))
        resolved_model = str(
            _resolve_value(row.get("model"), row.get("model_env")) or resolved_default_model
        ).strip()
        if not resolved_model:
            raise RuntimeError(
                f"LLM profile {profile_id} must define model or model_env."
            )
        profile = LlmProfile(
            profile_id=profile_id,
            profile=profile_label,
            provider=str(row.get("provider") or "openai_compatible"),
            model=resolved_model,
            base_url=_resolve_value(row.get("base_url"), row.get("base_url_env")),
            api_key=_resolve_value(row.get("api_key"), row.get("api_key_env")),
            enabled=bool(row.get("enabled", True)),
            supports_structured_output=bool(
                row.get("supports_structured_output", True)
            ),
            cost_tier=str(row.get("cost_tier") or "standard"),
            max_concurrency=max(1, int(row.get("max_concurrency", 2))),
            cooldown_seconds=max(1.0, float(row.get("cooldown_seconds", 30.0))),
        )
        if profile.profile_id in profiles:
            raise RuntimeError(f"Duplicate LLM profile_id: {profile.profile_id}")
        profiles[profile.profile_id] = profile

    if not profiles:
        default_profile = _build_default_profile(
            default_model=resolved_default_model,
            base_url=base_url,
            api_key=api_key,
        )
        profiles[default_profile.profile_id] = default_profile
    return profiles, source_meta


def _default_route_presets(
    profiles: dict[str, LlmProfile],
) -> dict[str, dict[str, list[str]]]:
    default_label = _preferred_default_profile_label(profiles)
    return {
        "default": {
            task_name: [default_label] for task_name in LLM_TASK_NAMES
        }
    }


def _load_route_presets(
    profiles: dict[str, LlmProfile],
) -> tuple[dict[str, dict[str, list[str]]], dict[str, str]]:
    payload, source_meta = _load_json_payload(
        filename=_LLM_ROUTE_PRESETS_FILENAME,
        env_name="WP11_LLM_ROUTE_PRESETS_JSON",
    )
    if payload is None:
        return _default_route_presets(profiles), source_meta
    if not isinstance(payload, dict):
        raise RuntimeError("WP11_LLM_ROUTE_PRESETS_JSON must be a JSON object.")

    route_presets: dict[str, dict[str, list[str]]] = {}
    for preset_name, preset_payload in payload.items():
        if not isinstance(preset_payload, dict):
            raise RuntimeError("Each route preset must be a JSON object.")
        task_routes: dict[str, list[str]] = {}
        for task_name in LLM_TASK_NAMES:
            route = preset_payload.get(task_name) or [
                _preferred_default_profile_label(profiles)
            ]
            if not isinstance(route, list):
                raise RuntimeError("Each route preset entry must be a JSON array.")
            task_routes[task_name] = _normalize_route_labels(route)
        route_presets[str(preset_name)] = task_routes

    if "default" not in route_presets:
        route_presets["default"] = {
            task_name: [_preferred_default_profile_label(profiles)]
            for task_name in LLM_TASK_NAMES
        }
    return route_presets, source_meta


def resolve_model_pool(
    *,
    task_name: str,
    default_model: str | None,
    base_url: str | None,
    api_key: str | None,
    runtime_config: dict[str, Any] | None = None,
) -> tuple[list[LlmProfile], dict[str, Any]]:
    resolved_default_model = resolve_default_model(
        default_model,
        runtime_config=runtime_config,
    )
    profiles, profiles_source = _load_profiles(
        default_model=resolved_default_model,
        base_url=base_url,
        api_key=api_key,
    )
    route_presets, route_source = _load_route_presets(profiles)

    runtime_config = runtime_config or {}
    preset_name = str(
        runtime_config.get("llm_route_preset")
        or os.getenv("WP11_LLM_DEFAULT_ROUTE_PRESET")
        or "default"
    )
    preset = route_presets.get(preset_name) or route_presets["default"]
    task_routes = runtime_config.get("llm_task_routes") or {}
    if not isinstance(task_routes, dict):
        task_routes = {}
    configured_route = task_routes.get(task_name) or preset.get(task_name) or [
        _preferred_default_profile_label(profiles)
    ]
    route_labels = _normalize_route_labels(configured_route)
    selected_profiles = _expand_route_labels(route_labels, profiles)

    return selected_profiles, {
        "selected_preset": preset_name,
        "selected_route_labels": route_labels,
        "expanded_profile_ids": [profile.profile_id for profile in selected_profiles],
        "expanded_profile_labels": [profile.profile for profile in selected_profiles],
        "route_presets": route_presets,
        "profiles": profiles,
        "profiles_source": profiles_source,
        "route_presets_source": route_source,
        "resolved_default_model": resolved_default_model,
    }


def describe_model_pool(
    *,
    default_model: str | None,
    base_url: str | None,
    api_key: str | None,
    runtime_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime_config = runtime_config or {}
    resolved_default_model = resolve_default_model(
        default_model,
        runtime_config=runtime_config,
    )
    profiles, profiles_source = _load_profiles(
        default_model=resolved_default_model,
        base_url=base_url,
        api_key=api_key,
    )
    route_presets, route_source = _load_route_presets(profiles)
    _, route_meta = resolve_model_pool(
        task_name="standardization",
        default_model=resolved_default_model,
        base_url=base_url,
        api_key=api_key,
        runtime_config=runtime_config,
    )
    return {
        "selected_preset": route_meta["selected_preset"],
        "resolved_default_model": resolved_default_model,
        "profiles": [
            {
                "profile_id": profile.profile_id,
                "profile": profile.profile,
                "provider": profile.provider,
                "model": profile.model,
                "base_url": profile.base_url,
                "enabled": profile.enabled,
                "supports_structured_output": profile.supports_structured_output,
                "cost_tier": profile.cost_tier,
                "max_concurrency": profile.max_concurrency,
                "cooldown_seconds": profile.cooldown_seconds,
                "has_api_key": bool(profile.api_key),
            }
            for profile in sorted(profiles.values(), key=_profile_sort_key)
        ],
        "profiles_source": profiles_source,
        "route_presets_source": route_source,
        "route_presets": route_presets,
        "selected_route_labels": route_meta["selected_route_labels"],
        "expanded_profile_ids": route_meta["expanded_profile_ids"],
        "expanded_profile_labels": route_meta["expanded_profile_labels"],
    }


def recommended_task_concurrency(
    *,
    task_name: str,
    default_model: str | None,
    base_url: str | None,
    api_key: str | None,
    runtime_config: dict[str, Any] | None = None,
    upper_bound: int = 32,
) -> int:
    profiles, _ = resolve_model_pool(
        task_name=task_name,
        default_model=default_model,
        base_url=base_url,
        api_key=api_key,
        runtime_config=runtime_config,
    )
    budget = sum(
        max(1, int(profile.max_concurrency))
        for profile in profiles
        if profile.supports_structured_output
        and profile.enabled
        and (profile.api_key or profile.base_url)
    )
    if budget <= 0:
        budget = 1
    return max(1, min(int(upper_bound), budget))


def list_available_profile_ids(
    *,
    task_name: str,
    default_model: str | None,
    base_url: str | None,
    api_key: str | None,
    runtime_config: dict[str, Any] | None = None,
) -> list[str]:
    profiles, _ = resolve_model_pool(
        task_name=task_name,
        default_model=default_model,
        base_url=base_url,
        api_key=api_key,
        runtime_config=runtime_config,
    )
    return [profile.profile_id for profile in profiles if profile.api_key or profile.base_url]


def _extract_status_code(exc: Exception) -> int | None:
    for attr_name in ("status_code", "status"):
        raw = getattr(exc, attr_name, None)
        if isinstance(raw, int):
            return raw
    response = getattr(exc, "response", None)
    if response is not None:
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int):
            return status_code
    message = str(exc).lower()
    for code in (429, 408, 401, 403, 400, 422, 500, 502, 503, 504):
        if f"{code}" in message:
            return code
    return None


def classify_llm_error(exc: Exception) -> str:
    class_name = exc.__class__.__name__.lower()
    message = str(exc).lower()
    status_code = _extract_status_code(exc)

    if "ratelimit" in class_name or status_code == 429 or "rate limit" in message:
        return "rate_limit"
    if "timeout" in class_name or status_code == 408:
        return "timeout"
    if any(token in class_name for token in ("connection", "apierror", "internalserver")):
        return "transient"
    if status_code in {500, 502, 503, 504}:
        return "transient"
    if status_code in {401, 403} or "api key" in message or "unauthorized" in message:
        return "auth"
    if status_code in {400, 404, 409, 422}:
        return "invalid_request"
    if "tool_choice" in message or "structured output" in message:
        return "invalid_request"
    return "fatal"


def _is_retryable_family(error_family: str) -> bool:
    return error_family in {"rate_limit", "timeout", "transient"}


def _cooldown_remaining_seconds(profile_id: str) -> float:
    with _PROFILE_STATE_LOCK:
        until = _PROFILE_COOLDOWN_UNTIL.get(profile_id, 0.0)
    return max(0.0, until - time.time())


def _mark_profile_cooldown(profile_id: str, cooldown_seconds: float) -> None:
    with _PROFILE_STATE_LOCK:
        _PROFILE_COOLDOWN_UNTIL[profile_id] = max(
            _PROFILE_COOLDOWN_UNTIL.get(profile_id, 0.0),
            time.time() + cooldown_seconds,
        )


def _try_acquire_profile_slot(profile: LlmProfile) -> bool:
    with _PROFILE_STATE_LOCK:
        active = _PROFILE_ACTIVE_COUNT.get(profile.profile_id, 0)
        if active >= max(1, profile.max_concurrency):
            return False
        _PROFILE_ACTIVE_COUNT[profile.profile_id] = active + 1
        return True


def _release_profile_slot(profile_id: str) -> None:
    with _PROFILE_STATE_LOCK:
        active = _PROFILE_ACTIVE_COUNT.get(profile_id, 0)
        if active <= 1:
            _PROFILE_ACTIVE_COUNT.pop(profile_id, None)
            return
        _PROFILE_ACTIVE_COUNT[profile_id] = active - 1


def _acquire_profile_slot_with_wait(
    profile: LlmProfile,
    *,
    max_wait_seconds: float,
    poll_interval_seconds: float = 0.25,
) -> float | None:
    if _try_acquire_profile_slot(profile):
        return 0.0
    if max_wait_seconds <= 0:
        return None

    deadline = time.monotonic() + max_wait_seconds
    waited_seconds = 0.0
    while time.monotonic() < deadline:
        sleep_seconds = min(
            poll_interval_seconds,
            max(0.0, deadline - time.monotonic()),
        )
        if sleep_seconds <= 0:
            break
        time.sleep(sleep_seconds)
        waited_seconds += sleep_seconds
        if _try_acquire_profile_slot(profile):
            return round(waited_seconds, 3)
    return None


def invoke_structured_with_model_pool(
    *,
    task_name: str,
    prompt: Any,
    schema: type[Any],
    payload: dict[str, Any],
    default_model: str | None,
    temperature: float,
    base_url: str | None,
    api_key: str | None,
    runtime_config: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime_config = runtime_config or {}
    retry_attempts = int(runtime_config.get("llm_retry_attempts", 3) or 3)
    backoff_base = float(runtime_config.get("llm_backoff_base_seconds", 2.0) or 2.0)
    backoff_max = float(runtime_config.get("llm_backoff_max_seconds", 30.0) or 30.0)
    short_wait_threshold = float(
        runtime_config.get("llm_short_wait_threshold_seconds", 60.0) or 60.0
    )
    profiles, route_meta = resolve_model_pool(
        task_name=task_name,
        default_model=default_model,
        base_url=base_url,
        api_key=api_key,
        runtime_config=runtime_config,
    )
    errors: list[str] = []
    total_wait_seconds = 0.0
    attempted_profiles: list[str] = []
    attempted_profile_labels: list[str] = []
    failed_profile_errors: list[dict[str, Any]] = []
    suggested_retry_after = 0.0

    for profile in profiles:
        if not profile.api_key and not profile.base_url:
            failure_payload = _profile_log_payload(
                profile,
                task_name=task_name,
                error_family="config_missing",
                error="profile has neither api_key nor base_url configured",
            )
            failed_profile_errors.append(failure_payload)
            errors.append(
                f"{profile.profile_id}/{profile.profile}: missing api_key/base_url configuration"
            )
            _LOGGER.error("wp11_llm_profile_invalid_config %s", failure_payload)
            continue
        if not profile.supports_structured_output:
            errors.append(
                f"{profile.profile_id}/{profile.profile}: structured output not supported"
            )
            continue

        cooldown_remaining = _cooldown_remaining_seconds(profile.profile_id)
        if cooldown_remaining > 0:
            suggested_retry_after = max(suggested_retry_after, cooldown_remaining)
            errors.append(
                f"{profile.profile_id}/{profile.profile}: cooling down for {cooldown_remaining:.1f}s"
            )
            _LOGGER.warning(
                "wp11_llm_profile_skipped_cooldown %s",
                _profile_log_payload(
                    profile,
                    task_name=task_name,
                    error_family="cooldown",
                    error=f"cooling down for {cooldown_remaining:.1f}s",
                ),
            )
            continue
        slot_waited_seconds = _acquire_profile_slot_with_wait(
            profile,
            max_wait_seconds=short_wait_threshold,
        )
        if slot_waited_seconds is None:
            suggested_retry_after = max(suggested_retry_after, short_wait_threshold)
            errors.append(
                f"{profile.profile_id}/{profile.profile}: max_concurrency {profile.max_concurrency} reached"
            )
            _LOGGER.warning(
                "wp11_llm_profile_skipped_capacity %s",
                _profile_log_payload(
                    profile,
                    task_name=task_name,
                    error_family="capacity",
                    error=f"max_concurrency {profile.max_concurrency} reached",
                ),
            )
            continue
        total_wait_seconds += slot_waited_seconds

        attempted_profiles.append(profile.profile_id)
        attempted_profile_labels.append(profile.profile)
        try:
            for attempt in range(1, retry_attempts + 1):
                try:
                    llm = build_structured_chat_openai(
                        model=profile.model,
                        temperature=temperature,
                        base_url=profile.base_url,
                        api_key=profile.api_key,
                    )
                    structured_llm = llm.with_structured_output(
                        schema, method="function_calling"
                    )
                    chain = prompt | structured_llm
                    result = chain.invoke(payload)
                    if isinstance(result, schema):
                        validated = result.model_dump(mode="python")
                    else:
                        validated = schema.model_validate(result).model_dump(
                            mode="python"
                        )
                    return validated, {
                        "profile_id": profile.profile_id,
                        "profile": profile.profile,
                        "provider": profile.provider,
                        "llm_model": profile.model,
                        "base_url": profile.base_url,
                        "attempts": attempt,
                        "wait_seconds": round(total_wait_seconds, 3),
                        "selected_preset": route_meta["selected_preset"],
                        "selected_route_labels": route_meta["selected_route_labels"],
                        "attempted_profiles": attempted_profiles,
                        "attempted_profile_labels": attempted_profile_labels,
                        "failed_profile_errors": failed_profile_errors,
                    }
                except Exception as exc:
                    error_family = classify_llm_error(exc)
                    message = (
                        f"{profile.profile_id}/{profile.profile}:{error_family}:{type(exc).__name__}:"
                        f"{str(exc)[:220]}"
                    )
                    failure_payload = _profile_log_payload(
                        profile,
                        task_name=task_name,
                        attempt=attempt,
                        error_family=error_family,
                        error=exc,
                    )
                    failed_profile_errors.append(failure_payload)
                    _LOGGER.error("wp11_llm_profile_failed %s", failure_payload)
                    if _is_retryable_family(error_family) and attempt < retry_attempts:
                        wait_seconds = min(
                            backoff_max,
                            compute_backoff_delay(backoff_base, attempt),
                        )
                        if wait_seconds <= short_wait_threshold:
                            total_wait_seconds += wait_seconds
                            time.sleep(wait_seconds)
                            continue
                        _mark_profile_cooldown(
                            profile.profile_id,
                            max(profile.cooldown_seconds, wait_seconds),
                        )
                        suggested_retry_after = max(
                            suggested_retry_after,
                            wait_seconds,
                        )
                        errors.append(
                            f"{message}:deferred_wait={round(wait_seconds, 3)}s"
                        )
                        break

                    if error_family in {"rate_limit", "timeout", "transient"}:
                        cooldown_seconds = max(
                            profile.cooldown_seconds,
                            min(backoff_max, max(backoff_base, short_wait_threshold)),
                        )
                        _mark_profile_cooldown(
                            profile.profile_id,
                            cooldown_seconds,
                        )
                        suggested_retry_after = max(
                            suggested_retry_after,
                            cooldown_seconds,
                        )
                    errors.append(message)
                    break
        finally:
            _release_profile_slot(profile.profile_id)

    recommended_changes = [
        "lower standardization_max_concurrency",
        "reduce source max_results",
        "switch llm_route_preset or llm_task_routes",
    ]
    retry_after = max(
        total_wait_seconds,
        suggested_retry_after,
        max(
            (_cooldown_remaining_seconds(profile.profile_id) for profile in profiles),
            default=0.0,
        ),
    )
    raise LlmInvocationError(
        "All configured LLM profiles were exhausted or unavailable for structured output. "
        + " | ".join(errors[-6:]),
        error_family="pool_exhausted",
        retry_after_seconds=retry_after,
        recommended_tuning_changes=recommended_changes,
        attempted_profiles=attempted_profiles,
        attempted_profile_labels=attempted_profile_labels,
        failed_profile_errors=failed_profile_errors,
    )
