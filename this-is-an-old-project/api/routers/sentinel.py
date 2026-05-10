"""Sentinel workspace bridge router for the dashboard."""
from __future__ import annotations


import asyncio
import contextlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
import httpx
from pydantic import BaseModel

router = APIRouter(prefix="/api/sentinel", tags=["sentinel"])

_DEFAULT_AGENT_ID = "llm-security-intel"
_DEFAULT_WORKSPACE = Path.home() / ".openclaw" / "workspace-llm-security-intel"
_DEFAULT_CONFIG = Path.home() / ".openclaw" / "openclaw.json"
_MAX_HISTORY = 1200
_MAX_RUNS = 20
_TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}

_COLLECTOR_COMMANDS: dict[str, list[str]] = {
    "full": ["src/other/daily_run.py"],
    "nvd": ["src/collectors/nvd_collector.py", "--days", "1", "--max-results", "200"],
    "github": [
        "src/collectors/github_collector.py",
        "--days",
        "1",
        "--max-results",
        "100",
        "--ai-mode",
    ],
    "arxiv": ["src/collectors/arxiv_collector.py", "--days", "7", "--max-results", "20"],
    "community": [
        "src/collectors/community_collector.py",
        "--hours",
        "24",
        "--source",
        "hackernews,reddit",
    ],
}

_COLLECTOR_NODE_NAMES: dict[str, str] = {
    "full": "daily_run",
    "nvd": "nvd_collector",
    "github": "github_collector",
    "arxiv": "arxiv_collector",
    "community": "community_collector",
}

_COLLECT_MODE_DESCRIPTIONS: dict[str, str] = {
    "full": "Collect NVD, GitHub Advisory, arXiv, and community intelligence.",
    "nvd": "Collect the latest NVD / CVE intelligence.",
    "github": "Collect GitHub Security Advisory intelligence.",
    "arxiv": "Collect AI security related arXiv papers and research updates.",
    "community": "Collect community security signals from sources like Hacker News and Reddit.",
}



def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _ensure_offset(dt_str: str) -> str:
    if dt_str and "+" not in dt_str and not dt_str.endswith("Z"):
        return dt_str + "+00:00"
    return dt_str


def _ms_to_iso(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc).isoformat()
    if isinstance(value, str) and value:
        return _ensure_offset(value)
    return _now_iso()


def _same_path(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
        os.path.normpath(str(right))
    )


def _parse_window_hours(window: str) -> int:
    if match := re.match(r"(\d+)h$", window):
        return int(match.group(1))
    if match := re.match(r"(\d+)d$", window):
        return int(match.group(1)) * 24
    return 48


def _latest_daily_file(workspace_root: Path) -> Path | None:
    files = sorted((workspace_root / "kb" / "daily").glob("ai-threat-*.json"))
    return files[-1] if files else None


def _latest_memory_file(workspace_root: Path) -> Path | None:
    date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}\.md$")
    files = sorted(
        f for f in (workspace_root / "memory").glob("*.md") if date_pattern.match(f.name)
    )
    return files[-1] if files else None


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _read_coverage_snapshot(workspace_root: Path) -> dict[str, Any]:
    return _read_json_file(workspace_root / "kb" / "output" / "coverage-snapshot.json")


def _read_daily_intel(path: Path) -> dict[str, Any]:
    return _read_json_file(path)


def _owasp_coverage_pct(snapshot: dict[str, Any]) -> float:
    taxonomy = snapshot.get("dimensions", {}).get("taxonomy_source", {})
    covered = sum(
        1
        for category in taxonomy.values()
        if isinstance(category, dict) and category.get("total", 0) > 0
    )
    return round(min(covered, 10) / 10.0 * 100, 1)


def _intel_count(daily: dict[str, Any]) -> int:
    return int(daily.get("ai_related_count", 0) or 0)


def _high_risk_count(daily: dict[str, Any]) -> int:
    return sum(1 for item in daily.get("top5", []) if (item.get("cvss_score") or 0) >= 7.0)


def _derive_gateway_http_url(config: dict[str, Any]) -> str:
    gateway = config.get("gateway") or {}
    port = gateway.get("port") or 18789
    bind = gateway.get("bind") or "loopback"
    if bind in {"loopback", "localhost", "0.0.0.0", "::"}:
        host = "127.0.0.1"
    else:
        host = str(bind)
    return f"http://{host}:{port}"


def _http_to_ws(url: str) -> str:
    parsed = urlparse(url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunparse(parsed._replace(scheme=scheme))


def _responses_url(http_url: str) -> str:
    return http_url.rstrip("/") + "/v1/responses"


def _models_url(http_url: str) -> str:
    return http_url.rstrip("/") + "/v1/models"


def _extract_gateway_token(config: dict[str, Any]) -> str | None:
    gateway = config.get("gateway") or {}
    auth = gateway.get("auth") or {}
    token = auth.get("token")
    return str(token) if token else None


def _format_gateway_scope_error(detail: Any) -> str:
    text = str(detail or "rpc failed")
    match = re.search(r"missing scope:\s*([A-Za-z0-9_.*:-]+)", text, re.IGNORECASE)
    if not match:
        return text

    missing_scope = match.group(1)
    guidance = (
        f"gateway token is missing {missing_scope}; configure OPENCLAW_GATEWAY_TOKEN "
        "with operator.read/operator.write and avoid reusing OPENCLAW_HOOKS_TOKEN "
        "for Gateway operator RPC"
    )
    if guidance.lower() in text.lower():
        return text
    return f"{text}; {guidance}"


@dataclass(slots=True)
class OpenClawSettings:
    config_path: Path
    config_exists: bool
    config_error: str | None
    workspace_root: Path
    workspace_exists: bool
    workspace_source: str
    agent_id: str
    agent_configured: bool
    agent_workspace: Path | None
    agent_workspace_matches: bool
    gateway_http_url: str
    gateway_responses_url: str
    gateway_ws_url: str
    gateway_token: str | None
    gateway_token_source: str | None
    hooks_enabled: bool
    hook_mapping_present: bool


def _load_openclaw_settings() -> OpenClawSettings:
    config_path = Path(os.getenv("OPENCLAW_CONFIG_PATH", str(_DEFAULT_CONFIG)))
    config_exists = config_path.exists()
    config_error: str | None = None
    config: dict[str, Any] = {}

    if config_exists:
        try:
            config = json.loads(config_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            config_error = f"failed to parse {config_path.name}: {exc}"

    agent_id = os.getenv("OPENCLAW_AGENT_ID", _DEFAULT_AGENT_ID)
    agent_list = (config.get("agents") or {}).get("list") or []
    agent_entry = next(
        (
            item
            for item in agent_list
            if isinstance(item, dict) and str(item.get("id")) == agent_id
        ),
        None,
    )
    agent_workspace = Path(agent_entry["workspace"]) if agent_entry and agent_entry.get("workspace") else None
    workspace_env = os.getenv("SENTINEL_WORKSPACE_ROOT")
    workspace_root = Path(workspace_env) if workspace_env else (agent_workspace or _DEFAULT_WORKSPACE)
    workspace_source = "env" if workspace_env else "openclaw-config"
    hooks = config.get("hooks") or {}
    mappings = hooks.get("mappings") or []

    hook_mapping_present = any(
        isinstance(item, dict)
        and (
            item.get("agentId") == agent_id
            or item.get("id") == "sentinel-collect"
            or (item.get("match") or {}).get("path") == "sentinel-collect"
        )
        for item in mappings
    )

    gateway_http_url = os.getenv("OPENCLAW_GATEWAY_URL") or _derive_gateway_http_url(config)
    gateway_token = os.getenv("OPENCLAW_GATEWAY_TOKEN")
    gateway_token_source = "env:OPENCLAW_GATEWAY_TOKEN" if gateway_token else None
    if not gateway_token:
        gateway_token = _extract_gateway_token(config)
        gateway_token_source = "config:gateway.auth.token" if gateway_token else None
    return OpenClawSettings(
        config_path=config_path,
        config_exists=config_exists,
        config_error=config_error,
        workspace_root=workspace_root,
        workspace_exists=workspace_root.exists(),
        workspace_source=workspace_source,
        agent_id=agent_id,
        agent_configured=agent_entry is not None,
        agent_workspace=agent_workspace,
        agent_workspace_matches=_same_path(workspace_root, agent_workspace),
        gateway_http_url=gateway_http_url,
        gateway_responses_url=_responses_url(gateway_http_url),
        gateway_ws_url=_http_to_ws(gateway_http_url),
        gateway_token=gateway_token,
        gateway_token_source=gateway_token_source,
        hooks_enabled=bool(hooks.get("enabled")),
        hook_mapping_present=hook_mapping_present,
    )


class OpenClawResponsesError(RuntimeError):
    """Raised when the OpenClaw HTTP Responses surface is unavailable."""


class OpenClawResponsesClient:
    """HTTP client for the OpenClaw `/v1/responses` and `/v1/models` endpoints."""

    def __init__(self, settings: OpenClawSettings):
        self.settings = settings
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=None, write=30.0, pool=10.0),
            follow_redirects=False,
        )

    async def __aenter__(self) -> OpenClawResponsesClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self.client.aclose()

    def _auth_headers(self) -> dict[str, str]:
        if not self.settings.gateway_token:
            raise OpenClawResponsesError("gateway token is missing")
        return {"Authorization": f"Bearer {self.settings.gateway_token}"}

    async def probe_models(self) -> dict[str, Any]:
        response: httpx.Response | None = None
        try:
            response = await self.client.get(
                _models_url(self.settings.gateway_http_url),
                headers=self._auth_headers(),
                timeout=httpx.Timeout(connect=10.0, read=10.0, write=10.0, pool=10.0),
            )
        except httpx.HTTPError as exc:
            raise OpenClawResponsesError(
                f"failed to connect to {self.settings.gateway_responses_url}: {exc}"
            ) from exc

        content_type = (response.headers.get("content-type") or "").lower()
        probe: dict[str, Any] = {
            "reachable": True,
            "status_code": response.status_code,
            "content_type": content_type,
            "models_ready": False,
            "model_ids": [],
            "server_version": response.headers.get("x-openclaw-version"),
        }

        if "application/json" not in content_type:
            return probe

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise OpenClawResponsesError(f"/v1/models returned invalid JSON: {exc}") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, list):
            probe["model_ids"] = [
                str(item.get("id"))
                for item in data
                if isinstance(item, dict) and item.get("id")
            ]
            probe["models_ready"] = response.status_code == 200
        return probe

    async def complete_response(
        self,
        *,
        agent_id: str,
        message: str,
    ) -> dict[str, Any]:
        headers = {
            **self._auth_headers(),
            "Content-Type": "application/json",
            "x-openclaw-agent-id": agent_id,
        }
        payload = {
            "model": "openclaw",
            "input": message,
        }
        try:
            response = await self.client.post(
                self.settings.gateway_responses_url,
                headers=headers,
                json=payload,
            )
            if response.status_code >= 400:
                raise OpenClawResponsesError(
                    f"/v1/responses failed: {await _read_openclaw_http_error(response)}"
                )
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise OpenClawResponsesError(f"/v1/responses returned invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise OpenClawResponsesError("/v1/responses returned a non-object payload")
            return payload
        except httpx.HTTPError as exc:
            raise OpenClawResponsesError(
                f"failed to call {self.settings.gateway_responses_url}: {exc}"
            ) from exc


async def _read_openclaw_http_error(response: httpx.Response) -> str:
    body = (await response.aread()).decode("utf-8", errors="replace").strip()
    content_type = (response.headers.get("content-type") or "").lower()
    if "application/json" in content_type and body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict) and error.get("message"):
                return f"HTTP {response.status_code}: {error['message']}"
    if body:
        snippet = body[:240].replace("\r", " ").replace("\n", " ")
        return f"HTTP {response.status_code}: {snippet}"
    return f"HTTP {response.status_code}"


def _flush_sse_data_lines(data_lines: list[str]) -> dict[str, Any] | str | None:
    if not data_lines:
        return None
    raw = "\n".join(data_lines)
    data_lines.clear()
    if raw == "[DONE]":
        return raw
    return json.loads(raw)


def _expected_openclaw_model_ids(agent_id: str) -> set[str]:
    return {"openclaw", "openclaw/default", f"openclaw/{agent_id}"}


@dataclass(slots=True)
class SentinelEvent:
    index: int
    payload: dict[str, Any]


@dataclass(slots=True)
class SentinelRun:
    run_id: str
    mode: str
    transport: str
    status: str
    started_at: str
    use_gateway: bool
    process: asyncio.subprocess.Process | None = None
    task: asyncio.Task[None] | None = None
    ended_at: str | None = None
    error: str | None = None
    gateway_run_id: str | None = None
    session_key: str | None = None
    assistant_buffer: str = ""
    assistant_text: str = ""
    cancel_requested: bool = False
    event_index: int = 0
    history: list[SentinelEvent] = field(default_factory=list)
    updated: asyncio.Event = field(default_factory=asyncio.Event)
    finished: asyncio.Event = field(default_factory=asyncio.Event)

    def add_event(self, payload: dict[str, Any]) -> None:
        self.event_index += 1
        self.history.append(SentinelEvent(index=self.event_index, payload=payload))
        if len(self.history) > _MAX_HISTORY:
            self.history = self.history[-_MAX_HISTORY:]
        self.updated.set()


_runs: dict[str, SentinelRun] = {}
_run_order: list[str] = []
_active_run_id: str | None = None
_runs_lock = asyncio.Lock()


def _run_summary(run: SentinelRun) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "status": run.status,
        "mode": run.mode,
        "transport": run.transport,
        "use_gateway": run.use_gateway,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "error": run.error,
        "gateway_run_id": run.gateway_run_id,
        "session_key": run.session_key,
        "assistant_markdown": run.assistant_text or None,
    }


def _get_run(run_id: str) -> SentinelRun | None:
    return _runs.get(run_id)


def _get_active_run() -> SentinelRun | None:
    return _runs.get(_active_run_id) if _active_run_id else None


def _get_latest_run() -> SentinelRun | None:
    while _run_order:
        run_id = _run_order[-1]
        run = _runs.get(run_id)
        if run is not None:
            return run
        _run_order.pop()
    return None


def _trim_runs_locked() -> None:
    while len(_run_order) > _MAX_RUNS:
        oldest_id = _run_order.pop(0)
        if oldest_id == _active_run_id:
            _run_order.insert(0, oldest_id)
            break
        _runs.pop(oldest_id, None)


async def _finish_run(run: SentinelRun, status: str, error: str | None = None) -> None:
    run.status = status
    run.error = error
    run.ended_at = _now_iso()

    if run.assistant_buffer.strip():
        _emit_assistant_line(run, run.assistant_buffer, run.ended_at)
        run.assistant_buffer = ""

    if error:
        run.add_event(
            {
                "type": "error",
                "node": "sentinel",
                "message": error,
                "ts": run.ended_at,
            }
        )

    run.add_event(
        {
            "type": "done",
            "status": "succeeded" if status == "succeeded" else ("cancelled" if status == "cancelled" else "failed"),
            "percent": 100,
        }
    )
    run.finished.set()
    run.updated.set()

    async with _runs_lock:
        global _active_run_id
        if _active_run_id == run.run_id:
            _active_run_id = None
        _trim_runs_locked()


async def _register_run(mode: str, transport: str) -> SentinelRun:
    async with _runs_lock:
        global _active_run_id
        active = _get_active_run()
        if active and active.status not in _TERMINAL_STATUSES:
            raise HTTPException(status_code=409, detail="宸叉湁 Sentinel 閲囬泦浠诲姟姝ｅ湪杩愯")

        run = SentinelRun(
            run_id=uuid.uuid4().hex[:8],
            mode=mode,
            transport=transport,
            status="starting",
            started_at=_now_iso(),
            use_gateway=transport == "openclaw",
        )
        _runs[run.run_id] = run
        _run_order.append(run.run_id)
        _active_run_id = run.run_id
        _trim_runs_locked()
        return run


def _build_openclaw_command(mode: str, workspace_root: Path) -> str:
    python_bin = _build_subprocess_python(workspace_root)
    args = _COLLECTOR_COMMANDS.get(mode)
    if not args:
        raise ValueError(f"unsupported Sentinel mode: {mode}")
    return " ".join([str(python_bin), *(str(part) for part in args)])


def _build_openclaw_message(mode: str, workspace_root: Path) -> str:
    task = {
        "full": "sentinel，为我收集最近7天与大模型攻击相关的情报，重点覆盖 NVD、GitHub Advisory、arXiv 和社区讨论。",
        "nvd": "sentinel，为我收集最近7天与大模型攻击相关、且可从 NVD / CVE 侧验证的情报。",
        "github": "sentinel，为我收集最近7天与大模型攻击相关、侧重 GitHub Security Advisory 与 PoC 的情报。",
        "arxiv": "sentinel，为我收集最近7天与大模型攻击相关、侧重 arXiv 论文与研究进展的情报。",
        "community": "sentinel，为我收集最近7天与大模型攻击相关、侧重社区讨论与实战案例的情报。",
    }.get(mode, f"sentinel，为我收集最近7天与 {mode} 相关的安全情报。")
    stage = {
        "full": "正在收集最近7天与大模型攻击相关的情报",
        "nvd": "正在收集最近7天与大模型攻击相关的 NVD / CVE 情报",
        "github": "正在收集最近7天与大模型攻击相关的 GitHub Advisory 情报",
        "arxiv": "正在收集最近7天与大模型攻击相关的 arXiv 研究情报",
        "community": "正在收集最近7天与大模型攻击相关的社区情报",
    }.get(mode, f"正在收集最近7天与 {mode} 相关的安全情报")
    return (
        f"{task}\n"
        f"当前 workspace: {workspace_root}\n"
        "你可以自由使用当前环境中可用的 skills、原生搜索工具、workspace 内已有脚本，以及其他必要工具。"
        "不要求先读取 skill 文件，也不要求固定执行某一条命令；请根据实际情况自行决定研究路径。\n"
        "如果你判断直接运行 workspace 中的采集脚本更合适，可以自行执行，但这不是硬性要求。\n"
        f"最终请使用中文回复。第一行必须严格输出：[STATUS] {stage}\n"
        "随后给出简洁总结，说明你使用了哪些来源或工具、有哪些关键发现，以及失败时的具体错误。"
    )


def _build_subprocess_python(workspace_root: Path) -> Path:
    windows = workspace_root / ".venv" / "Scripts" / "python.exe"
    if windows.exists():
        return windows
    return workspace_root / ".venv" / "bin" / "python"


def _parse_optional_timeout_ms(name: str, default_ms: int | None) -> int | None:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default_ms

    value = raw.strip().lower()
    if value in {"0", "none", "off", "false", "unlimited", "infinite"}:
        return None

    parsed = int(value)
    return parsed if parsed > 0 else None


def _parse_optional_timeout_s(name: str, default_s: float | None) -> float | None:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default_s

    value = raw.strip().lower()
    if value in {"0", "none", "off", "false", "unlimited", "infinite"}:
        return None

    parsed = float(value)
    return parsed if parsed > 0 else None


def _format_duration(seconds: float) -> str:
    whole = max(0, int(seconds))
    minutes, secs = divmod(whole, 60)
    hours, minutes = divmod(minutes, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


async def _probe_responses_api(settings: OpenClawSettings) -> dict[str, Any]:
    async with OpenClawResponsesClient(settings) as client:
        return await client.probe_models()


async def _build_connection_snapshot() -> dict[str, Any]:
    settings = _load_openclaw_settings()
    issues: list[str] = []

    if not settings.config_exists:
        issues.append(f"OpenClaw config file not found: {settings.config_path}")
    if settings.config_error:
        issues.append(settings.config_error)
    if not settings.workspace_exists:
        issues.append(f"Workspace not found: {settings.workspace_root}")
    if not settings.agent_configured:
        issues.append(f"OpenClaw agent not configured: {settings.agent_id}")
    if settings.agent_workspace and not settings.agent_workspace_matches:
        issues.append(
            f"Workspace mismatch between frontend target and agent config: {settings.workspace_root} != {settings.agent_workspace}"
        )
    if not settings.gateway_token:
        issues.append(
            "Missing Gateway token. Set OPENCLAW_GATEWAY_TOKEN or configure gateway.auth.token in ~/.openclaw/openclaw.json."
        )

    gateway_info = {
        "http_url": settings.gateway_http_url,
        "responses_url": settings.gateway_responses_url,
        "ws_url": settings.gateway_ws_url,
        "auth_configured": bool(settings.gateway_token),
        "reachable": False,
        "surface": "subprocess-fallback",
        "models_ready": False,
        "protocol": None,
        "server_version": None,
        "default_agent_id": None,
    }

    if not issues:
        try:
            gateway_probe = await _probe_responses_api(settings)
            gateway_info.update(
                {
                    "reachable": gateway_probe.get("reachable", False),
                    "models_ready": gateway_probe.get("models_ready", False),
                    "server_version": gateway_probe.get("server_version"),
                }
            )
            model_ids = set(gateway_probe.get("model_ids") or [])
            expected_ids = _expected_openclaw_model_ids(settings.agent_id)
            if not gateway_probe.get("models_ready"):
                status_code = gateway_probe.get("status_code")
                content_type = gateway_probe.get("content_type") or "unknown"
                issues.append(
                    "OpenClaw HTTP Responses API is not ready: /v1/models did not return a JSON model list. "
                    "Enable gateway.http.endpoints.responses.enabled=true and restart Gateway "
                    f"(HTTP={status_code}, Content-Type={content_type})."
                )
            elif not expected_ids.issubset(model_ids):
                missing_ids = ", ".join(sorted(expected_ids - model_ids))
                issues.append(f"OpenClaw /v1/models is missing required agent model ids: {missing_ids}")
        except Exception as exc:
            issues.append(str(exc))


    if gateway_info["models_ready"] and not issues:
        status = "ready"
    elif settings.workspace_exists or settings.agent_configured:
        status = "degraded"
    else:
        status = "error"
    gateway_info["surface"] = "responses" if status == "ready" else "subprocess-fallback"

    return {
        "status": status,
        "checked_at": _now_iso(),
        "workspace_root": str(settings.workspace_root),
        "workspace_exists": settings.workspace_exists,
        "workspace_source": settings.workspace_source,
        "agent": {
            "id": settings.agent_id,
            "configured": settings.agent_configured,
            "workspace": str(settings.agent_workspace) if settings.agent_workspace else None,
            "workspace_matches": settings.agent_workspace_matches,
        },
        "gateway": gateway_info,
        "hooks": {
            "enabled": settings.hooks_enabled,
            "mapping_present": settings.hook_mapping_present,
        },
        "preferred_transport": "openclaw" if status == "ready" else "subprocess",
        "issues": issues,
    }


async def _run_subprocess_collector(run: SentinelRun) -> None:
    settings = _load_openclaw_settings()
    workspace_root = settings.workspace_root
    python_bin = _build_subprocess_python(workspace_root)

    if not workspace_root.exists():
        await _finish_run(run, "failed", f"workspace not found: {workspace_root}")
        return
    if not python_bin.exists():
        await _finish_run(run, "failed", f"collector python not found: {python_bin}")
        return

    command = _COLLECTOR_COMMANDS[run.mode]
    node_name = _COLLECTOR_NODE_NAMES.get(run.mode, "sentinel")
    args = [str(python_bin), *[str(workspace_root / part) for part in command]]

    run.status = "running"
    run.add_event(
        {
            "type": "run_header",
            "run_id": run.run_id,
            "run_mode": run.mode,
            "source_runtime_mode": "subprocess",
            "llm_model": "workspace-script",
            "ts": _now_iso(),
        }
    )
    run.add_event(
        {
            "type": "node_detail",
            "node": node_name,
            "display_name": node_name,
            "message": f"Starting local collector script: {' '.join(command)}",
            "ts": _now_iso(),
        }
    )

    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(workspace_root),
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
    except Exception as exc:
        await _finish_run(run, "failed", f"failed to start collector: {exc}")
        return

    run.process = process

    try:
        while True:
            if run.cancel_requested and process.returncode is None:
                process.terminate()
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                if process.returncode is not None:
                    break
                continue
            if not line:
                if process.returncode is not None:
                    break
                continue

            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                run.add_event(
                    {
                        "type": "node_verbose",
                        "node": node_name,
                        "display_name": node_name,
                        "ts": _now_iso(),
                        "key": "stdout",
                        "value": text,
                        "truncated": False,
                    }
                )
    except asyncio.CancelledError:
        run.cancel_requested = True
        if process.returncode is None:
            process.terminate()
        raise
    finally:
        exit_code = process.returncode if process.returncode is not None else await process.wait()
        run.process = None

    if run.cancel_requested:
        await _finish_run(run, "cancelled")
    elif exit_code == 0:
        await _finish_run(run, "succeeded")
    else:
        await _finish_run(run, "failed", f"collector exited with code {exit_code}")


def _emit_assistant_line(run: SentinelRun, text: str, ts: str) -> None:
    line = text.strip()
    if not line:
        return

    if line.startswith("[STATUS]"):
        run.add_event(
            {
                "type": "node_detail",
                "node": "openclaw",
                "display_name": "OpenClaw Agent",
                "message": line.removeprefix("[STATUS]").strip() or "OpenClaw 闃舵鏇存柊",
                "ts": ts,
            }
        )
        return

    run.add_event(
        {
            "type": "node_verbose",
            "node": "openclaw",
            "display_name": "OpenClaw Agent",
            "ts": ts,
            "key": "assistant",
            "value": line,
            "truncated": False,
        }
    )


def _consume_assistant_delta(run: SentinelRun, text: str, ts: str) -> None:
    run.assistant_buffer += text
    while "\n" in run.assistant_buffer:
        line, run.assistant_buffer = run.assistant_buffer.split("\n", 1)
        _emit_assistant_line(run, line, ts)


def _extract_response_text(event: dict[str, Any]) -> str:
    response = event.get("response")
    if not isinstance(response, dict):
        return ""
    output = response.get("output")
    if not isinstance(output, list):
        return ""
    parts: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and part.get("type") == "output_text":
                text = part.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
    return "".join(parts)


def _extract_response_error(event: dict[str, Any]) -> str:
    response = event.get("response")
    if not isinstance(response, dict):
        return "OpenClaw response failed"
    error = response.get("error")
    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])
    return f"OpenClaw response failed: {response.get('status') or 'unknown'}"


def _translate_responses_event(run: SentinelRun, event: dict[str, Any], ts: str) -> None:
    event_type = str(event.get("type") or "")
    response = event.get("response")
    if isinstance(response, dict) and response.get("id"):
        run.gateway_run_id = str(response["id"])

    if event_type == "response.created":
        run.add_event(
            {
                "type": "node_detail",
                "node": "openclaw",
                "display_name": "OpenClaw Gateway",
                "message": f"Created OpenClaw response: {run.gateway_run_id}",
                "ts": ts,
            }
        )
        return

    if event_type == "response.in_progress":
        run.add_event(
            {
                "type": "node_detail",
                "node": "openclaw",
                "display_name": "OpenClaw Agent",
                "message": "OpenClaw agent started execution.",
                "ts": ts,
            }
        )
        return

    if event_type == "response.output_text.delta":
        delta = event.get("delta")
        if isinstance(delta, str) and delta:
            _consume_assistant_delta(run, delta, ts)
        return

    if event_type == "response.output_text.done":
        text = event.get("text")
        if isinstance(text, str):
            run.assistant_text = text
        return

    if event_type == "response.completed":
        had_streamed_text = bool(run.assistant_buffer.strip() or run.assistant_text.strip())
        response_text = _extract_response_text(event)
        if response_text:
            run.assistant_text = response_text
            if not had_streamed_text:
                for line in response_text.splitlines():
                    _emit_assistant_line(run, line, ts)
        if run.assistant_buffer.strip():
            _emit_assistant_line(run, run.assistant_buffer, ts)
            run.assistant_buffer = ""
        run.add_event(
            {
                "type": "node_detail",
                "node": "openclaw",
                "display_name": "OpenClaw Agent",
                "message": "OpenClaw agent execution finished; waiting for final status.",
                "ts": ts,
            }
        )
        return


    if event_type == "response.failed":
        if run.assistant_buffer.strip():
            _emit_assistant_line(run, run.assistant_buffer, ts)
            run.assistant_buffer = ""
        run.add_event(
            {
                "type": "node_error_detail",
                "node": "openclaw",
                "display_name": "OpenClaw Agent",
                "message": _extract_response_error(event),
                "ts": ts,
            }
        )
        return

    if event_type == "[DONE]":
        return

    run.add_event(
        {
            "type": "node_verbose",
            "node": "openclaw",
            "display_name": "OpenClaw Agent",
            "ts": ts,
            "key": event_type or "event",
            "value": json.dumps(event, ensure_ascii=False),
            "truncated": False,
        }
    )


def _response_event_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    status = str(payload.get("status") or "").lower()
    if status == "failed":
        return {"type": "response.failed", "response": payload}
    return {"type": "response.completed", "response": payload}


async def _run_openclaw_collector(run: SentinelRun) -> None:
    connection = await _build_connection_snapshot()
    if connection["preferred_transport"] != "openclaw":
        await _finish_run(run, "failed", "; ".join(connection["issues"]) or "OpenClaw Gateway is not ready")
        return

    settings = _load_openclaw_settings()
    wait_timeout_ms = _parse_optional_timeout_ms("OPENCLAW_WAIT_TIMEOUT_MS", 3_900_000)
    wait_timeout_s = _parse_optional_timeout_s(
        "OPENCLAW_WAIT_TIMEOUT_S",
        wait_timeout_ms / 1000.0 if wait_timeout_ms is not None else None,
    )
    run.session_key = None
    run.status = "running"
    run.add_event(
        {
            "type": "run_header",
            "run_id": run.run_id,
            "run_mode": run.mode,
            "source_runtime_mode": "openclaw",
            "llm_model": settings.agent_id,
            "ts": _now_iso(),
        }
    )
    run.add_event(
        {
            "type": "node_detail",
            "node": "openclaw",
            "display_name": "OpenClaw Gateway",
            "message": f"Connecting to OpenClaw HTTP Responses: {settings.gateway_responses_url}",
            "ts": _now_iso(),
        }
    )
    run.add_event(
        {
            "type": "node_detail",
            "node": "openclaw",
            "display_name": "OpenClaw Gateway",
            "message": (
                "HTTP Responses compatibility mode: non-streaming completion request; wait timeout="
                + (
                    f"{_format_duration(wait_timeout_s)}"
                    if wait_timeout_ms is not None
                    else "unbounded"
                )
                + "; cancel is local best-effort termination."
            ),
            "ts": _now_iso(),
        }
    )

    try:
        async with OpenClawResponsesClient(settings) as client:
            run.add_event(
                {
                    "type": "node_detail",
                    "node": "openclaw",
                    "display_name": "OpenClaw Gateway",
                    "message": f"Responses API ready; agent={settings.agent_id}",
                    "ts": _now_iso(),
                }
            )
            response_task = asyncio.create_task(
                client.complete_response(
                    agent_id=settings.agent_id,
                    message=_build_openclaw_message(run.mode, settings.workspace_root),
                )
            )
            loop_started_at = asyncio.get_running_loop().time()
            next_progress_ping = loop_started_at + 30.0
            deadline = (
                loop_started_at + wait_timeout_s
                if wait_timeout_s is not None
                else None
            )

            while True:
                if run.cancel_requested:
                    response_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await response_task
                    run.add_event(
                        {
                            "type": "node_detail",
                            "node": "openclaw",
                            "display_name": "OpenClaw Gateway",
                            "message": "Cancelled local OpenClaw wait task.",
                            "ts": _now_iso(),
                        }
                    )
                    await _finish_run(run, "cancelled")
                    return

                if deadline is not None and asyncio.get_running_loop().time() >= deadline:
                    response_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await response_task
                    raise OpenClawResponsesError(
                        f"/v1/responses timed out after {wait_timeout_s:.0f}s"
                    )

                try:
                    payload = await asyncio.wait_for(asyncio.shield(response_task), timeout=1.0)
                except asyncio.TimeoutError:
                    now = asyncio.get_running_loop().time()
                    if now >= next_progress_ping:
                        run.add_event(
                            {
                                "type": "node_detail",
                                "node": "openclaw",
                                "display_name": "OpenClaw Agent",
                                "message": f"Still running; elapsed {_format_duration(now - loop_started_at)}; waiting for final result.",
                                "ts": _now_iso(),
                            }
                        )
                        next_progress_ping = now + 30.0
                    continue
                break
                break

            _translate_responses_event(run, _response_event_from_payload(payload), _now_iso())
            if run.assistant_buffer.strip():
                _emit_assistant_line(run, run.assistant_buffer, _now_iso())
                run.assistant_buffer = ""

            if str(payload.get("status") or "").lower() == "failed":
                await _finish_run(run, "failed", _extract_response_error({"response": payload}))
            elif run.assistant_text.strip():
                await _finish_run(run, "succeeded")
            else:
                await _finish_run(run, "failed", "OpenClaw response did not include assistant output")
    except asyncio.CancelledError:
        run.cancel_requested = True
        raise
    except Exception as exc:
        await _finish_run(run, "failed", str(exc))


class SentinelRunRequest(BaseModel):
    mode: str = "full"
    transport: str | None = None
    use_gateway: bool | None = None


@router.get("/connection")
async def get_connection() -> dict[str, Any]:
    return await _build_connection_snapshot()


@router.get("/status")
async def get_status() -> dict[str, Any]:
    settings = _load_openclaw_settings()
    active = _get_active_run()
    latest = _get_latest_run()

    daily_path = _latest_daily_file(settings.workspace_root)
    daily = _read_daily_intel(daily_path) if daily_path else {}
    snapshot = _read_coverage_snapshot(settings.workspace_root)

    if active and active.status not in _TERMINAL_STATUSES:
        status = "running"
    elif latest and latest.status == "failed":
        status = "warning"
    else:
        status = "idle"

    current_tasks: list[str] = []
    if active and active.status not in _TERMINAL_STATUSES:
        transport_label = "OpenClaw" if active.transport == "openclaw" else "subprocess"
        current_tasks.append(f"{active.mode} collector running via {transport_label}")

    uptime_seconds = 0
    if active:
        try:
            started = datetime.fromisoformat(_ensure_offset(active.started_at))
            uptime_seconds = max(0, int((_now() - started).total_seconds()))
        except ValueError:
            uptime_seconds = 0

    return {
        "wp_id": "sentinel",
        "status": status,
        "uptime_seconds": uptime_seconds,
        "version": "v2.0.0",
        "metrics": {
            "intel_count": _intel_count(daily),
            "owasp_coverage": _owasp_coverage_pct(snapshot),
            "high_risk_count": _high_risk_count(daily),
        },
        "current_tasks": current_tasks,
        "last_updated": _now_iso(),
    }


@router.get("/metrics")
async def get_metrics(
    keys: str = "intel_count,owasp_coverage,high_risk_count",
    window: str = "48h",
) -> list[dict[str, Any]]:
    settings = _load_openclaw_settings()
    key_list = [key.strip() for key in keys.split(",") if key.strip()]
    if not key_list:
        return []

    all_files = sorted((settings.workspace_root / "kb" / "daily").glob("ai-threat-*.json"))
    if not all_files:
        return [{"key": key, "unit": "", "points": []} for key in key_list]

    cutoff = _now() - timedelta(hours=_parse_window_hours(window))
    series: dict[str, list[dict[str, Any]]] = {key: [] for key in key_list}
    snapshot = _read_coverage_snapshot(settings.workspace_root)

    for file_path in all_files:
        daily = _read_daily_intel(file_path)
        if not daily:
            continue
        point_ts = _ensure_offset(str(daily.get("report_date") or _now_iso()))
        try:
            if datetime.fromisoformat(point_ts) < cutoff:
                continue
        except ValueError:
            pass

        values = {
            "intel_count": float(_intel_count(daily)),
            "owasp_coverage": float(_owasp_coverage_pct(snapshot)),
            "high_risk_count": float(_high_risk_count(daily)),
        }
        for key in key_list:
            if key in values:
                series[key].append({"timestamp": point_ts, "value": values[key]})

    units = {"intel_count": "items", "owasp_coverage": "%", "high_risk_count": "items"}
    return [{"key": key, "unit": units.get(key, ""), "points": series.get(key, [])} for key in key_list]


@router.get("/alerts")
async def get_alerts(limit: int = 10) -> list[dict[str, Any]]:
    settings = _load_openclaw_settings()
    daily_path = _latest_daily_file(settings.workspace_root)
    if not daily_path:
        return []

    daily = _read_daily_intel(daily_path)
    alerts: list[dict[str, Any]] = []
    for item in daily.get("top5", [])[:limit]:
        score = float(item.get("cvss_score") or 0.0)
        if score < 7.0:
            continue
        desc = str(item.get("description") or "")
        alerts.append(
            {
                "id": f"sentinel-{item.get('external_id', uuid.uuid4().hex[:8])}",
                "severity": "HIGH" if score >= 9.0 else "MEDIUM",
                "title": f"[{item.get('external_id', '?')}] {desc[:120]}{'...' if len(desc) > 120 else ''}",
                "cvss": score,
                "created_at": _ensure_offset(str(item.get("published_at") or _now_iso())),
            }
        )
    return alerts


@router.get("/reports")
async def list_reports() -> list[dict[str, str]]:
    settings = _load_openclaw_settings()
    date_re = re.compile(r"\d{4}-\d{2}-\d{2}")
    files = [
        file_path
        for file_path in (settings.workspace_root / "reports").rglob("*.md")
        if file_path.is_file() and date_re.search(file_path.name)
    ]
    files.sort(key=lambda item: item.name, reverse=True)
    return [
        {
            "date": date_re.search(file_path.name).group(0) if date_re.search(file_path.name) else "",
            "filename": file_path.name,
        }
        for file_path in files
    ]


@router.get("/reports/{date}")
async def get_report(date: str) -> dict[str, str]:
    settings = _load_openclaw_settings()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise HTTPException(status_code=400, detail="date must be YYYY-MM-DD")

    for file_path in (settings.workspace_root / "reports").rglob("*.md"):
        if file_path.is_file() and date in file_path.name:
            return {
                "date": date,
                "content": file_path.read_text(encoding="utf-8", errors="replace"),
            }

    raise HTTPException(status_code=404, detail=f"report not found for {date}")


@router.post("/runs", status_code=201)
async def start_run(body: SentinelRunRequest) -> dict[str, Any]:
    if body.mode not in _COLLECTOR_COMMANDS:
        raise HTTPException(status_code=400, detail=f"unknown mode: {body.mode}")

    transport = body.transport
    if transport is None:
        transport = "openclaw" if body.use_gateway else "subprocess"
    if transport not in {"subprocess", "openclaw"}:
        raise HTTPException(status_code=400, detail=f"unknown transport: {transport}")

    if transport == "openclaw":
        connection = await _build_connection_snapshot()
        if connection["preferred_transport"] != "openclaw":
            raise HTTPException(
                status_code=503,
                detail="; ".join(connection["issues"]) or "OpenClaw Gateway is not ready",
            )

    run = await _register_run(body.mode, transport)
    run.add_event(
        {
            "type": "init",
            "run_id": run.run_id,
            "run_mode": run.mode,
            "ts": run.started_at,
        }
    )
    run.task = asyncio.create_task(
        _run_openclaw_collector(run) if transport == "openclaw" else _run_subprocess_collector(run)
    )
    return _run_summary(run)


@router.get("/runs/active")
async def get_active_run_endpoint() -> dict[str, Any]:
    active = _get_active_run()
    if active is None or active.status in _TERMINAL_STATUSES:
        raise HTTPException(status_code=404, detail="no active run")
    return _run_summary(active)


@router.get("/runs/{run_id}")
async def get_run_endpoint(run_id: str) -> dict[str, Any]:
    run = _get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    return _run_summary(run)


@router.delete("/runs/{run_id}")
async def cancel_run(run_id: str) -> dict[str, Any]:
    run = _get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    if run.status in _TERMINAL_STATUSES:
        return _run_summary(run)

    run.cancel_requested = True
    run.status = "cancelling"
    if run.process is not None and run.process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            run.process.terminate()

    run.add_event(
        {
            "type": "node_detail",
            "node": "sentinel",
            "display_name": "Sentinel",
            "message": "鏀跺埌鍙栨秷璇锋眰",
            "ts": _now_iso(),
        }
    )
    return _run_summary(run)


def _sse_frame(index: int, payload: dict[str, Any]) -> str:
    return f"id: {index}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.get("/logs/stream")
async def stream_logs(
    last_event_index: int = Query(default=0, ge=0),
) -> StreamingResponse:
    async def event_generator():
        cursor = last_event_index
        source_run_id: str | None = None
        replayed_memory = False
        heartbeat_at = asyncio.get_running_loop().time()

        while True:
            source = _get_active_run() or _get_latest_run()
            if source is not None:
                if source_run_id != source.run_id:
                    source_run_id = source.run_id
                    if cursor > source.event_index:
                        cursor = 0
                    replayed_memory = True

                pending = [event for event in source.history if event.index > cursor]
                if pending:
                    for event in pending:
                        cursor = event.index
                        yield _sse_frame(event.index, event.payload)
                    source.updated.clear()
                    heartbeat_at = asyncio.get_running_loop().time()
                    continue

                source.updated.clear()
                await asyncio.sleep(1.0)
            else:
                if not replayed_memory and cursor == 0:
                    settings = _load_openclaw_settings()
                    memory_file = _latest_memory_file(settings.workspace_root)
                    if memory_file is not None:
                        next_index = 1
                        for line in memory_file.read_text(encoding="utf-8", errors="replace").splitlines():
                            if not line.strip():
                                continue
                            yield _sse_frame(
                                next_index,
                                {
                                    "type": "node_verbose",
                                    "node": "sentinel_memory",
                                    "display_name": "鍘嗗彶鏃ュ織",
                                    "ts": _now_iso(),
                                    "key": "memory",
                                    "value": line,
                                    "truncated": False,
                                },
                            )
                            cursor = next_index
                            next_index += 1
                        yield _sse_frame(next_index, {"type": "done", "status": "succeeded", "percent": 100})
                        cursor = next_index
                    replayed_memory = True
                    heartbeat_at = asyncio.get_running_loop().time()
                    continue
                await asyncio.sleep(1.0)

            if asyncio.get_running_loop().time() - heartbeat_at >= 30:
                yield _sse_frame(cursor + 1, {"type": "heartbeat"})
                heartbeat_at = asyncio.get_running_loop().time()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

