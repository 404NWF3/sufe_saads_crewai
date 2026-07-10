"""structured_decision: SDK query -> tool-forced JSON -> Pydantic -> None on failure.

Used for the termination critic (a short, reliable tool-forcing call). The
contract is: any failure (runtime unavailable, timeout, parse error, validation
error) returns None so the caller falls back to deterministic rules. Every
failure is counted and exposed via telemetry.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from . import client as runtime_client

DEFAULT_DECISION_TIMEOUT_SECONDS = 180.0


@dataclass
class DecisionTelemetry:
    attempts: int = 0
    successes: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)

    def record_failure(self, decision_name: str, reason: str) -> None:
        self.failures.append({"decision": decision_name, "reason": reason[:300]})

    def summary(self) -> dict[str, Any]:
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "failure_count": len(self.failures),
            "failures": self.failures[-20:],
        }


def _run_coro_sync(coro: Any, timeout_seconds: float) -> Any:
    async def _bounded() -> Any:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_bounded())

    outcome: dict[str, Any] = {}

    def _worker() -> None:
        try:
            outcome["value"] = asyncio.run(_bounded())
        except BaseException as exc:  # noqa: BLE001 - re-raised in caller thread
            outcome["error"] = exc

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds + 30)
    if "error" in outcome:
        raise outcome["error"]
    if "value" not in outcome:
        raise TimeoutError("structured decision worker thread did not finish")
    return outcome["value"]


def extract_json_object(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    elif "{" in cleaned and "}" in cleaned:
        cleaned = cleaned[cleaned.find("{") : cleaned.rfind("}") + 1]
    return json.loads(cleaned)


async def _sdk_decision_call(
    prompt: str, schema: dict[str, Any], system_prompt: str | None, model: str, max_turns: int
) -> Any:
    from claude_agent_sdk import (
        AssistantMessage,
        ResultMessage,
        TextBlock,
        create_sdk_mcp_server,
        query,
        tool,
    )

    captured: list[dict[str, Any]] = []

    @tool(
        "submit_decision",
        "Submit your final structured decision. Call exactly once; the input must satisfy the JSON schema.",
        schema,
    )
    async def submit_decision(args: dict[str, Any]) -> dict[str, Any]:
        captured.append(dict(args))
        return {"content": [{"type": "text", "text": "decision recorded"}]}

    options = runtime_client.build_options(
        model=model,
        max_turns=max_turns,
        system_prompt=system_prompt,
        mcp_servers={"decide": create_sdk_mcp_server(name="decide", tools=[submit_decision])},
        allowed_tools=["mcp__decide__submit_decision"],
    )
    final_text: list[str] = []
    forced_prompt = (
        f"{prompt}\n\n"
        "You MUST call the submit_decision tool exactly once with your decision. "
        "Do not answer in plain text."
    )
    async for message in query(prompt=forced_prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    final_text.append(block.text)
        elif isinstance(message, ResultMessage) and message.is_error and not captured:
            raise RuntimeError(f"sdk session error: {str(message.result)[:200]}")

    if captured:
        return captured[0]
    return "\n".join(final_text) or None


class StructuredDecisionEngine:
    def __init__(
        self,
        model: str | None = None,
        fast_model: str | None = None,
        timeout_seconds: float = DEFAULT_DECISION_TIMEOUT_SECONDS,
        max_turns: int = 4,
        runner: Callable[..., Any] | None = None,
    ) -> None:
        self.model = model or runtime_client.main_model()
        self.fast_model = fast_model or runtime_client.fast_model()
        self.timeout_seconds = timeout_seconds
        self.max_turns = max_turns
        self.telemetry = DecisionTelemetry()
        # Test seam: async (prompt, schema, system_prompt, model, max_turns) -> dict | str | None
        self._runner = runner or _sdk_decision_call

    def available(self) -> bool:
        if self._runner is not _sdk_decision_call:
            return True
        ok, _ = runtime_client.sdk_runtime_available()
        return ok

    def decide(
        self,
        decision_name: str,
        prompt: str,
        output_model: type[BaseModel],
        system_prompt: str | None = None,
        fast: bool = False,
    ) -> BaseModel | None:
        self.telemetry.attempts += 1
        if not self.available():
            self.telemetry.record_failure(decision_name, "sdk runtime unavailable")
            return None
        schema = _tool_input_schema(output_model)
        try:
            raw = _run_coro_sync(
                self._runner(
                    prompt, schema, system_prompt,
                    self.fast_model if fast else self.model, self.max_turns,
                ),
                timeout_seconds=self.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - fallback contract
            self.telemetry.record_failure(decision_name, f"{exc.__class__.__name__}: {exc}")
            return None

        parsed = self._validate(raw, output_model)
        if parsed is None:
            self.telemetry.record_failure(decision_name, f"unparseable output: {str(raw)[:160]}")
            return None
        self.telemetry.successes += 1
        return parsed

    def _validate(self, raw: Any, output_model: type[BaseModel]) -> BaseModel | None:
        if raw is None:
            return None
        if isinstance(raw, BaseModel):
            raw = raw.model_dump()
        if isinstance(raw, dict):
            try:
                return output_model.model_validate(raw)
            except ValidationError:
                return None
        if isinstance(raw, str):
            try:
                return output_model.model_validate_json(raw)
            except ValidationError:
                pass
            try:
                return output_model.model_validate(extract_json_object(raw))
            except (json.JSONDecodeError, ValidationError, ValueError):
                return None
        return None


def _tool_input_schema(output_model: type[BaseModel]) -> dict[str, Any]:
    return _inline_defs(output_model.model_json_schema())


def _inline_defs(schema: dict[str, Any]) -> dict[str, Any]:
    defs = schema.pop("$defs", {})
    if not defs:
        return schema

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref", "")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                target = defs.get(ref.split("/")[-1], {})
                merged = {key: value for key, value in node.items() if key != "$ref"}
                merged.update(resolve(dict(target)))
                return merged
            return {key: resolve(value) for key, value in node.items()}
        if isinstance(node, list):
            return [resolve(item) for item in node]
        return node

    return resolve(schema)
