"""P0 spike: run the chapter-5 capability matrix for claude-agent-sdk x GLM endpoint.

Usage (from repo root):
    uv run --group agentsdk python spikes/agent_sdk_glm/run_matrix.py [--only check1,check2] [--n 20]

Writes spikes/agent_sdk_glm/results.json and prints a summary table.
Each check is independent; a crash in one check is recorded and the rest run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
import traceback
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AgentDefinition,
    AssistantMessage,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from _env import base_options, premium_model, provider_models, provider_name

HERE = Path(__file__).resolve().parent
PROVIDER = provider_name()
RESULTS_PATH = HERE / f"results.{PROVIDER}.json"

MAIN_MODEL, FAST_MODEL = provider_models()
PREMIUM_MODEL = premium_model()


# ---------------------------------------------------------------- helpers

async def _collect(prompt: str, options) -> tuple[str, ResultMessage | None]:
    """Run a one-shot query; return (final_text, result_message)."""
    final_text: list[str] = []
    result: ResultMessage | None = None
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    final_text.append(block.text)
        elif isinstance(message, ResultMessage):
            result = message
    return "\n".join(final_text), result


def _mk_calc_server(call_log: list[dict[str, Any]]):
    @tool(
        "add_numbers",
        "Add two integers and return their sum. Always use this tool for addition.",
        {"a": int, "b": int},
    )
    async def add_numbers(args: dict[str, Any]) -> dict[str, Any]:
        call_log.append(dict(args))
        total = int(args["a"]) + int(args["b"])
        return {"content": [{"type": "text", "text": str(total)}]}

    return create_sdk_mcp_server(name="calc", tools=[add_numbers])


def _mk_decision_server(decisions: list[dict[str, Any]]):
    @tool(
        "submit_decision",
        "Submit the final continue/stop decision. Call exactly once with your verdict.",
        {
            "should_continue": bool,
            "confidence": float,
            "rationale": str,
        },
    )
    async def submit_decision(args: dict[str, Any]) -> dict[str, Any]:
        decisions.append(dict(args))
        return {"content": [{"type": "text", "text": "decision recorded"}]}

    return create_sdk_mcp_server(name="decide", tools=[submit_decision])


def _valid_decision(payload: dict[str, Any]) -> bool:
    return (
        isinstance(payload.get("should_continue"), bool)
        and isinstance(payload.get("confidence"), (int, float))
        and 0.0 <= float(payload["confidence"]) <= 1.0
        and isinstance(payload.get("rationale"), str)
        and len(payload["rationale"]) > 0
    )


# ---------------------------------------------------------------- checks

async def check_basic_query_main() -> dict[str, Any]:
    text, result = await _collect(
        "Reply with exactly the two characters: OK",
        base_options(model=MAIN_MODEL, max_turns=2),
    )
    return {
        "ok": "OK" in text,
        "model": MAIN_MODEL,
        "is_error": bool(result and result.is_error),
        "reply_excerpt": text[:120],
    }


async def check_basic_query_fast() -> dict[str, Any]:
    text, result = await _collect(
        "Reply with exactly the two characters: OK",
        base_options(model=FAST_MODEL, max_turns=2),
    )
    return {
        "ok": "OK" in text,
        "model": FAST_MODEL,
        "is_error": bool(result and result.is_error),
        "reply_excerpt": text[:120],
    }


async def check_multi_turn() -> dict[str, Any]:
    turns_ok = 0
    total_turns = 5
    options = base_options(model=MAIN_MODEL, max_turns=2 * total_turns + 2)
    async with ClaudeSDKClient(options=options) as client:
        await client.query("Remember the codeword ZEBRA-42. Reply with: stored")
        async for message in client.receive_response():
            if isinstance(message, ResultMessage):
                turns_ok += 0 if message.is_error else 1
        for index in range(total_turns - 1):
            await client.query(
                f"Turn {index + 2}: what is the codeword? Reply with the codeword only."
            )
            text_parts: list[str] = []
            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text_parts.append(block.text)
            if "ZEBRA-42" in "\n".join(text_parts):
                turns_ok += 1
    return {"ok": turns_ok == total_turns, "turns_ok": turns_ok, "turns_total": total_turns}


async def check_tool_calls(n: int) -> dict[str, Any]:
    successes = 0
    failures: list[str] = []
    for index in range(n):
        call_log: list[dict[str, Any]] = []
        server = _mk_calc_server(call_log)
        a, b = 11 + index, 31 + index
        options = base_options(
            model=MAIN_MODEL,
            max_turns=4,
            mcp_servers={"calc": server},
            allowed_tools=["mcp__calc__add_numbers"],
        )
        try:
            text, _ = await _collect(
                f"Use the add_numbers tool to compute {a}+{b}. "
                f"Then reply with the numeric result only.",
                options,
            )
            called = any(c.get("a") == a and c.get("b") == b for c in call_log)
            answered = str(a + b) in text
            if called and answered:
                successes += 1
            else:
                failures.append(f"iter{index}: called={called} answered={answered} text={text[:80]}")
        except Exception as exc:  # noqa: BLE001 - record and continue
            failures.append(f"iter{index}: {exc.__class__.__name__}: {exc}")
    return {
        "ok": successes / n >= 0.95,
        "success_rate": round(successes / n, 3),
        "n": n,
        "failures": failures[:5],
    }


async def check_structured_decision(n: int) -> dict[str, Any]:
    parsed = 0
    failures: list[str] = []
    for index in range(n):
        decisions: list[dict[str, Any]] = []
        server = _mk_decision_server(decisions)
        novelty = 0.4 - index * 0.02
        options = base_options(
            model=MAIN_MODEL,
            max_turns=4,
            mcp_servers={"decide": server},
            allowed_tools=["mcp__decide__submit_decision"],
        )
        prompt = (
            "You manage an intelligence collection loop.\n"
            f"Round {index + 1} metrics: novelty={novelty:.2f}, duplicate_ratio={0.3 + index * 0.02:.2f}, "
            f"new_relevant_items_per_call={max(0.05, 0.9 - index * 0.05):.2f}, remaining_budget_calls={40 - index}.\n"
            "Decide whether to continue collecting. You MUST call the submit_decision tool "
            "exactly once with should_continue, confidence (0..1), and a short rationale. "
            "Do not answer in plain text."
        )
        try:
            await _collect(prompt, options)
            if len(decisions) >= 1 and _valid_decision(decisions[0]):
                parsed += 1
            else:
                failures.append(f"iter{index}: decisions={decisions[:1]}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"iter{index}: {exc.__class__.__name__}: {exc}")
    return {
        "ok": parsed / n >= 0.90,
        "parse_rate": round(parsed / n, 3),
        "n": n,
        "failures": failures[:5],
    }


async def check_hooks() -> dict[str, Any]:
    pre_events: list[dict[str, Any]] = []
    post_events: list[dict[str, Any]] = []
    call_log: list[dict[str, Any]] = []
    server = _mk_calc_server(call_log)

    async def pre_tool_use(input_data: dict[str, Any], tool_use_id: str | None, context: Any):
        pre_events.append(input_data)
        tool_input = input_data.get("tool_input") or {}
        if tool_input.get("a") == 13:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "a=13 is blocked by spike policy; use a different first operand",
                }
            }
        return {}

    async def post_tool_use(input_data: dict[str, Any], tool_use_id: str | None, context: Any):
        post_events.append(input_data)
        return {}

    options = base_options(
        model=MAIN_MODEL,
        max_turns=6,
        mcp_servers={"calc": server},
        allowed_tools=["mcp__calc__add_numbers"],
        hooks={
            "PreToolUse": [HookMatcher(matcher="mcp__calc__add_numbers", hooks=[pre_tool_use])],
            "PostToolUse": [HookMatcher(matcher="mcp__calc__add_numbers", hooks=[post_tool_use])],
        },
    )
    text, _ = await _collect(
        "First use add_numbers with a=13, b=1. If that is blocked, use add_numbers "
        "with a=2, b=3 and reply with that result only.",
        options,
    )
    blocked_call_executed = any(c.get("a") == 13 for c in call_log)
    fallback_executed = any(c.get("a") == 2 and c.get("b") == 3 for c in call_log)
    return {
        "ok": (not blocked_call_executed) and fallback_executed and bool(pre_events) and bool(post_events),
        "pre_events": len(pre_events),
        "post_events": len(post_events),
        "blocked_call_executed": blocked_call_executed,
        "fallback_executed": fallback_executed,
        "reply_excerpt": text[:120],
    }


async def check_subagent() -> dict[str, Any]:
    task_used = False
    options = base_options(
        model=MAIN_MODEL,
        max_turns=8,
        allowed_tools=["Task"],
        agents={
            "yield-critic": AgentDefinition(
                description="Judges whether an intelligence collection loop should continue based on marginal yield metrics.",
                prompt=(
                    "You are a strict yield critic. Given metrics, reply with exactly one word: "
                    "CONTINUE or STOP, followed by one short sentence of rationale."
                ),
                model=FAST_MODEL,
                tools=[],
            )
        },
    )
    final_text: list[str] = []
    async for message in query(
        prompt=(
            "Delegate to the 'yield-critic' subagent: metrics are novelty=0.02, "
            "duplicate_ratio=0.7, two consecutive low-yield rounds. "
            "Report the critic verdict back as your final answer."
        ),
        options=options,
    ):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock) and block.name == "Task":
                    task_used = True
                if isinstance(block, TextBlock):
                    final_text.append(block.text)
    text = "\n".join(final_text)
    return {
        "ok": task_used and ("STOP" in text.upper() or "CONTINUE" in text.upper()),
        "task_tool_used": task_used,
        "reply_excerpt": text[:160],
    }


async def check_premium_model() -> dict[str, Any]:
    text, result = await _collect(
        "Reply with exactly the two characters: OK",
        base_options(model=PREMIUM_MODEL, max_turns=2),
    )
    return {
        "ok": "OK" in text and not (result and result.is_error),
        "model": PREMIUM_MODEL,
        "reply_excerpt": text[:120],
    }


async def check_prompt_caching() -> dict[str, Any]:
    filler = " ".join(
        f"Rule {i}: always preserve provenance for source {i} and never fabricate identifiers."
        for i in range(120)
    )
    system_prompt = "You are an intelligence collection planner.\n" + filler
    usages: list[dict[str, Any]] = []
    for _ in range(2):
        _, result = await _collect(
            "Reply with exactly: ACK",
            base_options(model=MAIN_MODEL, max_turns=2, system_prompt=system_prompt),
        )
        usages.append(dict(result.usage or {}) if result else {})
    cache_read = sum(int(u.get("cache_read_input_tokens") or 0) for u in usages)
    cache_created = sum(int(u.get("cache_creation_input_tokens") or 0) for u in usages)
    return {
        "ok": cache_read > 0 or cache_created > 0,
        "cache_creation_input_tokens": cache_created,
        "cache_read_input_tokens": cache_read,
        "usages": usages,
    }


async def check_long_session() -> dict[str, Any]:
    rounds_total = 10
    rounds_ok = 0
    options = base_options(model=MAIN_MODEL, max_turns=2 * rounds_total + 2)
    async with ClaudeSDKClient(options=options) as client:
        for round_index in range(rounds_total):
            metrics_blob = json.dumps(
                {
                    "round": round_index,
                    "per_source": {
                        source: {
                            "calls": 3 + round_index,
                            "new": max(0, 14 - 2 * round_index),
                            "dup_ratio": round(0.1 + 0.05 * round_index, 2),
                            "noise_ratio": round(0.2 + 0.03 * round_index, 2),
                            "sample_titles": [
                                f"{source} finding {round_index}-{j}: vulnerability detail text"
                                for j in range(6)
                            ],
                        }
                        for source in ("nvd", "arxiv", "cisa_kev", "osv")
                    },
                }
            )
            await client.query(
                f"Round {round_index} metrics JSON:\n{metrics_blob}\n"
                "Summarize this round in one sentence."
            )
            errored = False
            got_text = False
            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock) and block.text.strip():
                            got_text = True
                elif isinstance(message, ResultMessage) and message.is_error:
                    errored = True
            if got_text and not errored:
                rounds_ok += 1
    return {"ok": rounds_ok == rounds_total, "rounds_ok": rounds_ok, "rounds_total": rounds_total}


async def check_output_format() -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "should_continue": {"type": "boolean"},
            "confidence": {"type": "number"},
            "rationale": {"type": "string"},
        },
        "required": ["should_continue", "confidence", "rationale"],
        "additionalProperties": False,
    }
    options = base_options(
        model=MAIN_MODEL,
        max_turns=2,
        output_format={"type": "json_schema", "schema": schema},
    )
    text, result = await _collect(
        "Metrics: novelty=0.03, duplicate_ratio=0.65, budget left=2 calls. "
        "Decide whether to continue collecting.",
        options,
    )
    structured: Any = None
    raw = getattr(result, "result", None) if result else None
    for candidate in (raw, text):
        if not candidate:
            continue
        try:
            structured = json.loads(candidate)
            break
        except (TypeError, json.JSONDecodeError):
            continue
    return {
        "ok": isinstance(structured, dict) and _valid_decision(structured),
        "parsed": structured,
        "is_error": bool(result and result.is_error),
        "reply_excerpt": (text or str(raw))[:160],
    }


CHECKS = {
    "basic_query_main": lambda n: check_basic_query_main(),
    "basic_query_fast": lambda n: check_basic_query_fast(),
    "multi_turn": lambda n: check_multi_turn(),
    "tool_calls": check_tool_calls,
    "structured_decision": check_structured_decision,
    "hooks": lambda n: check_hooks(),
    "subagent": lambda n: check_subagent(),
    "premium_model": lambda n: check_premium_model(),
    "prompt_caching": lambda n: check_prompt_caching(),
    "long_session": lambda n: check_long_session(),
    "output_format": lambda n: check_output_format(),
}


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="", help="comma separated check names")
    parser.add_argument("--n", type=int, default=20, help="iterations for rate-based checks")
    args = parser.parse_args()

    selected = [name.strip() for name in args.only.split(",") if name.strip()] or list(CHECKS)
    results: dict[str, Any] = {}
    if RESULTS_PATH.is_file():
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))

    for name in selected:
        runner = CHECKS[name]
        print(f"[spike] running {name} ...", flush=True)
        started = time.perf_counter()
        try:
            outcome = await runner(args.n)
        except Exception as exc:  # noqa: BLE001 - one failing check must not kill the matrix
            outcome = {
                "ok": False,
                "error": f"{exc.__class__.__name__}: {exc}",
                "traceback": traceback.format_exc()[-1500:],
            }
        outcome["elapsed_seconds"] = round(time.perf_counter() - started, 1)
        results[name] = outcome
        RESULTS_PATH.write_text(
            json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[spike] {name}: ok={outcome.get('ok')} ({outcome['elapsed_seconds']}s)", flush=True)

    print("\n=== capability matrix summary ===")
    for name, outcome in results.items():
        print(f"{name:24s} ok={outcome.get('ok')}")


if __name__ == "__main__":
    asyncio.run(main())
