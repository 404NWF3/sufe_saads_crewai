"""Verbose connectivity probe: print every SDK message and CLI stderr line."""

from __future__ import annotations

import asyncio
import sys

from claude_agent_sdk import query

from _env import base_options


async def main() -> None:
    model = sys.argv[1] if len(sys.argv) > 1 else None
    options = base_options(model=model, max_turns=2)
    options.stderr = lambda line: print(f"[stderr] {line}", flush=True)
    print(f"[debug] model={options.model}", flush=True)
    try:
        async for message in query(prompt="Reply with exactly: OK", options=options):
            print(f"[msg] {type(message).__name__}: {message!r}"[:600], flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[error] {exc.__class__.__name__}: {exc}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
