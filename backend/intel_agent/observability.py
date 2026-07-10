"""Verbose tracing for a collection run.

A ``TraceSink`` receives structured events (round boundaries, per-turn model
text, tool calls + results, session/critic summaries) and optionally (a) prints
a readable line to the console, (b) appends the raw event to a JSONL
transcript, and (c) invokes an optional ``on_event`` callback for live UI streaming.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

DEFAULT_TRACE_DIR = Path("data") / "intel_agent" / "traces"
EventCallback = Callable[[dict[str, Any]], None]


def _truncate(value: Any, limit: int = 600) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else f"{text[:limit]}... (+{len(text) - limit} chars)"


def _safe(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._") or "intel_run"


@dataclass
class TraceSink:
    """Console + JSONL transcript for a run. Set ``trace_dir=None`` to skip the file."""

    console: bool = True
    trace_dir: Path | None = DEFAULT_TRACE_DIR
    on_event: EventCallback | None = None
    path: Path | None = field(default=None, init=False)
    _fh: TextIO | None = field(default=None, init=False, repr=False)

    def bind_run(self, run_id: str) -> None:
        if self.trace_dir is not None:
            self.path = Path(self.trace_dir) / f"{_safe(run_id)}.jsonl"

    def emit(self, event: str, **fields: Any) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        if self.path is not None:
            self._append(record)
        if self.console:
            line = _format(record)
            if line:
                print(line, flush=True)
        if self.on_event is not None:
            try:
                self.on_event(record)
            except Exception:  # noqa: BLE001 - UI callbacks must not break collection
                pass

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def _append(self, record: dict[str, Any]) -> None:
        if self._fh is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)  # type: ignore[union-attr]
            self._fh = self.path.open("a", encoding="utf-8")  # type: ignore[union-attr]
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()


def format_event_line(record: dict[str, Any]) -> str:
    """Public formatter for Gradio / replay UIs."""
    return _format(record)


def load_trace_jsonl(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _format(record: dict[str, Any]) -> str:
    event = record.get("event")
    if event == "round_start":
        gaps = record.get("open_gaps") or []
        gap_txt = f" | open gaps: {gaps}" if gaps else ""
        return (
            f"\n===== round {record['round']}/{record['max_rounds']} "
            f"[{record.get('mode', '?')}]{gap_txt} ====="
        )
    if event == "assistant_text":
        return f"  [assistant] {_truncate(record.get('text', ''))}"
    if event == "thinking":
        return f"  [thinking] {_truncate(record.get('text', ''), 300)}"
    if event == "tool_call":
        args = record.get("input") or {}
        return f"  -> {record.get('tool')}({_truncate(args, 300)})"
    if event == "tool_result":
        flag = " [error]" if record.get("is_error") else ""
        return f"  <-{flag} {_truncate(record.get('content', ''), 400)}"
    if event == "session_end":
        cost = record.get("cost_usd")
        cost_txt = f" | cost=${cost:.4f}" if isinstance(cost, (int, float)) else ""
        err = " | ERROR" if record.get("is_error") else ""
        return f"  [session end] turns={record.get('turns')}{cost_txt}{err}"
    if event == "session_fallback":
        return f"  [fallback] agent round unavailable: {record.get('reason')}"
    if event == "session_truncated":
        return (
            f"  [truncated] session ended early but kept collected items: "
            f"{record.get('reason')}"
        )
    if event == "round_summary":
        return (
            f"  [round {record['round']}] +{record.get('new_items', 0)} new items | "
            f"new_relevant={record.get('new_relevant', 0)} | "
            f"api_calls={record.get('api_calls_used', 0)} | "
            f"gaps={record.get('open_gaps') or []}"
        )
    if event == "critic":
        return (
            f"  [critic] continue={record.get('should_continue')} "
            f"score={record.get('completeness_score')} :: {_truncate(record.get('rationale', ''), 200)}"
        )
    return ""
