"""The agentic collection loop: per-round SDK sessions and the termination critic."""

from __future__ import annotations

__all__ = ["IntelAgentLoop", "RoundSessionResult", "decide_termination"]


def __getattr__(name: str):
    if name in {"IntelAgentLoop", "RoundSessionResult"}:
        from .loop import IntelAgentLoop, RoundSessionResult

        return {"IntelAgentLoop": IntelAgentLoop, "RoundSessionResult": RoundSessionResult}[name]
    if name == "decide_termination":
        from .critic import decide_termination

        return decide_termination
    raise AttributeError(name)
