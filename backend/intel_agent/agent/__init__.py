"""The agentic collection loop: per-round SDK sessions and the termination critic."""

from __future__ import annotations

from .loop import IntelAgentLoop, RoundSessionResult
from .critic import decide_termination

__all__ = ["IntelAgentLoop", "RoundSessionResult", "decide_termination"]
