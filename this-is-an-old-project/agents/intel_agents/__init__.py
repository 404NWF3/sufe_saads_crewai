"""WP1-1 intelligence agents and orchestration runtime."""

from __future__ import annotations

from typing import Any

__all__ = ["Phase1GraphRuntime"]


def __getattr__(name: str) -> Any:
    if name == "Phase1GraphRuntime":
        from .orchestrator.runtime import Phase1GraphRuntime

        return Phase1GraphRuntime
    raise AttributeError(name)
