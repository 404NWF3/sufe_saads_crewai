"""In-process MCP tools the collection agent calls during a round."""

from __future__ import annotations

__all__ = ["ToolContext", "build_round_server"]


def __getattr__(name: str):
    if name == "ToolContext":
        from .context import ToolContext

        return ToolContext
    if name == "build_round_server":
        from .server import build_round_server

        return build_round_server
    raise AttributeError(name)
