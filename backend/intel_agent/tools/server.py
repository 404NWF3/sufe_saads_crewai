"""Bundle the per-round tools into one in-process MCP server."""

from __future__ import annotations

from typing import Any

from .context import ToolContext
from .control_tools import build_control_tools
from .memory_tools import build_memory_tools
from .source_tools import build_source_tools

SERVER_NAME = "intel_sources"

# Fully-qualified tool names for ClaudeAgentOptions.allowed_tools.
ALLOWED_TOOLS = [
    f"mcp__{SERVER_NAME}__{name}"
    for name in (
        "search_nvd", "search_arxiv", "search_cisa_kev", "search_osv",
        "recall_playbook", "record_technique", "submit_round_summary",
    )
]


def build_round_server(ctx: ToolContext) -> tuple[dict[str, Any], list[str]]:
    """Return ({server_name: server_config}, allowed_tools) for a round."""
    from claude_agent_sdk import create_sdk_mcp_server

    tools = build_source_tools(ctx) + build_memory_tools(ctx) + build_control_tools(ctx)
    server = create_sdk_mcp_server(name=SERVER_NAME, tools=tools)
    return {SERVER_NAME: server}, list(ALLOWED_TOOLS)
