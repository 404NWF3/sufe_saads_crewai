from __future__ import annotations

from ..orchestrator.runtime import Phase1GraphRuntime


def run_phase1_stub() -> dict:
    """Run the Phase 1 graph using deterministic stub inputs."""

    runtime = Phase1GraphRuntime()
    return runtime.invoke_stub_run()
