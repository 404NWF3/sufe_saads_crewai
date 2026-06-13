"""Engine factory: INTEL_ENGINE=rules|sdk selects the collection controller.

Default is ``rules`` (the existing RealIntelRunController). ``sdk`` requires the
claude-agent-sdk runtime and an Anthropic-compatible provider key (DeepSeek or
GLM, see agent_runtime/client.py); when unavailable the factory degrades to the
rules engine and reports why (engine-level fallback, roadmap 4.3).
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_ENGINE = "rules"


def selected_engine() -> str:
    value = os.getenv("INTEL_ENGINE", DEFAULT_ENGINE).strip().lower()
    return value if value in {"rules", "sdk"} else DEFAULT_ENGINE


def create_intel_controller(
    run_goal: str,
    initial_query: str,
    max_rounds: int = 5,
    max_results_per_round: int = 80,
    run_store: Any = None,
    target_topics: list[str] | None = None,
    engine: str | None = None,
    **engine_kwargs: Any,
) -> Any:
    engine_name = (engine or selected_engine()).lower()

    if engine_name == "sdk":
        from sufe_saads_crewai.agent_runtime.client import sdk_runtime_available

        available, reason = sdk_runtime_available()
        if available:
            from sufe_saads_crewai.intel.sdk_loop import SdkIntelRunController

            return SdkIntelRunController(
                run_goal=run_goal,
                initial_query=initial_query,
                max_rounds=max_rounds,
                max_results_per_round=max_results_per_round,
                run_store=run_store,
                target_topics=target_topics,
                **engine_kwargs,
            )
        print(f"[intel.engine] sdk engine unavailable ({reason}); falling back to rules engine")

    from sufe_saads_crewai.intel.real_loop import RealIntelRunController

    return RealIntelRunController(
        run_goal=run_goal,
        initial_query=initial_query,
        max_rounds=max_rounds,
        max_results_per_round=max_results_per_round,
        run_store=run_store,
        target_topics=target_topics,
    )
