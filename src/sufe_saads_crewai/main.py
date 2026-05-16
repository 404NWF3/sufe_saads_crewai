from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import warnings

from sufe_saads_crewai.crew import SufeSaadsCrewai
from sufe_saads_crewai.intel import RealIntelRunController, run_mock_autonomous_loop
from sufe_saads_crewai.llms import configure_glm_runtime, describe_glm_runtime
from sufe_saads_crewai.persistence import JsonIntelRunStore, MongoIntelRunStore
from sufe_saads_crewai.tools import default_registered_api_sources

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


DEFAULT_RUN_GOAL = "Collect comprehensive LLM security intelligence."
DEFAULT_BASELINE_SEARCH_QUERY = (
    "LLM security intelligence baseline: prompt injection OR jailbreak OR "
    "agent tool abuse OR RAG poisoning OR data leakage OR model supply chain OR "
    "AI application vulnerability OR AI infrastructure vulnerability"
)


def build_default_run_store():
    if os.getenv("INTEL_RUN_STORE", "").lower() == "mongodb" or os.getenv("MONGODB_URI"):
        return MongoIntelRunStore.from_env()
    return JsonIntelRunStore()


def configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def default_blackboard_json() -> str:
    return json.dumps(
        {
            "approved_sources": [
                source.model_dump(mode="json")
                for source in default_registered_api_sources()
            ]
        },
        ensure_ascii=False,
    )


def run():
    configure_console_encoding()
    run_goal = DEFAULT_RUN_GOAL
    search_query = DEFAULT_BASELINE_SEARCH_QUERY
    try:
        configure_glm_runtime(enable_agent_kickoff=True)
        print(describe_glm_runtime(), file=sys.stderr)
        run_store = build_default_run_store()
        result = RealIntelRunController(
            run_goal=run_goal,
            initial_query=search_query,
            max_rounds=50,
            run_store=run_store,
        ).run()
        summary = {
            "run_id": result.run_id,
            "rounds": len(result.query_history),
            "raw_items": len(result.raw_items),
            "coverage_gaps_remaining": [
                gap.taxonomy_or_component for gap in result.coverage_gaps
            ],
            "saved_to": str(run_store.run_path(result.run_id)),
            "last_action": result.action_history[-1].action_type if result.action_history else None,
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}") from e


def run_mock_loop():
    configure_console_encoding()
    initial_query = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "LLM prompt injection and agent tool abuse"
    )
    run_store = JsonIntelRunStore(Path("data") / "mock_intel_runs")
    result = run_mock_autonomous_loop(initial_query=initial_query, run_store=run_store)
    saved_path = run_store.run_path(result.run_id)
    summary = {
        "run_id": result.run_id,
        "rounds": len(result.query_history),
        "raw_items": len(result.raw_items),
        "saved_to": str(saved_path),
        "rewrites": [
            query.query_text
            for note in result.reflection_notes
            for query in note.rewritten_queries
        ],
        "coverage_gaps_remaining": [
            gap.taxonomy_or_component for gap in result.coverage_gaps
        ],
        "source_proposals": [
            {
                "source_name": proposal.source_name,
                "approval_status": proposal.approval_status,
            }
            for proposal in result.source_proposals
        ],
        "last_action": result.action_history[-1].action_type if result.action_history else None,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def show_latest_intel():
    configure_console_encoding()
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    print(build_default_run_store().format_latest_intel(limit=limit, real_only=True))


def train():
    configure_console_encoding()
    configure_glm_runtime(enable_agent_kickoff=True)
    inputs = {
        "run_goal": DEFAULT_RUN_GOAL,
        "blackboard_json": default_blackboard_json(),
        "search_query": DEFAULT_BASELINE_SEARCH_QUERY,
    }
    try:
        SufeSaadsCrewai().crew().train(
            n_iterations=int(sys.argv[1]),
            filename=sys.argv[2],
            inputs=inputs,
        )
    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}") from e


def replay():
    configure_console_encoding()
    configure_glm_runtime(enable_agent_kickoff=True)
    try:
        SufeSaadsCrewai().crew().replay(task_id=sys.argv[1])
    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}") from e


def test():
    configure_console_encoding()
    configure_glm_runtime(enable_agent_kickoff=True)
    inputs = {
        "run_goal": DEFAULT_RUN_GOAL,
        "blackboard_json": default_blackboard_json(),
        "search_query": DEFAULT_BASELINE_SEARCH_QUERY,
    }
    try:
        SufeSaadsCrewai().crew().test(
            n_iterations=int(sys.argv[1]),
            eval_llm=sys.argv[2],
            inputs=inputs,
        )
    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}") from e


def run_with_trigger():
    configure_console_encoding()
    if len(sys.argv) < 2:
        raise Exception("No trigger payload provided. Please provide JSON payload as argument.")

    try:
        trigger_payload = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        raise Exception("Invalid JSON payload provided as argument") from e

    try:
        configure_glm_runtime(enable_agent_kickoff=True)
        print(describe_glm_runtime(), file=sys.stderr)
        run_store = build_default_run_store()
        result = RealIntelRunController(
            run_goal=trigger_payload.get(
                "run_goal",
                DEFAULT_RUN_GOAL,
            ),
            initial_query=trigger_payload.get(
                "search_query",
                DEFAULT_BASELINE_SEARCH_QUERY,
            ),
            max_rounds=int(trigger_payload.get("max_rounds", 5)),
            run_store=run_store,
        ).run()
        print(
            json.dumps(
                {
                    "run_id": result.run_id,
                    "rounds": len(result.query_history),
                    "raw_items": len(result.raw_items),
                    "saved_to": str(run_store.run_path(result.run_id)),
                    "last_action": result.action_history[-1].action_type
                    if result.action_history
                    else None,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return result
    except Exception as e:
        raise Exception(f"An error occurred while running the crew with trigger: {e}") from e


if __name__ == "__main__":
    run()
