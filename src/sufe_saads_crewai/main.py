from __future__ import annotations

import json
from pathlib import Path
import sys
import warnings

from sufe_saads_crewai.crew import SufeSaadsCrewai
from sufe_saads_crewai.intel import create_intel_controller, run_mock_autonomous_loop
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import IntelRunBlackboard
from sufe_saads_crewai.tools import default_registered_api_sources

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


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
    run_goal = "Collect comprehensive LLM security intelligence."
    search_query = "LLM prompt injection jailbreak RAG poisoning model supply chain"
    try:
        run_store = JsonIntelRunStore()
        result = create_intel_controller(
            run_goal=run_goal,
            initial_query=search_query,
            max_rounds=50,
            run_store=run_store,
        ).run()
        summary = _run_summary(result, run_store)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}") from e


def run_mock_loop():
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
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    print(JsonIntelRunStore().format_latest_intel(limit=limit, real_only=True))


def train():
    inputs = {
        "run_goal": "Collect comprehensive LLM security intelligence.",
        "blackboard_json": default_blackboard_json(),
        "search_query": "LLM prompt injection jailbreak RAG poisoning model supply chain",
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
    try:
        SufeSaadsCrewai().crew().replay(task_id=sys.argv[1])
    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}") from e


def test():
    inputs = {
        "run_goal": "Collect comprehensive LLM security intelligence.",
        "blackboard_json": default_blackboard_json(),
        "search_query": "LLM prompt injection jailbreak RAG poisoning model supply chain",
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
    if len(sys.argv) < 2:
        raise Exception("No trigger payload provided. Please provide JSON payload as argument.")

    try:
        trigger_payload = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        raise Exception("Invalid JSON payload provided as argument") from e

    try:
        run_store = JsonIntelRunStore()
        result = create_intel_controller(
            run_goal=trigger_payload.get(
                "run_goal",
                "Collect comprehensive LLM security intelligence.",
            ),
            initial_query=trigger_payload.get(
                "search_query",
                "LLM prompt injection jailbreak RAG poisoning model supply chain",
            ),
            max_rounds=int(trigger_payload.get("max_rounds", 5)),
            max_results_per_round=int(trigger_payload.get("max_results_per_round", 80)),
            run_store=run_store,
        ).run()
        print(
            json.dumps(
                _run_summary(result, run_store),
                ensure_ascii=False,
                indent=2,
            )
        )
        return result
    except Exception as e:
        raise Exception(f"An error occurred while running the crew with trigger: {e}") from e


def _run_summary(result: IntelRunBlackboard, run_store: JsonIntelRunStore) -> dict:
    kg_counts = {
        "total": len(result.item_knowledge_graphs),
        "succeeded": sum(1 for record in result.item_knowledge_graphs if record.status == "succeeded"),
        "failed": sum(1 for record in result.item_knowledge_graphs if record.status == "failed"),
        "skipped": sum(1 for record in result.item_knowledge_graphs if record.status == "skipped"),
    }
    return {
        "run_id": result.run_id,
        "rounds": len(result.query_history),
        "raw_items": len(result.raw_items),
        "knowledge_graphs": kg_counts,
        "coverage_gaps_remaining": [
            gap.taxonomy_or_component for gap in result.coverage_gaps
        ],
        "saved_to": str(run_store.run_path(result.run_id)),
        "kg_manifest_path": str(
            run_store.root_dir / f"{result.run_id}_kg" / "manifest.json"
        ),
        "last_action": result.action_history[-1].action_type if result.action_history else None,
    }


if __name__ == "__main__":
    run_mock_loop()
