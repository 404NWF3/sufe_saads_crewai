from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

import yaml

from sufe_saads_crewai.crew import SufeSaadsCrewai
from sufe_saads_crewai.schemas.crew_outputs import (
    CollectionBatchOutput,
    CompletenessDecisionOutput,
    CoverageAnalysisOutput,
    PlannerDecisionOutput,
    RewriteDecisionOutput,
    SearchSemanticExpansionOutput,
    SourceProposalBatchOutput,
    YieldAssessmentOutput,
)


CREW_OUTPUT_MODELS = [
    PlannerDecisionOutput,
    CollectionBatchOutput,
    YieldAssessmentOutput,
    CoverageAnalysisOutput,
    SearchSemanticExpansionOutput,
    SourceProposalBatchOutput,
    RewriteDecisionOutput,
    CompletenessDecisionOutput,
]


def iter_schema_objects(node: Any):
    if isinstance(node, dict):
        if node.get("type") == "object" or "properties" in node:
            yield node
        for value in node.values():
            yield from iter_schema_objects(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_schema_objects(item)


class CrewOutputSchemaTests(unittest.TestCase):
    def test_crew_output_schemas_do_not_expose_open_additional_properties(self) -> None:
        for model in CREW_OUTPUT_MODELS:
            with self.subTest(model=model.__name__):
                schema = model.model_json_schema()
                for object_schema in iter_schema_objects(schema):
                    self.assertIsNot(
                        object_schema.get("additionalProperties"),
                        True,
                        f"{model.__name__} has an open object schema: {object_schema}",
                    )

    def test_planner_output_ignores_provider_extra_fields(self) -> None:
        parsed = PlannerDecisionOutput.model_validate(
            {
                "actions": [
                    {
                        "action_type": "STOP",
                        "priority": "low",
                        "rationale": "diagnostic",
                        "expected_gain": "none",
                        "required_context": [],
                        "success_criteria": [],
                        "retry_conditions": [],
                        "stop_conditions": [],
                        "estimated_cost_level": "low",
                        "provider_extra": "ignored",
                    }
                ],
                "planner_rationale": "diagnostic",
                "should_start_collection": False,
                "provider_extra": "ignored",
            }
        )

        self.assertFalse(hasattr(parsed, "provider_extra"))

    def test_crew_output_schemas_require_all_declared_fields(self) -> None:
        for model in CREW_OUTPUT_MODELS:
            with self.subTest(model=model.__name__):
                schema = model.model_json_schema()
                for object_schema in iter_schema_objects(schema):
                    properties = object_schema.get("properties", {})
                    required = set(object_schema.get("required", []))
                    self.assertEqual(required, set(properties))

    def test_crew_tasks_use_lightweight_output_models(self) -> None:
        crew = SufeSaadsCrewai().crew()
        output_models = [
            task.output_pydantic
            for task in crew.tasks
            if getattr(task, "output_pydantic", None) is not None
        ]

        self.assertEqual(output_models, CREW_OUTPUT_MODELS)

    def test_rewrite_task_expected_output_mentions_all_schema_fields(self) -> None:
        tasks_path = Path("src/sufe_saads_crewai/config/tasks.yaml")
        tasks_config = yaml.safe_load(tasks_path.read_text(encoding="utf-8"))
        expected_output = tasks_config["rewrite_search_strategy_task"]["expected_output"]

        for field_name in RewriteDecisionOutput.model_fields:
            with self.subTest(field_name=field_name):
                self.assertIn(field_name, expected_output)


if __name__ == "__main__":
    unittest.main()
