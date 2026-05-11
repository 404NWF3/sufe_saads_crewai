from __future__ import annotations

import unittest
from typing import Any

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
    def test_crew_output_schemas_forbid_additional_properties(self) -> None:
        for model in CREW_OUTPUT_MODELS:
            with self.subTest(model=model.__name__):
                schema = model.model_json_schema()
                for object_schema in iter_schema_objects(schema):
                    self.assertIs(
                        object_schema.get("additionalProperties"),
                        False,
                        f"{model.__name__} has an open object schema: {object_schema}",
                    )

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


if __name__ == "__main__":
    unittest.main()
