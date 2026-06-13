from __future__ import annotations

import unittest

from pydantic import ValidationError

from sufe_saads_crewai.schemas import (
    ActionDecision,
    ActionDecisionBatch,
    AlertCandidate,
    IntelRunBlackboard,
    ItemKnowledgeGraphRecord,
    KgEligibilityDecision,
    PersistenceBundle,
    PersistenceOperation,
    RawIntelItem,
    SearchQueryPlan,
    SourceProposal,
)


class SchemaTests(unittest.TestCase):
    def test_models_allow_extra_fields(self) -> None:
        item = RawIntelItem(
            item_id="raw-1",
            source_name="nvd",
            source_uri="https://example.test/item",
            unexpected_field="kept for compatibility",
        )

        self.assertEqual(item.model_extra["unexpected_field"], "kept for compatibility")

    def test_invalid_action_type_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ActionDecision(action_type="UNKNOWN", rationale="bad action")

    def test_score_fields_are_bounded(self) -> None:
        with self.assertRaises(ValidationError):
            RawIntelItem(
                item_id="raw-2",
                source_name="nvd",
                source_uri="https://example.test/item",
                relevance_score=1.5,
            )

    def test_persistence_bundle_derives_operation_groups(self) -> None:
        operation = PersistenceOperation(
            operation_group="upsert_raw_intel",
            idempotency_key="raw-1",
            records=[{"item_id": "raw-1"}],
        )
        bundle = PersistenceBundle(operations=[operation])

        self.assertEqual(bundle.operation_groups, ["upsert_raw_intel"])

    def test_blackboard_json_round_trip(self) -> None:
        blackboard = IntelRunBlackboard(
            run_id="run-1",
            run_goal="Collect LLM security intelligence",
            source_proposals=[
                SourceProposal(
                    source_name="Example Security Blog",
                    base_uri="https://example.test",
                    source_type="research",
                )
            ],
            action_history=[
                ActionDecision(
                    action_type="SEARCH_REGISTERED_SOURCE",
                    rationale="Need initial coverage",
                )
            ],
            raw_items=[
                RawIntelItem(
                    item_id="raw-3",
                    source_name="example",
                    source_uri="https://example.test/post",
                )
            ],
            item_knowledge_graphs=[
                ItemKnowledgeGraphRecord(
                    run_id="run-1",
                    item_id="raw-3",
                    source_name="example",
                    source_uri="https://example.test/post",
                    status="skipped",
                    eligibility=KgEligibilityDecision(
                        item_id="raw-3",
                        eligible=False,
                        excluded_reason="test_skip",
                    ),
                )
            ],
            alerts=[
                AlertCandidate(
                    title="Prompt injection signal",
                    confidence=0.7,
                )
            ],
        )

        dumped = blackboard.model_dump(mode="json")
        restored = IntelRunBlackboard.model_validate(dumped)

        self.assertEqual(restored.run_id, "run-1")
        self.assertEqual(restored.source_proposals[0].approval_status, "pending")
        self.assertEqual(restored.action_history[0].action_type, "SEARCH_REGISTERED_SOURCE")
        self.assertEqual(restored.item_knowledge_graphs[0].status, "skipped")

    def test_action_batch_accepts_query_plan_context(self) -> None:
        query_plan = SearchQueryPlan(
            query_text="LLM prompt injection agent tool abuse",
            source_names=["nvd", "github_advisories"],
        )
        batch = ActionDecisionBatch(
            actions=[
                ActionDecision(
                    action_type="SEARCH_REGISTERED_SOURCE",
                    rationale="Search approved sources",
                    required_context=[query_plan.query_text],
                )
            ]
        )

        self.assertEqual(len(batch.actions), 1)


if __name__ == "__main__":
    unittest.main()


class SdkDecisionSchemaTests(unittest.TestCase):
    def test_collection_plan_decision_validates_and_forbids_extras(self) -> None:
        from sufe_saads_crewai.schemas import (
            CollectionPlanDecision,
            SearchQueryProposal,
            SourceSelectionDecision,
        )

        decision = CollectionPlanDecision.model_validate(
            {
                "proposals": [
                    {
                        "source_name": "nvd_cve_api",
                        "query_text": "MLflow deserialization",
                        "params": {"nvd_cwe_id": "CWE-502"},
                        "rationale": "supply chain",
                    }
                ],
                "rationale": "plan",
            }
        )
        self.assertEqual(decision.proposals[0].params["nvd_cwe_id"], "CWE-502")

        with self.assertRaises(ValidationError):
            SearchQueryProposal.model_validate(
                {"source_name": "unknown_source", "query_text": "q"}
            )
        with self.assertRaises(ValidationError):
            SourceSelectionDecision.model_validate(
                {
                    "selected_sources": ["arxiv_api"],
                    "follow_bandit": True,
                    "rationale": "r",
                    "extra_field": "forbidden",
                }
            )
