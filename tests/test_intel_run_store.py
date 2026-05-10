from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sufe_saads_crewai.intel import run_mock_autonomous_loop
from sufe_saads_crewai.persistence import JsonIntelRunStore
from sufe_saads_crewai.schemas import IntelRunBlackboard
from sufe_saads_crewai.tools import default_registered_api_sources


class IntelRunStoreTests(unittest.TestCase):
    def test_mock_loop_persists_raw_item_batches_and_latest_index(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")

            result = run_mock_autonomous_loop(
                initial_query="LLM prompt injection and agent tool abuse",
                max_rounds=2,
                run_store=run_store,
            )

            run_path = run_store.run_path(result.run_id)
            latest_path = run_store.latest_index_path()
            self.assertTrue(run_path.exists())
            self.assertTrue(latest_path.exists())

            payload = json.loads(run_path.read_text(encoding="utf-8"))
            latest = json.loads(latest_path.read_text(encoding="utf-8"))

            self.assertEqual(payload["run_id"], result.run_id)
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(latest["run_id"], result.run_id)
            self.assertGreaterEqual(len(payload["raw_item_batches"]), 1)
            self.assertGreaterEqual(payload["summary"]["raw_items"], 1)
            self.assertGreaterEqual(
                len(payload["blackboard"]["raw_items"]),
                len(payload["raw_item_batches"][0]["items"]),
            )

    def test_latest_payload_round_trips_to_blackboard(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")

            result = run_mock_autonomous_loop(
                initial_query="LLM prompt injection",
                max_rounds=1,
                run_store=run_store,
            )
            payload = run_store.load_latest_payload()

            self.assertIsNotNone(payload)
            restored = IntelRunBlackboard.model_validate(payload["blackboard"])
            self.assertEqual(restored.run_id, result.run_id)
            self.assertEqual(len(restored.raw_items), len(result.raw_items))

    def test_format_latest_intel_prints_item_details(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")
            run_mock_autonomous_loop(
                initial_query="LLM prompt injection",
                max_rounds=1,
                run_store=run_store,
            )

            output = run_store.format_latest_intel(limit=3)

            self.assertIn("Latest run:", output)
            self.assertIn("source:", output)
            self.assertIn("uri:", output)

    def test_real_only_latest_skips_newer_mock_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_store = JsonIntelRunStore(Path(temp_dir) / "intel_runs")

            real_blackboard = IntelRunBlackboard(
                run_id="real-unit-test",
                run_goal="Collect real LLM security intelligence.",
                approved_sources=default_registered_api_sources(),
            )
            run_store.save_run(real_blackboard, status="succeeded")
            run_mock_autonomous_loop(
                initial_query="LLM prompt injection",
                max_rounds=1,
                run_store=run_store,
            )

            latest_payload = run_store.load_latest_payload()
            real_payload = run_store.load_latest_payload(real_only=True)

            self.assertIsNotNone(latest_payload)
            self.assertIsNotNone(real_payload)
            self.assertTrue(latest_payload["run_id"].startswith("mock-"))
            self.assertEqual(real_payload["run_id"], "real-unit-test")


if __name__ == "__main__":
    unittest.main()
