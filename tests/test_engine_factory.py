from __future__ import annotations

import os
import unittest
from unittest import mock

from sufe_saads_crewai.intel import create_intel_controller, selected_engine
from sufe_saads_crewai.intel.real_loop import RealIntelRunController


class EngineFactoryTests(unittest.TestCase):
    def test_default_engine_is_rules(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INTEL_ENGINE", None)
            self.assertEqual(selected_engine(), "rules")

    def test_unknown_engine_falls_back_to_rules(self) -> None:
        with mock.patch.dict(os.environ, {"INTEL_ENGINE": "quantum"}):
            self.assertEqual(selected_engine(), "rules")

    def test_rules_engine_returns_real_controller(self) -> None:
        with mock.patch.dict(os.environ, {"INTEL_ENGINE": "rules"}):
            controller = create_intel_controller(
                run_goal="g", initial_query="q", max_rounds=1
            )
            self.assertIsInstance(controller, RealIntelRunController)

    def test_sdk_engine_unavailable_degrades_to_rules(self) -> None:
        with mock.patch.dict(os.environ, {"INTEL_ENGINE": "sdk"}):
            with mock.patch(
                "sufe_saads_crewai.agent_runtime.client.sdk_runtime_available",
                return_value=(False, "test: forced unavailable"),
            ):
                controller = create_intel_controller(
                    run_goal="g", initial_query="q", max_rounds=1
                )
                self.assertIsInstance(controller, RealIntelRunController)

    def test_sdk_engine_selected_when_available(self) -> None:
        from sufe_saads_crewai.intel.sdk_loop import SdkIntelRunController

        with mock.patch.dict(os.environ, {"INTEL_ENGINE": "sdk"}):
            with mock.patch(
                "sufe_saads_crewai.agent_runtime.client.sdk_runtime_available",
                return_value=(True, "ok"),
            ):
                from sufe_saads_crewai.intel.bandit import SourceBandit

                controller = create_intel_controller(
                    run_goal="g",
                    initial_query="q",
                    max_rounds=1,
                    bandit=SourceBandit(state_path=None),
                )
                self.assertIsInstance(controller, SdkIntelRunController)


if __name__ == "__main__":
    unittest.main()
