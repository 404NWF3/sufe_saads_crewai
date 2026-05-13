from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sufe_saads_crewai.llms import (
    DEFAULT_GLM_BASE_URL,
    configure_glm_runtime,
    glm_runtime_config,
)


class GlmRuntimeTests(unittest.TestCase):
    def test_configure_glm_runtime_enables_agent_kickoff_and_defaults(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "GLM_API_KEY": "test-key",
                "GLM_MODEL": "",
                "GLM_FAST_MODEL": "",
                "GLM_BASE_URL": "",
            },
            clear=True,
        ):
            config = configure_glm_runtime()
            tracing_enabled = os.environ["CREWAI_TRACING_ENABLED"]

        self.assertEqual(config["agent_kickoff"], "true")
        self.assertEqual(config["main_model"], "glm-5")
        self.assertEqual(config["fast_model"], "glm-4.7-flash")
        self.assertEqual(config["base_url"], DEFAULT_GLM_BASE_URL)
        self.assertEqual(tracing_enabled, "false")
        runtime_config = glm_runtime_config("main")
        self.assertEqual(runtime_config.timeout, 120.0)
        self.assertEqual(runtime_config.max_retries, 1)

    def test_glm_runtime_normalizes_model_and_completion_url(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "GLM_API_KEY": "test-key",
                "GLM_FAST_MODEL": "GLM-4.7-FlashX",
                "GLM_BASE_URL": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            },
            clear=True,
        ):
            config = glm_runtime_config("fast")

        self.assertEqual(config.model, "glm-4.7-flashx")
        self.assertEqual(config.base_url, "https://open.bigmodel.cn/api/paas/v4")


if __name__ == "__main__":
    unittest.main()
