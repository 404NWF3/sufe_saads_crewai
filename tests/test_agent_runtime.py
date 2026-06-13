from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

from pydantic import BaseModel

from sufe_saads_crewai.agent_runtime import client as runtime_client

from sufe_saads_crewai.agent_runtime.hooks import (
    HookState,
    build_post_tool_use_hook,
    build_pre_tool_use_hook,
    tool_query_key,
)
from sufe_saads_crewai.agent_runtime.structured import (
    StructuredDecisionEngine,
    extract_json_object,
)
from sufe_saads_crewai.intel.context import render_round_context
from sufe_saads_crewai.schemas import IntelRunBlackboard, QueryHistoryEntry, RawIntelItem


class DecisionModel(BaseModel):
    should_continue: bool
    confidence: float
    rationale: str


def _run(coro):
    return asyncio.run(coro)


class ProviderResolutionTests(unittest.TestCase):
    def test_explicit_provider_selection(self) -> None:
        with mock.patch.dict(os.environ, {"INTEL_SDK_PROVIDER": "glm"}):
            spec = runtime_client.selected_provider()
            self.assertEqual(spec.name, "glm")
            self.assertEqual(spec.base_url, runtime_client.GLM_ANTHROPIC_BASE_URL)
        with mock.patch.dict(os.environ, {"INTEL_SDK_PROVIDER": "deepseek"}):
            spec = runtime_client.selected_provider()
            self.assertEqual(spec.name, "deepseek")
            self.assertEqual(spec.base_url, runtime_client.DEEPSEEK_ANTHROPIC_BASE_URL)

    def test_unknown_provider_raises(self) -> None:
        with mock.patch.dict(os.environ, {"INTEL_SDK_PROVIDER": "nope"}):
            with self.assertRaises(ValueError):
                runtime_client.selected_provider()

    def test_intel_sdk_model_overrides_provider_default(self) -> None:
        env = {"INTEL_SDK_PROVIDER": "deepseek", "INTEL_SDK_MODEL": "custom-main"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(runtime_client.main_model(), "custom-main")

    def test_anthropic_env_shape(self) -> None:
        env = {
            "INTEL_SDK_PROVIDER": "deepseek",
            "DEEPSEEK_API_KEY": "sk-test",
            "INTEL_SDK_MODEL": "",
            "INTEL_SDK_FAST_MODEL": "",
            "DEEPSEEK_MODEL": "",
            "DEEPSEEK_FAST_MODEL": "",
            "ANTHROPIC_BASE_URL": "",
            "ANTHROPIC_AUTH_TOKEN": "",
        }
        with mock.patch.dict(os.environ, env):
            injected = runtime_client.anthropic_env()
        self.assertEqual(
            injected["ANTHROPIC_BASE_URL"], runtime_client.DEEPSEEK_ANTHROPIC_BASE_URL
        )
        self.assertEqual(injected["ANTHROPIC_AUTH_TOKEN"], "sk-test")
        self.assertEqual(injected["ANTHROPIC_API_KEY"], "")
        self.assertEqual(injected["ANTHROPIC_DEFAULT_OPUS_MODEL"], "deepseek-v4-pro")
        self.assertEqual(injected["ANTHROPIC_DEFAULT_HAIKU_MODEL"], "deepseek-v4-flash")


class HookTests(unittest.TestCase):
    def _input(self, a: int = 1) -> dict:
        return {
            "tool_name": "mcp__intel_sources__search_nvd",
            "tool_input": {"keyword_search": "MLflow", "a": a},
        }

    def test_post_hook_records_and_pre_hook_blocks_duplicates(self) -> None:
        state = HookState()
        pre = build_pre_tool_use_hook(state)
        post = build_post_tool_use_hook(state)

        self.assertEqual(_run(pre(self._input(), None, None)), {})
        _run(post(self._input(), "tu1", None))
        self.assertEqual(state.calls_used, 1)

        verdict = _run(pre(self._input(), None, None))
        self.assertEqual(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertEqual(state.denied[-1]["reason"], "duplicate_query")
        # different params pass again
        self.assertEqual(_run(pre(self._input(a=2), None, None)), {})

    def test_pre_hook_enforces_run_budget(self) -> None:
        state = HookState(max_api_calls=1)
        pre = build_pre_tool_use_hook(state)
        post = build_post_tool_use_hook(state)
        _run(post(self._input(), None, None))
        verdict = _run(pre(self._input(a=3), None, None))
        self.assertEqual(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertEqual(state.denied[-1]["reason"], "run_budget_exhausted")

    def test_non_intel_tools_pass_through(self) -> None:
        state = HookState(max_api_calls=0)
        pre = build_pre_tool_use_hook(state)
        verdict = _run(pre({"tool_name": "Read", "tool_input": {}}, None, None))
        self.assertEqual(verdict, {})

    def test_tool_query_key_ignores_empty_values(self) -> None:
        key1 = tool_query_key("t", {"a": 1, "b": None, "c": ""})
        key2 = tool_query_key("t", {"a": 1})
        self.assertEqual(key1, key2)


class StructuredDecisionTests(unittest.TestCase):
    def test_valid_tool_forced_dict_is_validated(self) -> None:
        async def runner(prompt, schema, system_prompt, model, max_turns):
            self.assertIn("properties", schema)
            return {"should_continue": True, "confidence": 0.8, "rationale": "go"}

        engine = StructuredDecisionEngine(model="fake", runner=runner)
        decision = engine.decide("test", "prompt", DecisionModel)
        self.assertIsNotNone(decision)
        self.assertTrue(decision.should_continue)
        self.assertEqual(engine.telemetry.successes, 1)

    def test_json_text_dual_mode(self) -> None:
        async def runner(prompt, schema, system_prompt, model, max_turns):
            return 'Here you go:\n```json\n{"should_continue": false, "confidence": 0.4, "rationale": "stop"}\n```'

        engine = StructuredDecisionEngine(model="fake", runner=runner)
        decision = engine.decide("test", "prompt", DecisionModel)
        self.assertIsNotNone(decision)
        self.assertFalse(decision.should_continue)

    def test_failures_return_none_and_are_counted(self) -> None:
        async def crash(prompt, schema, system_prompt, model, max_turns):
            raise RuntimeError("endpoint down")

        async def garbage(prompt, schema, system_prompt, model, max_turns):
            return "not json at all"

        for runner in (crash, garbage):
            engine = StructuredDecisionEngine(model="fake", runner=runner)
            self.assertIsNone(engine.decide("test", "prompt", DecisionModel))
            self.assertEqual(engine.telemetry.successes, 0)
            self.assertEqual(len(engine.telemetry.failures), 1)

    def test_extract_json_object_handles_fences(self) -> None:
        self.assertEqual(extract_json_object('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(extract_json_object('noise {"a": 1} noise'), {"a": 1})


class ContextRenderTests(unittest.TestCase):
    def test_digest_contains_metrics_but_never_raw_text(self) -> None:
        blackboard = IntelRunBlackboard(run_id="t", run_goal="collect intel")
        secret = "RAW_TEXT_MUST_NOT_LEAK_INTO_CONTEXT"
        blackboard.raw_items.append(
            RawIntelItem(
                item_id="arxiv:1",
                source_name="arxiv_api",
                source_uri="https://example.test/1",
                title="prompt injection survey",
                summary="short summary",
                raw_text=secret * 50,
                relevance_score=0.8,
            )
        )
        blackboard.query_history.append(
            QueryHistoryEntry(
                query_text="q1",
                source_names=["arxiv_api"],
                result_count=1,
                novelty_score=1.0,
                round_index=0,
                metadata={"new_item_ids": ["arxiv:1"], "source_query_plans": []},
            )
        )
        digest = render_round_context(blackboard, 1, 5, bandit_summary="Bandit ranking: arxiv first")
        self.assertIn("prompt injection survey", digest)
        self.assertIn("Bandit ranking", digest)
        self.assertNotIn(secret, digest)
        self.assertLessEqual(len(digest), 9000)

    def test_digest_truncates_to_budget(self) -> None:
        blackboard = IntelRunBlackboard(run_id="t", run_goal="g" * 50)
        for index in range(200):
            blackboard.query_history.append(
                QueryHistoryEntry(
                    query_text=f"query {index} " + "x" * 80,
                    source_names=["arxiv_api"],
                    result_count=1,
                    round_index=index,
                    metadata={"new_item_ids": [], "source_query_plans": []},
                )
            )
        digest = render_round_context(blackboard, 199, 200, max_chars=2000)
        self.assertLessEqual(len(digest), 2000)


if __name__ == "__main__":
    unittest.main()
