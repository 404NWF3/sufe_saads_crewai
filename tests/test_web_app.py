from __future__ import annotations

import unittest


class WebAppTests(unittest.TestCase):
    def test_build_app_registers_state_component(self) -> None:
        try:
            from gradio.components import State
        except Exception as exc:
            self.skipTest(f"Gradio is not installed in this environment: {exc}")

        from sufe_saads_crewai.web.app import build_app

        app = build_app()
        states = [component for component in app.blocks.values() if isinstance(component, State)]

        self.assertEqual(len(states), 1)
        self.assertTrue(states[0].stateful)

    def test_raw_item_dropdown_choices_use_existing_indices(self) -> None:
        from sufe_saads_crewai.schemas import RawIntelItem
        from sufe_saads_crewai.web.app import _make_kg_config, _raw_item_choices, _selected_item_index

        kg_config = _make_kg_config(
            enabled=True,
            model="gpt-4.1",
            temperature=0.8,
            base_url="",
            embedding_model="text-embedding-3-large",
            similarity_threshold=0.6,
            ie_shot=2,
            et_shot=8,
            lp_shot=2,
        )
        choices = _raw_item_choices(
            [
                RawIntelItem(
                    item_id="nvd:cve-test",
                    source_name="nvd_cve_api",
                    source_uri="https://example.test/cve",
                    title="Prompt injection issue",
                    summary="A prompt injection issue affects an LLM application.",
                    relevance_score=0.8,
                    metadata={"topics": ["prompt injection"]},
                ),
                RawIntelItem(
                    item_id="arxiv:paper-test",
                    source_name="arxiv_api",
                    source_uri="https://arxiv.org/abs/0000.00000",
                    title="Prompt injection paper",
                    summary="A prompt injection paper.",
                    relevance_score=0.9,
                    metadata={"topics": ["prompt injection"]},
                )
            ],
            kg_config,
        )

        self.assertEqual(len(choices), 1)
        self.assertTrue(choices[0][0].startswith("#0 | nvd_cve_api | score=0.80 |"))
        self.assertEqual(choices[0][1], "0")
        self.assertEqual(_selected_item_index(choices[0][1]), 0)
        self.assertEqual(_selected_item_index("100 | missing"), 100)
        self.assertEqual(_selected_item_index(None), -1)


if __name__ == "__main__":
    unittest.main()
