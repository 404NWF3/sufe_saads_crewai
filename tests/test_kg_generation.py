from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sufe_saads_crewai.kg import CtinexusKgGenerator, assess_kg_eligibility
from sufe_saads_crewai.kg.ctinexus_adapter import _litellm_openai_model_name
from sufe_saads_crewai.kg.prompting import build_ctinexus_input_text
from sufe_saads_crewai.schemas import KgGenerationConfig, RawIntelItem


class KgGenerationTests(unittest.TestCase):
    def test_arxiv_items_are_skipped_by_default(self) -> None:
        item = RawIntelItem(
            item_id="paper-1",
            source_name="arxiv_api",
            source_uri="https://arxiv.org/abs/0000.00000",
            title="Prompt injection benchmark",
            summary="A study about prompt injection in LLM systems.",
            relevance_score=0.9,
            metadata={"topics": ["prompt injection"]},
        )

        decision = assess_kg_eligibility(
            item,
            KgGenerationConfig(),
            target_topics=["prompt injection"],
        )

        self.assertFalse(decision.eligible)
        self.assertEqual(decision.excluded_reason, "source_excluded:arxiv_api")

    def test_ctinexus_adapter_writes_record_and_manifest_with_fake_processor(self) -> None:
        with TemporaryDirectory() as temp_dir:
            graph_html = Path(temp_dir) / "graph.html"
            graph_html.write_text("<html></html>", encoding="utf-8")

            def fake_process(**kwargs):
                self.assertIn("text", kwargs)
                self.assertNotIn("source_url", kwargs)
                output = Path(kwargs["output"])
                payload = {
                    "IE": {
                        "triplets": [
                            {
                                "subject": "vulnerable LLM app",
                                "relation": "is targeted by",
                                "object": "prompt injection",
                            }
                        ]
                    },
                    "EA": {
                        "aligned_triplets": [
                            {
                                "subject": {"entity_id": "llm-app"},
                                "relation": "is targeted by",
                                "object": {"entity_id": "prompt-injection"},
                            }
                        ]
                    },
                    "LP": {"predicted_links": []},
                    "entity_relation_graph": str(graph_html),
                }
                output.write_text(json.dumps(payload), encoding="utf-8")
                return payload

            item = RawIntelItem(
                item_id="nvd-1",
                source_name="nvd_cve_api",
                source_uri="https://nvd.nist.gov/vuln/detail/CVE-TEST",
                title="Prompt injection vulnerability in an LLM application",
                summary="A prompt injection flaw lets an attacker override system instructions.",
                relevance_score=0.85,
                metadata={"topics": ["prompt injection"], "cve_id": "CVE-TEST"},
            )
            generator = CtinexusKgGenerator(
                KgGenerationConfig(output_root=temp_dir),
                process_func=fake_process,
            )

            records = generator.generate_for_items(
                "run-kg",
                [item],
                target_topics=["prompt injection"],
            )

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].status, "succeeded")
            self.assertEqual(records[0].triplet_count, 1)
            self.assertEqual(records[0].entity_count, 2)
            self.assertTrue(Path(records[0].ctinexus_json_path or "").exists())
            self.assertTrue(Path(records[0].graph_html_path or "").exists())
            manifest = Path(temp_dir) / "run-kg_kg" / "manifest.json"
            self.assertTrue(manifest.exists())
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["succeeded"], 1)

    def test_kg_input_uses_raw_text_or_summary_without_item_metadata(self) -> None:
        item = RawIntelItem(
            item_id="nvd-2",
            source_name="nvd_cve_api",
            source_uri="https://nvd.nist.gov/vuln/detail/CVE-SECRET",
            title="Metadata title should not become KG evidence",
            summary="Summary evidence about prompt injection.",
            raw_text="Raw CTI evidence: attacker sends prompt injection payload.",
            relevance_score=0.9,
            metadata={"cve_id": "CVE-SECRET", "topics": ["prompt injection"]},
        )

        text = build_ctinexus_input_text(
            item,
            matched_topics=["prompt injection"],
            max_chars=4000,
        )

        self.assertIn("Raw CTI evidence: attacker sends prompt injection payload.", text)
        self.assertEqual(text, "Raw CTI evidence: attacker sends prompt injection payload.")
        self.assertNotIn("Metadata title should not become KG evidence", text)
        self.assertNotIn("CVE-SECRET", text)
        self.assertNotIn("https://nvd.nist.gov", text)

    def test_items_without_summary_or_raw_text_are_not_eligible(self) -> None:
        item = RawIntelItem(
            item_id="empty-1",
            source_name="nvd_cve_api",
            source_uri="https://example.test/empty",
            title="Prompt injection only in title",
            relevance_score=0.9,
            metadata={"topics": ["prompt injection"]},
        )

        decision = assess_kg_eligibility(
            item,
            KgGenerationConfig(),
            target_topics=["prompt injection"],
        )

        self.assertFalse(decision.eligible)
        self.assertEqual(decision.excluded_reason, "no_summary_or_raw_text")

    def test_bare_openai_compatible_model_names_are_prefixed_for_litellm(self) -> None:
        self.assertEqual(_litellm_openai_model_name("glm-4.7"), "openai/glm-4.7")
        self.assertEqual(_litellm_openai_model_name("gpt-4.1"), "openai/gpt-4.1")
        self.assertEqual(
            _litellm_openai_model_name("openai/glm-4.7"),
            "openai/glm-4.7",
        )


if __name__ == "__main__":
    unittest.main()
