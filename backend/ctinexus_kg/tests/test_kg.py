from __future__ import annotations

import json
from pathlib import Path

from ctinexus_kg import (
    CtinexusKgGenerator,
    KgGenerationConfig,
    RawIntelItem,
    assess_kg_eligibility,
    build_ctinexus_input_text,
    coerce_raw_item,
    generate_for_run,
)
from ctinexus_kg.ctinexus_adapter import _litellm_openai_model_name


def _item(**kwargs) -> RawIntelItem:
    defaults = dict(
        item_id="nvd-1",
        source_name="nvd_cve_api",
        source_uri="https://nvd.nist.gov/vuln/detail/CVE-TEST",
        title="Prompt injection vulnerability",
        summary="A prompt injection flaw lets an attacker override system instructions.",
        relevance_score=0.85,
        metadata={"topics": ["prompt injection"]},
    )
    defaults.update(kwargs)
    return RawIntelItem(**defaults)


def test_arxiv_items_are_skipped_by_default():
    item = _item(
        item_id="paper-1",
        source_name="arxiv_api",
        source_uri="https://arxiv.org/abs/0000.00000",
        summary="A study about prompt injection in LLM systems.",
    )
    decision = assess_kg_eligibility(item, KgGenerationConfig(), target_topics=["prompt injection"])
    assert decision.eligible is False
    assert decision.excluded_reason == "source_excluded:arxiv_api"


def test_items_without_text_not_eligible():
    item = _item(summary="", raw_text=None, title="Prompt injection only in title")
    decision = assess_kg_eligibility(item, KgGenerationConfig(), target_topics=["prompt injection"])
    assert decision.eligible is False
    assert decision.excluded_reason == "no_summary_or_raw_text"


def test_kg_input_uses_raw_text_without_metadata():
    item = _item(
        title="Metadata title should not become KG evidence",
        summary="Summary evidence about prompt injection.",
        raw_text="Raw CTI evidence: attacker sends prompt injection payload.",
        metadata={"cve_id": "CVE-SECRET", "topics": ["prompt injection"]},
    )
    text = build_ctinexus_input_text(item, matched_topics=["prompt injection"], max_chars=4000)
    assert text == "Raw CTI evidence: attacker sends prompt injection payload."
    assert "CVE-SECRET" not in text
    assert "https://nvd.nist.gov" not in text


def test_adapter_writes_record_and_manifest(tmp_path: Path):
    graph_html = tmp_path / "graph.html"
    graph_html.write_text("<html></html>", encoding="utf-8")

    def fake_process(**kwargs):
        assert "text" in kwargs
        assert "source_url" not in kwargs
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

    generator = CtinexusKgGenerator(
        KgGenerationConfig(output_root=str(tmp_path)),
        process_func=fake_process,
    )
    records = generator.generate_for_items(
        "run-kg", [_item()], target_topics=["prompt injection"]
    )
    assert len(records) == 1
    assert records[0].status == "succeeded"
    assert records[0].triplet_count == 1
    assert records[0].entity_count == 2
    assert Path(records[0].ctinexus_json_path or "").exists()
    assert Path(records[0].graph_html_path or "").exists()
    manifest = tmp_path / "run-kg_kg" / "manifest.json"
    assert manifest.exists()
    assert json.loads(manifest.read_text(encoding="utf-8"))["summary"]["succeeded"] == 1


def test_failure_isolation_does_not_raise(tmp_path: Path):
    def boom(**_kwargs):
        raise RuntimeError("ctinexus exploded")

    records = generate_for_run(
        "run-fail",
        [_item()],
        config=KgGenerationConfig(output_root=str(tmp_path), fail_on_error=False),
        process_func=boom,
    )
    assert records[0].status == "failed"
    assert "exploded" in (records[0].error or "")
    assert (tmp_path / "run-fail_kg" / "manifest.json").exists()


def test_coerce_from_intel_agent_shaped_dict():
    dumped = {
        "item_id": "nvd:a",
        "source_name": "nvd_cve_api",
        "source_uri": "https://x/a",
        "title": "t",
        "summary": "prompt injection",
        "relevance_score": 0.9,
        "metadata": {"topics": ["prompt injection"]},
    }
    item = coerce_raw_item(dumped)
    assert item.item_id == "nvd:a"


def test_litellm_model_prefix():
    assert _litellm_openai_model_name("glm-4.7") == "openai/glm-4.7"
    assert _litellm_openai_model_name("openai/glm-4.7") == "openai/glm-4.7"
