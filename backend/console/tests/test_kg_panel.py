"""Tests for KG panel persist + env config."""

from __future__ import annotations

import json
from pathlib import Path

from console.kg_panel import _persist_record, default_kg_config, list_kg_records
from ctinexus_kg.schemas import (
    ItemKnowledgeGraphRecord,
    KgEligibilityDecision,
    KgGenerationConfig,
)
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.tests.conftest import make_item


def test_kg_config_from_env_defaults(monkeypatch):
    monkeypatch.delenv("CTINEXUS_MODEL", raising=False)
    monkeypatch.delenv("GLM_MODEL", raising=False)
    monkeypatch.setenv("GLM_BASE_URL", "https://example.glm")
    cfg = KgGenerationConfig.from_env()
    assert cfg.model == "glm-4.7"
    assert cfg.embedding_model == "embedding-3"
    assert cfg.base_url == "https://example.glm"
    assert default_kg_config().model == "glm-4.7"


def test_persist_and_list_kg_records(tmp_path: Path, monkeypatch):
    store = JsonIntelRunStore(root_dir=tmp_path / "runs", kg_dir=tmp_path / "kgs")
    monkeypatch.setattr("console.kg_panel.default_store", lambda: store)
    monkeypatch.setattr("console.db_browser.default_store", lambda: store)
    monkeypatch.setattr("console.db_browser.EXPORT_DIR", tmp_path / "exports")

    graph_path = tmp_path / "item.json"
    graph_path.write_text(
        json.dumps({"IE": {"triplets": [{"s": "a", "r": "b", "o": "c"}]}}),
        encoding="utf-8",
    )
    item = make_item("nvd:kg-1", topics=["jailbreak"])
    record = ItemKnowledgeGraphRecord(
        run_id="run-kg",
        item_id=item.item_id,
        source_name=item.source_name,
        source_uri=item.source_uri,
        status="succeeded",
        eligibility=KgEligibilityDecision(
            item_id=item.item_id, eligible=True, matched_topics=["jailbreak"]
        ),
        triplet_count=1,
        entity_count=2,
        model="glm-4.7",
        embedding_model="embedding-3",
        ctinexus_json_path=str(graph_path),
    )
    _persist_record(record)
    loaded = store.load_knowledge_graph("nvd:kg-1")
    assert loaded is not None
    assert loaded["status"] == "succeeded"
    assert loaded["graph"]["IE"]["triplets"]

    msg, rows, csv_path = list_kg_records(limit=10)
    assert "1 KG" in msg
    assert rows[0][0] == "nvd:kg-1"
    assert csv_path and Path(csv_path).exists()
