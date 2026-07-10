"""Tests for Gradio Memory panel helpers."""

from __future__ import annotations

import json
from pathlib import Path

from console.memory_browser import load_playbook, load_relevance_cache, memory_status
from intel_agent.memory.playbook import PlaybookStore


def test_load_playbook_and_cache(tmp_path: Path, monkeypatch):
    pb_path = tmp_path / "playbook.jsonl"
    store = PlaybookStore(path=pb_path, embedder=None)
    store.upsert(
        technique_text="query NVD with CWE-94 for agent tool abuse",
        source_name="nvd_cve_api",
        operator_signature="cwe=CWE-94",
        topic_bucket="agent tool abuse",
        reward=2.5,
        run_id="run-m1",
    )
    store.save()

    cache_path = tmp_path / "relevance_cache.jsonl"
    cache_path.write_text(
        json.dumps({"hash": "abc123", "embedding_score": 0.71, "topic": "jailbreak"}) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("console.memory_browser._playbook_path", lambda: pb_path)
    monkeypatch.setattr("console.memory_browser._cache_path", lambda: cache_path)
    monkeypatch.setattr("console.db_browser.EXPORT_DIR", tmp_path / "exports")

    status = memory_status()
    assert "Techniques: 1" in status
    assert "Cached embedding scores: 1" in status

    msg, rows, csv_path = load_playbook(topic="agent tool abuse", limit=10)
    assert "1 technique" in msg
    assert rows[0][2] == "nvd_cve_api"
    assert "CWE-94" in rows[0][10]
    assert csv_path and Path(csv_path).exists()

    msg2, cache_rows, csv2 = load_relevance_cache(min_score=0.5, limit=10)
    assert "1 cache" in msg2
    assert cache_rows[0][0] == "abc123"
    assert csv2 and Path(csv2).exists()
