"""Offline tests for Gradio database panel helpers."""

from __future__ import annotations

from pathlib import Path

from console.db_browser import _item_table, _write_csv, query_items_panel, refresh_runs
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.schemas import IntelRunBlackboard
from intel_agent.tests.conftest import make_item


def test_json_store_query_and_csv(tmp_path: Path, monkeypatch):
    store = JsonIntelRunStore(root_dir=tmp_path / "runs")
    bb = IntelRunBlackboard(run_id="run-db-1", run_goal="g", run_mode="bootstrap")
    bb.raw_items.append(make_item("nvd:db-1", topics=["jailbreak"]))
    store.save_run(bb)

    monkeypatch.setattr("console.db_browser.default_store", lambda: store)
    monkeypatch.setattr("console.db_browser.EXPORT_DIR", tmp_path / "exports")

    msg, table, path = refresh_runs(10)
    assert "1 run" in msg
    assert table[0][0] == "run-db-1"
    assert path and Path(path).exists()

    msg2, items, path2 = query_items_panel("", "jailbreak", "", "", 50)
    assert "1 item" in msg2
    assert items[0][0] == "nvd:db-1"
    assert path2 and Path(path2).exists()
    assert "jailbreak" in Path(path2).read_text(encoding="utf-8")


def test_item_table_flattens_topics(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("console.db_browser.EXPORT_DIR", tmp_path / "exports")
    rows = _item_table(
        [
            {
                "item_id": "x",
                "source_name": "nvd_cve_api",
                "title": "t",
                "summary": "s",
                "relevance_score": 0.9,
                "topics": ["prompt injection"],
                "run_ids": ["r1"],
            }
        ]
    )
    assert rows[0][5] == "prompt injection"
    path = _write_csv(["a", "b"], [["1", "2"]], "t")
    assert Path(path).exists()
