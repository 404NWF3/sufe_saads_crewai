from __future__ import annotations

import pytest

from intel_agent import mongo_store
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.schemas import IntelRunBlackboard, SourceCheckpoint
from intel_agent.tests.conftest import make_item


def _blackboard(run_id: str, item_ids: list[str]) -> IntelRunBlackboard:
    bb = IntelRunBlackboard(run_id=run_id, run_goal="g")
    bb.raw_items.extend(make_item(i) for i in item_ids)
    return bb


# ------------------------------------------------------------ pure builders


def test_build_item_update_keys_on_item_id_and_tracks_provenance():
    item = make_item("nvd:cve-2026-1", topics=["prompt injection"])
    filt, update = mongo_store.build_item_update(item, "run-1", "2026-07-09T00:00:00Z")
    assert filt == {"_id": "nvd:cve-2026-1"}
    assert update["$addToSet"] == {"run_ids": "run-1"}
    assert update["$setOnInsert"]["first_run_id"] == "run-1"
    assert update["$set"]["last_run_id"] == "run-1"
    assert update["$set"]["topics"] == ["prompt injection"]
    # first/last timestamps must not collide across $set and $setOnInsert
    assert set(update["$set"]) & set(update["$setOnInsert"]) == set()


def test_build_run_document_strips_raw_text_but_keeps_item_ids():
    bb = _blackboard("run-1", ["nvd:a", "nvd:b"])
    doc = mongo_store.build_run_document(bb, [], "succeeded", "2026-07-09T00:00:00Z")
    assert doc["_id"] == "run-1"
    assert doc["item_count"] == 2
    assert doc["item_ids"] == ["nvd:a", "nvd:b"]
    assert all(raw["raw_text"] is None for raw in doc["blackboard"]["raw_items"])


def test_json_and_mongo_run_summaries_use_the_same_adaptive_fields(tmp_path):
    board = _blackboard("consistent", ["nvd:a"])
    expected = JsonIntelRunStore(root_dir=tmp_path)._summary(board, [])
    assert mongo_store.run_summary(board, []) == expected


# ----------------------------------------------------- integration (mongomock)


@pytest.fixture()
def store():
    mongomock = pytest.importorskip("mongomock")
    pytest.importorskip("pymongo")
    db = mongomock.MongoClient()["intel_agent_test"]
    return mongo_store.MongoIntelRunStore(database=db)


def test_cross_run_dedup_upserts_shared_items(store):
    store.save_run(_blackboard("run-1", ["nvd:a", "nvd:b"]))
    store.save_run(_blackboard("run-2", ["nvd:b", "nvd:c"]))  # nvd:b repeats

    # 3 distinct items despite 4 sightings across 2 runs
    assert store.distinct_item_count() == 3
    shared = store._items.find_one({"_id": "nvd:b"})
    assert sorted(shared["run_ids"]) == ["run-1", "run-2"]
    assert shared["first_run_id"] == "run-1"
    assert shared["last_run_id"] == "run-2"


def test_load_all_blackboards_and_latest(store):
    store.save_run(_blackboard("run-1", ["nvd:a"]))
    import time

    time.sleep(0.05)
    store.save_run(_blackboard("run-2", ["nvd:b"]))

    boards = store.load_all_blackboards(limit=10)
    assert {b.run_id for b in boards} == {"run-1", "run-2"}
    latest = store.load_latest_payload()
    assert latest["run_id"] == "run-2"
    assert "Store: MongoDB" in store.format_latest_intel()


def test_load_global_corpus_and_latest_source_checkpoint(store):
    board = _blackboard("run-checkpoint", ["nvd:a"])
    board.source_checkpoints.append(
        SourceCheckpoint(source_name="nvd_cve_api", complete=True)
    )
    store.save_run(board)
    assert store.load_latest_payload()["schema_version"] == 3
    assert [item.item_id for item in store.load_corpus_items()] == ["nvd:a"]
    assert store.load_source_checkpoints()[0].source_name == "nvd_cve_api"


def test_mongo_store_reads_v2_blackboard_with_v3_defaults(store):
    board = _blackboard("v2-mongo", ["nvd:a"])
    doc = mongo_store.build_run_document(board, [], "succeeded", "2026-07-09T00:00:00Z")
    doc["schema_version"] = 2
    for field in (
        "corpus_gaps",
        "run_gaps",
        "query_outcomes",
        "source_checkpoints",
        "candidate_topics",
        "extended_trends",
        "sdk_session_id",
        "stop_reason",
        "collection_strategy",
    ):
        doc["blackboard"].pop(field, None)
    store._runs.insert_one(doc)
    loaded = store.load_all_blackboards(limit=10)[0]
    assert loaded.run_id == "v2-mongo"
    assert loaded.corpus_gaps == [] and loaded.collection_strategy == "legacy"


def test_list_run_summaries_and_query_items(store):
    store.save_run(_blackboard("run-1", ["nvd:a", "nvd:b"]))
    import time

    time.sleep(0.05)
    store.save_run(_blackboard("run-2", ["nvd:b", "nvd:c"]))

    summaries = store.list_run_summaries(limit=10)
    assert [s["run_id"] for s in summaries] == ["run-2", "run-1"]
    assert summaries[0]["item_count"] == 2

    by_run = store.query_items(run_id="run-1", limit=50)
    assert {d["item_id"] for d in by_run} == {"nvd:a", "nvd:b"}

    by_text = store.query_items(text="nvd:c", limit=10)
    assert len(by_text) == 1
    assert by_text[0]["item_id"] == "nvd:c"

    assert store.run_count() == 2
    assert "nvd_cve_api" in store.distinct_sources()


def test_save_and_list_knowledge_graphs(store):
    store.save_run(_blackboard("run-kg", ["nvd:kg"]))
    record = {
        "item_id": "nvd:kg",
        "run_id": "run-kg",
        "status": "succeeded",
        "source_name": "nvd_cve_api",
        "triplet_count": 3,
        "entity_count": 4,
        "model": "glm-4.7",
        "embedding_model": "embedding-3",
    }
    store.save_knowledge_graph(record, graph={"IE": {"triplets": []}})
    rows = store.list_knowledge_graphs(limit=10)
    assert len(rows) == 1
    assert rows[0]["item_id"] == "nvd:kg"
    assert "graph" not in rows[0]
    full = store.load_knowledge_graph("nvd:kg")
    assert full is not None and "graph" in full
    item = store.get_item("nvd:kg")
    assert item["kg_status"] == "succeeded"
    assert store.knowledge_graph_count() == 1
