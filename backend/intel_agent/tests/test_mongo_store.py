from __future__ import annotations

import pytest

from intel_agent import mongo_store
from intel_agent.schemas import IntelRunBlackboard
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
    store.save_run(_blackboard("run-2", ["nvd:b"]))

    boards = store.load_all_blackboards(limit=10)
    assert {b.run_id for b in boards} == {"run-1", "run-2"}
    latest = store.load_latest_payload()
    assert latest["run_id"] == "run-2"
    assert "Store: MongoDB" in store.format_latest_intel()
