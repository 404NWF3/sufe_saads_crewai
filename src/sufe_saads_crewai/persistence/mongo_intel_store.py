from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

import importlib
import importlib.util

ASCENDING = 1
DESCENDING = -1

from sufe_saads_crewai.schemas import IntelRunBlackboard, RawIntelItem, RawIntelItemBatch

from .intel_run_store import REAL_SOURCE_NAMES, format_intel_items

DEFAULT_MONGODB_URI = "mongodb://localhost:27017"
DEFAULT_MONGODB_DATABASE = "sufe_saads_crewai"
RUNS_COLLECTION = "intel_runs"
RAW_ITEMS_COLLECTION = "raw_intel_items"
QUERY_FEEDBACK_COLLECTION = "query_feedback"
LATEST_INDEX_COLLECTION = "latest_indexes"


class MongoIntelRunStore:
    """MongoDB-backed document store for autonomous intelligence runs.

    The store keeps a full run document in ``intel_runs`` and also upserts raw
    intelligence items and query feedback into their own collections so future
    runs can plan against the database's actual coverage and source quality.
    """

    def __init__(
        self,
        uri: str = DEFAULT_MONGODB_URI,
        database_name: str = DEFAULT_MONGODB_DATABASE,
        client: Any | None = None,
    ) -> None:
        self.uri = uri
        self.database_name = database_name
        if importlib.util.find_spec("pymongo") is None:
            raise RuntimeError(
                "MongoDB persistence requires pymongo. Install it with "
                "`uv add pymongo>=4.7`."
            )
        pymongo = importlib.import_module("pymongo")
        self._update_one = pymongo.UpdateOne
        self.client = client or pymongo.MongoClient(uri)
        self.db = self.client[database_name]
        self.runs = self.db[RUNS_COLLECTION]
        self.raw_items = self.db[RAW_ITEMS_COLLECTION]
        self.query_feedback = self.db[QUERY_FEEDBACK_COLLECTION]
        self.latest_indexes = self.db[LATEST_INDEX_COLLECTION]
        self._ensure_indexes()

    @classmethod
    def from_env(cls) -> "MongoIntelRunStore":
        return cls(
            uri=os.getenv("MONGODB_URI", DEFAULT_MONGODB_URI),
            database_name=os.getenv("MONGODB_DATABASE", DEFAULT_MONGODB_DATABASE),
        )

    def run_path(self, run_id: str) -> Path:
        return Path(f"mongodb/{self.database_name}/{RUNS_COLLECTION}/{run_id}")

    def latest_index_path(self) -> Path:
        return Path(f"mongodb/{self.database_name}/{LATEST_INDEX_COLLECTION}/latest")

    def save_run(
        self,
        blackboard: IntelRunBlackboard,
        raw_item_batches: list[RawIntelItemBatch] | None = None,
        status: str = "succeeded",
    ) -> Path:
        saved_at = _utcnow_iso()
        batches = raw_item_batches or []
        payload = {
            "schema_version": 1,
            "run_id": blackboard.run_id,
            "status": status,
            "saved_at": saved_at,
            "summary": self._summary(blackboard, batches),
            "raw_item_batches": [batch.model_dump(mode="json") for batch in batches],
            "blackboard": blackboard.model_dump(mode="json"),
        }
        self.runs.update_one(
            {"run_id": blackboard.run_id},
            {"$set": payload, "$setOnInsert": {"created_at": saved_at}},
            upsert=True,
        )
        self.latest_indexes.update_one(
            {"index_name": "latest"},
            {
                "$set": {
                    "index_name": "latest",
                    "run_id": blackboard.run_id,
                    "status": status,
                    "saved_at": saved_at,
                    "raw_items": len(blackboard.raw_items),
                    "rounds": len(blackboard.query_history),
                }
            },
            upsert=True,
        )
        self._upsert_raw_items(blackboard, saved_at)
        self._upsert_query_feedback(blackboard, saved_at)
        return self.run_path(blackboard.run_id)

    def load_run_payload(self, run_id: str) -> dict[str, Any]:
        payload = self.runs.find_one({"run_id": run_id}, {"_id": 0})
        if payload is None:
            raise FileNotFoundError(f"No MongoDB intelligence run found for {run_id}")
        return payload

    def latest_run_path(self, real_only: bool = False) -> Path | None:
        payload = self.load_latest_payload(real_only=real_only)
        if payload is None:
            return None
        return self.run_path(str(payload["run_id"]))

    def load_latest_payload(self, real_only: bool = False) -> dict[str, Any] | None:
        query: dict[str, Any] = {}
        if real_only:
            query["run_id"] = {"$regex": "^real-"}
        return self.runs.find_one(query, {"_id": 0}, sort=[("saved_at", DESCENDING)])

    def list_run_paths(self, limit: int = 20) -> list[Path]:
        docs = self.runs.find({}, {"_id": 0, "run_id": 1}, sort=[("saved_at", DESCENDING)], limit=limit)
        return [self.run_path(str(doc["run_id"])) for doc in docs]

    def latest_raw_items(
        self,
        limit: int = 20,
        real_only: bool = False,
    ) -> list[RawIntelItem]:
        query: dict[str, Any] = {}
        if real_only:
            query["source_name"] = {"$in": sorted(REAL_SOURCE_NAMES)}
        docs = self.raw_items.find(
            query,
            {"_id": 0, "item": 1},
            sort=[("sort_timestamp", DESCENDING), ("saved_at", DESCENDING)],
            limit=limit,
        )
        return [RawIntelItem.model_validate(doc["item"]) for doc in docs]

    def format_latest_intel(self, limit: int = 20, real_only: bool = False) -> str:
        payload = self.load_latest_payload(real_only=real_only)
        if not payload:
            qualifier = " real" if real_only else ""
            return f"No persisted{qualifier} intelligence runs found in MongoDB {self.database_name}."

        path = self.latest_run_path(real_only=real_only)
        lines = [
            f"Latest run: {payload['run_id']}",
            f"Status: {payload.get('status', 'unknown')}",
            f"Saved at: {payload.get('saved_at', 'unknown')}",
            f"Store: {path}",
            "",
            format_intel_items(self.latest_raw_items(limit=limit, real_only=real_only)),
        ]
        return "\n".join(lines).rstrip()

    def _ensure_indexes(self) -> None:
        self.runs.create_index([("run_id", ASCENDING)], unique=True)
        self.runs.create_index([("saved_at", DESCENDING)])
        self.raw_items.create_index([("item_id", ASCENDING)], unique=True)
        self.raw_items.create_index([("source_name", ASCENDING), ("sort_timestamp", DESCENDING)])
        self.query_feedback.create_index(
            [("run_id", ASCENDING), ("round_index", ASCENDING), ("query_text", ASCENDING)],
            unique=True,
        )
        self.latest_indexes.create_index([("index_name", ASCENDING)], unique=True)

    def _upsert_raw_items(self, blackboard: IntelRunBlackboard, saved_at: str) -> None:
        operations = []
        for item in blackboard.raw_items:
            item_payload = item.model_dump(mode="json")
            operations.append(
                self._update_one(
                    {"item_id": item.item_id},
                    {
                        "$set": {
                            "item_id": item.item_id,
                            "source_name": item.source_name,
                            "source_uri": item.source_uri,
                            "title": item.title,
                            "summary": item.summary,
                            "topics": item.metadata.get("topics", []),
                            "relevance_score": item.relevance_score,
                            "sort_timestamp": _item_sort_timestamp(item),
                            "last_seen_run_id": blackboard.run_id,
                            "saved_at": saved_at,
                            "item": item_payload,
                        },
                        "$addToSet": {"run_ids": blackboard.run_id},
                        "$setOnInsert": {"first_seen_run_id": blackboard.run_id},
                    },
                    upsert=True,
                )
            )
        if operations:
            self.raw_items.bulk_write(operations, ordered=False)

    def _upsert_query_feedback(self, blackboard: IntelRunBlackboard, saved_at: str) -> None:
        operations = []
        for entry in blackboard.query_history:
            operations.append(
                self._update_one(
                    {
                        "run_id": blackboard.run_id,
                        "round_index": entry.round_index,
                        "query_text": entry.query_text,
                    },
                    {
                        "$set": {
                            "run_id": blackboard.run_id,
                            "query_text": entry.query_text,
                            "source_names": entry.source_names,
                            "result_count": entry.result_count,
                            "novelty_score": entry.novelty_score,
                            "noise_ratio": entry.noise_ratio,
                            "duplicate_ratio": entry.duplicate_ratio,
                            "round_index": entry.round_index,
                            "metadata": entry.metadata,
                            "saved_at": saved_at,
                        }
                    },
                    upsert=True,
                )
            )
        if operations:
            self.query_feedback.bulk_write(operations, ordered=False)

    def _summary(
        self,
        blackboard: IntelRunBlackboard,
        raw_item_batches: list[RawIntelItemBatch],
    ) -> dict[str, Any]:
        return {
            "run_goal": blackboard.run_goal,
            "run_mode": blackboard.run_mode,
            "rounds": len(blackboard.query_history),
            "raw_items": len(blackboard.raw_items),
            "raw_item_batches": len(raw_item_batches),
            "coverage_gaps_remaining": [
                gap.taxonomy_or_component for gap in blackboard.coverage_gaps
            ],
            "source_proposals": [
                {
                    "source_name": proposal.source_name,
                    "approval_status": proposal.approval_status,
                }
                for proposal in blackboard.source_proposals
            ],
            "last_action": (
                blackboard.action_history[-1].action_type
                if blackboard.action_history
                else None
            ),
        }


def _item_sort_timestamp(item: RawIntelItem) -> str:
    timestamp = item.published_at or item.fetched_at
    return timestamp.isoformat()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
