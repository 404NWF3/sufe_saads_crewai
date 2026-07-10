"""MongoDB-backed history store for intel_agent runs.

Two collections, mirroring the two requirements:

- ``runs``  — one document per collection task (the whole blackboard, minus
  per-item ``raw_text`` which is bulky and already kept in ``items``). This is
  the durable record of *every* agent run.
- ``items`` — the global, de-duplicated intelligence store. Each document's
  ``_id`` is the item's natural key (``item_id`` = ``nvd:cve-...`` / ``arxiv:...``
  / ``cisa-kev:...`` / ``osv:...``), so the same piece of intel can never be
  stored twice: repeat sightings upsert into the same document, appending the
  run to a ``run_ids`` provenance array and refreshing ``last_seen_at``.

``pymongo`` is imported lazily inside the IO methods so this module (and the
pure document builders) import fine without the driver installed. Config is
read from the environment / ``.env`` via the runtime client's resolver.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from .persistence import format_intel_items
from .runtime.client import _setting
from .schemas import IntelRunBlackboard, RawIntelItem, RawIntelItemBatch

DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_MONGO_DB = "intel_agent"
DEFAULT_RUNS_COLLECTION = "runs"
DEFAULT_ITEMS_COLLECTION = "items"


# ------------------------------------------------------------------ config


def mongo_uri() -> str:
    return _setting("INTEL_MONGO_URI") or DEFAULT_MONGO_URI


def mongo_db_name() -> str:
    return _setting("INTEL_MONGO_DB") or DEFAULT_MONGO_DB


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def mongo_enabled() -> bool:
    """Mongo is on when a URI is configured or the flag is explicitly truthy."""
    return bool(_setting("INTEL_MONGO_URI")) or _truthy(_setting("INTEL_MONGO_ENABLED"))


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------- pure doc builders


def run_summary(blackboard: IntelRunBlackboard, batches: list[RawIntelItemBatch]) -> dict[str, Any]:
    return {
        "run_goal": blackboard.run_goal,
        "run_mode": blackboard.run_mode,
        "rounds": len(blackboard.query_history),
        "raw_items": len(blackboard.raw_items),
        "raw_item_batches": len(batches),
        "coverage_gaps_remaining": [g.taxonomy_or_component for g in blackboard.coverage_gaps],
        "last_action": (
            blackboard.action_history[-1].action_type if blackboard.action_history else None
        ),
    }


def build_run_document(
    blackboard: IntelRunBlackboard,
    batches: list[RawIntelItemBatch],
    status: str,
    saved_at: str,
) -> dict[str, Any]:
    board = blackboard.model_dump(mode="json")
    # raw_text is preserved in the items collection; drop it here to bound doc size.
    for raw in board.get("raw_items", []):
        raw["raw_text"] = None
    return {
        "_id": blackboard.run_id,
        "run_id": blackboard.run_id,
        "status": status,
        "saved_at": saved_at,
        "engine": "intel_agent",
        "summary": run_summary(blackboard, batches),
        "item_ids": [item.item_id for item in blackboard.raw_items],
        "item_count": len(blackboard.raw_items),
        "blackboard": board,
    }


def build_item_update(item: RawIntelItem, run_id: str, saved_at: str) -> tuple[dict, dict]:
    """Return ``(filter, update)`` for an idempotent upsert keyed on item_id."""
    doc = item.model_dump(mode="json")
    item_id = doc.pop("item_id")
    topics = list((item.metadata or {}).get("topics", []))
    filter_ = {"_id": item_id}
    update = {
        "$setOnInsert": {"first_seen_at": saved_at, "first_run_id": run_id},
        "$set": {
            **doc,
            "item_id": item_id,
            "topics": topics,
            "last_seen_at": saved_at,
            "last_run_id": run_id,
        },
        "$addToSet": {"run_ids": run_id},
    }
    return filter_, update


# --------------------------------------------------------------- the store


class MongoIntelRunStore:
    """Drop-in replacement for ``JsonIntelRunStore`` backed by MongoDB."""

    def __init__(
        self,
        uri: str | None = None,
        db_name: str | None = None,
        *,
        database: Any | None = None,
        runs_collection: str = DEFAULT_RUNS_COLLECTION,
        items_collection: str = DEFAULT_ITEMS_COLLECTION,
    ) -> None:
        self._uri = uri
        self._db_name = db_name
        self._database = database
        self._runs_name = runs_collection
        self._items_name = items_collection
        self._indexes_ready = False

    # ------------------------------------------------------------ plumbing

    def _db(self) -> Any:
        if self._database is None:
            from pymongo import MongoClient

            self._database = MongoClient(self._uri or mongo_uri())[self._db_name or mongo_db_name()]
        return self._database

    @property
    def _runs(self) -> Any:
        return self._db()[self._runs_name]

    @property
    def _items(self) -> Any:
        return self._db()[self._items_name]

    def _ensure_indexes(self) -> None:
        if self._indexes_ready:
            return
        self._runs.create_index("saved_at")
        self._items.create_index("last_seen_at")
        self._items.create_index("topics")
        self._items.create_index("source_name")
        self._indexes_ready = True

    # --------------------------------------------------------------- write

    def save_run(
        self,
        blackboard: IntelRunBlackboard,
        raw_item_batches: list[RawIntelItemBatch] | None = None,
        status: str = "succeeded",
    ) -> str:
        from pymongo import UpdateOne

        self._ensure_indexes()
        saved_at = _utcnow_iso()

        ops = [
            UpdateOne(*build_item_update(item, blackboard.run_id, saved_at), upsert=True)
            for item in blackboard.raw_items
        ]
        if ops:
            self._items.bulk_write(ops, ordered=False)

        run_doc = build_run_document(blackboard, raw_item_batches or [], status, saved_at)
        self._runs.replace_one({"_id": blackboard.run_id}, run_doc, upsert=True)
        return blackboard.run_id

    # ---------------------------------------------------------------- read

    def load_latest_payload(self) -> dict[str, Any] | None:
        return self._runs.find_one({}, sort=[("saved_at", -1)])

    def load_run_payload(self, run_id: str) -> dict[str, Any] | None:
        return self._runs.find_one({"_id": run_id})

    def load_all_blackboards(self, limit: int = 200) -> list[IntelRunBlackboard]:
        boards: list[IntelRunBlackboard] = []
        for doc in self._runs.find({}).sort("saved_at", -1).limit(limit):
            try:
                boards.append(IntelRunBlackboard.model_validate(doc["blackboard"]))
            except (KeyError, ValidationError, TypeError):
                continue
        return boards

    def format_latest_intel(self, limit: int = 20) -> str:
        payload = self.load_latest_payload()
        if not payload:
            return f"No persisted intelligence runs found in MongoDB ({mongo_db_name()})."
        blackboard = IntelRunBlackboard.model_validate(payload["blackboard"])
        items = sorted(
            blackboard.raw_items,
            key=lambda item: item.published_at or item.fetched_at,
            reverse=True,
        )[:limit]
        lines = [
            f"Latest run: {payload['run_id']}",
            f"Status: {payload.get('status', 'unknown')}",
            f"Saved at: {payload.get('saved_at', 'unknown')}",
            f"Store: MongoDB ({mongo_db_name()})",
            "",
            format_intel_items(items),
        ]
        return "\n".join(lines).rstrip()

    def distinct_item_count(self) -> int:
        return self._items.count_documents({})
