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
DEFAULT_KGS_COLLECTION = "knowledge_graphs"


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
        kgs_collection: str = DEFAULT_KGS_COLLECTION,
    ) -> None:
        self._uri = uri
        self._db_name = db_name
        self._database = database
        self._runs_name = runs_collection
        self._items_name = items_collection
        self._kgs_name = kgs_collection
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

    @property
    def _kgs(self) -> Any:
        return self._db()[self._kgs_name]

    def _ensure_indexes(self) -> None:
        if self._indexes_ready:
            return
        self._runs.create_index("saved_at")
        self._items.create_index("last_seen_at")
        self._items.create_index("topics")
        self._items.create_index("source_name")
        self._kgs.create_index("saved_at")
        self._kgs.create_index("status")
        self._kgs.create_index("run_id")
        self._indexes_ready = True

    # --------------------------------------------------------------- write

    def save_run(
        self,
        blackboard: IntelRunBlackboard,
        raw_item_batches: list[RawIntelItemBatch] | None = None,
        status: str = "succeeded",
    ) -> str:
        self._ensure_indexes()
        saved_at = _utcnow_iso()

        if blackboard.raw_items:
            # Prefer bulk_write; fall back to per-doc update_one for mongomock
            # (older mongomock rejects pymongo UpdateOne's ``sort`` kwarg).
            try:
                from pymongo import UpdateOne

                ops = [
                    UpdateOne(*build_item_update(item, blackboard.run_id, saved_at), upsert=True)
                    for item in blackboard.raw_items
                ]
                self._items.bulk_write(ops, ordered=False)
            except TypeError:
                for item in blackboard.raw_items:
                    filt, update = build_item_update(item, blackboard.run_id, saved_at)
                    self._items.update_one(filt, update, upsert=True)

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

    def store_backend(self) -> str:
        return f"mongodb:{self._db_name or mongo_db_name()}"

    def list_run_summaries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Lightweight run rows for the Gradio database panel."""
        self._ensure_indexes()
        cursor = (
            self._runs.find(
                {},
                {
                    "run_id": 1,
                    "status": 1,
                    "saved_at": 1,
                    "item_count": 1,
                    "engine": 1,
                    "summary": 1,
                },
            )
            .sort("saved_at", -1)
            .limit(max(1, int(limit)))
        )
        rows: list[dict[str, Any]] = []
        for doc in cursor:
            summary = doc.get("summary") or {}
            rows.append(
                {
                    "run_id": doc.get("run_id") or doc.get("_id"),
                    "status": doc.get("status"),
                    "saved_at": doc.get("saved_at"),
                    "item_count": doc.get("item_count", summary.get("raw_items")),
                    "run_mode": summary.get("run_mode"),
                    "rounds": summary.get("rounds"),
                    "run_goal": summary.get("run_goal"),
                    "coverage_gaps": ", ".join(summary.get("coverage_gaps_remaining") or []),
                    "engine": doc.get("engine"),
                }
            )
        return rows

    def query_items(
        self,
        *,
        source_name: str | None = None,
        topic: str | None = None,
        text: str | None = None,
        run_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Query the global deduplicated ``items`` collection."""
        self._ensure_indexes()
        filt: dict[str, Any] = {}
        if source_name and source_name.strip():
            filt["source_name"] = source_name.strip()
        if topic and topic.strip():
            filt["topics"] = topic.strip()
        if run_id and run_id.strip():
            filt["run_ids"] = run_id.strip()
        needle = (text or "").strip()
        if needle:
            filt["$or"] = [
                {"title": {"$regex": needle, "$options": "i"}},
                {"summary": {"$regex": needle, "$options": "i"}},
                {"item_id": {"$regex": needle, "$options": "i"}},
                {"_id": {"$regex": needle, "$options": "i"}},
            ]
        cursor = (
            self._items.find(filt)
            .sort("last_seen_at", -1)
            .limit(max(1, int(limit)))
        )
        return [dict(doc) for doc in cursor]

    def distinct_sources(self) -> list[str]:
        self._ensure_indexes()
        return sorted(s for s in self._items.distinct("source_name") if s)

    def run_count(self) -> int:
        return self._runs.count_documents({})

    def save_knowledge_graph(
        self,
        record: dict[str, Any],
        graph: dict[str, Any] | None = None,
    ) -> str:
        """Upsert an item-level KG: metadata + optional full CTINexus JSON graph."""
        self._ensure_indexes()
        item_id = str(record.get("item_id") or "").strip()
        if not item_id:
            raise ValueError("record.item_id is required")
        saved_at = _utcnow_iso()
        run_id = record.get("run_id")
        doc = {
            "_id": item_id,
            "item_id": item_id,
            "run_id": run_id,
            "status": record.get("status"),
            "source_name": record.get("source_name"),
            "source_uri": record.get("source_uri"),
            "triplet_count": record.get("triplet_count", 0),
            "entity_count": record.get("entity_count", 0),
            "predicted_link_count": record.get("predicted_link_count", 0),
            "ctinexus_json_path": record.get("ctinexus_json_path"),
            "graph_html_path": record.get("graph_html_path"),
            "model": record.get("model"),
            "embedding_model": record.get("embedding_model"),
            "error": record.get("error"),
            "record": record,
            "saved_at": saved_at,
        }
        if graph is not None:
            doc["graph"] = graph
        self._kgs.replace_one({"_id": item_id}, doc, upsert=True)
        self._items.update_one(
            {"_id": item_id},
            {
                "$set": {
                    "kg_status": record.get("status"),
                    "kg_run_id": run_id,
                    "kg_saved_at": saved_at,
                    "kg_triplet_count": record.get("triplet_count", 0),
                    "kg_entity_count": record.get("entity_count", 0),
                }
            },
        )
        return item_id

    def list_knowledge_graphs(
        self,
        *,
        status: str | None = None,
        run_id: str | None = None,
        item_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List KG generation records (excludes bulky graph payload by default)."""
        self._ensure_indexes()
        filt: dict[str, Any] = {}
        if status and status.strip():
            filt["status"] = status.strip()
        if run_id and run_id.strip():
            filt["run_id"] = run_id.strip()
        if item_id and item_id.strip():
            filt["item_id"] = item_id.strip()
        cursor = (
            self._kgs.find(filt, {"graph": 0})
            .sort("saved_at", -1)
            .limit(max(1, int(limit)))
        )
        return [dict(doc) for doc in cursor]

    def load_knowledge_graph(self, item_id: str) -> dict[str, Any] | None:
        self._ensure_indexes()
        return self._kgs.find_one({"_id": item_id})

    def knowledge_graph_count(self) -> int:
        return self._kgs.count_documents({})

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        self._ensure_indexes()
        return self._items.find_one({"_id": item_id})

