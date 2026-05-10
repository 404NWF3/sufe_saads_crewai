from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from qdrant_client import QdrantClient
from qdrant_client.http import models

from ..tools import build_dedup_text, generate_embedding


class AttackSignatureMemory:
    """Persistent semantic memory for stable attack signatures.

    Uses local embedded Qdrant storage so semantic recall is separated from the
    final adjudication logic. No Docker or standalone Qdrant server is required.
    The index is rebuilt from stable records for consistency.
    """

    def __init__(
        self,
        *,
        base_dir: str | None = None,
        collection_name: str = "wp11_attack_signature_memory",
        vector_size: int = 32,
    ) -> None:
        self.base_dir = Path(base_dir or ".runtime/wp11/vector_memory")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.collection_name = collection_name
        self.vector_size = vector_size
        self.client = QdrantClient(path=str(self.base_dir))
        self._ensure_collection()

    def rebuild_index(self, stable_records: list[dict[str, Any]]) -> None:
        self.client.delete_collection(self.collection_name)
        self._ensure_collection()
        if not stable_records:
            return
        points = [
            self._point_from_record(record, fallback_index=offset)
            for offset, record in enumerate(stable_records)
        ]
        self.client.upsert(collection_name=self.collection_name, points=points)

    def upsert_record(self, record: dict[str, Any]) -> None:
        """Incrementally add or update one stable record."""
        self._ensure_collection()
        point = self._point_from_record(record)
        self.client.upsert(collection_name=self.collection_name, points=[point])

    def semantic_recall(
        self,
        candidate: dict[str, Any],
        *,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        query_vector = self._record_vector(candidate)
        response = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            limit=max(1, top_k),
            with_payload=True,
        )
        recalled: list[dict[str, Any]] = []
        for row in response.points:
            payload = row.payload or {}
            recalled.append(
                {
                    "stable_attack_id": payload.get("stable_attack_id"),
                    "stable_attack_code": payload.get("stable_attack_code"),
                    "canonical_name": payload.get("canonical_name"),
                    "attack_family": payload.get("attack_family"),
                    "semantic_score": float(row.score),
                    "source_coverage": payload.get("source_coverage", []),
                }
            )
        return recalled

    def _ensure_collection(self) -> None:
        existing = [item.name for item in self.client.get_collections().collections]
        if self.collection_name in existing:
            return
        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=models.VectorParams(
                size=self.vector_size,
                distance=models.Distance.COSINE,
            ),
        )

    def _point_from_record(
        self,
        record: dict[str, Any],
        *,
        fallback_index: int | None = None,
    ) -> models.PointStruct:
        stable_attack_id = self._stable_attack_key(
            record,
            fallback_index=fallback_index,
        )
        return models.PointStruct(
            id=self._record_id(stable_attack_id),
            vector=self._record_vector(record),
            payload={
                "stable_attack_id": stable_attack_id,
                "stable_attack_code": record.get("stable_attack_code"),
                "canonical_name": record.get("canonical_name"),
                "attack_family": record.get("attack_family"),
                "source_coverage": record.get("source_coverage", []),
            },
        )

    def _stable_attack_key(
        self,
        record: dict[str, Any],
        *,
        fallback_index: int | None = None,
    ) -> str:
        stable_attack_id = (
            record.get("stable_attack_id")
            or record.get("stable_attack_code")
            or (
                f"stable_{fallback_index}"
                if fallback_index is not None
                else None
            )
        )
        if not stable_attack_id:
            raise ValueError("stable_attack_id is required for vector memory upserts")
        return str(stable_attack_id)

    def _record_id(self, stable_attack_id: str) -> str:
        return str(uuid5(NAMESPACE_URL, stable_attack_id))

    def _record_text(self, record: dict[str, Any]) -> str:
        text = record.get("dedup_text")
        if isinstance(text, str) and text.strip():
            return text
        return build_dedup_text(record)

    def _record_vector(self, record: dict[str, Any]) -> list[float]:
        vector = record.get("embedding_signature")
        if isinstance(vector, list) and len(vector) == self.vector_size:
            return [float(value) for value in vector]
        return generate_embedding(self._record_text(record))

    def close(self) -> None:
        self.client.close()
