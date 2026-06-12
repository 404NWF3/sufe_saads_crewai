"""Load validated extractions into Neo4j.

Node identity: (entity type, lowercased canonical name). Nodes carry a common
:Entity label plus their schema type as a second label. Provenance (source
documents) is accumulated on both nodes and relationships.
"""

from __future__ import annotations

import re

from neo4j import GraphDatabase

from .config import BaseKgConfig
from .extract import load_extractions
from .schema_loader import load_schema, relation_specs

_SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class Neo4jStore:
    def __init__(self, cfg: BaseKgConfig):
        self.cfg = cfg
        self.driver = GraphDatabase.driver(
            cfg.neo4j_uri, auth=(cfg.neo4j_user, cfg.neo4j_password)
        )
        schema = load_schema()
        # Relation/label names are injected into Cypher strings, so restrict them
        # to schema-defined, identifier-safe names.
        self.valid_relations = {
            name for name in relation_specs(schema) if _SAFE_NAME.match(name)
        }
        self.valid_types = {
            et["name"] for et in schema["entity_types"] if _SAFE_NAME.match(et["name"])
        }

    def close(self) -> None:
        self.driver.close()

    def setup(self) -> None:
        with self.driver.session() as session:
            session.run(
                "CREATE CONSTRAINT entity_key IF NOT EXISTS "
                "FOR (n:Entity) REQUIRE n.key IS UNIQUE"
            )

    def ingest(self, extraction: dict) -> dict[str, int]:
        doc_id = extraction["doc_id"]
        category = extraction.get("category", "unknown")
        by_id = {e["id"]: e for e in extraction["entities"] if e.get("id")}
        counts = {"nodes": 0, "relationships": 0}
        with self.driver.session() as session:
            for entity in by_id.values():
                if entity["type"] not in self.valid_types:
                    continue
                session.execute_write(self._merge_entity, entity, doc_id, category)
                counts["nodes"] += 1
            for triplet in extraction["triplets"]:
                subject = by_id.get(triplet.get("subject"))
                obj = by_id.get(triplet.get("object"))
                relation = triplet.get("relation", "")
                if not subject or not obj or relation not in self.valid_relations:
                    continue
                session.execute_write(
                    self._merge_relationship, subject, obj, relation, triplet, doc_id
                )
                counts["relationships"] += 1
        return counts

    @staticmethod
    def _entity_key(entity: dict) -> str:
        canonical = (entity.get("canonicalName") or entity["name"]).strip().lower()
        return f"{entity['type']}::{canonical}"

    @classmethod
    def _merge_entity(cls, tx, entity: dict, doc_id: str, category: str) -> None:
        attributes = {
            f"attr_{k}": v
            for k, v in (entity.get("attributes") or {}).items()
            if isinstance(v, (str, int, float, bool)) and _SAFE_NAME.match(k or "")
        }
        tx.run(
            f"MERGE (n:Entity:{entity['type']} {{key: $key}}) "
            "ON CREATE SET n.name = $name, n.canonicalName = $canonical "
            "SET n += $attributes, "
            "    n.sourceDocs = CASE WHEN $doc IN coalesce(n.sourceDocs, []) "
            "        THEN n.sourceDocs ELSE coalesce(n.sourceDocs, []) + $doc END, "
            "    n.sourceCategories = CASE WHEN $category IN coalesce(n.sourceCategories, []) "
            "        THEN n.sourceCategories ELSE coalesce(n.sourceCategories, []) + $category END",
            key=cls._entity_key(entity),
            name=entity["name"],
            canonical=entity.get("canonicalName") or entity["name"],
            attributes=attributes,
            doc=doc_id,
            category=category,
        )

    @classmethod
    def _merge_relationship(
        cls, tx, subject: dict, obj: dict, relation: str, triplet: dict, doc_id: str
    ) -> None:
        tx.run(
            "MATCH (s:Entity {key: $skey}), (o:Entity {key: $okey}) "
            f"MERGE (s)-[r:{relation}]->(o) "
            "SET r.sourceDocs = CASE WHEN $doc IN coalesce(r.sourceDocs, []) "
            "        THEN r.sourceDocs ELSE coalesce(r.sourceDocs, []) + $doc END, "
            "    r.mentionText = coalesce(r.mentionText, $mention)",
            skey=cls._entity_key(subject),
            okey=cls._entity_key(obj),
            doc=doc_id,
            mention=triplet.get("mentionText", ""),
        )


def run_load(cfg: BaseKgConfig, limit: int | None = None) -> dict[str, int]:
    extractions = load_extractions(cfg.extractions_dir, limit=limit)
    store = Neo4jStore(cfg)
    totals = {"docs": 0, "nodes": 0, "relationships": 0}
    try:
        store.setup()
        for extraction in extractions:
            counts = store.ingest(extraction)
            totals["docs"] += 1
            totals["nodes"] += counts["nodes"]
            totals["relationships"] += counts["relationships"]
            print(
                f"[load] {extraction['doc_id']}: {counts['nodes']} nodes, "
                f"{counts['relationships']} relationships"
            )
    finally:
        store.close()
    return totals
