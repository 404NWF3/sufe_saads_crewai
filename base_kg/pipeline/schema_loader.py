"""Load the LLM security schema and render prompt-ready slices."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from .config import SCHEMA_PATH


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def render_entity_types(schema: dict[str, Any]) -> str:
    lines: list[str] = []
    for et in schema["entity_types"]:
        lines.append(f"- {et['name']} ({et['dimension']}): {et['description']}")
        for attr in et.get("attributes", []):
            enum = f" [one of: {', '.join(attr['values'])}]" if attr.get("values") else ""
            lines.append(f"    - {attr['name']} ({attr['type']}{enum}): {attr['description']}")
    return "\n".join(lines)


def render_relations(schema: dict[str, Any]) -> str:
    lines: list[str] = []
    for rel in schema["relations"]:
        domain = " | ".join(rel["domain"])
        rng = " | ".join(rel["range"])
        lines.append(
            f"- {rel['name']} ({rel['category']}) — {domain} -> {rng} — {rel['description']}"
        )
    return "\n".join(lines)


def entity_type_names(schema: dict[str, Any]) -> set[str]:
    return {et["name"] for et in schema["entity_types"]}


def relation_specs(schema: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    return {
        rel["name"]: {"domain": set(rel["domain"]), "range": set(rel["range"])}
        for rel in schema["relations"]
    }
