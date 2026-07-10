"""File-backed store for intel_agent runs.

Writes ``data/intel_runs/<run_id>.json`` + ``latest.json`` in a layout that the
legacy Gradio console can still read (extra keys tolerated), while carrying no
import dependency on the legacy package. KG bookkeeping is intentionally
dropped: the intel_agent engine does not generate knowledge graphs.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schemas import IntelRunBlackboard, RawIntelItem, RawIntelItemBatch

DEFAULT_INTEL_RUN_DIR = Path("data") / "intel_runs"
LATEST_INDEX_NAME = "latest.json"


class JsonIntelRunStore:
    def __init__(self, root_dir: str | Path = DEFAULT_INTEL_RUN_DIR) -> None:
        self.root_dir = Path(root_dir)

    def run_path(self, run_id: str) -> Path:
        return self.root_dir / f"{_safe_run_id(run_id)}.json"

    def latest_index_path(self) -> Path:
        return self.root_dir / LATEST_INDEX_NAME

    def save_run(
        self,
        blackboard: IntelRunBlackboard,
        raw_item_batches: list[RawIntelItemBatch] | None = None,
        status: str = "succeeded",
    ) -> Path:
        self.root_dir.mkdir(parents=True, exist_ok=True)
        saved_at = _utcnow_iso()
        path = self.run_path(blackboard.run_id)
        payload = {
            "schema_version": 2,
            "run_id": blackboard.run_id,
            "status": status,
            "saved_at": saved_at,
            "engine": "intel_agent",
            "summary": self._summary(blackboard, raw_item_batches or []),
            "raw_item_batches": [b.model_dump(mode="json") for b in raw_item_batches or []],
            "blackboard": blackboard.model_dump(mode="json"),
        }
        tmp_path = path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(path)

        self.latest_index_path().write_text(
            json.dumps(
                {
                    "run_id": blackboard.run_id,
                    "status": status,
                    "path": path.name,
                    "saved_at": saved_at,
                    "raw_items": len(blackboard.raw_items),
                    "rounds": len(blackboard.query_history),
                },
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def load_run_payload(self, run_id: str) -> dict[str, Any]:
        return json.loads(self.run_path(run_id).read_text(encoding="utf-8"))

    def load_latest_payload(self) -> dict[str, Any] | None:
        index_path = self.latest_index_path()
        if not index_path.exists():
            return None
        index = json.loads(index_path.read_text(encoding="utf-8"))
        name = index.get("path")
        if not name:
            return None
        path = self.root_dir / str(name)
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def list_run_paths(self, limit: int = 20) -> list[Path]:
        if not self.root_dir.exists():
            return []
        paths = [p for p in self.root_dir.glob("*.json") if p.name != LATEST_INDEX_NAME]
        paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return paths[:limit]

    def load_all_blackboards(self, limit: int = 200) -> list[IntelRunBlackboard]:
        boards: list[IntelRunBlackboard] = []
        for path in self.list_run_paths(limit=limit):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                boards.append(IntelRunBlackboard.model_validate(payload["blackboard"]))
            except (OSError, json.JSONDecodeError, KeyError, ValueError):
                continue
        return boards

    def format_latest_intel(self, limit: int = 20) -> str:
        payload = self.load_latest_payload()
        if not payload:
            return f"No persisted intelligence runs found in {self.root_dir}."
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
            "",
            format_intel_items(items),
        ]
        return "\n".join(lines).rstrip()

    def _summary(
        self, blackboard: IntelRunBlackboard, batches: list[RawIntelItemBatch]
    ) -> dict[str, Any]:
        return {
            "run_goal": blackboard.run_goal,
            "run_mode": blackboard.run_mode,
            "rounds": len(blackboard.query_history),
            "raw_items": len(blackboard.raw_items),
            "raw_item_batches": len(batches),
            "coverage_gaps_remaining": [
                gap.taxonomy_or_component for gap in blackboard.coverage_gaps
            ],
            "last_action": (
                blackboard.action_history[-1].action_type
                if blackboard.action_history else None
            ),
        }


def format_intel_items(items: list[RawIntelItem]) -> str:
    if not items:
        return "No raw intelligence items found."
    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        topics = ", ".join(item.metadata.get("topics", [])) or "unclassified"
        published = item.published_at.isoformat() if item.published_at else "unknown date"
        lines.append(
            "\n".join([
                f"{index}. {item.title or '(untitled)'}",
                f"   source: {item.source_name}",
                f"   published: {published}",
                f"   relevance: {item.relevance_score:.2f}",
                f"   topics: {topics}",
                f"   uri: {item.source_uri}",
            ])
        )
    return "\n\n".join(lines)


def _safe_run_id(run_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", run_id).strip("._") or "intel_run"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
