from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from sufe_saads_crewai.schemas import IntelRunBlackboard, RawIntelItem, RawIntelItemBatch


DEFAULT_INTEL_RUN_DIR = Path("data") / "intel_runs"
LATEST_INDEX_NAME = "latest.json"
REAL_SOURCE_NAMES = {
    "nvd_cve_api",
    "arxiv_api",
    "cisa_kev_catalog",
    "cisa_kev_json",
    "osv_dev_api",
}


class JsonIntelRunStore:
    """File-backed store for autonomous intelligence runs.

    Each run is stored as a single JSON document:
    data/intel_runs/<run_id>.json
    """

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
            "schema_version": 1,
            "run_id": blackboard.run_id,
            "status": status,
            "saved_at": saved_at,
            "summary": self._summary(blackboard, raw_item_batches or []),
            "raw_item_batches": [
                batch.model_dump(mode="json") for batch in raw_item_batches or []
            ],
            "blackboard": blackboard.model_dump(mode="json"),
        }

        tmp_path = path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp_path.replace(path)

        latest_payload = {
            "run_id": blackboard.run_id,
            "status": status,
            "path": path.name,
            "saved_at": saved_at,
            "raw_items": len(blackboard.raw_items),
            "rounds": len(blackboard.query_history),
        }
        self.latest_index_path().write_text(
            json.dumps(latest_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path

    def load_run_payload(self, run_id: str) -> dict[str, Any]:
        path = self.run_path(run_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def latest_run_path(self, real_only: bool = False) -> Path | None:
        if real_only:
            indexed_path = self._indexed_run_path()
            if indexed_path and self._path_is_real_run(indexed_path):
                return indexed_path
            for path in self.list_run_paths(limit=200):
                if self._path_is_real_run(path):
                    return path
            return None

        return self._indexed_run_path()

    def _indexed_run_path(self) -> Path | None:
        index_path = self.latest_index_path()
        if not index_path.exists():
            return None
        index = json.loads(index_path.read_text(encoding="utf-8"))
        path_name = index.get("path")
        if not path_name:
            return None
        path = self.root_dir / str(path_name)
        return path if path.exists() else None

    def load_latest_payload(self, real_only: bool = False) -> dict[str, Any] | None:
        path = self.latest_run_path(real_only=real_only)
        if path is None:
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_run_paths(self, limit: int = 20) -> list[Path]:
        if not self.root_dir.exists():
            return []
        paths = [
            path
            for path in self.root_dir.glob("*.json")
            if path.name != LATEST_INDEX_NAME
        ]
        paths.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        return paths[:limit]

    def latest_raw_items(
        self,
        limit: int = 20,
        real_only: bool = False,
    ) -> list[RawIntelItem]:
        payload = self.load_latest_payload(real_only=real_only)
        if not payload:
            return []
        blackboard = IntelRunBlackboard.model_validate(payload["blackboard"])
        return sorted(
            blackboard.raw_items,
            key=lambda item: item.published_at or item.fetched_at,
            reverse=True,
        )[:limit]

    def format_latest_intel(self, limit: int = 20, real_only: bool = False) -> str:
        payload = self.load_latest_payload(real_only=real_only)
        if not payload:
            if real_only:
                return f"No persisted real intelligence runs found in {self.root_dir}."
            return f"No persisted intelligence runs found in {self.root_dir}."

        path = self.latest_run_path(real_only=real_only)

        lines = [
            f"Latest run: {payload['run_id']}",
            f"Status: {payload.get('status', 'unknown')}",
            f"Saved at: {payload.get('saved_at', 'unknown')}",
            f"File: {path}",
            "",
            format_intel_items(
                self.latest_raw_items(limit=limit, real_only=real_only)
            ),
        ]
        return "\n".join(lines).rstrip()

    def _path_is_real_run(self, path: Path) -> bool:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return _payload_is_real_run(payload)

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


def format_intel_items(items: list[RawIntelItem]) -> str:
    if not items:
        return "No raw intelligence items found."

    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        topics = ", ".join(item.metadata.get("topics", [])) or "unclassified"
        published = item.published_at.isoformat() if item.published_at else "unknown date"
        lines.append(
            "\n".join(
                [
                    f"{index}. {item.title or '(untitled)'}",
                    f"   source: {item.source_name}",
                    f"   published: {published}",
                    f"   relevance: {item.relevance_score:.2f}",
                    f"   topics: {topics}",
                    f"   uri: {item.source_uri}",
                    f"   summary: {item.summary or '(no summary)'}",
                ]
            )
        )
    return "\n\n".join(lines)


def _safe_run_id(run_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", run_id).strip("._")
    return safe or "intel_run"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _payload_is_real_run(payload: dict[str, Any]) -> bool:
    run_id = str(payload.get("run_id", ""))
    if run_id.startswith("mock-"):
        return False
    if run_id.startswith("real-"):
        return True

    blackboard = payload.get("blackboard")
    if not isinstance(blackboard, dict):
        return False

    for source in blackboard.get("approved_sources", []):
        if isinstance(source, dict) and source.get("source_name") in REAL_SOURCE_NAMES:
            return True

    for item in blackboard.get("raw_items", []):
        if isinstance(item, dict) and item.get("source_name") in REAL_SOURCE_NAMES:
            return True

    return False
