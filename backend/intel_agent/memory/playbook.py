"""The Playbook: a self-evolving store of natural-language search techniques.

Each entry is a human-readable technique ("for Claude Code CVEs, query NVD with
keyword=claude-code + CWE-94 + a 7-day pub_date window") carrying a rolling
reward (new relevant items per API call), usage counts, provenance, and an
optional embedding for semantic recall. Entries are harvested from high-yield
rounds, recalled into the agent's context on later runs, decayed when they stop
paying off, and can be promoted/retired by status.

This is what lets the agent "grow its own search skills" across runs. Persisted
as JSONL at ``data/intel_agent/playbook.jsonl``; pass ``path=None`` for an
in-memory instance (tests / A-B isolation).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from .retrieval import cosine_similarity

DEFAULT_PLAYBOOK_PATH = Path("data") / "intel_agent" / "playbook.jsonl"
EmbedFn = Callable[[list[str]], list[list[float]]]

ACTIVE_STATUSES = {"active", "verified"}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PlaybookEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    entry_id: str
    technique_text: str
    source_name: str
    operator_signature: str
    topic_bucket: str = "general"
    time_scope_hint: str | None = None
    params_example: dict[str, Any] = Field(default_factory=dict)
    reward: float = 1.0
    pulls: float = 0.0
    hits: float = 0.0
    status: str = "active"
    created_run_id: str = ""
    provenance_runs: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=_utcnow_iso)
    last_used_at: str | None = None
    embedding: list[float] | None = None

    @property
    def hit_rate(self) -> float:
        return self.hits / self.pulls if self.pulls else 0.0

    def summary_line(self) -> str:
        scope = f" scope={self.time_scope_hint}" if self.time_scope_hint else ""
        return (
            f"[{self.source_name} | {self.topic_bucket}{scope} | "
            f"reward={self.reward:.2f} pulls={self.pulls:.0f} "
            f"hit_rate={self.hit_rate:.0%} | {self.status}] {self.technique_text}"
        )


def entry_key(topic_bucket: str, source_name: str, operator_signature: str) -> str:
    return f"{topic_bucket}::{source_name}::{operator_signature}"


class PlaybookStore:
    def __init__(
        self,
        path: Path | None = DEFAULT_PLAYBOOK_PATH,
        embedder: EmbedFn | None = None,
        decay: float = 0.9,
        deprecate_below_reward: float = 0.1,
        deprecate_min_pulls: float = 3.0,
    ) -> None:
        self.path = path
        self.embedder = embedder
        self.decay = decay
        self.deprecate_below_reward = deprecate_below_reward
        self.deprecate_min_pulls = deprecate_min_pulls
        self.entries: dict[str, PlaybookEntry] = {}
        if path is not None and path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = PlaybookEntry.model_validate_json(line)
                    self.entries[entry.entry_id] = entry
                except ValueError:
                    continue

    # ------------------------------------------------------------- persistence

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            for entry in self.entries.values():
                fh.write(entry.model_dump_json() + "\n")

    # ------------------------------------------------------------- mutation

    def upsert(
        self,
        technique_text: str,
        source_name: str,
        operator_signature: str,
        topic_bucket: str,
        reward: float,
        run_id: str,
        params_example: dict[str, Any] | None = None,
        time_scope_hint: str | None = None,
        produced_relevant: bool = True,
    ) -> PlaybookEntry:
        key = entry_key(topic_bucket, source_name, operator_signature)
        existing = self.entries.get(key)
        if existing is None:
            entry = PlaybookEntry(
                entry_id=key,
                technique_text=technique_text,
                source_name=source_name,
                operator_signature=operator_signature,
                topic_bucket=topic_bucket,
                time_scope_hint=time_scope_hint,
                params_example=params_example or {},
                reward=max(0.0, reward),
                pulls=1.0,
                hits=1.0 if produced_relevant else 0.0,
                created_run_id=run_id,
                provenance_runs=[run_id],
                last_used_at=_utcnow_iso(),
            )
            self._maybe_embed(entry)
            self.entries[key] = entry
            return entry

        # Rolling update: reward is a pull-weighted running mean.
        existing.reward = (existing.reward * existing.pulls + max(0.0, reward)) / (existing.pulls + 1)
        existing.pulls += 1
        if produced_relevant:
            existing.hits += 1
        existing.last_used_at = _utcnow_iso()
        if run_id not in existing.provenance_runs:
            existing.provenance_runs.append(run_id)
        if len(technique_text) > len(existing.technique_text):
            existing.technique_text = technique_text
        if existing.reward >= 1.0 and existing.pulls >= 3 and existing.status == "active":
            existing.status = "verified"
        return existing

    def record_usage(self, entry_id: str, reward: float, produced_relevant: bool) -> None:
        entry = self.entries.get(entry_id)
        if entry is None:
            return
        entry.reward = (entry.reward * entry.pulls + max(0.0, reward)) / (entry.pulls + 1)
        entry.pulls += 1
        if produced_relevant:
            entry.hits += 1
        entry.last_used_at = _utcnow_iso()

    def decay_unused(self, used_ids: set[str]) -> None:
        """Fade entries not reinforced this run; deprecate persistently weak ones."""
        for entry in self.entries.values():
            if entry.entry_id in used_ids or entry.status == "deprecated":
                continue
            entry.reward *= self.decay
            if (
                entry.pulls >= self.deprecate_min_pulls
                and entry.reward < self.deprecate_below_reward
            ):
                entry.status = "deprecated"

    # ------------------------------------------------------------- recall

    def recall(
        self,
        query_text: str,
        topic_bucket: str | None = None,
        source_name: str | None = None,
        top_k: int = 5,
    ) -> list[PlaybookEntry]:
        candidates = [e for e in self.entries.values() if e.status in ACTIVE_STATUSES]
        if topic_bucket:
            bucket_hits = [
                e for e in candidates if e.topic_bucket in (topic_bucket, "general")
            ]
            candidates = bucket_hits or candidates
        if source_name:
            source_hits = [e for e in candidates if e.source_name == source_name]
            candidates = source_hits or candidates
        if not candidates:
            return []

        query_vec = self._embed_query(query_text)
        scored: list[tuple[float, PlaybookEntry]] = []
        for entry in candidates:
            reward_weight = 0.5 + min(1.0, entry.reward) / 2  # in [0.5, 1.0]
            if query_vec is not None and entry.embedding:
                similarity = cosine_similarity(query_vec, entry.embedding)
                score = similarity * reward_weight
            else:
                score = reward_weight  # no embeddings -> rank by reward
            scored.append((score, entry))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [entry for _, entry in scored[:top_k]]

    def render_recall(self, entries: list[PlaybookEntry]) -> str:
        if not entries:
            return ""
        lines = ["Recommended techniques from past runs (reuse what worked):"]
        lines.extend(f"- {entry.summary_line()}" for entry in entries)
        return "\n".join(lines)

    # ------------------------------------------------------------- embedding

    def _embed_query(self, text: str) -> list[float] | None:
        if self.embedder is None or not text.strip():
            return None
        try:
            return self.embedder([text[:2000]])[0]
        except Exception:  # noqa: BLE001 - embedding failure -> reward-only ranking
            return None

    def _maybe_embed(self, entry: PlaybookEntry) -> None:
        if self.embedder is None or entry.embedding:
            return
        try:
            entry.embedding = self.embedder([entry.technique_text[:2000]])[0]
        except Exception:  # noqa: BLE001 - embedding optional
            entry.embedding = None


def playbook_enabled() -> bool:
    return os.getenv("INTEL_PLAYBOOK_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def default_playbook_path() -> Path:
    raw = os.getenv("INTEL_AGENT_PLAYBOOK_PATH")
    return Path(raw) if raw else DEFAULT_PLAYBOOK_PATH
