from __future__ import annotations

import json
from pathlib import Path

from .schemas import TripletFeedbackRecord


def append_triplet_feedback(
    output_dir: str | Path,
    feedback: TripletFeedbackRecord,
) -> Path:
    path = Path(output_dir) / "triplet_feedback.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(feedback.model_dump(mode="json"), ensure_ascii=False) + "\n")
    return path


def load_triplet_feedback(output_dir: str | Path) -> list[TripletFeedbackRecord]:
    path = Path(output_dir) / "triplet_feedback.jsonl"
    if not path.exists():
        return []
    records: list[TripletFeedbackRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(TripletFeedbackRecord.model_validate_json(line))
    return records
