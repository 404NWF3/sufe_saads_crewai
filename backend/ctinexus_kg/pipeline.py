"""Public pipeline API: hand off collected intel items to CTINexus KG generation.

Contract: callers pass ``run_id`` + item list (dicts or objects with model_dump)
+ optional config. This module never imports ``intel_agent``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ctinexus_adapter import CtinexusKgGenerator, ProcessCtiReport
from .eligibility import assess_kg_eligibility
from .schemas import (
    ItemKnowledgeGraphRecord,
    KgGenerationConfig,
    RawIntelItem,
    coerce_raw_item,
)
from .topics import TARGET_SECURITY_TOPICS


def generate_for_item(
    run_id: str,
    item: Any,
    config: KgGenerationConfig | None = None,
    target_topics: list[str] | None = None,
    process_func: ProcessCtiReport | None = None,
) -> ItemKnowledgeGraphRecord:
    generator = CtinexusKgGenerator(config=config, process_func=process_func)
    record = generator.generate_for_item(
        run_id, item, target_topics=target_topics or list(TARGET_SECURITY_TOPICS)
    )
    generator.write_manifest(run_id, [record])
    return record


def generate_for_run(
    run_id: str,
    items: list[Any],
    config: KgGenerationConfig | None = None,
    target_topics: list[str] | None = None,
    process_func: ProcessCtiReport | None = None,
    eligible_only: bool = True,
) -> list[ItemKnowledgeGraphRecord]:
    """Generate KGs for a collection run's items.

    When ``eligible_only`` is True (default), ineligible items are still recorded
    as ``skipped`` via the generator; when False, every item is attempted the same way.
    """
    del eligible_only  # generator always records skipped; flag reserved for future filter
    generator = CtinexusKgGenerator(config=config, process_func=process_func)
    return generator.generate_for_items(
        run_id,
        items,
        target_topics=target_topics or list(TARGET_SECURITY_TOPICS),
    )


def list_kg_ready(
    items: list[Any],
    config: KgGenerationConfig | None = None,
    target_topics: list[str] | None = None,
) -> list[RawIntelItem]:
    cfg = config or KgGenerationConfig()
    topics = target_topics or list(TARGET_SECURITY_TOPICS)
    ready: list[RawIntelItem] = []
    for item in items:
        local = coerce_raw_item(item)
        if assess_kg_eligibility(local, cfg, target_topics=topics).eligible:
            ready.append(local)
    return ready


def kg_output_dir(run_id: str, config: KgGenerationConfig | None = None) -> Path:
    cfg = config or KgGenerationConfig()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in run_id).strip("._") or "run"
    return Path(cfg.output_root) / f"{safe}_kg"
