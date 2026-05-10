"""Business-agent layer for WP1-1."""

from __future__ import annotations

from typing import Any

__all__ = [
    "DedupAdjudicatorAgent",
    "DedupMergeAgent",
    "BomMapperAgent",
    "BomResolutionReviewerAgent",
    "SearchReflectionAgent",
    "StandardizerAgent",
    "SupervisorAgent",
]


def __getattr__(name: str) -> Any:
    if name == "BomMapperAgent":
        from .bom_mapper_agent import BomMapperAgent

        return BomMapperAgent
    if name == "BomResolutionReviewerAgent":
        from .bom_resolution_reviewer_agent import BomResolutionReviewerAgent

        return BomResolutionReviewerAgent
    if name == "DedupAdjudicatorAgent":
        from .dedup_adjudicator_agent import DedupAdjudicatorAgent

        return DedupAdjudicatorAgent
    if name == "DedupMergeAgent":
        from .dedup_merge_agent import DedupMergeAgent

        return DedupMergeAgent
    if name == "SearchReflectionAgent":
        from .search_reflection_agent import SearchReflectionAgent

        return SearchReflectionAgent
    if name == "StandardizerAgent":
        from .standardizer_agent import StandardizerAgent

        return StandardizerAgent
    if name == "SupervisorAgent":
        from .supervisor_agent import SupervisorAgent

        return SupervisorAgent
    raise AttributeError(name)
