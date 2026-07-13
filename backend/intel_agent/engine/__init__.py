"""Engine layer: modes, round orchestration, context digest, rules fallback."""

from __future__ import annotations

__all__ = [
    "IntelAgentController",
    "CollectionMode",
    "FullCollectionMode",
    "IncrementalCollectionMode",
]


def __getattr__(name: str):
    if name == "IntelAgentController":
        from .controller import IntelAgentController

        return IntelAgentController
    if name in {"CollectionMode", "FullCollectionMode", "IncrementalCollectionMode"}:
        from .modes import CollectionMode, FullCollectionMode, IncrementalCollectionMode

        return {
            "CollectionMode": CollectionMode,
            "FullCollectionMode": FullCollectionMode,
            "IncrementalCollectionMode": IncrementalCollectionMode,
        }[name]
    raise AttributeError(name)
