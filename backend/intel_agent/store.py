"""Store selection: MongoDB when configured, JSON files otherwise.

``default_store()`` returns a :class:`MongoIntelRunStore` when Mongo is enabled
(``INTEL_MONGO_URI`` set or ``INTEL_MONGO_ENABLED`` truthy) *and* ``pymongo`` is
importable; otherwise it falls back to the dependency-free
:class:`JsonIntelRunStore` so offline runs and tests need no database.
"""

from __future__ import annotations

from typing import Any

from .mongo_store import mongo_enabled
from .persistence import JsonIntelRunStore


def default_store() -> Any:
    if mongo_enabled():
        try:
            import pymongo  # noqa: F401
        except ImportError:
            print("[warn] INTEL_MONGO_* set but pymongo is not installed; using JSON store.")
            return JsonIntelRunStore()
        from .mongo_store import MongoIntelRunStore

        return MongoIntelRunStore()
    return JsonIntelRunStore()
