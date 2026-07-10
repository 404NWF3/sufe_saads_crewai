"""One-shot Mongo connectivity check for host-side localhost:27017."""
from __future__ import annotations

import sys

try:
    from pymongo import MongoClient
except ImportError:
    print("FAIL: pymongo not installed (uv sync --group intelagent)")
    sys.exit(1)

uri = "mongodb://localhost:27017"
print(f"Connecting to {uri} ...")
try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    ping = client.admin.command("ping")
    print(f"OK ping: {ping}")
    db = client["intel_agent"]
    cols = db.list_collection_names()
    print(f"OK database=intel_agent collections={cols}")
    print(f"OK runs={db.runs.count_documents({})}")
    print(f"OK items={db.items.count_documents({})}")
    if cols:
        sample = db.items.find_one() or db.runs.find_one()
        if sample:
            print(f"OK sample _id={sample.get('_id')}")
    print("RESULT: host localhost:27017 is reachable (use this in VS Code)")
    sys.exit(0)
except Exception as exc:  # noqa: BLE001
    print(f"FAIL: {exc.__class__.__name__}: {exc}")
    print("HINT: run `docker compose up -d mongo` then retry")
    print("HINT: VS Code Host must be localhost (not mongo)")
    sys.exit(2)
