"""One-shot Mongo connectivity check for host-side Docker Mongo (port 27018)."""
from __future__ import annotations

import os
import sys

try:
    from pymongo import MongoClient
except ImportError:
    print("FAIL: pymongo not installed (uv sync --group intelagent)")
    sys.exit(1)

uri = os.environ.get("INTEL_MONGO_URI") or "mongodb://localhost:27018"
db_name = os.environ.get("INTEL_MONGO_DB") or "intel_agent"
print(f"Connecting to {uri} (db={db_name}) ...")
try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    ping = client.admin.command("ping")
    print(f"OK ping: {ping}")
    db = client[db_name]
    cols = db.list_collection_names()
    print(f"OK database={db_name} collections={cols}")
    print(f"OK runs={db.runs.count_documents({})}")
    print(f"OK items={db.items.count_documents({})}")
    if cols:
        sample = db.items.find_one() or db.runs.find_one()
        if sample:
            print(f"OK sample _id={sample.get('_id')}")
    print(f"RESULT: {uri} is reachable (host tools / DBeaver use this URI)")
    sys.exit(0)
except Exception as exc:  # noqa: BLE001
    print(f"FAIL: {exc.__class__.__name__}: {exc}")
    print("HINT: run `docker compose up -d mongo` then retry")
    print("HINT: host port is 27018 (not 27017); Host must be localhost (not mongo)")
    sys.exit(2)
