from __future__ import annotations

from datetime import datetime, timezone

from intel_agent.engine.modes import FullCollectionMode, IncrementalCollectionMode
from intel_agent.persistence import JsonIntelRunStore
from intel_agent.schemas import IntelRunBlackboard
from intel_agent.tests.conftest import make_item


def test_full_mode_has_no_time_scope(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    since, until = FullCollectionMode().resolve_time_scope(store)
    assert since is None and until is None


def test_incremental_explicit_since(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    mode = IncrementalCollectionMode(focus="jailbreak", since=since, use_watermark=False)
    got_since, got_until = mode.resolve_time_scope(store)
    assert got_since == since
    assert got_until is not None
    assert mode.target_topics == ["jailbreak"]


def test_incremental_uses_watermark(tmp_path):
    store = JsonIntelRunStore(root_dir=tmp_path)
    bb = IntelRunBlackboard(run_id="prev", run_goal="g")
    watermark = datetime(2026, 6, 10, tzinfo=timezone.utc)
    bb.raw_items.append(make_item("nvd:x", published=watermark))
    store.save_run(bb)

    mode = IncrementalCollectionMode(window_days=365, use_watermark=True)
    since, _ = mode.resolve_time_scope(store)
    # window_start is ~1yr ago; watermark is more recent, so max() picks watermark.
    assert since == watermark
