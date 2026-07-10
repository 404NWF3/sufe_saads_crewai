"""Tests for Core / Extended topic taxonomy."""

from __future__ import annotations

from common.topics import (
    ALL_SECURITY_TOPICS,
    CORE_SECURITY_TOPICS,
    EXTENDED_SECURITY_TOPICS,
    TOPIC_ANCHORS,
    TOPIC_KEYWORDS,
    detect_topics,
)
from intel_agent.engine.modes import FullCollectionMode, IncrementalCollectionMode


def test_core_extended_partition():
    assert len(CORE_SECURITY_TOPICS) == 18
    assert len(EXTENDED_SECURITY_TOPICS) == 15
    assert len(ALL_SECURITY_TOPICS) == 33
    assert set(CORE_SECURITY_TOPICS).isdisjoint(EXTENDED_SECURITY_TOPICS)
    assert set(ALL_SECURITY_TOPICS) == set(CORE_SECURITY_TOPICS) | set(EXTENDED_SECURITY_TOPICS)


def test_keywords_and_anchors_cover_all_topics():
    assert set(TOPIC_KEYWORDS) == set(ALL_SECURITY_TOPICS)
    assert set(TOPIC_ANCHORS) == set(ALL_SECURITY_TOPICS)


def test_detect_topics_hits_core_and_extended():
    assert "jailbreak" in detect_topics("a jailbreak against GPT")
    assert "plugin and mcp trust attack" in detect_topics("malicious MCP server trust attack")
    assert "server-side request forgery" in detect_topics("LLM tool SSRF to metadata")


def test_full_mode_coverage_uses_core_only():
    mode = FullCollectionMode()
    assert mode.target_topics == list(CORE_SECURITY_TOPICS)
    assert "server-side request forgery" not in mode.target_topics


def test_incremental_focus_accepts_extended():
    mode = IncrementalCollectionMode(focus="model extraction")
    assert mode.target_topics == ["model extraction"]
