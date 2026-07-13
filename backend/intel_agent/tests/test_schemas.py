from __future__ import annotations

import pytest
from pydantic import ValidationError

from intel_agent.schemas import IntelRunBlackboard, QueryCandidate


def test_adaptive_blackboard_fields_are_backward_compatible():
    board = IntelRunBlackboard(run_id="legacy", run_goal="g")
    assert board.corpus_gaps == []
    assert board.run_gaps == []
    assert board.query_outcomes == []
    assert board.source_checkpoints == []
    assert board.candidate_topics == []
    assert board.collection_strategy == "legacy"


def test_query_candidate_is_strict_and_source_specific():
    payload = {
        "candidate_id": "c1",
        "source_name": "arxiv_api",
        "query_text": 'all:"prompt injection"',
        "query_intent": "discovery",
        "evidence_channel": "research",
        "target_topics": ["prompt injection"],
        "target_gap_ids": [],
    }
    assert QueryCandidate.model_validate(payload).candidate_id == "c1"
    with pytest.raises(ValidationError):
        QueryCandidate.model_validate({**payload, "unexpected": True})
