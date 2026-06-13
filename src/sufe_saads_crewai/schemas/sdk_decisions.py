from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .crew_outputs import RegisteredSourceName


class StrictSdkDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceSelectionDecision(StrictSdkDecision):
    """Agent verdict on which sources to query this round (bandit recommend + veto)."""

    selected_sources: list[RegisteredSourceName]
    follow_bandit: bool
    rationale: str


class SearchQueryProposal(StrictSdkDecision):
    """One source-specific query the agent proposes, with optional advanced operators.

    `params` keys must match the typed parameters of the registered source tool
    (e.g. nvd_cwe_id, nvd_cvss_v3_severity, arxiv_search_query, osv_ecosystem);
    unknown keys are dropped by code-side validation before execution.
    """

    source_name: RegisteredSourceName
    query_text: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


class CollectionPlanDecision(StrictSdkDecision):
    proposals: list[SearchQueryProposal]
    rationale: str
