from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from sufe_saads_crewai.schemas import (
    ApprovedSource,
    RawIntelItem,
    RawIntelItemBatch,
    SearchQueryPlan,
    SourceExecutionStat,
    SourceProposal,
)
from sufe_saads_crewai.topic_utils import (
    TARGET_SECURITY_TOPICS,
    build_gap_query,
    detect_topics,
    tokenize,
)

MOCK_SOURCE_LIBRARY: list[dict[str, Any]] = [
    {
        "item_id": "mock-owasp-prompt-agent-001",
        "source_name": "owasp_llm_top_10",
        "source_type": "advisory",
        "source_uri": "https://mock.local/owasp/llm/prompt-injection-agent-tools",
        "title": "Prompt injection abuses agent tools to exfiltrate secrets",
        "summary": "Indirect prompt injection can cause an agent to misuse tools and leak sensitive data.",
        "published_at": "2026-02-12T00:00:00+00:00",
        "topics": ["prompt injection", "agent tool abuse", "data leakage"],
    },
    {
        "item_id": "mock-github-plugin-002",
        "source_name": "github_advisories",
        "source_type": "security_db",
        "source_uri": "https://mock.local/github/advisories/llm-plugin-tool-abuse",
        "title": "LLM plugin prompt injection leads to unsafe tool execution",
        "summary": "A vulnerable plugin accepts untrusted model output as a tool instruction.",
        "published_at": "2026-01-28T00:00:00+00:00",
        "topics": ["prompt injection", "agent tool abuse"],
    },
    {
        "item_id": "mock-arxiv-rag-003",
        "source_name": "arxiv_security",
        "source_type": "paper",
        "source_uri": "https://mock.local/arxiv/rag-poisoning-enterprise-kb",
        "title": "RAG poisoning through malicious enterprise knowledge base documents",
        "summary": "Poisoned retrieval documents can steer generated answers toward attacker goals.",
        "published_at": "2026-03-03T00:00:00+00:00",
        "topics": ["rag poisoning", "prompt injection"],
    },
    {
        "item_id": "mock-model-supply-004",
        "source_name": "ai_security_research_feed",
        "source_type": "research",
        "source_uri": "https://mock.local/research/model-artifact-supply-chain",
        "title": "Model supply chain risk in open model artifacts",
        "summary": "Unsafe model artifact formats can introduce supply-chain execution risk.",
        "published_at": "2026-03-25T00:00:00+00:00",
        "topics": ["model supply chain"],
    },
    {
        "item_id": "mock-vendor-jailbreak-005",
        "source_name": "vendor_security_blogs",
        "source_type": "vendor",
        "source_uri": "https://mock.local/vendor/jailbreak-evaluation-bypass-patterns",
        "title": "Jailbreak evaluation benchmark identifies policy bypass patterns",
        "summary": "A vendor red-team report describes repeatable jailbreak and guardrail bypass patterns.",
        "published_at": "2026-04-08T00:00:00+00:00",
        "topics": ["jailbreak"],
    },
    {
        "item_id": "mock-arxiv-api-rag-prompt-008",
        "source_name": "arxiv_api",
        "source_type": "paper",
        "source_uri": "https://mock.local/arxiv-api/rag-prompt-injection-preprint",
        "title": "Prompt injection and RAG poisoning attacks against LLM applications",
        "summary": "A preprint studies prompt injection, poisoned retrieval contexts, and mitigation evaluation.",
        "published_at": "2026-04-12T00:00:00+00:00",
        "topics": ["prompt injection", "rag poisoning"],
    },
    {
        "item_id": "mock-nvd-api-model-supply-009",
        "source_name": "nvd_cve_api",
        "source_type": "security_db",
        "source_uri": "https://mock.local/nvd-api/cve-model-artifact-loader",
        "title": "CVE record describes unsafe model artifact loading in an ML service",
        "summary": "A vulnerable model artifact loader can trigger supply-chain execution risk.",
        "published_at": "2026-04-14T00:00:00+00:00",
        "topics": ["model supply chain"],
    },
    {
        "item_id": "mock-cisa-kev-ai-gateway-010",
        "source_name": "cisa_kev_json",
        "source_type": "advisory",
        "source_uri": "https://mock.local/cisa-kev/ai-gateway-dependency",
        "title": "Known exploited vulnerability affects an AI gateway dependency",
        "summary": "The exploited dependency can expose model service data through a vulnerable edge component.",
        "published_at": "2026-04-16T00:00:00+00:00",
        "topics": ["data leakage", "model supply chain"],
    },
    {
        "item_id": "mock-osv-dev-agent-dependency-011",
        "source_name": "osv_dev_api",
        "source_type": "security_db",
        "source_uri": "https://mock.local/osv-dev/llm-agent-dependency-advisory",
        "title": "OSV advisory tracks vulnerable Python LLM agent dependency",
        "summary": "An open source agent dependency mishandles tool permissions and enables unsafe execution.",
        "published_at": "2026-04-17T00:00:00+00:00",
        "topics": ["agent tool abuse", "model supply chain"],
    },
    {
        "item_id": "mock-nvd-data-leak-006",
        "source_name": "nvd",
        "source_type": "security_db",
        "source_uri": "https://mock.local/nvd/data-leakage-training-extraction",
        "title": "Data leakage from training data extraction in language model services",
        "summary": "A weakness report links extraction probes to exposure of private training snippets.",
        "published_at": "2026-04-18T00:00:00+00:00",
        "topics": ["data leakage"],
    },
    {
        "item_id": "mock-community-noise-007",
        "source_name": "community_discussions",
        "source_type": "community",
        "source_uri": "https://mock.local/community/general-ai-news",
        "title": "General AI product discussion without security evidence",
        "summary": "A broad discussion mentions AI systems but contains no actionable security evidence.",
        "published_at": "2026-04-20T00:00:00+00:00",
        "topics": [],
    },
]

MOCK_SOURCE_PROPOSALS: dict[str, dict[str, Any]] = {
    "model supply chain": {
        "source_name": "model_hub_security_advisories",
        "base_uri": "https://mock.local/proposed/model-hub-security",
        "source_type": "vendor",
        "expected_coverage_gain": 0.75,
        "trust_rationale": "Potentially covers unsafe model artifacts, model cards, and takedown advisories.",
        "risk_notes": ["Requires approval before collection because source schemas may change."],
    },
    "rag poisoning": {
        "source_name": "rag_security_papers_feed",
        "base_uri": "https://mock.local/proposed/rag-security-papers",
        "source_type": "paper",
        "expected_coverage_gain": 0.7,
        "trust_rationale": "Likely improves coverage of retrieval poisoning and knowledge-base attacks.",
        "risk_notes": ["Paper feeds can be noisy and need deduplication."],
    },
    "jailbreak": {
        "source_name": "red_team_eval_reports",
        "base_uri": "https://mock.local/proposed/red-team-eval-reports",
        "source_type": "research",
        "expected_coverage_gain": 0.65,
        "trust_rationale": "Could surface jailbreak benchmarks and red-team evaluations earlier.",
        "risk_notes": ["Some reports may lack reproducible evidence."],
    },
}


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


class MockSourceRepository:
    def search(
        self,
        query_plan: SearchQueryPlan,
        approved_sources: list[ApprovedSource],
    ) -> RawIntelItemBatch:
        approved_names = {source.source_name for source in approved_sources if source.enabled}
        requested_names = query_plan.source_names or sorted(approved_names)
        source_names = [name for name in requested_names if name in approved_names]
        if requested_names and not source_names:
            source_names = sorted(approved_names)

        query_topics = set(detect_topics(query_plan.query_text))
        query_tokens = tokenize(query_plan.query_text)

        items: list[RawIntelItem] = []
        source_counts = {name: 0 for name in source_names}
        for entry in MOCK_SOURCE_LIBRARY:
            if entry["source_name"] not in source_names:
                continue

            score = self._score_entry(entry, query_topics, query_tokens)
            if score <= 0:
                continue

            item = RawIntelItem(
                item_id=entry["item_id"],
                source_name=entry["source_name"],
                source_uri=entry["source_uri"],
                title=entry["title"],
                summary=entry["summary"],
                published_at=parse_datetime(entry["published_at"]),
                raw_text=f"{entry['title']}. {entry['summary']}",
                relevance_score=score,
                extraction_notes="Matched by deterministic mock source repository.",
                metadata={
                    "topics": entry["topics"],
                    "source_type": entry["source_type"],
                    "mock": True,
                },
            )
            items.append(item)
            source_counts[entry["source_name"]] += 1

        items.sort(key=lambda item: item.relevance_score, reverse=True)
        limited_items = items[: query_plan.max_results]
        limited_ids = {item.item_id for item in limited_items}

        stats = [
            SourceExecutionStat(
                source_name=source_name,
                query_count=1,
                result_count=sum(
                    1
                    for entry in MOCK_SOURCE_LIBRARY
                    if entry["source_name"] == source_name and entry["item_id"] in limited_ids
                ),
                success=True,
                notes="mock search executed",
            )
            for source_name in source_names
        ]

        return RawIntelItemBatch(
            items=limited_items,
            query_plan=query_plan,
            source_stats=stats,
            batch_notes="Deterministic mock source search; no network calls were made.",
        )

    def _score_entry(
        self,
        entry: dict[str, Any],
        query_topics: set[str],
        query_tokens: set[str],
    ) -> float:
        entry_topics = set(entry["topics"])
        topic_matches = len(query_topics & entry_topics)
        haystack = f"{entry['title']} {entry['summary']} {' '.join(entry['topics'])}"
        token_matches = len(query_tokens & tokenize(haystack))

        if not topic_matches and token_matches < 2:
            return 0.0

        return min(1.0, 0.35 + 0.22 * topic_matches + 0.05 * token_matches)


class MockSourceSearchInput(BaseModel):
    query_text: str = Field(..., description="Search query text.")
    source_names: list[str] = Field(default_factory=list, description="Approved source names.")
    target_topics: list[str] = Field(default_factory=list, description="Target coverage topics.")
    round_index: int = Field(default=0, ge=0, description="Autonomous loop round index.")
    max_results: int = Field(default=10, ge=1, description="Maximum mock results to return.")
    approved_sources_json: str = Field(
        default="[]",
        description="JSON encoded ApprovedSource list. Empty means all mock sources are allowed.",
    )


class MockSourceSearchTool(BaseTool):
    name: str = "mock_registered_source_search"
    description: str = (
        "Searches deterministic mock registered sources for LLM security intelligence. "
        "Use this only for local autonomous-loop validation."
    )
    args_schema: Type[BaseModel] = MockSourceSearchInput

    def _run(
        self,
        query_text: str,
        source_names: list[str] | None = None,
        target_topics: list[str] | None = None,
        round_index: int = 0,
        max_results: int = 10,
        approved_sources_json: str = "[]",
    ) -> str:
        approved_sources = _parse_approved_sources(approved_sources_json)
        if not approved_sources:
            approved_sources = default_mock_sources()

        query_plan = SearchQueryPlan(
            query_text=query_text,
            source_names=source_names or [],
            target_topics=target_topics or [],
            round_index=round_index,
            max_results=max_results,
        )
        batch = MockSourceRepository().search(query_plan, approved_sources)
        return batch.model_dump_json()


class MockSourceProposalInput(BaseModel):
    missing_topics: list[str] = Field(default_factory=list, description="Coverage gaps to improve.")


class MockSourceProposalTool(BaseTool):
    name: str = "mock_new_source_proposal"
    description: str = (
        "Creates pending source proposals for uncovered LLM security topics. "
        "It never approves or collects from proposed sources."
    )
    args_schema: Type[BaseModel] = MockSourceProposalInput

    def _run(self, missing_topics: list[str] | None = None) -> str:
        proposals: list[SourceProposal] = []
        for topic in missing_topics or []:
            proposal = MOCK_SOURCE_PROPOSALS.get(topic)
            if not proposal:
                continue
            proposals.append(SourceProposal(**proposal))
        return json.dumps([proposal.model_dump(mode="json") for proposal in proposals])


def default_mock_sources() -> list[ApprovedSource]:
    return [
        ApprovedSource(
            source_name="nvd",
            base_uri="https://mock.local/nvd",
            source_type="security_db",
            trust_level=0.78,
            notes="Mock NVD-like security database.",
        ),
        ApprovedSource(
            source_name="github_advisories",
            base_uri="https://mock.local/github/advisories",
            source_type="security_db",
            trust_level=0.74,
            notes="Mock GitHub advisory source.",
        ),
        ApprovedSource(
            source_name="owasp_llm_top_10",
            base_uri="https://mock.local/owasp/llm",
            source_type="advisory",
            trust_level=0.86,
            notes="Mock OWASP LLM Top 10 source.",
        ),
        ApprovedSource(
            source_name="arxiv_security",
            base_uri="https://mock.local/arxiv/security",
            source_type="paper",
            trust_level=0.66,
            notes="Mock security paper feed.",
        ),
        ApprovedSource(
            source_name="ai_security_research_feed",
            base_uri="https://mock.local/research/ai-security",
            source_type="research",
            trust_level=0.72,
            notes="Mock AI security research feed.",
        ),
        ApprovedSource(
            source_name="vendor_security_blogs",
            base_uri="https://mock.local/vendor/security",
            source_type="vendor",
            trust_level=0.68,
            notes="Mock vendor security blog source.",
        ),
        ApprovedSource(
            source_name="community_discussions",
            base_uri="https://mock.local/community/security",
            source_type="community",
            trust_level=0.42,
            notes="Mock noisy community discussion source.",
        ),
        ApprovedSource(
            source_name="nvd_cve_api",
            base_uri="https://services.nvd.nist.gov/rest/json/cves/2.0",
            source_type="security_db",
            trust_level=0.9,
            notes="Registered NVD CVE API source; mocked in local autonomous-loop tests.",
            metadata={"supports": ["keywordSearch", "pubStartDate", "pubEndDate", "hasKev"]},
        ),
        ApprovedSource(
            source_name="arxiv_api",
            base_uri="https://export.arxiv.org/api/query",
            source_type="paper",
            trust_level=0.72,
            notes="Registered arXiv API source; mocked in local autonomous-loop tests.",
        ),
        ApprovedSource(
            source_name="cisa_kev_json",
            base_uri="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            source_type="advisory",
            trust_level=0.92,
            notes="Registered CISA KEV JSON source; mocked in local autonomous-loop tests.",
        ),
        ApprovedSource(
            source_name="osv_dev_api",
            base_uri="https://api.osv.dev/v1/query",
            source_type="security_db",
            trust_level=0.84,
            notes="Registered OSV.dev API source; mocked in local autonomous-loop tests.",
        ),
    ]


def _parse_approved_sources(raw_sources: str) -> list[ApprovedSource]:
    try:
        parsed = json.loads(raw_sources or "[]")
    except (TypeError, json.JSONDecodeError):
        return []

    if not isinstance(parsed, list):
        return []

    approved_sources: list[ApprovedSource] = []
    for source in parsed:
        if not isinstance(source, dict):
            continue
        try:
            approved_sources.append(ApprovedSource.model_validate(source))
        except ValueError:
            continue
    return approved_sources
