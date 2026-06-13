"""Shared deterministic rules for the intelligence collection loop.

Extracted from RealIntelRunController so the rules engine (real_loop) and the
claude-agent-sdk engine (sdk_loop) share one implementation of every fallback
decision. Functions here are pure: all state comes in through arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from typing import Any

from sufe_saads_crewai.topic_utils import build_gap_query, detect_topics
from sufe_saads_crewai.schemas import (
    CollectionYieldAssessment,
    CoverageGap,
    CoverageGapAnalysis,
    IntelRunBlackboard,
    PlannerDecisionOutput,
    QueryHistoryEntry,
    RawIntelItem,
    RawIntelItemBatch,
    SearchCompletenessAssessment,
    SearchQueryPlan,
    SearchReflectionDecision,
    SearchSemanticExpansionOutput,
    SemanticGapExpansion,
    SourceExecutionStat,
    SourceSemanticTerms,
    SourceYieldMetric,
)
from sufe_saads_crewai.tools.registered_source_tools import (
    DEFAULT_OSV_PACKAGE_TARGETS,
    NVD_AI_ATTACK_KEYWORDS,
    NVD_AI_PRODUCT_KEYWORDS,
    NVD_AI_RELEVANT_CWE_IDS,
    NVD_EXACT_MATCH_KEYWORDS,
)


@dataclass(frozen=True)
class SourceQuerySpec:
    source_name: str
    query_text: str
    target_topics: list[str]
    max_results: int
    strategy_name: str
    params: dict[str, Any]


# ---------------------------------------------------------------- helpers


def dedupe_preserve_order(values: list[Any]) -> list[Any]:
    deduped: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = (
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            if isinstance(value, (dict, list, tuple))
            else str(value)
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


def rotating_slice(values: list[Any], round_index: int, limit: int) -> list[Any]:
    if not values or limit <= 0:
        return []
    if len(values) <= limit:
        return values
    start = (round_index * limit) % len(values)
    rotated = values[start:] + values[:start]
    return rotated[:limit]


def item_id(source_name: str, source_uri: str, title: str) -> str:
    digest = hashlib.sha256(f"{source_name}|{source_uri}|{title}".encode("utf-8")).hexdigest()
    return f"real:{digest[:16]}"


def source_query_key(spec: SourceQuerySpec) -> str:
    return json.dumps(
        {
            "source_name": spec.source_name,
            "query_text": spec.query_text,
            "strategy_name": spec.strategy_name,
            "params": spec.params,
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def batch_source_query_plans(batch_notes: str | None) -> list[dict[str, Any]]:
    if not batch_notes:
        return []
    try:
        parsed = json.loads(batch_notes)
    except json.JSONDecodeError:
        return []
    plans = parsed.get("source_query_plans") if isinstance(parsed, dict) else None
    if not isinstance(plans, list):
        return []
    return [plan for plan in plans if isinstance(plan, dict)]


def covered_topics(items: list[RawIntelItem], target_topics: list[str]) -> set[str]:
    covered: set[str] = set()
    for item in items:
        covered.update(topic for topic in item.metadata.get("topics", []) if topic in target_topics)
        covered.update(detect_topics(f"{item.title} {item.summary} {item.raw_text or ''}"))
    return covered & set(target_topics)


def semantic_terms_for_source(
    semantic_expansion: SearchSemanticExpansionOutput | None,
    source_name: str,
    focus_topics: list[str],
) -> list[str]:
    if semantic_expansion is None:
        return []
    focus = {topic.lower() for topic in focus_topics}
    terms: list[str] = []
    for expansion in semantic_expansion.expansions:
        if focus and expansion.gap_topic.lower() not in focus:
            matched = any(topic in expansion.gap_topic.lower() for topic in focus)
            matched = matched or any(expansion.gap_topic.lower() in topic for topic in focus)
            if not matched:
                continue
        for source_terms in expansion.source_specific_terms:
            if source_terms.source_name == source_name:
                terms.extend(source_terms.positive_terms)
    return dedupe_preserve_order(terms)


# ---------------------------------------------------------------- decision fallbacks


def fallback_planner_decision(query_plan: SearchQueryPlan) -> PlannerDecisionOutput:
    return PlannerDecisionOutput(
        actions=[
            {
                "action_type": "SEARCH_REGISTERED_SOURCE",
                "priority": "high",
                "rationale": "Collect from approved real registered API sources.",
                "expected_gain": "More real raw intelligence and coverage signals.",
                "required_context": [query_plan.query_text],
                "success_criteria": ["RawIntelItemBatch contains source_uri for each item."],
                "retry_conditions": ["Transient source API failure."],
                "stop_conditions": ["No enabled approved sources remain."],
                "estimated_cost_level": "medium",
            },
            {
                "action_type": "ANALYZE_COVERAGE_GAPS",
                "priority": "medium",
                "rationale": "Find missing LLM security topics after collection.",
                "expected_gain": "A better next query if coverage is incomplete.",
                "required_context": ["raw_items", "target_topics"],
                "success_criteria": ["Coverage gaps are explicit."],
                "retry_conditions": [],
                "stop_conditions": ["Target coverage reached."],
                "estimated_cost_level": "low",
            },
        ],
        planner_rationale="Fallback planner selected real-source collection and coverage analysis.",
        should_start_collection=True,
    )


def fallback_yield_assessment(
    history: QueryHistoryEntry,
    latest_batch: RawIntelItemBatch,
) -> CollectionYieldAssessment:
    metrics = []
    for stat in latest_batch.source_stats:
        source_items = [
            item for item in latest_batch.items if item.source_name == stat.source_name
        ]
        evidence_quality = (
            sum(item.relevance_score for item in source_items) / len(source_items)
            if source_items
            else 0.0
        )
        metrics.append(
            SourceYieldMetric(
                source_name=stat.source_name,
                result_count=stat.result_count,
                novelty_score=history.novelty_score,
                noise_ratio=history.noise_ratio,
                duplicate_ratio=history.duplicate_ratio,
                evidence_quality=evidence_quality,
                notes=stat.notes,
            )
        )
    return CollectionYieldAssessment(
        per_source_metrics=metrics,
        low_yield_sources=[
            metric.source_name
            for metric in metrics
            if metric.result_count == 0 or metric.evidence_quality < 0.45
        ],
        high_noise_queries=[history.query_text] if history.noise_ratio >= 0.5 else [],
        useful_queries=[history.query_text] if history.novelty_score >= 0.2 else [],
        novelty_summary=(
            f"Latest query returned {history.result_count} items with "
            f"novelty={history.novelty_score:.2f}, duplicate={history.duplicate_ratio:.2f}."
        ),
        recommended_adjustments=[],
    )


def fallback_coverage_analysis(
    raw_items: list[RawIntelItem],
    target_topics: list[str],
) -> CoverageGapAnalysis:
    covered = covered_topics(raw_items, target_topics)
    gaps = [
        CoverageGap(
            gap_id=f"gap-{topic.replace(' ', '-')}",
            dimension="llm_security_taxonomy",
            taxonomy_or_component=topic,
            current_coverage=0.0,
            target_coverage=1.0,
            estimated_gap_fill_roi=0.82,
            recommended_queries=[
                SearchQueryPlan(
                    query_text=build_gap_query([topic]),
                    target_topics=[topic],
                    query_intent="gap_fill",
                    priority="high",
                )
            ],
            priority="high",
        )
        for topic in target_topics
        if topic not in covered
    ]
    return CoverageGapAnalysis(
        gaps=gaps,
        overall_coverage_score=len(covered) / len(target_topics) if target_topics else 0.0,
        analysis_rationale="Coverage measured against target LLM security topics.",
    )


def fallback_semantic_expansion(
    gap_analysis: CoverageGapAnalysis,
) -> SearchSemanticExpansionOutput:
    high_roi_gaps = [
        gap
        for gap in gap_analysis.gaps
        if gap.priority in {"high", "critical"} or gap.estimated_gap_fill_roi >= 0.55
    ]
    expansions = [
        fallback_semantic_gap_expansion(gap.taxonomy_or_component) for gap in high_roi_gaps[:4]
    ]
    return SearchSemanticExpansionOutput(
        expansions=expansions,
        overall_rationale=(
            "Fallback semantic expansion maps coverage gaps to source-specific "
            "terms for NVD, OSV, arXiv, and CISA KEV."
        ),
        confidence=0.74 if expansions else 0.0,
    )


def fallback_semantic_gap_expansion(gap_topic: str) -> SemanticGapExpansion:
    topic = gap_topic.lower()
    expanded_terms: list[str] = []
    nvd_terms: list[str] = []
    osv_terms: list[str] = []
    arxiv_terms: list[str] = []
    cisa_terms: list[str] = []
    nvd_hints = ["noRejected", "keywordExactMatch for multi-word phrases"]

    if "agent" in topic or "tool" in topic:
        expanded_terms.extend(
            [
                "tool invocation abuse",
                "unsafe tool execution",
                "agent code execution",
                "computer-use agent",
                "browser agent attack",
                "MCP server compromise",
                "confused deputy",
                "capability misuse",
            ]
        )
        nvd_terms.extend(
            [
                "code injection",
                "command injection",
                "arbitrary code execution",
                "sandbox escape",
                "LangChain",
                "LlamaIndex",
                "Jupyter",
                "Ray",
                "browser agent",
            ]
        )
        osv_terms.extend(["langchain", "llama-index", "langflow", "flowise", "jupyter-server", "ray"])
        arxiv_terms.extend(
            [
                "agentic AI security",
                "tool-use agents",
                "computer-use agents",
                "indirect prompt injection",
                "confused deputy",
                "sandboxing LLM agents",
            ]
        )
        cisa_terms.extend(["code injection", "command injection", "remote code execution", "authentication bypass"])
        nvd_hints.extend(["CWE-78", "CWE-94", "CWE-287"])

    if "rag" in topic or "poison" in topic:
        expanded_terms.extend(
            [
                "retrieval poisoning",
                "embedding poisoning",
                "vector database injection",
                "knowledge base poisoning",
            ]
        )
        nvd_terms.extend(["RAG", "embedding", "vector database", "Milvus", "Qdrant", "Weaviate", "Chroma"])
        osv_terms.extend(["chromadb", "qdrant-client", "weaviate-client", "llama-index", "langchain"])
        arxiv_terms.extend(["RAG poisoning", "retrieval augmented generation poisoning", "embedding attack"])
        cisa_terms.extend(["injection", "data exposure", "authentication bypass"])
        nvd_hints.extend(["CWE-20", "CWE-89", "CWE-918"])

    if "supply" in topic or "model" in topic:
        expanded_terms.extend(
            [
                "model loading vulnerability",
                "unsafe deserialization",
                "model artifact tampering",
                "AI package supply chain",
            ]
        )
        nvd_terms.extend(["MLflow", "Gradio", "Hugging Face", "Transformers", "Langflow", "Dify", "model"])
        osv_terms.extend(["mlflow", "gradio", "transformers", "vllm", "open-webui", "langflow"])
        arxiv_terms.extend(["model supply chain", "model artifact security", "LLM supply chain"])
        cisa_terms.extend(["deserialization", "code injection", "file upload", "path traversal"])
        nvd_hints.extend(["CWE-502", "CWE-434", "CWE-22"])

    if "data" in topic or "leak" in topic:
        expanded_terms.extend(
            [
                "sensitive information exposure",
                "training data leakage",
                "prompt data exfiltration",
                "cross-tenant data leakage",
            ]
        )
        nvd_terms.extend(["sensitive information", "training data", "chatbot", "Jupyter", "Chroma"])
        osv_terms.extend(["jupyter-server", "chromadb", "weaviate-client", "qdrant-client"])
        arxiv_terms.extend(["LLM data leakage", "training data extraction", "privacy attack"])
        cisa_terms.extend(["information disclosure", "sensitive information", "data exposure"])
        nvd_hints.extend(["CWE-200"])

    if "prompt" in topic:
        expanded_terms.extend(["indirect prompt injection", "prompt injection", "instruction hierarchy attack"])
        nvd_terms.extend(["prompt injection", "indirect prompt injection", "chatbot", "AnythingLLM"])
        osv_terms.extend(["anythingllm", "open-webui", "langchain"])
        arxiv_terms.extend(["prompt injection", "indirect prompt injection", "prompt injection defense"])
        cisa_terms.extend(["cross-site scripting", "injection", "chatbot"])
        nvd_hints.extend(["keywordExactMatch"])

    if "jailbreak" in topic:
        expanded_terms.extend(["safety bypass", "policy bypass", "adversarial prompt", "red teaming"])
        nvd_terms.extend(["jailbreak", "large language model", "LLM"])
        arxiv_terms.extend(["jailbreak attack", "safety bypass", "LLM red teaming"])
        cisa_terms.extend(["policy bypass", "authentication bypass"])

    if not expanded_terms:
        expanded_terms.extend([gap_topic, "large language model security", "AI vulnerability"])
        nvd_terms.extend(["large language model", "LLM", "machine learning"])
        osv_terms.extend(["langchain", "llama-index", "mlflow"])
        arxiv_terms.extend([gap_topic, "large language model security"])
        cisa_terms.extend(["code injection", "remote code execution"])

    return SemanticGapExpansion(
        gap_topic=gap_topic,
        expanded_terms=dedupe_preserve_order(expanded_terms),
        source_specific_terms=[
            SourceSemanticTerms(
                source_name="nvd_cve_api",
                positive_terms=dedupe_preserve_order(nvd_terms),
                negative_terms=["AI", "ML"],
                query_templates=[
                    "keywordSearch={term}&noRejected",
                    "keywordSearch={product}&cweId={cwe}&noRejected",
                    "keywordSearch={product}&hasKev&noRejected",
                ],
                parameter_hints=dedupe_preserve_order(nvd_hints),
                rationale="NVD searches CVE descriptions and product/CWE metadata, not an AI attack taxonomy.",
            ),
            SourceSemanticTerms(
                source_name="osv_dev_api",
                positive_terms=dedupe_preserve_order(osv_terms),
                negative_terms=[],
                query_templates=[
                    "package.ecosystem=PyPI package.name={package}",
                    "package.ecosystem=npm package.name={package}",
                    "vulns/{GHSA_OR_CVE_ID}",
                ],
                parameter_hints=["ecosystem", "package_name", "purl", "vuln_id"],
                rationale="OSV is package-centric, so terms should map to ecosystems and package names.",
            ),
            SourceSemanticTerms(
                source_name="arxiv_api",
                positive_terms=dedupe_preserve_order(arxiv_terms),
                negative_terms=["leaderboard", "video generation", "robotics"],
                query_templates=[
                    '(all:"{term}") AND (cat:cs.CR OR cat:cs.AI OR cat:cs.CL)',
                ],
                parameter_hints=["sortBy=submittedDate", "sortOrder=descending"],
                rationale="arXiv works best with research phrases and security categories.",
            ),
            SourceSemanticTerms(
                source_name="cisa_kev_json",
                positive_terms=dedupe_preserve_order(cisa_terms),
                negative_terms=[],
                query_templates=["keyword={term}", "cve_id={cve}"],
                parameter_hints=["product", "vendorProject", "shortDescription"],
                rationale="CISA KEV captures exploitation-prioritized vulnerabilities, often through product and vulnerability type terms.",
            ),
        ],
        global_negative_terms=["marketing", "benchmark only", "unrelated robotics", "pure video generation"],
        rationale=f"Expanded {gap_topic} into terms that match each source's retrieval semantics.",
        confidence=0.76,
    )


def non_repeating_gap_query(
    topics: list[str],
    previous_queries: set[str],
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> str:
    topic_text = " ".join(topics).lower()
    templates: list[str] = []
    semantic_terms = []
    for source_name in ("arxiv_api", "nvd_cve_api", "cisa_kev_json"):
        semantic_terms.extend(semantic_terms_for_source(semantic_expansion, source_name, topics))
    if semantic_terms:
        templates.append(" ".join(dedupe_preserve_order(semantic_terms)[:8]))
    if "agent" in topic_text or "tool" in topic_text:
        templates.extend(
            [
                "agent tool abuse incidents LLM autonomous agents code execution permissions",
                "LangChain LlamaIndex agent tool execution vulnerability advisory",
            ]
        )
    if "data" in topic_text or "leak" in topic_text:
        templates.extend(
            [
                "LLM data leakage sensitive information exposure training data vulnerability",
                "chatbot data exposure embedding vector database sensitive information",
            ]
        )
    if "supply" in topic_text or "model" in topic_text:
        templates.extend(
            [
                "AI model supply chain MLflow Gradio Langflow vulnerability advisory",
                "Hugging Face Transformers model loading deserialization vulnerability",
            ]
        )
    if "rag" in topic_text or "poison" in topic_text:
        templates.extend(
            [
                "RAG poisoning embedding vector database vulnerability advisory",
                "retrieval augmented generation data poisoning vector database security",
            ]
        )
    if "prompt" in topic_text:
        templates.append("prompt injection indirect prompt injection chatbot vulnerability")
    if "jailbreak" in topic_text:
        templates.append("LLM jailbreak attack benchmark mitigation security paper")

    templates.append(build_gap_query(topics))
    for template in templates:
        if template not in previous_queries:
            return template
    return f"{templates[0]} latest exploitation mitigation evidence"


def fallback_rewrite_decision(
    gap_analysis: CoverageGapAnalysis,
    target_topics: list[str],
    blackboard: IntelRunBlackboard,
    max_results_per_round: int,
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> SearchReflectionDecision:
    high_roi_gaps = [
        gap
        for gap in gap_analysis.gaps
        if gap.estimated_gap_fill_roi >= 0.55 and gap.priority in {"high", "critical"}
    ]
    if not high_roi_gaps:
        return SearchReflectionDecision(
            rewritten_queries=[],
            topics_to_stop=target_topics,
            rationale="No high-ROI coverage gaps remain.",
            confidence=0.75,
        )
    topics = [gap.taxonomy_or_component for gap in high_roi_gaps[:4]]
    previous_queries = {entry.query_text for entry in blackboard.query_history}
    query_text = non_repeating_gap_query(topics, previous_queries, semantic_expansion)
    query = SearchQueryPlan(
        query_text=query_text,
        source_names=[source.source_name for source in blackboard.approved_sources if source.enabled],
        target_topics=topics,
        query_intent="gap_fill",
        max_results=max_results_per_round,
        priority="high",
        rationale="Fallback rewrite around missing high-ROI topics.",
        round_index=len(blackboard.query_history),
    )
    return SearchReflectionDecision(
        rewritten_queries=[query],
        topics_to_expand=topics,
        topics_to_stop=sorted(set(target_topics) - set(topics)),
        rationale="Coverage gaps remain, so rewrite query for another real-source round.",
        confidence=0.8,
    )


def fallback_completeness(
    gap_analysis: CoverageGapAnalysis,
    reflection: SearchReflectionDecision,
    round_index: int,
    max_rounds: int,
) -> SearchCompletenessAssessment:
    should_continue = (
        round_index + 1 < max_rounds
        and gap_analysis.overall_coverage_score < 0.85
        and bool(gap_analysis.gaps)
        and bool(reflection.rewritten_queries)
    )
    return SearchCompletenessAssessment(
        completeness_score=gap_analysis.overall_coverage_score,
        should_continue=should_continue,
        missing_dimensions=[gap.taxonomy_or_component for gap in gap_analysis.gaps],
        recommended_next_mode="gap_fill" if should_continue else None,
        stop_rationale=None if should_continue else "Coverage threshold, query, or round budget stop condition met.",
    )


# ---------------------------------------------------------------- source query specs


def focus_topics_for_round(
    blackboard: IntelRunBlackboard,
    query_plan: SearchQueryPlan,
    target_topics: list[str],
) -> list[str]:
    gap_topics = [
        gap.taxonomy_or_component
        for gap in blackboard.coverage_gaps
        if gap.priority in {"high", "critical"} or gap.estimated_gap_fill_roi >= 0.55
    ]
    topics = gap_topics or query_plan.target_topics or target_topics
    normalized: list[str] = []
    for topic in topics:
        lowered = topic.lower()
        if lowered not in normalized:
            normalized.append(lowered)
    return normalized[:6]


def nvd_query_limit() -> int:
    default_limit = 8 if os.getenv("NVD_API_KEY") else 3
    raw_limit = os.getenv("NVD_STRATEGY_QUERY_LIMIT")
    if not raw_limit:
        return default_limit
    try:
        return max(1, int(raw_limit))
    except ValueError:
        return default_limit


def nvd_keywords_for_topics(
    focus_topics: list[str],
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> list[str]:
    keywords: list[str] = semantic_terms_for_source(semantic_expansion, "nvd_cve_api", focus_topics)
    topic_text = " ".join(focus_topics).lower()
    if "prompt injection" in topic_text:
        keywords.extend(["prompt injection", "indirect prompt injection", "chatbot"])
    if "jailbreak" in topic_text:
        keywords.extend(["jailbreak", "large language model", "LLM"])
    if "rag" in topic_text or "poison" in topic_text:
        keywords.extend(["RAG", "embedding", "vector database", "data poisoning"])
    if "supply" in topic_text or "model" in topic_text:
        keywords.extend(["model extraction", "model inversion", "training data"])
        keywords.extend(["LangChain", "LlamaIndex", "MLflow", "Gradio", "Hugging Face"])
    if "agent" in topic_text or "tool" in topic_text:
        keywords.extend(["LangChain", "LlamaIndex", "Jupyter", "Ray", "code injection"])
    if "data leakage" in topic_text or "leak" in topic_text:
        keywords.extend(["training data", "sensitive information", "Jupyter", "Chroma"])

    keywords.extend(NVD_AI_ATTACK_KEYWORDS)
    keywords.extend(NVD_AI_PRODUCT_KEYWORDS)
    return dedupe_preserve_order(keywords)


def nvd_product_cwe_pairs(focus_topics: list[str], round_index: int) -> list[tuple[str, str]]:
    topic_text = " ".join(focus_topics).lower()
    pairs: list[tuple[str, str]] = []
    if "supply" in topic_text or "model" in topic_text:
        pairs.extend([("MLflow", "CWE-502"), ("Gradio", "CWE-434"), ("Langflow", "CWE-94")])
    if "agent" in topic_text or "tool" in topic_text:
        pairs.extend([("LangChain", "CWE-94"), ("Jupyter", "CWE-78"), ("Ray", "CWE-287")])
    if "rag" in topic_text or "data" in topic_text:
        pairs.extend([("Chroma", "CWE-200"), ("Qdrant", "CWE-287"), ("Weaviate", "CWE-918")])
    if not pairs:
        pairs.extend([("MLflow", "CWE-502"), ("Gradio", "CWE-434"), ("Langflow", "CWE-94")])
    pairs = [pair for pair in pairs if pair[1] in NVD_AI_RELEVANT_CWE_IDS]
    return rotating_slice(dedupe_preserve_order(pairs), round_index, 2)


def nvd_query_specs(
    focus_topics: list[str],
    round_index: int,
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> list[SourceQuerySpec]:
    query_limit = nvd_query_limit()
    keywords = rotating_slice(
        nvd_keywords_for_topics(focus_topics, semantic_expansion),
        round_index,
        query_limit,
    )
    specs: list[SourceQuerySpec] = []
    for keyword in keywords:
        specs.append(
            SourceQuerySpec(
                source_name="nvd_cve_api",
                query_text=f"NVD keywordSearch:{keyword}",
                target_topics=focus_topics,
                max_results=20,
                strategy_name="nvd_keyword_candidate",
                params={
                    "nvd_keyword_search": keyword,
                    "nvd_keyword_exact_match": keyword.lower() in NVD_EXACT_MATCH_KEYWORDS,
                    "nvd_no_rejected": True,
                },
            )
        )

    for keyword, cwe_id in nvd_product_cwe_pairs(focus_topics, round_index):
        specs.append(
            SourceQuerySpec(
                source_name="nvd_cve_api",
                query_text=f"NVD product+CWE:{keyword} {cwe_id}",
                target_topics=focus_topics,
                max_results=20,
                strategy_name="nvd_product_cwe_candidate",
                params={
                    "nvd_keyword_search": keyword,
                    "nvd_cwe_id": cwe_id,
                    "nvd_no_rejected": True,
                },
            )
        )
    return specs


def cisa_keywords(
    focus_topics: list[str],
    round_index: int,
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> list[str]:
    semantic_terms = semantic_terms_for_source(semantic_expansion, "cisa_kev_json", focus_topics)
    candidates = semantic_terms + nvd_keywords_for_topics(focus_topics, semantic_expansion)
    product_terms = [term for term in candidates if term in NVD_AI_PRODUCT_KEYWORDS]
    attack_terms = [term for term in candidates if term not in NVD_AI_PRODUCT_KEYWORDS]
    ordered = product_terms + attack_terms
    return rotating_slice(dedupe_preserve_order(ordered), round_index, 3)


def osv_packages(
    focus_topics: list[str],
    round_index: int,
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> list[dict[str, str]]:
    topic_text = " ".join(focus_topics).lower()
    preferred_names: list[str] = [
        term.lower()
        for term in semantic_terms_for_source(semantic_expansion, "osv_dev_api", focus_topics)
    ]
    if "supply" in topic_text or "model" in topic_text:
        preferred_names.extend(["mlflow", "transformers", "gradio", "vllm", "open-webui"])
    if "agent" in topic_text or "tool" in topic_text:
        preferred_names.extend(["langchain", "llama-index", "langflow", "flowise"])
    if "rag" in topic_text or "data" in topic_text:
        preferred_names.extend(["chromadb", "qdrant-client", "weaviate-client", "llama-index"])

    packages = [
        package
        for name in preferred_names
        for package in DEFAULT_OSV_PACKAGE_TARGETS
        if package["name"].lower() == name.lower()
    ]
    packages.extend(DEFAULT_OSV_PACKAGE_TARGETS)
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for package in packages:
        key = (package["ecosystem"], package["name"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(package)
    return rotating_slice(deduped, round_index, 5)


def arxiv_strategy_query(
    focus_topics: list[str],
    target_topics: list[str],
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> str:
    semantic_terms = semantic_terms_for_source(semantic_expansion, "arxiv_api", focus_topics)
    phrases = dedupe_preserve_order(semantic_terms + focus_topics)[:6] or target_topics[:4]
    phrase_query = " OR ".join(f'all:"{phrase}"' for phrase in phrases)
    return f"({phrase_query}) AND (cat:cs.CR OR cat:cs.AI OR cat:cs.CL)"


def build_source_query_specs(
    blackboard: IntelRunBlackboard,
    query_plan: SearchQueryPlan,
    target_topics: list[str],
    max_results_per_round: int,
    executed_query_keys: set[str],
    semantic_expansion: SearchSemanticExpansionOutput | None,
) -> list[SourceQuerySpec]:
    enabled_sources = set(query_plan.source_names) or {
        source.source_name for source in blackboard.approved_sources if source.enabled
    }
    focus_topics = focus_topics_for_round(blackboard, query_plan, target_topics)
    per_source_limit = max(5, min(20, max_results_per_round // 4))

    specs: list[SourceQuerySpec] = []
    if "nvd_cve_api" in enabled_sources:
        specs.extend(nvd_query_specs(focus_topics, query_plan.round_index, semantic_expansion))
    if "arxiv_api" in enabled_sources:
        query_text = arxiv_strategy_query(focus_topics, target_topics, semantic_expansion)
        specs.append(
            SourceQuerySpec(
                source_name="arxiv_api",
                query_text=query_text,
                target_topics=focus_topics,
                max_results=per_source_limit,
                strategy_name="arxiv_topic_research",
                params={"arxiv_search_query": query_text},
            )
        )
    if "cisa_kev_json" in enabled_sources:
        for keyword in cisa_keywords(focus_topics, query_plan.round_index, semantic_expansion):
            specs.append(
                SourceQuerySpec(
                    source_name="cisa_kev_json",
                    query_text=f"CISA KEV keyword:{keyword}",
                    target_topics=focus_topics,
                    max_results=min(12, per_source_limit),
                    strategy_name="cisa_kev_keyword",
                    params={"cisa_keyword": keyword},
                )
            )
    if "osv_dev_api" in enabled_sources:
        for package in osv_packages(focus_topics, query_plan.round_index, semantic_expansion):
            specs.append(
                SourceQuerySpec(
                    source_name="osv_dev_api",
                    query_text=f"OSV package:{package['ecosystem']}/{package['name']}",
                    target_topics=focus_topics,
                    max_results=6,
                    strategy_name="osv_package_ecosystem",
                    params={
                        "osv_ecosystem": package["ecosystem"],
                        "osv_package_name": package["name"],
                    },
                )
            )

    fresh_specs = [spec for spec in specs if source_query_key(spec) not in executed_query_keys]
    if fresh_specs:
        return fresh_specs
    if specs:
        return specs[: max(1, min(4, len(specs)))]

    return [
        SourceQuerySpec(
            source_name=source_name,
            query_text=query_plan.query_text,
            target_topics=query_plan.target_topics,
            max_results=per_source_limit,
            strategy_name="fallback_registered_source_query",
            params={},
        )
        for source_name in sorted(enabled_sources)
    ]


# ---------------------------------------------------------------- batch accounting


def combine_source_batches(
    query_plan: SearchQueryPlan,
    source_specs: list[SourceQuerySpec],
    batches: list[RawIntelItemBatch],
    max_results_per_round: int,
) -> RawIntelItemBatch:
    items: list[RawIntelItem] = []
    overflow_items: list[RawIntelItem] = []
    stats: list[SourceExecutionStat] = []
    seen_candidate_ids: set[str] = set()
    selected_item_ids: set[str] = set()
    source_item_counts: dict[str, int] = {}
    source_plan_summaries: list[dict[str, Any]] = []
    distinct_sources = {spec.source_name for spec in source_specs}
    per_source_cap = max(8, max_results_per_round // max(1, len(distinct_sources)))

    for spec, batch in zip(source_specs, batches):
        source_plan_summaries.append(
            {
                "source_name": spec.source_name,
                "strategy_name": spec.strategy_name,
                "query_text": spec.query_text,
                "params": {
                    key: value for key, value in spec.params.items() if value not in (None, [], "")
                },
            }
        )
        for stat in batch.source_stats:
            stat.notes = " | ".join(
                part
                for part in [
                    stat.notes,
                    f"strategy={spec.strategy_name}",
                    f"query={spec.query_text}",
                ]
                if part
            )
            stats.append(stat)
        for item in batch.items:
            if item.item_id in seen_candidate_ids:
                continue
            seen_candidate_ids.add(item.item_id)
            count = source_item_counts.get(item.source_name, 0)
            if count < per_source_cap and len(items) < max_results_per_round:
                items.append(item)
                selected_item_ids.add(item.item_id)
                source_item_counts[item.source_name] = count + 1
            else:
                overflow_items.append(item)

    for item in overflow_items:
        if len(items) >= max_results_per_round:
            break
        if item.item_id in selected_item_ids:
            continue
        items.append(item)
        selected_item_ids.add(item.item_id)
        source_item_counts[item.source_name] = source_item_counts.get(item.source_name, 0) + 1

    source_names = sorted({spec.source_name for spec in source_specs})
    combined_plan = SearchQueryPlan(
        query_text=query_plan.query_text,
        source_names=source_names,
        target_topics=query_plan.target_topics,
        query_intent="source_specific_registered_api_collection",
        max_results=max_results_per_round,
        priority=query_plan.priority,
        rationale=query_plan.rationale,
        round_index=query_plan.round_index,
    )
    return RawIntelItemBatch(
        items=items,
        query_plan=combined_plan,
        source_stats=stats,
        batch_notes=json.dumps(
            {
                "mode": "source_specific_collection",
                "source_query_plans": source_plan_summaries,
                "unique_items": len(items),
            },
            ensure_ascii=False,
        ),
    )


def merge_batch_into_blackboard(
    blackboard: IntelRunBlackboard,
    query_plan: SearchQueryPlan,
    latest_batch: RawIntelItemBatch,
) -> None:
    existing_ids = {item.item_id for item in blackboard.raw_items}
    new_items: list[RawIntelItem] = []
    duplicate_count = 0
    for item in latest_batch.items:
        if item.item_id in existing_ids:
            duplicate_count += 1
            continue
        blackboard.raw_items.append(item)
        new_items.append(item)
        existing_ids.add(item.item_id)

    result_count = len(latest_batch.items)
    low_relevance_count = sum(1 for item in latest_batch.items if item.relevance_score < 0.5)
    failed_sources = [stat.source_name for stat in latest_batch.source_stats if not stat.success]
    source_query_plans = batch_source_query_plans(latest_batch.batch_notes)
    blackboard.query_history.append(
        QueryHistoryEntry(
            query_text=query_plan.query_text,
            source_names=query_plan.source_names,
            result_count=result_count,
            novelty_score=(len(new_items) / result_count) if result_count else 0.0,
            noise_ratio=(low_relevance_count / result_count) if result_count else 0.0,
            duplicate_ratio=(duplicate_count / result_count) if result_count else 0.0,
            round_index=query_plan.round_index,
            metadata={
                "new_item_ids": [item.item_id for item in new_items],
                "batch_item_ids": [item.item_id for item in latest_batch.items],
                "failed_sources": failed_sources,
                "source_query_plans": source_query_plans,
                "target_topics": list(query_plan.target_topics),
            },
        )
    )
    blackboard.metrics.api_calls_used += max(1, len(latest_batch.source_stats))
    blackboard.metrics.sources_used = len(
        {source for history in blackboard.query_history for source in history.source_names}
    )
