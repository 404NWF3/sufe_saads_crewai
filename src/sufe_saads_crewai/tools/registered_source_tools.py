from __future__ import annotations

from datetime import datetime, timezone
from http.client import RemoteDisconnected
import json
import os
import re
import time
from typing import Any, ClassVar, Type
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from sufe_saads_crewai.schemas import (
    ApprovedSource,
    RawIntelItem,
    RawIntelItemBatch,
    SearchQueryPlan,
    SourceExecutionStat,
)
from sufe_saads_crewai.topic_utils import detect_topics, tokenize


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ARXIV_API_URL = "https://export.arxiv.org/api/query"
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

REGISTERED_API_SOURCE_NAMES = {
    "nvd_cve_api",
    "arxiv_api",
    "cisa_kev_json",
    "osv_dev_api",
}

ATOM_NAMESPACE = {"atom": "http://www.w3.org/2005/Atom"}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ADVISORY_ID_PATTERN = re.compile(
    r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)",
    re.IGNORECASE,
)

DEFAULT_OSV_PACKAGE_TARGETS = [
    {"ecosystem": "PyPI", "name": "langchain"},
    {"ecosystem": "PyPI", "name": "llama-index"},
    {"ecosystem": "PyPI", "name": "transformers"},
    {"ecosystem": "PyPI", "name": "gradio"},
    {"ecosystem": "PyPI", "name": "mlflow"},
    {"ecosystem": "PyPI", "name": "vllm"},
    {"ecosystem": "PyPI", "name": "open-webui"},
    {"ecosystem": "PyPI", "name": "langflow"},
    {"ecosystem": "PyPI", "name": "chromadb"},
    {"ecosystem": "PyPI", "name": "qdrant-client"},
    {"ecosystem": "PyPI", "name": "weaviate-client"},
    {"ecosystem": "PyPI", "name": "jupyter-server"},
    {"ecosystem": "PyPI", "name": "ray"},
    {"ecosystem": "npm", "name": "flowise"},
    {"ecosystem": "npm", "name": "langchain"},
]

NVD_AI_ATTACK_KEYWORDS = [
    "prompt injection",
    "indirect prompt injection",
    "jailbreak",
    "large language model",
    "LLM",
    "chatbot",
    "model extraction",
    "model inversion",
    "data poisoning",
    "adversarial example",
    "training data",
    "RAG",
    "embedding",
    "vector database",
]

NVD_AI_PRODUCT_KEYWORDS = [
    "LangChain",
    "LlamaIndex",
    "Ollama",
    "vLLM",
    "llama.cpp",
    "Hugging Face",
    "Transformers",
    "MLflow",
    "Gradio",
    "Jupyter",
    "Ray",
    "Kubeflow",
    "TensorFlow",
    "PyTorch",
    "NVIDIA Triton",
    "ONNX",
    "Dify",
    "Langflow",
    "Flowise",
    "Milvus",
    "Qdrant",
    "Weaviate",
    "Chroma",
]

NVD_AI_RELEVANT_CWE_IDS = [
    "CWE-20",
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-200",
    "CWE-287",
    "CWE-434",
    "CWE-502",
    "CWE-918",
]

NVD_EXACT_MATCH_KEYWORDS = {
    "prompt injection",
    "indirect prompt injection",
    "large language model",
    "machine learning",
    "artificial intelligence",
    "model extraction",
    "model inversion",
    "data poisoning",
    "adversarial example",
    "training data",
    "hugging face",
    "nvidia triton",
    "vector database",
}


def default_registered_api_sources() -> list[ApprovedSource]:
    return [
        ApprovedSource(
            source_name="nvd_cve_api",
            base_uri=NVD_CVE_API_URL,
            source_type="security_db",
            trust_level=0.9,
            notes=(
                "NVD CVE API 2.0. Supports keywordSearch, pubStartDate/pubEndDate, "
                "hasKev, cveId, and pagination parameters."
            ),
            metadata={
                "supports": ["keywordSearch", "pubStartDate", "pubEndDate", "hasKev"],
            },
        ),
        ApprovedSource(
            source_name="arxiv_api",
            base_uri=ARXIV_API_URL,
            source_type="paper",
            trust_level=0.72,
            notes="arXiv Atom API for LLM security papers and preprints.",
            metadata={
                "best_for": ["prompt injection", "jailbreak", "rag poisoning"],
            },
        ),
        ApprovedSource(
            source_name="cisa_kev_json",
            base_uri=CISA_KEV_JSON_URL,
            source_type="advisory",
            trust_level=0.92,
            notes="CISA Known Exploited Vulnerabilities JSON catalog.",
            metadata={"best_for": ["known exploited vulnerabilities", "kev"]},
        ),
        ApprovedSource(
            source_name="osv_dev_api",
            base_uri=OSV_QUERY_URL,
            source_type="security_db",
            trust_level=0.84,
            notes="OSV.dev API for open source ecosystem vulnerability intelligence.",
            metadata={
                "best_for": ["GitHub Advisory", "PyPI", "RustSec", "npm", "Go"],
            },
        ),
    ]


class RegisteredApiSourceSearchInput(BaseModel):
    query_text: str = Field(..., description="Mission query text for source search.")
    source_names: list[str] = Field(
        default_factory=list,
        description="Approved source names. Empty means all registered API sources.",
    )
    target_topics: list[str] = Field(
        default_factory=list,
        description="Coverage topics the search should improve.",
    )
    max_results: int = Field(default=10, ge=1, le=50)
    round_index: int = Field(default=0, ge=0)
    approved_sources_json: str = Field(
        default="[]",
        description="JSON encoded ApprovedSource list. Empty means default registered API sources.",
    )
    nvd_keyword_search: str | None = Field(
        default=None,
        description="Optional NVD keywordSearch override.",
    )
    nvd_pub_start_date: str | None = Field(
        default=None,
        description="Optional NVD pubStartDate in extended ISO-8601 format.",
    )
    nvd_pub_end_date: str | None = Field(
        default=None,
        description="Optional NVD pubEndDate in extended ISO-8601 format.",
    )
    nvd_has_kev: bool = Field(default=False, description="Filter NVD results to CISA KEV CVEs.")
    nvd_cve_id: str | None = Field(default=None, description="Optional CVE ID for NVD lookup.")
    nvd_keyword_exact_match: bool = Field(
        default=False,
        description="Use NVD keywordExactMatch for phrase searches.",
    )
    nvd_cwe_id: str | None = Field(default=None, description="Optional NVD cweId filter.")
    nvd_cvss_v3_severity: str | None = Field(
        default=None,
        description="Optional NVD cvssV3Severity filter, e.g. HIGH or CRITICAL.",
    )
    nvd_no_rejected: bool = Field(
        default=True,
        description="Add noRejected to exclude rejected CVE records.",
    )
    arxiv_search_query: str | None = Field(
        default=None,
        description="Optional arXiv search_query override.",
    )
    cisa_cve_ids: list[str] = Field(default_factory=list)
    cisa_keyword: str | None = None
    osv_ecosystem: str | None = Field(default=None, description="OSV package ecosystem, e.g. PyPI.")
    osv_package_name: str | None = None
    osv_version: str | None = None
    osv_purl: str | None = None
    osv_vuln_id: str | None = Field(
        default=None,
        description="OSV, GHSA, PYSEC, RUSTSEC, or CVE identifier for direct lookup.",
    )
    timeout_seconds: int = Field(default=20, ge=1, le=60)


class RegisteredApiSourceSearchTool(BaseTool):
    name: str = "registered_api_source_search"
    description: str = (
        "Search approved structured intelligence APIs: NVD CVE API, arXiv API, "
        "CISA KEV JSON, and OSV.dev API. Use this for real source collection."
    )
    args_schema: Type[BaseModel] = RegisteredApiSourceSearchInput
    user_agent: ClassVar[str] = "sufe-saads-crewai/0.1"

    def _run(
        self,
        query_text: str,
        source_names: list[str] | None = None,
        target_topics: list[str] | None = None,
        max_results: int = 10,
        round_index: int = 0,
        approved_sources_json: str = "[]",
        nvd_keyword_search: str | None = None,
        nvd_pub_start_date: str | None = None,
        nvd_pub_end_date: str | None = None,
        nvd_has_kev: bool = False,
        nvd_cve_id: str | None = None,
        nvd_keyword_exact_match: bool = False,
        nvd_cwe_id: str | None = None,
        nvd_cvss_v3_severity: str | None = None,
        nvd_no_rejected: bool = True,
        arxiv_search_query: str | None = None,
        cisa_cve_ids: list[str] | None = None,
        cisa_keyword: str | None = None,
        osv_ecosystem: str | None = None,
        osv_package_name: str | None = None,
        osv_version: str | None = None,
        osv_purl: str | None = None,
        osv_vuln_id: str | None = None,
        timeout_seconds: int = 20,
    ) -> str:
        approved_sources = _parse_approved_sources(approved_sources_json)
        if not approved_sources:
            approved_sources = default_registered_api_sources()

        selected_sources = _select_registered_source_names(
            requested_names=source_names or [],
            approved_sources=approved_sources,
        )
        query_plan = SearchQueryPlan(
            query_text=query_text,
            source_names=selected_sources,
            target_topics=target_topics or [],
            query_intent="registered_api_collection",
            max_results=max_results,
            round_index=round_index,
        )

        items: list[RawIntelItem] = []
        stats: list[SourceExecutionStat] = []
        per_source_limit = max(1, max_results)

        for source_name in selected_sources:
            start = time.perf_counter()
            try:
                fetched_items = self._search_source(
                    source_name=source_name,
                    query_text=query_text,
                    target_topics=target_topics or [],
                    max_results=per_source_limit,
                    timeout_seconds=timeout_seconds,
                    nvd_keyword_search=nvd_keyword_search,
                    nvd_pub_start_date=nvd_pub_start_date,
                    nvd_pub_end_date=nvd_pub_end_date,
                    nvd_has_kev=nvd_has_kev,
                    nvd_cve_id=nvd_cve_id,
                    nvd_keyword_exact_match=nvd_keyword_exact_match,
                    nvd_cwe_id=nvd_cwe_id,
                    nvd_cvss_v3_severity=nvd_cvss_v3_severity,
                    nvd_no_rejected=nvd_no_rejected,
                    arxiv_search_query=arxiv_search_query,
                    cisa_cve_ids=cisa_cve_ids or [],
                    cisa_keyword=cisa_keyword,
                    osv_ecosystem=osv_ecosystem,
                    osv_package_name=osv_package_name,
                    osv_version=osv_version,
                    osv_purl=osv_purl,
                    osv_vuln_id=osv_vuln_id,
                )
                items.extend(fetched_items)
                stats.append(
                    SourceExecutionStat(
                        source_name=source_name,
                        query_count=1,
                        result_count=len(fetched_items),
                        success=True,
                        latency_ms=_elapsed_ms(start),
                        notes="registered API source search executed",
                    )
                )
            except (
                HTTPError,
                URLError,
                TimeoutError,
                RemoteDisconnected,
                ConnectionError,
                ValueError,
                ET.ParseError,
            ) as exc:
                stats.append(
                    SourceExecutionStat(
                        source_name=source_name,
                        query_count=1,
                        result_count=0,
                        success=False,
                        latency_ms=_elapsed_ms(start),
                        error_type=exc.__class__.__name__,
                        notes=str(exc),
                    )
                )

        items.sort(key=lambda item: (item.published_at or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
        batch = RawIntelItemBatch(
            items=items[:max_results],
            query_plan=query_plan,
            source_stats=stats,
            batch_notes=(
                "Registered API source search completed. Failed sources are recorded "
                "in source_stats and should be retried or deprioritized by the planner."
            ),
        )
        return batch.model_dump_json()

    def _search_source(
        self,
        source_name: str,
        query_text: str,
        target_topics: list[str],
        max_results: int,
        timeout_seconds: int,
        **kwargs: Any,
    ) -> list[RawIntelItem]:
        if source_name == "nvd_cve_api":
            return search_nvd_cve_api(
                query_text=query_text,
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                keyword_search=kwargs.get("nvd_keyword_search"),
                pub_start_date=kwargs.get("nvd_pub_start_date"),
                pub_end_date=kwargs.get("nvd_pub_end_date"),
                has_kev=bool(kwargs.get("nvd_has_kev")),
                cve_id=kwargs.get("nvd_cve_id"),
                keyword_exact_match=bool(kwargs.get("nvd_keyword_exact_match")),
                cwe_id=kwargs.get("nvd_cwe_id"),
                cvss_v3_severity=kwargs.get("nvd_cvss_v3_severity"),
                no_rejected=bool(kwargs.get("nvd_no_rejected", True)),
            )
        if source_name == "arxiv_api":
            return search_arxiv_api(
                query_text=query_text,
                target_topics=target_topics,
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                arxiv_search_query=kwargs.get("arxiv_search_query"),
            )
        if source_name == "cisa_kev_json":
            return search_cisa_kev_json(
                query_text=query_text,
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                cve_ids=kwargs.get("cisa_cve_ids") or [],
                keyword=kwargs.get("cisa_keyword"),
            )
        if source_name == "osv_dev_api":
            return search_osv_dev_api(
                query_text=query_text,
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                ecosystem=kwargs.get("osv_ecosystem"),
                package_name=kwargs.get("osv_package_name"),
                version=kwargs.get("osv_version"),
                purl=kwargs.get("osv_purl"),
                vuln_id=kwargs.get("osv_vuln_id"),
            )
        return []


def search_nvd_cve_api(
    query_text: str,
    max_results: int,
    timeout_seconds: int,
    keyword_search: str | None = None,
    pub_start_date: str | None = None,
    pub_end_date: str | None = None,
    has_kev: bool = False,
    cve_id: str | None = None,
    keyword_exact_match: bool = False,
    cwe_id: str | None = None,
    cvss_v3_severity: str | None = None,
    no_rejected: bool = True,
) -> list[RawIntelItem]:
    params = build_nvd_query_params(
        query_text=query_text,
        max_results=max_results,
        keyword_search=keyword_search,
        pub_start_date=pub_start_date,
        pub_end_date=pub_end_date,
        has_kev=has_kev,
        cve_id=cve_id,
        keyword_exact_match=keyword_exact_match,
        cwe_id=cwe_id,
        cvss_v3_severity=cvss_v3_severity,
        no_rejected=no_rejected,
    )
    data = _fetch_json(_url_with_params(NVD_CVE_API_URL, params), timeout_seconds=timeout_seconds)
    return parse_nvd_items(data)


def search_arxiv_api(
    query_text: str,
    target_topics: list[str],
    max_results: int,
    timeout_seconds: int,
    arxiv_search_query: str | None = None,
) -> list[RawIntelItem]:
    search_query = arxiv_search_query or build_arxiv_search_query(query_text, target_topics)
    params = {
        "search_query": search_query,
        "start": "0",
        "max_results": str(max_results),
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }
    raw_xml = _fetch_text(_url_with_params(ARXIV_API_URL, params), timeout_seconds=timeout_seconds)
    return parse_arxiv_items(raw_xml)


def search_cisa_kev_json(
    query_text: str,
    max_results: int,
    timeout_seconds: int,
    cve_ids: list[str] | None = None,
    keyword: str | None = None,
) -> list[RawIntelItem]:
    data = _fetch_json(CISA_KEV_JSON_URL, timeout_seconds=timeout_seconds)
    return parse_cisa_kev_items(
        data=data,
        query_text=query_text,
        cve_ids=cve_ids or [],
        keyword=keyword,
        max_results=max_results,
    )


def search_osv_dev_api(
    query_text: str,
    max_results: int,
    timeout_seconds: int,
    ecosystem: str | None = None,
    package_name: str | None = None,
    version: str | None = None,
    purl: str | None = None,
    vuln_id: str | None = None,
) -> list[RawIntelItem]:
    direct_id = vuln_id or _extract_first_vulnerability_id(query_text)
    if direct_id:
        data = _fetch_json(f"{OSV_VULN_URL}/{direct_id}", timeout_seconds=timeout_seconds)
        return parse_osv_vulnerability(data)[:max_results]

    payload = build_osv_query_payload(
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
        purl=purl,
    )
    payloads = [payload] if payload else [{"package": package} for package in DEFAULT_OSV_PACKAGE_TARGETS]

    items: list[RawIntelItem] = []
    seen_ids: set[str] = set()
    for next_payload in payloads:
        data = _fetch_json(
            OSV_QUERY_URL,
            timeout_seconds=timeout_seconds,
            method="POST",
            payload=next_payload,
        )
        for item in parse_osv_query_response(data, query_text=query_text):
            if item.item_id in seen_ids:
                continue
            seen_ids.add(item.item_id)
            items.append(item)
            if len(items) >= max_results:
                return items
    return items


def build_nvd_query_params(
    query_text: str,
    max_results: int,
    keyword_search: str | None = None,
    pub_start_date: str | None = None,
    pub_end_date: str | None = None,
    has_kev: bool = False,
    cve_id: str | None = None,
    keyword_exact_match: bool = False,
    cwe_id: str | None = None,
    cvss_v3_severity: str | None = None,
    no_rejected: bool = True,
) -> dict[str, str | None]:
    cve = cve_id or _extract_first_cve_id(query_text)
    params: dict[str, str | None] = {"resultsPerPage": str(max_results), "startIndex": "0"}
    if cve:
        params["cveId"] = cve
    else:
        params["keywordSearch"] = keyword_search or _compact_keyword_query(query_text)
        if keyword_exact_match and " " in params["keywordSearch"]:
            params["keywordExactMatch"] = None
    if cwe_id:
        params["cweId"] = cwe_id
    if cvss_v3_severity:
        params["cvssV3Severity"] = cvss_v3_severity.upper()
    if pub_start_date and pub_end_date:
        params["pubStartDate"] = pub_start_date
        params["pubEndDate"] = pub_end_date
    if has_kev:
        params["hasKev"] = None
    if no_rejected:
        params["noRejected"] = None
    return params


def build_arxiv_search_query(query_text: str, target_topics: list[str]) -> str:
    phrases = target_topics or detect_topics(query_text)
    if not phrases:
        phrases = [
            "prompt injection",
            "jailbreak",
            "RAG poisoning",
            "large language model security",
        ]
    phrase_query = " OR ".join(f'all:"{phrase}"' for phrase in phrases[:6])
    return f"({phrase_query}) AND (cat:cs.CR OR cat:cs.AI OR cat:cs.CL)"


def build_osv_query_payload(
    ecosystem: str | None = None,
    package_name: str | None = None,
    version: str | None = None,
    purl: str | None = None,
) -> dict[str, Any]:
    if purl:
        payload: dict[str, Any] = {"package": {"purl": purl}}
    elif ecosystem and package_name:
        payload = {"package": {"ecosystem": ecosystem, "name": package_name}}
    else:
        return {}

    if version and "@" not in payload["package"].get("purl", ""):
        payload["version"] = version
    return payload


def parse_nvd_items(data: dict[str, Any]) -> list[RawIntelItem]:
    items: list[RawIntelItem] = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        description = _first_english_description(cve.get("descriptions", []))
        published_at = _parse_datetime(cve.get("published"))
        references = _extract_nvd_references(cve)
        primary_ref = references[0].get("url") if references else f"{NVD_CVE_API_URL}?cveId={cve_id}"
        title = f"{cve_id}: {_shorten(description, 120)}"
        cwe_ids = _extract_nvd_cwe_ids(cve)
        cpe_products = _extract_nvd_cpe_products(cve)
        nvd_text = " ".join([description, " ".join(cpe_products)])
        topics = detect_topics(nvd_text)
        ai_category, matched_terms = _classify_ai_vulnerability(nvd_text, cwe_ids)
        relevance = _estimate_relevance(nvd_text, topics)
        if ai_category != "uncategorized":
            relevance = max(relevance, 0.68)
        items.append(
            RawIntelItem(
                item_id=f"nvd:{cve_id.lower()}",
                source_name="nvd_cve_api",
                source_uri=primary_ref,
                title=title,
                summary=description,
                published_at=published_at,
                raw_text=description,
                relevance_score=relevance,
                extraction_notes="Parsed from NVD CVE API 2.0 response.",
                metadata={
                    "cve_id": cve_id,
                    "topics": topics,
                    "ai_intel_category": ai_category,
                    "matched_ai_terms": matched_terms,
                    "cwe_ids": cwe_ids,
                    "cvss_v3_severity": _extract_nvd_cvss_v3_severity(cve),
                    "cpe_products": cpe_products,
                    "nvd_url": f"{NVD_CVE_API_URL}?cveId={cve_id}",
                    "source_type": "security_db",
                },
            )
        )
    return items


def parse_arxiv_items(raw_xml: str) -> list[RawIntelItem]:
    root = ET.fromstring(raw_xml)
    items: list[RawIntelItem] = []
    for entry in root.findall("atom:entry", ATOM_NAMESPACE):
        item_id = _node_text(entry, "atom:id")
        title = _clean_text(_node_text(entry, "atom:title"))
        summary = _clean_text(_node_text(entry, "atom:summary"))
        published = _node_text(entry, "atom:published")
        topics = detect_topics(f"{title} {summary}")
        if title.lower() == "error":
            continue
        items.append(
            RawIntelItem(
                item_id=f"arxiv:{item_id.rsplit('/', 1)[-1].lower()}",
                source_name="arxiv_api",
                source_uri=item_id,
                title=title,
                summary=summary,
                published_at=_parse_datetime(published),
                raw_text=summary,
                relevance_score=_estimate_relevance(f"{title} {summary}", topics),
                extraction_notes="Parsed from arXiv Atom API response.",
                metadata={
                    "topics": topics,
                    "source_type": "paper",
                    "authors": [
                        _node_text(author, "atom:name")
                        for author in entry.findall("atom:author", ATOM_NAMESPACE)
                    ],
                },
            )
        )
    return items


def parse_cisa_kev_items(
    data: dict[str, Any],
    query_text: str,
    cve_ids: list[str],
    keyword: str | None,
    max_results: int,
) -> list[RawIntelItem]:
    wanted_cves = {cve_id.upper() for cve_id in cve_ids}
    wanted_cves.update(match.upper() for match in CVE_PATTERN.findall(query_text))
    query_tokens = tokenize(keyword or query_text)
    items: list[RawIntelItem] = []

    for entry in data.get("vulnerabilities", []):
        cve_id = str(entry.get("cveID", "")).upper()
        text = " ".join(
            str(entry.get(key, ""))
            for key in (
                "vendorProject",
                "product",
                "vulnerabilityName",
                "shortDescription",
                "requiredAction",
                "knownRansomwareCampaignUse",
            )
        )
        if wanted_cves and cve_id not in wanted_cves:
            continue
        if not wanted_cves and query_tokens and not (query_tokens & tokenize(text)):
            continue

        topics = detect_topics(text)
        items.append(
            RawIntelItem(
                item_id=f"cisa-kev:{cve_id.lower()}",
                source_name="cisa_kev_json",
                source_uri=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                title=f"{cve_id}: {entry.get('vulnerabilityName', '')}",
                summary=str(entry.get("shortDescription", "")),
                published_at=_parse_date(entry.get("dateAdded")),
                raw_text=text,
                relevance_score=max(0.55, _estimate_relevance(text, topics)),
                extraction_notes="Parsed from CISA KEV JSON catalog.",
                metadata={
                    "cve_id": cve_id,
                    "topics": topics,
                    "vendor_project": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "due_date": entry.get("dueDate"),
                    "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
                    "source_type": "advisory",
                },
            )
        )
        if len(items) >= max_results:
            break
    return items


def parse_osv_query_response(data: dict[str, Any], query_text: str) -> list[RawIntelItem]:
    items: list[RawIntelItem] = []
    for vuln in data.get("vulns", []):
        items.extend(parse_osv_vulnerability(vuln, query_text=query_text))
    return items


def parse_osv_vulnerability(data: dict[str, Any], query_text: str = "") -> list[RawIntelItem]:
    vuln_id = str(data.get("id", ""))
    if not vuln_id:
        return []
    summary = str(data.get("summary") or data.get("details") or "")
    details = str(data.get("details") or summary)
    affected = data.get("affected", [])
    aliases = data.get("aliases", [])
    references = data.get("references", [])
    source_uri = references[0].get("url") if references else f"{OSV_VULN_URL}/{vuln_id}"
    topics = detect_topics(f"{summary} {details} {query_text}")
    ecosystems = sorted(
        {
            package.get("ecosystem", "")
            for item in affected
            for package in [item.get("package", {})]
            if package.get("ecosystem")
        }
    )
    items = [
        RawIntelItem(
            item_id=f"osv:{vuln_id.lower()}",
            source_name="osv_dev_api",
            source_uri=source_uri,
            title=f"{vuln_id}: {_shorten(summary, 160)}",
            summary=summary or _shorten(details, 300),
            published_at=_parse_datetime(data.get("published") or data.get("modified")),
            raw_text=details,
            relevance_score=_estimate_relevance(f"{summary} {details} {query_text}", topics),
            extraction_notes="Parsed from OSV.dev vulnerability API response.",
            metadata={
                "vulnerability_id": vuln_id,
                "aliases": aliases,
                "topics": topics,
                "ecosystems": ecosystems,
                "source_type": "security_db",
            },
        )
    ]
    return items


def _fetch_json(
    url: str,
    timeout_seconds: int,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json", "User-Agent": RegisteredApiSourceSearchTool.user_agent}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    nvd_api_key = os.getenv("NVD_API_KEY")
    if nvd_api_key and url.startswith(NVD_CVE_API_URL):
        request.add_header("apiKey", nvd_api_key)
    with urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _fetch_text(url: str, timeout_seconds: int) -> str:
    request = Request(url, headers={"User-Agent": RegisteredApiSourceSearchTool.user_agent})
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.read().decode("utf-8")


def _url_with_params(base_url: str, params: dict[str, str | None]) -> str:
    encoded_parts: list[str] = []
    for key, value in params.items():
        if value is None:
            encoded_parts.append(key)
        else:
            encoded_parts.append(urlencode({key: value}))
    return f"{base_url}?{'&'.join(encoded_parts)}"


def _select_registered_source_names(
    requested_names: list[str],
    approved_sources: list[ApprovedSource],
) -> list[str]:
    approved = {
        source.source_name
        for source in approved_sources
        if source.enabled and source.source_name in REGISTERED_API_SOURCE_NAMES
    }
    if not approved:
        approved = set(REGISTERED_API_SOURCE_NAMES)
    requested = [name for name in requested_names if name in approved]
    return requested or sorted(approved)


def _parse_approved_sources(raw_sources: str) -> list[ApprovedSource]:
    try:
        parsed = json.loads(raw_sources or "[]")
    except (TypeError, json.JSONDecodeError):
        return []

    if not isinstance(parsed, list):
        return []

    sources: list[ApprovedSource] = []
    for source in parsed:
        if not isinstance(source, dict):
            continue
        try:
            sources.append(ApprovedSource.model_validate(source))
        except ValueError:
            continue
    return sources


def _compact_keyword_query(query_text: str) -> str:
    topics = detect_topics(query_text)
    if topics:
        return " ".join(topics[:3])
    tokens = sorted(tokenize(query_text))
    return " ".join(tokens[:4]) or "large language model"


def _extract_first_vulnerability_id(query_text: str) -> str | None:
    cve_id = _extract_first_cve_id(query_text)
    if cve_id:
        return cve_id

    match = ADVISORY_ID_PATTERN.search(query_text)
    if match:
        return match.group(0).upper()
    return None


def _extract_first_cve_id(query_text: str) -> str | None:
    cve_match = CVE_PATTERN.search(query_text)
    if cve_match:
        return cve_match.group(0).upper()
    return None


def _extract_nvd_cwe_ids(cve: dict[str, Any]) -> list[str]:
    cwe_ids: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = str(description.get("value", ""))
            if value.startswith("CWE-"):
                cwe_ids.add(value)
    return sorted(cwe_ids)


def _extract_nvd_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    raw_references = cve.get("references", [])
    if isinstance(raw_references, dict):
        reference_data = raw_references.get("referenceData", [])
        return reference_data if isinstance(reference_data, list) else []
    if isinstance(raw_references, list):
        return [item for item in raw_references if isinstance(item, dict)]
    return []


def _extract_nvd_cvss_v3_severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key) or []
        if not values:
            continue
        severity = values[0].get("cvssData", {}).get("baseSeverity")
        if severity:
            return str(severity)
    return None


def _extract_nvd_cpe_products(cve: dict[str, Any]) -> list[str]:
    products: set[str] = set()
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = str(match.get("criteria", ""))
                parts = criteria.split(":")
                if len(parts) >= 6:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    products.add(f"{vendor} {product}".strip())
    return sorted(products)


def _classify_ai_vulnerability(text: str, cwe_ids: list[str]) -> tuple[str, list[str]]:
    lower_text = text.lower()
    attack_terms = [
        term for term in NVD_AI_ATTACK_KEYWORDS if term.lower() in lower_text
    ]
    product_terms = [
        term for term in NVD_AI_PRODUCT_KEYWORDS if term.lower() in lower_text
    ]
    cwe_terms = [cwe_id for cwe_id in cwe_ids if cwe_id in NVD_AI_RELEVANT_CWE_IDS]

    matched = sorted(set(attack_terms + product_terms + cwe_terms))
    if attack_terms:
        return "ai_native_attack", matched
    if product_terms and cwe_terms:
        return "ai_application_infrastructure_vulnerability", matched
    if product_terms:
        return "ai_data_model_supply_chain", matched
    return "uncategorized", matched


def _first_english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    if descriptions:
        return str(descriptions[0].get("value", ""))
    return ""


def _estimate_relevance(text: str, topics: list[str]) -> float:
    topic_bonus = min(0.3, 0.1 * len(topics))
    token_bonus = min(0.2, 0.02 * len(tokenize(text)))
    return min(1.0, 0.45 + topic_bonus + token_bonus)


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    raw = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return _parse_date(raw)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _node_text(node: ET.Element, path: str) -> str:
    found = node.find(path, ATOM_NAMESPACE)
    if found is None or found.text is None:
        return ""
    return found.text


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _shorten(text: str, max_length: int) -> str:
    cleaned = _clean_text(text)
    if len(cleaned) <= max_length:
        return cleaned
    return f"{cleaned[: max_length - 3].rstrip()}..."


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)
