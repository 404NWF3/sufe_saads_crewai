"""Registered intelligence source clients: NVD, arXiv, CISA KEV, OSV.dev.

Self-contained port of the legacy ``registered_source_tools`` HTTP/parse layer
with the CrewAI ``BaseTool`` wrapper removed (the agentic loop calls these plain
functions through ``@tool`` wrappers instead) and a small shared retry added to
the previously bare urllib calls.
"""

from __future__ import annotations

import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.client import RemoteDisconnected
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .schemas import ApprovedSource, RawIntelItem, SourceExecutionStat
from .topics import detect_topics, tokenize

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ARXIV_API_URL = "https://export.arxiv.org/api/query"
CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

REGISTERED_API_SOURCE_NAMES = {"nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api"}
USER_AGENT = "intel-agent/0.1"

ATOM_NAMESPACE = {"atom": "http://www.w3.org/2005/Atom"}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ADVISORY_ID_PATTERN = re.compile(
    r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)",
    re.IGNORECASE,
)

_RETRYABLE = (URLError, TimeoutError, RemoteDisconnected, ConnectionError)

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
    "prompt injection", "indirect prompt injection", "jailbreak",
    "large language model", "LLM", "chatbot", "model extraction",
    "model inversion", "data poisoning", "adversarial example",
    "training data", "RAG", "embedding", "vector database",
]
NVD_AI_PRODUCT_KEYWORDS = [
    "LangChain", "LlamaIndex", "Ollama", "vLLM", "llama.cpp", "Hugging Face",
    "Transformers", "MLflow", "Gradio", "Jupyter", "Ray", "Kubeflow",
    "TensorFlow", "PyTorch", "NVIDIA Triton", "ONNX", "Dify", "Langflow",
    "Flowise", "Milvus", "Qdrant", "Weaviate", "Chroma",
]
NVD_AI_RELEVANT_CWE_IDS = [
    "CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94",
    "CWE-200", "CWE-287", "CWE-434", "CWE-502", "CWE-918",
]


def default_registered_api_sources() -> list[ApprovedSource]:
    return [
        ApprovedSource(
            source_name="nvd_cve_api",
            base_uri=NVD_CVE_API_URL,
            source_type="security_db",
            trust_level=0.9,
            notes="NVD CVE API 2.0 (keywordSearch, pubStartDate/pubEndDate, hasKev, cveId).",
            metadata={"supports": ["keywordSearch", "pubStartDate", "pubEndDate", "hasKev"]},
        ),
        ApprovedSource(
            source_name="arxiv_api",
            base_uri=ARXIV_API_URL,
            source_type="paper",
            trust_level=0.72,
            notes="arXiv Atom API for LLM security papers and preprints.",
            metadata={"best_for": ["prompt injection", "jailbreak", "rag poisoning"]},
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
            metadata={"best_for": ["GitHub Advisory", "PyPI", "RustSec", "npm", "Go"]},
        ),
    ]


# --------------------------------------------------------------------- dispatch


def search_source(
    source_name: str,
    query_text: str,
    target_topics: list[str] | None = None,
    max_results: int = 10,
    timeout_seconds: int = 20,
    **params: Any,
) -> tuple[list[RawIntelItem], SourceExecutionStat]:
    """Run one source search; never raises -- failures return an error stat."""
    start = time.perf_counter()
    topics = target_topics or []
    try:
        if source_name == "nvd_cve_api":
            items = search_nvd_cve_api(
                query_text, max_results, timeout_seconds,
                keyword_search=params.get("nvd_keyword_search"),
                pub_start_date=params.get("nvd_pub_start_date"),
                pub_end_date=params.get("nvd_pub_end_date"),
                has_kev=bool(params.get("nvd_has_kev")),
                cve_id=params.get("nvd_cve_id"),
                keyword_exact_match=bool(params.get("nvd_keyword_exact_match")),
                cwe_id=params.get("nvd_cwe_id"),
                cvss_v3_severity=params.get("nvd_cvss_v3_severity"),
                no_rejected=bool(params.get("nvd_no_rejected", True)),
                start_index=int(params.get("nvd_start_index") or 0),
            )
        elif source_name == "arxiv_api":
            items = search_arxiv_api(
                query_text, topics, max_results, timeout_seconds,
                arxiv_search_query=params.get("arxiv_search_query"),
                arxiv_start=int(params.get("arxiv_start") or 0),
            )
        elif source_name == "cisa_kev_json":
            items = search_cisa_kev_json(
                query_text, max_results, timeout_seconds,
                cve_ids=params.get("cisa_cve_ids") or [],
                keyword=params.get("cisa_keyword"),
            )
        elif source_name == "osv_dev_api":
            items = search_osv_dev_api(
                query_text, max_results, timeout_seconds,
                ecosystem=params.get("osv_ecosystem"),
                package_name=params.get("osv_package_name"),
                version=params.get("osv_version"),
                purl=params.get("osv_purl"),
                vuln_id=params.get("osv_vuln_id"),
            )
        else:
            items = []
        stat = SourceExecutionStat(
            source_name=source_name, query_count=1, result_count=len(items),
            success=True, latency_ms=_elapsed_ms(start), notes="ok",
        )
        return items, stat
    except (HTTPError, URLError, TimeoutError, RemoteDisconnected, ConnectionError,
            ValueError, ET.ParseError) as exc:
        stat = SourceExecutionStat(
            source_name=source_name, query_count=1, result_count=0, success=False,
            latency_ms=_elapsed_ms(start), error_type=exc.__class__.__name__, notes=str(exc),
        )
        return [], stat


# ---------------------------------------------------------------- per-source


def search_nvd_cve_api(
    query_text: str, max_results: int, timeout_seconds: int,
    keyword_search: str | None = None, pub_start_date: str | None = None,
    pub_end_date: str | None = None, has_kev: bool = False, cve_id: str | None = None,
    keyword_exact_match: bool = False, cwe_id: str | None = None,
    cvss_v3_severity: str | None = None, no_rejected: bool = True,
    start_index: int = 0,
) -> list[RawIntelItem]:
    params = _build_nvd_query_params(
        query_text, max_results, keyword_search, pub_start_date, pub_end_date,
        has_kev, cve_id, keyword_exact_match, cwe_id, cvss_v3_severity, no_rejected,
        start_index,
    )
    data = _fetch_json(_url_with_params(NVD_CVE_API_URL, params), timeout_seconds)
    return parse_nvd_items(data)


def search_arxiv_api(
    query_text: str, target_topics: list[str], max_results: int,
    timeout_seconds: int, arxiv_search_query: str | None = None,
    arxiv_start: int = 0,
) -> list[RawIntelItem]:
    search_query = arxiv_search_query or build_arxiv_search_query(query_text, target_topics)
    params = {
        "search_query": search_query, "start": str(max(0, arxiv_start)), "max_results": str(max_results),
        "sortBy": "submittedDate", "sortOrder": "descending",
    }
    raw_xml = _fetch_text(_url_with_params(ARXIV_API_URL, params), timeout_seconds)
    return parse_arxiv_items(raw_xml)


def search_cisa_kev_json(
    query_text: str, max_results: int, timeout_seconds: int,
    cve_ids: list[str] | None = None, keyword: str | None = None,
) -> list[RawIntelItem]:
    data = _fetch_json(CISA_KEV_JSON_URL, timeout_seconds)
    return parse_cisa_kev_items(data, query_text, cve_ids or [], keyword, max_results)


def search_osv_dev_api(
    query_text: str, max_results: int, timeout_seconds: int,
    ecosystem: str | None = None, package_name: str | None = None,
    version: str | None = None, purl: str | None = None, vuln_id: str | None = None,
) -> list[RawIntelItem]:
    direct_id = vuln_id or _extract_first_vulnerability_id(query_text)
    if direct_id:
        data = _fetch_json(f"{OSV_VULN_URL}/{direct_id}", timeout_seconds)
        return parse_osv_vulnerability(data)[:max_results]

    payload = build_osv_query_payload(ecosystem, package_name, version, purl)
    payloads = [payload] if payload else [{"package": pkg} for pkg in DEFAULT_OSV_PACKAGE_TARGETS]

    items: list[RawIntelItem] = []
    seen: set[str] = set()
    for next_payload in payloads:
        data = _fetch_json(OSV_QUERY_URL, timeout_seconds, method="POST", payload=next_payload)
        for item in parse_osv_query_response(data, query_text):
            if item.item_id in seen:
                continue
            seen.add(item.item_id)
            items.append(item)
            if len(items) >= max_results:
                return items
    return items


# ------------------------------------------------------------- query builders


def _build_nvd_query_params(
    query_text: str, max_results: int, keyword_search: str | None,
    pub_start_date: str | None, pub_end_date: str | None, has_kev: bool,
    cve_id: str | None, keyword_exact_match: bool, cwe_id: str | None,
    cvss_v3_severity: str | None, no_rejected: bool,
    start_index: int = 0,
) -> dict[str, str | None]:
    cve = cve_id or _extract_first_cve_id(query_text)
    params: dict[str, str | None] = {
        "resultsPerPage": str(max_results), "startIndex": str(max(0, start_index))
    }
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
    phrases = target_topics or detect_topics(query_text) or [
        "prompt injection", "jailbreak", "RAG poisoning", "large language model security",
    ]
    phrase_query = " OR ".join(f'all:"{phrase}"' for phrase in phrases[:6])
    return f"({phrase_query}) AND (cat:cs.CR OR cat:cs.AI OR cat:cs.CL)"


def build_osv_query_payload(
    ecosystem: str | None = None, package_name: str | None = None,
    version: str | None = None, purl: str | None = None,
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


# ------------------------------------------------------------------- parsers


def parse_nvd_items(data: dict[str, Any]) -> list[RawIntelItem]:
    items: list[RawIntelItem] = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        description = _first_english_description(cve.get("descriptions", []))
        references = _extract_nvd_references(cve)
        primary_ref = references[0].get("url") if references else f"{NVD_CVE_API_URL}?cveId={cve_id}"
        cwe_ids = _extract_nvd_cwe_ids(cve)
        cpe_products = _extract_nvd_cpe_products(cve)
        nvd_text = " ".join([description, " ".join(cpe_products)])
        topics = detect_topics(nvd_text)
        ai_category, matched_terms = classify_ai_vulnerability(nvd_text, cwe_ids)
        relevance = estimate_relevance(nvd_text, topics)
        if ai_category != "uncategorized":
            relevance = max(relevance, 0.68)
        items.append(
            RawIntelItem(
                item_id=f"nvd:{cve_id.lower()}",
                source_name="nvd_cve_api",
                source_uri=primary_ref,
                title=f"{cve_id}: {_shorten(description, 120)}",
                summary=description,
                published_at=_parse_datetime(cve.get("published")),
                raw_text=description,
                relevance_score=relevance,
                extraction_notes="Parsed from NVD CVE API 2.0 response.",
                metadata={
                    "cve_id": cve_id, "topics": topics, "ai_intel_category": ai_category,
                    "matched_ai_terms": matched_terms, "cwe_ids": cwe_ids,
                    "cvss_v3_severity": _extract_nvd_cvss_v3_severity(cve),
                    "cpe_products": cpe_products, "source_type": "security_db",
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
        if title.lower() == "error":
            continue
        topics = detect_topics(f"{title} {summary}")
        items.append(
            RawIntelItem(
                item_id=f"arxiv:{item_id.rsplit('/', 1)[-1].lower()}",
                source_name="arxiv_api",
                source_uri=item_id,
                title=title,
                summary=summary,
                published_at=_parse_datetime(_node_text(entry, "atom:published")),
                raw_text=summary,
                relevance_score=estimate_relevance(f"{title} {summary}", topics),
                extraction_notes="Parsed from arXiv Atom API response.",
                metadata={
                    "topics": topics, "source_type": "paper",
                    "authors": [
                        _node_text(author, "atom:name")
                        for author in entry.findall("atom:author", ATOM_NAMESPACE)
                    ],
                },
            )
        )
    return items


def parse_cisa_kev_items(
    data: dict[str, Any], query_text: str, cve_ids: list[str],
    keyword: str | None, max_results: int,
) -> list[RawIntelItem]:
    wanted = {cve_id.upper() for cve_id in cve_ids}
    wanted.update(match.upper() for match in CVE_PATTERN.findall(query_text))
    query_tokens = tokenize(keyword or query_text)
    items: list[RawIntelItem] = []
    for entry in data.get("vulnerabilities", []):
        cve_id = str(entry.get("cveID", "")).upper()
        text = " ".join(
            str(entry.get(key, ""))
            for key in ("vendorProject", "product", "vulnerabilityName",
                        "shortDescription", "requiredAction", "knownRansomwareCampaignUse")
        )
        if wanted and cve_id not in wanted:
            continue
        if not wanted and query_tokens and not (query_tokens & tokenize(text)):
            continue
        topics = detect_topics(text)
        items.append(
            RawIntelItem(
                item_id=f"cisa-kev:{cve_id.lower()}",
                source_name="cisa_kev_json",
                source_uri=(
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                    f"?search_api_fulltext={cve_id}"
                ),
                title=f"{cve_id}: {entry.get('vulnerabilityName', '')}",
                summary=str(entry.get("shortDescription", "")),
                published_at=_parse_date(entry.get("dateAdded")),
                raw_text=text,
                relevance_score=max(0.55, estimate_relevance(text, topics)),
                extraction_notes="Parsed from CISA KEV JSON catalog.",
                metadata={
                    "cve_id": cve_id, "topics": topics,
                    "vendor_project": entry.get("vendorProject"),
                    "product": entry.get("product"), "due_date": entry.get("dueDate"),
                    "date_added": entry.get("dateAdded"), "source_type": "advisory",
                },
            )
        )
        if len(items) >= max_results:
            break
    return items


def parse_osv_query_response(data: dict[str, Any], query_text: str) -> list[RawIntelItem]:
    items: list[RawIntelItem] = []
    for vuln in data.get("vulns", []):
        items.extend(parse_osv_vulnerability(vuln, query_text))
    return items


def parse_osv_vulnerability(data: dict[str, Any], query_text: str = "") -> list[RawIntelItem]:
    vuln_id = str(data.get("id", ""))
    if not vuln_id:
        return []
    summary = str(data.get("summary") or data.get("details") or "")
    details = str(data.get("details") or summary)
    affected = data.get("affected", [])
    references = data.get("references", [])
    source_uri = references[0].get("url") if references else f"{OSV_VULN_URL}/{vuln_id}"
    topics = detect_topics(f"{summary} {details} {query_text}")
    ecosystems = sorted(
        {
            pkg.get("ecosystem", "")
            for item in affected
            for pkg in [item.get("package", {})]
            if pkg.get("ecosystem")
        }
    )
    return [
        RawIntelItem(
            item_id=f"osv:{vuln_id.lower()}",
            source_name="osv_dev_api",
            source_uri=source_uri,
            title=f"{vuln_id}: {_shorten(summary, 160)}",
            summary=summary or _shorten(details, 300),
            published_at=_parse_datetime(data.get("published") or data.get("modified")),
            raw_text=details,
            relevance_score=estimate_relevance(f"{summary} {details} {query_text}", topics),
            extraction_notes="Parsed from OSV.dev vulnerability API response.",
            metadata={
                "vulnerability_id": vuln_id, "aliases": data.get("aliases", []),
                "topics": topics, "ecosystems": ecosystems,
                "modified": data.get("modified"), "source_type": "security_db",
            },
        )
    ]


# --------------------------------------------------------------------- http


def _fetch_json(
    url: str, timeout_seconds: int, method: str = "GET",
    payload: dict[str, Any] | None = None, retries: int = 2,
) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    nvd_key = os.getenv("NVD_API_KEY")
    if nvd_key and url.startswith(NVD_CVE_API_URL):
        headers["apiKey"] = nvd_key
    raw = _request_with_retry(url, headers, data, method, timeout_seconds, retries)
    return json.loads(raw)


def _fetch_text(url: str, timeout_seconds: int, retries: int = 2) -> str:
    return _request_with_retry(
        url, {"User-Agent": USER_AGENT}, None, "GET", timeout_seconds, retries
    )


def _request_with_retry(
    url: str, headers: dict[str, str], data: bytes | None,
    method: str, timeout_seconds: int, retries: int,
) -> str:
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = Request(url, data=data, headers=headers, method=method)
            with urlopen(request, timeout=timeout_seconds) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                last_exc = exc
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except _RETRYABLE as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
    raise last_exc if last_exc else RuntimeError("request failed without exception")


def _url_with_params(base_url: str, params: dict[str, str | None]) -> str:
    parts = [key if value is None else urlencode({key: value}) for key, value in params.items()]
    return f"{base_url}?{'&'.join(parts)}"


# ------------------------------------------------------------------ helpers


def estimate_relevance(text: str, topics: list[str]) -> float:
    topic_bonus = min(0.3, 0.1 * len(topics))
    token_bonus = min(0.2, 0.02 * len(tokenize(text)))
    return min(1.0, 0.45 + topic_bonus + token_bonus)


def classify_ai_vulnerability(text: str, cwe_ids: list[str]) -> tuple[str, list[str]]:
    lower = text.lower()
    attack = [term for term in NVD_AI_ATTACK_KEYWORDS if term.lower() in lower]
    product = [term for term in NVD_AI_PRODUCT_KEYWORDS if term.lower() in lower]
    cwe = [cwe_id for cwe_id in cwe_ids if cwe_id in NVD_AI_RELEVANT_CWE_IDS]
    matched = sorted(set(attack + product + cwe))
    if attack:
        return "ai_native_attack", matched
    if product and cwe:
        return "ai_application_infrastructure_vulnerability", matched
    if product:
        return "ai_data_model_supply_chain", matched
    return "uncategorized", matched


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
    return match.group(0).upper() if match else None


def _extract_first_cve_id(query_text: str) -> str | None:
    match = CVE_PATTERN.search(query_text)
    return match.group(0).upper() if match else None


def _extract_nvd_cwe_ids(cve: dict[str, Any]) -> list[str]:
    cwe_ids: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = str(description.get("value", ""))
            if value.startswith("CWE-"):
                cwe_ids.add(value)
    return sorted(cwe_ids)


def _extract_nvd_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    raw = cve.get("references", [])
    if isinstance(raw, dict):
        data = raw.get("referenceData", [])
        return data if isinstance(data, list) else []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _extract_nvd_cvss_v3_severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key) or []
        if values:
            severity = values[0].get("cvssData", {}).get("baseSeverity")
            if severity:
                return str(severity)
    return None


def _extract_nvd_cpe_products(cve: dict[str, Any]) -> list[str]:
    products: set[str] = set()
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) >= 6:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    products.add(f"{vendor} {product}".strip())
    return sorted(products)


def _first_english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    raw = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return _parse_date(raw)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _node_text(node: ET.Element, path: str) -> str:
    found = node.find(path, ATOM_NAMESPACE)
    return found.text if found is not None and found.text is not None else ""


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _shorten(text: str, max_length: int) -> str:
    cleaned = _clean_text(text)
    return cleaned if len(cleaned) <= max_length else f"{cleaned[: max_length - 3].rstrip()}..."


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)
