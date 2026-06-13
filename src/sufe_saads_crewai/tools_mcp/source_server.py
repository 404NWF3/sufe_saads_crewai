"""SDK MCP server exposing the four registered intel sources as typed tools.

Thin wrappers: every tool delegates to the existing HTTP/parsing functions in
``tools/registered_source_tools.py`` (zero new request code). Typed parameters
expose each source's advanced operators directly to the agent (roadmap 6.3);
the descriptions teach operator semantics and useful combinations.

The agent receives a compact JSON digest (ids, titles, scores); the full
``RawIntelItem`` objects go into the :class:`SourceCallRecorder` so the Python
controller keeps blackboard accounting authoritative.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from sufe_saads_crewai.schemas import RawIntelItem, SourceExecutionStat
from sufe_saads_crewai.tools.registered_source_tools import (
    search_arxiv_api,
    search_cisa_kev_json,
    search_nvd_cve_api,
    search_osv_dev_api,
)


@dataclass
class SourceCall:
    source_name: str
    query_text: str
    params: dict[str, Any]
    items: list[RawIntelItem]
    stat: SourceExecutionStat


@dataclass
class SourceCallRecorder:
    calls: list[SourceCall] = field(default_factory=list)

    def record(
        self,
        source_name: str,
        query_text: str,
        params: dict[str, Any],
        items: list[RawIntelItem],
        success: bool,
        latency_ms: float,
        error: str | None = None,
    ) -> SourceCall:
        call = SourceCall(
            source_name=source_name,
            query_text=query_text,
            params={k: v for k, v in params.items() if v not in (None, "", [], {})},
            items=items,
            stat=SourceExecutionStat(
                source_name=source_name,
                query_count=1,
                result_count=len(items),
                success=success,
                latency_ms=latency_ms,
                error_type=None if success else "ToolCallError",
                notes=error or "sdk agent tool call",
            ),
        )
        self.calls.append(call)
        return call

    def reset(self) -> None:
        self.calls.clear()


def _digest(items: list[RawIntelItem], limit: int = 20) -> str:
    return json.dumps(
        {
            "result_count": len(items),
            "items": [
                {
                    "item_id": item.item_id,
                    "title": item.title[:140],
                    "relevance_score": round(item.relevance_score, 2),
                    "topics": item.metadata.get("topics", []),
                }
                for item in items[:limit]
            ],
        },
        ensure_ascii=False,
    )


def build_intel_sources_server(
    recorder: SourceCallRecorder,
    timeout_seconds: int = 20,
    max_results_cap: int = 20,
) -> Any:
    """Create the ``intel_sources`` SDK MCP server (lazy claude_agent_sdk import)."""
    from claude_agent_sdk import create_sdk_mcp_server, tool

    def _execute(source_name: str, query_text: str, params: dict[str, Any], fetch) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            items = fetch()
            call = recorder.record(
                source_name,
                query_text,
                params,
                items,
                success=True,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
            )
            return {"content": [{"type": "text", "text": _digest(call.items)}]}
        except Exception as exc:  # noqa: BLE001 - tool errors go back to the agent
            recorder.record(
                source_name,
                query_text,
                params,
                [],
                success=False,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
                error=f"{exc.__class__.__name__}: {exc}",
            )
            return {
                "content": [
                    {"type": "text", "text": f"source error: {exc.__class__.__name__}: {exc}"}
                ],
                "is_error": True,
            }

    @tool(
        "search_nvd",
        "Search the NVD CVE 2.0 API for vulnerabilities. Operators: keyword_search "
        "(free text over CVE descriptions; set keyword_exact_match=true for multi-word "
        "phrases like 'prompt injection'), cwe_id (e.g. CWE-502 deserialization, CWE-94 "
        "code injection, CWE-1039 adversarial ML), cvss_v3_severity (HIGH/CRITICAL), "
        "pub_start_date+pub_end_date (ISO-8601, both required together; recent windows "
        "cut noise sharply), has_kev=true (only known-exploited CVEs). Effective combos: "
        "product keyword + cwe_id (e.g. 'MLflow'+CWE-502) targets AI supply-chain bugs; "
        "keyword + has_kev surfaces actively exploited issues.",
        {
            "keyword_search": str,
            "keyword_exact_match": bool,
            "cwe_id": str,
            "cvss_v3_severity": str,
            "pub_start_date": str,
            "pub_end_date": str,
            "has_kev": bool,
            "cve_id": str,
            "max_results": int,
        },
    )
    async def search_nvd(args: dict[str, Any]) -> dict[str, Any]:
        max_results = min(int(args.get("max_results") or 20), max_results_cap)
        query_text = args.get("keyword_search") or args.get("cve_id") or ""
        return _execute(
            "nvd_cve_api",
            f"NVD:{query_text}",
            args,
            lambda: search_nvd_cve_api(
                query_text=query_text,
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                keyword_search=args.get("keyword_search") or None,
                pub_start_date=args.get("pub_start_date") or None,
                pub_end_date=args.get("pub_end_date") or None,
                has_kev=bool(args.get("has_kev")),
                cve_id=args.get("cve_id") or None,
                keyword_exact_match=bool(args.get("keyword_exact_match")),
                cwe_id=args.get("cwe_id") or None,
                cvss_v3_severity=args.get("cvss_v3_severity") or None,
            ),
        )

    @tool(
        "search_arxiv",
        "Search arXiv for security research papers. search_query supports the arXiv "
        "query language: field prefixes (all:, ti:, abs:, au:), boolean AND/OR/ANDNOT, "
        "quoted phrases, and category filters (cat:cs.CR security, cs.AI, cs.CL). "
        "Example: '(all:\"indirect prompt injection\" OR all:\"jailbreak\") AND "
        "(cat:cs.CR OR cat:cs.CL)'. Results sort by submission date descending; "
        "tight phrase + category combos beat bag-of-words queries.",
        {"search_query": str, "max_results": int},
    )
    async def search_arxiv(args: dict[str, Any]) -> dict[str, Any]:
        max_results = min(int(args.get("max_results") or 15), max_results_cap)
        search_query = str(args.get("search_query") or "")
        return _execute(
            "arxiv_api",
            f"arXiv:{search_query[:120]}",
            args,
            lambda: search_arxiv_api(
                query_text=search_query,
                target_topics=[],
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                arxiv_search_query=search_query or None,
            ),
        )

    @tool(
        "search_cisa_kev",
        "Search the CISA Known Exploited Vulnerabilities catalog (confirmed in-the-wild "
        "exploitation). keyword matches vendor/product/vulnerability-name/description "
        "tokens (e.g. 'code injection', 'Langflow'); cve_ids fetches specific CVEs. "
        "Use after NVD to check whether a vulnerability class is actively exploited.",
        {"keyword": str, "cve_ids": list, "max_results": int},
    )
    async def search_cisa_kev(args: dict[str, Any]) -> dict[str, Any]:
        max_results = min(int(args.get("max_results") or 12), max_results_cap)
        keyword = str(args.get("keyword") or "")
        cve_ids = [str(value) for value in (args.get("cve_ids") or [])]
        return _execute(
            "cisa_kev_json",
            f"CISA KEV:{keyword or ','.join(cve_ids)}",
            args,
            lambda: search_cisa_kev_json(
                query_text=keyword,
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                cve_ids=cve_ids,
                keyword=keyword or None,
            ),
        )

    @tool(
        "search_osv",
        "Query OSV.dev for open-source package vulnerabilities. OSV is package-centric: "
        "give ecosystem (PyPI, npm, Go, crates.io) + package_name (e.g. PyPI/langchain, "
        "PyPI/mlflow, npm/flowise), or purl (pkg:pypi/gradio), or a direct vuln_id "
        "(GHSA-/PYSEC-/CVE-). Optional version narrows to affected releases. Best for "
        "AI-stack supply chain: model servers, agent frameworks, vector databases.",
        {
            "ecosystem": str,
            "package_name": str,
            "version": str,
            "purl": str,
            "vuln_id": str,
            "max_results": int,
        },
    )
    async def search_osv(args: dict[str, Any]) -> dict[str, Any]:
        max_results = min(int(args.get("max_results") or 10), max_results_cap)
        label = args.get("vuln_id") or args.get("purl") or (
            f"{args.get('ecosystem', '')}/{args.get('package_name', '')}"
        )
        return _execute(
            "osv_dev_api",
            f"OSV:{label}",
            args,
            lambda: search_osv_dev_api(
                query_text=str(args.get("vuln_id") or ""),
                max_results=max_results,
                timeout_seconds=timeout_seconds,
                ecosystem=args.get("ecosystem") or None,
                package_name=args.get("package_name") or None,
                version=args.get("version") or None,
                purl=args.get("purl") or None,
                vuln_id=args.get("vuln_id") or None,
            ),
        )

    return create_sdk_mcp_server(
        name="intel_sources",
        tools=[search_nvd, search_arxiv, search_cisa_kev, search_osv],
    )
