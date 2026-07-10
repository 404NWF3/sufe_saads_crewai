"""Source-search tools the agent calls directly inside a round.

Each registered source is a typed ``@tool`` exposing its advanced operators, so
the agent learns to combine them (this is the roadmap's "high-level search
strategy" capability). Handlers are thin wrappers over ``sources.search_source``;
they enforce the API-call budget and cross-round query dedup, apply the active
time scope (incremental mode), and record every call for playbook harvesting.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..analysis import operator_signature, source_query_key, SourceQuerySpec
from ..sources import search_source
from .context import ToolContext

_NVD_SCHEMA = {
    "type": "object",
    "properties": {
        "query_text": {"type": "string", "description": "Free-text mission query / keywordSearch."},
        "nvd_cwe_id": {"type": "string", "description": "CWE filter, e.g. CWE-94, CWE-502."},
        "nvd_cvss_v3_severity": {"type": "string", "description": "HIGH or CRITICAL."},
        "nvd_pub_start_date": {"type": "string", "description": "ISO-8601 ext, e.g. 2026-07-01T00:00:00.000"},
        "nvd_pub_end_date": {"type": "string", "description": "ISO-8601 ext; pair with start."},
        "nvd_has_kev": {"type": "boolean", "description": "Only CVEs in the CISA KEV catalog."},
        "nvd_keyword_exact_match": {"type": "boolean", "description": "Phrase match for multi-word keywords."},
        "nvd_cve_id": {"type": "string", "description": "Direct CVE lookup."},
    },
    "required": ["query_text"],
}

_ARXIV_SCHEMA = {
    "type": "object",
    "properties": {
        "query_text": {"type": "string", "description": "Mission query (used if no arxiv_search_query)."},
        "arxiv_search_query": {
            "type": "string",
            "description": 'arXiv query language: all:/ti:/abs:, AND/OR, quoted phrases, cat:cs.CR. '
            'E.g. (all:"prompt injection") AND (cat:cs.CR)',
        },
    },
    "required": ["query_text"],
}

_CISA_SCHEMA = {
    "type": "object",
    "properties": {
        "query_text": {"type": "string", "description": "Keyword to match against KEV entries."},
        "cisa_keyword": {"type": "string", "description": "Explicit keyword override."},
        "cisa_cve_ids": {"type": "array", "items": {"type": "string"}, "description": "Specific CVE IDs."},
    },
    "required": ["query_text"],
}

_OSV_SCHEMA = {
    "type": "object",
    "properties": {
        "query_text": {"type": "string", "description": "Mission query / identifier."},
        "osv_ecosystem": {"type": "string", "description": "e.g. PyPI, npm, Go."},
        "osv_package_name": {"type": "string", "description": "Package to query (pair with ecosystem)."},
        "osv_purl": {"type": "string", "description": "Package URL."},
        "osv_vuln_id": {"type": "string", "description": "OSV/GHSA/PYSEC/CVE id for direct lookup."},
    },
    "required": ["query_text"],
}

_PARAM_KEYS: dict[str, tuple[str, ...]] = {
    "nvd_cve_api": (
        "nvd_cwe_id", "nvd_cvss_v3_severity", "nvd_pub_start_date", "nvd_pub_end_date",
        "nvd_has_kev", "nvd_keyword_exact_match", "nvd_cve_id",
    ),
    "arxiv_api": ("arxiv_search_query",),
    "cisa_kev_json": ("cisa_keyword", "cisa_cve_ids"),
    "osv_dev_api": ("osv_ecosystem", "osv_package_name", "osv_purl", "osv_vuln_id"),
}


def _apply_time_scope(source_name: str, params: dict[str, Any], ctx: ToolContext) -> None:
    """Inject native date operators for sources that support them (incremental mode)."""
    if ctx.since is None:
        return
    until = ctx.until
    if source_name == "nvd_cve_api" and "nvd_pub_start_date" not in params:
        params["nvd_pub_start_date"] = ctx.since.strftime("%Y-%m-%dT%H:%M:%S.000")
        end = until if until is not None else datetime.now(timezone.utc)
        params["nvd_pub_end_date"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    elif source_name == "arxiv_api":
        existing = params.get("arxiv_search_query") or ""
        if "submittedDate" not in existing:
            frm = ctx.since.strftime("%Y%m%d%H%M")
            to = until.strftime("%Y%m%d%H%M") if until is not None else ctx.since.strftime("%Y%m%d") + "2359"
            window = f"submittedDate:[{frm} TO {to}]"
            params["arxiv_search_query"] = f"({existing}) AND {window}" if existing else window


def _run_call(ctx: ToolContext, source_name: str, args: dict[str, Any]) -> dict[str, Any]:
    query_text = str(args.get("query_text") or "").strip()
    params = {
        key: args[key]
        for key in _PARAM_KEYS[source_name]
        if key in args and args[key] not in (None, "", [], {})
    }
    _apply_time_scope(source_name, params, ctx)

    spec = SourceQuerySpec(
        source_name=source_name, query_text=query_text, target_topics=ctx.target_topics,
        max_results=ctx.max_results_per_call, strategy_name="agent", params=params,
    )
    key = source_query_key(spec)
    if key in ctx.executed_keys:
        return _text(f"Skipped: this exact {source_name} query already ran. Vary the operators or query text.")
    if not ctx.budget_remaining():
        return _text("Skipped: API-call budget exhausted for this run. Call submit_round_summary.")

    items, stat = search_source(
        source_name, query_text or " ".join(ctx.target_topics[:3]),
        target_topics=ctx.target_topics, max_results=ctx.max_results_per_call, **params,
    )
    ctx.executed_keys.add(key)
    ctx.api_calls_used += 1
    ctx.stats.append(stat)

    new_ids: list[str] = []
    kept = 0
    for item in items:
        if not ctx.in_time_scope(item):
            continue
        kept += 1
        if item.item_id in ctx.existing_item_ids or item.item_id in ctx.collected_items:
            continue
        item.metadata["collection_strategy"] = "agent"
        item.metadata["source_query"] = query_text
        item.metadata["source_query_params"] = params
        ctx.collected_items[item.item_id] = item
        new_ids.append(item.item_id)

    ctx.executed_calls.append(
        {
            "source_name": source_name,
            "query_text": query_text,
            "params": params,
            "new_item_ids": new_ids,
            "signature": operator_signature(source_name, params),
        }
    )
    if not stat.success:
        return _text(f"{source_name} error: {stat.error_type}. Try a different source or operators.")
    titles = "; ".join(item.title[:70] for item in list(ctx.collected_items.values())[-3:])
    return _text(
        f"{source_name}: fetched {kept} in-scope, {len(new_ids)} new. "
        f"operators={_fmt(params)}. Newest: {titles or '(none)'}"
    )


def build_source_tools(ctx: ToolContext) -> list[Any]:
    from claude_agent_sdk import tool

    @tool("search_nvd", "Search the NVD CVE API 2.0 for LLM/AI-related CVEs. "
          "Combine keyword_text with nvd_cwe_id / nvd_cvss_v3_severity / date window / nvd_has_kev "
          "to cut noise (e.g. CWE-502 unsafe deserialization, CWE-94 code injection).", _NVD_SCHEMA)
    async def search_nvd(args: dict[str, Any]) -> dict[str, Any]:
        return _run_call(ctx, "nvd_cve_api", args)

    @tool("search_arxiv", "Search arXiv for LLM-security papers. Prefer arxiv_search_query with the "
          "arXiv query language (field prefixes, AND/OR, quoted phrases, cat:cs.CR) for precision.",
          _ARXIV_SCHEMA)
    async def search_arxiv(args: dict[str, Any]) -> dict[str, Any]:
        return _run_call(ctx, "arxiv_api", args)

    @tool("search_cisa_kev", "Search the CISA Known Exploited Vulnerabilities catalog by keyword or "
          "specific CVE IDs. Best for confirming real-world exploited AI-stack CVEs.", _CISA_SCHEMA)
    async def search_cisa_kev(args: dict[str, Any]) -> dict[str, Any]:
        return _run_call(ctx, "cisa_kev_json", args)

    @tool("search_osv", "Search OSV.dev for open-source ecosystem advisories. Use osv_ecosystem + "
          "osv_package_name (e.g. PyPI/mlflow) or osv_vuln_id for direct lookup.", _OSV_SCHEMA)
    async def search_osv(args: dict[str, Any]) -> dict[str, Any]:
        return _run_call(ctx, "osv_dev_api", args)

    return [search_nvd, search_arxiv, search_cisa_kev, search_osv]


def _fmt(params: dict[str, Any]) -> str:
    return json.dumps(params, ensure_ascii=False) if params else "base"


def _text(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}]}
