from __future__ import annotations

import json
import os
import random
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

import httpx

from ..schemas.source import (
    QueryRunDTO,
    RegisteredSourceDTO,
    SourceFetchAuditDTO,
    SourceFetchBatchDTO,
    SourceFetchedItemDTO,
)


class RateLimitFetchError(RuntimeError):
    pass


class AuthFetchError(RuntimeError):
    pass


class TransientFetchError(RuntimeError):
    pass


class SourceFetchToolbox:
    USER_AGENT = "SAADS-WP11/0.3"

    def fetch(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        runtime_mode: str,
        timeout: float,
        cursor_state: dict[str, Any],
    ) -> SourceFetchBatchDTO:
        started = time.perf_counter()
        requested_at = datetime.now(timezone.utc).isoformat()
        request_meta = {
            "base_uri": source.base_uri,
            "runtime_mode": runtime_mode,
            "pagination_style": source.pagination_style,
            "cursor_in": cursor_state.get("cursor") if cursor_state else None,
        }
        request_plan = self._intent_aware_request_plan(source, query_run)
        request_meta["query_intent"] = query_run.query_intent
        request_meta["original_query_text"] = query_run.query_text
        request_meta["transformed_query_text"] = request_plan["query_text"]
        request_meta["request_profile"] = request_plan["request_profile"]
        request_meta["query_tokens"] = request_plan["query_tokens"]
        if runtime_mode == "stub":
            items = self._stub_items(source, query_run, request_plan=request_plan)
            return self._build_batch(
                source,
                query_run,
                items,
                started,
                used_stub=True,
                requested_at=requested_at,
                request_meta=request_meta,
            )

        try:
            items, next_cursor = self._fetch_live(
                source,
                query_run,
                timeout=timeout,
                cursor_state=cursor_state,
                request_plan=request_plan,
            )
            return self._build_batch(
                source,
                query_run,
                items,
                started,
                used_stub=False,
                next_cursor=next_cursor,
                requested_at=requested_at,
                request_meta=request_meta,
            )
        except Exception as exc:
            if runtime_mode == "hybrid":
                items = self._stub_items(source, query_run, request_plan=request_plan)
                batch = self._build_batch(
                    source,
                    query_run,
                    items,
                    started,
                    used_stub=True,
                    requested_at=requested_at,
                    request_meta=request_meta,
                )
                batch.error_type = exc.__class__.__name__
                batch.error_message = str(exc)
                batch.degraded_from_live = True
                return batch
            raise

    def _build_batch(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        items: list[SourceFetchedItemDTO],
        started: float,
        *,
        used_stub: bool,
        requested_at: str,
        request_meta: dict[str, Any],
        next_cursor: str | None = None,
    ) -> SourceFetchBatchDTO:
        fetched_at = datetime.now(timezone.utc).isoformat()
        audit = SourceFetchAuditDTO(
            query_run_id=query_run.query_run_id,
            source_name=source.source_name,
            requested_at=requested_at,
            completed_at=fetched_at,
            runtime_mode="stub" if used_stub else "live",
            attempt_count=1,
            success=True,
            degraded_from_live=False,
            request_meta=request_meta,
        ).model_dump(mode="python")
        return SourceFetchBatchDTO(
            query_run=query_run,
            items=items,
            fetched_at=fetched_at,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            attempt_count=1,
            success=True,
            used_stub=used_stub,
            next_cursor=next_cursor,
            request_audit=audit,
        )

    def _fetch_live(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        timeout: float,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        headers = {"User-Agent": self.USER_AGENT}
        auth_value = (
            os.getenv(source.auth_env_var or "", "") if source.auth_env_var else ""
        )
        if source.auth_type == "header_bearer":
            if not auth_value:
                raise AuthFetchError(
                    f"{source.auth_env_var} is required for {source.source_name}"
                )
            headers["Authorization"] = f"Bearer {auth_value}"
        elif source.auth_type == "header_api_key" and auth_value:
            headers["apiKey"] = auth_value

        with httpx.Client(
            timeout=timeout, headers=headers, follow_redirects=True
        ) as client:
            adapter = getattr(self, f"_fetch_{source.adapter_name}")
            return adapter(
                client,
                source,
                query_run,
                cursor_state=cursor_state,
                request_plan=request_plan,
            )

    def _check_response(self, response: httpx.Response) -> None:
        if response.status_code == 429:
            raise RateLimitFetchError("Rate limited by upstream source.")
        if response.status_code in {401, 403}:
            raise AuthFetchError(
                f"Authentication failed with status {response.status_code}."
            )
        if response.status_code >= 500:
            raise TransientFetchError(f"Upstream server error {response.status_code}.")
        response.raise_for_status()

    def _fetch_nvd(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        start_index = int(cursor_state.get("cursor") or 0)
        items: list[SourceFetchedItemDTO] = []
        next_cursor: str | None = None
        while len(items) < query_run.max_results:
            page_size = min(20, query_run.max_results - len(items))
            response = client.get(
                source.base_uri,
                params={
                    "keywordSearch": request_plan["query_text"],
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                },
            )
            self._check_response(response)
            payload = response.json()
            vulns = payload.get("vulnerabilities", [])
            total_results = int(payload.get("totalResults", len(vulns)))
            for entry in vulns:
                cve = entry.get("cve", {})
                description = next(
                    (
                        desc.get("value", "")
                        for desc in cve.get("descriptions", [])
                        if desc.get("lang") == "en"
                    ),
                    "",
                )
                metrics = cve.get("metrics", {})
                severity = _extract_nvd_severity(metrics)
                items.append(
                    self._item(
                        source_name=source.source_name,
                        source_uri=f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                        external_id=cve.get("id"),
                        title=cve.get("id"),
                        summary=description[:400],
                        published_at=cve.get("published"),
                        raw_format="json",
                        payload=json.dumps(entry, ensure_ascii=True),
                        metadata={
                            "query": request_plan["query_text"],
                            "query_intent": query_run.query_intent,
                            "request_profile": request_plan["request_profile"],
                            "severity": severity,
                        },
                        relevance_score=0.9,
                    )
                )
            start_index += len(vulns)
            if not vulns or start_index >= total_results:
                next_cursor = None
                break
            next_cursor = str(start_index)
        return items[: query_run.max_results], next_cursor

    def _fetch_github_advisories(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        end_cursor = cursor_state.get("cursor")
        items: list[SourceFetchedItemDTO] = []
        next_cursor: str | None = None
        while len(items) < query_run.max_results:
            first = min(20, query_run.max_results - len(items))
            graphql = {
                "query": """
                query($query: String!, $first: Int!, $after: String) {
                  securityAdvisories(first: $first, query: $query, after: $after) {
                    pageInfo { hasNextPage endCursor }
                    nodes {
                      ghsaId
                      summary
                      description
                      severity
                      publishedAt
                      references { url }
                    }
                  }
                }
                """,
                "variables": {
                    "query": request_plan["query_text"],
                    "first": first,
                    "after": end_cursor,
                },
            }
            response = client.post(source.base_uri, json=graphql)
            self._check_response(response)
            advisories = response.json().get("data", {}).get("securityAdvisories", {})
            nodes = advisories.get("nodes", [])
            page_info = advisories.get("pageInfo", {})
            for entry in nodes:
                url = (entry.get("references") or [{}])[0].get(
                    "url"
                ) or "https://github.com/advisories"
                items.append(
                    self._item(
                        source_name=source.source_name,
                        source_uri=url,
                        external_id=entry.get("ghsaId"),
                        title=entry.get("summary"),
                        summary=(
                            entry.get("description") or entry.get("summary") or ""
                        )[:400],
                        published_at=entry.get("publishedAt"),
                        raw_format="json",
                        payload=json.dumps(entry, ensure_ascii=True),
                        metadata={
                            "severity": entry.get("severity"),
                            "query_intent": query_run.query_intent,
                            "request_profile": request_plan["request_profile"],
                        },
                        relevance_score=0.95,
                    )
                )
            if not page_info.get("hasNextPage"):
                next_cursor = None
                break
            end_cursor = page_info.get("endCursor")
            next_cursor = end_cursor
        return items[: query_run.max_results], next_cursor

    def _fetch_github_discussions(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        end_cursor = cursor_state.get("cursor")
        graphql = {
            "query": """
            query($query: String!, $first: Int!, $after: String) {
              search(type: DISCUSSION, query: $query, first: $first, after: $after) {
                pageInfo { hasNextPage endCursor }
                nodes {
                  ... on Discussion {
                    id
                    title
                    bodyText
                    createdAt
                    url
                    author { login }
                  }
                }
              }
            }
            """,
            "variables": {
                "query": request_plan["query_text"],
                "first": min(20, query_run.max_results),
                "after": end_cursor,
            },
        }
        response = client.post(source.base_uri, json=graphql)
        self._check_response(response)
        search = response.json().get("data", {}).get("search", {})
        items = [
            self._item(
                source_name=source.source_name,
                source_uri=entry.get("url", "https://github.com/discussions"),
                external_id=entry.get("id"),
                title=entry.get("title"),
                summary=(entry.get("bodyText") or "")[:400],
                author=(entry.get("author") or {}).get("login"),
                published_at=entry.get("createdAt"),
                raw_format="json",
                payload=json.dumps(entry, ensure_ascii=True),
                metadata={
                    "query_intent": query_run.query_intent,
                    "request_profile": request_plan["request_profile"],
                },
                relevance_score=0.7,
            )
            for entry in search.get("nodes", [])
        ]
        page_info = search.get("pageInfo", {})
        return items, page_info.get("endCursor") if page_info.get(
            "hasNextPage"
        ) else None

    def _fetch_arxiv(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        start = int(cursor_state.get("cursor") or 0)
        response = client.get(
            source.base_uri,
            params={
                "search_query": request_plan["query_text"],
                "start": start,
                "max_results": query_run.max_results,
                "sortBy": request_plan.get("sort_by", "lastUpdatedDate"),
                "sortOrder": "descending",
            },
        )
        self._check_response(response)
        root = ET.fromstring(response.text)
        ns = {
            "a": "http://www.w3.org/2005/Atom",
            "opensearch": "http://a9.com/-/spec/opensearch/1.1/",
        }
        total_results = int(
            root.findtext("opensearch:totalResults", default="0", namespaces=ns) or 0
        )
        entries = root.findall("a:entry", ns)
        items = []
        for entry in entries:
            entry_id = entry.findtext("a:id", default="", namespaces=ns)
            summary = entry.findtext("a:summary", default="", namespaces=ns).strip()
            title = entry.findtext("a:title", default="", namespaces=ns).strip()
            author = ", ".join(
                author.findtext("a:name", default="", namespaces=ns)
                for author in entry.findall("a:author", ns)
            )
            categories = [
                cat.get("term")
                for cat in entry.findall("a:category", ns)
                if cat.get("term")
            ]
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri=entry_id,
                    external_id=entry_id.rsplit("/", 1)[-1],
                    title=title,
                    summary=summary[:400],
                    author=author,
                    published_at=entry.findtext(
                        "a:published", default=None, namespaces=ns
                    ),
                    raw_format="text",
                    payload=ET.tostring(entry, encoding="unicode"),
                    metadata={
                        "categories": categories,
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.85,
                )
            )
        next_cursor = (
            str(start + len(entries)) if start + len(entries) < total_results else None
        )
        return items, next_cursor

    def _fetch_reddit(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        subreddit = source.default_params.get("subreddit", "netsec")
        response = client.get(
            f"{source.base_uri}/r/{subreddit}/search.rss",
            params={
                "q": request_plan["query_text"],
                "restrict_sr": "on",
                "sort": request_plan.get("sort", "new"),
                "t": request_plan.get("time_filter", "week"),
            },
        )
        self._check_response(response)
        root = ET.fromstring(response.text)
        ns = {"a": "http://www.w3.org/2005/Atom"}
        items = []
        for entry in root.findall("a:entry", ns)[: query_run.max_results]:
            link = entry.findtext("a:id", default="", namespaces=ns)
            title = entry.findtext("a:title", default="", namespaces=ns)
            summary = entry.findtext("a:content", default="", namespaces=ns)
            author = entry.findtext("a:author/a:name", default="", namespaces=ns)
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri=link,
                    external_id=link.rsplit("/", 2)[-2] if link else None,
                    title=title,
                    summary=summary[:400],
                    author=author,
                    published_at=entry.findtext(
                        "a:updated", default=None, namespaces=ns
                    ),
                    raw_format="text",
                    payload=ET.tostring(entry, encoding="unicode"),
                    metadata={
                        "subreddit": subreddit,
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.65,
                )
            )
        return items, None

    def _fetch_hackernews(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        page = int(cursor_state.get("cursor") or 0)
        response = client.get(
            source.base_uri,
            params={
                "query": request_plan["query_text"],
                "tags": request_plan.get("tags", "story"),
                "hitsPerPage": min(20, query_run.max_results),
                "page": page,
            },
        )
        self._check_response(response)
        payload = response.json()
        hits = payload.get("hits", [])
        total_pages = int(payload.get("nbPages", 1))
        items = []
        for hit in hits:
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri=hit.get("url")
                    or hit.get("story_url")
                    or "https://news.ycombinator.com/",
                    external_id=hit.get("objectID"),
                    title=hit.get("title") or hit.get("story_title"),
                    summary=(
                        hit.get("story_text")
                        or hit.get("comment_text")
                        or hit.get("title")
                        or ""
                    )[:400],
                    author=hit.get("author"),
                    published_at=hit.get("created_at"),
                    raw_format="json",
                    payload=json.dumps(hit, ensure_ascii=True),
                    metadata={
                        "points": hit.get("points"),
                        "comments": hit.get("num_comments"),
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.6,
                )
            )
        next_cursor = str(page + 1) if page + 1 < total_pages and hits else None
        return items, next_cursor

    def _fetch_cisa_kev(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        response = client.get(source.base_uri)
        self._check_response(response)
        payload = response.json()
        entries = payload.get("vulnerabilities", [])
        query_tokens = [
            str(token).lower() for token in request_plan.get("query_tokens", [])
        ]
        items = []
        for entry in entries:
            haystack = json.dumps(entry, ensure_ascii=True).lower()
            if query_tokens and not any(token in haystack for token in query_tokens):
                continue
            cve_id = entry.get("cveID")
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve_id}",
                    external_id=cve_id,
                    title=entry.get("vulnerabilityName") or cve_id,
                    summary=(entry.get("shortDescription") or "")[:400],
                    published_at=entry.get("dateAdded"),
                    raw_format="json",
                    payload=json.dumps(entry, ensure_ascii=True),
                    metadata={
                        "vendorProject": entry.get("vendorProject"),
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.9,
                )
            )
            if len(items) >= query_run.max_results:
                break
        return items, None

    def _fetch_mitre_attack(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        response = client.get(source.base_uri)
        self._check_response(response)
        payload = response.json()
        query_tokens = [
            str(token).lower() for token in request_plan.get("query_tokens", [])
        ]
        items = []
        for obj in payload.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            haystack = f"{obj.get('name', '')} {obj.get('description', '')}".lower()
            if query_tokens and not any(token in haystack for token in query_tokens):
                continue
            ext_refs = obj.get("external_references", [])
            attack_id = next(
                (
                    ref.get("external_id")
                    for ref in ext_refs
                    if ref.get("source_name") == "mitre-attack"
                ),
                None,
            )
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri="https://attack.mitre.org/",
                    external_id=attack_id,
                    title=obj.get("name"),
                    summary=(obj.get("description") or "")[:400],
                    published_at=obj.get("modified"),
                    raw_format="json",
                    payload=json.dumps(obj, ensure_ascii=True),
                    metadata={
                        "attack_id": attack_id,
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.8,
                )
            )
            if len(items) >= query_run.max_results:
                break
        return items, None

    def _fetch_vendor_advisories(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        response = client.get(source.base_uri)
        self._check_response(response)
        root = ET.fromstring(response.text)
        items = []
        query_tokens = [
            str(token).lower() for token in request_plan.get("query_tokens", [])
        ]
        for item in root.findall("./channel/item")[: query_run.max_results * 3]:
            title = item.findtext("title", default="")
            description = item.findtext("description", default="")
            link = item.findtext("link", default=source.base_uri)
            haystack = f"{title} {description}".lower()
            if query_tokens and not any(token in haystack for token in query_tokens):
                continue
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri=link,
                    external_id=link,
                    title=title,
                    summary=description[:400],
                    published_at=item.findtext("pubDate", default=None),
                    raw_format="rss",
                    payload=ET.tostring(item, encoding="unicode"),
                    metadata={
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.72,
                )
            )
            if len(items) >= query_run.max_results:
                break
        return items, None

    def _fetch_huggingface(
        self,
        client: httpx.Client,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        cursor_state: dict[str, Any],
        request_plan: dict[str, Any],
    ) -> tuple[list[SourceFetchedItemDTO], str | None]:
        offset = int(cursor_state.get("cursor") or 0)
        response = client.get(
            source.base_uri,
            params={
                "search": request_plan["query_text"],
                "limit": min(20, query_run.max_results),
                "full": "true",
            },
        )
        self._check_response(response)
        entries = response.json()[offset : offset + query_run.max_results]
        items = []
        for entry in entries:
            model_id = entry.get("id") or entry.get("modelId")
            card_data = entry.get("cardData") or {}
            tags = entry.get("tags") or []
            summary = (
                json.dumps(card_data, ensure_ascii=True)[:400]
                if card_data
                else ", ".join(tags)[:400]
            )
            items.append(
                self._item(
                    source_name=source.source_name,
                    source_uri=f"https://huggingface.co/{model_id}",
                    external_id=model_id,
                    title=model_id,
                    summary=summary,
                    published_at=None,
                    raw_format="json",
                    payload=json.dumps(entry, ensure_ascii=True),
                    metadata={
                        "tags": tags,
                        "query_intent": query_run.query_intent,
                        "request_profile": request_plan["request_profile"],
                    },
                    relevance_score=0.55,
                )
            )
        next_cursor = (
            str(offset + len(entries))
            if len(entries) == query_run.max_results
            else None
        )
        return items, next_cursor

    def _stub_items(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
        *,
        request_plan: dict[str, Any],
    ) -> list[SourceFetchedItemDTO]:
        now = datetime.now(timezone.utc).isoformat()
        base_payload = {
            "source": source.source_name,
            "query": query_run.query_text,
            "transformed_query": request_plan["query_text"],
            "query_intent": query_run.query_intent,
            "request_profile": request_plan["request_profile"],
            "query_tokens": request_plan["query_tokens"],
            "published_at": now,
        }
        title_map = {
            "nvd": "Stub CVE advisory for AI component misuse",
            "github_advisories": "Stub GitHub advisory affecting LangChain-like package",
            "github_discussions": "Stub GitHub discussion on agent jailbreak",
            "arxiv": "Stub arXiv paper on prompt injection attacks",
            "reddit": "Stub Reddit discussion on jailbreak behavior",
            "hackernews": "Stub HN thread on AI system vulnerabilities",
            "cisa_kev": "Stub CISA KEV entry for AI-adjacent stack",
            "mitre_attack": "Stub ATT&CK technique update for agent misuse",
            "vendor_advisories": "Stub vendor advisory for AI framework dependency",
            "huggingface": "Stub HuggingFace model security issue",
        }
        return [
            self._item(
                source_name=source.source_name,
                source_uri=f"stub://{source.source_name}/{query_run.query_run_id}",
                external_id=f"{source.source_name}-{query_run.query_run_id[-6:]}",
                title=title_map.get(
                    source.source_name, f"Stub item from {source.source_name}"
                ),
                summary=f"Stub collection result for query '{query_run.query_text}'.",
                author="phase2_stub",
                published_at=now,
                raw_format="json",
                payload=json.dumps(base_payload, ensure_ascii=True),
                metadata={
                    "stub": True,
                    "query_intent": query_run.query_intent,
                    "request_profile": request_plan["request_profile"],
                    "transformed_query_text": request_plan["query_text"],
                },
                relevance_score=0.75,
            )
        ]

    def _intent_aware_request_plan(
        self,
        source: RegisteredSourceDTO,
        query_run: QueryRunDTO,
    ) -> dict[str, Any]:
        query_text = query_run.query_text.strip()
        tokens = _normalized_query_tokens(query_text)
        query_intent = query_run.query_intent
        source_name = source.source_name
        source_type = source.source_type

        transformed = query_text
        request_profile = "generic"
        params: dict[str, Any] = {}

        if source_name == "github_advisories":
            transformed = _github_advisory_query(query_text, query_intent, tokens)
            request_profile = "github_security_search"
        elif source_name == "github_discussions":
            transformed = _github_discussion_query(query_text, query_intent, tokens)
            request_profile = "github_discussion_search"
        elif source_name == "arxiv":
            transformed, params = _arxiv_query(query_text, query_intent, tokens)
            request_profile = "arxiv_atom_search"
        elif source_name == "reddit":
            transformed, params = _reddit_query(query_text, query_intent, tokens)
            request_profile = "reddit_rss_search"
        elif source_name == "hackernews":
            transformed, params = _hackernews_query(query_text, query_intent, tokens)
            request_profile = "hn_algolia_search"
        elif source_name in {"cisa_kev", "mitre_attack", "vendor_advisories"}:
            transformed = _token_filter_query(query_text, query_intent, tokens)
            request_profile = "local_filter_scan"
        elif source_name == "huggingface":
            transformed = _huggingface_query(query_text, query_intent, tokens)
            request_profile = "huggingface_search"
        elif source_name == "nvd":
            transformed = _nvd_query(query_text, query_intent, tokens)
            request_profile = "nvd_keyword_search"
        else:
            transformed = _generic_intent_query(
                query_text, query_intent, tokens, source_type
            )
            request_profile = "generic_source_query"

        return {
            "query_text": transformed,
            "query_tokens": _normalized_query_tokens(transformed),
            "request_profile": request_profile,
            **params,
        }

    def _item(
        self,
        *,
        source_name: str,
        source_uri: str,
        external_id: str | None,
        title: str | None,
        summary: str | None,
        raw_format: str,
        payload: str,
        author: str | None = None,
        published_at: str | None = None,
        language_code: str | None = None,
        metadata: dict[str, Any] | None = None,
        relevance_score: float | None = None,
    ) -> SourceFetchedItemDTO:
        clean_payload = payload.strip() or json.dumps(
            {"empty": True}, ensure_ascii=True
        )
        return SourceFetchedItemDTO(
            source_name=source_name,
            source_uri=source_uri,
            external_id=external_id,
            title=title,
            summary=summary,
            author=author,
            published_at=published_at,
            raw_format=raw_format,
            payload=clean_payload,
            language_code=language_code,
            relevance_score=relevance_score,
            metadata={
                **(metadata or {}),
                "payload_sha256": sha256(clean_payload.encode("utf-8")).hexdigest(),
            },
        )


def classify_fetch_error(exc: Exception) -> str:
    if isinstance(exc, RateLimitFetchError):
        return "rate_limit"
    if isinstance(exc, AuthFetchError):
        return "auth"
    if isinstance(exc, TransientFetchError):
        return "transient"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    return "fatal"


def compute_backoff_delay(base_seconds: float, attempt: int) -> float:
    jitter = random.uniform(0.0, 0.35)
    return round((base_seconds * (2 ** max(0, attempt - 1))) + jitter, 3)


def _extract_nvd_severity(metrics: dict[str, Any]) -> str | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData") or {}
            severity = data.get("baseSeverity") or rows[0].get("baseSeverity")
            return severity.lower() if isinstance(severity, str) else None
    return None


def _normalized_query_tokens(query_text: str) -> list[str]:
    return [
        token.strip().lower()
        for token in query_text.replace("|", " ").replace('"', " ").split()
        if token.strip()
    ]


def _nvd_query(query_text: str, query_intent: str, tokens: list[str]) -> str:
    if query_intent == "precision_probe":
        return f"{query_text} vulnerability exploit impacted package".strip()
    if query_intent == "component_anchor":
        return " ".join(tokens[:4])
    if query_intent == "taxonomy_anchor":
        return f"{query_text} weakness CWE CVE".strip()
    return query_text


def _github_advisory_query(
    query_text: str, query_intent: str, tokens: list[str]
) -> str:
    if query_intent == "precision_probe":
        return f"{query_text} severity:high OR severity:critical".strip()
    if query_intent == "evidence_corroboration":
        return f"{query_text} references:github OR references:cve".strip()
    if query_intent == "component_anchor":
        anchor = tokens[0] if tokens else query_text
        return f"{anchor} advisory vulnerability".strip()
    return query_text


def _github_discussion_query(
    query_text: str, query_intent: str, tokens: list[str]
) -> str:
    if query_intent == "weak_signal_probe":
        return f"{query_text} exploit OR issue OR bypass".strip()
    if query_intent == "source_specific_rewrite":
        return f"{query_text} in:title in:body".strip()
    return query_text


def _arxiv_query(
    query_text: str,
    query_intent: str,
    tokens: list[str],
) -> tuple[str, dict[str, Any]]:
    if query_intent == "taxonomy_anchor":
        return f'all:"{query_text}" OR abs:"OWASP LLM"', {"sort_by": "relevance"}
    if query_intent == "evidence_corroboration":
        return f'all:"{query_text}"', {"sort_by": "relevance"}
    if query_intent == "precision_probe":
        return f'ti:"{query_text}" OR abs:"{query_text}"', {"sort_by": "relevance"}
    return query_text, {"sort_by": "lastUpdatedDate"}


def _reddit_query(
    query_text: str,
    query_intent: str,
    tokens: list[str],
) -> tuple[str, dict[str, Any]]:
    if query_intent == "weak_signal_probe":
        return f"{query_text} OR weird OR bypass OR jailbreak".strip(), {
            "sort": "new",
            "time_filter": "week",
        }
    if query_intent == "precision_probe":
        return f'"{query_text}" exploit vulnerability', {
            "sort": "relevance",
            "time_filter": "month",
        }
    return query_text, {"sort": "new", "time_filter": "week"}


def _hackernews_query(
    query_text: str,
    query_intent: str,
    tokens: list[str],
) -> tuple[str, dict[str, Any]]:
    if query_intent == "weak_signal_probe":
        return f"{query_text} security incident".strip(), {"tags": "story"}
    if query_intent == "evidence_corroboration":
        return f"{query_text} vulnerability disclosure".strip(), {"tags": "story"}
    return query_text, {"tags": "story"}


def _token_filter_query(query_text: str, query_intent: str, tokens: list[str]) -> str:
    if query_intent == "taxonomy_anchor":
        return " ".join(tokens + ["attack", "technique"])
    if query_intent == "component_anchor":
        return " ".join(tokens[:3])
    return query_text


def _huggingface_query(query_text: str, query_intent: str, tokens: list[str]) -> str:
    if query_intent == "component_anchor":
        return " ".join(tokens[:2])
    if query_intent == "weak_signal_probe":
        return f"{query_text} security safety".strip()
    return query_text


def _generic_intent_query(
    query_text: str,
    query_intent: str,
    tokens: list[str],
    source_type: str,
) -> str:
    if query_intent == "precision_probe":
        return f"{query_text} vulnerability exploit".strip()
    if query_intent == "weak_signal_probe" or source_type == "community":
        return f"{query_text} issue bypass".strip()
    if query_intent == "taxonomy_anchor":
        return f"{query_text} attack taxonomy".strip()
    return query_text
