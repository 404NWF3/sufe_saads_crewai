from __future__ import annotations

import unittest

from sufe_saads_crewai.crew import SufeSaadsCrewai
from sufe_saads_crewai.tools import RegisteredApiSourceSearchTool, default_registered_api_sources
from sufe_saads_crewai.tools.registered_source_tools import (
    DEFAULT_OSV_PACKAGE_TARGETS,
    build_arxiv_search_query,
    build_nvd_query_params,
    build_osv_query_payload,
    parse_arxiv_items,
    parse_cisa_kev_items,
    parse_nvd_items,
    parse_osv_query_response,
)


class RegisteredSourceToolTests(unittest.TestCase):
    def test_default_registered_sources_include_requested_apis(self) -> None:
        source_names = {source.source_name for source in default_registered_api_sources()}

        self.assertEqual(
            source_names,
            {"nvd_cve_api", "arxiv_api", "cisa_kev_json", "osv_dev_api"},
        )

    def test_source_collector_has_unified_registered_api_tool(self) -> None:
        crew = SufeSaadsCrewai().crew()
        collector = next(agent for agent in crew.agents if "多源情报采集员" in agent.role)
        tool_names = {tool.name for tool in collector.tools}

        self.assertIn("registered_api_source_search", tool_names)
        self.assertNotIn("mock_registered_source_search", tool_names)
        self.assertNotIn("mock_new_source_proposal", tool_names)

    def test_nvd_query_params_support_keyword_dates_and_kev(self) -> None:
        params = build_nvd_query_params(
            query_text="LLM prompt injection",
            max_results=25,
            keyword_search="langchain",
            pub_start_date="2026-01-01T00:00:00.000",
            pub_end_date="2026-04-30T00:00:00.000",
            has_kev=True,
        )

        self.assertEqual(params["keywordSearch"], "langchain")
        self.assertEqual(params["resultsPerPage"], "25")
        self.assertEqual(params["pubStartDate"], "2026-01-01T00:00:00.000")
        self.assertEqual(params["pubEndDate"], "2026-04-30T00:00:00.000")
        self.assertIn("hasKev", params)

    def test_nvd_query_params_support_cve_id_lookup(self) -> None:
        params = build_nvd_query_params(
            query_text="Investigate CVE-2026-12345 exploitation",
            max_results=5,
        )

        self.assertEqual(params["cveId"], "CVE-2026-12345")
        self.assertNotIn("keywordSearch", params)

    def test_arxiv_query_targets_llm_security_topics(self) -> None:
        query = build_arxiv_search_query(
            query_text="RAG poisoning prompt injection",
            target_topics=["prompt injection", "RAG poisoning"],
        )

        self.assertIn('all:"prompt injection"', query)
        self.assertIn('all:"RAG poisoning"', query)
        self.assertIn("cat:cs.CR", query)

    def test_osv_payload_supports_ecosystem_package_and_purl(self) -> None:
        package_payload = build_osv_query_payload(
            ecosystem="PyPI",
            package_name="langchain",
            version="0.0.100",
        )
        purl_payload = build_osv_query_payload(purl="pkg:pypi/mlflow@0.4.0")

        self.assertEqual(
            package_payload,
            {
                "package": {"ecosystem": "PyPI", "name": "langchain"},
                "version": "0.0.100",
            },
        )
        self.assertEqual(purl_payload, {"package": {"purl": "pkg:pypi/mlflow@0.4.0"}})
        self.assertIn({"ecosystem": "PyPI", "name": "langchain"}, DEFAULT_OSV_PACKAGE_TARGETS)

    def test_source_parsers_normalize_external_results(self) -> None:
        nvd_items = parse_nvd_items(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "published": "2026-04-01T00:00:00.000",
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "Prompt injection in an LLM agent plugin leaks data.",
                                }
                            ],
                            "references": {"referenceData": [{"url": "https://example.test/cve"}]},
                        }
                    }
                ]
            }
        )
        arxiv_items = parse_arxiv_items(
            """<?xml version="1.0" encoding="UTF-8"?>
            <feed xmlns="http://www.w3.org/2005/Atom">
              <entry>
                <id>http://arxiv.org/abs/2601.00001v1</id>
                <updated>2026-01-01T00:00:00Z</updated>
                <published>2026-01-01T00:00:00Z</published>
                <title>RAG poisoning against LLM systems</title>
                <summary>Retrieval poisoning can steer model outputs.</summary>
                <author><name>Example Author</name></author>
              </entry>
            </feed>"""
        )
        cisa_items = parse_cisa_kev_items(
            data={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-9999",
                        "vendorProject": "Example",
                        "product": "AI Gateway",
                        "vulnerabilityName": "AI Gateway Data Exposure Vulnerability",
                        "shortDescription": "A gateway bug can leak sensitive model traffic.",
                        "requiredAction": "Apply mitigations.",
                        "dateAdded": "2026-04-02",
                    }
                ]
            },
            query_text="CVE-2026-9999",
            cve_ids=[],
            keyword=None,
            max_results=5,
        )
        osv_items = parse_osv_query_response(
            {
                "vulns": [
                    {
                        "id": "GHSA-1234-5678-9abc",
                        "summary": "Unsafe tool permission handling in an LLM agent package",
                        "details": "The package allows unsafe tool execution.",
                        "published": "2026-04-03T00:00:00Z",
                        "affected": [{"package": {"ecosystem": "PyPI", "name": "example-agent"}}],
                        "references": [{"url": "https://example.test/ghsa"}],
                    }
                ]
            },
            query_text="agent tool abuse",
        )

        self.assertEqual(nvd_items[0].source_name, "nvd_cve_api")
        self.assertEqual(arxiv_items[0].source_name, "arxiv_api")
        self.assertEqual(cisa_items[0].source_name, "cisa_kev_json")
        self.assertEqual(osv_items[0].source_name, "osv_dev_api")
        self.assertIn("prompt injection", nvd_items[0].metadata["topics"])
        self.assertIn("rag poisoning", arxiv_items[0].metadata["topics"])
        self.assertEqual(osv_items[0].metadata["ecosystems"], ["PyPI"])


if __name__ == "__main__":
    unittest.main()
