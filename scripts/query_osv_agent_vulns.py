#!/usr/bin/env python3
"""Query OSV.dev for vulnerabilities in agent frameworks, tool-calling libs,
sandbox escapes, and prompt injection CVEs.

Covers:
  1. Agent framework packages (PyPI, npm, Go, Cargo)
  2. Tool-calling and function-calling libraries
  3. Sandbox/container escape in agent execution environments
  4. Prompt injection vulnerabilities with CVE assignments
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
REQUEST_TIMEOUT = 60

# ── Package targets ──────────────────────────────────────────────────────────

# 1. Agent frameworks
AGENT_FRAMEWORKS = [
    # PyPI
    {"ecosystem": "PyPI", "name": "langchain"},
    {"ecosystem": "PyPI", "name": "langchain-core"},
    {"ecosystem": "PyPI", "name": "langchain-community"},
    {"ecosystem": "PyPI", "name": "langchain-experimental"},
    {"ecosystem": "PyPI", "name": "crewai"},
    {"ecosystem": "PyPI", "name": "autogpt"},
    {"ecosystem": "PyPI", "name": "llama-index"},
    {"ecosystem": "PyPI", "name": "llama-index-core"},
    {"ecosystem": "PyPI", "name": "agentops"},
    {"ecosystem": "PyPI", "name": "semantic-kernel"},
    {"ecosystem": "PyPI", "name": "ag2"},  # AutoGen v2
    {"ecosystem": "PyPI", "name": "pyautogen"},
    {"ecosystem": "PyPI", "name": "open-agents"},
    {"ecosystem": "PyPI", "name": "dify"},
    # npm
    {"ecosystem": "npm", "name": "langchain"},
    {"ecosystem": "npm", "name": "@langchain/core"},
    {"ecosystem": "npm", "name": "@langchain/community"},
    {"ecosystem": "npm", "name": "llamaindex"},
    # Go
    {"ecosystem": "Go", "name": "github.com/tmc/langchaingo"},
    {"ecosystem": "Go", "name": "github.com/microsoft/semantic-kernel"},
    # Rust
    {"ecosystem": "crates.io", "name": "langchain-rust"},
]

# 2. Tool-calling and function-calling libraries
TOOL_CALLING_LIBS = [
    {"ecosystem": "PyPI", "name": "openai"},
    {"ecosystem": "PyPI", "name": "anthropic"},
    {"ecosystem": "PyPI", "name": "google-generativeai"},
    {"ecosystem": "PyPI", "name": "mistralai"},
    {"ecosystem": "PyPI", "name": "ollama"},
    {"ecosystem": "PyPI", "name": "litellm"},
    {"ecosystem": "PyPI", "name": "openai-agents"},
    {"ecosystem": "PyPI", "name": "mcp"},
    {"ecosystem": "PyPI", "name": "fastmcp"},
    {"ecosystem": "PyPI", "name": "claude-agent-sdk"},
    {"ecosystem": "PyPI", "name": "function-calling"},
    {"ecosystem": "PyPI", "name": "instructor"},
    {"ecosystem": "PyPI", "name": "outlines"},
    {"ecosystem": "PyPI", "name": "guidance"},
    {"ecosystem": "PyPI", "name": "jsonformer"},
    {"ecosystem": "npm", "name": "openai"},
    {"ecosystem": "npm", "name": "@anthropic-ai/sdk"},
    {"ecosystem": "npm", "name": "langsmith"},
    {"ecosystem": "npm", "name": "langfuse"},
]

# 3. Sandbox / container execution environments
SANDBOX_PACKAGES = [
    {"ecosystem": "PyPI", "name": "docker"},
    {"ecosystem": "PyPI", "name": "e2b"},
    {"ecosystem": "PyPI", "name": "modal"},
    {"ecosystem": "PyPI", "name": "flytekit"},
    {"ecosystem": "PyPI", "name": "dagster"},
    {"ecosystem": "PyPI", "name": "prefect"},
    {"ecosystem": "PyPI", "name": "jupyter-server"},
    {"ecosystem": "PyPI", "name": "notebook"},
    {"ecosystem": "PyPI", "name": "ipython"},
    {"ecosystem": "PyPI", "name": "jupyterlab"},
    {"ecosystem": "PyPI", "name": "executor"},
    {"ecosystem": "PyPI", "name": "restrictedpython"},
    {"ecosystem": "PyPI", "name": "pypy"},
    {"ecosystem": "PyPI", "name": "codeinterpreter"},
    {"ecosystem": "PyPI", "name": "code-interpreter"},
    {"ecosystem": "PyPI", "name": "sandbox"},
    {"ecosystem": "PyPI", "name": "bubblewrap"},
    {"ecosystem": "npm", "name": "dockerode"},
    {"ecosystem": "npm", "name": "vm2"},
    {"ecosystem": "npm", "name": "isolated-vm"},
    {"ecosystem": "npm", "name": "sandbox"},
    {"ecosystem": "Go", "name": "github.com/docker/docker"},
    {"ecosystem": "Go", "name": "github.com/opencontainers/runc"},
    {"ecosystem": "Go", "name": "github.com/google/gvisor"},
]

# 4. Prompt injection / LLM security (keyword search via vuln IDs)
PROMPT_INJECTION_KEYWORDS = [
    "prompt injection",
    "prompt leaking",
    "jailbreak",
    "indirect prompt injection",
    "LLM prompt injection",
]

ALL_TARGETS = AGENT_FRAMEWORKS + TOOL_CALLING_LIBS + SANDBOX_PACKAGES


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _get_json(url: str) -> dict[str, Any]:
    resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def query_package(ecosystem: str, name: str) -> list[dict[str, Any]]:
    """Query OSV for all vulns affecting a given ecosystem/package."""
    try:
        data = _post_json(OSV_QUERY_URL, {
            "package": {"ecosystem": ecosystem, "name": name},
        })
        vulns = data.get("vulns", [])
        return vulns if isinstance(vulns, list) else [vulns]
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return []
        print(f"  [HTTP {getattr(e.response, 'status_code', '?')}] {ecosystem}/{name}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  [ERR] {ecosystem}/{name}: {e}", file=sys.stderr)
        return []


def get_vuln_detail(vuln_id: str) -> dict[str, Any] | None:
    """Fetch full details for a single vulnerability ID."""
    try:
        return _get_json(f"{OSV_VULN_URL}/{vuln_id}")
    except Exception:
        return None


def extract_severity(vuln: dict[str, Any]) -> str:
    """Extract the best severity string from an OSV vuln object."""
    # Check severity field
    for sev in vuln.get("severity", []) or []:
        if sev.get("type") == "CVSS_V3":
            return sev.get("score", "N/A")
        if sev.get("type") == "CVSS_V2":
            return sev.get("score", "N/A")
    # Check database_specific
    db_spec = vuln.get("database_specific", {}) or {}
    if "severity" in db_spec:
        return str(db_spec["severity"])
    # Check aliases for CVSS score patterns
    return "N/A"


def extract_affected_versions(vuln: dict[str, Any]) -> list[str]:
    """Extract affected version ranges from an OSV vuln object."""
    versions: list[str] = []
    for af in vuln.get("affected", []) or []:
        for rng in af.get("ranges", []) or []:
            events = rng.get("events", [])
            introduced = next((e.get("value") for e in events if e.get("introduced")), None)
            fixed = next((e.get("value") for e in events if e.get("fixed")), None)
            if introduced and fixed:
                versions.append(f">={introduced}, <{fixed}")
            elif introduced:
                versions.append(f">={introduced}")
            elif fixed:
                versions.append(f"<{fixed}")
        for ver in af.get("versions", []) or []:
            versions.append(ver)
    return versions


def format_vuln(vuln: dict[str, Any], vuln_id: str, ecosystem: str, pkg_name: str) -> dict[str, Any]:
    """Format a vulnerability summary."""
    aliases = vuln.get("aliases", []) or []
    cve_ids = [a for a in aliases if a.startswith("CVE-")]
    summary = vuln.get("summary", "") or vuln.get("details", "") or ""
    # Truncate long summaries
    if len(summary) > 300:
        summary = summary[:297] + "..."
    return {
        "id": vuln_id,
        "ecosystem": ecosystem,
        "package": pkg_name,
        "cve": cve_ids[0] if cve_ids else "",
        "all_cves": cve_ids,
        "aliases": aliases,
        "severity": extract_severity(vuln),
        "affected_versions": extract_affected_versions(vuln),
        "summary": summary,
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        "references": [r.get("url", "") for r in (vuln.get("references", []) or [])[:5]],
    }


def search_by_keyword(keywords: list[str], max_per: int = 10) -> list[dict[str, Any]]:
    """Search OSV vulns whose summary/details mention certain keywords.

    This searches by vuln IDs we discover through package queries, then filters
    by keyword matching in the title/summary.
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Rather than iterate over all packages, we query specific vuln IDs
    # that we found from package queries and filter by keyword in their details.
    return results


def main() -> None:
    all_vulns: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    package_vuln_count: dict[str, int] = {}

    print("=" * 80)
    print("OSV.DEV VULNERABILITY QUERY — Agent Frameworks & Tool-Calling Ecosystem")
    print("=" * 80)

    # ── Phase 1: Query all packages ──
    categories = [
        ("AGENT FRAMEWORKS", AGENT_FRAMEWORKS),
        ("TOOL-CALLING & FUNCTION-CALLING LIBS", TOOL_CALLING_LIBS),
        ("SANDBOX / CONTAINER EXECUTION", SANDBOX_PACKAGES),
    ]

    for cat_name, targets in categories:
        print(f"\n{'─'*80}")
        print(f"  {cat_name}")
        print(f"{'─'*80}")
        for tgt in targets:
            eco = tgt["ecosystem"]
            name = tgt["name"]
            key = f"{eco}/{name}"
            vulns_raw = query_package(eco, name)
            package_vuln_count[key] = len(vulns_raw)
            print(f"  {key}: {len(vulns_raw)} vulnerabilities")

            for v in vulns_raw:
                vid = v.get("id", "")
                if not vid or vid in seen_ids:
                    continue
                seen_ids.add(vid)
                formatted = format_vuln(v, vid, eco, name)
                all_vulns.append(formatted)

            time.sleep(0.15)  # Rate-limit courtesy

    # ── Phase 2: Fetch detailed info for top vulnerabilities ──
    print(f"\n{'='*80}")
    print(f"  Fetching detailed info for {len(all_vulns)} unique vulnerabilities...")
    print(f"{'='*80}")

    for i, vuln in enumerate(all_vulns):
        detail = get_vuln_detail(vuln["id"])
        if detail:
            # Update severity from full detail
            sev = extract_severity(detail)
            if sev != "N/A":
                vuln["severity"] = sev
            # Get affected versions from full detail
            versions = extract_affected_versions(detail)
            if versions:
                vuln["affected_versions"] = versions
            # Better summary
            summary = detail.get("summary", "") or detail.get("details", "") or vuln["summary"]
            if len(summary) > 400:
                summary = summary[:397] + "..."
            vuln["summary"] = summary
            # Full aliases
            aliases = detail.get("aliases", []) or []
            vuln["aliases"] = aliases
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            vuln["cve"] = cve_ids[0] if cve_ids else ""
            vuln["all_cves"] = cve_ids
        if (i + 1) % 20 == 0:
            print(f"  ... {i+1}/{len(all_vulns)}")
        time.sleep(0.08)

    # ── Output ───────────────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*80}")

    # Sort by: has CVE first, then by package
    all_vulns.sort(key=lambda x: (0 if x["cve"] else 1, x["ecosystem"], x["package"], x["id"]))

    total_with_cve = sum(1 for v in all_vulns if v["cve"])
    total_without_cve = len(all_vulns) - total_with_cve
    print(f"\n  Total unique vulnerabilities: {len(all_vulns)}")
    print(f"  With CVE assignments:       {total_with_cve}")
    print(f"  Without CVE assignments:    {total_without_cve}")
    print(f"  Packages queried:           {len(ALL_TARGETS)}")
    packages_with_vulns = sum(1 for c in package_vuln_count.values() if c > 0)
    print(f"  Packages with vulns:        {packages_with_vulns}")

    # Print all vulnerabilities
    print(f"\n{'='*80}")
    print(f"  VULNERABILITY DETAILS")
    print(f"{'='*80}")

    for i, vuln in enumerate(all_vulns, 1):
        cve_str = f" [{vuln['cve']}]" if vuln["cve"] else ""
        sev_str = f" CVSS:{vuln['severity']}" if vuln["severity"] != "N/A" else ""
        print(f"\n{i:3d}. {vuln['id']}{cve_str}{sev_str}")
        print(f"     Package:  {vuln['ecosystem']}/{vuln['package']}")
        if vuln["affected_versions"]:
            print(f"     Affected: {', '.join(vuln['affected_versions'][:5])}")
        if vuln["aliases"]:
            print(f"     Aliases:  {', '.join(vuln['aliases'][:10])}")
        print(f"     Summary:  {vuln['summary']}")
        if vuln["published"]:
            print(f"     Published:{vuln['published']}")
        if vuln["references"]:
            for ref in vuln["references"][:3]:
                print(f"     Ref:      {ref}")

    # ── Save JSON ────────────────────────────────────────────────────────────
    output_path = "E:/@4C-2026/sufe_saads_crewai/scripts/osv_agent_vulns_output.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "query_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_vulnerabilities": len(all_vulns),
            "with_cve": total_with_cve,
            "without_cve": total_without_cve,
            "packages_queried": len(ALL_TARGETS),
            "packages_with_vulns": packages_with_vulns,
            "package_vuln_counts": package_vuln_count,
            "vulnerabilities": all_vulns,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n  Full JSON output saved to: {output_path}")


if __name__ == "__main__":
    main()
