"""Filter CISA KEV for ML/LLM/AI-relevant entries — word‑boundary aware.

Run: .venv/Scripts/python.exe scripts/filter_cisa_kev_ml.py
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any

# ---------------------------------------------------------------------------
# Topic definitions — two layers:
#   1) EXACT vendor/product patterns (checked against vendorProject + product only)
#   2) Description/keyword patterns (checked against full text with \b boundaries)
# ---------------------------------------------------------------------------

# Layer 1: exact product/vendor identities (case-insensitive)
EXACT_PRODUCTS: dict[str, list[str]] = {
    "LLM Framework": [
        r"\blangchain\b", r"\bllama.?index\b", r"\bllamaindex\b",
        r"\bhugging\s*face\b", r"\bhuggingface\b",
        r"\btransformers\b", r"\bvllm\b", r"\bollama\b",
        r"\bllama\.?cpp\b", r"\blangflow\b",
        r"\bdify\b", r"\bflowise\b", r"\bopen.?webui\b",
        r"\banythingllm\b", r"\banything\s*llm\b",
        r"\bgradio\b", r"\bcrewai\b", r"\bautogen\b",
        r"\btext-generation-webui\b", r"\blocalai\b",
        r"\blitellm\b",
    ],
    "ML Framework": [
        r"\bpytorch\b", r"\btensorflow\b", r"\bjax\b",
        r"\bkeras\b", r"\bscikit-learn\b", r"\bscikit_learn\b",
        r"\bonnx\b", r"\bnvidia triton\b", r"\btriton inference server\b",
        r"\bkubeflow\b", r"\btorchserve\b",
        r"\bmlflow\b", r"\bseldon\b",
        r"\bnvidia cuda\b", r"\bcuda toolkit\b", r"\bcudnn\b",
        r"\bxgboost\b", r"\blightgbm\b",
    ],
    "Vector Database": [
        r"\bpinecone\b", r"\bchromadb\b", r"\bchroma\b",
        r"\bweaviate\b", r"\bqdrant\b", r"\bmilvus\b",
        r"\bpgvector\b", r"\bpg_vector\b",
        r"\bvespa\b", r"\bfaiss\b",
    ],
    "ML Infrastructure": [
        r"\bjupyter\b", r"\bjupyterhub\b", r"\bjupyterlab\b",
        r"\bray\b", r"\bdatabricks\b",
        r"\bsagemaker\b", r"\bvertex\s*ai\b",
        r"\bmlflow\b",
        r"\bapache airflow\b",
        r"\bdagster\b", r"\bprefect\b",
    ],
}

# Layer 2: attack / technique patterns (checked against full text)
ATTACK_PATTERNS: dict[str, list[str]] = {
    "Deserialization": [
        r"\bdeserialization\b",
        r"\bpickle\b", r"\bunpickle\b",
        r"\bserialization\b",
        r"\bjoblib\b", r"\bdill\b",
        r"\bsafetensors\b", r"\bgguf\b",
        r"\bmodel loading\b", r"\bmodel file\b",
    ],
    "Supply Chain": [
        r"\bdependency confusion\b",
        r"\btyposquatt",
        r"\bpackage confusion\b",
        r"\bsoftware supply chain\b",
        r"\bsupply chain compromis",
        r"\bprotestware\b",
    ],
    "Container/GPU Escape": [
        r"\bcontainer escape\b", r"\bcontainer breakout\b",
        r"\bsandbox escape\b", r"\bsandbox bypass\b",
        r"\bgpu driver\b", r"\bcuda driver\b",
        r"\bvm escape\b", r"\bvirtual machine escape\b",
        r"\bhypervisor escape\b",
    ],
    "Code/Command Injection": [
        r"\bcode injection\b", r"\bcommand injection\b",
        r"\bremote code execution\b",
        r"\barbitrary code\b",
        r"\bos command\b",
    ],
    "Data Exposure": [
        r"\binformation disclosure\b",
        r"\bdata leak", r"\bdata exposure\b",
        r"\bsensitive information\b",
        r"\bcredential leak", r"\bcredential exposure\b",
    ],
}

# CWEs that are ML-relevant even without text match
ML_CWE_SET = {
    "CWE-502",   # Deserialization
    "CWE-94",    # Code Injection
    "CWE-78",    # OS Command Injection
    "CWE-915",   # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "CWE-1321",  # Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
    "CWE-1039",  # Automated Recognition Mechanism with Inadequate Detection/Notification
    "CWE-20",    # Improper Input Validation
    "CWE-200",   # Exposure of Sensitive Information
    "CWE-89",    # SQL Injection
}

def build_text(entry: dict[str, Any]) -> str:
    parts = [
        str(entry.get("cveID", "")),
        str(entry.get("vendorProject", "")),
        str(entry.get("product", "")),
        str(entry.get("vulnerabilityName", "")),
        str(entry.get("shortDescription", "")),
        str(entry.get("requiredAction", "")),
        str(entry.get("notes", "")),
    ]
    return " ".join(parts)

def build_vendor_product_text(entry: dict[str, Any]) -> str:
    """Only vendor + product fields for exact product matching."""
    return f"{entry.get('vendorProject', '')} {entry.get('product', '')}"

def match_regex_list(text: str, patterns: list[str]) -> list[str]:
    """Return patterns that match in text (case-insensitive, word-boundary)."""
    matched: list[str] = []
    lower = text.lower()
    for pat in patterns:
        if re.search(pat, lower, re.IGNORECASE):
            # Store a clean version of the pattern for display
            clean = pat.replace("\\b", "").replace("\\s*", " ").replace("\\.?", ".")
            matched.append(clean)
    return matched

def compute_relevance(
    entry: dict[str, Any],
    exact_topics: dict[str, list[str]],
    attack_topics: dict[str, list[str]],
    vuln_name: str,
    full_text: str,
    is_recent: bool,
) -> float:
    """0-1 relevance. Exact product matches score much higher."""
    score = 0.0
    has_exact = len(exact_topics) > 0
    has_attack = len(attack_topics) > 0
    num_topics = len(exact_topics) + len(attack_topics)

    # Exact product match: strong signal
    if has_exact:
        score = 0.65
        # Extra for matching the primary ML tooling tier
        primary = {"LLM Framework", "ML Framework", "Vector Database"}
        if any(t in primary for t in exact_topics):
            score = 0.78
        # Two+ exact categories -> very high
        if len(exact_topics) >= 2:
            score = 0.90

    # Attack pattern in product context
    if has_exact and has_attack:
        score = max(score, 0.85)
        if "Deserialization" in attack_topics:
            score = max(score, 0.90)
        if "Code/Command Injection" in attack_topics:
            score = max(score, 0.88)

    # Standalone attack patterns are lower confidence (not obviously ML, but relevant)
    if not has_exact and has_attack:
        score = 0.50

    # CWE bonuses
    cwes = set(entry.get("cwes", []))
    cwe_bonus = len(cwes & ML_CWE_SET) * 0.05
    score = min(1.0, score + cwe_bonus)

    # Recent bonus
    if is_recent:
        score = min(1.0, score + 0.03)

    # Ransomware known use
    if entry.get("knownRansomwareCampaignUse") and entry["knownRansomwareCampaignUse"] != "Unknown":
        score = min(1.0, score + 0.02)

    return round(score, 2)

def main() -> None:
    vulns = load_kev("E:/@4C-2026/sufe_saads_crewai/scripts/cisa_kev_full.json")
    now = datetime.now(timezone.utc)
    cutoff_90d = (now - timedelta(days=90)).strftime("%Y-%m-%d")

    results: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    for entry in vulns:
        cve_id = str(entry.get("cveID", ""))
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        vp_text = build_vendor_product_text(entry)
        full_text = build_text(entry)
        vuln_name = str(entry.get("vulnerabilityName", ""))
        date_added = str(entry.get("dateAdded", ""))
        is_recent = date_added >= cutoff_90d

        # Layer 1: exact product matches
        exact_topics: dict[str, list[str]] = {}
        # Check vendor+product first (strongest signal)
        for topic, patterns in EXACT_PRODUCTS.items():
            matched = match_regex_list(vp_text, patterns)
            if not matched:
                # Also check vulnerability name (e.g. "Langflow Code Injection")
                matched = match_regex_list(vuln_name, patterns)
            if not matched:
                # Broader check on full text for product names that are less ambiguous
                if topic in ("LLM Framework", "ML Framework", "Vector Database"):
                    matched = match_regex_list(full_text, patterns)
            if matched:
                exact_topics[topic] = matched

        # Layer 2: attack pattern matches in full text
        attack_topics: dict[str, list[str]] = {}
        for topic, patterns in ATTACK_PATTERNS.items():
            matched = match_regex_list(full_text, patterns)
            if matched:
                attack_topics[topic] = matched

        # Must have at least one match
        if not exact_topics and not attack_topics:
            continue

        relevance = compute_relevance(entry, exact_topics, attack_topics, vuln_name, full_text, is_recent)

        # Only include if relevance >= 0.50, OR it's an exact product match at any score
        if relevance < 0.50 and not exact_topics:
            continue

        # For attack-only matches without exact product, require relevance >= 0.55
        if not exact_topics and relevance < 0.55:
            continue

        all_topics = {**exact_topics, **attack_topics}
        results.append({
            "cve_id": cve_id,
            "vendor_project": str(entry.get("vendorProject", "")),
            "product": str(entry.get("product", "")),
            "vulnerability_name": vuln_name,
            "date_added": date_added,
            "short_description": str(entry.get("shortDescription", ""))[:300],
            "exact_matches": {k: v for k, v in exact_topics.items()},
            "attack_matches": {k: v for k, v in attack_topics.items()},
            "all_topics": list(all_topics.keys()),
            "num_exact": len(exact_topics),
            "num_attack": len(attack_topics),
            "relevance": relevance,
            "is_recent_90d": is_recent,
            "cwes": entry.get("cwes", []),
            "ransomware": str(entry.get("knownRansomwareCampaignUse", "")),
        })

    # Sort: exact matches first, then by relevance, then date
    results.sort(key=lambda r: (
        1 if r["num_exact"] > 0 else 0,
        r["relevance"],
        r["date_added"]
    ), reverse=True)

    # ---------- Print report ----------
    print(f"{'='*70}")
    print(f"  CISA KEV ML/LLM/AI Filter Report  |  {now.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*70}")
    print(f"  Total KEV entries: {len(vulns)}")
    print(f"  Recent (90d, since {cutoff_90d}): 77")
    print(f"  ML/LLM-relevant after filtering: {len(results)}")
    print()

    tier1 = [r for r in results if r["num_exact"] > 0]
    tier2 = [r for r in results if r["num_exact"] == 0]
    print(f"  Tier 1 (exact product match): {len(tier1)}")
    print(f"  Tier 2 (attack pattern only):  {len(tier2)}")
    print()

    # Tier 1 first
    for label, tier in [("EXACT PRODUCT MATCHES", tier1), ("ATTACK PATTERN MATCHES (no product hit)", tier2)]:
        if not tier:
            continue
        print(f"{'─'*70}")
        print(f"  {label} ({len(tier)} entries)")
        print(f"{'─'*70}")
        for r in tier:
            recent_tag = " [90d]" if r["is_recent_90d"] else ""
            rw_tag = " [RANSOMWARE]" if r["ransomware"] and r["ransomware"] != "Unknown" else ""
            exact_str = ", ".join(r["exact_matches"].keys()) if r["exact_matches"] else "—"
            attack_str = ", ".join(r["attack_matches"].keys()) if r["attack_matches"] else "—"
            print(f"  {r['cve_id']}  |  rel={r['relevance']:.2f}{recent_tag}{rw_tag}")
            print(f"    Vendor: {r['vendor_project']}  |  Product: {r['product']}")
            print(f"    Vuln:   {r['vulnerability_name']}")
            print(f"    Date:   {r['date_added']}  |  CWEs: {', '.join(r['cwes']) if r['cwes'] else 'N/A'}")
            print(f"    Exact:  {exact_str}")
            print(f"    Attack: {attack_str}")
            if r["exact_matches"]:
                for t, terms in r["exact_matches"].items():
                    print(f"      {t}: {', '.join(terms)}")
            if r["attack_matches"]:
                for t, terms in r["attack_matches"].items():
                    print(f"      {t}: {', '.join(terms)}")
            print(f"    Desc:   {r['short_description'][:200]}")
            print()

    # Summary
    print(f"{'='*70}")
    print(f"  Summary by Topic")
    print(f"{'='*70}")
    topic_counts: dict[str, int] = {}
    for r in results:
        for topic in r["all_topics"]:
            topic_counts[topic] = topic_counts.get(topic, 0) + 1
    for topic, count in sorted(topic_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {topic:30s} {count:3d}")

    # Save JSON
    out_path = "E:/@4C-2026/sufe_saads_crewai/scripts/cisa_kev_ml_filtered.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": now.isoformat(),
            "total_kev_entries": len(vulns),
            "filtered_count": len(results),
            "tier1_exact_product": len(tier1),
            "tier2_attack_pattern": len(tier2),
            "results": results,
        }, f, ensure_ascii=False, indent=2)
    print(f"\n  Full results saved to: {out_path}")

def load_kev(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("vulnerabilities", [])

if __name__ == "__main__":
    main()
