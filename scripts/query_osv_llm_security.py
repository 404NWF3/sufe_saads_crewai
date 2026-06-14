#!/usr/bin/env python3
"""Query OSV.dev for vulnerabilities relevant to LLM security supply chain,
RAG poisoning, and data leakage. Deduplicates against existing OSV data.

Search categories:
  1. ML/DL frameworks: torch, tensorflow, jax, keras, transformers, huggingface
  2. Vector databases: chromadb, pinecone, weaviate, qdrant, milvus, faiss
  3. Deserialization: safetensors, pickle, dill, cloudpickle, onnx
  4. RAG & embedding tools: ragas, deepeval, trulens, guardrails, sentence-transformers
  5. Keyword-based searches where supported
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

# ── New package targets for LLM security ────────────────────────────────────

# 1. ML / Deep Learning Frameworks
ML_FRAMEWORKS = [
    # PyTorch ecosystem
    {"ecosystem": "PyPI", "name": "torch"},
    {"ecosystem": "PyPI", "name": "pytorch"},
    {"ecosystem": "PyPI", "name": "torchvision"},
    {"ecosystem": "PyPI", "name": "torchaudio"},
    {"ecosystem": "PyPI", "name": "torchserve"},
    # TensorFlow ecosystem
    {"ecosystem": "PyPI", "name": "tensorflow"},
    {"ecosystem": "PyPI", "name": "tensorflow-cpu"},
    {"ecosystem": "PyPI", "name": "tensorflow-gpu"},
    {"ecosystem": "PyPI", "name": "tensorflow-serving"},
    {"ecosystem": "PyPI", "name": "tf-nightly"},
    # JAX
    {"ecosystem": "PyPI", "name": "jax"},
    {"ecosystem": "PyPI", "name": "jaxlib"},
    {"ecosystem": "PyPI", "name": "flax"},
    # Keras
    {"ecosystem": "PyPI", "name": "keras"},
    {"ecosystem": "PyPI", "name": "tf-keras"},
    # Hugging Face ecosystem
    {"ecosystem": "PyPI", "name": "transformers"},
    {"ecosystem": "PyPI", "name": "huggingface-hub"},
    {"ecosystem": "PyPI", "name": "huggingface_hub"},
    {"ecosystem": "PyPI", "name": "datasets"},
    {"ecosystem": "PyPI", "name": "accelerate"},
    {"ecosystem": "PyPI", "name": "peft"},
    {"ecosystem": "PyPI", "name": "diffusers"},
    {"ecosystem": "PyPI", "name": "tokenizers"},
    {"ecosystem": "PyPI", "name": "safetensors"},
    {"ecosystem": "PyPI", "name": "trl"},
    {"ecosystem": "PyPI", "name": "evaluate"},
    # npm
    {"ecosystem": "npm", "name": "@huggingface/transformers"},
    {"ecosystem": "npm", "name": "@xenova/transformers"},
    {"ecosystem": "npm", "name": "@tensorflow/tfjs"},
    {"ecosystem": "npm", "name": "onnxruntime-web"},
]

# 2. Vector Databases
VECTOR_DB = [
    # PyPI
    {"ecosystem": "PyPI", "name": "chromadb"},
    {"ecosystem": "PyPI", "name": "pinecone-client"},
    {"ecosystem": "PyPI", "name": "pinecone"},
    {"ecosystem": "PyPI", "name": "weaviate-client"},
    {"ecosystem": "PyPI", "name": "qdrant-client"},
    {"ecosystem": "PyPI", "name": "pymilvus"},
    {"ecosystem": "PyPI", "name": "milvus"},
    {"ecosystem": "PyPI", "name": "milvus-lite"},
    {"ecosystem": "PyPI", "name": "faiss-cpu"},
    {"ecosystem": "PyPI", "name": "faiss-gpu"},
    {"ecosystem": "PyPI", "name": "faiss"},
    {"ecosystem": "PyPI", "name": "pgvector"},
    {"ecosystem": "PyPI", "name": "pgvector-python"},
    {"ecosystem": "PyPI", "name": "annoy"},
    {"ecosystem": "PyPI", "name": "hnswlib"},
    {"ecosystem": "PyPI", "name": "lancedb"},
    {"ecosystem": "PyPI", "name": "vearch"},
    {"ecosystem": "PyPI", "name": "elasticsearch"},
    {"ecosystem": "PyPI", "name": "opensearch-py"},
    # npm
    {"ecosystem": "npm", "name": "chromadb"},
    {"ecosystem": "npm", "name": "@pinecone-database/pinecone"},
    {"ecosystem": "npm", "name": "@qdrant/js-client-rest"},
    {"ecosystem": "npm", "name": "hnswlib-node"},
    {"ecosystem": "npm", "name": "faiss-node"},
    {"ecosystem": "npm", "name": "lancedb"},
    {"ecosystem": "npm", "name": "milvus-sdk-node"},
    # Go
    {"ecosystem": "Go", "name": "github.com/milvus-io/milvus"},
    {"ecosystem": "Go", "name": "github.com/weaviate/weaviate"},
    {"ecosystem": "Go", "name": "github.com/qdrant/qdrant"},
    {"ecosystem": "Go", "name": "github.com/chroma-core/chroma"},
]

# 3. ML Deserialization / Model Formats
ML_SERIALIZATION = [
    {"ecosystem": "PyPI", "name": "safetensors"},
    {"ecosystem": "PyPI", "name": "dill"},
    {"ecosystem": "PyPI", "name": "cloudpickle"},
    {"ecosystem": "PyPI", "name": "pickle5"},
    {"ecosystem": "PyPI", "name": "onnx"},
    {"ecosystem": "PyPI", "name": "onnxruntime"},
    {"ecosystem": "PyPI", "name": "onnxruntime-gpu"},
    {"ecosystem": "PyPI", "name": "onnxruntime-tools"},
    {"ecosystem": "PyPI", "name": "coremltools"},
    {"ecosystem": "PyPI", "name": "mlflow"},
    {"ecosystem": "PyPI", "name": "bentoml"},
    {"ecosystem": "PyPI", "name": "ray"},
    # npm
    {"ecosystem": "npm", "name": "onnxruntime-node"},
    {"ecosystem": "npm", "name": "onnxruntime"},
    # Go
    {"ecosystem": "Go", "name": "github.com/ray-project/ray"},
]

# 4. RAG & Embedding Tools + LLM Guardrails
RAG_TOOLS = [
    {"ecosystem": "PyPI", "name": "ragas"},
    {"ecosystem": "PyPI", "name": "deepeval"},
    {"ecosystem": "PyPI", "name": "trulens"},
    {"ecosystem": "PyPI", "name": "trulens-eval"},
    {"ecosystem": "PyPI", "name": "guardrails"},
    {"ecosystem": "PyPI", "name": "guardrails-ai"},
    {"ecosystem": "PyPI", "name": "llm-guard"},
    {"ecosystem": "PyPI", "name": "sentence-transformers"},
    {"ecosystem": "PyPI", "name": "FlagEmbedding"},
    {"ecosystem": "PyPI", "name": "InstructorEmbedding"},
    {"ecosystem": "PyPI", "name": "openinference"},
    {"ecosystem": "PyPI", "name": "arize-phoenix"},
    {"ecosystem": "PyPI", "name": "langfuse"},
    {"ecosystem": "PyPI", "name": "langsmith"},
    {"ecosystem": "PyPI", "name": "langwatch"},
    {"ecosystem": "PyPI", "name": "langkit"},
    {"ecosystem": "PyPI", "name": "nemo-guardrails"},
    {"ecosystem": "PyPI", "name": "llama-guard"},
    {"ecosystem": "PyPI", "name": "vllm"},
    {"ecosystem": "PyPI", "name": "text-generation-inference"},
    {"ecosystem": "PyPI", "name": "aphrodite-engine"},
    {"ecosystem": "PyPI", "name": "text-embeddings-inference"},
    # npm
    {"ecosystem": "npm", "name": "langchain"},
    {"ecosystem": "npm", "name": "llamaindex"},
    {"ecosystem": "npm", "name": "@langchain/core"},
    # Go
    {"ecosystem": "Go", "name": "github.com/tmc/langchaingo"},
    {"ecosystem": "Go", "name": "github.com/nvidia/nemo-guardrails"},
]

# 5. ML Supply Chain / Model Hub / Data Pipeline
ML_SUPPLY_CHAIN = [
    {"ecosystem": "PyPI", "name": "wandb"},
    {"ecosystem": "PyPI", "name": "dvc"},
    {"ecosystem": "PyPI", "name": "mlflow"},
    {"ecosystem": "PyPI", "name": "kubeflow"},
    {"ecosystem": "PyPI", "name": "seldon-core"},
    {"ecosystem": "PyPI", "name": "kserve"},
    {"ecosystem": "PyPI", "name": "bentoml"},
    {"ecosystem": "PyPI", "name": "gradio"},
    {"ecosystem": "PyPI", "name": "streamlit"},
    {"ecosystem": "PyPI", "name": "fastapi"},
    {"ecosystem": "PyPI", "name": "nvidia-tensorrt"},
    {"ecosystem": "PyPI", "name": "tritonclient"},
    {"ecosystem": "PyPI", "name": "tensorboard"},
    {"ecosystem": "npm", "name": "@wandb/sdk"},
]

ALL_NEW_TARGETS = ML_FRAMEWORKS + VECTOR_DB + ML_SERIALIZATION + RAG_TOOLS + ML_SUPPLY_CHAIN

# ── Relevance evaluation ─────────────────────────────────────────────────────

# Keywords for automatic relevance scoring
RELEVANCE_PATTERNS = {
    "model_supply_chain": [
        "supply chain", "model poisoning", "backdoor", "trojan", "weight",
        "checkpoint", "model file", "pickle", "deserialization", "code execution",
        "arbitrary code", "remote code", "rce", "malicious model", "safetensor",
        "serialized", "untrusted", "model loading", "load_model", "torch.load",
        "tf.load", "keras.load", "joblib.load", "model registry", "model hub",
    ],
    "rag_poisoning": [
        "rag", "retrieval augmented", "embedding", "vector database", "nearest neighbor",
        "index poisoning", "data poisoning", "adversarial", "document injection",
        "knowledge base", "prompt injection", "context pollution",
        "semantic search", "similarity search", "approximate nearest",
    ],
    "data_leakage": [
        "data leak", "data exfil", "data exfiltration", "information disclosure",
        "api key", "secret", "credential", "token leak", "log injection",
        "memory leak", "cache poisoning", "side channel", "privacy",
        "sensitive data", "pii", "personally identifiable",
        "cross-tenant", "isolation", "sandbox escape",
    ],
}

# Package-to-topic mapping for packages that don't have keyword matches
PACKAGE_TOPIC_MAP = {
    # ML frameworks → model supply chain
    "torch": ["model_supply_chain"],
    "pytorch": ["model_supply_chain"],
    "tensorflow": ["model_supply_chain"],
    "jax": ["model_supply_chain"],
    "keras": ["model_supply_chain"],
    "transformers": ["model_supply_chain"],
    "huggingface-hub": ["model_supply_chain"],
    "huggingface_hub": ["model_supply_chain"],
    "datasets": ["model_supply_chain", "data_leakage"],
    "diffusers": ["model_supply_chain"],
    "tokenizers": ["model_supply_chain"],
    "safetensors": ["model_supply_chain"],
    # Vector DBs → RAG poisoning
    "chromadb": ["rag_poisoning", "data_leakage"],
    "pinecone-client": ["rag_poisoning", "data_leakage"],
    "pinecone": ["rag_poisoning", "data_leakage"],
    "weaviate-client": ["rag_poisoning", "data_leakage"],
    "qdrant-client": ["rag_poisoning", "data_leakage"],
    "pymilvus": ["rag_poisoning", "data_leakage"],
    "milvus": ["rag_poisoning", "data_leakage"],
    "faiss-cpu": ["rag_poisoning"],
    "faiss-gpu": ["rag_poisoning"],
    "faiss": ["rag_poisoning"],
    "pgvector": ["rag_poisoning", "data_leakage"],
    "annoy": ["rag_poisoning"],
    "hnswlib": ["rag_poisoning"],
    "lancedb": ["rag_poisoning", "data_leakage"],
    # Serialization → model supply chain
    "dill": ["model_supply_chain"],
    "cloudpickle": ["model_supply_chain"],
    "pickle5": ["model_supply_chain"],
    "onnx": ["model_supply_chain"],
    "onnxruntime": ["model_supply_chain"],
    "mlflow": ["model_supply_chain", "data_leakage"],
    # RAG tools
    "ragas": ["rag_poisoning"],
    "deepeval": ["rag_poisoning"],
    "trulens": ["rag_poisoning"],
    "trulens-eval": ["rag_poisoning"],
    "guardrails": ["rag_poisoning", "model_supply_chain"],
    "guardrails-ai": ["rag_poisoning", "model_supply_chain"],
    "llm-guard": ["rag_poisoning", "model_supply_chain"],
    "nemo-guardrails": ["rag_poisoning", "model_supply_chain"],
    "sentence-transformers": ["rag_poisoning", "model_supply_chain"],
    "vllm": ["model_supply_chain", "data_leakage"],
    # Supply chain
    "gradio": ["model_supply_chain", "data_leakage"],
    "streamlit": ["model_supply_chain", "data_leakage"],
    "bentoml": ["model_supply_chain"],
    "wandb": ["data_leakage"],
    "dvc": ["model_supply_chain"],
    "kubeflow": ["model_supply_chain", "data_leakage"],
}


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
    try:
        return _get_json(f"{OSV_VULN_URL}/{vuln_id}")
    except Exception:
        return None


def extract_severity(vuln: dict[str, Any]) -> str:
    for sev in vuln.get("severity", []) or []:
        if sev.get("type") == "CVSS_V3":
            score = sev.get("score", "")
            return f"CVSS:3.1/{score}"
        if sev.get("type") == "CVSS_V2":
            score = sev.get("score", "")
            return f"CVSS:2.0/{score}"
    db_spec = vuln.get("database_specific", {}) or {}
    if "severity" in db_spec:
        return str(db_spec["severity"])
    return "N/A"


def extract_affected_versions(vuln: dict[str, Any]) -> list[str]:
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


def compute_relevance(vuln: dict[str, Any], pkg_name: str) -> dict[str, Any]:
    """Score relevance to our three LLM security topics."""
    summary = (vuln.get("summary", "") or "").lower()
    details = (vuln.get("details", "") or "").lower()
    combined = summary + " " + details

    scores = {}
    for topic, patterns in RELEVANCE_PATTERNS.items():
        score = 0.0
        for pat in patterns:
            if pat.lower() in combined:
                score += 0.15
        scores[topic] = min(score, 1.0)

    # Boost from package-topic mapping
    pkg_topics = PACKAGE_TOPIC_MAP.get(pkg_name.lower(), [])
    for topic in pkg_topics:
        if topic in scores:
            scores[topic] = max(scores[topic], 0.2)

    # Overall relevance is max of the three
    overall = max(scores.values()) if scores else 0.0

    # Determine matched topics
    matched = [t for t, s in scores.items() if s >= 0.15]

    return {
        "relevance_score": round(overall, 2),
        "model_supply_chain": round(scores.get("model_supply_chain", 0.0), 2),
        "rag_poisoning": round(scores.get("rag_poisoning", 0.0), 2),
        "data_leakage": round(scores.get("data_leakage", 0.0), 2),
        "topics_matched": matched,
    }


def is_ml_llm_relevant(vuln: dict[str, Any], pkg_name: str) -> bool:
    """Quick filter: is this vulnerability likely relevant to LLM security?"""
    summary = (vuln.get("summary", "") or "").lower()
    details = (vuln.get("details", "") or "").lower()
    combined = summary + " " + details

    # ML/LLM specific keywords
    ml_keywords = [
        "machine learning", "llm", "transformer", "model", "neural",
        "deep learning", "pickle", "deserializ", "serializ",
        "vector", "embedding", "rag", "retriev", "hugging",
        "pytorch", "tensorflow", "jax", "keras", "safetensors",
        "tokeniz", "checkpoint", "weight", "gradient",
        "inference", "training", "fine-tun", "fine tun",
        "data poison", "backdoor", "adversarial", "prompt",
        "chroma", "pinecone", "weaviate", "qdrant", "milvus",
        "faiss", "lancedb", "langchain", "llamaindex",
        "bert", "gpt", "chatgpt", "openai", "anthropic",
        "langgraph", "crewai", "autogen",
    ]
    for kw in ml_keywords:
        if kw in combined:
            return True

    # Check package name for relevance
    pkg_lower = pkg_name.lower()
    pkg_keywords = [
        "torch", "tensorflow", "jax", "keras", "transform",
        "hugging", "chroma", "pinecone", "weaviate", "qdrant",
        "milvus", "faiss", "safetensor", "onnx", "dill",
        "cloudpickle", "rag", "embedding", "guardrail",
        "llm", "vllm", "langchain", "llamaindex",
    ]
    for kw in pkg_keywords:
        if kw in pkg_lower:
            return True

    return False


def format_vuln(vuln: dict[str, Any], vuln_id: str, ecosystem: str, pkg_name: str) -> dict[str, Any]:
    aliases = vuln.get("aliases", []) or []
    cve_ids = [a for a in aliases if a.startswith("CVE-")]
    summary = vuln.get("summary", "") or vuln.get("details", "") or ""
    if len(summary) > 400:
        summary = summary[:397] + "..."

    relevance = compute_relevance(vuln, pkg_name)

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
        "relevance_score": relevance["relevance_score"],
        "relevance_model_supply_chain": relevance["model_supply_chain"],
        "relevance_rag_poisoning": relevance["rag_poisoning"],
        "relevance_data_leakage": relevance["data_leakage"],
        "topics_matched": relevance["topics_matched"],
        "is_new": True,  # Will be set False for duplicates
    }


def load_existing_ids(filepath: str) -> set[str]:
    try:
        with open(filepath, 'r') as f:
            ids = json.load(f)
        return set(ids)
    except FileNotFoundError:
        return set()


def main() -> None:
    existing_ids = load_existing_ids("scripts/_existing_osv_ids.json")
    print(f"Loaded {len(existing_ids)} existing OSV IDs for dedup")

    all_vulns: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    new_count = 0
    dup_count = 0

    categories = [
        ("ML/DL FRAMEWORKS (torch, tf, jax, keras, huggingface)", ML_FRAMEWORKS),
        ("VECTOR DATABASES (chroma, pinecone, weaviate, qdrant, milvus, faiss)", VECTOR_DB),
        ("ML SERIALIZATION & MODEL FORMATS (safetensors, dill, cloudpickle, onnx)", ML_SERIALIZATION),
        ("RAG TOOLS & EMBEDDING + LLM GUARDRAILS", RAG_TOOLS),
        ("ML SUPPLY CHAIN & MODEL HUB", ML_SUPPLY_CHAIN),
    ]

    print("=" * 80)
    print("OSV.DEV VULNERABILITY QUERY — LLM Security Supply Chain, RAG & Data Leakage")
    print("=" * 80)

    for cat_name, targets in categories:
        print(f"\n{'─'*80}")
        print(f"  {cat_name}")
        print(f"{'─'*80}")
        for tgt in targets:
            eco = tgt["ecosystem"]
            name = tgt["name"]
            key = f"{eco}/{name}"
            vulns_raw = query_package(eco, name)
            relevant = [v for v in vulns_raw if is_ml_llm_relevant(v, name)]
            print(f"  {key}: {len(vulns_raw)} total, {len(relevant)} ML/LLM-relevant")

            for v in relevant:
                vid = v.get("id", "")
                if not vid or vid in seen_ids:
                    continue
                seen_ids.add(vid)
                formatted = format_vuln(v, vid, eco, name)
                if vid in existing_ids:
                    formatted["is_new"] = False
                    dup_count += 1
                else:
                    new_count += 1
                all_vulns.append(formatted)

            time.sleep(0.15)

    # ── Fetch detailed info ─────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"  Fetching detailed info for {len(all_vulns)} vulnerabilities...")
    print(f"{'='*80}")

    for i, vuln in enumerate(all_vulns):
        detail = get_vuln_detail(vuln["id"])
        if detail:
            sev = extract_severity(detail)
            if sev != "N/A":
                vuln["severity"] = sev
            versions = extract_affected_versions(detail)
            if versions:
                vuln["affected_versions"] = versions
            summary = detail.get("summary", "") or detail.get("details", "") or vuln["summary"]
            if len(summary) > 500:
                summary = summary[:497] + "..."
            vuln["summary"] = summary
            aliases = detail.get("aliases", []) or []
            vuln["aliases"] = aliases
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            vuln["cve"] = cve_ids[0] if cve_ids else ""
            vuln["all_cves"] = cve_ids
            # Recompute relevance with full details
            rel = compute_relevance(detail, vuln["package"])
            vuln["relevance_score"] = rel["relevance_score"]
            vuln["relevance_model_supply_chain"] = rel["model_supply_chain"]
            vuln["relevance_rag_poisoning"] = rel["rag_poisoning"]
            vuln["relevance_data_leakage"] = rel["data_leakage"]
            vuln["topics_matched"] = rel["topics_matched"]
        if (i + 1) % 20 == 0:
            print(f"  ... {i+1}/{len(all_vulns)}")
        time.sleep(0.08)

    # ── Sort by relevance ───────────────────────────────────────────────────
    all_vulns.sort(key=lambda x: (-x["relevance_score"], 0 if x["cve"] else 1))

    # ── Output summary ──────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*80}")

    total_with_cve = sum(1 for v in all_vulns if v["cve"])
    high_relevance = [v for v in all_vulns if v["relevance_score"] >= 0.5]
    medium_relevance = [v for v in all_vulns if 0.3 <= v["relevance_score"] < 0.5]
    low_relevance = [v for v in all_vulns if v["relevance_score"] < 0.3]

    print(f"\n  Total ML/LLM-relevant vulnerabilities: {len(all_vulns)}")
    print(f"    NEW (not in existing data):         {new_count}")
    print(f"    DUPLICATE (already in existing):    {dup_count}")
    print(f"  With CVE assignments:                 {total_with_cve}")
    print(f"  High relevance   (score >= 0.5):      {len(high_relevance)}")
    print(f"  Medium relevance (0.3 <= score < 0.5):{len(medium_relevance)}")
    print(f"  Low relevance    (score < 0.3):       {len(low_relevance)}")

    topic_counts = {
        "model_supply_chain": sum(1 for v in all_vulns if v["relevance_model_supply_chain"] >= 0.15),
        "rag_poisoning": sum(1 for v in all_vulns if v["relevance_rag_poisoning"] >= 0.15),
        "data_leakage": sum(1 for v in all_vulns if v["relevance_data_leakage"] >= 0.15),
    }
    print(f"\n  Topic matches:")
    for topic, cnt in topic_counts.items():
        print(f"    {topic}: {cnt}")

    # ── Print high and medium relevance ─────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"  HIGH & MEDIUM RELEVANCE VULNERABILITIES")
    print(f"{'='*80}")

    for i, vuln in enumerate(high_relevance + medium_relevance, 1):
        tag = "NEW" if vuln["is_new"] else "DUP"
        cve_str = f" [{vuln['cve']}]" if vuln["cve"] else ""
        print(f"\n{i:3d}. [{tag}] {vuln['id']}{cve_str}  score={vuln['relevance_score']:.2f}")
        print(f"     Package:    {vuln['ecosystem']}/{vuln['package']}")
        print(f"     Severity:   {vuln['severity']}")
        print(f"     Topics:     {', '.join(vuln['topics_matched']) if vuln['topics_matched'] else 'none'}")
        if vuln["affected_versions"]:
            print(f"     Affected:   {', '.join(vuln['affected_versions'][:3])}")
        print(f"     Summary:    {vuln['summary'][:300]}")
        if vuln["published"]:
            print(f"     Published:  {vuln['published']}")

    # ── Save JSON ───────────────────────────────────────────────────────────
    output_path = "E:/@4C-2026/sufe_saads_crewai/scripts/osv_llm_security_output.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "query_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_relevant": len(all_vulns),
            "new_vulnerabilities": new_count,
            "duplicates": dup_count,
            "with_cve": total_with_cve,
            "high_relevance_count": len(high_relevance),
            "medium_relevance_count": len(medium_relevance),
            "low_relevance_count": len(low_relevance),
            "topic_counts": topic_counts,
            "vulnerabilities": all_vulns,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n  Full JSON output saved to: {output_path}")

    # ── Print only NEW high/medium for quick review ─────────────────────────
    print(f"\n{'='*80}")
    print(f"  NEW HIGH-RELEVANCE VULNERABILITIES (for manual review)")
    print(f"{'='*80}")
    new_high = [v for v in all_vulns if v["is_new"] and v["relevance_score"] >= 0.4]
    for i, vuln in enumerate(new_high, 1):
        cve_str = f" [{vuln['cve']}]" if vuln["cve"] else ""
        print(f"\n{i:3d}. {vuln['id']}{cve_str}  score={vuln['relevance_score']:.2f}")
        print(f"     Package:    {vuln['ecosystem']}/{vuln['package']}")
        print(f"     Topics:     {', '.join(vuln['topics_matched']) if vuln['topics_matched'] else 'none'}")
        print(f"     Summary:    {vuln['summary'][:300]}")


if __name__ == "__main__":
    main()
