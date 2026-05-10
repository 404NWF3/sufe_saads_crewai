from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any


_WS_RE = re.compile(r"\s+")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CVSS_RE = re.compile(r"CVSS[^\d]*(\d(?:\.\d)?)", re.IGNORECASE)

_ATTACK_FAMILY_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "prompt_injection",
        ("prompt injection", "indirect prompt injection", "prompt-injection"),
    ),
    ("jailbreak", ("jailbreak", "system prompt bypass", "alignment bypass")),
    (
        "agent_hijack",
        ("agent hijack", "tool hijack", "agent misuse", "agent workflow abuse"),
    ),
    ("supply_chain", ("dependency", "package", "advisory", "supply chain")),
    (
        "data_leakage",
        ("data leak", "information disclosure", "secret exposure", "leakage"),
    ),
    ("dos", ("dos", "denial of service", "resource exhaustion")),
]

_TAXONOMY_RULES: list[tuple[dict[str, str], tuple[str, ...]]] = [
    (
        {
            "taxonomy_type": "OWASP_LLM",
            "taxonomy_code": "OWASP-LLM-01",
            "taxonomy_name": "Prompt Injection",
        },
        ("prompt injection", "indirect prompt injection", "prompt-injection"),
    ),
    (
        {
            "taxonomy_type": "OWASP_LLM",
            "taxonomy_code": "OWASP-LLM-02",
            "taxonomy_name": "Insecure Output Handling",
        },
        ("unsafe output", "insecure output", "output injection"),
    ),
    (
        {
            "taxonomy_type": "OWASP_LLM",
            "taxonomy_code": "OWASP-LLM-07",
            "taxonomy_name": "Insecure Plugin Design",
        },
        ("plugin", "tool abuse", "tool hijack", "agent hijack"),
    ),
    (
        {
            "taxonomy_type": "CWE",
            "taxonomy_code": "CWE-20",
            "taxonomy_name": "Improper Input Validation",
        },
        ("prompt injection", "input validation", "payload injection"),
    ),
    (
        {
            "taxonomy_type": "CWE",
            "taxonomy_code": "CWE-94",
            "taxonomy_name": "Code Injection",
        },
        ("code injection", "arbitrary code", "unsafe execution"),
    ),
    (
        {
            "taxonomy_type": "ATTACK",
            "taxonomy_code": "T1190",
            "taxonomy_name": "Exploit Public-Facing Application",
        },
        ("exploit", "public-facing", "remote exploitation"),
    ),
]

_COMPONENT_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("langchain", ("langchain",)),
    ("llamaindex", ("llamaindex", "llama index")),
    ("openai api", ("openai api", "openai sdk")),
    ("huggingface transformers", ("transformers", "huggingface")),
    ("retrieval plugin", ("plugin", "tooling layer")),
    ("agent runtime", ("agent runtime", "agent workflow")),
]

_COMPONENT_ALIAS_MAP: dict[str, tuple[str, ...]] = {
    "langchain": ("langchain-core", "langchain community", "langgraph", "langsmith"),
    "llamaindex": ("llama index", "gpt index"),
    "huggingface transformers": ("hf transformers", "transformers library"),
    "openai api": ("openai sdk", "openai python"),
}


def load_raw_payload(payload_uri: str) -> str:
    path = Path(payload_uri)
    return path.read_text(encoding="utf-8")


def clean_raw_content(raw_text: str, raw_format: str) -> str:
    text = raw_text.strip()
    if raw_format == "json":
        try:
            parsed = json.loads(text)
            text = json.dumps(parsed, ensure_ascii=True, sort_keys=True)
        except json.JSONDecodeError:
            pass
    text = text.replace("\r", "\n")
    text = _WS_RE.sub(" ", text)
    return text.strip()


def source_specific_projection(
    raw_item: dict[str, Any], cleaned_payload: str
) -> dict[str, Any]:
    source_name = raw_item.get("source_name", "")
    if source_name == "nvd":
        return _parse_nvd_projection(cleaned_payload)
    if source_name in {"github_advisories", "github_discussions"}:
        return _parse_github_projection(cleaned_payload)
    if source_name == "arxiv":
        return _parse_arxiv_projection(cleaned_payload)
    if source_name in {"reddit", "hackernews"}:
        return _parse_community_projection(cleaned_payload)
    return {}


def normalize_text_fields(
    raw_item: dict[str, Any], cleaned_payload: str
) -> dict[str, str]:
    title = (raw_item.get("title") or "").strip()
    summary = (raw_item.get("summary") or "").strip()
    query_text = str(raw_item.get("metadata", {}).get("query_text", "")).strip()
    source_name = str(raw_item.get("source_name", "")).strip()
    if not title:
        title = _fallback_title(source_name, query_text, cleaned_payload)
    if not summary:
        summary = cleaned_payload[:240]
    description = cleaned_payload[:2000]
    return {
        "title": title,
        "summary": summary,
        "description": description,
    }


def infer_attack_family(text: str) -> tuple[str, str]:
    lowered = text.lower()
    for family, patterns in _ATTACK_FAMILY_RULES:
        if any(pattern in lowered for pattern in patterns):
            return family, f"matched attack family keywords for {family}"
    return (
        "generic_ai_security",
        "defaulted to generic_ai_security due to missing strong family signals",
    )


def infer_severity_level(text: str, source_name: str) -> str:
    lowered = text.lower()
    if any(
        token in lowered
        for token in ("critical", "known exploited", "actively exploited")
    ):
        return "critical"
    if any(
        token in lowered
        for token in ("high", "remote code execution", "arbitrary code", "exploitation")
    ):
        return "high"
    if source_name in {"cisa_kev", "nvd", "github_advisories"}:
        return "medium"
    return "low"


def infer_taxonomy_labels(text: str, attack_family: str) -> list[dict[str, Any]]:
    lowered = text.lower()
    labels: list[dict[str, Any]] = []
    for base, patterns in _TAXONOMY_RULES:
        if any(pattern in lowered for pattern in patterns):
            labels.append({**base, "confidence_score": 0.78, "is_primary": False})
    if not labels:
        labels.append(
            {
                "taxonomy_type": "OWASP_LLM",
                "taxonomy_code": "OWASP-LLM-09",
                "taxonomy_name": "Overreliance",
                "confidence_score": 0.35,
                "is_primary": False,
            }
        )
    labels[0]["is_primary"] = True
    if attack_family == "prompt_injection":
        labels[0].update(
            {
                "taxonomy_type": "OWASP_LLM",
                "taxonomy_code": "OWASP-LLM-01",
                "taxonomy_name": "Prompt Injection",
            }
        )
        labels[0]["is_primary"] = True
    return labels


def infer_cvss_hint(text: str, severity_level: str) -> dict[str, Any] | None:
    match = _CVSS_RE.search(text)
    base_score = None
    if match:
        try:
            base_score = float(match.group(1))
        except ValueError:
            base_score = None
    if base_score is None:
        default_map = {
            "critical": 9.1,
            "high": 8.1,
            "medium": 6.4,
            "low": 3.7,
            "info": 0.0,
        }
        base_score = default_map.get(severity_level)
    if base_score is None:
        return None
    severity_label = (
        "Critical"
        if base_score >= 9.0
        else "High"
        if base_score >= 7.0
        else "Medium"
        if base_score >= 4.0
        else "Low"
    )
    return {
        "cvss_version": "3.1",
        "base_score": base_score,
        "severity_label": severity_label,
        "score_origin": "estimated",
        "vector_string": None,
    }


def extract_bom_mentions(text: str) -> list[dict[str, Any]]:
    lowered = text.lower()
    mentions: list[dict[str, Any]] = []
    for component_name, patterns in _COMPONENT_PATTERNS:
        aliases = _COMPONENT_ALIAS_MAP.get(component_name, ())
        if any(pattern in lowered for pattern in (*patterns, *aliases)):
            mentions.append(
                {
                    "mentioned_name": component_name,
                    "mentioned_vendor": _infer_vendor(component_name),
                    "mentioned_version": None,
                    "confidence_score": 0.72,
                    "reason_code": "name_mention",
                }
            )
    return mentions


def score_field_confidence(
    *,
    summary: str,
    description: str,
    taxonomy_items: list[dict[str, Any]],
    cvss_hint: dict[str, Any] | None,
    bom_mentions: list[dict[str, Any]],
    strategy_used: str,
) -> dict[str, float]:
    base = 0.84 if strategy_used == "llm_enhanced" else 0.72
    return {
        "summary": round(base if summary else 0.3, 3),
        "description": round(base if len(description) >= 40 else 0.35, 3),
        "taxonomy_items": round(min(0.95, 0.55 + (0.12 * len(taxonomy_items))), 3),
        "cvss_hint": round(0.82 if cvss_hint else 0.25, 3),
        "bom_mentions": round(0.8 if bom_mentions else 0.3, 3),
    }


def detect_conflict_flags(
    *,
    severity_level: str,
    cvss_hint: dict[str, Any] | None,
    taxonomy_items: list[dict[str, Any]],
    bom_mentions: list[dict[str, Any]],
) -> list[str]:
    conflicts: list[str] = []
    if cvss_hint is not None:
        base_score = float(cvss_hint.get("base_score", 0.0))
        if severity_level == "low" and base_score >= 7.0:
            conflicts.append("severity_cvss_mismatch")
    primary_count = sum(1 for item in taxonomy_items if item.get("is_primary"))
    if primary_count != 1:
        conflicts.append("taxonomy_primary_inconsistent")
    mention_names = [item.get("mentioned_name") for item in bom_mentions]
    if len(mention_names) != len(set(mention_names)):
        conflicts.append("duplicate_bom_mentions")
    return conflicts


def validate_standardized_projection(
    *,
    taxonomy_items: list[dict[str, Any]],
    cvss_hint: dict[str, Any] | None,
    bom_mentions: list[dict[str, Any]],
    stix_payload: dict[str, Any],
) -> list[str]:
    findings: list[str] = []
    if sum(1 for item in taxonomy_items if item.get("is_primary")) != 1:
        findings.append("taxonomy-primary uniqueness violated")
    if cvss_hint is not None:
        base_score = float(cvss_hint.get("base_score", 0.0))
        if not 0.0 <= base_score <= 10.0:
            findings.append("cvss base_score out of range")
    seen_bom: set[str] = set()
    for mention in bom_mentions:
        name = str(mention.get("mentioned_name", "")).lower()
        if name in seen_bom:
            findings.append("bom dedupe violation")
            break
        seen_bom.add(name)
    if stix_payload.get("type") != "attack-pattern":
        findings.append("stix type must be attack-pattern")
    if not stix_payload.get("external_references"):
        findings.append("stix external references missing")
    return findings


def build_stix_attack_object(
    *,
    attack_code: str,
    canonical_name: str,
    description: str,
    labels: list[dict[str, Any]],
    source_name: str,
    source_uri: str,
    bom_mentions: list[dict[str, Any]] | None = None,
    cve_refs: list[str] | None = None,
) -> dict[str, Any]:
    external_refs = [{"source_name": source_name, "url": source_uri}]
    for cve in cve_refs or []:
        external_refs.append({"source_name": "cve", "external_id": cve})
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": f"attack-pattern--{sha256(attack_code.encode('utf-8')).hexdigest()[:32]}",
        "name": canonical_name,
        "description": description,
        "labels": [label["taxonomy_code"] for label in labels],
        "external_references": external_refs,
        "x_ai_bom_mentions": bom_mentions or [],
    }


def extract_evidence_snippet(text: str, canonical_name: str) -> str:
    if not text:
        return canonical_name
    snippet = text[:280].strip()
    return snippet or canonical_name


def extract_cve_references(text: str) -> list[str]:
    return sorted({match.group(0).upper() for match in _CVE_RE.finditer(text)})


def build_attack_code(raw_id: str, source_name: str, canonical_name: str) -> str:
    digest = sha256(
        f"{raw_id}:{source_name}:{canonical_name}".encode("utf-8")
    ).hexdigest()[:10]
    return f"ATTACK-{digest.upper()}"


def build_extraction_reason(
    *, source_name: str, attack_family_reason: str, taxonomy_count: int, bom_count: int
) -> str:
    return (
        f"Standardized from {source_name}; {attack_family_reason}; "
        f"taxonomy_candidates={taxonomy_count}; bom_mentions={bom_count}"
    )


def _fallback_title(source_name: str, query_text: str, cleaned_payload: str) -> str:
    if query_text:
        return f"{source_name} intelligence for {query_text}"
    return cleaned_payload[:80] or f"{source_name} intelligence"


def _infer_vendor(component_name: str) -> str | None:
    if component_name == "langchain":
        return "LangChain"
    if component_name == "llamaindex":
        return "LlamaIndex"
    if component_name == "huggingface transformers":
        return "HuggingFace"
    if component_name == "openai api":
        return "OpenAI"
    return None


def _parse_nvd_projection(cleaned_payload: str) -> dict[str, Any]:
    try:
        payload = json.loads(cleaned_payload)
    except json.JSONDecodeError:
        return {}
    cve = payload.get("cve") or {}
    descriptions = cve.get("descriptions") or []
    description = next(
        (row.get("value", "") for row in descriptions if row.get("lang") == "en"), ""
    )
    metrics = cve.get("metrics") or {}
    severity = None
    base_score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData") or {}
            severity = (
                data.get("baseSeverity") or rows[0].get("baseSeverity") or ""
            ).lower() or None
            base_score = data.get("baseScore") or rows[0].get("baseScore")
            break
    return {
        "title": cve.get("id"),
        "summary": description[:400],
        "severity": severity,
        "cvss_base_score": base_score,
    }


def _parse_github_projection(cleaned_payload: str) -> dict[str, Any]:
    try:
        payload = json.loads(cleaned_payload)
    except json.JSONDecodeError:
        return {}
    summary = (
        payload.get("description")
        or payload.get("bodyText")
        or payload.get("summary")
        or ""
    )
    return {
        "summary": summary[:400],
        "severity": str(payload.get("severity", "")).lower() or None,
    }


def _parse_arxiv_projection(cleaned_payload: str) -> dict[str, Any]:
    lowered = cleaned_payload.lower()
    categories = []
    for token in ("cs.cr", "cs.ai", "cs.lg"):
        if token in lowered:
            categories.append(token)
    return {"arxiv_categories": categories}


def _parse_community_projection(cleaned_payload: str) -> dict[str, Any]:
    lowered = cleaned_payload.lower()
    return {
        "community_signal": True,
        "contains_question": "?" in cleaned_payload,
        "possible_exploit_discussion": any(
            token in lowered for token in ("exploit", "bypass", "leak", "jailbreak")
        ),
    }
