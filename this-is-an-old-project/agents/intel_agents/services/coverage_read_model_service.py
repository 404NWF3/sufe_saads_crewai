from __future__ import annotations

from typing import Any

from ..schemas.coverage import CoverageSliceDTO, VendorModelCoverageRowDTO


class CoverageReadModelService:
    def build_taxonomy_component_source_view(
        self,
        stable_attack_records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
        for record in stable_attack_records:
            stable_attack_id = str(
                record.get("stable_attack_id")
                or record.get("stable_attack_code")
                or record.get("attack_code")
                or "unknown_attack"
            )
            taxonomy_items = record.get("taxonomy_items") or []
            source_coverage = record.get("source_coverage") or ["unknown"]
            component_families = sorted(
                {
                    _normalize_component_family(item.get("mentioned_name"))
                    for item in record.get("bom_mentions", [])
                    if item.get("mentioned_name")
                }
            ) or ["unknown"]
            for taxonomy in taxonomy_items or [
                {"taxonomy_code": "OWASP-LLM-UNKNOWN", "taxonomy_name": "Unknown"}
            ]:
                taxonomy_code = str(
                    taxonomy.get("taxonomy_code") or "OWASP-LLM-UNKNOWN"
                )
                taxonomy_name = str(taxonomy.get("taxonomy_name") or taxonomy_code)
                for source_name in source_coverage:
                    for component_family in component_families:
                        key = (taxonomy_code, str(source_name), component_family)
                        bucket = grouped.setdefault(
                            key,
                            {
                                "taxonomy_code": taxonomy_code,
                                "taxonomy_name": taxonomy_name,
                                "attack_family": record.get("attack_family"),
                                "source_name": str(source_name),
                                "component_family": component_family,
                                "stable_attack_ids": set(),
                                "high_severity_attack_ids": set(),
                                "corroborated_attack_ids": set(),
                                "version_mapped_attack_ids": set(),
                            },
                        )
                        bucket["stable_attack_ids"].add(stable_attack_id)
                        if str(record.get("severity_level", "")).lower() in {
                            "high",
                            "critical",
                        }:
                            bucket["high_severity_attack_ids"].add(stable_attack_id)
                        if len(source_coverage) >= 2:
                            bucket["corroborated_attack_ids"].add(stable_attack_id)
                        if any(
                            item.get("mentioned_version")
                            for item in record.get("bom_mentions", [])
                        ):
                            bucket["version_mapped_attack_ids"].add(stable_attack_id)
        return [
            CoverageSliceDTO(
                coverage_axis="taxonomy_component_source",
                taxonomy_code=row["taxonomy_code"],
                taxonomy_name=row["taxonomy_name"],
                attack_family=row.get("attack_family"),
                source_name=row["source_name"],
                component_family=row["component_family"],
                attack_count=len(row["stable_attack_ids"]),
                high_severity_count=len(row["high_severity_attack_ids"]),
                source_diversity_count=1,
                corroborated_attack_count=len(row["corroborated_attack_ids"]),
                version_mapped_count=len(row["version_mapped_attack_ids"]),
                last_seen_at=None,
                stable_attack_ids=sorted(row["stable_attack_ids"]),
                high_severity_attack_ids=sorted(row["high_severity_attack_ids"]),
                corroborated_attack_ids=sorted(row["corroborated_attack_ids"]),
                version_mapped_attack_ids=sorted(row["version_mapped_attack_ids"]),
            ).model_dump(mode="python")
            for row in grouped.values()
        ]

    def build_vendor_model_source_view(
        self,
        stable_attack_records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for record in stable_attack_records:
            stable_attack_id = str(
                record.get("stable_attack_id")
                or record.get("stable_attack_code")
                or record.get("attack_code")
                or "unknown_attack"
            )
            source_coverage = record.get("source_coverage") or ["unknown"]
            taxonomy_items = record.get("taxonomy_items") or [
                {"taxonomy_code": "OWASP-LLM-UNKNOWN", "taxonomy_name": "Unknown"}
            ]
            families = _extract_families(record.get("bom_mentions", []))
            for family in families:
                family_key = str(
                    family.get("vendor_name")
                    or family.get("model_family")
                    or family.get("framework_family")
                    or "unknown"
                )
                for source_name in source_coverage:
                    for taxonomy in taxonomy_items:
                        taxonomy_code = str(
                            taxonomy.get("taxonomy_code") or "OWASP-LLM-UNKNOWN"
                        )
                        taxonomy_name = str(
                            taxonomy.get("taxonomy_name") or taxonomy_code
                        )
                        key = (
                            family_key,
                            str(source_name),
                            taxonomy_code,
                            taxonomy_name,
                        )
                        bucket = grouped.setdefault(
                            key,
                            {
                                "vendor_name": family.get("vendor_name"),
                                "model_family": family.get("model_family"),
                                "framework_family": family.get("framework_family"),
                                "source_name": str(source_name),
                                "taxonomy_code": taxonomy_code,
                                "taxonomy_name": taxonomy_name,
                                "stable_attack_ids": set(),
                                "high_severity_attack_ids": set(),
                                "corroborated_attack_ids": set(),
                                "version_mapped_attack_ids": set(),
                            },
                        )
                        bucket["stable_attack_ids"].add(stable_attack_id)
                        if str(record.get("severity_level", "")).lower() in {
                            "high",
                            "critical",
                        }:
                            bucket["high_severity_attack_ids"].add(stable_attack_id)
                        if len(source_coverage) >= 2:
                            bucket["corroborated_attack_ids"].add(stable_attack_id)
                        if any(
                            item.get("mentioned_version")
                            for item in record.get("bom_mentions", [])
                        ):
                            bucket["version_mapped_attack_ids"].add(stable_attack_id)
        return [
            VendorModelCoverageRowDTO(
                vendor_name=row.get("vendor_name"),
                model_family=row.get("model_family"),
                framework_family=row.get("framework_family"),
                source_name=row["source_name"],
                taxonomy_code=row.get("taxonomy_code"),
                taxonomy_name=row.get("taxonomy_name"),
                attack_count=len(row["stable_attack_ids"]),
                high_severity_count=len(row["high_severity_attack_ids"]),
                corroborated_attack_count=len(row["corroborated_attack_ids"]),
                version_mapped_count=len(row["version_mapped_attack_ids"]),
                stable_attack_ids=sorted(row["stable_attack_ids"]),
                high_severity_attack_ids=sorted(row["high_severity_attack_ids"]),
                corroborated_attack_ids=sorted(row["corroborated_attack_ids"]),
                version_mapped_attack_ids=sorted(row["version_mapped_attack_ids"]),
            ).model_dump(mode="python")
            for row in grouped.values()
        ]

    def build_recent_attack_summary(
        self,
        stable_attack_records: list[dict[str, Any]],
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for row in stable_attack_records[:limit]:
            output.append(
                {
                    "stable_attack_id": row.get("stable_attack_id"),
                    "canonical_name": row.get("canonical_name"),
                    "attack_family": row.get("attack_family"),
                    "taxonomy_codes": [
                        item.get("taxonomy_code")
                        for item in row.get("taxonomy_items", [])
                    ],
                    "source_coverage": row.get("source_coverage", []),
                    "component_families": sorted(
                        {
                            _normalize_component_family(item.get("mentioned_name"))
                            for item in row.get("bom_mentions", [])
                            if item.get("mentioned_name")
                        }
                    ),
                    "severity_level": row.get("severity_level"),
                }
            )
        return output


def _normalize_component_family(name: str | None) -> str:
    text = str(name or "unknown").strip().lower()
    aliases = {
        "llama-index": "llamaindex",
        "llama_index": "llamaindex",
        "hugging face": "huggingface",
        "azure openai": "openai",
    }
    return aliases.get(text, text or "unknown")


def _extract_families(
    bom_mentions: list[dict[str, Any]],
) -> list[dict[str, str | None]]:
    output: list[dict[str, str | None]] = []
    for mention in bom_mentions:
        normalized = _normalize_component_family(mention.get("mentioned_name"))
        vendor = str(
            mention.get("mentioned_vendor") or ""
        ).strip() or _vendor_from_name(normalized)
        model_family = _model_family_from_name(normalized)
        framework_family = _framework_family_from_name(normalized)
        if (
            not vendor
            and not model_family
            and not framework_family
            and normalized != "unknown"
        ):
            framework_family = normalized.title()
        output.append(
            {
                "vendor_name": vendor,
                "model_family": model_family,
                "framework_family": framework_family,
            }
        )
    return output or [
        {"vendor_name": None, "model_family": None, "framework_family": None}
    ]


def _vendor_from_name(name: str) -> str | None:
    mapping = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "google": "Google",
        "meta": "Meta",
        "mistral": "Mistral",
        "qwen": "Alibaba",
        "deepseek": "DeepSeek",
        "huggingface": "HuggingFace",
    }
    return mapping.get(name)


def _model_family_from_name(name: str) -> str | None:
    for key, value in {
        "claude": "Claude",
        "gemini": "Gemini",
        "llama": "Llama",
        "qwen": "Qwen",
        "deepseek": "DeepSeek",
    }.items():
        if key in name:
            return value
    return None


def _framework_family_from_name(name: str) -> str | None:
    for key, value in {
        "langchain": "LangChain",
        "llamaindex": "LlamaIndex",
        "crewai": "CrewAI",
        "autogen": "AutoGen",
    }.items():
        if key in name:
            return value
    return None
