from __future__ import annotations

from typing import Any


class SourceQueryTemplateService:
    """Provides source-aware rewrite templates for LLM reflection context."""

    def get_templates(self, source_names: list[str]) -> list[dict[str, Any]]:
        templates: dict[str, list[dict[str, str]]] = {
            "nvd": [
                {
                    "template_name": "nvd_broad_recall",
                    "query_intent": "broad_recall",
                    "pattern": "{topic} vulnerability",
                },
                {
                    "template_name": "nvd_component_anchor",
                    "query_intent": "component_anchor",
                    "pattern": "{component} security vulnerability",
                },
            ],
            "github_advisories": [
                {
                    "template_name": "gh_precision_probe",
                    "query_intent": "precision_probe",
                    "pattern": "{component} {attack_phrase}",
                }
            ],
            "arxiv": [
                {
                    "template_name": "paper_taxonomy_anchor",
                    "query_intent": "taxonomy_anchor",
                    "pattern": "{taxonomy} large language model",
                }
            ],
            "reddit": [
                {
                    "template_name": "community_weak_signal",
                    "query_intent": "weak_signal_probe",
                    "pattern": "{topic} jailbreak issue",
                }
            ],
            "hackernews": [
                {
                    "template_name": "hn_corroboration",
                    "query_intent": "evidence_corroboration",
                    "pattern": "{topic} security discussion",
                }
            ],
        }
        output: list[dict[str, Any]] = []
        for source_name in source_names:
            output.append(
                {
                    "source_name": source_name,
                    "templates": templates.get(
                        source_name,
                        [
                            {
                                "template_name": "generic_broad_recall",
                                "query_intent": "broad_recall",
                                "pattern": "{topic} ai security",
                            }
                        ],
                    ),
                }
            )
        return output
