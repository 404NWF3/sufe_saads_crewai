from __future__ import annotations

from typing import Any

from ..schemas.coverage import CoverageGapCandidateDTO


class GapScoringService:
    def score_taxonomy_gaps(
        self, coverage_rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for row in coverage_rows:
            taxonomy_code = str(row.get("taxonomy_code") or "OWASP-LLM-UNKNOWN")
            bucket = grouped.setdefault(
                taxonomy_code,
                {
                    "taxonomy_code": taxonomy_code,
                    "taxonomy_name": row.get("taxonomy_name") or taxonomy_code,
                    "attack_family": row.get("attack_family"),
                    "stable_attack_ids": set(),
                    "source_names": set(),
                    "component_families": set(),
                    "corroborated_attack_ids": set(),
                    "high_severity_attack_ids": set(),
                },
            )
            bucket["stable_attack_ids"].update(
                str(item) for item in row.get("stable_attack_ids", []) if item
            )
            bucket["source_names"].add(str(row.get("source_name") or "unknown"))
            if row.get("component_family"):
                bucket["component_families"].add(str(row.get("component_family")))
            bucket["corroborated_attack_ids"].update(
                str(item) for item in row.get("corroborated_attack_ids", []) if item
            )
            bucket["high_severity_attack_ids"].update(
                str(item) for item in row.get("high_severity_attack_ids", []) if item
            )

        gaps: list[dict[str, Any]] = []
        for bucket in grouped.values():
            current = len(bucket["stable_attack_ids"])
            target = 3
            gap_score = round(min(1.0, max(0.0, (target - current) / target)), 4)
            source_gap = round(
                min(1.0, max(0.0, (3 - len(bucket["source_names"])) / 3)), 4
            )
            component_gap = round(
                min(1.0, max(0.0, (2 - len(bucket["component_families"])) / 2)), 4
            )
            corroboration_gap = round(
                min(
                    1.0,
                    max(
                        0.0,
                        1.0
                        - (len(bucket["corroborated_attack_ids"]) / max(current, 1)),
                    ),
                ),
                4,
            )
            severity_pressure = round(
                min(1.0, len(bucket["high_severity_attack_ids"]) / max(current, 1)),
                4,
            )
            recent_activity = round(min(1.0, current / 3), 4)
            roi = round(
                min(
                    1.0,
                    0.35 * gap_score
                    + 0.2 * source_gap
                    + 0.15 * component_gap
                    + 0.15 * corroboration_gap
                    + 0.15 * severity_pressure,
                ),
                4,
            )
            gaps.append(
                CoverageGapCandidateDTO(
                    gap_id=f"taxonomy::{bucket['taxonomy_code']}",
                    gap_axis="taxonomy",
                    taxonomy_code=bucket["taxonomy_code"],
                    taxonomy_name=bucket["taxonomy_name"],
                    attack_family=bucket.get("attack_family"),
                    current_attack_count=current,
                    target_attack_count=target,
                    gap_score=gap_score,
                    source_diversity_gap=source_gap,
                    component_coverage_gap=component_gap,
                    corroboration_gap=corroboration_gap,
                    vendor_model_gap=0.0,
                    severity_pressure=severity_pressure,
                    recent_activity_score=recent_activity,
                    estimated_gap_fill_roi=roi,
                    evidence_summary=f"taxonomy={bucket['taxonomy_code']} attacks={current} sources={len(bucket['source_names'])}",
                ).model_dump(mode="python")
            )
        return gaps

    def score_vendor_model_gaps(
        self, vendor_rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for row in vendor_rows:
            family = str(
                row.get("vendor_name")
                or row.get("model_family")
                or row.get("framework_family")
                or "unknown"
            )
            taxonomy_code = str(row.get("taxonomy_code") or "OWASP-LLM-UNKNOWN")
            taxonomy_name = str(row.get("taxonomy_name") or taxonomy_code)
            framework_family = row.get("framework_family")
            group_key = (
                family,
                taxonomy_code,
                str(framework_family or ""),
            )
            bucket = grouped.setdefault(
                "::".join(group_key),
                {
                    "family": family,
                    "taxonomy_code": taxonomy_code,
                    "taxonomy_name": taxonomy_name,
                    "vendor_name": row.get("vendor_name"),
                    "model_family": row.get("model_family"),
                    "framework_family": framework_family,
                    "stable_attack_ids": set(),
                    "source_names": set(),
                    "corroborated_attack_ids": set(),
                    "high_severity_attack_ids": set(),
                },
            )
            bucket["stable_attack_ids"].update(
                str(item) for item in row.get("stable_attack_ids", []) if item
            )
            bucket["source_names"].add(str(row.get("source_name") or "unknown"))
            bucket["corroborated_attack_ids"].update(
                str(item) for item in row.get("corroborated_attack_ids", []) if item
            )
            bucket["high_severity_attack_ids"].update(
                str(item) for item in row.get("high_severity_attack_ids", []) if item
            )

        gaps: list[dict[str, Any]] = []
        for bucket in grouped.values():
            family = bucket["family"]
            current = len(bucket["stable_attack_ids"])
            vendor_gap = round(min(1.0, max(0.0, (2 - current) / 2)), 4)
            source_gap = round(
                min(1.0, max(0.0, (3 - len(bucket["source_names"])) / 3)), 4
            )
            corroboration_gap = round(
                min(
                    1.0,
                    max(
                        0.0,
                        1.0
                        - (len(bucket["corroborated_attack_ids"]) / max(current, 1)),
                    ),
                ),
                4,
            )
            severity_pressure = round(
                min(1.0, len(bucket["high_severity_attack_ids"]) / max(current, 1)),
                4,
            )
            roi = round(
                min(
                    1.0,
                    0.4 * vendor_gap
                    + 0.2 * source_gap
                    + 0.2 * corroboration_gap
                    + 0.2 * severity_pressure,
                ),
                4,
            )
            gaps.append(
                CoverageGapCandidateDTO(
                    gap_id=(
                        "vendor_model::"
                        f"{family.lower().replace(' ', '_')}::"
                        f"{bucket['taxonomy_code'].lower().replace(' ', '_')}"
                    ),
                    gap_axis="vendor_model",
                    taxonomy_code=bucket["taxonomy_code"],
                    taxonomy_name=bucket["taxonomy_name"],
                    vendor_name=bucket.get("vendor_name"),
                    model_family=bucket.get("model_family"),
                    framework_family=bucket.get("framework_family"),
                    current_attack_count=current,
                    target_attack_count=2,
                    gap_score=vendor_gap,
                    source_diversity_gap=source_gap,
                    component_coverage_gap=0.0,
                    corroboration_gap=corroboration_gap,
                    vendor_model_gap=vendor_gap,
                    severity_pressure=severity_pressure,
                    recent_activity_score=round(min(1.0, current / 2), 4),
                    estimated_gap_fill_roi=roi,
                    evidence_summary=(
                        f"vendor/model={family} taxonomy={bucket['taxonomy_code']} "
                        f"attacks={current} sources={len(bucket['source_names'])}"
                    ),
                ).model_dump(mode="python")
            )
        return gaps

    def rank_gap_candidates(
        self, candidates: list[dict[str, Any]], *, max_candidates: int = 8
    ) -> list[dict[str, Any]]:
        return sorted(
            candidates,
            key=lambda row: (
                float(row.get("estimated_gap_fill_roi", 0.0)),
                float(row.get("gap_score", 0.0)),
            ),
            reverse=True,
        )[:max_candidates]
