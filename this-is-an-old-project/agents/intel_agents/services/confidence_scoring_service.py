from __future__ import annotations

from copy import deepcopy
from typing import Any

from ..schemas.intel import ConfidenceScoreBreakdownDTO


class ConfidenceScoringService:
    def score_items(
        self,
        items: list[dict[str, Any]],
        *,
        dedup_decisions: list[dict[str, Any]] | None = None,
        source_quality_rows: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        quality_by_source = {
            str(row.get("source_name")): float(row.get("trust_level", 0.0))
            for row in (source_quality_rows or [])
        }
        dedup_by_audit = {
            str(row.get("merge_audit_ref")): row
            for row in (dedup_decisions or [])
            if row.get("merge_audit_ref")
        }
        scored: list[dict[str, Any]] = []
        for item in items:
            enriched = deepcopy(item)
            source_name = str(
                enriched.get("source_metadata", {}).get("source_name", "")
            )
            source_trust = quality_by_source.get(
                source_name, float(enriched.get("source_confidence", 0.0))
            )
            dedup = dedup_by_audit.get(str(enriched.get("merge_audit_ref")), {})
            dedup_certainty = self._dedup_certainty(dedup)
            bom_confidence = self._bom_resolution_confidence(
                enriched.get("bom_resolutions", [])
            )
            evidence_density = min(
                1.0, round(len(enriched.get("evidence_refs", [])) / 4.0, 4)
            )
            source_diversity_bonus = min(
                0.15,
                round(
                    max(
                        0,
                        len(
                            enriched.get("source_metadata", {}).get(
                                "source_coverage", []
                            )
                        )
                        - 1,
                    )
                    * 0.05,
                    4,
                ),
            )
            final_confidence = round(
                min(
                    1.0,
                    source_trust * 0.22
                    + float(enriched.get("extraction_confidence", 0.0)) * 0.2
                    + dedup_certainty * 0.18
                    + bom_confidence * 0.22
                    + evidence_density * 0.18
                    + source_diversity_bonus,
                ),
                4,
            )
            novelty_score = round(
                self._novelty_score(
                    dedup_decision=str(
                        enriched.get("dedup_decision", dedup.get("decision", "new"))
                    ),
                    source_diversity_bonus=source_diversity_bonus,
                    unresolved_count=sum(
                        1
                        for resolution in enriched.get("bom_resolutions", [])
                        if resolution.get("resolution_status") != "resolved"
                    ),
                    has_conflicts=bool(enriched.get("conflict_flags")),
                ),
                4,
            )
            breakdown = ConfidenceScoreBreakdownDTO(
                source_trust=round(source_trust, 4),
                extraction_confidence=round(
                    float(enriched.get("extraction_confidence", 0.0)), 4
                ),
                dedup_certainty=dedup_certainty,
                bom_resolution_confidence=bom_confidence,
                evidence_density=evidence_density,
                source_diversity_bonus=source_diversity_bonus,
                final_confidence=final_confidence,
                novelty_score=novelty_score,
            ).model_dump(mode="python")
            enriched["confidence_breakdown"] = breakdown
            enriched["confidence_score"] = final_confidence
            enriched["novelty_score"] = novelty_score
            scored.append(enriched)
        return scored

    def _dedup_certainty(self, dedup: dict[str, Any]) -> float:
        decision = str(dedup.get("decision", "new"))
        similarity = float(dedup.get("similarity_score", 0.0))
        if decision == "merge":
            return round(max(0.45, similarity), 4)
        if decision == "review":
            return round(min(0.6, max(0.35, similarity)), 4)
        return round(max(0.68, 1.0 - similarity * 0.25), 4)

    def _bom_resolution_confidence(self, resolutions: list[dict[str, Any]]) -> float:
        if not resolutions:
            return 0.35
        scores: list[float] = []
        for resolution in resolutions:
            base = float(resolution.get("match_confidence", 0.0))
            status = resolution.get("resolution_status")
            review = (resolution.get("review") or {}).get("decision")
            if status == "resolved":
                score = base
            elif status == "review_queue":
                score = base * 0.55
            else:
                score = max(0.1, base * 0.25)
            if review == "accept":
                score += 0.05
            elif review == "revise":
                score += 0.02
            elif review == "review_queue":
                score -= 0.08
            scores.append(max(0.0, min(1.0, score)))
        return round(sum(scores) / len(scores), 4)

    def _novelty_score(
        self,
        *,
        dedup_decision: str,
        source_diversity_bonus: float,
        unresolved_count: int,
        has_conflicts: bool,
    ) -> float:
        base_map = {"new": 0.72, "review": 0.56, "merge": 0.38}
        score = base_map.get(dedup_decision, 0.5)
        score += source_diversity_bonus * 0.4
        score -= unresolved_count * 0.08
        score += -0.06 if has_conflicts else 0.04
        return max(0.0, min(1.0, score))
