from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from typing import Any

from ..schemas.intel import BomResolutionReviewDTO
from ..tools import LangChainLlmBomReviewer, normalize_vendor_name


class BomResolutionReviewerAgent:
    def __init__(
        self,
        *,
        strategy: str = "llm_required",
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        llm_runtime_config: dict[str, Any] | None = None,
        max_concurrency: int = 4,
    ) -> None:
        self.strategy = strategy
        self.max_concurrency = max_concurrency
        self.llm_runtime_config = llm_runtime_config or {}
        self._llm: LangChainLlmBomReviewer | None = None
        if strategy in ("llm_required", "llm_optional"):
            self._llm = LangChainLlmBomReviewer(
                model=llm_model,
                temperature=llm_temperature,
                runtime_config=self.llm_runtime_config,
            )
            if validate_online and strategy == "llm_required":
                self._llm.validate_connectivity()

    def review_batch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        def _review_one(item: dict[str, Any]) -> tuple[dict[str, Any], int]:
            reviewed = deepcopy(item)
            attack_context = {
                "attack_name": reviewed.get("canonical_name", ""),
                "attack_family": reviewed.get("attack_family", ""),
                "attack_summary": reviewed.get("summary", "")
                or reviewed.get("description", ""),
            }
            evidence_text = (
                reviewed.get("evidence_snippet", "")
                or reviewed.get("description", "")
                or reviewed.get("summary", "")
            )
            resolutions: list[dict[str, Any]] = []
            item_queue_count = 0
            for resolution in reviewed.get("bom_resolutions", []):
                checked = self.review_resolution(
                    resolution,
                    attack_context=attack_context,
                    evidence_text=evidence_text,
                )
                if checked.get("resolution_status") != "resolved":
                    item_queue_count += 1
                resolutions.append(checked)
            reviewed["bom_resolutions"] = resolutions
            reviewed["source_metadata"] = {
                **reviewed.get("source_metadata", {}),
                "bom_review_summary": {
                    "accepted": sum(
                        1
                        for resolution in resolutions
                        if (resolution.get("review") or {}).get("decision") == "accept"
                    ),
                    "revised": sum(
                        1
                        for resolution in resolutions
                        if (resolution.get("review") or {}).get("decision") == "revise"
                    ),
                    "review_queue": sum(
                        1
                        for resolution in resolutions
                        if resolution.get("resolution_status") != "resolved"
                    ),
                },
            }
            return reviewed, item_queue_count

        max_workers = min(self.max_concurrency, max(1, len(items)))
        results: list[tuple[dict[str, Any], int]] = [None] * len(items)  # type: ignore[list-item]
        if max_workers == 1:
            for idx, item in enumerate(items):
                results[idx] = _review_one(item)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_idx = {
                    executor.submit(_review_one, item): i for i, item in enumerate(items)
                }
                for future in as_completed(future_to_idx):
                    results[future_to_idx[future]] = future.result()

        reviewed_items = [r[0] for r in results]
        queue_count = sum(r[1] for r in results)
        return {
            "standardized_items": reviewed_items,
            "bom_queue_count": queue_count,
        }

    def review_resolution(
        self,
        resolution: dict[str, Any],
        *,
        attack_context: dict[str, Any] | None = None,
        evidence_text: str = "",
    ) -> dict[str, Any]:
        if self._llm is not None:
            try:
                return self._llm_review_resolution(
                    resolution,
                    attack_context=attack_context or {},
                    evidence_text=evidence_text,
                )
            except Exception:
                if self.strategy == "llm_required":
                    raise
        return self._heuristic_review_resolution(resolution)

    def _llm_review_resolution(
        self,
        resolution: dict[str, Any],
        *,
        attack_context: dict[str, Any],
        evidence_text: str,
    ) -> dict[str, Any]:
        if self._llm is None:
            raise RuntimeError("LLM BOM reviewer is not initialized.")
        checked = deepcopy(resolution)
        if checked.get("resolution_status") != "resolved" or checked.get(
            "selected_component"
        ) is None:
            review = BomResolutionReviewDTO(
                decision="review_queue",
                confidence=0.0,
                reasons=["no confident component resolution available"],
                ambiguity_notes=[],
                review_trace=[
                    "No accepted component candidate was available for publication.",
                ],
                component_suggestion=None,
            ).model_dump(mode="python")
            checked["review"] = review
            checked["resolution_status"] = "review_queue"
            return checked

        review = self._llm.review(
            {
                **attack_context,
                "resolution_json": json.dumps(checked, ensure_ascii=False),
                "candidate_list_json": json.dumps(
                    checked.get("candidate_components", []),
                    ensure_ascii=False,
                ),
                "evidence_text": evidence_text,
            }
        )
        checked["review"] = BomResolutionReviewDTO.model_validate(review).model_dump(
            mode="python"
        )
        if checked["review"]["decision"] != "accept":
            checked["resolution_status"] = "review_queue"
            suggestion = checked["review"].get("component_suggestion")
            if checked["review"]["decision"] == "revise" and suggestion:
                checked["selected_component"] = suggestion
        return checked

    def _heuristic_review_resolution(self, resolution: dict[str, Any]) -> dict[str, Any]:
        checked = deepcopy(resolution)
        reasons: list[str] = []
        ambiguity_notes: list[str] = []
        review_trace: list[str] = []
        decision = "accept"
        selected = checked.get("selected_component")
        candidates = list(checked.get("candidate_components", []))

        # Detect whether this resolution came from LLM
        llm_resolved = any(
            "llm_reason:" in rc or "llm_no_match" in rc or "llm_low_confidence" in rc
            for rc in checked.get("reason_codes", [])
        )

        if checked.get("resolution_status") == "unresolved" or selected is None:
            decision = "review_queue"
            reasons.append("no confident component resolution available")
            review_trace.append("Reviewer found no resolved component candidate to publish.")
        else:
            mentioned_vendor = normalize_vendor_name(checked.get("mentioned_vendor"))

            # --- LLM-resolved high-confidence accept: skip heuristic downgrades ---
            # When LLM resolved with high confidence and accept decision, the
            # reviewer trusts the LLM's semantic judgment more than retrieval
            # score heuristics.  We still check vendor mismatch and version
            # ambiguity but skip the fuzzy-threshold and candidate-gap rules.
            llm_high_confidence = (
                llm_resolved
                and float(checked.get("match_confidence", 0.0)) >= 0.85
                and checked.get("resolution_status") == "resolved"
            )

            if checked.get("match_mode") == "embedding" and not llm_high_confidence:
                alias_candidate = self._find_mode_candidate(
                    candidates, {"exact", "alias"}
                )
                if alias_candidate is not None and float(
                    alias_candidate.get("final_score", 0.0)
                ) >= max(0.82, float(selected.get("final_score", 0.0)) - 0.08):
                    selected = alias_candidate
                    checked["selected_component"] = alias_candidate
                    checked["match_mode"] = alias_candidate.get("match_mode")
                    checked["match_confidence"] = float(
                        alias_candidate.get("final_score", 0.0)
                    )
                    decision = "revise"
                    reasons.append(
                        "reviewer replaced embedding-first candidate with stronger alias match"
                    )
                    review_trace.append(
                        "Embedding-led choice was replaced by a stronger alias-backed candidate."
                    )
            selected_vendor = normalize_vendor_name(selected.get("vendor_name"))
            if (
                mentioned_vendor
                and selected_vendor
                and mentioned_vendor != selected_vendor
            ):
                alternate = self._find_vendor_aligned_candidate(
                    candidates, mentioned_vendor
                )
                if alternate is not None:
                    selected = alternate
                    checked["selected_component"] = alternate
                    checked["match_mode"] = alternate.get("match_mode")
                    checked["match_confidence"] = float(
                        alternate.get("final_score", 0.0)
                    )
                    decision = "revise"
                    reasons.append(
                        "reviewer swapped to vendor-aligned component candidate"
                    )
                    review_trace.append(
                        "Reviewer found a candidate aligned with the vendor mention."
                    )
                else:
                    decision = "review_queue"
                    reasons.append(
                        "selected component vendor conflicts with mention vendor"
                    )
                    review_trace.append(
                        "Vendor evidence conflicts with the selected component."
                    )
            if checked.get("mentioned_version") and not checked.get(
                "normalized_version_constraint"
            ):
                decision = "review_queue"
                reasons.append("version constraint remains ambiguous")
                review_trace.append(
                    "Version constraint could not be normalized reliably."
                )

            # --- Heuristic candidate-gap and fuzzy checks (skip for LLM high-confidence) ---
            if not llm_high_confidence:
                if len(candidates) > 1:
                    ranked_candidates = sorted(
                        candidates,
                        key=lambda candidate: float(candidate.get("final_score", 0.0)),
                        reverse=True,
                    )
                    first = float(ranked_candidates[0].get("final_score", 0.0))
                    second = float(ranked_candidates[1].get("final_score", 0.0))
                    if first - second < 0.05 and first < 0.9:
                        decision = "review_queue"
                        ambiguity_notes.append(
                            "multiple component candidates remain too close"
                        )
                        review_trace.append(
                            "Top candidates remain too close for automatic publication."
                        )
                if (
                    checked.get("match_mode") in {"trigram", "embedding"}
                    and float(checked.get("match_confidence", 0.0)) < 0.85
                ):
                    decision = "review_queue"
                    ambiguity_notes.append("fuzzy-only match needs manual confirmation")
                    review_trace.append(
                        "Only fuzzy matching supported the resolution."
                    )
                if len(str(checked.get("normalized_alias", ""))) < 4 and checked.get(
                    "match_mode"
                ) not in {
                    "exact",
                    "alias",
                }:
                    decision = "review_queue"
                    ambiguity_notes.append("alias normalization may be too coarse")
                    review_trace.append(
                        "Alias normalization is too coarse for safe auto-publication."
                    )
            elif llm_high_confidence:
                reasons.append("llm high-confidence resolution accepted by reviewer")
                review_trace.append(
                    "LLM and retrieval confidence jointly support the selected component."
                )

        if decision == "review_queue":
            checked["resolution_status"] = "review_queue"
        confidence = min(
            float(checked.get("match_confidence", 0.0) or 0.0),
            0.95 if decision == "accept" else 0.55,
        )
        review = BomResolutionReviewDTO(
            decision=decision,
            confidence=confidence,
            reasons=reasons or ["resolution passes reviewer checks"],
            ambiguity_notes=ambiguity_notes,
            review_trace=review_trace or ["Reviewer found no blocking issues."],
            component_suggestion=selected,
        ).model_dump(mode="python")
        checked["review"] = review
        return checked

    def _find_vendor_aligned_candidate(
        self,
        candidates: list[dict[str, Any]],
        mentioned_vendor: str,
    ) -> dict[str, Any] | None:
        for candidate in candidates:
            if normalize_vendor_name(candidate.get("vendor_name")) == mentioned_vendor:
                return candidate
        return None

    def _find_mode_candidate(
        self,
        candidates: list[dict[str, Any]],
        target_modes: set[str],
    ) -> dict[str, Any] | None:
        ranked_candidates = sorted(
            candidates,
            key=lambda candidate: float(candidate.get("final_score", 0.0)),
            reverse=True,
        )
        for candidate in ranked_candidates:
            if candidate.get("match_mode") in target_modes:
                return candidate
        return None
