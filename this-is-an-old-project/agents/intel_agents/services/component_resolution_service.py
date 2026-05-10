from __future__ import annotations

from copy import deepcopy
from typing import Any

from backend.db.repositories.component_repository import normalize_component_alias
from backend.db.services.component_seed_service import AiComponentSeedService
from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork

from ..schemas.intel import BomCandidateDTO, BomResolutionDTO
from ..tools import (
    cosine_similarity,
    generate_embedding,
    normalize_vendor_name,
    normalize_version_constraint,
    trigram_similarity,
)


_DEFAULT_COMPONENT_CATALOG: list[dict[str, Any]] = (
    AiComponentSeedService.default_seeds()
)


class ComponentResolutionService:
    def __init__(self, component_catalog: list[dict[str, Any]] | None = None) -> None:
        self.component_catalog = deepcopy(
            component_catalog or _DEFAULT_COMPONENT_CATALOG
        )

    # ------------------------------------------------------------------
    # Candidate-retrieval-only API (for LLM-primary path)
    # ------------------------------------------------------------------

    def retrieve_candidates_for_mention(
        self,
        mention: dict[str, Any],
        *,
        uow: UnitOfWork | None = None,
    ) -> dict[str, Any]:
        """Retrieve top-k candidates for a single BOM mention WITHOUT making
        a resolution decision.  Returns a dict containing normalized fields
        and the ranked candidate list.

        This is the entry point for the LLM-primary BOM resolution path:
        the caller passes these candidates to the LLM for final judgment.
        """
        mentioned_name = str(mention.get("mentioned_name", "")).strip()
        mentioned_vendor = mention.get("mentioned_vendor")
        normalized_vendor = normalize_vendor_name(mentioned_vendor)
        normalized_alias = normalize_component_alias(mentioned_name)
        vendor_scoped_alias = (
            normalize_component_alias(mentioned_name, mentioned_vendor)
            if mentioned_vendor
            else normalized_alias
        )
        normalized_version = normalize_version_constraint(
            mention.get("mentioned_version")
        )
        candidate_components = self._rank_candidates(
            mentioned_name=mentioned_name,
            normalized_alias=normalized_alias,
            vendor_scoped_alias=vendor_scoped_alias,
            mentioned_vendor=mentioned_vendor,
            normalized_vendor=normalized_vendor,
            uow=uow,
        )
        return {
            "mentioned_name": mentioned_name,
            "mentioned_vendor": mentioned_vendor,
            "mentioned_version": mention.get("mentioned_version"),
            "normalized_alias": vendor_scoped_alias or normalized_alias,
            "normalized_vendor": normalized_vendor,
            "normalized_version_constraint": normalized_version,
            "component_layer_hint": mention.get("component_layer", "unknown"),
            "candidates": candidate_components,
        }

    def persist_llm_resolution(
        self,
        *,
        mention: dict[str, Any],
        llm_decision: dict[str, Any],
        candidates: list[dict[str, Any]],
        evidence_uri: str | None,
        attack_id: str | None,
        uow: UnitOfWork | None,
        mention_id: str | None = None,
        raw_id: str | None = None,
        evidence_snippet: str | None = None,
        review_status: str = "accepted",
        resolver_strategy: str = "llm_primary",
    ) -> dict[str, Any]:
        built = self.build_llm_resolution(
            mention=mention,
            llm_decision=llm_decision,
            candidates=candidates,
        )
        return self.persist_reviewed_resolution(
            resolution=built,
            attack_id=attack_id,
            uow=uow,
            mention_id=mention_id,
            raw_id=raw_id,
            evidence_uri=evidence_uri,
            evidence_snippet=evidence_snippet,
            review_status=review_status,
            resolver_strategy=resolver_strategy,
        )

    def build_llm_resolution(
        self,
        *,
        mention: dict[str, Any],
        llm_decision: dict[str, Any],
        candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        mentioned_name = str(mention.get("mentioned_name", "")).strip()
        mentioned_vendor = mention.get("mentioned_vendor")
        normalized_vendor = normalize_vendor_name(mentioned_vendor)
        normalized_alias = normalize_component_alias(mentioned_name)
        vendor_scoped_alias = (
            normalize_component_alias(mentioned_name, mentioned_vendor)
            if mentioned_vendor
            else normalized_alias
        )
        normalized_version = normalize_version_constraint(
            mention.get("mentioned_version")
        )

        decision = llm_decision.get("decision", "review_queue")
        llm_component = llm_decision.get("selected_component")
        llm_version = llm_decision.get("normalized_version_constraint")
        confidence = float(llm_decision.get("confidence", 0.0))

        # Map LLM decision to resolution_status
        if decision == "accept":
            resolution_status = "resolved"
        elif decision == "no_match":
            resolution_status = "unresolved"
        else:
            resolution_status = "review_queue"

        # Find the matching candidate in our retrieval results
        selected: dict[str, Any] | None = None
        match_mode: str | None = None
        if llm_component and candidates:
            sel_code = llm_component.get("component_code")
            sel_name = llm_component.get("component_name", "")
            for candidate in candidates:
                if sel_code and candidate.get("component_code") == sel_code:
                    selected = candidate
                    break
                if candidate.get("component_name") == sel_name:
                    selected = candidate
                    break
            if selected is None and candidates:
                # LLM picked something not in candidates; use top candidate
                # but downgrade to review_queue
                selected = candidates[0]
                resolution_status = "review_queue"
            if selected:
                match_mode = selected.get("match_mode")

        # Override version with LLM output if available
        final_version = llm_version or normalized_version

        reason_codes: list[str] = []
        queue_ref: str | None = None

        if resolution_status == "unresolved":
            reason_codes.append("llm_no_match")
        elif resolution_status == "review_queue":
            reason_codes.append("llm_low_confidence")

        # LLM evidence and reasoning as reason codes
        reasoning = llm_decision.get("reasoning_summary", "")
        if reasoning:
            reason_codes.append(f"llm_reason:{reasoning[:120]}")

        return BomResolutionDTO(
            mentioned_name=mentioned_name,
            mentioned_vendor=mentioned_vendor,
            mentioned_version=mention.get("mentioned_version"),
            normalized_alias=vendor_scoped_alias or normalized_alias,
            normalized_vendor=normalized_vendor,
            normalized_version_constraint=final_version,
            resolution_status=resolution_status,
            selected_component=selected,
            candidate_components=[
                BomCandidateDTO.model_validate(candidate) for candidate in candidates
            ],
            match_mode=match_mode,
            match_confidence=confidence,
            reason_codes=reason_codes,
            queue_ref=queue_ref,
            review=None,
        ).model_dump(mode="python")

    def persist_reviewed_resolution(
        self,
        *,
        resolution: dict[str, Any],
        attack_id: str | None,
        uow: UnitOfWork | None,
        mention_id: str | None = None,
        raw_id: str | None = None,
        evidence_uri: str | None = None,
        evidence_snippet: str | None = None,
        review_status: str = "accepted",
        resolver_strategy: str = "llm_primary",
    ) -> dict[str, Any]:
        final_resolution = deepcopy(resolution)
        review = dict(final_resolution.get("review") or {})
        reason_codes = list(final_resolution.get("reason_codes", []) or [])
        selected = self._resolve_selected_candidate(
            review.get("component_suggestion") or final_resolution.get("selected_component"),
            final_resolution.get("candidate_components", []),
        )
        queue_ref: str | None = None

        review_decision = str(review.get("decision") or "")
        if review_decision == "review_queue" and "llm_low_confidence" not in reason_codes:
            reason_codes.append("llm_low_confidence")
        if review_decision == "revise" and "reviewer_rejected" not in reason_codes:
            reason_codes.append("reviewer_rejected")
        if (
            final_resolution.get("resolution_status") != "resolved"
            and selected is None
            and "missing_evidence" not in reason_codes
        ):
            reason_codes.append("missing_evidence")

        if review_decision in {"review_queue", "revise"}:
            final_resolution["resolution_status"] = "review_queue"

        should_persist_selected = (
            selected is not None
            and attack_id is not None
            and uow is not None
            and final_resolution.get("resolution_status") in {"resolved", "review_queue"}
        )
        should_enqueue_review = (
            final_resolution.get("resolution_status") != "resolved"
            or review_status != "accepted"
        )

        if should_persist_selected:
            component_id = self._ensure_component(selected, uow=uow)
            if component_id is not None:
                uow.components.upsert_attack_component_impact(
                    attack_id=attack_id,
                    component_id=component_id,
                    mention_id=mention_id,
                    source_raw_id=raw_id,
                    version_constraint_raw=final_resolution.get("mentioned_version"),
                    normalized_constraint=final_resolution.get("normalized_version_constraint"),
                    match_mode=(
                        final_resolution.get("match_mode")
                        or selected.get("match_mode")
                        or "alias"
                    ),
                    impact_scope="direct",
                    review_status=review_status,
                    resolver_strategy=resolver_strategy,
                    confidence_score=float(final_resolution.get("match_confidence", 0.0) or 0.0),
                    evidence_uri=evidence_uri,
                    evidence_snippet=evidence_snippet,
                )
                selected = {**selected, "component_id": component_id}
        if should_enqueue_review and uow:
            queue_item = uow.governance.enqueue_bom_resolution(
                attack_id=attack_id,
                raw_id=raw_id,
                mention_id=mention_id,
                mentioned_name=str(final_resolution.get("mentioned_name", "")),
                mentioned_vendor=final_resolution.get("mentioned_vendor"),
                mentioned_version=final_resolution.get("mentioned_version"),
                reason_code=self._queue_reason_code(reason_codes, review=review),
                candidate_snapshot={
                    "resolution": final_resolution,
                    "selected_component": selected,
                    "review": review,
                },
                reasoning_summary=(
                    str(review.get("reasons", [""])[:1][0]).strip()
                    or str(final_resolution.get("reason_codes", [""])[:1][0]).strip()
                    or None
                ),
            )
            queue_ref = str(queue_item.queue_id)

        final_resolution["selected_component"] = selected
        final_resolution["reason_codes"] = list(dict.fromkeys(reason_codes))
        final_resolution["queue_ref"] = queue_ref
        return BomResolutionDTO.model_validate(final_resolution).model_dump(mode="python")

    # ------------------------------------------------------------------
    # Rules-only resolution API (backward-compatible)
    # ------------------------------------------------------------------

    def resolve_item(
        self,
        item: dict[str, Any],
        *,
        trace_id: str | None = None,
    ) -> tuple[dict[str, Any], int]:
        result = self._resolve_item(item, uow=None)
        try:
            with UnitOfWork(
                context=SqlContext(trace_id=trace_id, agent_name="bom_mapper_agent")
            ) as uow:
                AiComponentSeedService(uow).ensure_seeded(trace_id=trace_id)
                result = self._resolve_item(item, uow=uow)
        except Exception as exc:
            fallback_item, fallback_queue_count = result
            fallback_item["source_metadata"] = {
                **fallback_item.get("source_metadata", {}),
                "bom_resolution_db_fallback": {
                    "active": True,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc)[:300],
                },
            }
            return fallback_item, fallback_queue_count
        return result

    def _resolve_item(
        self,
        item: dict[str, Any],
        *,
        uow: UnitOfWork | None,
    ) -> tuple[dict[str, Any], int]:
        updated = deepcopy(item)
        attack_id = self._lookup_attack_id(updated, uow=uow)
        resolutions: list[dict[str, Any]] = []
        unresolved_mentions: list[dict[str, Any]] = []
        queue_count = 0
        for mention in updated.get("bom_mentions", []):
            resolution = self._resolve_mention(
                mention,
                evidence_uri=next(iter(updated.get("evidence_refs", []) or []), None),
                attack_id=attack_id,
                uow=uow,
            )
            if resolution["resolution_status"] != "resolved":
                queue_count += 1
                unresolved_mentions.append(
                    {
                        "mentioned_name": resolution["mentioned_name"],
                        "mentioned_vendor": resolution.get("mentioned_vendor"),
                        "reason_codes": resolution.get("reason_codes", []),
                        "queue_ref": resolution.get("queue_ref"),
                        "top_candidate": (
                            resolution.get("selected_component") or {}
                        ).get("component_name"),
                    }
                )
            resolutions.append(resolution)
        updated["bom_resolutions"] = resolutions
        updated["source_metadata"] = {
            **updated.get("source_metadata", {}),
            "bom_resolution_summary": {
                "resolved": sum(
                    1
                    for resolution in resolutions
                    if resolution["resolution_status"] == "resolved"
                ),
                "queued": queue_count,
                "unresolved_mentions": unresolved_mentions,
            },
        }
        return updated, queue_count

    def _resolve_mention(
        self,
        mention: dict[str, Any],
        *,
        evidence_uri: str | None,
        attack_id: str | None,
        uow: UnitOfWork | None,
    ) -> dict[str, Any]:
        mentioned_name = str(mention.get("mentioned_name", "")).strip()
        mentioned_vendor = mention.get("mentioned_vendor")
        normalized_vendor = normalize_vendor_name(mentioned_vendor)
        normalized_alias = normalize_component_alias(mentioned_name)
        vendor_scoped_alias = (
            normalize_component_alias(mentioned_name, mentioned_vendor)
            if mentioned_vendor
            else normalized_alias
        )
        normalized_version = normalize_version_constraint(
            mention.get("mentioned_version")
        )
        candidate_components = self._rank_candidates(
            mentioned_name=mentioned_name,
            normalized_alias=normalized_alias,
            vendor_scoped_alias=vendor_scoped_alias,
            mentioned_vendor=mentioned_vendor,
            normalized_vendor=normalized_vendor,
            uow=uow,
        )
        selected = candidate_components[0] if candidate_components else None
        second = candidate_components[1] if len(candidate_components) > 1 else None
        gap = round(
            float(selected.get("final_score", 0.0))
            - float(second.get("final_score", 0.0))
            if second and selected
            else 1.0,
            4,
        )
        reason_codes: list[str] = []
        queue_ref: str | None = None
        resolution_status = "unresolved"
        if selected is None or float(selected.get("final_score", 0.0)) < 0.58:
            reason_codes.append("alias_not_found")
        elif (
            selected.get("match_mode") in {"exact", "alias"}
            and float(selected.get("final_score", 0.0)) >= 0.94
        ):
            resolution_status = "resolved"
        elif float(selected.get("final_score", 0.0)) >= 0.9 and gap >= 0.05:
            resolution_status = "resolved"
        elif (
            float(selected.get("final_score", 0.0)) >= 0.8
            and selected.get("match_mode") in {"exact", "alias"}
            and (
                second is None
                or second.get("match_mode") not in {"exact", "alias"}
                or gap >= 0.01
            )
        ):
            resolution_status = "resolved"
        else:
            resolution_status = "review_queue"
            reason_codes.append("conflict")
        if mention.get("mentioned_version") and normalized_version is None:
            reason_codes.append("version_ambiguous")
            if resolution_status == "resolved":
                resolution_status = "review_queue"
        if selected is not None and selected.get("match_mode") in {
            "trigram",
            "embedding",
        }:
            reason_codes.append(f"fuzzy_match:{selected['match_mode']}")
        if (
            resolution_status == "resolved"
            and selected is not None
            and attack_id
            and uow
        ):
            component_id = self._ensure_component(selected, uow=uow)
            if component_id is not None:
                uow.components.upsert_attack_component_impact(
                    attack_id=attack_id,
                    component_id=component_id,
                    mention_id=None,
                    source_raw_id=mention.get("raw_id"),
                    version_constraint_raw=mention.get("mentioned_version"),
                    normalized_constraint=normalized_version,
                    match_mode=selected["match_mode"],
                    impact_scope="direct",
                    review_status="accepted",
                    resolver_strategy="rules_only",
                    confidence_score=float(selected["final_score"]),
                    evidence_uri=evidence_uri,
                    evidence_snippet=None,
                )
                selected["component_id"] = component_id
        elif resolution_status != "resolved" and uow:
            queue_item = uow.governance.enqueue_bom_resolution(
                attack_id=attack_id,
                raw_id=mention.get("raw_id"),
                mention_id=None,
                mentioned_name=mentioned_name,
                mentioned_vendor=mentioned_vendor,
                mentioned_version=mention.get("mentioned_version"),
                reason_code=self._queue_reason_code(reason_codes),
                candidate_snapshot={
                    "candidates": candidate_components,
                    "selected_component": selected,
                },
                reasoning_summary="rules_only_resolution",
            )
            queue_ref = str(queue_item.queue_id)
        return BomResolutionDTO(
            mentioned_name=mentioned_name,
            mentioned_vendor=mentioned_vendor,
            mentioned_version=mention.get("mentioned_version"),
            normalized_alias=vendor_scoped_alias or normalized_alias,
            normalized_vendor=normalized_vendor,
            normalized_version_constraint=normalized_version,
            resolution_status=resolution_status,
            selected_component=selected,
            candidate_components=[
                BomCandidateDTO.model_validate(candidate)
                for candidate in candidate_components
            ],
            match_mode=selected.get("match_mode") if selected else None,
            match_confidence=float(
                selected.get("final_score", 0.0) if selected else 0.0
            ),
            reason_codes=reason_codes,
            queue_ref=queue_ref,
            review=None,
        ).model_dump(mode="python")

    def _rank_candidates(
        self,
        *,
        mentioned_name: str,
        normalized_alias: str,
        vendor_scoped_alias: str,
        mentioned_vendor: str | None,
        normalized_vendor: str | None,
        uow: UnitOfWork | None,
    ) -> list[dict[str, Any]]:
        candidates = self._memory_candidates(
            mentioned_name=mentioned_name,
            normalized_alias=normalized_alias,
            vendor_scoped_alias=vendor_scoped_alias,
            normalized_vendor=normalized_vendor,
        )
        if uow is not None:
            candidates.extend(
                self._db_candidates(
                    mentioned_name=mentioned_name,
                    normalized_alias=normalized_alias,
                    vendor_scoped_alias=vendor_scoped_alias,
                    normalized_vendor=normalized_vendor,
                    uow=uow,
                )
            )
        deduped: dict[str, dict[str, Any]] = {}
        for candidate in candidates:
            key = str(
                candidate.get("component_id")
                or candidate.get("component_code")
                or candidate.get("component_name")
            )
            current = deduped.get(key)
            if current is None or float(candidate["final_score"]) > float(
                current["final_score"]
            ):
                deduped[key] = candidate
        return sorted(
            deduped.values(),
            key=lambda row: (float(row["final_score"]), float(row["match_score"])),
            reverse=True,
        )[:5]

    def _memory_candidates(
        self,
        *,
        mentioned_name: str,
        normalized_alias: str,
        vendor_scoped_alias: str,
        normalized_vendor: str | None,
    ) -> list[dict[str, Any]]:
        mention_embedding = generate_embedding(mentioned_name)
        results: list[dict[str, Any]] = []
        aliases_to_match = {normalized_alias, vendor_scoped_alias}
        for component in self.component_catalog:
            alias_names = [
                component["component_name"],
                *[
                    alias["alias_name"] if isinstance(alias, dict) else alias
                    for alias in component.get("aliases", [])
                ],
            ]
            normalized_candidates = {
                normalize_component_alias(alias)
                for alias in alias_names
                if normalize_component_alias(alias)
            }
            match_mode = "embedding"
            match_score = 0.0
            if (
                normalize_component_alias(component["component_name"])
                in aliases_to_match
            ):
                match_mode = "exact"
                match_score = 1.0
            elif aliases_to_match & normalized_candidates:
                match_mode = "alias"
                match_score = 0.97
            else:
                trigram_score = max(
                    trigram_similarity(alias, candidate_alias)
                    for alias in aliases_to_match
                    for candidate_alias in normalized_candidates
                )
                embedding_score = max(
                    cosine_similarity(mention_embedding, generate_embedding(alias_name))
                    for alias_name in alias_names
                )
                if trigram_score >= embedding_score:
                    match_mode = "trigram"
                    match_score = trigram_score
                else:
                    match_mode = "embedding"
                    match_score = embedding_score
            vendor_score = self._vendor_score(
                normalized_vendor, component.get("vendor_name")
            )
            final_score = self._final_candidate_score(
                match_mode=match_mode,
                match_score=match_score,
                vendor_score=vendor_score,
            )
            if final_score < 0.45:
                continue
            results.append(
                BomCandidateDTO.model_validate(
                    {
                        "component_id": None,
                        "component_code": component.get("component_code"),
                        "component_name": component["component_name"],
                        "vendor_name": component.get("vendor_name"),
                        "component_type": component.get("component_type"),
                        "component_modality": component.get("modality"),
                        "match_mode": match_mode,
                        "match_score": match_score,
                        "vendor_score": vendor_score,
                        "final_score": final_score,
                        "aliases": [
                            alias["alias_name"] if isinstance(alias, dict) else alias
                            for alias in component.get("aliases", [])
                        ],
                        "reasons": [
                            f"alias={normalized_alias}",
                            f"vendor_hint={normalized_vendor or 'none'}",
                        ],
                    }
                ).model_dump(mode="python")
            )
        return results

    def _db_candidates(
        self,
        *,
        mentioned_name: str,
        normalized_alias: str,
        vendor_scoped_alias: str,
        normalized_vendor: str | None,
        uow: UnitOfWork,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        direct = uow.components.get_component_by_name(mentioned_name)
        if direct is not None:
            seen_ids.add(str(direct.component_id))
            results.append(
                self._candidate_from_db_component(
                    component=direct,
                    match_mode="exact",
                    match_score=1.0,
                    normalized_vendor=normalized_vendor,
                )
            )
        for alias in [vendor_scoped_alias, normalized_alias]:
            if not alias:
                continue
            alias_match = uow.components.find_component_by_alias(alias)
            if alias_match is None or str(alias_match.component_id) in seen_ids:
                continue
            seen_ids.add(str(alias_match.component_id))
            results.append(
                self._candidate_from_db_component(
                    component=alias_match,
                    match_mode="alias",
                    match_score=0.97,
                    normalized_vendor=normalized_vendor,
                )
            )
        searched = uow.components.search_component_alias(
            vendor_scoped_alias or normalized_alias, limit=5
        )
        for row in searched:
            component_id = str(row.get("component_id"))
            if component_id in seen_ids:
                continue
            seen_ids.add(component_id)
            vendor_score = self._vendor_score(normalized_vendor, row.get("vendor_name"))
            match_score = round(float(row.get("similarity", 0.0)), 4)
            final_score = self._final_candidate_score(
                match_mode="trigram",
                match_score=match_score,
                vendor_score=vendor_score,
            )
            if final_score < 0.45:
                continue
            results.append(
                BomCandidateDTO.model_validate(
                    {
                        "component_id": component_id,
                        "component_code": row.get("component_code"),
                        "component_name": row.get("component_name") or component_id,
                        "vendor_name": row.get("vendor_name"),
                        "component_type": row.get("component_type"),
                        "component_modality": None,
                        "match_mode": "trigram",
                        "match_score": match_score,
                        "vendor_score": vendor_score,
                        "final_score": final_score,
                        "aliases": [str(row["alias_name"])]
                        if row.get("alias_name")
                        else [],
                        "reasons": ["db_alias_similarity"],
                    }
                ).model_dump(mode="python")
            )
        return results

    def _candidate_from_db_component(
        self,
        *,
        component: Any,
        match_mode: str,
        match_score: float,
        normalized_vendor: str | None,
    ) -> dict[str, Any]:
        vendor_score = self._vendor_score(normalized_vendor, component.vendor_name)
        return BomCandidateDTO.model_validate(
            {
                "component_id": str(component.component_id),
                "component_code": component.component_code,
                "component_name": component.component_name,
                "vendor_name": component.vendor_name,
                "component_type": component.component_type,
                "component_modality": component.modality,
                "match_mode": match_mode,
                "match_score": match_score,
                "vendor_score": vendor_score,
                "final_score": self._final_candidate_score(
                    match_mode=match_mode,
                    match_score=match_score,
                    vendor_score=vendor_score,
                ),
                "aliases": [],
                "reasons": [f"db_{match_mode}_match"],
            }
        ).model_dump(mode="python")

    def _lookup_attack_id(
        self,
        item: dict[str, Any],
        *,
        uow: UnitOfWork | None,
    ) -> str | None:
        if uow is None:
            return None
        source_metadata = item.get("source_metadata", {})
        attack_code = (
            source_metadata.get("stable_attack_code")
            or source_metadata.get("stable_attack_id")
            or item.get("attack_code")
        )
        if not attack_code:
            return None
        attack = uow.attacks.get_attack_by_code(str(attack_code))
        if attack is None:
            return None
        return str(attack.attack_id)

    def _ensure_component(
        self,
        candidate: dict[str, Any],
        *,
        uow: UnitOfWork,
    ) -> str | None:
        component_id = candidate.get("component_id")
        if component_id:
            return str(component_id)
        component_code = candidate.get("component_code")
        if component_code:
            existing = uow.components.get_component_by_code(str(component_code))
            if existing is not None:
                return str(existing.component_id)
        existing_by_name = uow.components.get_component_by_name(
            candidate["component_name"]
        )
        if existing_by_name is not None:
            return str(existing_by_name.component_id)
        created = uow.components.create_component(
            component_code=str(
                component_code
                or f"CMP-{normalize_component_alias(candidate['component_name'])[:24].upper()}"
            ),
            component_name=candidate["component_name"],
            vendor_name=candidate.get("vendor_name"),
            component_type=candidate.get("component_type") or "agent_tool",
            modality=candidate.get("component_modality"),
        )
        for alias in candidate.get("aliases", []):
            try:
                uow.components.upsert_component_alias(
                    component_id=str(created.component_id),
                    alias_name=alias,
                    alias_type="common",
                    vendor_name=candidate.get("vendor_name"),
                )
            except Exception:
                continue
        return str(created.component_id)

    def _vendor_score(
        self,
        normalized_vendor: str | None,
        candidate_vendor: str | None,
    ) -> float:
        if not normalized_vendor:
            return 0.0
        candidate_vendor_norm = normalize_vendor_name(candidate_vendor)
        if not candidate_vendor_norm:
            return -0.02
        if candidate_vendor_norm == normalized_vendor:
            return 0.08
        if (
            normalized_vendor in candidate_vendor_norm
            or candidate_vendor_norm in normalized_vendor
        ):
            return 0.04
        return -0.1

    def _final_candidate_score(
        self,
        *,
        match_mode: str,
        match_score: float,
        vendor_score: float,
    ) -> float:
        mode_weight = {
            "exact": 1.0,
            "alias": 1.0,
            "trigram": 0.9,
            "embedding": 0.72,
        }.get(match_mode, 0.8)
        return max(0.0, min(1.0, round(match_score * mode_weight + vendor_score, 4)))

    def _resolve_selected_candidate(
        self,
        selected_component: dict[str, Any] | None,
        candidate_components: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if selected_component is None:
            return None
        selected_code = selected_component.get("component_code")
        selected_name = selected_component.get("component_name")
        for candidate in candidate_components:
            if selected_code and candidate.get("component_code") == selected_code:
                return candidate
            if selected_name and candidate.get("component_name") == selected_name:
                return candidate
        return selected_component

    def _queue_reason_code(
        self,
        reason_codes: list[str],
        *,
        review: dict[str, Any] | None = None,
    ) -> str:
        review = review or {}
        lowered_reasons = [str(code).lower() for code in reason_codes]
        review_text = " ".join(
            [
                *[str(item).lower() for item in review.get("reasons", []) or []],
                *[str(item).lower() for item in review.get("ambiguity_notes", []) or []],
            ]
        )
        if "catalog_gap" in lowered_reasons:
            return "catalog_gap"
        if "cross_source_conflict" in lowered_reasons:
            return "cross_source_conflict"
        if "layer_conflict" in lowered_reasons:
            return "layer_conflict"
        if "version_parse_failed" in lowered_reasons:
            return "version_parse_failed"
        if not reason_codes:
            return "conflict"
        if "version_ambiguous" in lowered_reasons or "version constraint remains ambiguous" in review_text:
            return "version_ambiguous"
        if (
            "vendor_conflict" in lowered_reasons
            or "vendor conflict" in review_text
            or "vendor conflicts" in review_text
        ):
            return "vendor_conflict"
        if "llm_no_match" in lowered_reasons:
            return "llm_no_match"
        if "missing_evidence" in lowered_reasons:
            return "missing_evidence"
        if "reviewer_rejected" in lowered_reasons or "candidate overlap" in review_text:
            return "reviewer_rejected"
        if "llm_low_confidence" in lowered_reasons:
            return "llm_low_confidence"
        if "conflict" in lowered_reasons:
            return "conflict"
        return "alias_not_found"
