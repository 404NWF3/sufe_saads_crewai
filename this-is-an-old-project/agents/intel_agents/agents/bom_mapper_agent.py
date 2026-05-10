from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Literal

from backend.db.services.component_seed_service import AiComponentSeedService
from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork

from ..schemas.intel import BomResolutionDTO, LlmBomResolutionAuditDTO
from ..services.component_resolution_service import ComponentResolutionService
from ..tools.llm_client_factory import resolve_default_model
from ..tools.llm_bom_resolver_tools import LangChainLlmBomResolver


# ---------------------------------------------------------------------------
# Strategy type
# ---------------------------------------------------------------------------
BomResolutionStrategyValue = Literal[
    "rules_only", "llm_optional", "llm_required", "rules_only_degraded"
]


class _BomResolutionUowContext:
    def __init__(self, uow: UnitOfWork | None) -> None:
        self._uow = uow

    def __enter__(self) -> UnitOfWork | None:
        return self._uow

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._uow is not None:
            self._uow.__exit__(exc_type, exc, tb)
        return False


class BomMapperAgent:
    """Phase 5 BOM resolution agent.

    Architecture (LLM-primary, mirrors Phase 3 design):
    1. ``ComponentResolutionService.retrieve_candidates_for_mention()`` does
       candidate recall (seed catalog + DB alias/trigram/embedding).
    2. ``LangChainLlmBomResolver.resolve()`` receives attack context +
       candidates and makes the final accept/review_queue/no_match decision.
    3. ``ComponentResolutionService.build_llm_resolution()`` builds the
       in-memory ``BomResolutionDTO`` without touching the DB.
    4. Final persistence happens only after reviewer output via
       ``BomMapperAgent.persist_batch()``.

    The strategy parameter controls which path is taken:
    - ``llm_required``: LLM must succeed, otherwise the node fails.
    - ``llm_optional``: LLM is attempted; on failure, falls back to rules.
    - ``rules_only``: no LLM, uses existing rule-based resolution.
    - ``rules_only_degraded``: same as rules_only but flagged as degraded.
    """

    def __init__(
        self,
        *,
        resolution_service: ComponentResolutionService | None = None,
        strategy: BomResolutionStrategyValue = "llm_required",
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        llm_runtime_config: dict[str, Any] | None = None,
        max_concurrency: int = 4,
    ) -> None:
        self.resolution_service = resolution_service or ComponentResolutionService()
        self.strategy = strategy
        self.max_concurrency = max(1, max_concurrency)
        self.llm_runtime_config = llm_runtime_config or {}
        self.llm_model = resolve_default_model(
            llm_model,
            runtime_config=self.llm_runtime_config,
        )
        self.llm_temperature = llm_temperature
        self.validate_online = validate_online

        self._llm: LangChainLlmBomResolver | None = None
        if strategy in ("llm_required", "llm_optional"):
            self._llm = LangChainLlmBomResolver(
                model=self.llm_model,
                temperature=llm_temperature,
                runtime_config=self.llm_runtime_config,
            )
            if validate_online and strategy == "llm_required":
                self._llm.validate_connectivity()

    def resolve_batch(
        self,
        items: list[dict[str, Any]],
        *,
        trace_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Resolve BOM mentions for a batch of standardized items.

        Returns
        -------
        tuple[list[dict], list[dict]]
            (resolved_items, llm_bom_resolution_audits)
        """
        resolved_items: list[dict[str, Any]] = []
        all_audits: list[dict[str, Any]] = []
        queue_count = 0

        if not items:
            return resolved_items, all_audits

        def _process_item(
            item: dict[str, Any],
        ) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
            if self.strategy in ("llm_required", "llm_optional"):
                return self._llm_primary_resolve_item(item, trace_id=trace_id)
            return self._rules_only_resolve_item(item, trace_id=trace_id)

        max_workers = min(self.max_concurrency, max(1, len(items)))
        results: list[Any] = [None] * len(items)
        if max_workers == 1:
            for idx, item in enumerate(items):
                results[idx] = _process_item(item)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_idx = {
                    executor.submit(_process_item, item): i
                    for i, item in enumerate(items)
                }
                for future in as_completed(future_to_idx):
                    results[future_to_idx[future]] = future.result()

        for resolved, item_queue, audits in results:
            resolved_items.append(resolved)
            queue_count += item_queue
            all_audits.extend(audits)

        return resolved_items, all_audits

    # ------------------------------------------------------------------
    # LLM-primary path
    # ------------------------------------------------------------------

    def _llm_primary_resolve_item(
        self,
        item: dict[str, Any],
        *,
        trace_id: str | None = None,
    ) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
        """Resolve all BOM mentions in an item using LLM as primary judge."""
        updated = deepcopy(item)
        resolutions: list[dict[str, Any]] = []
        unresolved_mentions: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []
        queue_count = 0

        attack_context = {
            "attack_name": updated.get("canonical_name", ""),
            "attack_family": updated.get("attack_family", ""),
            "attack_summary": updated.get("summary", "")
            or updated.get("description", ""),
        }
        evidence_text = (
            updated.get("evidence_snippet", "") or updated.get("description", "") or ""
        )
        evidence_uri = next(iter(updated.get("evidence_refs", []) or []), None)
        db_fallback: dict[str, Any] | None = None
        with self._open_resolution_uow(trace_id=trace_id) as uow:
            if uow is None:
                db_fallback = {
                    "active": True,
                    "reason": "db_resolution_context_unavailable",
                }
            for mention_idx, mention in enumerate(updated.get("bom_mentions", [])):
                mention = {
                    **mention,
                    "raw_id": updated.get("raw_id"),
                }
                resolution, audit = self._llm_resolve_mention(
                    mention=mention,
                    mention_idx=mention_idx,
                    item=updated,
                    attack_context=attack_context,
                    evidence_text=evidence_text,
                    evidence_uri=evidence_uri,
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
                if audit:
                    audits.append(audit)
            if not updated.get("bom_mentions"):
                audits.append(
                    self._build_no_signal_audit(
                        raw_id=str(updated.get("raw_id") or "unknown"),
                        reason="no bom mentions extracted from standardized item",
                    )
                )

        updated["bom_resolutions"] = resolutions
        updated["source_metadata"] = {
            **updated.get("source_metadata", {}),
            "bom_resolution_summary": {
                "resolved": sum(
                    1 for r in resolutions if r["resolution_status"] == "resolved"
                ),
                "queued": queue_count,
                "unresolved_mentions": unresolved_mentions,
                "resolution_strategy": self.strategy,
            },
        }
        if db_fallback:
            updated["source_metadata"]["bom_resolution_db_fallback"] = db_fallback
        return updated, queue_count, audits

    def _llm_resolve_mention(
        self,
        *,
        mention: dict[str, Any],
        mention_idx: int,
        item: dict[str, Any],
        attack_context: dict[str, Any],
        evidence_text: str,
        evidence_uri: str | None,
        uow: UnitOfWork | None,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Resolve a single mention via retrieval + LLM."""
        raw_id = item.get("raw_id", "unknown")
        mentioned_name = str(mention.get("mentioned_name", "")).strip()

        # Step 1: Candidate retrieval
        retrieval = self.resolution_service.retrieve_candidates_for_mention(
            mention, uow=uow
        )
        candidates = retrieval["candidates"]

        # Step 2: LLM resolution
        strategy_executed = self.strategy
        llm_decision: dict[str, Any] | None = None
        fallback_reason: str | None = None

        try:
            if self._llm is None:
                raise RuntimeError("LLM resolver not initialized")
            if not self._llm.is_available():
                raise RuntimeError("OPENAI_API_KEY not configured")

            candidate_text = LangChainLlmBomResolver.format_candidate_list(candidates)
            payload = {
                **attack_context,
                "mentioned_name": mentioned_name,
                "mentioned_vendor": mention.get("mentioned_vendor"),
                "mentioned_version": mention.get("mentioned_version"),
                "component_layer_hint": mention.get("component_layer", "unknown"),
                "candidate_list": candidate_text,
                "evidence_text": evidence_text[:2000],
            }
            llm_decision = self._llm.resolve(payload)
            strategy_executed = "llm_primary"

        except Exception as exc:
            if self.strategy == "llm_required":
                raise RuntimeError(
                    f"LLM BOM resolution required but failed for "
                    f"'{mentioned_name}': {exc}"
                ) from exc
            # llm_optional: fall back to rules
            fallback_reason = f"llm_failed:{type(exc).__name__}:{str(exc)[:200]}"
            strategy_executed = "rules_only_degraded"

        # Step 3: Build resolution
        if llm_decision is not None:
            resolution = self.resolution_service.build_llm_resolution(
                mention=mention,
                llm_decision=llm_decision,
                candidates=candidates,
            )
        else:
            # Rules-only fallback
            resolution = self._rule_based_resolution(
                mention=mention,
                candidates=candidates,
                evidence_uri=evidence_uri,
            )

        # Step 4: Build audit
        llm_meta = (
            dict(getattr(self._llm, "last_invocation_meta", {}) or {})
            if llm_decision is not None
            else {}
        )
        audit = self._build_audit(
            raw_id=raw_id,
            mention_idx=mention_idx,
            mentioned_name=mentioned_name,
            strategy_executed=strategy_executed,
            llm_decision=llm_decision,
            fallback_reason=fallback_reason,
            candidate_count=len(candidates),
            llm_meta=llm_meta,
        )

        return resolution, audit

    def _open_resolution_uow(self, *, trace_id: str | None):
        try:
            context = SqlContext(trace_id=trace_id, agent_name="bom_mapper_agent_llm")
            uow = UnitOfWork(context=context)
            entered = uow.__enter__()
            AiComponentSeedService(entered).ensure_seeded(trace_id=trace_id)
            return _BomResolutionUowContext(entered)
        except Exception:
            return _BomResolutionUowContext(None)

    def _persist_mention(
        self,
        *,
        mention: dict[str, Any],
        attack_id: str | None,
        raw_id: str | None,
        evidence_text: str,
        uow: UnitOfWork | None,
    ) -> str | None:
        if uow is None:
            return None
        from ..tools import normalize_vendor_name
        from backend.db.repositories.component_repository import normalize_component_alias

        normalized_alias = normalize_component_alias(
            str(mention.get("mentioned_name", "")),
            mention.get("mentioned_vendor"),
        )
        row = uow.components.insert_attack_component_mention(
            attack_id=attack_id,
            raw_id=str(raw_id) if raw_id else None,
            mentioned_name=str(mention.get("mentioned_name", "")),
            mentioned_vendor=mention.get("mentioned_vendor"),
            mentioned_version=mention.get("mentioned_version"),
            normalized_alias=normalized_alias,
            normalized_vendor=normalize_vendor_name(mention.get("mentioned_vendor")),
            component_layer=mention.get("component_layer"),
            impact_scope=mention.get("impact_scope"),
            dependency_role=mention.get("dependency_role"),
            evidence_snippet=evidence_text[:1000] or None,
            extractor_name="bom_mapper_agent_llm",
            extraction_confidence=float(mention.get("confidence_score", 0.0) or 0.0),
        )
        return str(row.mention_id)

    def _persist_audit(
        self,
        *,
        audit: dict[str, Any],
        attack_id: str | None,
        raw_id: str | None,
        mention_id: str | None,
        uow: UnitOfWork | None,
    ) -> None:
        if uow is None:
            return
        uow.governance.insert_bom_resolution_audit(
            mention_id=mention_id,
            attack_id=attack_id,
            raw_id=str(raw_id) if raw_id else None,
            strategy_requested=audit["strategy_requested"],
            strategy_executed=audit["strategy_executed"],
            llm_model=audit["llm_model"],
            prompt_version=audit["prompt_version"],
            llm_decision=audit["llm_decision"],
            llm_confidence=float(audit["llm_confidence"]),
            selected_component_code=audit.get("selected_component_code"),
            reasoning_summary=audit["llm_reasoning"],
            reasoning_trace=list(audit.get("reasoning_trace", []) or [])[:8] or None,
            candidate_count=int(audit["candidate_count"]),
            evidence_quotes=list(audit.get("evidence_quotes", []) or [])[:8] or None,
        )

    def persist_batch(
        self,
        items: list[dict[str, Any]],
        *,
        audits: list[dict[str, Any]] | None = None,
        trace_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        audit_lookup: dict[tuple[str, int], dict[str, Any]] = {}
        for audit in audits or []:
            audit_lookup[
                (
                    str(audit.get("raw_id") or "unknown"),
                    int(audit.get("mention_index", -1)),
                )
            ] = audit

        # Seed AI component taxonomy once upfront (shared reference data)
        with UnitOfWork(
            context=SqlContext(trace_id=trace_id, agent_name="bom_mapper_agent_seed")
        ) as seed_uow:
            AiComponentSeedService(seed_uow).ensure_seeded(trace_id=trace_id)

        def _persist_one(item: dict[str, Any]) -> tuple[dict[str, Any], int]:
            try:
                with UnitOfWork(
                    context=SqlContext(trace_id=trace_id, agent_name="bom_mapper_agent_persist")
                ) as uow:
                    return self._persist_item(item, audit_lookup=audit_lookup, uow=uow)
            except Exception as exc:
                fallback = {
                    **deepcopy(item),
                    "source_metadata": {
                        **item.get("source_metadata", {}),
                        "bom_persist_fallback": {
                            "active": True,
                            "error_type": type(exc).__name__,
                            "error_message": str(exc)[:300],
                        },
                    },
                }
                item_queue_count = sum(
                    1
                    for r in fallback.get("bom_resolutions", [])
                    if r.get("resolution_status") != "resolved"
                )
                return fallback, item_queue_count

        max_workers = min(self.max_concurrency, max(1, len(items)))
        results: list[tuple[dict[str, Any], int]] = [None] * len(items)  # type: ignore[list-item]
        if max_workers == 1:
            for idx, item in enumerate(items):
                results[idx] = _persist_one(item)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_idx = {
                    executor.submit(_persist_one, item): i for i, item in enumerate(items)
                }
                for future in as_completed(future_to_idx):
                    results[future_to_idx[future]] = future.result()

        persisted_items = [r[0] for r in results]
        queue_count = sum(r[1] for r in results)
        return persisted_items, queue_count

    def _persist_item(
        self,
        item: dict[str, Any],
        *,
        audit_lookup: dict[tuple[str, int], dict[str, Any]],
        uow: UnitOfWork,
    ) -> tuple[dict[str, Any], int]:
        updated = deepcopy(item)
        raw_id = str(updated.get("raw_id") or "unknown")
        attack_id = self.resolution_service._lookup_attack_id(updated, uow=uow)
        evidence_text = (
            updated.get("evidence_snippet", "")
            or updated.get("description", "")
            or updated.get("summary", "")
        )
        evidence_uri = next(iter(updated.get("evidence_refs", []) or []), None)
        persisted_resolutions: list[dict[str, Any]] = []
        item_queue_count = 0

        for mention_idx, resolution in enumerate(updated.get("bom_resolutions", [])):
            mention = (
                list(updated.get("bom_mentions", []))[mention_idx]
                if mention_idx < len(updated.get("bom_mentions", []))
                else self._mention_from_resolution(resolution)
            )
            mention_id = self._persist_mention(
                mention={**mention, "raw_id": raw_id},
                attack_id=attack_id,
                raw_id=raw_id,
                evidence_text=evidence_text,
                uow=uow,
            )
            audit = audit_lookup.get((raw_id, mention_idx))
            if audit is not None:
                self._persist_audit(
                    audit=audit,
                    attack_id=attack_id,
                    raw_id=raw_id,
                    mention_id=mention_id,
                    uow=uow,
                )

            finalized_resolution = deepcopy(resolution)
            finalized_resolution["reason_codes"] = list(
                dict.fromkeys(
                    [
                        *list(finalized_resolution.get("reason_codes", []) or []),
                        *self._confidence_reason_codes(finalized_resolution),
                    ]
                )
            )
            final_review_status = self._final_review_status(finalized_resolution)
            finalized_resolution = self.resolution_service.persist_reviewed_resolution(
                resolution=finalized_resolution,
                attack_id=attack_id,
                uow=uow,
                mention_id=mention_id,
                raw_id=raw_id,
                evidence_uri=evidence_uri,
                evidence_snippet=evidence_text[:1000] or None,
                review_status=final_review_status,
                resolver_strategy=(
                    "llm_primary"
                    if self.strategy in ("llm_required", "llm_optional")
                    else "rules_only"
                ),
            )
            if finalized_resolution.get("resolution_status") != "resolved":
                item_queue_count += 1
            persisted_resolutions.append(finalized_resolution)

        if not updated.get("bom_resolutions"):
            audit = audit_lookup.get((raw_id, -1))
            if audit is not None:
                self._persist_audit(
                    audit=audit,
                    attack_id=attack_id,
                    raw_id=raw_id,
                    mention_id=None,
                    uow=uow,
                )

        updated["bom_resolutions"] = persisted_resolutions
        updated["source_metadata"] = {
            **updated.get("source_metadata", {}),
            "bom_resolution_summary": {
                **updated.get("source_metadata", {}).get("bom_resolution_summary", {}),
                "persisted_at_end": True,
                "resolved": sum(
                    1
                    for resolution in persisted_resolutions
                    if resolution.get("resolution_status") == "resolved"
                ),
                "queued": item_queue_count,
            },
        }
        return updated, item_queue_count

    def _mention_from_resolution(self, resolution: dict[str, Any]) -> dict[str, Any]:
        return {
            "mentioned_name": resolution.get("mentioned_name"),
            "mentioned_vendor": resolution.get("mentioned_vendor"),
            "mentioned_version": resolution.get("mentioned_version"),
            "component_layer": None,
            "impact_scope": "direct",
            "dependency_role": None,
            "confidence_score": float(resolution.get("match_confidence", 0.0) or 0.0),
        }

    def _final_review_status(self, resolution: dict[str, Any]) -> str:
        review = dict(resolution.get("review") or {})
        review_confidence = float(
            review.get("confidence", resolution.get("match_confidence", 0.0)) or 0.0
        )
        final_confidence = min(
            float(resolution.get("match_confidence", 0.0) or 0.0),
            review_confidence,
        )
        auto_publish_threshold = float(
            self.llm_runtime_config.get("bom_auto_publish_threshold", 0.85) or 0.85
        )
        if (
            resolution.get("resolution_status") == "resolved"
            and review.get("decision", "accept") == "accept"
            and final_confidence >= auto_publish_threshold
        ):
            return "accepted"
        return "review_queue"

    def _confidence_reason_codes(self, resolution: dict[str, Any]) -> list[str]:
        review = dict(resolution.get("review") or {})
        review_confidence = float(
            review.get("confidence", resolution.get("match_confidence", 0.0)) or 0.0
        )
        final_confidence = min(
            float(resolution.get("match_confidence", 0.0) or 0.0),
            review_confidence,
        )
        review_queue_threshold = float(
            self.llm_runtime_config.get("review_queue_threshold", 0.60) or 0.60
        )
        reason_codes: list[str] = []
        if not resolution.get("selected_component"):
            reason_codes.append("missing_evidence")
        if final_confidence < review_queue_threshold:
            reason_codes.append("llm_low_confidence")
        return reason_codes

    def _build_no_signal_audit(
        self,
        *,
        raw_id: str,
        reason: str,
    ) -> dict[str, Any]:
        return LlmBomResolutionAuditDTO(
            raw_id=raw_id,
            mention_index=-1,
            mentioned_name="(no_component_signal)",
            strategy_requested=self.strategy,
            strategy_executed="audit_only",
            llm_model=self.llm_model,
            llm_profile_id=None,
            llm_profile=None,
            prompt_version=(self._llm.PROMPT_VERSION if self._llm else "n/a"),
            llm_confidence=0.0,
            llm_decision="no_signal",
            llm_reasoning=reason,
            fallback_reason=None,
            candidate_count=0,
            selected_component_code=None,
            reasoning_trace=["No reliable AI BOM mention was available in the standardized item."],
            evidence_quotes=[],
            llm_wait_seconds=None,
            attempted_profiles=[],
            attempted_profile_labels=[],
            invoked_at=datetime.now(timezone.utc).isoformat(),
        ).model_dump(mode="python")

    def _rule_based_resolution(
        self,
        *,
        mention: dict[str, Any],
        candidates: list[dict[str, Any]],
        evidence_uri: str | None,
    ) -> dict[str, Any]:
        """Build a BomResolutionDTO using rules-only logic from candidates.
        This mirrors the original ComponentResolutionService._resolve_mention
        decision logic but without DB persistence."""
        from ..schemas.intel import BomCandidateDTO

        mentioned_name = str(mention.get("mentioned_name", "")).strip()
        mentioned_vendor = mention.get("mentioned_vendor")
        from ..tools import normalize_vendor_name, normalize_version_constraint
        from backend.db.repositories.component_repository import (
            normalize_component_alias,
        )

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

        selected = candidates[0] if candidates else None
        second = candidates[1] if len(candidates) > 1 else None
        gap = round(
            float(selected.get("final_score", 0.0))
            - float(second.get("final_score", 0.0))
            if second and selected
            else 1.0,
            4,
        )

        reason_codes: list[str] = []
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
                BomCandidateDTO.model_validate(c) for c in candidates
            ],
            match_mode=selected.get("match_mode") if selected else None,
            match_confidence=float(
                selected.get("final_score", 0.0) if selected else 0.0
            ),
            reason_codes=reason_codes,
            queue_ref=None,
            review=None,
        ).model_dump(mode="python")

    # ------------------------------------------------------------------
    # Rules-only path (backward-compatible)
    # ------------------------------------------------------------------

    def _rules_only_resolve_item(
        self,
        item: dict[str, Any],
        *,
        trace_id: str | None = None,
    ) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
        """Resolve using retrieval + heuristics without intermediate persistence."""
        resolved = deepcopy(item)
        strategy_label = (
            "rules_only_degraded"
            if self.strategy == "rules_only_degraded"
            else "rules_only"
        )
        queue_count = 0
        audits: list[dict[str, Any]] = []
        resolutions: list[dict[str, Any]] = []
        unresolved_mentions: list[dict[str, Any]] = []
        raw_id = str(item.get("raw_id", "unknown"))

        with self._open_resolution_uow(trace_id=trace_id) as uow:
            for idx, mention in enumerate(item.get("bom_mentions", [])):
                retrieval = self.resolution_service.retrieve_candidates_for_mention(
                    mention,
                    uow=uow,
                )
                resolution = self._rule_based_resolution(
                    mention=mention,
                    candidates=retrieval["candidates"],
                    evidence_uri=next(iter(item.get("evidence_refs", []) or []), None),
                )
                if resolution["resolution_status"] != "resolved":
                    queue_count += 1
                    unresolved_mentions.append(
                        {
                            "mentioned_name": resolution["mentioned_name"],
                            "mentioned_vendor": resolution.get("mentioned_vendor"),
                            "reason_codes": resolution.get("reason_codes", []),
                        }
                    )
                resolutions.append(resolution)
                audits.append(
                    self._build_audit(
                        raw_id=raw_id,
                        mention_idx=idx,
                        mentioned_name=str(
                            mention.get("mentioned_name", "unknown")
                        ).strip(),
                        strategy_executed=strategy_label,
                        llm_decision=None,
                        fallback_reason=(
                            "rules_only_by_strategy"
                            if self.strategy == "rules_only"
                            else "degraded_fallback"
                        ),
                        candidate_count=len(retrieval["candidates"]),
                    )
                )

        if not item.get("bom_mentions"):
            audits.append(
                self._build_no_signal_audit(
                    raw_id=raw_id,
                    reason="rules-only path found no AI BOM mentions to resolve",
                )
            )

        resolved["bom_resolutions"] = resolutions
        resolved["source_metadata"] = {
            **resolved.get("source_metadata", {}),
            "bom_resolution_summary": {
                "resolved": sum(
                    1
                    for resolution in resolutions
                    if resolution["resolution_status"] == "resolved"
                ),
                "queued": queue_count,
                "unresolved_mentions": unresolved_mentions,
                "resolution_strategy": strategy_label,
            },
        }
        return resolved, queue_count, audits

    # ------------------------------------------------------------------
    # Audit builder
    # ------------------------------------------------------------------

    def _build_audit(
        self,
        *,
        raw_id: str,
        mention_idx: int,
        mentioned_name: str,
        strategy_executed: str,
        llm_decision: dict[str, Any] | None,
        fallback_reason: str | None,
        candidate_count: int,
        llm_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        llm_meta = llm_meta or {}
        if llm_decision:
            llm_confidence = float(llm_decision.get("confidence", 0.0))
            llm_decision_val = llm_decision.get("decision", "review_queue")
            llm_reasoning = llm_decision.get("reasoning_summary", "n/a")
            selected = llm_decision.get("selected_component") or {}
            selected_code = selected.get("component_code")
            reasoning_trace = list(llm_decision.get("reasoning_trace", []) or [])
            evidence_quotes = list(llm_decision.get("evidence_quotes", []) or [])
        else:
            llm_confidence = 0.0
            llm_decision_val = "n/a"
            llm_reasoning = fallback_reason or "rules_only"
            selected_code = None
            reasoning_trace = [fallback_reason or "Rules-only fallback executed."]
            evidence_quotes = []

        return LlmBomResolutionAuditDTO(
            raw_id=raw_id,
            mention_index=mention_idx,
            mentioned_name=mentioned_name,
            strategy_requested=self.strategy,
            strategy_executed=strategy_executed,
            llm_model=str(llm_meta.get("llm_model", self.llm_model)),
            llm_profile_id=llm_meta.get("profile_id"),
            llm_profile=llm_meta.get("profile"),
            prompt_version=(self._llm.PROMPT_VERSION if self._llm else "n/a"),
            llm_confidence=llm_confidence,
            llm_decision=llm_decision_val,
            llm_reasoning=llm_reasoning,
            fallback_reason=fallback_reason,
            candidate_count=candidate_count,
            selected_component_code=selected_code,
            reasoning_trace=reasoning_trace[:8],
            evidence_quotes=evidence_quotes[:8],
            llm_wait_seconds=llm_meta.get("wait_seconds"),
            attempted_profiles=list(llm_meta.get("attempted_profiles", []) or []),
            attempted_profile_labels=list(
                llm_meta.get("attempted_profile_labels", []) or []
            ),
            invoked_at=datetime.now(timezone.utc).isoformat(),
        ).model_dump(mode="python")
