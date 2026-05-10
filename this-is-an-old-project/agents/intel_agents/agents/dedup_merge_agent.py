from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..schemas.intel import DedupDecisionDTO, MergeAuditRecordDTO, StableAttackRecordDTO
from ..tools.llm_client_factory import resolve_default_model
from ..tools import (
    bom_overlap_score,
    build_dedup_text,
    compute_content_hash,
    compute_minhash,
    compute_simhash,
    cosine_similarity,
    cve_overlap_score,
    describe_bom_delta,
    generate_embedding,
    minhash_similarity,
    rerank_similarity,
    simhash_similarity,
    taxonomy_overlap_score,
)
from ..tools.llm_merge_judge_tools import LangChainLlmMergeJudge

DEDUP_MINHASH_SIZE = 16
DEDUP_EMBEDDING_SIZE = 32


class DedupMergeAgent:
    """Phase 4 dedup / merge agent with LLM-primary merge judge.

    Architecture (LLM-primary):
        1. Retrieval: content hash → near duplicate → vector recall → rerank
        2. Rule prior: compute rule-based merge/new/review decision
        3. LLM merge judge (if strategy permits): receives candidate + best
           match + signals + rule prior → verdict + recommended_action
        4. Fusion: reconcile rule prior and LLM verdict to final decision
        5. Apply: merge, create new, or queue for review

    Strategies:
        - ``rules_only``: No LLM involvement; pure rule-based (backward compat)
        - ``llm_optional``: LLM judge invoked but gracefully falls back to
          rules on failure
        - ``llm_required``: LLM judge must succeed or the node fails
        - ``rules_only_degraded``: Rules-only with degradation flag (for
          explicit silent-free fallback tracking)

    Return signature:
        ``tuple[dict, list[dict]]`` — (dedup_result, llm_dedup_judgments)
        The dedup_result dict has the same shape as the old return value.
    """

    def __init__(
        self,
        *,
        vector_memory: Any | None = None,
        adjudicator: Any | None = None,
        strategy: str = "rules_only",
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        merge_judge: Any | None = None,
        llm_runtime_config: dict[str, Any] | None = None,
        max_concurrency: int = 4,
    ):
        self.vector_memory = vector_memory
        self.adjudicator = adjudicator
        self.strategy = strategy
        self.max_concurrency = max(1, max_concurrency)
        self.llm_runtime_config = llm_runtime_config or {}
        self.llm_model = resolve_default_model(
            llm_model,
            runtime_config=self.llm_runtime_config,
        )
        self.llm_temperature = llm_temperature
        self.validate_online = validate_online
        self.merge_judge = merge_judge or LangChainLlmMergeJudge(
            model=self.llm_model,
            temperature=llm_temperature,
            runtime_config=self.llm_runtime_config,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dedup_and_merge(
        self,
        items: list[dict[str, Any]],
        existing_records: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Run the full dedup-and-merge pipeline.

        Returns
        -------
        tuple[dict, list[dict]]
            (dedup_result, llm_dedup_judgments)
        """
        records = [self._build_candidate(item) for item in items]
        stable_records = [
            self._normalize_stable_record(deepcopy(record))
            for record in (existing_records or [])
        ]
        if self.vector_memory is not None:
            self.vector_memory.rebuild_index(stable_records)

        decisions: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []
        resolved_items: list[dict[str, Any]] = []
        llm_dedup_judgments: list[dict[str, Any]] = []

        if not records:
            dedup_merged_count = 0
            new_attack_count = 0
            return {
                "dedup_decisions": decisions,
                "stable_attack_records": stable_records,
                "merge_audits": audits,
                "resolved_items": resolved_items,
                "dedup_merged_count": dedup_merged_count,
                "new_attack_count": new_attack_count,
            }, llm_dedup_judgments

        # ---------------------------------------------------------------
        # Phase 1 (parallel): evaluate each candidate against the initial
        # stable_records snapshot.  LLM judge calls are the bottleneck and
        # are independent per candidate, so we run them concurrently.
        # Note: all candidates are scored against the *pre-batch* snapshot;
        # within-batch incremental merges do not feed back into this pass.
        # ---------------------------------------------------------------
        stable_snapshot = list(stable_records)

        def _evaluate(
            candidate: dict[str, Any],
        ) -> tuple[
            list[dict[str, Any]],
            dict[str, Any] | None,
            dict[str, Any] | None,
            dict[str, Any] | None,
            str,
            list[str],
        ]:
            recalled = self._semantic_recall(candidate, stable_snapshot)
            candidate_pool = self._build_candidate_pool(
                candidate, stable_snapshot, recalled
            )
            ranked = sorted(
                [self._score_candidate(candidate, stable) for stable in candidate_pool],
                key=lambda row: row["score"],
                reverse=True,
            )
            best = ranked[0] if ranked else None
            rule_prior_decision, rule_prior_reasons = self._compute_rule_prior(
                candidate, best
            )
            llm_judgment: dict[str, Any] | None = None
            llm_audit: dict[str, Any] | None = None
            if self._should_use_llm() and best is not None:
                llm_judgment, llm_audit = self._invoke_merge_judge(
                    candidate, best, rule_prior_decision, rule_prior_reasons
                )
            fused_decision, fused_reasons = self._fuse_decisions(
                rule_prior_decision, rule_prior_reasons, llm_judgment, best
            )
            return recalled, best, llm_judgment, llm_audit, fused_decision, fused_reasons

        max_workers = min(self.max_concurrency, max(1, len(records)))
        eval_results: list[Any] = [None] * len(records)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {
                executor.submit(_evaluate, candidate): i
                for i, candidate in enumerate(records)
            }
            for future in as_completed(future_to_idx):
                eval_results[future_to_idx[future]] = future.result()

        # ---------------------------------------------------------------
        # Phase 2 (serial): apply fused decisions in order so that
        # stable_records mutations are deterministic.
        # ---------------------------------------------------------------
        for i, candidate in enumerate(records):
            recalled, best, llm_judgment, llm_audit, fused_decision, fused_reasons = (
                eval_results[i]
            )

            if llm_audit is not None:
                llm_dedup_judgments.append(llm_audit)

            # --- Apply decision ---
            decision, stable_record, audit = self._apply_fused_decision(
                candidate,
                best,
                stable_records,
                fused_decision=fused_decision,
                fused_reasons=fused_reasons,
                top_k_candidates=recalled,
                llm_judgment=llm_judgment,
            )
            stable_record = self._normalize_stable_record(
                stable_record,
                refresh=decision["decision"] == "merge",
            )

            # Update llm_audit with final fused decision if available
            if llm_audit is not None:
                llm_audit["fused_final_decision"] = decision["decision"]
                llm_audit["fusion_agreed"] = (
                    llm_judgment is not None
                    and llm_judgment.get("recommended_action") == decision["decision"]
                )

            decisions.append(decision)
            audits.append(audit)
            if decision["decision"] in {"new", "review"}:
                stable_records.append(stable_record)
            resolved_items.append(
                self._build_resolved_item(candidate, stable_record, decision)
            )
            if self.vector_memory is not None:
                self.vector_memory.upsert_record(stable_record)

        dedup_merged_count = sum(1 for row in decisions if row["decision"] == "merge")
        new_attack_count = sum(1 for row in decisions if row["decision"] == "new")
        result = {
            "dedup_decisions": decisions,
            "stable_attack_records": stable_records,
            "merge_audits": audits,
            "resolved_items": resolved_items,
            "dedup_merged_count": dedup_merged_count,
            "new_attack_count": new_attack_count,
        }
        return result, llm_dedup_judgments

    # ------------------------------------------------------------------
    # Strategy helpers
    # ------------------------------------------------------------------

    def _should_use_llm(self) -> bool:
        return self.strategy in ("llm_optional", "llm_required")

    def _invoke_merge_judge(
        self,
        candidate: dict[str, Any],
        best: dict[str, Any],
        rule_prior_decision: str,
        rule_prior_reasons: list[str],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Call the LLM merge judge and build the audit record.

        Returns (llm_judgment_dict, audit_dict) or (None, audit_with_fallback)
        on failure.
        """
        matched = best["stable"]
        invoked_at = datetime.now(timezone.utc).isoformat()

        try:
            if self.validate_online:
                self.merge_judge.validate_connectivity()

            payload = LangChainLlmMergeJudge.format_judge_payload(
                candidate=candidate,
                existing=matched,
                best_signals=best,
                rule_prior_decision=rule_prior_decision,
                rule_prior_reasons=rule_prior_reasons,
            )
            result = self.merge_judge.judge(payload)
            llm_meta = dict(getattr(self.merge_judge, "last_invocation_meta", {}) or {})

            # Build audit
            audit = {
                "candidate_raw_id": str(candidate.get("raw_id", "")),
                "candidate_attack_code": str(candidate.get("attack_code", "")),
                "existing_stable_id": matched.get("stable_attack_id"),
                "strategy_requested": self.strategy,
                "strategy_executed": "llm_primary",
                "llm_model": llm_meta.get("llm_model", self.llm_model),
                "llm_profile_id": llm_meta.get("profile_id"),
                "llm_profile": llm_meta.get("profile"),
                "prompt_version": self.merge_judge.PROMPT_VERSION,
                "llm_confidence": result.get("confidence", 0.0),
                "llm_verdict": result.get("verdict", "uncertain"),
                "llm_recommended_action": result.get("recommended_action", "review"),
                "llm_explanation": result.get("explanation", ""),
                "fallback_reason": None,
                "rule_prior_decision": rule_prior_decision,
                "fused_final_decision": rule_prior_decision,  # updated later
                "fusion_agreed": True,  # updated later
                "overall_similarity_score": best.get("score", 0.0),
                "bom_delta_detected": best.get("bom_delta_detected", False),
                "llm_wait_seconds": llm_meta.get("wait_seconds"),
                "attempted_profiles": list(
                    llm_meta.get("attempted_profiles", []) or []
                ),
                "attempted_profile_labels": list(
                    llm_meta.get("attempted_profile_labels", []) or []
                ),
                "invoked_at": invoked_at,
            }
            return result, audit

        except Exception as exc:
            if self.strategy == "llm_required":
                raise

            # llm_optional: graceful fallback
            fallback_audit = {
                "candidate_raw_id": str(candidate.get("raw_id", "")),
                "candidate_attack_code": str(candidate.get("attack_code", "")),
                "existing_stable_id": matched.get("stable_attack_id"),
                "strategy_requested": self.strategy,
                "strategy_executed": "rules_only_fallback",
                "llm_model": self.llm_model,
                "prompt_version": self.merge_judge.PROMPT_VERSION,
                "llm_confidence": 0.0,
                "llm_verdict": "uncertain",
                "llm_recommended_action": "review",
                "llm_explanation": f"LLM fallback: {exc}",
                "fallback_reason": str(exc),
                "rule_prior_decision": rule_prior_decision,
                "fused_final_decision": rule_prior_decision,  # updated later
                "fusion_agreed": True,  # updated later
                "overall_similarity_score": best.get("score", 0.0),
                "bom_delta_detected": best.get("bom_delta_detected", False),
                "invoked_at": invoked_at,
            }
            return None, fallback_audit

    # ------------------------------------------------------------------
    # Rule prior computation (extracted from old _decide_and_apply logic)
    # ------------------------------------------------------------------

    def _compute_rule_prior(
        self,
        candidate: dict[str, Any],
        best: dict[str, Any] | None,
    ) -> tuple[str, list[str]]:
        """Compute the rule-based prior decision without applying it.

        Returns (decision_str, reasons_list).
        """
        if best is None or best["score"] < 0.42:
            return "new", ["no high-confidence prior candidate"]

        reasons = [
            f"rerank_score={best['rerank_score']}",
            f"embedding_score={best['embedding_score']}",
            f"taxonomy_overlap={best['taxonomy_score']}",
            *best["bom_delta_reasons"],
        ]

        if best["content_hash_match"] or (
            best["score"] >= 0.86 and not best["bom_delta_detected"]
        ):
            return "merge", reasons + ["high similarity merge"]

        if best["score"] >= 0.5 and best["bom_delta_detected"]:
            return "review", reasons + ["narrative similar but BOM differs"]

        if best["score"] >= 0.6 and not best["bom_delta_detected"]:
            return "merge", reasons + ["high semantic similarity merge"]

        return "new", reasons + ["insufficient certainty for merge"]

    # ------------------------------------------------------------------
    # Fusion logic
    # ------------------------------------------------------------------

    def _fuse_decisions(
        self,
        rule_prior: str,
        rule_reasons: list[str],
        llm_judgment: dict[str, Any] | None,
        best: dict[str, Any] | None,
    ) -> tuple[str, list[str]]:
        """Fuse rule prior and LLM verdict into a final decision.

        Fusion rules:
        1. If no LLM judgment → use rule prior.
        2. Rule prior and LLM recommended_action agree → execute.
        3. They conflict → review (conservative).
        4. BOM delta large and LLM says merge → review (override).
        5. LLM confidence < 0.6 → review regardless.
        """
        if llm_judgment is None:
            return rule_prior, rule_reasons

        llm_action = llm_judgment.get("recommended_action", "review")
        llm_verdict = llm_judgment.get("verdict", "uncertain")
        llm_confidence = llm_judgment.get("confidence", 0.0)
        bom_delta = best.get("bom_delta_detected", False) if best else False

        fused_reasons = list(rule_reasons) + [
            f"llm_verdict={llm_verdict}",
            f"llm_action={llm_action}",
            f"llm_confidence={llm_confidence}",
        ]

        # Low confidence → always review
        if llm_confidence < 0.6:
            fused_reasons.append("fusion=low_llm_confidence_forces_review")
            return "review", fused_reasons

        # LLM says merge but BOM delta detected → review
        if llm_action == "merge" and bom_delta:
            fused_reasons.append("fusion=bom_delta_blocks_llm_merge")
            return "review", fused_reasons

        # Agreement → execute
        if rule_prior == llm_action:
            fused_reasons.append("fusion=rule_llm_agree")
            return rule_prior, fused_reasons

        # High confidence LLM overrides rule prior for certain cases
        if llm_confidence >= 0.85:
            # LLM is highly confident — trust it, but:
            # - If LLM says merge and rules say new → trust LLM
            # - If LLM says new and rules say merge → trust LLM
            # - If LLM says review → review
            if llm_action == "review":
                fused_reasons.append("fusion=llm_high_confidence_review")
                return "review", fused_reasons
            fused_reasons.append("fusion=llm_high_confidence_override")
            return llm_action, fused_reasons

        # Conflict with moderate confidence → review (conservative)
        fused_reasons.append("fusion=rule_llm_conflict_forces_review")
        return "review", fused_reasons

    # ------------------------------------------------------------------
    # Apply fused decision
    # ------------------------------------------------------------------

    def _apply_fused_decision(
        self,
        candidate: dict[str, Any],
        best: dict[str, Any] | None,
        stable_records: list[dict[str, Any]],
        *,
        fused_decision: str,
        fused_reasons: list[str],
        top_k_candidates: list[dict[str, Any]],
        llm_judgment: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Apply the fused decision: merge, new, or review."""
        matched = best["stable"] if best is not None else None

        if fused_decision == "merge" and matched is not None:
            merged = self._merge_records(matched, candidate)
            self._replace_stable_record(
                stable_records, matched["stable_attack_id"], merged
            )
            decision = self._decision(
                candidate,
                matched,
                best,
                decision="merge",
                reasons=fused_reasons,
                llm_judgment=llm_judgment,
            )
            decision = self._adjudicate(candidate, decision, top_k_candidates, best)

            # If adjudicator overrides merge → undo
            if decision["decision"] != "merge":
                self._replace_stable_record(
                    stable_records, matched["stable_attack_id"], matched
                )
                final_record = self._new_stable_record(
                    candidate, decision=decision["decision"]
                )
            else:
                final_record = merged

            audit = self._audit(final_record, candidate, decision)
            return decision, final_record, audit

        elif fused_decision == "new" or matched is None:
            stable_record = self._new_stable_record(candidate, decision="new")
            decision = self._decision(
                candidate,
                matched,
                best,
                decision="new",
                reasons=fused_reasons,
                llm_judgment=llm_judgment,
            )
            decision = self._adjudicate(candidate, decision, top_k_candidates, best)

            # If adjudicator overrides new → merge
            if decision["decision"] == "merge" and matched is not None:
                final_record = self._merge_records(matched, candidate)
                self._replace_stable_record(
                    stable_records, matched["stable_attack_id"], final_record
                )
            else:
                final_record = stable_record

            audit = self._audit(final_record, candidate, decision)
            return decision, final_record, audit

        else:  # review
            review_record = self._new_stable_record(candidate, decision="review")
            decision = self._decision(
                candidate,
                matched,
                best,
                decision="review",
                reasons=fused_reasons,
                llm_judgment=llm_judgment,
            )
            decision = self._adjudicate(candidate, decision, top_k_candidates, best)

            # If adjudicator overrides review → merge
            if decision["decision"] == "merge" and matched is not None:
                final_record = self._merge_records(matched, candidate)
                self._replace_stable_record(
                    stable_records, matched["stable_attack_id"], final_record
                )
            else:
                final_record = review_record

            audit = self._audit(final_record, candidate, decision)
            return decision, final_record, audit

    # ------------------------------------------------------------------
    # Candidate building and scoring (unchanged from original)
    # ------------------------------------------------------------------

    def _build_candidate(self, item: dict[str, Any]) -> dict[str, Any]:
        text = build_dedup_text(item)
        return {
            **deepcopy(item),
            "dedup_text": text,
            "content_hash_signature": compute_content_hash(item),
            "simhash_signature": compute_simhash(text),
            "minhash_signature": compute_minhash(text),
            "embedding_signature": generate_embedding(text),
            "stable_attack_id": item.get("attack_code") or f"stable_{uuid4().hex[:12]}",
            "member_attack_codes": [item.get("attack_code")],
            "related_raw_ids": [item.get("raw_id")],
            "source_coverage": [item.get("source_metadata", {}).get("source_name")],
            "last_decision": "new",
        }

    def _semantic_recall(
        self, candidate: dict[str, Any], stable_records: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if self.vector_memory is None or not stable_records:
            return []
        return self.vector_memory.semantic_recall(candidate, top_k=5)

    def _build_candidate_pool(
        self,
        candidate: dict[str, Any],
        stable_records: list[dict[str, Any]],
        recalled: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not stable_records:
            return []
        recalled_ids = {
            str(row.get("stable_attack_id"))
            for row in recalled
            if row.get("stable_attack_id")
        }
        pool: list[dict[str, Any]] = []
        for stable in stable_records:
            stable_id = str(stable.get("stable_attack_id"))
            if stable_id in recalled_ids:
                pool.append(stable)
                continue
            if candidate["content_hash_signature"] == stable.get(
                "content_hash_signature"
            ):
                pool.append(stable)
                continue
            if (
                taxonomy_overlap_score(candidate, stable) >= 0.5
                or bom_overlap_score(candidate, stable) >= 0.5
            ):
                pool.append(stable)
        return pool or stable_records

    def _score_candidate(
        self, candidate: dict[str, Any], stable: dict[str, Any]
    ) -> dict[str, Any]:
        content_hash_match = candidate["content_hash_signature"] == stable.get(
            "content_hash_signature"
        )
        simhash_score = simhash_similarity(
            candidate["simhash_signature"], stable.get("simhash_signature", 0)
        )
        minhash_score = minhash_similarity(
            candidate["minhash_signature"], stable.get("minhash_signature", [0] * 16)
        )
        embedding_score = cosine_similarity(
            candidate["embedding_signature"],
            stable.get("embedding_signature", [0.0] * 32),
        )
        rerank_score = rerank_similarity(candidate, stable)
        taxonomy_score = taxonomy_overlap_score(candidate, stable)
        cve_score = cve_overlap_score(candidate, stable)
        bom_score_val = bom_overlap_score(candidate, stable)
        score = round(
            (1.0 if content_hash_match else 0.0) * 0.3
            + simhash_score * 0.12
            + minhash_score * 0.08
            + embedding_score * 0.18
            + rerank_score * 0.18
            + taxonomy_score * 0.07
            + cve_score * 0.04
            + bom_score_val * 0.03,
            4,
        )
        narrative_delta = rerank_score < 0.82
        bom_delta, bom_delta_reasons = describe_bom_delta(stable, candidate)
        return {
            "stable": stable,
            "score": score,
            "content_hash_match": content_hash_match,
            "simhash_score": simhash_score,
            "minhash_score": minhash_score,
            "embedding_score": embedding_score,
            "rerank_score": rerank_score,
            "taxonomy_score": taxonomy_score,
            "cve_score": cve_score,
            "bom_score": bom_score_val,
            "narrative_delta_detected": narrative_delta,
            "bom_delta_detected": bom_delta,
            "bom_delta_reasons": bom_delta_reasons,
        }

    # ------------------------------------------------------------------
    # Stable record management (unchanged from original)
    # ------------------------------------------------------------------

    def _normalize_stable_record(
        self,
        record: dict[str, Any],
        *,
        refresh: bool = False,
    ) -> dict[str, Any]:
        text = record.get("dedup_text")
        if refresh or not isinstance(text, str) or not text.strip():
            text = build_dedup_text(record)
            record["dedup_text"] = text

        if refresh or not record.get("content_hash_signature"):
            record["content_hash_signature"] = compute_content_hash(record)

        simhash_signature = record.get("simhash_signature")
        if refresh or not isinstance(simhash_signature, int):
            record["simhash_signature"] = compute_simhash(text)

        minhash_signature = record.get("minhash_signature")
        if (
            refresh
            or not isinstance(minhash_signature, list)
            or len(minhash_signature) != DEDUP_MINHASH_SIZE
        ):
            record["minhash_signature"] = compute_minhash(text)

        embedding_signature = record.get("embedding_signature")
        if (
            refresh
            or not isinstance(embedding_signature, list)
            or len(embedding_signature) != DEDUP_EMBEDDING_SIZE
        ):
            record["embedding_signature"] = generate_embedding(text)

        return record

    def _new_stable_record(
        self, candidate: dict[str, Any], *, decision: str
    ) -> dict[str, Any]:
        stable_code = f"stable_{uuid4().hex[:16]}"
        return StableAttackRecordDTO(
            stable_attack_id=stable_code,
            stable_attack_code=stable_code,
            canonical_name=candidate["canonical_name"],
            attack_family=candidate["attack_family"],
            severity_level=candidate["severity_level"],
            summary=candidate.get("summary"),
            description=candidate["description"],
            taxonomy_items=candidate.get("taxonomy_items", []),
            cvss_hint=candidate.get("cvss_hint"),
            bom_mentions=candidate.get("bom_mentions", []),
            evidence_refs=list(dict.fromkeys(candidate.get("evidence_refs", []))),
            source_coverage=list(dict.fromkeys(candidate.get("source_coverage", []))),
            related_raw_ids=list(dict.fromkeys(candidate.get("related_raw_ids", []))),
            member_attack_codes=list(
                dict.fromkeys(candidate.get("member_attack_codes", []))
            ),
            last_decision=decision,
            confidence_score=float(candidate.get("confidence_score", 0.0)),
        ).model_dump(mode="python") | {
            "content_hash_signature": candidate["content_hash_signature"],
            "simhash_signature": candidate["simhash_signature"],
            "minhash_signature": candidate["minhash_signature"],
            "embedding_signature": candidate["embedding_signature"],
            "dedup_text": candidate["dedup_text"],
        }

    def _merge_records(
        self, existing: dict[str, Any], incoming: dict[str, Any]
    ) -> dict[str, Any]:
        merged = deepcopy(existing)
        merged["summary"] = merged.get("summary") or incoming.get("summary")
        if len(incoming.get("description", "")) > len(merged.get("description", "")):
            merged["description"] = incoming.get("description")
        merged["taxonomy_items"] = _merge_dict_list(
            existing.get("taxonomy_items", []),
            incoming.get("taxonomy_items", []),
            key="taxonomy_code",
        )
        merged["bom_mentions"] = _merge_dict_list(
            existing.get("bom_mentions", []),
            incoming.get("bom_mentions", []),
            key="mentioned_name",
        )
        merged["evidence_refs"] = list(
            dict.fromkeys(
                [*existing.get("evidence_refs", []), *incoming.get("evidence_refs", [])]
            )
        )
        merged["source_coverage"] = list(
            dict.fromkeys(
                [
                    *existing.get("source_coverage", []),
                    *incoming.get("source_coverage", []),
                ]
            )
        )
        merged["related_raw_ids"] = list(
            dict.fromkeys(
                [
                    *existing.get("related_raw_ids", []),
                    *incoming.get("related_raw_ids", []),
                ]
            )
        )
        merged["member_attack_codes"] = list(
            dict.fromkeys(
                [
                    *existing.get("member_attack_codes", []),
                    *incoming.get("member_attack_codes", []),
                ]
            )
        )
        merged["last_decision"] = "merge"
        merged["confidence_score"] = max(
            float(existing.get("confidence_score", 0.0)),
            float(incoming.get("confidence_score", 0.0)),
        )
        return merged

    def _replace_stable_record(
        self,
        stable_records: list[dict[str, Any]],
        stable_attack_id: str,
        replacement: dict[str, Any],
    ) -> None:
        for index, record in enumerate(stable_records):
            if record.get("stable_attack_id") == stable_attack_id:
                stable_records[index] = replacement
                return

    # ------------------------------------------------------------------
    # Decision building (enhanced with LLM fields)
    # ------------------------------------------------------------------

    def _decision(
        self,
        candidate: dict[str, Any],
        matched: dict[str, Any] | None,
        best: dict[str, Any] | None,
        *,
        decision: str,
        reasons: list[str],
        llm_judgment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        matched_candidate_ids: list[str] = []
        if matched and matched.get("stable_attack_id"):
            matched_candidate_ids = [str(matched.get("stable_attack_id"))]

        adjudicator_summary: dict[str, Any] | None = None
        if llm_judgment is not None:
            adjudicator_summary = {
                "llm_merge_judge": True,
                "llm_verdict": llm_judgment.get("verdict"),
                "llm_recommended_action": llm_judgment.get("recommended_action"),
                "llm_confidence": llm_judgment.get("confidence"),
                "llm_explanation": llm_judgment.get("explanation"),
                "llm_risk_notes": llm_judgment.get("risk_notes", []),
            }

        return DedupDecisionDTO(
            decision=decision,
            matched_attack_id=matched.get("stable_attack_id") if matched else None,
            similarity_score=float(best.get("score", 0.0) if best else 0.0),
            reasons=reasons,
            bom_delta_detected=bool(
                best.get("bom_delta_detected", False) if best else False
            ),
            narrative_delta_detected=bool(
                best.get("narrative_delta_detected", True) if best else True
            ),
            content_hash_match=bool(
                best.get("content_hash_match", False) if best else False
            ),
            simhash_score=float(best.get("simhash_score", 0.0) if best else 0.0),
            minhash_score=float(best.get("minhash_score", 0.0) if best else 0.0),
            embedding_score=float(best.get("embedding_score", 0.0) if best else 0.0),
            rerank_score=float(best.get("rerank_score", 0.0) if best else 0.0),
            taxonomy_overlap_score=float(
                best.get("taxonomy_score", 0.0) if best else 0.0
            ),
            cve_overlap_score=float(best.get("cve_score", 0.0) if best else 0.0),
            bom_overlap_score=float(best.get("bom_score", 0.0) if best else 0.0),
            matched_candidate_ids=matched_candidate_ids,
            merge_audit_ref=None,
            adjudicator_summary=adjudicator_summary,
        ).model_dump(mode="python")

    def _adjudicate(
        self,
        candidate: dict[str, Any],
        decision: dict[str, Any],
        top_k_candidates: list[dict[str, Any]],
        best: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if self.adjudicator is None:
            return decision
        return self.adjudicator.adjudicate(
            candidate=candidate,
            system_decision=decision,
            top_k_candidates=top_k_candidates,
            best_signals=best,
        )

    def _audit(
        self,
        stable_record: dict[str, Any],
        candidate: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        audit_id = f"merge_audit_{uuid4().hex[:16]}"
        decision["merge_audit_ref"] = audit_id
        return MergeAuditRecordDTO(
            merge_audit_id=audit_id,
            stable_attack_id=stable_record["stable_attack_id"],
            candidate_raw_id=str(candidate["raw_id"]),
            decision=decision["decision"],
            incoming_attack_code=candidate["attack_code"],
            matched_attack_id=decision.get("matched_attack_id"),
            similarity_score=decision["similarity_score"],
            reasons=decision["reasons"],
            bom_delta_detected=decision["bom_delta_detected"],
            narrative_delta_detected=decision["narrative_delta_detected"],
            evidence_refs=stable_record.get("evidence_refs", []),
            source_coverage=stable_record.get("source_coverage", []),
            created_at=datetime.now(timezone.utc).isoformat(),
        ).model_dump(mode="python")

    def _build_resolved_item(
        self,
        candidate: dict[str, Any],
        stable_record: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        resolved = deepcopy(candidate)
        resolved["source_metadata"] = {
            **resolved.get("source_metadata", {}),
            "stable_attack_id": stable_record["stable_attack_id"],
            "stable_attack_code": stable_record.get("stable_attack_code"),
            "dedup_decision": decision["decision"],
            "matched_attack_id": decision.get("matched_attack_id"),
            "source_coverage": stable_record.get("source_coverage", []),
        }
        resolved["evidence_refs"] = list(
            dict.fromkeys(
                [
                    *resolved.get("evidence_refs", []),
                    *stable_record.get("evidence_refs", []),
                ]
            )
        )
        resolved["bom_mentions"] = stable_record.get(
            "bom_mentions", resolved.get("bom_mentions", [])
        )
        resolved["taxonomy_items"] = stable_record.get(
            "taxonomy_items", resolved.get("taxonomy_items", [])
        )
        resolved["dedup_decision"] = decision["decision"]
        resolved["merge_audit_ref"] = decision.get("merge_audit_ref")
        return resolved


def _merge_dict_list(
    left: list[dict[str, Any]], right: list[dict[str, Any]], *, key: str
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in [*left, *right]:
        item_key = str(item.get(key, "")).lower()
        if not item_key:
            continue
        existing = merged.get(item_key)
        if existing is None:
            merged[item_key] = deepcopy(item)
            continue
        candidate_conf = float(item.get("confidence_score", 0.0))
        existing_conf = float(existing.get("confidence_score", 0.0))
        if candidate_conf >= existing_conf:
            merged[item_key] = deepcopy(item)
    return list(merged.values())
