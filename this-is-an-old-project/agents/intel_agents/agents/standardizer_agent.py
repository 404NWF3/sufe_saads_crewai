from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from ..schemas.intel import (
    LlmStandardizationAuditDTO,
    RawCollectedItemDTO,
    StandardizedIntelDTO,
)
from ..schemas.runtime import StandardizationStrategyValue
from ..tools.llm_client_factory import resolve_default_model
from ..tools import (
    LangChainLlmStandardizer,
    RuleValidatorFuser,
    build_attack_code,
    build_extraction_reason,
    build_stix_attack_object,
    clean_raw_content,
    detect_conflict_flags,
    extract_bom_mentions,
    extract_cve_references,
    extract_evidence_snippet,
    infer_attack_family,
    infer_cvss_hint,
    infer_taxonomy_labels,
    load_raw_payload,
    normalize_text_fields,
    score_field_confidence,
    source_specific_projection,
    validate_standardized_projection,
)
from ..tools.llm_standardization_tools import PROMPT_VERSION


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class StandardizerAgent:
    """Normalize heterogeneous raw records into unified attack-intel objects.

    Architecture (v2 — LLM primary):
        1. Parse & clean the raw payload.
        2. If strategy allows LLM (``llm_required`` or ``llm_optional``):
           a. Call ``LangChainLlmStandardizer.extract()`` — this is the *primary*
              extraction path.
           b. Run ``RuleValidatorFuser.validate_and_fuse()`` on the LLM output.
        3. If LLM is unavailable / fails:
           - ``llm_required`` → propagate error (never silently degrade).
           - ``llm_optional`` → fall back to rule-based extraction but tag the
             result ``rules_only_degraded`` and write ``fallback_reason``.
           - ``rules_only`` / ``rules_only_degraded`` → use rules directly.
        4. Build STIX, evidence, field-confidence, conflict flags, audit.
    """

    def __init__(
        self,
        *,
        strategy: StandardizationStrategyValue = "llm_required",
        llm_standardizer: Any | None = None,
        rule_validator: RuleValidatorFuser | None = None,
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        validate_online: bool = False,
        llm_runtime_config: dict[str, Any] | None = None,
        standardization_max_concurrency: int = 2,
    ) -> None:
        self.strategy = strategy
        self.validate_online = validate_online
        self.llm_runtime_config = llm_runtime_config or {}
        self.llm_model = resolve_default_model(
            llm_model,
            runtime_config=self.llm_runtime_config,
        )
        self.standardization_max_concurrency = max(
            1, int(standardization_max_concurrency or 1)
        )
        self.llm_standardizer = llm_standardizer or LangChainLlmStandardizer(
            model=self.llm_model,
            temperature=llm_temperature,
            runtime_config=self.llm_runtime_config,
        )
        self.rule_validator = rule_validator or RuleValidatorFuser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def standardize_batch(
        self,
        raw_items: list[dict[str, Any]],
        stored_raw_records: list[dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Standardize a batch of raw items.

        Returns
        -------
        tuple[list[dict], list[dict]]
            (standardized_items, llm_standardization_audits)
        """
        raw_index = {
            record["query_run_id"]: record.get("raw_id")
            for record in (stored_raw_records or [])
            if record.get("query_run_id")
        }
        standardized: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []

        def _process_one(raw_item: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            item = RawCollectedItemDTO.model_validate(raw_item)
            raw_id = str(
                raw_index.get(item.query_run_id) or f"raw_untracked_{item.query_run_id}"
            )

            payload = load_raw_payload(item.payload_uri)
            cleaned_payload = clean_raw_content(payload, item.raw_format)
            text_fields = normalize_text_fields(
                item.model_dump(mode="python"), cleaned_payload
            )
            source_projection = source_specific_projection(
                item.model_dump(mode="python"), cleaned_payload
            )
            text_fields["title"] = (
                source_projection.get("title") or text_fields["title"]
            )
            text_fields["summary"] = (
                source_projection.get("summary") or text_fields["summary"]
            )

            # Analysis text for rule fallback
            analysis_text = " ".join(
                part
                for part in [
                    text_fields["title"],
                    text_fields["summary"],
                    text_fields["description"],
                    str(item.metadata.get("query_text", "")),
                    item.source_name,
                ]
                if part
            )

            # ---- Decide execution path ----
            try:
                projection, audit = self._execute_strategy(
                    item=item.model_dump(mode="python"),
                    raw_id=raw_id,
                    analysis_text=analysis_text,
                    text_fields=text_fields,
                    cleaned_payload=cleaned_payload,
                    source_projection=source_projection,
                )
            except Exception as exc:
                # All LLM profiles exhausted or unrecoverable error → degrade
                # this item to rules-only rather than dropping it entirely.
                projection, audit = self._rules_only_path(
                    item=item.model_dump(mode="python"),
                    raw_id=raw_id,
                    analysis_text=analysis_text,
                    text_fields=text_fields,
                    source_projection=source_projection,
                )
                audit = {
                    **audit,
                    "strategy_executed": "rules_only_degraded",
                    "fallback_reason": (
                        f"LLM all profiles exhausted: "
                        f"{exc.__class__.__name__}: {str(exc)[:200]}"
                    ),
                }

            # ---- Build downstream artefacts ----
            cve_refs = extract_cve_references(analysis_text)
            attack_code = build_attack_code(
                raw_id, item.source_name, projection["canonical_name"]
            )
            stix_payload = build_stix_attack_object(
                attack_code=attack_code,
                canonical_name=projection["canonical_name"],
                description=projection["description"],
                labels=projection["taxonomy_items"],
                source_name=item.source_name,
                source_uri=item.source_uri,
                bom_mentions=projection["bom_mentions"],
                cve_refs=cve_refs,
            )
            evidence_snippet = extract_evidence_snippet(
                analysis_text, projection["canonical_name"]
            )

            # Field confidence: use LLM per-field confidences if available,
            # otherwise fall back to rule heuristic
            if projection.get("field_confidences"):
                field_confidence = {
                    fc["field_name"]: round(fc["confidence"], 3)
                    for fc in projection["field_confidences"]
                    if isinstance(fc, dict)
                }
                # Ensure minimum fields exist
                for fname in (
                    "summary",
                    "description",
                    "taxonomy_items",
                    "cvss_hint",
                    "bom_mentions",
                ):
                    if fname not in field_confidence:
                        field_confidence[fname] = 0.5
            else:
                field_confidence = score_field_confidence(
                    summary=projection["summary"],
                    description=projection["description"],
                    taxonomy_items=projection["taxonomy_items"],
                    cvss_hint=projection["cvss_hint"],
                    bom_mentions=projection["bom_mentions"],
                    strategy_used=projection["strategy_used"],
                )

            # Conflict flags: merge rule-validator flags with STIX validation
            conflict_flags = projection.get("conflict_flags", [])
            validation_findings = projection.get("validation_findings", [])

            stix_validation = validate_standardized_projection(
                taxonomy_items=projection["taxonomy_items"],
                cvss_hint=projection["cvss_hint"],
                bom_mentions=projection["bom_mentions"],
                stix_payload=stix_payload,
            )
            validation_findings = list({*validation_findings, *stix_validation})

            standardized_item = StandardizedIntelDTO(
                raw_id=raw_id,
                attack_code=attack_code,
                canonical_name=projection["canonical_name"],
                attack_family=projection["attack_family"],
                severity_level=projection["severity_level"],
                summary=projection["summary"],
                description=projection["description"],
                exploit_preconditions=projection.get("exploit_preconditions"),
                impact_scope=projection.get("impact_scope"),
                first_seen_at=item.published_at,
                last_seen_at=item.fetched_at,
                stix_type="attack-pattern",
                stix_payload=stix_payload,
                evidence_snippet=evidence_snippet,
                artifact_ref=item.artifact_ref,
                evidence_refs=[item.source_uri, item.artifact_ref],
                extraction_reason=projection["extraction_reason"],
                source_confidence=source_confidence_for(item.source_name),
                extraction_confidence=projection["extraction_confidence"],
                taxonomy_items=projection["taxonomy_items"],
                cvss_hint=projection["cvss_hint"],
                bom_mentions=projection["bom_mentions"],
                field_confidence=field_confidence,
                conflict_flags=conflict_flags,
                validation_findings=validation_findings,
                normalization_trace=projection.get("normalization_trace", []),
                source_metadata={
                    "source_name": item.source_name,
                    "query_run_id": item.query_run_id,
                    "external_id": item.external_id,
                    "cve_refs": cve_refs,
                    "standardization_strategy": projection["strategy_used"],
                    "llm_model": projection.get("llm_model"),
                    "prompt_version": projection.get("prompt_version"),
                },
            ).model_dump(mode="python")
            return standardized_item, audit

        max_workers = min(self.standardization_max_concurrency, max(1, len(raw_items)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_one, item) for item in raw_items]
            for future in as_completed(futures):
                s_item, audit = future.result()
                standardized.append(s_item)
                audits.append(audit)

        return standardized, audits

    # ------------------------------------------------------------------
    # Strategy dispatch
    # ------------------------------------------------------------------

    def _execute_strategy(
        self,
        *,
        item: dict[str, Any],
        raw_id: str,
        analysis_text: str,
        text_fields: dict[str, str],
        cleaned_payload: str,
        source_projection: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Choose LLM-primary or rules path and return (projection, audit)."""

        use_llm = self.strategy in ("llm_required", "llm_optional")

        if use_llm:
            return self._llm_primary_path(
                item=item,
                raw_id=raw_id,
                analysis_text=analysis_text,
                text_fields=text_fields,
                cleaned_payload=cleaned_payload,
                source_projection=source_projection,
            )

        # rules_only or rules_only_degraded — pure rules path
        return self._rules_only_path(
            item=item,
            raw_id=raw_id,
            analysis_text=analysis_text,
            text_fields=text_fields,
            source_projection=source_projection,
        )

    # ------------------------------------------------------------------
    # LLM-primary path
    # ------------------------------------------------------------------

    def _llm_primary_path(
        self,
        *,
        item: dict[str, Any],
        raw_id: str,
        analysis_text: str,
        text_fields: dict[str, str],
        cleaned_payload: str,
        source_projection: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """LLM extracts first, then rules validate/fuse."""

        # Build rule fallback projection (lightweight, for fusion only)
        rule_fallback = self._rule_extraction(
            item=item,
            analysis_text=analysis_text,
            text_fields=text_fields,
            source_projection=source_projection,
        )

        fallback_reason: str | None = None
        strategy_executed = "llm_primary"

        try:
            if self.validate_online:
                self.llm_standardizer.validate_connectivity()

            llm_result = self.llm_standardizer.extract(
                {
                    "source_name": item["source_name"],
                    "query_text": item.get("metadata", {}).get("query_text", ""),
                    "title": text_fields["title"],
                    "summary": text_fields["summary"],
                    "cleaned_payload": cleaned_payload[:6000],
                }
            )
        except Exception as exc:
            if self.strategy == "llm_required":
                raise
            # llm_optional → degrade to rules
            fallback_reason = f"LLM failed ({exc.__class__.__name__}: {str(exc)[:200]})"
            strategy_executed = "rules_only_degraded"
            projection = {
                **rule_fallback,
                "strategy_used": "rules_only_degraded",
                "fallback_reason": fallback_reason,
            }
            audit = self._build_audit(
                raw_id=raw_id,
                source_name=item["source_name"],
                strategy_executed=strategy_executed,
                llm_confidence=0.0,
                llm_reason=fallback_reason,
                fallback_reason=fallback_reason,
                projection=projection,
            )
            return projection, audit

        llm_meta: dict[str, Any] = {}
        if isinstance(llm_result, dict):
            llm_meta = dict(llm_result.pop("_llm_meta", {}) or {})

        # Guard: chain.invoke() may return None without raising (LangChain parser failure)
        if llm_result is None:
            if self.strategy == "llm_required":
                raise RuntimeError("LLM standardizer returned None (no structured output)")
            fallback_reason = "LLM returned None (no structured output)"
            strategy_executed = "rules_only_degraded"
            projection = {
                **rule_fallback,
                "strategy_used": "rules_only_degraded",
                "fallback_reason": fallback_reason,
            }
            audit = self._build_audit(
                raw_id=raw_id,
                source_name=item["source_name"],
                strategy_executed=strategy_executed,
                llm_confidence=0.0,
                llm_reason=fallback_reason,
                fallback_reason=fallback_reason,
                projection=projection,
            )
            return projection, audit

        # LLM succeeded — run rule validation/fusion
        validated = self.rule_validator.validate_and_fuse(
            llm_result,
            rule_fallback=rule_fallback,
            allow_field_fusion=False,
        )

        # Merge CVSS: prefer source-supplied CVSS over both LLM and rule estimates
        if source_projection.get("cvss_base_score") is not None:
            validated["cvss_hint"] = {
                **(
                    validated.get("cvss_hint")
                    or {
                        "cvss_version": "3.1",
                        "score_origin": "supplied",
                        "vector_string": None,
                    }
                ),
                "base_score": float(source_projection["cvss_base_score"]),
                "score_origin": "supplied",
            }

        # Build final projection
        extraction_confidence = float(llm_result.get("overall_confidence", 0.85))
        projection = {
            **validated,
            "extraction_confidence": extraction_confidence,
            "strategy_used": strategy_executed,
            "llm_model": llm_meta.get(
                "llm_model", getattr(self.llm_standardizer, "model", "unknown")
            ),
            "prompt_version": getattr(
                self.llm_standardizer, "PROMPT_VERSION", PROMPT_VERSION
            ),
        }

        audit = self._build_audit(
            raw_id=raw_id,
            source_name=item["source_name"],
            strategy_executed=strategy_executed,
            llm_confidence=extraction_confidence,
            llm_reason=str(llm_result.get("extraction_reason", "")),
            fallback_reason=None,
            projection=projection,
            llm_meta=llm_meta,
        )

        return projection, audit

    # ------------------------------------------------------------------
    # Rules-only path (backwards-compatible)
    # ------------------------------------------------------------------

    def _rules_only_path(
        self,
        *,
        item: dict[str, Any],
        raw_id: str,
        analysis_text: str,
        text_fields: dict[str, str],
        source_projection: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Pure rule-based extraction — same logic as v1."""
        projection = self._rule_extraction(
            item=item,
            analysis_text=analysis_text,
            text_fields=text_fields,
            source_projection=source_projection,
        )
        audit = self._build_audit(
            raw_id=raw_id,
            source_name=item["source_name"],
            strategy_executed=projection["strategy_used"],
            llm_confidence=0.0,
            llm_reason="rules_only — no LLM invoked",
            fallback_reason=None,
            projection=projection,
        )
        return projection, audit

    # ------------------------------------------------------------------
    # Rule extraction helper (used as fallback & for fusion)
    # ------------------------------------------------------------------

    def _rule_extraction(
        self,
        *,
        item: dict[str, Any],
        analysis_text: str,
        text_fields: dict[str, str],
        source_projection: dict[str, Any],
    ) -> dict[str, Any]:
        """Deterministic rule-based standardization (same as v1 logic)."""
        attack_family, family_reason = infer_attack_family(analysis_text)
        severity_level = (
            item.get("metadata", {}).get("severity")
            or source_projection.get("severity")
            or infer_severity_level_proxy(analysis_text, item["source_name"])
        )
        taxonomy_items = infer_taxonomy_labels(analysis_text, attack_family)
        cvss_hint = infer_cvss_hint(analysis_text, severity_level)
        if source_projection.get("cvss_base_score") is not None:
            cvss_hint = {
                **(
                    cvss_hint
                    or {
                        "cvss_version": "3.1",
                        "score_origin": "supplied",
                        "vector_string": None,
                    }
                ),
                "base_score": float(source_projection["cvss_base_score"]),
                "score_origin": "supplied",
            }
        bom_mentions = extract_bom_mentions(analysis_text)
        extraction_reason = build_extraction_reason(
            source_name=item["source_name"],
            attack_family_reason=family_reason,
            taxonomy_count=len(taxonomy_items),
            bom_count=len(bom_mentions),
        )

        strategy_label = (
            self.strategy
            if self.strategy in ("rules_only", "rules_only_degraded")
            else "rules_only"
        )

        return {
            "canonical_name": text_fields["title"],
            "attack_family": attack_family,
            "severity_level": severity_level,
            "summary": text_fields["summary"],
            "description": text_fields["description"],
            "exploit_preconditions": None,
            "impact_scope": "ai_component_or_agent_stack",
            "taxonomy_items": taxonomy_items,
            "cvss_hint": cvss_hint,
            "bom_mentions": bom_mentions,
            "extraction_reason": extraction_reason,
            "extraction_confidence": 0.72,
            "strategy_used": strategy_label,
            "normalization_trace": [
                f"source_specific_projection={sorted(source_projection.keys())}",
                f"attack_family={attack_family}",
                f"severity_level={severity_level}",
            ],
            "field_confidences": [],
            "evidence_spans": [],
            "validation_findings": [],
            "conflict_flags": [],
        }

    # ------------------------------------------------------------------
    # Audit builder
    # ------------------------------------------------------------------

    def _build_audit(
        self,
        *,
        raw_id: str,
        source_name: str,
        strategy_executed: str,
        llm_confidence: float,
        llm_reason: str,
        fallback_reason: str | None,
        projection: dict[str, Any],
        llm_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        llm_meta = llm_meta or {}
        return LlmStandardizationAuditDTO(
            raw_id=raw_id,
            source_name=source_name,
            strategy_requested=self.strategy,
            strategy_executed=strategy_executed,
            llm_model=str(
                llm_meta.get(
                    "llm_model", getattr(self.llm_standardizer, "model", "unknown")
                )
            ),
            llm_profile_id=llm_meta.get("profile_id"),
            llm_profile=llm_meta.get("profile"),
            prompt_version=getattr(
                self.llm_standardizer, "PROMPT_VERSION", PROMPT_VERSION
            ),
            llm_confidence=llm_confidence,
            llm_reason=llm_reason or "n/a",
            fallback_reason=fallback_reason,
            evidence_span_count=len(projection.get("evidence_spans", [])),
            field_confidence_count=len(projection.get("field_confidences", [])),
            validation_finding_count=len(projection.get("validation_findings", [])),
            conflict_flag_count=len(projection.get("conflict_flags", [])),
            rule_validation_passed=projection.get("rule_validation_passed", True),
            llm_wait_seconds=llm_meta.get("wait_seconds"),
            attempted_profiles=list(llm_meta.get("attempted_profiles", []) or []),
            attempted_profile_labels=list(
                llm_meta.get("attempted_profile_labels", []) or []
            ),
            invoked_at=_utcnow(),
        ).model_dump(mode="python")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def source_confidence_for(source_name: str) -> float:
    if source_name in {"nvd", "cisa_kev", "mitre_attack"}:
        return 0.92
    if source_name in {"github_advisories", "arxiv"}:
        return 0.84
    return 0.68


def infer_severity_level_proxy(text: str, source_name: str) -> str:
    lowered = text.lower()
    if any(
        token in lowered
        for token in ("critical", "known exploited", "actively exploited")
    ):
        return "critical"
    if any(
        token in lowered
        for token in ("high", "remote code execution", "arbitrary code", "exploit")
    ):
        return "high"
    if source_name in {"nvd", "github_advisories", "cisa_kev", "mitre_attack"}:
        return "medium"
    return "low"
