from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any
from uuid import UUID

from backend.db.dtos import TaxonomyItemDTO
from backend.db.services.cvss_service import CvssService
from backend.db.services.taxonomy_service import TaxonomyService
from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)

_VALID_SEVERITY_LEVELS = {"info", "low", "medium", "high", "critical"}
_VALID_CVSS_VERSIONS = {"3.0", "3.1", "4.0"}
_VALID_CVSS_SEVERITY_LABELS = {"None", "Low", "Medium", "High", "Critical"}


class DedupMemoryService:
    """DB/read-model aligned stable attack memory service.

    This service loads prior stable attack units from DB read models when available and
    persists post-dedup merge results back into DB attack tables and governance audit
    records. If the DB is unavailable, it degrades to an in-memory empty baseline for
    the current run, instead of using local file persistence.
    """

    def __init__(self, base_dir: str | None = None):
        self.base_dir = base_dir

    def load_records(self, *, trace_id: str | None = None) -> list[dict[str, Any]]:
        try:
            with UnitOfWork(
                context=SqlContext(trace_id=trace_id, agent_name="dedup_memory_load"),
                read_only=True,
            ) as uow:
                rows = uow.read_models.list_wp12_attack_feed(limit=500)
                grouped: dict[str, list[Any]] = defaultdict(list)
                for row in rows:
                    grouped[str(row.attack_id)].append(row)

                records: list[dict[str, Any]] = []
                for attack_id, group_rows in grouped.items():
                    first = group_rows[0]
                    taxonomy_items = [
                        {
                            "taxonomy_type": item.taxonomy_type,
                            "taxonomy_code": item.taxonomy_code,
                            "taxonomy_name": item.taxonomy_name,
                            "is_primary": item.is_primary,
                            "confidence_score": float(item.confidence_score),
                        }
                        for item in uow.attacks.list_taxonomy_maps(attack_id)
                    ]
                    evidence = uow.attacks.list_attack_evidence(attack_id)
                    component_impacts = uow.components.list_component_impacts_by_attack(
                        attack_id
                    )

                    bom_mentions: list[dict[str, Any]] = []
                    source_coverage: set[str] = set()
                    evidence_refs: set[str] = set()
                    member_attack_codes: set[str] = set()
                    related_raw_ids: set[str] = set()
                    for row in group_rows:
                        member_attack_codes.add(row.attack_code)
                        if row.artifact_uri:
                            evidence_refs.add(row.artifact_uri)
                        if row.component_name:
                            bom_mentions.append(
                                {
                                    "mentioned_name": row.component_name,
                                    "mentioned_vendor": None,
                                    "mentioned_version": row.normalized_constraint,
                                    "confidence_score": 0.85,
                                    "reason_code": "db_read_model_component",
                                }
                            )
                        if row.taxonomy_code:
                            source_coverage.add(f"taxonomy:{row.taxonomy_code}")
                    for evidence_row in evidence:
                        related_raw_ids.add(str(evidence_row.raw_id))
                        evidence_refs.add(f"raw://{evidence_row.raw_id}")
                    for impact in component_impacts:
                        bom_mentions.append(
                            {
                                "mentioned_name": str(impact.component_id),
                                "mentioned_vendor": None,
                                "mentioned_version": impact.normalized_constraint,
                                "confidence_score": float(impact.confidence_score),
                                "reason_code": f"db_component_impact:{impact.match_mode}",
                            }
                        )

                    dedup_bom = _dedupe_bom_mentions(bom_mentions)
                    records.append(
                        {
                            "stable_attack_id": attack_id,
                            "stable_attack_code": first.attack_code,
                            "canonical_name": first.canonical_name,
                            "attack_family": first.attack_family,
                            "severity_level": first.severity_level,
                            "summary": first.summary,
                            "description": first.summary or first.canonical_name,
                            "taxonomy_items": taxonomy_items,
                            "cvss_hint": {
                                "cvss_version": first.primary_cvss_version,
                                "base_score": float(first.primary_cvss_base_score)
                                if first.primary_cvss_base_score is not None
                                else None,
                                "severity_label": first.primary_cvss_severity_label,
                                "score_origin": _normalize_score_origin("db_primary"),
                                "vector_string": first.primary_cvss_vector,
                            }
                            if first.primary_cvss_version
                            else None,
                            "bom_mentions": dedup_bom,
                            "evidence_refs": sorted(evidence_refs),
                            "source_coverage": sorted(source_coverage)
                            or [first.attack_code],
                            "related_raw_ids": sorted(related_raw_ids),
                            "member_attack_codes": sorted(member_attack_codes),
                            "last_decision": "merge",
                            "confidence_score": float(
                                first.primary_cvss_base_score or 0.0
                            )
                            / 10.0
                            if first.primary_cvss_base_score is not None
                            else 0.0,
                        }
                    )
                return records
        except Exception as exc:
            logger.warning("dedup_memory_load failed: %s", exc)
            return []
        return []

    def save_records(
        self, records: list[dict[str, Any]], *, trace_id: str | None = None
    ) -> dict[str, Any]:
        return self.persist_records(records, trace_id=trace_id)

    def persist_records(
        self, records: list[dict[str, Any]], *, trace_id: str | None = None
    ) -> dict[str, Any]:
        summary = _new_persist_summary()
        if not records:
            return summary
        for record in records:
            attack_code = str(
                record.get("stable_attack_code")
                or record.get("stable_attack_id")
                or "unknown"
            )
            summary["attempted_count"] += 1
            try:
                normalized, normalization_notes = _normalize_record_for_persist(record)
                item_result = {
                    "attack_code": attack_code,
                    "status": "persisted",
                    "normalization_notes": normalization_notes,
                    "substeps": {
                        "attack_entry": "ok",
                        "evidence": "skipped_no_valid_raw",
                        "taxonomy": "skipped_empty",
                        "component_impacts": "skipped_empty",
                        "cvss": "skipped_empty",
                    },
                }
                # Single UoW per record: reduces 5 separate DB connections to 1.
                with UnitOfWork(
                    context=SqlContext(
                        trace_id=trace_id,
                        agent_name="dedup_memory_persist",
                    )
                ) as uow:
                    attack = self._persist_attack_entry(
                        attack_code=attack_code,
                        record=normalized,
                        uow=uow,
                    )
                    attack_id = str(attack.attack_id)
                    _mark_substep(summary, "attack_entry", "ok")

                    raw_id = _select_existing_raw_id_with_uow(
                        raw_ids=normalized.get("related_raw_ids", []) or [],
                        uow=uow,
                    )

                    evidence_status = self._persist_attack_evidence(
                        attack_id=attack_id,
                        raw_id=raw_id,
                        evidence_snippet=normalized.get("summary"),
                        uow=uow,
                    )
                    item_result["substeps"]["evidence"] = evidence_status
                    _mark_substep(summary, "evidence", evidence_status)

                    taxonomy_status = self._persist_taxonomy_items(
                        attack_id=attack_id,
                        taxonomy_items=normalized.get("taxonomy_items", []),
                        uow=uow,
                    )
                    item_result["substeps"]["taxonomy"] = taxonomy_status
                    _mark_substep(summary, "taxonomy", taxonomy_status)

                    component_status = self._persist_component_impacts(
                        attack_id=attack_id,
                        bom_mentions=normalized.get("bom_mentions", []),
                        evidence_refs=normalized.get("evidence_refs", []) or [],
                        uow=uow,
                    )
                    item_result["substeps"]["component_impacts"] = component_status
                    _mark_substep(summary, "component_impacts", component_status)

                    cvss_status = self._persist_cvss_hint(
                        attack_id=attack_id,
                        cvss_hint=normalized.get("cvss_hint"),
                        raw_id=raw_id,
                        uow=uow,
                    )
                    item_result["substeps"]["cvss"] = cvss_status
                    _mark_substep(summary, "cvss", cvss_status)

                summary["persisted_count"] += 1

                if any(
                    status.endswith("_failed")
                    for status in item_result["substeps"].values()
                ):
                    item_result["status"] = "partial_failure"
                    summary["partial_failure_count"] += 1
                    summary["failure_reasons"].append(
                        {
                            "attack_code": attack_code,
                            "stage": "substeps",
                            "message": "One or more persistence substeps failed.",
                            "substeps": dict(item_result["substeps"]),
                        }
                    )
                    summary["dead_letter_count"] += 1
                    dead_letter_path = self._append_dead_letter(
                        trace_id=trace_id,
                        kind="persist_partial",
                        payload={
                            "attack_code": attack_code,
                            "record": normalized,
                            "result": item_result,
                        },
                    )
                    summary["dead_letter_path"] = dead_letter_path
            except Exception as exc:
                logger.warning(
                    "dedup_memory_persist skipped attack_code=%s: %s",
                    attack_code,
                    exc,
                )
                summary["failed_count"] += 1
                summary["failure_reasons"].append(
                    {
                        "attack_code": attack_code,
                        "stage": "attack_entry",
                        "message": str(exc),
                    }
                )
                summary["dead_letter_count"] += 1
                summary["dead_letter_path"] = self._append_dead_letter(
                    trace_id=trace_id,
                    kind="persist_failed",
                    payload={
                        "attack_code": attack_code,
                        "record": record,
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    },
                )
                _mark_substep(summary, "attack_entry", "failed")
                continue
        summary["failure_reasons"] = summary["failure_reasons"][:20]
        return summary

    def append_audits(
        self, audits: list[dict[str, Any]], *, trace_id: str | None = None
    ) -> dict[str, Any]:
        summary = _new_audit_summary()
        if not audits:
            return summary

        # Validate raw_ids before opening any DB connection.
        valid_entries: list[tuple[str, dict[str, Any]]] = []
        for audit in audits:
            summary["attempted_count"] += 1
            candidate_raw_id = _parse_uuid_or_none(audit.get("candidate_raw_id"))
            if candidate_raw_id is None:
                logger.warning(
                    "dedup_memory_audit skipped invalid candidate_raw_id=%r",
                    audit.get("candidate_raw_id"),
                )
                summary["invalid_candidate_count"] += 1
                continue
            valid_entries.append((candidate_raw_id, audit))

        if not valid_entries:
            summary["failure_reasons"] = summary["failure_reasons"][:20]
            return summary

        # Single UoW for all audit inserts: reduces N DB connections to 1.
        try:
            with UnitOfWork(
                context=SqlContext(
                    trace_id=trace_id,
                    agent_name="dedup_memory_audit",
                )
            ) as uow:
                for candidate_raw_id, audit in valid_entries:
                    if uow.sources.get_raw_record_by_id(candidate_raw_id) is None:
                        logger.warning(
                            "dedup_memory_audit skipped missing candidate_raw_id=%s",
                            candidate_raw_id,
                        )
                        summary["missing_candidate_count"] += 1
                        continue
                    uow.governance.insert_dedup_audit(
                        candidate_raw_id=candidate_raw_id,
                        matched_attack_id=_parse_uuid_or_none(
                            audit.get("matched_attack_id")
                        ),
                        similarity_score=float(audit.get("similarity_score", 0.0)),
                        rule_name=str(
                            audit.get("rule_name") or "phase4_multi_stage_dedup"
                        ),
                        decision=audit.get("decision", "review"),
                        reviewer_name=None,
                    )
                    summary["persisted_count"] += 1
        except Exception as exc:
            logger.warning("dedup_memory_audit batch failed: %s", exc)
            unwritten = len(valid_entries) - summary["persisted_count"]
            summary["failed_count"] += unwritten
            summary["failure_reasons"].append({"message": str(exc)})

        summary["failure_reasons"] = summary["failure_reasons"][:20]
        return summary

    def _persist_attack_entry(
        self,
        *,
        attack_code: str,
        record: dict[str, Any],
        uow: Any,
    ):
        return uow.attacks.upsert_attack_entry_by_code(
            attack_code=attack_code,
            canonical_name=record["canonical_name"],
            attack_family=record["attack_family"],
            severity_level=record["severity_level"],
            entry_status="active",
            summary=record["summary"],
            description=record["description"],
            exploit_preconditions=None,
            impact_scope=None,
            confidence_score=float(record.get("confidence_score", 0.0)),
            first_seen_at=None,
            last_seen_at=None,
            stix_type=None,
            stix_payload=None,
        )

    def _persist_attack_evidence(
        self,
        *,
        attack_id: str,
        raw_id: str | None,
        evidence_snippet: Any,
        uow: Any,
    ) -> str:
        if raw_id is None:
            return "skipped_no_valid_raw"
        try:
            uow.attacks.insert_attack_evidence(
                attack_id=attack_id,
                raw_id=raw_id,
                evidence_role="supporting",
                extractor_name="dedup_memory_service",
                evidence_snippet=str(evidence_snippet or "")[:1000] or None,
            )
            return "ok"
        except Exception as exc:
            logger.warning(
                "dedup_memory_persist_evidence failed attack_id=%s raw_id=%s: %s",
                attack_id,
                raw_id,
                exc,
            )
            return "write_failed"

    def _persist_taxonomy_items(
        self,
        *,
        attack_id: str,
        taxonomy_items: list[dict[str, Any]],
        uow: Any,
    ) -> str:
        normalized_taxonomy, _ = _normalize_taxonomy_items(taxonomy_items)
        if not normalized_taxonomy:
            return "skipped_empty"
        try:
            TaxonomyService(uow).replace_taxonomy_set(
                attack_id=attack_id,
                taxonomy_items=normalized_taxonomy,
            )
            return "ok"
        except Exception as exc:
            logger.warning(
                "dedup_memory_persist_taxonomy failed attack_id=%s: %s",
                attack_id,
                exc,
            )
            return "write_failed"

    def _persist_component_impacts(
        self,
        *,
        attack_id: str,
        bom_mentions: list[dict[str, Any]],
        evidence_refs: list[Any],
        uow: Any,
    ) -> str:
        normalized_mentions = _normalize_bom_mentions(bom_mentions)
        if not normalized_mentions:
            return "skipped_empty"
        # Component relationships are now owned by the AI BOM subgraph.
        # Dedup only preserves weak mentions in the stable record and does not
        # perform early rule-based writes into attack_component_impact.
        return "deferred_to_ai_bom_subgraph"

    def _persist_cvss_hint(
        self,
        *,
        attack_id: str,
        cvss_hint: dict[str, Any] | None,
        raw_id: str | None,
        uow: Any,
    ) -> str:
        normalized_cvss = _normalize_cvss_hint(cvss_hint)
        if normalized_cvss is None:
            return "skipped_empty"
        try:
            CvssService(uow).add_cvss_assessment(
                attack_id=attack_id,
                source_raw_id=raw_id,
                cvss_version=normalized_cvss["cvss_version"],
                vector_string=normalized_cvss.get("vector_string"),
                base_score=float(normalized_cvss["base_score"]),
                temporal_score=None,
                environmental_score=None,
                severity_label=normalized_cvss["severity_label"],
                exploitability_subscore=None,
                impact_subscore=None,
                score_origin=normalized_cvss["score_origin"],
                score_provider="dedup_memory_service",
                confidence_score=0.8,
                is_primary=True,
            )
            return "ok"
        except Exception as exc:
            logger.warning(
                "dedup_memory_persist_cvss failed attack_id=%s: %s",
                attack_id,
                exc,
            )
            return "write_failed"

    def _append_dead_letter(
        self,
        *,
        trace_id: str | None,
        kind: str,
        payload: dict[str, Any],
    ) -> str | None:
        try:
            dead_letter_dir = Path(self.base_dir or ".runtime/wp11/dedup") / "dead_letters"
            dead_letter_dir.mkdir(parents=True, exist_ok=True)
            safe_trace = _safe_path_token(trace_id or "manual")
            target = dead_letter_dir / f"{kind}_{safe_trace}.jsonl"
            envelope = {
                "kind": kind,
                "trace_id": trace_id,
                "written_at": datetime.now(timezone.utc).isoformat(),
                **payload,
            }
            with target.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(envelope, ensure_ascii=False, default=str))
                fh.write("\n")
            return str(target)
        except Exception as exc:
            logger.warning("dedup_memory_dead_letter failed: %s", exc)
            return None


def _dedupe_bom_mentions(mentions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for mention in mentions:
        key = str(mention.get("mentioned_name", "")).lower()
        if not key:
            continue
        existing = deduped.get(key)
        if existing is None or float(mention.get("confidence_score", 0.0)) >= float(
            existing.get("confidence_score", 0.0)
        ):
            deduped[key] = mention
    return list(deduped.values())


def _normalize_score_origin(value: Any) -> str:
    allowed = {"supplied", "calculated", "estimated", "manual"}
    normalized = str(value or "").strip().lower()
    if normalized in allowed:
        return normalized
    return "estimated"


def _parse_uuid_or_none(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        return str(UUID(raw))
    except (TypeError, ValueError, AttributeError):
        return None


def _select_existing_raw_id(*, raw_ids: list[Any], trace_id: str | None) -> str | None:
    for raw_id in raw_ids:
        normalized = _parse_uuid_or_none(raw_id)
        if normalized is None:
            continue
        with UnitOfWork(
            context=SqlContext(
                trace_id=trace_id,
                agent_name="dedup_memory_resolve_raw",
            ),
            read_only=True,
        ) as uow:
            if uow.sources.get_raw_record_by_id(normalized) is not None:
                return normalized
    return None


def _select_existing_raw_id_with_uow(
    *, raw_ids: list[Any], uow: Any
) -> str | None:
    """Like _select_existing_raw_id but reuses an existing UoW session."""
    for raw_id in raw_ids:
        normalized = _parse_uuid_or_none(raw_id)
        if normalized is None:
            continue
        if uow.sources.get_raw_record_by_id(normalized) is not None:
            return normalized
    return None


def _new_persist_summary() -> dict[str, Any]:
    return {
        "attempted_count": 0,
        "persisted_count": 0,
        "partial_failure_count": 0,
        "failed_count": 0,
        "dead_letter_count": 0,
        "dead_letter_path": None,
        "failure_reasons": [],
        "substep_counts": {
            "attack_entry": {},
            "evidence": {},
            "taxonomy": {},
            "component_impacts": {},
            "cvss": {},
        },
    }


def _new_audit_summary() -> dict[str, Any]:
    return {
        "attempted_count": 0,
        "persisted_count": 0,
        "invalid_candidate_count": 0,
        "missing_candidate_count": 0,
        "failed_count": 0,
        "failure_reasons": [],
    }


def _mark_substep(summary: dict[str, Any], substep: str, status: str) -> None:
    bucket = summary.setdefault("substep_counts", {}).setdefault(substep, {})
    bucket[status] = int(bucket.get(status, 0)) + 1


def _normalize_record_for_persist(
    record: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    notes: list[str] = []
    canonical_name = str(record.get("canonical_name") or "").strip()
    if not canonical_name:
        canonical_name = str(
            record.get("stable_attack_code")
            or record.get("stable_attack_id")
            or "unknown_attack"
        ).strip()
        notes.append("canonical_name_defaulted_from_attack_code")

    attack_family = str(record.get("attack_family") or "").strip()
    if not attack_family:
        attack_family = "unknown"
        notes.append("attack_family_defaulted_unknown")
    if len(attack_family) > 80:
        attack_family = attack_family[:80]
        notes.append("attack_family_truncated_80")

    severity_level = str(record.get("severity_level") or "").strip().lower()
    if severity_level not in _VALID_SEVERITY_LEVELS:
        raise ValueError(f"invalid severity_level={severity_level!r}")

    summary = str(record.get("summary") or "").strip()
    if not summary:
        summary = canonical_name
        notes.append("summary_defaulted_from_canonical_name")

    description = str(record.get("description") or "").strip()
    if not description:
        description = summary
        notes.append("description_defaulted_from_summary")

    raw_confidence = record.get("confidence_score", 0.0)
    try:
        parsed_confidence = float(raw_confidence or 0.0)
    except (TypeError, ValueError):
        parsed_confidence = 0.0
        notes.append("confidence_score_defaulted_zero")
    confidence_score = _clamp(parsed_confidence, 0.0, 1.0)
    if parsed_confidence != confidence_score:
        notes.append("confidence_score_clamped")

    normalized_taxonomy, taxonomy_notes = _normalize_taxonomy_items(
        record.get("taxonomy_items", []) or []
    )
    notes.extend(taxonomy_notes)

    normalized = dict(record)
    normalized.update(
        {
            "canonical_name": canonical_name,
            "attack_family": attack_family,
            "severity_level": severity_level,
            "summary": summary,
            "description": description,
            "confidence_score": confidence_score,
            "taxonomy_items": normalized_taxonomy,
            "bom_mentions": _normalize_bom_mentions(record.get("bom_mentions", []) or []),
            "cvss_hint": _normalize_cvss_hint(record.get("cvss_hint")),
        }
    )
    return normalized, notes


def _normalize_taxonomy_items(
    items: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    normalized: list[dict[str, Any]] = []
    notes: list[str] = []
    seen_primary: set[str] = set()
    for idx, item in enumerate(items):
        try:
            dto = TaxonomyItemDTO.model_validate(item)
            payload = dto.model_dump(mode="python")
            taxonomy_type = payload["taxonomy_type"]
            if payload["is_primary"]:
                if taxonomy_type in seen_primary:
                    payload["is_primary"] = False
                    notes.append(
                        f"taxonomy_items[{idx}] duplicate_primary_demoted"
                    )
                else:
                    seen_primary.add(taxonomy_type)
            normalized.append(payload)
        except Exception as exc:
            notes.append(f"taxonomy_items[{idx}] skipped:{type(exc).__name__}")
    return normalized, notes


def _normalize_bom_mentions(mentions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for mention in mentions:
        name = str(mention.get("mentioned_name") or "").strip()
        if not name:
            continue
        dedupe_key = name.lower()
        if dedupe_key in seen_names:
            continue
        seen_names.add(dedupe_key)
        normalized.append(
            {
                **mention,
                "mentioned_name": name,
                "mentioned_version": (
                    str(mention.get("mentioned_version")).strip()
                    if mention.get("mentioned_version") is not None
                    else None
                ),
                "confidence_score": _clamp(
                    float(mention.get("confidence_score", 0.7) or 0.7),
                    0.0,
                    1.0,
                ),
            }
        )
    return normalized


def _normalize_cvss_hint(cvss_hint: dict[str, Any] | None) -> dict[str, Any] | None:
    if not cvss_hint:
        return None
    raw_score = cvss_hint.get("base_score")
    if raw_score is None:
        return None
    try:
        base_score = _clamp(float(raw_score), 0.0, 10.0)
    except (TypeError, ValueError):
        return None
    cvss_version = str(cvss_hint.get("cvss_version") or "3.1").strip()
    if cvss_version not in _VALID_CVSS_VERSIONS:
        cvss_version = "3.1"
    severity_label = str(cvss_hint.get("severity_label") or "").strip()
    if severity_label not in _VALID_CVSS_SEVERITY_LABELS:
        severity_label = _cvss_severity_label(base_score)
    vector_string = cvss_hint.get("vector_string")
    return {
        "cvss_version": cvss_version,
        "base_score": base_score,
        "severity_label": severity_label,
        "score_origin": _normalize_score_origin(cvss_hint.get("score_origin")),
        "vector_string": str(vector_string).strip()[:255] if vector_string else None,
    }


def _cvss_severity_label(base_score: float) -> str:
    if base_score <= 0.0:
        return "None"
    if base_score < 4.0:
        return "Low"
    if base_score < 7.0:
        return "Medium"
    if base_score < 9.0:
        return "High"
    return "Critical"


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _safe_path_token(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)
