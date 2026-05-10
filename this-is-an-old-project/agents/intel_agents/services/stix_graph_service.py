from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork


def _utcnow() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class StixGraphService:
    def build_extraction_payload(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "attack_code": self._attack_code_from_item(item),
            "canonical_name": item.get("canonical_name") or "",
            "attack_family": item.get("attack_family") or "",
            "severity_level": item.get("severity_level") or "",
            "summary": item.get("summary") or "",
            "description": item.get("description") or "",
            "taxonomy_json": json.dumps(
                item.get("taxonomy_items", []), ensure_ascii=False
            ),
            "cvss_json": json.dumps(item.get("cvss_hint"), ensure_ascii=False),
            "bom_json": json.dumps(
                item.get("bom_resolutions") or item.get("bom_mentions", []),
                ensure_ascii=False,
            ),
            "evidence_text": "\n".join(
                [
                    str(item.get("summary") or ""),
                    str(item.get("description") or ""),
                    str(item.get("evidence_snippet") or ""),
                ]
            )[:3500],
        }

    def validate_graph_draft(
        self,
        *,
        item: dict[str, Any],
        graph_draft: dict[str, Any] | None,
    ) -> dict[str, Any]:
        evidence_text = "\n".join(
            [
                str(item.get("summary") or ""),
                str(item.get("description") or ""),
                str(item.get("evidence_snippet") or ""),
            ]
        ).strip()
        if graph_draft is None:
            return {
                "attack_code": self._attack_code_from_item(item),
                "fatal": True,
                "findings": ["llm_extraction_missing"],
                "object_count": 0,
                "relationship_count": 0,
                "primary_attack_pattern_refs": [],
                "has_report": False,
                "evidence_text_present": bool(evidence_text),
            }

        findings: list[str] = []
        objects = list(graph_draft.get("objects", []))
        relationships = list(graph_draft.get("relationships", []))
        local_refs = {str(obj.get("local_ref")) for obj in objects if obj.get("local_ref")}
        primary_attack_patterns = [
            str(obj.get("local_ref"))
            for obj in objects
            if obj.get("object_type") == "attack-pattern" and obj.get("is_primary")
        ]
        report_count = sum(1 for obj in objects if obj.get("object_type") == "report")

        if not evidence_text:
            findings.append("insufficient_evidence_text")
        if not objects:
            findings.append("no_objects")
        if report_count != 1:
            findings.append("missing_report" if report_count == 0 else "multiple_reports")
        if len(primary_attack_patterns) != 1:
            findings.append(
                "missing_primary_attack_pattern"
                if len(primary_attack_patterns) == 0
                else "multiple_primary_attack_patterns"
            )

        for obj in objects:
            if obj.get("object_type") == "indicator" and not str(
                obj.get("pattern") or ""
            ).strip():
                findings.append(
                    f"indicator_missing_pattern:{str(obj.get('local_ref') or 'unknown')}"
                )
        for rel in relationships:
            source_ref = str(rel.get("source_ref") or "")
            target_ref = str(rel.get("target_ref") or "")
            if source_ref not in local_refs or target_ref not in local_refs:
                findings.append(
                    f"broken_relationship_ref:{str(rel.get('local_ref') or 'unknown')}"
                )

        fatal_prefixes = (
            "llm_extraction_missing",
            "no_objects",
            "missing_primary_attack_pattern",
            "multiple_primary_attack_patterns",
            "missing_report",
            "multiple_reports",
            "indicator_missing_pattern:",
            "broken_relationship_ref:",
        )
        return {
            "attack_code": self._attack_code_from_item(item),
            "fatal": any(
                finding == prefix or finding.startswith(prefix)
                for finding in findings
                for prefix in fatal_prefixes
            ),
            "findings": findings,
            "object_count": len(objects),
            "relationship_count": len(relationships),
            "primary_attack_pattern_refs": primary_attack_patterns,
            "has_report": report_count == 1,
            "evidence_text_present": bool(evidence_text),
        }

    def materialize_bundle(
        self,
        *,
        item: dict[str, Any],
        graph_draft: dict[str, Any],
        validation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validation = validation or self.validate_graph_draft(
            item=item,
            graph_draft=graph_draft,
        )
        if validation.get("fatal"):
            raise ValueError(
                f"STIX draft failed validation: {validation.get('findings', [])}"
            )

        attack_code = self._attack_code_from_item(item) or "unknown"
        bundle_stix_id = f"bundle--{uuid4()}"
        created_ts = _utcnow()

        local_ref_to_id: dict[str, str] = {}
        primary_attack_pattern_id: str | None = None
        primary_attack_payload: dict[str, Any] | None = None
        object_payloads: list[dict[str, Any]] = []
        object_rows: list[dict[str, Any]] = []

        for obj in graph_draft.get("objects", []):
            object_type = str(obj["object_type"])
            stix_id = self._build_object_stix_id(
                attack_code=attack_code,
                object_type=object_type,
                name=str(obj["name"]),
            )
            local_ref_to_id[str(obj["local_ref"])] = stix_id
            payload = {
                "type": object_type,
                "spec_version": "2.1",
                "id": stix_id,
                "created": created_ts,
                "modified": created_ts,
                "name": obj["name"],
                "description": obj.get("description") or item.get("summary") or "",
                "labels": list(obj.get("labels", []) or []),
                "external_references": [
                    {
                        "source_name": ref["source_name"],
                        **(
                            {"external_id": ref["external_id"]}
                            if ref.get("external_id")
                            else {}
                        ),
                        **({"url": ref["url"]} if ref.get("url") else {}),
                        **(
                            {"description": ref["description"]}
                            if ref.get("description")
                            else {}
                        ),
                    }
                    for ref in obj.get("external_references", [])
                ],
            }
            if obj.get("aliases"):
                payload["aliases"] = list(obj.get("aliases", []))
            if object_type == "attack-pattern" and obj.get("kill_chain_phases"):
                payload["kill_chain_phases"] = [
                    {
                        "kill_chain_name": phase["kill_chain_name"],
                        "phase_name": phase["phase_name"],
                    }
                    for phase in obj.get("kill_chain_phases", [])
                ]
            if object_type == "indicator":
                pattern = str(obj.get("pattern") or "").strip()
                if not pattern:
                    raise ValueError(
                        f"Indicator object requires a concrete pattern: {obj.get('local_ref')}"
                    )
                payload["pattern_type"] = obj.get("pattern_type") or "stix"
                payload["pattern"] = pattern

            if object_type == "attack-pattern" and obj.get("is_primary"):
                primary_attack_pattern_id = stix_id
                primary_attack_payload = payload

            object_payloads.append(payload)
            object_rows.append(
                {
                    "stix_id": stix_id,
                    "object_type": object_type,
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "confidence": float(obj.get("confidence", 0.0)),
                    "is_primary": bool(obj.get("is_primary", False)),
                    "labels": list(obj.get("labels", []) or []),
                    "aliases": list(obj.get("aliases", []) or []),
                    "external_references": list(
                        obj.get("external_references", []) or []
                    ),
                    "kill_chain_phases": list(obj.get("kill_chain_phases", []) or []),
                    "raw_payload": payload,
                }
            )

        relationship_rows: list[dict[str, Any]] = []
        for rel in graph_draft.get("relationships", []):
            source_ref = local_ref_to_id.get(str(rel["source_ref"]))
            target_ref = local_ref_to_id.get(str(rel["target_ref"]))
            if not source_ref or not target_ref:
                raise ValueError(
                    f"Relationship references are incomplete: {rel.get('local_ref')}"
                )
            relationship_id = self._build_relationship_stix_id(
                relationship_type=str(rel["relationship_type"]),
                source_ref=source_ref,
                target_ref=target_ref,
            )
            payload = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": relationship_id,
                "created": created_ts,
                "modified": created_ts,
                "relationship_type": rel["relationship_type"],
                "source_ref": source_ref,
                "target_ref": target_ref,
                "description": rel.get("description") or "",
            }
            object_payloads.append(payload)
            relationship_rows.append(
                {
                    "stix_id": relationship_id,
                    "relationship_type": rel["relationship_type"],
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "description": rel.get("description"),
                    "confidence": float(rel.get("confidence", 0.0)),
                    "raw_payload": payload,
                }
            )

        for payload in object_payloads:
            if payload["type"] == "report":
                payload["published"] = created_ts
                payload["object_refs"] = [
                    obj["stix_id"]
                    for obj in object_rows
                    if obj["object_type"] != "report"
                ] + [rel["stix_id"] for rel in relationship_rows]

        bundle_payload = {
            "type": "bundle",
            "id": bundle_stix_id,
            "objects": object_payloads,
        }
        return {
            "bundle_stix_id": bundle_stix_id,
            "primary_attack_pattern_stix_id": primary_attack_pattern_id,
            "primary_attack_pattern_payload": primary_attack_payload,
            "graph_confidence": float(graph_draft.get("graph_confidence", 0.0)),
            "bundle_payload": bundle_payload,
            "object_rows": object_rows,
            "relationship_rows": relationship_rows,
        }

    def persist_bundle(
        self,
        *,
        item: dict[str, Any],
        graph_draft: dict[str, Any] | None,
        materialized: dict[str, Any] | None,
        validation: dict[str, Any],
        review_decision: dict[str, Any],
        extractor_model: str,
        reviewer_model: str | None,
        prompt_version: str,
        trace_id: str | None,
        runtime_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        runtime_context = runtime_context or {}
        with UnitOfWork(
            context=SqlContext(trace_id=trace_id, agent_name="stix_graph_service")
        ) as uow:
            attack_id = self._lookup_attack_id(item, uow=uow)
            publication_status = self._publication_status(
                materialized=materialized,
                validation=validation,
                review_decision=review_decision,
                runtime_context=runtime_context,
                attack_bound=attack_id is not None,
            )
            bundle_id: str | None = None
            primary_object_pk: str | None = None

            if materialized is not None:
                bundle = uow.stix.create_bundle(
                    attack_id=attack_id,
                    bundle_stix_id=materialized["bundle_stix_id"],
                    spec_version="2.1",
                    bundle_role="attack_graph",
                    graph_confidence=materialized.get("graph_confidence"),
                    review_status=publication_status,
                    primary_object_stix_id=materialized.get(
                        "primary_attack_pattern_stix_id"
                    ),
                    bundle_payload=materialized["bundle_payload"],
                )
                bundle_id = str(bundle.bundle_id)
                for row in materialized.get("object_rows", []):
                    created = uow.stix.create_object(
                        bundle_id=bundle_id,
                        attack_id=attack_id,
                        stix_id=row["stix_id"],
                        object_type=row["object_type"],
                        spec_version="2.1",
                        name=row.get("name"),
                        description=row.get("description"),
                        created_ts=None,
                        modified_ts=None,
                        revoked=False,
                        confidence=row.get("confidence"),
                        lang="en",
                        is_primary=bool(row.get("is_primary", False)),
                        raw_payload=row["raw_payload"],
                    )
                    if row.get("is_primary"):
                        primary_object_pk = str(created.object_pk)
                    for label in row.get("labels", []):
                        uow.stix.insert_object_label(
                            object_pk=str(created.object_pk),
                            label=str(label),
                        )
                    for alias in row.get("aliases", []):
                        uow.stix.insert_object_alias(
                            object_pk=str(created.object_pk),
                            alias=str(alias),
                        )
                    for ref in row.get("external_references", []):
                        uow.stix.insert_external_reference(
                            object_pk=str(created.object_pk),
                            source_name=str(ref["source_name"]),
                            external_id=ref.get("external_id"),
                            url=ref.get("url"),
                            description=ref.get("description"),
                        )
                    for phase in row.get("kill_chain_phases", []):
                        uow.stix.insert_kill_chain_phase(
                            object_pk=str(created.object_pk),
                            kill_chain_name=str(phase["kill_chain_name"]),
                            phase_name=str(phase["phase_name"]),
                        )
                for rel in materialized.get("relationship_rows", []):
                    created = uow.stix.create_object(
                        bundle_id=bundle_id,
                        attack_id=attack_id,
                        stix_id=rel["stix_id"],
                        object_type="relationship",
                        spec_version="2.1",
                        name=None,
                        description=rel.get("description"),
                        created_ts=None,
                        modified_ts=None,
                        revoked=False,
                        confidence=rel.get("confidence"),
                        lang="en",
                        is_primary=False,
                        raw_payload=rel["raw_payload"],
                    )
                    uow.stix.insert_relationship_projection(
                        object_pk=str(created.object_pk),
                        bundle_id=bundle_id,
                        relationship_type=str(rel["relationship_type"]),
                        source_ref=str(rel["source_ref"]),
                        target_ref=str(rel["target_ref"]),
                    )

            if attack_id and primary_object_pk and bundle_id:
                uow.stix.upsert_attack_binding(
                    attack_id=attack_id,
                    active_bundle_id=bundle_id,
                    primary_object_pk=primary_object_pk,
                    publication_status=publication_status,
                    published_at=(
                        datetime.now(timezone.utc)
                        if publication_status == "published"
                        else None
                    ),
                )
                uow.attacks.update_attack_entry(
                    attack_id,
                    primary_stix_bundle_id=bundle_id,
                    primary_stix_object_id=primary_object_pk,
                    stix_graph_status=publication_status,
                    stix_type="attack-pattern",
                    stix_payload=materialized.get("primary_attack_pattern_payload")
                    if materialized
                    else None,
                )
            elif attack_id:
                uow.attacks.update_attack_entry(
                    attack_id,
                    stix_graph_status="review_queue",
                )

            review_decision_value = (
                "accept" if publication_status == "published" else "review_queue"
            )
            queue_reason = self._queue_reason_code(
                validation=validation,
                review_decision=review_decision,
                publication_status=publication_status,
                attack_bound=attack_id is not None,
            )
            if review_decision_value != "accept":
                uow.stix.enqueue_review(
                    attack_id=attack_id,
                    bundle_id=bundle_id,
                    reason_code=queue_reason,
                    queue_status="open",
                    review_payload={
                        "validation": validation,
                        "review": review_decision,
                        "graph_draft": graph_draft,
                    },
                )

            uow.stix.insert_extraction_audit(
                attack_id=attack_id,
                bundle_id=bundle_id,
                extractor_model=extractor_model,
                reviewer_model=reviewer_model,
                prompt_version=prompt_version,
                review_decision=review_decision_value,
                graph_confidence=(
                    materialized.get("graph_confidence")
                    if materialized is not None
                    else float(graph_draft.get("graph_confidence", 0.0))
                    if graph_draft is not None
                    else None
                ),
                reasoning_summary=self._reasoning_summary(
                    validation=validation,
                    review_decision=review_decision,
                    publication_status=publication_status,
                ),
                reasoning_trace=self._reasoning_trace(
                    graph_draft=graph_draft,
                    validation=validation,
                    review_decision=review_decision,
                    publication_status=publication_status,
                ),
                finding_count=len(validation.get("findings", []) or [])
                + len(review_decision.get("finding_codes", []) or []),
            )
            return {
                "primary_stix_bundle_id": bundle_id,
                "primary_stix_object_id": primary_object_pk,
                "stix_graph_status": publication_status,
                "stix_type": "attack-pattern" if materialized else None,
                "stix_payload": (
                    materialized.get("primary_attack_pattern_payload")
                    if materialized
                    else None
                ),
            }

    def _attack_code_from_item(self, item: dict[str, Any]) -> str:
        source_metadata = dict(item.get("source_metadata", {}) or {})
        return str(
            source_metadata.get("stable_attack_code")
            or item.get("stable_attack_code")
            or item.get("attack_code")
            or ""
        )

    def _lookup_attack_id(
        self,
        item: dict[str, Any],
        *,
        uow: UnitOfWork,
    ) -> str | None:
        attack_code = self._attack_code_from_item(item)
        if not attack_code:
            return None
        attack = uow.attacks.get_attack_by_code(attack_code)
        if attack is None:
            return None
        return str(attack.attack_id)

    def _publication_status(
        self,
        *,
        materialized: dict[str, Any] | None,
        validation: dict[str, Any],
        review_decision: dict[str, Any],
        runtime_context: dict[str, Any],
        attack_bound: bool,
    ) -> str:
        if materialized is None or validation.get("fatal") or not attack_bound:
            return "review_queue"
        review_confidence = float(
            review_decision.get(
                "confidence",
                materialized.get("graph_confidence", 0.0),
            )
            or 0.0
        )
        final_confidence = min(
            float(materialized.get("graph_confidence", 0.0) or 0.0),
            review_confidence,
        )
        auto_publish_threshold = float(
            runtime_context.get("stix_auto_publish_threshold", 0.85) or 0.85
        )
        if (
            review_decision.get("decision") == "accept"
            and final_confidence >= auto_publish_threshold
        ):
            return "published"
        return "review_queue"

    def _queue_reason_code(
        self,
        *,
        validation: dict[str, Any],
        review_decision: dict[str, Any],
        publication_status: str,
        attack_bound: bool,
    ) -> str:
        findings = list(validation.get("findings", []) or [])
        if not attack_bound:
            return "attack_binding_missing"
        if any(finding.startswith("indicator_missing_pattern:") for finding in findings):
            return "indicator_missing_pattern"
        if any(finding.startswith("broken_relationship_ref:") for finding in findings):
            return "broken_relationship_ref"
        if "missing_primary_attack_pattern" in findings:
            return "missing_primary_attack_pattern"
        if "missing_report" in findings:
            return "missing_report"
        if "insufficient_evidence_text" in findings:
            return "insufficient_evidence"
        if review_decision.get("finding_codes"):
            return str(review_decision["finding_codes"][0])
        if publication_status != "published":
            return "low_confidence"
        return "review_required"

    def _reasoning_summary(
        self,
        *,
        validation: dict[str, Any],
        review_decision: dict[str, Any],
        publication_status: str,
    ) -> str:
        validation_finding = next(iter(validation.get("findings", []) or []), "")
        review_summary = str(review_decision.get("reasoning_summary", "")).strip()
        if publication_status == "published" and review_summary:
            return review_summary[:500]
        if validation_finding:
            return f"queued_for_review:{validation_finding}"[:500]
        return (review_summary or "queued_for_review:stix_graph_requires_human_review")[
            :500
        ]

    def _reasoning_trace(
        self,
        *,
        graph_draft: dict[str, Any] | None,
        validation: dict[str, Any],
        review_decision: dict[str, Any],
        publication_status: str,
    ) -> list[str] | None:
        trace: list[str] = []
        if graph_draft is not None:
            trace.extend(list(graph_draft.get("reasoning_trace", []) or []))
        if validation.get("findings"):
            trace.append(
                "Validation findings: "
                + ", ".join(str(finding) for finding in validation["findings"][:3])
            )
        trace.extend(list(review_decision.get("review_trace", []) or []))
        trace.append(f"Final publication status: {publication_status}")
        deduped = list(dict.fromkeys(step.strip() for step in trace if str(step).strip()))
        return deduped[:10] or None

    def _build_object_stix_id(self, *, attack_code: str, object_type: str, name: str) -> str:
        object_uuid = uuid5(
            NAMESPACE_URL,
            f"wp11:{attack_code}:{object_type}:{name.strip().lower()}",
        )
        return f"{object_type}--{object_uuid}"

    def _build_relationship_stix_id(
        self,
        *,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
    ) -> str:
        relationship_uuid = uuid5(
            NAMESPACE_URL,
            f"wp11:relationship:{relationship_type}:{source_ref}:{target_ref}",
        )
        return f"relationship--{relationship_uuid}"
