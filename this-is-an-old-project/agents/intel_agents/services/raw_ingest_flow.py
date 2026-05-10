from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from backend.db.exceptions import DatabaseError, NotFoundError
from backend.db.services.ingestion_service import IngestionService
from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork

from ..schemas.intel import RawCollectedItemDTO
from ..schemas.source import StoredRawRecordDTO


class RawIngestFlow:
    """Persist raw records with audit manifests, optional DB ingestion, and cleanup."""

    def __init__(
        self, artifact_store_dir: str | None = None, audit_store_dir: str | None = None
    ):
        self.artifact_store_dir = Path(
            artifact_store_dir or ".runtime/wp11/raw_records"
        )
        self.audit_store_dir = Path(audit_store_dir or ".runtime/wp11/audit")

    def _ensure_dir(self, base_dir: Path, run_id: str) -> Path:
        target = base_dir / run_id
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _write_manifest(self, run_id: str, item: dict[str, Any]) -> tuple[str, str]:
        target_dir = self._ensure_dir(self.artifact_store_dir, run_id)
        raw_id = f"raw_local_{uuid4().hex[:16]}"
        file_path = target_dir / f"{raw_id}.json"
        payload = {
            "raw_id": raw_id,
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "record": item,
        }
        file_path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8"
        )
        return raw_id, file_path.as_posix()

    def _write_audit(self, run_id: str, payload: dict[str, Any]) -> str:
        audit_dir = self._ensure_dir(self.audit_store_dir, run_id)
        audit_ref = f"audit_{uuid4().hex[:16]}"
        (audit_dir / f"{audit_ref}.json").write_text(
            json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8"
        )
        return (audit_dir / f"{audit_ref}.json").as_posix()

    def ingest(
        self,
        raw_items: list[dict[str, Any]],
        *,
        run_id: str,
        trace_id: str,
        persist_to_db: bool = False,
        task_mode: str = "fast",
        trigger_type: str = "manual",
        created_by: str = "phase2_collector",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not raw_items:
            return [], []

        validated = [RawCollectedItemDTO.model_validate(item) for item in raw_items]
        if persist_to_db:
            stored, audits = self._ingest_via_db(
                validated,
                run_id=run_id,
                trace_id=trace_id,
                task_mode=task_mode,
                trigger_type=trigger_type,
                created_by=created_by,
            )
            if stored:
                return stored, audits

        stored_records: list[dict[str, Any]] = []
        ingest_audits: list[dict[str, Any]] = []
        for item in validated:
            raw_id, manifest_uri = self._write_manifest(
                run_id, item.model_dump(mode="python")
            )
            audit_payload = {
                "trace_id": trace_id,
                "run_id": run_id,
                "query_run_id": item.query_run_id,
                "source_name": item.source_name,
                "stored_via": "local_manifest",
                "payload_uri": item.payload_uri,
                "manifest_uri": manifest_uri,
                "content_hash": item.content_hash,
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
            audit_ref = self._write_audit(run_id, audit_payload)
            ingest_audits.append(audit_payload | {"audit_ref": audit_ref})
            stored_records.append(
                StoredRawRecordDTO(
                    raw_id=raw_id,
                    query_run_id=item.query_run_id,
                    source_name=item.source_name,
                    payload_uri=item.payload_uri,
                    stored_via="local_manifest",
                    content_hash=item.content_hash,
                    ingest_audit_ref=audit_ref,
                ).model_dump(mode="python")
            )
        return stored_records, ingest_audits

    def cleanup_expired_payloads(self, *, retention_days: int) -> list[str]:
        removed: list[str] = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        for base_dir in (self.artifact_store_dir, self.audit_store_dir):
            if not base_dir.exists():
                continue
            for file_path in base_dir.rglob("*.json"):
                modified = datetime.fromtimestamp(
                    file_path.stat().st_mtime, tz=timezone.utc
                )
                if modified < cutoff:
                    removed.append(file_path.as_posix())
                    file_path.unlink(missing_ok=True)
        return removed

    def _ingest_via_db(
        self,
        raw_items: list[RawCollectedItemDTO],
        *,
        run_id: str,
        trace_id: str,
        task_mode: str,
        trigger_type: str,
        created_by: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        tasks_by_source: dict[str, str] = {}
        stored_records: list[dict[str, Any]] = []
        ingest_audits: list[dict[str, Any]] = []
        try:
            with UnitOfWork(
                context=SqlContext(trace_id=trace_id, agent_name="phase2_ingest")
            ) as uow:
                service = IngestionService(uow)
                for item in raw_items:
                    task_id = tasks_by_source.get(item.source_name)
                    if task_id is None:
                        task = service.create_collection_task(
                            source_name=item.source_name,
                            task_mode=task_mode,
                            trigger_type=trigger_type,
                            created_by=created_by,
                            trace_id=trace_id,
                        )
                        service.mark_task_running(str(task.task_id))
                        task_id = str(task.task_id)
                        tasks_by_source[item.source_name] = task_id
                    raw_record = service.store_raw_intel_record(
                        task_id=task_id,
                        source_uri=item.source_uri,
                        title=item.title,
                        content_hash=item.content_hash,
                        raw_format=item.raw_format,
                        payload_uri=item.payload_uri,
                        language_code=item.language_code,
                        relevance_score=item.relevance_score,
                        fetched_at=datetime.fromisoformat(item.fetched_at),
                    )
                    audit_payload = {
                        "trace_id": trace_id,
                        "run_id": run_id,
                        "task_id": task_id,
                        "query_run_id": item.query_run_id,
                        "source_name": item.source_name,
                        "stored_via": "db",
                        "payload_uri": item.payload_uri,
                        "content_hash": item.content_hash,
                        "stored_at": datetime.now(timezone.utc).isoformat(),
                    }
                    audit_ref = self._write_audit(run_id, audit_payload)
                    ingest_audits.append(audit_payload | {"audit_ref": audit_ref})
                    stored_records.append(
                        StoredRawRecordDTO(
                            raw_id=str(raw_record.raw_id),
                            query_run_id=item.query_run_id,
                            source_name=item.source_name,
                            payload_uri=item.payload_uri,
                            stored_via="db",
                            task_id=task_id,
                            content_hash=item.content_hash,
                            ingest_audit_ref=audit_ref,
                        ).model_dump(mode="python")
                    )
                for task_id in tasks_by_source.values():
                    service.finish_task(task_id, success=True)
        except (DatabaseError, NotFoundError, OSError, ValueError):
            return [], []
        return stored_records, ingest_audits
